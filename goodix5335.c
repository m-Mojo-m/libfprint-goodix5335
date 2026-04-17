/*
 * Goodix 5335 (27c6:5335) libfprint driver - Main
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "goodix5335.h"
#include <string.h>
#include <math.h>


int sigfm_match (const unsigned char *sample, const unsigned char *live, int width, int height);

G_DEFINE_TYPE (FpiDeviceGoodix5335, fpi_device_goodix5335, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
    { .vid = GOODIX5335_VID, .pid = GOODIX5335_PID },
    { .vid = 0,              .pid = 0              },
};

/* =========================================================================
 * Open SSM
 * States: PING → PING_ACK → FW_VERSION → FW_ACK → FW_REPLY →
 *         OTP → OTP_ACK → OTP_REPLY →
 *         CONFIG → CONFIG_ACK → CONFIG_REPLY
 * =========================================================================*/

static void
open_ssm_handler (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);

    switch (fpi_ssm_get_cur_state (ssm)) {
    case OPEN_STATE_PING:
        goodix5335_do_ping (self, ssm);
        break;
    case OPEN_STATE_FW_VERSION:
        goodix5335_get_fw_version (self, ssm);
        break;
    case OPEN_STATE_OTP:
        goodix5335_read_otp (self, ssm);
        break;
    case OPEN_STATE_UPLOAD_CONFIG:
        goodix5335_upload_config (self, ssm);
        break;
    case OPEN_STATE_PSK_CHECK:
        goodix5335_psk_check (self, ssm);
        break;
    case OPEN_STATE_PSK_WRITE:
        goodix5335_psk_write (self, ssm);
        break;
    case OPEN_STATE_GTLS_CLIENT_HELLO:
        goodix5335_gtls_client_hello (self, ssm);
        break;
    case OPEN_STATE_GTLS_SERVER_IDENTITY:
        goodix5335_gtls_server_identity (self, ssm);
        break;
    case OPEN_STATE_GTLS_VERIFY:
        goodix5335_gtls_send_verify (self, ssm);
        break;
    case OPEN_STATE_GTLS_DONE:
        goodix5335_gtls_recv_done (self, ssm);
        break;
    default:
        fpi_ssm_mark_failed (ssm,
            fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
        break;
    }
}

static void
open_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    if (error)
        fp_dbg ("Goodix 5335: open failed: %s", error->message);
    else
        fp_dbg ("Goodix 5335: open complete");
    fpi_device_open_complete (device, error);
}

static void
dev_open (FpDevice *device)
{
    GUsbDevice *usb_dev = fpi_device_get_usb_device (device);
    GError *error = NULL;

    if (!g_usb_device_claim_interface (usb_dev, 1, 0, &error)) {
        fpi_device_open_complete (device, error);
        return;
    }

    fpi_ssm_start (fpi_ssm_new (device, open_ssm_handler,
                                 OPEN_STATE_NUM_STATES),
                   open_ssm_done);
}

/* =========================================================================
 * Close
 * =========================================================================*/

static void
dev_close (FpDevice *device)
{
    GUsbDevice *usb_dev = fpi_device_get_usb_device (device);

    g_usb_device_release_interface (usb_dev, 1, 0, NULL);
    fpi_device_close_complete (device, NULL);
}

/* =========================================================================
 * Enroll SSM
 * States: WAIT_FINGER_DOWN → FDT_ACK → FDT_EVENT →
 *         CAPTURE → CAPTURE_ACK → CAPTURE_REPLY →
 *         PROCESS →
 *         WAIT_FINGER_UP → FDT_UP_ACK → FDT_UP_EVENT →
 *         NEXT_SAMPLE → DONE
 * =========================================================================*/

static void
enroll_ssm_handler (FpiSsm *ssm, FpDevice *device)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);

    switch (fpi_ssm_get_cur_state (ssm)) {
    case ENROLL_STATE_WAIT_FINGER_DOWN:
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
        goodix5335_wait_finger_down (self, ssm);
        break;
    case ENROLL_STATE_CAPTURE:
        g_warning ("Goodix 5335: ENROLL_STATE_CAPTURE entered - starting capture sub-SSM");
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        goodix5335_capture_image (self, ssm);
        break;
    case ENROLL_STATE_PROCESS: {
        /* On verify action, stop after first capture */
        if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY) {
            /* Decrypt and jump straight to DONE */
            if (self->gtls.established && self->rx_len > 4) {
                const guint8 *payload = self->rx_buf + 3;
                gsize plen2 = self->rx_len - 4;
                gsize dec_len2;
                guint8 *decrypted2 = goodix5335_gtls_decrypt_image (&self->gtls,
                                                                      payload, plen2,
                                                                      &dec_len2);
                if (decrypted2) {
                    gsize copy2 = MIN (dec_len2, (gsize) GOODIX5335_IMG_SIZE);
                    memcpy (self->image_buf, decrypted2, copy2);
                    g_free (decrypted2);
                }
            }
            fpi_ssm_jump_to_state (ssm, ENROLL_STATE_DONE);
            break;
        }
        /* Decrypt image from rx_buf if GTLS is active */
        if (self->gtls.established && self->rx_len > 4) {
            const guint8 *payload = self->rx_buf + 3;
            gsize plen = self->rx_len - 4;
            gsize dec_len;
            guint8 *decrypted = goodix5335_gtls_decrypt_image (&self->gtls,
                                                                payload, plen,
                                                                &dec_len);
            if (decrypted) {
                fp_info ("Goodix 5335: image decrypted OK (%zu bytes)", dec_len);
                gsize copy = MIN (dec_len, (gsize) GOODIX5335_IMG_SIZE);
                memcpy (self->image_buf, decrypted, copy);
                g_free (decrypted);
            } else {
                fp_warn ("Goodix 5335: decryption failed, using placeholder");
                memset (self->image_buf, 128, GOODIX5335_IMG_SIZE);
            }
        }
        guint8 *processed = g_malloc (GOODIX5335_IMG_SIZE);
        goodix5335_process_image (self, processed);
        if (!self->enroll_samples)
            self->enroll_samples = g_ptr_array_new_with_free_func (g_free);

        g_ptr_array_add (self->enroll_samples, processed);
        self->enroll_stage++;
        fp_dbg ("Goodix 5335: sample %d/%d",
                self->enroll_stage, GOODIX5335_ENROLL_SAMPLES);
        fpi_device_enroll_progress (device, self->enroll_stage, NULL, NULL);
        fpi_ssm_next_state (ssm);
        break;
    }
    case ENROLL_STATE_WAIT_FINGER_UP:
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        goodix5335_wait_finger_up (self, ssm);
        break;
    case ENROLL_STATE_NEXT_SAMPLE:
        if (self->enroll_stage < GOODIX5335_ENROLL_SAMPLES)
            fpi_ssm_jump_to_state (ssm, ENROLL_STATE_WAIT_FINGER_DOWN);
        else
            fpi_ssm_next_state (ssm);
        break;
    case ENROLL_STATE_DONE:
        fpi_ssm_mark_completed (ssm);
        break;
    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);
    FpPrint *print = NULL;

    if (error) { fpi_device_enroll_complete (device, NULL, error); goto cleanup; }

    fpi_device_get_enroll_data (device, &print);
    fpi_print_set_type (print, FPI_PRINT_RAW);

    {
        GVariantBuilder builder;
        GVariant *data;
        guint i;

        g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

        if (self->gtls.established && self->enroll_samples && self->enroll_samples->len > 0) {
            fp_info ("Goodix 5335: saving %d real enrollment samples",
                     self->enroll_samples->len);
            for (i = 0; i < self->enroll_samples->len; i++) {
                guint8 *sample = self->enroll_samples->pdata[i];
                g_variant_builder_add (&builder, "@ay",
                    g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                               sample, GOODIX5335_IMG_SIZE, 1));
            }
        } else {
            fp_dbg ("Goodix 5335: saving placeholder enrollment");
            guint8 dummy[GOODIX5335_IMG_SIZE];
            memset (dummy, 128, sizeof (dummy));
            g_variant_builder_add (&builder, "@ay",
                g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                           dummy, GOODIX5335_IMG_SIZE, 1));
        }

        data = g_variant_builder_end (&builder);
        g_object_set (G_OBJECT (print), "fpi-data", data, NULL);
    }

    fpi_device_enroll_complete (device, g_object_ref (print), NULL);

cleanup:
    if (self->enroll_samples) {
        g_ptr_array_free (self->enroll_samples, TRUE);
        self->enroll_samples = NULL;
    }
    self->enroll_stage = 0;
}

static void
dev_enroll (FpDevice *device)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);
    self->enroll_stage = 0;
    fpi_ssm_start (fpi_ssm_new (device, enroll_ssm_handler,
                                 ENROLL_STATE_NUM_STATES),
                   enroll_ssm_done);
}

/* =========================================================================
 * Match helper
 * =========================================================================*/




/* =========================================================================
 * Verify SSM — reuses enroll flow to capture one image, then matches
 * =========================================================================*/

/* Simple normalized cross-correlation matcher */
/* SIGFM-based matching — score >= GOODIX5335_SIGFM_THRESHOLD is a match */
#define GOODIX5335_SIGFM_THRESHOLD    10
#define GOODIX5335_SIGFM_BEST_MIN     12
#define GOODIX5335_SIGFM_MIN_SAMPLES  3


static void
verify_ssm_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);
    FpPrint *enrolled_print = NULL;
    GVariant *fpi_data = NULL;

    if (error) {
        fpi_device_verify_complete (device, error);
        goto cleanup;
    }

    /* image_buf was already filled and decoded by ENROLL_STATE_PROCESS */
    guint8 *probe = g_malloc (GOODIX5335_IMG_SIZE);
    goodix5335_process_image (self, probe);

    /* Load enrolled templates */
    fpi_device_get_verify_data (device, &enrolled_print);
    g_object_get (G_OBJECT (enrolled_print), "fpi-data", &fpi_data, NULL);

    if (fpi_data) {
        GVariantIter iter;
        GVariant *child;
        gint sample_num = 0;
        gint votes = 0;
        gint best_score = 0;

        g_variant_iter_init (&iter, fpi_data);
        while ((child = g_variant_iter_next_value (&iter)) != NULL) {
            gsize tmpl_len;
            const guint8 *tmpl = g_variant_get_fixed_array (child,
                                                              &tmpl_len, 1);
            if (tmpl_len == GOODIX5335_IMG_SIZE) {
                int score = sigfm_match (tmpl, probe,
                                         GOODIX5335_IMG_WIDTH,
                                         GOODIX5335_IMG_HEIGHT);
                fp_dbg ("Goodix 5335: SIGFM score=%d (sample %d)", score, sample_num);
                if (score > best_score) best_score = score;
                if (score >= GOODIX5335_SIGFM_THRESHOLD) votes++;
            }
            sample_num++;
            g_variant_unref (child);
        }
        g_variant_unref (fpi_data);

        gboolean matched = (best_score >= GOODIX5335_SIGFM_BEST_MIN) ||
                           (votes >= GOODIX5335_SIGFM_MIN_SAMPLES);
        fp_info ("Goodix 5335: verify %s (best=%d votes=%d/%d)", matched ? "MATCH" : "NO MATCH", best_score, votes, sample_num);
        fpi_device_verify_report (device,
                                   matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                   NULL, NULL);
    } else {
        fpi_device_verify_report (device, FPI_MATCH_FAIL, NULL, NULL);
    }

    g_free (probe);
    fpi_device_verify_complete (device, NULL);

cleanup:
    if (self->enroll_samples) {
        g_ptr_array_free (self->enroll_samples, TRUE);
        self->enroll_samples = NULL;
    }
    self->enroll_stage = 0;
}

static void
dev_verify (FpDevice *device)
{
    fpi_ssm_start (fpi_ssm_new (device, enroll_ssm_handler,
                                 ENROLL_STATE_NUM_STATES),
                   verify_ssm_done);
}

static void
dev_identify (FpDevice *device)
{
  /* TODO: identify is not yet implemented for goodix5335.
   * The GTLS crypto handshake is complete, but wiring image capture
   * into the identify path (mirroring dev_verify) is pending.
   * For now, report no-match immediately so callers do not hang. */
  fpi_device_identify_report (device, NULL, NULL, NULL);
  fpi_device_identify_complete (device, NULL);
}

/* =========================================================================
 * GObject class init
 * =========================================================================*/

static void
fpi_device_goodix5335_init (FpiDeviceGoodix5335 *self)
{
  self->rx_buf = g_malloc (16 * 1024);
    self->fdt_state = FDT_STATE_NONE;
    self->enroll_samples = NULL; /* initialized on first use */
    self->enroll_stage = 0;
}

static void
fpi_device_goodix5335_finalize (GObject *obj)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (obj);

    if (self->enroll_samples)
        g_ptr_array_free (self->enroll_samples, TRUE);

    G_OBJECT_CLASS (fpi_device_goodix5335_parent_class)->finalize (obj);
}

static void
fpi_device_goodix5335_class_init (FpiDeviceGoodix5335Class *klass)
{
    GObjectClass  *obj_class = G_OBJECT_CLASS (klass);
    FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

    obj_class->finalize = fpi_device_goodix5335_finalize;

    dev_class->id               = "goodix5335";
    dev_class->full_name        = "Goodix Fingerprint Sensor 5335";
    dev_class->type             = FP_DEVICE_TYPE_USB;
    dev_class->id_table         = id_table;
    dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
    dev_class->nr_enroll_stages = GOODIX5335_ENROLL_SAMPLES;
    dev_class->temp_hot_seconds = -1;
    dev_class->features         = FP_DEVICE_FEATURE_CAPTURE |
                                   FP_DEVICE_FEATURE_VERIFY |
                                   FP_DEVICE_FEATURE_IDENTIFY;

    dev_class->open     = dev_open;
    dev_class->close    = dev_close;
    dev_class->enroll   = dev_enroll;
    dev_class->verify   = dev_verify;
    dev_class->identify = dev_identify;
}
