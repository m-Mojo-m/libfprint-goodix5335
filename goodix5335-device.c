/*
 * Goodix 5335 libfprint driver - Device helpers
 *
 * Architecture follows goodix53x5 (goodix-fp-linux-dev):
 *  - Every SSM state has EXACTLY ONE pending transfer
 *  - Commands run as sub-SSMs: SEND → RECV_ACK → RECV_DATA
 *  - FDT wait uses separate SETUP and RECV_EVENT states
 *  - Infinite timeout (0) + cancellable for finger event wait
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "goodix5335.h"
#include <string.h>

static void gtls_done_rx_cb (FpiUsbTransfer *, FpDevice *, gpointer, GError *);

#include <math.h>

#define CMD_TIMEOUT   2000
#define ACK_TIMEOUT   2000
#define DATA_TIMEOUT  5000

/* Calibrated sensor config for 27c6:5335 (Dell XPS 13 9305)
 * tcode=0x85, delta_down=0x10, dac_l=0xc2 derived from OTP */
static const guint8 SENSOR_CONFIG_5335[256] = {
    0x40, 0x11, 0x6c, 0x7d, 0x28, 0xa5, 0x28, 0xcd, 0x1c, 0xe9, 0x10, 0xf9, 0x00, 0xf9, 0x00, 0xf9,
    0x00, 0x04, 0x02, 0x00, 0x00, 0x08, 0x00, 0x11, 0x11, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x07,
    0x00, 0x84, 0x00, 0xbe, 0xb2, 0x86, 0x00, 0xc5, 0xb9, 0x88, 0x00, 0xb5, 0xad, 0x8a, 0x00, 0x9d,
    0x95, 0x8c, 0x00, 0x00, 0xbe, 0x8e, 0x00, 0x00, 0xc5, 0x90, 0x00, 0x00, 0xb5, 0x92, 0x00, 0x00,
    0x9d, 0x94, 0x00, 0x00, 0xaf, 0x96, 0x00, 0x00, 0xbf, 0x98, 0x00, 0x00, 0xb6, 0x9a, 0x00, 0x00,
    0xa7, 0x30, 0x00, 0x6c, 0x1c, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00,
    0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34, 0x12, 0x26, 0x00, 0x00, 0x12, 0x20, 0x00, 0x10,
    0x40, 0x12, 0x00, 0x03, 0x04, 0x02, 0x02, 0x16, 0x21, 0x2c, 0x02, 0x0a, 0x03, 0x2a, 0x01, 0x02,
    0x00, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x05, 0x04, 0x5c, 0x00, 0x00,
    0x01, 0x56, 0x00, 0x28, 0x20, 0x58, 0x00, 0x01, 0x00, 0x32, 0x00, 0x24, 0x02, 0x82, 0x00, 0x80,
    0x0c, 0x20, 0x02, 0x88, 0x0d, 0x2a, 0x01, 0x92, 0x07, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14,
    0x00, 0x80, 0x00, 0x05, 0x04, 0x5c, 0x00, 0x85, 0x00, 0x56, 0x00, 0x08, 0x20, 0x58, 0x00, 0x03,
    0x00, 0x32, 0x00, 0x08, 0x04, 0x82, 0x00, 0x80, 0x10, 0x20, 0x02, 0x28, 0x0c, 0x2a, 0x01, 0x18,
    0x04, 0x5c, 0x00, 0x85, 0x00, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x09, 0x03, 0x64, 0x00, 0x18,
    0x00, 0x82, 0x00, 0x80, 0x0c, 0x20, 0x02, 0x28, 0x0c, 0x2a, 0x01, 0x18, 0x04, 0x5c, 0x00, 0x85,
    0x00, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x40,
};

/* FDT base for finger-down (calibrated from OTP) */
static const guint8 FDT_BASE_DOWN[24] = {
    0x8d, 0x8d, 0x9d, 0x9d, 0x9b, 0x9b, 0x92, 0x92,
    0x8c, 0x8c, 0x98, 0x98, 0x98, 0x98, 0x91, 0x91,
    0x86, 0x86, 0x93, 0x93, 0x92, 0x92, 0x8b, 0x8b,
};

/* ===========================================================================
 * Low-level TX callback: advances SSM on success, fails on error
 * ===========================================================================*/

static void
goodix_tx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
              gpointer user_data, GError *error)
{
    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }
    fpi_ssm_next_state (transfer->ssm);
}

/* Send a message and advance SSM when the OUT transfer completes */
static void
goodix_send (FpiSsm              *ssm,
             FpDevice            *dev,
             guint8               category,
             guint8               command,
             const guint8        *payload,
             gsize                payload_len)
{
    g_autoptr(GBytes) msg = goodix5335_encode_msg (category, command,
                                                    payload, payload_len);
    gsize msglen;
    const guint8 *msgdata = g_bytes_get_data (msg, &msglen);

    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
    t->ssm = ssm;
    fpi_usb_transfer_fill_bulk_full (t, GOODIX5335_EP_OUT,
                                     (guint8 *) msgdata, msglen, NULL);
    t->short_is_error = FALSE;
    fpi_usb_transfer_submit (t, CMD_TIMEOUT, NULL, goodix_tx_cb, NULL);
}

/* ===========================================================================
 * Low-level RX callback: skips empty reads, advances SSM when data arrives
 * ===========================================================================*/

static void
goodix_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
              gpointer user_data, GError *error)
{
    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }

    /* Skip zero-length reads — resubmit */
    if (transfer->actual_length == 0) {
        guint timeout = GPOINTER_TO_UINT (user_data);
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, timeout,
                                  timeout == 0 ? fpi_device_get_cancellable (dev) : NULL,
                                  goodix_rx_cb, user_data);
        return;
    }

    fpi_ssm_next_state (transfer->ssm);
}


/* ===========================================================================
 * Command sub-SSM: SEND → RECV_ACK → RECV_DATA
 * Each state has exactly one pending transfer.
 * ===========================================================================*/

typedef enum {
    CMD_STATE_SEND = 0,
    CMD_STATE_RECV_ACK,
    CMD_STATE_RECV_DATA,
    CMD_STATE_NUM_STATES,
} CmdState;

typedef struct {
    guint8       category;
    guint8       command;
    guint8      *payload;
    gsize        payload_len;
    gboolean     expect_data;
} CmdParams;

/* Callback for CMD_STATE_RECV_ACK: keeps reading until it sees an ACK (cat=0xB) */
static void
cmd_ack_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
               gpointer user_data, GError *error)
{
    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }
    if (transfer->actual_length == 0) {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, ACK_TIMEOUT, NULL, cmd_ack_rx_cb, NULL);
        return;
    }
    /* Check if this is an ACK (cat=0xB, cmd=0) */
    const guint8 *buf = transfer->buffer;
    guint8 cat = buf[0] >> 4;
    if (cat == 0xB) {
        /* Got ACK - advance to next state */
        fpi_ssm_next_state (transfer->ssm);
    } else {
        /* Not an ACK yet - skip and keep reading */
        fp_dbg ("Goodix 5335: expected ACK, got cat=0x%X, skipping", cat);
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, ACK_TIMEOUT, NULL, cmd_ack_rx_cb, NULL);
    }
}

/* Callback for CMD_STATE_RECV_DATA: reassembles multi-chunk responses */
static void
cmd_data_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                gpointer user_data, GError *error)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (dev);

    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }
    if (transfer->actual_length == 0) {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, DATA_TIMEOUT, NULL, cmd_data_rx_cb, NULL);
        return;
    }

    const guint8 *buf = transfer->buffer;
    gsize chunk_len = transfer->actual_length;
    guint8 cat = buf[0] >> 4;

    /* Skip ACKs */
    if (cat == 0xB) {
        fp_dbg ("Goodix 5335: got extra ACK in data state, skipping");
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, DATA_TIMEOUT, NULL, cmd_data_rx_cb, NULL);
        return;
    }

    /* First or continuation chunk? */
    if (self->rx_len == 0) {
        /* First chunk: read size to know total */
        self->rx_cmd_byte = buf[0];
        guint16 msg_size = buf[1] | ((guint16) buf[2] << 8);
        self->rx_expected = (gsize) msg_size + 3;
        gsize copy = MIN (chunk_len, self->rx_expected);
        memcpy (self->rx_buf, buf, copy);
        self->rx_len = copy;
        fp_dbg ("Goodix 5335: data reply cat=0x%X, expecting %zu bytes total",
                cat, self->rx_expected);
    } else {
        /* Continuation: skip first byte (marker), append rest */
        if (chunk_len > 1) {
            gsize remaining = self->rx_expected - self->rx_len;
            gsize copy = MIN (chunk_len - 1, remaining);
            memcpy (self->rx_buf + self->rx_len, buf + 1, copy);
            self->rx_len += copy;
        }
    }

    if (self->rx_len >= self->rx_expected) {
        fp_dbg ("Goodix 5335: data reply complete (%zu bytes)", self->rx_len);
        fpi_ssm_mark_completed (transfer->ssm);
        return;
    }

    /* Need more chunks */
    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
    t->ssm = transfer->ssm;
    fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
    fpi_usb_transfer_submit (t, DATA_TIMEOUT, NULL, cmd_data_rx_cb, NULL);
}

static void
cmd_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
    CmdParams *p = fpi_ssm_get_data (ssm);

    switch (fpi_ssm_get_cur_state (ssm)) {
    case CMD_STATE_SEND:
        goodix_send (ssm, dev, p->category, p->command,
                     p->payload, p->payload_len);
        break;
    case CMD_STATE_RECV_ACK:
        {
            FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
            t->ssm = ssm;
            fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
            fpi_usb_transfer_submit (t, ACK_TIMEOUT, NULL, cmd_ack_rx_cb, NULL);
        }
        break;
    case CMD_STATE_RECV_DATA:
        if (p->expect_data) {
            FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
            t->ssm = ssm;
            fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
            fpi_usb_transfer_submit (t, DATA_TIMEOUT, NULL, cmd_data_rx_cb, NULL);
        } else {
            fpi_ssm_mark_completed (ssm);
        }
        break;
    }
}



static void
cmd_params_free (CmdParams *p)
{
    if (p) {
        g_free (p->payload);
        g_free (p);
    }
}

/* Same but with proper free */
static void
goodix_run_cmd2 (FpiSsm       *parent,
                 FpDevice     *dev,
                 guint8        category,
                 guint8        command,
                 const guint8 *payload,
                 gsize         payload_len,
                 gboolean      expect_data)
{
    CmdParams *p = g_new0 (CmdParams, 1);
    p->category    = category;
    p->command     = command;
    p->payload     = payload_len > 0 ? g_memdup2 (payload, payload_len) : NULL;
    p->payload_len = payload_len;
    p->expect_data = expect_data;

    FpiSsm *sub = fpi_ssm_new_full (dev, cmd_ssm_handler,
                                     CMD_STATE_NUM_STATES,
                                     CMD_STATE_NUM_STATES,
                                     "goodix-cmd");
    fpi_ssm_set_data (sub, p, (GDestroyNotify) cmd_params_free);
    fpi_ssm_start_subsm (parent, sub);
}

/* ===========================================================================
 * Public API: each function starts a sub-SSM, parent advances on completion
 * ===========================================================================*/

void
goodix5335_do_ping (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: ping");
    static const guint8 payload[] = { 0x00, 0x00 };
    goodix_run_cmd2 (ssm, FP_DEVICE (dev), 0x0, 0x0,
                     payload, sizeof (payload), FALSE);
}

void
goodix5335_get_fw_version (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: get fw version");
    static const guint8 payload[] = { 0x00, 0x00 };
    goodix_run_cmd2 (ssm, FP_DEVICE (dev), GOODIX5335_CAT_MCU,
                     GOODIX5335_CMD_FW_VERSION,
                     payload, sizeof (payload), TRUE);
}

void
goodix5335_read_otp (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: read OTP");
    static const guint8 payload[] = { 0x00, 0x00 };
    goodix_run_cmd2 (ssm, FP_DEVICE (dev), GOODIX5335_CAT_MCU,
                     GOODIX5335_CMD_OTP,
                     payload, sizeof (payload), TRUE);
}

void
goodix5335_upload_config (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: upload config");
    goodix_run_cmd2 (ssm, FP_DEVICE (dev), GOODIX5335_CAT_CONFIG,
                     GOODIX5335_CMD_CONFIG,
                     SENSOR_CONFIG_5335, sizeof (SENSOR_CONFIG_5335), TRUE);
}

/* ===========================================================================
 * FDT finger wait sub-SSM
 * State 0: SEND the FDT command (one OUT transfer)
 * State 1: RECV the ACK (one IN transfer, short timeout)
 * State 2: RECV the finger event (one IN transfer, INFINITE timeout)
 * ===========================================================================*/

typedef enum {
    FDT_STATE_SEND = 0,
    FDT_STATE_RECV_ACK,
    FDT_STATE_RECV_EVENT,
    FDT_STATE_NUM,
} FdtSubState;

typedef struct {
    guint8   fdt_cmd;
    gboolean is_down;
} FdtParams;

static void
fdt_event_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                  gpointer user_data, GError *error)
{
    if (error) {
        fpi_ssm_mark_failed (transfer->ssm, error);
        return;
    }
    if (transfer->actual_length == 0) {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, 0, fpi_device_get_cancellable (dev),
                                  fdt_event_rx_cb, NULL);
        return;
    }
    /* Skip stray ACKs - only complete on actual FDT event (cat=3) */
    const guint8 *buf = transfer->buffer;
    guint8 cat = buf[0] >> 4;
    if (cat == 0xB) {
        fp_dbg ("Goodix 5335: stray ACK in FDT event wait, re-arming");
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = transfer->ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, 0, fpi_device_get_cancellable (dev),
                                  fdt_event_rx_cb, NULL);
        return;
    }
    fp_dbg ("Goodix 5335: finger event received (cat=0x%X), completing FDT wait", cat);
    fpi_ssm_mark_completed (transfer->ssm);
}

static void
fdt_ssm_handler (FpiSsm *ssm, FpDevice *dev)
{
    FdtParams *p = fpi_ssm_get_data (ssm);

    switch (fpi_ssm_get_cur_state (ssm)) {
    case FDT_STATE_SEND:
        {
            guint8 payload[26];
            payload[0] = p->is_down ? 0x0C : 0x0E;
            payload[1] = 0x01;
            memcpy (payload + 2, FDT_BASE_DOWN, 24);
            goodix_send (ssm, dev, GOODIX5335_CAT_FDT, p->fdt_cmd,
                         payload, sizeof (payload));
        }
        break;
    case FDT_STATE_RECV_ACK:
        {
            FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
            t->ssm = ssm;
            fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
            fpi_usb_transfer_submit (t, ACK_TIMEOUT, NULL, cmd_ack_rx_cb, NULL);
        }
        break;
    case FDT_STATE_RECV_EVENT:
        /* Infinite timeout, cancellable — blocks until finger event.
         * This is the last state: use fdt_event_rx_cb that calls mark_completed */
        {
            FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
            t->ssm = ssm;
            fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
            fpi_usb_transfer_submit (t, 0, fpi_device_get_cancellable (dev),
                                      fdt_event_rx_cb, NULL);
        }
        break;
    }
}


static void
goodix_fdt_wait (FpiDeviceGoodix5335 *dev, FpiSsm *ssm,
                 guint8 fdt_cmd, gboolean is_down)
{
    FdtParams *p = g_new0 (FdtParams, 1);
    p->fdt_cmd = fdt_cmd;
    p->is_down = is_down;

    FpiSsm *sub = fpi_ssm_new_full (FP_DEVICE (dev), fdt_ssm_handler,
                                     FDT_STATE_NUM, FDT_STATE_NUM,
                                     "goodix-fdt");
    fpi_ssm_set_data (sub, p, (GDestroyNotify) g_free);
    fpi_ssm_start_subsm (ssm, sub);
}

void
goodix5335_wait_finger_down (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: waiting for finger down");
    dev->fdt_state = FDT_STATE_NONE;
    goodix_fdt_wait (dev, ssm, GOODIX5335_CMD_FDT_DOWN, TRUE);
}

void
goodix5335_wait_finger_up (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    fp_dbg ("Goodix 5335: waiting for finger up");
    goodix_fdt_wait (dev, ssm, GOODIX5335_CMD_FDT_UP, FALSE);
}

/* ===========================================================================
 * Image capture (placeholder - GTLS not yet implemented)
 * ===========================================================================*/

static void
capture_drain_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                  gpointer user_data, GError *error)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (dev);
    if (error) g_error_free (error);
    fp_dbg ("Goodix 5335: capture complete (placeholder)");
    memset (self->image_buf, 128, GOODIX5335_IMG_SIZE * 6 / 4);
    fpi_ssm_next_state (transfer->ssm);
}

/* Callback to receive large encrypted image response (may span many chunks) */
static void
image_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
              gpointer user_data, GError *error)
{
    FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (dev);
    FpiSsm *ssm = transfer->ssm;

    if (error) { fpi_ssm_mark_failed (ssm, error); return; }

    if (transfer->actual_length > 0) {
        const guint8 *chunk = transfer->buffer;
        gsize chunk_len = transfer->actual_length;

        if (self->rx_len == 0) {
            /* First chunk */
            self->rx_cmd_byte = chunk[0];
            guint16 msg_size = chunk[1] | ((guint16)chunk[2] << 8);
            self->rx_expected = (gsize)msg_size + 3;
            gsize copy = MIN (chunk_len, self->rx_expected);
            memcpy (self->rx_buf, chunk, copy);
            self->rx_len = copy;
        } else {
            /* Continuation chunk: skip first byte (marker) */
            gsize copy = MIN (chunk_len - 1, self->rx_expected - self->rx_len);
            if (copy > 0) {
                memcpy (self->rx_buf + self->rx_len, chunk + 1, copy);
                self->rx_len += copy;
            }
        }

        if (self->rx_len >= self->rx_expected) {
            /* Full message received - decrypt and store */
            fp_dbg ("Goodix 5335: image received (%zu bytes), decrypting", self->rx_len);
            const guint8 *payload = self->rx_buf + 3;
            gsize plen = self->rx_len - 4;
            gsize dec_len;
            guint8 *decrypted = goodix5335_gtls_decrypt_image (&self->gtls,
                                                                payload, plen,
                                                                &dec_len);
            if (decrypted) {
                /* Convert 12-bit packed to 8-bit */
                gsize raw_bytes = (gsize) GOODIX5335_IMG_SIZE * 6 / 4; /* 12-bit packed */
                fp_dbg ("Goodix 5335: image decrypted (%zu bytes)", dec_len);
                gsize copy = MIN (raw_bytes, dec_len);
                memcpy (self->image_buf, decrypted, copy);
                g_free (decrypted);
            } else {
                fp_warn ("Goodix 5335: image decryption failed, using placeholder");
                memset (self->image_buf, 128, GOODIX5335_IMG_SIZE * 6 / 4);
            }
            self->rx_len = 0;
            self->rx_expected = 0;
            fpi_ssm_next_state (ssm);
            return;
        }
    }

    /* Need more data */
    FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
    t->ssm = ssm;
    fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
    fpi_usb_transfer_submit (t, DATA_TIMEOUT, NULL, image_rx_cb, NULL);
}

void
goodix5335_capture_image (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
    FpDevice *device = FP_DEVICE (dev);

    if (!dev->gtls.established) {
        fp_dbg ("Goodix 5335: capture (drain+placeholder, GTLS not ready)");
        FpiUsbTransfer *t = fpi_usb_transfer_new (device);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
        fpi_usb_transfer_submit (t, 1, NULL, capture_drain_cb, NULL);
        return;
    }

    fp_dbg ("Goodix 5335: capture (real image via GTLS)");
    dev->rx_len = 0;
    dev->rx_expected = 0;

    guint8 img_req[4];
    img_req[0] = 0x41;  /* TX on + finger */
    img_req[1] = 0x06;  /* HV value */
    img_req[2] = 0x7e;  /* dac_h low byte */
    img_req[3] = 0x00;

    goodix_run_cmd2 (ssm, device,
                     GOODIX5335_CAT_IMAGE, GOODIX5335_CMD_IMAGE,
                     img_req, sizeof (img_req), TRUE);
}

/* ===========================================================================
 * Image processing
 * ===========================================================================*/

void
goodix5335_process_image (FpiDeviceGoodix5335 *dev, guint8 *img_out)
{
    /* Decode 12-bit packed image data → 16-bit pixels (goodix53x5 format)
     * 6 bytes → 4 pixels:
     *   px0 = (buf[0] & 0x0F) << 8 | buf[1]
     *   px1 = buf[3] << 4 | buf[0] >> 4
     *   px2 = (buf[5] & 0x0F) << 8 | buf[2]
     *   px3 = buf[4] << 4 | buf[5] >> 4
     */
    const int W = GOODIX5335_IMG_WIDTH;
    const int H = GOODIX5335_IMG_HEIGHT;
    const int N = GOODIX5335_IMG_SIZE;
    const guint8 *raw = dev->image_buf;
    gsize raw_len = (gsize) N * 6 / 4; /* bytes needed for N 12-bit pixels */

    float *img = g_malloc (N * sizeof (float));
    int pixel_idx = 0;

    /* Decode 12-bit packed pixels */
    for (gsize i = 0; i + 5 < raw_len && pixel_idx + 3 < N; i += 6) {
        img[pixel_idx++] = (float)(((raw[i + 0] & 0x0F) << 8) | raw[i + 1]);
        img[pixel_idx++] = (float)(((guint16)raw[i + 3] << 4) | (raw[i + 0] >> 4));
        img[pixel_idx++] = (float)(((raw[i + 5] & 0x0F) << 8) | raw[i + 2]);
        img[pixel_idx++] = (float)(((guint16)raw[i + 4] << 4) | (raw[i + 5] >> 4));
    }
    /* Fill any remaining pixels */
    while (pixel_idx < N)
        img[pixel_idx++] = 2048.0f;

    /* Gaussian lowpass (sigma=5, radius=15) for highpass correction */
    const int radius = 15;
    const float sigma = 5.0f;
    float kernel[31];
    float ksum = 0.0f;
    for (int k = 0; k <= 2 * radius; k++) {
        float x = k - radius;
        kernel[k] = expf (-0.5f * x * x / (sigma * sigma));
        ksum += kernel[k];
    }
    for (int k = 0; k <= 2 * radius; k++) kernel[k] /= ksum;

    float *tmp = g_malloc (N * sizeof (float));
    float *blurred = g_malloc (N * sizeof (float));

    /* Horizontal pass */
    for (int r = 0; r < H; r++)
        for (int c = 0; c < W; c++) {
            float s = 0.0f;
            for (int k = -radius; k <= radius; k++) {
                int cc = c + k;
                if (cc < 0) cc = 0;
                if (cc >= W) cc = W - 1;
                s += img[r * W + cc] * kernel[k + radius];
            }
            tmp[r * W + c] = s;
        }
    /* Vertical pass */
    for (int r = 0; r < H; r++)
        for (int c = 0; c < W; c++) {
            float s = 0.0f;
            for (int k = -radius; k <= radius; k++) {
                int rr = r + k;
                if (rr < 0) rr = 0;
                if (rr >= H) rr = H - 1;
                s += tmp[rr * W + c] * kernel[k + radius];
            }
            blurred[r * W + c] = s;
        }

    /* Highpass = original - lowpass; find range and normalize to [0,255] */
    float vmin = 1e9f, vmax = -1e9f;
    for (int i = 0; i < N; i++) {
        float v = img[i] - blurred[i];
        img[i] = v;
        if (v < vmin) vmin = v;
        if (v > vmax) vmax = v;
    }
    float range = vmax - vmin;
    if (range < 1.0f) range = 1.0f;
    for (int i = 0; i < N; i++) {
        float v = (img[i] - vmin) / range * 255.0f;
        img_out[i] = (guint8) CLAMP ((int) v, 0, 255);
    }

    g_free (img);
    g_free (tmp);
    g_free (blurred);
}

/* ===========================================================================
 * GTLS Handshake (ported from goodix53x5)
 * PSK = 32 zero bytes (all-zero for unconfigured sensors)
 * ===========================================================================*/

static const guint8 GOODIX5335_PSK[32] = { 0 };

static const guint8 GOODIX5335_PSK_WHITE_BOX[96] = {
  0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f,
  0x12, 0xc4, 0x75, 0x1f, 0x1e, 0x5c, 0x2c, 0xc0,
  0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
  0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b,
  0x6f, 0xd6, 0x6b, 0x1d, 0x97, 0xcf, 0x80, 0xf1,
  0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
  0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75,
  0xc4, 0x1e, 0x65, 0x92, 0xcd, 0x2a, 0x2f, 0x9e,
  0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
  0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3,
  0x1e, 0xdb, 0x33, 0x94, 0x04, 0x6e, 0xc0, 0x6b,
  0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};

/* Build MCU message envelope: [type(4LE)][size(4LE)][data] */
static guint8 *
build_mcu_msg (guint32 data_type, const guint8 *data, gsize data_len,
               gsize *out_len)
{
  gsize total = 4 + 4 + data_len;
  guint8 *buf = g_malloc (total);
  guint32 size_val = (guint32)(data_len + 8);

  buf[0] = data_type & 0xFF; buf[1] = (data_type >> 8) & 0xFF;
  buf[2] = (data_type >> 16) & 0xFF; buf[3] = (data_type >> 24) & 0xFF;
  buf[4] = size_val & 0xFF; buf[5] = (size_val >> 8) & 0xFF;
  buf[6] = (size_val >> 16) & 0xFF; buf[7] = (size_val >> 24) & 0xFF;
  if (data_len > 0) memcpy (buf + 8, data, data_len);
  *out_len = total;
  return buf;
}

/* Parse MCU message envelope */
static gboolean
parse_mcu_msg (const guint8 *payload, gsize plen, guint32 expected_type,
               const guint8 **out_data, gsize *out_len)
{
  if (plen < 8) return FALSE;
  guint32 msg_type = payload[0] | ((guint32)payload[1]<<8) |
                     ((guint32)payload[2]<<16) | ((guint32)payload[3]<<24);
  if (msg_type != expected_type) {
    fp_warn ("MCU msg type mismatch: 0x%x != 0x%x", msg_type, expected_type);
    return FALSE;
  }
  *out_data = payload + 8;
  *out_len = plen - 8;
  return TRUE;
}

/* PSK check: read PSK hash via production_read(0xB003) */
void
goodix5335_psk_check (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  fp_dbg ("Goodix 5335: PSK check");
  guint8 payload[4] = { 0x03, 0xB0, 0x00, 0x00 };
  goodix_run_cmd2 (ssm, FP_DEVICE (dev),
                   GOODIX5335_CAT_PROD, GOODIX5335_CMD_PROD_READ,
                   payload, sizeof (payload), TRUE);
}

/* PSK write: write white-box PSK if hash doesn't match */
void
goodix5335_psk_write (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  /* Check PSK hash from last received data */
  FpDevice *device = FP_DEVICE (dev);

  /* Compute expected hash of all-zero PSK */
  guint8 expected_hash[32];
  gsize hash_len = 32;
  g_autoptr(GChecksum) sha = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (sha, GOODIX5335_PSK, 32);
  g_checksum_get_digest (sha, expected_hash, &hash_len);

  /* Parse the production_read reply stored in rx_buf */
  gboolean need_write = TRUE;
  /* rx_buf has framed message: cmd(1)+size(2)+payload... */
  /* payload starts at offset 3; prod_read payload: status(1)+type(4)+size(4)+hash(32) */
  if (dev->rx_len >= 3 + 1 + 4 + 4 + 32) {
    const guint8 *payload = dev->rx_buf + 3;
    if (payload[0] == 0) {  /* status OK */
      const guint8 *hash = payload + 1 + 4 + 4;  /* skip status+type+size */
      if (memcmp (hash, expected_hash, 32) == 0) {
        fp_dbg ("Goodix 5335: PSK hash matches, no write needed");
        need_write = FALSE;
      } else {
        fp_dbg ("Goodix 5335: PSK hash mismatch, will write");
      }
    }
  }

  if (!need_write) {
    fpi_ssm_next_state (ssm);
    (void) device;
    return;
  }

  fp_info ("Goodix 5335: writing PSK white-box");
  gsize wb_len = 4 + 4 + 96; /* type + size + whitebox */
  guint8 *wb_payload = g_malloc (wb_len);
  guint32 data_type = 0xB002;
  guint32 data_size = 96;
  wb_payload[0] = data_type & 0xFF; wb_payload[1] = (data_type>>8) & 0xFF;
  wb_payload[2] = (data_type>>16) & 0xFF; wb_payload[3] = (data_type>>24) & 0xFF;
  wb_payload[4] = data_size & 0xFF; wb_payload[5] = (data_size>>8) & 0xFF;
  wb_payload[6] = (data_size>>16) & 0xFF; wb_payload[7] = (data_size>>24) & 0xFF;
  memcpy (wb_payload + 8, GOODIX5335_PSK_WHITE_BOX, 96);

  goodix_run_cmd2 (ssm, FP_DEVICE (dev),
                   GOODIX5335_CAT_PROD, GOODIX5335_CMD_PROD_WRITE,
                   wb_payload, wb_len, TRUE);
  g_free (wb_payload);
}

/* GTLS client hello: send client_random */
void
goodix5335_gtls_client_hello (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  fp_dbg ("Goodix 5335: GTLS client hello");
  goodix5335_gtls_init (&dev->gtls, GOODIX5335_PSK);
  RAND_bytes (dev->gtls.client_random, 32);

  gsize mcu_len;
  g_autofree guint8 *mcu_payload = build_mcu_msg (0xFF01, dev->gtls.client_random,
                                                   32, &mcu_len);
  goodix_run_cmd2 (ssm, FP_DEVICE (dev),
                   GOODIX5335_CAT_MCU2, GOODIX5335_CMD_MCU_MSG,
                   mcu_payload, mcu_len, FALSE);
}

static void
gtls_server_id_rx_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                      gpointer user_data, GError *error)
{
  FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (dev);
  if (error) { fpi_ssm_mark_failed (transfer->ssm, error); return; }

  if (transfer->actual_length > 0) {
    const guint8 *chunk = transfer->buffer;
    gsize chunk_len = transfer->actual_length;

    if (self->rx_len == 0) {
      /* First chunk: read size field to know total expected */
      if (chunk_len >= 3) {
        self->rx_cmd_byte = chunk[0];
        guint16 msg_size = chunk[1] | ((guint16) chunk[2] << 8);
        self->rx_expected = (gsize) msg_size + 3;
      }
      gsize copy = MIN (chunk_len, self->rx_expected > 0 ? self->rx_expected : chunk_len);
      memcpy (self->rx_buf, chunk, copy);
      self->rx_len = copy;
    } else {
      /* Continuation chunk: skip first byte */
      gsize copy = MIN (chunk_len - 1, self->rx_expected - self->rx_len);
      if (copy > 0 && chunk_len > 1) {
        memcpy (self->rx_buf + self->rx_len, chunk + 1, copy);
        self->rx_len += copy;
      }
    }

    if (self->rx_expected > 0 && self->rx_len >= self->rx_expected) {
      fp_dbg ("Goodix 5335: GTLS server identity received (%zu bytes total)", self->rx_len);
      fpi_ssm_next_state (transfer->ssm);
      return;
    }
  }

  /* Need more chunks */
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  t->ssm = transfer->ssm;
  fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
  fpi_usb_transfer_submit (t, 5000, NULL, gtls_server_id_rx_cb, NULL);
}

/* GTLS server identity: receive server_random + server_identity */
void
goodix5335_gtls_server_identity (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  fp_dbg ("Goodix 5335: GTLS waiting for server identity");
  dev->rx_len = 0;
  dev->rx_expected = 0;
  FpDevice *device = FP_DEVICE (dev);
  FpiUsbTransfer *t = fpi_usb_transfer_new (device);
  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
  fpi_usb_transfer_submit (t, 5000, NULL, gtls_server_id_rx_cb, NULL);
}

/* GTLS send verify: parse server identity, derive keys, send client identity */
void
goodix5335_gtls_send_verify (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  fp_dbg ("Goodix 5335: GTLS send verify");

  /* Parse the server reply from rx */
  const guint8 *buf = dev->rx_buf;
  gsize buf_len = dev->rx_len;

  /* Skip cmd byte and size field to get payload */
  if (buf_len < 4) {
    fpi_ssm_mark_failed (ssm,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                "GTLS server reply too short"));
    return;
  }
  guint16 msg_size = buf[1] | ((guint16)buf[2] << 8);
  const guint8 *payload = buf + 3;
  gsize plen = (gsize)msg_size - 1; /* minus checksum */

  const guint8 *mcu_data;
  gsize mcu_len;
  if (!parse_mcu_msg (payload, plen, 0xFF02, &mcu_data, &mcu_len) ||
      mcu_len != 64) {
    fpi_ssm_mark_failed (ssm,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                "GTLS server identity parse failed"));
    return;
  }

  memcpy (dev->gtls.server_random, mcu_data, 32);
  memcpy (dev->gtls.server_identity, mcu_data + 32, 32);

  goodix5335_gtls_derive_keys (&dev->gtls);

  if (!goodix5335_gtls_verify_identity (&dev->gtls)) {
    fpi_ssm_mark_failed (ssm,
      fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                "GTLS identity verification failed"));
    return;
  }

  /* Build verify payload: client_identity + 0xEEEEEEEE */
  guint8 verify_data[36];
  memcpy (verify_data, dev->gtls.client_identity, 32);
  memset (verify_data + 32, 0xEE, 4);

  gsize mcu_payload_len;
  g_autofree guint8 *mcu_payload = build_mcu_msg (0xFF03, verify_data, 36,
                                                   &mcu_payload_len);
  goodix_run_cmd2 (ssm, FP_DEVICE (dev),
                   GOODIX5335_CAT_MCU2, GOODIX5335_CMD_MCU_MSG,
                   mcu_payload, mcu_payload_len, FALSE);
}

/* GTLS done: receive handshake complete confirmation */
void
goodix5335_gtls_recv_done (FpiDeviceGoodix5335 *dev, FpiSsm *ssm)
{
  fp_dbg ("Goodix 5335: GTLS waiting for handshake done");
  FpDevice *device = FP_DEVICE (dev);
  FpiUsbTransfer *t = fpi_usb_transfer_new (device);
  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);

  /* Use a special callback that also marks GTLS as established */
  fpi_usb_transfer_submit (t, 5000, NULL, gtls_done_rx_cb, NULL);
}

static void
gtls_done_rx_cb (FpiUsbTransfer *transfer, FpDevice *device,
                  gpointer user_data, GError *error)
{
  FpiDeviceGoodix5335 *self = FPI_DEVICE_GOODIX5335 (device);

  if (error) { fpi_ssm_mark_failed (transfer->ssm, error); return; }
  if (transfer->actual_length == 0) {
    FpiUsbTransfer *t = fpi_usb_transfer_new (device);
    t->ssm = transfer->ssm;
    fpi_usb_transfer_fill_bulk (t, GOODIX5335_EP_IN, GOODIX5335_TRANSFER_LEN);
    fpi_usb_transfer_submit (t, 5000, NULL, gtls_done_rx_cb, NULL);
    return;
  }

  /* Parse and check result */
  const guint8 *buf = transfer->buffer;
  if (transfer->actual_length >= 4) {
    guint16 msg_size = buf[1] | ((guint16)buf[2] << 8);
    const guint8 *payload = buf + 3;
    gsize plen = (gsize)msg_size - 1;
    const guint8 *mcu_data;
    gsize mcu_len;
    if (parse_mcu_msg (payload, plen, 0xFF04, &mcu_data, &mcu_len) &&
        mcu_len >= 4) {
      guint32 result = mcu_data[0] | ((guint32)mcu_data[1]<<8) |
                       ((guint32)mcu_data[2]<<16) | ((guint32)mcu_data[3]<<24);
      if (result != 0) {
        fpi_ssm_mark_failed (transfer->ssm,
          fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                    "GTLS handshake failed: %u", result));
        return;
      }
    }
  }

  self->gtls.established = TRUE;
  fp_info ("Goodix 5335: GTLS handshake complete!");
  fpi_ssm_next_state (transfer->ssm);
}
