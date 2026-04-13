/*
 * Goodix 5335 libfprint driver
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "drivers_api.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

#define GOODIX5335_VID           0x27c6
#define GOODIX5335_PID           0x5335

#define GOODIX5335_EP_IN         0x81
#define GOODIX5335_EP_OUT        0x03
#define GOODIX5335_USB_INTERFACE 1
#define GOODIX5335_TRANSFER_LEN  64

#define GOODIX5335_IMG_WIDTH     80
#define GOODIX5335_IMG_HEIGHT    88
#define GOODIX5335_IMG_SIZE      (GOODIX5335_IMG_WIDTH * GOODIX5335_IMG_HEIGHT)

#define GOODIX5335_ENROLL_SAMPLES 8

/* PSK (all-zero for unconfigured sensors) */
#define GOODIX5335_PSK_LEN        32
#define GOODIX5335_SESSION_KEY_LEN 0x44

/* Protocol categories and commands */
#define GOODIX5335_CAT_MCU    0xA
#define GOODIX5335_CAT_CONFIG 0x9
#define GOODIX5335_CAT_FDT    0x3
#define GOODIX5335_CAT_IMAGE  0x2
#define GOODIX5335_CAT_MCU2   0xD  /* GTLS handshake */
#define GOODIX5335_CAT_PROD   0xE  /* PSK read/write */

#define GOODIX5335_CMD_FW_VERSION 0x4
#define GOODIX5335_CMD_OTP        0x3
#define GOODIX5335_CMD_CONFIG     0x0
#define GOODIX5335_CMD_FDT_DOWN   0x1
#define GOODIX5335_CMD_FDT_UP     0x2
#define GOODIX5335_CMD_IMAGE      0x0
#define GOODIX5335_CMD_MCU_MSG    0x1  /* GTLS MCU message */
#define GOODIX5335_CMD_PROD_READ  0x2
#define GOODIX5335_CMD_PROD_WRITE 0x1

/* GTLS context */
typedef struct {
  guint8   psk[GOODIX5335_PSK_LEN];
  guint8   client_random[32];
  guint8   server_random[32];
  guint8   client_identity[32];
  guint8   server_identity[32];
  guint8   symmetric_key[16];
  guint8   symmetric_iv[16];
  guint8   hmac_key[32];
  guint32  hmac_server_counter;
  gboolean established;
} Goodix5335GtlsCtx;

/* Open SSM states */
typedef enum {
  OPEN_STATE_PING = 0,
  OPEN_STATE_FW_VERSION,
  OPEN_STATE_OTP,
  OPEN_STATE_UPLOAD_CONFIG,
  OPEN_STATE_PSK_CHECK,           /* read PSK hash */
  OPEN_STATE_PSK_WRITE,           /* write PSK whitebox if needed */
  OPEN_STATE_GTLS_CLIENT_HELLO,   /* send client random */
  OPEN_STATE_GTLS_SERVER_IDENTITY,/* recv server random+identity */
  OPEN_STATE_GTLS_VERIFY,         /* send client identity */
  OPEN_STATE_GTLS_DONE,           /* recv handshake complete */
  OPEN_STATE_NUM_STATES,
} Goodix5335OpenState;

/* Enroll SSM states */
typedef enum {
  ENROLL_STATE_WAIT_FINGER_DOWN = 0,
  ENROLL_STATE_CAPTURE,
  ENROLL_STATE_PROCESS,
  ENROLL_STATE_WAIT_FINGER_UP,
  ENROLL_STATE_NEXT_SAMPLE,
  ENROLL_STATE_DONE,
  ENROLL_STATE_NUM_STATES,
} Goodix5335EnrollState;

typedef enum {
  FDT_STATE_NONE = 0,
  FDT_STATE_DOWN,
  FDT_STATE_UP,
} Goodix5335FdtStatus;

struct _FpiDeviceGoodix5335 {
  FpDevice parent;

  /* State */
  Goodix5335FdtStatus  fdt_state;
  guint                enroll_stage;
  guint8               image_buf[GOODIX5335_IMG_SIZE * 6 / 4];  /* 12-bit packed raw: 6 bytes per 4 pixels */
  GPtrArray           *enroll_samples;

  /* GTLS */
  Goodix5335GtlsCtx    gtls;

  /* Received data buffer for multi-chunk messages */
  guint8              *rx_buf;
  gsize                rx_len;
  gsize                rx_expected;
  guint8               rx_cmd_byte;

  /* Cancellable for FDT finger wait */
  GCancellable        *cancellable;
};

#define FPI_TYPE_DEVICE_GOODIX5335 (fpi_device_goodix5335_get_type ())
G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5335, fpi_device_goodix5335,
                      FPI, DEVICE_GOODIX5335, FpDevice)
#define FPI_DEVICE_GOODIX5335(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj), FPI_TYPE_DEVICE_GOODIX5335, FpiDeviceGoodix5335))

/* Proto (goodix5335-proto.c) */
GBytes  *goodix5335_encode_msg  (guint8 category, guint8 command,
                                  const guint8 *payload, gsize payload_len);
gboolean goodix5335_decode_msg  (const guint8 *buf, gsize buflen,
                                  guint8 *cat_out, guint8 *cmd_out,
                                  const guint8 **payload_out, gsize *plen_out);

/* Crypto (goodix5335-crypto.c) */
void     goodix5335_gtls_init            (Goodix5335GtlsCtx *ctx, const guint8 *psk);
gboolean goodix5335_gtls_derive_keys     (Goodix5335GtlsCtx *ctx);
gboolean goodix5335_gtls_verify_identity (Goodix5335GtlsCtx *ctx);
guint8  *goodix5335_gtls_decrypt_image   (Goodix5335GtlsCtx *ctx,
                                          const guint8 *encrypted,
                                          gsize encrypted_len,
                                          gsize *out_len);
void     goodix5335_hmac_sha256          (const guint8 *key, gsize key_len,
                                          const guint8 *data, gsize data_len,
                                          guint8 *out);

/* Device helpers (goodix5335-device.c) */

void goodix5335_do_ping          (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_get_fw_version   (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_read_otp         (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_upload_config    (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_wait_finger_down (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_wait_finger_up   (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_capture_image    (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_process_image    (FpiDeviceGoodix5335 *dev, guint8 *img_out);

/* GTLS handshake helpers (goodix5335-device.c) */
void goodix5335_psk_check        (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_psk_write        (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_gtls_client_hello   (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_gtls_server_identity(FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_gtls_send_verify    (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
void goodix5335_gtls_recv_done      (FpiDeviceGoodix5335 *dev, FpiSsm *ssm);
