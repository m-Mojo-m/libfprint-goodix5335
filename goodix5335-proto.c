/*
 * Goodix 5335 libfprint driver - Protocol layer
 *
 * Message format (from goodix-fp-linux-dev/goodix-fp-dump/wrapless.py):
 *
 *   Byte 0:    command_byte = (category << 4) | (command << 1)
 *   Bytes 1-2: payload_len + 1 (little-endian u16)
 *   Bytes 3-N: payload
 *   Byte N+1:  checksum = (0xAA - sum(bytes 0..N)) & 0xFF
 *
 * All transfers padded to multiples of 64 bytes.
 * Every sent command gets an ACK (category=0xB, command=0) before the reply.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "goodix5335.h"
#include <string.h>

#define USB_CHUNK_SIZE  64

GBytes *
goodix5335_encode_msg (guint8        category,
                       guint8        command,
                       const guint8 *payload,
                       gsize         payload_len)
{
    guint8 command_byte = (category << 4) | (command << 1);
    gsize msg_len = 1 + 2 + payload_len + 1;
    guint8 csum = 0xAA;
    gsize i;

    /* Build the raw message first */
    guint8 *raw = g_malloc0 (msg_len);
    raw[0] = command_byte;
    raw[1] = (guint8) ((payload_len + 1) & 0xFF);
    raw[2] = (guint8) (((payload_len + 1) >> 8) & 0xFF);
    if (payload && payload_len > 0)
        memcpy (raw + 3, payload, payload_len);
    for (i = 0; i < msg_len - 1; i++)
        csum = (csum - raw[i]) & 0xFF;
    raw[msg_len - 1] = csum;

    /*
     * Chunk the message into 64-byte USB packets.
     * First chunk: raw[0..63]
     * Continuation chunks: (command_byte | 1) + raw[64*(n-1)+1 .. 64*n]
     * Each chunk is exactly 64 bytes (zero-padded).
     */
    gsize n_chunks = (msg_len + USB_CHUNK_SIZE - 1) / USB_CHUNK_SIZE;
    gsize total = n_chunks * USB_CHUNK_SIZE;
    guint8 *buf = g_malloc0 (total);

    /* First chunk */
    gsize first_len = MIN (msg_len, (gsize) USB_CHUNK_SIZE);
    memcpy (buf, raw, first_len);

    /* Continuation chunks */
    gsize raw_pos = USB_CHUNK_SIZE; /* position in raw where we left off */
    gsize buf_pos = USB_CHUNK_SIZE;
    while (raw_pos < msg_len) {
        buf[buf_pos] = command_byte | 1; /* continuation marker */
        gsize copy_len = MIN (msg_len - raw_pos, (gsize)(USB_CHUNK_SIZE - 1));
        memcpy (buf + buf_pos + 1, raw + raw_pos, copy_len);
        raw_pos += copy_len;
        buf_pos += USB_CHUNK_SIZE;
    }

    g_free (raw);
    return g_bytes_new_take (buf, total);
}

gboolean
goodix5335_decode_msg (const guint8  *buf,
                       gsize          buflen,
                       guint8        *category_out,
                       guint8        *command_out,
                       const guint8 **payload_out,
                       gsize         *payload_len_out)
{
    guint8 command_byte;
    gsize payload_len;

    if (buflen < 4)
        return FALSE;

    command_byte = buf[0];
    payload_len  = (gsize) buf[1] | ((gsize) buf[2] << 8);
    if (payload_len == 0)
        return FALSE;
    payload_len -= 1;

    if (buflen < 3 + payload_len + 1)
        return FALSE;

    if (category_out)    *category_out    = command_byte >> 4;
    if (command_out)     *command_out     = (command_byte & 0x0F) >> 1;
    if (payload_out)     *payload_out     = buf + 3;
    if (payload_len_out) *payload_len_out = payload_len;

    return TRUE;
}





