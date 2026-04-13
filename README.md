# libfprint driver for Goodix 27c6:5335 fingerprint sensor

A Linux fingerprint driver for the Goodix 27c6:5335 sensor, as found in the
Dell XPS 13 9305. Written for the [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) / [fprintd](https://gitlab.freedesktop.org/libfprint/fprintd) ecosystem.

## Authorship

This driver was written by [Claude](https://claude.ai) (Anthropic's AI assistant)
and tested on real hardware by a human contributor. Portions of the crypto and
image processing code are adapted from the
[goodix53x5 driver](https://gitlab.freedesktop.org/libfprint/libfprint/-/tree/master/libfprint/drivers/goodix)
by the goodix-fp-linux-dev contributors, which is also LGPL-2.1 licensed.

Specific adaptations from goodix53x5:

- GTLS handshake protocol structure and key derivation logic
- 12-bit packed image decode algorithm (`goodix_device_decode_image`)
- Sensor configuration and OTP calibration approach
- PSK white-box constants for the all-zero PSK

## Supported hardware

| Vendor | Product ID | Device |
|--------|-----------|--------|
| Goodix | 27c6:5335 | Dell XPS 13 9305 |

## Status

- ✅ GTLS crypto handshake (AES-128-CBC, HMAC-SHA256, TLS-PRF)
- ✅ Encrypted image capture and decryption
- ✅ 12-bit image decode + Gaussian highpass filter
- ✅ Enrollment (8 samples)
- ✅ Verification via SIGFM keypoint matching
- ✅ PAM integration (sudo, su, screen lock)
- ⚠️ ~30-40% false reject rate on bad placements (retry usually succeeds)
- ⚠️ Adjacent finger rejection not perfect at this sensor resolution (80×88px)
- ❌ `identify` not yet implemented (stub returns no-match)

## Requirements

- libfprint (with SIGFM support — present in recent versions)
- fprintd
- OpenSSL >= 3.0 (for AES-128-CBC image decryption; same dependency as `uru4000`)

## Installation

This driver is integrated into the libfprint source tree. To build:

```bash
cd /path/to/libfprint/builddir
ninja && sudo ninja install
```

## Known issues / TODO

- `identify` action is stubbed out — wiring GTLS image capture into the
  identify path is pending
- Upstream submission to libfprint in progress

## Related

- [goodix53x5 driver](https://gitlab.freedesktop.org/libfprint/libfprint/-/tree/master/libfprint/drivers/goodix) — similar hardware, upstream driver that this work is based on
- [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) — the fingerprint library this driver targets
