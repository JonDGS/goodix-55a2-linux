# Experiment 0013 result: one image request with no finger on the sensor

Status: **run; image reply received and decrypted.** One `2.0` McuGetImage
(`01 00`) was ACKed without a chip-config upload. The reader answered with
one TLS-protected `0xb2` frame that decrypted to exactly 14,788 bytes, the
size the Windows driver log reports. A plain `--run` passed right after.

Plan: [`0013-image-request-no-finger.md`](0013-image-request-no-finger.md).

## Setup

- Hardware, host and key: same as experiments 0005–0012. **No key was
  written to the reader.**
- Tool: `tools/goodix_handshake.py` from commit `ff925f7` (independently
  reviewed: PASS; the review's minor points were fixed before deployment).
  The operator ran it as root from an interactive terminal, no finger on the
  sensor: `goodix_handshake.py --run --query-state --image`, then plain
  `--run`.

## What the tool sent

`0.0`, `A.4`, `D.0`, the TLS-PSK handshake, `D.2`, `A.7 55`, then `2.0`
`01 00`. No `9.0` chip config, FDT, `6.0`, reset, key or firmware command.

## Runs

| Field | Run 1, `--image` | Run 2, plain `--run` |
|---|---|---|
| `stage` | complete | complete |
| `tls_verified` / cipher | true / `PSK-AES128-CBC-SHA256` | true / same |
| `state_reply_hex` (A.7) | `0100` | – |
| `image_ack` | true | – |
| `image_frame_flag` | `b2` | – |
| `image_frame_len` (USB body) | 14,862 | – |
| `image_prefix_len` | 9 | – |
| `image_record_len` (TLS record) | 14,853 | – |
| `image_decrypted` | true | – |
| `image_plain_len` | 14,788 | – |
| `image_len_expected` | true | – |
| `usb_released` | true | true |

Image data was decrypted in memory, measured and zeroed. No pixel values or
statistics were recorded.

## Findings

1. **The image path works end to end from Linux**, with the
   Windows-provisioned PSK and without the chip-config (`9.0`) upload that
   Lambertz's capture script sends.
2. **Frame layout matches the Windows log byte for byte:** 14,862-byte
   `0xb2` body = 9-byte prefix + one 14,853-byte TLS record (5-byte header
   + 14,848), decrypting to 14,788 bytes. That fits 56 × 176 12-bit pixels
   (14,784) plus a 4-byte trailer.
3. **The 64-byte discrepancy is resolved:** the project's USBPcap 14,866-byte IN
   transfers are this 14,862-byte body plus the 4-byte frame header.
   Lambertz's 14,930 includes his capture's framing, not a larger image.
4. **No `6.0` was needed afterwards:** the next run's stale check saw no
   unasked frame and the plain run completed.

## Follow-up check

Windows Hello: _Result: TODO (operator to confirm)._

## Not established

- Whether the pixels are usable: nothing was decoded or inspected, and no
  finger was on the sensor. Without `9.0` the sensor may be uncalibrated.
- Image capture with a finger, repeatability, frame rate.
- Anything about matching or authentication.
