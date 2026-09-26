# Experiment 0014 result: one image with a finger, saved on the laptop

Status: **run; passed. Fingerprint image captured from Linux.** One `2.0`
McuGetImage sent right after a `0x32` finger-down event returned an image
that the operator describes as showing ridge lines and resembling a finger.
The no-finger baseline shows only uniform grey blocks. No chip-config
(`9.0`) upload was needed.

Plan: [`0014-image-with-finger.md`](0014-image-with-finger.md).

## Setup

- Hardware, host and key: same as experiments 0005–0013. **No key was
  written to the reader.**
- Tool: `tools/goodix_handshake.py` from commit `3733214` (independently
  reviewed: PASS; minor points fixed before deployment). Run as root from
  an interactive terminal in the order below.
- Images were saved as `.raw` and 16-bit `.pgm` in `images/` beside the
  tool on the laptop. **They were not copied off the laptop** and are not
  in this repository. Only the statistics below were reported.

## What the tool sent

- Run 1 (no finger): as 0013, `… D.2`, `A.7 55`, `2.0 01 00`.
- Run 3 (finger): as 0011, `… A.7 55`, `3.3`, `A.7 55`, `3.1`, wait, then
  after the down event `2.0 01 00`, then `6.0 01 00`.
- Runs 2 and 4: plain `--run`.
- No `9.0`, `3.2`, reset, key or firmware command.

## Runs

| Field | Run 1, no finger | Run 3, finger |
|---|---|---|
| `stage` | complete | complete |
| `fdt_down_event` / wait | – | true / 1,100 ms |
| `fdt_down_irq_status` / touch flag / zones | – | `0002` / `03ff` / 10 |
| `image_ack` / `image_decrypted` | true / true | true / true |
| `image_frame_len` / `image_record_len` / `image_plain_len` | 14,862 / 14,853 / 14,788 | same |
| `image_saved` | true | true |
| `image_pixel_count` | 9,856 | 9,856 |
| `image_min` / `image_max` | 0 / 3,035 | 0 / 2,504 |
| `image_mean` / `image_stddev` | 2,383.0 / 740.3 | 1,755.9 / 570.5 |
| `sleep_ack` (`6.0`) | – | true |
| Next plain `--run` | complete | complete |

`A.7` stayed `01 00` throughout.

## Operator observation

- No-finger image: "somewhat grey squares overall".
- Finger image: "lines that look like ridges"; "does seem to resemble an
  image of a finger".

## Findings

1. **The full Linux capture path works:** TLS-PSK with the Windows key,
   FDT down event, `2.0` image request, TLS decryption, 12-bit unpacking
   (tlambertz layout) and 176 × 56 display all produce a recognisable
   fingerprint image.
2. **No chip-config upload is needed** for a visible ridge pattern on this
   reader/firmware (GF3206_RTSEC_APP_10063).
3. The finger lowers the mean (~2,383 → ~1,756) and spread, consistent with
   skin contact across the sensor.
4. Both images contain at least one 0-valued pixel; the cause (edge, dead
   pixel or padding) is not established.
5. The grey blocks in the baseline suggest a per-region offset pattern that
   background subtraction or calibration would remove.

## Follow-up check

Windows Hello: _Result: TODO (operator to confirm)._

## Not established

- Image quality for matching: no enhancement, background subtraction or
  quality metric was applied.
- Orientation (flip/transpose) and the meaning of the 4-byte trailer.
- Repeatability: one finger image.
- Enrollment, matching or authentication.
