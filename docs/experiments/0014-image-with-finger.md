# Experiment 0014 plan: one image with a finger, saved on the laptop

Status: **approved (defaults; images beside the tool), implemented, reviewed (PASS), awaiting run.**

## Why

Experiment 0013 showed that one `2.0` McuGetImage returns a TLS reply that
decrypts to 14,788 bytes, but nothing was decoded, so it's still unknown
whether the image is usable. This experiment takes one image with a finger
on the sensor, plus a no-finger baseline for comparison. For the first time
the pixels are **kept, on the laptop only**, so the operator can look at them.

## Prior work

- Windows log `logs/2_wbdi_singleunlock.log` (tlambertz/goodix-fingerprint-
  reversing, sha256 `e7510a57…`): the driver arms `3.1` FDT down
  (`outDataSize: 0x16`). In `HandleFdtDown` it sends `2.0` (`outDataSize: 0x2`)
  straight after the down event, logs `Image_isTouchedByFinger: finger`, then
  sends `3.3` to re-read the base. So on Windows the image is requested
  **after the `0x32` down event**, with no `6.0` or `3.2` in between.
- tlambertz `capture.py` @0479ce9:
  - `unpack_data_to_16bit` (line 140–153) unpacks 12-bit pixels, 6 bytes to
    4 values: `o1 = (b0&0xf)<<8 | b1`, `o2 = b3<<4 | b0>>4`,
    `o3 = (b5&0xf)<<8 | b2`, `o4 = b4<<4 | b5>>4`.
  - `getImage()` strips the last 4 bytes (a checksum per its variable name,
    `chksum`) before unpacking.
  - `save_pgm` (line 171–186) writes an ASCII PGM with width
    `SENSOR_HEIGHT` (176), height `SENSOR_WIDTH` (56), maxval 4095, values in
    received order. `readInLoop` shows the display as `reshape(176, 56).T`
    flipped up-down; orientation is cosmetic.
- 14,784 / 6 × 4 = 9,856 = 56 × 176 pixels, consistent with 0013's length.

## Approach

Two new flags on the existing tool. The USB traffic reuses the reviewed 0011
and 0013 building blocks; the new part is the local file handling.

- `--image --save-image` (0013 plus saving): **no-finger baseline.** Same
  frames as 0013.
- `--fdt-manual --fdt-down --image-on-touch --save-image`: 0011 up to the
  `0x32` down event, then **one `2.0`** while the finger rests, then the
  usual single `6.0` disarm on every path. On a `3.1` timeout no image is
  requested. `3.2` isn't sent (`--image-on-touch` excludes `--fdt-up`).
- USB boundary: `2.0` still allowed only once and only with the fixed
  payload. In touch mode it's allowed only after the `3.1` send and before
  `6.0`; the tool sends it only after a valid down event.
- Without `--save-image`, both modes behave like 0013 (shape only).

## Pixel data handling

Jon approved keeping pixel data on the laptop, in a plain folder next to the
tool rather than under `/root` (simpler; he accepts that the folder has no
special permissions). Rules:

1. **Location:** `images/` beside `goodix_handshake.py`, created on first
   use. Because the tool runs under `sudo`, new files and the folder are
   handed to the invoking user (`SUDO_UID`/`SUDO_GID`) so they open in a
   normal image viewer without sudo.
2. **Files**, never overwritten (`O_EXCL`), named
   `YYYYmmdd-HHMMSS-<nofinger|finger>`:
   - `.raw`: the 14,788 decrypted bytes exactly as received, trailer included;
   - `.pgm`: a binary 16-bit PGM (`P5`, maxval 4095, 176 × 56 in received
     order, like Lambertz), openable in any image viewer.
3. **Report (the JSON that comes back to Alfred):** shape fields as in
   0013, plus the file basename, `pixel_count`, and 12-bit `min`, `max`,
   `mean`, `stddev`. **No pixel values, rows, hashes or trailer bytes.**
4. **Nothing leaves the laptop** by the tool or by Alfred: no Nextcloud,
   Hermes or Git (`images/` is outside the repo on the laptop; the repo's
   ignore rules also cover `images/`). Alfred never reads the files.
5. **Deletion:** the tool never deletes; Jon removes the folder when done.
6. If writing fails, the run stops with a fixed label and a partial file is
   removed; nothing is retried.

## Decisions for Jon

1. **Summary numbers in the JSON** (min/max/mean/stddev): default yes.
   Without them, comparing the two images means you describe what you see.
2. **When in the touch cycle:** default image right after the down event, as
   Windows does. The alternative (manual `3.3` with finger, then `2.0`)
   departs from the Windows sequence.
3. **Still no `9.0` chip config.** If the finger image looks like noise,
   the config upload is the next plan.

## Runs

1. No finger: `--run --query-state --image --save-image`. Pass:
   `image_plain_len: 14788`, `image_saved: true`.
2. Plain `--run`.
3. Finger: `--run --query-state --fdt-manual --fdt-down --image-on-touch
   --save-image`; touch at the prompt, keep the finger still until the tool
   exits. Pass: `fdt_down_event: true`, `image_saved: true`,
   `sleep_ack: true`.
4. Plain `--run`.
5. Jon opens both `.pgm` files locally and reports only what he sees
   (e.g. "ridges visible", "noise", "blank").

## Stop conditions

Same as 0011–0013: any failed `sleep_ack`, `stale_reader_frame` or
`unexpected_firmware` stops the series; recover with one Windows
fingerprint unlock. No automatic retries.

## Not established by this run

A visible ridge pattern shows the sensor and decoding work. It doesn't show
the image is good enough for matching, and says nothing about enrollment,
matching or authentication.
