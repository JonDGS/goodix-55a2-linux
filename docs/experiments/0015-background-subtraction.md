# Experiment 0015 plan: background subtraction on fresh image pairs

Status: **implemented; reviewed (PASS, nits fixed).** Approved by Jon with all defaults (3 pairs, `nofinger − finger` with 1–99 % stretch, zero-pixel counts only).

## Why

Experiment 0014 captured a finger image with a visible ridge pattern, but the
no-finger baseline shows grey blocks, so the finger image carries the same
fixed pattern underneath. Removing the baseline (no-finger − finger) should
leave mostly ridge information. Taking several fresh pairs also shows whether
the baseline is stable from run to run (repeatability).

## Prior work

- tlambertz `capture.py` @0479ce9, `readInLoop`: displays
  `flipud(reshape(176, 56).T)`, i.e. transposed and flipped up-down. It's
  cosmetic; the 0014 `.pgm` files keep the received order.
- The Windows log (`logs/2_wbdi_singleunlock.log`) sends `3.3` after the image
  to re-read the base. This suggests the driver keeps a baseline, but the
  log doesn't show how it's applied. **No prior-work source documents a
  subtraction formula**, so the method below is a project choice, not a copy.
- 0014 stats: no-finger mean 2383 sd 740, finger mean 1756 sd 570, min 0 in
  both. The source of the zero pixels is unknown (dead columns, clipping or
  a decoding edge).

## Approach

### Captures (hardware, unchanged reviewed tool)

No new USB commands and no tool change. Each pair is the two 0014 commands
run back to back, so the baseline is fresh:

1. No finger: `--run --query-state --image --save-image`
2. Finger: `--run --query-state --fdt-manual --fdt-down --image-on-touch --save-image`

Three pairs, with a plain `--run` after each finger run as in 0014. That's
9 runs in total. The tool names files by timestamp, so a pair is a
`nofinger` file and the next `finger` file.

### New offline script `tools/goodix_image_diff.py` (no USB)

- Standard library plus the reviewed 12-bit unpacker; imports nothing from the hardware tool except the
  image constants and the 12-bit unpacker, so it cannot open the device.
  It doesn't import `usb` at all; a test asserts this.
- Input: two `.raw` files (14,788 bytes each; anything else is refused).
  Unpacks with the reviewed `unpack_pixels` on the first 14,784 bytes.
- Output: `<finger-base>-diff.pgm` (or `-diff-lambertz.pgm`), written beside
  the finger file (normally `images/`) with
  `O_EXCL` (never overwrite), owned by the user (the script runs without
  sudo because the files are the user's).
- Difference: `d = nofinger − finger` per pixel. Ridges pressed on the
  sensor read lower than the background (0014 finger mean is lower), so this
  makes ridges bright. Then it's linearly rescaled from the 1st–99th
  percentile to 0–4095 so a few outliers don't wash out the image.
- `--orient lambertz` (default `raw`): writes the Lambertz display
  orientation. Implemented as an index map, tested on a synthetic image.
- `--pair-stats`, with two no-finger files: prints only the mean absolute
  difference and its stddev, to measure baseline repeatability.
- stdout prints one JSON line with coarse stats only: pixel count, min, max,
  mean, stddev of the difference, count of zero-valued input pixels per
  file, and the output basename. **No pixel values, rows, hashes or trailer
  bytes.** The 4-byte trailer is discarded and never reported, as in 0014.
- `argparse.ArgumentParser(allow_abbrev=False)`.

### Tests

Synthetic images only (no real biometric data in the repo): shape checks,
subtraction and rescale on a known pattern, orientation index map, refusal
of wrong lengths and of existing output, a planted marker proving no pixel
bytes reach stdout, and the no-`usb`-import check.

## Data handling

Same as 0014: files stay in `~/goodix-handshake-pilot/images/` on the
laptop, never on Hermes, Nextcloud or Git. Alfred deploys the script over
SSH, runs nothing that reads the images, and doesn't open them. Jon runs the
script himself and describes what he sees. Jon deletes the folder when done.

## Decisions for Jon

1. **Difference sign and scaling:** default is `nofinger − finger` with a
   1–99 % stretch. The alternative (plain difference plus a fixed offset)
   keeps absolute levels but will look flatter.
2. **Number of pairs:** default is 3 (9 runs). One pair gives no
   repeatability data; more than 3 adds runs for little extra.
3. **Finger placement:** same finger, placed as consistently as
   possible each time, so differences come from the sensor, not from placement.
4. **Zero pixels:** default is to report their count only and investigate
   later. The alternative is to report their positions (row/column indices,
   not values), which would show whether they're dead columns. Positions
   carry no fingerprint data, but they are a new kind of report field.

## Runs

1. Pair 1: no finger, finger (touch at the prompt, hold still until exit),
   plain `--run`.
2. Pairs 2 and 3: same.
3. Jon runs `python3 goodix_image_diff.py <nofinger.raw> <finger.raw>`
   (plus `--orient lambertz`) for each pair, and `--pair-stats` on the
   no-finger files. He pastes the JSON lines and describes the diff images
   (e.g. "clear ridges, fixed blocks gone").

Pass: every hardware run passes as in 0014 (`image_saved: true`,
`fdt_down_event: true`, `sleep_ack: true`), and each diff image is produced.
Whether the blocks disappear is the finding, not a pass condition.

## Stop conditions

Same as 0011–0014: any failed `sleep_ack`, `stale_reader_frame` or
`unexpected_firmware` stops the series; recover with one Windows fingerprint
unlock. No automatic retries.

## Not established by this run

A cleaner image says nothing about image quality for matching, enrollment or
authentication. The subtraction is a project method, not the vendor's.
