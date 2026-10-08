# Experiment 0017 plan: raw image set and offline preprocessing comparison

Status: **run; passed.** See [`0017-preprocessing-comparison-result.md`](0017-preprocessing-comparison-result.md).

## Why

0016a showed capture works, but sigfm scored 0/24 on live verify and only
10 of 210 same-finger pairs reached 24 offline. Keypoints are plentiful
(140–241), so they mostly don't correspond between presses. The leading
suspect is preprocessing (per-image percentile stretch, residual background
texture). This experiment measures that offline, without changing the
driver or sending any new USB command.

## Question

Which preprocessing gives the widest gap between same-finger and
other-finger sigfm scores on this sensor? And is any variant good enough
(same-finger scores well above every other-finger score) to put into the
driver, or is the sensor area itself the limit?

## Captures (hardware, unchanged reviewed tool)

Same commands as 0015, no tool change, no new USB commands:

- No finger: `--run --query-state --image --save-image`
- Finger: `--run --query-state --fdt-manual --fdt-down --image-on-touch --save-image`

Set:

- **Finger A** (the enrolled finger): 20 presses, varying placement slightly,
  as in normal use.
- **Finger B** (another finger): 10 presses.
- A fresh no-finger image before every 5 finger presses (0015 showed the
  baseline drifts ~4 counts over days; a fresh one every 5 presses keeps it
  current). 6–7 no-finger images in total.
- One plain `--run` at the end of the set, as the clean-state check. 0016a
  showed no stale state after captures, so the per-press `--run` from 0015 is
  dropped. If any run fails, the helper stops and the set is not resumed
  without a check.

A small helper `run-0017-capture.sh` (deployed by TARS, run once by Jon with
`sudo bash`) loops the runs, prompts "finger A / finger B / lift" between
presses, and writes a label file (`labels.txt`: filename → A/B/nofinger).
It calls only the tool above. About 40 tool runs, ~10–15 minutes. No pipes
around the tool (0016a SIGTTIN lesson).

Files land in a new folder `~/goodix-handshake-pilot/images-0017/`.

## Offline evaluation (no USB)

New C++ program `sigfm-eval` in the libfprint build tree on the laptop,
linked against the already built `libsigfm.a` (with the ordering fix from
0016a) and OpenCV 4.13 (installed). It does not link libfprint or libusb, so
it cannot open the reader.

- Input: `labels.txt` and the `.raw` files. Each finger image is paired
  with the newest preceding no-finger image.
- Variants (each applied to the whole set):
  1. **V0 baseline**: the 0016a driver pipeline (diff, 1–99 percentile
     stretch per image, dead px → median, Lambertz orientation).
  2. **V1 fixed stretch**: one global gain/offset for all images instead of
     per-image percentiles.
  3. **V2 CLAHE**: V0 then local contrast equalisation.
  4. **V3 band-pass**: V0 then difference of Gaussians, to keep ridge
     frequency and drop smooth background.
  5. **V4 V3 + 2× upscale.**
  6. **V5 border/dead mask**: V3 with keypoints within a few px of the
     edges and the dead-pixel columns ignored.
  Parameters are fixed in the plan's result before scoring the set; no
  tuning on the same data beyond the listed variants.
- Scores: every press vs every other press, per variant (A–A genuine,
  A–B impostor).
- Output: per variant only summary numbers: genuine/impostor score
  min/median/max, share of genuine pairs ≥ 24, highest impostor score, and
  the best threshold that keeps impostors at zero with the genuine rate there.
  **No pixel values, images, keypoint coordinates or descriptors.**
  Optional `--dump-pgm` writes variant images beside the inputs (O_EXCL) so
  Jon can look at them; off by default.

Tests: synthetic images only (shift/rotate a synthetic ridge pattern; check
genuine > impostor on synthetic data, rejection of wrong file sizes, no
pixel data on stdout).

## Success criteria

- Measurement succeeds if all variants are scored on the full set.
- A variant is a **driver candidate** if its zero-impostor threshold still
  accepts ≥ 50% of genuine pairs. (A matcher that accepts half of single
  presses is usable with several enrolled presses; that's the next check.)
- If no variant gets there, the conclusion is that the 176×56 area limits
  sigfm, and the next step is multi-press enrollment / stitching or a
  different matcher, not more preprocessing.

## Data handling

As 0014/0015: images stay on the laptop in `images-0017/`, never on Hermes,
Nextcloud or Git. Raw images are biometric data. Jon deletes the folder
when done. Git gets only the plan, the code, synthetic tests and the
summary numbers.

## Risks and recovery

- Captures use the reviewed tool and command sequence from 0014/0015;
  every arm is paired with a 6.0 disarm. If the reader is left armed
  (0011 symptom: `unexpected_firmware`), the recovery is the known one:
  boot Windows, one fingerprint unlock, back to Fedora.
- The eval program is offline only.
- No PSK, firmware, config or enrollment change. fprintd stays stopped.

## Decisions for Jon

1. Approve the capture set (20 × A, 10 × B, no-finger every 5).
2. Who runs `sigfm-eval`: TARS over SSH (prints summary numbers only,
   never opens or copies images), or Jon runs it and pastes the summary.
3. Whether to keep the old 0014–0016 images in `images/` or delete them now.
