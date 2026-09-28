# Experiment 0015 result: background subtraction on fresh image pairs

Status: **run; passed.** Subtracting a fresh no-finger baseline removes the
fixed grey-block pattern and leaves clear ridges in all four image pairs.
No-finger baselines agree closely across runs and across days.

Plan: [`0015-background-subtraction.md`](0015-background-subtraction.md).

## Setup

- Hardware, host and key: same as experiments 0005–0014. **No key was
  written to the reader.**
- Hardware tool: `tools/goodix_handshake.py`, unchanged since experiment
  0014 (sha256 `c1594330…` on the laptop, equal to `main`).
- Offline script: `tools/goodix_image_diff.py` from commit `2d4ce99`
  (sha256 `f10ef3f8…` on the laptop, equal to the repository; independently
  reviewed: PASS, minor points fixed before deployment). It never opens the
  USB device.
- Images stay in `images/` beside the tool on the laptop. **They were not
  copied off the laptop** and are not in this repository. Only the
  statistics below were reported.

## What the hardware tool sent

Three fresh pairs, each: no-finger run (as 0014 run 1), finger run (as 0014
run 3), then a plain `--run`. No new command; no `9.0`, `3.2`, reset, key or
firmware command. The sanitized JSON of these nine runs was not collected
for this write-up; each run produced its saved image, and the series ended
with no stop condition reported by the operator.

## Differences (no-finger − finger, before stretch)

| Pair | Files (no finger / finger) | min | max | mean | stddev | zero pixels (nf / f) |
|---|---|---|---|---|---|---|
| 0014 | `20260925-220017` / `-220157` | 0 | 1,211 | 627.2 | 253.0 | 808 / 808 |
| 1 | `20260928-143133` / `-143219` | 0 | 1,272 | 742.0 | 293.0 | 808 / 808 |
| 2 | `20260928-144230` / `-144253` | 0 | 1,269 | 767.4 | 293.8 | 808 / 808 |
| 3 | `20260928-144722` / `-144733` | 0 | 1,255 | 721.6 | 304.3 | 808 / 808 |

## Baseline repeatability (`--pair-stats`, mean |a − b|, 12-bit scale)

| | 0014 (25 Sep) | pair 1 | pair 2 |
|---|---|---|---|
| pair 1 | 4.0 (sd 3.4) | | |
| pair 2 | 3.9 (sd 3.8) | 4.2 (sd 4.1) | |
| pair 3 | 10.5 (sd 11.9) | 11.7 (sd 12.3) | 9.9 (sd 11.5) |

## Operator observation

- 0014 pair diff: "grey blocks are gone and ridges are clear, definitely
  an improvement".
- Pairs 1–3, Lambertz orientation: "all look about the same, clear ridges
  that are on par with being a finger".

## Findings

1. **Baseline subtraction works.** Removing a no-finger image removes the
   fixed block pattern seen in 0014; ridges remain clear in every pair.
2. **The baseline is stable.** Three no-finger images taken over three days
   differ by about 4 counts on average (0.1 % of the 12-bit range). The
   pair 3 baseline differs by about 10–12, still under 2 % of the typical
   finger signal (mean difference 630–770). Likely causes (temperature,
   residue from the previous touch) are unconfirmed.
3. **Exactly 808 pixels read 0 in every image**, finger or not. They are a
   fixed property of the sensor or of the decoding, not noise. Their
   positions were not examined.
4. The finger signal (difference mean and max) is consistent across the
   three fresh pairs.

## Follow-up check

Windows Hello after this series: _Result: TODO (operator to confirm)._

## Not established

Image quality for matching, enrollment or authentication. The subtraction
is a project method, not the vendor's. The origin of the 808 zero pixels and
of the 4-byte trailer.
