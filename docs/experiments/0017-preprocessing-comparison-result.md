# Experiment 0017 result: raw image set and offline preprocessing comparison

Status: **run; passed.** Plan: [`0017-preprocessing-comparison.md`](0017-preprocessing-comparison.md).

## Capture

`run-0017-capture.sh`, run once by Jon on 2026-10-08: 20 presses of finger A,
10 of finger B, 6 no-finger images, final plain `--run`. All 37 tool runs
reached `complete` with USB released. Images stay on the laptop in
`images-0017/` (mode 700). Independent review of the helper and evaluator:
PASS, nits only.

## Evaluation

`tools/sigfm_eval` (offline, OpenCV core/imgproc/features2d only, sigfm with
the 0016a ordering fix). Genuine = A–A ordered pairs (380), impostor = A–B
(400). Each press used the newest preceding no-finger image.

| Variant | Genuine ≥ 24 | Max impostor | Genuine at zero-impostor threshold |
|---|---|---|---|
| V0 driver pipeline | 54.2% | 0 | 58.9% (t=1) |
| V1 fixed stretch | 53.9% | 36 | 53.4% (t=37) |
| V2 CLAHE | 51.6% | 10 | 53.4% (t=11) |
| V3 band-pass (DoG 1/4) | 60.8% | 40 | 59.7% (t=41) |
| V4 band-pass, 2× | 61.8% | 21 | 62.1% (t=22) |
| V5 band-pass, border/dead mask | 60.5% | 0 | 63.9% (t=1) |

In every variant each A press matches at least one other A press above the
zero-impostor threshold. Some genuine scores reach millions (near-duplicate
consecutive presses); medians are the fairer guide.

### Stale baseline check

Re-scored with the set's first no-finger image for every press
(`--baseline first`, modelling the driver's single calibration at
activation): V0 53.9%, V5 60.5% at ≥ 24, V5 max impostor still 0. **A stale
baseline does not explain the 0016a failure.**

## Interpretation

- Every variant meets the plan's bar (≥ 50% genuine at zero impostors). V5
  is the best candidate.
- The same V0 pipeline that scored 10/210 pairs ≥ 24 in 0016a scores 54%
  here. The difference is not preprocessing and not baseline age. Open
  candidates: something in the driver's live path (image timing, libfprint
  image handling before sigfm extract, or stored-print round trip) or the
  0016a press set itself. Not yet tested.
- Limits: one session, one person, finger B only 10 presses.

## Next

0018: find why the driver's images match worse than the tool's, e.g. capture
a few presses through `img-capture` and score them against this set offline,
then add V5 to the driver and retest live.
