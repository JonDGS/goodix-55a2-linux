# Experiment 0016a result: first libfprint driver for the 55a2

Status: **partial.** Capture works end to end through libfprint. Matching
does not work yet with either libfprint matcher.

Driver code: [JonDGS/libfprint](https://github.com/JonDGS/libfprint)
- `goodixtls-v1.94.100` (`3e1e34fa`): goodix-fp-linux-dev port onto
  libfprint v1.94.100 (the version Fedora 44 ships).
- `goodix55a2` (`c30f6ccf`): the `goodix55a2` driver with the NBIS
  (minutiae) matcher.
- `goodix55a2-sigfm` (`67818714`): the same driver with sigfm, from libfprint
  MR !530, ported onto v1.94.100.

All runs used the Windows-provisioned PSK from `/root/goodix-psk` (0016a
development mode). No PSK, firmware or config write was sent.

## Driver

A standalone `drivers/goodix55a2/goodix55a2.c`, not built on the fork's
shared `goodix5xx` scan sequence, which sends MCU config, nav and FDT
calibration commands never verified on this reader. The driver sends only
the command frames already used by `tools/goodix_handshake.py`, byte for
byte, from a fixed allow-list:

1. Activate: stale-frame listen, NOP, firmware check, TLS-PSK handshake
   (OpenSSL memory BIOs), A.7, one 2.0 image with no finger (calibration).
2. Scan: A.7, 3.3, A.7, 3.1 (arm), wait for the down event, 2.0, 3.2, wait
   for the up event, 6.0 (disarm).
3. Every arm is paired with one 6.0 on every exit path.

Image: nofinger − finger (0015), 1–99 percentile stretch to 8 bits, Lambertz
orientation (176×56), `COLORS_INVERTED`. The 808 always-zero pixels are set
to the median.

Two independent read-only reviews: driver PASS (12 nits, 11 fixed; blocking
USB I/O on the main loop deferred), sigfm port PASS (7 nits, ownership,
probe type check and doctest handling fixed).

## Hardware results

| Run | Result |
|---|---|
| Capture (`img-capture`) | OK. Down event → image 42 ms → up event → 6.0 ACK. Python `--run` afterwards: clean handshake, no `sleep_ack`/`stale_reader_frame`. |
| Image | Operator: ridges and finger clear after switching to Lambertz orientation and neutralising dead pixels. |
| NBIS enroll, native 176×56 | 10/10 presses accepted, but **1–3 minutiae** per press. Verify: no match, every attempt. |
| NBIS enroll, 3× bilinear upscale | **1–7 minutiae** per press. Verify: no match, every attempt. |
| sigfm enroll, native | 15/15 presses accepted, 140–241 SIFT keypoints each. Verify: **score 0/24 against all 15**, every attempt. |

## Offline sigfm analysis (stored enrollment, no reader commands)

Every enrolled press was scored against every other press (same finger, 210
ordered pairs):

| Measure | sigfm as merged | with ordering fix |
|---|---|---|
| Pairs with score > 0 | 22 | 33 |
| Pairs with score ≥ 24 | 10 | not recounted |
| Presses matching at least one other press | 7 of 15 | not recounted |

Ordering fix: `match::operator<` in `sigfm.cpp` is not a strict weak
ordering (its second clause can never be true), so `std::set` merges distinct
matches that only differ in x. This is an upstream sigfm bug worth
reporting, but fixing it does not change the outcome.

## Interpretation

Keypoint count is not the limit. Different presses of the same finger mostly
yield keypoints that do not correspond. Likely causes, most likely first:

1. The per-image percentile stretch and background subtraction give
   different contrast between presses, and residual background texture
   becomes keypoints.
2. Placement: 176×56 covers a small area, so presses overlap little.
3. The image is too small for an off-the-shelf matcher. The Windows driver
   likely uses a matcher tuned to this sensor.

## Tooling lessons

- Example programs read stdin. Any pipe around `sudo ./enroll` makes sudo
  run the program in a background process group, and the first read stops
  it. The run scripts write stdout straight to the terminal and redirect
  stderr to a file.
- Fedora's `doctest-devel` has no pkg-config file. The sigfm meson now falls
  back to the header, and `sigfm-tests` is not built by default.
- libfprint v1.94.100 fails to configure with `-Dintrospection=false`
  (upstream bug); keep introspection on.

## Next

Experiment 0017 (proposed, not approved): capture a raw image set (the same
finger many times plus a second finger) with the existing Python tool, then
compare preprocessing variants offline by the same-finger vs other-finger
score gap. Separately, 0016b (PSK write) remains unplanned.
