# Experiment 0016 plan: first libfprint driver for the 55a2

Status: **approved (2026-09-28); setup in progress.** Decisions: 0016a
file-based Windows key first, 0016b key write planned separately; code in a
JonDGS fork of goodix-fp-linux-dev/libfprint; time-boxed rebase onto
`v1.94.100`; operator installs build dependencies.

## Goal

Enroll and verify a finger with libfprint on the test laptop (Fedora 44),
using a driver built only there. The system `libfprint`/`fprintd` packages and
the Windows install stay untouched. The first milestone is the libfprint
`examples/` programs run from the build tree; `fprintd-enroll` follows once
those work.

## Prior work (checked 2026-09-28)

- **goodix-fp-linux-dev/libfprint** (LGPL-2.1), default branch `master`,
  last push 2023-07-23; not archived. Branches:
  - `goodixtls` (2023-07-23): `libfprint/drivers/goodixtls/` with a shared
    protocol layer (`goodix.c`, `goodix_proto.c`), an OpenSSL TLS-PSK server
    (`goodixtls.c`), a 5xx image-device base (`goodix5xx.c`: calibration
    image, linear subtraction, squash to 8-bit) and one device, `goodix511.c`
    (5110, 64 × 80, NBIS/bozorth3, `bz3_threshold` 24, 20 enroll stages).
    The README lists only 27c6:5110 as "in the works".
  - `sigfm` (2023-01-04): a SIFT-based matcher (`libfprint/sigfm/`,
    OpenCV ≥ 4.5) for small sensors where NBIS finds too few minutiae.
- **Upstream libfprint** (gitlab.freedesktop.org, latest tag `v1.94.100`,
  the same version Fedora 44 ships): **no Goodix TLS driver.** The sigfm
  matcher is proposed in MR !530 (a rebase of !418 from 2022), still open,
  last updated 2026-09-01. Upstream has not accepted it yet.
- **PSK handling in prior work.** `goodix5xx.c:153–197` reads the device PSK
  and **fails** unless it equals a PSK compiled into the driver (all zeros
  for 5110). The provisioning (write) happens outside libfprint, in
  goodix-fp-dump's `write_psk` (`driver_55x4.py:63`). For the 55a2
  specifically, tlambertz `capture.py:14–16, 206–228` writes a white-box
  blob (`PSK_WB`) for the all-zero PSK and checks `PMK_HASH 81b8ff49…`.
- **Windows behaviour** (tlambertz `logs/8_set_psk.log`, firmware 10056): on
  every driver load, if the sealed PSK on the sensor can't be unsealed,
  Windows generates and writes a new one. So Windows would re-key after
  Linux writes the zero PSK. **Not verified on this firmware (10063)**, and
  whether Windows Hello enrollments survive a re-key is unknown.

## Key decisions

### 1. Code base: the fork's `goodixtls` branch (Jon agreed)

Add `goodix55a2.c` beside `goodix511.c`, reusing the shared layer. Rebase onto
upstream `v1.94.100` first, so the built library matches Fedora's ABI and
fprintd can later load it. The rebase effort is unknown until tried; if it's
large, build the fork as-is for milestone 1 and rebase afterwards.

### 2. PSK: must work without Windows (Jon's requirement)

Without Windows there is no sealed key to reuse, so the driver has to
**provision a known PSK on the reader**, as all prior work does. This is the
first device write in the project and a large escalation:

- Writing the zero PSK **breaks Windows Hello** on this laptop until Windows
  re-keys. The log says it re-keys by itself, but that's unverified on this
  firmware, and existing Windows Hello enrollments may be lost.
- The existing Windows-reuse path (key file in `/root/goodix-psk/`) stays
  available as a development option, so the driver can be written and
  tested **before** any PSK write happens.

Proposed staging:

- **0016a (no write):** the driver reads the PSK from a root-only file
  (`GOODIX_55A2_PSK_FILE`, a build-time dev option only, never the default).
  All of the driver, enrollment and matching work happens here.
- **0016b (separate plan, separate approval):** a one-time provisioning of
  the zero PSK using the white-box blob that tlambertz wrote to the 55a2
  (firmware 10056). This needs a recovery rehearsal first:
  - PIN sign-in confirmed on Windows;
  - a check that Windows re-keys and Windows Hello works afterwards;
  - acceptance that the existing Windows enrollment may need redoing.

  The default driver then uses the zero PSK like the 5110 driver, and
  refuses to run (with a clear message) if the reader holds any other key.
  Provisioning stays a separate explicit tool, never automatic inside the
  driver.

### 3. Matcher: test first, then decide

176 × 56 is larger than the 5110 (64 × 80), but still small. Plan:

1. Build with NBIS (the upstream default) first and count minutiae on
   enrollment images. The count is logged by libfprint; no images leave the
   laptop.
2. If NBIS finds too few minutiae, or genuine matches score below
   `bz3_threshold`, switch to the fork's `sigfm` branch (OpenCV). The catch:
   sigfm isn't upstream yet (MR !530 is open), so a sigfm-based driver
   can't go upstream until that MR lands.

### 4. Image pipeline

The fork's `goodix5xx.c` already does what 0015 showed works: it captures a
calibration (no-finger) image at activation, subtracts it from each frame,
and squashes the result to 8 bits. The 55a2 driver supplies:

- the 12-bit unpacker;
- the size 176 × 56 (check which orientation libfprint expects);
- dropping the 4-byte trailer;
- the finger-down (`3.1`) → `2.0` → `6.0` sequence from 0014.

The 808 zero pixels will need masking if they hurt matching; they're left
as found for now.

## Build and test environment (Fedora laptop)

- Read-only check: the build tools aren't installed (`gcc`, `meson`,
  `ninja-build`, `*-devel` packages are all missing). The laptop has 8 cores,
  38 GB RAM and 417 GB free in `/home`.
- Jon runs once, with sudo: `sudo dnf builddep libfprint` plus
  `sudo dnf install gcc meson ninja-build openssl-devel` (plus `opencv-devel`
  if sigfm is needed). These install packages only; the system libfprint is
  unchanged.
- Build in `~/goodix-libfprint/` with meson `-Ddrivers=goodix55a2` (only
  this driver). The library is **not** installed system-wide. Test with
  `examples/img-capture`, `examples/enroll` and `examples/verify` from the
  build tree under `sudo`, with `LD_LIBRARY_PATH` set to the build dir.
- fprintd milestone (later): stop `fprintd`, run the system `fprintd` binary
  against the build-tree library via `LD_LIBRARY_PATH`, or install into
  `/usr/local` with a documented rollback. Decided at that milestone.
- Code lives in a new public repository or a branch of a fork on Jon's
  GitHub (decision below). No real images, keys or prints go into Git.

## Milestones and hardware runs (0016a)

1. **Build only.** No hardware.
2. **Activate:** handshake plus a calibration image, no finger. Pass:
   `img-capture` reports activation and captures one frame, the next plain
   `--run` of the Python tool completes (no stuck reader), and `sleep_ack` /
   `6.0` is sent on deactivation.
3. **Capture:** one finger image through `img-capture`, saved locally.
   Jon describes it, as in 0014.
4. **Enroll + verify:** `examples/enroll`, then `examples/verify` with the
   same finger (expect a match) and with another finger (expect no match).
   Report stage counts, match / no-match and scores only.

Every run keeps the 0011–0015 stop rules: a stuck reader means stop and
recover with a Windows fingerprint unlock (possible only while the Windows
key is still on the reader, i.e. before 0016b).

## Decisions for Jon

1. **PSK staging:** file-based dev key first (0016a), and the zero-PSK
   provisioning as its own plan later (0016b). Default: yes.
2. **Where the driver code lives:** a fork of `goodix-fp-linux-dev/libfprint`
   under JonDGS (keeps history and attribution, and makes upstreaming
   easier), or a `libfprint/` subtree in this repo. Default: fork.
3. **Rebase onto upstream `v1.94.100` before starting,** or build the fork
   as-is first. Default: try the rebase and time-box it; fall back to as-is.
4. **Build dependencies:** the operator runs the one `dnf` line above on
   the laptop. Default: yes.

## Not established by this plan

Whether the fork rebases cleanly, whether NBIS works at this size, whether
Windows re-keys safely on firmware 10063, or whether upstream would accept a
driver that writes a PSK.
