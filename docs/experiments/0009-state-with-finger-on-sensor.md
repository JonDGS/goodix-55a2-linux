# Experiment 0009 plan: A.7 state with a finger on the sensor

Status: **run; no change.** See
[`0009-state-with-finger-on-sensor-result.md`](0009-state-with-finger-on-sensor-result.md).

## Why

In experiments 0007 and 0008 the 2-byte `A.7` reply was `01 00` before and
after the TLS handshake. With only one value seen, it is still unknown which
byte carries the flags and what bit `0x01` means. A second sample taken with
a finger resting on the sensor may produce a different value. A Windows USB
capture is ruled out.

## Approach

No code change. The tool, test suite and frames are the same as in 0008
(SHA-256 `0e8f0cf2…`, reviewed in PR #10).

Run it once in the same mode as 0008. The operator places one finger flat on
the sensor **before** pressing Enter and keeps it there until the JSON line
appears. That gives two samples with the finger on (before and after TLS).
The finger-off baseline is the 0008 run.

Frames sent, unchanged from 0008: `0.0`, `A.4`, `A.7 55`, `D.0`, TLS-PSK
handshake, `D.2`, `A.7 55`. No image request, no finger-detection (FDT)
command, no key, firmware or reset command.

## Data handling

The reply is 2 bytes of MCU status. It cannot hold an image, template or
key. No image data is requested. Any reply that is not exactly 2 bytes is
recorded by shape only (existing rule). The finger used is not recorded.

## How to read the result

- **The reply changes** (for example a bit set in one byte only): that byte
  carries at least one finger-related flag. Record which bit, and compare it
  with the names used in prior work.
- **The reply stays `01 00`:** this is likely. In goodix-fp-dump, finger
  detection on similar readers only happens after the host sends the
  FDT-mode commands (`0x32`/`0x34`/`0x36`), which this tool never sends. So
  an unchanged value means only that a resting finger is not reported
  without FDT mode. It does not show that the state word ignores touch.
- **The run stops with an unexpected frame:** the reader may have sent an
  unrequested message because of the touch. This is a stop condition, not a
  failure of the reader. Record the label and do not retry with the finger
  on until a new plan is approved.

## Run

Once, as root, from an interactive terminal on Fedora, finger already on the
sensor:

    sudo python3 -I -B /home/jon/goodix-handshake-pilot/goodix_handshake.py --run --query-state --query-state-pre-tls

## Stop conditions

Same as 0008. No retries.

## Recovery and follow-up

Same as 0008: if the reader misbehaves, reboot or boot into Windows. Then
verify Windows Hello fingerprint unlock and record the result in
`0009-state-with-finger-on-sensor-result.md`.

## Next step if unchanged

A later plan could put the reader in FDT mode first. That is a new command
family with unknown side effects, so it needs its own plan, code, review
and approval.
