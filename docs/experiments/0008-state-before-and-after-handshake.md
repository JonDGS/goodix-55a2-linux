# Experiment 0008 plan: A.7 state before and after the handshake

Status: **run; no difference.** See
[`0008-state-before-and-after-handshake-result.md`](0008-state-before-and-after-handshake-result.md).

## Why

Experiment 0007 recorded the `A.7` reply `01 00` after the TLS handshake.
Two published layouts read the MCU flags from different bytes, and the
expected sign (`tls_connected` true after the handshake) appeared in neither.
A second sample, taken while the reader is in a different state, can show
which byte changes and which flag follows the TLS session.

## Approach

Send the same fixed `A.7` frame (`a00500a5ae020055a5`) twice in one run:

1. **Before TLS:** after `A.4` (firmware query), before `D.0`.
2. **After TLS:** after `D.2` is acknowledged, as in 0006 and 0007.

This adds no new command type. The only change is a second copy of a
read-only command that the reader has already accepted twice.

**Risk, stated plainly:** there is no evidence yet that `A.7` is valid
before TLS. goodix-fp-dump (for example `driver_51x7.py`, around lines 151
and 188) only sends `A.7 55` after `tls_successfully_established()`, once
straight after the handshake and once after an image. Experiment 0004 did
not capture early driver initialisation, so there is no Windows evidence
either way. The worst expected outcome is a missing ACK or an error reply.
That is a stop condition, and a reboot recovers the volatile session.

Each reply is decoded with `decode_state` only if the body is exactly 2
bytes, under the same rules as 0007. The results are stored under separate
keys: `state_pre_*` for the pre-TLS reply, and the unchanged 0007 `state_*`
keys for the post-TLS reply.

## How to read the result

- One byte differs between the two samples, and the change is bit `0x02`:
  that byte holds the flags, and `tls_connected` tracks the host session.
- One byte differs, but in another bit: that byte probably holds the flags,
  but the flag names need revising.
- The two samples are identical: the handshake does not change this state.
  A different contrast will be needed (for example a Windows capture, or a
  sample after an image request in a later experiment).

## Run

Once, as root, from an interactive terminal on Fedora:

    sudo python3 -I -B tools/goodix_handshake.py --run --query-state --query-state-pre-tls

`--query-state-pre-tls` is refused unless `--query-state` is also given. Only
this combination lets the USB boundary send `A.7` twice.

## Stop conditions

Same as 0006. In addition, stop if the reader does not acknowledge the
pre-TLS `A.7` or answers it with anything other than a plaintext `0xa0`/`0xae`
reply. In that case the handshake is not attempted. No retries.

## Recovery and follow-up

Same as 0006: if the reader misbehaves, reboot or boot into Windows. Then
verify Windows Hello fingerprint unlock.

## Implementation plan (after this plan is approved)

1. Tests first: exactly two `A.7` frames, in the approved positions; any
   other extra frame is rejected; separate pre and post report keys; the
   16-byte synthetic secret still never appears in the report.
2. Put the second query behind a new explicit flag
   (`--query-state-pre-tls`). Existing behaviour stays unchanged.
3. Independent review, then one operator run, then write up the result in
   `0008-state-before-and-after-handshake-result.md`.
