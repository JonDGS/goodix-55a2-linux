# Experiment 0006: one read-only command after the TLS handshake

Status: **approved plan; tool ready, not yet run on hardware.**

## Question

After the Linux handshake of experiment 0005, does the reader accept one
ordinary, read-only command? Does it answer in plaintext `0xa0` frames or
inside the TLS session (`0xb2` TLS data frames)?

## Why this command, and why not an image

Prior work (`goodix-fp-dump@cc43bb3`, `goodix.py`, `tool.py`,
`driver_55x4.py`) does not put commands inside TLS. The host sends every
command as a plaintext `0xa0` frame. After the handshake, only image data
comes back TLS-protected, in `0xb2` frames that the host decrypts. So "a
command inside the TLS session" really means: a plaintext command sent after
the handshake, while the TLS session is still held open in memory.

The chosen command is `A.7` QueryMcuState with the one-byte argument `0x55`,
as prior work uses it:

- The Windows driver sends `A.7` during every ordinary unlock (see the
  ledger), so the reader already handles it in normal use.
- Prior work treats it as a state read. It does not write to flash, change
  the key or firmware, reset the reader, or start a scan.
- Its reply is not biometric.

Rejected alternatives:

- `A.3` ReadOtp is read-only, but its reply is a per-device calibration and
  identity blob. It is more sensitive and is not needed yet.
- `2.0` McuGetImage returns fingerprint image material. It stays out of scope
  until the transport is understood and a separate plan covers handling
  biometric data.

## What the tool may send

Everything from experiment 0005, unchanged, plus exactly one extra frame:

1. `0.0` NOP, `A.4` FirmwareVersion, `D.0` RequestTlsConnection, the TLS-PSK
   handshake (host as server), and `D.2` TlsSuccessfullyEstablished. The same
   byte-for-byte checks apply.
2. `A.7` QueryMcuState with payload `55`, sent once, only after `D.2` has been
   acknowledged. Its full frame is a fixed constant, checked at the USB send
   boundary like the others.

After the handshake the tool never forwards further TLS output from its
in-memory session, such as a close_notify. A TLS alert in the reply stops the
run with the fixed label `tls_alert_in_state_reply`.

Still forbidden: `E.0`/`E.2` key commands, firmware, reset, sensor-register
writes, config upload, FDT mode switches, `2.0` McuGetImage, and outbound TLS
application data. The same 45 s deadline, transfer budget, and
claim-only-if-unbound rule apply.

## Expected outcome and what gets recorded

Expected, based on prior work: an ACK for `A.7`, then a plaintext `0xa0`
reply with command byte `0xae`.

The public report records only:

- whether the ACK arrived;
- the reply's frame flag (`0xa0`, `0xb0` or `0xb2`), command byte, and
  length. For `0xa0` this is the argument length without the command
  header and checksum byte; for `0xb2` it is the whole frame body;
- if the reply is `0xb2`, whether the in-memory TLS session decrypts it
  (true/false) and the plaintext length. It never records the plaintext.

Reply bytes are not printed, even for a plaintext reply. Decoding the state
fields is a later step, done after reviewing prior work, and only if the
fields turn out to be non-identifying.

## Stop conditions

Stop and release the USB interface on any of these: a missing or wrong ACK,
an unexpected frame flag or command byte, a TLS alert, a decryption failure,
the deadline, or the transfer budget. The tool never retries on its own. Each
attempt is one operator-run `--run`.

## Recovery and follow-up

The command writes nothing, so the only state it affects is the reader's
volatile session. After the run:

1. If the reader misbehaves, reboot Linux or boot into Windows. Both reset
   the session without unplugging anything.
2. Verify Windows Hello fingerprint unlock, as was done after 0005.

## Implementation plan (after this plan is approved)

1. Add unit tests first: the fixed `A.7` frame, rejection of any other extra
   command, report fields, and handling of an `0xa0` or `0xb2` reply using
   synthetic data.
2. Extend `tools/goodix_handshake.py` behind an explicit `--query-state`
   flag. The default behaviour stays identical to experiment 0005.
3. Get an independent review, then one operator run, and write up the result
   in `0006-post-handshake-state-query-result.md`.
