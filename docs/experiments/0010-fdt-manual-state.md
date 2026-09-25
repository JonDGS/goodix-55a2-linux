# Experiment 0010 plan: one manual finger-detection (FDT) reading

Status: **done.** Result:
[`0010-fdt-manual-state-result.md`](0010-fdt-manual-state-result.md).

## Why

Across experiments 0007–0009 the `A.7` state word was always `01 00`: before
and after TLS, with and without a finger resting on the sensor. Prior work
suggests the reader only reports touch after the host switches it into a
finger-detection (FDT) mode. This experiment tests that with the smallest
FDT command that replies straight away.

## Prior work

- tlambertz/goodix-fingerprint-reversing (`capture.py`, 55a2-specific) sends
  `3.3` McuSwitchToFdtMode (`0x36`) with a fixed 22-byte payload
  `0d0180a08093809b80948090808f8094808b808a8083`, after reset, config upload
  (`9.0`), `C.2` and `D.1`.
- The same author's Windows driver logs (`logs/3_wbdi_singleunlock.log`,
  `logs/5_tls_init.log`) show `0x36` in "manual" mode replying at once with
  25 bytes (24 plus checksum), parsed as `interrupt: 0x100`, a touch flag and
  a 20-byte "fdt manual base". The touch flag was `0x0` at driver start
  (no finger) and `0x3ff` during an unlock (finger present).
- goodix-fp-dump (`wrapless.py`) parses FDT replies the same way: IRQ status
  (LE16), touch flag (LE16), then base values.

`3.1` (FDT down, `0x32`) is **not** used: it waits for a finger and replies
later without being asked, which the tool's strict request/reply model does
not handle.

## Approach

New flag `--fdt-manual`, only together with `--query-state`, and not with
`--query-state-pre-tls`. Frames sent:

`0.0`, `A.4`, `D.0`, TLS-PSK handshake, `D.2`, `A.7 55`, **`3.3` (fixed
payload above)**, `A.7 55`.

- The USB boundary allows exactly one `3.3` frame, byte-identical to the
  fixed one, and only after it is armed in this mode. Any other `0x36`
  payload, and `0x32`/`0x34`, stay refused.
- The `3.3` reply must be a plaintext `0xa0` frame, command `0x36`, body of
  exactly 24 bytes. Anything else stops the run before the second `A.7`.
- Reported: `fdt_ack`, `fdt_reply_flag`, `fdt_reply_cmd`, `fdt_reply_length`,
  `fdt_irq_status` and `fdt_touch_flag` (hex), `fdt_touch_zones` (number of
  set bits in the low 10 bits of the touch flag) and `fdt_base_length`. The
  second `A.7` reply uses `state_fdt_*` keys.
- Not sent: `9.0` config upload, reset, `D.1`, `C.2`, image request, key,
  firmware or sleep/idle commands.

## Data handling

The 20-byte FDT base is per-zone sensor readings, not an image. It is
probably not identifying, but that is not established, so it is **recorded
by length only** and never printed. The touch flag is 10 bits of coarse
per-zone touch state. The finger used is not recorded.

## Runs

Two runs, same tool, from an interactive root terminal on Fedora:

1. **Finger off:** nothing on the sensor.
2. **Finger on:** one finger flat on the sensor before pressing Enter, kept
   there until the JSON line appears.

    sudo python3 -I -B /home/jon/goodix-handshake-pilot/goodix_handshake.py --run --query-state --fdt-manual

## How to read the result

- **Touch flag `0000` off and non-zero on:** manual FDT works without a
  config upload. Compare the second `A.7` word with `01 00`.
- **Touch flag the same in both runs:** the reader may need the `9.0` config
  (not sent) before FDT is meaningful. Do not add `9.0` without a new plan.
- **ACK missing, wrong length or unexpected frame:** stop condition. Record
  the label. No retries.
- **The second `A.7` word changes after `3.3`:** the reader is in a
  different mode; note which byte and bit changed.

## Risk

`3.3` changes the MCU's detection mode. Its effect without the Windows
config is unknown. Mode is volatile; a reboot recovers it. Do not run
Windows Hello between the two Linux runs.

## Stop conditions

Same as 0006, plus any `3.3` reply outside the rules above. The second run
happens only if the first completed.

## Recovery and follow-up

If the reader misbehaves, reboot or boot into Windows. After both runs, boot
Windows and check fingerprint unlock. Record the results in
`0010-fdt-manual-state-result.md`.
