# Experiment 0012 plan: wait for one finger-up (FDT up) event

Status: **approved by the operator; implemented, awaiting independent
review and the two runs.**

## Why

Experiment 0011 showed the reader pushes an unrequested `0x32` finger-down
event after `3.1`, and that `6.0` disarms it. The Windows and goodix-fp-dump
flows use `3.2` McuSwitchToFdtUp (`0x34`) next, to learn when the finger
lifts before re-arming for the next touch. This is the last FDT primitive
before an image request.

## Prior work

- goodix-fp-dump `wrapless.py`: `execute_fdt_operation(UP)` sends category
  3 / command 2 (`0x34`) with op code `0x0e`, `01`, then a 22-byte base
  (24 total, same size as DOWN); only the ACK comes back at once.
  `wait_for_fdt_event(UP)` later reads a 3/2 reply: IRQ status (LE16),
  touch flag (LE16), base values.
- goodix-fp-dump `goodix.py`: `COMMAND_MCU_SWITCH_TO_FDT_UP = 0x34`;
  `mcu_switch_to_fdt_up()` reads the ACK, then blocks for one `0x34` reply.
- goodix-fp-dump `driver_5503.py`: after an image, `3.3`, prints "remove
  your finger", `3.2` twice (`0e01 8b00 8400 8c00 8800 8095 8089 8099 808a
  808d 808d`, then a second set), then `3.1`. The 5503 payload has a
  different layout (4 fixed words + 6 thresholds) from Lambertz's 55a2
  `3.1` (10 thresholds), so it cannot be reused directly.
- Experiment 0003: the Windows successful capture ends `… 3.3 → 3.2`, then
  `A.7`, `6.0`; the failure path has an extra `3.2`.
- Windows log `logs/3_wbdi_singleunlock.log` (tlambertz/goodix-fingerprint-
  reversing, SHA-256 `2eff3655…`), same 55a2 reader family:
  - line 657–666: after the image, "switch to fdt up", `0x34`,
    `outDataSize: 0x16` (22 = `0e 01` + 20 threshold bytes), ACK only.
    Thresholds `80a3 8097 80a0 8097 8095 8093 8097 8094 808f 808e`.
  - line 682–727: the driver updates the up base and sends `3.2` again
    (ACK line 764) with `80a0 8093 809b 8094 8090 808f 8094 808b 808a 8083`.
  - line 873–908: no up event arrives before the unlock ends; the driver
    sends `6.0` (`outDataSize: 0x2`) with `3.2` still armed and gets its
    ACK. So `6.0` after an armed `3.2` is exactly the Windows sequence.
  - Layout matches Lambertz's 55a2 `3.1` (`0c 01` + ten `80xx` words).

## Approach

`--run --query-state --fdt-manual --fdt-down --fdt-up` (`--fdt-up` needs
`--fdt-down`): run 0011 unchanged up to the `0x32` event.
Only if the event arrived (`fdt_down_event: true`), send **one fixed `3.2`**
while the finger is still down, wait up to 15 s for one unrequested `0x34`
frame with a 24-byte body, summarise it like the `0x32` event, then the same
single `6.0` disarm on every path. On a `3.1` timeout, skip `3.2` and disarm
as in 0011.

- USB boundary: `3.2` allowed once, only after `3.1` and before `6.0`, only
  with the fixed payload; `6.0` still once, now also after `3.2`. The tool
  sends `3.2` only after a valid `0x32` event (checked in `fdt_down_wait`).
- Operator: touch at the prompt, keep the finger down until the second
  prompt ("lift now"), then lift.
- Not sent: `9.0`, reset, idle, image request, key, firmware, second `3.1`.

## Payload choice (decision needed)

**Chosen: the second (updated) Windows `3.2`**, the one the driver leaves
armed, as one fixed 22-byte payload:
`0e01 80a0 8093 809b 8094 8090 808f 8094 808b 808a 8083`.
It was recorded on another 55a2 with its own calibration, as was the `3.1`
payload that worked in 0011. Known risk: if the thresholds do not suit this
reader, the up event may fire at once or never; both are results, and the
`6.0` disarm covers both. Rejected: reusing the `3.1` thresholds (they are
down thresholds) and deriving from base bytes (would record base values).

## Runs

1. Touch, hold, lift at prompt. Pass: `fdt_down_event: true`,
   `fdt_up_ack: true`, `fdt_up_event: true`, `sleep_ack: true`, then a
   clean plain `--run`.
2. Touch, hold past the 15 s up window (do not lift). Pass: clean
   `fdt_up_event: false` timeout, `sleep_ack: true`, clean `--run`.

## Stop conditions

Same as 0011. Any failed `sleep_ack` or later `stale_reader_frame` or
`unexpected_firmware`: stop and recover with a Windows fingerprint unlock.
