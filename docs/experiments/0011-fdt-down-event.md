# Experiment 0011 plan: wait for one finger-down (FDT down) event

Status: **done.** Run 1 timed out and left the reader armed; the amendment
below was reviewed, then run 1b and run 2 passed. Results:
[`0011-fdt-down-event-result.md`](0011-fdt-down-event-result.md).

## Why

Experiment 0010 showed that a manual FDT reading (`3.3`) reports touch
(`0000` without a finger, `01ed` with one) without the Windows config
upload. The next step is the command the Windows driver actually uses to
wait for a finger: `3.1` McuSwitchToFdtDown (`0x32`). It is acknowledged at
once, and the reader sends a reply later, **without being asked**, when a
finger lands. That is the first unrequested frame this tool would accept.

## Prior work

- tlambertz `capture.py` (55a2): `waitForFinger()` sends `0x32` with the
  fixed 22-byte payload `0c0180b980b480b580af80b480ac80b280a780ab80a5`
  (op `0x0c`, `01`, then ten 16-bit per-zone thresholds), after `3.3`.
- Windows log `logs/3_wbdi_singleunlock.log`:
  - line 169–215: "switch to fdt down", `0x32`, `outDataSize: 0x16`,
    `recvBufSize: 0x0`; only the ACK comes back at once.
  - line 357–374: ~14.6 s later, an unrequested frame `0xa0`, cmd `0x32`,
    `len: 25` (24-byte body + checksum), parsed as `interrupt: 0x2`,
    `fdt touch flag: 0x3ff`, then a 20-byte "fdt up base". The driver logs
    "no pending cmd, ignore" at the transport layer and handles it as an
    event.
  - `logs/1_wbdi_enroll.log`: the same event with partial flags
    (`0xfc`, `0x3f8`, `0x3f0`), so a partial touch can trigger it.
- goodix-fp-dump `wrapless.py`: `execute_fdt_operation(DOWN)` returns after
  the ACK; `wait_for_fdt_event()` later reads a category-3/command-1 reply
  with IRQ status (LE16), touch flag (LE16) and base values.

## Approach

New flag `--fdt-down`. It requires `--query-state` and `--fdt-manual`, and
is not allowed with `--query-state-pre-tls`. Frames sent:

`0.0`, `A.4`, `D.0`, TLS-PSK handshake, `D.2`, `A.7 55`, `3.3` (0010's fixed
payload), `A.7 55`, **`3.1` (fixed payload above)**, one wait, then
**`6.0` McuSwitchToSleepMode `01 00`** (amended, see below) and release.

- The USB boundary allows exactly one `3.1` frame, byte-identical to the
  fixed one, only after it is armed, and only after the `3.3` exchange
  completed. Other `0x32` payloads, and `0x34` (FDT up), stay refused.
- After the `3.1` ACK, the tool prints one line to **stderr**:
  `armed: touch the sensor now (waiting 15 s)`. That is the only non-JSON
  output.
- **Wait window: 15 s** after the ACK. The overall USB deadline goes from
  45 s to 70 s in this mode only; the read timeout is capped at the time
  left in the window.
- Outcomes:
  - **Event:** a plaintext `0xa0` frame, command `0x32`, body exactly
    24 bytes. Reported: `fdt_down_event: true`, `fdt_down_wait_ms`
    (rounded to 100 ms), `fdt_down_irq_status`, `fdt_down_touch_flag`
    (hex), `fdt_down_touch_zones`, `fdt_down_base_length`. The base is
    recorded by length only, as in 0010.
  - **Clean timeout** (no bytes at all within 15 s): `fdt_down_event:
    false`, stage `complete`. This is a result, not an error.
  - **Anything else** (another flag or command, wrong length, partial
    frame): stop with a fixed label.
- No `A.7` after `3.1`: while armed, a touch could send an event in the
  middle of an A.7 exchange. The run ends with the `6.0` below.
- Not sent: `3.2` FDT up, `9.0` config, idle, reset, image request,
  key or firmware commands.

## Payload choice (known risk)

The `3.1` thresholds are from Lambertz's reader, not ours; the Windows log
from another unit shows slightly different values (`80 B9 80 B3 …`). Our
own base values from 0010 were deliberately not recorded. So the fixed
thresholds may be too sensitive (event with no finger) or not sensitive
enough (no event with a finger). Either is a finding. Deriving thresholds
from our reader's manual base is a separate step that needs the base
values, and so a separate data-handling decision.

## Runs

Same command both times, from an interactive root terminal on Fedora:

    sudo python3 -I -B /home/jon/goodix-handshake-pilot/goodix_handshake.py --run --query-state --fdt-manual --fdt-down

1. **No touch:** keep hands off the sensor for the whole run. Expect a
   clean timeout.
2. **Touch:** start with no finger on the sensor. When the stderr line
   appears, wait about 3 s, then put one finger flat on the sensor and keep
   it there until the JSON line appears.

## How to read the result

- **Run 1 timeout, run 2 event with non-zero touch flag:** FDT down works
  with the borrowed thresholds; the tool can wait for a finger. Next step:
  a plan for one image request.
- **Event in run 1:** thresholds too sensitive (or the `3.3` finger-off
  state already counts as touch). Note `fdt_down_wait_ms`.
- **Timeout in both:** thresholds not sensitive enough, or `3.1` needs
  config/sleep first. Do not add those without a new plan.
- **Stop label:** record it. No retries.

## Risk

`3.1` leaves the MCU armed after the run. A later touch may queue an
unrequested frame that nothing reads.

## Amendment after run 1 (2026-09-25)

Run 1 ended in a clean timeout (`fdt_down_event: false`), as expected. It
also showed the risk above is real and **a warm Fedora reboot does not clear
it**: the reader was never re-enumerated, and every later run, including
plain `--run`, stopped at `unexpected_firmware` (`A.4` ACKed, next frame not
the firmware reply). Booting Windows and unlocking once with a fingerprint
recovered it; `--run` then passed.

Changes, all tested against the synthetic reader and USB fakes:

- **Disarm:** after every outcome of `3.1` (event, timeout, invalid or
  partial reply, operator interrupt), one fixed `6.0`
  McuSwitchToSleepMode (`01 00`, goodix-fp-dump `mcu_switch_to_sleep_mode`;
  the Windows unlock trace also ends with `6.0`). The USB boundary allows it
  once, only after `3.1`. Its ACK is required (`sleep_ack`); on an error
  path the original label is kept and `sleep_ack` shows whether disarm
  worked. A finger-down
  event that races the timeout and arrives before the ACK is counted
  (`fdt_down_late_events`), not decoded. Whether `6.0` really clears the
  armed state on this reader is unverified; run 1b below checks it.
- **Stale check:** every run (all modes) first listens for 0.5 s before
  sending anything. Any frame there stops the run with `stale_reader_frame`
  and only its flag, command and length (`stale_frame_*`).
- **Firmware diagnosis:** `unexpected_firmware` now records the reply's
  flag, command and length (`firmware_reply_*`), never its contents.

**Run 1b (before run 2):** repeat the no-touch run, then immediately run
plain `--run`. Pass: `sleep_ack: true`, then `--run` completes with no
`stale_reader_frame`. If `--run` fails, stop; recover via Windows unlock.

## Stop conditions

Same as 0010, plus any reply after `3.1` outside the rules above. Run 2
happens only if run 1 completed.

## Recovery and follow-up

If the reader misbehaves, boot Windows and unlock once (a warm reboot is
not enough). After both runs, reboot into Windows and
check fingerprint unlock. (Skipped by operator decision; see the result.) Record results in `0011-fdt-down-event-result.md`.
