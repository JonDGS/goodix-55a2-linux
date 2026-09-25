# Experiment 0012 result: one finger-up (FDT up) event

Status: **run; finger-up event received.** After the `0x32` finger-down
event, one `3.2` was ACKed and the reader sent an unrequested `0x34` frame
1.9 s after the lift prompt, when the finger lifted. When the finger was held
past the 15 s window, the wait timed out cleanly. `6.0` disarmed the reader
on both paths; a plain `--run` passed after each.

Plan: [`0012-fdt-up-event.md`](0012-fdt-up-event.md).

## Setup

- Hardware, host and key: same as experiments 0005–0011. **No key was
  written to the reader.**
- Tool: `tools/goodix_handshake.py` from commit `5dc40a0` (independently
  reviewed: PASS; `60c20fb` only reworded the plan). The operator ran it as
  root from an interactive terminal:
  `goodix_handshake.py --run --query-state --fdt-manual --fdt-down --fdt-up`,
  then plain `--run`.

## What the tool sent

`0.0`, `A.4`, `D.0`, the TLS-PSK handshake, `D.2`, `A.7 55`, `3.3`, `A.7 55`,
`3.1` (fixed payload), one wait of up to 15 s, then (after the down event)
`3.2` (fixed payload, second Windows `3.2`), one wait of up to 15 s, then
`6.0` `01 00`. No `9.0`, reset, image request, key or firmware command.

## Runs

| Field | Run 1, touch, hold, lift | Run 2, touch, hold (no lift) |
|---|---|---|
| `fdt_down_event` | true | true |
| `fdt_down_wait_ms` | 1000 | 1500 |
| `fdt_down_irq_status` / touch flag / zones | `0002` / `03ff` / 10 | `0002` / `03ff` / 10 |
| `fdt_up_ack` | true | true |
| `fdt_up_event` | true | false (timeout) |
| `fdt_up_reply_flag` / `cmd` / `length` | `a0` / `34` / 24 | – |
| `fdt_up_wait_ms` | 1900 | – |
| `fdt_up_irq_status` | `0200` | – |
| `fdt_up_touch_flag` / zones | `0000` / 0 | – |
| `fdt_up_base_length` | 20 | – |
| `sleep_ack` (`6.0`) | true | true |
| late events | absent | absent |
| Next plain `--run` | complete | complete |

In both runs the `3.3` reply was `0180`/`0000`/0 zones and `A.7` stayed
`01 00` before and after `3.3`. TLS fields as in 0010.

## Findings

1. **FDT up works with the borrowed Windows `3.2` thresholds.** They did not
   fire while the finger was down and did fire on lift.
2. **IRQ status separates the events:** down `0x0002` (now seen in three
   runs), up `0x0200`, `3.3` manual reply `0x0180`.
3. **`6.0` also disarms an armed `3.2`**, as in the Windows unlock log.
4. The full touch cycle (arm → down → arm up → up → disarm) now runs
   without an image request.

## Not established

- Repeatability of the up event: one event run.
- Whether the `3.2` thresholds suit this reader beyond these two runs;
  base values were not recorded.
- Image capture needs a separate plan, code, review and approval.
