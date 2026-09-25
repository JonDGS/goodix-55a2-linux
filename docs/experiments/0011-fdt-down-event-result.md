# Experiment 0011 result: one finger-down (FDT down) event

Status: **run; finger-down event received.** After `3.1` the reader sent an
unrequested `0x32` frame 1.3 s after arming, when the finger landed, with all
10 touch zones set. The added `6.0` sleep disarmed the reader after both the
timeout and the event; a plain `--run` passed afterwards each time.

Plan: [`0011-fdt-down-event.md`](0011-fdt-down-event.md).

## Setup

- Hardware, host and key: same as experiments 0005–0010. **No key was
  written to the reader.**
- Tool: `tools/goodix_handshake.py`. Run 1 used commit `60ef321`, which had
  no disarm. Runs 1b and 2 used the reviewed amendment, commit `fd8f90e`
  (SHA-256 `e163f976…`). The operator ran it as root from an interactive
  terminal: `goodix_handshake.py --run --query-state --fdt-manual --fdt-down`,
  then plain `--run`.

## What the tool sent

`0.0`, `A.4`, `D.0`, the TLS-PSK handshake, `D.2`, `A.7 55`, `3.3`, `A.7 55`,
`3.1` (fixed payload), one wait of up to 15 s, then (from the amendment
onward) `6.0` `01 00`. No `3.2`, `9.0`, reset, image request, key or
firmware command.

## Runs

| Field | Run 1, no touch (`60ef321`) | Run 1b, no touch | Run 2, touch after prompt |
|---|---|---|---|
| `fdt_down_ack` | true | true | true |
| `fdt_down_event` | false (timeout) | false (timeout) | true |
| `fdt_down_reply_flag` / `cmd` / `length` | – | – | `a0` / `32` / 24 |
| `fdt_down_wait_ms` | – | – | 1300 |
| `fdt_down_irq_status` | – | – | `0002` |
| `fdt_down_touch_flag` / zones | – | – | `03ff` / 10 |
| `fdt_down_base_length` | – | – | 20 |
| `sleep_ack` (`6.0`) | not sent | true | true |
| `fdt_down_late_events` | – | absent | absent |
| Next plain `--run` | failed `unexpected_firmware` | complete | complete |

In all runs the `3.3` reply was `0180`/`0000`/0 zones (no finger yet), and
`A.7` stayed `01 00` before and after `3.3`. TLS fields as in 0010.

## Findings

1. **FDT down works without the Windows config (`9.0`).** The reader
   ACKed `3.1` and later sent a `0x32` event with a 24-byte body. The report
   printed the moment the finger touched, so the reader pushes the event; the
   host does not poll for it.
2. The event's touch flag `03ff` (all 10 zones) matches the Windows unlock
   log. The IRQ status `0002` differs from the `3.3` reply (`0180`/`0100`);
   it may be the finger-down interrupt bit, but that rests on one sample.
3. **An armed `3.1` survives a warm reboot.** After run 1 every later run
   failed at `unexpected_firmware` until a Windows fingerprint unlock.
4. **`6.0` McuSwitchToSleepMode (`01 00`) disarms it.** After both a timeout
   (1b) and an event (2) it was ACKed and the next `--run` passed, with no
   stale frame.

## Follow-up check

The plan called for a Windows Hello check after both runs. **The operator
decided to skip it**, because the stale-frame check and the clean `--run`
after runs 1b and 2 show directly that the reader was not left armed. If the
reader starts refusing again, a Windows fingerprint unlock remains the only
known recovery.

## Not established

- Whether the result is repeatable: one event run.
- What IRQ status bits `0x0002` and `0x0080` mean.
- Whether the `3.1` thresholds (Lambertz's reader) suit this reader;
  base values were not recorded.
- FDT up (`3.2`), the finger-lift event, needs a separate plan, code,
  review and approval.
