# Experiment 0010 result: one manual finger-detection (FDT) reading

Status: **run; touch detected.** With no config upload, the `3.3` manual FDT
reply had touch flag `0000` with no finger and `01ed` (7 of 10 zones) with a
finger on the sensor. The `A.7` state word stayed `01 00` throughout.

Plan: [`0010-fdt-manual-state.md`](0010-fdt-manual-state.md).

## Setup

- Hardware, host and key: same as experiments 0005–0009. **No key was
  written to the reader.**
- Tool: `tools/goodix_handshake.py` as of commit `3c7c20b` (SHA-256
  `08b9c3e2…`), reviewed independently before the runs. The operator ran it
  as root from an interactive terminal:
  `goodix_handshake.py --run --query-state --fdt-manual`.
- Run 1: nothing on the sensor. Run 2: one finger flat on the sensor before
  starting, kept there until the report appeared.

## What the tool sent

`0.0`, `A.4`, `D.0`, the TLS-PSK handshake, `D.2`, `A.7 55`, `3.3` (fixed
22-byte manual payload), `A.7 55`. No `9.0` config upload, reset, `D.1`,
`C.2`, image request, key, firmware or sleep/idle command.

## Runs

One attempt per condition; both completed on the first run. FDT-related and
state fields only (TLS fields: `TLSv1.2`, `PSK-AES128-CBC-SHA256`,
`tls_verified: true`, `device_confirmation_ack: true`, `usb_released: true`
in both).

| Field | Run 1, finger off | Run 2, finger on |
|---|---|---|
| `fdt_ack` | true | true |
| `fdt_reply_flag` / `cmd` / `length` | `a0` / `36` / 24 | `a0` / `36` / 24 |
| `fdt_irq_status` | `0180` | `0100` |
| `fdt_touch_flag` | `0000` | `01ed` |
| `fdt_touch_zones` | 0 | 7 |
| `fdt_base_length` | 20 | 20 |
| `state_reply_hex` (A.7 before `3.3`) | `0100` | `0100` |
| `state_fdt_reply_hex` (A.7 after `3.3`) | `0100` | `0100` |

No stop condition was hit. The 20 FDT base bytes were recorded by length
only, as planned.

## Findings

1. **Manual FDT works without the Windows config (`9.0`).** The reader
   accepted `3.3`, replied at once with the expected 24-byte body, and the
   touch flag separated finger off (`0000`) from finger on (`01ed`).
2. `01ed` sets bits 0, 2, 3, 5, 6, 7, 8 (zones 1, 4, 9 clear). The Windows
   log showed `0x3ff` during an unlock; a partial pattern is consistent with a
   finger not covering the whole sensor.
3. The IRQ status differed by bit `0x0080`: `0180` without a finger, `0100`
   with one (`0100` also matches the Windows log during an unlock). This may
   mean "no touch", but it rests on one sample per condition.
4. The `A.7` state word stayed `01 00` before and after `3.3`, in both runs.
   Touch is reported in the FDT reply, not in `A.7`, even after switching to
   manual FDT mode.

## Follow-up check

After both runs the operator booted Windows and verified fingerprint unlock
with Windows Hello. _Result: confirmed working._ The `3.3` command left no
lasting effect on the reader.

## Not established

- Whether the result is repeatable: one run per condition.
- What bit `0x0080` of the IRQ status means.
- How near each zone was to its threshold (base values not recorded).
- FDT down (`3.1`, `0x32`), which replies later without being asked, needs
  unrequested-reply handling and a separate plan, code, review and approval.
