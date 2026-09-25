# Experiment 0009 result: A.7 state with a finger on the sensor

Status: **run; no change.** With a finger resting on the sensor, the `A.7`
reply was `01 00` before and after the handshake, the same as without a
finger.

Plan: [`0009-state-with-finger-on-sensor.md`](0009-state-with-finger-on-sensor.md).

## Setup

- Hardware, host and key: same as experiments 0005–0008. **No key was
  written to the reader.**
- Tool: unchanged from 0008 (SHA-256 `0e8f0cf2…`), run once by the operator
  as root from an interactive terminal:
  `goodix_handshake.py --run --query-state --query-state-pre-tls`.
- The operator placed one finger flat on the sensor before starting and kept
  it there until the report appeared.

## What the tool sent

The same frames as 0008: `0.0`, `A.4`, `A.7 55`, `D.0`, the TLS-PSK
handshake, `D.2`, `A.7 55`. No image request, finger-detection (FDT), key,
firmware or reset command.

## Run

One attempt; it completed on the first run.

```json
{"cipher": "PSK-AES128-CBC-SHA256", "device_confirmation_ack": true,
 "nop_ack": false, "protocol": "TLSv1.2", "stage": "complete",
 "state_pre_query_ack": true, "state_pre_reply_flag": "a0",
 "state_pre_reply_cmd": "ae", "state_pre_reply_length": 2,
 "state_pre_reply_hex": "0100",
 "state_pre_flags_byte0": {"image_valid": true, "locked": false,
                           "spi_send": false, "tls_connected": false},
 "state_pre_flags_byte1": {"image_valid": false, "locked": false,
                           "spi_send": false, "tls_connected": false},
 "state_pre_unknown_bits_byte0": "00", "state_pre_unknown_bits_byte1": "00",
 "state_query_ack": true, "state_reply_flag": "a0", "state_reply_cmd": "ae",
 "state_reply_length": 2, "state_reply_hex": "0100",
 "state_flags_byte0": {"image_valid": true, "locked": false,
                       "spi_send": false, "tls_connected": false},
 "state_flags_byte1": {"image_valid": false, "locked": false,
                       "spi_send": false, "tls_connected": false},
 "state_unknown_bits_byte0": "00", "state_unknown_bits_byte1": "00",
 "tls_verified": true, "usb_released": true}
```

No stop condition was hit. No unrequested frame was observed; the tool only
reads when it expects a reply, so one arriving after the last read would not
be seen.

## Findings

1. With a finger resting on the sensor, the reply is `01 00` both before and
   after the handshake. This matches the finger-off result from 0008.
2. No unrequested message was seen during the run.
3. Without finger-detection (FDT) mode, a resting finger does not show up in
   this state word. This fits the plan's expectation. Whether FDT mode would
   change the word is untested, and this does not show that the word ignores
   touch.

Across 0007–0009, the `A.7` reply has always been `01 00`: without a finger
and with one, before and after TLS. It has not yet changed in any tested
condition, so the byte layout is still unresolved.

## Follow-up check

After the run, the operator is to boot Windows and verify fingerprint unlock
with Windows Hello. _Result: TODO (operator to confirm)._

## Not established

- Which byte carries the flags, and what bit `0x01` means.
- Whether the state changes in FDT mode or after an image request. Both need
  new command families and a separate plan, code, review and approval.
