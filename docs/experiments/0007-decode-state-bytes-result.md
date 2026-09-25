# Experiment 0007 result: the 2-byte A.7 state reply

Status: **run; inconclusive.** The reply bytes were recorded and decoded. The
value does not show which of the two published layouts is correct.

Plan: [`0007-decode-state-bytes.md`](0007-decode-state-bytes.md).

## Setup

- Hardware, host and key: same as experiments 0005 and 0006 (Goodix
  `27c6:55a2`, firmware `GF3206_RTSEC_APP_10063`, Fedora 44, the existing
  pre-shared key provisioned by Windows). **No key was written to the reader.**
- Tool: `tools/goodix_handshake.py --run --query-state`, run once by the
  operator as root from an interactive terminal. The change only affects
  reporting. It was reviewed independently before the run, and all 124
  synthetic unit tests passed.

## What the tool sent

The same frames as experiment 0006: `0.0`, `A.4`, `D.0`, the TLS-PSK
handshake, `D.2`, then one `A.7` QueryMcuState with payload `55`. No new
command was sent.

## Run

One attempt; it completed on the first run.

```json
{"cipher": "PSK-AES128-CBC-SHA256", "device_confirmation_ack": true,
 "nop_ack": false, "protocol": "TLSv1.2", "stage": "complete",
 "state_flags_byte0": {"image_valid": true, "locked": false,
                       "spi_send": false, "tls_connected": false},
 "state_flags_byte1": {"image_valid": false, "locked": false,
                       "spi_send": false, "tls_connected": false},
 "state_query_ack": true, "state_reply_cmd": "ae", "state_reply_flag": "a0",
 "state_reply_hex": "0100", "state_reply_length": 2,
 "state_unknown_bits_byte0": "00", "state_unknown_bits_byte1": "00",
 "tls_verified": true, "usb_released": true}
```

No stop condition was hit.

## Findings

1. The handshake and the `A.7` exchange behaved exactly as in experiment
   0006. The NOP was again unanswered (`nop_ack: false`), as in 0005 and 0006.
2. The reply body is `01 00`.
3. If the flags are in byte 0 (tlambertz dissector), the only flag set is
   `0x01` isImageValid.
4. If the flags are in byte 1 (goodix-fp-dump), no flag is set.
5. No unknown upper bits are set in either byte.
6. The expected sign did not appear. `tls_connected` is false in both
   layouts, even though the host TLS session completed and was verified. So
   the test planned in 0007 cannot settle the layout.

A non-zero byte 0 fits the tlambertz layout slightly better than an all-zero
byte 1. One sample is not evidence, and this document does not adopt either
layout.

Possible reasons why `tls_connected` is false:

- the flag may describe a different link (for example the sensor or SPI
  side), not the host TLS session;
- the flag may only be set after later commands that this tool does not send;
- the name given in prior work may be wrong. Both dissectors mark several of
  these fields as "meaning unknown".

## Follow-up check

After the run, the operator is to boot Windows and verify fingerprint unlock
with Windows Hello. _Result: confirmed working (checked by the operator after experiment 0009, covering 0007–0009)._

## Not established

- Which byte carries the flags, and what `tls_connected` actually means.
- Whether the value changes with device state. That needs a second sample in
  a different state; see the planned experiment 0008.
- Everything left open by 0006: `0xb2` decryption, image capture, enrollment
  and matching.
