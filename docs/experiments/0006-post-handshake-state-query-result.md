# Experiment 0006 result: one read-only command after the TLS handshake

Status: **passed.** After the Linux TLS-PSK handshake of experiment 0005, the
reader accepted one `A.7` QueryMcuState command and answered in a plaintext
`0xa0` frame. This matches prior work. It does not prove image capture or
fingerprint matching.

Plan: [`0006-post-handshake-state-query.md`](0006-post-handshake-state-query.md).

## Setup

- Hardware, host and key: same as experiment 0005 (Goodix `27c6:55a2`,
  firmware `GF3206_RTSEC_APP_10063`, Fedora 44, the existing pre-shared key
  provisioned by Windows). **No key was written to the reader.**
- Tool: `tools/goodix_handshake.py --run --query-state`, run once by the
  operator as root from an interactive terminal. Tests:
  `tests/test_goodix_handshake.py` (synthetic only, no hardware). The change
  was reviewed independently before the run.

## What the tool sent

The four fixed frames from experiment 0005 (`0.0`, `A.4`, `D.0`, `D.2`) and
the TLS-PSK handshake, then exactly one extra fixed frame: `A.7`
QueryMcuState with payload `55` (`a00500a5ae020055a5`). The USB send boundary
allowed that frame only once and only after `D.2` was acknowledged. No key
commands, firmware commands, resets, image requests or outbound TLS
application data were sent.

## Run

One attempt; it completed on the first run.

```json
{"cipher": "PSK-AES128-CBC-SHA256", "device_confirmation_ack": true,
 "nop_ack": false, "protocol": "TLSv1.2", "stage": "complete",
 "state_query_ack": true, "state_reply_cmd": "ae", "state_reply_flag": "a0",
 "state_reply_length": 2, "tls_verified": true, "usb_released": true}
```

No stop condition was hit. Reply bytes were not printed or recorded.

## Findings

1. The handshake behaved exactly as in experiment 0005: TLS 1.2,
   `PSK-AES128-CBC-SHA256`, `D.2` acknowledged, NOP still unanswered.
2. The reader acknowledges `A.7` after the handshake.
3. The `A.7` reply is a plaintext `0xa0` frame with command byte `0xae`,
   not TLS-protected. This supports the prior-work model: after the
   handshake, commands and their replies stay plaintext. Only image data is
   expected to come back inside TLS (`0xb2` frames). That last part is still
   untested.
4. The reply body is 2 bytes long, measured after the 3-byte command header
   and with the trailing checksum removed. This is shorter than the 16-byte
   synthetic reply used in the unit tests. What these bytes mean has not been
   examined.

## Follow-up check

After the run, the operator booted Windows and verified fingerprint unlock
with Windows Hello. It still works.

## Not established

- The meaning of the two `A.7` reply bytes. Decoding them is a later step,
  after reviewing prior work, and only if they turn out to be non-identifying.
- Whether `0xb2` TLS data frames decrypt with the in-memory session. No such
  frame was received in this run.
- Image capture, enrollment or matching.
