# Experiment 0008 result: A.7 state before and after the handshake

Status: **run; no difference.** The reader accepted `A.7` before TLS and gave
the same reply before and after the handshake.

Plan: [`0008-state-before-and-after-handshake.md`](0008-state-before-and-after-handshake.md).

## Setup

- Hardware, host and key: same as experiments 0005–0007 (Goodix `27c6:55a2`,
  firmware `GF3206_RTSEC_APP_10063`, Fedora 44, the existing pre-shared key
  provisioned by Windows). **No key was written to the reader.**
- Tool: `goodix_handshake.py --run --query-state --query-state-pre-tls`
  (SHA-256 `0e8f0cf2…`, matching the reviewed copy), run once by the operator
  as root from an interactive terminal. The change was reviewed independently
  before the run. 130 synthetic tests passed in the repository, and 42
  handshake tests passed on the Fedora host.

## What the tool sent

`0.0`, `A.4`, **`A.7` (payload `55`)**, `D.0`, the TLS-PSK handshake, `D.2`,
`A.7` (payload `55`). Both `A.7` frames were the fixed
`a00500a5ae020055a5`. No other command was sent.

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

No stop condition was hit.

## Findings

1. The reader accepts `A.7` before TLS. It acknowledges it and answers in
   plaintext (`0xa0`, command `0xae`, 2-byte body), exactly as after the
   handshake. The handshake that followed was unaffected.
2. The reply was `01 00` both times. It matches 0007.
3. The TLS handshake does not change this state word. So the TLS-connected
   flag named in prior work (`0x02`, in either byte) does not track the host
   TLS session on this reader. Either the name is wrong, or it refers to
   something else.
4. The plan's third outcome applies: the samples are identical, so this
   contrast cannot settle which byte holds the flags.

## Follow-up check

After the run, the operator is to boot Windows and verify fingerprint unlock
with Windows Hello. _Result: TODO (operator to confirm)._

## Not established

- Which byte carries the flags, and what bit `0x01` means.
- Whether the state changes after other events, for example after an image
  request or a sensor touch. Those need new commands or a Windows capture,
  and a separate plan.
