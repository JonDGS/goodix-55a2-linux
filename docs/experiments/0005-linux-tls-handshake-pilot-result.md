# Experiment 0005 result: Linux TLS-PSK handshake pilot

Status: **passed.** A Linux host completed the reader's TLS-PSK handshake and
the reader acknowledged `D.2` TlsSuccessfullyEstablished. This proves the host
held the reader's pre-shared key. It does not prove image capture or
fingerprint matching.

## Setup

- Hardware: Goodix `27c6:55a2`, firmware `GF3206_RTSEC_APP_10063`.
- Host: Fedora 44, stock kernel, no kernel driver bound to the reader,
  `fprintd` not claiming it.
- Tool: `tools/goodix_handshake.py`, run once per attempt by the operator as
  root from an interactive terminal (`--run`). Tests:
  `tests/test_goodix_handshake.py` (synthetic only, no hardware).
- Key: the reader's existing pre-shared key, recovered beforehand from the
  Windows install that provisioned it. **No key was written to the reader.**
  The key is not part of this repository and is never printed.

## What the tool may send

Only four fixed command frames, checked byte for byte at the USB send
boundary: `0.0` NOP, `A.4` FirmwareVersion, `D.0` RequestTlsConnection and
`D.2` TlsSuccessfullyEstablished. Outbound TLS is restricted to handshake and
change-cipher-spec records. No PSK writes, firmware commands, resets, image
requests or TLS application data. USB traffic is bounded by a 45 s deadline
and a transfer budget; the interface is claimed only when no kernel driver is
bound and released afterwards.

This is still USB traffic that changes the reader's volatile session state,
not a passive read.

## Runs

| Run | Tool change | Result |
| --- | --- | --- |
| 1 | initial | Stopped after `0.0`: the reader sent no reply. |
| 2 | Accept a clean read timeout after NOP, as prior tools do | Firmware check passed, `D.0` accepted, TLS failed with an unlabelled error. |
| 3 | Report the OpenSSL reason code | `tls_handshake_rejected:NO_SHARED_CIPHER`. |
| 4 | Report the reader's offered cipher suites | Reader offers only `0x00AE` plus `0x00FF` (the renegotiation SCSV). |
| 5 | Allow `PSK-AES128-CBC-SHA256` | **Complete:** TLS 1.2 verified, `D.2` acknowledged, USB released. |

Final report from run 5:

```json
{"cipher": "PSK-AES128-CBC-SHA256", "device_confirmation_ack": true,
 "nop_ack": false, "protocol": "TLSv1.2", "stage": "complete",
 "tls_verified": true, "usb_released": true}
```

Each change was reviewed independently before the next hardware run.

## Findings

1. The reader does not answer `0.0` NOP. Its first reply comes after `A.4`.
2. `A.4` reports `GF3206_RTSEC_APP_10063` (Lambertz's reader reported
   `GF3208_RTSEC_APP_10056`).
3. After `D.0` the reader sends a TLS 1.2 ClientHello offering exactly one
   suite: `TLS_PSK_WITH_AES_128_CBC_SHA256` (`0x00AE`), plus `0x00FF`.
4. The pre-shared key recovered from the Windows install works as-is.
   Linux can use the key Windows provisioned without rewriting it, so the
   prior-work approach of writing a known key is not needed here.
5. The reader acknowledges `D.2` after a successful handshake.

## Not established

- Image capture or decoding through the TLS session.
- Fingerprint enrollment or matching.
- Whether Windows Hello still works after these runs (not yet checked).
- The derivation behind the `E.2` PSK hash; the tool does not use `E.2`.
