# Protocol Ledger

This ledger separates direct observations from names supplied by the MIT-licensed upstream Goodix dissector and later prior work. It contains no packet bodies, frame data, credentials, or raw captures.

## Evidence scope

- Target: Goodix `27c6:55a2`, USB bulk OUT `0x01` / IN `0x82`.
- Source traces: private native-Windows captures described in the experiment records.
- Command classification: one outbound command byte only; arguments remain unread.
- Prior-work mapping: [`tlambertz/goodix-fingerprint-reversing` dissector](https://raw.githubusercontent.com/tlambertz/goodix-fingerprint-reversing/main/wireshark-dissector/goodix_message.lua), MIT licensed, and the command constants in [`goodix-fp-linux-dev/goodix-fp-dump`](https://github.com/goodix-fp-linux-dev/goodix-fp-dump) (`goodix.py`, MIT licensed).

## Command byte encoding

The command byte packs a family and a sub-command: `byte = family << 4 | sub << 1`; the low bit is always zero. This ledger writes commands as `family.sub`, e.g. `0xd6` is `D.3`.

## Command map

Names come from prior work. "Seen" means the command byte appears in this project's captures.

| Byte | Class | Prior-work name | Seen |
| --- | --- | --- | --- |
| `0x00` | `0.0` | NOP | yes (unlock, shutdown) |
| `0x20` | `2.0` | McuGetImage | yes (unlock) |
| `0x32` | `3.1` | McuSwitchToFdtDown | yes |
| `0x34` | `3.2` | McuSwitchToFdtUp | yes |
| `0x36` | `3.3` | McuSwitchToFdtMode | yes |
| `0x50` | `5.0` | Nav | no |
| `0x60` | `6.0` | McuSwitchToSleepMode | yes |
| `0x70` | `7.0` | McuSwitchToIdleMode | no |
| `0x80` / `0x82` | `8.0` / `8.1` | Write / ReadSensorRegister | no |
| `0x90` | `9.0` | UploadConfigMcu | no |
| `0x92` | `9.1` | SwitchToSleepMode | no |
| `0x94` | `9.2` | SetPowerdownScanFrequency | no |
| `0x96` | `9.3` | EnableChip | no |
| `0xa2` | `A.1` | Reset | no |
| `0xa4` | `A.2` | McuEraseApp | no |
| `0xa6` | `A.3` | ReadOtp | no |
| `0xa8` | `A.4` | FirmwareVersion | yes (Linux pilot) |
| `0xac` | `A.6` | SetPovConfig | no |
| `0xae` | `A.7` | QueryMcuState | yes (unlock) |
| `0xb0` | `B.0` | Ack | reply |
| `0xc4` | `C.2` | SetDrvState | yes (shutdown) |
| `0xc6` | `C.3` | McuSetLedState (dissector) | yes (failed unlock) |
| `0xd0` | `D.0` | RequestTlsConnection | yes (Linux pilot) |
| `0xd2` | `D.1` | McuGetPovImage | no |
| `0xd4` | `D.2` | TlsSuccessfullyEstablished | yes (Linux pilot) |
| `0xd6` | `D.3` | PovImageCheck | yes (unlock, shutdown) |
| `0xe0` | `E.0` | PresetPskWriteR | no |
| `0xe4` | `E.2` | PresetPskReadR | no |
| `0xf0`–`0xf6` | `F.x` | Firmware write/read/check, IAP version | no |

## Observed sequences

### Ordinary unlock (runtime)

| OUT record | Classified command | Upstream dissector name | Related observation |
| --- | --- | --- | --- |
| 26, 118 | `A.7` | Query MCU State | Framing/status query; bodies unread. |
| 32 | `0.0` | NOP | Purpose unknown upstream. |
| 36 | `D.3` | PovImageCheck | Bodies unread. |
| 42, 46, 92 | `3.1` | McuSwitchToFdtDown | Mode transition sequence. |
| 52, 80, 86, 98 | `2.0` | McuGetImage | Each is followed by a 14,866-byte IN completion in the private trace. |
| 58, 104 | `3.3` | McuSwitchToFdtMode | Mode transition sequence. |
| 64, 74, 110, 114 | `3.2` | McuSwitchToFdtUp | Mode transition sequence. |
| 68 | `C.3` | McuSetLedState | Bodies unread. |
| 124 | `6.0` | McuSwitchToSleepMode | Appears at the end of the observed sequence. |

### Driver shutdown (PnP disable)

Seen identically in three captures (experiments 0004 and `goodix-reenable-001`): `0.0` → `D.3` → `C.2`, each followed by a 10-byte reply (plus one 9-byte reply after `D.3`), then a canceled IN (`0xc0010000`). The whole burst takes about 4 ms and arrives several seconds after the disable request.

### TLS handshake from Linux (experiment 0005)

Sent by our own tool, not the Windows driver:

1. `0.0` NOP — the reader sends no reply.
2. `A.4` FirmwareVersion — ACK, then `GF3206_RTSEC_APP_10063`.
3. `D.0` RequestTlsConnection — ACK, then a TLS 1.2 ClientHello offering only
   `TLS_PSK_WITH_AES_128_CBC_SHA256` (`0x00AE`) and the renegotiation SCSV.
4. TLS-PSK handshake in `0xb0` frames, host as server, using the key the
   Windows driver provisioned. Handshake verified.
5. `D.2` TlsSuccessfullyEstablished — acknowledged.

`E.2`/`E.0` were not used. See
`experiments/0005-linux-tls-handshake-pilot-result.md`.

### Driver startup (prior work, not observed here)

From Lambertz's `capture.py` for this USB ID, and the same flow in `goodix-fp-dump` for `55a4`/`55b4`:

1. `0.0` NOP.
2. `A.4` FirmwareVersion.
3. `E.2` PresetPskReadR — read a hash of the stored pre-shared key and compare it with the expected one.
4. `E.0` PresetPskWriteR — only when the hash does not match; the prior Linux tools write their own known key here.
5. `D.0` RequestTlsConnection — the device replies with a TLS ClientHello; the host acts as a TLS-PSK server and the handshake runs over the transport in message-pack framing.
6. `D.2` TlsSuccessfullyEstablished.
7. Image data from `McuGetImage` is then read through the TLS session.

## Current conclusions

1. The upstream command framing and command-family classification apply to this exact hardware/driver trace.
2. The four large IN completions are transport-correlated with `McuGetImage` commands. Treat them as potentially biometric image data; they remain unread and private.
3. Command names are prior-work labels, not independently proven semantics. A future proof requires a repeatable, non-sensitive experiment for each command family.
4. No `D.0`/`D.2` appears in unlock captures, so the TLS session is established once at driver start and reused. This matches the prior-work startup flow.
5. Startup could not be captured (experiment 0004 result). Steps 1, 2, 5 and 6 of the prior-work flow were since confirmed from Linux (experiment 0005); the `E.2`/`E.0` PSK steps remain unconfirmed.
6. The Windows-provisioned PSK works from Linux without rewriting it.

## Unknowns

- Exact message arguments and reply contents.
- Device state transitions that distinguish the failed scan from the successful scan.
- Whether the 14,866-byte data is raw, compressed, encrypted, or otherwise encoded image material. Prior work reads images through TLS, which suggests encrypted transport.
- Authentication/matching location and template handling.
- Whether Windows can recover if the key on the sensor changes (not needed now: Linux can reuse the existing key).
- The derivation behind the `E.2` PSK hash value.
- Image transfer and decoding inside the TLS session.
