# Protocol Ledger

This ledger separates direct observations from names supplied by the MIT-licensed upstream Goodix dissector. It contains no packet bodies, frame data, credentials, or raw captures.

## Evidence scope

- Target: Goodix `27c6:55a2`, USB bulk OUT `0x01` / IN `0x82`.
- Source trace: private native-Windows Windows Hello capture described in the experiment records.
- Command classification: one outbound command byte only; arguments remain unread.
- Prior-work mapping: [`tlambertz/goodix-fingerprint-reversing` dissector](https://raw.githubusercontent.com/tlambertz/goodix-fingerprint-reversing/main/wireshark-dissector/goodix_message.lua), MIT licensed.

## Observed sequence

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

## Current conclusions

1. The upstream command framing and command-family classification apply to this exact hardware/driver trace.
2. The four large IN completions are transport-correlated with `McuGetImage` commands. Treat them as potentially biometric image data; they remain unread and private.
3. Command names are prior-work labels, not independently proven semantics. A future proof requires a repeatable, non-sensitive experiment for each command family.

## Unknowns

- Exact message arguments and reply contents.
- Device state transitions that distinguish the failed scan from the successful scan.
- Whether the 14,866-byte data is raw, compressed, encrypted, or otherwise encoded image material.
- Authentication/matching location and template handling.
