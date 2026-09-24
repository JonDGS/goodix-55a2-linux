# Goodix 55A2 Linux

An open, privacy-conscious research effort to support the Goodix USB fingerprint sensor `27c6:55a2` on Linux.

> **Status: early research.** This is not an authentication solution and must not be relied on to protect an account or device.

## Current state

- Windows Hello captures have mapped the reader's command families and transfer
  cycles without reading message bodies ([`docs/PROTOCOL_LEDGER.md`](docs/PROTOCOL_LEDGER.md)).
- **Linux handshake works.** A handshake-only Linux tool completed the reader's
  TLS-PSK handshake using the key the Windows driver already provisioned, and the
  reader acknowledged it. No key was written and no images were requested
  ([experiment 0005](docs/experiments/0005-linux-tls-handshake-pilot-result.md)).
  Windows Hello was checked afterwards and still works.
- **A command after the handshake works.** The reader answered one read-only
  `A.7` state query in plaintext while the TLS session was open
  ([experiment 0006](docs/experiments/0006-post-handshake-state-query-result.md)).
  Windows Hello still works afterwards.
- **The state reply is decoded but not yet understood.** The 2-byte `A.7`
  reply is `01 00` both before and after the handshake, so the published
  `tls_connected` flag does not track the TLS session on this reader
  ([experiment 0007](docs/experiments/0007-decode-state-bytes-result.md),
  [experiment 0008](docs/experiments/0008-state-before-and-after-handshake-result.md)).
  It stays `01 00` with a finger resting on the sensor
  ([experiment 0009](docs/experiments/0009-state-with-finger-on-sensor-result.md)).
- Not yet done: TLS-protected data from the reader, image capture, enrollment or
  matching. There is no usable Linux driver.

## Windows capture helper

The [command-line capture helper](docs/WINDOWS_CAPTURE_CLI.md) locates the exact
Goodix reader dynamically, records private scenario-based USBPcap sessions, and
validates traffic without decoding packet bodies. **Experimental checkpoint, not
validated Windows capture support:** on-device discovery and output readiness
have succeeded, but orderly recorder shutdown is unresolved and post-stop
validation was skipped. The guide records the known failure and next diagnostic
steps. Guarded warm-restart code exists but must remain unused until an ordinary
unlock capture passes the capture/cleanup gates.

```powershell
py -3 .\tools\goodix_capture.py discover
py -3 .\tools\goodix_capture.py
```

## Goals

1. Document the sensor protocol with reproducible experiments.
2. Build small, auditable Linux tools for device interrogation and capture analysis.
3. Establish a minimal, safe proof of communication with the device (TLS handshake done, experiment 0005).
4. Pursue an upstream-quality path toward `libfprint` support, if technically and security-wise appropriate.

## Non-goals

- Publishing fingerprint images, user-bound secrets, device credentials, or unredacted captures.
- Circumventing authentication on devices we do not own or have permission to test.
- Treating an experimental driver as a security boundary.

## Device target

| USB ID | Vendor | Target |
| --- | --- | --- |
| `27c6:55a2` | Goodix | Goodix fingerprint sensor |

Related but differently identified Goodix sensors may use substantially different firmware or protocols.

## Research principles

- **Reproducible:** record hardware, OS, tool versions, commands, and sanitized evidence.
- **Privacy first:** raw biometric material and secrets remain local and Git-ignored.
- **Upstream-minded:** favor designs and tests that could eventually support a `libfprint` contribution.
- **Attribution preserved:** upstream research and reused material are credited in [`docs/UPSTREAM.md`](docs/UPSTREAM.md).

## Repository layout

- [`docs/`](docs/) — protocol notes, experimental records, and operating rules.
  - [`docs/baselines/2026-08-22-fedora-linux.md`](docs/baselines/2026-08-22-fedora-linux.md) — initial stock-Linux enumeration and support baseline.
  - [`docs/experiments/0001-windows-reference-capture.md`](docs/experiments/0001-windows-reference-capture.md) — read-only Windows reference and capture protocol.
  - [`docs/experiments/0001-windows-reference-result.md`](docs/experiments/0001-windows-reference-result.md) — verified working Windows driver metadata.
  - [`docs/experiments/0002-windows-native-passive-capture.md`](docs/experiments/0002-windows-native-passive-capture.md) — constrained native-Windows capture plan.
  - [`docs/experiments/0002-windows-native-passive-capture-result.md`](docs/experiments/0002-windows-native-passive-capture-result.md) — private capture completed; Windows Hello preserved.
  - [`docs/PROTOCOL_LEDGER.md`](docs/PROTOCOL_LEDGER.md) — evidence-backed command-family observations and open questions.
  - [`docs/PRIOR_WORK_COMPARISON.md`](docs/PRIOR_WORK_COMPARISON.md) — agreement and open differences with the 2021 reverse-engineering work.
  - [`docs/experiments/0003-controlled-outcome-comparison.md`](docs/experiments/0003-controlled-outcome-comparison.md) — controlled private captures for failed-versus-successful comparison.
  - [`docs/experiments/0003-controlled-outcome-comparison-result.md`](docs/experiments/0003-controlled-outcome-comparison-result.md) — payload-free outcome comparison result.
  - [`docs/experiments/0004-early-driver-initialization-capture.md`](docs/experiments/0004-early-driver-initialization-capture.md) — gated, recoverable plan to observe the installed Windows driver's warm-start initialization.
  - [`docs/experiments/0004-early-driver-initialization-result.md`](docs/experiments/0004-early-driver-initialization-result.md) — startup could not be captured; prior-work startup sequence recorded instead.
  - [`docs/experiments/0005-linux-tls-handshake-pilot-result.md`](docs/experiments/0005-linux-tls-handshake-pilot-result.md) — Linux TLS-PSK handshake completed with the existing key.
  - [`docs/experiments/0006-post-handshake-state-query.md`](docs/experiments/0006-post-handshake-state-query.md) — plan: one read-only `A.7` state query after the handshake.
  - [`docs/experiments/0006-post-handshake-state-query-result.md`](docs/experiments/0006-post-handshake-state-query-result.md) — reader answered `A.7` in plaintext after the handshake.
  - [`docs/experiments/0007-decode-state-bytes.md`](docs/experiments/0007-decode-state-bytes.md) — plan: record and decode the 2-byte `A.7` reply.
  - [`docs/experiments/0007-decode-state-bytes-result.md`](docs/experiments/0007-decode-state-bytes-result.md) — reply `01 00`; layout inconclusive.
  - [`docs/experiments/0008-state-before-and-after-handshake.md`](docs/experiments/0008-state-before-and-after-handshake.md) — plan: `A.7` before and after the handshake.
  - [`docs/experiments/0008-state-before-and-after-handshake-result.md`](docs/experiments/0008-state-before-and-after-handshake-result.md) — same reply before and after; TLS does not change it.
  - [`docs/experiments/0009-state-with-finger-on-sensor.md`](docs/experiments/0009-state-with-finger-on-sensor.md) — plan: `A.7` with a finger on the sensor.
  - [`docs/experiments/0009-state-with-finger-on-sensor-result.md`](docs/experiments/0009-state-with-finger-on-sensor-result.md) — still `01 00`; a resting finger does not change it.
  - [`docs/WINDOWS_CAPTURE_CLI.md`](docs/WINDOWS_CAPTURE_CLI.md) — experimental Windows capture helper guide.
- [`tools/pcap_metadata.py`](tools/pcap_metadata.py) — local-only classic-PCAP metadata inspector; it never emits packet payload bytes.
- [`tools/usbpcap_bulk_index.py`](tools/usbpcap_bulk_index.py) — local-only USBPcap bulk-header indexer; it skips transfer payloads entirely.
- [`tools/usbpcap_bulk_correlation.py`](tools/usbpcap_bulk_correlation.py) — locally maps related bulk headers to anonymous operation labels; it never outputs IRP pointers or payloads.
- [`tools/usbpcap_bulk_cycles.py`](tools/usbpcap_bulk_cycles.py) — locally pairs each bulk submission with its completion under anonymous cycle labels.
- [`tools/usbpcap_bulk_timeline.py`](tools/usbpcap_bulk_timeline.py) — emits relative-only cycle offsets, with no wall-clock timestamps, pointers, or payloads.
- [`tools/goodix_outbound_envelopes.py`](tools/goodix_outbound_envelopes.py) — reads only four-byte outbound Goodix envelope headers; it never outputs message bodies.
- [`tools/goodix_outbound_commands.py`](tools/goodix_outbound_commands.py) — reads one command byte and emits only split category/command fields.
- [`tools/goodix_small_inbound_envelopes.py`](tools/goodix_small_inbound_envelopes.py) — reads only four-byte envelopes from small IN replies; it skips all reply bodies and large transfers.
- [`tools/goodix_small_inbound_commands.py`](tools/goodix_small_inbound_commands.py) — reads one small-reply command byte and emits only split category/command fields.
- [`tools/goodix_capture.py`](tools/goodix_capture.py) — experimental Windows capture CLI (see the guide above).
- [`tools/goodix_handshake.py`](tools/goodix_handshake.py) — Linux handshake-only pilot: four fixed commands, TLS-PSK server in memory, no key writes or image requests. Run only as an approved experiment.
- `wireshark/` — dissector work (to be added).
- `fixtures/` — reviewed, sanitized fixtures only (to be added).

## Getting involved

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/RESEARCH_CHARTER.md`](docs/RESEARCH_CHARTER.md) before opening an issue or sharing a trace.

## License

MIT. See [`LICENSE`](LICENSE).
