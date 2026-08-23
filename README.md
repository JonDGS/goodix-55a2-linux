# Goodix 55A2 Linux

An open, privacy-conscious research effort to support the Goodix USB fingerprint sensor `27c6:55a2` on Linux.

> **Status: early research.** This is not an authentication solution and must not be relied on to protect an account or device.

## Goals

1. Document the sensor protocol with reproducible experiments.
2. Build small, auditable Linux tools for device interrogation and capture analysis.
3. Establish a minimal, safe proof of communication with the device.
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
  - [`docs/experiments/0003-controlled-outcome-comparison.md`](docs/experiments/0003-controlled-outcome-comparison.md) — controlled private captures for failed-versus-successful comparison.
- [`tools/pcap_metadata.py`](tools/pcap_metadata.py) — local-only classic-PCAP metadata inspector; it never emits packet payload bytes.
- [`tools/usbpcap_bulk_index.py`](tools/usbpcap_bulk_index.py) — local-only USBPcap bulk-header indexer; it skips transfer payloads entirely.
- [`tools/usbpcap_bulk_correlation.py`](tools/usbpcap_bulk_correlation.py) — locally maps related bulk headers to anonymous operation labels; it never outputs IRP pointers or payloads.
- [`tools/usbpcap_bulk_cycles.py`](tools/usbpcap_bulk_cycles.py) — locally pairs each bulk submission with its completion under anonymous cycle labels.
- [`tools/usbpcap_bulk_timeline.py`](tools/usbpcap_bulk_timeline.py) — emits relative-only cycle offsets, with no wall-clock timestamps, pointers, or payloads.
- [`tools/goodix_outbound_envelopes.py`](tools/goodix_outbound_envelopes.py) — reads only four-byte outbound Goodix envelope headers; it never outputs message bodies.
- [`tools/goodix_outbound_commands.py`](tools/goodix_outbound_commands.py) — reads one command byte and emits only split category/command fields.
- `wireshark/` — dissector work (to be added).
- `fixtures/` — reviewed, sanitized fixtures only (to be added).

## Getting involved

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/RESEARCH_CHARTER.md`](docs/RESEARCH_CHARTER.md) before opening an issue or sharing a trace.

## License

MIT. See [`LICENSE`](LICENSE).
