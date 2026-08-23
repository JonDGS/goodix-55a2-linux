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
- `tools/` — small capture, decoding, and analysis tools (to be added).
- `wireshark/` — dissector work (to be added).
- `fixtures/` — reviewed, sanitized fixtures only (to be added).

## Getting involved

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/RESEARCH_CHARTER.md`](docs/RESEARCH_CHARTER.md) before opening an issue or sharing a trace.

## License

MIT. See [`LICENSE`](LICENSE).
