# Experiment 0002 Result: Native Windows Passive Capture

## Outcome

A private capture named `win-native-hello-001.pcap` was collected on the known-working native Windows installation, following the constrained capture plan.

- Action captured: one ordinary Windows Hello fingerprint verification.
- Original capture handling: retained locally; not committed, uploaded, or shared with this repository.
- Post-capture Windows Hello verification: **pass**.

## Local metadata result

The local-only inspector reported the following safe, payload-free metadata:

| Field | Value |
| --- | --- |
| Container | classic little-endian PCAP |
| Link type | `249` (`LINKTYPE_USBPCAP`) |
| Timestamp resolution | microseconds |
| Capture duration | 16 seconds |
| Packet records | 128 |
| Captured bytes | 65,999 |
| Original bytes | 65,999 |
| Per-record truncation | none reported (`captured_bytes == original_bytes`) |

`LINKTYPE_USBPCAP` is defined by the USBPcap capture-format specification. The equal captured/original byte totals mean the PCAP records themselves were not snaplen-truncated; it does not establish that every USB transfer on the root hub was observed.

Reference: <https://desowin.org/usbpcap/captureformat.html>

## Scope preserved

No driver replacement, firmware operation, enrollment, virtual-machine passthrough, custom USB transaction, or device reset is recorded for this experiment.

## Next step

Use a local-only metadata inspector to determine the capture container type and packet-level volume without displaying or exporting payload bytes. Do not share the original capture; share only the inspector's metadata output after review.
