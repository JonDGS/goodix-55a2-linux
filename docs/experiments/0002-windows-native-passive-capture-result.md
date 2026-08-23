# Experiment 0002 Result: Native Windows Passive Capture

## Outcome

A private capture named `win-native-hello-001.pcap` was collected on the known-working native Windows installation, following the constrained capture plan.

- Action captured: Windows lock followed by two ordinary Windows Hello fingerprint verifications: the first attempt failed, and the second attempt succeeded.
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

Run the local-only bulk-header indexer against the private capture:

```powershell
py .\tools\usbpcap_bulk_index.py "C:\path\to\win-native-hello-001.pcap"
```

The tool reads USBPcap headers and skips all transfer payload bytes. Do not share the PCAP; share only its JSON output after removing entries that are clearly unrelated to the Goodix reader.
