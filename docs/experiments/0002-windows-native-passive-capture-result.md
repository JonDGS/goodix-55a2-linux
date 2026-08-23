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

## Bulk-header index result

A payload-free USBPcap header index identified one bulk-transfer stream:

- USBPcap bus/device: `2/3` (Windows device address; this is not the physical Port 9 label).
- Record range: 25–128, comprising all 104 indexed bulk records.
- Endpoints: expected `0x01` OUT and `0x82` IN.
- Normal status: `0x00000000` throughout the observed stream except the final `0xc0010000` IN record.
- Repeated OUT transfer size: 64 bytes.
- Observed IN transfer sizes include 9, 10, 32, and 14,866 bytes.
- Four IN records declared 14,866 bytes each, totaling 59,464 bytes.

The 14,866-byte IN transfers are large enough to be potentially sensitive biometric or image-adjacent device data. Their payloads remain unread and unshared. The final nonzero status is recorded as an observation only; it must not be interpreted as an authentication result without correlating request/completion metadata.

## Anonymous correlation result

The correlation index identifies 15 locally labeled IRP-pointer allocations. One long-lived label, `op-001`, owns the repeated IN `0x82` stream, including all four 14,866-byte records and the final `0xc0010000` status. The 64-byte OUT `0x01` writes use the remaining labels.

The pointer labels are not one-to-one protocol transactions: the Windows driver reuses them. A recurring pattern is an `fdo_to_pdo` IN submission followed by a `pdo_to_fdo` response, then another submission under the same label. The final nonzero status therefore terminates the persistent IN stream—not an OUT command—and remains uninterpreted as an authentication result.

## Scope preserved

No driver replacement, firmware operation, enrollment, virtual-machine passthrough, custom USB transaction, or device reset is recorded for this experiment.

## Next step

Run the local-only bulk-header indexer against the private capture:

```powershell
py .\tools\usbpcap_bulk_index.py "C:\path\to\win-native-hello-001.pcap"
```

To correlate related bulk-header records without disclosing the underlying Windows IRP pointers, run:

```powershell
py .\tools\usbpcap_bulk_correlation.py "C:\path\to\win-native-hello-001.pcap"
```

Both tools skip all transfer payload bytes. Do not share the PCAP; share only the JSON output after removing entries that are clearly unrelated to the Goodix reader.
