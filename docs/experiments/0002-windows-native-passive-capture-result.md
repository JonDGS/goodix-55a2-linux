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

## Cycle index result

The stream resolves into 52 anonymous submit/complete cycles: 33 cycles on the persistent `op-001` IN stream and 19 cycles for 64-byte OUT submissions. The four large IN completions are precisely located at:

- `op-001.cycle-010` (records 55–56)
- `op-001.cycle-019` (records 83–84)
- `op-001.cycle-021` (records 89–90)
- `op-001.cycle-025` (records 101–102)

The final nonzero completion is `op-001.cycle-033` (records 127–128). This provides a complete transport-level sequence but no wall-clock or payload evidence for assigning an individual large completion to the failed or successful scan.

## Relative timeline result

The four large IN completions occur at relative offsets 2.099131 s, 2.829337 s, 2.873400 s, and 3.021803 s from the first indexed bulk record. Their successive gaps are 730.206 ms, 44.063 ms, and 148.403 ms; they occupy a 922.672 ms window.

This timing is compatible with activity from the two recorded scan attempts, but it does not prove which completion belongs to which attempt. The final persistent IN cycle remained pending for 5.010069 s before the nonzero completion, which is consistent with capture shutdown ending an outstanding read, but remains an interpretation rather than a decoded status.

## Outbound envelope result

All 19 observed outbound envelopes use flags `0xa0`, consistent with the clear Goodix message-pack framing described by the upstream dissector. Declared message-length frequencies are 5 bytes (1), 6 bytes (6), 7 bytes (2), 8 bytes (1), and 26 bytes (9). Each appears inside a 64-byte USB OUT transfer, so the USB transport length is not the declared message length.

For this capture, each observed checksum equals the low byte of `0xa0 + declared_length`; this is a capture-specific framing hypothesis, not yet a validated checksum rule. No command byte or message body has been read or recorded.

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

Both tools skip all transfer payload bytes. To pair each submission with its corresponding completion under a per-capture anonymous cycle label, run:

```powershell
py .\tools\usbpcap_bulk_cycles.py "C:\path\to\win-native-hello-001.pcap"
```

Do not share the PCAP; share only the JSON output after removing entries that are clearly unrelated to the Goodix reader.

To align cycles to the two scan attempts without disclosing wall-clock time, run:

```powershell
py .\tools\usbpcap_bulk_timeline.py "C:\path\to\win-native-hello-001.pcap"
```

For the next protocol layer, this local-only tool reads the four-byte Goodix envelope header on 64-byte outbound messages and omits every message body:

```powershell
py .\tools\goodix_outbound_envelopes.py "C:\path\to\win-native-hello-001.pcap"
```

The next local-only tool reads one command byte and emits only its split category/command fields, never the raw byte or message body:

```powershell
py .\tools\goodix_outbound_commands.py "C:\path\to\win-native-hello-001.pcap"
```

The resulting command-family evidence is maintained in [`docs/PROTOCOL_LEDGER.md`](../PROTOCOL_LEDGER.md); no payload data is included.
