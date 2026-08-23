# Experiment 0002 Result: Native Windows Passive Capture

## Outcome

A private capture named `win-native-hello-001.pcap` was collected on the known-working native Windows installation, following the constrained capture plan.

- Action captured: one ordinary Windows Hello fingerprint verification.
- Original capture handling: retained locally; not committed, uploaded, or shared with this repository.
- Post-capture Windows Hello verification: **pass**.

## Scope preserved

No driver replacement, firmware operation, enrollment, virtual-machine passthrough, custom USB transaction, or device reset is recorded for this experiment.

## Next step

Use a local-only metadata inspector to determine the capture container type and packet-level volume without displaying or exporting payload bytes. Do not share the original capture; share only the inspector's metadata output after review.
