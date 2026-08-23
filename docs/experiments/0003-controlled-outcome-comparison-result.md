# Experiment 0003 Result: Controlled Windows Hello Outcome Comparison

## Evidence boundary

This comparison uses only local, payload-free metadata: container statistics, anonymous bulk cycles, relative offsets, four-byte outbound envelopes, and one-byte command-family classification. Original PCAP files and all transfer/message bodies remain private.

Command names below are supplied by the MIT-licensed upstream dissector and are treated as prior-work labels rather than independently proven semantics.

## Observed difference

Both captures share the same initial command-family sequence through record 64:

```text
A.7 → 0.0 → D.3 → 3.1 → 3.1 → 2.0 → 3.3 → 3.2
```

The **successful** capture then emits one additional `3.2`, followed by `A.7` and `6.0`. It has one `2.0` (`McuGetImage`) command at record 52 and one correlated 14,866-byte IN completion at record 56.

The **unsuccessful** capture diverges after the shared prefix:

```text
C.3 → 3.2 → 2.0 → 2.0 → 3.1 → A.7 → 6.0
```

It has three `2.0` (`McuGetImage`) commands at records 52, 80, and 86. Each is correlated with a 14,866-byte IN completion at records 56, 84, and 90 respectively.

## Current interpretation

The outcome comparison supports a narrow, reproducible observation: this driver/reader path requests one image-associated transfer in the successful capture and three in the unsuccessful capture. The extra failure-path sequence also includes the `C.3` command family, labelled `McuSetLedState` by prior work.

This does **not** establish why Windows accepted or rejected the scan, the meaning of image data, or the location of biometric matching. Those questions require further controlled evidence.

## Next investigation

Compare only non-sensitive reply metadata for the command families that differ after the shared prefix, before considering any additional command-body or image handling.
