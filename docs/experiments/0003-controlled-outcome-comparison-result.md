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

## Small-reply envelope comparison

All inspected small replies use the same clear envelope flag, `0xa0`. The successful capture has 16 small reply envelopes with declared-length frequencies `{5: 1, 6: 13, 28: 2}`. The unsuccessful capture has 22 with `{5: 2, 6: 17, 28: 3}`.

Both captures share the early non-6-byte reply metadata at records 40, 50, and 62. The unsuccessful path adds a 5-byte declared reply at record 72 and a 28-byte declared reply at record 78, alongside additional 6-byte replies. This is consistent with the already observed branch after the shared command prefix; no reply bodies were read.

## Small-reply command-family comparison

The one-byte reply classification shows that both captures share the early reply sequence through record 62, including `B.0` acknowledgements, `A.7` state replies, `D.3` image-check replies, `3.1` FDT-down replies, and `3.3` FDT-mode replies.

Only the unsuccessful path contains a `C.3` reply at record 72 and a `3.2` reply at record 78. These correspond in sequence to the failure-path-only outbound `C.3` and `3.2` command families. The successful path proceeds to its final state query and sleep sequence without those observed reply-family events.

The labels are sourced from prior work; this establishes a repeatable message-family difference, not argument values or device-state semantics.

## Next investigation

Compare only non-sensitive reply metadata for the command families that differ after the shared prefix, before considering any additional command-body or image handling.
