# Experiment 0001 Result: Working Windows Reference

## Observation

A native dual-boot Windows installation on the same physical laptop reports a working Goodix fingerprint reader with the following driver metadata:

| Field | Observed value |
| --- | --- |
| Provider | Goodix |
| Driver date | 2021-07-14 |
| Driver version | `3.1.581.610` |
| INF name | `oem158.inf` |
| Hardware ID | `USB\VID_27C6&PID_55A2&REV_0100` |
| Compatible hardware ID | `USB\VID_27C6&PID_55A2` |
| Windows Hello fingerprint sign-in | Working normally |

## Interpretation

This establishes a known-working reference driver on the exact `27c6:55a2`, revision `0100` device recorded in the Fedora baseline. It bounds the initial reverse-engineering target to the Goodix Windows driver version `3.1.581.610`.

No capture, enrollment, driver replacement, firmware update, virtual-machine passthrough, or custom USB transaction was performed as part of this observation.

## Next gate

Before a passive capture is attempted, define the capture tool, the sanitization process, and the recovery plan for the working Windows enrollment. See [Experiment 0001 protocol](0001-windows-reference-capture.md).
