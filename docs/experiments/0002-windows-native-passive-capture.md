# Experiment 0002: Native Windows Passive USB Capture Plan

## Decision

Use **USBPcap with Wireshark** for one short, native-Windows passive capture of an already-working Windows Hello fingerprint verification.

USBPcap is an open-source Windows USB capture driver with Wireshark support. This experiment deliberately uses the existing Windows installation rather than USB passthrough to a new virtual machine, because a new environment could initialize the sensor differently or change its state.

References:

- USBPcap: <https://desowin.org/usbpcap/>
- Wireshark USB capture guidance: <https://wiki.wireshark.org/CaptureSetup/USB>

## Risk assessment

Installing USBPcap adds a Windows capture driver and requires a restart according to its documentation. That is a **conscious, bounded system change**, not a harmless viewer installation.

Expected benefit: a short trace of the normal working driver and one Windows Hello verification.

Primary risks:

- a capture may contain biometric image data, device state, or cryptographic material;
- the capture-driver installation may affect USB behavior until removed; and
- any later attempt to reset, re-enumerate, provision, or virtualize the reader could disrupt the working enrollment.

This experiment does **not** include device reset, disable/enable cycles, a new user, a driver update, enrollment, firmware operations, or custom USB traffic.

## Prerequisites

Before installing anything:

- Confirm the Windows password or PIN works without a fingerprint.
- Record the known-good driver metadata from Experiment 0001.
- Ensure at least one normal Windows Hello fingerprint verification succeeds.
- Reserve an encrypted, local-only folder outside this Git checkout for the capture and its manifest.
- Decide in advance that the original capture will not be uploaded, committed, or pasted into chat.

## Capture procedure

1. Download USBPcap only from its official site or linked official project release.
2. Install it and restart Windows if the installer requests it.
3. Open Wireshark and select the USBPcap interface corresponding to the USB controller that contains the Goodix reader. Do not guess from the Linux bus number; Windows controller numbering is independent.
4. Start the capture.
5. Perform exactly **one** ordinary Windows Hello fingerprint verification. Do not enter enrollment, device-management, or driver-update screens.
6. Stop the capture immediately—target duration: under 60 seconds.
7. Verify that Windows Hello still works once more after stopping the capture.
8. Save the original capture only in the local encrypted folder. Do not open it in cloud-synced storage.

## Local manifest

Create a text file beside the capture containing only:

```text
capture_id: win-native-hello-001
capture_tool: USBPcap <version> + Wireshark <version>
windows_version: <edition/build>
goodix_driver: 3.1.581.610 (2021-07-14, oem158.inf)
action: one ordinary Windows Hello fingerprint verification
started_at: <local timestamp>
duration_seconds: <value>
post_capture_hello: pass|fail
notes: <USB controller selected; no biometric or personal values>
```

## Stop conditions and recovery

Stop immediately if Windows Hello fails unexpectedly, the reader reconnects repeatedly, Windows requests re-enrollment, or any tool offers a firmware/driver update or reset.

If the reader no longer works, do not experiment further. First restore the known-good Windows driver state and re-establish password/PIN access. Record only the symptom and recovery steps; never publish captures from a failed state without a separate sensitivity review.

## Handling after capture

The next project step is **local review and sanitization design**, not public release. The original trace remains private. Any future shareable artifact must be derived, minimal, and reviewed for biometric content, keys, unique identifiers, and personal information.
