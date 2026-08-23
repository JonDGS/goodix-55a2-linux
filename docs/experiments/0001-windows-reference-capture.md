# Experiment 0001: Windows Reference Driver and Passive Capture

## Objective

Record enough information about a known-working Windows deployment of the Goodix `27c6:55a2` reader to guide Linux protocol work, while preserving the owner's existing Windows Hello enrollment.

## Risk boundary

The reference research for this sensor describes TLS-PSK provisioning and a workflow that replaces the device's PSK. A fresh driver, virtual machine, different Windows user, enrollment flow, or protocol tool may therefore alter device state and could leave the current Windows enrollment unusable until it is repaired or re-enrolled.

**This experiment is read-only.** It does not create a VM, add a Windows account, enroll a finger, install an alternate driver, write registry values, reset the device, or transmit custom USB requests.

Before continuing, ensure the owner has a working Windows password or PIN that does not depend on fingerprint sign-in.

Reference: Th0mas, [“Reversing a Fingerprint Reader Protocol”](https://blog.th0m.as/misc/fingerprint-reversing/).

## Phase A — record public driver metadata

In Windows Device Manager:

1. Locate the Goodix fingerprint device.
2. Record the **Driver** tab fields: provider, date, version, and INF name.
3. Record the Hardware Ids property.
4. Confirm that Windows Hello fingerprint sign-in still works normally.

Safe-to-share evidence is a text transcription or redacted screenshot of those fields. Do not publish an export of the complete driver package without first reviewing its license and contents.

## Phase B — optional passive USB capture

A Windows-side USB capture is useful, but it is sensitive: it can contain device state, encrypted traffic, or biometric image data.

1. Install and use a USB capture tool only on the Windows installation already known to work.
2. Capture the Goodix device's USB controller while performing a normal, existing Windows Hello verification.
3. Stop the capture immediately after one successful or failed verification.
4. Store the original capture locally in an encrypted directory, outside the Git checkout.
5. Create a small manifest with timestamp, Windows version, driver version, capture-tool version, and the exact action performed.

Never commit or attach the original capture to an issue, pull request, or chat. Do not assume TLS encryption makes a biometric capture safe to publish.

## Stop conditions

Stop and preserve the original state if any of the following happens:

- Windows Hello no longer recognizes the device.
- The device disappears or begins reconnecting repeatedly.
- Windows requests fingerprint re-enrollment unexpectedly.
- A tool asks to update firmware, reset a sensor, replace a driver, or install a filter driver.
- A capture contains raw frames, key material, or personal information.

## Deferred work

The following are explicitly out of scope until the passive evidence is assessed and a recovery plan is written:

- USB passthrough to a virtual machine.
- A fresh Windows account or driver installation.
- Debugging or patching the Windows driver.
- Any experiment that provisions or changes the sensor's TLS state.
- Publishing packet captures or imported artifacts from prior projects.

## Expected deliverable

A private manifest and, if desired, a redacted text record of the driver metadata. The project will then define a sanitization and analysis path before handling any capture.
