# Experiment 0003: Controlled Windows Hello Outcome Comparison

## Objective

Collect two short, private native-Windows USB captures that differ in one observable outcome only: one deliberately unsuccessful fingerprint attempt and one successful attempt. The comparison will be limited to metadata, framing, command-family, and relative-time analysis.

## Safety boundary

This experiment is passive. It does not enroll or delete fingerprints, change drivers, reset the reader, use a VM, send custom USB traffic, or publish any capture material.

Before either capture, verify that Windows password/PIN access works independently of the fingerprint reader.

## Common preparation

1. Turn Bluetooth off and close camera-using applications.
2. Prepare a local encrypted, non-cloud-synced folder outside the Git checkout.
3. Open an Administrator Command Prompt and launch USBPcapCMD.
4. Select `\\.\USBPcap2`, the root hub that contains the Goodix reader at Port 9.
5. Record the USBPcap and Wireshark versions in a private local manifest.

## Capture A: single unsuccessful attempt

1. Begin capture and wait about two seconds.
2. Lock Windows with `Win+L`.
3. Make **one** intentionally unsuccessful fingerprint attempt—e.g. an incomplete placement.
4. Do not retry fingerprint verification. Use PIN/password to unlock.
5. Stop capture within 60 seconds.
6. Confirm the fingerprint sign-in option remains available; do not perform any recovery action unless it has actually failed.
7. Store the original capture locally as `win-hello-fail-001.pcap`.

## Capture B: single successful attempt

1. Begin a separate capture and wait about two seconds.
2. Lock Windows with `Win+L`.
3. Make **one** normal successful fingerprint attempt.
4. Stop capture within 60 seconds after reaching the desktop.
5. Store the original capture locally as `win-hello-success-001.pcap`.
6. Confirm Windows Hello works once more after capture.

## Stop conditions

Stop immediately if Windows requests re-enrollment, the reader vanishes/reconnects, a tool prompts for a driver or firmware change, or Windows Hello stops working. Use PIN/password recovery first; do not perform further protocol experiments.

## Analysis boundary

Run only the repository's local metadata, bulk-cycle, relative-timeline, envelope, and command-family tools against each capture. Keep original PCAP files private. Share only reviewed JSON outputs; never share raw captures, large IN payloads, templates, credentials, or message bodies.

## Expected comparison

For each capture, record the command-family sequence, count and relative positions of large IN completions, and final IN completion status. Interpret differences as hypotheses until reproduced.
