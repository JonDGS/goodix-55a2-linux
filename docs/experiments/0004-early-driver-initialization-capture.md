# Experiment 0004: Recoverable Early Driver Initialization Capture

## Objective

Capture the beginning of the installed Goodix Windows driver's communication with the known-working `27c6:55a2` reader, without replacing the driver, changing enrollment, writing a PSK, sending custom USB traffic, or exposing packet contents.

The primary question is whether a normal driver restart produces an initialization exchange compatible with the PSK validation and TLS startup flow reported by the prior reverse-engineering work.

## Why a new capture is needed

The existing private Windows Hello captures began after the installed driver and reader were already operational. Their clear `0xa0` runtime envelopes therefore do not establish whether initialization used TLS, whether a PSK was checked, or whether the driver followed a different warm-start path.

A software restart of the installed device is the lowest-risk useful first step. It may still differ from a cold boot or true power loss, so a negative result must not be interpreted as proof that the cold-start path lacks PSK or TLS handling.

## Safety classification

This is **not fully passive**: disabling and re-enabling the device restarts its installed driver and interrupts fingerprint service temporarily. It remains substantially narrower than driver replacement, VM passthrough, firmware work, enrollment changes, PSK experiments, or custom USB commands.

The capture itself is observational. Windows and the installed Goodix driver remain the only components allowed to communicate with the reader.

## Required recovery gate

Do not begin until every item below is confirmed:

- Windows password or PIN login works without the fingerprint reader.
- The current reader still reports hardware ID `USB\VID_27C6&PID_55A2&REV_0100` and Goodix driver `3.1.581.610`.
- The current driver package's published INF name is recorded. It was previously `oem158.inf`, but must be checked again because published INF numbers can change.
- A known-good copy of the installed Goodix driver package or the laptop vendor's matching installer is available locally.
- The driver-restoration route has been written down and can be used without fingerprint authentication.
- The raw-capture destination is encrypted, local, outside the Git checkout, and excluded from cloud sync.
- USBPcap is already installed and a short ordinary capture has been verified not to break Windows Hello.
- No pending Windows or driver update will run during the experiment.

If any item is uncertain, stop at this gate. Recovery plans are most useful before they become autobiographical.

## Explicit prohibitions

During this experiment, do not:

- uninstall, update, replace, or roll back the Goodix driver;
- remove or re-enroll any fingerprint;
- delete the device from Device Manager;
- select an option to remove driver software;
- run the upstream proof-of-concept against the device;
- read, export, compare, or modify any PSK or device credential;
- use VM USB passthrough, WinUSB/libusb, firmware tools, or custom USB transactions;
- inspect or publish transfer bodies from the resulting capture; or
- perform a cold boot merely to obtain a different initialization path.

## Stage 0: recovery rehearsal

Perform this stage without changing the reader:

1. Confirm PIN/password login by locking and unlocking Windows without touching the sensor.
2. Open Device Manager and locate the Goodix reader under **Biometric devices**.
3. Record the current device status, hardware ID, driver provider, version, and published INF name in the private experiment manifest.
4. Confirm the known-good driver package or vendor installer can be reached from the Windows installation while offline.
5. Record the recovery order:
   1. re-enable the device if it is disabled;
   2. scan for hardware changes;
   3. restart Windows and use PIN/password;
   4. restore the recorded driver package only if the device remains unavailable;
   5. stop all fingerprint research until ordinary Windows Hello operation is restored.
6. Cancel the experiment if the current metadata differs from the established working baseline or Windows Hello is already degraded.

## Stage 1: warm driver-restart capture

This is the only capture stage approved by this plan.

1. Turn Bluetooth off and close applications likely to use USB cameras or other devices on the same root hub.
2. Open an elevated command prompt and start USBPcap on the previously verified root-hub filter. Write to a new file in the private capture directory.
3. Wait about two seconds and verify the capture process is still running.
4. In Device Manager, disable the Goodix biometric device. Do not uninstall it and do not remove its driver.
5. Wait about two seconds.
6. Re-enable the same device.
7. Wait no more than 15 seconds for initialization traffic, then stop the capture. Do not attempt a fingerprint scan while recording.
8. Confirm Device Manager reports normal operation.
9. Lock Windows and perform one ordinary Windows Hello verification after the capture has stopped.
10. Record pass/fail and the capture duration in the private manifest.
11. Before leaving Windows, verify the PCAP spans real elapsed time and contains records after any injected descriptor preamble. A small file containing only same-timestamp descriptors is not a lifecycle capture and should be retained as an unsuccessful attempt, not analyzed as initialization evidence.

Keep the window short. USBPcap records the selected root hub, not an abstract promise to mind its own business.

## Immediate stop conditions

Stop the capture and make no further device changes if:

- Device Manager offers to uninstall, update, or replace the driver;
- the reader repeatedly disconnects or changes identity;
- the device cannot be re-enabled immediately;
- Windows requests fingerprint re-enrollment;
- Windows Hello no longer offers fingerprint sign-in;
- the capture tool requests installation or filter changes; or
- any unexpected firmware, security, credential, or PSK prompt appears.

Use PIN/password, follow the recorded recovery order, and do not repeat the experiment until the original working state is restored.

## Private manifest

Record locally, without publishing machine-specific identifiers:

- Windows build;
- Goodix driver provider, version, and published INF name;
- USBPcap and Wireshark versions;
- selected USBPcap root-hub filter;
- capture start/stop method and duration;
- Device Manager disable, enable, and final status;
- post-capture Windows Hello verification result; and
- whether recovery was needed and where the known-good driver package came from.

Do not put serial numbers, user names, absolute private paths, raw timestamps, device credentials, or capture payloads in a public result.

## Analysis ladder

Analyze the private capture locally and stop at the first layer that answers the transport question:

1. Run the repository PCAP metadata inspector.
2. Run the payload-free USBPcap bulk-header indexer.
3. Confirm the expected Goodix bulk endpoints `0x01` OUT and `0x82` IN after re-enable.
4. Run anonymous correlation, cycle, and relative-timeline tools.
5. Run the small-envelope classifiers only on transfer sizes they already accept. Large IN transfers remain unread and excluded.
6. Compare the early command-family and transfer-length sequence with the existing runtime captures and the prior-work initialization description.

Do not classify a byte sequence as TLS solely because it is not a clear `0xa0` envelope. Record only framing, direction, length, relative ordering, and evidence boundaries until a non-sensitive discriminator is defined and tested.

## Success criteria

The experiment succeeds operationally only if all of the following are true:

- the capture spans disable, re-enable, and driver initialization;
- the expected Goodix endpoints reappear;
- Windows Hello works after the capture;
- no recovery action, enrollment change, driver change, or custom device command occurred; and
- a payload-free derivative can describe whether the early exchange differs from the established runtime sequence.

A technically useful outcome may be any of:

- an initialization-only sequence not present in runtime captures;
- evidence of a warm-start path that omits the prior-work PSK/TLS setup;
- evidence insufficient to distinguish clear framing from a TLS handshake; or
- no Goodix initialization traffic because the restart method did not recreate the relevant device lifecycle.

The latter three are not failures and do not justify escalating automatically.

## Escalation gate

Do not proceed directly to cold-boot capture, power-cycle experiments, VM passthrough, PSK access, or protocol replay.

First publish a reviewed, payload-free result for Stage 1 and decide whether a stronger lifecycle event is necessary. Any cold-start design must separately explain how capture starts before the Goodix driver initializes, how the machine recovers if the biometric device fails, and why the expected evidence cannot be obtained from the warm restart.

## Public result template

A future result document may include:

- whether the recovery gate passed;
- whether the capture covered the intended lifecycle;
- payload-free packet counts, endpoint directions, transfer lengths, relative timing, and command-family labels;
- comparison with the prior runtime captures and upstream initialization claims;
- post-capture Windows Hello status; and
- explicit unknowns and the next decision gate.

It must not include the PCAP, message bodies, large-transfer contents, PSKs, credentials, templates, biometric frames, IRP pointers, serial numbers, or unreviewed host metadata.

## References

- [Experiment 0001 result: working Windows reference](0001-windows-reference-result.md)
- [Experiment 0002 result: native Windows passive capture](0002-windows-native-passive-capture-result.md)
- [Comparison with prior work](../PRIOR_WORK_COMPARISON.md)
- [Protocol ledger](../PROTOCOL_LEDGER.md)
- [USBPcap usage documentation](https://desowin.org/usbpcap/tour.html)
- [Th0mas Lambertz's Goodix reverse-engineering repository](https://github.com/tlambertz/goodix-fingerprint-reversing)
