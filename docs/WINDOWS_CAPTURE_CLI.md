# Goodix capture CLI — Windows pilot

A command-line Python helper for **Goodix `27c6:55a2`**, using the installed
USBPcap driver. No GUI, pip packages, Wireshark UI, or fingerprint driver replacement
is required. This is research tooling, not a fingerprint authentication driver.

**Status: paused experimental checkpoint.** Portable logic and synthetic
subprocess tests pass on Linux. The Windows pilot has confirmed exact-reader
discovery after the empty-port fix, and output-ready metadata was visible during
recording. Orderly recorder shutdown is unresolved: the saved session reports
`graceful_stop: false` and `validation_error: orderly_stop_unconfirmed`, so packet
validation was skipped. Successful fingerprint unlock was operator-reported, not
established by capture analysis. Folder ACL effectiveness, console/process cleanup,
full capture operation, and PnP restart are not Windows-validated.

**Do not proceed to warm restart.** Resume with the saved stopped-file inspection
and shutdown diagnostics below, not repeated biometric recordings.

## Current pilot findings and resume point

- Empty-port discovery initially failed because a full USB connection response
  returned `NoDeviceConnected` with `ConnectionIndex` zero. The SDK marks this
  field INPUT. The narrow fix accepts zero only for that empty-port state; short
  responses, connected/unhealthy port mismatches, and other nonzero mismatches
  remain rejected. Subsequent native discovery succeeded.
- An ordinary-unlock attempt reached output-ready and displayed output bytes.
  Its manifest recorded `operator_finish`, then `recorder_stopped` with
  `graceful: false`. No packet summary was produced. `live_reader_traffic: false`
  therefore means unvalidated here, not proof that reader traffic was absent.
- The current manifest does not distinguish a helper launch/attachment/input
  failure, unexpected recorder exit, nonzero exit code, or shutdown timeout.
  The exact cause is unknown. Do not weaken orderly-stop requirements to make the
  report appear successful.
- Preserve unsuccessful captures privately. Inspect the existing stopped segment
  locally using `inspect` and its session bus/address; a parseable file does not
  retroactively establish continuity or a clean shutdown. Confirm
  `goodix_console.py` is beside the other modules. Next investigate bounded,
  privacy-safe shutdown diagnostics before another recording.
- Do not publish raw captures, local manifests, personal paths, or device instance
  identifiers. No raw pilot artifacts are included in this repository.

## Requirements

- Windows with the existing working Goodix driver and USBPcap already installed.
- Python 3.10 or later (`py -3 --version`). No third-party Python packages.
- PowerShell opened **as Administrator**. The helper does not silently elevate.
- A private folder on encrypted local storage, outside Git and cloud sync.
- Stop other USBPcap/Wireshark recording sessions before starting this helper.
- For restart: tested PIN/password access, matching local driver backup/installer,
  no pending Windows/driver update, and explicit confirmation on every run.

The program does not install drivers, change firmware/PSKs, access enrollments,
perform cold boots, use VM passthrough, or send custom Goodix commands.

## Run from the standalone source bundle

Extract the entire ZIP. Keep all Python files together. From that directory:

```powershell
# First pilot: read-only exact hardware discovery. No recording or restart.
py -3 .\goodix_capture.py discover

# Interactive menu: choose scenario and private output folder.
py -3 .\goodix_capture.py

# Or select an ordinary-unlock pilot explicitly.
py -3 .\goodix_capture.py capture --scenario success --output 'D:\PrivateCaptures'
```

From a repository checkout, replace `.\goodix_capture.py` with
`.\tools\goodix_capture.py`. Output must remain outside the checkout.

If USBPcap is installed elsewhere:

```powershell
py -3 .\goodix_capture.py discover --usbpcap 'C:\custom\USBPcapCMD.exe'
```

`--usbpcap` is also accepted by `capture`. `--seconds` sets a **soft** recording
time budget, between 10 and 120 seconds; the default is 60. It is checked between
monitor iterations, not enforced by an independent watchdog. PowerShell subprocess
calls and recorder waits have timeouts, but native discovery uses synchronous
`DeviceIoControl` without a cancellation deadline. A stalled native IOCTL can
block discovery, delay handling Enter, and delay reaching cleanup indefinitely.
Native filesystem metadata queries are synchronous too. The time budget, polling
size limit, and mapping-loss grace interval are not hard wall-clock guarantees.

## Scenarios

| Name | What happens |
| --- | --- |
| `success` | Start; perform one ordinary fingerprint unlock; return and press Enter. |
| `failure` | Start; make one unsuccessful scan; use PIN/password, not another scan; finish. |
| `warm-restart` | After safety checks and typing `RESTART 27c6:55a2`, the helper records, disables only the verified reader, waits briefly, and re-enables it. Do not touch the sensor during capture. Finish, then verify Windows Hello afterward. |
| `activation` | With the reader already enabled, record opening the Windows lock screen without touching the sensor; return using PIN and finish. This is a no-finger client-activation study, not another restart. |

The program does not itself lock Windows or decide whether a fingerprint matched.
It asks you to report the outcome after recording stops. A transport-valid capture
is not evidence of a successful authentication or complete initialization.

## Discovery and capture behavior

The helper locates the exact USB VID/PID and resolves the current USBPcap root-hub
mapping. It must refuse zero or ambiguous matches rather than select a friendly
name or equate Device Manager physical port numbers with USB device addresses.

It records **all connected and newly connected devices on the identified root hub**,
with descriptor injection, snaplen 65535, and a 1048576-byte kernel buffer. This is
intentional: address-only capture filters are unsafe across re-enumeration. Other
hub devices may appear even if their applications are idle. Disable unrelated
Bluetooth activity and close camera applications where practical.

During capture, the helper periodically re-discovers the reader. An interface
change starts a new file and marks a recording gap; it does not pretend that USB
traffic lost before discovery was recovered. Merely changing address within an
already-recorded hub does not require restarting the recorder.

Any discovery failure immediately marks a conservative, sticky `capture_gap`,
including a failure immediately after restart. Later discovery recovery does not
clear it: continuity through the uncertain interval cannot be established. Enter
or expiration of the time budget while mapping is unavailable cannot yield a
continuous-success report. The recorder can continue briefly on its current hub
while discovery retries, but its output is not proof of the reader's mapping.

### Output readiness is metadata only

USBPcapCMD opens the `-o` file with `GENERIC_WRITE`, **share mode 0**, and
`CREATE_NEW` ([pinned source, lines 866–872](https://github.com/desowin/usbpcap/blob/477b6edcbd7e99a47f77afc0c4168a9ebee603bb/USBPcapCMD/cmd.c#L866-L872)).
The helper therefore does not try to open/read the PCAP while recording. It calls
[`GetFileAttributesExW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesexw)
for metadata and requires a reported size of at least 24 bytes **and** a running
recorder before declaring **output-ready**. This is more than liveness alone, but
it is not validation of those bytes as a PCAP header.

Microsoft's [`CreateFileW` sharing contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew#parameters)
explicitly exempts attribute access from sharing restrictions;
[`WIN32_FILE_ATTRIBUTE_DATA`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-win32_file_attribute_data)
includes the high/low file-size fields. This is the documented basis for the
metadata-only approach, not a claim of a completed Windows runtime test. Size
visibility and update timing with the installed USBPcap and local filesystem must
be checked in the pilot. If the minimum size is not visible within the readiness
polling budget, startup fails closed; it never falls back to liveness-only success.

While recording, the UI reports **output bytes only**, which include all hub
traffic and descriptor injection. There are no live reader-packet counts or live
header checks. Metadata size is not a flush/durability guarantee or evidence of
reader activity. The full payload-free PCAP/USBPcap validation runs at session
finish, only for segments whose recorder stopped orderly. An unconfirmed/forced
stop marks the segment incomplete and skips automatic validation.

USBPcapCMD uses Windows console input events for `q`; writing `q` to a subprocess
stdin pipe is insufficient. The helper owns an isolated recorder console and sends
that console a quit event. Failure to stop cleanly forces termination and marks the
capture as potentially incomplete. A Windows kill-on-close Job Object limits
orphan recordings if the controller exits abnormally.

## Files and privacy

Every run creates a unique `goodix-<scenario>-<random>/` session directory:

- `segment-001.pcap`, and additional numbered files if the interface changes;
- `manifest.json`, containing scenario, relative event times, discovered bus/address
  mappings, capture validation, cleanup state, and the operator-reported outcome.

The program restricts the new Windows session directory to the current user and
SYSTEM before recording, using the absolute system Windows PowerShell executable
under `SystemRoot` rather than searching the working directory or `PATH`.
This is **access control, not encryption**. It cannot
verify that a drive is encrypted or detect every sync client; you must confirm the
storage choice. It does not upload anything or overwrite existing captures.

The validator reads only container and USBPcap headers. It never reads transfer
bodies, descriptor strings, TLS/PSK data, fingerprint images or templates, and never
emits raw IRP pointers or the PnP instance identifier. Raw PCAPs still contain
whatever the Windows driver and other hub devices exchanged. Keep them private.
The metadata manifest is a local diagnostic, not automatically approved for public
publication.

## Interpreting the result

- **Recorder output-ready** means metadata reports at least 24 output bytes and
  the recorder is alive, not that a valid PCAP header or reader traffic was seen.
- **Reader data observed in stopped capture** requires data-bearing bulk records
  at a discovered reader address and its expected endpoints, validated after an
  orderly stop. Descriptor-only captures fail this. The manifest retains the
  field name `live_reader_traffic`; it is a post-stop result, not a live UI counter.
- **Continuous capture** means no recorder gap or mapping uncertainty was detected. It does not prove
  USBPcap saw every transaction or that a full startup/TLS handshake was captured.
- Event offsets are relative to the helper session; packet offsets are relative to
  the first packet. Do not treat these as identical clock origins.
- A same-address device replacement can defeat address-only offline attribution;
  the tool is for a short controlled session, not arbitrary hot-plug monitoring.
- The reported Windows Hello outcome comes from the operator, never packet sizes.
- Capture exit code 0: live reader traffic and no detected capture gap; 2: incomplete
  or no-live-data capture; 1: operational failure. Offline `inspect` returns 0 for a
  parseable file, even if it contains no live traffic.

Offline inspection (works on Linux too):

```powershell
py -3 .\goodix_capture.py inspect .\segment-001.pcap --bus 2 --address 3
```

Use the mapping from that session's manifest, not numbers from an older capture.

## Pilot acceptance gates

1. `discover` reports exactly the owned `27c6:55a2` reader, its current USBPcap
   interface/address, enabled state, and driver version. Compare locally with Device
   Manager; do not publish instance IDs or serials.
2. Run `success`: confirm output-ready appears while the recorder is still active
   and the byte display updates without opening the locked PCAP. Confirm Enter
   stops the recorder, the process exits, and **post-stop** validation reports real
   bulk traffic rather than only descriptors. Verify Windows Hello still works.
   A readiness timeout or missing size updates is a failed metadata pilot, not a
   reason to accept recorder liveness alone or proceed to restart.
3. Only then run `warm-restart`: confirm recovery prompts cannot be skipped, timing
   events record disable and re-enable, and Windows Hello works after capture.
4. Confirm private folder permissions, unique filenames, no unwanted recorder left
   running, and explicit incomplete status for any forced-stop or interface-gap case.
5. Preserve unsuccessful runs; do not retry indefinitely or escalate to cold boot,
   firmware changes, PSK changes, driver replacement, or VM passthrough.

## Recovery

An ordinary Ctrl+C during an automated restart enters a restoration block that
attempts to re-enable the same verified reader before stopping recording. A forced
kill, terminal destruction, machine crash or power loss can interrupt any program;
there is no promise of automatic recovery in those cases.

If the reader remains disabled or Windows Hello stops working: stop research, use
PIN/password, re-enable Goodix in Device Manager, scan for hardware changes, and
restart Windows if needed. Restore the matching driver only if the working state
cannot otherwise be recovered. Never uninstall the reader or delete its driver as
part of a capture experiment.

If finalization cannot save the manifest, the helper still attempts recorder
cleanup and preserves any original failure (especially `READER RECOVERY FAILED`)
instead of replacing it with a metadata-write error. A finalization warning means
the on-disk manifest may be incomplete; do not infer successful recovery from it.

## Developer verification

```text
python3 -m unittest discover -s tests -v
```

Tests use synthetic fixtures and injected device/process adapters; they are not
claims of physical Windows validation. Real private PCAP files may be inspected
locally with `inspect`, but must never become committed fixtures.
Review regressions simulate exclusive data-open denial with a real synthetic
recorder, metadata-only startup and byte display, post-stop malformed capture
rejection, mapping failure followed by Enter/deadline (including after restart),
and manifest failure during failed reader recovery. Native metadata ABI calls use
an injected API, not a Windows execution environment.

References: [USBPcap source](https://github.com/desowin/usbpcap),
[USBPcap usage](https://desowin.org/usbpcap/tour.html),
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
