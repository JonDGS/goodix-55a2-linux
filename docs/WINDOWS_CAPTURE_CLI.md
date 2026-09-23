# Goodix capture CLI — Windows pilot

A command-line Python helper for **Goodix `27c6:55a2`**, using the installed
USBPcap driver. No GUI, pip packages, Wireshark UI, or fingerprint driver replacement
is required. This is research tooling, not a fingerprint authentication driver.

**Status: experimental pilot, ordinary capture validated on one machine.**
Portable logic and synthetic subprocess tests pass on Linux. On the pilot
laptop, version 0.2.0 recorded one ordinary successful fingerprint unlock end to
end: exact-reader discovery (bus 2, address 3), 82 records over about 16 s, 58
reader bulk records including one large incoming transfer, no truncation, no
capture gap, valid output. Folder ACL effectiveness and PnP restart are not
Windows-validated.

**Do not proceed to warm restart** without the separate recovery gate and
explicit per-run approval.

## Current pilot findings

- Recording uses a standard-output pipe (`-o -`); see
  [Recorder transport](#recorder-transport-and-stopping). The earlier
  console-quit approach and its diagnostics are superseded.
- Empty-port discovery initially failed because a full USB connection response
  returned `NoDeviceConnected` with `ConnectionIndex` zero. The SDK marks this
  field INPUT. The narrow fix accepts zero only for that empty-port state; short
  responses, connected/unhealthy port mismatches, and other nonzero mismatches
  remain rejected.
- The reader's USB address changes between boots (1, 2 and 3 have been
  observed). Always use the address from a fresh `discover`, never one from an
  earlier session.
- **Known issue: USBPcap can stop delivering transfers until Windows restarts.**
  In that state every capture, including Wireshark's own extcap capture,
  contains only the injected descriptors (zero time span), although Windows
  Hello unlocks succeed. Discovery and recorder startup look normal. A full
  Windows restart restored capture. The trigger is unknown. Symptom check: a
  session reporting `live_reader_traffic: false` with only descriptor records
  after a real unlock; confirm with one Wireshark capture before debugging the
  helper.
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
| `warm-restart` | After safety checks and typing `RESTART 27c6:55a2`, the helper records, disables only the verified reader, waits briefly, and re-enables it. After re-enable it rediscovers the reader and starts a fresh recording segment (`segment-002.pcap`), because a recorder that was already running did not deliver the re-enabled device in testing. The hand-over is a planned rotation, so `continuous_capture` is false. Do not touch the sensor during capture. Finish, then verify Windows Hello afterward. |
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

### Output readiness

The recorder is **output-ready** once the helper has received and validated the
PCAP global header from the pipe while the recorder is still running. If that
does not happen within 10 seconds, startup fails closed.

While recording, the UI reports output bytes only, which include all hub
traffic and descriptor injection; it is not evidence of reader activity. The
payload-free PCAP/USBPcap validation runs at session finish for every segment
whose stream is valid, including an idle recorder terminated after the grace
period. A corrupt or unreadable stream marks the segment incomplete and skips
automatic validation.

### Recorder transport and stopping

USBPcapCMD writes the capture to its standard output (`-o -`). The helper reads
that pipe and writes the private PCAP itself, committing only complete records,
so a forced recorder exit cannot leave a torn record on disk. Standard input is
the null device; no console, `AttachConsole` or injected `q` is used.

To stop, the helper drains buffered records and closes its end of the pipe; the
recorder exits on its next failed write (`stop_method: exited_after_pipe_close`).
An **idle** recorder has nothing to write and cannot notice, so after a
5-second grace period it is terminated (`terminated_after_grace`). The file is
still valid. The manifest records both:

- `graceful_stop` stays strict: true only for a self-exit after pipe close.
- `orderly_stop` is true for an operator-requested stop with a valid stream,
  including termination of an idle recorder. It is false for an unrequested
  recorder exit or a corrupt/unreadable stream.

Only an unrequested exit or an invalid stream marks a `capture_gap`. Driver-side
drops under back-pressure are not visible in the stream. A Windows kill-on-close
Job Object limits orphan recordings if the controller exits abnormally.

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
