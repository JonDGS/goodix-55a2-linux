# Experiment 0004 result: warm-restart initialization capture

Status: **stopped; startup traffic not captured.** USBPcap cannot record a
warm restart on this system. This record uses transfer headers, sizes,
timing and one command byte per outbound message only. No packet bodies,
image data or key material were read.

## Setup

- Hardware: Goodix `27c6:55a2`, Windows driver `3.1.581.610`, Windows Hello
  working throughout.
- Capture: USBPcap `1.5.4.0` via the repository's Windows capture CLI
  (`warm-restart` scenario), recording the whole root hub with
  `-A --capture-from-new-devices --inject-descriptors`.
- Each run disabled and re-enabled only the verified reader through PnP, after
  the recovery checks and a separate approval for each run. Fingerprint
  unlock was checked after every run and always worked.

## Runs

| Run | Tool | USBPcap state before | Result |
| --- | --- | --- | --- |
| 1 | 0.2.0 | working | One bulk burst ~8.6 s after disable: `0.0` → `D.3` → `C.2`, each with a small reply, ending in a canceled IN. Nothing after re-enable. A false PnP failure (fixed in #2) ended the run early. |
| 2 | 0.2.1 | not rechecked | Only injected descriptors. |
| 3 | 0.2.1 | working (after reboot) | Same shutdown burst as run 1. Nothing after re-enable, not even standard enumeration of the re-enabled device. |
| 4 | 0.2.2 | not rechecked | Both segments only injected descriptors. |
| 5 | 0.2.2 | working (after reboot) | Segment 1: shutdown burst. Segment 2 (a new recorder started after re-enable, #3): only injected descriptors for 60 s, including a lock-screen interval. |

After run 5 an ordinary Wireshark/USBPcap capture of a fingerprint unlock
also recorded nothing, while the unlock itself worked. A Windows restart
restored capture each time.

## Findings

1. **USBPcap stops delivering after a PnP disable/re-enable** of the reader,
   to every consumer (including Wireshark), until Windows restarts. Starting a
   new recorder does not help. So warm-restart capture with USBPcap cannot
   observe driver startup.
2. **The shutdown burst is `0.0` (NOP) → `D.3` (PovImageCheck, `0xd6`) →
   `C.2` (SetDrvState, `0xc4`).** The earlier `goodix-reenable-001` capture had
   the same burst and was almost certainly shutdown, not initialization.
3. **Every re-enable moved the reader to a new USB address.** The CLI already
   records the whole hub, so this is not a capture gap by itself.
4. **Boot capture is not available:** USBPcap `1.5.4.0` has no boot-time
   capture option.
5. **In-box Windows USB tracing is not a substitute.** A short ETW trace of the
   USB 3 stack (`USB-USBXHCI`, `USB-UCX`, `USB-USBHUB3`, all keywords,
   verbose) during one unlock gave bulk dispatch/complete events with
   pointers, pipe handles, status, endpoint and byte counts, but no transfer
   contents.

## Consequence

Startup traffic stays unobserved in this project. The prior-work startup
sequence (see `../PRIOR_WORK_COMPARISON.md`) is consistent with everything
observed here but remains unconfirmed on this device.
