# Comparison with Prior Work

> Updated after experiment 0014. The section "Comparison after experiments 0005–0014" supersedes older conclusions below where they conflict.

This note compares the project's payload-free observations with Th0mas Lambertz's 2021 work on the same Goodix `27c6:55a2` sensor. It does not reproduce, import, or disclose prior or current raw captures.

## Where the evidence agrees

| Topic | Prior work | This project | Assessment |
| --- | --- | --- | --- |
| Hardware target | Goodix `27c6:55a2` | Goodix `27c6:55a2`, revision `0100` | Same USB product target. |
| USB transport | Vendor-specific bulk protocol | Bulk OUT `0x01` and IN `0x82` | Direct match. |
| Message framing | Custom Goodix protocol; Wireshark Lua dissector | All inspected small envelopes use `0xa0`; declared lengths and checksum framing match the dissector's clear-message envelope | Strong framing match. |
| Image request | `McuGetImage` command family | Every observed 14,866-byte IN completion follows classified `2.0` / `McuGetImage` | Strong command-to-large-transfer match. |
| Image sensitivity | Large scan-time packets appeared random/encrypted or compressed | Large transfers remain unread and private | Same cautious conclusion. |

Sources: [Th0mas blog post](https://blog.th0m.as/misc/fingerprint-reversing/) and [upstream dissector](https://raw.githubusercontent.com/tlambertz/goodix-fingerprint-reversing/main/wireshark-dissector/goodix_message.lua).

## Important difference: large-transfer length

The blog reports scan-time large packets of 14,930 bytes. Our USBPcap metadata records 14,866-byte IN transfers, a difference of 64 bytes. This may be a capture-format/framing difference, a driver/firmware variation, or another protocol-layer distinction. It is an open discrepancy, not evidence that the devices differ. **Resolved by experiment 0013:** the reader's image frame body is 14,862 bytes; USBPcap's 14,866 adds the 4-byte frame header, so the image size is the same.

## TLS is not disproven

Prior work found TLS-PSK over USB after initialization. Our passive Windows captures began after the installed driver was already functioning and deliberately exclude large-transfer contents. Observing clear `0xa0` control envelopes in this later workflow does not prove that TLS is absent, bypassed, or unnecessary. It only establishes that these control messages were visible in clear framing at this stage.


Experiment 0004 adds a consistent negative: no `D.0` (RequestTlsConnection) or `D.2` (TlsSuccessfullyEstablished) appears in any unlock capture, so the TLS session is set up once at driver start and reused, as the prior-work startup flow predicts. Startup itself could not be captured (see `experiments/0004-early-driver-initialization-result.md`).

## New evidence from the controlled comparison

The prior work demonstrates image streaming after PSK control; it does not provide this project's controlled one-failure versus one-success comparison. Here, both outcomes share an initial setup sequence. The unsuccessful capture then requests three image-associated transfers and contains an additional `C.3`/`3.2` command-and-reply branch, whereas the successful capture requests one image-associated transfer and proceeds to state query and sleep.

This is a useful behavioral refinement, but it does not locate biometric matching or identify command arguments.

## Consequence for next work

The current observations validate using the prior dissector as a starting point. The safest next research layer is a reproducible initialization study that captures early driver startup under a recoverable setup, rather than exposing frame data or changing the PSK on the working Windows installation.


## Comparison after experiments 0005–0014

Sources: [blog post](https://blog.th0m.as/misc/fingerprint-reversing/) (27 May 2021) and
[`capture.py`](https://github.com/tlambertz/goodix-fingerprint-reversing/blob/0479ce9/capture.py)
at `0479ce9` (MIT).

### Where the results agree

| Topic | Prior work | This project |
| --- | --- | --- |
| Reader | `27c6:55a2` (AMD laptop) | `27c6:55a2` (Intel laptop) |
| Framing | `0xa0` commands, `0xb0` handshake, `0xb2` TLS image data | Same, confirmed on the wire |
| Encryption | TLS-PSK, set up once at driver load | Same (0004); reproduced from Linux (0005) |
| Image request | `0x20`, payload `01 00` | Same (0013) |
| Decrypted image | 14,788 bytes = 176 × 84 + 4 | 14,788 bytes (0013, 0014) |
| Pixel packing | 4 × 12-bit pixels in 6 bytes | Same formula; checked against the published example |
| Streaming | ~15–16 frames/s | Not tested (one image per run) |

### Where they differ

1. **Key handling.** Prior work overwrites the reader's PSK with a known
   all-zero key via a white-box blob. The Windows driver then re-keys on its
   next load. This project reads the sealed key Windows already stored,
   unseals it once on Windows and uses the same key from Linux. Nothing is
   written to the reader, so Windows and Linux can share it.
2. **Firmware.** Prior work: `GF3206_RTSEC_APP_10056` (logs also show a
   `GF3208` 10056 build). This reader: `GF3206_RTSEC_APP_10063`. No protocol
   difference has been observed.
3. **Start-up commands.** `capture.py` sends reset, register read, OTP read,
   a 256-byte chip-config upload (`9.0`) and more before TLS, commented
   "not needed?". This project sends none of them and still gets a ridge
   image (0014), so on this firmware they are not required.
4. **Image width.** The blog says 54 pixels per row, but 84 bytes × 8 / 12
   = 56, and `capture.py` uses 56. The 9,856 pixels observed here (56 × 176)
   agree with the code. The 54 comes from a sensor spec listing.
5. **Transfer length.** Prior work reports 14,930 bytes per image; this
   project's frame body is 14,862 bytes (14,866 with its 4-byte header). The
   64-byte difference is probably due to how the prior capture (usbmon, VM,
   128-byte reads) counted data. Likely, not proven.
6. **Capture trigger.** Prior work streams continuously, with the finger
   wait commented out. This project waits for the reader's finger-down event
   and takes one image, as the Windows driver does.
7. **Baseline appearance.** Prior work's empty image shows vertical lines.
   This project's empty image is described by the operator as grey blocks.
   Both suggest a fixed background pattern; the difference may be sensor
   revision, the missing chip config, or description. Background subtraction
   (planned 0015) should clarify it.

### Beyond the prior work

- Documented `A.7` state query, finger-down/up events with a verified
  `6.0` disarm, and a stale-frame check before every run.

### Not reproduced here

- Streaming frame rate, and writing a chosen PSK (not needed).
