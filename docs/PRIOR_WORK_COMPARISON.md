# Comparison with Prior Work

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

The blog reports scan-time large packets of 14,930 bytes. Our USBPcap metadata records 14,866-byte IN transfers, a difference of 64 bytes. This may be a capture-format/framing difference, a driver/firmware variation, or another protocol-layer distinction. It is an open discrepancy, not evidence that the devices differ.

## TLS is not disproven

Prior work found TLS-PSK over USB after initialization. Our passive Windows captures began after the installed driver was already functioning and deliberately exclude large-transfer contents. Observing clear `0xa0` control envelopes in this later workflow does not prove that TLS is absent, bypassed, or unnecessary. It only establishes that these control messages were visible in clear framing at this stage.

## New evidence from the controlled comparison

The prior work demonstrates image streaming after PSK control; it does not provide this project's controlled one-failure versus one-success comparison. Here, both outcomes share an initial setup sequence. The unsuccessful capture then requests three image-associated transfers and contains an additional `C.3`/`3.2` command-and-reply branch, whereas the successful capture requests one image-associated transfer and proceeds to state query and sleep.

This is a useful behavioral refinement, but it does not locate biometric matching or identify command arguments.

## Consequence for next work

The current observations validate using the prior dissector as a starting point. The safest next research layer is a reproducible initialization study that captures early driver startup under a recoverable setup, rather than exposing frame data or changing the PSK on the working Windows installation.
