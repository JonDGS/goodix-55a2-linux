# Experiment 0007 plan: decode the 2-byte A.7 state reply

Status: planned.

## Why

In experiment 0006 the reader answered `A.7` QueryMcuState with a plaintext
`0xa0` frame whose body is 2 bytes long. The bytes were not recorded. This
experiment records and decodes them.

## Is it safe to record them?

Prior work describes the reply as MCU status flags, not sensor data:

- tlambertz/goodix-fingerprint-reversing (55a2 dissector) reads byte 0 as
  bit flags: `0x01` isImageValid, `0x02` isTlsConnected, `0x04` isSpiSend,
  `0x08` isLocked.
- goodix-fp-dump (55a4/55b4 and others) reads the same four flags from
  byte 1, and a longer reply layout.

Two bytes cannot hold image, template or key material, so the bytes are
treated as non-identifying device state. They are printed in the report.

## What changes

Only the reporting of the existing `--query-state` run. No new command is
sent; the frames are the same as experiment 0006 (`0.0`, `A.4`, `D.0`, TLS
handshake, `D.2`, one `A.7` with payload `55`).

If the plaintext reply body is exactly 2 bytes, the report adds:

- `state_reply_hex`: the two bytes;
- `state_flags_byte0` and `state_flags_byte1`: the four flags read from each
  byte (both layouts, because prior work disagrees);
- `state_unknown_bits_byte0/1`: the upper four bits, which have no known name.

Any other length, and any TLS-protected reply, is still reported by shape
only.

## Expected result

Just after the handshake, `tls_connected` should be true in the correct
layout. That is how we tell which byte carries the flags.

## Run

Once, as root, from an interactive terminal on Fedora:

    sudo python3 -I -B tools/goodix_handshake.py --run --query-state

Afterwards, boot Windows and verify Windows Hello fingerprint unlock.

## Stop conditions

Same as experiment 0006. No retries.
