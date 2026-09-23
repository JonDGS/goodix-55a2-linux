# Upstream and Prior Research

This project begins as a clean repository so it can apply stricter artifact-review and privacy rules. It is nevertheless directly informed by the following prior work.

## Primary reference

- Th0mas, **“Reversing a Fingerprint Reader Protocol”** (27 May 2021):
  <https://blog.th0m.as/misc/fingerprint-reversing/>
- `tlambertz/goodix-fingerprint-reversing`:
  <https://github.com/tlambertz/goodix-fingerprint-reversing>

The reference repository is MIT-licensed. It contains scripts, logs, captures, patches, and a Wireshark dissector for the same USB ID, `27c6:55a2`.

## Later prior work

- `goodix-fp-linux-dev/goodix-fp-dump` (MIT, last reviewed at commit `cc43bb3`):
  <https://github.com/goodix-fp-linux-dev/goodix-fp-dump>. Python tooling for
  several Goodix sensors, including the related `55a4`/`55b4`. It does not
  list `55a2`. Its `goodix.py` command constants fill in the command map in
  `PROTOCOL_LEDGER.md`.
- `goodix-fp-linux-dev/libfprint`, branch `goodixtls` (LGPL-2.1): a libfprint
  driver for other TLS-based Goodix sensors. It does not support `55a2`.

The Lambertz repository was last reviewed at commit `0479ce9`.

## Reuse policy

When code or documentation is copied or adapted from the reference repository:

1. retain the applicable MIT copyright and license notice;
2. name the original file and commit in the receiving file or its documentation;
3. review any associated data before importing it; and
4. do not import biometric data, secrets, or traces whose provenance and redaction are unclear.

This repository is not affiliated with the prior researcher. Bugs, claims, and releases here are our own responsibility.
