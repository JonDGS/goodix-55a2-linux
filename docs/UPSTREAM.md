# Upstream and Prior Research

This project begins as a clean repository so it can apply stricter artifact-review and privacy rules. It is nevertheless directly informed by the following prior work.

## Primary reference

- Th0mas, **“Reversing a Fingerprint Reader Protocol”** (27 May 2021):
  <https://blog.th0m.as/misc/fingerprint-reversing/>
- `tlambertz/goodix-fingerprint-reversing`:
  <https://github.com/tlambertz/goodix-fingerprint-reversing>

The reference repository is MIT-licensed. It contains scripts, logs, captures, patches, and a Wireshark dissector for the same USB ID, `27c6:55a2`.

## Reuse policy

When code or documentation is copied or adapted from the reference repository:

1. retain the applicable MIT copyright and license notice;
2. name the original file and commit in the receiving file or its documentation;
3. review any associated data before importing it; and
4. do not import biometric data, secrets, or traces whose provenance and redaction are unclear.

This repository is not affiliated with the prior researcher. Bugs, claims, and releases here are our own responsibility.
