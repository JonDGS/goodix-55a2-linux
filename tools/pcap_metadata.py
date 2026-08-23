#!/usr/bin/env python3
"""Summarize a classic PCAP container without emitting packet payloads."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1": ("<", "little", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "big", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "little", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "big", "nanoseconds"),
}


def summarize_pcap(path: Path) -> dict[str, Any]:
    """Return container metadata and lengths from a classic PCAP file only."""
    with path.open("rb") as capture:
        magic = capture.read(4)
        if magic not in MAGIC_NUMBERS:
            raise ValueError("not a supported classic PCAP file")
        byte_format, byte_order, resolution = MAGIC_NUMBERS[magic]
        rest = capture.read(20)
        if len(rest) != 20:
            raise ValueError("truncated PCAP global header")
        _, _, _, _, snaplen, linktype = struct.unpack(byte_format + "HHIIII", rest)

        packet_count = 0
        captured_bytes = 0
        original_bytes = 0
        first_timestamp: int | None = None
        last_timestamp: int | None = None
        while header := capture.read(16):
            if len(header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, _, included_length, original_length = struct.unpack(
                byte_format + "IIII", header
            )
            capture.seek(included_length, 1)
            if capture.tell() > path.stat().st_size:
                raise ValueError("truncated PCAP packet payload")
            packet_count += 1
            captured_bytes += included_length
            original_bytes += original_length
            if first_timestamp is None:
                first_timestamp = seconds
            last_timestamp = seconds

    return {
        "format": "pcap",
        "byte_order": byte_order,
        "timestamp_resolution": resolution,
        "snaplen": snaplen,
        "linktype": linktype,
        "packet_count": packet_count,
        "captured_bytes": captured_bytes,
        "original_bytes": original_bytes,
        "first_timestamp_seconds": first_timestamp,
        "last_timestamp_seconds": last_timestamp,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize classic PCAP metadata without printing packet payloads."
    )
    parser.add_argument("capture", type=Path, help="local classic PCAP file")
    args = parser.parse_args()
    print(json.dumps(summarize_pcap(args.capture), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
