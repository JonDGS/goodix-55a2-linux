#!/usr/bin/env python3
"""Index USBPcap bulk-transfer headers without reading transfer payloads."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


PCAP_MAGIC_LITTLE_MICROSECONDS = b"\xd4\xc3\xb2\xa1"
PCAP_LINKTYPE_USBPCAP = 249
USBPCAP_HEADER_FORMAT = "<HQIHBHHBBI"
USBPCAP_HEADER_LENGTH = struct.calcsize(USBPCAP_HEADER_FORMAT)
USBPCAP_TRANSFER_BULK = 3


def index_bulk_transfers(path: Path) -> dict[str, Any]:
    """Return bulk endpoint metadata; transfer payload bytes are never read."""
    file_size = path.stat().st_size
    with path.open("rb") as capture:
        if capture.read(4) != PCAP_MAGIC_LITTLE_MICROSECONDS:
            raise ValueError("expected a little-endian, microsecond-resolution classic PCAP")
        global_rest = capture.read(20)
        if len(global_rest) != 20:
            raise ValueError("truncated PCAP global header")
        _, _, _, _, _, linktype = struct.unpack("<HHIIII", global_rest)
        if linktype != PCAP_LINKTYPE_USBPCAP:
            raise ValueError(f"expected USBPcap linktype {PCAP_LINKTYPE_USBPCAP}, got {linktype}")

        transfers: list[dict[str, int | str]] = []
        record_index = 0
        while record_header := capture.read(16):
            if len(record_header) != 16:
                raise ValueError("truncated PCAP packet header")
            _, _, included_length, _ = struct.unpack("<IIII", record_header)
            record_index += 1
            if included_length < USBPCAP_HEADER_LENGTH:
                raise ValueError("USBPcap record is shorter than its base header")
            header = capture.read(USBPCAP_HEADER_LENGTH)
            if len(header) != USBPCAP_HEADER_LENGTH:
                raise ValueError("truncated USBPcap base header")
            (
                header_length,
                _irp_id,
                status,
                function,
                _info,
                bus,
                device,
                endpoint,
                transfer,
                data_length,
            ) = struct.unpack(USBPCAP_HEADER_FORMAT, header)
            if header_length < USBPCAP_HEADER_LENGTH or header_length > included_length:
                raise ValueError("invalid USBPcap header length")
            remaining = included_length - USBPCAP_HEADER_LENGTH
            capture.seek(remaining, 1)
            if capture.tell() > file_size:
                raise ValueError("truncated PCAP record")
            if transfer == USBPCAP_TRANSFER_BULK:
                transfers.append(
                    {
                        "record_index": record_index,
                        "bus": bus,
                        "device": device,
                        "endpoint": f"0x{endpoint:02x}",
                        "direction": "in" if endpoint & 0x80 else "out",
                        "data_length": data_length,
                        "status": f"0x{status:08x}",
                        "urb_function": f"0x{function:04x}",
                    }
                )

    return {
        "format": "usbpcap-bulk-index",
        "bulk_transfer_count": len(transfers),
        "bulk_data_bytes": sum(int(item["data_length"]) for item in transfers),
        "bulk_transfers": transfers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Index USBPcap bulk headers without printing transfer payload bytes."
    )
    parser.add_argument("capture", type=Path, help="local USBPcap classic PCAP file")
    args = parser.parse_args()
    print(json.dumps(index_bulk_transfers(args.capture), indent=2))


if __name__ == "__main__":
    main()
