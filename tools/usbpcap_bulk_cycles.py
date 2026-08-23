#!/usr/bin/env python3
"""Pair USBPcap bulk submissions with completions without reading payloads."""

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
USBPCAP_INFO_PDO_TO_FDO = 0x01


def index_bulk_cycles(path: Path) -> dict[str, Any]:
    """Create anonymous submit/complete cycles from USBPcap bulk headers only."""
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

        aliases: dict[int, str] = {}
        cycle_counts: dict[int, int] = {}
        pending: dict[int, int] = {}
        cycles: list[dict[str, int | str | None]] = []
        record_index = 0
        while pcap_header := capture.read(16):
            if len(pcap_header) != 16:
                raise ValueError("truncated PCAP packet header")
            _, _, included_length, _ = struct.unpack("<IIII", pcap_header)
            record_index += 1
            if included_length < USBPCAP_HEADER_LENGTH:
                raise ValueError("USBPcap record is shorter than its base header")
            header = capture.read(USBPCAP_HEADER_LENGTH)
            if len(header) != USBPCAP_HEADER_LENGTH:
                raise ValueError("truncated USBPcap base header")
            (
                header_length, irp_id, status, _function, info, bus, device,
                endpoint, transfer, data_length,
            ) = struct.unpack(USBPCAP_HEADER_FORMAT, header)
            if header_length < USBPCAP_HEADER_LENGTH or header_length > included_length:
                raise ValueError("invalid USBPcap header length")
            capture.seek(included_length - USBPCAP_HEADER_LENGTH, 1)
            if capture.tell() > file_size:
                raise ValueError("truncated PCAP record")
            if transfer != USBPCAP_TRANSFER_BULK:
                continue

            operation = aliases.setdefault(irp_id, f"op-{len(aliases) + 1:03d}")
            is_completion = bool(info & USBPCAP_INFO_PDO_TO_FDO)
            if not is_completion:
                cycle_counts[irp_id] = cycle_counts.get(irp_id, 0) + 1
                cycle = {
                    "cycle": f"{operation}.cycle-{cycle_counts[irp_id]:03d}",
                    "operation": operation,
                    "bus": bus,
                    "device": device,
                    "endpoint": f"0x{endpoint:02x}",
                    "submitted_record_index": record_index,
                    "submitted_data_length": data_length,
                    "completion_record_index": None,
                    "completion_data_length": None,
                    "completion_status": None,
                }
                cycles.append(cycle)
                pending[irp_id] = len(cycles) - 1
            elif irp_id in pending:
                cycle = cycles[pending.pop(irp_id)]
                cycle["completion_record_index"] = record_index
                cycle["completion_data_length"] = data_length
                cycle["completion_status"] = f"0x{status:08x}"
            else:
                cycle_counts[irp_id] = cycle_counts.get(irp_id, 0) + 1
                cycles.append(
                    {
                        "cycle": f"{operation}.cycle-{cycle_counts[irp_id]:03d}",
                        "operation": operation,
                        "bus": bus,
                        "device": device,
                        "endpoint": f"0x{endpoint:02x}",
                        "submitted_record_index": None,
                        "submitted_data_length": None,
                        "completion_record_index": record_index,
                        "completion_data_length": data_length,
                        "completion_status": f"0x{status:08x}",
                    }
                )

    return {
        "format": "usbpcap-bulk-cycles",
        "cycle_count": len(cycles),
        "cycles": cycles,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pair USBPcap bulk headers without printing payloads or IRP pointers."
    )
    parser.add_argument("capture", type=Path, help="local USBPcap classic PCAP file")
    args = parser.parse_args()
    print(json.dumps(index_bulk_cycles(args.capture), indent=2))


if __name__ == "__main__":
    main()
