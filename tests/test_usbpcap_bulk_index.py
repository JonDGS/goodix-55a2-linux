import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "usbpcap_bulk_index.py"


def load_module():
    spec = importlib.util.spec_from_file_location("usbpcap_bulk_index", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def usbpcap_header(*, bus: int, device: int, endpoint: int, transfer: int, data_length: int) -> bytes:
    return struct.pack(
        "<HQIHBHHBBI",
        27,  # header length
        0,  # IRP id intentionally uninteresting for this tool
        0,  # status
        0,
        0,
        bus,
        device,
        endpoint,
        transfer,
        data_length,
    )


class UsbPcapBulkIndexTests(unittest.TestCase):
    def test_indexes_bulk_endpoints_without_returning_payload_or_irp_id(self):
        module = load_module()
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
        first = usbpcap_header(bus=2, device=9, endpoint=0x01, transfer=3, data_length=5) + b"abcde"
        second = usbpcap_header(bus=2, device=9, endpoint=0x82, transfer=3, data_length=7) + b"1234567"
        records = (
            struct.pack("<IIII", 100, 0, len(first), len(first)) + first
            + struct.pack("<IIII", 101, 0, len(second), len(second)) + second
        )
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(global_header + records)
            handle.flush()
            index = module.index_bulk_transfers(Path(handle.name))

        self.assertEqual(index["format"], "usbpcap-bulk-index")
        self.assertEqual(index["bulk_transfer_count"], 2)
        self.assertEqual(index["bulk_data_bytes"], 12)
        self.assertEqual(index["bulk_transfers"][0]["endpoint"], "0x01")
        self.assertEqual(index["bulk_transfers"][0]["direction"], "out")
        self.assertEqual(index["bulk_transfers"][1]["endpoint"], "0x82")
        self.assertEqual(index["bulk_transfers"][1]["direction"], "in")
        self.assertNotIn("payload", index["bulk_transfers"][0])
        self.assertNotIn("irp_id", index["bulk_transfers"][0])


if __name__ == "__main__":
    unittest.main()
