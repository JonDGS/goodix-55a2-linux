import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "usbpcap_bulk_correlation.py"


def load_module():
    spec = importlib.util.spec_from_file_location("usbpcap_bulk_correlation", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def usbpcap_record(irp_id: int, info: int, endpoint: int, data_length: int) -> bytes:
    header = struct.pack(
        "<HQIHBHHBBI",
        27,
        irp_id,
        0,
        9,
        info,
        2,
        3,
        endpoint,
        3,
        data_length,
    )
    return header + (b"x" * data_length)


class UsbPcapBulkCorrelationTests(unittest.TestCase):
    def test_replaces_irp_pointer_with_stable_operation_label(self):
        module = load_module()
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
        outbound = usbpcap_record(0xDEADBEEF, 0, 0x01, 64)
        inbound = usbpcap_record(0xDEADBEEF, 1, 0x82, 10)
        content = (
            global_header
            + struct.pack("<IIII", 100, 0, len(outbound), len(outbound)) + outbound
            + struct.pack("<IIII", 101, 0, len(inbound), len(inbound)) + inbound
        )
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(content)
            handle.flush()
            index = module.correlate_bulk_transfers(Path(handle.name))

        self.assertEqual(index["bulk_record_count"], 2)
        self.assertEqual(index["operation_count"], 1)
        self.assertEqual(index["records"][0]["operation"], "op-001")
        self.assertEqual(index["records"][1]["operation"], "op-001")
        self.assertEqual(index["records"][0]["flow"], "fdo_to_pdo")
        self.assertEqual(index["records"][1]["flow"], "pdo_to_fdo")
        self.assertNotIn("irp_id", index["records"][0])
        self.assertNotIn("payload", index["records"][0])


if __name__ == "__main__":
    unittest.main()
