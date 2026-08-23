import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "usbpcap_bulk_cycles.py"


def load_module():
    spec = importlib.util.spec_from_file_location("usbpcap_bulk_cycles", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def usbpcap_record(irp_id: int, info: int, endpoint: int, data_length: int, status: int = 0) -> bytes:
    header = struct.pack(
        "<HQIHBHHBBI",
        27, irp_id, status, 9, info, 2, 3, endpoint, 3, data_length
    )
    return header + (b"x" * data_length)


class UsbPcapBulkCyclesTests(unittest.TestCase):
    def test_pairs_each_submission_with_the_next_completion_for_same_allocation(self):
        module = load_module()
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
        submitted = usbpcap_record(0xDEADBEEF, 0, 0x82, 0)
        completed = usbpcap_record(0xDEADBEEF, 1, 0x82, 14866)
        content = (
            global_header
            + struct.pack("<IIII", 100, 0, len(submitted), len(submitted)) + submitted
            + struct.pack("<IIII", 101, 0, len(completed), len(completed)) + completed
        )
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(content)
            handle.flush()
            result = module.index_bulk_cycles(Path(handle.name))

        self.assertEqual(result["cycle_count"], 1)
        cycle = result["cycles"][0]
        self.assertEqual(cycle["cycle"], "op-001.cycle-001")
        self.assertEqual(cycle["submitted_record_index"], 1)
        self.assertEqual(cycle["completion_record_index"], 2)
        self.assertEqual(cycle["completion_data_length"], 14866)
        self.assertNotIn("payload", cycle)
        self.assertNotIn("irp_id", cycle)


if __name__ == "__main__":
    unittest.main()
