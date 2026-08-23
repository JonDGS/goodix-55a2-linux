import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools" / "usbpcap_bulk_timeline.py"

def load_module():
    spec = importlib.util.spec_from_file_location("usbpcap_bulk_timeline", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def record(irp_id, info, endpoint, length):
    return struct.pack("<HQIHBHHBBI", 27, irp_id, 0, 9, info, 2, 3, endpoint, 3, length) + b"x" * length

class TimelineTests(unittest.TestCase):
    def test_emits_relative_offsets_without_wall_clock_timestamps(self):
        module = load_module()
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
        submitted = record(42, 0, 0x82, 0)
        completed = record(42, 1, 0x82, 10)
        content = (global_header
            + struct.pack("<IIII", 100, 500000, len(submitted), len(submitted)) + submitted
            + struct.pack("<IIII", 102, 250000, len(completed), len(completed)) + completed)
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(content); handle.flush()
            timeline = module.index_bulk_timeline(Path(handle.name))
        cycle = timeline["cycles"][0]
        self.assertEqual(cycle["submitted_offset_us"], 0)
        self.assertEqual(cycle["completion_offset_us"], 1_750_000)
        self.assertNotIn("timestamp", cycle)
        self.assertNotIn("irp_id", cycle)
        self.assertNotIn("payload", cycle)

if __name__ == "__main__": unittest.main()
