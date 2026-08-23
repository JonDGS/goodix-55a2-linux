import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "pcap_metadata.py"


def load_module():
    spec = importlib.util.spec_from_file_location("pcap_metadata", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PcapMetadataTests(unittest.TestCase):
    def test_summarize_classic_little_endian_pcap_without_returning_payload(self):
        module = load_module()
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
        packets = (
            struct.pack("<IIII", 100, 50, 3, 3) + b"abc"
            + struct.pack("<IIII", 102, 75, 5, 7) + b"xxxxx"
        )
        with tempfile.NamedTemporaryFile(suffix=".pcap") as handle:
            handle.write(header + packets)
            handle.flush()
            summary = module.summarize_pcap(Path(handle.name))

        self.assertEqual(summary["format"], "pcap")
        self.assertEqual(summary["byte_order"], "little")
        self.assertEqual(summary["timestamp_resolution"], "microseconds")
        self.assertEqual(summary["linktype"], 249)
        self.assertEqual(summary["packet_count"], 2)
        self.assertEqual(summary["captured_bytes"], 8)
        self.assertEqual(summary["original_bytes"], 10)
        self.assertEqual(summary["first_timestamp_seconds"], 100)
        self.assertEqual(summary["last_timestamp_seconds"], 102)
        self.assertNotIn("payload", summary)


if __name__ == "__main__":
    unittest.main()
