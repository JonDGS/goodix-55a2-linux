"""CLI tests use synthetic PCAP files and never touch a Windows device."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "goodix_capture.py"


class CLITests(unittest.TestCase):
    def test_offline_inspect_works_without_windows(self):
        self.assertTrue(SCRIPT.exists(), "CLI not implemented")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "synthetic.pcap"
            path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249))
            run = subprocess.run([sys.executable, str(SCRIPT), "inspect", str(path),
                                  "--bus", "2", "--address", "3"],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertFalse(result["live_reader_traffic"])


    def test_discover_refuses_non_windows_without_importing_native_backend(self):
        import os
        if os.name == "nt":
            self.skipTest("Linux platform guard test")
        run = subprocess.run([sys.executable, str(SCRIPT), "discover"],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn("requires Windows", run.stderr)

    def test_capture_refreshes_mapping_after_user_prompts(self):
        sys.path.insert(0, str(SCRIPT.parent))
        import goodix_capture as cli
        from types import SimpleNamespace
        from test_goodix_capture_core import pcap
        started = []
        phase = [2]
        def reader():
            return SimpleNamespace(interface=rf"\\.\USBPcap{phase[0]}", bus=2,
                                   address=3, instance_id="SAME", driver_version="test")
        backend = SimpleNamespace(discover=reader, is_enabled=lambda r: True)
        class Recording:
            def __init__(self, interface, path):
                started.append(interface)
                self.path = path
            def start(self):
                self.path.write_bytes(pcap([(0, 0x82, 10, 3)]))
            def stop(self):
                return True
        def ask(prompt):
            if "START" in prompt:
                phase[0] = 4
                return ""
            return "yes"
        with tempfile.TemporaryDirectory() as d:
            cli.run_capture(backend, "unused", "success", Path(d), 60, ask=ask,
                            monitor=lambda *a: None, recording_factory=Recording)
        self.assertEqual(started, [r"\\.\USBPcap4"])

    def test_capture_workflow_records_reported_outcome(self):
        sys.path.insert(0, str(SCRIPT.parent))
        import goodix_capture as cli
        self.assertTrue(hasattr(cli, "run_capture"), "interactive workflow missing")
        from types import SimpleNamespace
        from test_goodix_capture_core import pcap
        reader = SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                 instance_id="PRIVATE", driver_version="test")
        backend = SimpleNamespace(discover=lambda: reader, is_enabled=lambda r: True)
        class Recording:
            def __init__(self, interface, path):
                self.path = path
            def start(self):
                self.path.write_bytes(pcap([(0, 0x80, 10, 2), (100, 0x82, 10, 3)]))
            def stop(self):
                return True
        replies = iter(["yes", "", "yes"])
        with tempfile.TemporaryDirectory() as d:
            report = cli.run_capture(backend, "unused", "success", Path(d), 60,
                                     ask=lambda _: next(replies),
                                     monitor=lambda *args: None,
                                     recording_factory=Recording)
            self.assertEqual(report["operator_outcome"], "yes")
            self.assertTrue(report["live_reader_traffic"])


if __name__ == "__main__":
    unittest.main()
