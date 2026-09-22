"""Synthetic-only capture-controller tests; no real device or capture fixtures."""
import importlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
try:
    core = importlib.import_module("goodix_capture_core")
except ModuleNotFoundError:
    core = None


def pcap(records):
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
    for micros, endpoint, length, transfer in records:
        payload = b"private" * ((length + 6) // 7)
        payload = payload[:length]
        usb = struct.pack("<HQIHBHHBBI", 27, 123456789, 0, 9, 1, 2, 3,
                          endpoint, transfer, length) + payload
        out += struct.pack("<IIII", 1000 + micros // 1000000,
                           micros % 1000000, len(usb), len(usb)) + usb
    return out


class SummaryTests(unittest.TestCase):
    def test_descriptor_only_is_not_live_capture(self):
        self.assertIsNotNone(core, "capture core not implemented")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "test.pcap"
            path.write_bytes(pcap([(0, 0x80, 10, 2)]))
            result = core.summarize_capture(path, {(2, 3)})
        self.assertFalse(result["live_reader_traffic"])
        self.assertEqual(result["record_count"], 1)
        self.assertNotIn("private", str(result))
        self.assertNotIn("123456789", str(result))


class SessionTests(unittest.TestCase):
    def test_new_interface_creates_segment_and_marks_gap(self):
        self.assertTrue(hasattr(core, "CaptureSession"), "session controller missing")
        from types import SimpleNamespace
        class Recording:
            def __init__(self, interface, path):
                self.path = path
                self.stopped = False
            def start(self):
                self.path.write_bytes(pcap([(0, 0x80, 10, 2), (100, 0x82, 10, 3)]))
            def stop(self):
                self.stopped = True
                return True
            def running(self):
                return not self.stopped
        with tempfile.TemporaryDirectory() as d:
            reader = SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                     instance_id="PRIVATE_ID", driver_version="test")
            session = core.CaptureSession(Path(d), "warm-restart", Recording)
            session.start(reader)
            reader.interface = r"\\.\USBPcap3"
            session.observe(reader)
            report = session.finish()
            self.assertEqual(len(report["segments"]), 2)
            self.assertTrue(report["capture_gap"])
            self.assertFalse(report["continuous_capture"])
            self.assertNotIn("PRIVATE_ID", str(report))
            self.assertTrue((session.directory / "manifest.json").is_file())


class RestartTests(unittest.TestCase):
    def test_interrupt_after_disable_always_reenables(self):
        self.assertTrue(hasattr(core, "warm_restart"), "restart guard missing")
        from types import SimpleNamespace
        reader = SimpleNamespace(instance_id="EXACT_READER")
        class Backend:
            def __init__(self):
                self.enabled = True
                self.calls = []
            def discover(self):
                return reader
            def is_enabled(self, target):
                return self.enabled
            def set_enabled(self, target, enabled):
                self.calls.append(enabled)
                self.enabled = enabled
        backend = Backend()
        def interrupted(_):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            core.warm_restart(backend, reader, approved=True, emit=lambda *a: None,
                              pause=interrupted)
        self.assertEqual(backend.calls, [False, True])
        self.assertTrue(backend.enabled)
        with self.assertRaises(RuntimeError):
            core.warm_restart(backend, reader, approved=False, emit=lambda *a: None)
        self.assertEqual(backend.calls, [False, True])


class RecorderTests(unittest.TestCase):
    def test_manages_real_subprocess_with_synthetic_capture(self):
        self.assertTrue(hasattr(core, "USBPcapRecording"), "recorder missing")
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            fake = folder / "synthetic_recorder.py"
            header = pcap([])
            fake.write_text(
                "import pathlib,sys,time\n"
                "p=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
                f"p.write_bytes({header!r})\n"
                "while not p.with_suffix('.stop').exists(): time.sleep(.01)\n")
            path = folder / "capture.pcap"
            recorder = core.USBPcapRecording(
                [sys.executable, str(fake)], r"\\.\USBPcap2", path,
                stop_signal=lambda process: path.with_suffix('.stop').touch(),
                native_windows=False)
            recorder.start()
            self.assertTrue(recorder.running())
            self.assertTrue(recorder.stop())
            self.assertFalse(recorder.running())
            self.assertEqual(path.read_bytes(), header)


if __name__ == "__main__":
    unittest.main()
