"""Boundary and recovery regressions for the capture helper (synthetic input)."""
import ctypes
import io
import contextlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import goodix_capture as cli
import goodix_capture_core as core
import goodix_console as console
from test_goodix_capture_core import pcap


class BoundaryTests(unittest.TestCase):
    def test_invalid_original_length_rejected(self):
        blob = bytearray(pcap([(0, 0x82, 10, 3)]))
        struct.pack_into("<I", blob, 36, 1)  # original smaller than captured
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.pcap"
            path.write_bytes(blob)
            with self.assertRaises(ValueError):
                core.summarize_capture(path, {(2, 3)})

    def test_other_device_not_counted_as_reader(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "other.pcap"
            path.write_bytes(pcap([(0, 0x82, 10, 3)]))
            self.assertFalse(core.summarize_capture(path, {(2, 4)})["live_reader_traffic"])

    def test_incomplete_record_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "broken.pcap"
            path.write_bytes(pcap([(0, 0x82, 10, 3)])[:-1])
            with self.assertRaises(ValueError):
                core.summarize_capture(path, {(2, 3)})

    def test_git_output_refused(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / ".git").mkdir()
            with self.assertRaises(ValueError):
                core.CaptureSession(folder / "captures", "success", None)

    def test_private_session_names_do_not_collide(self):
        with tempfile.TemporaryDirectory() as d:
            one = core.CaptureSession(Path(d), "success", None)
            two = core.CaptureSession(Path(d), "success", None)
            self.assertNotEqual(one.directory, two.directory)

    def test_console_input_layout(self):
        self.assertEqual(ctypes.sizeof(console.KeyEvent), 16)
        self.assertEqual(ctypes.sizeof(console.InputRecord), 20)
        self.assertEqual(console.InputRecord.event.offset, 4)

    def test_interface_argument_is_not_arbitrary_command(self):
        with self.assertRaises(ValueError):
            core.USBPcapRecording("USBPcapCMD.exe", "USBPcap2;anything", Path("unused"))

    def test_recovery_refuses_nonexistent_backup(self):
        answers = iter(["yes", "/does-not-exist/driver-backup"])
        with self.assertRaises(RuntimeError):
            cli.recovery_approval(lambda _: next(answers))

    def test_recovery_requires_exact_per_run_confirmation(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            answers = iter(["yes", d, "yes", "yes"])
            with self.assertRaises(RuntimeError):
                cli.recovery_approval(lambda _: next(answers))

    def test_changed_reader_never_disabled(self):
        changes = []
        backend = SimpleNamespace(discover=lambda: SimpleNamespace(instance_id="different"),
                                  is_enabled=lambda r: True,
                                  set_enabled=lambda r, state: changes.append(state))
        with self.assertRaises(RuntimeError):
            core.warm_restart(backend, SimpleNamespace(instance_id="original"),
                              approved=True, emit=lambda *a: None)
        self.assertEqual(changes, [])

    def test_failed_disable_still_attempts_restore(self):
        changes = []
        reader = SimpleNamespace(instance_id="same")
        def change(r, enabled):
            changes.append(enabled)
            if not enabled:
                raise RuntimeError("disable state uncertain")
        backend = SimpleNamespace(discover=lambda: reader, is_enabled=lambda r: True,
                                  set_enabled=change)
        with self.assertRaises(RuntimeError):
            core.warm_restart(backend, reader, approved=True, emit=lambda *a: None)
        self.assertEqual(changes, [False, True])

    def test_failed_restore_has_explicit_recovery_error(self):
        reader = SimpleNamespace(instance_id="same")
        changes = []
        def change(r, enabled):
            changes.append(enabled)
            if enabled:
                raise RuntimeError("enable failed")
        backend = SimpleNamespace(discover=lambda: reader, is_enabled=lambda r: True,
                                  set_enabled=change)
        with self.assertRaisesRegex(RuntimeError, "READER RECOVERY FAILED"):
            core.warm_restart(backend, reader, approved=True, emit=lambda *a: None,
                              pause=lambda _: None)
        self.assertEqual(changes, [False, True, True])


if __name__ == "__main__":
    unittest.main()
