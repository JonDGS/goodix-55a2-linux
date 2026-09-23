"""Synthetic tests for the stdout-pipe recorder; no Windows or USB access.

USBPcapCMD writes to standard output with ``-o -`` (cmd.c:860-863) and stops
capturing when a write fails (thread.c:132-137). The controller owns the PCAP
file, writing only validated whole records, so a forced recorder exit cannot
leave a torn record on disk.
"""
import ctypes
import os
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import goodix_capture_core as core
import goodix_pipe_capture as pipe

GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)


def record(bus=2, address=3, endpoint=0x82, payload=b"", seconds=1):
    usb = struct.pack("<HQIHBHHBBI", 27, 7, 0, 9, 1, bus, address, endpoint, 3,
                      len(payload)) + payload
    return struct.pack("<IIII", seconds, 0, len(usb), len(usb)) + usb


def synthetic(folder: Path, body: str) -> list[str]:
    script = folder / "synthetic_usbpcap.py"
    script.write_text(PREAMBLE + textwrap.dedent(body))
    return [sys.executable, str(script)]


PREAMBLE = f"""
import os, struct, sys, time
out = sys.stdout.buffer
GLOBAL = {GLOBAL!r}
def record(n):
    usb = struct.pack("<HQIHBHHBBI", 27, n, 0, 9, 1, 2, 3, 0x82, 3, 4) + b"data"
    return struct.pack("<IIII", 1, n, len(usb), len(usb)) + usb
assert sys.argv[sys.argv.index("-o") + 1] == "-", "recorder must stream to stdout"
"""


class WriterTests(unittest.TestCase):
    def test_writes_only_whole_records_regardless_of_chunking(self):
        stream = GLOBAL + record(payload=b"abcd") + record(endpoint=0x01)
        with tempfile.TemporaryDirectory() as d:
            whole, split = Path(d) / "whole.pcap", Path(d) / "split.pcap"
            a = pipe.PcapRecordWriter(whole)
            a.feed(stream + record()[:10])
            b = pipe.PcapRecordWriter(split)
            for byte in stream + record()[:10]:
                b.feed(bytes([byte]))
            self.assertEqual(a.close(), 10)
            self.assertEqual(b.close(), 10)
            self.assertEqual(whole.read_bytes(), stream)
            self.assertEqual(split.read_bytes(), stream)
            self.assertEqual(a.records, 2)
            summary = core.summarize_capture(whole, {(2, 3)})
            self.assertEqual(summary["record_count"], 2)

    def test_rejects_non_usbpcap_stream_and_writes_nothing(self):
        bad = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.pcap"
            writer = pipe.PcapRecordWriter(path)
            with self.assertRaises(pipe.PcapStreamError):
                writer.feed(bad)
            writer.close()
            self.assertEqual(path.read_bytes(), b"")
            self.assertFalse(writer.header_written)

    def test_oversized_record_stops_and_keeps_valid_prefix(self):
        oversized = struct.pack("<IIII", 1, 0, 70000, 70000)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "prefix.pcap"
            writer = pipe.PcapRecordWriter(path)
            with self.assertRaises(pipe.PcapStreamError):
                writer.feed(GLOBAL + record() + oversized)
            with self.assertRaises(pipe.PcapStreamError):
                writer.feed(record())  # no further acceptance after an error
            writer.close()
            self.assertEqual(path.read_bytes(), GLOBAL + record())
            core.summarize_capture(path, {(2, 3)})

    def test_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "existing.pcap"
            path.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                pipe.PcapRecordWriter(path)
            self.assertEqual(path.read_bytes(), b"keep")


class RecordingTests(unittest.TestCase):
    def make(self, folder, body, **options):
        options.setdefault("native_windows", False)
        options.setdefault("exit_grace", 2.0)
        return pipe.PipedUSBPcapRecording(synthetic(folder, body),
                                          r"\\.\USBPcap2", folder / "segment-001.pcap",
                                          **options)

    def test_command_streams_to_stdout_with_existing_capture_options(self):
        recorder = pipe.PipedUSBPcapRecording("USBPcapCMD.exe", r"\\.\USBPcap2",
                                              Path("unused.pcap"), native_windows=False)
        self.assertEqual(recorder.command, [
            "USBPcapCMD.exe", "-d", r"\\.\USBPcap2", "-o", "-", "-s", "65535",
            "-b", "1048576", "-A", "--capture-from-new-devices", "--inject-descriptors"])
        with self.assertRaises(ValueError):
            pipe.PipedUSBPcapRecording("x", "USBPcap2;other", Path("unused.pcap"))

    def test_closing_pipe_stops_writer_that_exits_on_write_failure(self):
        body = """
        out.write(GLOBAL); out.flush()
        n = 0
        try:
            while True:
                n += 1
                out.write(record(n)); out.flush()
                time.sleep(0.02)
        except (BrokenPipeError, OSError):
            os._exit(0)  # mirrors USBPcapCMD: write failure ends capture
        """
        with tempfile.TemporaryDirectory() as d:
            recorder = self.make(Path(d), body)
            recorder.start()
            time.sleep(0.15)
            self.assertTrue(recorder.running())
            self.assertTrue(recorder.stop())
            report = recorder.stop_report
            self.assertEqual(report["transport"], "stdout_pipe")
            self.assertEqual(report["stop_method"], "exited_after_pipe_close")
            self.assertEqual(report["halt_reason"], "operator_stop")
            self.assertEqual(report["recorder_exit_code"], 0)
            self.assertTrue(report["output_valid"])
            self.assertGreater(report["records_written"], 0)
            summary = core.summarize_capture(recorder.path, {(2, 3)})
            self.assertEqual(summary["record_count"], report["records_written"])
            self.assertTrue(summary["live_reader_traffic"])

    def test_idle_recorder_is_terminated_after_grace_without_invalidating_file(self):
        body = """
        out.write(GLOBAL + record(1)); out.flush()
        while True:
            time.sleep(1)  # no traffic: never notices the closed pipe
        """
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            session = core.CaptureSession(folder, "success",
                lambda interface, path: pipe.PipedUSBPcapRecording(
                    synthetic(folder, body), interface, path,
                    native_windows=False, exit_grace=0.3))
            reader = SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                     instance_id="synthetic")
            session.start(reader)
            time.sleep(0.1)
            report = session.finish()
            segment = report["segments"][0]
            self.assertFalse(segment["graceful_stop"])
            self.assertEqual(segment["stop"]["stop_method"], "terminated_after_grace")
            self.assertTrue(segment["stop"]["orderly_stop"])
            self.assertTrue(segment["stop"]["output_valid"])
            stopped = [e for e in report["events"] if e["event"] == "recorder_stopped"]
            self.assertTrue(stopped[0]["orderly_stop"])
            self.assertNotIn("validation_error", segment)
            self.assertEqual(segment["summary"]["record_count"], 1)
            self.assertFalse(report["capture_gap"])
            self.assertTrue(report["continuous_capture"])

    def test_recorder_exit_mid_record_is_a_gap_but_file_stays_parseable(self):
        body = """
        out.write(GLOBAL + record(1) + record(2)[:9]); out.flush()
        time.sleep(0.3)  # exit after the controller reports ready
        os._exit(3)
        """
        with tempfile.TemporaryDirectory() as d:
            recorder = self.make(Path(d), body)
            recorder.start()
            deadline = time.monotonic() + 3
            while recorder.running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(recorder.running())
            self.assertFalse(recorder.stop())
            report = recorder.stop_report
            self.assertEqual(report["stop_method"], "exited_before_stop")
            self.assertFalse(report["orderly_stop"])
            self.assertEqual(report["recorder_exit_code"], 3)
            self.assertEqual(report["discarded_partial_bytes"], 9)
            self.assertTrue(report["output_valid"])
            self.assertEqual(core.summarize_capture(recorder.path, {(2, 3)})["record_count"], 1)

    def test_session_marks_gap_when_recorder_exits_before_stop(self):
        body = """
        out.write(GLOBAL + record(1)); out.flush()
        time.sleep(0.2)
        os._exit(0)
        """
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            session = core.CaptureSession(folder, "success",
                lambda interface, path: pipe.PipedUSBPcapRecording(
                    synthetic(folder, body), interface, path,
                    native_windows=False))
            session.start(SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                          instance_id="synthetic"))
            time.sleep(0.6)
            report = session.finish()
            self.assertEqual(report["segments"][0]["stop"]["stop_method"], "exited_before_stop")
            self.assertTrue(report["capture_gap"])
            self.assertFalse(report["continuous_capture"])

    def test_corrupt_stream_fails_validation(self):
        body = """
        out.write(GLOBAL + record(1) + struct.pack("<IIII", 1, 0, 90000, 90000)); out.flush()
        while True:
            time.sleep(1)
        """
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            session = core.CaptureSession(folder, "success",
                lambda interface, path: pipe.PipedUSBPcapRecording(
                    synthetic(folder, body), interface, path,
                    native_windows=False, exit_grace=0.3))
            session.start(SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                          instance_id="synthetic"))
            deadline = time.monotonic() + 3
            while session.process.running() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(session.process.running())
            report = session.finish()
            segment = report["segments"][0]
            self.assertFalse(segment["stop"]["output_valid"])
            self.assertFalse(segment["stop"]["orderly_stop"])
            self.assertEqual(segment["stop"]["halt_reason"], "stream_error")
            self.assertNotEqual(segment["stop"]["stop_method"], "exited_before_stop")
            self.assertEqual(segment["stop"]["stream_error"], "record_length_exceeds_snaplen")
            self.assertEqual(segment["validation_error"], "incomplete_or_invalid_capture")
            self.assertTrue(report["capture_gap"])

    def test_heavy_stderr_is_drained_privately_and_not_copied_to_manifest(self):
        body = """
        sys.stderr.write("Z" * 300000); sys.stderr.flush()
        out.write(GLOBAL + record(1)); out.flush()
        sys.stderr.write("Write failed (232). Stopping capture.\\n"); sys.stderr.flush()
        try:
            while True:
                out.write(record(2)); out.flush(); time.sleep(0.02)
        except (BrokenPipeError, OSError):
            os._exit(0)
        """
        with tempfile.TemporaryDirectory() as d:
            recorder = self.make(Path(d), body, ready_timeout=5)
            recorder.start()  # would time out if stderr were left undrained
            time.sleep(0.1)
            recorder.stop()
            report = recorder.stop_report
            self.assertTrue(report["recorder_reported_write_failure"])
            self.assertLessEqual(report["recorder_stderr_bytes_kept"], 8192)
            self.assertNotIn("stderr", {k for k in report if "text" in k})
            log = recorder.path.with_name(recorder.path.stem + "-recorder-stderr.txt")
            self.assertTrue(log.exists())
            self.assertLessEqual(log.stat().st_size, 8192)

    def test_not_ready_until_global_header_arrives(self):
        body = """
        time.sleep(5)
        out.write(GLOBAL); out.flush()
        """
        with tempfile.TemporaryDirectory() as d:
            recorder = self.make(Path(d), body, ready_timeout=0.3, exit_grace=0.2)
            with self.assertRaisesRegex(RuntimeError, "output-ready"):
                recorder.start()
            self.assertFalse(recorder.running())
            self.assertEqual(recorder.stop_report["stop_method"], "terminated_after_grace")


class DrainTests(unittest.TestCase):
    def test_buffered_records_are_drained_before_pipe_close(self):
        # Burst of records written at once, then idle: all must be kept.
        body = """
        out.write(GLOBAL); out.flush()
        time.sleep(0.2)
        out.write(b"".join(record(n) for n in range(1, 201))); out.flush()
        while True:
            time.sleep(1)
        """
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            recorder = pipe.PipedUSBPcapRecording(synthetic(folder, body), r"\\.\USBPcap2",
                folder / "burst.pcap", native_windows=False, exit_grace=0.3)
            recorder.start()
            time.sleep(0.25)  # stop right after the burst lands in the pipe
            recorder.stop()
            self.assertEqual(recorder.stop_report["records_written"], 200)
            self.assertTrue(recorder.stop_report["output_valid"])


class WindowsAvailabilityTests(unittest.TestCase):
    def test_peek_reports_bytes_and_broken_pipe_as_eof(self):
        for result, avail, error, expected in ((1, 42, 0, 42), (1, 0, 0, 0), (0, 0, 109, None)):
            with self.subTest(expected=expected):
                def peek(handle, buffer, size, read, total, left, avail=avail, result=result):
                    total._obj.value = avail
                    return result
                k = SimpleNamespace(PeekNamedPipe=Mock(side_effect=peek))
                with patch.object(ctypes, "WinDLL", return_value=k, create=True), \
                        patch.object(ctypes, "get_last_error", return_value=error, create=True), \
                        patch.dict(sys.modules,
                                   {"msvcrt": SimpleNamespace(get_osfhandle=lambda fd: 5)}):
                    self.assertEqual(pipe.windows_available(3), expected)

    def test_peek_other_failure_raises(self):
        k = SimpleNamespace(PeekNamedPipe=Mock(return_value=0))
        with patch.object(ctypes, "WinDLL", return_value=k, create=True), \
                patch.object(ctypes, "get_last_error", return_value=6, create=True), \
                patch.dict(sys.modules, {"msvcrt": SimpleNamespace(get_osfhandle=lambda fd: 5)}):
            with self.assertRaises(OSError):
                pipe.windows_available(3)


class CliWiringTests(unittest.TestCase):
    def test_default_factory_uses_pipe_recorder(self):
        import goodix_capture as cli
        recorder = cli.default_recording_factory("USBPcapCMD.exe")(r"\\.\USBPcap2",
                                                                    Path("unused.pcap"))
        self.assertIsInstance(recorder, pipe.PipedUSBPcapRecording)


if __name__ == "__main__":
    unittest.main()
