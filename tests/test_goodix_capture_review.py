"""Independent-review regressions: synthetic only, no Windows hardware claims."""
import contextlib
import io
import ntpath
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import goodix_capture as cli
import goodix_capture_core as core
from test_goodix_capture_core import pcap


class ACLReviewTests(unittest.TestCase):
    def test_acl_uses_absolute_system_powershell_not_cwd_search(self):
        with patch.dict(os.environ, {"SystemRoot": r"D:\Windows"}), \
                patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as run:
            cli.restrict_directory(Path("private"))
        command = run.call_args.args[0]
        self.assertTrue(ntpath.isabs(command[0]), command[0])
        self.assertEqual(command[0], r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        self.assertEqual(run.call_args.kwargs["env"]["GOODIX_PRIVATE_DIRECTORY"], "private")

    def test_acl_refuses_relative_system_root(self):
        with patch.dict(os.environ, {"SystemRoot": "attacker"}), patch("subprocess.run") as run, \
                self.assertRaisesRegex(RuntimeError, "absolute"):
            cli.restrict_directory(Path("private"))
        run.assert_not_called()


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class SyntheticRecording:
    def __init__(self, interface, path):
        self.path = path
        self.stopped = False

    def start(self):
        self.path.write_bytes(pcap([(0, 0x82, 10, 3)]))

    def stop(self) -> bool:
        self.stopped = True
        return True

    def running(self):
        return not self.stopped


def synthetic_reader():
    return SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                           instance_id="synthetic", driver_version="test")


class MonitorReviewTests(unittest.TestCase):
    def test_unresolved_discovery_at_enter_or_deadline_is_not_continuous(self):
        for finish in ("enter", "deadline"):
            with self.subTest(finish=finish):
                clock = FakeClock()
                keyboard = SimpleNamespace(kbhit=lambda finish=finish, clock=clock: finish == "enter" and clock.now >= .1,
                                           getwch=lambda: "\r")
                discoveries = []
                def discover(discoveries=discoveries, clock=clock):
                    discoveries.append(clock.now)
                    if len(discoveries) > 2:
                        raise RuntimeError("synthetic unavailable mapping")
                    return synthetic_reader()
                backend = SimpleNamespace(discover=discover, is_enabled=lambda r: True)
                with tempfile.TemporaryDirectory() as d, \
                        patch.dict(sys.modules, {"msvcrt": keyboard}), \
                        patch.object(cli.time, "monotonic", clock.monotonic), \
                        patch.object(cli.time, "sleep", clock.sleep), \
                        contextlib.redirect_stdout(io.StringIO()):
                    report = cli.run_capture(backend, "unused", "success", Path(d), 10,
                                             ask=lambda _: "yes", recording_factory=SyntheticRecording)
                self.assertGreater(len(discoveries), 2)
                self.assertTrue(report["capture_gap"], finish)
                self.assertFalse(report["continuous_capture"])
                self.assertTrue(report["live_reader_traffic"])  # valid data must not hide uncertainty
                events = [e["event"] for e in report["events"]]
                self.assertIn("discovery_unavailable", events)
                self.assertIn("operator_finish" if finish == "enter" else "time_limit_reached", events)

    def test_postrestart_discovery_failure_then_immediate_enter_is_not_continuous(self):
        clock = FakeClock()
        keyboard = SimpleNamespace(kbhit=lambda: True, getwch=lambda: "\r")
        discoveries = []
        changes = []
        def discover():
            discoveries.append(clock.now)
            if len(discoveries) == 4:  # initial, after prompts, before disable, after restart
                raise RuntimeError("synthetic unavailable mapping")
            return synthetic_reader()
        backend = SimpleNamespace(discover=discover, is_enabled=lambda r: True,
                                  set_enabled=lambda reader, state: changes.append(state))
        def restart(*args, **kwargs):
            return core.warm_restart(*args, **kwargs, pause=clock.sleep)
        with tempfile.TemporaryDirectory() as d, \
                patch.dict(sys.modules, {"msvcrt": keyboard}), \
                patch.object(cli.time, "monotonic", clock.monotonic), \
                patch.object(cli.time, "sleep", clock.sleep), \
                patch.object(cli, "warm_restart", restart), \
                contextlib.redirect_stdout(io.StringIO()):
            def ask(prompt):
                if "backup/installer:" in prompt:
                    return d
                if "type RESTART" in prompt:
                    return "RESTART 27c6:55a2"
                return "yes"
            report = cli.run_capture(backend, "unused", "warm-restart", Path(d), 10,
                                     ask=ask, recording_factory=SyntheticRecording)
        self.assertEqual(changes, [False, True])
        self.assertEqual(len(discoveries), 4)
        self.assertTrue(report["capture_gap"])
        self.assertFalse(report["continuous_capture"])
        self.assertIn("post_restart_discovery_unavailable", [e["event"] for e in report["events"]])
        self.assertIn("operator_finish", [e["event"] for e in report["events"]])

    def test_live_display_is_metadata_bytes_only_not_packet_validation(self):
        clock = FakeClock()
        keyboard = SimpleNamespace(kbhit=lambda: clock.now >= 0.1, getwch=lambda: "\r")
        backend = SimpleNamespace(discover=synthetic_reader, is_enabled=lambda r: True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
                patch.dict(sys.modules, {"msvcrt": keyboard}), \
                patch.object(cli.time, "monotonic", clock.monotonic), \
                patch.object(cli.time, "sleep", clock.sleep), \
                patch.object(cli, "summarize_capture") as live_validator, \
                contextlib.redirect_stdout(output):
            report = cli.run_capture(backend, "unused", "success", Path(d), 10,
                                     ask=lambda _: "yes", recording_factory=SyntheticRecording)
        live_validator.assert_not_called()
        self.assertIn("Recorder output-ready", output.getvalue())
        self.assertIn("Output bytes:", output.getvalue())
        self.assertNotIn("Reader bulk records:", output.getvalue())
        self.assertTrue(report["live_reader_traffic"])  # stopped-file validator still runs


class FinishReviewTests(unittest.TestCase):
    def test_no_validation_when_orderly_stop_is_unconfirmed(self):
        class ForcedRecording(SyntheticRecording):
            def stop(self):
                super().stop()
                return False
        with tempfile.TemporaryDirectory() as d:
            session = core.CaptureSession(Path(d), "success", ForcedRecording)
            session.start(synthetic_reader())
            with patch.object(core, "summarize_capture", wraps=core.summarize_capture) as validate:
                report = session.finish()
        validate.assert_not_called()
        self.assertTrue(report["capture_gap"])
        self.assertFalse(report["live_reader_traffic"])
        self.assertEqual(report["segments"][0]["validation_error"], "orderly_stop_unconfirmed")

    def test_manifest_failure_does_not_mask_reader_recovery_failure_or_skip_cleanup(self):
        for failing_event in ("recorder_stopped", "session_finished"):
            with self.subTest(failing_event=failing_event):
                clock = FakeClock()
                changes = []
                recordings = []
                def change(reader, enabled, changes=changes):
                    changes.append(enabled)
                    if enabled:
                        raise RuntimeError("synthetic failed enable")
                backend = SimpleNamespace(discover=synthetic_reader, is_enabled=lambda r: True,
                                          set_enabled=change)
                def factory(interface, path, recordings=recordings):
                    recorder = SyntheticRecording(interface, path)
                    recordings.append(recorder)
                    return recorder
                persist = core.CaptureSession.persist
                persistence_failures = []
                def failing_persist(session, failing_event=failing_event,
                                    persistence_failures=persistence_failures, persist=persist):
                    if session.report["events"][-1]["event"] == failing_event:
                        persistence_failures.append(failing_event)
                        raise OSError("synthetic full metadata disk")
                    return persist(session)
                def restart(*args, clock=clock, **kwargs):
                    return core.warm_restart(*args, **kwargs, pause=clock.sleep)
                output, errors = io.StringIO(), io.StringIO()
                with tempfile.TemporaryDirectory() as d, \
                        patch.object(cli.time, "monotonic", clock.monotonic), \
                        patch.object(cli, "warm_restart", restart), \
                        patch.object(core.CaptureSession, "persist", failing_persist), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    def ask(prompt):
                        if "backup/installer:" in prompt:
                            return d
                        if "type RESTART" in prompt:
                            return "RESTART 27c6:55a2"
                        return "yes"
                    with self.assertRaisesRegex(RuntimeError, "READER RECOVERY FAILED.*PIN/password"):
                        cli.run_capture(backend, "unused", "warm-restart", Path(d), 10,
                                        ask=ask, recording_factory=factory)
                self.assertEqual(changes, [False, True, True])
                self.assertEqual(persistence_failures, [failing_event])
                self.assertTrue(recordings[0].stopped)
                self.assertIn("finalization failed", errors.getvalue())
                self.assertNotIn("Saved private session:", output.getvalue())


class OutputReadyReviewTests(unittest.TestCase):
    def test_liveness_without_minimum_output_size_is_not_ready(self):
        from unittest.mock import Mock
        for size in (0, 23):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "short.pcap"
                process = Mock()
                process.poll.return_value = None
                def launch(*args, path=path, size=size, process=process, **kwargs):
                    path.write_bytes(b"x" * size)
                    return process
                recorder = core.USBPcapRecording("synthetic", r"\\.\USBPcap2", path,
                                                native_windows=False, ready_timeout=.1)
                clock = FakeClock()
                with patch("subprocess.Popen", side_effect=launch), \
                        patch.object(core.time, "monotonic", clock.monotonic), \
                        patch.object(core.time, "sleep", clock.sleep), \
                        patch.object(recorder, "stop", return_value=True) as stop, \
                        self.assertRaisesRegex(RuntimeError, "output-ready"):
                    recorder.start()
                stop.assert_called_once()

    def test_sized_output_without_liveness_is_not_ready(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "exited.pcap"
            process = Mock()
            process.poll.return_value = 0
            def launch(*args, **kwargs):
                path.write_bytes(pcap([]))
                return process
            recorder = core.USBPcapRecording("synthetic", r"\\.\USBPcap2", path,
                                            native_windows=False)
            with patch("subprocess.Popen", side_effect=launch), \
                    patch.object(recorder, "stop", return_value=False) as stop, \
                    self.assertRaisesRegex(RuntimeError, "exited"):
                recorder.start()
            stop.assert_called_once()

    def test_native_size_queries_attributes_without_a_data_handle(self):
        import ctypes
        from unittest.mock import Mock
        calls = []
        def attributes(path, level, output):
            calls.append((path, level))
            data = output._obj
            self.assertEqual(ctypes.sizeof(data), 36)
            self.assertEqual(type(data).size_high.offset, 28)
            self.assertEqual(type(data).size_low.offset, 32)
            data.attributes = 0x80
            data.size_high = 1
            data.size_low = 24
            return 1
        kernel = SimpleNamespace(GetFileAttributesExW=Mock(side_effect=attributes))
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True), \
                patch.object(Path, "open", side_effect=AssertionError("data open")), \
                patch.object(Path, "stat", side_effect=AssertionError("stat may open a handle")):
            self.assertTrue(hasattr(core, "capture_file_size"), "metadata query missing")
            size = core.capture_file_size(Path("synthetic.pcap"), native_windows=True)
        self.assertEqual(size, (1 << 32) + 24)
        self.assertEqual(calls, [("synthetic.pcap", 0)])

    def test_exclusive_output_becomes_ready_without_read_then_invalid_after_stop(self):
        # Linux cannot enforce Windows share-mode zero. Deny PCAP data opens in
        # the controller while a real synthetic recorder owns the output.
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            fake = folder / "recorder.py"
            fake.write_text(
                "import pathlib,sys,time\n"
                "p=pathlib.Path(sys.argv[sys.argv.index('-o')+1])\n"
                "p.write_bytes(b'not a pcap header at all!')\n"
                "while not p.with_suffix('.stop').exists(): time.sleep(.01)\n")
            recorders = []
            def factory(interface, path):
                recorder = core.USBPcapRecording(
                    [sys.executable, str(fake)], interface, path,
                    native_windows=False, ready_timeout=0.5,
                    stop_signal=lambda process: path.with_suffix('.stop').touch())
                recorders.append(recorder)
                return recorder
            session = core.CaptureSession(folder, "success", factory)
            original_open = Path.open
            attempted_reads = []
            def exclusive_open(path, *args, **kwargs):
                if path.suffix == ".pcap" and any(r.running() for r in recorders):
                    attempted_reads.append(path)
                    raise PermissionError("synthetic sharing violation")
                return original_open(path, *args, **kwargs)
            reader = SimpleNamespace(interface=r"\\.\USBPcap2", bus=2, address=3,
                                     instance_id="synthetic")
            with patch.object(Path, "open", exclusive_open):
                try:
                    session.start(reader)
                    self.assertTrue(session.process.running())
                    self.assertEqual(attempted_reads, [])
                    self.assertIn("recorder_output_ready",
                                  [e["event"] for e in session.report["events"]])
                    self.assertNotIn("summary", session.report["segments"][0])
                finally:
                    report = session.finish()
            self.assertTrue(report["segments"][0]["graceful_stop"])
            self.assertEqual(report["segments"][0]["validation_error"],
                             "incomplete_or_invalid_capture")
            self.assertFalse(report["continuous_capture"])
            self.assertFalse(report["live_reader_traffic"])


if __name__ == "__main__":
    unittest.main()
