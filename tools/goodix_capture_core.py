"""Payload-free capture validation and managed USBPcap recording.

Raw captures remain private. Only PCAP/USBPcap headers are read here; transfer
bodies, descriptor strings, credentials and biometric data are never decoded.
"""
from __future__ import annotations

import struct
import json
import tempfile
import time
from pathlib import Path


def capture_file_size(path: Path, *, native_windows=None) -> int:
    """Query output metadata, never open a capture data handle.

    USBPcapCMD opens -o with share mode zero (cmd.c:866-872, commit
    477b6edcbd7e99a47f77afc0c4168a9ebee603bb). Microsoft's CreateFileW
    dwShareMode documentation exempts attribute queries from sharing restrictions.
    GetFileAttributesExW supplies WIN32_FILE_ATTRIBUTE_DATA, including file size.
    Size visibility/timing on the actual Windows filesystem still needs a pilot;
    this is NOT header validation, a flush guarantee, or evidence of reader data.
    """
    import os
    if native_windows is None:
        native_windows = os.name == "nt"
    if not native_windows:
        return path.stat().st_size  # portable synthetic-process tests only
    import ctypes

    class FileAttributeData(ctypes.Structure):
        _fields_ = [("attributes", ctypes.c_uint32),
                    ("times", ctypes.c_uint32 * 6),
                    ("size_high", ctypes.c_uint32), ("size_low", ctypes.c_uint32)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetFileAttributesExW
    query.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.POINTER(FileAttributeData)]
    query.restype = ctypes.c_int
    data = FileAttributeData()
    if not query(str(path), 0, ctypes.byref(data)):  # GetFileExInfoStandard
        raise ctypes.WinError(ctypes.get_last_error())
    return (data.size_high << 32) | data.size_low


def summarize_capture(path: Path, targets: set[tuple[int, int]]) -> dict:
    """Inspect a stopped classic USBPcap capture without reading payloads."""
    result = {"record_count": 0, "reader_bulk_records": 0,
              "reader_data_records": 0, "large_reader_in_records": 0,
              "span_seconds": 0.0, "truncated_records": 0,
              "live_reader_traffic": False}
    first = last = None
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("incomplete PCAP header")
        magic, major, minor, _, _, _, link = struct.unpack("<IHHIIII", header)
        if (magic, major, minor, link) != (0xA1B2C3D4, 2, 4, 249):
            raise ValueError("expected little-endian microsecond USBPcap PCAP")
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("incomplete PCAP record header")
            sec, us, captured, original = struct.unpack("<IIII", record)
            end = stream.tell() + captured
            if captured < 27 or captured > original or end > size or us >= 1000000:
                raise ValueError("incomplete or invalid USBPcap record")
            hlen, _, _, _, info, bus, addr, ep, kind, length = struct.unpack(
                "<HQIHBHHBBI", stream.read(27))
            if not 27 <= hlen <= captured:
                raise ValueError("invalid USBPcap header length")
            result["truncated_records"] += int(captured < original)
            now = sec * 1000000 + us
            first = now if first is None else min(first, now)
            last = now if last is None else max(last, now)
            result["record_count"] += 1
            if kind == 3 and (bus, addr) in targets and ep in (1, 0x82):
                result["reader_bulk_records"] += 1
                # Only actual OUT submissions or IN completions bearing data.
                has_data = length > 0 and captured - hlen >= length
                data_side = (ep == 1 and not info & 1) or (ep == 0x82 and info & 1)
                if has_data and data_side:
                    result["reader_data_records"] += 1
                    if ep == 0x82 and length > 128:
                        result["large_reader_in_records"] += 1
            stream.seek(end)
    if first is not None:
        result["span_seconds"] = (last - first) / 1000000
    result["live_reader_traffic"] = result["reader_data_records"] > 0
    return result


class CaptureSession:
    """Own unique private files and separate segments when hub mapping changes.

    `continuous_capture` means no detected recorder gap, NOT verified coverage of
    every hardware event. Reader records are associated using discovered addresses.
    """

    def __init__(self, output: Path, scenario: str, recording_factory):
        output = output.resolve()
        if scenario not in ("success", "failure", "warm-restart", "activation"):
            raise ValueError("unsupported scenario")
        if any((p / ".git").exists() for p in (output, *output.parents)):
            raise ValueError("raw captures must be outside a Git checkout")
        if any(word in str(output).casefold() for word in
               ("onedrive", "dropbox", "nextcloud", "google drive")):
            raise ValueError("choose a private folder outside cloud sync")
        output.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=f"goodix-{scenario}-", dir=output))
        self.factory = recording_factory
        self.origin = time.monotonic()
        self.process = None
        self.identity = None
        self.report = {"format": "goodix-capture-session-v1", "scenario": scenario,
                       "state": "prepared", "capture_gap": False,
                       "events": [], "segments": [], "operator_outcome": "not_recorded"}
        self.event("session_prepared")

    def persist(self):
        tmp = self.directory / "manifest.tmp"
        tmp.write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.directory / "manifest.json")

    def event(self, name: str, **details):
        self.report["events"].append({"event": name,
                                      "offset_s": round(time.monotonic() - self.origin, 6),
                                      **details})
        self.persist()

    def start(self, reader):
        if self.process is not None:
            raise RuntimeError("capture already started")
        if self.identity is None:
            self.identity = reader.instance_id
        if reader.instance_id != self.identity:
            raise RuntimeError("reader identity changed; refusing another device")
        index = len(self.report["segments"]) + 1
        path = self.directory / f"segment-{index:03d}.pcap"
        if path.exists():
            raise RuntimeError("refusing to overwrite capture")
        segment = {"file": path.name, "interface": reader.interface,
                   "targets": [[reader.bus, reader.address]], "graceful_stop": None}
        self.report["segments"].append(segment)
        self.process = self.factory(reader.interface, path)
        try:
            self.process.start()
        except BaseException:
            self.report["capture_gap"] = True
            try:
                segment["graceful_stop"] = self.process.stop()
            finally:
                self.process = None
                self.event("recorder_start_failed")
            raise
        self.report["state"] = "recording"
        self.event("recorder_output_ready", segment=index, bus=reader.bus, address=reader.address)

    def stop_segment(self):
        if self.process is not None:
            process, self.process = self.process, None
            try:
                graceful = process.stop()
            except Exception:
                graceful = False
            self.report["segments"][-1]["graceful_stop"] = bool(graceful)
            stop = getattr(process, "stop_report", None)
            if stop is not None:
                # Pipe recorder: file integrity comes from whole-record writes,
                # so only an unrequested exit or invalid stream is a gap.
                self.report["segments"][-1]["stop"] = stop
                if stop["stop_method"] == "exited_before_stop" or not stop["output_valid"]:
                    self.report["capture_gap"] = True
            elif not graceful:
                self.report["capture_gap"] = True
            self.event("recorder_stopped", graceful=bool(graceful),
                       **({"stop_method": stop["stop_method"],
                           "orderly_stop": stop.get("orderly_stop", False)} if stop else {}))

    def observe(self, reader):
        if reader.instance_id != self.identity:
            raise RuntimeError("reader identity changed; stop and inspect device state")
        segment = self.report["segments"][-1]
        if reader.interface != segment["interface"]:
            self.report["capture_gap"] = True
            self.event("capture_interface_changed")
            self.stop_segment()
            self.start(reader)
        elif self.process is None or not self.process.running():
            self.report["capture_gap"] = True
            raise RuntimeError("capture process exited unexpectedly")
        target = [reader.bus, reader.address]
        segment = self.report["segments"][-1]
        if target not in segment["targets"]:
            segment["targets"].append(target)
            self.event("reader_address_changed", bus=reader.bus, address=reader.address)

    def finish(self):
        self.stop_segment()
        live = False
        for segment in self.report["segments"]:
            stop = segment.get("stop")
            if stop is not None:
                if not stop["output_valid"]:
                    segment["validation_error"] = "incomplete_or_invalid_capture"
                    self.report["capture_gap"] = True
                    continue
            elif segment["graceful_stop"] is not True:
                segment["validation_error"] = "orderly_stop_unconfirmed"
                self.report["capture_gap"] = True
                continue
            try:
                summary = summarize_capture(self.directory / segment["file"],
                                            {tuple(t) for t in segment["targets"]})
                segment["summary"] = summary
                live |= summary["live_reader_traffic"]
                if summary["truncated_records"]:
                    self.report["capture_gap"] = True
            except (OSError, ValueError):
                segment["validation_error"] = "incomplete_or_invalid_capture"
                self.report["capture_gap"] = True
        self.report["state"] = "finished"
        self.report["live_reader_traffic"] = live
        self.report["continuous_capture"] = bool(self.report["segments"]) and not self.report["capture_gap"]
        self.event("session_finished")
        return self.report


def warm_restart(backend, reader, *, approved: bool, emit, pause=time.sleep):
    """Restart one freshly verified reader; always attempt restoration.

    The interactive caller must perform recovery checks and obtain an explicit
    per-run confirmation before setting approved. No unattended CLI switch does so.
    """
    if not approved:
        raise RuntimeError("warm restart requires recovery checks and per-run approval")
    current = backend.discover()
    if current.instance_id != reader.instance_id or not backend.is_enabled(current):
        raise RuntimeError("reader changed or is not healthy; restart refused")
    emit("disable_requested")
    try:
        backend.set_enabled(current, False)
        emit("reader_disabled")
        pause(2.0)
    finally:
        # Do not let logging failures or a second Ctrl+C prevent restoration.
        import signal
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        restored = False
        try:
            for _ in range(2):
                try:
                    backend.set_enabled(current, True)
                    restored = backend.is_enabled(current)
                    if restored:
                        break
                except Exception:
                    continue
        finally:
            signal.signal(signal.SIGINT, previous)
        if not restored:
            raise RuntimeError("READER RECOVERY FAILED: stop research, use PIN/password, "
                               "and re-enable Goodix in Device Manager")
        emit("reader_reenabled")


class USBPcapRecording:
    """Own USBPcap, require output-ready metadata, and stop cleanly.

    Tests may inject a subprocess executable and stop transport; production always
    uses Windows console input (USBPcapCMD does not accept a piped 'q').
    """

    def __init__(self, executable, interface: str, path: Path, *, stop_signal=None,
                 native_windows=True, ready_timeout=10.0):
        import re
        if not re.fullmatch(r"\\\\\.\\USBPcap[0-9]+", interface):
            raise ValueError("invalid USBPcap interface")
        self.command = [str(x) for x in executable] if isinstance(executable, list) else [str(executable)]
        self.command += ["-d", interface, "-o", str(path), "-s", "65535", "-b", "1048576",
                         "-A", "--capture-from-new-devices", "--inject-descriptors"]
        self.path = path
        self.native = native_windows
        self.stop_signal = stop_signal
        self.ready_timeout = ready_timeout
        self.process = None
        self.job = None

    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self):
        import os
        import subprocess
        if self.path.exists():
            raise RuntimeError("refusing to overwrite capture")
        options = {}
        if self.native:
            if os.name != "nt":
                raise RuntimeError("USBPcap recording requires Windows")
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0  # private console; no inherited keyboard input
            options = {"creationflags": subprocess.CREATE_NEW_CONSOLE, "startupinfo": startup}
        self.process = subprocess.Popen(self.command, **options)
        try:
            if self.native:
                from goodix_console import RecorderJob
                self.job = RecorderJob(self.process)
            deadline = time.monotonic() + self.ready_timeout
            while time.monotonic() < deadline:
                if not self.running():
                    raise RuntimeError("USBPcap exited before recording became ready")
                try:
                    if capture_file_size(self.path, native_windows=self.native) >= 24 and self.running():
                        return
                except (FileNotFoundError, PermissionError):
                    pass
                time.sleep(0.05)
            raise RuntimeError("USBPcap output-ready metadata (at least 24 bytes) unavailable in time")
        except BaseException:
            self.stop()
            raise

    def stop(self):
        import subprocess
        import sys
        if self.process is None:
            return False
        graceful = False
        try:
            if self.running():
                if self.stop_signal is not None:
                    self.stop_signal(self.process)
                else:
                    helper = Path(__file__).with_name("goodix_console.py")
                    subprocess.run([sys.executable, str(helper), str(self.process.pid)],
                                   creationflags=subprocess.CREATE_NO_WINDOW,
                                   timeout=5, check=True)
                self.process.wait(timeout=5)
                graceful = self.process.returncode == 0
        except Exception:
            graceful = False
        finally:
            if self.running():
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            if self.job is not None:
                self.job.close()
                self.job = None
        return graceful
