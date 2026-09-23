"""USBPcapCMD recording over a standard-output pipe.

Upstream USBPcapCMD writes to standard output with ``-o -`` (cmd.c:860-863,
commit 477b6edcbd7e99a47f77afc0c4168a9ebee603bb) and ends its capture when an
output write fails (thread.c:110-137). When stdout and stderr are both
redirected it does not attach to any console (cmd.c:1269-1287).

This controller therefore needs no console, AttachConsole or injected 'q':

* It reads the recorder's stdout and writes the private PCAP file itself,
  committing only validated *whole* records. A forced recorder exit can never
  leave a torn record on disk.
* To stop, it closes its end of the pipe; the recorder's next write fails and
  it exits. An idle recorder cannot notice immediately (its broken-pipe probe
  needs read access this pipe does not grant), so after a bounded grace period
  it is terminated. That outcome is recorded explicitly and does not by itself
  invalidate output, because the file holds only complete records.
* Standard input is the null device, never the operator's console, so the
  recorder cannot consume the operator's keystrokes.

Only PCAP/USBPcap framing fields are parsed. Transfer bodies are copied to the
private file unread; they are never decoded or reported.
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import threading
import time
from pathlib import Path

PCAP_GLOBAL = struct.Struct("<IHHiIII")
PCAP_RECORD = struct.Struct("<IIII")
USBPCAP_BASE_HEADER = 27
STDERR_KEEP = 8192
WRITE_FAILURE_MARKERS = (b"Write failed", b"Stopping capture")
ERROR_BROKEN_PIPE = 109


class PcapStreamError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class PcapRecordWriter:
    """Accept a classic USBPcap stream in arbitrary chunks; persist whole records.

    Bytes of an incomplete trailing record stay in memory and are discarded on
    close, so the file is always a parseable prefix of the stream.
    """

    def __init__(self, path: Path):
        self.path = path
        self.stream = open(path, "xb")  # exclusive create: never overwrite
        self.pending = bytearray()
        self.header_written = False
        self.snaplen = 0
        self.records = 0
        self.bytes_written = 0
        self.error: str | None = None

    def _fail(self, code: str):
        self.error = code
        raise PcapStreamError(code)

    def feed(self, chunk: bytes):
        if self.error is not None:
            raise PcapStreamError(self.error)
        self.pending += chunk
        commit = bytearray()
        view = self.pending
        offset = 0
        if not self.header_written:
            if len(view) < PCAP_GLOBAL.size:
                return
            magic, major, minor, _, _, snaplen, link = PCAP_GLOBAL.unpack_from(view, 0)
            if (magic, major, minor, link) != (0xA1B2C3D4, 2, 4, 249):
                self._fail("not_little_endian_microsecond_usbpcap")
            self.snaplen = snaplen
            commit += view[:PCAP_GLOBAL.size]
            offset = PCAP_GLOBAL.size
        failure = None
        while len(view) - offset >= PCAP_RECORD.size:
            _, micros, captured, original = PCAP_RECORD.unpack_from(view, offset)
            if captured > max(self.snaplen, USBPCAP_BASE_HEADER):
                failure = "record_length_exceeds_snaplen"
            elif captured < USBPCAP_BASE_HEADER:
                failure = "record_shorter_than_usbpcap_header"
            elif captured > original:
                failure = "captured_exceeds_original"
            elif micros >= 1_000_000:
                failure = "invalid_timestamp"
            if failure:
                break
            end = offset + PCAP_RECORD.size + captured
            if end > len(view):
                break
            (header_length,) = struct.unpack_from("<H", view, offset + PCAP_RECORD.size)
            if not USBPCAP_BASE_HEADER <= header_length <= captured:
                failure = "invalid_usbpcap_header_length"
                break
            commit += view[offset:end]
            self.records += 1
            offset = end
        if commit:
            self.stream.write(commit)
            self.stream.flush()
            self.bytes_written += len(commit)
            self.header_written = True
        del self.pending[:offset]
        if failure:
            self.pending.clear()
            self._fail(failure)

    def close(self) -> int:
        """Close the file; return the count of discarded partial-record bytes."""
        discarded = len(self.pending)
        self.pending.clear()
        if not self.stream.closed:
            self.stream.close()
        return discarded


def windows_available(fd: int):
    """Bytes readable now without blocking; None at end of stream (Windows)."""
    import ctypes
    import msvcrt
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.PeekNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                                ctypes.c_void_p]
    k.PeekNamedPipe.restype = ctypes.c_int
    total = ctypes.c_uint32(0)
    if not k.PeekNamedPipe(msvcrt.get_osfhandle(fd), None, 0, None,
                           ctypes.byref(total), None):
        error = ctypes.get_last_error()
        if error == ERROR_BROKEN_PIPE:
            return None
        raise OSError(error, "PeekNamedPipe failed")
    return total.value


def _posix_available(fd: int):
    import select
    readable, _, _ = select.select([fd], [], [], 0.05)
    return 65536 if readable else 0


def _process_cpu_seconds(process):
    if os.name != "nt":
        return None
    try:
        import ctypes
        times = [ctypes.c_uint64() for _ in range(4)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
        k.GetProcessTimes.restype = ctypes.c_int
        if not k.GetProcessTimes(ctypes.c_void_p(int(process._handle)),
                                 *(ctypes.byref(t) for t in times)):
            return None
        return round((times[2].value + times[3].value) / 10_000_000, 3)  # kernel+user
    except Exception:
        return None


def _elevated():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


class PipedUSBPcapRecording:
    """Owned USBPcapCMD whose capture stream passes through this controller."""

    def __init__(self, executable, interface: str, path: Path, *, native_windows=True,
                 ready_timeout=10.0, exit_grace=5.0):
        if not re.fullmatch(r"\\\\\.\\USBPcap[0-9]+", interface):
            raise ValueError("invalid USBPcap interface")
        self.command = [str(x) for x in executable] if isinstance(executable, list) else [str(executable)]
        self.command += ["-d", interface, "-o", "-", "-s", "65535", "-b", "1048576",
                         "-A", "--capture-from-new-devices", "--inject-descriptors"]
        self.path = path
        self.native = native_windows
        self.ready_timeout = ready_timeout
        self.exit_grace = exit_grace
        self.process = None
        self.job = None
        self.writer = None
        self.stop_report = None
        self._stop_reading = threading.Event()
        self._draining = threading.Event()
        self._stream_ended = threading.Event()
        self._halt_lock = threading.Lock()
        self._halted = False
        self._stop_requested = False
        self._reader = None
        self._stderr_thread = None
        self._stderr_bytes = 0
        self._stderr_kept = 0
        self._stderr_marker = False
        self._stream_error = None
        self._read_error = None
        self._halt_method = None
        self._halt_exit = None
        self._cpu = None

    # -- lifecycle -----------------------------------------------------------
    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self):
        if self.path.exists():
            raise RuntimeError("refusing to overwrite capture")
        options = {}
        if self.native:
            if os.name != "nt":
                raise RuntimeError("USBPcap recording requires Windows")
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        self.writer = PcapRecordWriter(self.path)
        try:
            self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            bufsize=0, **options)
        except BaseException:
            self.writer.close()
            raise
        try:
            if self.native:
                from goodix_console import RecorderJob
                self.job = RecorderJob(self.process)
            self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
            self._stderr_thread.start()
            self._reader = threading.Thread(target=self._read_stdout, daemon=True)
            self._reader.start()
            deadline = time.monotonic() + self.ready_timeout
            while time.monotonic() < deadline:
                if self.writer.header_written and self.running():
                    return
                if not self.running() or self._stream_ended.is_set():
                    raise RuntimeError("USBPcap exited before recording became ready")
                time.sleep(0.02)
            raise RuntimeError("USBPcap output-ready (PCAP global header) unavailable in time")
        except BaseException:
            self.stop()
            raise

    def _read_stdout(self):
        fd = self.process.stdout.fileno()
        available = windows_available if self.native else _posix_available
        try:
            while not self._stop_reading.is_set():
                count = available(fd)
                if count is None:
                    break
                if count == 0:
                    if self._draining.is_set():
                        break  # pipe emptied after stop request
                    if self.native:
                        time.sleep(0.001)  # recorder flushes per write; keep up
                    continue
                chunk = os.read(fd, count)
                if not chunk:
                    break
                try:
                    self.writer.feed(chunk)
                except PcapStreamError as error:
                    self._stream_error = error.code
                    break
        except OSError as error:
            self._read_error = type(error).__name__
        finally:
            self._stream_ended.set()
        if self._stream_error is not None or self._read_error is not None:
            # Corrupt or unreadable stream: stop the recorder rather than
            # silently continuing without persistence.
            threading.Thread(target=self._halt, daemon=True).start()

    def _drain_stderr(self):
        log = self.path.with_name(self.path.stem + "-recorder-stderr.txt")
        tail = b""
        try:
            with open(log, "xb") as private_log:
                while chunk := self.process.stderr.read(4096):
                    self._stderr_bytes += len(chunk)
                    window = tail + chunk
                    if any(marker in window for marker in WRITE_FAILURE_MARKERS):
                        self._stderr_marker = True
                    tail = window[-64:]
                    room = STDERR_KEEP - self._stderr_kept
                    if room > 0:
                        private_log.write(chunk[:room])
                        private_log.flush()
                        self._stderr_kept += min(room, len(chunk))
        except (OSError, ValueError):
            pass

    def _halt(self):
        """Close the pipe, wait for exit, then terminate. Runs once."""
        with self._halt_lock:
            if self._halted:
                return
            self._halted = True
            reader = self._reader
            own = reader is None or reader is threading.current_thread()
            if not own:
                # Drain what is already buffered, bounded, then force.
                self._draining.set()
                reader.join(timeout=2)
                if reader.is_alive():
                    self._stop_reading.set()
                    reader.join(timeout=5)
            reader_alive = not own and reader.is_alive()
            if not reader_alive:
                try:
                    self.process.stdout.close()  # recorder's next write now fails
                except OSError:
                    pass
            method = "exited_after_pipe_close"
            try:
                if reader_alive:
                    raise subprocess.TimeoutExpired(self.command, 0)
                self.process.wait(timeout=self.exit_grace)
            except subprocess.TimeoutExpired:
                method = "terminated_after_grace"
                self._cpu = _process_cpu_seconds(self.process)
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    method = "killed_after_grace"
                    self.process.kill()
                    self.process.wait(timeout=3)
            self._halt_method = method
            self._halt_exit = self.process.returncode

    def stop(self):
        if self.process is None:
            return False
        if self.stop_report is not None:
            return self._graceful()
        stream_failed = self._stream_error is not None or self._read_error is not None
        exited_first = (not self._stop_requested and not self._halted and not stream_failed
                        and (self.process.poll() is not None or self._stream_ended.is_set()))
        self._stop_requested = True
        if exited_first:
            # Recorder ended on its own: collect remaining stream, no halt needed.
            if self._reader is not None:
                self._reader.join(timeout=5)
            try:
                self.process.wait(timeout=self.exit_grace)
            except subprocess.TimeoutExpired:
                pass
            with self._halt_lock:
                self._halted = True
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=3)
            method, code = "exited_before_stop", self.process.returncode
        else:
            self._halt()
            method, code = self._halt_method, self._halt_exit
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=3)
        if self.job is not None:
            self.job.close()
            self.job = None
        discarded = self.writer.close()
        stream_error = self._stream_error or self.writer.error
        self.stop_report = {
            "transport": "stdout_pipe",
            "stop_method": method,
            # Who asked for the halt: operator stop, or the controller after a
            # corrupt/unreadable stream. Independent of how the process ended.
            "halt_reason": ("stream_error" if stream_error or self._read_error
                            else "recorder_exit" if method == "exited_before_stop"
                            else "operator_stop"),
            "recorder_exit_code": code,
            # Operator-requested stop that kept a valid file. An idle recorder
            # cannot notice the closed pipe, so termination after the grace
            # period is still an orderly outcome; "graceful" stays strict.
            "orderly_stop": (method in ("exited_after_pipe_close", "terminated_after_grace")
                             and stream_error is None and self._read_error is None
                             and self.writer.header_written),
            "records_written": self.writer.records,
            "bytes_written": self.writer.bytes_written,
            "discarded_partial_bytes": discarded,
            "stream_error": stream_error,
            "read_error": self._read_error,
            "output_valid": self.writer.header_written and stream_error is None
                            and self._read_error is None,
            "recorder_stderr_bytes": self._stderr_bytes,
            "recorder_stderr_bytes_kept": self._stderr_kept,
            "recorder_reported_write_failure": self._stderr_marker,
            "recorder_cpu_seconds_at_forced_stop": self._cpu,
            "controller_elevated": _elevated() if self.native else None,
            # USBPcapCMD flushes each write; a stalled reader back-pressures
            # the driver buffer, where drops are not visible in the stream.
            "backpressure_note": "driver-side drops under backpressure are not detectable here",
        }
        return self._graceful()

    def _graceful(self):
        r = self.stop_report
        return (r["stop_method"] == "exited_after_pipe_close" and r["recorder_exit_code"] == 0
                and r["output_valid"])
