"""Private Windows console/process helpers; not a user-facing command.

USBPcapCMD reads ReadConsoleInput, not a piped stdin 'q'. Each recorder owns
an isolated console. A short-lived helper attaches there to request a clean quit.
A kill-on-close Job Object prevents recordings surviving controller termination.
Native Windows calls require an on-device pilot; layouts use fixed-width types.
"""
from __future__ import annotations
import ctypes as C
import os
import sys

DWORD = C.c_uint32
WORD = C.c_uint16
BOOL = C.c_int32
HANDLE = C.c_void_p
SIZE = C.c_size_t


class KeyEvent(C.Structure):
    _fields_ = [("down", BOOL), ("repeat", WORD), ("virtual", WORD),
                ("scan", WORD), ("char", WORD), ("control", DWORD)]


class EventUnion(C.Union):
    _fields_ = [("key", KeyEvent), ("padding", C.c_byte * 16)]


class InputRecord(C.Structure):
    _fields_ = [("kind", WORD), ("event", EventUnion)]


class BasicLimits(C.Structure):
    _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64),
                ("flags", DWORD), ("min_ws", SIZE), ("max_ws", SIZE),
                ("active", DWORD), ("affinity", SIZE), ("priority", DWORD),
                ("scheduling", DWORD)]


class ExtendedLimits(C.Structure):
    _fields_ = [("basic", BasicLimits), ("io", C.c_uint64 * 6),
                ("process_mem", SIZE), ("job_mem", SIZE),
                ("peak_process", SIZE), ("peak_job", SIZE)]


def kernel():
    if os.name != "nt":
        raise RuntimeError("Windows console support requires Windows")
    return C.WinDLL("kernel32", use_last_error=True)


class RecorderJob:
    def __init__(self, process):
        k = self.k = kernel()
        k.CreateJobObjectW.argtypes = [C.c_void_p, C.c_wchar_p]
        k.CreateJobObjectW.restype = HANDLE
        k.SetInformationJobObject.argtypes = [HANDLE, C.c_int, C.c_void_p, DWORD]
        k.SetInformationJobObject.restype = BOOL
        k.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
        k.AssignProcessToJobObject.restype = BOOL
        k.CloseHandle.argtypes = [HANDLE]
        k.CloseHandle.restype = BOOL
        self.handle = k.CreateJobObjectW(None, None)
        if not self.handle:
            raise RuntimeError("cannot create recorder cleanup job")
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            if not k.SetInformationJobObject(self.handle, 9, C.byref(limits), C.sizeof(limits)):
                raise RuntimeError("cannot configure recorder cleanup job")
            if not k.AssignProcessToJobObject(self.handle, HANDLE(int(process._handle))):
                raise RuntimeError("cannot assign recorder cleanup job")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None


def send_quit(pid: int):
    k = kernel()
    k.AttachConsole.argtypes = [DWORD]
    k.AttachConsole.restype = BOOL
    k.FreeConsole.argtypes = []
    k.FreeConsole.restype = BOOL
    k.CreateFileW.argtypes = [C.c_wchar_p, DWORD, DWORD, C.c_void_p, DWORD, DWORD, HANDLE]
    k.CreateFileW.restype = HANDLE
    k.WriteConsoleInputW.argtypes = [HANDLE, C.POINTER(InputRecord), DWORD, C.POINTER(DWORD)]
    k.WriteConsoleInputW.restype = BOOL
    k.CloseHandle.argtypes = [HANDLE]
    k.CloseHandle.restype = BOOL
    if pid <= 0 or not k.AttachConsole(pid):
        raise RuntimeError("cannot attach to recorder console")
    handle = None
    try:
        handle = k.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
        if handle == C.c_void_p(-1).value:
            handle = None
            raise RuntimeError("cannot open recorder console input")
        events = (InputRecord * 2)()
        for i, down in enumerate((True, False)):
            events[i].kind = 1  # KEY_EVENT
            events[i].event.key = KeyEvent(down, 1, 0x51, 0, ord("q"), 0)
        written = DWORD()
        if not k.WriteConsoleInputW(handle, events, 2, C.byref(written)) or written.value != 2:
            raise RuntimeError("cannot request recorder shutdown")
    finally:
        if handle:
            k.CloseHandle(handle)
        k.FreeConsole()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("internal helper requires owned recorder PID")
        send_quit(int(sys.argv[1]))
    except Exception:
        sys.exit(1)
