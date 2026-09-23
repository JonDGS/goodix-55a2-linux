#!/usr/bin/env python3
"""Goodix 55A2 private capture CLI. Python 3.10+, USBPcap, Windows admin.

Offline `inspect` is portable and never reads packet bodies. Run --help for usage.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from goodix_capture_core import (CaptureSession, USBPcapRecording, capture_file_size,
                                 summarize_capture, warm_restart)
import os
import time

SCENARIOS = {
    "success": "Perform exactly one ordinary successful fingerprint unlock.",
    "failure": "Perform one rejected fingerprint scan, then recover with PIN/password; no retry.",
    "warm-restart": "Automatic disable/re-enable; do not touch the sensor during recording.",
    "activation": "With reader enabled, open the Windows lock screen without touching the sensor; use PIN to return.",
}


def yes(ask, question):
    if ask(question + " [yes/no]: ").strip().lower() != "yes":
        raise RuntimeError("cancelled; required confirmation was not given")


def recovery_approval(ask):
    yes(ask, "Have you tested PIN/password sign-in independently of the reader?")
    backup = Path(ask("Path to a locally available matching driver backup/installer: "))
    if not backup.exists():
        raise RuntimeError("local driver backup/installer path does not exist")
    yes(ask, "Is that the known-good matching driver, with no Windows/driver update pending?")
    print("Recovery: re-enable Goodix in Device Manager; if needed restart Windows using PIN/password, "
          "then restore your known-good driver. Never uninstall the reader for this experiment.")
    print("A forced process termination or power loss cannot guarantee automatic re-enabling.")
    if ask("To authorize this run only, type RESTART 27c6:55a2: ") != "RESTART 27c6:55a2":
        raise RuntimeError("restart not authorized")
    return True


def restrict_directory(directory: Path):
    """Remove inherited ACLs on this NEW session folder; current user + SYSTEM only."""
    import subprocess
    script = (
        "$ErrorActionPreference='Stop';"
        "$a=New-Object System.Security.AccessControl.DirectorySecurity;"
        "$a.SetAccessRuleProtection($true,$false);"
        "$u=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;"
        "foreach($s in @($u, [System.Security.Principal.SecurityIdentifier]'S-1-5-18')){"
        "$r=New-Object System.Security.AccessControl.FileSystemAccessRule "
        "($s,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$a.AddAccessRule($r)};"
        "Set-Acl -LiteralPath $env:GOODIX_PRIVATE_DIRECTORY -AclObject $a"
    )
    env = dict(os.environ, GOODIX_PRIVATE_DIRECTORY=str(directory))
    import ntpath
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if not ntpath.isabs(root) or not ntpath.splitdrive(root)[0]:
        raise RuntimeError("SystemRoot must be absolute; recording refused")
    powershell = ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                            env=env, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError("cannot restrict session-folder permissions; recording refused")


def monitor_capture(session, backend, seconds):
    """Poll discovery; keyboard Enter ends the recording. No device-state writes."""
    import msvcrt
    deadline = session.origin + seconds
    missing_since = None
    next_discovery = 0.0
    previous_size = None
    print("Recording. Press Enter to finish. Do not close this terminal.")
    while time.monotonic() < deadline:
        if msvcrt.kbhit():
            key = msvcrt.getwch()
            if key in ("\r", "\n"):
                session.event("operator_finish")
                return
            if key == "\x03":
                raise KeyboardInterrupt()
        if session.process is None or not session.process.running():
            session.report["capture_gap"] = True
            raise RuntimeError("recorder exited unexpectedly; capture may be incomplete")
        if time.monotonic() >= next_discovery:
            try:
                reader = backend.discover()
            except RuntimeError:
                # Sticky uncertainty: even a later recovery cannot prove that
                # mapping/traffic stayed continuous during the missing interval.
                session.report["capture_gap"] = True
                if missing_since is None:
                    missing_since = time.monotonic()
                    session.event("discovery_unavailable")
                    print("Reader mapping temporarily unavailable; current hub recording continues.")
                elif time.monotonic() - missing_since > 10:
                    session.report["capture_gap"] = True
                    raise RuntimeError("reader mapping unavailable for too long; stopping")
            else:
                if missing_since is not None:
                    session.event("discovery_recovered")
                    missing_since = None
                old_segments = len(session.report["segments"])
                session.observe(reader)
                if len(session.report["segments"]) != old_segments:
                    print("Capture interface changed: new segment started; continuity is NOT guaranteed.")
            next_discovery = time.monotonic() + 1.0
            segment = session.report["segments"][-1]
            path = session.directory / segment["file"]
            size = capture_file_size(path)
            if size > 256 * 1024 * 1024:
                raise RuntimeError("private capture exceeded safety size limit; stopping")
            if size != previous_size:
                print(f"Output bytes: {size} (metadata only; reader traffic checked after stop)")
                previous_size = size
        time.sleep(0.05)
    session.event("time_limit_reached")
    print("Capture time limit reached; stopping.")


def default_recording_factory(executable):
    """Stdout-pipe recorder: no console input or AttachConsole required."""
    from goodix_pipe_capture import PipedUSBPcapRecording
    return lambda interface, path: PipedUSBPcapRecording(executable, interface, path)


def run_capture(backend, executable, scenario, output, seconds, *, ask=input,
                monitor=None, recording_factory=None, secure_directory=None):
    if scenario not in SCENARIOS or not 10 <= seconds <= 120:
        raise ValueError("invalid scenario or duration; allowed duration 10..120 seconds")
    reader = backend.discover()
    if not backend.is_enabled(reader):
        raise RuntimeError("reader must be enabled and healthy before capture")
    print(f"Goodix 27c6:55a2: {reader.interface}, bus {reader.bus}, address {reader.address}.")
    print(f"Driver version: {reader.driver_version or 'unavailable'}")
    print(SCENARIOS[scenario])
    print("Raw captures can contain biometrics, secrets and other hub traffic. Nothing is uploaded.")
    yes(ask, "Is the output folder private, on encrypted local storage, and outside cloud sync?")
    approved = recovery_approval(ask) if scenario == "warm-restart" else False
    ask("Press Enter to START capture (Ctrl+C cancels): ")
    fresh = backend.discover()
    if fresh.instance_id != reader.instance_id or not backend.is_enabled(fresh):
        raise RuntimeError("reader changed during prompts; capture refused")
    if fresh.driver_version != reader.driver_version:
        raise RuntimeError("driver version changed during prompts; capture refused")
    reader = fresh
    factory = recording_factory or default_recording_factory(executable)
    session = CaptureSession(output, scenario, factory)
    run_failure = None
    try:
        if secure_directory:
            secure_directory(session.directory)
        session.start(reader)
        print(f"Recorder output-ready (not yet validated). Private session: {session.directory}")
        if scenario == "warm-restart":
            session.report["recovery_checks_confirmed"] = approved
            warm_restart(backend, reader, approved=approved, emit=session.event)
            # Capture remains active across the restart. Re-resolve immediately.
            try:
                session.observe(backend.discover())
            except RuntimeError:
                session.report["capture_gap"] = True
                session.event("post_restart_discovery_unavailable")
        (monitor or monitor_capture)(session, backend, seconds)
    except BaseException as exc:
        run_failure = exc
        session.report["run_error"] = type(exc).__name__
        session.report["capture_gap"] = True
        raise
    finally:
        # finish stops the recorder before writing metadata. A full/unwritable
        # disk must not hide the original reader recovery instructions.
        try:
            report = session.finish()
        except Exception as finish_error:
            if run_failure is None:
                raise
            print(f"Session finalization failed ({type(finish_error).__name__}); "
                  "metadata may be incomplete. Original failure preserved.", file=sys.stderr)
        else:
            print(f"Saved private session: {session.directory}")
            print("Reader data observed in stopped capture: " + ("yes" if report["live_reader_traffic"] else "NO"))
            print("Detected recording gap/incomplete data: " + ("yes" if report["capture_gap"] else "no"))
            print("These checks do not prove full initialization or TLS coverage.")
    question = {
        "success": "Did exactly one fingerprint unlock succeed?",
        "failure": "Was exactly one scan rejected, followed by PIN/password recovery?",
        "activation": "Did you open the lock screen without touching the sensor and return using PIN?",
        "warm-restart": "Now test one normal unlock AFTER recording. Does Windows Hello work normally?",
    }[scenario]
    try:
        answer = ask(question + " [yes/no/unknown]: ").strip().lower()
        session.report["operator_outcome"] = answer if answer in ("yes", "no") else "unknown"
    except (EOFError, KeyboardInterrupt):
        session.report["operator_outcome"] = "unknown"
    session.persist()
    return session.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    discovery = commands.add_parser("discover", help="read-only exact-reader discovery (Windows)")
    discovery.add_argument("--usbpcap", help="explicit USBPcapCMD.exe path")
    capture = commands.add_parser("capture", help="interactive guided capture (Windows)")
    capture.add_argument("--usbpcap", help="explicit USBPcapCMD.exe path")
    capture.add_argument("--scenario", choices=SCENARIOS)
    capture.add_argument("--output", type=Path, help="private encrypted local output folder")
    capture.add_argument("--seconds", type=int, default=60, help="recording time limit, 10..120 (default 60)")
    inspect = commands.add_parser("inspect", help="payload-free offline PCAP inspection")
    inspect.add_argument("capture", type=Path)
    inspect.add_argument("--bus", type=int, required=True)
    inspect.add_argument("--address", type=int, required=True)
    args = parser.parse_args(argv)
    if args.command == "inspect":
        if not 0 <= args.bus <= 65535 or not 1 <= args.address <= 127:
            parser.error("bus must be 0..65535 and USB address 1..127")
        print(json.dumps(summarize_capture(args.capture, {(args.bus, args.address)}), indent=2))
        return 0
    if os.name != "nt":
        raise RuntimeError("capture/discovery requires Windows; offline inspect is portable")
    from goodix_windows import WindowsBackend, find_usbpcap, is_admin
    if not is_admin():
        raise RuntimeError("open PowerShell as Administrator; this tool does not auto-elevate")
    executable = find_usbpcap(getattr(args, "usbpcap", None))
    backend = WindowsBackend(executable)
    if args.command == "discover":
        reader = backend.discover()
        print(json.dumps({"vid_pid": "27c6:55a2", "interface": reader.interface,
                          "bus": reader.bus, "address": reader.address,
                          "driver_version": reader.driver_version,
                          "enabled": backend.is_enabled(reader)}, indent=2))
        return 0
    if not sys.stdin.isatty():
        raise RuntimeError("capture requires an interactive terminal; confirmations cannot be piped")
    scenario = getattr(args, "scenario", None)
    if scenario is None:
        options = list(SCENARIOS)
        print("Goodix capture scenarios:")
        for n, option in enumerate(options, 1):
            print(f"  {n}. {option}: {SCENARIOS[option]}")
        selection = input("Select scenario [1]: ").strip() or "1"
        if selection not in ("1", "2", "3", "4"):
            raise ValueError("invalid scenario selection")
        scenario = options[int(selection) - 1]
    output = getattr(args, "output", None)
    if output is None:
        output = Path(input("Private encrypted local capture folder (outside cloud sync/Git): "))
    report = run_capture(backend, executable, scenario, output, getattr(args, "seconds", 60),
                         secure_directory=restrict_directory)
    return 0 if report["live_reader_traffic"] and not report["capture_gap"] else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
