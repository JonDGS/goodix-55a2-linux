"""Fail-closed Windows USBPcap mapping for the physical Goodix 27c6:55a2.

No third-party Python dependencies. Native execution needs elevated Windows,
USBPcap installed and Windows PowerShell's PnpDevice module. Linux tests use
synthetic SDK buffers; actual Windows/driver interoperability remains unverified.
No capture, protocol traffic, driver installation, firmware or enrollment writes.
The caller owns recovery checks and explicit per-run consent BEFORE set_enabled.
Do not print Reader.instance_id or native/PnP output: these contain identifiers.
Discovery is a snapshot, not a lock against unplugging or concurrent PnP changes.
Unsupported/ambiguous/inaccessible topology fails closed, including failures on
unrelated hubs. Composite interface children are not physical reader candidates.
An already-disabled reader cannot be discovered by a new backend: re-enable is
allowed only with this process's previously verified identity. No recovery state
is persisted. PowerShell actions have bounded verification; native hub queries
are synchronous Win32 calls. Hotplug races cannot be made atomic with PnP.

Layout/constant references (independent implementation, not copied source):
* USBPcap commit 477b6edcbd7e99a47f77afc0c4168a9ebee603bb:
  https://github.com/desowin/usbpcap/blob/477b6edcbd7e99a47f77afc0c4168a9ebee603bb/USBPcapDriver/include/USBPcap.h
  USBPcapCMD/enum.c, cmd.c; USBPcapDriver/USBPcapRootHubControl.c.
* Microsoft SDK usbioctl.h (pshpack1.h!), usbiodef.h and usbspec.h:
  https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders/shared
* https://learn.microsoft.com/windows-hardware/drivers/install/devpkey-device-driver
* https://learn.microsoft.com/windows-hardware/drivers/install/cm-prob-disabled
* https://learn.microsoft.com/powershell/module/pnpdevice/disable-pnpdevice
DeviceAddress comes from USB_NODE_CONNECTION_INFORMATION_EX, NEVER a PnP
address/location/port property. USBPcap's control-device suffix is its bus ID.
"""
from dataclasses import dataclass, field
from pathlib import Path
import ctypes
import json
import os
import re
import struct
import subprocess

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, function, METHOD_BUFFERED=0, ANY=0).
GET_HUB_SYMLINK = (0x22 << 16) | (0x803 << 2)
GET_NODE_INFORMATION = (0x22 << 16) | (258 << 2)
GET_CONNECTION_NAME = (0x22 << 16) | (261 << 2)
GET_DRIVERKEY_NAME = (0x22 << 16) | (264 << 2)
GET_CONNECTION_INFORMATION_EX = (0x22 << 16) | (274 << 2)


@dataclass(frozen=True)
class Reader:
    interface: str
    bus: int
    address: int
    instance_id: str = field(repr=False)
    driver_version: str = ''


@dataclass(frozen=True)
class Connection:
    vid: int
    pid: int
    address: int
    is_hub: bool


def decode_connection(data: bytes, port: int) -> Connection | None:
    """Decode the SDK's packed 35-byte fixed prefix, not a host C ABI."""
    if len(data) < 35:
        raise RuntimeError('Invalid USB connection response')
    returned_port = struct.unpack_from('<I', data)[0]
    status = struct.unpack_from('<I', data, 31)[0]
    # The SDK marks ConnectionIndex as INPUT. The Windows pilot returned zero
    # for an empty port; do not require that input field to survive in this case.
    # Retain strict matching for connected/unhealthy ports and nonzero mismatches.
    if returned_port != port and not (status == 0 and returned_port == 0):
        raise RuntimeError('Invalid USB connection response')
    if status == 0:  # NoDeviceConnected
        return None
    if status != 1 or data[4:6] != b'\x12\x01' or data[24] not in (0, 1):
        raise RuntimeError('Unhealthy or unsupported USB connection')
    vid, pid = struct.unpack_from('<HH', data, 12)
    address = struct.unpack_from('<H', data, 25)[0]
    if not 1 <= address <= 127:
        raise RuntimeError('Invalid USB device address')
    return Connection(vid, pid, address, bool(data[24]))


def _wide(data: bytes) -> str:
    try:
        text = data.decode('utf-16-le')
    except UnicodeError:
        raise RuntimeError('Invalid USB name encoding') from None
    if not text or '\0' not in text or not text.split('\0', 1)[0]:
        raise RuntimeError('Invalid USB name response')
    return text.split('\0', 1)[0]


def _hub_path(name: str) -> str:
    if name.startswith('\\??\\'):
        name = name[4:]
    if name.startswith(('\\\\.\\', '\\\\?\\')):
        return name
    return '\\\\.\\' + name


class HubEnumerator:
    """Portable traversal; ioctl(path, code, input_bytes, output_size) is injectable."""
    def __init__(self, ioctl):
        self.ioctl = ioctl

    def _name(self, path, code, port):
        request = struct.pack('<I', port) + bytes(6)
        header = self.ioctl(path, code, request, 10)
        if len(header) < 10 or struct.unpack_from('<I', header)[0] != port:
            raise RuntimeError('Invalid USB name header')
        length = struct.unpack_from('<I', header, 4)[0]
        if not 12 <= length <= 65536 or length % 2:
            raise RuntimeError('Invalid USB name length')
        data = self.ioctl(path, code, request.ljust(length, b'\0'), length)
        if len(data) < length or struct.unpack_from('<II', data) != (port, length):
            raise RuntimeError('Changed or truncated USB name response')
        return _wide(data[8:length])

    def connections(self, interface):
        root = _wide(self.ioctl(interface, GET_HUB_SYMLINK, b'', 65536))
        result = []
        visited = set()

        def visit(name, depth=0):
            path = _hub_path(name)
            if path.casefold() in visited or depth > 6:
                raise RuntimeError('Unsupported USB hub topology')
            visited.add(path.casefold())
            node = self.ioctl(path, GET_NODE_INFORMATION, bytes(76), 76)
            if (len(node) < 76 or struct.unpack_from('<I', node)[0] != 0
                    or node[5] not in (0x29, 0x2a) or node[6] == 0):
                raise RuntimeError('Invalid USB hub information')
            for port in range(1, node[6] + 1):
                request = struct.pack('<I', port) + bytes(31)
                conn = decode_connection(self.ioctl(path, GET_CONNECTION_INFORMATION_EX,
                                                    request, 35), port)
                if conn is None:
                    continue
                if conn.is_hub:
                    visit(self._name(path, GET_CONNECTION_NAME, port), depth + 1)
                elif (conn.vid, conn.pid) == (0x27c6, 0x55a2):
                    result.append((conn, self._name(path, GET_DRIVERKEY_NAME, port)))
        visit(root)
        return result


_PHYSICAL = re.compile(r'USB\\VID_27C6&PID_55A2\\[A-Z0-9_&.{}+-]+', re.I)
_INTERFACE = re.compile(r'\\\\\.\\USBPcap([1-9][0-9]*)', re.I)


def parse_interfaces(text: str) -> list[tuple[str, int]]:
    result = []
    for line in text.splitlines():
        if line.startswith('interface '):
            fields = re.findall(r'\{value=([^{}]+)\}', line)
            match = _INTERFACE.fullmatch(fields[0]) if len(fields) == 1 else None
            if match is None or not 1 <= int(match[1]) <= 65535:
                raise RuntimeError('Unsupported USBPcap interface response')
            result.append((fields[0], int(match[1])))
    if not result or len({bus for _, bus in result}) != len(result):
        raise RuntimeError('No unambiguous USBPcap interfaces available')
    return result


def _physical_devices(rows):
    return [p for p in rows if _PHYSICAL.fullmatch(p.get('instance_id', ''))]


def _enabled(device):
    if device.get('present') is not True or not device.get('driver_key'):
        raise RuntimeError('Reader presence or driver cannot be verified')
    if device.get('problem') == 0 and device.get('status') == 'OK':
        return True
    if device.get('problem') == 22:  # CM_PROB_DISABLED, not every PnP error
        return False
    raise RuntimeError('Reader is not in a verified healthy or disabled state')


class WindowsBackend:
    """A fresh instance must discover a healthy device before any state change.

    _io is a test seam: interfaces(), connections(interface), pnp(),
    set_enabled(instance_id, driver_key, enabled). Never substitutes live data.
    """
    def __init__(self, usbpcap: Path, *, _io=None):
        self.usbpcap = Path(usbpcap)
        self._io = _io if _io is not None else NativeIO(self.usbpcap)
        self._verified = None

    def discover(self) -> Reader:
        self._verified = None
        devices = _physical_devices(self._io.pnp())
        if len(devices) != 1:
            raise RuntimeError('Exactly one physical Goodix 27c6:55a2 reader is required')
        device = devices[0]
        if not _enabled(device):
            raise RuntimeError('Reader must be healthy and enabled before discovery')
        hits = [(interface, bus, conn, key)
                for interface, bus in parse_interfaces(self._io.interfaces())
                for conn, key in self._io.connections(interface)
                if (conn.vid, conn.pid) == (0x27c6, 0x55a2) and not conn.is_hub]
        if len(hits) != 1:
            raise RuntimeError('Exactly one USB-mapped Goodix reader is required')
        interface, bus, conn, key = hits[0]
        if not key or device['driver_key'].casefold() != key.casefold():
            raise RuntimeError('USB connection and PnP driver identity do not match')
        reader = Reader(interface, bus, conn.address, device['instance_id'], device.get('driver_version', ''))
        self._verified = (reader, key)
        try:
            if not self.is_enabled(reader):
                raise RuntimeError('Reader state changed during discovery')
        except RuntimeError:
            self._verified = None
            raise
        return reader

    def is_enabled(self, reader: Reader) -> bool:
        if self._verified is None or self._verified[0] != reader:
            raise RuntimeError('Reader was not verified by this backend')
        devices = _physical_devices(self._io.pnp())
        if (len(devices) != 1
                or devices[0]['instance_id'].casefold() != reader.instance_id.casefold()
                or devices[0].get('driver_key', '').casefold() != self._verified[1].casefold()):
            raise RuntimeError('Reader identity changed or is ambiguous')
        return _enabled(devices[0])

    def set_enabled(self, reader: Reader, enabled: bool) -> None:
        """Caller must gate this method on recovery checks and explicit consent."""
        if type(enabled) is not bool:
            raise RuntimeError('Enabled state must be a boolean')
        current = self.is_enabled(reader)
        verified = self._verified
        assert verified is not None  # Established by is_enabled, not an input guard.
        if current != enabled:
            if not enabled:
                # Reject stale capture selection before touching the device.
                self.discover()
                if self._verified != verified:
                    raise RuntimeError('USB mapping changed; repeat preflight')
            self._io.set_enabled(reader.instance_id, verified[1], enabled)
        if self.is_enabled(reader) != enabled:
            raise RuntimeError('PnP state change could not be verified')


class KernelIoctl:
    """Minimal synchronous Win32 transport; only the five read IOCTLs above."""
    def __init__(self, *, _kernel=None):
        if _kernel is None and os.name != 'nt':
            raise RuntimeError('Windows is required')
        self.kernel = _kernel if _kernel is not None else ctypes.WinDLL('kernel32', use_last_error=True)
        ptr, dword, boolean = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
        self.kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, dword, dword, ptr, dword, dword, ptr]
        self.kernel.CreateFileW.restype = ptr
        self.kernel.DeviceIoControl.argtypes = [ptr, dword, ptr, dword, ptr, dword,
                                                ctypes.POINTER(dword), ptr]
        self.kernel.DeviceIoControl.restype = boolean
        self.kernel.CloseHandle.argtypes = [ptr]
        self.kernel.CloseHandle.restype = boolean

    def __call__(self, path, code, data, size):
        if code not in {GET_HUB_SYMLINK, GET_NODE_INFORMATION, GET_CONNECTION_NAME,
                         GET_DRIVERKEY_NAME, GET_CONNECTION_INFORMATION_EX}:
            raise RuntimeError('Unsupported USB IOCTL')
        is_filter = code == GET_HUB_SYMLINK
        # USBPcapGenReq.c explicitly allows zero-access query handles alongside
        # the sole capture handle. Never open a second capture-capable handle.
        handle = self.kernel.CreateFileW(path, 0 if is_filter else 0x40000000,
                                         0 if is_filter else 2, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value or handle is None:
            raise RuntimeError('USB interface is inaccessible; check elevation and USBPcap')
        try:
            buf = ctypes.create_string_buffer(size)
            buf[:len(data)] = data
            returned = ctypes.c_uint32()
            if not self.kernel.DeviceIoControl(handle, code, buf, len(data), buf, size,
                                                ctypes.byref(returned), None):
                raise RuntimeError('USB query failed; topology may be inaccessible or changed')
            if returned.value > size:
                raise RuntimeError('Invalid USB query length')
            return buf.raw[:returned.value]
        finally:
            self.kernel.CloseHandle(handle)


# Static scripts: identifiers are environment DATA, never PowerShell source.
# PnpDevice cmdlets: https://learn.microsoft.com/powershell/module/pnpdevice/
_PS_COMMON = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
function PhysicalDevices {
    @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
        $_.InstanceId -match '^USB\\VID_27C6&PID_55A2\\[A-Z0-9_&.{}+-]+$'
    })
}
function Property($d, $key) {
    ($d | Get-PnpDeviceProperty -KeyName $key -ErrorAction Stop).Data
}
'''
_PS_QUERY = _PS_COMMON + r'''
$rows = @(PhysicalDevices | ForEach-Object {
    [PSCustomObject]@{
        instance_id = $_.InstanceId
        driver_key = (Property $_ 'DEVPKEY_Device_Driver')
        driver_version = (Property $_ 'DEVPKEY_Device_DriverVersion')
        problem = (Property $_ 'DEVPKEY_Device_ProblemCode')
        present = $true
        status = [string]$_.Status
    }
})
ConvertTo-Json -InputObject $rows -Compress -Depth 4
'''
_PS_SET = _PS_COMMON + r'''
function VerifiedDevice {
    $ds = @(PhysicalDevices)
    if ($ds.Count -ne 1) { throw 'Ambiguous reader' }
    $d = $ds[0]
    if (-not ($d.InstanceId -ieq $env:GOODIX_INSTANCE_ID)) { throw 'Identity changed' }
    if ((Property $d 'DEVPKEY_Device_Driver') -ine $env:GOODIX_DRIVER_KEY) {
        throw 'Driver identity changed'
    }
    return $d
}
$d = VerifiedDevice
$problem = Property $d 'DEVPKEY_Device_ProblemCode'
if ($env:GOODIX_ENABLE -eq '1') {
    if ($problem -ne 22) { throw 'Reader not disabled' }
    Enable-PnpDevice -InputObject $d -Confirm:$false -ErrorAction Stop | Out-Null
    $expected = 0
} elseif ($env:GOODIX_ENABLE -eq '0') {
    if ($problem -ne 0 -or $d.Status -ne 'OK') { throw 'Reader not healthy' }
    Disable-PnpDevice -InputObject $d -Confirm:$false -ErrorAction Stop | Out-Null
    $expected = 22
} else { throw 'Invalid action' }
# The pass-through output is a Win32_PnPEntity object, not a status code; comparing it
# to 0 always threw after the action succeeded. Cmdlet errors stop the script
# (ErrorActionPreference); success is proven by the state poll below.
$verified = $false
for ($i = 0; $i -lt 40; $i++) {
    $d = VerifiedDevice
    $problem = Property $d 'DEVPKEY_Device_ProblemCode'
    if ($problem -eq $expected -and ($expected -eq 22 -or $d.Status -eq 'OK')) {
        $verified = $true
        break
    }
    Start-Sleep -Milliseconds 250
}
if (-not $verified) { throw 'PnP state verification timed out' }
'{"ok":true}'
'''


def find_usbpcap(explicit: str | None = None) -> Path:
    """Find an existing binary; never download, install, or search working directory."""
    if explicit is not None:
        candidates = [Path(explicit)]
    else:
        roots = [os.environ[k] for k in ('ProgramW6432', 'ProgramFiles', 'ProgramFiles(x86)')
                 if os.environ.get(k)]
        candidates = [Path(root) / relative for root in dict.fromkeys(roots)
                      for relative in ('USBPcap/USBPcapCMD.exe',
                                       'Wireshark/extcap/USBPcapCMD.exe',
                                       'Wireshark/USBPcapCMD.exe')]
    try:
        for path in candidates:
            if path.is_file():
                return path.resolve(strict=True)
    except OSError:
        raise RuntimeError('USBPcap executable is inaccessible') from None
    raise RuntimeError('USBPcapCMD.exe not found; supply its installed path explicitly')


def is_admin() -> bool:
    """Check elevation without prompting or requesting elevation."""
    if os.name != 'nt':
        return False
    try:
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        shell.IsUserAnAdmin.argtypes = []
        shell.IsUserAnAdmin.restype = ctypes.c_int32
        return bool(shell.IsUserAnAdmin())
    except OSError:
        return False


class NativeIO:
    def __init__(self, usbpcap: Path, *, _run=None, _ioctl=None):
        if _run is None and os.name != 'nt':
            raise RuntimeError('Windows is required')
        self.usbpcap = usbpcap
        self.run = _run if _run is not None else subprocess.run
        self.ioctl = _ioctl

    def _command(self, argv, env=None):
        try:
            result = self.run(argv, capture_output=True, text=True, encoding='utf-8',
                              errors='strict', shell=False, timeout=45, env=env)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise RuntimeError('Windows device command could not complete') from None
        if result.returncode != 0:
            raise RuntimeError('Windows device query or action failed')
        return result.stdout

    def _powershell(self, script, env=None):
        exe = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
        output = self._command([str(exe), '-NoProfile', '-NonInteractive', '-Command', script], env)
        try:
            return json.loads(output)
        except ValueError:
            raise RuntimeError('Invalid Windows device response') from None

    def interfaces(self):
        return self._command([str(self.usbpcap), '--extcap-interfaces'])

    def connections(self, interface):
        if self.ioctl is None:
            self.ioctl = KernelIoctl()
        return HubEnumerator(self.ioctl).connections(interface)

    def pnp(self):
        rows = self._powershell(_PS_QUERY)
        fields = {'instance_id': str, 'driver_key': str, 'driver_version': str,
                  'problem': int, 'present': bool, 'status': str}
        if not isinstance(rows, list) or any(
                not isinstance(row, dict)
                or any(type(row.get(k)) is not kind for k, kind in fields.items())
                for row in rows):
            raise RuntimeError('Unsupported PnP response schema')
        return rows

    def set_enabled(self, instance, key, enabled):
        if not _PHYSICAL.fullmatch(instance) or not key or type(enabled) is not bool:
            raise RuntimeError('Invalid verified reader identity or action')
        env = os.environ.copy()
        env.update(GOODIX_INSTANCE_ID=instance, GOODIX_DRIVER_KEY=key,
                   GOODIX_ENABLE='1' if enabled else '0')
        if self._powershell(_PS_SET, env) != {'ok': True}:
            raise RuntimeError('Windows PnP action was not verified')
