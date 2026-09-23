"""Synthetic fixtures only: no Windows execution or real device identifiers."""
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


class DescriptorTests(unittest.TestCase):
    def test_packed_sdk_descriptor_uses_address_not_port(self):
        self.assertIsNotNone(importlib.util.find_spec('goodix_windows'),
                             'Windows backend is not implemented')
        import goodix_windows as w
        descriptor = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x200, 0, 0, 0, 64,
                                 0x27c6, 0x55a2, 0x100, 0, 0, 0, 1)
        data = struct.pack('<I', 9) + descriptor + struct.pack('<BBB HII', 1, 2, 0, 37, 2, 1)
        self.assertEqual(len(data), 35)  # usbioctl.h includes pshpack1.h
        result = w.decode_connection(data, 9)
        self.assertEqual((result.vid, result.pid, result.address, result.is_hub),
                         (0x27c6, 0x55a2, 37, False))


def connection(port=9, vid=0x27c6, pid=0x55a2, address=37, hub=False, status=1):
    desc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x200, 0, 0, 0, 64,
                       vid, pid, 0x100, 0, 0, 0, 1)
    return struct.pack('<I', port) + desc + struct.pack('<BBBHII', 1, 2, hub, address, 0, status)


class InvalidDescriptorTests(unittest.TestCase):
    def test_absent_port_is_not_a_device(self):
        import goodix_windows as w
        self.assertIsNone(w.decode_connection(connection(status=0), 9))

    def test_rejects_malformed_or_unhealthy_connection(self):
        import goodix_windows as w
        for data in [b'', connection()[:34], connection(port=8),
                     connection(status=2), connection(address=0),
                     connection(address=128), connection()[:4] + b'\x11' + connection()[5:]]:
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                w.decode_connection(data, 9)


def wide(text):
    return (text + '\0').encode('utf-16-le')


def named(port, text):
    value = wide(text)
    return struct.pack('<II', port, 8 + len(value)) + value


class HubTests(unittest.TestCase):
    def test_traverses_usbpcap_root_and_external_hub_with_sdk_ioctls(self):
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'HubEnumerator'), 'Native hub traversal is missing')
        seen = []
        def ioctl(path, code, data, size):
            seen.append((path, code, data, size))
            if code == 0x22200c:
                self.assertEqual(path, r'\\.\USBPcap12')
                return wide(r'\??\ROOT')
            if code == 0x220408:
                raw = bytearray(76)
                raw[4:7] = bytes([71, 0x29, 1])
                return bytes(raw)
            port = struct.unpack_from('<I', data)[0]
            self.assertEqual(port, 1)
            if code == 0x220448:
                return connection(port=1, vid=0x1234, hub=True, address=2) if path.endswith('ROOT') else connection(port=1)
            if code == 0x220414:
                result = named(1, 'CHILD')
            elif code == 0x220420:
                result = named(1, '{synthetic-driver-key}\\0001')
            else:
                self.fail('Unexpected IOCTL')
            return result[:size]
        result = w.HubEnumerator(ioctl).connections(r'\\.\USBPcap12')
        self.assertEqual(result, [(w.Connection(0x27c6, 0x55a2, 37, False), '{synthetic-driver-key}\\0001')])
        self.assertIn(r'\\.\ROOT', [item[0] for item in seen])
        self.assertIn(r'\\.\CHILD', [item[0] for item in seen])
        # The whole adapter path runs on Linux with only the two OS boundaries fake.
        import json
        from types import SimpleNamespace
        def run(argv, **kwargs):
            text = FakeIO().text if argv[-1] == '--extcap-interfaces' else json.dumps([pnp()])
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        io = w.NativeIO(Path('synthetic.exe'), _run=run, _ioctl=ioctl)
        self.assertEqual(w.WindowsBackend(Path('synthetic.exe'), _io=io).discover(),
                         w.Reader(r'\\.\USBPcap12', 12, 37, INSTANCE, '1.2.3.4'))


class HubValidationTests(unittest.TestCase):
    def test_rejects_truncated_names_and_bad_hub_responses(self):
        import goodix_windows as w
        for payload in [b'', b'x', wide('') , 'ROOT'.encode('utf-16-le')]:
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                w.HubEnumerator(lambda *args: payload).connections(r'\\.\USBPcap1')
        for node in [bytes(7), bytes(76), struct.pack('<I', 1) + bytes(72)]:
            def ioctl(path, code, data, size):
                return wide('ROOT') if code == w.GET_HUB_SYMLINK else node
            with self.subTest(node=node), self.assertRaises(RuntimeError):
                w.HubEnumerator(ioctl).connections(r'\\.\USBPcap1')

    def test_rejects_name_length_and_port_mismatch(self):
        import goodix_windows as w
        for payload in [bytes(4), struct.pack('<II', 1, 0),
                        struct.pack('<II', 1, 65538), named(2, 'KEY'),
                        struct.pack('<II', 1, 100) + wide('KEY')]:
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                w.HubEnumerator(lambda *args: payload)._name('ROOT', w.GET_DRIVERKEY_NAME, 1)

    def test_rejects_topology_cycle(self):
        import goodix_windows as w
        def ioctl(path, code, data, size):
            if code == w.GET_HUB_SYMLINK:
                return wide('ROOT')
            if code == w.GET_NODE_INFORMATION:
                node = bytearray(76)
                node[4:7] = bytes([71, 0x29, 1])
                return bytes(node)
            if code == w.GET_CONNECTION_INFORMATION_EX:
                return connection(port=1, hub=True)
            return named(1, 'ROOT')[:size]
        with self.assertRaisesRegex(RuntimeError, 'topology'):
            w.HubEnumerator(ioctl).connections(r'\\.\USBPcap1')


INSTANCE = r'USB\VID_27C6&PID_55A2\SYNTHETIC'
KEY = r'{synthetic-driver-key}\0001'


def pnp(instance=INSTANCE, key=KEY, problem=0, status='OK'):
    return {'instance_id': instance, 'driver_key': key, 'problem': problem,
            'status': status, 'driver_version': '1.2.3.4', 'present': True}


class FakeIO:
    def __init__(self):
        import goodix_windows as w
        self.text = 'extcap {version=1}\ninterface {value=\\\\.\\USBPcap12}{display=ignored}\n'
        self.devices = [pnp()]
        self.hits = [(w.Connection(0x27c6, 0x55a2, 37, False), KEY)]
        self.changes = []

    def interfaces(self):
        return self.text

    def pnp(self):
        return self.devices

    def connections(self, interface):
        return self.hits

    def set_enabled(self, instance, key, enabled):
        self.changes.append((instance, key, enabled))
        self.devices[0]['problem'] = 0 if enabled else 22
        self.devices[0]['status'] = 'OK' if enabled else 'Error'


class DiscoveryTests(unittest.TestCase):
    def test_maps_driver_key_to_exact_physical_pnp_instance(self):
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'WindowsBackend'), 'Discovery backend is missing')
        io = FakeIO()
        io.devices.append(pnp(r'USB\VID_27C6&PID_55A2&MI_00\CHILD', 'other'))
        reader = w.WindowsBackend(Path('synthetic.exe'), _io=io).discover()
        self.assertEqual(reader, w.Reader(r'\\.\USBPcap12', 12, 37, INSTANCE, '1.2.3.4'))
        self.assertNotIn(INSTANCE, repr(reader))


class FailClosedDiscoveryTests(unittest.TestCase):
    def test_rejects_zero_multiple_mismatch_or_unhealthy_devices(self):
        import goodix_windows as w
        cases = [([], 'hits'), ([pnp(), pnp(INSTANCE + '2')], 'devices'),
                 ([], 'devices'), ([pnp(key='wrong')], 'devices'),
                 ([pnp(problem=22, status='Error')], 'devices'),
                 ([pnp(problem=10, status='Error')], 'devices'),
                 ([pnp(status='Unknown')], 'devices'),
                 ([pnp(instance=r'USB\VID_27C6&PID_55A20\SYNTHETIC')], 'devices'),
                 ([pnp(instance=INSTANCE + '*')], 'devices'),
                 ([{**pnp(), 'present': False}], 'devices'),
                 ([(w.Connection(0x27c6, 0x55a3, 37, False), KEY)], 'hits'),
                 ([(w.Connection(0x27c6, 0x55a2, 37, False), KEY)] * 2, 'hits')]
        for value, attr in cases:
            io = FakeIO()
            setattr(io, attr, value)
            with self.subTest(attr=attr, value=value), self.assertRaises(RuntimeError):
                w.WindowsBackend(Path('synthetic.exe'), _io=io).discover()

    def test_rejects_missing_invalid_duplicate_interfaces(self):
        import goodix_windows as w
        for text in ['', 'interface {display=USBPcap3}',
                     'interface {value=USBPcap3}', 'interface {value=\\\\.\\USBPcap0}',
                     FakeIO().text + FakeIO().text]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                w.parse_interfaces(text)

    def test_refreshes_address_and_bus_instead_of_using_prior_snapshot(self):
        import goodix_windows as w
        io = FakeIO()
        backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
        backend.discover()
        io.text = io.text.replace('USBPcap12', 'USBPcap2')
        io.hits = [(w.Connection(0x27c6, 0x55a2, 6, False), KEY)]
        self.assertEqual(backend.discover(), w.Reader(r'\\.\USBPcap2', 2, 6, INSTANCE, '1.2.3.4'))


class StateTests(unittest.TestCase):
    def test_disable_then_reenable_only_verified_identity_with_readback(self):
        import goodix_windows as w
        io = FakeIO()
        backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
        reader = backend.discover()
        self.assertTrue(hasattr(backend, 'is_enabled'), 'PnP state checks are missing')
        self.assertTrue(backend.is_enabled(reader))
        backend.set_enabled(reader, False)
        self.assertFalse(backend.is_enabled(reader))
        # Disabled reader can lack a USB connection; recovery uses verified PnP identity.
        io.hits = []
        backend.set_enabled(reader, True)
        self.assertTrue(backend.is_enabled(reader))
        self.assertEqual(io.changes, [(INSTANCE, KEY, False), (INSTANCE, KEY, True)])


class StateSafetyTests(unittest.TestCase):
    def test_rejects_non_boolean_or_changed_usb_mapping_before_disable(self):
        import goodix_windows as w
        for mode in ['type', 'address', 'missing']:
            io = FakeIO()
            backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
            reader = backend.discover()
            if mode == 'address':
                io.hits = [(w.Connection(0x27c6, 0x55a2, 8, False), KEY)]
            if mode == 'missing':
                io.hits = []
            with self.subTest(mode=mode):
                with self.assertRaises(RuntimeError):
                    backend.set_enabled(reader, 0 if mode == 'type' else False)
                self.assertEqual(io.changes, [])

    def test_never_changes_unverified_changed_or_unhealthy_pnp_identity(self):
        import goodix_windows as w
        from dataclasses import replace
        for mode in ['unverified', 'forged', 'key', 'instance', 'multiple', 'problem', 'absent']:
            io = FakeIO()
            backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
            reader = backend.discover()
            if mode == 'unverified':
                backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
            if mode == 'forged':
                reader = replace(reader, instance_id=INSTANCE + '*')
            if mode == 'key':
                io.devices[0]['driver_key'] = 'other'
            if mode == 'instance':
                io.devices[0]['instance_id'] += '2'
            if mode == 'multiple':
                io.devices.append(pnp(INSTANCE + '2'))
            if mode == 'problem':
                io.devices[0]['problem'] = 10
            if mode == 'absent':
                io.devices = []
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                backend.set_enabled(reader, False)
            self.assertEqual(io.changes, [])

    def test_action_failure_and_unchanged_state_raise(self):
        import goodix_windows as w
        for error in [True, False]:
            io = FakeIO()
            def action(*args):
                if error:
                    raise RuntimeError('Synthetic action failure')
            io.set_enabled = action
            backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
            reader = backend.discover()
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                backend.set_enabled(reader, False)


class NativeIoctlTests(unittest.TestCase):
    def test_ctypes_uses_pointer_sized_handles_and_closes_them(self):
        import ctypes
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'KernelIoctl'), 'Win32 adapter is missing')
        calls = []
        class Function:
            def __init__(self, fn):
                self.fn = fn
            def __call__(self, *args):
                return self.fn(*args)
        class Kernel:
            pass
        kernel = Kernel()
        handle = 1 << 40
        kernel.CreateFileW = Function(lambda *args: calls.append(('open', args)) or handle)
        kernel.CloseHandle = Function(lambda h: calls.append(('close', h)) or 1)
        def control(h, code, src, count, dst, size, returned, overlapped):
            self.assertEqual(h, handle)
            self.assertEqual(code, w.GET_HUB_SYMLINK)
            self.assertEqual(count, 0)
            ctypes.memmove(dst, wide('ROOT'), len(wide('ROOT')))
            ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))[0] = len(wide('ROOT'))
            return 1
        kernel.DeviceIoControl = Function(control)
        ioctl = w.KernelIoctl(_kernel=kernel)
        self.assertEqual(ioctl(r'\\.\USBPcap2', w.GET_HUB_SYMLINK, b'', 128), wide('ROOT'))
        self.assertEqual(kernel.CreateFileW.restype, ctypes.c_void_p)
        self.assertEqual(calls[-1], ('close', handle))
        self.assertEqual(calls[0][1][1:3], (0, 0))
        kernel.DeviceIoControl.fn = lambda *args: 0
        with self.assertRaises(RuntimeError):
            ioctl(r'\\.\ROOT', w.GET_NODE_INFORMATION, bytes(76), 76)
        self.assertEqual(calls[-1], ('close', handle))
        self.assertEqual(calls[-2][1][1:3], (0x40000000, 2))


class NativeProcessTests(unittest.TestCase):
    def test_extcap_and_pnp_query_use_checked_private_subprocess_output(self):
        import json
        from types import SimpleNamespace
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'NativeIO'), 'Windows subprocess adapter is missing')
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            text = FakeIO().text if argv[-1] == '--extcap-interfaces' else json.dumps([pnp()])
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        io = w.NativeIO(Path('synthetic.exe'), _run=run, _ioctl=lambda *args: b'')
        self.assertEqual(io.interfaces(), FakeIO().text)
        self.assertEqual(io.pnp(), [pnp()])
        self.assertEqual(calls[0][0], ['synthetic.exe', '--extcap-interfaces'])
        argv, kwargs = calls[1]
        self.assertIn('-NoProfile', argv)
        self.assertIn('-NonInteractive', argv)
        self.assertIn('DEVPKEY_Device_Driver', argv[-1])
        self.assertIn('DEVPKEY_Device_ProblemCode', argv[-1])
        self.assertNotIn('DEVPKEY_Device_Address', argv[-1])
        self.assertTrue(kwargs['capture_output'])
        self.assertFalse(kwargs['shell'])
        self.assertGreater(kwargs['timeout'], 0)


class NativeActionTests(unittest.TestCase):
    def test_state_command_passes_identity_as_data_and_checks_result(self):
        from types import SimpleNamespace
        import goodix_windows as w
        io = w.NativeIO(Path('synthetic.exe'), _run=lambda *a, **k: None)
        self.assertTrue(hasattr(io, 'set_enabled'), 'Native PnP action is missing')
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr='')
        io.run = run
        for enabled in [False, True]:
            io.set_enabled(INSTANCE, KEY, enabled)
            argv, kwargs = calls[-1]
            self.assertNotIn(INSTANCE, argv[-1])
            self.assertEqual(kwargs['env']['GOODIX_INSTANCE_ID'], INSTANCE)
            self.assertEqual(kwargs['env']['GOODIX_DRIVER_KEY'], KEY)
            self.assertEqual(kwargs['env']['GOODIX_ENABLE'], '1' if enabled else '0')
            self.assertIn('-PassThru', argv[-1])
            self.assertIn('-InputObject', argv[-1])
            self.assertNotIn('-InstanceId', argv[-1])
            self.assertIn('$rc[0] -ne 0', argv[-1])
            self.assertIn('-ieq $env:GOODIX_INSTANCE_ID', argv[-1])
        for bad in [INSTANCE + '*', INSTANCE + "';exit;#", r'USB\VID_27C6&PID_55A3\SYNTHETIC']:
            with self.assertRaises(RuntimeError):
                io.set_enabled(bad, KEY, False)
        self.assertEqual(len(calls), 2)
        for result in ['{"ok":false}', '{}', 'null']:
            io.run = lambda *a, **k: SimpleNamespace(returncode=0, stdout=result, stderr='')
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                io.set_enabled(INSTANCE, KEY, False)


class ProcessFailureTests(unittest.TestCase):
    def test_os_timeout_and_malformed_pnp_errors_are_generic_runtime_errors(self):
        import subprocess
        from types import SimpleNamespace
        import goodix_windows as w
        failures = [OSError(INSTANCE), subprocess.TimeoutExpired(INSTANCE, 45),
                    SimpleNamespace(returncode=1, stdout=INSTANCE, stderr=INSTANCE),
                    SimpleNamespace(returncode=0, stdout=INSTANCE, stderr='')]
        for failure in failures:
            def run(*args, **kwargs):
                if isinstance(failure, Exception):
                    raise failure
                return failure
            io = w.NativeIO(Path('synthetic.exe'), _run=run)
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(RuntimeError) as caught:
                    io.pnp()
                self.assertNotIn(INSTANCE, str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__ or caught.exception.__context__ is None)

    def test_pnp_payload_schema_rejects_missing_or_wrong_types(self):
        import json
        from types import SimpleNamespace
        import goodix_windows as w
        for data in [None, {}, [None], [{}], [{**pnp(), 'problem': '0'}],
                     [{**pnp(), 'present': 1}], [{**pnp(), 'driver_key': None}],
                     [{**pnp(), 'instance_id': 123}]]:
            io = w.NativeIO(Path('synthetic.exe'), _run=lambda *a, **k:
                            SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr=''))
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                io.pnp()


class HelperTests(unittest.TestCase):
    def test_find_usbpcap_explicit_and_standard_installs(self):
        import os
        import tempfile
        from unittest.mock import patch
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'find_usbpcap'), 'Executable discovery is missing')
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,
                {'ProgramFiles': tmp, 'ProgramFiles(x86)': tmp, 'ProgramW6432': tmp}, clear=True):
            with self.assertRaises(RuntimeError):
                w.find_usbpcap()
            for relative in ['USBPcap/USBPcapCMD.exe', 'Wireshark/extcap/USBPcapCMD.exe',
                             'Wireshark/USBPcapCMD.exe']:
                target = Path(tmp) / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'synthetic executable placeholder - never run')
                self.assertEqual(w.find_usbpcap(), target.resolve())
                self.assertEqual(w.find_usbpcap(str(target)), target.resolve())
                target.unlink()
            with self.assertRaises(RuntimeError):
                w.find_usbpcap(str(Path(tmp) / 'missing.exe'))
            with self.assertRaises(RuntimeError):
                w.find_usbpcap(tmp)

    @unittest.skipIf(sys.platform == 'win32', 'Do not perform Windows operations in unit tests')
    def test_non_windows_admin_is_false_and_native_backend_is_rejected(self):
        import goodix_windows as w
        self.assertTrue(hasattr(w, 'is_admin'), 'Admin preflight is missing')
        self.assertFalse(w.is_admin())
        with self.assertRaisesRegex(RuntimeError, 'Windows'):
            w.WindowsBackend(Path('synthetic.exe'))


class DiscoveryRaceTests(unittest.TestCase):
    def test_discovery_rechecks_pnp_after_hub_walk(self):
        import goodix_windows as w
        io = FakeIO()
        def connections(interface):
            io.devices[0]['problem'] = 10
            return io.hits
        io.connections = connections
        backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
        with self.assertRaises(RuntimeError):
            backend.discover()
        self.assertIsNone(backend._verified)

    def test_rediscovery_does_not_replace_original_driver_authorization(self):
        import goodix_windows as w
        io = FakeIO()
        backend = w.WindowsBackend(Path('synthetic.exe'), _io=io)
        reader = backend.discover()
        original_pnp = io.pnp
        count = 0
        def changed_pnp():
            nonlocal count
            count += 1
            if count == 2:
                io.devices[0]['driver_key'] = 'replacement'
                io.hits = [(io.hits[0][0], 'replacement')]
            return original_pnp()
        io.pnp = changed_pnp
        with self.assertRaises(RuntimeError):
            backend.set_enabled(reader, False)
        self.assertEqual(io.changes, [])


if __name__ == '__main__':
    unittest.main()
