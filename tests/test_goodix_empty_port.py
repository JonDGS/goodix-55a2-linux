"""Synthetic regressions for the pilot's empty-port response metadata.

No captured buffers or private device identifiers are used. A zeroed fixed
prefix models NoDeviceConnected with the input ConnectionIndex not preserved.
"""
import json
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import goodix_windows as w
from test_goodix_windows import connection, named, wide, pnp, INSTANCE, KEY


class EmptyPortTests(unittest.TestCase):
    def test_no_device_with_zero_input_port_is_skipped(self):
        self.assertIsNone(w.decode_connection(bytes(35), 1))

    def test_short_empty_response_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Invalid USB connection response'):
            w.decode_connection(bytes(34), 1)

    def test_connected_port_mismatch_is_still_rejected(self):
        for returned_port in (0, 2):
            with self.subTest(returned_port=returned_port):
                with self.assertRaisesRegex(RuntimeError, 'Invalid USB connection response'):
                    w.decode_connection(connection(port=returned_port), 1)

    def test_empty_port_with_other_nonzero_index_is_still_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Invalid USB connection response'):
            w.decode_connection(connection(port=2, status=0), 1)

    def test_unhealthy_zero_index_is_not_treated_as_empty(self):
        with self.assertRaises(RuntimeError):
            w.decode_connection(connection(port=0, status=2), 1)

    def test_discovery_reaches_exact_reader_after_empty_port(self):
        queried_ports = []

        def ioctl(path, code, data, size):
            if code == w.GET_HUB_SYMLINK:
                return wide('SYNTHETIC_ROOT')
            if code == w.GET_NODE_INFORMATION:
                node = bytearray(76)
                node[4:7] = bytes((71, 0x29, 2))
                return bytes(node)
            port = struct.unpack_from('<I', data)[0]
            if code == w.GET_CONNECTION_INFORMATION_EX:
                queried_ports.append(port)
                self.assertEqual(len(data), 35)
                self.assertEqual(size, 35)
                if port == 1:
                    return bytes(35)
                self.assertEqual(port, 2)
                return connection(port=2, address=37)
            self.assertEqual(code, w.GET_DRIVERKEY_NAME)
            self.assertEqual(port, 2)  # Never look up a driver for the empty port.
            return named(2, KEY)[:size]

        def run(argv, **kwargs):
            if argv[-1] == '--extcap-interfaces':
                output = 'interface {value=\\\\.\\USBPcap12}{display=synthetic}\n'
            else:
                self.assertNotIn('Enable-PnpDevice', argv[-1])
                self.assertNotIn('Disable-PnpDevice', argv[-1])
                output = json.dumps([pnp()])
            return SimpleNamespace(returncode=0, stdout=output)

        native = w.NativeIO(Path('synthetic.exe'), _run=run, _ioctl=ioctl)
        reader = w.WindowsBackend(Path('synthetic.exe'), _io=native).discover()
        self.assertEqual(reader, w.Reader(r'\\.\USBPcap12', 12, 37, INSTANCE, '1.2.3.4'))
        self.assertEqual(queried_ports, [1, 2])


if __name__ == '__main__':
    unittest.main()
