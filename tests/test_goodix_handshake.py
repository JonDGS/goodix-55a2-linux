"""Synthetic-only tests: no real key, USB device or network connection."""
import importlib.util
import pathlib
import sys
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))

SPEC = importlib.util.find_spec('goodix_handshake')
if SPEC is not None:
    import goodix_handshake as g
else:
    g = None

class FramingTests(unittest.TestCase):
    def test_exact_firmware_request_and_command_allowlist(self):
        self.assertIsNotNone(g, 'handshake pilot not implemented')
        self.assertEqual(g.command_frame(0xa8).hex(), 'a00600a6a803000000ff')
        self.assertEqual(g.unpack_frame(g.command_frame(0xd0))[0], 0xa0)
        for cmd in range(256):
            if cmd not in (0, 0xa8, 0xd0, 0xd4):
                with self.assertRaises(g.ProbeError):
                    g.command_frame(cmd)

    def test_corrupt_truncated_and_oversized_frames_rejected(self):
        self.assertIsNotNone(g, 'handshake pilot not implemented')
        frame = g.command_frame(0xa8)
        for bad in (b'', frame[:3], frame[:-1], frame+b'x', b'\xa0\xff\xff\x9e'):
            with self.assertRaises(g.ProbeError):
                g.unpack_frame(bad)
        damaged = bytearray(frame); damaged[3] ^= 1
        with self.assertRaises(g.ProbeError):
            g.unpack_frame(bytes(damaged))
        payload = g.unpack_frame(frame)[1]
        self.assertEqual(g.unpack_command(payload), (0xa8, b'\0\0'))
        with self.assertRaises(g.ProbeError):
            g.unpack_command(payload[:-1]+bytes([payload[-1]^1]))

class TLSContextTests(unittest.TestCase):
    def exchange(self, client_key, cipher='PSK-AES128-CBC-SHA', server=None):
        import ssl
        self.assertTrue(hasattr(g, 'TLSServer'), 'TLS engine missing')
        key = bytes(range(32))  # public synthetic fixture, never a device key
        server = server or g.TLSServer(key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(cipher)
        ctx.set_psk_client_callback(lambda hint: ('synthetic', client_key))
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = ctx.wrap_bio(incoming, outgoing)
        client_done = False
        for _ in range(20):
            try:
                client.do_handshake(); client_done = True
            except ssl.SSLWantReadError:
                pass
            payload = outgoing.read()
            if payload:
                server.feed(payload)
            response = server.step()
            if response:
                incoming.write(response)
            if client_done and server.complete:
                return server
        self.fail('synthetic TLS did not complete')

    def test_real_tls12_psk_handshake_in_memory(self):
        server = self.exchange(bytes(range(32)))
        self.assertTrue(server.complete)
        self.assertEqual(server.protocol, 'TLSv1.2')
        self.assertEqual(server.cipher, 'PSK-AES128-CBC-SHA')

    def test_wrong_psk_rejected_without_secret_error_text(self):
        self.assertTrue(hasattr(g, 'TLSServer'), 'TLS engine missing')
        with self.assertRaisesRegex(g.ProbeError, '^tls_handshake_rejected:[A-Z0-9_]+$') as cm:
            self.exchange(bytes(reversed(range(32))))
        self.assertNotIn('UNKNOWN', str(cm.exception))

    def test_cipher_mismatch_reports_distinct_reason(self):
        with self.assertRaisesRegex(g.ProbeError, '^tls_handshake_rejected:[A-Z0-9_]+$') as cm:
            self.exchange(bytes(range(32)), cipher='PSK-CHACHA20-POLY1305')
        self.assertEqual(str(cm.exception), 'tls_handshake_rejected:NO_SHARED_CIPHER')

    def test_client_hello_ciphers_recorded_on_mismatch(self):
        server = g.TLSServer(bytes(range(32)))
        with self.assertRaises(g.ProbeError):
            self.exchange(bytes(range(32)), cipher='PSK-CHACHA20-POLY1305', server=server)
        report = {}
        g.add_client_hello(report, server)
        self.assertEqual(report['client_tls_version'], '0303')
        self.assertIn('ccab', report['client_cipher_ids'])  # PSK-CHACHA20-POLY1305
        self.assertTrue(all(len(x) == 4 and int(x, 16) >= 0 for x in report['client_cipher_ids']))
        self.assertEqual(set(report), {'client_tls_version', 'client_cipher_ids'})

    def test_client_hello_parser_rejects_partial_or_foreign_records(self):
        self.assertIsNone(g.parse_client_hello(b''))
        self.assertIsNone(g.parse_client_hello(b'\x17\x03\x03\x00\x05hello'))
        self.assertIsNone(g.parse_client_hello(b'\x16\x03\x03\x00\x40\x01'))
        body = b'\x01\x00\x00\x2b' + b'\x03\x03' + b'\0'*32 + b'\x00' + b'\x00\x03' + b'\x00\xae\x00'
        self.assertIsNone(g.parse_client_hello(b'\x16\x03\x03' + len(body).to_bytes(2,'big') + body))
        body = b'\x01\x00\x00\x29' + b'\x03\x03' + b'\x11'*32 + b'\x00' + b'\x00\x02\x00\xae' + b'\x01\x00'
        self.assertEqual(g.parse_client_hello(b'\x16\x03\x03' + len(body).to_bytes(2,'big') + body), ('0303', ['00ae']))

    def test_fragmented_client_hello_parses_and_feed_is_unchanged(self):
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('PSK-AES128-CBC-SHA')
        ctx.set_psk_client_callback(lambda hint: ('synthetic', bytes(range(32))))
        i, o = ssl.MemoryBIO(), ssl.MemoryBIO()
        c = ctx.wrap_bio(i, o)
        try: c.do_handshake()
        except ssl.SSLWantReadError: pass
        hello = o.read()
        for size in (1, 7):
            server = g.TLSServer(bytes(range(32)))
            fed = []
            class Tap:
                def write(self, b): fed.append(bytes(b)); return len(b)
            server.incoming = Tap()
            for n in range(0, len(hello), size):
                server.feed(hello[n:n+size])
            self.assertEqual(b''.join(fed), hello)
            self.assertIn('008c', server.client_ciphers)  # PSK-AES128-CBC-SHA
            self.assertIsNone(server.hello_buffer)

    def test_unparseable_hello_is_flagged_not_reported(self):
        server = g.TLSServer(bytes(range(32)))
        server.feed(b'\x16\x03\x03\x00\x40\x01')
        report = {}
        g.add_client_hello(report, server)
        self.assertEqual(report, {'client_hello_unparsed': True})
        self.assertIsNone(server.hello_buffer)

    def test_no_client_hello_adds_nothing(self):
        report = {}
        g.add_client_hello(report, g.TLSServer(bytes(range(32))))
        self.assertEqual(report, {})

    def test_reader_offer_00ae_negotiates(self):
        # Observed reader ClientHello offered only 00ae (+ 00ff SCSV).
        server = self.exchange(bytes(range(32)), cipher='PSK-AES128-CBC-SHA256')
        self.assertTrue(server.complete)
        self.assertEqual(server.cipher, 'PSK-AES128-CBC-SHA256')
        self.assertEqual(server.client_ciphers[:1], ['00ae'])

    def test_reason_is_sanitised(self):
        class E(Exception): reason = 'bad reason; key=abc'
        self.assertEqual(g.tls_reason(E()), 'UNKNOWN')
        self.assertEqual(g.tls_reason(Exception()), 'UNKNOWN')

class SessionTests(unittest.TestCase):
    def test_exchange_uses_only_approved_commands_and_finishes(self):
        self.assertTrue(hasattr(g, 'handshake'), 'session missing')
        wire = SyntheticReader()
        result = g.handshake(wire, g.TLSServer(bytes(range(32))), {})
        self.assertTrue(result['tls_verified'])
        self.assertTrue(result['device_confirmation_ack'])
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4])
        self.assertTrue(wire.client_done)

    def test_silent_nop_continues_to_strict_firmware_check(self):
        wire = SyntheticReader(bad='silent_nop')
        result = g.handshake(wire, g.TLSServer(bytes(range(32))), {})
        self.assertFalse(result['nop_ack'])
        self.assertEqual(result['stage'], 'complete')
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4])

    def test_wrong_key_never_sends_confirmation(self):
        self.assertTrue(hasattr(g, 'handshake'), 'session missing')
        wire = SyntheticReader()
        with self.assertRaises(g.ProbeError):
            g.handshake(wire, g.TLSServer(bytes(reversed(range(32)))), {})
        self.assertNotIn(0xd4, wire.commands)

    def test_bad_ack_and_unexpected_firmware_stop_before_tls(self):
        self.assertTrue(hasattr(g, 'handshake'), 'session missing')
        for bad in ('ack', 'firmware'):
            wire = SyntheticReader(bad=bad)
            with self.assertRaises(g.ProbeError):
                g.handshake(wire, g.TLSServer(bytes(range(32))), {})
            self.assertNotIn(0xd0, wire.commands)

    def test_outbound_application_data_is_refused(self):
        self.assertTrue(hasattr(g, 'validate_tls_records'), 'TLS record guard missing')
        with self.assertRaises(g.ProbeError):
            g.validate_tls_records(b'\x17\x03\x03\x00\x01x')
        with self.assertRaises(g.ProbeError):
            g.validate_tls_records(b'\x16\x03\x03\x00\x02x')


class StateQueryTests(unittest.TestCase):
    """Experiment 0006: one fixed A.7 after a confirmed handshake."""
    def run_query(self, mode):
        wire = SyntheticReader(state=mode)
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        return wire, server, report

    def test_fixed_state_query_frame(self):
        self.assertEqual(g.state_query_frame().hex(), 'a00500a5ae020055a5')
        cmd, body = g.unpack_command(g.unpack_frame(g.state_query_frame())[1])
        self.assertEqual((cmd, body), (0xae, b'\x55'))

    def test_plaintext_reply_records_shape_only(self):
        wire, server, report = self.run_query('plain')
        g.query_state(wire, server, report)
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4, 0xae])
        self.assertEqual(report['stage'], 'complete')
        self.assertTrue(report['state_query_ack'])
        self.assertEqual((report['state_reply_flag'], report['state_reply_cmd'], report['state_reply_length']), ('a0', 'ae', 16))
        self.assertNotIn(SECRET_STATE.hex(), repr(report))

    def test_tls_data_reply_decrypts_and_records_length_only(self):
        for prefix in (9, 0):
            wire, server, report = self.run_query(('tls', prefix))
            g.query_state(wire, server, report)
            self.assertTrue(report['state_reply_decrypted'])
            self.assertEqual(report['state_reply_plaintext_length'], len(SECRET_STATE))
            self.assertEqual(report['state_reply_flag'], 'b2')
            self.assertNotIn(SECRET_STATE.hex(), repr(report))

    def test_undecryptable_tls_reply_stops(self):
        wire, server, report = self.run_query('garbage_tls')
        with self.assertRaisesRegex(g.ProbeError, 'state_reply_not_decrypted'):
            g.query_state(wire, server, report)
        self.assertFalse(report['state_reply_decrypted'])

    def test_wrong_reply_command_or_missing_ack_stops(self):
        for mode, label in (('wrong_cmd', 'unexpected_state_reply_command'), ('no_ack', 'invalid_command_ack')):
            wire, server, report = self.run_query(mode)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.query_state(wire, server, report)
            self.assertEqual(report['stage'], 'state_query')

    def test_unexpected_flag_or_alert_stops(self):
        for mode, label in (('flag_b0', 'unexpected_state_reply_flag'), ('alert', 'tls_alert_in_state_reply')):
            wire, server, report = self.run_query(mode)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.query_state(wire, server, report)

    def test_state_query_requires_completed_handshake(self):
        wire = SyntheticReader(state='plain')
        with self.assertRaises(g.ProbeError):
            g.query_state(wire, g.TLSServer(bytes(range(32))), {'stage': 'complete'})
        self.assertEqual(wire.commands, [])

    def test_usb_boundary_allows_state_query_once_and_only_when_armed(self):
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            with self.assertRaisesRegex(g.ProbeError, 'state_query_not_armed'):
                wire.send(g.state_query_frame())
            self.assertEqual(dev.written, [])
            wire.arm_state_query(); wire.send(g.state_query_frame())
            self.assertEqual(len(dev.written), 1)
            with self.assertRaises(g.ProbeError):
                wire.arm_state_query()
            with self.assertRaises(g.ProbeError):
                wire.send(g.state_query_frame())
            for cmd in range(256):
                if cmd not in (0, 0xa8, 0xd0, 0xd4):
                    with self.assertRaises(g.ProbeError):
                        wire.send(reply(cmd, b'\x55'))
            self.assertEqual(len(dev.written), 1)

    def test_usb_receive_accepts_tls_data_frames(self):
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            raw = g.frame(0xb0, b'x')
            raw = bytes([0xb2]) + raw[1:3] + bytes([sum(bytes([0xb2]) + raw[1:3]) & 255]) + raw[4:]
            dev.reads = [raw]
            self.assertEqual(wire.receive(), raw)

    def test_default_run_never_queries_state(self):
        from unittest.mock import patch
        import contextlib, io, json
        for argv, expected in ((['--run'], 0), (['--run', '--query-state'], 1)):
            calls = []
            output = io.StringIO()
            wire = unittest.mock.MagicMock()
            wire.__enter__.return_value = wire; wire.cleanup_confirmed = True
            def fake_handshake(w, s, r): r['stage'] = 'complete'; return r
            with patch('sys.stdin.isatty', return_value=True), patch('os.geteuid', return_value=0), \
                 patch.object(g, 'load_key', return_value=bytes(32)), patch.object(g, 'USBWire', return_value=wire), \
                 patch.object(g, 'handshake', side_effect=fake_handshake), \
                 patch.object(g, 'query_state', side_effect=lambda *a: calls.append(1)), \
                 patch('resource.setrlimit'), contextlib.redirect_stdout(output):
                g.main(argv)
            self.assertEqual(len(calls), expected)
            self.assertNotIn('error', json.loads(output.getvalue()))


SECRET_STATE = bytes.fromhex('5a' * 13 + 'c3')


def reply(cmd, payload):
    import struct
    body = struct.pack('<BH', cmd, len(payload)+1)+payload
    return g.frame(0xa0, body+bytes([(0xaa-sum(body)) & 255]))


class SyntheticReader:
    """Real OpenSSL client behind a synthetic Goodix packet boundary."""
    def __init__(self, bad=None, state=None):
        import ssl
        self.state = state
        self.bad = bad; self.commands = []; self.queue = []; self.client_done = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers('PSK-AES128-CBC-SHA')
        ctx.set_psk_client_callback(lambda hint: ('synthetic', bytes(range(32))))
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = ctx.wrap_bio(self.incoming, self.outgoing)

    def advance(self):
        import ssl
        try:
            self.client.do_handshake(); self.client_done = True
        except ssl.SSLWantReadError:
            pass
        data = self.outgoing.read()
        # Deliberately fragment TLS across Goodix frames.
        for start in range(0, len(data), 37):
            self.queue.append(g.frame(0xb0, data[start:start+37]))

    def send(self, raw):
        flag, body = g.unpack_frame(raw)
        if flag == 0xb0:
            self.incoming.write(body); self.advance(); return
        cmd = body[0]
        self.commands.append(cmd)
        ack = b'\x00\x00' if self.bad == 'ack' else bytes([cmd, 1])
        self.queue.append(reply(0xb0, ack))
        if cmd == 0xa8:
            fw = b'UNEXPECTED' if self.bad == 'firmware' else b'GF3206_RTSEC_APP_10063\0'
            self.queue.append(reply(cmd, fw))
        elif cmd == 0xd0:
            self.advance()
        elif cmd == 0xae:
            self.state_reply()

    def arm_state_query(self):
        pass

    def state_reply(self):
        import struct
        mode = self.state
        if mode == 'no_ack':
            self.queue[-1] = reply(0xb0, b'\xae\x00'); return
        if mode in ('plain', 'wrong_cmd'):
            self.queue.append(reply(0xa0 if mode == 'wrong_cmd' else 0xae, SECRET_STATE + b'\0\0'))
            return
        if mode == 'flag_b0':
            self.queue.append(g.frame(0xb0, b'\x16\x03\x03\x00\x01x')); return
        if mode == 'alert':
            body = b'\0' * 9 + b'\x15\x03\x03\x00\x02\x02\x28'
        elif mode == 'garbage_tls':
            body = b'\x17\x03\x03\x00\x20' + b'\x01' * 32
        else:
            prefix = mode[1]
            self.client.write(SECRET_STATE)
            body = b'\0' * prefix + self.outgoing.read()
        head = struct.pack('<BH', 0xb2, len(body))
        self.queue.append(head + bytes([sum(head) & 255]) + body)

    def receive(self):
        if not self.queue:
            raise g.ProbeError('synthetic_queue_empty')
        return self.queue.pop(0)

    def receive_or_timeout(self):
        if self.bad == 'silent_nop':
            self.queue.pop(0)  # reader stays silent after NOP
            return None
        return self.receive()

class BoundaryTests(unittest.TestCase):
    def test_key_file_must_be_private_regular_and_exact_length(self):
        import os, tempfile
        self.assertTrue(hasattr(g, 'load_key'), 'key loader missing')
        with tempfile.TemporaryDirectory() as directory:
            p = pathlib.Path(directory)/'psk.bin'
            p.write_bytes(bytes(range(32))); p.chmod(0o600)
            self.assertEqual(g.load_key(directory), bytes(range(32)))
            p.chmod(0o644)
            with self.assertRaises(g.ProbeError): g.load_key(directory)
            p.chmod(0o600); p.write_bytes(b'x'*31)
            with self.assertRaises(g.ProbeError): g.load_key(directory)
            p.unlink(); p.symlink_to('/dev/zero')
            with self.assertRaises((g.ProbeError, OSError)): g.load_key(directory)

    def test_usb_claim_release_and_final_send_guard(self):
        self.assertTrue(hasattr(g, 'USBWire'), 'USB boundary missing')
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            wire.send(g.command_frame(0xa8))
            self.assertEqual(len(dev.written[0]), 64)
            before = len(dev.written)
            for raw in (reply(0xe0, b'\0\0'), g.frame(0xb0, b'\x17\x03\x03\x00\x01x')):
                with self.assertRaises(g.ProbeError): wire.send(raw)
            self.assertEqual(len(dev.written), before)
            response = reply(0xb0, b'\xa8\x01')
            dev.reads = [response[:2], response[2:5], response[5:]+b'\0'*8]
            self.assertEqual(wire.receive(), response)
        self.assertEqual(util.calls, ['claim', 'release', 'dispose'])

    def test_usb_refuses_bound_driver_or_other_endpoints(self):
        self.assertTrue(hasattr(g, 'USBWire'), 'USB boundary missing')
        for bad in ('bound', 'endpoints', 'duplicate'):
            dev, core, util = usb_fakes(bad)
            with self.assertRaises(g.ProbeError):
                with g.USBWire(core, util): pass
            self.assertNotIn('claim', util.calls)
            self.assertIn('dispose', util.calls)
            self.assertEqual(dev.written, [])

    def test_release_failure_not_reported_as_clean(self):
        self.assertTrue(hasattr(g, 'USBWire'), 'USB boundary missing')
        dev, core, util = usb_fakes()
        def fail(*args): raise OSError('synthetic release failure')
        util.release_interface = fail
        wire = g.USBWire(core, util)
        with self.assertRaises(OSError):
            with wire: pass
        self.assertFalse(getattr(wire, 'cleanup_confirmed', True))

    def test_usb_cleanup_on_exception(self):
        self.assertTrue(hasattr(g, 'USBWire'), 'USB boundary missing')
        dev, core, util = usb_fakes()
        with self.assertRaises(RuntimeError):
            with g.USBWire(core, util): raise RuntimeError('synthetic')
        self.assertEqual(util.calls, ['claim', 'release', 'dispose'])


def usb_fakes(bad=None):
    from types import SimpleNamespace as NS
    class Interface(list):
        bInterfaceNumber=0; bAlternateSetting=0; bInterfaceClass=255
    class Device:
        written = None
        def __init__(self): self.written=[]; self.reads=[]
        def get_active_configuration(self):
            return [Interface([NS(bEndpointAddress=e, bmAttributes=2, wMaxPacketSize=512)
                               for e in (1, 0x83 if bad=='endpoints' else 0x82)])]
        def is_kernel_driver_active(self, number): return bad=='bound'
        def write(self, ep, data, timeout): self.written.append(data); return len(data)
        def read(self, ep, size, timeout): return self.reads.pop(0)
    dev = Device()
    class USBTimeoutError(Exception): pass
    core = NS(USBTimeoutError=USBTimeoutError,
              find=lambda **kwargs: [dev, dev] if bad=='duplicate' else [dev])
    calls=[]
    util=NS(calls=calls, claim_interface=lambda *args: calls.append('claim'),
            release_interface=lambda *args: calls.append('release'),
            dispose_resources=lambda *args: calls.append('dispose'))
    return dev, core, util

class NopTimeoutTests(unittest.TestCase):
    def test_only_clean_read_timeout_is_tolerated(self):
        dev, core, util = usb_fakes()
        def timeout(*a, **k): raise core.USBTimeoutError()
        with g.USBWire(core, util) as wire:
            dev.read = timeout
            self.assertIsNone(wire.receive_or_timeout())
            self.assertEqual(wire.last_op, 'read')
            with self.assertRaises(core.USBTimeoutError):
                wire.receive()  # every non-NOP read stays strict
            wire.buffer = b'\xa0'
            with self.assertRaises(core.USBTimeoutError):
                wire.receive_or_timeout()  # partial frame is not silence
        dev, core, util = usb_fakes()
        def werr(*a, **k): raise core.USBTimeoutError()
        with g.USBWire(core, util) as wire:
            dev.write = werr
            with self.assertRaises(core.USBTimeoutError):
                wire.send(g.command_frame(0))
            self.assertEqual(wire.last_op, 'write')


class CLITests(unittest.TestCase):
    def test_noninteractive_run_cannot_read_key_or_open_usb(self):
        from unittest.mock import patch
        import contextlib, io, json
        self.assertTrue(hasattr(g, 'main'), 'entry point missing')
        output = io.StringIO()
        with patch('sys.stdin.isatty', return_value=False), patch.object(g, 'load_key') as read, patch.object(g, 'USBWire') as usb, contextlib.redirect_stdout(output):
            self.assertEqual(g.main(['--run']), 2)
        read.assert_not_called(); usb.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['error'], 'interactive_root_terminal_required')

if __name__ == '__main__':
    unittest.main(verbosity=2)
