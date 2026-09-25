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

    def test_two_byte_plain_reply_is_decoded(self):
        wire = SyntheticReader(state='plain2')
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        g.query_state(wire, server, report)
        self.assertEqual(report['state_reply_length'], 2)
        self.assertEqual(report['state_reply_hex'], '0702')
        self.assertEqual(report['state_flags_byte0'], dict(image_valid=True, tls_connected=True, spi_send=True, locked=False))
        self.assertEqual(report['state_flags_byte1'], dict(image_valid=False, tls_connected=True, spi_send=False, locked=False))
        self.assertEqual(report['state_unknown_bits_byte0'], '00')

    def test_decode_state_rejects_other_lengths(self):
        for body in (b'', b'\x01', b'\x01\x02\x03'):
            with self.assertRaisesRegex(g.ProbeError, 'state_decode_length'):
                g.decode_state(body)
        self.assertEqual(g.decode_state(b'\xf2\x00')['state_unknown_bits_byte0'], 'f0')

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


class PreTLSStateQueryTests(unittest.TestCase):
    """Experiment 0008: one extra fixed A.7 after A.4 and before D.0."""
    def run_pre(self, pre, state='plain2'):
        wire = SyntheticReader(state=state, pre=pre)
        server = g.TLSServer(bytes(range(32)))
        return wire, server, {}

    def test_pre_tls_query_sits_between_firmware_and_tls_request(self):
        wire, server, report = self.run_pre('plain2')
        g.handshake(wire, server, report, pre_tls_query=True)
        g.query_state(wire, server, report)
        self.assertEqual(wire.commands, [0, 0xa8, 0xae, 0xd0, 0xd4, 0xae])
        self.assertEqual(report['stage'], 'complete')
        self.assertTrue(report['state_pre_query_ack'])
        self.assertEqual(report['state_pre_reply_hex'], '0100')
        self.assertEqual(report['state_pre_flags_byte0']['image_valid'], True)
        self.assertEqual(report['state_pre_unknown_bits_byte1'], '00')
        self.assertEqual(report['state_reply_hex'], '0702')  # post-TLS keys unchanged

    def test_default_handshake_sends_no_pre_tls_query(self):
        wire, server, report = self.run_pre('plain2')
        g.handshake(wire, server, report)
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4])
        self.assertFalse(any(k.startswith('state_pre_') for k in report))

    def test_pre_tls_failures_stop_before_tls_request(self):
        for pre, label in (('no_ack', 'invalid_command_ack'), ('wrong_cmd', 'unexpected_state_reply_command'),
                           ('tls', 'unexpected_state_reply_flag'), ('flag_b0', 'unexpected_state_reply_flag')):
            wire, server, report = self.run_pre(pre)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.handshake(wire, server, report, pre_tls_query=True)
            self.assertNotIn(0xd0, wire.commands)
            self.assertEqual(report['stage'], 'state_pre_query')

    def test_pre_tls_long_reply_is_shape_only(self):
        wire, server, report = self.run_pre('plain')
        g.handshake(wire, server, report, pre_tls_query=True)
        self.assertEqual(report['state_pre_reply_length'], 16)
        self.assertNotIn('state_pre_reply_hex', report)
        self.assertNotIn(SECRET_STATE.hex(), repr(report))

    def test_usb_boundary_allows_two_queries_only_when_enabled(self):
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            wire.arm_state_query(); wire.send(g.state_query_frame())
            with self.assertRaisesRegex(g.ProbeError, 'state_query_already_sent'):
                wire.arm_state_query()
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2) as wire:
            for _ in range(2):
                wire.arm_state_query(); wire.send(g.state_query_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_state_query()
            with self.assertRaises(g.ProbeError):
                wire.send(g.state_query_frame())
            self.assertEqual(len(dev.written), 2)
        with self.assertRaises(g.ProbeError):
            g.USBWire(core, util, state_queries=3)

    def test_cli_pre_tls_flag_requires_query_state_and_wires_through(self):
        from unittest.mock import patch
        import contextlib, io, json
        cases = ((['--run', '--query-state-pre-tls'], None, 'pre_tls_query_requires_query_state'),
                 (['--run', '--query-state'], (1, False), None),
                 (['--run', '--query-state', '--query-state-pre-tls'], (2, True), None))
        for argv, expected, error in cases:
            seen = {}
            output = io.StringIO()
            wire = unittest.mock.MagicMock()
            wire.__enter__.return_value = wire; wire.cleanup_confirmed = True
            def fake_usb(*a, **k): seen['queries'] = k.get('state_queries', 1); return wire
            def fake_handshake(w, s, r, pre_tls_query=False):
                seen['pre'] = pre_tls_query; r['stage'] = 'complete'; return r
            with patch('sys.stdin.isatty', return_value=True), patch('os.geteuid', return_value=0), \
                 patch.object(g, 'load_key', return_value=bytes(32)), patch.object(g, 'USBWire', side_effect=fake_usb), \
                 patch.object(g, 'handshake', side_effect=fake_handshake), \
                 patch.object(g, 'query_state', side_effect=lambda *a: None), \
                 patch('resource.setrlimit'), contextlib.redirect_stdout(output):
                g.main(argv)
            result = json.loads(output.getvalue())
            if error:
                self.assertEqual(result['error'], error); self.assertEqual(seen, {})
            else:
                self.assertNotIn('error', result)
                self.assertEqual((seen['queries'], seen['pre']), expected)


class FDTManualTests(unittest.TestCase):
    """Experiment 0010: one fixed 3.3 manual FDT after the post-TLS A.7, then A.7."""
    def run_fdt(self, fdt='ok'):
        wire = SyntheticReader(state='plain2', fdt=fdt)
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        g.query_state(wire, server, report)
        return wire, server, report

    def test_fixed_fdt_frame_matches_prior_work(self):
        raw = g.fdt_manual_frame()
        cmd, body = g.unpack_command(g.unpack_frame(raw)[1])
        self.assertEqual((cmd, body.hex()), (0x36, '0d0180a08093809b80948090808f8094808b808a8083'))
        self.assertEqual(len(raw), 4 + 3 + 22 + 1)

    def test_fdt_reports_words_and_base_length_only(self):
        wire, server, report = self.run_fdt()
        g.fdt_manual(wire, server, report)
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4, 0xae, 0x36, 0xae])
        self.assertEqual(report['stage'], 'complete')
        self.assertTrue(report['fdt_ack'])
        self.assertEqual((report['fdt_reply_flag'], report['fdt_reply_cmd'], report['fdt_reply_length']), ('a0', '36', 24))
        self.assertEqual((report['fdt_irq_status'], report['fdt_touch_flag'], report['fdt_touch_zones']), ('0100', '03ff', 10))
        self.assertEqual(report['fdt_base_length'], 20)
        self.assertEqual(report['state_fdt_reply_hex'], '0702')
        self.assertTrue(report['state_fdt_query_ack'])
        self.assertNotIn(SECRET_FDT_BASE.hex(), repr(report))
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))

    def test_fdt_failures_stop_before_second_state_query(self):
        for fdt, label in (('no_ack', 'invalid_command_ack'), ('wrong_cmd', 'unexpected_fdt_reply_command'),
                           ('short', 'unexpected_fdt_reply_length'), ('long', 'unexpected_fdt_reply_length'),
                           ('tls', 'invalid_frame_header'), ('flag_b0', 'unexpected_fdt_reply_flag')):
            wire, server, report = self.run_fdt(fdt)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.fdt_manual(wire, server, report)
            self.assertEqual(wire.commands.count(0xae), 1)
            self.assertEqual(report['stage'], 'fdt_manual')
            self.assertNotIn(SECRET_FDT_BASE.hex(), repr(report))

    def test_fdt_requires_completed_post_tls_state_query(self):
        wire = SyntheticReader(state='plain2', fdt='ok')
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        with self.assertRaisesRegex(g.ProbeError, 'fdt_before_state_query'):
            g.fdt_manual(wire, server, report)
        self.assertNotIn(0x36, wire.commands)

    def test_usb_boundary_allows_fdt_once_only_when_enabled_and_armed(self):
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt()
            with self.assertRaises(g.ProbeError):
                wire.send(g.fdt_manual_frame())
            self.assertEqual(dev.written, [])
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True) as wire:
            with self.assertRaisesRegex(g.ProbeError, 'fdt_not_armed'):
                wire.send(g.fdt_manual_frame())
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt()
            with self.assertRaises(g.ProbeError):
                wire.send(g.fdt_manual_frame())
            # Any other 0x36 payload (e.g. prior-work FDT-down) stays refused.
            import struct
            other = bytes.fromhex('0c0180b980b480b580af80b480ac80b280a780ab80a5')
            with self.assertRaises(g.ProbeError):
                wire.send(reply(0x36, other))
            with self.assertRaises(g.ProbeError):
                wire.send(reply(0x32, other))
            self.assertEqual(len(dev.written), 1)

    def test_cli_fdt_flag_rules_and_wiring(self):
        from unittest.mock import patch
        import contextlib, io, json
        cases = ((['--run', '--fdt-manual'], None, 'fdt_manual_requires_query_state'),
                 (['--run', '--query-state', '--query-state-pre-tls', '--fdt-manual'], None, 'fdt_manual_excludes_pre_tls_query'),
                 (['--run', '--query-state'], (1, False, False), None),
                 (['--run', '--query-state', '--fdt-manual'], (2, True, True), None))
        for argv, expected, error in cases:
            seen = {}
            output = io.StringIO()
            wire = unittest.mock.MagicMock()
            wire.__enter__.return_value = wire; wire.cleanup_confirmed = True
            def fake_usb(*a, **k):
                seen['queries'] = k.get('state_queries', 1); seen['fdt_wire'] = k.get('fdt', False); return wire
            def fake_handshake(w, s, r, pre_tls_query=False):
                r['stage'] = 'complete'; return r
            def fake_fdt(*a): seen['fdt_called'] = True
            with patch('sys.stdin.isatty', return_value=True), patch('os.geteuid', return_value=0), \
                 patch.object(g, 'load_key', return_value=bytes(32)), patch.object(g, 'USBWire', side_effect=fake_usb), \
                 patch.object(g, 'handshake', side_effect=fake_handshake), \
                 patch.object(g, 'query_state', side_effect=lambda *a: None), \
                 patch.object(g, 'fdt_manual', side_effect=fake_fdt), \
                 patch('resource.setrlimit'), contextlib.redirect_stdout(output):
                g.main(argv)
            result = json.loads(output.getvalue())
            if error:
                self.assertEqual(result['error'], error); self.assertEqual(seen, {})
            else:
                self.assertNotIn('error', result)
                self.assertEqual((seen['queries'], seen['fdt_wire'], seen.get('fdt_called', False)), expected)


SECRET_STATE = bytes.fromhex('5a' * 13 + 'c3')
SECRET_FDT_BASE = bytes.fromhex('c7e1' * 10)


def reply(cmd, payload):
    import struct
    body = struct.pack('<BH', cmd, len(payload)+1)+payload
    return g.frame(0xa0, body+bytes([(0xaa-sum(body)) & 255]))


class SyntheticReader:
    """Real OpenSSL client behind a synthetic Goodix packet boundary."""
    def __init__(self, bad=None, state=None, pre=None, fdt=None, down=None, stale=None, sleep=None, up=None):
        import ssl
        self.up = up  # event mode after a 3.2 FDT up (experiment 0012)
        self.stale = stale  # frame left queued by an earlier run
        self.sleep = sleep  # 6.0 reply mode
        self.stale_windows = []
        self.down = down  # event mode after a 3.1 FDT down (experiment 0011)
        self.event_windows = []
        self.state = state
        self.fdt = fdt  # reply mode for a 3.3 manual FDT (experiment 0010)
        self.pre = pre  # reply mode for a pre-TLS A.7 (experiment 0008)
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
        elif cmd == 0x36:
            self.fdt_reply()
        elif cmd == 0x32:
            self.down_ack()
        elif cmd == 0x34:
            if self.up == 'no_ack':
                self.queue[-1] = reply(0xb0, b'\x34\x00')
        elif cmd == 0x60:
            if self.sleep == 'late_event':
                self.queue.insert(len(self.queue)-1, reply(0x32, SECRET_FDT_BASE[:4] + SECRET_FDT_BASE))
            elif self.sleep == 'late_up':
                self.queue.insert(len(self.queue)-1, reply(0x34, SECRET_FDT_BASE[:4] + SECRET_FDT_BASE))
            elif self.sleep == 'no_ack':
                self.queue[-1] = reply(0xb0, b'\x60\x00')

    def receive_stale(self, seconds):
        assert not self.commands, 'stale check after a send'
        self.stale_windows.append(seconds)
        return self.stale

    def arm_sleep(self):
        pass

    def down_ack(self):
        if self.down == 'no_ack':
            self.queue[-1] = reply(0xb0, b'\x32\x00')

    def down_event(self):
        import struct
        mode = self.down
        body = struct.pack('<HH', 0x2, 0x1ed) + SECRET_FDT_BASE
        if mode in (None, 'timeout'):
            return None
        if mode == 'short':
            body = body[:-2]
        elif mode == 'flag_b0':
            return g.frame(0xb0, b'\x16\x03\x03\x00\x01x')
        return reply(0x36 if mode == 'wrong_cmd' else 0x32, body)

    def arm_fdt_down(self):
        pass

    def arm_fdt_up(self):
        assert 0x32 in self.commands and 0x60 not in self.commands

    def up_event(self):
        import struct
        mode = self.up
        body = struct.pack('<HH', 0x4, 0x0) + SECRET_FDT_BASE
        if mode in (None, 'timeout', 'no_ack'):
            return None
        if mode == 'short':
            body = body[:-2]
        elif mode == 'flag_b0':
            return g.frame(0xb0, b'\x16\x03\x03\x00\x01x')
        return reply(0x32 if mode == 'wrong_cmd' else 0x34, body)

    def receive_event(self, seconds):
        self.event_windows.append(seconds)
        assert not self.queue, 'unread frames before the event wait'
        return self.up_event() if 0x34 in self.commands else self.down_event()

    def fdt_reply(self):
        import struct
        mode = self.fdt
        body = struct.pack('<HH', 0x100, 0x3ff) + SECRET_FDT_BASE
        if mode == 'no_ack':
            self.queue[-1] = reply(0xb0, b'\x36\x00'); return
        if mode == 'short':
            body = body[:-2]
        elif mode == 'long':
            body += b'\0\0'
        elif mode == 'flag_b0':
            self.queue.append(g.frame(0xb0, b'\x16\x03\x03\x00\x01x')); return
        elif mode == 'tls':
            data = b'\x17\x03\x03\x00\x20' + b'\x01' * 32
            head = struct.pack('<BH', 0xb2, len(data))
            self.queue.append(head + bytes([sum(head) & 255]) + data); return
        self.queue.append(reply(0xae if mode == 'wrong_cmd' else 0x36, body))

    def arm_state_query(self):
        pass

    def arm_fdt(self):
        pass

    def state_reply(self):
        import struct
        mode = self.state
        if 0xd0 not in self.commands:
            mode = self.pre
            if mode == 'plain2':
                self.queue.append(reply(0xae, b'\x01\x00')); return
            if mode == 'tls':
                body = b'\x17\x03\x03\x00\x20' + b'\x01' * 32
                head = struct.pack('<BH', 0xb2, len(body))
                self.queue.append(head + bytes([sum(head) & 255]) + body); return
        if mode == 'no_ack':
            self.queue[-1] = reply(0xb0, b'\xae\x00'); return
        if mode == 'plain2':
            self.queue.append(reply(0xae, b'\x07\x02')); return
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

class FDTDownTests(unittest.TestCase):
    """Experiment 0011: one fixed 3.1 after the 0010 sequence, then one wait."""
    def run_down(self, down='ok'):
        wire = SyntheticReader(state='plain2', fdt='ok', down=down)
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        g.query_state(wire, server, report)
        g.fdt_manual(wire, server, report)
        return wire, server, report

    def test_fixed_fdt_down_frame_matches_prior_work(self):
        raw = g.fdt_down_frame()
        cmd, body = g.unpack_command(g.unpack_frame(raw)[1])
        self.assertEqual((cmd, body.hex()), (0x32, '0c0180b980b480b580af80b480ac80b280a780ab80a5'))
        self.assertEqual(g.FDT_DOWN_WINDOW, 15.0)

    def test_event_reports_words_and_base_length_only(self):
        wire, server, report = self.run_down()
        notes = []
        g.fdt_down(wire, server, report, notify=notes.append)
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4, 0xae, 0x36, 0xae, 0x32, 0x60])
        self.assertTrue(report['sleep_ack'])
        self.assertEqual(wire.event_windows, [15.0])
        self.assertEqual(notes, ['armed: touch the sensor now (waiting 15 s)'])
        self.assertEqual(report['stage'], 'complete')
        self.assertTrue(report['fdt_down_ack'] and report['fdt_down_event'])
        self.assertEqual((report['fdt_down_irq_status'], report['fdt_down_touch_flag'], report['fdt_down_touch_zones']),
                         ('0002', '01ed', 7))
        self.assertEqual((report['fdt_down_reply_flag'], report['fdt_down_reply_cmd'], report['fdt_down_reply_length'],
                          report['fdt_down_base_length']), ('a0', '32', 24, 20))
        self.assertEqual(report['fdt_down_wait_ms'] % 100, 0)
        self.assertNotIn(SECRET_FDT_BASE.hex(), repr(report))
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))

    def test_clean_timeout_is_a_result(self):
        wire, server, report = self.run_down('timeout')
        g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual((report['stage'], report['fdt_down_event']), ('complete', False))
        self.assertNotIn('fdt_down_touch_flag', report)
        self.assertEqual(wire.commands[-2:], [0x32, 0x60])  # timeout disarms with 6.0
        self.assertTrue(report['sleep_ack'])
        self.assertFalse(wire.queue)

    def test_late_event_before_sleep_ack_is_counted_not_decoded(self):
        wire, server, report = self.run_down('timeout')
        wire.sleep = 'late_event'
        g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual((report['stage'], report['fdt_down_late_events'], report['sleep_ack']), ('complete', 1, True))
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))

    def test_interrupt_during_wait_still_disarms_once(self):
        wire, server, report = self.run_down('timeout')
        def interrupted(seconds): raise KeyboardInterrupt
        wire.receive_event = interrupted
        with self.assertRaises(KeyboardInterrupt):
            g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual(wire.commands[-2:], [0x32, 0x60])
        self.assertEqual(wire.commands.count(0x60), 1)
        self.assertTrue(report['sleep_ack'])

    def test_disarm_failure_keeps_original_label(self):
        wire, server, report = self.run_down('wrong_cmd')
        wire.sleep = 'no_ack'
        with self.assertRaisesRegex(g.ProbeError, 'unexpected_fdt_down_reply_command'):
            g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual((wire.commands.count(0x60), report['sleep_ack']), (1, False))

    def test_usb_partial_event_discards_buffer_then_disarms(self):
        from unittest.mock import patch
        dev, core, util = usb_fakes()
        ack, event = reply(0xb0, b'\x32\x01'), reply(0x32, bytes(24))
        sleep_ack = reply(0xb0, b'\x60\x01')
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            reads = [ack, event[:10]]
            def read(ep, size, timeout):
                if reads: return reads.pop(0)
                if dev.written[-1][4] == 0x60: return sleep_ack
                raise core.USBTimeoutError()
            dev.read = read
            report = {'stage': 'complete', 'fdt_ack': True, 'state_fdt_query_ack': True}
            with self.assertRaisesRegex(g.ProbeError, 'partial_fdt_down_frame'):
                g.fdt_down(wire, type('S', (), {'complete': True})(), report, notify=lambda t: None)
            self.assertEqual([w[4] for w in dev.written], [0x36, 0x32, 0x60])
            self.assertTrue(report['sleep_ack'])

    def test_missing_sleep_ack_is_an_error(self):
        wire, server, report = self.run_down('timeout')
        wire.sleep = 'no_ack'
        with self.assertRaisesRegex(g.ProbeError, 'invalid_command_ack'):
            g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual((report['stage'], report['sleep_ack']), ('disarm', False))

    def test_failures_stop_with_fixed_labels(self):
        for down, label in (('no_ack', 'invalid_command_ack'), ('wrong_cmd', 'unexpected_fdt_down_reply_command'),
                            ('short', 'unexpected_fdt_down_reply_length'), ('flag_b0', 'unexpected_fdt_down_reply_flag')):
            wire, server, report = self.run_down(down)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.fdt_down(wire, server, report, notify=lambda t: None)
            self.assertEqual(report['stage'], 'fdt_down')
            self.assertEqual(wire.commands[-2:], [0x32, 0x60])  # disarmed despite the error
            self.assertTrue(report['sleep_ack'])
            self.assertNotIn(SECRET_FDT_BASE.hex(), repr(report))
        wire, server, report = self.run_down('no_ack')
        with self.assertRaises(g.ProbeError):
            g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertEqual(wire.event_windows, [])  # no wait without an ACK

    def test_requires_completed_fdt_manual(self):
        wire = SyntheticReader(state='plain2', fdt='ok', down='ok')
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        g.query_state(wire, server, report)
        with self.assertRaisesRegex(g.ProbeError, 'fdt_down_before_fdt_manual'):
            g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertNotIn(0x32, wire.commands)

    def test_usb_boundary_allows_fdt_down_once_after_fdt_manual(self):
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True) as wire:
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_down()
            with self.assertRaises(g.ProbeError):
                wire.send(g.fdt_down_frame())
            with self.assertRaises(g.ProbeError):
                wire.receive_event(1)
        with self.assertRaisesRegex(g.ProbeError, 'fdt_down_requires_fdt'):
            g.USBWire(core, util, fdt_down=True)
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_down()  # 3.3 not sent yet
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            with self.assertRaisesRegex(g.ProbeError, 'fdt_down_not_armed'):
                wire.send(g.fdt_down_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_down()
            with self.assertRaises(g.ProbeError):
                wire.send(g.fdt_down_frame())
            other = bytes.fromhex('0c0180b980b380b580af80b480ad80b280a780ab80a5')  # Windows-log thresholds
            for cmd in (0x32, 0x34):
                with self.assertRaises(g.ProbeError):
                    wire.send(reply(cmd, other))
            with self.assertRaises(g.ProbeError):
                wire.send(reply(0x34, g.FDT_DOWN_PAYLOAD))
            self.assertEqual(len(dev.written), 2)

    def test_deadline_is_longer_only_in_fdt_down_mode(self):
        import time
        for kwargs, expected in (({}, 45), (dict(state_queries=2, fdt=True), 45),
                                 (dict(state_queries=2, fdt=True, fdt_down=True), 70)):
            dev, core, util = usb_fakes()
            with g.USBWire(core, util, **kwargs) as wire:
                self.assertAlmostEqual(wire.deadline-time.monotonic(), expected, delta=1)

    def test_receive_event_retries_clean_timeouts_then_returns_none(self):
        from unittest.mock import patch
        dev, core, util = usb_fakes()
        clock = [1000.0]
        seen = []
        def timeout(ep, size, timeout):
            seen.append(timeout); clock[0] += timeout/1000; raise core.USBTimeoutError()
        with patch('time.monotonic', side_effect=lambda: clock[0]):
            with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
                wire.arm_fdt(); wire.send(g.fdt_manual_frame())
                wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
                dev.read = timeout
                self.assertIsNone(wire.receive_event(15))
                self.assertTrue(all(t <= 2000 for t in seen))
                self.assertLessEqual(sum(seen), 15000+2)
                self.assertIsNone(wire.window_end)

    def test_receive_event_returns_frame_and_rejects_partial(self):
        dev, core, util = usb_fakes()
        event = reply(0x32, bytes(24))
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            dev.reads = [event + bytes(64-len(event))]
            self.assertEqual(wire.receive_event(15), event)
            def partial(ep, size, timeout):
                dev.read = boom; return event[:10]
            def boom(*a, **k): raise core.USBTimeoutError()
            dev.read = partial
            with self.assertRaisesRegex(g.ProbeError, 'partial_fdt_down_frame'):
                wire.receive_event(15)

    def test_sleep_frame_allowed_once_only_after_fdt_down(self):
        cmd, body = g.unpack_command(g.unpack_frame(g.sleep_frame())[1])
        self.assertEqual((cmd, body), (0x60, b'\x01\x00'))
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            with self.assertRaises(g.ProbeError):
                wire.arm_sleep()
            with self.assertRaisesRegex(g.ProbeError, 'sleep_not_armed'):
                wire.send(g.sleep_frame())
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            with self.assertRaisesRegex(g.ProbeError, 'sleep_not_armed'):
                wire.send(g.sleep_frame())
            wire.arm_sleep(); wire.send(g.sleep_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_sleep()
            with self.assertRaises(g.ProbeError):
                wire.send(g.sleep_frame())
            with self.assertRaises(g.ProbeError):
                wire.send(reply(0x60, b'\x00\x00'))
            self.assertEqual(len(dev.written), 3)
        dev, core, util = usb_fakes()
        with g.USBWire(core, util) as wire:
            with self.assertRaises(g.ProbeError):
                wire.send(g.sleep_frame())
            self.assertEqual(dev.written, [])

    def test_event_in_same_transfer_as_ack_is_returned_without_reading(self):
        dev, core, util = usb_fakes()
        ack, event = reply(0xb0, b'\x32\x01'), reply(0x32, bytes(24))
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            dev.reads = [ack + event]
            g.expect_ack(wire, 0x32)
            def no_read(*a, **k): raise AssertionError('should not read USB')
            dev.read = no_read
            self.assertEqual(wire.receive_event(15), event)

    def test_cli_fdt_down_rules_and_wiring(self):
        from unittest.mock import patch
        import contextlib, io, json
        cases = ((['--run', '--query-state', '--fdt-down'], None, 'fdt_down_requires_fdt_manual'),
                 (['--run', '--fdt-down'], None, 'fdt_down_requires_fdt_manual'),
                 (['--run', '--query-state', '--fdt-manual'], (False, False), None),
                 (['--run', '--query-state', '--fdt-manual', '--fdt-down'], (True, True), None))
        for argv, expected, error in cases:
            seen = {}
            output = io.StringIO()
            wire = unittest.mock.MagicMock()
            wire.__enter__.return_value = wire; wire.cleanup_confirmed = True
            def fake_usb(*a, **k): seen['down_wire'] = k.get('fdt_down', False); return wire
            def fake_handshake(w, s, r, pre_tls_query=False):
                r['stage'] = 'complete'; return r
            def fake_down(*a): seen['down_called'] = True
            with patch('sys.stdin.isatty', return_value=True), patch('os.geteuid', return_value=0), \
                 patch.object(g, 'load_key', return_value=bytes(32)), patch.object(g, 'USBWire', side_effect=fake_usb), \
                 patch.object(g, 'handshake', side_effect=fake_handshake), \
                 patch.object(g, 'query_state', side_effect=lambda *a: None), \
                 patch.object(g, 'fdt_manual', side_effect=lambda *a: None), \
                 patch.object(g, 'fdt_down', side_effect=fake_down), \
                 patch('resource.setrlimit'), contextlib.redirect_stdout(output):
                g.main(argv)
            result = json.loads(output.getvalue())
            if error:
                self.assertEqual(result['error'], error); self.assertEqual(seen, {})
            else:
                self.assertNotIn('error', result)
                self.assertEqual((seen['down_wire'], seen.get('down_called', False)), expected)


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


class StaleFrameTests(unittest.TestCase):
    """A reader left armed by an earlier run is detected before any send."""
    def test_clean_reader_listens_first_then_handshakes(self):
        wire = SyntheticReader(state='plain2')
        report = g.handshake(wire, g.TLSServer(bytes(range(32))), {})
        self.assertEqual(wire.stale_windows, [g.STALE_WINDOW])
        self.assertEqual(report['stage'], 'complete')

    def test_stale_event_stops_before_any_command_shape_only(self):
        import struct
        stale = reply(0x32, struct.pack('<HH', 2, 0x3ff) + SECRET_FDT_BASE)
        wire = SyntheticReader(stale=stale)
        report = {}
        with self.assertRaisesRegex(g.ProbeError, 'stale_reader_frame'):
            g.handshake(wire, g.TLSServer(bytes(range(32))), report)
        self.assertEqual(wire.commands, [])
        self.assertEqual((report['stage'], report['stale_frame_flag'], report['stale_frame_cmd'],
                          report['stale_frame_length']), ('stale_check', 'a0', '32', 24))
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))

    def test_wrong_firmware_reply_is_summarised(self):
        wire = SyntheticReader(bad='firmware')
        report = {}
        with self.assertRaisesRegex(g.ProbeError, 'unexpected_firmware'):
            g.handshake(wire, g.TLSServer(bytes(range(32))), report)
        self.assertEqual((report['firmware_reply_cmd'], report['firmware_reply_length']), ('a8', 10))
        self.assertNotIn('UNEXPECTED', repr(report))

    def test_usb_stale_check_only_before_first_send(self):
        from unittest.mock import patch
        dev, core, util = usb_fakes()
        clock = [1000.0]
        def timeout(ep, size, timeout):
            clock[0] += timeout/1000; raise core.USBTimeoutError()
        with patch('time.monotonic', side_effect=lambda: clock[0]):
            with g.USBWire(core, util) as wire:
                dev.read = timeout
                self.assertIsNone(wire.receive_stale(g.STALE_WINDOW))
                self.assertLess(clock[0]-1000, 1)
                wire.send(g.command_frame(0))
                with self.assertRaisesRegex(g.ProbeError, 'stale_check_after_send'):
                    wire.receive_stale(g.STALE_WINDOW)
        dev, core, util = usb_fakes()
        event = reply(0x32, bytes(24))
        with g.USBWire(core, util) as wire:
            dev.reads = [event]
            self.assertEqual(wire.receive_stale(0.5), event)


class FDTUpTests(unittest.TestCase):
    """Experiment 0012: after a 0011 finger-down event, one fixed 3.2 and one wait."""
    def run_up(self, down='ok', up='ok'):
        wire = SyntheticReader(state='plain2', fdt='ok', down=down, up=up)
        server = g.TLSServer(bytes(range(32)))
        report = g.handshake(wire, server, {})
        g.query_state(wire, server, report)
        g.fdt_manual(wire, server, report)
        return wire, server, report

    def test_fixed_fdt_up_frame_matches_windows_log(self):
        cmd, body = g.unpack_command(g.unpack_frame(g.fdt_up_frame())[1])
        self.assertEqual((cmd, body.hex()), (0x34, '0e0180a08093809b80948090808f8094808b808a8083'))
        self.assertEqual(len(body), 0x16)
        self.assertEqual(g.FDT_UP_WINDOW, 15.0)

    def test_up_event_reports_words_and_base_length_only(self):
        wire, server, report = self.run_up()
        notes = []
        g.fdt_down(wire, server, report, notify=notes.append, up=True)
        self.assertEqual(wire.commands, [0, 0xa8, 0xd0, 0xd4, 0xae, 0x36, 0xae, 0x32, 0x34, 0x60])
        self.assertEqual(wire.event_windows, [15.0, 15.0])
        self.assertEqual(notes, ['armed: touch the sensor now (waiting 15 s)',
                                 'finger down: lift it now (waiting 15 s)'])
        self.assertEqual(report['stage'], 'complete')
        self.assertTrue(report['fdt_down_event'] and report['fdt_up_ack'] and report['fdt_up_event'] and report['sleep_ack'])
        self.assertEqual((report['fdt_up_irq_status'], report['fdt_up_touch_flag'], report['fdt_up_touch_zones']),
                         ('0004', '0000', 0))
        self.assertEqual((report['fdt_up_reply_flag'], report['fdt_up_reply_cmd'], report['fdt_up_reply_length'],
                          report['fdt_up_base_length']), ('a0', '34', 24, 20))
        self.assertEqual(report['fdt_up_wait_ms'] % 100, 0)
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))

    def test_up_timeout_is_a_result_and_disarms(self):
        wire, server, report = self.run_up(up='timeout')
        g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertEqual((report['stage'], report['fdt_up_event'], report['sleep_ack']), ('complete', False, True))
        self.assertEqual(wire.commands[-3:], [0x32, 0x34, 0x60])
        self.assertNotIn('fdt_up_touch_flag', report)

    def test_no_down_event_never_sends_fdt_up(self):
        wire, server, report = self.run_up(down='timeout')
        g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertNotIn(0x34, wire.commands)
        self.assertEqual(wire.commands[-2:], [0x32, 0x60])
        self.assertEqual(wire.event_windows, [15.0])
        self.assertTrue(report['fdt_up_skipped'] and report['sleep_ack'])
        self.assertNotIn('fdt_up_ack', report)

    def test_bad_down_event_never_sends_fdt_up(self):
        wire, server, report = self.run_up(down='wrong_cmd')
        with self.assertRaisesRegex(g.ProbeError, 'unexpected_fdt_down_reply_command'):
            g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertNotIn(0x34, wire.commands)
        self.assertEqual(wire.commands.count(0x60), 1)

    def test_without_up_flag_0011_is_unchanged(self):
        wire, server, report = self.run_up()
        g.fdt_down(wire, server, report, notify=lambda t: None)
        self.assertNotIn(0x34, wire.commands)
        self.assertNotIn('fdt_up_skipped', report)

    def test_up_failures_stop_with_fixed_labels_and_disarm_once(self):
        for up, label in (('no_ack', 'invalid_command_ack'), ('wrong_cmd', 'unexpected_fdt_up_reply_command'),
                          ('short', 'unexpected_fdt_up_reply_length'), ('flag_b0', 'unexpected_fdt_up_reply_flag')):
            wire, server, report = self.run_up(up=up)
            with self.assertRaisesRegex(g.ProbeError, label):
                g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
            self.assertEqual(report['stage'], 'fdt_up')
            self.assertEqual(wire.commands[-3:], [0x32, 0x34, 0x60])
            self.assertEqual(wire.commands.count(0x60), 1)
            self.assertTrue(report['sleep_ack'])
            self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))
        wire, server, report = self.run_up(up='no_ack')
        with self.assertRaises(g.ProbeError):
            g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertEqual(wire.event_windows, [15.0])  # no up wait without an ACK

    def test_interrupt_during_up_wait_disarms_once(self):
        wire, server, report = self.run_up(up='timeout')
        real = wire.receive_event
        def interrupted(seconds):
            if 0x34 in wire.commands: raise KeyboardInterrupt
            return real(seconds)
        wire.receive_event = interrupted
        with self.assertRaises(KeyboardInterrupt):
            g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertEqual(wire.commands[-3:], [0x32, 0x34, 0x60])
        self.assertEqual((report['stage'], report['sleep_ack']), ('fdt_up', True))

    def test_late_up_event_counted_only_after_fdt_up(self):
        wire, server, report = self.run_up(up='timeout')
        wire.sleep = 'late_up'
        wire.fdt_up_sent = True  # the synthetic wire mirrors USBWire's flag
        g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertEqual((report['fdt_up_late_events'], report['sleep_ack']), (1, True))
        self.assertNotIn(SECRET_FDT_BASE.hex()[:8], repr(report))
        wire, server, report = self.run_up(down='timeout')
        wire.sleep = 'late_up'
        with self.assertRaisesRegex(g.ProbeError, 'invalid_command_ack'):
            g.fdt_down(wire, server, report, notify=lambda t: None, up=True)
        self.assertNotIn('fdt_up_late_events', report)

    def test_usb_boundary_allows_fdt_up_once_between_down_and_sleep(self):
        dev, core, util = usb_fakes()
        with self.assertRaisesRegex(g.ProbeError, 'fdt_up_requires_fdt_down'):
            g.USBWire(core, util, state_queries=2, fdt=True, fdt_up=True)
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_up()  # not enabled
            with self.assertRaisesRegex(g.ProbeError, 'fdt_up_not_armed'):
                wire.send(g.fdt_up_frame())
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True, fdt_up=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_up()  # 3.1 not sent
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            with self.assertRaisesRegex(g.ProbeError, 'fdt_up_not_armed'):
                wire.send(g.fdt_up_frame())
            wire.arm_fdt_up(); wire.send(g.fdt_up_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_up()
            with self.assertRaises(g.ProbeError):
                wire.send(g.fdt_up_frame())
            first = bytes.fromhex('0e0180a3809780a08097809580938097809480' + '8f808e')  # first Windows 3.2
            with self.assertRaises(g.ProbeError):
                wire.send(reply(0x34, first))
            wire.arm_sleep(); wire.send(g.sleep_frame())
            with self.assertRaises(g.ProbeError):
                wire.receive_event(1)  # no wait after 6.0
            self.assertEqual([w[4] for w in dev.written], [0x36, 0x32, 0x34, 0x60])
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True, fdt_up=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            wire.arm_fdt_down(); wire.send(g.fdt_down_frame())
            wire.arm_sleep(); wire.send(g.sleep_frame())
            with self.assertRaises(g.ProbeError):
                wire.arm_fdt_up()  # never after 6.0

    def test_usb_partial_up_event_is_labelled_and_disarms(self):
        dev, core, util = usb_fakes()
        down_ack, down = reply(0xb0, b'\x32\x01'), reply(0x32, bytes(24))
        up_ack, up = reply(0xb0, b'\x34\x01'), reply(0x34, bytes(24))
        sleep_ack = reply(0xb0, b'\x60\x01')
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True, fdt_up=True) as wire:
            wire.arm_fdt(); wire.send(g.fdt_manual_frame())
            reads = [down_ack, down, up_ack, up[:10]]
            def read(ep, size, timeout):
                if dev.written[-1][4] == 0x60: return sleep_ack
                if reads: return reads.pop(0)
                raise core.USBTimeoutError()
            dev.read = read
            report = {'stage': 'complete', 'fdt_ack': True, 'state_fdt_query_ack': True}
            with self.assertRaisesRegex(g.ProbeError, 'partial_fdt_up_frame'):
                g.fdt_down(wire, type('S', (), {'complete': True})(), report, notify=lambda t: None, up=True)
            self.assertEqual([w[4] for w in dev.written], [0x36, 0x32, 0x34, 0x60])
            self.assertTrue(report['sleep_ack'] and report['fdt_down_event'])

    def test_deadline_covers_two_windows(self):
        import time
        dev, core, util = usb_fakes()
        with g.USBWire(core, util, state_queries=2, fdt=True, fdt_down=True, fdt_up=True) as wire:
            self.assertAlmostEqual(wire.deadline-time.monotonic(), 90, delta=1)

    def test_cli_fdt_up_rules_and_wiring(self):
        from unittest.mock import patch
        import contextlib, io, json
        cases = ((['--run', '--query-state', '--fdt-manual', '--fdt-up'], None, 'fdt_up_requires_fdt_down'),
                 (['--run', '--query-state', '--fdt-manual', '--fdt-down'], (True, False, False), None),
                 (['--run', '--query-state', '--fdt-manual', '--fdt-down', '--fdt-up'], (True, True, True), None))
        for argv, expected, error in cases:
            seen = {}
            output = io.StringIO()
            wire = unittest.mock.MagicMock()
            wire.__enter__.return_value = wire; wire.cleanup_confirmed = True
            def fake_usb(*a, **k):
                seen['wire'] = (k.get('fdt_down', False), k.get('fdt_up', False)); return wire
            def fake_handshake(w, s, r, pre_tls_query=False):
                r['stage'] = 'complete'; return r
            def fake_down(*a, up=False): seen['up'] = up
            with patch('sys.stdin.isatty', return_value=True), patch('os.geteuid', return_value=0), \
                 patch.object(g, 'load_key', return_value=bytes(32)), patch.object(g, 'USBWire', side_effect=fake_usb), \
                 patch.object(g, 'handshake', side_effect=fake_handshake), \
                 patch.object(g, 'query_state', side_effect=lambda *a: None), \
                 patch.object(g, 'fdt_manual', side_effect=lambda *a: None), \
                 patch.object(g, 'fdt_down', side_effect=fake_down), \
                 patch('resource.setrlimit'), contextlib.redirect_stdout(output):
                g.main(argv)
            report = json.loads(output.getvalue())
            if error:
                self.assertEqual(report['error'], error)
                self.assertNotIn('wire', seen)
            else:
                self.assertNotIn('error', report)
                self.assertEqual(seen['wire'] + (seen['up'],), expected)
