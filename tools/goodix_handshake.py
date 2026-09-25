#!/usr/bin/env python3
"""Handshake-only Goodix 27c6:55a2 pilot. No persistent device writes.

Protocol references (independent implementation; no upstream code executed):
  tlambertz/goodix-fingerprint-reversing@0479ce9 capture.py (MIT)
  goodix-fp-linux-dev/goodix-fp-dump@cc43bb3 goodix.py (MIT)
Commands allowed: fixed NOP, firmware query, D0 TLS request, D4 confirmation,
and (only with --query-state, once, after D4) a fixed A7 QueryMcuState(0x55).
With --query-state-pre-tls (experiment 0008) the same fixed A7 is also sent
once between the firmware query and D0; the USB boundary then allows two.
No images, outbound TLS application data, key reads/writes, firmware or reset
commands. State-query replies are summarised by flag, command and length; a 2-byte
plaintext reply is also printed and decoded as MCU state flags (experiment 0007).
With --fdt-manual (experiment 0010, needs --query-state) one fixed 3.3
McuSwitchToFdtMode "manual" frame (Lambertz's 55a2 payload) is sent after the
post-TLS A7, then A7 once more. Only its IRQ status and touch flag are printed;
the 20 FDT base bytes are recorded by length only.
"""
import struct

MAX_FRAME = 16384
STATE_QUERY = 0xae
TLS_DATA = 0xb2
FDT_MODE = 0x36
# tlambertz/goodix-fingerprint-reversing capture.py: mcuSwitchToFdtMode (55a2).
FDT_MANUAL_PAYLOAD = bytes.fromhex('0d0180a08093809b80948090808f8094808b808a8083')

class ProbeError(Exception):
    """Messages are fixed diagnostic labels, never device/SSL contents."""


def frame(flag, payload):
    if flag not in (0xa0, 0xb0) or not 1 <= len(payload) <= MAX_FRAME:
        raise ProbeError('invalid_frame_size_or_flag')
    head = struct.pack('<BH', flag, len(payload))
    return head + bytes([sum(head) & 255]) + payload


def command_frame(cmd):
    if cmd not in (0, 0xa8, 0xd0, 0xd4):
        raise ProbeError('command_not_allowed')
    payload = b'\0' * (4 if cmd == 0 else 2)
    body = struct.pack('<BH', cmd, len(payload)+1)+payload
    body += bytes([0x88 if cmd == 0 else (0xaa-sum(body)) & 255])
    return frame(0xa0, body)


def state_query_frame():
    """The single fixed A.7 QueryMcuState(0x55) frame (experiment 0006)."""
    body = struct.pack('<BH', STATE_QUERY, 2) + b'\x55'
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def fdt_manual_frame():
    """The single fixed 3.3 McuSwitchToFdtMode manual frame (experiment 0010)."""
    body = struct.pack('<BH', FDT_MODE, len(FDT_MANUAL_PAYLOAD)+1) + FDT_MANUAL_PAYLOAD
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def unpack_frame(raw, flags=(0xa0, 0xb0)):
    if len(raw) < 4 or raw[0] not in flags or raw[3] != sum(raw[:3]) & 255:
        raise ProbeError('invalid_frame_header')
    size = struct.unpack_from('<H', raw, 1)[0]
    if not 1 <= size <= MAX_FRAME or len(raw) != size+4:
        raise ProbeError('invalid_frame_length')
    return raw[0], raw[4:]


def unpack_command(body):
    if len(body) < 4:
        raise ProbeError('short_command')
    size = struct.unpack_from('<H', body, 1)[0]
    if size < 1 or len(body) != size+3 or sum(body) & 255 != 0xaa:
        raise ProbeError('invalid_command_checksum_or_length')
    return body[0], body[3:-1]


class TLSServer:
    """OpenSSL PSK server in memory: no ports, subprocess argv or key logs."""
    def __init__(self, key):
        import ssl
        if len(key) != 32:
            raise ProbeError('key_length_not_32')
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_ciphers('PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384')
        self.ctx.options |= ssl.OP_NO_TICKET
        self.ctx.set_psk_server_callback(lambda identity: key)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.connection = self.ctx.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.complete = False
        self.hello_buffer = b''
        self.hello_seen = False
        self.client_version = None
        self.client_ciphers = None
        self.protocol = self.cipher = None

    def feed(self, payload):
        if not payload or len(payload) > MAX_FRAME:
            raise ProbeError('invalid_tls_fragment')
        self.hello_seen = True
        if self.client_ciphers is None and self.hello_buffer is not None:
            self.hello_buffer += payload[:4096-len(self.hello_buffer)]
            parsed = parse_client_hello(self.hello_buffer)
            if parsed is not None:
                self.client_version, self.client_ciphers = parsed
                self.hello_buffer = None
            elif len(self.hello_buffer) >= 4096:
                self.hello_buffer = None  # give up; keep no raw bytes
        self.incoming.write(payload)

    def step(self):
        import ssl
        try:
            self.connection.do_handshake()
            self.complete = True
            self.protocol = self.connection.version()
            self.cipher = self.connection.cipher()[0]
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as exc:
            raise ProbeError('tls_handshake_rejected:' + tls_reason(exc)) from None
        return self.outgoing.read()

    def decrypt_length(self, payload):
        """Length of inbound TLS application data; plaintext is discarded.

        Prior work strips a 9-byte prefix from 0xb2 bodies; try both offsets.
        Only the first record-shaped offset is fed to OpenSSL: a failure there
        stops the run rather than trying again. A TLS alert raises a fixed label.
        """
        import ssl
        for skip in (9, 0):
            record = payload[skip:]
            if len(record) >= 5 and record[0] == 21 and record[1:3] == b'\x03\x03':
                raise ProbeError('tls_alert_in_state_reply')
            if len(record) < 5 or record[0] != 23 or record[1:3] != b'\x03\x03':
                continue
            self.incoming.write(record)
            try:
                return len(self.connection.read(MAX_FRAME))
            except ssl.SSLError:
                return None
        return None


def tls_reason(exc):
    """OpenSSL reason code only (e.g. NO_SHARED_CIPHER); never message text."""
    import re
    reason = getattr(exc, 'reason', None)
    if isinstance(reason, str) and re.fullmatch(r'[A-Z0-9_]{1,64}', reason):
        return reason
    return 'UNKNOWN'


def parse_client_hello(data):
    """Public ClientHello metadata only: version and cipher-suite IDs as hex.

    Returns None until one complete handshake record holding a ClientHello is
    present. Never returns random, session ID, extensions or PSK identity.
    """
    if len(data) < 5 or data[0] != 22:
        return None
    size = int.from_bytes(data[3:5], 'big')
    body = data[5:5+size]
    if len(body) < size or len(body) < 4 or body[0] != 1:
        return None
    offset = 4 + 2 + 32
    if len(body) < offset + 1:
        return None
    version = body[4:6].hex()
    offset += 1 + body[offset]
    if len(body) < offset + 2:
        return None
    count = int.from_bytes(body[offset:offset+2], 'big')
    suites = body[offset+2:offset+2+count]
    if count % 2 or len(suites) != count:
        return None
    ids = [suites[i:i+2].hex() for i in range(0, count, 2)][:64]
    return version, ids


def add_client_hello(report, server):
    """Failure diagnostics: public TLS version and offered suite IDs only."""
    # client_tls_version is ClientHello legacy_version (0303 even for TLS 1.3).
    if server.client_ciphers is not None:
        report['client_tls_version'] = server.client_version
        report['client_cipher_ids'] = list(server.client_ciphers)
    elif server.hello_seen:
        report['client_hello_unparsed'] = True
    server.hello_buffer = None


def validate_tls_records(data):
    offset = 0
    if not data:
        raise ProbeError('empty_tls_output')
    while offset < len(data):
        if len(data)-offset < 5 or data[offset] not in (20, 22):
            raise ProbeError('tls_output_not_handshake')
        if data[offset+1:offset+3] not in (b'\x03\x01', b'\x03\x03'):
            raise ProbeError('tls_output_version')
        size = int.from_bytes(data[offset+3:offset+5], 'big')
        offset += 5+size
        if size == 0 or offset > len(data):
            raise ProbeError('tls_output_length')


def expect_ack(wire, command, raw=None):
    flag, payload = unpack_frame(wire.receive() if raw is None else raw)
    if flag != 0xa0:
        raise ProbeError('expected_command_ack')
    cmd, body = unpack_command(payload)
    if cmd != 0xb0 or len(body) != 2 or body[0] != command or not body[1] & 1:
        raise ProbeError('invalid_command_ack')


def handshake(wire, server, report, pre_tls_query=False):
    import time
    report.update(tls_verified=False, device_confirmation_ack=False)
    for command, stage in ((0, 'nop'), (0xa8, 'firmware'), (0xd0, 'request_tls')):
        report['stage'] = stage
        wire.send(command_frame(command))
        if command == 0:
            # Prior goodix.py treats a read timeout after NOP as normal.
            raw = wire.receive_or_timeout()
            report['nop_ack'] = raw is not None
            if raw is not None:
                expect_ack(wire, 0, raw)
            continue
        expect_ack(wire, command)
        if command == 0xa8:
            flag, payload = unpack_frame(wire.receive())
            cmd, firmware = unpack_command(payload)
            if flag != 0xa0 or cmd != command or firmware.rstrip(b'\0') != b'GF3206_RTSEC_APP_10063':
                raise ProbeError('unexpected_firmware')
            if pre_tls_query:
                state_exchange(wire, server, report, 'state_pre_', allow_tls=False)
    report['stage'] = 'tls_handshake'
    # USB calls have their own deadline; bound even a synthetic endless peer.
    deadline = time.monotonic()+30
    for _ in range(64):
        if time.monotonic() >= deadline:
            raise ProbeError('handshake_deadline')
        flag, payload = unpack_frame(wire.receive())
        if flag != 0xb0:
            raise ProbeError('expected_tls_frame')
        server.feed(payload)
        outgoing = server.step()
        if outgoing:
            validate_tls_records(outgoing)
            wire.send(frame(0xb0, outgoing))
        if server.complete:
            report.update(tls_verified=True, protocol=server.protocol, cipher=server.cipher)
            report['stage'] = 'device_confirmation'
            # Prior work waits after the final server flight before further I/O.
            time.sleep(0.02)
            wire.send(command_frame(0xd4))
            expect_ack(wire, 0xd4)
            report.update(device_confirmation_ack=True, stage='complete')
            return report
    raise ProbeError('handshake_frame_limit')


STATE_BITS = (('image_valid', 0x01), ('tls_connected', 0x02), ('spi_send', 0x04), ('locked', 0x08))


def decode_state(body):
    """Experiment 0007: decode a 2-byte plaintext A.7 reply (MCU state flags only).

    Two published layouts disagree: Lambertz's 55a2 dissector reads the flags
    from byte 0, goodix-fp-dump's from byte 1. Both readings are reported.
    Only called for exactly 2 bytes; any other length stays shape-only.
    """
    if len(body) != 2:
        raise ProbeError('state_decode_length')
    out = {'state_reply_hex': body.hex()}
    for index in (0, 1):
        out['state_flags_byte%d' % index] = {name: bool(body[index] & bit) for name, bit in STATE_BITS}
        out['state_unknown_bits_byte%d' % index] = '%02x' % (body[index] & 0xf0)
    return out


def state_exchange(wire, server, report, prefix, allow_tls):
    """Send the fixed A.7 once and record the reply under `prefix`.

    Plaintext 0xa0/0xae replies of exactly 2 bytes are decoded (experiment
    0007); other lengths are shape-only. TLS 0xb2 replies are only accepted
    after the handshake (allow_tls) and never decoded.
    """
    key = lambda name: prefix + name[len('state_'):]
    report.update({'stage': 'state_query' if prefix == 'state_' else prefix + 'query',
                   key('state_query_ack'): False})
    wire.arm_state_query()
    wire.send(state_query_frame())
    expect_ack(wire, STATE_QUERY)
    report[key('state_query_ack')] = True
    flag, payload = unpack_frame(wire.receive(), (0xa0, 0xb0, TLS_DATA))
    report.update({key('state_reply_flag'): '%02x' % flag, key('state_reply_length'): len(payload)})
    if flag == 0xa0:
        cmd, body = unpack_command(payload)
        report.update({key('state_reply_cmd'): '%02x' % cmd, key('state_reply_length'): len(body)})
        if cmd != STATE_QUERY:
            raise ProbeError('unexpected_state_reply_command')
        if len(body) == 2:
            report.update({key(k): v for k, v in decode_state(body).items()})
        del body
    elif flag == TLS_DATA and allow_tls:
        report[key('state_reply_decrypted')] = False
        size = server.decrypt_length(payload)
        report[key('state_reply_decrypted')] = size is not None
        if size is None:
            raise ProbeError('state_reply_not_decrypted')
        report[key('state_reply_plaintext_length')] = size
    else:
        raise ProbeError('unexpected_state_reply_flag')
    del payload
    return report


def query_state(wire, server, report):
    """Send A.7 once after a confirmed handshake (experiment 0006)."""
    if report.get('stage') != 'complete' or not server.complete:
        raise ProbeError('state_query_before_handshake')
    state_exchange(wire, server, report, 'state_', allow_tls=True)
    report['stage'] = 'complete'
    return report


def fdt_manual(wire, server, report):
    """Experiment 0010: one fixed 3.3 manual FDT after the post-TLS A.7, then A.7.

    Expected reply (Windows log: len 25 incl. checksum): 24 bytes =
    IRQ status (LE16), touch flag (LE16), 20-byte FDT base. Only the two
    16-bit words are reported; the base is recorded by length only.
    """
    if report.get('stage') != 'complete' or not server.complete or 'state_query_ack' not in report:
        raise ProbeError('fdt_before_state_query')
    report.update(stage='fdt_manual', fdt_ack=False)
    wire.arm_fdt()
    wire.send(fdt_manual_frame())
    expect_ack(wire, FDT_MODE)
    report['fdt_ack'] = True
    flag, payload = unpack_frame(wire.receive())
    report['fdt_reply_flag'] = '%02x' % flag
    if flag != 0xa0:
        raise ProbeError('unexpected_fdt_reply_flag')
    cmd, body = unpack_command(payload)
    report.update(fdt_reply_cmd='%02x' % cmd, fdt_reply_length=len(body))
    if cmd != FDT_MODE:
        raise ProbeError('unexpected_fdt_reply_command')
    if len(body) != 24:
        raise ProbeError('unexpected_fdt_reply_length')
    irq, touch = struct.unpack_from('<HH', body)
    report.update(fdt_irq_status='%04x' % irq, fdt_touch_flag='%04x' % touch,
                  fdt_touch_zones=bin(touch & 0x3ff).count('1'), fdt_base_length=len(body)-4)
    del body, payload
    state_exchange(wire, server, report, 'state_fdt_', allow_tls=True)
    report['stage'] = 'complete'
    return report


def load_key(directory='/root/goodix-psk'):
    import os, stat
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        ds = os.fstat(directory_fd)
        if ds.st_uid != os.geteuid() or ds.st_mode & 0o077:
            raise ProbeError('key_directory_not_private')
        fd = os.open('psk.bin', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(fd, 'rb') as handle:
            fs = os.fstat(handle.fileno())
            if not stat.S_ISREG(fs.st_mode) or fs.st_uid != os.geteuid() or fs.st_mode & 0o077 or fs.st_nlink != 1:
                raise ProbeError('key_file_not_private_regular')
            key = handle.read(33)
            if len(key) != 32:
                raise ProbeError('key_length_not_32')
            return key
    finally:
        os.close(directory_fd)


class USBWire:
    """One claimed interface, fixed endpoints, no detach/reset/configuration."""
    def __init__(self, core=None, util=None, state_queries=1, fdt=False):
        if state_queries not in (1, 2):
            raise ProbeError('state_query_limit_not_allowed')
        self.fdt_allowed = fdt is True; self.fdt_armed = False; self.fdt_sent = False
        if core is None:
            import usb.core as core
            import usb.util as util
        self.core, self.util = core, util
        self.devices = []; self.claimed = False; self.buffer = b''
        self.transfers = 0; self.sent = 0; self.cleanup_confirmed = False
        self.last_op = None
        self.state_query_armed = False
        self.state_query_limit = state_queries
        self.state_queries_sent = 0

    def arm_state_query(self):
        if self.state_queries_sent >= self.state_query_limit:
            raise ProbeError('state_query_already_sent')
        self.state_query_armed = True

    def arm_fdt(self):
        if not self.fdt_allowed or self.fdt_sent:
            raise ProbeError('fdt_not_allowed')
        self.fdt_armed = True

    def __enter__(self):
        import time
        self.deadline = time.monotonic()+45
        try:
            self.devices = list(self.core.find(find_all=True, idVendor=0x27c6, idProduct=0x55a2))
            if len(self.devices) != 1:
                raise ProbeError('expected_one_reader')
            self.dev = self.devices[0]
            interfaces = list(self.dev.get_active_configuration())
            if len(interfaces) != 1:
                raise ProbeError('unexpected_interfaces')
            interface = interfaces[0]
            if (interface.bInterfaceNumber, interface.bAlternateSetting, interface.bInterfaceClass) != (0, 0, 255):
                raise ProbeError('unexpected_interface')
            if sorted((e.bEndpointAddress, e.bmAttributes & 3, e.wMaxPacketSize) for e in interface) != [(1, 2, 512), (0x82, 2, 512)]:
                raise ProbeError('unexpected_endpoints')
            if self.dev.is_kernel_driver_active(0):
                raise ProbeError('reader_has_kernel_driver')
            self.util.claim_interface(self.dev, 0); self.claimed = True
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        try:
            if self.claimed:
                self.claimed = False
                self.util.release_interface(self.dev, 0)
        finally:
            for device in self.devices:
                self.util.dispose_resources(device)
        self.cleanup_confirmed = True

    def timeout(self):
        import time
        remaining = self.deadline-time.monotonic()
        self.transfers += 1
        if remaining <= 0 or self.transfers > 512:
            raise ProbeError('usb_budget_exhausted')
        return max(1, min(2000, int(remaining*1000)))

    def send(self, raw):
        flag, payload = unpack_frame(raw)
        if flag == 0xa0:
            if raw == state_query_frame():
                if not self.state_query_armed or self.state_queries_sent >= self.state_query_limit:
                    raise ProbeError('state_query_not_armed')
                self.state_query_armed = False
                self.state_queries_sent += 1
            elif raw == fdt_manual_frame():
                if not self.fdt_allowed or not self.fdt_armed or self.fdt_sent:
                    raise ProbeError('fdt_not_armed')
                self.fdt_armed = False
                self.fdt_sent = True
            elif raw != command_frame(payload[0]):
                raise ProbeError('non_allowlisted_command_payload')
        else:
            validate_tls_records(payload)
        padded = raw + b'\0' * (-len(raw) % 64)
        self.sent += len(padded)
        if self.sent > 65536:
            raise ProbeError('usb_send_budget_exhausted')
        for offset in range(0, len(padded), 64):
            chunk = padded[offset:offset+64]
            self.last_op = 'write'
            if self.dev.write(1, chunk, timeout=self.timeout()) != len(chunk):
                raise ProbeError('short_usb_write')

    def receive(self):
        while True:
            if len(self.buffer) >= 4:
                head = self.buffer[:4]
                size = struct.unpack_from('<H', head, 1)[0]
                if head[0] not in (0xa0, 0xb0, TLS_DATA) or head[3] != sum(head[:3]) & 255 or not 1 <= size <= MAX_FRAME:
                    raise ProbeError('invalid_usb_frame_header')
                if len(self.buffer) >= size+4:
                    raw, self.buffer = self.buffer[:size+4], self.buffer[size+4:]
                    if self.buffer and not any(self.buffer):
                        self.buffer = b''  # optional zero padding at USB transfer end
                    unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
                    return raw
            self.last_op = 'read'
            chunk = bytes(self.dev.read(0x82, 65536, timeout=self.timeout()))
            if not chunk or len(self.buffer)+len(chunk) > 65536:
                raise ProbeError('invalid_usb_read_size')
            self.buffer += chunk


    def receive_or_timeout(self):
        """Only for the NOP reply: a clean read timeout means no ACK."""
        timeout_error = getattr(self.core, 'USBTimeoutError', None)
        try:
            return self.receive()
        except Exception as exc:
            if timeout_error is not None and isinstance(exc, timeout_error) and not self.buffer:
                return None
            raise


def main(argv=None):
    import argparse, json, os, resource, sys
    parser = argparse.ArgumentParser(description='One handshake-only probe; does not scan or provision the reader.')
    parser.add_argument('--run', action='store_true', help='perform the approved single hardware test from an interactive root terminal')
    parser.add_argument('--query-state', action='store_true', help='experiment 0006: after the handshake, send one fixed A.7 QueryMcuState')
    parser.add_argument('--query-state-pre-tls', action='store_true', help='experiment 0008: also send the same A.7 once before the TLS request (needs --query-state)')
    parser.add_argument('--fdt-manual', action='store_true', help='experiment 0010: after the post-TLS A.7, send one fixed 3.3 manual FDT, then A.7 again (needs --query-state; not with --query-state-pre-tls)')
    args = parser.parse_args(argv)
    report = dict(stage='preflight', tls_verified=False, device_confirmation_ack=False, usb_released=False)
    wire = report_server = None
    try:
        if not args.run:
            raise ProbeError('explicit_run_required')
        if args.query_state_pre_tls and not args.query_state:
            raise ProbeError('pre_tls_query_requires_query_state')
        if args.fdt_manual and not args.query_state:
            raise ProbeError('fdt_manual_requires_query_state')
        if args.fdt_manual and args.query_state_pre_tls:
            raise ProbeError('fdt_manual_excludes_pre_tls_query')
        if not sys.stdin.isatty() or os.geteuid() != 0 or not sys.platform.startswith('linux'):
            raise ProbeError('interactive_root_terminal_required')
        # No dumps or keylog file. Python cannot guarantee erasure of every heap copy.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if os.environ.get('SSLKEYLOGFILE'):
            raise ProbeError('key_logging_environment_refused')
        report['stage'] = 'key_permissions'
        key = load_key()
        report['stage'] = 'tls_context'
        server = TLSServer(key)
        report_server = server
        report['stage'] = 'usb_preflight'
        if args.fdt_manual:
            wire = USBWire(state_queries=2, fdt=True)
        elif args.query_state_pre_tls:
            wire = USBWire(state_queries=2)
        else:
            wire = USBWire()
        with wire:
            if args.query_state_pre_tls:
                handshake(wire, server, report, pre_tls_query=True)
            else:
                handshake(wire, server, report)
            if args.query_state:
                query_state(wire, server, report)
            if args.fdt_manual:
                fdt_manual(wire, server, report)
        report['usb_released'] = True
    except ProbeError as exc:
        report['error'] = str(exc)  # ProbeError text is fixed labels only
    except KeyboardInterrupt:
        report['error'] = 'operator_interrupted'
    except Exception as exc:
        # Never print exception messages, tracebacks, payloads, identities or keys.
        report['error'] = type(exc).__name__
    finally:
        if wire is not None:
            report['usb_released'] = wire.cleanup_confirmed
            if 'error' in report and wire.last_op:
                report['usb_last_op'] = wire.last_op
        if report_server is not None and 'error' in report:
            add_client_hello(report, report_server)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['stage'] == 'complete' and 'error' not in report else 2


if __name__ == '__main__':
    raise SystemExit(main())
