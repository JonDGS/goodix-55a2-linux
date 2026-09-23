#!/usr/bin/env python3
"""Handshake-only Goodix 27c6:55a2 pilot. No persistent device writes.

Protocol references (independent implementation; no upstream code executed):
  tlambertz/goodix-fingerprint-reversing@0479ce9 capture.py (MIT)
  goodix-fp-linux-dev/goodix-fp-dump@cc43bb3 goodix.py (MIT)
Commands allowed: fixed NOP, firmware query, D0 TLS request, D4 confirmation.
No images, TLS application data, key reads/writes, firmware or reset commands.
"""
import struct

MAX_FRAME = 16384

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


def unpack_frame(raw):
    if len(raw) < 4 or raw[0] not in (0xa0, 0xb0) or raw[3] != sum(raw[:3]) & 255:
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


def handshake(wire, server, report):
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
    def __init__(self, core=None, util=None):
        if core is None:
            import usb.core as core
            import usb.util as util
        self.core, self.util = core, util
        self.devices = []; self.claimed = False; self.buffer = b''
        self.transfers = 0; self.sent = 0; self.cleanup_confirmed = False
        self.last_op = None

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
            if raw != command_frame(payload[0]):
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
                if head[0] not in (0xa0, 0xb0) or head[3] != sum(head[:3]) & 255 or not 1 <= size <= MAX_FRAME:
                    raise ProbeError('invalid_usb_frame_header')
                if len(self.buffer) >= size+4:
                    raw, self.buffer = self.buffer[:size+4], self.buffer[size+4:]
                    if self.buffer and not any(self.buffer):
                        self.buffer = b''  # optional zero padding at USB transfer end
                    unpack_frame(raw)
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
    args = parser.parse_args(argv)
    report = dict(stage='preflight', tls_verified=False, device_confirmation_ack=False, usb_released=False)
    wire = report_server = None
    try:
        if not args.run:
            raise ProbeError('explicit_run_required')
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
        wire = USBWire()
        with wire:
            handshake(wire, server, report)
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
