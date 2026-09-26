#!/usr/bin/env python3
"""Handshake-only Goodix 27c6:55a2 pilot. No persistent device writes.

Protocol references (independent implementation; no upstream code executed):
  tlambertz/goodix-fingerprint-reversing@0479ce9 capture.py (MIT)
  goodix-fp-linux-dev/goodix-fp-dump@cc43bb3 goodix.py (MIT)
Commands allowed: fixed NOP, firmware query, D0 TLS request, D4 confirmation,
and (only with --query-state, once, after D4) a fixed A7 QueryMcuState(0x55).
With --query-state-pre-tls (experiment 0008) the same fixed A7 is also sent
once between the firmware query and D0; the USB boundary then allows two.
No images (except --image, shape only), outbound TLS application data, key reads/writes, firmware or reset
commands. State-query replies are summarised by flag, command and length; a 2-byte
plaintext reply is also printed and decoded as MCU state flags (experiment 0007).
With --fdt-manual (experiment 0010, needs --query-state) one fixed 3.3
McuSwitchToFdtMode "manual" frame (Lambertz's 55a2 payload) is sent after the
post-TLS A7, then A7 once more. Only its IRQ status and touch flag are printed;
the 20 FDT base bytes are recorded by length only.
With --image (experiment 0013, needs --query-state) one fixed 2.0
McuGetImage (01 00) follows the post-TLS A7, with no finger on the sensor.
The TLS image reply is decrypted in memory, measured and zeroed; only
lengths and booleans are reported, never pixel data or statistics.
With --save-image (experiment 0014) the image is also written as .raw and a
16-bit .pgm into images/ beside this tool, and coarse 12-bit statistics
(min/max/mean/stddev) are reported. --image-on-touch requests the image
right after a finger-down event (needs --fdt-down), before the single 6.0.
With --fdt-up (experiment 0012, needs --fdt-down), and only after a valid
finger-down event, one fixed 3.2 McuSwitchToFdtUp follows and one more wait
of up to 15 s for the finger-up event, still before the single 6.0.
With --fdt-down (experiment 0011, needs --fdt-manual) one fixed 3.1
McuSwitchToFdtDown frame is sent after that, then the tool waits up to 15 s
for one unrequested finger-down event. A clean timeout is a result; the event
is summarised like the 3.3 reply. Either way one fixed 6.0 McuSwitchToSleepMode
(01 00) follows, so the reader is not left armed (a timed-out 3.1 otherwise
survives a warm reboot and breaks the next run's firmware query).
Every run first listens briefly and refuses to start if the reader sends
anything unasked (stale frame from an earlier run); only its command and
length are reported. A wrong firmware reply is summarised the same way.
"""
import struct

MAX_FRAME = 16384
STATE_QUERY = 0xae
TLS_DATA = 0xb2
FDT_MODE = 0x36
# tlambertz/goodix-fingerprint-reversing capture.py: mcuSwitchToFdtMode (55a2).
FDT_MANUAL_PAYLOAD = bytes.fromhex('0d0180a08093809b80948090808f8094808b808a8083')
FDT_DOWN = 0x32
# tlambertz/goodix-fingerprint-reversing capture.py: waitForFinger (55a2).
FDT_DOWN_PAYLOAD = bytes.fromhex('0c0180b980b480b580af80b480ac80b280a780ab80a5')
FDT_DOWN_WINDOW = 15.0
FDT_UP = 0x34
# Windows unlock log 3_wbdi_singleunlock.log lines 724-727: the second 3.2
# the driver leaves armed (op 0e, 01, ten 16-bit thresholds).
FDT_UP_PAYLOAD = bytes.fromhex('0e0180a08093809b80948090808f8094808b808a8083')
FDT_UP_WINDOW = 15.0
SLEEP_MODE = 0x60
# goodix-fp-dump goodix.py mcu_switch_to_sleep_mode(); Windows unlock ends with 6.0.
SLEEP_PAYLOAD = b'\x01\x00'
GET_IMAGE = 0x20
# tlambertz capture.py getImage() (55a2) and Windows log 2_wbdi_singleunlock.log
# line 392-491: McuGetImage, payload 01 00, outDataSize 0x2.
GET_IMAGE_PAYLOAD = b'\x01\x00'
# Windows log: 'tls decrypted (14788 bytes)'; 56 x 176 12-bit pixels + 4.
IMAGE_PLAIN_LEN = 14788
IMAGE_WINDOW = 5.0
# tlambertz capture.py save_pgm: width SENSOR_HEIGHT (176), height SENSOR_WIDTH (56).
IMAGE_WIDTH, IMAGE_HEIGHT = 176, 56
STALE_WINDOW = 0.5

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


def fdt_down_frame():
    """The single fixed 3.1 McuSwitchToFdtDown frame (experiment 0011)."""
    body = struct.pack('<BH', FDT_DOWN, len(FDT_DOWN_PAYLOAD)+1) + FDT_DOWN_PAYLOAD
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def fdt_up_frame():
    """The single fixed 3.2 McuSwitchToFdtUp frame (experiment 0012)."""
    body = struct.pack('<BH', FDT_UP, len(FDT_UP_PAYLOAD)+1) + FDT_UP_PAYLOAD
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def image_frame():
    """The single fixed 2.0 McuGetImage frame (experiment 0013)."""
    body = struct.pack('<BH', GET_IMAGE, len(GET_IMAGE_PAYLOAD)+1) + GET_IMAGE_PAYLOAD
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def sleep_frame():
    """The single fixed 6.0 McuSwitchToSleepMode frame (disarms a 3.1)."""
    body = struct.pack('<BH', SLEEP_MODE, len(SLEEP_PAYLOAD)+1) + SLEEP_PAYLOAD
    return frame(0xa0, body + bytes([(0xaa-sum(body)) & 255]))


def summarise_frame(raw, prefix, report):
    """Record only flag, command and length of an unexpected frame."""
    try:
        flag, payload = unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
        report[prefix+'flag'] = '%02x' % flag
        report[prefix+'length'] = len(payload)
        if flag == 0xa0:
            cmd, body = unpack_command(payload)
            report.update({prefix+'cmd': '%02x' % cmd, prefix+'length': len(body)})
    except ProbeError:
        report[prefix+'length'] = len(raw)


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

    def image_shape(self, payload, report, keep=False):
        """Experiment 0013: decrypt an image reply; record its shape only.

        Plaintext is read into one preallocated bytearray, measured, and
        zeroed. It is never returned, hashed, printed or summarised. Python
        and OpenSSL may keep internal copies (best effort only).
        """
        import ssl
        for skip in (9, 0):
            record = payload[skip:]
            if len(record) >= 5 and record[0] == 21 and record[1:3] == b'\x03\x03':
                raise ProbeError('tls_alert_in_image_reply')
            if len(record) < 5 or record[0] != 23 or record[1:3] != b'\x03\x03':
                continue
            report.update(image_prefix_len=skip, image_record_len=len(record))
            self.incoming.write(record)
            buf = bytearray(MAX_FRAME+1)
            total = 0
            kept = None
            try:
                for _ in range(8):
                    if total >= len(buf):
                        raise ProbeError('image_plaintext_too_long')
                    view = memoryview(buf)[total:]
                    try:
                        n = self.connection.read(len(view), view)
                    except ssl.SSLWantReadError:
                        break
                    except ssl.SSLError:
                        report['image_decrypted'] = False
                        raise ProbeError('image_not_decrypted') from None
                    finally:
                        view.release()
                    if not n:
                        break
                    total += n
                if keep and total == IMAGE_PLAIN_LEN:
                    kept = bytearray(buf[:total])  # experiment 0014: saved locally, never reported
            finally:
                buf[:] = bytes(len(buf))
                del buf
            # A cut-off record stays in OpenSSL's buffer and yields nothing, so
            # it fails as image_not_decrypted below; trailing bytes are fatal.
            if self.incoming.pending or self.connection.pending():
                raise ProbeError('image_trailing_data')
            report.update(image_decrypted=total > 0, image_plain_len=total,
                          image_len_expected=total == IMAGE_PLAIN_LEN)
            if not total:
                raise ProbeError('image_not_decrypted')
            return kept
        raise ProbeError('image_reply_not_tls_record')


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
    report['stage'] = 'stale_check'
    stale = wire.receive_stale(STALE_WINDOW)
    if stale is not None:
        summarise_frame(stale, 'stale_frame_', report)
        raise ProbeError('stale_reader_frame')
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
            raw = wire.receive()
            flag, payload = unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
            cmd, firmware = unpack_command(payload) if flag == 0xa0 else (None, b'')
            if flag != 0xa0 or cmd != command or firmware.rstrip(b'\0') != b'GF3206_RTSEC_APP_10063':
                summarise_frame(raw, 'firmware_reply_', report)
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


def fdt_down(wire, server, report, notify=None, up=False, image_save=None):
    """Experiment 0011: one fixed 3.1 after the 0010 sequence, then wait once.

    The reader ACKs at once and later sends an unrequested 0x32 frame with a
    24-byte body (IRQ status LE16, touch flag LE16, 20-byte base) when a
    finger lands. A clean timeout is a result. Every path after 3.1 (event,
    timeout, bad reply, interrupt) ends with one fixed 6.0 so the reader is
    not left armed; an error keeps its own label.
    With up=True (experiment 0012) and only after a valid finger-down
    event, one fixed 3.2 follows and one wait for the finger-up event, still
    before the single 6.0.
    """
    import time
    if (report.get('stage') != 'complete' or not server.complete or not report.get('fdt_ack')
            or not report.get('state_fdt_query_ack')):
        raise ProbeError('fdt_down_before_fdt_manual')
    report.update(stage='fdt_down', fdt_down_ack=False)
    wire.arm_fdt_down()
    wire.send(fdt_down_frame())
    try:
        return fdt_down_wait(wire, report, notify, up, server, image_save)
    except BaseException:
        # 3.1 is out: never release USB with the reader armed. Best effort;
        # the original error label wins, sleep_ack records the outcome.
        stage = report.get('stage')
        if 'sleep_ack' in report:
            raise  # disarm already attempted; never send 6.0 twice
        try:
            if getattr(wire, 'buffer', b''):
                wire.buffer = b''  # discard a partial/invalid frame
            disarm(wire, report)
        except Exception:
            report['sleep_ack'] = False
        report['stage'] = stage
        raise


def fdt_down_wait(wire, report, notify, up=False, server=None, image_save=None):
    import time
    expect_ack(wire, FDT_DOWN)
    report['fdt_down_ack'] = True
    start = time.monotonic()
    if notify is None:
        import sys
        notify = lambda text: print(text, file=sys.stderr, flush=True)
    notify('armed: touch the sensor now (waiting %d s)' % int(FDT_DOWN_WINDOW))
    raw = wire.receive_event(FDT_DOWN_WINDOW)
    if raw is None:
        report['fdt_down_event'] = False
    else:
        decode_down_event(raw, start, report)
        del raw
    if getattr(wire, 'image_touch_allowed', False):
        if report['fdt_down_event']:
            # Experiment 0014: image right after the down event, as Windows does.
            request_image(wire, server, report, image_save)
        else:
            report['image_skipped'] = True  # no finger: 2.0 never sent
    if up:
        if report['fdt_down_event']:
            fdt_up_wait(wire, report, notify)
        else:
            report['fdt_up_skipped'] = True  # no finger down: 3.2 never sent
    disarm(wire, report)
    report['stage'] = 'complete'
    return report


def fdt_up_wait(wire, report, notify):
    """One fixed 3.2 right after the down event, then one up-event wait."""
    import time
    report.update(stage='fdt_up', fdt_up_ack=False)
    wire.arm_fdt_up()
    wire.send(fdt_up_frame())
    expect_ack(wire, FDT_UP)
    report['fdt_up_ack'] = True
    start = time.monotonic()
    notify('finger down: lift it now (waiting %d s)' % int(FDT_UP_WINDOW))
    raw = wire.receive_event(FDT_UP_WINDOW)
    if raw is None:
        report['fdt_up_event'] = False
    else:
        decode_fdt_event(raw, start, report, 'fdt_up_', FDT_UP)
        del raw


def decode_down_event(raw, start, report):
    decode_fdt_event(raw, start, report, 'fdt_down_', FDT_DOWN)


def decode_fdt_event(raw, start, report, prefix, command):
    import time
    report[prefix+'wait_ms'] = int(round((time.monotonic()-start)*10))*100
    flag, payload = unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
    report[prefix+'reply_flag'] = '%02x' % flag
    if flag != 0xa0:
        raise ProbeError('unexpected_'+prefix+'reply_flag')
    cmd, body = unpack_command(payload)
    report.update({prefix+'reply_cmd': '%02x' % cmd, prefix+'reply_length': len(body)})
    if cmd != command:
        raise ProbeError('unexpected_'+prefix+'reply_command')
    if len(body) != 24:
        raise ProbeError('unexpected_'+prefix+'reply_length')
    irq, touch = struct.unpack_from('<HH', body)
    report.update({prefix+'event': True, prefix+'irq_status': '%04x' % irq, prefix+'touch_flag': '%04x' % touch,
                   prefix+'touch_zones': bin(touch & 0x3ff).count('1'), prefix+'base_length': len(body)-4})
    del body, payload


def late_event_command(raw):
    """FDT_DOWN or FDT_UP for a well-formed 24-byte event frame, else None."""
    try:
        flag, payload = unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
        if flag != 0xa0:
            return None
        cmd, body = unpack_command(payload)
        return cmd if cmd in (FDT_DOWN, FDT_UP) and len(body) == 24 else None
    except ProbeError:
        return None


def disarm(wire, report):
    """One fixed 6.0 after the 3.1 (and 3.2) outcome. A finger-down or
    finger-up event that races the timeout may arrive before the ACK; it is
    counted, never decoded. An up event counts only if 3.2 was sent."""
    report.update(stage='disarm', sleep_ack=False)
    wire.arm_sleep()
    wire.send(sleep_frame())
    for _ in range(3):
        raw = wire.receive()
        late = late_event_command(raw)
        if late == FDT_UP and not getattr(wire, 'fdt_up_sent', False):
            late = None  # no 3.2 sent: not a late event, fails the ACK check
        if late is not None:
            key = 'fdt_up_late_events' if late == FDT_UP else 'fdt_down_late_events'
            report[key] = report.get(key, 0)+1
            continue
        expect_ack(wire, SLEEP_MODE, raw)
        report['sleep_ack'] = True
        return
    raise ProbeError('sleep_ack_missing')


def get_image(wire, server, report, save_tag=None):
    """Experiment 0013: one fixed 2.0 after the post-TLS A.7, no finger.

    Expects an ACK, then one 0xb2 frame whose TLS record decrypts to the
    image (Windows log: 14,788 bytes). Only lengths and booleans are
    reported. No 6.0 follows: 2.0 does not arm FDT.
    """
    if report.get('stage') != 'complete' or not server.complete or not report.get('state_query_ack'):
        raise ProbeError('image_before_state_query')
    request_image(wire, server, report, save_tag)
    report['stage'] = 'complete'
    return report


def request_image(wire, server, report, save_tag=None):
    """Shared 2.0 exchange (0013 after A.7, 0014 also after a down event)."""
    report.update(stage='image', image_ack=False)
    wire.arm_image()
    wire.send(image_frame())
    expect_ack(wire, GET_IMAGE)
    report['image_ack'] = True
    raw = wire.receive_image(IMAGE_WINDOW)
    if raw is None:
        raise ProbeError('image_timeout')
    flag, payload = unpack_frame(raw, (0xa0, 0xb0, TLS_DATA))
    del raw
    report.update(image_frame_flag='%02x' % flag, image_frame_len=len(payload))
    if flag == 0xa0:
        cmd, body = unpack_command(payload)
        report.update(image_reply_cmd='%02x' % cmd, image_frame_len=len(body))
        del body, payload
        raise ProbeError('image_reply_plaintext')
    if flag != TLS_DATA:
        del payload
        raise ProbeError('unexpected_image_reply_flag')
    try:
        plain = server.image_shape(payload, report, keep=save_tag is not None)
    finally:
        del payload
    if save_tag is not None:
        report['image_saved'] = False
        if plain is None:
            report['image_save_skipped'] = 'unexpected_length'
        else:
            try:
                save_image(plain, save_tag, report)
            finally:
                plain[:] = bytes(len(plain))
                del plain


def unpack_pixels(data):
    """12-bit unpack, 6 bytes -> 4 values (tlambertz capture.py unpack_data_to_16bit)."""
    if len(data) % 6:
        raise ProbeError('image_pack_length')
    out = []
    for i in range(0, len(data), 6):
        b = data[i:i+6]
        out += [((b[0] & 0xf) << 8) | b[1], (b[3] << 4) | (b[0] >> 4),
                ((b[5] & 0xf) << 8) | b[2], (b[4] << 4) | (b[5] >> 4)]
    return out


def image_directory():
    import os
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images')


def save_image(plain, tag, report, directory=None):
    """Experiment 0014: write .raw and a 16-bit P5 .pgm beside the tool.

    Report gets the basename and coarse 12-bit statistics only; never pixel
    values, rows, hashes or trailer bytes. Files are never overwritten.
    Intermediate immutable copies (bytes, pixel list) can't be zeroed.
    """
    import os, time, math
    if tag not in ('nofinger', 'finger') or len(plain) != IMAGE_PLAIN_LEN:
        raise ProbeError('image_save_arguments')
    pixels = unpack_pixels(bytes(plain[:-4]))
    if len(pixels) != IMAGE_WIDTH*IMAGE_HEIGHT:
        raise ProbeError('image_pixel_count')
    directory = directory or image_directory()
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    owner = (int(uid), int(gid)) if uid and gid and uid.isdigit() and gid.isdigit() else None
    base = time.strftime('%Y%m%d-%H%M%S') + '-' + tag
    written = []
    try:
        if not os.path.isdir(directory):
            os.mkdir(directory)
            if owner:
                os.chown(directory, *owner)
        pgm = b'P5\n%d %d\n4095\n' % (IMAGE_WIDTH, IMAGE_HEIGHT) + b''.join(v.to_bytes(2, 'big') for v in pixels)
        for suffix, data in (('.raw', bytes(plain)), ('.pgm', pgm)):
            path = os.path.join(directory, base + suffix)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            written.append(path)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
            if owner:
                os.chown(path, *owner)
        del pgm
    except BaseException as exc:
        # Remove partial files on any failure, including Ctrl-C.
        for path in written:
            try:
                os.unlink(path)
            except OSError:
                pass
        if isinstance(exc, OSError):
            raise ProbeError('image_save_failed') from None
        raise
    mean = sum(pixels)/len(pixels)
    std = math.sqrt(sum((v-mean)**2 for v in pixels)/len(pixels))
    report.update(image_saved=True, image_file=base, image_pixel_count=len(pixels),
                  image_min=min(pixels), image_max=max(pixels),
                  image_mean=round(mean, 1), image_stddev=round(std, 1))
    del pixels


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
    def __init__(self, core=None, util=None, state_queries=1, fdt=False, fdt_down=False, fdt_up=False, image=False, image_touch=False):
        if image_touch is True and (fdt_down is not True or fdt_up is True or image is True):
            raise ProbeError('image_touch_mode_invalid')
        self.image_touch_allowed = image_touch is True
        if image is True and (fdt is True or state_queries != 1):
            raise ProbeError('image_excludes_other_modes')
        self.image_allowed = image is True; self.image_armed = False; self.image_sent = False
        if state_queries not in (1, 2):
            raise ProbeError('state_query_limit_not_allowed')
        if fdt_down is True and fdt is not True:
            raise ProbeError('fdt_down_requires_fdt')
        self.fdt_allowed = fdt is True; self.fdt_armed = False; self.fdt_sent = False
        if fdt_up is True and fdt_down is not True:
            raise ProbeError('fdt_up_requires_fdt_down')
        self.fdt_down_allowed = fdt_down is True; self.fdt_down_armed = False; self.fdt_down_sent = False
        self.fdt_up_allowed = fdt_up is True; self.fdt_up_armed = False; self.fdt_up_sent = False
        self.window_end = None
        self.sleep_armed = False; self.sleep_sent = False; self.sent_any = False
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

    def arm_fdt_down(self):
        if not self.fdt_down_allowed or not self.fdt_sent or self.fdt_down_sent:
            raise ProbeError('fdt_down_not_allowed')
        self.fdt_down_armed = True

    def arm_fdt_up(self):
        if not self.fdt_up_allowed or not self.fdt_down_sent or self.fdt_up_sent or self.sleep_sent:
            raise ProbeError('fdt_up_not_allowed')
        self.fdt_up_armed = True

    def arm_image(self):
        if not self.image_stage_ok():
            raise ProbeError('image_not_allowed')
        self.image_armed = True

    def image_stage_ok(self):
        if self.image_sent:
            return False
        if self.image_touch_allowed:
            return self.fdt_down_sent and not self.sleep_sent
        return self.image_allowed and self.state_queries_sent == 1

    def arm_sleep(self):
        if not self.fdt_down_sent or self.sleep_sent:
            raise ProbeError('sleep_not_allowed')
        self.sleep_armed = True

    def __enter__(self):
        import time
        # 0011 adds a 15 s wait window, 0012 a second; only those modes get longer.
        self.deadline = time.monotonic()+(90 if self.fdt_up_allowed else 70 if self.fdt_down_allowed else 45)
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
        now = time.monotonic()
        remaining = self.deadline-now
        self.transfers += 1
        if remaining <= 0 or self.transfers > 512:
            raise ProbeError('usb_budget_exhausted')
        if self.window_end is not None:
            remaining = min(remaining, self.window_end-now)
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
            elif raw == fdt_down_frame():
                if not self.fdt_down_allowed or not self.fdt_down_armed or self.fdt_down_sent or not self.fdt_sent:
                    raise ProbeError('fdt_down_not_armed')
                self.fdt_down_armed = False
                self.fdt_down_sent = True
            elif raw == fdt_up_frame():
                if (not self.fdt_up_allowed or not self.fdt_up_armed or self.fdt_up_sent
                        or not self.fdt_down_sent or self.sleep_sent):
                    raise ProbeError('fdt_up_not_armed')
                self.fdt_up_armed = False
                self.fdt_up_sent = True
            elif raw == image_frame():
                if not self.image_armed or not self.image_stage_ok():
                    raise ProbeError('image_not_armed')
                self.image_armed = False
                self.image_sent = True
            elif raw == sleep_frame():
                if not self.sleep_armed or self.sleep_sent or not self.fdt_down_sent:
                    raise ProbeError('sleep_not_armed')
                self.sleep_armed = False
                self.sleep_sent = True
            elif raw != command_frame(payload[0]):
                raise ProbeError('non_allowlisted_command_payload')
        else:
            validate_tls_records(payload)
        self.sent_any = True
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


    def receive_event(self, seconds):
        """Only after the 3.1 ACK: one frame, or None on a clean timeout.

        Read timeouts with an empty buffer are retried until the window ends;
        a timeout with a partial frame buffered is an error.
        """
        if not self.fdt_down_sent or self.sleep_sent:
            raise ProbeError('fdt_down_not_sent')
        label = 'partial_fdt_up_frame' if self.fdt_up_sent else 'partial_fdt_down_frame'
        return self.receive_window(seconds, label)

    def receive_image(self, seconds):
        """Only after the 2.0 ACK: one frame, or None on a clean timeout."""
        if not self.image_sent:
            raise ProbeError('image_not_sent')
        return self.receive_window(seconds, 'partial_image_frame')

    def receive_stale(self, seconds):
        """Before the first send only: any frame here was not asked for."""
        if self.sent_any:
            raise ProbeError('stale_check_after_send')
        return self.receive_window(seconds, 'partial_stale_frame')

    def receive_window(self, seconds, partial_label):
        import time
        timeout_error = getattr(self.core, 'USBTimeoutError', None)
        end = time.monotonic()+seconds
        if end >= self.deadline:
            raise ProbeError('wait_window_exceeds_deadline')
        self.window_end = end
        try:
            while True:
                if not self.buffer and time.monotonic() >= end:
                    return None
                try:
                    return self.receive()
                except Exception as exc:
                    if timeout_error is None or not isinstance(exc, timeout_error):
                        raise
                    if self.buffer:
                        raise ProbeError(partial_label)
        finally:
            self.window_end = None


def main(argv=None):
    import argparse, json, os, resource, sys
    parser = argparse.ArgumentParser(description='One handshake-only probe; does not scan or provision the reader.')
    parser.add_argument('--run', action='store_true', help='perform the approved single hardware test from an interactive root terminal')
    parser.add_argument('--query-state', action='store_true', help='experiment 0006: after the handshake, send one fixed A.7 QueryMcuState')
    parser.add_argument('--query-state-pre-tls', action='store_true', help='experiment 0008: also send the same A.7 once before the TLS request (needs --query-state)')
    parser.add_argument('--fdt-manual', action='store_true', help='experiment 0010: after the post-TLS A.7, send one fixed 3.3 manual FDT, then A.7 again (needs --query-state; not with --query-state-pre-tls)')
    parser.add_argument('--fdt-down', action='store_true', help='experiment 0011: after --fdt-manual, send one fixed 3.1 FDT down, wait up to 15 s for one finger-down event, then one fixed 6.0 sleep (needs --fdt-manual)')
    parser.add_argument('--fdt-up', action='store_true', help='experiment 0012: after a finger-down event, send one fixed 3.2 FDT up and wait up to 15 s for one finger-up event, before the 6.0 (needs --fdt-down)')
    parser.add_argument('--image-on-touch', action='store_true', help='experiment 0014: after a finger-down event, send one fixed 2.0 McuGetImage before the 6.0 (needs --fdt-down; not with --fdt-up or --image)')
    parser.add_argument('--save-image', action='store_true', help='experiment 0014: save the decrypted image as .raw and .pgm in images/ beside this tool; report coarse statistics only (needs --image or --image-on-touch)')
    parser.add_argument('--image', action='store_true', help='experiment 0013: after the post-TLS A.7, send one fixed 2.0 McuGetImage (no finger) and report the reply shape only (needs --query-state; no FDT or pre-TLS flags)')
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
        if args.fdt_down and not args.fdt_manual:
            raise ProbeError('fdt_down_requires_fdt_manual')
        if args.fdt_up and not args.fdt_down:
            raise ProbeError('fdt_up_requires_fdt_down')
        if args.image and not args.query_state:
            raise ProbeError('image_requires_query_state')
        if args.image and (args.fdt_manual or args.query_state_pre_tls):
            raise ProbeError('image_excludes_other_modes')
        if args.image_on_touch and (not args.fdt_down or args.fdt_up or args.image):
            raise ProbeError('image_on_touch_mode_invalid')
        if args.save_image and not (args.image or args.image_on_touch):
            raise ProbeError('save_image_requires_image')
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
            wire = USBWire(state_queries=2, fdt=True, fdt_down=args.fdt_down, fdt_up=args.fdt_up,
                           image_touch=args.image_on_touch)
        elif args.query_state_pre_tls:
            wire = USBWire(state_queries=2)
        elif args.image:
            wire = USBWire(image=True)
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
            if args.image:
                get_image(wire, server, report, 'nofinger' if args.save_image else None)
            if args.fdt_up:
                fdt_down(wire, server, report, up=True)
            elif args.image_on_touch:
                fdt_down(wire, server, report, image_save='finger' if args.save_image else None)
            elif args.fdt_down:
                fdt_down(wire, server, report)
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
