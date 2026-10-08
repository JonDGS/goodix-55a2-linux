"""Synthetic-only tests for experiment 0015; no real image, no USB device."""
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))

import goodix_image_diff as d  # noqa: E402


def pack(pixels):
    """Inverse of goodix_handshake.unpack_pixels (6 bytes <-> 4 values)."""
    out = bytearray()
    for i in range(0, len(pixels), 4):
        o1, o2, o3, o4 = pixels[i:i + 4]
        b0 = (o1 >> 8) | ((o2 & 0xf) << 4)
        b1 = o1 & 0xff
        b2 = o3 & 0xff
        b3 = o2 >> 4
        b4 = o4 >> 4
        b5 = (o3 >> 8) | ((o4 & 0xf) << 4)
        out += bytes((b0, b1, b2, b3, b4, b5))
    return bytes(out)


MARKER = 0xABC  # distinctive 12-bit value that must never reach stdout


class ImageDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, pixels, trailer=b'\xde\xad\xbe\xef'):
        path = os.path.join(self.dir, name)
        with open(path, 'wb') as handle:
            handle.write(pack(pixels) + trailer)
        return path

    def run_main(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = d.main(list(argv))
        return rc, buf.getvalue()

    def test_pack_roundtrip(self):
        pixels = [(i * 37) % 4096 for i in range(d.PIXELS)]
        self.assertEqual(d.unpack_pixels(pack(pixels)), pixels)

    def test_subtract_and_stretch(self):
        nofinger = [3000] * d.PIXELS
        finger = [3000 - (i % 100) for i in range(d.PIXELS)]
        diff, scaled = d.subtract(nofinger, finger)
        self.assertEqual(diff[:3], [0, 1, 2])
        self.assertEqual(min(scaled), 0)
        self.assertEqual(max(scaled), 4095)
        self.assertLess(scaled[10], scaled[90])  # ridges (lower finger) bright

    def test_flat_difference_gives_black(self):
        _, scaled = d.subtract([5] * d.PIXELS, [5] * d.PIXELS)
        self.assertEqual(set(scaled), {0})

    def test_lambertz_orientation_index_map(self):
        pixels = list(range(d.PIXELS))
        out, width, height = d.orient(pixels, 'lambertz')
        self.assertEqual((width, height), (176, 56))
        # flipud(reshape(176,56).T): row i, col j = p[j*56 + (55 - i)]
        for i, j in ((0, 0), (0, 175), (55, 0), (20, 99)):
            self.assertEqual(out[i * 176 + j], j * 56 + (55 - i))
        self.assertEqual(sorted(out), pixels)
        self.assertEqual(d.orient(pixels, 'raw'), (pixels, 176, 56))

    def test_diff_writes_pgm_and_prints_no_pixels(self):
        nof = self.write('20260101-000000-nofinger.raw', [MARKER] * d.PIXELS)
        fin = self.write('20260101-000100-finger.raw', [MARKER - (i % 7) for i in range(d.PIXELS)])
        rc, out = self.run_main(nof, fin)
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report['output_file'], '20260101-000100-finger-diff.pgm')
        self.assertEqual(report['pixel_count'], d.PIXELS)
        self.assertNotIn(str(MARKER), out)
        self.assertNotIn('dead', out.lower())
        self.assertNotIn('beef', out.lower())
        with open(os.path.join(self.dir, report['output_file']), 'rb') as handle:
            data = handle.read()
        self.assertTrue(data.startswith(b'P5\n176 56\n4095\n'))
        self.assertEqual(len(data), len(b'P5\n176 56\n4095\n') + 2 * d.PIXELS)

    def test_lambertz_output_name_and_no_overwrite(self):
        nof = self.write('a-nofinger.raw', [100] * d.PIXELS)
        fin = self.write('b-finger.raw', [i % 50 for i in range(d.PIXELS)])
        rc, out = self.run_main(nof, fin, '--orient', 'lambertz')
        self.assertEqual((rc, json.loads(out)['output_file']), (0, 'b-finger-diff-lambertz.pgm'))
        rc, out = self.run_main(nof, fin, '--orient', 'lambertz')
        self.assertEqual((rc, json.loads(out)), (1, {'error': 'output_exists'}))

    def test_wrong_length_and_missing_refused(self):
        good = self.write('good.raw', [1] * d.PIXELS)
        short = os.path.join(self.dir, 'short.raw')
        with open(short, 'wb') as handle:
            handle.write(b'\0' * (d.IMAGE_PLAIN_LEN - 1))
        long = os.path.join(self.dir, 'long.raw')
        with open(long, 'wb') as handle:
            handle.write(b'\0' * (d.IMAGE_PLAIN_LEN + 1))
        for bad, label in ((short, 'input_wrong_length'), (long, 'input_wrong_length'),
                           (os.path.join(self.dir, 'nope.raw'), 'input_unreadable')):
            rc, out = self.run_main(good, bad)
            self.assertEqual((rc, json.loads(out)), (1, {'error': label}))
        self.assertEqual(sorted(os.listdir(self.dir)), ['good.raw', 'long.raw', 'short.raw'])

    def test_pair_stats(self):
        a = self.write('a.raw', [MARKER] * d.PIXELS)
        b = self.write('b.raw', [MARKER - 10] * (d.PIXELS - 1) + [0])
        before = set(os.listdir(self.dir))
        rc, out = self.run_main(a, b, '--pair-stats')
        report = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(report['zero_pixels_second'], 1)
        self.assertAlmostEqual(report['mean_abs_diff'], 10.3, delta=0.1)
        self.assertNotIn(str(MARKER), out)
        self.assertEqual(set(os.listdir(self.dir)), before)

    def test_abbreviated_flags_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            d.main(['x', 'y', '--pair'])

    def test_never_imports_usb(self):
        code = ('import sys; sys.path.insert(0, %r); import goodix_image_diff; '
                'print(any(m == "usb" or m.startswith("usb.") for m in sys.modules))' % str(TOOLS))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), 'False')
        source = (TOOLS / 'goodix_image_diff.py').read_text()
        self.assertNotIn('import usb', source)


if __name__ == '__main__':
    unittest.main()
