#!/usr/bin/env python3
"""Experiment 0015: offline background subtraction for saved 55a2 images.

Reads two .raw files written by goodix_handshake.py --save-image (14,788
decrypted bytes each: 14,784 packed 12-bit pixels plus a 4-byte trailer that
is discarded, never reported). Never opens the USB device; no sudo needed.

  diff:       d = nofinger - finger, stretched from the 1st-99th percentile
              to 0-4095, written as <finger-base>-diff[-lambertz].pgm beside
              the finger file (never overwrites).
  --pair-stats: two no-finger files; prints the mean absolute difference.

stdout is one JSON line with coarse statistics only: no pixel values, rows,
hashes or trailer bytes.
"""
import argparse
import json
import math
import os
import sys

from goodix_handshake import IMAGE_HEIGHT, IMAGE_PLAIN_LEN, IMAGE_WIDTH, unpack_pixels

PIXELS = IMAGE_WIDTH * IMAGE_HEIGHT  # 176 x 56 in received order
MAXVAL = 4095


class DiffError(Exception):
    """Fixed label only; never carries data."""


def load_raw(path):
    try:
        with open(path, 'rb') as handle:
            data = handle.read(IMAGE_PLAIN_LEN + 1)
    except OSError:
        raise DiffError('input_unreadable') from None
    if len(data) != IMAGE_PLAIN_LEN:
        raise DiffError('input_wrong_length')
    pixels = unpack_pixels(data[:-4])
    if len(pixels) != PIXELS:
        raise DiffError('input_pixel_count')
    return pixels


def percentile(sorted_values, fraction):
    index = min(len(sorted_values) - 1, max(0, int(round(fraction * (len(sorted_values) - 1)))))
    return sorted_values[index]


def subtract(nofinger, finger):
    """nofinger - finger, stretched 1-99 % to 0..4095."""
    if len(nofinger) != PIXELS or len(finger) != PIXELS:
        raise DiffError('input_pixel_count')
    diff = [a - b for a, b in zip(nofinger, finger)]
    ordered = sorted(diff)
    low, high = percentile(ordered, 0.01), percentile(ordered, 0.99)
    span = high - low
    if span <= 0:
        return diff, [0] * PIXELS
    scaled = [min(MAXVAL, max(0, round((v - low) * MAXVAL / span))) for v in diff]
    return diff, scaled


def orient(pixels, mode):
    """raw: received order, 176 wide x 56 high.
    lambertz: flipud(reshape(176, 56).T), also 176 wide x 56 high but with
    the pixels regrouped as 56-pixel columns (tlambertz capture.py readInLoop)."""
    if mode == 'raw':
        return pixels, IMAGE_WIDTH, IMAGE_HEIGHT
    # reshape(176, 56): a[r][c] = p[r*56 + c]; .T: t[c][r]; flipud reverses
    # the 56 rows. Result: 56 rows of 176, row i = t[55 - i].
    n_r, n_c = 176, 56  # reshape dimensions, not image width/height
    out = []
    for c in reversed(range(n_c)):
        for r in range(n_r):
            out.append(pixels[r * n_c + c])
    return out, n_r, n_c  # width 176, height 56


def stats(values):
    mean = sum(values) / len(values)
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
    return {'min': min(values), 'max': max(values), 'mean': round(mean, 1), 'stddev': round(std, 1)}


def write_pgm(path, pixels, width, height):
    pgm = b'P5\n%d %d\n%d\n' % (width, height, MAXVAL) + b''.join(v.to_bytes(2, 'big') for v in pixels)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        raise DiffError('output_exists') from None
    except OSError:
        raise DiffError('output_failed') from None
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(pgm)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise DiffError('output_failed') from None


def output_path(finger_path, mode):
    base = os.path.basename(finger_path)
    if base.endswith('.raw'):
        base = base[:-4]
    suffix = '-diff' if mode == 'raw' else '-diff-lambertz'
    return os.path.join(os.path.dirname(os.path.abspath(finger_path)), base + suffix + '.pgm')


def run_diff(nofinger_path, finger_path, mode):
    nofinger, finger = load_raw(nofinger_path), load_raw(finger_path)
    diff, scaled = subtract(nofinger, finger)
    pixels, width, height = orient(scaled, mode)
    path = output_path(finger_path, mode)
    write_pgm(path, pixels, width, height)
    report = {'mode': 'diff', 'orient': mode, 'output_file': os.path.basename(path),
              'pixel_count': len(diff), 'width': width, 'height': height,
              'zero_pixels_nofinger': nofinger.count(0), 'zero_pixels_finger': finger.count(0)}
    report.update({'diff_' + k: v for k, v in stats(diff).items()})
    return report


def run_pair_stats(first_path, second_path):
    first, second = load_raw(first_path), load_raw(second_path)
    absdiff = [abs(a - b) for a, b in zip(first, second)]
    s = stats(absdiff)
    return {'mode': 'pair_stats', 'pixel_count': len(absdiff),
            'mean_abs_diff': s['mean'], 'abs_diff_stddev': s['stddev'],
            'zero_pixels_first': first.count(0), 'zero_pixels_second': second.count(0)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Experiment 0015: offline background subtraction', allow_abbrev=False)
    parser.add_argument('first', help='no-finger .raw')
    parser.add_argument('second', help='finger .raw (or a second no-finger .raw with --pair-stats)')
    parser.add_argument('--orient', choices=('raw', 'lambertz'), default='raw')
    parser.add_argument('--pair-stats', action='store_true',
                        help='compare two no-finger files; writes no image')
    args = parser.parse_args(argv)
    try:
        if args.pair_stats:
            report = run_pair_stats(args.first, args.second)
        else:
            report = run_diff(args.first, args.second, args.orient)
    except DiffError as exc:
        report = {'error': str(exc)}
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
