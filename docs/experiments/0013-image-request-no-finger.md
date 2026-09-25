# Experiment 0013 plan: one image request with no finger on the sensor

Status: **approved (defaults), implemented, awaiting review.**

## Why

Experiments 0005–0012 cover the TLS handshake, the state query and the FDT
down/up events. The remaining primitive for a Linux driver is the image
itself: `2.0` McuGetImage (`0x20`). This is the first experiment that brings
sensor pixel data across the USB link, so this first run is taken with **no
finger on the sensor**, and the report records the reply's form only.

## Prior work

- tlambertz/goodix-fingerprint-reversing@0479ce9 `capture.py` (55a2):
  - `getImage()` (line 295–310): sends `0x20` with payload `01 00`, expects
    an ACK and then a `0xb2` frame; strips a 4+9-byte header, feeds the rest
    to TLS, and reads **14,788** decrypted bytes: image plus a 4-byte trailer.
  - `SENSOR_WIDTH = 56`, `SENSOR_HEIGHT = 176` (line 18–19); 56 × 176
    12-bit pixels packed = 14,784 bytes, + 4 = 14,788. (goodix-fp-dump's
    88 × 108 is the 55x4 layout and does not apply.)
  - `main()` calls `someInitWindowsDoes()` (reset `A.2`, OTP read, chip
    config upload `9.0`, `C.2`, `D.1`, FDT mode `3.3`) before the handshake;
    its own comment says "not needed?". Not verified either way.
- Windows log `logs/2_wbdi_singleunlock.log` (same repo, sha256 `e7510a57…`),
  line 392–491: `sendCmd, cmd: 0x20, outDataSize: 0x2` → ACK
  (`0xa0`, `0xb0`) → one `0xb2` frame, `payload len: 14862` → TLS record of
  5 + 14,848 bytes → `tls decrypted (14788 bytes)`. Matches Lambertz.
- goodix-fp-dump `goodix.py` `mcu_get_image()` (line 202–215): same send,
  ACK, then one reply with the TLS-data flag; driver scripts strip `[9:]`.
- Our Windows captures (0003) show a 14,866-byte IN transfer for each image:
  14,862 + 4-byte frame header. Consistent with the log; the 64-byte gap to
  Lambertz's 14,930 in `PRIOR_WORK_COMPARISON.md` is now explained as his
  pcap framing, not a different image size (to be confirmed by this run).

## Approach

`--run --query-state --image` (`--image` needs `--query-state`, not with
the FDT flags): run 0006 unchanged up to the post-TLS `A.7`, then send
**one fixed `0x20` frame, payload `01 00`**, wait for its ACK, then read one
`0xb2` frame and pass its TLS record to the existing in-memory session.

- USB boundary: `0x20` allowed once, only after the post-TLS `A.7`, fixed
  payload only. No `9.0`, reset, FDT, `6.0`, key, firmware or second image.
- Reply handling: accept only `0xb2` whose TLS record is application data.
  Any other flag, a TLS alert, or a decrypt failure stops with a fixed label.

## Biometric data handling (the new part)

The decrypted plaintext is image data and is never written, printed, logged,
hashed or returned. The tool:

1. decrypts into a local `bytearray`, reads only `len()`, then overwrites
   it with zeros and drops the reference (best effort; Python may keep
   internal copies, as the 0005 plan already states for the PSK);
2. reports shape only:
   `image_ack`, `image_frame_flag`, `image_frame_len` (USB body),
   `image_prefix_len` (0 or 9), `image_record_len` (TLS record),
   `image_decrypted` (bool),
   `image_plain_len`, `image_len_expected` (bool, `== 14788`);
3. keeps core dumps disabled and prints one JSON line as before.

No pixel statistics (mean, min/max) are reported in this run: even
aggregate values are derived from sensor data, and they aren't needed to
prove the data path. A later plan can propose them, or a root-only file.

A planted marker in synthetic image replies must be absent from the report,
stdout and stderr (test), as in 0007/0012.

## Decisions for Jon

1. **No chip-config upload (`9.0`).** Default: don't send it. Lambertz's
   capture works from his init, but his init includes `9.0`; the reader may
   refuse the image without it (NACK, timeout or an error reply). That is a
   result, and adding `9.0` is its own plan (it's a 256-byte config write to
   volatile MCU RAM, borrowed from another unit).
2. **No `6.0` afterwards.** `0x20` doesn't arm FDT, and `6.0` has only been
   verified with FDT armed. The next run's pre-send stale listen plus a plain
   `--run` is the check that the reader returned to normal.
3. **Timeout.** 5 s for the image frame after the ACK (Windows took 63 ms).

## Runs

1. No finger, hands off the laptop palm rest: `sudo python3 -I -B
   /home/jon/goodix-handshake-pilot/goodix_handshake.py --run --query-state
   --image`. Pass: `image_ack: true`, `image_decrypted: true`,
   `image_plain_len: 14788`, `usb_released: true`.
2. Immediately after: plain `--run`. Pass: `stage: complete`, no
   `stale_reader_frame`.

## Stop conditions

Any `stale_reader_frame` or `unexpected_firmware` on run 2: stop, recover
with one Windows fingerprint unlock, record. No automatic retries.

## Also on this branch (0012 review leftovers)

- The shared wait-window deadline label said `fdt_down` for every window;
  renamed to `wait_window_exceeds_deadline`.
- (The 0008 `state_post_*` nit was already fixed in `main`.)

## Not established by this run

A decrypted length proves the image path through TLS works; it does not
prove the pixels are usable, that a finger image would decode, or anything
about matching or authentication.
