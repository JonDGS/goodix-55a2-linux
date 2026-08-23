# Fedora Linux Baseline — 2026-08-22

## Scope

This is the initial, pre-driver baseline supplied by an owner of the target hardware. It records USB enumeration and stock `fprintd` behavior before any project tooling or enrollment attempt.

No fingerprint enrollment or capture was performed for this baseline.

## Environment observed

- Distribution: Fedora 44
- Kernel: `7.1.9-200.fc44.x86_64`
- `fprintd`: `1.94.5-5.fc44.x86_64`
- `libfprint`: `1.94.100-1.fc44.x86_64`
- USB path: `3-9`
- USB speed: High Speed, 480 Mb/s

## USB identity and configuration

| Field | Observed value |
| --- | --- |
| Vendor ID | `27c6` (Goodix) |
| Product ID | `55a2` |
| Device release | `1.00` |
| USB specification | `2.00` |
| Device class | Miscellaneous / Interface Association |
| Configuration count | 1 |
| Interface | 0, vendor-specific class (`ff/00/00`) |
| OUT endpoint | `0x01`, bulk, 512-byte maximum packet |
| IN endpoint | `0x82`, bulk, 512-byte maximum packet |
| Remote wakeup | Advertised |
| Serial string | None |

The device has a single vendor-specific interface with the expected pair of bulk endpoints. This is a direct protocol-tooling target: a future userspace experiment will need to claim interface 0 and exchange bulk transfers through `0x01` and `0x82`.

## Current Linux support boundary

- `lsusb -t` shows interface 0 as `Driver=[none]`.
- udev identifies the device as USB class `239/2/1` with interface signature `:ff0000:`; it has no hardware serial string. The generated `ID_SERIAL` value is the generic product label, not a unique device identifier.
- The USB core enables autosuspend (`ID_AUTOSUSPEND=1`). Early protocol tools should keep this in mind when diagnosing unexplained resets or timeouts.
- `fprintd-list "$USER"` returns `No devices available`.
- Kernel boot logging records normal USB enumeration for `27c6:55a2`; it does not show a fingerprint-driver bind, reset loop, or transport failure.
- `fprintd.service` is a static, on-demand service and is currently inactive. Its start-then-stop cycle is consistent with an idle service when no usable device is exposed; it is not by itself an error.

**Baseline conclusion:** the device is electrically present and fully enumerated by USB, but no installed Linux driver stack currently claims or exposes it to `fprintd`.

## Collection notes

`lsusb -d 27c6:55a2 -v` reported that some information was unavailable because it was run without access to the device. The returned configuration and endpoint descriptors were nevertheless sufficient for this initial record.

Two commands in the original collection contained typographical errors:

- `vdevadm` should be `udevadm`.
- `system status fprintd` should be `systemctl status fprintd --no-pager`.

Neither error changes the support conclusion above.

## Follow-up metadata to collect

Run the following on the research laptop and attach only the redacted output:

```bash
uname -r
rpm -q fprintd libfprint
udevadm info --query=all --name=/dev/bus/usb/003/003
systemctl status fprintd --no-pager
```

If `udevadm` exposes a serial or other unique identifier, redact it before sharing.
