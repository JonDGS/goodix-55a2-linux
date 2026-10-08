#!/bin/bash
# Experiment 0017 capture set. Run ONCE from a terminal on the laptop:
#   cd ~/goodix-handshake-pilot && sudo bash run-0017-capture.sh
#
# Calls only the reviewed tool goodix_handshake.py with the 0015 command
# pairs (no new USB commands). Set: 20 presses of finger A, 10 of finger B,
# a fresh no-finger image before every 5 presses, one plain --run at the end.
# Images are moved from images/ into images-0017/ and listed in
# images-0017/labels.txt. Stops at the first failed run; does not retry.
# If a run fails with unexpected_firmware afterwards, the reader is still
# armed: boot Windows, one fingerprint unlock, back to Fedora.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL="$HERE/goodix_handshake.py"
SRC="$HERE/images"
DST="$HERE/images-0017"
LOG="$DST/capture.log"   # tool JSON lines: stages and coarse stats only

[ "$(id -u)" = 0 ] || { echo "run with: sudo bash $0"; exit 1; }
[ -t 0 ] || { echo "needs an interactive terminal"; exit 1; }
OWNER="${SUDO_UID:-0}:${SUDO_GID:-0}"
if [ -e "$DST" ]; then
    echo "$DST already exists; not overwriting a set. Rename it first."; exit 1
fi
mkdir -m 700 "$DST" && chown "$OWNER" "$DST"
touch "$DST/labels.txt" "$LOG" && chown "$OWNER" "$DST/labels.txt" "$LOG"

run_tool() {   # $1 = label for labels.txt, rest = tool args
    local label=$1; shift
    local out base
    out=$(python3 -I -B "$TOOL" "$@")
    local rc=$?
    echo "$out" >> "$LOG"
    base=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("image_file",""))' 2>/dev/null)
    if [ $rc -ne 0 ] || [ -z "$base" ]; then
        echo "STOP: run failed or no image saved (exit $rc). Last line is in $LOG."
        echo "Set so far is kept. Do not resume without checking with TARS."
        exit 2
    fi
    mv -n "$SRC/$base.raw" "$SRC/$base.pgm" "$DST/" || { echo "STOP: move failed"; exit 2; }
    echo "$base $label" >> "$DST/labels.txt"
}

nofinger() {
    echo; echo ">>> No-finger image: keep the sensor clear."
    read -r -p "    Press Enter when nothing touches the sensor... "
    run_tool nofinger --run --query-state --image --save-image
    echo "    ok"
}

press() {   # $1 = A or B, $2 = n, $3 = total
    echo; echo ">>> Finger $1, press $2 of $3. Vary placement slightly, as in normal use."
    read -r -p "    Press Enter, then touch when it says 'armed'... "
    run_tool "$1" --run --query-state --fdt-manual --fdt-down --image-on-touch --save-image
    echo "    ok - lift your finger"
    sleep 1
}

echo "Experiment 0017: 20 x finger A (your enrolled finger), 10 x finger B (another finger)."
echo "About 40 runs. Ctrl-C stops safely between runs."
for i in $(seq 1 20); do
    [ $(( (i - 1) % 5 )) = 0 ] && nofinger
    press A "$i" 20
done
for i in $(seq 1 10); do
    [ $(( (i - 1) % 5 )) = 0 ] && nofinger
    press B "$i" 10
done

echo; echo ">>> Final clean-state check (no touch needed)."
python3 -I -B "$TOOL" --run >> "$LOG"
rc=$?
chown "$OWNER" "$LOG"
echo "Done. Final check exit $rc (0 = clean). $(grep -c ' A$' "$DST/labels.txt") A, $(grep -c ' B$' "$DST/labels.txt") B, $(grep -c nofinger "$DST/labels.txt") no-finger."
echo "Tell TARS it's finished."
