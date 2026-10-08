#!/bin/bash
# Build sigfm-eval (experiment 0017) against a libfprint checkout with
# libfprint/sigfm (JonDGS/libfprint goodix55a2-sigfm). Offline tool: links
# OpenCV only, never libfprint or libusb.
#   bash build.sh ~/goodix-libfprint
# sigfm.cpp is compiled from a copy with the 0016a ordering fix:
# match::operator< becomes a strict weak ordering on (p1.y, p1.x).
set -euo pipefail
LF=${1:?libfprint checkout}
SRC=$LF/libfprint/sigfm
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/build
mkdir -p "$OUT"
cp "$SRC/sigfm.cpp" "$OUT/sigfm_fixed.cpp"
python3 - "$OUT/sigfm_fixed.cpp" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
old = "((this->p1.y < right.p1.y) && this->p1.x < right.p1.x)"
new = "((this->p1.y == right.p1.y) && this->p1.x < right.p1.x)"
n = s.count(old)
if n != 1:
    sys.exit("ordering fix matched %d times" % n)
open(p, "w").write(s.replace(old, new))
print("ordering fix applied: 1 match")
EOF
g++ -O2 -std=c++17 -Wall -I"$SRC" "$HERE/sigfm_eval.cpp" "$OUT/sigfm_fixed.cpp" \
    $(pkg-config --cflags opencv4) -Wl,--as-needed \
    -lopencv_features2d -lopencv_flann -lopencv_imgproc -lopencv_core \
    -o "$OUT/sigfm-eval"
# Only core/imgproc/features2d/flann: the full opencv4 link pulls in videoio,
# which loads libusb transitively. Check the whole load closure.
if ldd "$OUT/sigfm-eval" | grep -Eq 'libusb|libfprint'; then
    echo "refusing: binary links libusb/libfprint" >&2; exit 1
fi
echo "built $OUT/sigfm-eval"
