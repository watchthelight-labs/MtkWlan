#!/bin/bash
# <wtl> project: mtkwlan | file: tests/run.sh | author: watchthelight </wtl>
# Host tests for the WPA2 code of MtkWlan (MtkCrypto.c, MtkSupp.c) and the link supervisor (MtkSuper.c). Builds with the host clang (not the kext
# flags) with UBSan, runs the vectors and the simulated handshake, then compares the values the C code printed
# with the independent Python oracle (oracle.py). Writes only to ../out/tests/.
# AddressSanitizer is not used: its runtime dies with SIGILL even on an empty program on this Legion (2026-10-16).
set -euo pipefail
cd "$(dirname "$0")"
OUT=../out/tests
mkdir -p "$OUT"
clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer \
  mtk_wpa_test.c ../src/MtkCrypto.c ../src/MtkSupp.c -o "$OUT/mtk_wpa_test"
clang -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer \
  mtk_super_test.c ../src/MtkSuper.c -o "$OUT/mtk_super_test"
"$OUT/mtk_super_test" || exit 1
"$OUT/mtk_wpa_test" | tee "$OUT/result.txt"
python3 -I oracle.py > "$OUT/oracle.txt"
bad=0
while read -r name val; do
  got=$(sed -n "s/^oracle-check $name //p" "$OUT/result.txt")
  if [ "$got" = "$val" ]; then echo "ok   oracle $name"; else echo "FAIL oracle $name: C $got, Python $val"; bad=1; fi
done < "$OUT/oracle.txt"
[ $bad = 0 ] && echo "oracle: all values agree"
exit $bad
