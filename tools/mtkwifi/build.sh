#!/bin/bash
# <wtl> project: mtkwlan | file: tools/mtkwifi/build.sh | author: watchthelight </wtl>
# Build the mtkwifi tool on the Legion's macOS (Command Line Tools). Output: out/mtkwifi (ad-hoc signed).
# It links the kext's own MtkCrypto.c for the PMK derivation, so the tool and the driver agree byte for byte.
set -euo pipefail
cd "$(dirname "$0")"
D=../../src
mkdir -p out
clang -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -I"$D" mtkwifi.c "$D/MtkCrypto.c" \
  -framework IOKit -framework CoreFoundation -o out/mtkwifi
codesign -s - -f out/mtkwifi >/dev/null 2>&1 || true
echo "built out/mtkwifi ($(stat -f %z out/mtkwifi) bytes)"
