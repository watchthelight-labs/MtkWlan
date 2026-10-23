#!/bin/bash
# <wtl> project: mtkwlan | file: tools/bundle/make-bundle.sh | author: watchthelight </wtl>
# Packs the Wi-Fi set for one download: the driver release zip of this repo plus the native front end's release zip,
# with INSTALL.md and the config snippet, into mt7925-wifi-bundle-<driver>+<native>.zip. Needs gh (logged in).
#   tools/bundle/make-bundle.sh <driver tag> <native tag> [out dir]       e.g. 0.11.3 0.4.11
set -euo pipefail
D=${1:?driver tag}; N=${2:?native tag}; OUT=${3:-$PWD/out}
HERE=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d); mkdir -p "$OUT"
gh release download "$D" -R watchthelight-labs/mt7925-hackintosh-wifi -p '*-RELEASE.zip' -D "$W/d"
gh release download "$N" -R watchthelight-labs/mt7925-hackintosh-wifi-native -p '*-RELEASE.zip' -D "$W/n"
B="$W/mt7925-wifi-bundle-$D+$N"; mkdir -p "$B"
unzip -q "$W"/d/*.zip -d "$B"; unzip -q "$W"/n/*.zip -d "$B"
cp "$HERE/INSTALL.md" "$HERE/config-snippet.plist" "$B/"
# 0.12.0: the Recovery / installer helper folder (built here, it is not in the release zips)
bash "$HERE/../recovery/make.sh" >/dev/null && cp -R "$HERE/../../out/recovery/MtkWlan" "$B/Recovery"
{ echo "mt7925-hackintosh-wifi $D + mt7925-hackintosh-wifi-native $N, packed $(date -u +%F)"; echo; find "$B" -type f -name '*.kext' -o -type f -path '*MacOS/*' | sort | while read -r f; do shasum -a 256 "$f" | sed "s|$B/||"; done; } > "$B/SHA256SUMS.txt"
(cd "$W" && zip -qr "$OUT/$(basename "$B").zip" "$(basename "$B")")
echo "$OUT/$(basename "$B").zip"; unzip -l "$OUT/$(basename "$B").zip" | tail -1
