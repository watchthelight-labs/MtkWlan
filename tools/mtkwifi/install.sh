#!/bin/bash
# <wtl> project: mtkwlan | file: tools/mtkwifi/install.sh | author: watchthelight </wtl>
# Install the mtkwifi tool and its autojoin LaunchDaemon (run with sudo).
# Undo:
#   sudo launchctl bootout system/org.watchthelight.mtkwifi
#   sudo rm /Library/LaunchDaemons/org.watchthelight.mtkwifi.plist /usr/local/bin/mtkwifi
#   sudo rm -r "/Library/Application Support/legion/mtkwifi"      # the saved networks (PMKs), if wanted
set -e
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -x out/mtkwifi ] || { echo "build first: ./build.sh"; exit 1; }
mkdir -p /usr/local/bin /Users/Shared/legion-diag
install -m 755 -o root -g wheel out/mtkwifi /usr/local/bin/mtkwifi
install -m 644 -o root -g wheel org.watchthelight.mtkwifi.plist /Library/LaunchDaemons/org.watchthelight.mtkwifi.plist
launchctl bootout system/org.watchthelight.mtkwifi 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/org.watchthelight.mtkwifi.plist 2>/dev/null || true
echo "installed /usr/local/bin/mtkwifi and the autojoin daemon (log: /Users/Shared/legion-diag/mtkwifi.log)"
echo "save your network with: sudo mtkwifi add \"<SSID>\"   (asks for the passphrase; stores only the derived PMK)"
