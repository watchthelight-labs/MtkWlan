#!/bin/bash
# <wtl> project: mtkwlan | file: tools/wifi.sh | author: watchthelight </wtl>
# Wi-Fi driver (MtkWlan) milestone capture for macOS Recovery. Run from Recovery Terminal:
#   bash /Volumes/<stick>/wifi.sh run1
# Writes wifi-<ID>/ next to the script and prints a short summary on screen.
# W6: if MtkWlan attached a network interface, asks for a DHCP lease on it, pings the router and
# fetches http://captive.apple.com (a captive portal answers it before login). Nothing else changes.
ID="${1:-run}"
D="$(cd "$(dirname "$0")" && pwd)/wifi-$ID"
mkdir -p "$D" || { echo "cannot write $D"; exit 1; }
cd "$D" || exit 1

{ echo "date -u: $(date -u)"; sysctl kern.boottime; } > 00-clock.txt 2>&1
ioreg -r -c MtkWlan -l -w0 > mtkwlan.txt 2>&1
kmutil showloaded 2>&1 | grep -i watchthelight > kexts.txt
dmesg > dmesg.txt 2>&1
ifconfig -a > ifconfig.txt 2>&1
sync

IF=$(grep -m1 '"BSD Name" =' mtkwlan.txt | sed 's/.*= "\(.*\)"/\1/')
echo "interface: ${IF:-none}" > w6.txt
if [ -n "$IF" ]; then
  echo "== W6 on $IF (DHCP, up to 40 s)"
  ifconfig "$IF" up >> w6.txt 2>&1
  ipconfig set "$IF" DHCP >> w6.txt 2>&1
  ADDR=""
  for ((i = 1; i <= 40; i++)); do
    ADDR=$(ipconfig getifaddr "$IF" 2>/dev/null)
    [ -n "$ADDR" ] && break
    sleep 1
  done
  echo "address after ${i}s: ${ADDR:-none}" >> w6.txt
  ipconfig getpacket "$IF" > dhcp.txt 2>&1
  ifconfig "$IF" >> w6.txt 2>&1
  netstat -rn -f inet > routes.txt 2>&1
  scutil --dns > dns.txt 2>&1
  GW=$(ipconfig getoption "$IF" router 2>/dev/null)
  echo "router: ${GW:-none}" >> w6.txt
  if [ -n "$GW" ]; then
    ping -c 5 -t 15 "$GW" > ping.txt 2>&1
    curl -sS -m 20 -o captive.html -D captive-headers.txt -w '%{http_code} %{size_download} %{redirect_url}\n' \
      http://captive.apple.com/hotspot-detect.html > captive.txt 2>&1
    curl -sS -m 30 -o /dev/null -w '%{http_code} %{size_download} %{speed_download}\n' -L \
      http://captive.apple.com/ > captive-follow.txt 2>&1
  fi
  sleep 2
  ioreg -r -c MtkWlan -l -w0 > mtkwlan-after.txt 2>&1
  sync
  echo "  address: ${ADDR:-none}   router: ${GW:-none}"
  [ -f ping.txt ] && echo "  ping: $(grep -E 'packets transmitted' ping.txt)"
  [ -f captive.txt ] && echo "  captive: $(head -c 160 captive.txt)"
  [ -f captive.html ] && echo "  page: $(head -c 120 captive.html | tr '\n' ' ')"
  echo "== MtkW6 counters"
  grep -E '"Mtk(W6[A-Za-z0-9]+|State)" =' mtkwlan-after.txt | sed 's/^[ |]*/  /'
else
  echo "== MtkWlan"
  grep -E '"Mtk[A-Za-z0-9]+" =' mtkwlan.txt | sed 's/^[ |]*/  /' || echo "  (MtkWlan not attached)"
fi
sync
echo
ls "$D"
echo "WIFI CAPTURE DONE"
