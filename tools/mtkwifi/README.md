# mtkwifi

Command line control for the MtkWlan kext through its IOUserClient (`src/MtkUserApi.h`). It lists networks, joins one (open or WPA2-PSK), and keeps the saved networks the autojoin daemon uses at boot. Needs MtkWlan 0.9.0 or newer. There is no Wi-Fi menu: macOS sees an Ethernet card, and this tool is how you pick a network.

## Commands

| Command | Root | What it does |
|---|---|---|
| `mtkwifi status [--json]` | no | driver state, current network, port state, handshake counters |
| `mtkwifi scan [--wait]` | yes | start a scan; `--wait` prints the list when it finishes (3 to 6 s) |
| `mtkwifi list [--json]` | no | the driver's BSS cache, best first; `*` joinable, `>` current |
| `mtkwifi join <ssid> [--bssid X] [--open \| --ask]` | yes | join with the saved PMK, as an open network, or asking for the passphrase |
| `mtkwifi disconnect` | yes | leave and stay idle (also turns the open-network fallback off until the next join) |
| `mtkwifi add <ssid> [--open]` | yes | save a network: asks for the passphrase twice, stores only the derived PMK |
| `mtkwifi forget <ssid>` | yes | remove a saved network |
| `mtkwifi networks` | yes | saved SSIDs (no secrets printed) |
| `mtkwifi autojoin [--wait SECONDS]` | yes | wait for the driver, scan, join the first saved network in range |

## Where the secrets live

`/Library/Application Support/legion/mtkwifi/networks.plist`, root:wheel, mode 0600, directory 0700. It holds the SSID and the PMK (PBKDF2-SHA1 of the passphrase and SSID, computed by the same `MtkCrypto.c` the kext uses), never the passphrase. The passphrase is typed at a terminal prompt (`readpassphrase`, TTY required), never given on the command line or stored.

## Install

```sh
cd tools/mtkwifi
./build.sh                      # needs the Xcode Command Line Tools
sudo bash install.sh
sudo mtkwifi add "<your SSID>"  # asks for the passphrase; --open for an open network
```

The LaunchDaemon `org.watchthelight.mtkwifi` runs `mtkwifi autojoin --wait 90` once at boot (log in `/Users/Shared/legion-diag/mtkwifi.log`). A saved network that appears later needs `sudo mtkwifi autojoin` or `sudo mtkwifi join <ssid>` by hand; the kext itself rejoins the current network after a loss. The undo lines are in the header of `install.sh`.

## What the driver can join

Open networks, and WPA2-PSK networks that offer AKM PSK with pairwise CCMP (EAPOL descriptor version 2). The group key may be CCMP or TKIP (WPA/WPA2 mixed routers). Not yet: WPA3-SAE only, PSK-SHA256 only, networks that require management frame protection, WPA (TKIP pairwise), enterprise. `mtkwifi list` shows these as not joinable.
