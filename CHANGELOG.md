# Changelog

## 0.11.0 (2026-10-18)

- Core ops table v4 (`MtkCoreApi.h`): `set_mac` changes the station address after bring-up. The association ends first, the firmware station interface is removed and added again with the new address, and the manager rejoins the wanted network. macOS gives a Wi-Fi interface a private address per network; without this the station associated with the old address in the firmware and DHCP never saw a reply.
- `MtkMacAddr` and `MtkMacChanges` properties; `MtkMacChangeRefused` when the firmware rejects an address.
- `tools/mtk-report.sh`: one archive with everything a bug report needs, MAC addresses and SSIDs redacted.
- Ethernet front end unchanged. Tested with the native front end MtkWlanNative 0.4.1 on macOS 26.7.1 (25G241): macOS-driven join with a private address, DHCP lease on it.

## 0.10.0 (2026-10-17)

- Core ops table v3 (`MtkCoreApi.h`): `set_mode`, `get_bss`, `get_channels` and `tx_bytes`, so a native Wi-Fi front end can drive the core without a C++ link.
- Front-end selection: `MtkFrontEnd` in `Info.plist` picks the Ethernet front end (default) or a native front end built against the same ops table; if the chosen front end does not come up the core falls back to Ethernet (`MtkFrontEndFallback`). `OSBundleCompatibleVersion` is set so a separate front-end kext can link against the core.
- `mtkwifi status` reports the active front end and stands down (no join management) when the native front end owns the interface.
- Same behaviour as 0.9.0 on the Ethernet front end. Measured on the same open 5 GHz network: 192.7 Mb/s down, 134.6 Mb/s up (20 MB POST), 16 ms idle ping, 0 % loss, 15 dropped RX frames in the first minutes (0 in the 0.9.0 run; being watched).
- The release binary predates the last source edit of this version (`MtkNet.cpp`, `MtkFrontEndActive` property); see the README for both hashes.

## 0.9.0 (2026-10-17)

- The network name is no longer fixed in `Info.plist`. The driver scans from its 1 ms tick, keeps a cache of the networks it hears (with each one's security), and joins what it is asked to join.
- `tools/mtkwifi`: a command line tool that talks to the driver through an IOUserClient. Scan, list, join, disconnect, status, saved networks (stored as the derived PMK, never the passphrase), and an autojoin LaunchDaemon that joins the first saved network in range at boot.
- WPA2-PSK (CCMP): RSN element in the association request, the 4-way and group key handshakes in the driver, keys installed in the order Linux uses, host-side port gating, CCMP replay check after the block-ack reorder. Passes the host tests in `tests/` against a Python oracle. Not yet joined a real WPA2 network on air (see the README).
- Open-network fallback: when nothing is saved or asked for, the driver joins a network named in `MtkAutoOpenSsids` (exact match) 20 s after its first scan.
- The Ethernet front end starts before any association, so `en1` shows "no carrier" instead of an unknown link.
- Deauth during a join backs off and names a wrong key; legacy association retry on silence; a firmware watchdog stops the machines after three command timeouts in a row.
- Measured on the same open 5 GHz network as before: 190.8 Mb/s down, 174.8 Mb/s up, 16 ms idle ping.

## 0.8.0 (2026-10-16)

- The driver is split into a core (`MtkWlan`, IOService on the PCI device) and an Ethernet front end (`MtkWlanEth`, IOEthernetController) joined by a plain C ops table (`MtkCoreApi.h`), so a later native Wi-Fi front end can attach without a C++ link to the core.
- Native build on macOS with the Command Line Tools (`tools/build-mac.sh`).
- Same behaviour as 0.7.0: 195 Mb/s down, 97 Mb/s up in that boot (upload was a 20 MB POST, too short to settle).

## 0.7.0 (2026-10-15)

- Block ack in both directions: RX reorder (ported from mt76 `agg-rx.c`), TX ADDBA with the firmware building A-MPDUs.
- TX power: the firmware's country limit tables (CLC) and per-rate limits (SKU), sent as Linux mt76 does, with the TLV length fixes from Linux master.
- Station record TLVs in Linux order.
- 193 Mb/s down, 146 Mb/s up on an installed macOS 15.8.1.

## 0.6.1 (2026-10-15)

- Sampled TX status (rate, power, tries) and TX-free attempt counts in the registry.

## 0.6.0 (2026-10-15)

- HT/VHT association (80 MHz, 2 streams) with firmware rate control: 47.4 Mb/s down, 9.2 Mb/s up.

## 0.5.1 (2026-10-15)

- TX frames in flight capped at 32 and the output queue at 64: upload latency 1.2 s to 69 ms.

## 0.5.0 (2026-10-15)

- First working version: PCI attach, firmware download, scan, open-system join, Ethernet interface with DHCP. Safari and an Ookla speedtest from macOS Recovery: 19.4 Mb/s down, 9.6 Mb/s up.
