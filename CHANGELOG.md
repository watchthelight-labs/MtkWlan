# Changelog

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
