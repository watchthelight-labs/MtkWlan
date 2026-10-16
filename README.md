# MtkWlan

A macOS kext for the MediaTek MT7925 Wi-Fi card (PCI `14C3:7925`), written from scratch.

> **This driver is vibe coded.** Read it with that in mind, and don't run it on a machine you care about.

As far as I know there was no macOS driver for this card. On 2026-10-15 it got a Lenovo Legion 5
15IAX10 from a working macOS Recovery environment onto the internet: Safari loaded apple.com and
finished an Ookla speedtest over an open 5 GHz network.

## Status

| Milestone | What it proves | Result |
| --- | --- | --- |
| W1 | PCI attach, BAR0, driver ownership handshake, chip ID | pass |
| W2 | WFDMA rings and MSI interrupt | pass |
| W3 | patch + RAM firmware download, firmware running | pass |
| W4 | firmware scan, beacons parsed (2.4 GHz and 5 GHz, DFS included) | pass |
| W5 | open-system authentication and association | pass |
| W6 | Ethernet interface (`en1`), DHCP, ping, HTTP | pass |
| W7 | Safari in Recovery, Ookla speedtest | pass: 19.42 Mb/s down, 9.57 Mb/s up |
| 0.5.1 | latency under load | ping to 1.1.1.1: 15.8 ms idle, 32.9 ms while downloading, 68.7 ms while uploading (was 1.2 s) |

On the same network the Windows driver does about 208/211 Mb/s with 23 ms of latency, so there is
a long way to go.

## What it can't do yet

- **Open networks only.** No WPA2/WPA3, so traffic is unencrypted. Use HTTPS.
- **The network name is fixed in `Info.plist`** (`MtkSsid`). The driver scans once at boot and joins
  that SSID. There is no Wi-Fi menu: macOS sees an Ethernet card.
- **Legacy 802.11a/g rates only** (no HT/VHT/HE, no aggregation), and TX uses a fixed rate
  (`MtkDataRate`, default index 22 = 24 Mb/s). That's why it's slow.
- No Bluetooth (that's a separate USB device, `0489:E111`).
- Tested on one laptop, in macOS 15.4.1 Recovery booted from USB with OpenCore. Never tested on
  an installed macOS, after sleep, or with the kext unloaded and reloaded.
- RX is polled every millisecond by a work-loop timer rather than run from the interrupt.

## Build

It cross-builds on Linux (Ubuntu 24.04, also fine in WSL). You don't need a Mac or Xcode.

```sh
sudo bash tools/build-toolchain.sh   # clang, Apple ld64 (cctools-port), libdispatch, MacKernelSDK
make                                 # out/MtkWlan.kext
```

The firmware in `firmware/` is checked against `firmware/SHA256SUMS` and embedded in the binary.

## Use

1. Set `MtkSsid` in `Info.plist` to an open network near you (and `MtkDataRate`, 18 to 25, if you
   want a different fixed rate). Rebuild, or edit `out/MtkWlan.kext/Contents/Info.plist` directly.
2. Add `MtkWlan.kext` to OpenCore `Kernel > Add` (`ExecutablePath` `Contents/MacOS/MtkWlan`).
   It only depends on Apple's own families.
3. Boot. The driver joins during boot and attaches an Ethernet interface.
4. In Terminal: `ipconfig set en1 DHCP`, or run `tools/wifi.sh`. It does that, pings the router,
   fetches captive.apple.com and saves every `Mtk*` registry property.

The driver publishes its progress as registry properties (`ioreg -r -c MtkWlan -l`): `MtkState`,
plus one `MtkW1…` to `MtkW6…` value per step. The Recovery kernel log is small and the release
kernel ignores `msgbuf=`, which is why these exist.

## Layout

| Path | What |
| --- | --- |
| `src/MtkWlan.cpp`, `MtkRegs.cpp` | PCI attach, register remap, ownership handshake (W1) |
| `src/MtkFw.cpp`, `MtkDma.cpp` | rings, MSI, firmware download (W2, W3) |
| `src/MtkScan.cpp` | MCU commands, scan, RX dispatch (W4) |
| `src/MtkJoin.cpp` | BSS/STA records, auth and association (W5) |
| `src/MtkNet.cpp` | IOEthernetController front-end, data path, keepalive, rejoin (W6) |
| `tools/` | toolchain setup, firmware embedding, the Recovery capture script |

## Credits and licences

- Linux **mt76** (MediaTek, ISC): nearly everything about how the hardware works.
- **itlmt7925** by thanhnndev and contributors (Clear BSD): the join sequence and post-firmware
  setup in `MtkJoin.cpp` and `MtkScan.cpp` follow it. Those parts keep its licence.
- **itlwm** (OpenIntelWireless): the idea of a Wi-Fi kext that presents itself as Ethernet.
- **RealtekRTL8111** (Mieze): the usual shape of an IOEthernetController kext.
- MediaTek firmware from linux-firmware, unmodified.
- Toolchain: acidanthera **MacKernelSDK**, tpoechtrager **cctools-port**, swiftlang **libdispatch**.

`NOTICE.md` says which file comes from where, and lists the research behind it. `LICENSE`,
`NOTICE.md` and `LICENSES/` must travel with any built copy of the kext. The boot-by-boot history
(logs, register dumps, what broke and why) lives in
[project-legion](https://github.com/watchthelight/project-legion), under `evidence/native/N-27` to `N-33`.
