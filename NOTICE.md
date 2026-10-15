# Notices and sources

## Code this repository is derived from

### Linux mt76 (ISC)
Most of what MtkWlan knows about the hardware is ported from `drivers/net/wireless/mediatek/mt76`
in Linux v6.18 (https://github.com/torvalds/linux, tag v6.18, commit 7d0a66e4bb90).
Copyright (C) 2020, 2023 MediaTek Inc. mt76 moved to BSD-3-Clause-Clear after v6.18; nothing here
comes from the later versions.

| File | Ported from |
| --- | --- |
| `src/MtkWlan.cpp` | `mt7925/pci.c` probe, `mt792x_core.c` fw/drv ownership handshakes |
| `src/MtkRegs.cpp` | `mt7925/pci.c` bus address remapping (L1/L2 remap), `util.c` poll helper |
| `src/MtkFw.cpp` | `mt7925/pci.c`, `mt792x_dma.c`, `dma.c` (WFDMA rings), `mt7925/mcu.c`, `mt76_connac_mcu.c` (firmware download) |
| `src/MtkScan.cpp` | `mt7925/mcu.c` (UNI commands, NIC capability, EEPROM, channel domain, hw_scan), `mt7925/init.c`, `mt792x_mac.c` |
| `src/MtkJoin.cpp` | tag values and TLV layouts from `mt76_connac_mcu.h`, `mt7925/mcu.c` |
| `src/MtkNet.cpp` | `mt7925/mac.c` (`write_txwi`, `fill_rx`, `tx_free`, `queue_rx_skb`), `mt76_connac_mac.c` (`write_hw_txp`) |

`src/MtkDma.cpp` (IODMACommand memory) and the IOEthernetController parts of `src/MtkNet.cpp` are
written against Apple's IOKit headers and contain no mt76 code.

### itlmt7925 (BSD-3-Clause-Clear)
itlmt7925, from https://github.com/thanhnndev/ga403wm-hackintosh (release kext-v1.1), by thanhnndev
and contributors. It was the first MT7925 driver for macOS that I know of. MtkWlan follows it in two places:

- `src/MtkScan.cpp`: the short post-firmware command sequence (NIC capability, DEV_INFO, BSS_INFO,
  domain, scan) and the beacon locator in `mtkParseFrame` (`itlmt7925_m2.cpp`, `_m3.cpp`).
- `src/MtkJoin.cpp`: the join sequence and the BSS_INFO, STA_REC, ROC and EDCA layouts, plus the
  legacy-rate WTBL preparation (`itlmt7925_m3.cpp`: `m3Run1`, `m3Bss`, `m3Edca`, `m3Sta`, `m3Roc`,
  `m3Tx`, `m3Auth`, `m3Assoc`, `m3ParseAp`, `m3HwPrep`), changed for open networks.

Those parts stay under the Clear BSD licence, whose full text and copyright notice are in
`LICENSES/BSD-3-Clause-Clear-itlmt7925.txt`. Every value taken from itlmt7925 was checked against
Linux; where the two differ, MtkWlan follows Linux. itlmt7925 itself credits mt76 for its hardware
layer. Anyone shipping a built MtkWlan.kext must include `LICENSE`, `NOTICE.md` and `LICENSES/`
with it (the Clear BSD licence requires this for binary redistribution).

## Firmware
`firmware/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin` and `firmware/WIFI_RAM_CODE_MT7925_1_1.bin` are
MediaTek's, from linux-firmware (https://gitlab.com/kernel-firmware/linux-firmware, commit
d5455717ead0), unmodified and redistributable under `LICENSES/LICENCE.mediatek`. They are not
under ISC. The build embeds them in the kext.

## Design references (no code copied)
- **itlwm** (https://github.com/OpenIntelWireless/itlwm, GPL-2.0): the idea of a Wi-Fi kext that
  shows up as a plain Ethernet device and does its own 802.11 handling instead of using IO80211Family.
- **RealtekRTL8111** by Laura Müller (Mieze) (https://github.com/Mieze/RealtekRTL8111-OSX): the usual
  shape of an open-source IOEthernetController kext (own work loop, gated output queue, medium
  dictionary, link status), which `src/MtkNet.cpp` follows.
- **IEEE 802.11-2020**: management and data frame layouts, LLC/SNAP encapsulation.
- `src/kmod_info.c` reproduces the `kmod_info` block Xcode generates, using Apple's
  `KMOD_EXPLICIT_DECL` macro from `<mach/kmod.h>`.

## Build tools (used, not redistributed)
- acidanthera **MacKernelSDK** (https://github.com/acidanthera/MacKernelSDK): Apple kernel and IOKit
  headers, `libkmod`.
- tpoechtrager **cctools-port** (https://github.com/tpoechtrager/cctools-port): Apple's ld64 on Linux.
- swiftlang **swift-corelibs-libdispatch** (https://github.com/swiftlang/swift-corelibs-libdispatch):
  needed by ld64.
- LLVM/clang from Ubuntu.

## Research and history
MtkWlan was developed inside [project-legion](https://github.com/watchthelight/project-legion), a
hackintosh project for a Lenovo Legion 5 15IAX10. These records are there:

- `evidence/native/N-27` to `N-33`: every test boot, with OpenCore logs and the driver's
  registry dumps.
- `research/repository-audits/ga403wm-hackintosh.md`: the audit of itlmt7925 before any of it
  was used, with the cross-checks against Linux.
- `research/repository-audits/cctools-port.md`, `swift-corelibs-libdispatch.md`: toolchain audits.
- `research/mt7925-driver/`: the research that mapped the MT7925 bring-up path through mt76.

The code was written by Claude (Anthropic) in Claude Code. Claude on claude.ai read the boot-screen
photos and helped analyse the register dumps between test boots.
