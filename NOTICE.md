# Notices and sources

## Code this repository is derived from

### Linux mt76 (ISC)
Most of what MtkWlan knows about the hardware is ported from `drivers/net/wireless/mediatek/mt76`
in Linux v6.18 (https://github.com/torvalds/linux, tag v6.18, commit 7d0a66e4bb90), plus two TLV
length fixes from Linux master after v6.18 (commit 9ddb7487 and its CLC equivalent) in `MtkPower.cpp`.
Copyright (C) 2018 Felix Fietkau, Copyright (C) 2020, 2023 MediaTek Inc. mt76 moved to BSD-3-Clause-Clear
after v6.18; nothing here comes from the later versions except those two fixes.

| File | Ported from |
| --- | --- |
| `src/MtkWlan.cpp` | `mt7925/pci.c` probe, `mt792x_core.c` fw/drv ownership handshakes |
| `src/MtkRegs.cpp` | `mt7925/pci.c` bus address remapping (L1/L2 remap), `util.c` poll helper |
| `src/MtkFw.cpp` | `mt7925/pci.c`, `mt792x_dma.c`, `dma.c` (WFDMA rings), `mt7925/mcu.c`, `mt76_connac_mcu.c` (firmware download) |
| `src/MtkScan.cpp` | `mt7925/mcu.c` (UNI commands, NIC capability, EEPROM, channel domain, hw_scan), `mt7925/init.c`, `mt792x_mac.c` |
| `src/MtkJoin.cpp` | tag values and TLV layouts from `mt76_connac_mcu.h`, `mt7925/mcu.c`; STA_REC TLV order from `mt7925_mcu_sta_cmd` |
| `src/MtkNet.cpp` | `mt7925/mac.c` (`write_txwi`, `fill_rx`, `tx_free`, `queue_rx_skb`), `mt76_connac_mac.c` (`write_hw_txp`), `mac80211.c` (`mt76_check_ccmp_pn`) |
| `src/MtkBa.cpp` | `agg-rx.c` (`mt76_rx_aggr_reorder`, `_release_head`, `_check_release`, BlockAckReq), `mt7925/mcu.c` (`mt7925_mcu_sta_ba`), `mt7925/main.c` (`mt7925_ampdu_action`) |
| `src/MtkPower.cpp` | `mt7925/mcu.c` (`mt7925_load_clc`, `__mt7925_mcu_set_clc`, `mt7925_mcu_set_clc`, `mt7925_mcu_read_eeprom`, `mt7925_mcu_rate_txpower_band`, `mt7925_mcu_build_sku`) |
| `src/MtkSec.cpp` | the key install order and `mt7925_mcu_bss_sec_tlv` values from `mt7925/mcu.c`; `sta_rec_key_v3` layout from `mt76_connac_mcu.h` |

`src/MtkDma.cpp` (IODMACommand memory), `src/MtkWlanEth.cpp` (the IOEthernetController), `src/MtkUserClient.cpp`
(the IOUserClient), `src/MtkCoreApi.h` and `src/MtkUserApi.h` are written against Apple's IOKit headers and
contain no mt76 code.

### itlmt7925 (BSD-3-Clause-Clear)
itlmt7925, from https://github.com/thanhnndev/ga403wm-hackintosh (release kext-v1.1), by thanhnndev
and contributors. It was the first MT7925 driver for macOS that I know of. MtkWlan follows it in these places:

- `src/MtkScan.cpp`: the short post-firmware command sequence (NIC capability, DEV_INFO, BSS_INFO,
  domain, scan) and the beacon locator in `mtkParseFrame` (`itlmt7925_m2.cpp`, `_m3.cpp`).
- `src/MtkJoin.cpp`: the join sequence and the BSS_INFO, STA_REC, ROC and EDCA layouts, plus the
  legacy-rate WTBL preparation (`itlmt7925_m3.cpp`: `m3Run1`, `m3Bss`, `m3Edca`, `m3Sta`, `m3Roc`,
  `m3Tx`, `m3Auth`, `m3Assoc`, `m3ParseAp`, `m3HwPrep`), changed for open networks and restructured
  as a state machine in 0.9.0.
- `src/MtkCrypto.c`, `src/MtkCrypto.h`: adapted from `itl_wpa.cpp` / `itl_wpa.h` (SHA-1, HMAC, PBKDF2,
  the 802.11 PRF, AES-128, RFC 3394 key wrap). Whole files under the Clear BSD licence; the notice is
  in `MtkCrypto.h`.
- `src/MtkSupp.c`, `src/MtkSupp.h`: the EAPOL-Key frame handling started from `m3Handshake` in
  `itlmt7925_m3.cpp` and was restructured as an event-driven machine. Dual-licensed ISC AND
  BSD-3-Clause-Clear. The rules it enforces are from IEEE 802.11-2020 12.7.6 and from reading hostap's
  `wpa_supplicant` (`src/rsn_supp/wpa.c`); no hostap code was copied.

Those parts stay under the Clear BSD licence, whose full text and copyright notice are in
`LICENSES/BSD-3-Clause-Clear-itlmt7925.txt`. Every value taken from itlmt7925 was checked against
Linux; where the two differ, MtkWlan follows Linux. itlmt7925 itself credits mt76 for its hardware
layer. Anyone shipping a built MtkWlan.kext must include `LICENSE`, `NOTICE.md` and `LICENSES/`
with it (the Clear BSD licence requires this for binary redistribution).

`tools/mtkwifi/mtkwifi.c` links `src/MtkCrypto.c` for the PMK derivation and is otherwise IOKit user
client code under ISC.

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
  dictionary, link status), which `src/MtkWlanEth.cpp` follows.
- **hostap wpa_supplicant** (https://w1.fi/wpa_supplicant/, BSD): the handshake rules in `MtkSupp.h`.
- **IEEE 802.11-2020**: management and data frame layouts, LLC/SNAP encapsulation, RSN, the 4-way
  handshake (12.7.6), block ack (9.6.5).
- `src/kmod_info.c` reproduces the `kmod_info` block Xcode generates, using Apple's
  `KMOD_EXPLICIT_DECL` macro from `<mach/kmod.h>`.

## Build tools (used, not redistributed)
- acidanthera **MacKernelSDK** (https://github.com/acidanthera/MacKernelSDK): Apple kernel and IOKit
  headers, `libkmod`, for the Linux cross-build.
- tpoechtrager **cctools-port** (https://github.com/tpoechtrager/cctools-port): Apple's ld64 on Linux.
- swiftlang **swift-corelibs-libdispatch** (https://github.com/swiftlang/swift-corelibs-libdispatch):
  needed by ld64.
- LLVM/clang from Ubuntu, or Apple clang from the Xcode Command Line Tools on macOS.

## History
MtkWlan was developed inside a private notebook repository for a Lenovo Legion 5 15IAX10 hackintosh, with
one test boot per version and the OpenCore logs and registry dumps of each boot kept there. The
repository audit of itlmt7925 (cross-checks against Linux) was done before any of it was used.
