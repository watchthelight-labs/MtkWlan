# Notices

## Linux mt76 (ISC)
Register maps, the WFDMA ring setup, firmware download, MCU message formats, TX/RX descriptors and
the TX-free handling are ported from `drivers/net/wireless/mediatek/mt76` in Linux v6.18
(commit 7d0a66e4bb90). Copyright (C) 2023 MediaTek Inc. Those files are under ISC. mt76 moved to
BSD-3-Clause-Clear after v6.18; nothing here comes from the later versions.

Files: all of `src/` except `kmod_info.c`.

## itlmt7925 (BSD-3-Clause-Clear)
The post-firmware command sequence and beacon locator in `src/MtkScan.cpp`, and the join sequence
in `src/MtkJoin.cpp` (BSS_INFO, STA_REC, ROC, EDCA layouts and the legacy-rate WTBL prep), follow
itlmt7925 from https://github.com/thanhnndev/ga403wm-hackintosh (release kext-v1.1).
Copyright (c) 2026 thanhnndev and contributors. Those parts stay under the Clear BSD licence in
`LICENSES/BSD-3-Clause-Clear-itlmt7925.txt`. Every value taken from it was checked against Linux.
Where the two differ, MtkWlan follows Linux.

## MediaTek firmware
`firmware/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin` and `firmware/WIFI_RAM_CODE_MT7925_1_1.bin` come from
linux-firmware (https://gitlab.com/kernel-firmware/linux-firmware, commit d5455717ead0) and are
redistributable under `LICENSES/LICENCE.mediatek`. They are unmodified. The build embeds them in
the kext.
