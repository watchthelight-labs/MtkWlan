// <wtl> project: mtkwlan | file: src/MtkRegs.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Register access for the MT7925 over PCIe BAR0, including the bus address remapping.
// Ported from Linux drivers/net/wireless/mediatek/mt76/mt7925/pci.c (v6.18):
//   Copyright (C) 2023 MediaTek Inc. (ISC, see LICENSE in this folder)
// Linux mt76 accessors map 1:1: bus_ops->rr/wr = rawRead/rawWrite, mt7925_rr/wr/rmw = rr/wr/rmw.

#include "MtkWlan.hpp"

namespace {
struct RegMap { uint32_t phys, maps, size; };

// mt7925/pci.c fixed_map[]
const RegMap kFixedMap[] = {
    { 0x830c0000, 0x000000, 0x0001000 }, // WF_MCU_BUS_CR_REMAP
    { 0x54000000, 0x002000, 0x0001000 }, // WFDMA PCIE0 MCU DMA0
    { 0x55000000, 0x003000, 0x0001000 }, // WFDMA PCIE0 MCU DMA1
    { 0x56000000, 0x004000, 0x0001000 }, // WFDMA reserved
    { 0x57000000, 0x005000, 0x0001000 }, // WFDMA MCU wrap CR
    { 0x58000000, 0x006000, 0x0001000 }, // WFDMA PCIE1 MCU DMA0 (MEM_DMA)
    { 0x59000000, 0x007000, 0x0001000 }, // WFDMA PCIE1 MCU DMA1
    { 0x820c0000, 0x008000, 0x0004000 }, // WF_UMAC_TOP (PLE)
    { 0x820c8000, 0x00c000, 0x0002000 }, // WF_UMAC_TOP (PSE)
    { 0x820cc000, 0x00e000, 0x0002000 }, // WF_UMAC_TOP (PP)
    { 0x74030000, 0x010000, 0x0001000 }, // PCIe MAC
    { 0x820e0000, 0x020000, 0x0000400 }, // WF_LMAC_TOP BN0 (WF_CFG)
    { 0x820e1000, 0x020400, 0x0000200 }, // WF_LMAC_TOP BN0 (WF_TRB)
    { 0x820e2000, 0x020800, 0x0000400 }, // WF_LMAC_TOP BN0 (WF_AGG)
    { 0x820e3000, 0x020c00, 0x0000400 }, // WF_LMAC_TOP BN0 (WF_ARB)
    { 0x820e4000, 0x021000, 0x0000400 }, // WF_LMAC_TOP BN0 (WF_TMAC)
    { 0x820e5000, 0x021400, 0x0000800 }, // WF_LMAC_TOP BN0 (WF_RMAC)
    { 0x820ce000, 0x021c00, 0x0000200 }, // WF_LMAC_TOP (WF_SEC)
    { 0x820e7000, 0x021e00, 0x0000200 }, // WF_LMAC_TOP BN0 (WF_DMA)
    { 0x820cf000, 0x022000, 0x0001000 }, // WF_LMAC_TOP (WF_PF)
    { 0x820e9000, 0x023400, 0x0000200 }, // WF_LMAC_TOP BN0 (WF_WTBLOFF)
    { 0x820ea000, 0x024000, 0x0000200 }, // WF_LMAC_TOP BN0 (WF_ETBF)
    { 0x820eb000, 0x024200, 0x0000400 }, // WF_LMAC_TOP BN0 (WF_LPON)
    { 0x820ec000, 0x024600, 0x0000200 }, // WF_LMAC_TOP BN0 (WF_INT)
    { 0x820ed000, 0x024800, 0x0000800 }, // WF_LMAC_TOP BN0 (WF_MIB)
    { 0x820ca000, 0x026000, 0x0002000 }, // WF_LMAC_TOP BN0 (WF_MUCOP)
    { 0x820d0000, 0x030000, 0x0010000 }, // WF_LMAC_TOP (WF_WTBLON)
    { 0x40000000, 0x070000, 0x0010000 }, // WF_UMAC_SYSRAM
    { 0x00400000, 0x080000, 0x0010000 }, // WF_MCU_SYSRAM
    { 0x00410000, 0x090000, 0x0010000 }, // WF_MCU_SYSRAM (configure register)
    { 0x820f0000, 0x0a0000, 0x0000400 }, // WF_LMAC_TOP BN1 (WF_CFG)
    { 0x820f1000, 0x0a0600, 0x0000200 }, // WF_LMAC_TOP BN1 (WF_TRB)
    { 0x820f2000, 0x0a0800, 0x0000400 }, // WF_LMAC_TOP BN1 (WF_AGG)
    { 0x820f3000, 0x0a0c00, 0x0000400 }, // WF_LMAC_TOP BN1 (WF_ARB)
    { 0x820f4000, 0x0a1000, 0x0000400 }, // WF_LMAC_TOP BN1 (WF_TMAC)
    { 0x820f5000, 0x0a1400, 0x0000800 }, // WF_LMAC_TOP BN1 (WF_RMAC)
    { 0x820f7000, 0x0a1e00, 0x0000200 }, // WF_LMAC_TOP BN1 (WF_DMA)
    { 0x820f9000, 0x0a3400, 0x0000200 }, // WF_LMAC_TOP BN1 (WF_WTBLOFF)
    { 0x820fa000, 0x0a4000, 0x0000200 }, // WF_LMAC_TOP BN1 (WF_ETBF)
    { 0x820fb000, 0x0a4200, 0x0000400 }, // WF_LMAC_TOP BN1 (WF_LPON)
    { 0x820fc000, 0x0a4600, 0x0000200 }, // WF_LMAC_TOP BN1 (WF_INT)
    { 0x820fd000, 0x0a4800, 0x0000800 }, // WF_LMAC_TOP BN1 (WF_MIB)
    { 0x820c4000, 0x0a8000, 0x0004000 }, // WF_LMAC_TOP BN1 (WF_MUCOP)
    { 0x820b0000, 0x0ae000, 0x0001000 }, // [APB2] WFSYS_ON
    { 0x80020000, 0x0b0000, 0x0010000 }, // WF_TOP_MISC_OFF
    { 0x81020000, 0x0c0000, 0x0010000 }, // WF_TOP_MISC_ON
    { 0x7c020000, 0x0d0000, 0x0010000 }, // CONN_INFRA, wfdma
    { 0x7c060000, 0x0e0000, 0x0010000 }, // CONN_INFRA, conn_host_csr_top
    { 0x7c000000, 0x0f0000, 0x0010000 }, // CONN_INFRA
    { 0x70020000, 0x1f0000, 0x0010000 }, // Reserved for CBTOP, can't switch
    { 0x7c500000, 0x060000, 0x2000000 }, // remap
};

// mt7925/regs.h
constexpr uint32_t MT_HIF_REMAP_L1        = 0x155024;
constexpr uint32_t MT_HIF_REMAP_L1_MASK   = 0xffff0000; // GENMASK(31, 16)
constexpr uint32_t MT_HIF_REMAP_BASE_L1   = 0x130000;
constexpr uint32_t MT_HIF_REMAP_L2        = 0x0120;
constexpr uint32_t MT_HIF_REMAP_BASE_L2   = 0x18500000; // CONFIG_MT76_DEV is not a Kconfig symbol
} // namespace

uint32_t MtkWlan::rawRead(uint32_t off) {
    if (!mmio || off + 4 > mmioLen) { badAccess++; return 0xffffffff; }
    return OSReadLittleInt32((void *)mmio, off);
}

void MtkWlan::rawWrite(uint32_t off, uint32_t val) {
    if (!mmio || off + 4 > mmioLen) { badAccess++; return; }
    OSWriteLittleInt32((void *)mmio, off, val);
}

uint32_t MtkWlan::rawRmw(uint32_t off, uint32_t mask, uint32_t val) {
    uint32_t cur = rawRead(off) & ~mask;
    rawWrite(off, cur | val);
    return cur;
}

void MtkWlan::remapRestore() {
    if (backupL1) { rawWrite(MT_HIF_REMAP_L1, backupL1); backupL1 = 0; }
    if (backupL2) { rawWrite(MT_HIF_REMAP_L2, backupL2); backupL2 = 0; }
}

uint32_t MtkWlan::mapL1(uint32_t addr) {
    uint32_t offset = addr & 0xffff;
    uint32_t base = addr >> 16;
    backupL1 = rawRead(MT_HIF_REMAP_L1);
    rawRmw(MT_HIF_REMAP_L1, MT_HIF_REMAP_L1_MASK, base << 16);
    rawRead(MT_HIF_REMAP_L1); // read to push the write
    return MT_HIF_REMAP_BASE_L1 + offset;
}

uint32_t MtkWlan::mapL2(uint32_t addr) {
    uint32_t base = MT_HIF_REMAP_BASE_L2 >> 16;
    backupL2 = rawRead(MT_HIF_REMAP_L1);
    rawRmw(MT_HIF_REMAP_L1, MT_HIF_REMAP_L1_MASK, base << 16);
    rawWrite(MT_HIF_REMAP_L2, addr);
    rawRead(MT_HIF_REMAP_L1); // read to push the write
    return MT_HIF_REMAP_BASE_L1;
}

uint32_t MtkWlan::regAddr(uint32_t addr) {
    if (addr < 0x200000)
        return addr;

    remapRestore();

    for (const RegMap &m : kFixedMap) {
        if (addr < m.phys)
            continue;
        uint32_t ofs = addr - m.phys;
        if (ofs > m.size)
            continue;
        return m.maps + ofs;
    }

    if ((addr >= 0x18000000 && addr < 0x18c00000) ||
        (addr >= 0x70000000 && addr < 0x78000000) ||
        (addr >= 0x7c000000 && addr < 0x7c400000))
        return mapL1(addr);

    return mapL2(addr);
}

uint32_t MtkWlan::rr(uint32_t reg) { return rawRead(regAddr(reg)); }
void MtkWlan::wr(uint32_t reg, uint32_t val) { rawWrite(regAddr(reg), val); }
uint32_t MtkWlan::rmw(uint32_t reg, uint32_t mask, uint32_t val) { return rawRmw(regAddr(reg), mask, val); }

// mt76/util.c ____mt76_poll_msec
bool MtkWlan::pollMsec(uint32_t reg, uint32_t mask, uint32_t val, int timeoutMs, int tickMs) {
    int timeout = timeoutMs / tickMs;
    do {
        if ((rr(reg) & mask) == val)
            return true;
        IOSleep(tickMs);
    } while (timeout-- > 0);
    return false;
}
