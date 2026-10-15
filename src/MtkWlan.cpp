// <wtl> project: mtkwlan | file: src/MtkWlan.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// W1 bring-up, following mt7925_pci_probe() in Linux mt76 v6.18 (mt7925/pci.c) and the
// ownership handshakes in mt792x_core.c (Copyright (C) 2023 MediaTek Inc., ISC):
//   memory + bus master on, BAR0 mapped, fw_own then drv_own, read chip ID and revision.
// Then W2/W3 (MtkFw.cpp): WFSYS reset, WFDMA rings, MSI, patch + RAM firmware download.

#include "MtkWlan.hpp"

OSDefineMetaClassAndStructors(MtkWlan, IOEthernetController)

namespace {
// mt792x_regs.h / mt7925/regs.h
constexpr uint32_t MT_CONN_ON_LPCTL         = 0x7c060010;
constexpr uint32_t PCIE_LPCR_HOST_SET_OWN   = 1u << 0;
constexpr uint32_t PCIE_LPCR_HOST_CLR_OWN   = 1u << 1;
constexpr uint32_t PCIE_LPCR_HOST_OWN_SYNC  = 1u << 2;
constexpr uint32_t MT_CONN_ON_MISC          = 0x7c0600f0;
constexpr uint32_t MT_HW_CHIPID             = 0x70010200;
constexpr uint32_t MT_HW_REV                = 0x70010204;
constexpr uint32_t MT_WFSYS_SW_RST_B        = 0x7c000140;
constexpr int      MT792x_DRV_OWN_RETRY_COUNT = 10;
} // namespace

void MtkWlan::step(const char *state) {
    setProperty("MtkState", state);
    IOLog("MtkWlan: %s\n", state);
}

void MtkWlan::setNum(const char *key, uint64_t val, unsigned bits) {
    setProperty(key, val, bits);
}

// mt792xe_mcu_fw_pmctrl: hand the chip to the firmware (SET_OWN, wait for OWN_SYNC = 1)
int MtkWlan::fwOwn() {
    for (int i = 0; i < MT792x_DRV_OWN_RETRY_COUNT; i++) {
        wr(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_SET_OWN);
        if (pollMsec(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_OWN_SYNC, PCIE_LPCR_HOST_OWN_SYNC, 50, 1))
            return i + 1;
    }
    return -1;
}

// __mt792xe_mcu_drv_pmctrl: take the chip back for the driver (CLR_OWN, wait for OWN_SYNC = 0)
int MtkWlan::drvOwn() {
    for (int i = 0; i < MT792x_DRV_OWN_RETRY_COUNT; i++) {
        wr(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_CLR_OWN);
        if (pollMsec(MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_OWN_SYNC, 0, 50, 1))
            return i + 1;
    }
    return -1;
}

// Which interrupt sources IOPCIFamily offers for the card (MSI is what W2 needs)
void MtkWlan::listInterrupts() {
    char buf[96];
    int len = 0;
    buf[0] = 0;
    for (int i = 0; i < 8; i++) {
        int type = 0;
        if (pci->getInterruptType(i, &type) != kIOReturnSuccess)
            break;
        len += snprintf(buf + len, sizeof(buf) - len, "%s%d:%s", i ? " " : "", i,
                        (type & kIOInterruptTypePCIMessaged) ? "msi" :
                        (type & kIOInterruptTypeLevel) ? "level" : "edge");
        if (len >= (int)sizeof(buf))
            break;
    }
    setProperty("MtkInterrupts", buf[0] ? buf : "none");
}

bool MtkWlan::start(IOService *provider) {
    if (!IOEthernetController::start(provider))
        return false;

    pci = OSDynamicCast(IOPCIDevice, provider);
    if (!pci) {
        step("W1 fail: provider is not a PCI device");
        return true; // stay attached so the state is visible
    }
    pci->retain();
    OSString *ssid = OSDynamicCast(OSString, getProperty("MtkSsid"));
    if (ssid) strlcpy(tgtSsid, ssid->getCStringNoCopy(), sizeof(tgtSsid));
    OSNumber *rate = OSDynamicCast(OSNumber, getProperty("MtkDataRate"));
    if (rate && rate->unsigned32BitValue() >= 18 && rate->unsigned32BitValue() <= 25) dataRate = (uint8_t)rate->unsigned8BitValue();
    setProperty("MtkMilestone", "W1");

    setNum("MtkPciCommandBefore", pci->configRead16(kIOPCIConfigCommand), 16);
    pci->setMemoryEnable(true);
    pci->setBusMasterEnable(true);
    setNum("MtkPciCommand", pci->configRead16(kIOPCIConfigCommand), 16);

    map = pci->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
    if (!map) {
        step("W1 fail: BAR0 map");
        return true;
    }
    mmio = (volatile uint8_t *)map->getVirtualAddress();
    mmioLen = (uint32_t)map->getLength();
    setNum("MtkBar0Phys", map->getPhysicalAddress(), 64);
    setNum("MtkBar0Size", mmioLen);
    step("W1 BAR0 mapped");

    listInterrupts();

    setNum("MtkLpctlBefore", rr(MT_CONN_ON_LPCTL));
    int fw = fwOwn();
    setNum("MtkFwOwnTries", (uint32_t)fw);
    int drv = drvOwn();
    setNum("MtkDrvOwnTries", (uint32_t)drv);
    setNum("MtkLpctl", rr(MT_CONN_ON_LPCTL));
    if (drv < 0) {
        setNum("MtkBadAccess", badAccess);
        step(fw < 0 ? "W1 fail: fw_own and drv_own" : "W1 fail: drv_own");
        return true;
    }

    uint32_t chipId = rr(MT_HW_CHIPID);
    uint32_t hwRev = rr(MT_HW_REV);
    setNum("MtkChipId", chipId);
    setNum("MtkHwRev", hwRev);
    setNum("MtkAsicRevision", (chipId << 16) | (hwRev & 0xff)); // mdev->rev in mt7925_pci_probe
    setNum("MtkConnOnMisc", rr(MT_CONN_ON_MISC));
    setNum("MtkWfsysSwRst", rr(MT_WFSYS_SW_RST_B));
    setNum("MtkBadAccess", badAccess);

    if ((chipId & 0xffff) != 0x7925) {
        step("W1 partial: drv_own ok, unexpected chip id");
        return true;
    }
    step("W1 pass: drv_own ok, chip 7925");

    mapper = IOMapper::copyMapperForDevice(pci);
    setProperty("MtkMapper", mapper ? "device mapper" : "none (physical addresses)");
    bringUp();
    setNum("MtkBadAccess", badAccess);
    registerService();
    return true;
}

void MtkWlan::stop(IOService *provider) {
    if (timer) {
        timer->cancelTimeout();
        if (workLoop) workLoop->removeEventSource(timer);
        OSSafeReleaseNULL(timer);
    }
    if (netif) {
        detachInterface(netif);
        OSSafeReleaseNULL(netif);
    }
    if (irqIndex >= 0) {
        pci->disableInterrupt(irqIndex);
        pci->unregisterInterrupt(irqIndex);
        irqIndex = -1;
    }
    if (mmio)
        rawWrite(0xd4208, rawRead(0xd4208) & ~0x5u); // WFDMA0 GLO_CFG: stop TX/RX DMA before freeing rings
    ringFree(txData); ringFree(txMcu); ringFree(txFwdl); ringFree(rxMcu); ringFree(rxData);
    OSSafeReleaseNULL(mapper);
    OSSafeReleaseNULL(map);
    mmio = nullptr;
    OSSafeReleaseNULL(pci);
    IOEthernetController::stop(provider);
}

void MtkWlan::free() {
    OSSafeReleaseNULL(medium);
    OSSafeReleaseNULL(workLoop);
    IOEthernetController::free();
}
