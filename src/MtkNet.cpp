// <wtl> project: mtkwlan | file: src/MtkNet.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// W6: Ethernet front-end (IOEthernetController, en1) over the BSS joined in W5.
// TX: Ethernet -> 802.11 data (ToDS, non-QoS, LLC/SNAP) on TX ring 0 in CT mode; TXD per
//   mt7925_mac_write_txwi / _80211 and hw txp per mt76_connac_write_hw_txp. The token is the slot
//   index, released by the firmware's TXRX_NOTIFY (mt7925_mac_tx_free).
// RX: RXD groups and header pad per mt7925_mac_fill_rx, then 802.11 (FromDS) -> Ethernet. RX header
//   translation stays off (STA_REC_HDR_TRANS dis_rx_hdr_tran), but a translated frame is accepted too.
// All of the above from Linux mt76 v6.18 (Copyright (C) 2023 MediaTek Inc., ISC).
// A 1 ms work-loop timer polls both RX rings, sends a null-data keepalive when idle and re-joins
// after a deauthentication. Counters are published as MtkW6* properties once a second.

#include "MtkWlan.hpp"
#include <IOKit/network/IOGatedOutputQueue.h>

namespace {
constexpr uint16_t AP_WCID = 1;                  // same as MtkJoin.cpp
constexpr uint8_t LMAC_AC_BE = 1, LMAC_ALTX0 = 0x10;
constexpr uint8_t RATE_IDX_OFDM6 = 18, RATE_IDX_OFDM12 = 20;
constexpr uint32_t DMA_CTL_LAST_SEC0 = 1u << 30;
constexpr uint32_t TICK_US = 1000;

inline uint32_t le32(const uint8_t *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

const uint8_t kSnap[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
const uint8_t kBridgeTunnel[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8};
} // namespace

// ---------------------------------------------------------------- TX ring 0

// The head slot can be filled when the device has fetched every descriptor but one, and the
// firmware has released the slot's token (or 500 ticks passed without a release)
bool MtkWlan::txSlotReady(bool force) {
    uint16_t next = (uint16_t)((txData.head + 1) % txData.n);
    if (next == (rawRead(txData.regs + 12) & 0xffff)) { txRingFull++; return false; }
    uint16_t s = txData.head;
    if (txBusy[s]) {
        if (!force && ticks - txBusyAt[s] < 500) return false;
        txBusy[s] = false;
        txLostFree++;
    }
    return true;
}

// TXD + hw txp for the frame already at slot + 128, then kick ring 0
void MtkWlan::txQueue(uint32_t flen, uint8_t qIdx, uint8_t ftype, uint8_t stype, uint8_t rate, bool mcast, bool status) {
    uint16_t slot = txData.head;
    uint8_t *w = txData.bufs.va + slot * txData.bufSize;
    uint32_t pa = txData.bufs.iova + slot * txData.bufSize;
    bzero(w, 128);
    put32(w + 0, (flen + 32) | (0u << 23) | ((uint32_t)qIdx << 25));            // TX_BYTES, PKT_FMT CT, Q_IDX
    put32(w + 4, AP_WCID | (2u << 14) | ((24u / 2) << 16) | (1u << 31));        // WLAN_IDX, HDR 802.11, HDR_INFO, FIXED_RATE
    put32(w + 8, ((uint32_t)ftype << 4) | stype);                                 // FRAME_TYPE, SUB_TYPE
    put32(w + 12, (15u << 11) | (mcast ? 1u << 4 : 0) | (status ? 1u << 28 : 0)); // REM_TX_COUNT, BCM, BA_DISABLE
    put32(w + 20, status ? (3 | (1u << 10)) : 0);                                 // PID, TX_STATUS_HOST
    put32(w + 24, (1u << 2) | (1u << 4) | (1u << 3) | ((uint32_t)rate << 16));    // DAS, MSDU_CNT 1, DIS_MAT, TX_RATE
    put16(w + 32, (uint16_t)(slot | 0x8000));                                     // txp.msdu_id[0] = token | VALID
    put32(w + 40, pa + 128);                                                      // txp.ptr[0].buf0
    put16(w + 44, (uint16_t)(flen | 0x8000));                                     // len0 | LAST
    txData.bufs.toDevice();
    volatile uint32_t *d = desc(txData, slot);
    d[0] = pa;
    d[2] = 0;
    d[3] = 0;
    d[1] = (64u << 16) | DMA_CTL_LAST_SEC0;                                       // SD_LEN0 = TXD + txp
    txBusy[slot] = true;
    txBusyAt[slot] = ticks;
    txData.head = (uint16_t)((slot + 1) % txData.n);
    rawWrite(txData.regs + 8, txData.head);
    lastTxTick = ticks;
}

// Management frame (auth / assoc) at 6 Mb/s with TX status, waits until the device fetched it
bool MtkWlan::txMgmt(const uint8_t *frame, uint32_t len, uint8_t subtype) {
    if (len > 1900 || len < 24) return false;
    txSlotReady(true);
    memcpy(txData.bufs.va + txData.head * txData.bufSize + 128, frame, len);
    txQueue(len, LMAC_ALTX0, 0, subtype, RATE_IDX_OFDM6, false, true);
    for (int t = 0; t < 2000; t++) {
        if ((rawRead(txData.regs + 12) & 0xffff) == txData.head) return true;
        IODelay(100);
    }
    return false;
}

// mt7925_mac_tx_free: release the tokens (slot indexes) listed in a TXRX_NOTIFY packet
void MtkWlan::txFree(const uint8_t *p, uint32_t len) {
    txFreeEvents++;
    if (len < 8 || ((le32(p + 4) >> 16) & 0xf) < 4) { txFreeBadVer++; return; }
    uint32_t total = (le32(p) >> 16) & 0x3ff, count = 0;
    for (uint32_t o = 8; o + 4 <= len && count < total; o += 4) {
        uint32_t info = le32(p + o);
        if (info & (1u << 31)) continue;                          // new WLAN_ID pair
        if (info & (1u << 30)) {                                  // header: tx count / status
            if ((info >> 28) & 3) txFailed++;
            continue;
        }
        for (int i = 0; i < 2; i++) {
            uint32_t id = (info >> (15 * i)) & 0x7fff;
            if (id == 0x7fff) continue;
            count++;
            if (id < txData.n && txBusy[id]) {
                txBusy[id] = false;
                txFreed++;
            }
        }
    }
}

// ---------------------------------------------------------------- RX

// A received frame while joined: data to the stack, deauth / disassoc from the AP ends the link
void MtkWlan::rxFrame(const uint8_t *p, uint32_t len) {
    if (!(rxCtrl & DMA_CTL_LAST_SEC0)) { rxPartial++; return; }
    if (len < 32) { rxBad++; return; }
    uint32_t rxd0 = le32(p), rxd1 = le32(p + 4), rxd2 = le32(p + 8), rxd3 = le32(p + 12);
    uint32_t total = rxd0 & 0xffff;
    if (total && total < len) len = total;
    if (rxd2 & ((1u << 23) | (1u << 24))) { rxBad++; return; }        // AMSDU_ERR, MAX_LEN_ERROR
    if (rxd3 & (1u << 24)) { rxBad++; return; }                       // FCS_ERR
    uint32_t off = 32;
    if (rxd1 & (1u << 19)) off += 16;                                 // group 4
    if (rxd1 & (1u << 16)) off += 16;                                 // group 1
    if (rxd1 & (1u << 17)) off += 16;                                 // group 2
    if (rxd1 & (1u << 18)) {                                          // group 3 (P-RXV), group 5 (C-RXV)
        off += 16;
        if (rxd1 & (1u << 20)) off += 96;
    }
    off += 2 * ((rxd2 >> 13) & 7);                                    // HDR_OFFSET pad
    if (off + 14 > len) { rxBad++; return; }
    const uint8_t *f = p + off;
    uint32_t flen = len - off;

    if (rxd2 & (1u << 7)) {                                           // HDR_TRANS: already 802.3
        if (rxd2 & (1u << 25)) { rxBad++; return; }
        rxTrans++;
        if (!memcmp(f + 6, mac, 6)) return;
        deliver(f, f + 6, f + 12, flen - 12);
        return;
    }

    uint16_t fc = le16(f);
    uint8_t type = (fc >> 2) & 3, sub = (fc >> 4) & 0xf;
    if (flen < 24) { rxBad++; return; }
    if (type == 0) {
        if ((sub == 12 || sub == 10) && !memcmp(f + 4, mac, 6) && !memcmp(f + 16, tgtBssid, 6) && flen >= 26) {
            lastDeauth = (uint32_t)sub << 16 | le16(f + 24);         // subtype << 16 | reason
            deauths++;
            linkLost();
        }
        return;
    }
    if (type != 2 || (f[1] & 3) != 2 || memcmp(f + 10, tgtBssid, 6) != 0) return;   // data, FromDS, from our AP
    if (sub & 4) return;                                              // null / no payload
    if (!(f[4] & 1) && memcmp(f + 4, mac, 6)) return;                 // unicast to another station
    if (f[1] & 0x40) { rxProtected++; return; }
    uint32_t h = 24;
    if (sub & 8) {
        h += 2;                                                       // QoS control
        if (f[1] & 0x80) h += 4;                                      // HT control (Order)
    }
    if (flen < h + 8) { rxBad++; return; }
    const uint8_t *l = f + h;
    if (memcmp(l, kSnap, 6) && memcmp(l, kBridgeTunnel, 6)) { rxNonSnap++; return; }
    if (!memcmp(f + 16, mac, 6)) { rxOwn++; return; }                 // our broadcast, relayed back by the AP
    deliver(f + 4, f + 16, l + 6, flen - h - 6);
}

// Hand one Ethernet frame (DA, SA, ethertype + payload) to the network stack
void MtkWlan::deliver(const uint8_t *da, const uint8_t *sa, const uint8_t *typeAndPayload, uint32_t n) {
    if (!netif || !ifEnabled || n < 2 || n > 1502) { rxDropped++; return; }
    mbuf_t m = allocatePacket(12 + n);
    if (!m) { rxDropped++; return; }
    uint8_t eh[12];
    memcpy(eh, da, 6);
    memcpy(eh + 6, sa, 6);
    if (mbuf_copyback(m, 0, 12, eh, MBUF_DONTWAIT) || mbuf_copyback(m, 12, n, typeAndPayload, MBUF_DONTWAIT)) {
        freePacket(m);
        rxDropped++;
        return;
    }
    netif->inputPacket(m, 12 + n, IONetworkInterface::kInputOptionQueuePacket);
    rxQueued = true;
    rxPackets++;
}

// ---------------------------------------------------------------- link

void MtkWlan::linkLost() {
    if (!linkUp) return;
    linkUp = false;
    rejoinAt = ticks + 500;
    reportLink();
}

void MtkWlan::reportLink() {
    if (!medium) return;
    bool up = linkUp && ifEnabled;
    if (up == linkReported) return;
    linkReported = up;
    setLinkStatus(up ? (kIONetworkLinkValid | kIONetworkLinkActive) : kIONetworkLinkValid, up ? medium : nullptr,
                  up ? 54000000ULL : 0);
}

void MtkWlan::keepalive() {
    if (!txSlotReady(false)) return;
    uint8_t *f = txData.bufs.va + txData.head * txData.bufSize + 128;
    bzero(f, 24);
    f[0] = 0x48;                                // null data
    f[1] = 0x01;                                // ToDS
    memcpy(f + 4, tgtBssid, 6);
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, tgtBssid, 6);
    txQueue(24, LMAC_AC_BE, 2, 4, RATE_IDX_OFDM12, false, false);
    keepalives++;
}

void MtkWlan::timerFired(OSObject *owner, IOTimerEventSource *) {
    MtkWlan *self = OSDynamicCast(MtkWlan, owner);
    if (self) self->tick();
}

void MtkWlan::tick() {
    ticks++;
    pollRx();
    uint32_t len = 0;
    const uint8_t *p;
    for (int guard = 0; guard < 64 && (p = rxPoll(rxMcu, &len)); guard++) {
        dispatchRx(p, len);
        rxRelease(rxMcu);
    }
    if (rxQueued && netif) {
        netif->flushInputQueue();
        rxQueued = false;
    }
    if (txStalled && txSlotReady(false)) {
        txStalled = false;
        if (IOOutputQueue *q = getOutputQueue()) q->service(IOBasicOutputQueue::kServiceAsync);
    }
    if (linkUp && ticks - lastTxTick > 10000) keepalive();
    if (!linkUp && tgtFound && joinedOnce && (int32_t)(ticks - rejoinAt) >= 0) {
        rejoins++;
        if (authAssoc(false) == 0) {
            bssInfo(true);
            staRec(2, false, aid);
            linkUp = true;
        } else {
            rejoinAt = ticks + 5000;
        }
        reportLink();
    }
    if (ticks % 1000 == 0) publishW6();
    timer->setTimeoutUS(TICK_US);
}

void MtkWlan::publishW6() {
    setNum("MtkW6Ticks", ticks);
    setNum("MtkW6TxPackets", txPackets);
    setNum("MtkW6TxStall", txStall);
    setNum("MtkW6TxDrop", txDrop);
    setNum("MtkW6TxRingFull", txRingFull);
    setNum("MtkW6TxFreeEvents", txFreeEvents);
    setNum("MtkW6TxFreed", txFreed);
    setNum("MtkW6TxFreeBadVer", txFreeBadVer);
    setNum("MtkW6TxLostFree", txLostFree);
    setNum("MtkW6TxFailed", txFailed);
    setNum("MtkW6RxPackets", rxPackets);
    setNum("MtkW6RxBad", rxBad);
    setNum("MtkW6RxPartial", rxPartial);
    setNum("MtkW6RxTrans", rxTrans);
    setNum("MtkW6RxNonSnap", rxNonSnap);
    setNum("MtkW6RxProtected", rxProtected);
    setNum("MtkW6RxOwn", rxOwn);
    setNum("MtkW6RxDropped", rxDropped);
    setNum("MtkW6RxFrames", rxFrames);
    setNum("MtkW6Deauths", deauths);
    setNum("MtkW6LastDeauth", lastDeauth);
    setNum("MtkW6Rejoins", rejoins);
    setNum("MtkW6Keepalives", keepalives);
    setNum("MtkW6Link", (linkUp ? 1 : 0) | (ifEnabled ? 2 : 0) | (linkReported ? 4 : 0));
    char s[160];
    size_t k = 0;
    s[0] = 0;
    for (int t = 0; t < 32 && k + 12 < sizeof(s); t++)
        if (rxTypes[t]) k += snprintf(s + k, sizeof(s) - k, "%s%d:%u", k ? " " : "", t, rxTypes[t]);
    setProperty("MtkW6RxTypes", s[0] ? s : "none");
}

// Called at the end of start() once W5 passed: timer, medium, network interface
int MtkWlan::netStage() {
    IOWorkLoop *wl = getWorkLoop();
    if (!wl) { step("W6 fail: no work loop"); return -1; }
    timer = IOTimerEventSource::timerEventSource(this, &MtkWlan::timerFired);
    if (!timer || wl->addEventSource(timer) != kIOReturnSuccess) { step("W6 fail: timer"); return -2; }

    OSDictionary *md = OSDictionary::withCapacity(1);
    medium = IONetworkMedium::medium(kIOMediumEthernetAuto, 54000000ULL);
    if (!md || !medium || !IONetworkMedium::addMedium(md, medium) || !publishMediumDictionary(md)) {
        OSSafeReleaseNULL(md);
        step("W6 fail: medium dictionary");
        return -3;
    }
    md->release();

    if (!attachInterface((IONetworkInterface **)&netif, false)) { step("W6 fail: attachInterface"); return -4; }
    netif->registerService();
    timer->setTimeoutUS(TICK_US);
    step("W6 interface attached (link up, waiting for DHCP)");
    return 0;
}

// ---------------------------------------------------------------- IOEthernetController

bool MtkWlan::createWorkLoop() {
    workLoop = IOWorkLoop::workLoop();
    return workLoop != nullptr;
}

IOWorkLoop *MtkWlan::getWorkLoop() const {
    return workLoop;
}

IOOutputQueue *MtkWlan::createOutputQueue() {
    return IOGatedOutputQueue::withTarget(this, getWorkLoop(), 512);
}

IOReturn MtkWlan::getHardwareAddress(IOEthernetAddress *addr) {
    memcpy(addr->bytes, mac, 6);
    return kIOReturnSuccess;
}

IOReturn MtkWlan::enable(IONetworkInterface *) {
    ifEnabled = true;
    if (IOOutputQueue *q = getOutputQueue()) {
        q->setCapacity(512);
        q->start();
    }
    reportLink();
    return kIOReturnSuccess;
}

IOReturn MtkWlan::disable(IONetworkInterface *) {
    ifEnabled = false;
    if (IOOutputQueue *q = getOutputQueue()) {
        q->stop();
        q->setCapacity(0);
        q->flush();
    }
    reportLink();
    return kIOReturnSuccess;
}

IOReturn MtkWlan::setPromiscuousMode(bool) { return kIOReturnSuccess; }
IOReturn MtkWlan::setMulticastMode(bool) { return kIOReturnSuccess; }
IOReturn MtkWlan::setMulticastList(IOEthernetAddress *, UInt32) { return kIOReturnSuccess; }
const OSString *MtkWlan::newVendorString() const { return OSString::withCString("MediaTek"); }
const OSString *MtkWlan::newModelString() const { return OSString::withCString("MT7925 (MtkWlan)"); }

// Ethernet -> 802.11 data: ToDS, A1 BSSID, A2 us, A3 DA, LLC/SNAP + ethertype, then the payload
UInt32 MtkWlan::outputPacket(mbuf_t m, void *) {
    uint32_t len = (uint32_t)mbuf_pkthdr_len(m);
    if (!linkUp || len < 14 || len > 1514) {
        freePacket(m);
        txDrop++;
        return kIOReturnOutputDropped;
    }
    if (!txSlotReady(false)) {
        txStall++;
        txStalled = true;
        return kIOReturnOutputStall;
    }
    uint8_t eh[14];
    mbuf_copydata(m, 0, 14, eh);
    uint8_t *f = txData.bufs.va + txData.head * txData.bufSize + 128;
    f[0] = 0x08;                                // data
    f[1] = 0x01;                                // ToDS
    f[2] = f[3] = 0;
    memcpy(f + 4, tgtBssid, 6);
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, eh, 6);
    f[22] = f[23] = 0;
    memcpy(f + 24, kSnap, 6);
    f[30] = eh[12];
    f[31] = eh[13];
    mbuf_copydata(m, 14, len - 14, f + 32);
    bool mc = eh[0] & 1;
    txQueue(32 + len - 14, LMAC_AC_BE, 2, 0, mc ? RATE_IDX_OFDM12 : dataRate, mc, false);
    txPackets++;
    freePacket(m);
    return kIOReturnOutputSuccess;
}
