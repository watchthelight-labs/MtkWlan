// <wtl> project: mtkwlan | file: src/MtkWlan.hpp | author: watchthelight </wtl>
// MtkWlan: macOS driver for the MediaTek MT7925 Wi-Fi 7 PCIe card (14C3:7925) in the Legion 5 15IAX10.
// W1: PCI attach, BAR0 map, ownership handshake, chip ID. W2: WFDMA rings + MSI. W3: firmware download.
// W4: NIC capability (MAC), station interface, US channel domain, firmware scan.
// W5: open-system auth + association to the target SSID (MtkSsid in Info.plist).
// W6: Ethernet front-end (en1): 802.11 data TX/RX, TX-free tokens, keepalive, rejoin (MtkNet.cpp).
// Recovery keeps only 128 KB of kernel log, so every step publishes its result as a registry
// property (Mtk*), which recon.sh / wifi.sh capture with ioreg.

#ifndef MTKWLAN_HPP
#define MTKWLAN_HPP

#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkMedium.h>
#include <sys/kpi_mbuf.h>
#include <IOKit/IOLib.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSByteOrder.h>
#include "MtkDma.hpp"

// One WFDMA ring (mt76_queue): descriptors plus one fixed buffer per slot
struct MtkRing {
    MtkDmaMem desc, bufs;
    uint32_t regs = 0;      // BAR offset of {desc_base, ring_size, cpu_idx, dma_idx}
    uint32_t bufSize = 0;
    uint16_t n = 0, head = 0, tail = 0;
    bool rx = false;
};

struct MtkAp {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t ch;
    uint16_t seen;
};

class MtkWlan : public IOEthernetController {
    OSDeclareDefaultStructors(MtkWlan)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;

    // MtkNet.cpp: W6 Ethernet front-end
    bool createWorkLoop() override;
    IOWorkLoop *getWorkLoop() const override;
    IOOutputQueue *createOutputQueue() override;
    IOReturn getHardwareAddress(IOEthernetAddress *addr) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    IOReturn setPromiscuousMode(bool active) override;
    IOReturn setMulticastMode(bool active) override;
    IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count) override;
    const OSString *newVendorString() const override;
    const OSString *newModelString() const override;
    UInt32 outputPacket(mbuf_t m, void *param) override;

    // MtkRegs.cpp: BAR0 access with the mt7925 bus address remapping (port of mt7925/pci.c)
    uint32_t rr(uint32_t reg);
    void wr(uint32_t reg, uint32_t val);
    uint32_t rmw(uint32_t reg, uint32_t mask, uint32_t val);
    bool pollMsec(uint32_t reg, uint32_t mask, uint32_t val, int timeoutMs, int tickMs);

private:
    uint32_t rawRead(uint32_t off);
    void rawWrite(uint32_t off, uint32_t val);
    uint32_t rawRmw(uint32_t off, uint32_t mask, uint32_t val);
    uint32_t regAddr(uint32_t addr);
    uint32_t mapL1(uint32_t addr);
    uint32_t mapL2(uint32_t addr);
    void remapRestore();

    int fwOwn();
    int drvOwn();

    // MtkFw.cpp: W2/W3
    int bringUp();
    int ringAlloc(MtkRing &r, bool rx, uint16_t idx, uint16_t n, uint32_t bufSize);
    void ringFree(MtkRing &r) { r.desc.free(); r.bufs.free(); }
    volatile uint32_t *desc(MtkRing &r, uint16_t i) { return (volatile uint32_t *)(r.desc.va + i * 16); }
    void rxArm(MtkRing &r);
    int txSend(MtkRing &r, const void *data, uint32_t len);
    const uint8_t *rxPoll(MtkRing &r, uint32_t *len);
    void rxRelease(MtkRing &r);
    void setupInterrupt();
    static void interruptHandler(OSObject *owner, void *ref, IOService *nub, int source);
    uint8_t nextSeq();
    int mcuCmd(uint8_t cid, const void *payload, uint32_t plen);
    int mcuWait(uint8_t cid, uint8_t seq);
    int sendScatter(const uint8_t *data, uint32_t len);
    int initDownload(uint32_t addr, uint32_t len, uint32_t mode);
    int patchSem(bool get);
    int loadPatch();
    int loadRam();

    // MtkScan.cpp: W4
    int uniCmd(uint8_t cid, const void *payload, uint32_t plen, bool query, uint8_t *ev, uint32_t evMax, uint32_t *evLen);
    void pollRx();
    void mtkParseFrame(const uint8_t *p, uint32_t len);
    int scanStage();
    void noteEvent(const uint8_t *p, uint32_t len);
    void macInitBand(int band);
    void dispatchRx(const uint8_t *p, uint32_t len);

    // MtkJoin.cpp: W5
    void noteTarget(const uint8_t *frame, uint32_t len, const char *ssid, uint8_t ch);
    void noteMgmt(const uint8_t *p, uint32_t len);
    void pump(uint32_t ms);
    bool txMgmt(const uint8_t *frame, uint32_t len, uint8_t subtype);
    bool xchg(const uint8_t *frame, uint32_t len, uint8_t subtype, uint8_t want, uint32_t *txOk);
    void parseAp();
    int bssInfo(bool enable);
    int edca();
    int staRec(uint8_t state, bool newly, uint16_t aid);
    int roc(bool acquire);
    void hwPrep();
    int joinStage();
    int authAssoc(bool first);

    // MtkNet.cpp: W6
    bool txSlotReady(bool force);
    void txQueue(uint32_t flen, uint8_t qIdx, uint8_t ftype, uint8_t stype, uint8_t rate, bool mcast, bool status);
    void txFree(const uint8_t *p, uint32_t len);
    void rxFrame(const uint8_t *p, uint32_t len);
    void deliver(const uint8_t *da, const uint8_t *sa, const uint8_t *typeAndPayload, uint32_t n);
    void linkLost();
    void reportLink();
    void keepalive();
    static void timerFired(OSObject *owner, IOTimerEventSource *sender);
    void tick();
    void publishW6();
    int netStage();
    void listInterrupts();
    void step(const char *state);
    void setNum(const char *key, uint64_t val, unsigned bits = 32);

    IOPCIDevice *pci = nullptr;
    IOMemoryMap *map = nullptr;
    volatile uint8_t *mmio = nullptr;
    uint32_t mmioLen = 0;
    uint32_t backupL1 = 0, backupL2 = 0;
    uint32_t badAccess = 0;

    IOMapper *mapper = nullptr;
    MtkRing txData, txMcu, txFwdl, rxMcu, rxData;
    int irqIndex = -1;
    volatile uint32_t irqCount = 0, irqLastStatus = 0;
    uint32_t rxEvents = 0, rxUnmatched = 0, fwBytes = 0;
    uint8_t mcuSeq = 0;

    uint8_t mac[6] = {};
    bool scanDone = false;
    uint32_t rxFrames = 0, rxBeacons = 0, rxOther = 0;
    MtkAp aps[64];
    int nAps = 0;
    volatile uint32_t irqStatusOr = 0;
    uint32_t evCount[256] = {};
    uint32_t evShort = 0, evDumps = 0;

    // W5 target BSS and join state
    char tgtSsid[33] = {};
    bool tgtFound = false;
    uint8_t tgtBssid[6] = {}, tgtCh = 0;
    uint16_t tgtBcnInt = 0, tgtCap = 0;
    uint8_t tgtIe[512];
    uint32_t tgtIeLen = 0;
    uint8_t apSupp = 0, apBasic = 0;
    uint8_t wantFc = 0;
    uint8_t mgmt[512];
    uint32_t mgmtLen = 0;
    volatile bool rocGrant = false;
    uint8_t rocStatus = 0xff, rocTok = 0;
    bool linkUp = false;
    bool joinedOnce = false;
    uint16_t aid = 0;

    // W6 network interface and data path
    IOWorkLoop *workLoop = nullptr;
    IOTimerEventSource *timer = nullptr;
    IOEthernetInterface *netif = nullptr;
    IONetworkMedium *medium = nullptr;
    bool ifEnabled = false, linkReported = false, rxQueued = false, txStalled = false;
    uint8_t dataRate = 22;                     // fixed-rate table index (22 = OFDM 24 Mb/s), MtkDataRate
    uint32_t rxCtrl = 0;                       // DMA ctrl word of the last rxPoll
    uint32_t ticks = 0, lastTxTick = 0, rejoinAt = 0;
    bool txBusy[256] = {};
    uint32_t txBusyAt[256] = {};
    uint32_t txPackets = 0, txStall = 0, txDrop = 0, txRingFull = 0, txFreeEvents = 0, txFreed = 0,
             txFreeBadVer = 0, txLostFree = 0, txFailed = 0;
    uint32_t rxPackets = 0, rxBad = 0, rxPartial = 0, rxTrans = 0, rxNonSnap = 0, rxProtected = 0,
             rxOwn = 0, rxDropped = 0;
    uint32_t deauths = 0, lastDeauth = 0, rejoins = 0, keepalives = 0;
    uint32_t rxTypes[32] = {};
};

#endif
