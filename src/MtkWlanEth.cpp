// <wtl> project: mtkwlan | file: src/MtkWlanEth.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Ethernet front end (IOEthernetController, en1) over the MtkWlan core. The IONetworkController half of
// the 0.7.0 MtkNet.cpp, moved here unchanged in behaviour: output queue of 64 on the core's work loop,
// medium "auto" at 54 Mb/s, link Valid|Active while associated and enabled. The 802.11 framing, rings
// and counters stay in the core (MtkNet.cpp), reached through MtkCoreApi.h.
// 0.9.0: the front end starts before any association, so the link is published as valid and inactive at once
// (configd sees "no carrier" instead of an unknown link and does not start DHCP on a dead interface).

#include "MtkWlanEth.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/network/IOGatedOutputQueue.h>

OSDefineMetaClassAndStructors(MtkWlanEth, IOEthernetController)

namespace {
constexpr uint32_t TXQ_CAPACITY = 64;
} // namespace

bool MtkWlanEth::start(IOService *provider) {
    // the ops table and the work loop come from the core before IONetworkController::start asks for them
    if (!provider || provider->callPlatformFunction(MTK_CORE_OPS_V1, false, (void *)&ops, &core, nullptr, nullptr) !=
                         kIOReturnSuccess || !ops || !core) {
        IOLog("MtkWlanEth: no core ops table\n");
        return false;
    }
    if (ops->version != MTK_CORE_API_VERSION || ops->size < sizeof(mtk_core_ops)) {
        IOLog("MtkWlanEth: core ops version %u size %u not supported\n", ops->version, ops->size);
        return false;
    }
    workLoop = provider->getWorkLoop();
    if (!workLoop) { IOLog("MtkWlanEth: core has no work loop\n"); return false; }
    workLoop->retain();
    if (!IOEthernetController::start(provider))
        return false;

    OSDictionary *md = OSDictionary::withCapacity(1);
    medium = IONetworkMedium::medium(kIOMediumEthernetAuto, 54000000ULL);
    if (!md || !medium || !IONetworkMedium::addMedium(md, medium) || !publishMediumDictionary(md)) {
        OSSafeReleaseNULL(md);
        IOLog("MtkWlanEth: medium dictionary\n");
        return false;
    }
    md->release();
    setLinkStatus(kIONetworkLinkValid, nullptr, 0);     // known, and down, until the core joins a network

    // registered before the interface exists, as the medium was in 0.7.0: enable() can report the link at once
    mtk_fe_callbacks cb = {};
    cb.version = MTK_CORE_API_VERSION;
    cb.size = sizeof(cb);
    cb.ctx = this;
    cb.rx_alloc = &MtkWlanEth::cbRxAlloc;
    cb.rx = &MtkWlanEth::cbRx;
    cb.rx_flush = &MtkWlanEth::cbRxFlush;
    cb.link = &MtkWlanEth::cbLink;
    cb.tx_space = &MtkWlanEth::cbTxSpace;
    if (ops->set_callbacks(core, &cb)) { IOLog("MtkWlanEth: core refused the callbacks\n"); return false; }
    registered = true;

    if (!attachInterface((IONetworkInterface **)&netif, false)) {
        ops->set_callbacks(core, nullptr);
        registered = false;
        IOLog("MtkWlanEth: attachInterface\n");
        return false;
    }
    netif->registerService();
    setProperty("MtkFrontEnd", "ethernet");
    registerService();
    return true;
}

void MtkWlanEth::stop(IOService *provider) {
    // gated in the core: after this the tick no longer calls into this object
    if (registered) {
        ops->set_callbacks(core, nullptr);
        registered = false;
    }
    if (netif) {
        detachInterface(netif);
        OSSafeReleaseNULL(netif);
    }
    IOEthernetController::stop(provider);
}

void MtkWlanEth::free() {
    OSSafeReleaseNULL(medium);
    // IONetworkController::free may still ask getWorkLoop(), so the reference goes after it
    IOWorkLoop *wl = workLoop;
    IOEthernetController::free();
    if (wl) wl->release();
}

// ---------------------------------------------------------------- core callbacks (gate held)

mbuf_t MtkWlanEth::cbRxAlloc(void *ctx, uint32_t len) {
    return static_cast<MtkWlanEth *>(ctx)->allocatePacket(len);
}

void MtkWlanEth::cbRx(void *ctx, mbuf_t m) {
    MtkWlanEth *self = static_cast<MtkWlanEth *>(ctx);
    if (!self->netif) { self->freePacket(m); return; }
    self->netif->inputPacket(m, (UInt32)mbuf_pkthdr_len(m), IONetworkInterface::kInputOptionQueuePacket);
}

void MtkWlanEth::cbRxFlush(void *ctx) {
    MtkWlanEth *self = static_cast<MtkWlanEth *>(ctx);
    if (self->netif) self->netif->flushInputQueue();
}

void MtkWlanEth::cbLink(void *ctx, int up, uint64_t speed) {
    MtkWlanEth *self = static_cast<MtkWlanEth *>(ctx);
    self->setLinkStatus(up ? (kIONetworkLinkValid | kIONetworkLinkActive) : kIONetworkLinkValid,
                        up ? self->medium : nullptr, speed);
}

void MtkWlanEth::cbTxSpace(void *ctx) {
    if (IOOutputQueue *q = static_cast<MtkWlanEth *>(ctx)->getOutputQueue())
        q->service(IOBasicOutputQueue::kServiceAsync);
}

// ---------------------------------------------------------------- IOEthernetController

bool MtkWlanEth::createWorkLoop() {
    return workLoop != nullptr;
}

IOWorkLoop *MtkWlanEth::getWorkLoop() const {
    return workLoop;
}

IOOutputQueue *MtkWlanEth::createOutputQueue() {
    return IOGatedOutputQueue::withTarget(this, getWorkLoop(), TXQ_CAPACITY);
}

IOReturn MtkWlanEth::getHardwareAddress(IOEthernetAddress *addr) {
    if (!ops) return kIOReturnNotReady;
    return ops->get_mac(core, addr->bytes) ? kIOReturnError : kIOReturnSuccess;
}

IOReturn MtkWlanEth::enable(IONetworkInterface *) {
    if (IOOutputQueue *q = getOutputQueue()) {
        q->setCapacity(TXQ_CAPACITY);
        q->start();
    }
    ops->set_enabled(core, 1);                 // reports the link if the port is open
    return kIOReturnSuccess;
}

IOReturn MtkWlanEth::disable(IONetworkInterface *) {
    if (IOOutputQueue *q = getOutputQueue()) {
        q->stop();
        q->setCapacity(0);
        q->flush();
    }
    ops->set_enabled(core, 0);
    return kIOReturnSuccess;
}

IOReturn MtkWlanEth::setPromiscuousMode(bool) { return kIOReturnSuccess; }
IOReturn MtkWlanEth::setMulticastMode(bool) { return kIOReturnSuccess; }
IOReturn MtkWlanEth::setMulticastList(IOEthernetAddress *, UInt32) { return kIOReturnSuccess; }
const OSString *MtkWlanEth::newVendorString() const { return OSString::withCString("MediaTek"); }
const OSString *MtkWlanEth::newModelString() const { return OSString::withCString("MT7925 (MtkWlan)"); }

// Runs on the core's gate (IOGatedOutputQueue on the shared work loop)
UInt32 MtkWlanEth::outputPacket(mbuf_t m, void *) {
    int r = ops->tx(core, m);
    if (r == MTK_TX_STALL) return kIOReturnOutputStall;
    freePacket(m);
    return r == MTK_TX_OK ? kIOReturnOutputSuccess : kIOReturnOutputDropped;
}
