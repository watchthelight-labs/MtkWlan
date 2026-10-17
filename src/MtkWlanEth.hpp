// <wtl> project: mtkwlan | file: src/MtkWlanEth.hpp | author: watchthelight </wtl>
// MtkWlanEth: the Ethernet front end (en1) of the MtkWlan core, moved out of MtkWlan in 0.8.0 (W0).
// The core creates it as its child and starts it once the join passed. It talks to the core only through
// the C ops table in MtkCoreApi.h (as the later MtkWlanNative kext will), and shares the core's work
// loop, so TX, enable/disable and the core's 1 ms tick are serialised by one gate as before.

#ifndef MTKWLANETH_HPP
#define MTKWLANETH_HPP

#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkMedium.h>
#include <sys/kpi_mbuf.h>
#include "MtkCoreApi.h"

class MtkWlanEth : public IOEthernetController {
    OSDeclareDefaultStructors(MtkWlanEth)

public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;

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

private:
    // mtk_fe_callbacks, called by the core with its work loop gate held
    static mbuf_t cbRxAlloc(void *ctx, uint32_t len);
    static void cbRx(void *ctx, mbuf_t m);
    static void cbRxFlush(void *ctx);
    static void cbLink(void *ctx, int up, uint64_t speed);
    static void cbTxSpace(void *ctx);

    const mtk_core_ops *ops = nullptr;
    void *core = nullptr;
    bool registered = false;                   // callbacks are set in the core
    IOWorkLoop *workLoop = nullptr;            // the core's, retained
    IOEthernetInterface *netif = nullptr;
    IONetworkMedium *medium = nullptr;
};

#endif
