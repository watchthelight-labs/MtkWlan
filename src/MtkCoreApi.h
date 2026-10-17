// <wtl> project: mtkwlan | file: src/MtkCoreApi.h | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// The C interface between the MtkWlan core (IOService on the MT7925 PCI device) and a front end
// (MtkWlanEth here; later MtkWlanNative, a separate kext). Plain C on purpose: a front end in another
// kext gets this table through callPlatformFunction and needs no C++ library link to MtkWlan.
//
//   const struct mtk_core_ops *ops; void *core;
//   core_provider->callPlatformFunction(MTK_CORE_OPS_V1, false, &ops, &core, NULL, NULL);
//   then check ops->version == MTK_CORE_API_V1 and ops->size >= the size you were built with.
// Version 2 (0.9.0, W1) is a superset: MTK_CORE_OPS_V2 returns a struct mtk_core_ops_v2 whose first member is
// the v1 table (with version 2 in it), plus scan / results / join / disconnect / status, and accepts
// struct mtk_fe_callbacks_v2 (v1 callbacks + scan_done + join_result). A v1 front end (MtkWlanEth) keeps
// asking for MTK_CORE_OPS_V1 and gets exactly the v1 table it was built for.
//
// Threading (W0): the core runs one IOWorkLoop (its getWorkLoop()). The 1 ms tick, RX, block ack and
// rejoin all run on it, so every callback below is called with that work loop's gate held. A front end
// must make its own TX and enable/disable paths run on the same gate (MtkWlanEth returns the core's
// loop from getWorkLoop(), so IOGatedOutputQueue and the IONetworkController command gate share it).
// Callbacks must not sleep and must not call back into tx or set_enabled.

#ifndef MTK_CORE_API_H
#define MTK_CORE_API_H

#include <stdint.h>
#include <sys/kernel_types.h>   // mbuf_t
#include "MtkUserApi.h"          // mtk_scan_result, mtk_join_params, mtk_status

#ifdef __cplusplus
extern "C" {
#endif

#define MTK_CORE_OPS_V1      "mtk-core-ops-v1"
#define MTK_CORE_OPS_V2      "mtk-core-ops-v2"
#define MTK_CORE_API_V1      1
#define MTK_CORE_API_V2      2
#define MTK_CORE_API_VERSION MTK_CORE_API_V1   // what a v1 front end (MtkWlanEth) is built against

// tx results: on OK and DROPPED the caller frees the mbuf; on STALL it keeps it and retries after tx_space
enum { MTK_TX_OK = 0, MTK_TX_DROPPED = 1, MTK_TX_STALL = 2 };

// What the front end gives the core (copied by set_callbacks). All called on the core work loop gate.
struct mtk_fe_callbacks {
    uint32_t version;                                   // MTK_CORE_API_V1, or V2 for mtk_fe_callbacks_v2
    uint32_t size;                                      // sizeof the struct passed
    void *ctx;                                          // passed back as the first argument
    mbuf_t (*rx_alloc)(void *ctx, uint32_t len);        // a packet of len bytes for one received Ethernet frame
    void (*rx)(void *ctx, mbuf_t m);                    // one Ethernet frame (DA, SA, type, payload); front end owns m
    void (*rx_flush)(void *ctx);                        // end of an RX batch (once per tick at most)
    void (*link)(void *ctx, int up, uint64_t speed);    // reported link changed (associated and enabled)
    void (*tx_space)(void *ctx);                        // a stalled tx can be retried
};

// A snapshot of the association (racy unless read on the gate)
struct mtk_link_info {
    uint32_t up;                // associated
    uint32_t enabled;           // front end enabled (set_enabled)
    uint8_t bssid[6];
    uint8_t channel;            // primary channel
    uint8_t bw;                 // 0 = 20, 1 = 40, 2 = 80 MHz
    uint8_t center;             // center channel
    uint8_t nss;                // spatial streams in use
    uint8_t ht, vht;            // HT / VHT association
    uint16_t aid;
    char ssid[33];
    uint64_t speed;             // what the core reports to the front end, bits/s
};

// What the core offers. `core` is the opaque handle returned next to the table.
struct mtk_core_ops {
    uint32_t version;           // MTK_CORE_API_V1 (from MTK_CORE_OPS_V1) or V2 (first member of mtk_core_ops_v2)
    uint32_t size;              // sizeof(struct mtk_core_ops) or sizeof(struct mtk_core_ops_v2)
    // Register (cb != NULL) or remove (cb == NULL) the front end; takes the gate itself, so call it from a
    // thread that does not hold it (start / stop). Returns 0, or -1 when another front end is registered
    // or the versions do not match.
    int (*set_callbacks)(void *core, const struct mtk_fe_callbacks *cb);
    // One Ethernet frame (14-byte header + payload, up to 1514 bytes). Gate held. Returns MTK_TX_*.
    int (*tx)(void *core, mbuf_t m);
    // The front end's interface was enabled / disabled (frames reach it and the link is reported only when
    // enabled). Gate held.
    void (*set_enabled)(void *core, int enabled);
    // The station MAC from NIC capability (fixed after bring-up, any thread). 0 on success.
    int (*get_mac)(void *core, uint8_t mac[6]);
    // Fill *out (any thread, racy off the gate). 0 on success.
    int (*get_link_info)(void *core, struct mtk_link_info *out);
};

// v2 callbacks (W1). Gate held, must not sleep; they may not call scan / join / disconnect back.
struct mtk_fe_callbacks_v2 {
    struct mtk_fe_callbacks v1;                         // v1.version = MTK_CORE_API_V2, v1.size = sizeof(this)
    void (*scan_done)(void *ctx, int status, uint32_t count);           // status 0, or -1 (timed out)
    void (*join_result)(void *ctx, int result, const uint8_t bssid[6]); // MTK_JOIN_* (OK = port open)
};

// v2 table. All of the new calls run with the core work loop gate held (a front end on the shared loop is
// already there; others use runAction). Return 0 on success, -1 bad argument, -2 busy / not ready.
struct mtk_core_ops_v2 {
    struct mtk_core_ops v1;
    // start a scan of every channel in the domain (results go to the BSS cache, scan_done when finished)
    int (*scan)(void *core);
    // copy up to max cache entries, best first; *count = how many were written
    int (*get_scan_results)(void *core, struct mtk_scan_result *out, uint32_t max, uint32_t *count);
    // join a network: open (MTK_KEY_NONE) or WPA2-PSK with a PMK. Replaces any current association and
    // stays the wanted network (rejoined after a loss) until disconnect. Result through join_result / status.
    int (*join)(void *core, const struct mtk_join_params *p);
    // leave the network and forget the wanted one; the open-network auto-join stays off until the next join
    int (*disconnect)(void *core);
    int (*get_status)(void *core, struct mtk_status *out);
};

#ifdef __cplusplus
}
#endif

#endif
