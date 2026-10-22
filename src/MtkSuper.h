// <wtl> project: mtkwlan | file: src/MtkSuper.h | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Link supervisor (I-096): decides once a second, from counters only, whether a link that stays associated still
// works. Plain C with no kernel calls so tests/mtk_super_test.c runs it on the host. The idea of a supervisor that
// resets the chip, reloads the firmware and rejoins comes from thanhnndev/ga403wm-hackintosh 5f00557 (Clear BSD,
// 2026 thanhnndev and contributors); this state machine is our own.

#ifndef MTK_SUPER_H
#define MTK_SUPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    MTK_SUPER_NONE = 0,
    MTK_SUPER_PROBE = 1,      // Rx silent: send one null frame with Tx status and look at the result next time
    MTK_SUPER_REJOIN = 2,     // the AP no longer acknowledges us: drop the link and rejoin (chip is fine)
    MTK_SUPER_RELOAD = 3,     // firmware or DMA stuck: reset the chip, reload the firmware, rejoin
};

#define MTK_SUPER_RELOAD_CAP 3            // reloads per window, then stop trying
#define MTK_SUPER_WINDOW_MS 600000u       // 10 minutes
#define MTK_SUPER_PROBE_WAIT_MS 2000u     // no Tx status at all in this time counts as stuck

struct mtk_super_in {
    uint32_t now_ms;
    int link;                 // associated and the port is open
    int fw_dead;              // the core gave up on the firmware (command timeouts)
    uint32_t rx_frames;       // any frame received from the air
    uint32_t tx_queued;       // frames handed to the Tx ring so far
    uint32_t tx_freed;        // tokens the firmware released so far
    uint32_t txs_records;     // Tx status records so far
    uint32_t txs_ack_err;     // of which failed (no ACK after every retry)
};

struct mtk_super {
    uint32_t stall_ms;        // 0 = supervisor off
    uint32_t rx_seen, rx_at, tx_seen, txq_seen, tx_at;
    int probing;
    uint32_t probe_at, probe_txs, probe_err;
    uint32_t reload_at[MTK_SUPER_RELOAD_CAP];
    uint32_t probes, idle_ok, rejoins, reloads, capped;
    int primed;
};

void mtk_super_init(struct mtk_super *s, uint32_t stall_ms);
// One decision; the caller does what it says. A RELOAD past the cap comes back as NONE and counts in s->capped.
int mtk_super_step(struct mtk_super *s, const struct mtk_super_in *in);
// After the caller acted (or the link changed by itself): start watching from scratch
void mtk_super_reset(struct mtk_super *s, const struct mtk_super_in *in);

// "0123...ef" (64 hex digits) -> 32 bytes; 0 on success, -1 on any other input
int mtk_hex_pmk(const char *hex, uint8_t pmk[32]);

#ifdef __cplusplus
}
#endif

#endif
