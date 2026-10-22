// <wtl> project: mtkwlan | file: src/MtkSuper.c | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// See MtkSuper.h.

#include "MtkSuper.h"

void mtk_super_init(struct mtk_super *s, uint32_t stall_ms) {
    struct mtk_super z = {0};
    *s = z;
    s->stall_ms = stall_ms;
}

void mtk_super_reset(struct mtk_super *s, const struct mtk_super_in *in) {
    s->rx_seen = in->rx_frames;
    s->rx_at = in->now_ms;
    s->tx_seen = in->tx_freed;
    s->txq_seen = in->tx_queued;
    s->tx_at = in->now_ms;
    s->probing = 0;
    s->primed = 1;
}

static int reload_allowed(struct mtk_super *s, uint32_t now) {
    int used = 0;
    for (int i = 0; i < MTK_SUPER_RELOAD_CAP; i++)
        if (s->reload_at[i] && now - s->reload_at[i] < MTK_SUPER_WINDOW_MS) used++;
    if (used >= MTK_SUPER_RELOAD_CAP) { s->capped++; return 0; }
    for (int i = 0; i < MTK_SUPER_RELOAD_CAP; i++)
        if (!s->reload_at[i] || now - s->reload_at[i] >= MTK_SUPER_WINDOW_MS) { s->reload_at[i] = now ? now : 1; break; }
    s->reloads++;
    return 1;
}

int mtk_super_step(struct mtk_super *s, const struct mtk_super_in *in) {
    if (!s->stall_ms) return MTK_SUPER_NONE;
    uint32_t now = in->now_ms;
    if (in->fw_dead) {
        if (!reload_allowed(s, now)) return MTK_SUPER_NONE;
        mtk_super_reset(s, in);
        return MTK_SUPER_RELOAD;
    }
    if (!in->link || !s->primed) {
        mtk_super_reset(s, in);
        return MTK_SUPER_NONE;
    }
    if (in->rx_frames != s->rx_seen) {
        s->rx_seen = in->rx_frames;
        s->rx_at = now;
        s->probing = 0;
    }
    // frames went out and no token came back: the firmware or the DMA stopped, whatever the air does
    if (in->tx_freed != s->tx_seen || in->tx_queued == s->txq_seen) {
        s->tx_seen = in->tx_freed;
        s->txq_seen = in->tx_queued;
        s->tx_at = now;
    }
    if (now - s->tx_at >= s->stall_ms) {
        if (!reload_allowed(s, now)) { mtk_super_reset(s, in); return MTK_SUPER_NONE; }
        mtk_super_reset(s, in);
        return MTK_SUPER_RELOAD;
    }
    if (s->probing) {
        uint32_t recs = in->txs_records - s->probe_txs, errs = in->txs_ack_err - s->probe_err;
        if (recs) {
            s->probing = 0;
            if (errs >= recs) {           // every frame since the probe went unacknowledged
                s->rejoins++;
                mtk_super_reset(s, in);
                return MTK_SUPER_REJOIN;
            }
            s->idle_ok++;                 // the AP answered: a quiet link, not a dead one
            s->rx_at = now;
            return MTK_SUPER_NONE;
        }
        if (now - s->probe_at < MTK_SUPER_PROBE_WAIT_MS) return MTK_SUPER_NONE;
        s->probing = 0;                   // the probe frame never got a status back
        if (!reload_allowed(s, now)) { mtk_super_reset(s, in); return MTK_SUPER_NONE; }
        mtk_super_reset(s, in);
        return MTK_SUPER_RELOAD;
    }
    if (now - s->rx_at >= s->stall_ms) {
        s->probing = 1;
        s->probe_at = now;
        s->probe_txs = in->txs_records;
        s->probe_err = in->txs_ack_err;
        s->probes++;
        return MTK_SUPER_PROBE;
    }
    return MTK_SUPER_NONE;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int mtk_hex_pmk(const char *hex, uint8_t pmk[32]) {
    if (!hex) return -1;
    uint8_t tmp[32];
    for (int i = 0; i < 32; i++) {
        int hi = hexval(hex[2 * i]);
        if (hi < 0) return -1;
        int lo = hexval(hex[2 * i + 1]);
        if (lo < 0) return -1;
        tmp[i] = (uint8_t)(hi << 4 | lo);
    }
    if (hex[64]) return -1;
    for (int i = 0; i < 32; i++) pmk[i] = tmp[i];
    return 0;
}
