// <wtl> project: mtkwlan | file: src/MtkBa.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// W9: block ack (A-MPDU) in both directions.
// RX: the AP's ADDBA request is accepted, the firmware gets a recipient STA_REC_BA and the driver
//   reorders by sequence number, a port of mt76 agg-rx.c (mt76_rx_aggr_reorder, _release_head,
//   _check_release with the HZ/10 timeout, BlockAckReq handling; Copyright (C) 2018 Felix Fietkau, ISC).
// TX: once data flows, the driver sends an ADDBA request for TID 0; on success the firmware gets an
//   originator STA_REC_BA and builds A-MPDUs itself (mt7925_ampdu_action, mt7925_mcu_sta_ba in
//   Linux mt76 v6.18; Copyright (C) 2023 MediaTek Inc., ISC). Frame layouts per IEEE 802.11-2020 9.6.5.
// Info.plist MtkRxBa / MtkTxBa switch either side off (then ADDBA requests are declined as in 0.6.x).
// 0.8.0: buffered frames are mbufs from the front end's rx_alloc; dropped ones go back with mbuf_freem.
// 0.9.0: each buffered frame carries its CCMP PN and replay-counter slot; the check runs when the frame leaves the
// buffer in order (inputChecked), as mt76 runs mt76_check_ccmp_pn after the reorder.

#include "MtkWlan.hpp"

namespace {
constexpr uint16_t SN_MASK = 0xfff;
inline bool snLess(uint16_t a, uint16_t b) { return ((a - b) & SN_MASK) > 0x800; }   // ieee80211_sn_less
inline uint16_t snInc(uint16_t a) { return (a + 1) & SN_MASK; }
inline uint16_t snSub(uint16_t a, uint16_t b) { return (a - b) & SN_MASK; }
inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
constexpr uint32_t REORDER_TIMEOUT_TICKS = 100;   // HZ / 10 for TIDs 0-3 (agg-rx.c)
} // namespace

// ---------------------------------------------------------------- frames

// RX path: copy the action frame and leave the firmware work to tick() (uniCmd drains the MCU ring
// that the RX path is reading, so it must not run from there)
void MtkWlan::baQueue(const uint8_t *f, uint32_t flen) {
    uint8_t next = (uint8_t)((baQHead + 1) % 8);
    if (next == baQTail) { baQDropped++; return; }
    BaEvt &e = baQ[baQHead];
    e.len = flen < sizeof(e.f) ? flen : (uint32_t)sizeof(e.f);
    memcpy(e.f, f, e.len);
    baQHead = next;
}

void MtkWlan::baService() {
    while (baQTail != baQHead) {
        BaEvt &e = baQ[baQTail];
        baQTail = (uint8_t)((baQTail + 1) % 8);
        baAction(e.f, e.len);
    }
}

void MtkWlan::baActionHeader(uint8_t *r, uint8_t action) {
    bzero(r, 24);
    r[0] = 0xd0;                                // action
    memcpy(r + 4, tgtBssid, 6);
    memcpy(r + 10, mac, 6);
    memcpy(r + 16, tgtBssid, 6);
    r[24] = 3;                                  // category: block ack
    r[25] = action;
}

// Block-ack action frame from the AP (f = 802.11 header, body at 24)
void MtkWlan::baAction(const uint8_t *f, uint32_t flen) {
    uint8_t action = f[25];
    if (action == 0 && flen >= 33) {                         // ADDBA request: the AP wants to aggregate to us
        uint8_t dialog = f[26];
        uint16_t param = le16(f + 27), timeout = le16(f + 29), ssn = le16(f + 31) >> 4;
        uint8_t tid = (param >> 2) & 0xf;
        uint16_t win = param >> 6;
        if (!win || win > MTK_BA_WIN) win = MTK_BA_WIN;
        while (win & (win - 1)) win &= (uint16_t)(win - 1);   // power of two: seqno % size stays continuous at 4095 -> 0
        if (!rxBaOn || tid >= 8 || !(param & 0x2)) { addbaDecline(f, flen); return; }   // immediate policy only
        rxBaStart(tid, ssn, win);
        int rc = staBa(tid, ssn, win, false, true);
        baLastRc = (uint32_t)rc;
        uint8_t r[24 + 9];
        baActionHeader(r, 1);                                // ADDBA response
        r[26] = dialog;
        put16(r + 27, rc ? 37 : 0);                          // success, or declined if the firmware refused
        put16(r + 29, (uint16_t)((param & 0x2) | (tid << 2) | (win << 6)));   // no A-MSDU, policy as asked
        put16(r + 31, timeout);
        if (rc) rxBaStop(tid);
        txMgmt(r, sizeof(r), 13);
        if (!rc) baRxSessions++;
        else addbaDeclined++;
    } else if (action == 1 && flen >= 33) {                  // ADDBA response to our request
        uint16_t status = le16(f + 27), param = le16(f + 29);
        baTxStatus = status;
        if (txBaState != 1 || f[26] != txBaDialog) return;
        if (status) { txBaState = 3; return; }               // refused: do not ask again
        uint16_t win = param >> 6;
        if (!win || win > MTK_BA_WIN) win = MTK_BA_WIN;
        int rc = staBa(0, txBaSsn, win, true, true);
        baLastRc = (uint32_t)rc;
        txBaState = rc ? 3 : 2;
        if (!rc) { txBaWin = win; baTxSessions++; }
    } else if (action == 2 && flen >= 28) {                  // DELBA
        uint16_t param = le16(f + 26);
        uint8_t tid = (param >> 12) & 0xf;
        bool apWasOriginator = param & (1u << 11);
        delbaRx++;
        if (apWasOriginator && tid < 8) {
            rxBaStop(tid);
            staBa(tid, 0, 0, false, false);
        } else if (!apWasOriginator && tid == 0) {
            staBa(0, 0, 0, true, false);
            txBaState = 0;
            txBaNextTick = ticks + 10000;
        }
    }
}

// Ask the AP for a TX block-ack session on TID 0 (called from tick once data flows)
void MtkWlan::txBaRequest() {
    uint8_t r[24 + 9];
    baActionHeader(r, 0);
    txBaDialog = (uint8_t)(txBaDialog + 1);
    if (!txBaDialog) txBaDialog = 1;
    r[26] = txBaDialog;
    put16(r + 27, (uint16_t)(0x2 | (0 << 2) | (MTK_BA_WIN << 6)));     // immediate policy, TID 0, no A-MSDU
    put16(r + 29, 0);                                                  // no timeout
    // the hardware numbers our frames; start the window at the last sequence number a TX status reported
    txBaSsn = txsLast[1] ? (uint16_t)(((txsLast[1] >> 20) + 1) & SN_MASK) : 0;
    put16(r + 31, (uint16_t)(txBaSsn << 4));
    txMgmt(r, sizeof(r), 13, 1, 2);             // AC_BE queue, TXD TID = MT_TX_ADDBA (mt7925_mac_write_txwi_80211)
    txBaState = 1;
    txBaRequests++;
    txBaNextTick = ticks + 2000;                                       // no answer in 2 s: ask again
}

// ---------------------------------------------------------------- RX reorder (mt76 agg-rx.c)

void MtkWlan::rxBaStart(uint8_t tid, uint16_t ssn, uint16_t size) {
    rxBaStop(tid);
    MtkRxTid &t = rxTid[tid];
    t.head = ssn;
    t.size = size;
    t.started = false;
    t.nframes = 0;
    t.active = true;
}

void MtkWlan::rxBaStop(uint8_t tid) {
    MtkRxTid &t = rxTid[tid];
    for (int i = 0; i < MTK_BA_WIN; i++)
        if (t.buf[i]) { mbuf_freem(t.buf[i]); t.buf[i] = nullptr; }
    t.nframes = 0;
    t.active = false;
}

void MtkWlan::rxBaReleaseSlot(MtkRxTid &t, int idx) {
    t.head = snInc(t.head);
    mbuf_t m = t.buf[idx];
    if (!m) return;
    t.buf[idx] = nullptr;
    t.nframes--;
    inputChecked(m, t.pnSlot[idx], t.pn[idx]);
}

void MtkWlan::rxBaReleaseFrames(MtkRxTid &t, uint16_t head) {
    while (snLess(t.head, head)) rxBaReleaseSlot(t, t.head % t.size);
}

void MtkWlan::rxBaReleaseHead(MtkRxTid &t) {
    int idx = t.head % t.size;
    while (t.buf[idx]) {
        rxBaReleaseSlot(t, idx);
        idx = t.head % t.size;
    }
}

// mt76_rx_aggr_reorder: in order -> stack now, early -> buffered, old/duplicate -> dropped
void MtkWlan::rxBaReorder(uint8_t tid, uint16_t seqno, mbuf_t m, int pnSlot, uint64_t pn) {
    MtkRxTid &t = rxTid[tid];
    uint16_t head = t.head, size = t.size;
    bool snl = snLess(seqno, head);
    if (!t.started) {
        if (snl) { inputChecked(m, pnSlot, pn); return; }
        t.started = true;
    }
    if (snl) { mbuf_freem(m); baDup++; return; }
    if (seqno == head) {
        t.head = snInc(head);
        inputChecked(m, pnSlot, pn);
        if (t.nframes) rxBaReleaseHead(t);
        return;
    }
    if (!snLess(seqno, (uint16_t)((head + size) & SN_MASK))) {        // beyond the window: slide it
        head = snInc(snSub(seqno, size));
        rxBaReleaseFrames(t, head);
    }
    int idx = seqno % size;
    if (t.buf[idx]) { mbuf_freem(m); baDup++; return; }
    t.buf[idx] = m;
    t.at[idx] = ticks;
    t.seq[idx] = seqno;
    t.pn[idx] = pn;
    t.pnSlot[idx] = (int8_t)pnSlot;
    t.nframes++;
    baBuffered++;
    rxBaReleaseHead(t);
}

// mt76_rx_aggr_check_release: frames waiting longer than the timeout push the head past the hole
void MtkWlan::rxBaTimeouts() {
    for (int tid = 0; tid < 8; tid++) {
        MtkRxTid &t = rxTid[tid];
        if (!t.active || !t.nframes) continue;
        rxBaReleaseHead(t);
        int start = t.head % t.size;
        int left = t.nframes;
        for (int idx = (t.head + 1) % t.size; idx != start && left; idx = (idx + 1) % t.size) {
            if (!t.buf[idx]) continue;
            left--;
            if (ticks - t.at[idx] < REORDER_TIMEOUT_TICKS) continue;
            baTimeoutRelease++;
            rxBaReleaseFrames(t, t.seq[idx]);
        }
        rxBaReleaseHead(t);
    }
}

// BlockAckReq from the AP: release everything before its starting sequence number
void MtkWlan::rxBar(const uint8_t *f, uint32_t flen) {
    if (flen < 20) return;
    barRx++;
    uint16_t ctl = le16(f + 16), ssn = le16(f + 18) >> 4;
    uint8_t tid = ctl >> 12;
    if (tid >= 8 || !rxTid[tid].active) return;
    rxBaReleaseFrames(rxTid[tid], ssn);
    rxBaReleaseHead(rxTid[tid]);
}
