// <wtl> project: mtkwlan | file: src/MtkJoin.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// W5: join an open network (open-system authentication + association, no RSN).
// The command sequence and the BSS_INFO / STA_REC / ROC / EDCA layouts follow itlmt7925
// (github.com/thanhnndev/ga403wm-hackintosh, kexts/itlmt7925/itlmt7925_m3.cpp: m3Run1, m3Bss, m3Edca, m3Sta,
// m3Roc, m3Tx, m3Auth, m3Assoc, m3ParseAp, m3HwPrep; Copyright (c) 2026 thanhnndev and contributors,
// BSD-3-Clause-Clear), its legacy 20 MHz path, adapted to an open network (capability without Privacy,
// no RSN element, BSS security "open"). Tag values were checked against Linux mt76 v6.18
// (mt76_connac_mcu.h: UNI_BSS_INFO_*, STA_REC_*, MCU_UNI_CMD_EDCA_UPDATE; Copyright (C) MediaTek Inc., ISC).

#include "MtkWlan.hpp"

namespace {
constexpr uint8_t UNI_BSS_INFO_UPDATE = 0x02, UNI_STA_REC_UPDATE = 0x03, UNI_EDCA_UPDATE = 0x04, UNI_ROC = 0x27;
constexpr uint16_t BSS_IDX = 0, AP_WCID = 1, BMC_WCID = 19;   // BMC = MT792x_WTBL_RESERVED - bss idx
constexpr uint8_t RATE_IDX_OFDM6 = 18;                        // fixed-rate table: 14 + 4 (OFDM 6 Mb/s)
constexpr uint32_t WTBL_UPDATE = 0x820d4380, WTBL_ITCR = 0x820d43b0, WTBL_ITDR0 = 0x820d43b8, WTBL_ITDR1 = 0x820d43bc;

inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

// MCU message: fixed header (4 bytes for BSS_INFO, 8 for STA_REC, tlv count at offset 2) + TLVs
struct Msg {
    uint8_t b[512];
    uint16_t n;
    void init(uint16_t hdr) { bzero(b, sizeof(b)); n = hdr; }
    uint8_t *tlv(uint16_t tag, uint16_t len) {
        uint8_t *p = b + n;
        put16(p, tag);
        put16(p + 2, len);
        n += len;
        put16(b + 2, (uint16_t)(le16(b + 2) + 1));
        return p;
    }
};
} // namespace

// Called by the beacon locator for every beacon / probe response: remember the target BSS (prefer 5 GHz)
void MtkWlan::noteTarget(const uint8_t *frame, uint32_t len, const char *ssid, uint8_t ch) {
    if (!tgtSsid[0] || len < 36 || strcmp(ssid, tgtSsid) != 0) return;
    if (tgtFound && !(ch > 14 && tgtCh <= 14)) return;
    tgtFound = true;
    memcpy(tgtBssid, frame + 16, 6);
    tgtCh = ch;
    tgtBcnInt = le16(frame + 32);
    tgtCap = le16(frame + 34);
    tgtIeLen = len - 36 > sizeof(tgtIe) ? (uint32_t)sizeof(tgtIe) : len - 36;
    memcpy(tgtIe, frame + 36, tgtIeLen);
}

// While waiting for an auth / assoc response: a management frame from the AP to us with fc byte 0 == wantFc
void MtkWlan::noteMgmt(const uint8_t *p, uint32_t len) {
    if (!wantFc || mgmtLen || len < 32 + 24) return;
    for (uint32_t off = 32; off + 24 <= len && off < 224; off++) {
        if (p[off] != wantFc) continue;
        if (memcmp(p + off + 4, mac, 6) != 0 || memcmp(p + off + 10, tgtBssid, 6) != 0) continue;
        uint32_t n = len - off;
        if (n > sizeof(mgmt)) n = sizeof(mgmt);
        memcpy(mgmt, p + off, n);
        mgmtLen = n;
        return;
    }
}

// Poll both RX rings for `ms` milliseconds (frames -> beacon locator / mgmt matcher, events -> noteEvent)
void MtkWlan::pump(uint32_t ms) {
    for (uint32_t i = 0; i < ms; i++) {
        pollRx();
        uint32_t len = 0;
        const uint8_t *p;
        while ((p = rxPoll(rxMcu, &len))) {
            dispatchRx(p, len);
            rxRelease(rxMcu);
        }
        IOSleep(1);
    }
}

// Send a frame (up to 4 times, 150 ms apart) until a frame with fc byte 0 == want comes back
bool MtkWlan::xchg(const uint8_t *frame, uint32_t len, uint8_t subtype, uint8_t want, uint32_t *txOk) {
    mgmtLen = 0;
    wantFc = want;
    for (int attempt = 0; attempt < 4 && !mgmtLen; attempt++) {
        if (txMgmt(frame, len, subtype)) (*txOk)++;
        pump(150);
    }
    wantFc = 0;
    return mgmtLen != 0;
}

void MtkWlan::parseAp() {
    static const uint8_t r5g[8] = {12, 18, 24, 36, 48, 72, 96, 108};   // 500 kb/s units, mac80211 5 GHz indices
    apSupp = apBasic = 0;
    for (const uint8_t *ie = tgtIe, *end = tgtIe + tgtIeLen; ie + 2 <= end && ie + 2 + ie[1] <= end; ie += 2 + ie[1]) {
        if (ie[0] != 1 && ie[0] != 50) continue;
        for (int i = 0; i < ie[1]; i++)
            for (int k = 0; k < 8; k++)
                if ((ie[2 + i] & 0x7f) == r5g[k]) {
                    apSupp |= (uint8_t)(1u << k);
                    if (ie[2 + i] & 0x80) apBasic |= (uint8_t)(1u << k);
                }
    }
}

int MtkWlan::bssInfo(bool enable) {
    Msg m;
    m.init(4);
    m.b[0] = BSS_IDX;
    uint8_t *b = m.tlv(0, 32);                  // UNI_BSS_INFO_BASIC
    b[4] = 1;                                   // active
    b[7] = 0xff;                                // band_idx
    put32(b + 8, 0x10001);                      // CONNECTION_INFRA_STA
    b[12] = enable ? 0 : 1;                     // conn_state
    memcpy(b + 14, tgtBssid, 6);
    put16(b + 20, BMC_WCID);
    put16(b + 22, tgtBcnInt ? tgtBcnInt : 100);
    b[24] = 1;                                  // dtim_period
    b[25] = tgtCh > 14 ? 0x01 : (0x02 | 0x04);  // phymode: A (5 GHz) / B|G
    put16(b + 26, AP_WCID);
    put16(b + 28, tgtCh > 14 ? 3 : 1);          // nonht_basic_phy: OFDM / ERP
    uint8_t *s = m.tlv(16, 8);                  // UNI_BSS_INFO_SEC: open
    s[4] = 0; s[5] = 1; s[6] = 0;
    uint8_t *r = m.tlv(11, 16);                 // UNI_BSS_INFO_RATE
    put16(r + 6, (1 << 6) | (1 << 8) | (1 << 10));   // OFDM basic rates 6/12/24
    r[13] = RATE_IDX_OFDM6;                     // bc_fixed_rate
    r[14] = RATE_IDX_OFDM6;                     // mc_fixed_rate
    uint8_t *q = m.tlv(15, 8);                  // UNI_BSS_INFO_QBSS
    q[4] = 1;
    uint8_t *ml = m.tlv(26, 20);                // UNI_BSS_INFO_MLD
    ml[4] = 0xff;
    ml[5] = BSS_IDX + 32;
    memcpy(ml + 6, mac, 6);
    ml[12] = 0xff;
    ml[13] = 0xff;
    uint8_t *f = m.tlv(23, 20);                 // UNI_BSS_INFO_IFS_TIME
    f[4] = 1;
    put16(f + 8, 9);
    if (enable) {
        uint8_t *rl = m.tlv(2, 16);             // UNI_BSS_INFO_RLM: 20 MHz on the AP's channel
        rl[4] = tgtCh;
        rl[5] = tgtCh;
        rl[8] = 1; rl[9] = 1;
        rl[12] = tgtCh > 14 ? 2 : 1;
    }
    int rc = uniCmd(UNI_BSS_INFO_UPDATE, m.b, m.n, false, nullptr, 0, nullptr);
    edca();
    return rc;
}

// EDCA_UPDATE (mt7925_mcu_set_tx): station defaults, overridden by the AP's WMM parameter element
int MtkWlan::edca() {
    uint8_t aifs[4] = {2, 2, 3, 7}, ecwMin[4] = {2, 3, 4, 4}, ecwMax[4] = {3, 4, 10, 10};
    uint16_t txop[4] = {47, 94, 0, 0};
    static const uint8_t aciToAc[4] = {2, 3, 1, 0};
    for (const uint8_t *e = tgtIe, *end = tgtIe + tgtIeLen; e + 2 <= end && e + 2 + e[1] <= end; e += 2 + e[1]) {
        if (e[0] != 0xdd || e[1] < 24 || e[2] != 0x00 || e[3] != 0x50 || e[4] != 0xf2 || e[5] != 2 || e[6] != 1) continue;
        const uint8_t *r = e + 10;
        for (int i = 0; i < 4; i++, r += 4) {
            uint8_t ac = aciToAc[(r[0] >> 5) & 3];
            aifs[ac] = (r[0] & 0xf) < 2 ? 2 : (r[0] & 0xf);
            ecwMin[ac] = (r[1] & 0xf) ? (r[1] & 0xf) : 5;
            ecwMax[ac] = (r[1] >> 4) ? (r[1] >> 4) : 10;
            txop[ac] = le16(r + 2);
        }
        break;
    }
    uint8_t req[4 + 4 * 12] = {};
    req[0] = BSS_IDX;
    for (int ac = 0; ac < 4; ac++) {
        uint8_t *t = req + 4 + ac * 12;
        put16(t, 0);
        put16(t + 2, 12);
        t[4] = (uint8_t)ac;
        t[5] = 0xf;
        t[6] = ecwMin[ac];
        t[7] = ecwMax[ac];
        put16(t + 8, txop[ac]);
        t[10] = aifs[ac];
    }
    return uniCmd(UNI_EDCA_UPDATE, req, sizeof(req), false, nullptr, 0, nullptr);
}

// STA_REC_UPDATE for the AP; state 0 none, 2 associated
int MtkWlan::staRec(uint8_t state, bool newly, uint16_t aid) {
    Msg m;
    m.init(8);
    m.b[0] = BSS_IDX;
    m.b[1] = AP_WCID & 0xff;
    m.b[4] = 1;                                 // is_tlv_append
    m.b[6] = AP_WCID >> 8;
    uint8_t *b = m.tlv(0, 20);                  // STA_REC_BASIC
    put32(b + 4, 0x10002);                      // CONNECTION_INFRA_AP
    b[8] = 2;                                   // CONN_STATE_PORT_SECURE (open network)
    b[9] = 1;                                   // qos
    put16(b + 10, aid);
    memcpy(b + 12, tgtBssid, 6);
    put16(b + 18, newly ? 3 : 1);               // EXTRA_INFO_VER | NEW
    uint8_t *p = m.tlv(0x15, 12);               // STA_REC_PHY
    put16(p + 4, apBasic);
    p[6] = 1u << 3;                             // PHY_TYPE_BIT_OFDM
    uint8_t *ra = m.tlv(1, 16);                 // STA_REC_RA
    put16(ra + 4, (uint16_t)(apSupp << 6));     // RA_LEGACY_OFDM
    uint8_t *st = m.tlv(7, 16);                 // STA_REC_STATE
    st[4] = state;
    if (state) {
        uint8_t *ml = m.tlv(0x20, 28);          // STA_REC_MLD
        memcpy(ml + 4, tgtBssid, 6);
        put16(ml + 10, AP_WCID);
        put16(ml + 14, AP_WCID);
        ml[16] = 1;
        put16(ml + 20, AP_WCID);
        ml[22] = BSS_IDX;
    }
    uint8_t *h = m.tlv(0x2b, 8);                // STA_REC_HDR_TRANS: from_ds 0, to_ds 1, no RX header translation
    h[5] = 1;
    h[6] = 1;
    return uniCmd(UNI_STA_REC_UPDATE, m.b, m.n, false, nullptr, 0, nullptr);
}

int MtkWlan::roc(bool acquire) {
    uint8_t req[4 + 24] = {};
    uint8_t *t = req + 4;
    if (acquire) {
        rocGrant = false;
        rocStatus = 0xff;
        rocTok++;
        put16(t, 0);                            // UNI_ROC_ACQUIRE
        put16(t + 2, 24);
        t[4] = BSS_IDX;
        t[5] = rocTok;
        t[6] = tgtCh;
        t[8] = tgtCh > 14 ? 2 : 1;
        t[10] = tgtCh;
        t[13] = tgtCh;
        t[15] = 0;                              // reqtype JOIN
        put32(t + 16, 5000);
        t[20] = 0xff;
        return uniCmd(UNI_ROC, req, sizeof(req), false, nullptr, 0, nullptr);
    }
    put16(t, 1);                                // UNI_ROC_ABORT
    put16(t + 2, 12);
    t[4] = BSS_IDX;
    t[5] = rocTok;
    t[6] = 0xff;
    return uniCmd(UNI_ROC, req, 4 + 12, false, nullptr, 0, nullptr);
}

// Fixed-rate table (idx 14..25: CCK 1/2/5.5/11, OFDM 6..54) and WTBL admission counters (m3HwPrep)
void MtkWlan::hwPrep() {
    static const uint16_t rates[12] = {0, 1, 2, 3, (1 << 6) | 11, (1 << 6) | 15, (1 << 6) | 10, (1 << 6) | 14,
                                       (1 << 6) | 9, (1 << 6) | 13, (1 << 6) | 8, (1 << 6) | 12};
    for (int i = 0; i < 12; i++) {
        wr(WTBL_ITDR0, rates[i]);
        wr(WTBL_ITDR1, 1u << 6);
        wr(WTBL_ITCR, (1u << 16) | (1u << 31) | (uint32_t)(14 + i));
    }
    static const uint16_t wcids[2] = {BMC_WCID, AP_WCID};
    for (int i = 0; i < 2; i++) {
        rmw(WTBL_UPDATE, 0xfff | (1u << 14), wcids[i] | (1u << 14));
        pollMsec(WTBL_UPDATE, 1u << 31, 0, 50, 1);
    }
}

int MtkWlan::joinStage() {
    setProperty("MtkTargetSsid", tgtSsid);
    if (!tgtFound) { step("W5 fail: target SSID not in scan"); return -1; }
    char t[48];
    snprintf(t, sizeof(t), "ch %u cap %04x bi %u ies %u", tgtCh, tgtCap, tgtBcnInt, tgtIeLen);
    setProperty("MtkTarget", t);
    if (tgtCap & 0x10) { step("W5 fail: target needs Privacy (not an open network)"); return -2; }
    parseAp();
    setNum("MtkW5ApRates", (uint32_t)apSupp << 8 | apBasic);
    hwPrep();
    setNum("MtkW5BssAdd", (uint32_t)bssInfo(false));
    setNum("MtkW5StaNone", (uint32_t)staRec(0, true, 0));
    setNum("MtkW5Roc", (uint32_t)roc(true));
    for (int i = 0; i < 1000 && !rocGrant; i++) pump(1);
    setNum("MtkW5RocGrant", rocGrant ? rocStatus : 0xffff);
    if (!rocGrant || rocStatus) { step("W5 fail: no ROC grant"); roc(false); return -3; }
    int r = authAssoc(true);
    if (r) { roc(false); return r; }
    setNum("MtkW5BssUp", (uint32_t)bssInfo(true));
    setNum("MtkW5StaAssoc", (uint32_t)staRec(2, false, aid));
    roc(false);
    linkUp = true;
    joinedOnce = true;
    char s[80];
    snprintf(s, sizeof(s), "W5 pass: associated to %s (ch %u, aid %u)", tgtSsid, tgtCh, aid);
    step(s);
    return 0;
}

// Open-system auth + association; first = the W5 join (publishes MtkW5*), else a W6 rejoin
int MtkWlan::authAssoc(bool first) {
    // open-system authentication: algorithm 0, transaction 1
    uint8_t f[256] = {};
    auto hdr = [&](uint8_t fc0) {
        bzero(f, 24);
        f[0] = fc0;
        memcpy(f + 4, tgtBssid, 6);
        memcpy(f + 10, mac, 6);
        memcpy(f + 16, tgtBssid, 6);
    };
    uint32_t txOk = 0;
    hdr(0xb0);
    put16(f + 24, 0); put16(f + 26, 1); put16(f + 28, 0);
    bool got = xchg(f, 30, 11, 0xb0, &txOk);
    setNum(first ? "MtkW5AuthTx" : "MtkW6RejoinAuthTx", txOk);
    uint32_t authSt = got ? ((uint32_t)le16(mgmt + 24) << 16 | (uint32_t)le16(mgmt + 26) << 8 | le16(mgmt + 28)) : 0xffffffff;
    setNum(first ? "MtkW5AuthResp" : "MtkW6RejoinAuthResp", authSt);   // alg << 16 | seq << 8 | status
    if (!got || le16(mgmt + 24) != 0 || le16(mgmt + 26) != 2 || le16(mgmt + 28) != 0) {
        if (first) step(got ? "W5 fail: auth rejected" : "W5 fail: no auth response");
        return -4;
    }

    // association request: ESS | short slot, listen interval 10, SSID, OFDM rates, no RSN (open)
    hdr(0x00);
    uint8_t *p = f + 24;
    put16(p, tgtCh > 14 ? 0x0401 : 0x0421); p += 2;
    put16(p, 10); p += 2;
    uint8_t sl = (uint8_t)strlen(tgtSsid);
    *p++ = 0; *p++ = sl; memcpy(p, tgtSsid, sl); p += sl;
    static const uint8_t rates5[8] = {0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};
    static const uint8_t rates2[8] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    static const uint8_t ext2[4] = {0x30, 0x48, 0x60, 0x6c};
    *p++ = 1; *p++ = 8; memcpy(p, tgtCh > 14 ? rates5 : rates2, 8); p += 8;
    if (tgtCh <= 14) { *p++ = 50; *p++ = 4; memcpy(p, ext2, 4); p += 4; }
    txOk = 0;
    got = xchg(f, (uint32_t)(p - f), 0, 0x10, &txOk);
    setNum(first ? "MtkW5AssocTx" : "MtkW6RejoinAssocTx", txOk);
    uint16_t st = got ? le16(mgmt + 26) : 0xffff;
    if (got && !st) aid = le16(mgmt + 28) & 0x3fff;
    setNum(first ? "MtkW5AssocStatus" : "MtkW6RejoinAssocStatus", st);
    setNum(first ? "MtkW5Aid" : "MtkW6RejoinAid", aid);
    if (!got || st) {
        if (first) step(got ? "W5 fail: association rejected" : "W5 fail: no association response");
        return -5;
    }

    return 0;
}
