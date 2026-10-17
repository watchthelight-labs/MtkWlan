// <wtl> project: mtkwlan | file: src/MtkJoin.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// W5: join a network (open-system authentication + association), open or WPA2-PSK.
// The command sequence and the BSS_INFO / STA_REC / ROC / EDCA layouts follow itlmt7925
// (github.com/thanhnndev/ga403wm-hackintosh, kexts/itlmt7925/itlmt7925_m3.cpp: m3Run1, m3Bss, m3Edca, m3Sta,
// m3Roc, m3Tx, m3Auth, m3Assoc, m3ParseAp, m3HwPrep, m3Key; Copyright (c) 2026 thanhnndev and contributors,
// BSD-3-Clause-Clear). Tag values were checked against Linux mt76 v6.18 (mt76_connac_mcu.h: UNI_BSS_INFO_*,
// STA_REC_*, MCU_UNI_CMD_EDCA_UPDATE; mt7925/mcu.h sta_rec_sec_uni, mt7925/mcu.c mt7925_mcu_sta_key_tlv and
// mt7925_mcu_bss_sec_tlv; Copyright (C) MediaTek Inc., ISC).
// W8 (HT/VHT) follows Linux only: mt7925/mcu.c sta_ht_tlv, sta_vht_tlv, sta_phy_tlv, sta_state_v2_tlv,
// sta_rate_ctrl_tlv, bss_rlm_tlv, and mt76_connac_get_phy_mode(_v2); the caps mirror mt7925/init.c.
// 0.9.0 (W1): the one-shot joinStage / authAssoc became a join machine driven from the tick (joinStart,
// joinService: ROC, auth, assoc, 4-way handshake, up) and a connection manager (cmService) that picks the
// wanted network (ops table v2 / user client) or an allow-listed open one from the BSS cache. The RX path
// never issues firmware commands; everything here runs on the tick or the bring-up thread.

#include "MtkWlan.hpp"
#include "MtkCrypto.h"

namespace {
constexpr uint8_t UNI_BSS_INFO_UPDATE = 0x02, UNI_STA_REC_UPDATE = 0x03, UNI_EDCA_UPDATE = 0x04, UNI_ROC = 0x27;
constexpr uint16_t BSS_IDX = 0, AP_WCID = 1, BMC_WCID = 19;   // BMC = MT792x_WTBL_RESERVED - bss idx
constexpr uint8_t RATE_IDX_OFDM6 = 18;                        // fixed-rate table: 14 + 4 (OFDM 6 Mb/s)
constexpr uint32_t WTBL_UPDATE = 0x820d4380, WTBL_ITCR = 0x820d43b0, WTBL_ITDR0 = 0x820d43b8, WTBL_ITDR1 = 0x820d43bc;
constexpr uint16_t STA_REC_KEY_V3 = 0x27;                     // struct sta_rec_sec_uni
constexpr uint8_t CIPHER_NONE = 0, CIPHER_TKIP = 2, CIPHER_CCMP = 4;   // CONNAC3_CIPHER_*
constexpr uint8_t SEC_MODE_OPEN = 0, SEC_MODE_WPA2_PSK = 7;            // mt7925.h MODE_*
constexpr uint32_t JOIN_PHASE_TICKS = 150, JOIN_ROC_TICKS = 1000, JOIN_HANDSHAKE_TICKS = 10000;
constexpr int JOIN_TRIES = 4;
constexpr uint32_t CM_PERIOD_TICKS = 100, CM_IDLE_RESCAN_TICKS = 15000, CM_WANT_RESCAN_TICKS = 5000,
                   CM_WANT_RESCAN_SLOW_TICKS = 15000, CM_WANT_FALLBACK_TICKS = 30000, CM_USER_SCAN_GRACE_TICKS = 10000,
                   CM_BOOT_GRACE_TICKS = 20000, CM_ONFALLBACK_RESCAN_TICKS = 30000, CM_BACKOFF_MAX_TICKS = 60000;
constexpr uint16_t REASON_LEAVING = 3;

// printable copy of an SSID for properties and log lines
void safeSsid(const char *in, uint8_t len, char out[33]) {
    int n = len > 32 ? 32 : len;
    for (int i = 0; i < n; i++) {
        char c = in[i];
        out[i] = (c >= 0x20 && c <= 0x7e && c != ';' && c != '/') ? c : '?';
    }
    out[n] = 0;
}

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

const char *resultName(uint32_t r) {
    static const char *names[] = {"ok", "pending", "network not found", "security mismatch", "no ROC grant",
                                  "auth timeout", "auth rejected", "assoc timeout", "assoc rejected",
                                  "handshake timeout", "wrong key", "key install failed", "AP left", "cancelled",
                                  "RSN element mismatch"};
    return r < sizeof(names) / sizeof(names[0]) ? names[r] : "?";
}
} // namespace

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
    apHt = apVht = false;
    uint8_t vhtWidth = 0;
    for (const uint8_t *ie = tgtIe, *end = tgtIe + tgtIeLen; ie + 2 <= end && ie + 2 + ie[1] <= end; ie += 2 + ie[1]) {
        const uint8_t *b = ie + 2;
        if (ie[0] == 45 && ie[1] >= 26) {               // HT Capabilities
            apHt = true;
            apHtCap = le16(b);
            apAmpdu = b[2];
            memcpy(apRxMcs, b + 3, 10);
        } else if (ie[0] == 61 && ie[1] >= 2) {         // HT Operation
            apHtOp = b[1];
        } else if (ie[0] == 191 && ie[1] >= 12) {       // VHT Capabilities
            apVht = true;
            apVhtCap = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
            apVhtRx = le16(b + 4);
            apVhtTx = le16(b + 8);
        } else if (ie[0] == 192 && ie[1] >= 3) {        // VHT Operation
            vhtWidth = b[0];
        }
    }
    if (tgtCh <= 14) apVht = false;
    apNss = (apRxMcs[1] || (apVht && ((apVhtRx >> 2) & 3) != 3)) ? 2 : 1;
    chBw = 0;
    chCenter = tgtCh;
    if (apHt && (apHtOp & 4) && (apHtOp & 3)) {        // 40 MHz: secondary above (1) or below (3)
        chBw = 1;
        chCenter = (apHtOp & 3) == 1 ? tgtCh + 2 : tgtCh - 2;
    }
    if (apVht && vhtWidth >= 1 && tgtCh > 14) {         // 80 MHz (160 is used as 80)
        chBw = 2;
        chCenter = tgtCh >= 149 ? 155 : (uint8_t)(36 + ((tgtCh - 36) / 16) * 16 + 6);
    }
    if (chBw > maxBw) {
        chBw = maxBw;
        chCenter = tgtCh;
        if (chBw == 1 && (apHtOp & 3)) chCenter = (apHtOp & 3) == 1 ? tgtCh + 2 : tgtCh - 2;
        else chBw = 0;
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
    b[25] = tgtCh > 14 ? (uint8_t)(0x01 | (htActive ? 0x10 : 0) | (vhtActive ? 0x20 : 0))     // A | AN | AC
                       : (uint8_t)(0x02 | 0x04 | (htActive ? 0x08 : 0));                      // B | G | GN
    put16(b + 26, AP_WCID);
    put16(b + 28, tgtCh > 14 ? 3 : 1);          // nonht_basic_phy: OFDM / ERP
    uint8_t *s = m.tlv(16, 8);                  // UNI_BSS_INFO_SEC (mt7925_mcu_bss_sec_tlv): mode, status, cipher
    if (secCipher == CIPHER_CCMP) { s[4] = SEC_MODE_WPA2_PSK; s[5] = 6; s[6] = CIPHER_CCMP; }
    else { s[4] = SEC_MODE_OPEN; s[5] = 1; s[6] = CIPHER_NONE; }
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
        uint8_t *rl = m.tlv(2, 16);             // UNI_BSS_INFO_RLM (mt7925_mcu_bss_rlm_tlv)
        uint8_t bw = htActive ? chBw : 0, center = bw ? chCenter : tgtCh;
        rl[4] = tgtCh;
        rl[5] = center;
        rl[7] = bw;
        rl[8] = rl[9] = htActive ? 2 : 1;      // tx / rx streams (antenna mask 0x3)
        rl[10] = bw ? 4 : 0;                    // ht_op_info: 40 MHz allowed
        rl[11] = tgtCh < center ? 1 : tgtCh > center ? 3 : 0;   // sco: SCA / SCB
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

// STA_REC_UPDATE for the AP; state 0 none, 2 associated. conn_state is PORT_SECURE from the first record on,
// as Linux (mt76_connac_mcu_sta_cmd, enable) and itlmt7925 send it: the data port is gated on the host.
int MtkWlan::staRec(uint8_t state, bool newly, uint16_t aidArg) {
    Msg m;
    m.init(8);
    m.b[0] = BSS_IDX;
    m.b[1] = AP_WCID & 0xff;
    m.b[4] = 1;                                 // is_tlv_append
    m.b[6] = AP_WCID >> 8;
    uint8_t *b = m.tlv(0, 20);                  // STA_REC_BASIC
    put32(b + 4, 0x10002);                      // CONNECTION_INFRA_AP
    b[8] = 2;                                   // CONN_STATE_PORT_SECURE
    b[9] = 1;                                   // qos
    put16(b + 10, aidArg);
    memcpy(b + 12, tgtBssid, 6);
    put16(b + 18, newly ? 3 : 1);               // EXTRA_INFO_VER | NEW
    bool ht = state && htActive, vht = state && vhtActive;
    uint8_t *p = m.tlv(0x15, 12);               // STA_REC_PHY
    put16(p + 4, apBasic);
    p[6] = (uint8_t)((1u << 3) | (ht ? 1u << 4 : 0) | (vht ? 1u << 5 : 0));   // PHY_TYPE_BIT_OFDM | HT | VHT
    if (ht) {
        uint8_t af = apAmpdu & 3, mm = (apAmpdu >> 2) & 7;
        if (vht && ((apVhtCap >> 23) & 7) > af) af = (apVhtCap >> 23) & 7;
        p[7] = (uint8_t)(af | (mm << 2));       // ampdu: factor | density
        p[10] = af;                             // max_ampdu_len
    }
    // Linux mt7925_mcu_sta_cmd order: BASIC, PHY, HT, VHT, ..., RA, STATE, MLD, HDR_TRANS
    if (ht) {
        uint8_t *h = m.tlv(9, 8);               // STA_REC_HT: the AP's HT capability info, limited to ours
        put16(h + 4, (uint16_t)(apHtCap & (0x0001 | (chBw ? 0x0002 : 0) | 0x000c | 0x0020 | (chBw ? 0x0040 : 0) |
                                           0x0080 | 0x0300)));
    }
    if (vht) {
        uint8_t *v = m.tlv(10, 16);             // STA_REC_VHT
        put32(v + 4, apVhtCap & (0x3 | 0x10 | 0x20 | 0x80 | 0x700 | (7u << 23)));
        put16(v + 8, (uint16_t)(apVhtRx | 0xfff0));       // streams 3-8 not supported
        put16(v + 10, (uint16_t)(apVhtTx | 0xfff0));
    }
    uint8_t *ra = m.tlv(1, 16);                 // STA_REC_RA
    put16(ra + 4, (uint16_t)(apSupp << 6));     // RA_LEGACY_OFDM
    if (ht) { ra[6] = apRxMcs[0]; ra[7] = apNss > 1 ? apRxMcs[1] : 0; }   // HT MCS the AP can receive
    uint8_t *st = m.tlv(7, 16);                 // STA_REC_STATE (v2)
    st[4] = state;
    if (vht) st[12] = (uint8_t)(chBw | (apNss << 4));                      // vht_opmode: bandwidth | rx_nss
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

// The disable form of the station record (mt76_connac_mcu_sta_basic_tlv with enable = false): conn_state
// DISCONNECT, extra info VER only. Sent when we leave or lose the AP, before the next joinStart adds a new record.
int MtkWlan::staRemove() {
    Msg m;
    m.init(8);
    m.b[0] = BSS_IDX;
    m.b[1] = AP_WCID & 0xff;
    m.b[4] = 1;
    m.b[6] = AP_WCID >> 8;
    uint8_t *b = m.tlv(0, 20);                  // STA_REC_BASIC
    put32(b + 4, 0x10002);
    b[8] = 0;                                   // CONN_STATE_DISCONNECT
    b[9] = 1;
    put16(b + 10, 0);
    memcpy(b + 12, tgtBssid, 6);
    put16(b + 18, 1);                           // EXTRA_INFO_VER
    return uniCmd(UNI_STA_REC_UPDATE, m.b, m.n, false, nullptr, 0, nullptr);
}

// STA_REC_BA (mt7925_mcu_sta_ba): tid, ba_type (1 originator, 2 recipient), amsdu, ba_en = enable << tid,
// ssn, winsize
int MtkWlan::staBa(uint8_t tid, uint16_t ssn, uint16_t win, bool tx, bool enable) {
    Msg m;
    m.init(8);
    m.b[0] = BSS_IDX;
    m.b[1] = AP_WCID & 0xff;
    m.b[4] = 1;
    m.b[6] = AP_WCID >> 8;
    uint8_t *t = m.tlv(6, 16);
    t[4] = tid;
    t[5] = tx ? 1 : 2;
    t[6] = 0;
    t[7] = enable ? (uint8_t)(1u << tid) : 0;
    put16(t + 8, ssn);
    put16(t + 10, win);
    return uniCmd(UNI_STA_REC_UPDATE, m.b, m.n, false, nullptr, 0, nullptr);
}

// STA_REC_KEY_V3 (struct sta_rec_sec_uni, mt7925_mcu_sta_key_tlv): the pairwise key on the AP's record
// (WCID 1, muar_idx 0), the group key on the broadcast record (WCID 19, muar_idx 0xe, as Linux installs it on
// the interface's own WCID). 16 bytes = CCMP, 32 bytes = TKIP with the two MIC halves swapped for a station.
int MtkWlan::staKey(bool pairwise, uint8_t keyId, const uint8_t *key, uint8_t keyLen, bool add) {
    if (keyLen != 16 && keyLen != 32) return -1;
    uint16_t wcid = pairwise ? AP_WCID : BMC_WCID;
    Msg m;
    m.init(8);
    m.b[0] = BSS_IDX;
    m.b[1] = wcid & 0xff;
    m.b[4] = 1;                                 // is_tlv_append
    m.b[5] = pairwise ? 0 : 0x0e;               // muar_idx: omac 0 for a station, 0xe for the broadcast record
    m.b[6] = wcid >> 8;
    uint8_t *k = m.tlv(STA_REC_KEY_V3, 68);
    k[4] = add ? 1 : 0;                         // add
    k[5] = pairwise ? 1 : 0;                    // tx_key
    k[6] = pairwise ? 1 : 0;                    // key_type
    k[7] = 0;                                   // is_authenticator
    memcpy(k + 8, tgtBssid, 6);                 // peer_addr
    k[14] = BSS_IDX;
    k[15] = keyLen == 32 ? CIPHER_TKIP : CIPHER_CCMP;
    k[16] = keyId;
    k[17] = keyLen;
    k[18] = (uint8_t)wcid;
    k[19] = 1;                                  // mgmt_prot
    if (add) {
        memcpy(k + 20, key, keyLen);
        if (keyLen == 32) {                     // Rx/Tx MIC keys are swapped (mt7925_mcu_sta_key_tlv)
            memcpy(k + 20 + 16, key + 24, 8);
            memcpy(k + 20 + 24, key + 16, 8);
        }
    }                                           // key_rsc stays zero, as in Linux
    int rc = uniCmd(UNI_STA_REC_UPDATE, m.b, m.n, false, nullptr, 0, nullptr);
    mtk_zero(m.b, sizeof(m.b));
    return rc;
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

// Association request body: capability (ESS | short slot, Privacy for WPA2), listen interval 10, SSID, rates,
// the RSN element for a WPA2-PSK target (after the rates, before HT Capabilities: 802.11 element order), and with
// ht the HT and VHT capabilities of the MT7925 (mt7925/init.c, 2 streams, no beamforming, no A-MSDU above
// 3839 bytes) plus the WMM information element.
uint8_t *MtkWlan::assocIes(uint8_t *p, bool ht) {
    uint16_t cap = tgtCh > 14 ? 0x0401 : 0x0421;
    if (tgtRsn) cap |= 0x0010;                  // Privacy
    put16(p, cap); p += 2;
    put16(p, 10); p += 2;
    uint8_t sl = tgtSsidLen;
    *p++ = 0; *p++ = sl; memcpy(p, tgtSsid, sl); p += sl;
    static const uint8_t rates5[8] = {0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c};
    static const uint8_t rates2[8] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    static const uint8_t ext2[4] = {0x30, 0x48, 0x60, 0x6c};
    *p++ = 1; *p++ = 8; memcpy(p, tgtCh > 14 ? rates5 : rates2, 8); p += 8;
    if (tgtCh <= 14) { *p++ = 50; *p++ = 4; memcpy(p, ext2, 4); p += 4; }
    if (tgtRsn) p += mtk_rsn_ie_psk(p, tgtGroup);
    if (!ht) return p;
    *p++ = 45; *p++ = 26;                       // HT Capabilities
    uint8_t *h = p;
    bzero(h, 26);
    put16(h, 0x0001 | 0x0002 | 0x000c | 0x0020 | 0x0040 | 0x0100);  // LDPC, 20/40, SM PS off, SGI20/40, RX STBC 1
    h[2] = 0x03;                                // A-MPDU: 64 KB, no density restriction
    h[3] = 0xff; h[4] = 0xff;                   // RX MCS 0-15
    h[15] = 0x01;                               // TX MCS set defined
    p += 26;
    if (apVht) {
        *p++ = 191; *p++ = 12;                  // VHT Capabilities
        put32(p, 0x10 | 0x20 | 0x80 | 0x100 | (7u << 23));                // RXLDPC, SGI80, TX STBC, RX STBC 1, A-MPDU 1 MB
        put16(p + 4, 0xfffa);                   // RX MCS 0-9, 2 streams
        put16(p + 6, 0);
        put16(p + 8, 0xfffa);                   // TX MCS 0-9, 2 streams
        put16(p + 10, 0);
        p += 12;
    }
    static const uint8_t wmm[9] = {0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00};   // WMM information
    memcpy(p, wmm, 9);
    return p + 9;
}

// ---------------------------------------------------------------- join machine (tick)

void MtkWlan::mgmtHeader(uint8_t *f, uint8_t fc0) {
    bzero(f, 24);
    f[0] = fc0;
    memcpy(f + 4, tgtBssid, 6);
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, tgtBssid, 6);
}

// Open-system authentication: algorithm 0, transaction 1. The response is caught by noteMgmt (wantFc 0xb0).
void MtkWlan::sendAuth() {
    uint8_t f[30];
    mgmtHeader(f, 0xb0);
    put16(f + 24, 0); put16(f + 26, 1); put16(f + 28, 0);
    mgmtLen = 0;
    wantFc = 0xb0;
    if (txMgmt(f, 30, 11)) authTx++;
    joinTries++;
    joinPhaseEnd = ticks + JOIN_PHASE_TICKS;
}

// Association request (HT/VHT + WMM on the first pass when the AP offers HT, legacy on the second)
void MtkWlan::sendAssoc() {
    uint8_t f[320];
    mgmtHeader(f, 0x00);
    uint8_t *p = assocIes(f + 24, joinHtPass);
    mgmtLen = 0;
    wantFc = 0x10;
    if (txMgmt(f, (uint32_t)(p - f), 0)) assocTx++;
    joinTries++;
    joinPhaseEnd = ticks + JOIN_PHASE_TICKS;
}

// Start joining the cached BSS idx: copy it into tgt*, prepare the firmware records, ask for the channel
bool MtkWlan::joinStart(int idx) {
    if (idx < 0 || idx >= nBss || fwDead || joinState != 0) return false;
    const MtkBss &b = bss[idx];
    memcpy(tgtBssid, b.bssid, 6);
    tgtCh = b.ch;
    tgtCap = b.cap;
    tgtBcnInt = b.bcnInt;
    tgtRssi = b.rssi;
    tgtSsidLen = b.ssidLen;
    memcpy(tgtSsid, b.ssid, sizeof(tgtSsid));
    tgtIeLen = b.ieLen > sizeof(tgtIe) ? (uint32_t)sizeof(tgtIe) : b.ieLen;
    memcpy(tgtIe, b.ie, tgtIeLen);
    tgtRsn = b.sec == MTK_SEC_RSN;
    tgtGroup = b.group;
    tgtRsnIeLen = 0;
    for (const uint8_t *ie = tgtIe, *end = tgtIe + tgtIeLen; ie + 2 <= end && ie + 2 + ie[1] <= end; ie += 2 + ie[1])
        if (ie[0] == 48 && (uint32_t)ie[1] + 2 <= sizeof(tgtRsnIe)) { tgtRsnIeLen = (uint16_t)(ie[1] + 2); memcpy(tgtRsnIe, ie, tgtRsnIeLen); break; }
    secCipher = CIPHER_NONE;                     // the association runs with the open values; the keys change it
    tgtFound = true;
    memcpy(cmLastBssid, tgtBssid, 6);
    htActive = vhtActive = false;
    aid = 0;
    wantFc = 0;
    mgmtLen = 0;
    parseAp();
    hwPrep();
    setNum("MtkW5ApRates", (uint32_t)apSupp << 8 | apBasic);
    setNum("MtkW5BssAdd", (uint32_t)bssInfo(false));
    setNum("MtkW5StaNone", (uint32_t)staRec(0, true, 0));
    setNum("MtkW5Roc", (uint32_t)roc(true));
    rocHeld = true;
    joinHtPass = htOn && apHt;
    joinTries = 0;
    joinState = 1;
    joinDeadline = ticks + JOIN_ROC_TICKS;
    joins++;
    char shown[33];
    safeSsid(tgtSsid, tgtSsidLen, shown);
    setProperty("MtkTargetSsid", shown);
    char t[96];
    snprintf(t, sizeof(t), "W5 joining %s (ch %u, %s, rssi %d)", shown, tgtCh, tgtRsn ? "wpa2" : "open", tgtRssi);
    step(t);
    return true;
}

// One step of the join per tick. Every state has a deadline; auth and assoc resend up to JOIN_TRIES times.
void MtkWlan::joinService() {
    switch (joinState) {
    case 1:                                     // waiting for the channel (ROC grant event 0x27)
        if (rocGrant) {
            if (rocStatus != 0) { joinFail(MTK_JOIN_ROC); return; }
            joinState = 2;
            joinTries = 0;
            sendAuth();
            return;
        }
        if ((int32_t)(ticks - joinDeadline) >= 0) joinFail(MTK_JOIN_ROC);
        return;
    case 2: {                                   // authentication
        if (mgmtLen) {
            uint16_t alg = le16(mgmt + 24), seq = le16(mgmt + 26), st = le16(mgmt + 28);
            mgmtLen = 0;
            wantFc = 0;
            setNum("MtkW5AuthResp", (uint32_t)alg << 16 | (uint32_t)seq << 8 | st);
            if (alg == 0 && seq == 2 && st == 0) { joinState = 3; joinTries = 0; sendAssoc(); }
            else joinFail(MTK_JOIN_AUTH_REJECT);
            return;
        }
        if ((int32_t)(ticks - joinPhaseEnd) >= 0) {
            if (joinTries < JOIN_TRIES) sendAuth();
            else joinFail(MTK_JOIN_AUTH_TIMEOUT);
        }
        return;
    }
    case 3: {                                   // association
        if (mgmtLen) {
            uint16_t st = le16(mgmt + 26), a = (uint16_t)(le16(mgmt + 28) & 0x3fff);
            mgmtLen = 0;
            wantFc = 0;
            if (joinHtPass) setNum("MtkW8AssocHtStatus", st);
            setNum("MtkW5AssocStatus", st);
            if (st) {
                if (joinHtPass) { joinHtPass = false; joinTries = 0; sendAssoc(); return; }   // legacy retry
                joinFail(MTK_JOIN_ASSOC_REJECT);
                return;
            }
            aid = a;
            htActive = joinHtPass;
            vhtActive = joinHtPass && apVht;
            setNum("MtkW5Aid", aid);
            setNum("MtkW5AuthTx", authTx);
            setNum("MtkW5AssocTx", assocTx);
            {
                static const char *bwName[3] = {"20", "40", "80"};
                char mode[64];
                snprintf(mode, sizeof(mode), "%s, %u MHz, %u stream%s", vhtActive ? "VHT" : htActive ? "HT" : "legacy 11a/g",
                         htActive ? (chBw == 2 ? 80 : chBw == 1 ? 40 : 20) : 20, htActive ? apNss : 1, htActive && apNss > 1 ? "s" : "");
                setProperty("MtkW8Mode", mode);
                char ap[96];
                snprintf(ap, sizeof(ap), "ht %d cap %04x ampdu %02x mcs %02x%02x op %02x vht %d cap %08x rx %04x tx %04x bw %s ctr %u",
                         apHt, apHtCap, apAmpdu, apRxMcs[0], apRxMcs[1], apHtOp, apVht, apVhtCap, apVhtRx, apVhtTx, bwName[chBw], chCenter);
                setProperty("MtkW8Ap", ap);
            }
            setNum("MtkW5BssUp", (uint32_t)bssInfo(true));
            setNum("MtkW5StaAssoc", (uint32_t)staRec(2, false, aid));
            roc(false);
            rocHeld = false;
            linkUp = true;
            joinedOnce = true;
            lastTxTick = ticks;
            if (tgtRsn) {
                secStart();
                joinState = 4;
                joinDeadline = ticks + JOIN_HANDSHAKE_TICKS;
                step("W5 associated, 4-way handshake");
            } else {
                joinUp();
            }
            return;
        }
        if ((int32_t)(ticks - joinPhaseEnd) >= 0) {
            if (joinTries < JOIN_TRIES) sendAssoc();
            else if (joinHtPass) { joinHtPass = false; joinTries = 0; sendAssoc(); }   // no answer to the HT request: legacy, as 0.8.0
            else joinFail(MTK_JOIN_ASSOC_TIMEOUT);
        }
        return;
    }
    case 4:                                     // 4-way handshake: secService drives it, this is the deadline
        if ((int32_t)(ticks - joinDeadline) >= 0) joinFail(supp.m2 ? MTK_JOIN_WRONG_KEY : MTK_JOIN_HANDSHAKE_TIMEOUT);
        return;
    default:
        return;
    }
}

// The port is open: tell the front end and the manager
void MtkWlan::joinUp() {
    portOpen = true;
    joinState = 5;
    linkUpAt = ticks;
    lastResult = MTK_JOIN_OK;
    rejoinPending = false;
    cmResult(MTK_JOIN_OK);
    reportLink();
    char shown[33], s[96];
    safeSsid(tgtSsid, tgtSsidLen, shown);
    snprintf(s, sizeof(s), "W5 pass: associated to %s (ch %u, aid %u, %s)", shown, tgtCh, aid, tgtRsn ? "wpa2, keys installed" : "open");
    step(s);
}

void MtkWlan::joinFail(uint32_t result) {
    joinTeardown(linkUp ? REASON_LEAVING : 0);
    lastResult = result;
    joinFailures++;
    cmResult(result);
    char s[80];
    snprintf(s, sizeof(s), "W5 fail: %s (%u)", resultName(result), result);
    step(s);
}

// Leave the AP: deauthenticate when asked (reason != 0 and still associated), forget keys and sessions, remove
// the firmware records (best effort), back to idle. Never called from the RX path (the tick does it).
void MtkWlan::joinTeardown(uint16_t reason) {
    uint8_t prev = joinState;
    if (reason && linkUp) {
        uint8_t f[26];
        mgmtHeader(f, 0xc0);
        put16(f + 24, reason);
        txMgmt(f, 26, 12);
    }
    // state first: the firmware commands below poll the RX ring, and a second deauth seen there must not re-arm
    linkUp = false;
    portOpen = false;
    joinState = 0;
    secReset();
    for (uint8_t t = 0; t < 8; t++) rxBaStop(t);
    txBaState = 0;
    baQHead = baQTail = 0;
    if (rocHeld) { roc(false); rocHeld = false; }
    wantFc = 0;
    mgmtLen = 0;
    if (prev) {
        staRemove();                            // joinStart added the record, whatever state the join reached
        bssInfo(false);
    }
    secCipher = CIPHER_NONE;
    deauthPending = false;
    reportLink();
}

// ---------------------------------------------------------------- connection manager (tick, every 100 ms)

// Best cached BSS for the wanted network that we can join with what we have; -1 when none. Sets lastResult to
// NOT_FOUND (SSID not seen) or SECURITY (seen, but not joinable with / without the key given).
int MtkWlan::cmPick() {
    bool bssidSet = false;
    for (int i = 0; i < 6; i++) if (wantBssid[i]) bssidSet = true;
    int best = -1, bestScore = 0;
    bool seen = false;
    for (int i = 0; i < nBss; i++) {
        const MtkBss &b = bss[i];
        if (b.ssidLen != wantSsidLen || memcmp(b.ssid, wantSsid, wantSsidLen)) continue;
        if (bssidSet && memcmp(b.bssid, wantBssid, 6)) continue;
        seen = true;
        if (!bssJoinable(b, wantHasPmk)) continue;
        int s = bssScore(b);
        if (best < 0 || s > bestScore) { best = i; bestScore = s; }
    }
    if (best < 0) lastResult = seen ? MTK_JOIN_SECURITY : MTK_JOIN_NOT_FOUND;
    return best;
}

// Best open BSS whose SSID is exactly one of MtkAutoOpenSsids; after a failure, not the same BSS again when
// another candidate exists
int MtkWlan::cmPickOpen() {
    int best = -1, bestScore = 0, alt = -1, altScore = 0;
    for (int i = 0; i < nBss; i++) {
        const MtkBss &b = bss[i];
        if (!bssJoinable(b, false)) continue;
        bool listed = false;
        for (int k = 0; k < nAutoOpenSsids && !listed; k++) {
            size_t pl = strlen(autoOpenSsids[k]);
            if (pl && pl == b.ssidLen && !memcmp(b.ssid, autoOpenSsids[k], pl)) listed = true;
        }
        if (!listed) continue;
        int s = bssScore(b);
        if (best < 0 || s > bestScore) { best = i; bestScore = s; }
        if (memcmp(b.bssid, cmLastBssid, 6) && (alt < 0 || s > altScore)) { alt = i; altScore = s; }
    }
    if (cmFails && alt >= 0) return alt;
    return best;
}

// Outcome of a join: reset or grow the backoff (5, 10, 20, 40, 60 s), tell a v2 front end
void MtkWlan::cmResult(uint32_t result) {
    lastResult = result;
    if (result == MTK_JOIN_OK) {
        cmFails = 0;
        if (feJoinResult && fe.ctx) feJoinResult(fe.ctx, (int)result, tgtBssid);
        return;
    }
    cmFails++;
    uint32_t shift = cmFails > 4 ? 4 : cmFails - 1;
    uint32_t delay = 5000u << shift;
    if (delay > CM_BACKOFF_MAX_TICKS) delay = CM_BACKOFF_MAX_TICKS;
    rejoinAt = ticks + delay;
    if (feJoinResult && fe.ctx) feJoinResult(fe.ctx, (int)result, tgtBssid);
}

void MtkWlan::cmService() {
    // requests from the user client / ops table: the teardown runs here, never on the caller's thread
    if (disconnectPending) {
        disconnectPending = false;
        if (joinState) joinTeardown(REASON_LEAVING);
        lastResult = MTK_JOIN_CANCELLED;
        rejoinPending = false;
        onFallback = false;
        step("W5 disconnected (user request), idle");
    }
    if (switchPending) {
        switchPending = false;
        if (joinState) joinTeardown(REASON_LEAVING);
        rejoinPending = false;
        onFallback = false;
    }
    if (fwDead) return;
    if (!cmKick && (int32_t)(ticks - cmNextAt) < 0) return;
    cmKick = false;
    cmNextAt = ticks + CM_PERIOD_TICKS;
    cmRuns++;
    if (scanRunning) return;
    if (joinState == 5) {
        // on the open fallback while a network is wanted: look for it after every scan, rescan every 30 s
        if (wantActive && onFallback) {
            if ((int32_t)(scanFinishedAt - cmLastPickAt) > 0) {
                cmLastPickAt = ticks;
                int idx = cmPick();
                if (idx >= 0) {
                    joinTeardown(REASON_LEAVING);
                    onFallback = false;
                    joinStart(idx);
                    return;
                }
            }
            if (ticks - cmLastScanAt >= CM_ONFALLBACK_RESCAN_TICKS) scanWanted = true;
        }
        return;
    }
    if (joinState != 0) return;
    if (!scanEverDone) { scanWanted = true; return; }
    if ((int32_t)(ticks - rejoinAt) < 0) return;                 // backoff after a failure or a loss
    bool userScanRecent = userScanDoneAt && ticks - userScanDoneAt < CM_USER_SCAN_GRACE_TICKS;
    bool bootGrace = !firstScanDoneAt || ticks - firstScanDoneAt < CM_BOOT_GRACE_TICKS;   // the daemon goes first
    if (wantActive) {
        int idx = cmPick();
        if (idx >= 0) {
            wantMissingSince = 0;
            if (rejoinPending) { rejoins++; rejoinPending = false; }
            onFallback = false;
            joinStart(idx);
            return;
        }
        if (!wantMissingSince) wantMissingSince = ticks;
        uint32_t rescan = ticks - wantMissingSince < CM_WANT_FALLBACK_TICKS ? CM_WANT_RESCAN_TICKS : CM_WANT_RESCAN_SLOW_TICKS;
        if (ticks - cmLastScanAt >= rescan) { scanWanted = true; return; }
        if (!autoOpen || ticks - wantMissingSince < CM_WANT_FALLBACK_TICKS) return;
    }
    if (autoOpen && !userScanPending && !userScanRecent && !bootGrace) {
        int idx = cmPickOpen();
        if (idx >= 0) {
            if (rejoinPending) { rejoins++; rejoinPending = false; }
            onFallback = true;
            joinStart(idx);
            return;
        }
    }
    if (ticks - cmLastScanAt >= CM_IDLE_RESCAN_TICKS) scanWanted = true;
}

// ---------------------------------------------------------------- core entry points (gate held)

// These only set flags and copy data; the tick does the firmware work, so the caller never sleeps in uniCmd.
int MtkWlan::coreScan() {
    if (fwDead || !timer) return -2;
    scanWanted = true;
    userScanPending = true;
    return 0;
}

int MtkWlan::coreJoin(const mtk_join_params *p) {
    if (!p || p->version != MTK_USER_API_VERSION || p->ssid_len < 1 || p->ssid_len > 32) return -1;
    if (p->key_type != MTK_KEY_NONE && p->key_type != MTK_KEY_PMK) return -1;
    if (fwDead || !timer) return -2;
    bool hasPmk = p->key_type == MTK_KEY_PMK;
    bool bssidGiven = false;
    for (int i = 0; i < 6; i++) if (p->bssid[i]) bssidGiven = true;
    // already associated to exactly that network (not the fallback), with the same key and BSSID if one was given
    bool same = wantActive && !onFallback && joinState == 5 && tgtSsidLen == p->ssid_len &&
                !memcmp(tgtSsid, p->ssid, p->ssid_len) && wantHasPmk == hasPmk &&
                (!hasPmk || mtk_ct_equal(wantPmk, p->pmk, 32)) && (!bssidGiven || !memcmp(tgtBssid, p->bssid, 6));
    if (same) return 0;
    // a join turns the open fallback back on after a disconnect, unless the native front end owns the joins
    autoOpen = nAutoOpenSsids > 0 && !(feMode == MTK_FE_NATIVE && !(feModeFlags & MTK_FE_KEEP_AUTOOPEN));
    wantActive = true;
    wantHasPmk = hasPmk;
    wantSsidLen = p->ssid_len;
    bzero(wantSsid, sizeof(wantSsid));
    memcpy(wantSsid, p->ssid, p->ssid_len);
    memcpy(wantBssid, p->bssid, 6);
    if (hasPmk) memcpy(wantPmk, p->pmk, 32);
    else mtk_zero(wantPmk, sizeof(wantPmk));
    wantMissingSince = 0;
    cmFails = 0;
    rejoinAt = ticks;
    rejoinPending = false;
    lastResult = MTK_JOIN_PENDING;
    if (joinState) switchPending = true;
    cmKick = true;
    return 0;
}

int MtkWlan::coreDisconnect() {
    disconnectPending = true;
    wantActive = false;
    wantHasPmk = false;
    mtk_zero(wantPmk, sizeof(wantPmk));
    autoOpen = false;
    cmKick = true;
    return 0;
}

void MtkWlan::coreStatus(mtk_status *out) {
    bzero(out, sizeof(*out));
    out->version = MTK_USER_API_VERSION;
    if (joinState == 5) out->state = MTK_ST_CONNECTED;
    else if (joinState == 4) out->state = MTK_ST_HANDSHAKE;
    else if (joinState) out->state = MTK_ST_JOINING;
    else if (scanRunning) out->state = MTK_ST_SCANNING;
    else if (wantActive || autoOpen) out->state = MTK_ST_WAITING;
    else out->state = MTK_ST_IDLE;
    out->link_up = linkUp;
    out->port_open = portOpen;
    out->security = tgtRsn ? MTK_SEC_RSN : MTK_SEC_OPEN;
    out->scanning = scanRunning;
    out->auto_open = autoOpen;
    out->want_active = wantActive;
    out->front_end = (uint8_t)feMode;
    if (joinState || joinedOnce) {
        out->channel = tgtCh;
        memcpy(out->bssid, tgtBssid, 6);
        out->rssi = tgtRssi;
        out->ssid_len = tgtSsidLen;
        memcpy(out->ssid, tgtSsid, sizeof(out->ssid));
    } else {
        out->rssi = -127;
    }
    out->last_result = lastResult;
    out->bss_count = (uint32_t)nBss;
    out->scans = scans;
    out->joins = joins;
    out->join_failures = joinFailures;
    out->rejoins = rejoins;
    out->m1 = supp.m1; out->m2 = supp.m2; out->m3 = supp.m3; out->m4 = supp.m4;
    out->g1 = supp.g1; out->g2 = supp.g2;
    out->bad_mic = supp.bad_mic;
    out->eapol_replays = supp.replays;
    out->rx_pn_replays = rxPnReplays;
    out->rx_no_pn = rxNoPn;
    out->speed = (linkUp && portOpen) ? 54000000ULL : 0;
}

// Copy up to max cache entries, best first
uint32_t MtkWlan::coreResults(mtk_scan_result *out, uint32_t max) {
    bool used[MTK_SCAN_MAX] = {};
    uint32_t n = 0;
    while (n < max && (int)n < nBss) {
        int best = -1, bestScore = 0;
        for (int i = 0; i < nBss; i++) {
            if (used[i]) continue;
            int s = bssScore(bss[i]);
            if (best < 0 || s > bestScore) { best = i; bestScore = s; }
        }
        if (best < 0) break;
        used[best] = true;
        const MtkBss &b = bss[best];
        mtk_scan_result &r = out[n++];
        bzero(&r, sizeof(r));
        memcpy(r.bssid, b.bssid, 6);
        r.ssid_len = b.ssidLen;
        r.channel = b.ch;
        memcpy(r.ssid, b.ssid, sizeof(r.ssid));
        r.rssi = b.rssi;
        r.security = b.sec;
        r.akm = b.akm;
        r.pairwise = b.pairwise;
        r.group = b.group;
        r.flags = b.flags;
        if (joinState && !memcmp(b.bssid, tgtBssid, 6)) r.flags |= MTK_BSS_CURRENT;
        r.age_ms = ticks - b.lastSeen;
    }
    return n;
}

// The cached BSS at index in best-first order (as coreResults), with its elements
int MtkWlan::coreGetBss(uint32_t index, mtk_bss_info *out) {
    if (!out || (int)index >= nBss) return -1;
    bool used[MTK_SCAN_MAX] = {};
    int best = -1;
    for (uint32_t n = 0; n <= index; n++) {
        best = -1;
        int bestScore = 0;
        for (int i = 0; i < nBss; i++) {
            if (used[i]) continue;
            int s = bssScore(bss[i]);
            if (best < 0 || s > bestScore) { best = i; bestScore = s; }
        }
        if (best < 0) return -1;
        used[best] = true;
    }
    const MtkBss &b = bss[best];
    bzero(out, sizeof(*out));
    memcpy(out->bssid, b.bssid, 6);
    out->channel = b.ch;
    out->rssi = b.rssi;
    out->ssid_len = b.ssidLen;
    memcpy(out->ssid, b.ssid, 32);
    out->security = b.sec;
    out->akm = b.akm;
    out->pairwise = b.pairwise;
    out->group = b.group;
    out->flags = b.flags;
    if (joinState && !memcmp(b.bssid, tgtBssid, 6)) out->flags |= MTK_BSS_CURRENT;
    out->probe_resp = b.probe;
    out->capability = b.cap;
    out->beacon_interval = b.bcnInt;
    out->ie_len = b.ieLen > MTK_BSS_IE_MAX ? MTK_BSS_IE_MAX : b.ieLen;
    memcpy(out->ie, b.ie, out->ie_len);
    out->age_ms = ticks - b.lastSeen;
    return 0;
}

// The user client's calls land here through workLoop->runAction (MtkUserClient.cpp)
IOReturn MtkWlan::gatedUserCall(OSObject *owner, void *sel, void *in, void *out, void *outSize) {
    MtkWlan *self = OSDynamicCast(MtkWlan, owner);
    if (!self) return kIOReturnBadArgument;
    uint32_t selector = (uint32_t)(uintptr_t)sel;
    uint32_t *osz = static_cast<uint32_t *>(outSize);
    switch (selector) {
    case kMtkUcScan:
        return self->coreScan() == 0 ? kIOReturnSuccess : kIOReturnNotReady;
    case kMtkUcResults: {
        if (!out || !osz) return kIOReturnBadArgument;
        uint32_t max = *osz / (uint32_t)sizeof(mtk_scan_result);
        uint32_t n = self->coreResults(static_cast<mtk_scan_result *>(out), max);
        *osz = n * (uint32_t)sizeof(mtk_scan_result);
        return kIOReturnSuccess;
    }
    case kMtkUcJoin: {
        // the native front end owns the joins (macOS manages networks): the tool only reports
        if (self->feMode == MTK_FE_NATIVE && !(self->feModeFlags & MTK_FE_KEEP_AUTOOPEN)) return kIOReturnBusy;
        int r = self->coreJoin(static_cast<const mtk_join_params *>(in));
        return r == 0 ? kIOReturnSuccess : r == -1 ? kIOReturnBadArgument : kIOReturnNotReady;
    }
    case kMtkUcDisconnect:
        if (self->feMode == MTK_FE_NATIVE && !(self->feModeFlags & MTK_FE_KEEP_AUTOOPEN)) return kIOReturnBusy;
        return self->coreDisconnect() == 0 ? kIOReturnSuccess : kIOReturnNotReady;
    case kMtkUcStatus:
        if (!out || !osz || *osz < sizeof(mtk_status)) return kIOReturnBadArgument;
        self->coreStatus(static_cast<mtk_status *>(out));
        *osz = sizeof(mtk_status);
        return kIOReturnSuccess;
    default:
        return kIOReturnUnsupported;
    }
}
