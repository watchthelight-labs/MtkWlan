// <wtl> project: mtkwlan | file: src/MtkScan.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// W4: firmware commands after the firmware runs (hwInit), then firmware scans, listed as Mtk* properties.
// Command layouts are ported from Linux mt76 v6.18 (Copyright (C) 2023 MediaTek Inc., ISC):
//   mt7925/mcu.c fill_message (UNI txd), get_nic_capability, set_eeprom, set_channel_domain, hw_scan;
//   mt76_connac_mcu.c uni_add_dev; mt7925/init.c mac_init (MDP RX length, de-AMSDU); mt7925/mac.c fill_rx
//   (RXD group layout, P-RXV RCPI).
// The minimal post-firmware sequence (NIC capability, DEV_INFO, BSS_INFO, domain, scan, skipping the
// rest of init_hardware) and the beacon locator fallback in mtkParseFrame follow itlmt7925
// (github.com/thanhnndev/ga403wm-hackintosh, kexts/itlmt7925/itlmt7925_m2.cpp and _m3.cpp,
// Copyright (c) 2026 thanhnndev and contributors, BSD-3-Clause-Clear). Its values were checked against
// Linux. Where they differ we follow Linux: EFUSE format WHOLE (1), MAX_RX_LEN shifted into bits 15:3.
// The scan includes the DFS channels 52-144, marked passive (NO_IR | RADAR).
// 0.9.0 (W1): the one-shot scanStage became hwInit (hardware ready) plus a scan machine driven from the tick
// (scanStart / scanService) that fills a BSS cache (bssNote) with each network's security from its RSN or WPA
// element (mtk_rsn_parse in MtkSupp.c). The connection manager in MtkJoin.cpp picks from that cache.

#include "MtkWlan.hpp"

namespace {
constexpr uint32_t MCU_UNI_TXD_LEN = 48;   // struct mt76_connac2_mcu_uni_txd
constexpr uint8_t UNI_DEV_INFO_UPDATE = 0x01, UNI_BSS_INFO_UPDATE = 0x02, UNI_CHIP_CONFIG = 0x0e,
                  UNI_SET_DOMAIN_INFO = 0x15, UNI_SCAN_REQ = 0x16, UNI_EFUSE_CTRL = 0x2d;
constexpr uint8_t MCU_CMD_ACK = 1u << 0, MCU_CMD_UNI = 1u << 1, MCU_CMD_SET = 1u << 2;
constexpr uint8_t EVENT_SCAN_DONE = 0x0e;      // MCU_UNI_EVENT_SCAN_DONE
constexpr uint32_t MDP_DCR0 = 0x820cc800, MDP_DCR1 = 0x820cc804;
constexpr uint8_t UNI_BAND_CONFIG = 0x08;
// mt792x_regs.h, per band
inline uint32_t tmacCtcr0(int b) { return (b ? 0x820f4000 : 0x820e4000) + 0x0f4; }
inline uint32_t rmacBase(int b) { return b ? 0x820f5000 : 0x820e5000; }
inline uint32_t mibScr1(int b) { return (b ? 0x820fd000 : 0x820ed000) + 0x004; }
inline uint32_t dmaDcr0(int b) { return b ? 0x820f7000 : 0x820e7000; }
inline uint32_t wtbloffRscr(int b) { return (b ? 0x820f9000 : 0x820e9000) + 0x008; }
constexpr uint32_t CHAN_NO_IR = 1u << 1, CHAN_RADAR = 1u << 3;   // cfg80211 ieee80211_channel_flags
constexpr uint32_t SCAN_SETTLE_TICKS = 500, SCAN_TIMEOUT_TICKS = 20000, BSS_AGE_TICKS = 60000;
constexpr int UNICMD_DEAD_AFTER = 3;           // consecutive command timeouts before the firmware counts as dead

inline uint32_t le32(const uint8_t *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[1] << 8 | p[0]); }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }

const uint8_t kCh2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
const uint8_t kCh5[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                         149, 153, 157, 161, 165 };
inline bool isDfs(uint8_t ch) { return ch >= 52 && ch <= 144; }

// mt7925_queue_rx_skb (mt7925/mac.c): RXD0 PKT_TYPE bits 31:27, PKT_FLAG bits 19:16, SW_PKT_TYPE bits 31:16.
// A frame is PKT_TYPE_NORMAL (2), or SW_PKT_TYPE FRAME (0x3801 under mask 0x380F), or RX_EVENT (7) with
// PKT_FLAG 1 (PKT_TYPE_NORMAL_MCU). a test boot showed scan results arrive on the MCU ring as the latter.
enum RxKind { RX_FRAME, RX_EVENT, RX_TXFREE, RX_TXS, RX_OTHER };
inline RxKind rxKind(const uint8_t *p, uint32_t len) {
    if (len < 4) return RX_OTHER;
    uint32_t w = le32(p), type = w >> 27, flag = (w >> 16) & 0xf, sw = (w >> 16) & 0xffff;
    if (type != 2 && (sw & 0x380f) == 0x3801) type = 2;
    if (type == 7 && flag == 1) type = 8;
    if (type == 2 || type == 8) return RX_FRAME;
    if (type == 6) return RX_TXFREE;               // PKT_TYPE_TXRX_NOTIFY
    if (type == 0) return RX_TXS;                  // PKT_TYPE_TXS
    return type == 7 ? RX_EVENT : RX_OTHER;
}

// A beacon (FC 0x80, broadcast DA) or probe response (0x50) with TA == BSSID (unicast) at offset o of the RX buffer
inline bool isBeaconAt(const uint8_t *p, uint32_t len, uint32_t o) {
    if (o + 38 > len) return false;
    uint8_t fc = p[o];
    if ((fc != 0x80 && fc != 0x50) || p[o + 1] != 0) return false;
    if (memcmp(p + o + 10, p + o + 16, 6) != 0 || (p[o + 10] & 1)) return false;
    if (fc == 0x80 && (p[o + 4] & p[o + 5] & p[o + 6] & p[o + 7] & p[o + 8] & p[o + 9]) != 0xff) return false;
    return true;
}
} // namespace

// UNI command (mt7925_mcu_fill_message, __MCU_CMD_FIELD_UNI branch) on TX ring 15; waits for the reply
// with the same sequence number on RX ring 0 and copies it to ev (up to evMax bytes). It drains both RX rings
// while waiting, so it must never run from inside dispatchRx (the slot being dispatched would be dispatched
// again): that case returns -13 and is counted. After UNICMD_DEAD_AFTER timeouts in a row the firmware counts
// as dead and every later command returns -14 at once, so the tick does not sleep 3 s per command forever.
int MtkWlan::uniCmd(uint8_t cid, const void *payload, uint32_t plen, bool query, uint8_t *ev, uint32_t evMax, uint32_t *evLen) {
    static uint8_t msg[2048];
    if (evLen) *evLen = 0;
    if (inDispatch) { uniCmdInDispatch++; return -13; }
    if (fwDead) { uniCmdFails++; return -14; }
    if (MCU_UNI_TXD_LEN + plen > sizeof(msg)) return -10;
    bzero(msg, MCU_UNI_TXD_LEN);
    uint8_t seq = nextSeq();
    uint32_t total = MCU_UNI_TXD_LEN + plen;
    put32(msg + 0, (total & 0xffff) | (2u << 23) | (0x20u << 25));   // TX_BYTES, PKT_FMT CMD, Q_IDX MCU_PORT_RX_Q0
    put32(msg + 4, 1u << 14);                                         // HDR_FORMAT CMD
    put16(msg + 32, (uint16_t)(total - 32));                          // uni_txd->len
    put16(msg + 34, cid);                                             // uni_txd->cid
    msg[37] = 0xa0;                                                   // MCU_PKT_ID
    msg[39] = seq;
    uint8_t opt = query ? (MCU_CMD_ACK | MCU_CMD_UNI) : (MCU_CMD_ACK | MCU_CMD_UNI | MCU_CMD_SET);
    if (cid == UNI_CHIP_CONFIG) opt &= ~MCU_CMD_ACK;                  // HIF_CTRL / CHIP_CONFIG
    msg[42] = 0;                                                      // s2d_index H2N
    msg[43] = opt;
    memcpy(msg + MCU_UNI_TXD_LEN, payload, plen);
    int sent = txSend(txMcu, msg, total);
    bzero(msg + MCU_UNI_TXD_LEN, plen);                               // key material does not stay in the static buffer
    if (sent < 0) { uniCmdFails++; return -11; }

    for (int t = 0; t < 3000; t++) {
        pollRx();
        uint32_t len = 0;
        const uint8_t *p = rxPoll(rxMcu, &len);
        if (!p) { IOSleep(1); continue; }
        if (rxKind(p, len) != RX_EVENT) { dispatchRx(p, len); rxRelease(rxMcu); continue; }
        noteEvent(p, len);
        bool match = len >= 44 && p[37] == seq;
        if (match && ev && evMax) {
            uint32_t c = len < evMax ? len : evMax;
            memcpy(ev, p, c);
            if (evLen) *evLen = c;
        }
        rxRelease(rxMcu);
        if (match) { uniCmdTimeouts = 0; return 0; }
        rxUnmatched++;
    }
    uniCmdFails++;
    if (++uniCmdTimeouts >= UNICMD_DEAD_AFTER && !fwDead) {
        fwDead = true;
        step("fail: firmware unresponsive (3 command timeouts), machines stopped");
    }
    return -12;
}

// Count an MCU event by id and keep hex of the first few (diagnostics)
void MtkWlan::noteEvent(const uint8_t *p, uint32_t len) {
    rxEvents++;
    if (len < 44) { evShort++; return; }
    evCount[p[36]]++;
    if (p[36] == EVENT_SCAN_DONE) scanDone = true;
    if (p[36] == 0x27 && len >= 55) {         // MCU_UNI_EVENT_ROC grant: TLV at 48 {tag, len, bss_idx, tokenid, status}
        rocTok = p[53];
        rocStatus = p[54];
        rocGrant = true;
    }
    if (evDumps < 4 && p[36] != 0x01) {       // 0x01 = command results, already counted
        char key[24], hex[3 * 64 + 1];
        uint32_t n = len < 64 ? len : 64, k = 0;
        for (uint32_t i = 0; i < n; i++) k += snprintf(hex + k, sizeof(hex) - k, "%02x", p[i]);
        snprintf(key, sizeof(key), "MtkEvDump%u", evDumps++);
        setProperty(key, hex);
    }
}

// mt792x_mac_init_band (mt792x_mac.c), called for band 0 and 1
void MtkWlan::macInitBand(int b) {
    rmw(tmacCtcr0(b), 0x3f, 0x3f);                                 // INS_DDLMT_REFTIME
    rmw(tmacCtcr0(b), (1u << 18) | (1u << 17), (1u << 18) | (1u << 17));
    rmw(rmacBase(b) + 0x3c4, 1u << 30, 1u << 30);                  // RMAC_MIB_TIME0 RXTIME_EN
    rmw(rmacBase(b) + 0x380, 1u << 30, 1u << 30);                  // RMAC_MIB_AIRTIME0 RXTIME_EN
    rmw(mibScr1(b), (1u << 8) | (1u << 9), (1u << 8) | (1u << 9)); // TXDUR / RXDUR
    rmw(dmaDcr0(b), 0xfff8, 1536u << 3);                           // MAX_RX_LEN
    rmw(dmaDcr0(b), 1u << 23, 0);                                  // RXD_G5 off
    rmw(wtbloffRscr(b), (3u << 30) | (3u << 24), 3u << 24);        // RCPI mode 0, param 3
}

// One RX packet from either ring (mt7925_queue_rx_skb classification). Frames go to the data path from the
// association on (joinState 3 = association request sent), so a message 1 or a deauthentication arriving while
// the post-association commands run is not lost; before that only the beacon locator sees them.
void MtkWlan::dispatchRx(const uint8_t *p, uint32_t len) {
    if (len >= 4) rxTypes[le32(p) >> 27]++;
    bool was = inDispatch;
    inDispatch = true;
    switch (rxKind(p, len)) {
    case RX_FRAME:
        rxFrames++;
        noteMgmt(p, len);
        if (linkUp || joinState >= 3) rxFrame(p, len);
        else mtkParseFrame(p, len);
        break;
    case RX_TXS:
        txStatus(p, len);
        break;
    case RX_TXFREE:
        txFree(p, len);
        break;
    case RX_EVENT:
        noteEvent(p, len);
        break;
    default:
        rxOther++;
        break;
    }
    inDispatch = was;
}

// Drain the band0 data ring (scan results arrive there as beacons / probe responses)
void MtkWlan::pollRx() {
    if (stallFreezeRx) return;                  // supervisor test: the data ring goes unread until the reload
    for (int guard = 0; guard < 256; guard++) {
        uint32_t len = 0;
        const uint8_t *p = rxPoll(rxData, &len);
        if (!p) break;
        dispatchRx(p, len);
        rxRelease(rxData);
    }
}

// Where the 802.11 frame starts in an RX buffer (mt7925_mac_fill_rx): RXD 32 bytes, then groups 4, 1, 2, 3
// (16 bytes each), group 5 (96 bytes, only with group 3), then the 2-byte header pad units of RXD2 HDR_OFFSET
uint32_t MtkWlan::rxFrameOffset(uint32_t rxd1, uint32_t rxd2) {
    uint32_t off = 32;
    if (rxd1 & (1u << 19)) off += 16;                                 // group 4
    if (rxd1 & (1u << 16)) off += 16;                                 // group 1
    if (rxd1 & (1u << 17)) off += 16;                                 // group 2
    if (rxd1 & (1u << 18)) {                                          // group 3 (P-RXV), group 5 (C-RXV)
        off += 16;
        if (rxd1 & (1u << 20)) off += 96;
    }
    return off + 2 * ((rxd2 >> 13) & 7);
}

// RSSI in dBm from the P-RXV group (word 3 bits 7:0 = RCPI of chain 0, to_rssi: (rcpi - 220) / 2), or -127
int8_t MtkWlan::rxRssi(const uint8_t *p, uint32_t len, uint32_t rxd1) {
    if (!(rxd1 & (1u << 18))) return -127;
    uint32_t off = 32;
    if (rxd1 & (1u << 19)) off += 16;
    if (rxd1 & (1u << 16)) off += 16;
    if (rxd1 & (1u << 17)) off += 16;
    if (off + 16 > len) return -127;
    uint32_t rcpi = le32(p + off + 12) & 0xff;
    if (rcpi == 0 || rcpi == 0xff) return -127;
    int v = ((int)rcpi - 220) / 2;
    if (v < -127) v = -127;
    if (v > 0) v = 0;
    return (int8_t)v;
}

// Find the beacon / probe response in an RX buffer: at the offset the RXD groups give, else (the itlmt7925
// rxParseFrame approach, kept as a fallback) by scanning for FC 0x80/0x50 with TA == BSSID
void MtkWlan::mtkParseFrame(const uint8_t *p, uint32_t len) {
    if (len < 32 + 36 + 2) return;
    uint32_t rxd1 = le32(p + 4), rxd2 = le32(p + 8);
    uint32_t off = rxFrameOffset(rxd1, rxd2);
    if (!isBeaconAt(p, len, off)) {
        bool found = false;
        for (off = 32; off + 38 <= len && off < 224; off++)
            if (isBeaconAt(p, len, off)) { found = true; break; }
        if (!found) { rxOther++; return; }
    }
    bssNoteFrame(p + off, len - off, rxRssi(p, len, rxd1));
}

// An 802.11 beacon / probe response (f = frame control): SSID and channel from its elements, then the cache
void MtkWlan::bssNoteFrame(const uint8_t *f, uint32_t flen, int8_t rssi) {
    if (flen < 36) return;
    const uint8_t *ie = f + 36, *end = f + flen;
    char ssid[33] = {};
    uint8_t ssidLen = 0, ch = 0;
    while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
        if (ie[0] == 0 && ie[1] <= 32) { memcpy(ssid, ie + 2, ie[1]); ssidLen = ie[1]; ssid[ie[1]] = 0; }
        else if (ie[0] == 3 && ie[1] >= 1) ch = ie[2];
        else if (ie[0] == 61 && ie[1] >= 1 && !ch) ch = ie[2];
        ie += 2 + ie[1];
    }
    rxBeacons++;
    bssNote(f, flen, ssid, ssidLen, ch, rssi);
    for (int i = 0; i < nBss; i++)
        if (!memcmp(bss[i].bssid, f + 16, 6)) { bss[i].probe = (f[0] & 0xf0) == 0x50; break; }
}

// The primary 20 MHz channels of the domain the firmware scans (kCh2 + kCh5): what the native front end reports as
// supported channels. Any thread: the arrays are constants.
uint32_t MtkWlan::coreChannels(uint8_t *list, uint32_t max) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < sizeof(kCh2) && n < max; i++) list[n++] = kCh2[i];
    for (uint32_t i = 0; i < sizeof(kCh5) && n < max; i++) list[n++] = kCh5[i];
    return n;
}

// Upsert one BSS by BSSID: the newest beacon's fixed fields and elements, its security, when it was last seen.
// The oldest entry goes when the cache is full (never the one being joined).
void MtkWlan::bssNote(const uint8_t *frame, uint32_t len, const char *ssid, uint8_t ssidLen, uint8_t ch, int8_t rssi) {
    if (len < 36) return;
    const uint8_t *bssid = frame + 16;
    int idx = -1;
    for (int i = 0; i < nBss; i++)
        if (!memcmp(bss[i].bssid, bssid, 6)) { idx = i; break; }
    if (idx < 0) {
        if (nBss < MTK_BSS_CACHE) {
            idx = nBss++;
        } else {
            // full: drop the oldest entry this scan has not heard; 2.4 GHz finds would otherwise lose to the 5 GHz
            // channels scanned after them
            uint32_t oldest = 0;
            bool stale = false;
            for (int i = 0; i < nBss; i++) {
                if (joinState && !memcmp(bss[i].bssid, tgtBssid, 6)) continue;
                bool s = bss[i].seenGen != bssGen;
                if (idx < 0 || (s != stale ? s : ticks - bss[i].lastSeen > oldest)) {
                    idx = i; oldest = ticks - bss[i].lastSeen; stale = s;
                }
            }
            if (idx < 0) return;
        }
        bzero(&bss[idx], sizeof(bss[idx]));
        memcpy(bss[idx].bssid, bssid, 6);
        bss[idx].rssi = -127;
    }
    MtkBss &b = bss[idx];
    memcpy(b.ssid, ssid, 33);
    b.ssidLen = ssidLen;
    if (ch) b.ch = ch;
    if (rssi != -127) b.rssi = rssi;
    b.bcnInt = le16(frame + 32);
    b.cap = le16(frame + 34);
    uint32_t n = len - 36;
    if (n > sizeof(b.ie)) n = sizeof(b.ie);
    memcpy(b.ie, frame + 36, n);
    b.ieLen = (uint16_t)n;
    b.lastSeen = ticks;
    b.seenGen = bssGen;
    b.seen++;
    bssParseSec(b);
    b.flags &= (uint8_t)~(MTK_BSS_JOINABLE | MTK_BSS_CURRENT);
    if (bssJoinable(b, false) || bssJoinable(b, true)) b.flags |= MTK_BSS_JOINABLE;
    if (joinState && !memcmp(b.bssid, tgtBssid, 6)) b.flags |= MTK_BSS_CURRENT;
}

// Security of a cached BSS from its RSN element (48), WPA vendor element (dd 00 50 f2 01) or Privacy bit
void MtkWlan::bssParseSec(MtkBss &b) {
    b.sec = (b.cap & 0x10) ? MTK_SEC_WEP : MTK_SEC_OPEN;
    b.akm = b.pairwise = b.group = 0;
    b.rsnCaps = 0;
    b.flags &= (uint8_t)~(MTK_BSS_MFPC | MTK_BSS_MFPR);
    const uint8_t *wpa = nullptr;
    size_t wpaLen = 0;
    for (const uint8_t *ie = b.ie, *end = b.ie + b.ieLen; ie + 2 <= end && ie + 2 + ie[1] <= end; ie += 2 + ie[1]) {
        mtk_rsn_info r;
        if (ie[0] == 48) {
            if (mtk_rsn_parse(ie, (size_t)(end - ie), &r) == 0) {
                b.sec = MTK_SEC_RSN;
                b.akm = r.akm;
                b.pairwise = r.pairwise;
                b.group = r.group;
                b.rsnCaps = r.caps;
                if (r.caps & MTK_RSN_CAP_MFPC) b.flags |= MTK_BSS_MFPC;
                if (r.caps & MTK_RSN_CAP_MFPR) b.flags |= MTK_BSS_MFPR;
                return;                                              // RSN wins over a WPA1 element
            }
        } else if (ie[0] == 0xdd && ie[1] >= 4 && ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xf2 && ie[5] == 0x01) {
            wpa = ie;
            wpaLen = (size_t)(end - ie);
        }
    }
    if (wpa) {
        mtk_rsn_info r;
        if (mtk_rsn_parse(wpa, wpaLen, &r) == 0) {
            b.sec = MTK_SEC_WPA1;
            b.akm = r.akm;
            b.pairwise = r.pairwise;
            b.group = r.group;
        }
    }
}

// What we can join: an open network without a key; with a PMK a WPA2 network that offers AKM PSK with pairwise
// CCMP (EAPOL descriptor version 2) and a CCMP or TKIP group key, and does not require management frame protection
bool MtkWlan::bssJoinable(const MtkBss &b, bool withKey) const {
    if (!b.ssidLen) return false;
    if (!withKey) return b.sec == MTK_SEC_OPEN;
    if (b.sec != MTK_SEC_RSN) return false;
    if (!(b.akm & MTK_AKM_PSK) || !(b.pairwise & MTK_CIPHER_CCMP)) return false;
    if (b.group != 4 && b.group != 2) return false;
    if (b.flags & MTK_BSS_MFPR) return false;
    return true;
}

// Higher is better: signal, 5 GHz preferred, something we can join preferred
int MtkWlan::bssScore(const MtkBss &b) const {
    int s = b.rssi;
    if (b.ch > 14) s += 10;
    if (!(b.flags & MTK_BSS_JOINABLE)) s -= 100;
    return s;
}

// Forget networks not seen for a minute (never the one being joined)
void MtkWlan::bssAge() {
    for (int i = 0; i < nBss;) {
        if (ticks - bss[i].lastSeen > BSS_AGE_TICKS && !(joinState && !memcmp(bss[i].bssid, tgtBssid, 6))) {
            if (i != nBss - 1) bss[i] = bss[nBss - 1];
            nBss--;
            continue;
        }
        i++;
    }
}

// MtkScan property: ssid/channel/rssi/security per network (no BSSIDs, so ioreg dumps need no redaction)
void MtkWlan::publishScan() {
    static const char *secName[] = {"open", "wep", "wpa", "wpa2"};
    static char list[1536];
    size_t n = 0;
    list[0] = 0;
    for (int i = 0; i < nBss && n + 64 < sizeof(list); i++) {
        const MtkBss &b = bss[i];
        char ssid[33];
        memcpy(ssid, b.ssid, 33);
        for (int k = 0; ssid[k]; k++)
            if (ssid[k] < 0x20 || ssid[k] > 0x7e || ssid[k] == ';' || ssid[k] == '/') ssid[k] = '?';
        n += snprintf(list + n, sizeof(list) - n, "%s%s/%u/%d/%s%s", i ? "; " : "", b.ssidLen ? ssid : "(hidden)", b.ch,
                      b.rssi, secName[b.sec & 3], (b.flags & MTK_BSS_JOINABLE) ? "" : "!");
    }
    setProperty("MtkScan", list[0] ? list : "(no networks)");
    setNum("MtkW1Bss", (uint32_t)nBss);
}

// The station interface (mt76_connac_mcu_uni_add_dev, NL80211_IFTYPE_STATION): DEV_INFO with our own MAC, then the
// idle BSS_INFO basic record. The firmware accepts unicast only for this address, so a station address change
// (coreSetMac) removes the interface and adds it again with the new one, the way Linux re-adds the vif.
int MtkWlan::devInfo(bool enable) {
    uint8_t dev[16] = {};
    dev[0] = 0;                 // omac_idx
    dev[1] = 0xff;              // band_idx (mt7925 uses 0xff)
    put16(dev + 4, 0);          // DEV_INFO_ACTIVE
    put16(dev + 6, 12);
    dev[8] = enable ? 1 : 0;    // active
    dev[9] = 0;                 // link_idx
    memcpy(dev + 10, mac, 6);
    int rc = uniCmd(UNI_DEV_INFO_UPDATE, dev, sizeof(dev), false, nullptr, 0, nullptr);

    uint8_t bssb[36] = {};
    uint8_t *b = bssb + 4;      // hdr: bss_idx 0, pad[3]
    put16(b + 0, 0);            // UNI_BSS_INFO_BASIC
    put16(b + 2, 32);
    b[4] = enable ? 1 : 0;      // active
    b[7] = 0xff;                // band_idx
    put32(b + 8, 0x10001);      // CONNECTION_INFRA_STA
    b[12] = 1;                  // conn_state
    put16(b + 20, 19);          // bmc_tx_wlan_idx (itlmt7925 value, WTBL reserved)
    put16(b + 26, 19);          // sta_idx
    setNum("MtkW4BssInfo", (uint32_t)uniCmd(UNI_BSS_INFO_UPDATE, bssb, sizeof(bssb), false, nullptr, 0, nullptr));
    return rc;
}

// Everything after the firmware runs and before the first scan: NIC capability (MAC), EFUSE mode, MDP and band
// init, the station interface, the US domain and power tables, RTS threshold and RX filter
int MtkWlan::hwInit(bool keepMac) {
    static uint8_t ev[512];
    uint32_t evl = 0;

    // drain anything the firmware sent after FW_START
    for (int i = 0; i < 200; i++) {
        pollRx();
        uint32_t len;
        const uint8_t *q = rxPoll(rxMcu, &len);
        if (q) { dispatchRx(q, len); rxRelease(rxMcu); continue; }
        IOSleep(1);
    }

    // 1. NIC capability -> MAC address (mt7925_mcu_get_nic_capability)
    uint8_t cap[8] = {0, 0, 0, 0, 3, 0, 4, 0};   // rsv[4], tag UNI_CHIP_CONFIG_NIC_CAPA, len sizeof - 4
    int rc = uniCmd(UNI_CHIP_CONFIG, cap, sizeof(cap), false, ev, sizeof(ev), &evl);
    setNum("MtkW4NicCap", (uint32_t)rc);
    bool gotMac = false;
    if (!rc && evl > 48) {
        const uint8_t *q = ev + 44, *end = ev + evl;
        uint16_t n = le16(q);
        q += 4;
        for (uint16_t i = 0; i < n && q + 4 <= end; i++) {
            uint16_t tag = le16(q), tl = le16(q + 2);
            if (tl < 4 || q + tl > end) break;
            if (tag == 7 && tl >= 10 && !keepMac) { memcpy(mac, q + 4, 6); gotMac = true; }   // MT_NIC_CAP_MAC_ADDR
            q += tl;
        }
        setNum("MtkW4NicCapElements", n);
    }
    if (keepMac) {
        // a reload keeps the address macOS may have set (I-058): the firmware gets it again in DEV_INFO below
    } else if (gotMac) {
        char s[18];
        snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        setProperty("MtkMacAddr", s);
    } else {
        static const uint8_t fallback[6] = {0x02, 0x00, 0x79, 0x25, 0x00, 0x01};   // locally administered
        memcpy(mac, fallback, 6);
        setProperty("MtkMacAddr", "none (using 02:00:79:25:00:01)");
    }

    // 2. EFUSE buffer mode = efuse, whole (mt7925_mcu_set_eeprom)
    uint8_t ee[12] = {0, 0, 0, 0, 2, 0, 8, 0, 0, 1, 0, 0};
    setNum("MtkW4Eeprom", (uint32_t)uniCmd(UNI_EFUSE_CTRL, ee, sizeof(ee), false, nullptr, 0, nullptr));

    // 3. MDP: max RX length 1536 (bits 15:3), hardware de-AMSDU (mt7925_mac_init)
    rmw(MDP_DCR1, 0xfff8, 1536u << 3);
    rmw(MDP_DCR0, 1u << 15, 1u << 15);
    setNum("MtkW4DmaDcr0Before", rr(dmaDcr0(0)));
    macInitBand(0);
    macInitBand(1);
    setNum("MtkW4DmaDcr0", rr(dmaDcr0(0)));
    setNum("MtkW4Rfcr", rr(rmacBase(0)));

    // 4. station interface (mt76_connac_mcu_uni_add_dev, NL80211_IFTYPE_STATION)
    setNum("MtkW4DevInfo", (uint32_t)devInfo(true));

    // 5. channel domain "US", DFS channels passive (mt7925_mcu_set_channel_domain)
    static uint8_t dom[16 + 8 * 40];
    bzero(dom, sizeof(dom));
    dom[0] = 'U'; dom[1] = 'S';
    dom[4] = 0; dom[5] = 3; dom[6] = 3;           // bw_2g 20/40, bw_5g/6g up to 160
    uint32_t n2 = sizeof(kCh2), n5 = sizeof(kCh5);
    put16(dom + 8, 2);
    put16(dom + 10, (uint16_t)(8 + (n2 + n5) * 8));
    dom[12] = (uint8_t)n2; dom[13] = (uint8_t)n5; dom[14] = 0;
    uint8_t *w = dom + 16;
    for (uint32_t i = 0; i < n2; i++, w += 8) put16(w, kCh2[i]);
    for (uint32_t i = 0; i < n5; i++, w += 8) {
        put16(w, kCh5[i]);
        if (isDfs(kCh5[i])) put32(w + 4, CHAN_NO_IR | CHAN_RADAR);
    }
    powerStage(false);                          // CLC country tables first (mt7925_regd_update order)
    setNum("MtkW4Domain", (uint32_t)uniCmd(UNI_SET_DOMAIN_INFO, dom, (uint32_t)(w - dom), false, nullptr, 0, nullptr));
    powerStage(true);                           // then the per-rate limits

    // __mt7925_start: RTS threshold 0x92b (mt7925_mcu_set_rts_thresh)
    uint8_t rts[16] = {0, 0, 0, 0, 0x08, 0, 12, 0, 0x2b, 0x09, 0, 0, 2, 0, 0, 0};
    setNum("MtkW4Rts", (uint32_t)uniCmd(UNI_BAND_CONFIG, rts, sizeof(rts), false, nullptr, 0, nullptr));
    // configure_filter: FILTER_ENABLE | FILTER_OTHER_BSS (mt7925_mcu_set_rxfilter, mode 0 = use fif)
    uint8_t flt[72] = {};
    put16(flt + 4, 0x0c);                       // UNI_BAND_CONFIG_SET_MAC80211_RX_FILTER
    put16(flt + 6, 68);
    put32(flt + 12, (1u << 31) | (1u << 6));    // fif
    setNum("MtkW4RxFilter", (uint32_t)uniCmd(UNI_BAND_CONFIG, flt, sizeof(flt), false, nullptr, 0, nullptr));
    setNum("MtkW4RfcrAfterFilter", rr(rmacBase(0)));
    if (fwDead) { step("W4 fail: firmware stopped answering during hardware init"); return -1; }
    step("W4 pass: station ready (MAC, domain, power), scanning from the tick");
    return 0;
}

// One firmware scan of every channel in the domain (mt7925_mcu_hw_scan): wildcard SSID, active where allowed.
// Results arrive as beacons / probe responses on the data ring (bssNote), the end as event SCAN_DONE.
int MtkWlan::scanStart() {
    static uint8_t sc[4 + 20 + 368 + 16 + 136 + 12];
    bzero(sc, sizeof(sc));
    uint32_t n2 = sizeof(kCh2), n5 = sizeof(kCh5);
    uint8_t *w = sc;
    scanSeq = (uint8_t)((scanSeq % 0x7f) + 1);
    bssGen++;
    w[0] = (uint8_t)(0x80 | scanSeq);             // seq_num | band_idx << 7 (0xff truncates to 1)
    w += 4;
    put16(w, 1); put16(w + 2, 20);                // UNI_SCAN_REQ
    w[4] = 1;                                     // active (the firmware stays passive on NO_IR channels)
    w[5] = 2;                                     // probe_req_num
    w[6] = 1u << 5;                               // SCAN_FUNC_SPLIT_SCAN
    put16(w + 8, 60);                             // channel_min_dwell_time
    put16(w + 10, 120);                           // channel_dwell_time
    w += 20;
    put16(w, 10); put16(w + 2, 368);              // UNI_SCAN_SSID
    w[4] = 1;                                     // wildcard
    w += 368;
    put16(w, 11); put16(w + 2, 16);               // UNI_SCAN_BSSID
    memset(w + 4, 0xff, 6);
    w += 16;
    put16(w, 12); put16(w + 2, 136);              // UNI_SCAN_CHANNEL
    w[4] = 4;                                     // specified channels
    w[5] = (uint8_t)(n2 + n5);
    uint32_t k = 0;
    for (uint32_t i = 0; i < n2; i++, k++) { w[8 + 2 * k] = 1; w[9 + 2 * k] = kCh2[i]; }
    for (uint32_t i = 0; i < n5; i++, k++) { w[8 + 2 * k] = 2; w[9 + 2 * k] = kCh5[i]; }
    w += 136;
    put16(w, 14); put16(w + 2, 12);               // UNI_SCAN_MISC
    scanDone = false;
    scanDoneAt = 0;
    scanStartedAt = ticks;
    cmLastScanAt = ticks;
    int rc = uniCmd(UNI_SCAN_REQ, sc, sizeof(sc), false, nullptr, 0, nullptr);
    setNum("MtkW4ScanReq", (uint32_t)rc);
    if (rc) {
        scanFails++;
        if (userScanPending) { userScanPending = false; userScanDoneAt = ticks; }   // the fallback must not wait forever
        return rc;
    }
    scanRunning = true;
    scans++;
    return 0;
}

// Tick: finish a running scan half a second after SCAN_DONE (or at the 20 s limit), start a wanted one when
// the radio is free (idle, or associated: the firmware scans around the association)
void MtkWlan::scanService() {
    if (scanRunning) {
        if (scanDone && !scanDoneAt) scanDoneAt = ticks;
        bool finish = (scanDoneAt && ticks - scanDoneAt >= SCAN_SETTLE_TICKS) || ticks - scanStartedAt >= SCAN_TIMEOUT_TICKS;
        if (!finish) return;
        scanRunning = false;
        scanFinishedAt = ticks;
        scanEverDone = true;
        if (!firstScanDoneAt) firstScanDoneAt = ticks;
        if (!scanDoneAt) scanFails++;
        setNum("MtkW4ScanDone", scanDoneAt ? scanDoneAt - scanStartedAt : 0xffffffff);
        publishScan();
        if (userScanPending) { userScanPending = false; userScanDoneAt = ticks; }
        if (feScanDone && fe.ctx) feScanDone(fe.ctx, scanDoneAt ? 0 : -1, (uint32_t)nBss);
        cmKick = true;
        return;
    }
    if (scanWanted && !fwDead && (joinState == 0 || joinState == 5)) {
        scanWanted = false;
        scanStart();
    }
}
