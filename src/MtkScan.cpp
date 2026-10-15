// <wtl> project: mtkwlan | file: src/MtkScan.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// W4: firmware commands after the firmware runs, then a firmware scan, listed as Mtk* properties.
// Command layouts are ported from Linux mt76 v6.18 (Copyright (C) 2023 MediaTek Inc., ISC):
//   mt7925/mcu.c fill_message (UNI txd), get_nic_capability, set_eeprom, set_channel_domain, hw_scan;
//   mt76_connac_mcu.c uni_add_dev; mt7925/init.c mac_init (MDP RX length, de-AMSDU).
// The minimal post-firmware sequence (NIC capability, DEV_INFO, BSS_INFO, domain, scan, skipping the
// rest of init_hardware) and the beacon locator in mtkParseFrame follow itlmt7925
// (github.com/thanhnndev/ga403wm-hackintosh, kexts/itlmt7925/itlmt7925_m2.cpp and _m3.cpp,
// Copyright (c) 2026 thanhnndev and contributors, BSD-3-Clause-Clear). Its values were checked against
// Linux. Where they differ we follow Linux: EFUSE format WHOLE (1), MAX_RX_LEN shifted into bits 15:3.
// The scan includes the DFS channels 52-144, marked passive (NO_IR | RADAR), because the target
// network is on channel 104.

#include "MtkWlan.hpp"

namespace {
constexpr uint32_t MCU_UNI_TXD_LEN = 48;   // struct mt76_connac2_mcu_uni_txd
constexpr uint8_t UNI_DEV_INFO_UPDATE = 0x01, UNI_BSS_INFO_UPDATE = 0x02, UNI_CHIP_CONFIG = 0x0e,
                  UNI_SET_DOMAIN_INFO = 0x15, UNI_SCAN_REQ = 0x16, UNI_EFUSE_CTRL = 0x2d;
constexpr uint8_t MCU_CMD_ACK = 1u << 0, MCU_CMD_UNI = 1u << 1, MCU_CMD_SET = 1u << 2;
constexpr uint8_t EVENT_SCAN_DONE = 0x0e;      // MCU_UNI_EVENT_SCAN_DONE
constexpr uint32_t PKT_TYPE_RX_EVENT = 7;      // RXD0 bits 31:27
constexpr uint32_t MDP_DCR0 = 0x820cc800, MDP_DCR1 = 0x820cc804;
constexpr uint8_t UNI_BAND_CONFIG = 0x08;
// mt792x_regs.h, per band
inline uint32_t tmacCtcr0(int b) { return (b ? 0x820f4000 : 0x820e4000) + 0x0f4; }
inline uint32_t rmacBase(int b) { return b ? 0x820f5000 : 0x820e5000; }
inline uint32_t mibScr1(int b) { return (b ? 0x820fd000 : 0x820ed000) + 0x004; }
inline uint32_t dmaDcr0(int b) { return b ? 0x820f7000 : 0x820e7000; }
inline uint32_t wtbloffRscr(int b) { return (b ? 0x820f9000 : 0x820e9000) + 0x008; }
constexpr uint32_t CHAN_NO_IR = 1u << 1, CHAN_RADAR = 1u << 3;   // cfg80211 ieee80211_channel_flags

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
// PKT_FLAG 1 (PKT_TYPE_NORMAL_MCU). N-30 showed scan results arrive on the MCU ring as the latter.
enum RxKind { RX_FRAME, RX_EVENT, RX_TXFREE, RX_OTHER };
inline RxKind rxKind(const uint8_t *p, uint32_t len) {
    if (len < 4) return RX_OTHER;
    uint32_t w = le32(p), type = w >> 27, flag = (w >> 16) & 0xf, sw = (w >> 16) & 0xffff;
    if (type != 2 && (sw & 0x380f) == 0x3801) type = 2;
    if (type == 7 && flag == 1) type = 8;
    if (type == 2 || type == 8) return RX_FRAME;
    if (type == 6) return RX_TXFREE;               // PKT_TYPE_TXRX_NOTIFY
    return type == 7 ? RX_EVENT : RX_OTHER;
}
} // namespace

// UNI command (mt7925_mcu_fill_message, __MCU_CMD_FIELD_UNI branch) on TX ring 15; waits for the reply
// with the same sequence number on RX ring 0 and copies it to ev (up to evMax bytes)
int MtkWlan::uniCmd(uint8_t cid, const void *payload, uint32_t plen, bool query, uint8_t *ev, uint32_t evMax, uint32_t *evLen) {
    static uint8_t msg[2048];
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
    if (evLen) *evLen = 0;
    if (txSend(txMcu, msg, total) < 0) return -11;

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
        if (match) return 0;
        rxUnmatched++;
    }
    return -12;
}

// Count an MCU event by id and keep hex of the first few (N-30 diagnostics)
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

// One RX packet from either ring (mt7925_queue_rx_skb classification)
void MtkWlan::dispatchRx(const uint8_t *p, uint32_t len) {
    if (len >= 4) rxTypes[le32(p) >> 27]++;
    switch (rxKind(p, len)) {
    case RX_FRAME:
        rxFrames++;
        noteMgmt(p, len);
        if (linkUp) rxFrame(p, len);
        else mtkParseFrame(p, len);
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
}

// Drain the band0 data ring (scan results arrive there as beacons / probe responses)
void MtkWlan::pollRx() {
    for (int guard = 0; guard < 256; guard++) {
        uint32_t len = 0;
        const uint8_t *p = rxPoll(rxData, &len);
        if (!p) break;
        dispatchRx(p, len);
        rxRelease(rxData);
    }
}

// Find an 802.11 beacon / probe response behind the RXD groups (itlmt7925 rxParseFrame approach:
// FC 0x80/0x50, TA == BSSID, unicast BSSID) and record SSID + channel
void MtkWlan::mtkParseFrame(const uint8_t *p, uint32_t len) {
    if (len < 32 + 36 + 2) return;
    for (uint32_t off = 32; off + 38 <= len && off < 224; off++) {
        uint8_t fc = p[off];
        if ((fc != 0x80 && fc != 0x50) || p[off + 1] != 0) continue;
        if (memcmp(p + off + 10, p + off + 16, 6) != 0 || (p[off + 10] & 1)) continue;
        if (fc == 0x80 && (p[off + 4] & p[off + 5] & p[off + 6] & p[off + 7] & p[off + 8] & p[off + 9]) != 0xff) continue;
        const uint8_t *ie = p + off + 36, *end = p + len;
        char ssid[33] = {};
        uint8_t ch = 0;
        while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
            if (ie[0] == 0 && ie[1] <= 32) { memcpy(ssid, ie + 2, ie[1]); ssid[ie[1]] = 0; }
            else if (ie[0] == 3 && ie[1] >= 1) ch = ie[2];
            else if (ie[0] == 61 && ie[1] >= 1 && !ch) ch = ie[2];
            ie += 2 + ie[1];
        }
        for (int i = 0; ssid[i]; i++)
            if (ssid[i] < 0x20 || ssid[i] > 0x7e || ssid[i] == ';' || ssid[i] == '/') ssid[i] = '?';
        rxBeacons++;
        noteTarget(p + off, len - off, ssid, ch);
        for (int i = 0; i < nAps; i++)
            if (!memcmp(aps[i].bssid, p + off + 16, 6)) { aps[i].seen++; return; }
        if (nAps < (int)(sizeof(aps) / sizeof(aps[0]))) {
            MtkAp &a = aps[nAps++];
            memcpy(a.bssid, p + off + 16, 6);
            memcpy(a.ssid, ssid, sizeof(a.ssid));
            a.ch = ch;
            a.seen = 1;
        }
        return;
    }
    rxOther++;
}

int MtkWlan::scanStage() {
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
            if (tag == 7 && tl >= 10) { memcpy(mac, q + 4, 6); gotMac = true; }   // MT_NIC_CAP_MAC_ADDR
            q += tl;
        }
        setNum("MtkW4NicCapElements", n);
    }
    if (gotMac) {
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
    uint8_t dev[16] = {};
    dev[0] = 0;                 // omac_idx
    dev[1] = 0xff;              // band_idx (mt7925 uses 0xff)
    put16(dev + 4, 0);          // DEV_INFO_ACTIVE
    put16(dev + 6, 12);
    dev[8] = 1;                 // active
    dev[9] = 0;                 // link_idx
    memcpy(dev + 10, mac, 6);
    setNum("MtkW4DevInfo", (uint32_t)uniCmd(UNI_DEV_INFO_UPDATE, dev, sizeof(dev), false, nullptr, 0, nullptr));

    uint8_t bss[36] = {};
    uint8_t *b = bss + 4;       // hdr: bss_idx 0, pad[3]
    put16(b + 0, 0);            // UNI_BSS_INFO_BASIC
    put16(b + 2, 32);
    b[4] = 1;                   // active
    b[7] = 0xff;                // band_idx
    put32(b + 8, 0x10001);      // CONNECTION_INFRA_STA
    b[12] = 1;                  // conn_state
    put16(b + 20, 19);          // bmc_tx_wlan_idx (itlmt7925 value, WTBL reserved)
    put16(b + 26, 19);          // sta_idx
    setNum("MtkW4BssInfo", (uint32_t)uniCmd(UNI_BSS_INFO_UPDATE, bss, sizeof(bss), false, nullptr, 0, nullptr));

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
    setNum("MtkW4Domain", (uint32_t)uniCmd(UNI_SET_DOMAIN_INFO, dom, (uint32_t)(w - dom), false, nullptr, 0, nullptr));

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

    // 6. scan (mt7925_mcu_hw_scan): wildcard SSID, all channels above
    static uint8_t sc[4 + 20 + 368 + 16 + 136 + 12];
    bzero(sc, sizeof(sc));
    w = sc;
    w[0] = 0x81;                                  // seq_num 1 | band_idx << 7 (0xff truncates to 1)
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
    setNum("MtkW4Rx2CpuDmaBefore", (rawRead(rxData.regs + 8) << 16) | (rawRead(rxData.regs + 12) & 0xffff));
    irqStatusOr = 0;
    rc = uniCmd(UNI_SCAN_REQ, sc, sizeof(sc), false, nullptr, 0, nullptr);
    setNum("MtkW4ScanReq", (uint32_t)rc);
    if (rc) { step("W4 fail: scan request"); return -1; }

    // 7. collect until SCAN_DONE (or 20 s), plus a little extra
    uint32_t ms = 0, doneAt = 0;
    for (; ms < 20000; ms++) {
        pollRx();
        uint32_t len = 0;
        const uint8_t *p;
        while ((p = rxPoll(rxMcu, &len))) {
            dispatchRx(p, len);
            rxRelease(rxMcu);
        }
        if (scanDone && !doneAt) doneAt = ms;
        if (doneAt && ms > doneAt + 500) break;
        IOSleep(1);
    }
    setNum("MtkW4ScanDone", scanDone ? doneAt : 0xffffffff);
    setNum("MtkW4Rx2CpuDmaAfter", (rawRead(rxData.regs + 8) << 16) | (rawRead(rxData.regs + 12) & 0xffff));
    setNum("MtkW4Rx0CpuDmaAfter", (rawRead(rxMcu.regs + 8) << 16) | (rawRead(rxMcu.regs + 12) & 0xffff));
    setNum("MtkW4Rx2Desc0Ctrl", desc(rxData, 0)[1]);
    setNum("MtkW4IrqStatusOr", irqStatusOr);
    setNum("MtkW4LpctlAfter", rr(0x7c060010));
    setNum("MtkW4ConnOnMiscAfter", rr(0x7c0600f0));
    {
        static char h[512];
        size_t k = 0;
        h[0] = 0;
        for (int e = 0; e < 256 && k + 12 < sizeof(h); e++)
            if (evCount[e]) k += snprintf(h + k, sizeof(h) - k, "%s%02x:%u", k ? " " : "", e, evCount[e]);
        setProperty("MtkW4EventIds", h[0] ? h : "none");
        setNum("MtkW4EventShort", evShort);
    }
    setNum("MtkW4RxFrames", rxFrames);
    setNum("MtkW4Beacons", rxBeacons);
    setNum("MtkW4OtherFrames", rxOther);
    setNum("MtkW4Aps", (uint32_t)nAps);

    static char list[1536];
    size_t n = 0;
    bool target = false;
    list[0] = 0;
    for (int i = 0; i < nAps && n + 48 < sizeof(list); i++) {
        n += snprintf(list + n, sizeof(list) - n, "%s%s/%u", i ? "; " : "", aps[i].ssid[0] ? aps[i].ssid : "(hidden)", aps[i].ch);
        if (!strncmp(aps[i].ssid, "Boingo", 6)) target = true;
    }
    setProperty("MtkScan", list[0] ? list : "(no networks)");
    setProperty("MtkBoingoSeen", target);
    step(nAps ? (target ? "W4 pass: scan found Boingo" : "W4 partial: scan works, Boingo not seen")
              : "W4 fail: no beacons");
    return nAps ? 0 : -2;
}
