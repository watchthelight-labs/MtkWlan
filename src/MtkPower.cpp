// <wtl> project: mtkwlan | file: src/MtkPower.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// TX power: the firmware's country limit tables (CLC) and the per-rate power limits (SKU), which the
// driver sent nothing of before 0.7.0. Ported from Linux mt76 v6.18 (Copyright (C) 2023 MediaTek Inc., ISC):
//   mt7925/mcu.c mt7925_load_clc (CLC region of the RAM firmware, filtered by EEPROM HW_TYPE encap),
//   __mt7925_mcu_set_clc / mt7925_mcu_set_clc (UNI SET_POWER_LIMIT tag 3 per matching country rule),
//   with the TLV length fixes from Linux master after v6.18 (9ddb7487 and the CLC equivalent):
//   len = whole message minus the 4-byte prefix,
//   mt7925_mcu_read_eeprom (UNI EFUSE_CTRL query), mt7925_mcu_rate_txpower_band / mt7925_mcu_build_sku
//   (UNI SET_POWER_LIMIT tag 1, 3 channels per message, 449-byte SKU per channel).
// Country "US", environment indoor. Per-rate limits are 23 dBm on 5 GHz and 20 dBm on 2.4 GHz (half-dB
// units in the SKU); the firmware still applies the CLC table and its own calibration on top.
// Info.plist MtkPower = false skips all of it.

#include "MtkWlan.hpp"

extern "C" {
extern const unsigned char mtk_fw_ram[];
extern const unsigned int mtk_fw_ram_len;
}

namespace {
constexpr uint8_t UNI_EFUSE_CTRL = 0x2d, UNI_SET_POWER_LIMIT = 0x2c;
constexpr uint32_t MT_EE_HW_TYPE = 0xa71, EEPROM_BLOCK = 16;
constexpr uint32_t SKU_LEN = 449;                 // MT_CONNAC3_SKU_POWER_LIMIT
constexpr uint8_t ENVIRON_INDOOR = 1;
constexpr uint8_t FW_FEATURE_NON_DL = 1u << 6, FW_TYPE_CLC = 2;

inline uint32_t le32(const uint8_t *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
inline void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
} // namespace

// mt7925_mcu_read_eeprom: one byte of the efuse/EEPROM buffer through an EFUSE_CTRL query
int MtkWlan::readEeprom(uint32_t offset, uint8_t *val) {
    uint8_t req[4 + 4 + 4 + 4 + EEPROM_BLOCK] = {};
    put16(req + 4, 1);                            // tag
    put16(req + 6, sizeof(req) - 4);
    put32(req + 8, offset & ~(EEPROM_BLOCK - 1));  // addr
    static uint8_t ev[256];
    uint32_t evl = 0;
    int rc = uniCmd(UNI_EFUSE_CTRL, req, sizeof(req), true, ev, sizeof(ev), &evl);
    if (rc) return rc;
    // event payload at 44: rsv[4] tag len ver addr valid size magic type rsv1[16] data[32]
    uint32_t at = 44 + 48 + (offset % EEPROM_BLOCK);
    if (evl <= at) return -20;
    *val = ev[at];
    return 0;
}

// The CLC tables (idx 0 power, 1 power ext) inside the RAM firmware's non-downloaded CLC region
int MtkWlan::clcStage() {
    uint8_t hw = 0;
    int rc = readEeprom(MT_EE_HW_TYPE, &hw);
    setNum("MtkW9EepromHwType", rc ? 0xffff0000u | (uint16_t)rc : hw);
    if (rc) return -1;
    uint8_t encap = hw & 3;

    const uint8_t *fw = mtk_fw_ram, *trailer = fw + mtk_fw_ram_len - 36;
    uint32_t nRegion = trailer[2], offset = 0, clcLen = 0;
    const uint8_t *clcBase = nullptr;
    for (uint32_t i = 0; i < nRegion; i++) {
        const uint8_t *reg = trailer - (nRegion - i) * 40;
        uint32_t len = le32(reg + 20);
        if (offset + len > mtk_fw_ram_len) return -2;
        if ((reg[24] & FW_FEATURE_NON_DL) && reg[25] == FW_TYPE_CLC) { clcBase = fw + offset; clcLen = len; break; }
        offset += len;
    }
    if (!clcBase) return -3;

    const uint8_t *tables[2] = {};
    for (uint32_t o = 0; o + 16 <= clcLen;) {
        const uint8_t *c = clcBase + o;
        uint32_t len = le32(c);
        uint8_t idx = c[4];
        if (!len || o + len > clcLen) break;
        if (idx >= 3) break;                         // ARRAY_SIZE(phy->clc)
        if (idx < 2 && !tables[idx] && (c[7] & 3) == encap) tables[idx] = c;   // t0.type encap matches
        o += len;
    }

    int sent = 0, failed = 0;
    for (int idx = 0; idx < 2; idx++) {
        const uint8_t *c = tables[idx];
        if (!c) continue;
        const uint8_t *data = c + 16;
        uint8_t nSeg = c[8];
        const uint8_t *pos = data + 16 * nSeg, *last = data + le32(data + 4);
        static const char *const countries[2] = {"US", "00"};
        for (const char *cc : countries) {
            int matched = 0;
            for (const uint8_t *r = pos; r + 8 <= last; r += 8) {
                if (r[0] != (uint8_t)cc[0] || r[1] != (uint8_t)cc[1]) continue;
                uint8_t segIdx = r[4];
                if (!segIdx || segIdx > nSeg) continue;
                const uint8_t *seg = data + 16 * (segIdx - 1);
                uint32_t sOff = le32(seg + 4), sLen = le32(seg + 8);
                static uint8_t msg[84 + 1400];
                if (sLen > sizeof(msg) - 84 || 16 + sOff + sLen > le32(c)) { failed++; continue; }
                bzero(msg, 84);
                put16(msg + 4, 3);                    // tag
                put16(msg + 6, (uint16_t)(80 + sLen));   // sizeof(req) + seg len - 4 (upstream after v6.18)
                msg[8] = c[5];                        // ver
                put16(msg + 10, (uint16_t)sLen);      // size
                msg[12] = (uint8_t)idx;
                msg[13] = ENVIRON_INDOOR;
                msg[16] = r[0]; msg[17] = r[1];       // alpha2
                msg[18] = r[2]; msg[19] = r[3];       // type
                memcpy(msg + 84, data + sOff, sLen);
                if (uniCmd(UNI_SET_POWER_LIMIT, msg, 84 + sLen, false, nullptr, 0, nullptr)) failed++;
                else sent++;
                matched++;
            }
            if (matched) break;                       // "00" only when the country has no rule
        }
    }
    setNum("MtkW9ClcSent", (uint32_t)sent);
    setNum("MtkW9ClcFailed", (uint32_t)failed);
    return failed ? -4 : (sent ? 0 : -5);
}

// mt7925_mcu_rate_txpower_band: per-channel SKU limits, 3 channels per message
int MtkWlan::ratePowerBand(bool is5g, int8_t halfDbm) {
    static const uint8_t ch2[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    static const uint8_t ch5[] = {36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110,
                                  112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151,
                                  153, 155, 157, 159, 161, 165, 167};
    const uint8_t *list = is5g ? ch5 : ch2;
    int n = is5g ? (int)sizeof(ch5) : (int)sizeof(ch2);
    static uint8_t msg[52 + 3 * (1 + SKU_LEN)];
    int failed = 0;
    for (int i = 0; i < n; i += 3) {
        int num = n - i < 3 ? n - i : 3;
        bzero(msg, 52);
        put16(msg + 4, 1);                            // tag
        msg[12] = (uint8_t)num;                       // n_chan
        msg[13] = is5g ? 2 : 1;                       // band
        msg[14] = (i + num >= n) ? 1 : 0;             // last_msg
        msg[16] = 'U'; msg[17] = 'S';                 // alpha2
        uint8_t *p = msg + 52;
        for (int j = 0; j < num; j++, p += 1 + SKU_LEN) {
            p[0] = list[i + j];
            uint8_t *sku = p + 1;
            memset(sku, 127, SKU_LEN);                // mt7925_mcu_build_sku: 127 where nothing is filled
            if (!is5g) memset(sku, (uint8_t)halfDbm, 4);              // cck
            memset(sku + 4, (uint8_t)halfDbm, 8);                     // ofdm (offset then advances by 8 * 5)
            memset(sku + 44, (uint8_t)halfDbm, 17);                   // ht: 2 x 8 + mcs32
            for (int k = 0; k < 4; k++) memset(sku + 61 + 12 * k, (uint8_t)halfDbm, 10);   // vht: 4 x 10 of 12
            memset(sku + 109, (uint8_t)halfDbm, 84);                  // he: 7 RU sizes x 12
            memset(sku + 193, (uint8_t)halfDbm, 256);                 // eht: 16 x 16
        }
        // whole message minus the 4-byte prefix (Linux 9ddb7487 'fix msg len mismatch between driver and
        // firmware', after v6.18, which sent sizeof(tlv))
        put16(msg + 6, (uint16_t)(p - msg - 4));
        if (uniCmd(UNI_SET_POWER_LIMIT, msg, (uint32_t)(p - msg), false, nullptr, 0, nullptr)) failed++;
    }
    return failed;
}

// Linux order (mt7925_regd_update): CLC, then the channel domain, then the per-rate limits
int MtkWlan::powerStage(bool afterDomain) {
    if (!powerOn) { setProperty("MtkW9Power", "off (MtkPower false)"); return 0; }
    if (!afterDomain) { clcResult = clcStage(); return clcResult; }
    int f2 = ratePowerBand(false, 40), f5 = ratePowerBand(true, 46);
    char s[96];
    snprintf(s, sizeof(s), "clc %d, sku 2g failed %d, sku 5g failed %d", clcResult, f2, f5);
    setProperty("MtkW9Power", s);
    return f2 || f5 ? -1 : 0;
}
