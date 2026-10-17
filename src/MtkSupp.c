// <wtl> project: mtkwlan | file: src/MtkSupp.c | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// See MtkSupp.h for the rules this follows and where it came from.

#include "MtkSupp.h"
#include "MtkCrypto.h"
#include <string.h>

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

size_t mtk_rsn_ie_psk(uint8_t *o, uint8_t group) {
    static const uint8_t t[22] = {0x30, 20, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                                  0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00};
    memcpy(o, t, sizeof(t));
    o[7] = group;
    return sizeof(t);
}

void mtk_supp_init(struct mtk_supp *s, const struct mtk_supp_ops *ops, const uint8_t pmk[32], const uint8_t aa[6],
                   const uint8_t spa[6], const uint8_t *own_ie, size_t own_ie_len, const uint8_t *ap_ie,
                   size_t ap_ie_len) {
    mtk_zero(s, sizeof(*s));
    s->ops = *ops;
    memcpy(s->pmk, pmk, 32);
    memcpy(s->aa, aa, 6);
    memcpy(s->spa, spa, 6);
    if (own_ie_len > sizeof(s->own_ie)) own_ie_len = sizeof(s->own_ie);
    memcpy(s->own_ie, own_ie, own_ie_len);
    s->own_ie_len = own_ie_len;
    if (ap_ie_len > sizeof(s->ap_ie)) ap_ie_len = sizeof(s->ap_ie);
    if (ap_ie_len) memcpy(s->ap_ie, ap_ie, ap_ie_len);
    s->ap_ie_len = ap_ie_len;
    s->renew_snonce = 1;
    s->eapol_ver = 2;
    s->state = MTK_SUPP_WAIT_M1;
}

void mtk_supp_clear(struct mtk_supp *s) {
    mtk_zero(s, sizeof(*s));
}

// EAPOL-Key frame of 99 + dlen bytes: our reply shape (descriptor 2, key length 0, IV / RSC / ID zero)
static size_t build(struct mtk_supp *s, uint8_t *out, uint16_t info, const uint8_t replay[8], const uint8_t *nonce,
                    const uint8_t *data, uint16_t dlen) {
    memset(out, 0, MTK_EAPOL_HDR);
    out[0] = s->eapol_ver;
    out[1] = 3;                                             // EAPOL-Key
    put_be16(out + 2, (uint16_t)(95 + dlen));
    out[4] = 2;                                             // RSN key descriptor
    put_be16(out + 5, info);
    memcpy(out + 9, replay, 8);
    if (nonce) memcpy(out + 17, nonce, 32);
    put_be16(out + 97, dlen);
    if (dlen) memcpy(out + 99, data, dlen);
    return (size_t)MTK_EAPOL_HDR + dlen;
}

static int send_signed(struct mtk_supp *s, uint8_t *f, size_t n, const uint8_t kck[16], int protect) {
    uint8_t mic[16];
    mtk_eapol_mic(kck, f, n, MTK_EAPOL_MIC, mic);
    memcpy(f + MTK_EAPOL_MIC, mic, 16);
    int rc = s->ops.send_eapol(s->ops.ctx, f, n, protect);
    mtk_zero(f, n);
    return rc ? MTK_SUPP_ERR_SEND : 0;
}

static int mic_ok(const uint8_t kck[16], const uint8_t *f, size_t n) {
    uint8_t mic[16];
    mtk_eapol_mic(kck, f, n, MTK_EAPOL_MIC, mic);
    int ok = mtk_ct_equal(mic, f + MTK_EAPOL_MIC, 16);
    mtk_zero(mic, sizeof(mic));
    return ok;
}

// Key data elements / KDEs: the first RSN element and the GTK KDE (00-0F-AC:1). Returns 0 when well formed.
static int parse_kd(const uint8_t *kd, size_t n, const uint8_t **rsn, size_t *rsnlen, const uint8_t **gtk,
                    size_t *gtklen, int *keyid) {
    const uint8_t *e = kd, *end = kd + n;
    *rsn = NULL; *rsnlen = 0; *gtk = NULL; *gtklen = 0; *keyid = 0;
    while (e + 2 <= end) {
        if (e[0] == 0xdd && (e[1] == 0 || e + 2 + e[1] > end)) break;   // padding (0xdd 00 ...)
        if (e + 2 + e[1] > end) return -1;
        if (e[0] == 0x30 && !*rsn) { *rsn = e; *rsnlen = (size_t)2 + e[1]; }
        else if (e[0] == 0xdd && e[1] >= 6 && e[2] == 0x00 && e[3] == 0x0f && e[4] == 0xac && e[5] == 1) {
            if (e[1] < 6 + 5) return -1;
            *keyid = e[6] & 3;
            *gtk = e + 8;
            *gtklen = (size_t)e[1] - 6;
        }
        e += 2 + e[1];
    }
    return 0;
}

// A GTK is 16 bytes (CCMP) or 32 bytes (TKIP group cipher on WPA/WPA2 mixed networks)
static int gtk_len_ok(size_t n) { return n == 16 || n == 32; }

static int install_gtk(struct mtk_supp *s, int keyid, const uint8_t *gtk, size_t gtklen, const uint8_t rsc[8]) {
    if (s->gtk_installed && s->gtk_id == keyid && s->gtk_len == gtklen && mtk_ct_equal(s->gtk_inst, gtk, gtklen)) {
        s->reinstall_skipped++;                             // same key: keep its replay counter (KRACK)
        return 0;
    }
    if (s->ops.install_gtk(s->ops.ctx, keyid, gtk, gtklen, rsc)) return MTK_SUPP_ERR_INSTALL;
    memcpy(s->gtk_inst, gtk, gtklen);
    s->gtk_len = gtklen;
    s->gtk_installed = 1;
    s->gtk_id = keyid;
    s->gtk_installs++;
    return 0;
}

static int fail(struct mtk_supp *s, int e) {
    s->last_error = e;
    if (e == MTK_SUPP_ERR_MIC) s->bad_mic++;
    else if (e == MTK_SUPP_ERR_REPLAY) s->replays++;
    else s->dropped++;
    return e;
}

static int rx_m1(struct mtk_supp *s, const uint8_t *f, const uint8_t *replay) {
    // no MIC on message 1: the replay counter only has to beat the last verified one
    if (s->renew_snonce) {
        s->ops.random(s->ops.ctx, s->snonce, 32);
        s->renew_snonce = 0;
    }
    memcpy(s->anonce, f + 17, 32);
    mtk_wpa_ptk(s->pmk, s->aa, s->spa, s->anonce, s->snonce, s->tptk);
    s->tptk_set = 1;
    s->m1++;
    uint8_t out[MTK_EAPOL_HDR + 64];
    size_t n = build(s, out, 0x0100 | MTK_KI_PAIRWISE | 2, replay, s->snonce, s->own_ie, (uint16_t)s->own_ie_len);
    int rc = send_signed(s, out, n, s->tptk, s->tk_installed);   // a PTK rekey goes out under the current PTK
    if (rc) return fail(s, rc);
    s->m2++;
    if (s->state != MTK_SUPP_DONE) s->state = MTK_SUPP_WAIT_M3;
    return MTK_SUPP_OK_M2;
}

static int rx_m3(struct mtk_supp *s, const uint8_t *f, size_t n, uint16_t info, const uint8_t *replay) {
    if (!s->tptk_set) return fail(s, MTK_SUPP_DROP);
    if (!mtk_ct_equal(f + 17, s->anonce, 32)) return fail(s, MTK_SUPP_DROP);   // ANonce differs from message 1
    if (!mic_ok(s->tptk, f, n)) return fail(s, MTK_SUPP_ERR_MIC);
    memcpy(s->rx_replay, replay, 8);                        // verified: from now on counters must exceed this
    s->rx_replay_set = 1;
    s->m3++;
    if (!(info & MTK_KI_ENCRYPTED) || !(info & MTK_KI_SECURE)) return fail(s, MTK_SUPP_ERR_KEYDATA);
    size_t dlen = be16(f + 97);
    uint8_t kd[MTK_EAPOL_MAX];
    if (dlen < 24 || dlen % 8 || dlen > sizeof(kd) + 8 || MTK_EAPOL_HDR + dlen > n) return fail(s, MTK_SUPP_ERR_KEYDATA);
    if (mtk_aes128_unwrap(s->tptk + 16, f + MTK_EAPOL_HDR, dlen, kd)) return fail(s, MTK_SUPP_ERR_KEYDATA);
    const uint8_t *rsn, *gtk;
    size_t rsnlen, gtklen;
    int keyid, rc;
    if (parse_kd(kd, dlen - 8, &rsn, &rsnlen, &gtk, &gtklen, &keyid)) { rc = MTK_SUPP_ERR_KEYDATA; goto out; }
    if (s->ap_ie_len && (!rsn || rsnlen != s->ap_ie_len || memcmp(rsn, s->ap_ie, rsnlen))) { rc = MTK_SUPP_ERR_IE; goto out; }
    if (!gtk || !gtk_len_ok(gtklen)) { rc = MTK_SUPP_ERR_KEYDATA; goto out; }

    // message 4, then the keys
    {
        int protect = s->tk_installed && !mtk_ct_equal(s->tk_inst, s->tptk + 32, 16);   // a rekey: under the old PTK
        memcpy(s->ptk, s->tptk, 48);
        s->ptk_set = 1;
        uint8_t out[MTK_EAPOL_HDR];
        size_t on = build(s, out, 0x0100 | MTK_KI_SECURE | MTK_KI_PAIRWISE | 2, replay, NULL, NULL, 0);
        if ((rc = send_signed(s, out, on, s->ptk, protect))) goto out;
        s->m4++;
    }
    if (s->tk_installed && mtk_ct_equal(s->tk_inst, s->ptk + 32, 16)) {
        s->reinstall_skipped++;                             // retransmitted message 3: no reinstallation
    } else {
        if (s->ops.install_ptk(s->ops.ctx, s->ptk + 32)) { rc = MTK_SUPP_ERR_INSTALL; goto out; }
        memcpy(s->tk_inst, s->ptk + 32, 16);
        s->tk_installed = 1;
        s->ptk_installs++;
    }
    if ((rc = install_gtk(s, keyid, gtk, gtklen, f + 65))) goto out;
    s->state = MTK_SUPP_DONE;
    s->renew_snonce = 1;
    rc = MTK_SUPP_OK_DONE;
out:
    mtk_zero(kd, sizeof(kd));
    return rc > 0 ? rc : fail(s, rc);
}

static int rx_g1(struct mtk_supp *s, const uint8_t *f, size_t n, uint16_t info, const uint8_t *replay) {
    if (!s->ptk_set || s->state != MTK_SUPP_DONE) return fail(s, MTK_SUPP_DROP);
    if (!mic_ok(s->ptk, f, n)) return fail(s, MTK_SUPP_ERR_MIC);
    memcpy(s->rx_replay, replay, 8);
    s->rx_replay_set = 1;
    s->g1++;
    if (!(info & MTK_KI_ENCRYPTED)) return fail(s, MTK_SUPP_ERR_KEYDATA);
    size_t dlen = be16(f + 97);
    uint8_t kd[MTK_EAPOL_MAX];
    if (dlen < 24 || dlen % 8 || dlen > sizeof(kd) + 8 || MTK_EAPOL_HDR + dlen > n) return fail(s, MTK_SUPP_ERR_KEYDATA);
    if (mtk_aes128_unwrap(s->ptk + 16, f + MTK_EAPOL_HDR, dlen, kd)) return fail(s, MTK_SUPP_ERR_KEYDATA);
    const uint8_t *rsn, *gtk;
    size_t rsnlen, gtklen;
    int keyid, rc;
    if (parse_kd(kd, dlen - 8, &rsn, &rsnlen, &gtk, &gtklen, &keyid) || !gtk || !gtk_len_ok(gtklen)) {
        rc = MTK_SUPP_ERR_KEYDATA;
        goto out;
    }
    if ((rc = install_gtk(s, keyid, gtk, gtklen, f + 65))) goto out;
    {
        uint8_t out[MTK_EAPOL_HDR];
        size_t on = build(s, out, 0x0100 | MTK_KI_SECURE | 2, replay, NULL, NULL, 0);
        if ((rc = send_signed(s, out, on, s->ptk, 1))) goto out;
        s->g2++;
    }
    rc = MTK_SUPP_OK_GTK;
out:
    mtk_zero(kd, sizeof(kd));
    return rc > 0 ? rc : fail(s, rc);
}

int mtk_supp_rx(struct mtk_supp *s, const uint8_t *f, size_t len) {
    if (s->state == MTK_SUPP_IDLE) return MTK_SUPP_DROP;
    if (len < MTK_EAPOL_HDR || f[1] != 3) return fail(s, MTK_SUPP_ERR_FORMAT);
    size_t n = (size_t)4 + be16(f + 2);                     // the frame without trailing padding
    if (n > len || n < MTK_EAPOL_HDR || n > MTK_EAPOL_MAX) return fail(s, MTK_SUPP_ERR_FORMAT);
    if (f[4] != 2) return fail(s, MTK_SUPP_ERR_FORMAT);     // RSN descriptor only
    if ((size_t)MTK_EAPOL_HDR + be16(f + 97) > n) return fail(s, MTK_SUPP_ERR_FORMAT);
    uint16_t info = be16(f + 5);
    if ((info & MTK_KI_VER_MASK) != 2) return fail(s, MTK_SUPP_ERR_FORMAT);   // HMAC-SHA1 MIC, AES key wrap
    if (!(info & MTK_KI_ACK) || (info & (MTK_KI_REQUEST | MTK_KI_ERROR))) return fail(s, MTK_SUPP_DROP);
    const uint8_t *replay = f + 9;
    if (s->rx_replay_set && memcmp(replay, s->rx_replay, 8) <= 0) return fail(s, MTK_SUPP_ERR_REPLAY);
    s->eapol_ver = (f[0] >= 1 && f[0] <= 2) ? f[0] : 2;

    if (info & MTK_KI_PAIRWISE) {
        if (!(info & MTK_KI_MIC) && !(info & MTK_KI_INSTALL)) return rx_m1(s, f, replay);
        if ((info & (MTK_KI_MIC | MTK_KI_INSTALL)) == (MTK_KI_MIC | MTK_KI_INSTALL)) return rx_m3(s, f, n, info, replay);
        return fail(s, MTK_SUPP_DROP);
    }
    if ((info & (MTK_KI_MIC | MTK_KI_SECURE)) == (MTK_KI_MIC | MTK_KI_SECURE)) return rx_g1(s, f, n, info, replay);
    return fail(s, MTK_SUPP_DROP);
}

// ---------------------------------------------------------------- RSN / WPA element parser

static uint8_t suite_cipher(const uint8_t *s, const uint8_t *oui) {
    if (memcmp(s, oui, 3)) return MTK_CIPHER_OTHER;
    switch (s[3]) {
    case 2: return MTK_CIPHER_TKIP;
    case 4: return MTK_CIPHER_CCMP;
    case 8: case 9: return MTK_CIPHER_GCMP;                 // GCMP-128 / GCMP-256
    default: return MTK_CIPHER_OTHER;
    }
}

static uint8_t suite_akm(const uint8_t *s, const uint8_t *oui) {
    if (memcmp(s, oui, 3)) return MTK_AKM_OTHER;
    switch (s[3]) {
    case 1: case 3: case 5: return MTK_AKM_8021X;          // 802.1X, FT-802.1X, 802.1X-SHA256
    case 2: return MTK_AKM_PSK;                            // PSK (FT-PSK, 4, needs the FT handshake: other)
    case 6: return MTK_AKM_PSK256;
    case 8: case 9: return MTK_AKM_SAE;                    // SAE, FT-SAE
    case 18: return MTK_AKM_OWE;
    default: return MTK_AKM_OTHER;
    }
}

int mtk_rsn_parse(const uint8_t *ie, size_t len, struct mtk_rsn_info *out) {
    static const uint8_t oui_rsn[3] = {0x00, 0x0f, 0xac}, oui_wpa[3] = {0x00, 0x50, 0xf2};
    static const uint8_t wpa_hdr[4] = {0x00, 0x50, 0xf2, 0x01};
    memset(out, 0, sizeof(*out));
    if (len < 2 || (size_t)ie[1] + 2 > len) return -1;
    const uint8_t *p = ie + 2, *end = ie + 2 + ie[1], *oui;
    if (ie[0] == 48) {
        oui = oui_rsn;
        out->kind = MTK_SEC_RSN;
    } else if (ie[0] == 0xdd && ie[1] >= 4 && !memcmp(p, wpa_hdr, 4)) {
        oui = oui_wpa;
        out->kind = MTK_SEC_WPA1;
        p += 4;
    } else {
        return -1;
    }
    if (p + 2 > end) return -1;                             // version
    p += 2;
    out->group = 4;                                         // IEEE 802.11-2020 9.4.2.24: defaults when absent
    out->pairwise = MTK_CIPHER_CCMP;
    out->akm = MTK_AKM_8021X;
    if (p == end) return 0;
    if (p + 4 > end) return -1;
    out->group = memcmp(p, oui, 3) ? 0xff : p[3];
    p += 4;
    if (p == end) return 0;
    if (p + 2 > end) return -1;
    unsigned n = (unsigned)p[0] | (unsigned)p[1] << 8;
    p += 2;
    if (n > 8 || (size_t)(end - p) < 4 * (size_t)n) return -1;
    if (n) out->pairwise = 0;
    for (unsigned i = 0; i < n; i++, p += 4) out->pairwise |= suite_cipher(p, oui);
    if (p == end) return 0;
    if (p + 2 > end) return -1;
    n = (unsigned)p[0] | (unsigned)p[1] << 8;
    p += 2;
    if (n > 8 || (size_t)(end - p) < 4 * (size_t)n) return -1;
    if (n) out->akm = 0;
    for (unsigned i = 0; i < n; i++, p += 4) out->akm |= suite_akm(p, oui);
    if (p == end || out->kind != MTK_SEC_RSN) return 0;
    if (p + 2 > end) return -1;
    out->caps = (uint16_t)(p[0] | p[1] << 8);               // the PMKID list and group management cipher follow
    return 0;
}
