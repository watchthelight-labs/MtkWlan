// <wtl> project: mtkwlan | file: src/MtkSupp.h | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC AND BSD-3-Clause-Clear
// WPA2-PSK (RSN, AKM 00-0F-AC:2, CCMP, EAPOL-Key descriptor version 2) supplicant state machine: the 4-way
// handshake and the group key handshake, with no OS calls. The kext glue (MtkSec.cpp) feeds it received
// EAPOL-Key frames and gives it callbacks to send EAPOL and to install keys; tests/mtk_supp_test.c drives it
// against a simulated authenticator.
//
// Frame handling started from m3Handshake in itlmt7925 (github.com/thanhnndev/ga403wm-hackintosh,
// kexts/itlmt7925/itlmt7925_m3.cpp, commit 8f0ff67; Copyright (c) 2026 thanhnndev and contributors, The Clear
// BSD License, notice in MtkCrypto.h), restructured as an event-driven machine and checked against the rules of
// IEEE 802.11-2020 12.7.6 and hostap's wpa_supplicant (src/rsn_supp/wpa.c), from the spec text and memory:
//   - an EAPOL-Key frame is dropped unless its replay counter is larger than the last one received in a frame
//     whose MIC verified (rx_replay is only updated after a MIC check)
//   - message 3: the ANonce must equal message 1's, the MIC must verify with the temporary PTK, the RSN element
//     in the key data must equal the AP's beacon / probe response element (downgrade check), and only then does
//     the temporary PTK become the PTK
//   - message 4 is sent before the PTK is installed; a key equal to the one installed is never installed again
//     (KRACK, CVE-2017-13077/13080): retransmitted message 3 or group message 1 only gets its reply
//   - one SNonce per handshake; a new one after a completed handshake
//   - the GTK comes wrapped (AES key wrap with the KEK) in a GTK KDE; its RSC seeds the group replay counter

#ifndef MTK_SUPP_H
#define MTK_SUPP_H

#include <stdint.h>
#include <stddef.h>
#include "MtkUserApi.h"          // MTK_SEC_* / MTK_AKM_* / MTK_CIPHER_* values used by mtk_rsn_parse

#ifdef __cplusplus
extern "C" {
#endif

// EAPOL-Key key information bits (IEEE 802.11-2020 Figure 12-33)
#define MTK_KI_VER_MASK  0x0007
#define MTK_KI_PAIRWISE  0x0008
#define MTK_KI_INSTALL   0x0040
#define MTK_KI_ACK       0x0080
#define MTK_KI_MIC       0x0100
#define MTK_KI_SECURE    0x0200
#define MTK_KI_ERROR     0x0400
#define MTK_KI_REQUEST   0x0800
#define MTK_KI_ENCRYPTED 0x1000

#define MTK_EAPOL_HDR    99      // EAPOL header (4) + key descriptor up to and including Key Data Length
#define MTK_EAPOL_MIC    81      // offset of the Key MIC field
#define MTK_EAPOL_MAX    600     // largest EAPOL-Key frame handled

struct mtk_supp_ops {
    void *ctx;
    // send one EAPOL frame to the AP (ethertype 0x888E); protect = encrypt with the installed PTK
    int (*send_eapol)(void *ctx, const uint8_t *frame, size_t len, int protect);
    // install the pairwise temporal key (CCMP, 16 bytes, key id 0). 0 on success.
    int (*install_ptk)(void *ctx, const uint8_t tk[16]);
    // install the group key: 16 bytes (CCMP) or 32 bytes (TKIP: TK | TX MIC | RX MIC as the AP sends it);
    // rsc = Key RSC (little endian PN, 6 bytes used). 0 on success.
    int (*install_gtk)(void *ctx, int keyid, const uint8_t *gtk, size_t gtklen, const uint8_t rsc[8]);
    // fill buf with n random bytes (SNonce)
    void (*random)(void *ctx, uint8_t *buf, size_t n);
};

enum mtk_supp_state { MTK_SUPP_IDLE = 0, MTK_SUPP_WAIT_M1, MTK_SUPP_WAIT_M3, MTK_SUPP_DONE };

// Results of mtk_supp_rx
enum {
    MTK_SUPP_OK_M2 = 1,         // message 1 answered with message 2
    MTK_SUPP_OK_DONE = 2,       // message 3 verified, message 4 sent, keys installed (or already installed)
    MTK_SUPP_OK_GTK = 3,        // group key handshake done
    MTK_SUPP_DROP = 0,          // not for us / unexpected in this state (ignored)
    MTK_SUPP_ERR_FORMAT = -1,
    MTK_SUPP_ERR_REPLAY = -2,
    MTK_SUPP_ERR_MIC = -3,
    MTK_SUPP_ERR_IE = -4,       // RSN element in message 3 differs from the beacon: deauthenticate
    MTK_SUPP_ERR_KEYDATA = -5,
    MTK_SUPP_ERR_INSTALL = -6,
    MTK_SUPP_ERR_SEND = -7,
};

struct mtk_supp {
    struct mtk_supp_ops ops;
    int state;
    uint8_t pmk[32];
    uint8_t aa[6], spa[6];
    uint8_t own_ie[64];          // our RSN element, as in the association request
    size_t own_ie_len;
    uint8_t ap_ie[258];          // the AP's RSN element from its beacon / probe response
    size_t ap_ie_len;
    uint8_t snonce[32], anonce[32];
    int renew_snonce;
    uint8_t tptk[48];            // temporary PTK from the latest message 1
    int tptk_set;
    uint8_t ptk[48];             // KCK | KEK | TK after message 3 verified
    int ptk_set;
    uint8_t rx_replay[8];
    int rx_replay_set;
    uint8_t tk_inst[16];         // installed TK and GTK, compared before any install (no reinstallation)
    int tk_installed;
    uint8_t gtk_inst[32];
    size_t gtk_len;
    int gtk_installed, gtk_id;
    uint8_t eapol_ver;           // EAPOL protocol version to answer with (the AP's, at most 2)
    // counters
    uint32_t m1, m2, m3, m4, g1, g2, bad_mic, replays, dropped, reinstall_skipped, ptk_installs, gtk_installs;
    int last_error;
};

// own_ie / ap_ie are complete elements (tag 48, length, body)
void mtk_supp_init(struct mtk_supp *s, const struct mtk_supp_ops *ops, const uint8_t pmk[32], const uint8_t aa[6],
                   const uint8_t spa[6], const uint8_t *own_ie, size_t own_ie_len, const uint8_t *ap_ie,
                   size_t ap_ie_len);
// One received EAPOL frame (version byte first, len = bytes after the LLC/SNAP header)
int mtk_supp_rx(struct mtk_supp *s, const uint8_t *eapol, size_t len);
// Forget every key and nonce
void mtk_supp_clear(struct mtk_supp *s);

// Build our RSN element for a WPA2-PSK CCMP association: version 1, group cipher `group` (00-0F-AC:group),
// pairwise CCMP, AKM PSK, RSN capabilities 0. Returns its length (22).
size_t mtk_rsn_ie_psk(uint8_t *out, uint8_t group);

// What an AP's RSN element (tag 48) or WPA vendor element (dd 00 50 f2 01) offers, as MtkUserApi.h bitmaps
struct mtk_rsn_info {
    uint8_t kind;                // MTK_SEC_RSN or MTK_SEC_WPA1
    uint8_t akm;                 // MTK_AKM_* bits
    uint8_t pairwise;            // MTK_CIPHER_* bits
    uint8_t group;               // group cipher suite type (2 TKIP, 4 CCMP, ...), 0xff = unknown OUI
    uint16_t caps;               // RSN capabilities (bit 6 MFPR, bit 7 MFPC); 0 for WPA1
};
#define MTK_RSN_CAP_MFPR 0x0040
#define MTK_RSN_CAP_MFPC 0x0080
// ie = the whole element (tag, length, body), len = bytes available. Returns 0, or -1 when it is not an RSN /
// WPA element or a suite count runs past its end. Missing trailing fields take the IEEE defaults
// (group and pairwise CCMP, AKM 802.1X, capabilities 0).
int mtk_rsn_parse(const uint8_t *ie, size_t len, struct mtk_rsn_info *out);

#ifdef __cplusplus
}
#endif

#endif
