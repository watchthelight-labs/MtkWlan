// <wtl> project: mtkwlan | file: tests/mtk_wpa_test.c | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Host test of MtkCrypto.c and MtkSupp.c (built with the host clang, not the kext flags): published vectors,
// values from the independent Python oracle (tests/oracle.py), and the 4-way / group handshake against a
// simulated authenticator, including the KRACK and replay cases. Run with tests/run.sh.

#include "../src/MtkCrypto.h"
#include "../src/MtkSupp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures, checks;

static void unhex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void expect_hex(const char *name, const uint8_t *got, size_t n, const char *want) {
    uint8_t w[256];
    checks++;
    unhex(want, w, n);
    if (strlen(want) != 2 * n || memcmp(got, w, n)) {
        failures++;
        printf("FAIL %s\n  got  ", name);
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n  want %s\n", want);
    } else {
        printf("ok   %s\n", name);
    }
}

static void expect(const char *name, int cond) {
    checks++;
    if (!cond) failures++;
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
}

static void hexline(const char *name, const uint8_t *p, size_t n) {
    printf("oracle-check %s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

// ---------------------------------------------------------------- crypto vectors

static void test_crypto(void) {
    uint8_t h[64];
    mtk_sha1("abc", 3, h);
    expect_hex("SHA-1 FIPS 180 'abc'", h, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    const char *m2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    mtk_sha1(m2, strlen(m2), h);
    expect_hex("SHA-1 FIPS 180 two-block", h, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    {
        static uint8_t a[1000000];
        memset(a, 'a', sizeof(a));
        mtk_sha1(a, sizeof(a), h);
        expect_hex("SHA-1 FIPS 180 million a", h, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    uint8_t k[80];
    memset(k, 0x0b, 20);
    mtk_hmac_sha1(k, 20, (const uint8_t *)"Hi There", 8, NULL, 0, h);
    expect_hex("HMAC-SHA1 RFC 2202 case 1", h, 20, "b617318655057264e28bc0b6fb378c8ef146be00");
    mtk_hmac_sha1((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya ", 11, (const uint8_t *)"want for nothing?", 17, h);
    expect_hex("HMAC-SHA1 RFC 2202 case 2 (split input)", h, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    memset(k, 0xaa, 80);
    mtk_hmac_sha1(k, 80, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, NULL, 0, h);
    expect_hex("HMAC-SHA1 RFC 2202 case 6 (80-byte key)", h, 20, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

    mtk_pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, h, 20);
    expect_hex("PBKDF2 RFC 6070 c=1", h, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    mtk_pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, h, 20);
    expect_hex("PBKDF2 RFC 6070 c=4096", h, 20, "4b007901b765489abead49d926f721d065a429c1");
    mtk_pbkdf2_sha1((const uint8_t *)"passwordPASSWORDpassword", 24,
                    (const uint8_t *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, h, 25);
    expect_hex("PBKDF2 RFC 6070 c=4096 dkLen 25", h, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");

    mtk_wpa_pmk((const uint8_t *)"password", 8, (const uint8_t *)"IEEE", 4, h);
    expect_hex("PSK IEEE 802.11 Annex J 'password'/'IEEE'", h, 32,
               "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
    hexline("psk1", h, 32);
    mtk_wpa_pmk((const uint8_t *)"ThisIsAPassword", 15, (const uint8_t *)"ThisIsASSID", 11, h);
    expect_hex("PSK IEEE 802.11 Annex J 'ThisIsAPassword'/'ThisIsASSID'", h, 32,
               "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");
    hexline("psk2", h, 32);

    memset(k, 0x0b, 20);
    mtk_prf_sha1(k, 20, "prefix", (const uint8_t *)"Hi There", 8, h, 24);
    expect_hex("PRF-192 IEEE 802.11 Annex J case 1", h, 24, "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606");
    hexline("prf1", h, 24);
    mtk_prf_sha1((const uint8_t *)"Jefe", 4, "prefix-2", (const uint8_t *)"what do ya want for nothing?", 28, h, 32);
    expect_hex("PRF-256 IEEE 802.11 Annex J case 2", h, 32,
               "47c4908e30c947521ad20be9053450ecbea23d3aa604b77326d8b3825ff7475c");
    hexline("prf2", h, 32);
    memset(k, 0xaa, 80);
    mtk_prf_sha1(k, 80, "prefix-3", (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, h, 48);
    expect_hex("PRF-384 IEEE 802.11 Annex J case 3", h, 48,
               "0ab6c33ccf70d0d736f4b04c8a7373255511abc5073713163bd0b8c9eeb7e1956fa066820a73ddee3f6d3bd407e0682a");
    hexline("prf3", h, 48);

    // PTK derivation (address and nonce ordering), checked against the Python oracle
    {
        uint8_t pmk[32], aa[6], spa[6], an[32], sn[32], ptk[48], ptk2[48];
        for (int i = 0; i < 32; i++) { pmk[i] = (uint8_t)i; an[i] = (uint8_t)(i * 7); sn[i] = (uint8_t)(i * 13 + 5); }
        unhex("020000000001", aa, 6);
        unhex("020000000002", spa, 6);
        mtk_wpa_ptk(pmk, aa, spa, an, sn, ptk);
        expect_hex("PTK PRF-384 (oracle)", ptk, 48,
                   "987f3dab2a210d258f739d0cb3d3cd92cd6ed513bf5acc1344f66d63704c5d893aa5092a2c1eb89ca5e36ba696565f1b");
        hexline("ptk", ptk, 48);
        mtk_wpa_ptk(pmk, spa, aa, sn, an, ptk2);            // the same key from the other side
        expect("PTK symmetric in AA/SPA and nonces", !memcmp(ptk, ptk2, 48));
    }
    // EAPOL MIC (HMAC-SHA1-128 over the frame with a zero MIC field), oracle
    {
        uint8_t f[121], kck[16], mic[16];
        for (int i = 0; i < 121; i++) f[i] = (uint8_t)(i * 3 + 1);
        for (int i = 0; i < 16; i++) kck[i] = (uint8_t)i;
        mtk_eapol_mic(kck, f, sizeof(f), 81, mic);
        expect_hex("EAPOL-Key MIC HMAC-SHA1-128 (oracle)", mic, 16, "6e52e670084a9f6c69c5e1f92c96745c");
        hexline("mic", mic, 16);
    }

    // AES-128 FIPS 197 C.1
    {
        uint8_t key[16], pt[16], ct[16], back[16];
        mtk_aes128 a;
        unhex("000102030405060708090a0b0c0d0e0f", key, 16);
        unhex("00112233445566778899aabbccddeeff", pt, 16);
        mtk_aes128_setkey(&a, key);
        mtk_aes128_encrypt(&a, pt, ct);
        expect_hex("AES-128 FIPS 197 C.1 encrypt", ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
        mtk_aes128_decrypt(&a, ct, back);
        expect("AES-128 FIPS 197 C.1 decrypt", !memcmp(back, pt, 16));
    }
    // RFC 3394 4.1 (128-bit KEK, 128-bit key data), 4.2 is AES-192 and out of scope
    {
        uint8_t kek[16], kd[16], w[24], u[16];
        unhex("000102030405060708090a0b0c0d0e0f", kek, 16);
        unhex("00112233445566778899aabbccddeeff", kd, 16);
        expect("RFC 3394 4.1 wrap rc", mtk_aes128_wrap(kek, kd, 16, w) == 0);
        expect_hex("RFC 3394 4.1 wrap", w, 24, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        expect("RFC 3394 4.1 unwrap rc", mtk_aes128_unwrap(kek, w, 24, u) == 0);
        expect_hex("RFC 3394 4.1 unwrap", u, 16, "00112233445566778899aabbccddeeff");
        w[5] ^= 1;
        expect("RFC 3394 unwrap rejects a modified block", mtk_aes128_unwrap(kek, w, 24, u) == -2);
        expect("RFC 3394 unwrap rejects a bad length", mtk_aes128_unwrap(kek, w, 20, u) == -1);
    }
}

// ---------------------------------------------------------------- simulated authenticator

static const uint8_t AA[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, SPA[6] = {0x02, 0x00, 0x79, 0x25, 0x00, 0x01};
static const uint8_t PSK_IE[22] = {0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0};

struct sim {
    uint8_t last[MTK_EAPOL_MAX];
    size_t last_len;
    int last_protect, sends;
    uint8_t tk[16];
    int ptk_installs;
    uint8_t gtk[32], rsc[8];
    size_t gtk_len;
    int gtk_id, gtk_installs;
    int fail_install;
};

static int cb_send(void *c, const uint8_t *f, size_t n, int protect) {
    struct sim *s = c;
    memcpy(s->last, f, n);
    s->last_len = n;
    s->last_protect = protect;
    s->sends++;
    return 0;
}
static int cb_ptk(void *c, const uint8_t tk[16]) {
    struct sim *s = c;
    if (s->fail_install) return -1;
    memcpy(s->tk, tk, 16);
    s->ptk_installs++;
    return 0;
}
static int cb_gtk(void *c, int id, const uint8_t *g, size_t glen, const uint8_t rsc[8]) {
    struct sim *s = c;
    memcpy(s->gtk, g, glen);
    s->gtk_len = glen;
    memcpy(s->rsc, rsc, 8);
    s->gtk_id = id;
    s->gtk_installs++;
    return 0;
}
static void cb_rand(void *c, uint8_t *b, size_t n) {
    static uint8_t x = 0x40;
    (void)c;
    for (size_t i = 0; i < n; i++) b[i] = x++;
}

// authenticator side: builds key frames like hostapd does (descriptor 2, version 2)
static size_t ap_frame(uint8_t *f, uint16_t info, uint64_t replay, const uint8_t *anonce, const uint8_t *rsc,
                       const uint8_t *kd, size_t kdlen, const uint8_t *kck, const uint8_t *kek) {
    memset(f, 0, MTK_EAPOL_HDR);
    f[0] = 2; f[1] = 3; f[4] = 2;
    f[5] = (uint8_t)(info >> 8); f[6] = (uint8_t)info;
    f[8] = 16;                                              // key length 16 (CCMP) in message 1 / 3
    for (int i = 0; i < 8; i++) f[9 + i] = (uint8_t)(replay >> (56 - 8 * i));
    if (anonce) memcpy(f + 17, anonce, 32);
    if (rsc) memcpy(f + 65, rsc, 8);
    size_t dl = 0;
    if (kd && kek) {
        uint8_t pad[512];
        size_t pl = kdlen;
        memcpy(pad, kd, kdlen);
        if (pl % 8 || pl < 16) { pad[pl++] = 0xdd; while (pl % 8 || pl < 16) pad[pl++] = 0; }
        mtk_aes128_wrap(kek, pad, pl, f + MTK_EAPOL_HDR);
        dl = pl + 8;
    } else if (kd) {
        memcpy(f + MTK_EAPOL_HDR, kd, kdlen);
        dl = kdlen;
    }
    f[97] = (uint8_t)(dl >> 8); f[98] = (uint8_t)dl;
    size_t n = MTK_EAPOL_HDR + dl;
    f[2] = (uint8_t)((n - 4) >> 8); f[3] = (uint8_t)(n - 4);
    if (kck) { uint8_t mic[16]; mtk_eapol_mic(kck, f, n, MTK_EAPOL_MIC, mic); memcpy(f + MTK_EAPOL_MIC, mic, 16); }
    return n;
}

static size_t gtk_kd_n(uint8_t *kd, int with_rsn, const uint8_t *ie, size_t ielen, int keyid, const uint8_t *gtk,
                       size_t gtklen) {
    size_t n = 0;
    if (with_rsn) { memcpy(kd, ie, ielen); n = ielen; }
    kd[n++] = 0xdd; kd[n++] = (uint8_t)(6 + gtklen); kd[n++] = 0x00; kd[n++] = 0x0f; kd[n++] = 0xac; kd[n++] = 1;
    kd[n++] = (uint8_t)keyid; kd[n++] = 0;
    memcpy(kd + n, gtk, gtklen);
    return n + gtklen;
}

static size_t gtk_kd(uint8_t *kd, int with_rsn, const uint8_t *ie, size_t ielen, int keyid, const uint8_t *gtk) {
    return gtk_kd_n(kd, with_rsn, ie, ielen, keyid, gtk, 16);
}

static int ap_mic_ok(const uint8_t *kck, const uint8_t *f, size_t n) {
    uint8_t mic[16];
    mtk_eapol_mic(kck, f, n, MTK_EAPOL_MIC, mic);
    return !memcmp(mic, f + MTK_EAPOL_MIC, 16);
}

static void test_handshake(void) {
    struct sim sim;
    struct mtk_supp s;
    struct mtk_supp_ops ops = {&sim, cb_send, cb_ptk, cb_gtk, cb_rand};
    uint8_t pmk[32], anonce[32], ptk[48], f[MTK_EAPOL_MAX], kd[128], gtk1[16], gtk2[16], rsc[8] = {5, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ie[22];
    size_t n;
    memset(&sim, 0, sizeof(sim));
    mtk_wpa_pmk((const uint8_t *)"correct horse", 13, (const uint8_t *)"LegionTest", 10, pmk);
    for (int i = 0; i < 32; i++) anonce[i] = (uint8_t)(0xa0 + i);
    for (int i = 0; i < 16; i++) { gtk1[i] = (uint8_t)(0x10 + i); gtk2[i] = (uint8_t)(0x80 + i); }
    expect("own RSN element (PSK, CCMP)", mtk_rsn_ie_psk(ie, 4) == 22 && !memcmp(ie, PSK_IE, 22));
    mtk_supp_init(&s, &ops, pmk, AA, SPA, ie, 22, PSK_IE, 22);

    // message 1 -> message 2
    n = ap_frame(f, 0x008a, 1, anonce, NULL, NULL, 0, NULL, NULL);
    expect("msg1 answered", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_M2);
    expect("msg2 sent in the clear", sim.sends == 1 && !sim.last_protect);
    uint8_t snonce[32];
    memcpy(snonce, sim.last + 17, 32);
    mtk_wpa_ptk(pmk, AA, SPA, anonce, snonce, ptk);
    expect("msg2 MIC verifies at the AP", ap_mic_ok(ptk, sim.last, sim.last_len));
    expect("msg2 key info 0x010a, replay 1", sim.last[5] == 0x01 && sim.last[6] == 0x0a && sim.last[16] == 1);
    expect("msg2 carries our RSN element", sim.last[98] == 22 && !memcmp(sim.last + 99, PSK_IE, 22));

    // wrong passphrase: the AP's MIC check fails
    {
        uint8_t bad[32], bptk[48];
        mtk_wpa_pmk((const uint8_t *)"wrong horse", 11, (const uint8_t *)"LegionTest", 10, bad);
        mtk_wpa_ptk(bad, AA, SPA, anonce, snonce, bptk);
        expect("msg2 from a wrong PMK fails at the AP", !ap_mic_ok(bptk, sim.last, sim.last_len));
    }

    // retransmitted message 1 (same ANonce, higher counter): same SNonce, still waiting for message 3
    n = ap_frame(f, 0x008a, 2, anonce, NULL, NULL, 0, NULL, NULL);
    expect("msg1 retransmit answered", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_M2 && !memcmp(sim.last + 17, snonce, 32));

    // message 3 with a bad MIC: dropped, counter not advanced
    size_t kl = gtk_kd(kd, 1, PSK_IE, 22, 1, gtk1);
    n = ap_frame(f, 0x13ca, 3, anonce, rsc, kd, kl, ptk, ptk + 16);
    f[MTK_EAPOL_MIC] ^= 0x55;
    expect("msg3 with a bad MIC rejected", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_MIC && sim.ptk_installs == 0);
    expect("no reply to a bad msg3", sim.sends == 2);

    // message 3 with a different ANonce: dropped
    {
        uint8_t other[32];
        memcpy(other, anonce, 32);
        other[0] ^= 1;
        n = ap_frame(f, 0x13ca, 3, other, rsc, kd, kl, ptk, ptk + 16);
        expect("msg3 with another ANonce dropped", mtk_supp_rx(&s, f, n) == MTK_SUPP_DROP && sim.ptk_installs == 0);
    }

    // message 3 whose RSN element differs from the beacon (downgrade): error, no key
    {
        uint8_t ie2[22];
        memcpy(ie2, PSK_IE, 22);
        ie2[13] = 2;                                        // pairwise TKIP
        size_t l2 = gtk_kd(kd, 1, ie2, 22, 1, gtk1);
        n = ap_frame(f, 0x13ca, 3, anonce, rsc, kd, l2, ptk, ptk + 16);
        struct mtk_supp copy = s;
        expect("msg3 with a different RSN element rejected", mtk_supp_rx(&copy, f, n) == MTK_SUPP_ERR_IE &&
                                                              sim.ptk_installs == 0);
    }

    // valid message 3 -> message 4, then PTK and GTK
    kl = gtk_kd(kd, 1, PSK_IE, 22, 1, gtk1);
    n = ap_frame(f, 0x13ca, 3, anonce, rsc, kd, kl, ptk, ptk + 16);
    int sends = sim.sends;
    expect("msg3 accepted", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_DONE);
    expect("msg4 sent before install, in the clear", sim.sends == sends + 1 && !sim.last_protect);
    expect("msg4 key info 0x030a, replay 3", sim.last[5] == 0x03 && sim.last[6] == 0x0a && sim.last[16] == 3);
    expect("msg4 MIC verifies at the AP", ap_mic_ok(ptk, sim.last, sim.last_len));
    expect("PTK installed once, TK = PTK[32..47]", sim.ptk_installs == 1 && !memcmp(sim.tk, ptk + 32, 16));
    expect("GTK installed with key id 1 and RSC", sim.gtk_installs == 1 && sim.gtk_id == 1 && !memcmp(sim.gtk, gtk1, 16) &&
                                                   sim.rsc[0] == 5);

    // KRACK: retransmitted message 3 (higher counter) gets message 4 again, keys are not reinstalled
    n = ap_frame(f, 0x13ca, 4, anonce, rsc, kd, kl, ptk, ptk + 16);
    sends = sim.sends;
    expect("retransmitted msg3 answered", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_DONE && sim.sends == sends + 1);
    expect("no PTK / GTK reinstallation (KRACK)", sim.ptk_installs == 1 && sim.gtk_installs == 1 &&
                                                  s.reinstall_skipped == 2);
    // replay of that message 3 (same counter): dropped
    expect("replayed msg3 dropped", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_REPLAY && sim.sends == sends + 1);
    // stale message 1 (counter below the verified one): dropped
    n = ap_frame(f, 0x008a, 2, anonce, NULL, NULL, 0, NULL, NULL);
    expect("stale msg1 dropped", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_REPLAY);

    // group key handshake: new GTK, key id 2
    kl = gtk_kd(kd, 0, NULL, 0, 2, gtk2);
    uint8_t rsc2[8] = {0x10, 0x20, 0, 0, 0, 0, 0, 0};
    n = ap_frame(f, 0x1382, 5, NULL, rsc2, kd, kl, ptk, ptk + 16);
    sends = sim.sends;
    expect("group msg1 accepted", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_GTK);
    expect("new GTK installed", sim.gtk_installs == 2 && sim.gtk_id == 2 && !memcmp(sim.gtk, gtk2, 16) && sim.rsc[1] == 0x20);
    expect("group msg2 sent under the PTK", sim.sends == sends + 1 && sim.last_protect);
    expect("group msg2 key info 0x0302 and MIC", sim.last[5] == 0x03 && sim.last[6] == 0x02 &&
                                                 ap_mic_ok(ptk, sim.last, sim.last_len));
    expect("replayed group msg1 dropped", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_REPLAY && sim.gtk_installs == 2);
    n = ap_frame(f, 0x1382, 6, NULL, rsc2, kd, kl, ptk, ptk + 16);
    expect("same GTK again: answered, not reinstalled", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_GTK && sim.gtk_installs == 2);
    n = ap_frame(f, 0x1382, 7, NULL, rsc2, kd, kl, ptk, ptk + 16);
    f[MTK_EAPOL_MIC + 3] ^= 1;
    expect("group msg1 with a bad MIC rejected", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_MIC);

    // group key handshake with a 32-byte TKIP group key (WPA/WPA2 mixed router), key id 1
    {
        uint8_t tgtk[32];
        for (int i = 0; i < 32; i++) tgtk[i] = (uint8_t)(0xc0 + i);
        kl = gtk_kd_n(kd, 0, NULL, 0, 1, tgtk, 32);
        n = ap_frame(f, 0x1382, 8, NULL, rsc2, kd, kl, ptk, ptk + 16);
        sends = sim.sends;
        expect("group msg1 with a 32-byte GTK accepted", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_GTK && sim.sends == sends + 1);
        expect("32-byte GTK installed as given", sim.gtk_installs == 3 && sim.gtk_id == 1 && sim.gtk_len == 32 &&
                                                 !memcmp(sim.gtk, tgtk, 32));
        uint8_t odd[24] = {0};
        kl = gtk_kd_n(kd, 0, NULL, 0, 1, odd, 24);
        n = ap_frame(f, 0x1382, 9, NULL, rsc2, kd, kl, ptk, ptk + 16);
        expect("24-byte GTK rejected", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_KEYDATA && sim.gtk_installs == 3);
    }

    // PTK rekey: a new message 1 after the handshake uses a new SNonce and goes out under the old PTK
    uint8_t anonce2[32];
    for (int i = 0; i < 32; i++) anonce2[i] = (uint8_t)(0x30 + i);
    n = ap_frame(f, 0x008a, 10, anonce2, NULL, NULL, 0, NULL, NULL);
    expect("rekey msg1 answered", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_M2);
    expect("rekey: new SNonce, protected msg2", memcmp(sim.last + 17, snonce, 32) && sim.last_protect);
    uint8_t ptk2[48];
    mtk_wpa_ptk(pmk, AA, SPA, anonce2, sim.last + 17, ptk2);
    kl = gtk_kd(kd, 1, PSK_IE, 22, 2, gtk2);
    n = ap_frame(f, 0x13ca, 11, anonce2, rsc2, kd, kl, ptk2, ptk2 + 16);
    expect("rekey msg3 accepted", mtk_supp_rx(&s, f, n) == MTK_SUPP_OK_DONE);
    expect("rekey: new TK installed, msg4 under the old PTK", sim.ptk_installs == 2 && !memcmp(sim.tk, ptk2 + 32, 16) &&
                                                               sim.last_protect);

    // format checks
    expect("short frame rejected", mtk_supp_rx(&s, f, 50) == MTK_SUPP_ERR_FORMAT);
    n = ap_frame(f, 0x0089, 12, anonce, NULL, NULL, 0, NULL, NULL);   // descriptor version 1 (TKIP)
    expect("descriptor version 1 rejected", mtk_supp_rx(&s, f, n) == MTK_SUPP_ERR_FORMAT);

    mtk_supp_clear(&s);
    int zero = 1;
    for (size_t i = 0; i < sizeof(s); i++) if (((uint8_t *)&s)[i]) zero = 0;
    expect("clear zeroes every key", zero);
}

// ---------------------------------------------------------------- RSN / WPA element parser

static void test_rsn(void) {
    struct mtk_rsn_info r;
    // WPA2-PSK, CCMP only (the element we send ourselves)
    expect("rsn: WPA2-PSK CCMP", mtk_rsn_parse(PSK_IE, 22, &r) == 0 && r.kind == MTK_SEC_RSN && r.akm == MTK_AKM_PSK &&
                                   r.pairwise == MTK_CIPHER_CCMP && r.group == 4 && r.caps == 0);
    // WPA/WPA2 mixed: group TKIP, pairwise CCMP + TKIP, AKM PSK, capabilities 0x000c (replay counters)
    static const uint8_t mixed[] = {0x30, 24, 1, 0, 0, 0x0f, 0xac, 2, 2, 0, 0, 0x0f, 0xac, 4, 0, 0x0f, 0xac, 2,
                                    1, 0, 0, 0x0f, 0xac, 2, 0x0c, 0};
    expect("rsn: mixed TKIP group", mtk_rsn_parse(mixed, sizeof(mixed), &r) == 0 && r.group == 2 &&
                                      r.pairwise == (MTK_CIPHER_CCMP | MTK_CIPHER_TKIP) && r.akm == MTK_AKM_PSK && r.caps == 0x0c);
    // WPA3-SAE only with PMF required (caps MFPC | MFPR)
    static const uint8_t sae[] = {0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xc0, 0};
    expect("rsn: SAE only, MFP required", mtk_rsn_parse(sae, sizeof(sae), &r) == 0 && r.akm == MTK_AKM_SAE &&
                                            (r.caps & MTK_RSN_CAP_MFPR) && (r.caps & MTK_RSN_CAP_MFPC));
    // WPA2/WPA3 transition: PSK + SAE, MFP capable only
    static const uint8_t trans[] = {0x30, 24, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 2, 0, 0, 0x0f, 0xac, 2,
                                    0, 0x0f, 0xac, 8, 0x80, 0};
    expect("rsn: transition PSK + SAE, MFP capable", mtk_rsn_parse(trans, sizeof(trans), &r) == 0 &&
                                                       r.akm == (MTK_AKM_PSK | MTK_AKM_SAE) && r.caps == MTK_RSN_CAP_MFPC);
    // PSK-SHA256 only (descriptor version 3, not supported by MtkSupp)
    static const uint8_t psk256[] = {0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 6, 0, 0};
    expect("rsn: PSK-SHA256 only", mtk_rsn_parse(psk256, sizeof(psk256), &r) == 0 && r.akm == MTK_AKM_PSK256);
    // 802.1X enterprise
    static const uint8_t ent[] = {0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 1, 0, 0};
    expect("rsn: 802.1X", mtk_rsn_parse(ent, sizeof(ent), &r) == 0 && r.akm == MTK_AKM_8021X);
    // version only: IEEE defaults
    static const uint8_t ver[] = {0x30, 2, 1, 0};
    expect("rsn: defaults when fields are absent", mtk_rsn_parse(ver, sizeof(ver), &r) == 0 && r.group == 4 &&
                                                     r.pairwise == MTK_CIPHER_CCMP && r.akm == MTK_AKM_8021X);
    // WPA1 vendor element: group TKIP, pairwise CCMP, AKM PSK
    static const uint8_t wpa1[] = {0xdd, 22, 0x00, 0x50, 0xf2, 1, 1, 0, 0x00, 0x50, 0xf2, 2, 1, 0, 0x00, 0x50, 0xf2, 4,
                                   1, 0, 0x00, 0x50, 0xf2, 2};
    expect("wpa1: vendor element", mtk_rsn_parse(wpa1, sizeof(wpa1), &r) == 0 && r.kind == MTK_SEC_WPA1 && r.group == 2 &&
                                     r.pairwise == MTK_CIPHER_CCMP && r.akm == MTK_AKM_PSK && r.caps == 0);
    // malformed: pairwise count runs past the end; truncated buffer; not an RSN element
    static const uint8_t bad1[] = {0x30, 12, 1, 0, 0, 0x0f, 0xac, 4, 9, 0, 0, 0x0f, 0xac, 4};
    expect("rsn: oversized suite count rejected", mtk_rsn_parse(bad1, sizeof(bad1), &r) == -1);
    expect("rsn: truncated buffer rejected", mtk_rsn_parse(PSK_IE, 10, &r) == -1);
    static const uint8_t notrsn[] = {0x00, 4, 'a', 'b', 'c', 'd'};
    expect("rsn: other element rejected", mtk_rsn_parse(notrsn, sizeof(notrsn), &r) == -1);
}

int main(void) {
    test_crypto();
    test_handshake();
    test_rsn();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
