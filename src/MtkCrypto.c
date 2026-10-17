// <wtl> project: mtkwlan | file: src/MtkCrypto.c | author: watchthelight </wtl>
// SPDX-License-Identifier: BSD-3-Clause-Clear
// See MtkCrypto.h. Adapted from itl_wpa.cpp of itlmt7925 (github.com/thanhnndev/ga403wm-hackintosh, commit 8f0ff67),
// Copyright (c) 2026 thanhnndev and contributors, The Clear BSD License (full notice in MtkCrypto.h).
// Checked by tests/mtk_crypto_test.c against FIPS 180 (SHA-1), RFC 2202 (HMAC-SHA1), RFC 6070 (PBKDF2),
// IEEE 802.11-2020 Annex J (PSK and PRF vectors), FIPS 197 (AES-128) and RFC 3394 (key wrap).

#include "MtkCrypto.h"
#include <string.h>

// ---------------------------------------------------------------- SHA-1 (FIPS 180-4)

static inline uint32_t rol32(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

static void sha1_block(uint32_t h[5], const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 80; i++) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                   k = 0xca62c1d6; }
        uint32_t t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    mtk_zero(w, sizeof(w));
}

void mtk_sha1_init(mtk_sha1_ctx *c) {
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89; c->h[2] = 0x98badcfe; c->h[3] = 0x10325476; c->h[4] = 0xc3d2e1f0;
    c->len = 0;
    c->n = 0;
}

void mtk_sha1_update(mtk_sha1_ctx *c, const void *d, size_t n) {
    const uint8_t *p = (const uint8_t *)d;
    c->len += n;
    while (n) {
        size_t k = 64 - c->n;
        if (k > n) k = n;
        memcpy(c->buf + c->n, p, k);
        c->n += (uint32_t)k;
        p += k;
        n -= k;
        if (c->n == 64) { sha1_block(c->h, c->buf); c->n = 0; }
    }
}

void mtk_sha1_final(mtk_sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80, lb[8];
    mtk_sha1_update(c, &pad, 1);
    pad = 0;
    while (c->n != 56) mtk_sha1_update(c, &pad, 1);
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    mtk_sha1_update(c, lb, 8);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
    mtk_zero(c, sizeof(*c));
}

void mtk_sha1(const void *d, size_t n, uint8_t out[20]) {
    mtk_sha1_ctx c;
    mtk_sha1_init(&c);
    mtk_sha1_update(&c, d, n);
    mtk_sha1_final(&c, out);
}

// ---------------------------------------------------------------- HMAC, PBKDF2, PRF

void mtk_hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2,
                   uint8_t out[20]) {
    uint8_t k[64], pad[64], inner[20];
    mtk_sha1_ctx c;
    memset(k, 0, sizeof(k));
    if (klen > 64) mtk_sha1(key, klen, k);
    else if (klen) memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    mtk_sha1_init(&c);
    mtk_sha1_update(&c, pad, 64);
    if (n1) mtk_sha1_update(&c, d1, n1);
    if (n2) mtk_sha1_update(&c, d2, n2);
    mtk_sha1_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    mtk_sha1_init(&c);
    mtk_sha1_update(&c, pad, 64);
    mtk_sha1_update(&c, inner, 20);
    mtk_sha1_final(&c, out);
    mtk_zero(k, sizeof(k));
    mtk_zero(pad, sizeof(pad));
    mtk_zero(inner, sizeof(inner));
}

void mtk_pbkdf2_sha1(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out,
                     size_t olen) {
    for (uint32_t blk = 1; olen; blk++) {
        uint8_t ctr[4] = {(uint8_t)(blk >> 24), (uint8_t)(blk >> 16), (uint8_t)(blk >> 8), (uint8_t)blk};
        uint8_t u[20], t[20];
        mtk_hmac_sha1(pass, plen, salt, slen, ctr, 4, u);
        memcpy(t, u, 20);
        for (uint32_t i = 1; i < iter; i++) {
            mtk_hmac_sha1(pass, plen, u, 20, NULL, 0, u);
            for (int j = 0; j < 20; j++) t[j] ^= u[j];
        }
        size_t k = olen < 20 ? olen : 20;
        memcpy(out, t, k);
        out += k;
        olen -= k;
        mtk_zero(u, sizeof(u));
        mtk_zero(t, sizeof(t));
    }
}

int mtk_prf_sha1(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen, uint8_t *out,
                 size_t olen) {
    uint8_t buf[160];
    size_t ll = strlen(label);
    if (ll + 1 + dlen + 1 > sizeof(buf)) return -1;
    memcpy(buf, label, ll);
    buf[ll] = 0;
    memcpy(buf + ll + 1, data, dlen);
    size_t m = ll + 1 + dlen;
    for (uint8_t i = 0; olen; i++) {
        uint8_t h[20];
        buf[m] = i;
        mtk_hmac_sha1(key, klen, buf, m + 1, NULL, 0, h);
        size_t k = olen < 20 ? olen : 20;
        memcpy(out, h, k);
        out += k;
        olen -= k;
        mtk_zero(h, sizeof(h));
    }
    mtk_zero(buf, sizeof(buf));
    return 0;
}

// ---------------------------------------------------------------- AES-128 (FIPS 197)
// The S-box is computed from its definition (multiplicative inverse in GF(2^8) + affine map), not typed in.

static uint8_t g_sbox[256], g_isbox[256];
static volatile int g_aes_ready;

static inline uint8_t xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static inline uint8_t rol8(uint8_t x, int s) { return (uint8_t)((x << s) | (x >> (8 - s))); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xt(a);
        b >>= 1;
    }
    return r;
}

static void aes_tables(void) {
    if (g_aes_ready) return;
    // p walks the powers of the generator 3, q the powers of its inverse, so q = p^-1 at every step
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ xt(p));
        q ^= (uint8_t)(q << 1);
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        g_sbox[p] = (uint8_t)(q ^ rol8(q, 1) ^ rol8(q, 2) ^ rol8(q, 3) ^ rol8(q, 4) ^ 0x63);
    } while (p != 1);
    g_sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) g_isbox[g_sbox[i]] = (uint8_t)i;
    g_aes_ready = 1;
}

void mtk_aes128_setkey(mtk_aes128 *k, const uint8_t key[16]) {
    aes_tables();
    memcpy(k->rk, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, k->rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t a = t[0];
            t[0] = (uint8_t)(g_sbox[t[1]] ^ rcon);
            t[1] = g_sbox[t[2]];
            t[2] = g_sbox[t[3]];
            t[3] = g_sbox[a];
            rcon = xt(rcon);
        }
        for (int j = 0; j < 4; j++) k->rk[i + j] = (uint8_t)(k->rk[i - 16 + j] ^ t[j]);
    }
}

// state s[c * 4 + row], column major as in FIPS 197
void mtk_aes128_encrypt(const mtk_aes128 *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ k->rk[i];
    for (int r = 1; r <= 10; r++) {
        for (int c = 0; c < 4; c++)                         // SubBytes + ShiftRows (row r moves left by r)
            for (int row = 0; row < 4; row++) t[c * 4 + row] = g_sbox[s[((c + row) & 3) * 4 + row]];
        if (r < 10) {                                       // MixColumns
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3];
                s[c * 4]     = (uint8_t)(xt(a0) ^ (xt(a1) ^ a1) ^ a2 ^ a3);
                s[c * 4 + 1] = (uint8_t)(a0 ^ xt(a1) ^ (xt(a2) ^ a2) ^ a3);
                s[c * 4 + 2] = (uint8_t)(a0 ^ a1 ^ xt(a2) ^ (xt(a3) ^ a3));
                s[c * 4 + 3] = (uint8_t)((xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3));
            }
        } else {
            memcpy(s, t, 16);
        }
        for (int i = 0; i < 16; i++) s[i] ^= k->rk[r * 16 + i];
    }
    memcpy(out, s, 16);
    mtk_zero(s, sizeof(s));
    mtk_zero(t, sizeof(t));
}

void mtk_aes128_decrypt(const mtk_aes128 *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ k->rk[160 + i];
    for (int r = 9; r >= 0; r--) {
        for (int c = 0; c < 4; c++)                         // inverse ShiftRows
            for (int row = 0; row < 4; row++) t[((c + row) & 3) * 4 + row] = s[c * 4 + row];
        for (int i = 0; i < 16; i++) s[i] = g_isbox[t[i]] ^ k->rk[r * 16 + i];   // inverse SubBytes, AddRoundKey
        if (r) {                                            // inverse MixColumns
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[c * 4], a1 = s[c * 4 + 1], a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
                s[c * 4]     = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
                s[c * 4 + 1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
                s[c * 4 + 2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
                s[c * 4 + 3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
            }
        }
    }
    memcpy(out, s, 16);
    mtk_zero(s, sizeof(s));
    mtk_zero(t, sizeof(t));
}

// ---------------------------------------------------------------- RFC 3394 key wrap

int mtk_aes128_wrap(const uint8_t kek[16], const uint8_t *in, size_t inlen, uint8_t *out) {
    if (inlen < 16 || inlen % 8 || inlen > 8 * 64) return -1;
    size_t n = inlen / 8;
    mtk_aes128 k;
    uint8_t a[8], b[16];
    mtk_aes128_setkey(&k, kek);
    memset(a, 0xa6, 8);
    memmove(out + 8, in, inlen);
    for (int j = 0; j <= 5; j++) {
        for (size_t i = 1; i <= n; i++) {
            memcpy(b, a, 8);
            memcpy(b + 8, out + 8 * i, 8);
            mtk_aes128_encrypt(&k, b, b);
            uint32_t t = (uint32_t)(n * (size_t)j + i);
            memcpy(a, b, 8);
            a[7] ^= (uint8_t)t; a[6] ^= (uint8_t)(t >> 8); a[5] ^= (uint8_t)(t >> 16); a[4] ^= (uint8_t)(t >> 24);
            memcpy(out + 8 * i, b + 8, 8);
        }
    }
    memcpy(out, a, 8);
    mtk_zero(&k, sizeof(k));
    mtk_zero(b, sizeof(b));
    return 0;
}

int mtk_aes128_unwrap(const uint8_t kek[16], const uint8_t *in, size_t inlen, uint8_t *out) {
    if (inlen < 24 || inlen % 8 || inlen > 8 + 8 * 64) return -1;
    size_t n = inlen / 8 - 1;
    mtk_aes128 k;
    uint8_t a[8], b[16];
    mtk_aes128_setkey(&k, kek);
    memcpy(a, in, 8);
    memmove(out, in + 8, 8 * n);
    for (int j = 5; j >= 0; j--) {
        for (size_t i = n; i >= 1; i--) {
            uint32_t t = (uint32_t)(n * (size_t)j + i);
            memcpy(b, a, 8);
            b[7] ^= (uint8_t)t; b[6] ^= (uint8_t)(t >> 8); b[5] ^= (uint8_t)(t >> 16); b[4] ^= (uint8_t)(t >> 24);
            memcpy(b + 8, out + 8 * (i - 1), 8);
            mtk_aes128_decrypt(&k, b, b);
            memcpy(a, b, 8);
            memcpy(out + 8 * (i - 1), b + 8, 8);
        }
    }
    mtk_zero(&k, sizeof(k));
    mtk_zero(b, sizeof(b));
    uint8_t d = 0;
    for (int i = 0; i < 8; i++) d |= (uint8_t)(a[i] ^ 0xa6);
    if (d) {
        mtk_zero(out, 8 * n);
        return -2;
    }
    return 0;
}

// ---------------------------------------------------------------- helpers

int mtk_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

void mtk_zero(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

void mtk_wpa_pmk(const uint8_t *pass, size_t plen, const uint8_t *ssid, size_t ssidlen, uint8_t pmk[32]) {
    mtk_pbkdf2_sha1(pass, plen, ssid, ssidlen, 4096, pmk, 32);
}

void mtk_wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6], const uint8_t anonce[32],
                 const uint8_t snonce[32], uint8_t ptk[48]) {
    uint8_t d[76];
    const uint8_t *lo = memcmp(aa, spa, 6) < 0 ? aa : spa, *hi = lo == aa ? spa : aa;
    memcpy(d, lo, 6);
    memcpy(d + 6, hi, 6);
    const uint8_t *nlo = memcmp(anonce, snonce, 32) < 0 ? anonce : snonce, *nhi = nlo == anonce ? snonce : anonce;
    memcpy(d + 12, nlo, 32);
    memcpy(d + 44, nhi, 32);
    mtk_prf_sha1(pmk, 32, "Pairwise key expansion", d, sizeof(d), ptk, 48);
    mtk_zero(d, sizeof(d));
}

void mtk_eapol_mic(const uint8_t kck[16], const uint8_t *frame, size_t len, size_t mic_off, uint8_t mic[16]) {
    static const uint8_t zero[16] = {0};
    uint8_t h[20];
    mtk_sha1_ctx c;
    // HMAC over frame[0..mic_off) || 16 zero bytes || frame[mic_off+16..len), without copying the frame
    uint8_t k[64], pad[64], inner[20];
    memset(k, 0, sizeof(k));
    memcpy(k, kck, 16);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    mtk_sha1_init(&c);
    mtk_sha1_update(&c, pad, 64);
    mtk_sha1_update(&c, frame, mic_off);
    mtk_sha1_update(&c, zero, 16);
    if (len > mic_off + 16) mtk_sha1_update(&c, frame + mic_off + 16, len - mic_off - 16);
    mtk_sha1_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    mtk_sha1_init(&c);
    mtk_sha1_update(&c, pad, 64);
    mtk_sha1_update(&c, inner, 20);
    mtk_sha1_final(&c, h);
    memcpy(mic, h, 16);
    mtk_zero(k, sizeof(k));
    mtk_zero(pad, sizeof(pad));
    mtk_zero(h, sizeof(h));
    mtk_zero(inner, sizeof(inner));
}
