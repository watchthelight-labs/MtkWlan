// <wtl> project: mtkwlan | file: src/MtkCrypto.h | author: watchthelight </wtl>
// SPDX-License-Identifier: BSD-3-Clause-Clear
// WPA2-PSK primitives with no OS dependencies: SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1, the IEEE 802.11 PRF,
// AES-128 and RFC 3394 key wrap / unwrap, constant-time compare. Plain C, built three ways: in the kext
// (build-mac.sh, kernel flags), in the host test (tests/run.sh) and in the userspace tool (tools/mtkwifi).
//
// Adapted from itl_wpa.h / itl_wpa.cpp of itlmt7925 (github.com/thanhnndev/ga403wm-hackintosh,
// kexts/itlmt7925, commit 8f0ff67), audited before use.
// Copyright (c) 2026 thanhnndev and contributors. Licensed under The Clear BSD License:
//   Redistribution and use in source and binary forms, with or without modification, are permitted
//   (subject to the limitations in the disclaimer below) provided that the following conditions are met:
//   redistributions of source code must retain the above copyright notice, this list of conditions and
//   the following disclaimer; redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation and/or other materials
//   provided with the distribution; neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived from this software without specific
//   prior written permission.
//   NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE. THIS SOFTWARE
//   IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
//   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
//   IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// Changes here: C instead of C++, mtk_ prefix, AES encryption and key wrap added (for the tests), the
// constant-time compare and the zeroise helper added, the PRF takes its buffers from the caller's stack size.

#ifndef MTK_CRYPTO_H
#define MTK_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; uint32_t n; } mtk_sha1_ctx;
void mtk_sha1_init(mtk_sha1_ctx *c);
void mtk_sha1_update(mtk_sha1_ctx *c, const void *d, size_t n);
void mtk_sha1_final(mtk_sha1_ctx *c, uint8_t out[20]);
void mtk_sha1(const void *d, size_t n, uint8_t out[20]);

// HMAC-SHA1 over d1 || d2 (either may be empty)
void mtk_hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *d1, size_t n1, const uint8_t *d2, size_t n2,
                   uint8_t out[20]);
// PBKDF2-HMAC-SHA1 (RFC 8018); the WPA PMK is pbkdf2(passphrase, ssid, 4096, 32)
void mtk_pbkdf2_sha1(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen, uint32_t iter, uint8_t *out,
                     size_t olen);
// IEEE 802.11-2020 12.7.1.2 PRF-n(K, A, B) with A = label (no NUL), output olen bytes. Returns 0, or -1
// when label + data do not fit the internal buffer (160 bytes).
int mtk_prf_sha1(const uint8_t *key, size_t klen, const char *label, const uint8_t *data, size_t dlen, uint8_t *out,
                 size_t olen);

typedef struct { uint8_t rk[176]; } mtk_aes128;
void mtk_aes128_setkey(mtk_aes128 *k, const uint8_t key[16]);
void mtk_aes128_encrypt(const mtk_aes128 *k, const uint8_t in[16], uint8_t out[16]);
void mtk_aes128_decrypt(const mtk_aes128 *k, const uint8_t in[16], uint8_t out[16]);
// RFC 3394 with the default IV A6..A6. wrap: in n*8 bytes -> out n*8+8. unwrap: in n*8+8 -> out n*8.
// Return 0 on success, -1 on a bad length, -2 when the integrity check fails (unwrap).
int mtk_aes128_wrap(const uint8_t kek[16], const uint8_t *in, size_t inlen, uint8_t *out);
int mtk_aes128_unwrap(const uint8_t kek[16], const uint8_t *in, size_t inlen, uint8_t *out);

// 1 when equal; time independent of where the buffers differ
int mtk_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);
// memset that the compiler does not drop
void mtk_zero(void *p, size_t n);

// WPA2-PSK helpers (IEEE 802.11-2020 12.7.1.3 / 12.7.6)
void mtk_wpa_pmk(const uint8_t *pass, size_t plen, const uint8_t *ssid, size_t ssidlen, uint8_t pmk[32]);
// PTK = PRF-384(PMK, "Pairwise key expansion", min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(...)):
// KCK = ptk[0..15], KEK = ptk[16..31], TK = ptk[32..47]
void mtk_wpa_ptk(const uint8_t pmk[32], const uint8_t aa[6], const uint8_t spa[6], const uint8_t anonce[32],
                 const uint8_t snonce[32], uint8_t ptk[48]);
// EAPOL-Key MIC for descriptor version 2: first 16 bytes of HMAC-SHA1(KCK, frame with the MIC field zero).
// frame = the whole EAPOL packet (version byte first), mic_off = offset of the MIC field (81).
void mtk_eapol_mic(const uint8_t kck[16], const uint8_t *frame, size_t len, size_t mic_off, uint8_t mic[16]);

#ifdef __cplusplus
}
#endif

#endif
