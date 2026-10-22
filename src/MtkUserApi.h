// <wtl> project: mtkwlan | file: src/MtkUserApi.h | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Data shapes shared by the MtkWlan core, its ops table v2 (MtkCoreApi.h), the IOUserClient (MtkUserClient.cpp)
// and the userspace tool tools/mtkwifi. Only fixed-size integer fields, so the layout is the same in the
// kernel and in a 64-bit user process. Bump MTK_USER_API_VERSION on any change.

#ifndef MTK_USER_API_H
#define MTK_USER_API_H

#include <stdint.h>

#define MTK_USER_API_VERSION   1
#define MTK_USER_CLIENT_CLASS  "MtkWlanUserClient"
#define MTK_SCAN_MAX           48     // the most results one get_scan_results call returns (the core caches more)

// IOUserClient selectors (IOConnectCall*Method)
enum {
    kMtkUcScan = 0,          // no arguments; starts a scan (admin)
    kMtkUcResults = 1,       // structure out: mtk_scan_result[n], n = out size / sizeof
    kMtkUcJoin = 2,          // structure in: mtk_join_params (admin)
    kMtkUcDisconnect = 3,    // no arguments (admin); also turns the open-network auto-join off until the next join
    kMtkUcStatus = 4,        // structure out: mtk_status
    kMtkUcTune = 5,          // scalar in: key (MTK_TUNE_*), value; 0 = default (admin; 0.11.3)
    kMtkUcCount
};

// kMtkUcTune keys: data path limits that can be swept live instead of one value per boot
enum { MTK_TUNE_TX_INFLIGHT_BA = 1, MTK_TUNE_TX_INFLIGHT = 2,
       MTK_TUNE_STALL_SEC = 3,      // 0.12.0: link supervisor threshold in seconds, 0 = off
       MTK_TUNE_STALL_TEST = 4 };   // 0.12.0: 1 = ignore received frames so the supervisor trips (test), 0 = normal

// security / akm / cipher bits in mtk_scan_result
enum { MTK_SEC_OPEN = 0, MTK_SEC_WEP = 1, MTK_SEC_WPA1 = 2, MTK_SEC_RSN = 3 };
enum { MTK_AKM_PSK = 1, MTK_AKM_SAE = 2, MTK_AKM_8021X = 4, MTK_AKM_PSK256 = 8, MTK_AKM_OWE = 16, MTK_AKM_OTHER = 128 };
enum { MTK_CIPHER_CCMP = 1, MTK_CIPHER_TKIP = 2, MTK_CIPHER_GCMP = 4, MTK_CIPHER_OTHER = 128 };
// flags
enum { MTK_BSS_MFPR = 1, MTK_BSS_MFPC = 2, MTK_BSS_JOINABLE = 4, MTK_BSS_CURRENT = 8 };

struct mtk_scan_result {
    uint8_t bssid[6];
    uint8_t ssid_len;
    uint8_t channel;
    char ssid[33];            // NUL terminated copy; non-printable bytes are kept (use ssid_len)
    int8_t rssi;              // dBm, -127 = unknown
    uint8_t security;         // MTK_SEC_*
    uint8_t akm;              // MTK_AKM_* bits (RSN)
    uint8_t pairwise;         // MTK_CIPHER_* bits (RSN)
    uint8_t group;            // group cipher suite type (00-0F-AC:n), 0 = none
    uint8_t flags;            // MTK_BSS_*
    uint8_t _pad;
    uint32_t age_ms;          // since the last beacon / probe response
};

enum { MTK_KEY_NONE = 0, MTK_KEY_PMK = 1 };

struct mtk_join_params {
    uint32_t version;         // MTK_USER_API_VERSION
    uint8_t ssid_len;         // 1..32
    uint8_t key_type;         // MTK_KEY_NONE (open network) or MTK_KEY_PMK
    uint8_t bssid[6];         // all zero = best BSS with this SSID
    uint8_t ssid[32];
    uint8_t pmk[32];          // PBKDF2-SHA1(passphrase, SSID, 4096), computed in userspace
};

// join results (mtk_status.last_result and the join_result callback)
enum {
    MTK_JOIN_OK = 0,
    MTK_JOIN_PENDING = 1,
    MTK_JOIN_NOT_FOUND = 2,
    MTK_JOIN_SECURITY = 3,    // the network's security does not match the key given (or is not supported)
    MTK_JOIN_ROC = 4,
    MTK_JOIN_AUTH_TIMEOUT = 5,
    MTK_JOIN_AUTH_REJECT = 6,
    MTK_JOIN_ASSOC_TIMEOUT = 7,
    MTK_JOIN_ASSOC_REJECT = 8,
    MTK_JOIN_HANDSHAKE_TIMEOUT = 9,
    MTK_JOIN_WRONG_KEY = 10,  // message 2 sent, no valid message 3: most likely a wrong passphrase
    MTK_JOIN_KEY_INSTALL = 11,
    MTK_JOIN_AP_LEFT = 12,    // deauthenticated / disassociated during the join
    MTK_JOIN_CANCELLED = 13,
    MTK_JOIN_RSN_MISMATCH = 14,
};

// which front end owns the data path (mtk_status.front_end, mtk_core_ops_v3 set_mode)
enum { MTK_FE_ETHERNET = 0, MTK_FE_NATIVE = 1 };

// connection manager states (mtk_status.state)
enum { MTK_ST_IDLE = 0, MTK_ST_SCANNING = 1, MTK_ST_JOINING = 2, MTK_ST_HANDSHAKE = 3, MTK_ST_CONNECTED = 4,
       MTK_ST_WAITING = 5 };

struct mtk_status {
    uint32_t version;         // MTK_USER_API_VERSION
    uint8_t state;            // MTK_ST_*
    uint8_t link_up;          // associated
    uint8_t port_open;        // data allowed (open network, or keys installed)
    uint8_t security;         // of the current / last target: MTK_SEC_*
    uint8_t scanning;
    uint8_t auto_open;        // the core joins the best open network by itself
    uint8_t want_active;      // a network was requested through join
    uint8_t channel;
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t ssid_len;
    char ssid[33];
    uint8_t front_end;        // MTK_FE_* (0.10.0; was padding)
    uint8_t _pad[2];
    uint32_t last_result;     // MTK_JOIN_*
    uint32_t bss_count;
    uint32_t scans, joins, join_failures, rejoins;
    uint32_t m1, m2, m3, m4, g1, g2, bad_mic, eapol_replays, rx_pn_replays, rx_no_pn;
    uint64_t speed;
};

#endif
