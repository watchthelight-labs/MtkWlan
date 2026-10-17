// <wtl> project: mtkwlan | file: src/MtkSec.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// W2: WPA2-PSK glue between the data path and the supplicant in MtkSupp.c.
// EAPOL frames from the AP are queued by rxFrame (MtkNet.cpp) and fed to mtk_supp_rx from the tick
// (secService). The supplicant's callbacks never poll the rings or issue firmware commands: txEapol only queues
// a frame, and the key callbacks only stash the keys. secInstallService then installs them from the tick in the
// order Linux mt7925 and itlmt7925 use: message 4 on air (its TX-free seen, 100 ms bound), BSS_INFO with the
// WPA2 security values (mt7925_mcu_bss_sec_tlv, what Linux sends at its first set_key), the pairwise key, the
// group key, then the port opens and en1 reports link up.

#include "MtkWlan.hpp"
#include "MtkCrypto.h"
#include <sys/random.h>

namespace {
constexpr uint8_t LMAC_AC_BE = 1;
constexpr uint8_t RATE_IDX_OFDM6 = 18;
constexpr uint8_t CIPHER_CCMP = 4;
constexpr uint32_t M4_FREE_WAIT_TICKS = 100;
const uint8_t kSnap[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
} // namespace

void MtkWlan::secReset() {
    mtk_supp_clear(&supp);
    suppActive = false;
    ptkInstalled = false;
    pendingTkSet = pendingGtkSet = false;
    mtk_zero(pendingTk, sizeof(pendingTk));
    mtk_zero(pendingGtk, sizeof(pendingGtk));
    pendingGtkLen = pendingGtkId = 0;
    eapolSlot = -1;
    eapolQHead = eapolQTail = 0;
}

// Associated to a WPA2-PSK network: arm the supplicant with the PMK, our RSN element (the one in the association
// request) and the AP's (its beacon's, for the message 3 check). The EAPOL queue is left alone: message 1 may
// already be waiting in it.
void MtkWlan::secStart() {
    mtk_supp_ops ops = {this, &MtkWlan::secSendEapol, &MtkWlan::secInstallPtk, &MtkWlan::secInstallGtk, &MtkWlan::secRandom};
    uint8_t own[64];
    size_t ownLen = mtk_rsn_ie_psk(own, tgtGroup);
    mtk_supp_init(&supp, &ops, wantPmk, tgtBssid, mac, own, ownLen, tgtRsnIe, tgtRsnIeLen);
    suppActive = true;
    ptkInstalled = false;
    portOpen = false;
    pendingTkSet = pendingGtkSet = false;
    eapolSlot = -1;
}

// From rxFrame: one EAPOL frame (version byte first) from the AP, protected or not
void MtkWlan::secQueueEapol(const uint8_t *p, uint32_t len) {
    if (len < 4 || len > MTK_EAPOL_MAX) { eapolQDropped++; return; }
    uint8_t next = (uint8_t)((eapolQHead + 1) % 4);
    if (next == eapolQTail) { eapolQDropped++; return; }
    EapolEvt &e = eapolQ[eapolQHead];
    e.len = (uint16_t)len;
    memcpy(e.f, p, len);
    eapolQHead = next;
}

// Tick: feed the supplicant, then install whatever keys it handed over
void MtkWlan::secService() {
    while (eapolQTail != eapolQHead) {
        if (!suppActive) {
            if (joinState == 3) break;          // message 1 ahead of the association response: keep it for secStart
            EapolEvt &d = eapolQ[eapolQTail];
            eapolQTail = (uint8_t)((eapolQTail + 1) % 4);
            mtk_zero(d.f, d.len);
            eapolQDropped++;
            continue;
        }
        EapolEvt &e = eapolQ[eapolQTail];
        eapolQTail = (uint8_t)((eapolQTail + 1) % 4);
        int r = mtk_supp_rx(&supp, e.f, e.len);
        mtk_zero(e.f, e.len);
        if (r == MTK_SUPP_ERR_IE) {
            // the RSN element in message 3 is not the beacon's: a downgrade attempt or a misconfigured AP
            joinTeardown(17);                           // reason 17: information element differs
            lastResult = MTK_JOIN_RSN_MISMATCH;
            joinFailures++;
            cmResult(lastResult);
            step("W5 fail: RSN element in message 3 differs from the beacon");
            return;
        }
    }
    if (!suppActive) return;
    if (pendingTkSet || pendingGtkSet) {
        if (!secInstallService()) return;
    }
    if (joinState == 4 && ptkInstalled && supp.state == MTK_SUPP_DONE && !pendingTkSet && !pendingGtkSet) joinUp();
}

// Install the pending keys once the last EAPOL frame we sent (message 4, or a protected message 4 on a PTK
// rekey, or group message 2) has left the card, so the frame cannot go out under the new key. Returns false
// while still waiting or after a failure (joinFail was called).
bool MtkWlan::secInstallService() {
    if (eapolSlot >= 0) {
        if (txBusy[eapolSlot] && ticks - eapolSentAt < M4_FREE_WAIT_TICKS) return false;
        eapolSlot = -1;
    }
    if (pendingTkSet) {
        if (secCipher != CIPHER_CCMP) {
            secCipher = CIPHER_CCMP;
            int rb = bssInfo(true);
            setNum("MtkW2BssSec", (uint32_t)rb);
            if (rb) { secInstallFails++; joinFail(MTK_JOIN_KEY_INSTALL); return false; }
        }
        int rk = staKey(true, 0, pendingTk, 16, true);
        setNum("MtkW2PtkInstall", (uint32_t)rk);
        mtk_zero(pendingTk, sizeof(pendingTk));
        pendingTkSet = false;
        if (rk) { secInstallFails++; joinFail(MTK_JOIN_KEY_INSTALL); return false; }
        for (int i = 0; i < 8; i++) rxPn[i] = 0;                 // new pairwise key: replay counters restart
        ptkInstalled = true;
        secInstalls++;
    }
    if (pendingGtkSet) {
        int rg = staKey(false, pendingGtkId, pendingGtk, pendingGtkLen, true);
        setNum("MtkW2GtkInstall", (uint32_t)rg);
        gtkId = pendingGtkId;
        mtk_zero(pendingGtk, sizeof(pendingGtk));
        pendingGtkSet = false;
        if (rg) { secInstallFails++; joinFail(MTK_JOIN_KEY_INSTALL); return false; }
        uint64_t rsc = 0;                                         // Key RSC: the group PN the AP has reached
        for (int i = 5; i >= 0; i--) rsc = rsc << 8 | pendingGtkRsc[i];
        for (int i = 8; i < 16; i++) rxPn[i] = rsc;
        secInstalls++;
    }
    return true;
}

// CCMP replay check at delivery (after the block-ack reorder), as mt76_check_ccmp_pn: a PN not above the last one
// accepted on that key and TID is a replay. slot -1 = not a protected CCMP frame, nothing to check.
bool MtkWlan::pnAccept(int slot, uint64_t pn) {
    if (slot < 0) return true;
    if (pn <= rxPn[slot]) { rxPnReplays++; return false; }
    rxPn[slot] = pn;
    return true;
}

// One EAPOL frame to the AP as 802.11 data (QoS TID 0 when WMM was negotiated): LLC/SNAP 0x888E, fixed OFDM 6 Mb/s
// (what mac80211's USE_MINRATE gives EAPOL), TX status on, block ack off. protect = the hardware encrypts it with
// the installed PTK (FC Protected and TXD3 PROTECT_FRAME). Never polls; remembers the slot so a key install can
// wait until the frame has left.
bool MtkWlan::txEapol(const uint8_t *eapol, uint32_t len, bool protect) {
    if (!linkUp || len + 34 > 1900) return false;
    if (!txSlotReady(true)) return false;
    uint8_t *f = txData.bufs.va + txData.head * txData.bufSize + 128;
    bool qos = htActive;
    uint32_t h = qos ? 26 : 24;
    f[0] = qos ? 0x88 : 0x08;                   // QoS data / data
    f[1] = (uint8_t)(0x01 | (protect ? 0x40 : 0));   // ToDS, Protected
    f[2] = f[3] = 0;
    memcpy(f + 4, tgtBssid, 6);
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, tgtBssid, 6);
    f[22] = f[23] = 0;
    if (qos) f[24] = f[25] = 0;
    memcpy(f + h, kSnap, 6);
    f[h + 6] = 0x88;
    f[h + 7] = 0x8e;
    memcpy(f + h + 8, eapol, len);
    uint16_t slot = txData.head;
    txQueue(h + 8 + len, LMAC_AC_BE, 2, qos ? 8 : 0, RATE_IDX_OFDM6, false, true, h, 0, protect);
    txEapolCount++;
    eapolSlot = slot;
    eapolSentAt = ticks;
    return true;
}

// ---------------------------------------------------------------- supplicant callbacks (inside mtk_supp_rx)

int MtkWlan::secSendEapol(void *ctx, const uint8_t *f, size_t n, int protect) {
    return static_cast<MtkWlan *>(ctx)->txEapol(f, (uint32_t)n, protect != 0) ? 0 : -1;
}

int MtkWlan::secInstallPtk(void *ctx, const uint8_t tk[16]) {
    MtkWlan *self = static_cast<MtkWlan *>(ctx);
    memcpy(self->pendingTk, tk, 16);
    self->pendingTkSet = true;
    return 0;
}

int MtkWlan::secInstallGtk(void *ctx, int keyid, const uint8_t *gtk, size_t gtklen, const uint8_t rsc[8]) {
    MtkWlan *self = static_cast<MtkWlan *>(ctx);
    if (gtklen != 16 && gtklen != 32) return -1;
    memcpy(self->pendingGtk, gtk, gtklen);
    memcpy(self->pendingGtkRsc, rsc, 8);        // seeds the group replay counters at install time
    self->pendingGtkLen = (uint8_t)gtklen;
    self->pendingGtkId = (uint8_t)keyid;
    self->pendingGtkSet = true;
    return 0;
}

void MtkWlan::secRandom(void *, uint8_t *buf, size_t n) {
    read_random(buf, (u_int)n);
}
