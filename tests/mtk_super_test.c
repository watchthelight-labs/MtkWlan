// <wtl> project: mtkwlan | file: tests/mtk_super_test.c | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// Host tests for the link supervisor (MtkSuper.c): every decision path, the reload cap, and the PMK hex parser.

#include <stdio.h>
#include <string.h>
#include "../src/MtkSuper.h"

static int fails;
#define CHECK(name, cond) do { if (cond) printf("ok   %s\n", name); else { printf("FAIL %s\n", name); fails++; } } while (0)

static struct mtk_super_in in;
static int run(struct mtk_super *s, uint32_t seconds) {
    int last = MTK_SUPER_NONE;
    for (uint32_t i = 0; i < seconds; i++) {
        in.now_ms += 1000;
        last = mtk_super_step(s, &in);
        if (last != MTK_SUPER_NONE && last != MTK_SUPER_PROBE) return last;
    }
    return last;
}

static void fresh(struct mtk_super *s, uint32_t stall) {
    memset(&in, 0, sizeof(in));
    in.now_ms = 5000;
    in.link = 1;
    mtk_super_init(s, stall);
    mtk_super_step(s, &in);             // primes the counters
}

int main(void) {
    struct mtk_super s;

    fresh(&s, 0);
    in.fw_dead = 1;
    CHECK("off: never acts", run(&s, 30) == MTK_SUPER_NONE);

    fresh(&s, 8000);
    for (int i = 0; i < 60; i++) { in.rx_frames++; in.tx_freed++; in.tx_queued += 2; in.now_ms += 1000; mtk_super_step(&s, &in); }
    CHECK("busy link: nothing", s.probes == 0 && s.reloads == 0);

    fresh(&s, 8000);
    int r = MTK_SUPER_NONE;
    for (int i = 0; i < 8 && r != MTK_SUPER_PROBE; i++) { in.now_ms += 1000; r = mtk_super_step(&s, &in); }
    CHECK("rx silent 8 s: probe", r == MTK_SUPER_PROBE);
    in.txs_records++;                    // the null frame was acknowledged
    in.now_ms += 1000;
    CHECK("probe acked: quiet link, no action", mtk_super_step(&s, &in) == MTK_SUPER_NONE && s.idle_ok == 1);

    fresh(&s, 8000);
    run(&s, 8);
    in.txs_records++; in.txs_ack_err++;  // no ACK
    in.now_ms += 1000;
    CHECK("probe unacked: rejoin", mtk_super_step(&s, &in) == MTK_SUPER_REJOIN);

    fresh(&s, 8000);
    run(&s, 8);
    in.now_ms += 1000; mtk_super_step(&s, &in);
    in.now_ms += 1000;
    CHECK("probe without any status: reload", mtk_super_step(&s, &in) == MTK_SUPER_RELOAD);

    fresh(&s, 8000);
    in.tx_queued += 5;
    r = MTK_SUPER_NONE;
    for (int i = 0; i < 10 && r == MTK_SUPER_NONE; i++) { in.rx_frames++; in.now_ms += 1000; r = mtk_super_step(&s, &in); }
    CHECK("tx tokens stuck 8 s while rx flows: reload", r == MTK_SUPER_RELOAD);

    fresh(&s, 8000);
    in.tx_queued += 1;
    in.now_ms += 1000; mtk_super_step(&s, &in);
    in.tx_freed += 1;                    // the token came back, then the link sits idle
    int any = 0;
    for (int i = 0; i < 20; i++) { in.rx_frames++; in.now_ms += 1000; if (mtk_super_step(&s, &in) == MTK_SUPER_RELOAD) any = 1; }
    CHECK("idle tx with tokens back: no reload", !any);

    fresh(&s, 8000);
    in.fw_dead = 1;
    int reloads = 0;
    for (int i = 0; i < 10; i++) { in.now_ms += 1000; if (mtk_super_step(&s, &in) == MTK_SUPER_RELOAD) reloads++; }
    CHECK("firmware dead: 3 reloads, then capped", reloads == 3 && s.capped == 7);
    in.now_ms += MTK_SUPER_WINDOW_MS;
    CHECK("cap window passed: reload again", mtk_super_step(&s, &in) == MTK_SUPER_RELOAD);

    fresh(&s, 8000);
    in.link = 0;
    CHECK("no link: nothing", run(&s, 30) == MTK_SUPER_NONE && s.probes == 0);
    in.link = 1;
    in.now_ms += 1000; mtk_super_step(&s, &in);
    CHECK("link comes up: clock starts again", run(&s, 6) == MTK_SUPER_NONE && s.probes == 0);

    uint8_t pmk[32];
    const char *good = "000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F";
    CHECK("pmk hex: valid", mtk_hex_pmk(good, pmk) == 0 && pmk[0] == 0 && pmk[31] == 0x1f && pmk[26] == 0x1a);
    CHECK("pmk hex: short", mtk_hex_pmk("0011", pmk) == -1);
    CHECK("pmk hex: long", mtk_hex_pmk("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00", pmk) == -1);
    CHECK("pmk hex: not hex", mtk_hex_pmk("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", pmk) == -1);
    CHECK("pmk hex: null", mtk_hex_pmk(NULL, pmk) == -1);

    printf(fails ? "supervisor: %d FAILED\n" : "supervisor: all passed\n", fails);
    return fails ? 1 : 0;
}
