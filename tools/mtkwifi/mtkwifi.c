// <wtl> project: mtkwlan | file: tools/mtkwifi/mtkwifi.c | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// mtkwifi: userspace control for the MtkWlan kext (MT7925) through its IOUserClient (MtkUserApi.h).
//   mtkwifi status [--json]            driver and connection state
//   mtkwifi scan [--wait]              start a scan (root); --wait prints the list when it is done
//   mtkwifi list [--json]              networks in the driver's cache, best first
//   mtkwifi join <ssid> [--bssid X] [--open | --ask]   join (root): saved PMK, open network, or ask for the passphrase
//   mtkwifi disconnect                 leave and stay idle (root)
//   mtkwifi add <ssid> [--open]        save a network (root): asks for the passphrase, stores only the derived PMK
//   mtkwifi forget <ssid>              remove a saved network (root)
//   mtkwifi networks                   list saved SSIDs
//   mtkwifi autojoin [--wait SECONDS]  wait for the driver, scan, join the first saved network in range (the LaunchDaemon)
//   mtkwifi pmk <ssid>                 asks for the passphrase, prints an MtkAutoNetworks entry for MtkWlan's Info.plist
// The passphrase is never written anywhere: the PMK (PBKDF2-SHA1, mtk_wpa_pmk from the kext's own MtkCrypto.c) goes
// to /Library/Application Support/legion/mtkwifi/networks.plist, root only, mode 0600, outside the repository.

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <fcntl.h>
#include <readpassphrase.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "MtkUserApi.h"
#include "MtkCrypto.h"

static const char *kNetDir = "/Library/Application Support/legion/mtkwifi";
static const char *kNetFile = "/Library/Application Support/legion/mtkwifi/networks.plist";

struct net { char ssid[33]; int open; uint8_t pmk[32]; int has_pmk; };
#define MAX_NETS 32
static struct net g_nets[MAX_NETS];
static int g_nnets;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("mtkwifi: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void sleep_ms(unsigned ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

// ---------------------------------------------------------------- driver

static io_connect_t open_driver(int wait_s) {
    for (int i = 0;; i++) {
        io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL, IOServiceMatching("MtkWlan"));
        if (svc) {
            io_connect_t conn = 0;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
            IOObjectRelease(svc);
            if (kr == KERN_SUCCESS) return conn;
            if (kr == kIOReturnUnsupported || kr == kIOReturnNoResources)
                die("the MtkWlan driver has no user client (older than 0.9.0, or its bring-up failed: see MtkState in "
                    "`ioreg -r -c MtkWlan`): 0x%x", kr);
            if (i >= wait_s) die("IOServiceOpen failed: 0x%x", kr);
        } else if (i >= wait_s) {
            die("MtkWlan is not loaded");
        }
        sleep_ms(1000);
    }
}

static int get_status(io_connect_t c, struct mtk_status *st) {
    size_t n = sizeof(*st);
    memset(st, 0, n);
    kern_return_t kr = IOConnectCallStructMethod(c, kMtkUcStatus, NULL, 0, st, &n);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "mtkwifi: status failed: 0x%x\n", kr); return -1; }
    if (st->version != MTK_USER_API_VERSION) { fprintf(stderr, "mtkwifi: driver API version %u, tool %u\n", st->version, MTK_USER_API_VERSION); return -1; }
    return 0;
}

static int get_results(io_connect_t c, struct mtk_scan_result *out, int max) {
    size_t n = (size_t)max * sizeof(*out);
    kern_return_t kr = IOConnectCallStructMethod(c, kMtkUcResults, NULL, 0, out, &n);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "mtkwifi: results failed: 0x%x\n", kr); return -1; }
    return (int)(n / sizeof(*out));
}

static const char *kr_text(kern_return_t kr) {
    if (kr == kIOReturnNotPrivileged) return "needs root (sudo)";
    if (kr == kIOReturnNotReady) return "driver not ready (firmware stopped or still starting)";
    if (kr == kIOReturnBadArgument) return "bad argument";
    return "error";
}

static int do_scan(io_connect_t c) {
    kern_return_t kr = IOConnectCallStructMethod(c, kMtkUcScan, NULL, 0, NULL, NULL);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "mtkwifi: scan refused: %s (0x%x)\n", kr_text(kr), kr); return -1; }
    return 0;
}

// Wait until a new scan has started and finished (the driver defers a request while a join is in progress; a
// full scan takes 3 to 6 s). scans0 = the scan counter before the request.
static int wait_scan(io_connect_t c, int timeout_s, uint32_t scans0) {
    struct mtk_status st;
    for (int i = 0; i < timeout_s * 10; i++) {
        sleep_ms(100);
        if (get_status(c, &st)) return -1;
        if (st.scans > scans0 && !st.scanning) return 0;
    }
    fprintf(stderr, "mtkwifi: scan did not finish in %d s\n", timeout_s);
    return -1;
}

static const char *result_name(uint32_t r) {
    static const char *names[] = {"ok", "pending", "network not found", "security mismatch", "no channel grant",
                                  "auth timeout", "auth rejected", "assoc timeout", "assoc rejected",
                                  "handshake timeout", "wrong passphrase", "key install failed", "AP left",
                                  "cancelled", "RSN element mismatch"};
    return r < sizeof(names) / sizeof(names[0]) ? names[r] : "?";
}

static const char *state_name(uint8_t s) {
    static const char *names[] = {"idle", "scanning", "joining", "handshake", "connected", "waiting"};
    return s < 6 ? names[s] : "?";
}

static void sec_text(const struct mtk_scan_result *r, char *out, size_t n) {
    static const char *sec[] = {"open", "wep", "wpa", "wpa2"};
    const char *akm = "";
    if (r->security >= MTK_SEC_WPA1) {
        if ((r->akm & MTK_AKM_PSK) && (r->akm & MTK_AKM_SAE)) akm = "-psk/sae";
        else if (r->akm & MTK_AKM_PSK) akm = "-psk";
        else if (r->akm & MTK_AKM_SAE) akm = "-sae";
        else if (r->akm & MTK_AKM_PSK256) akm = "-psk256";
        else if (r->akm & MTK_AKM_8021X) akm = "-ent";
        else if (r->akm & MTK_AKM_OWE) akm = "-owe";
    }
    const char *grp = (r->security == MTK_SEC_RSN && r->group == 2) ? " tkip-group" : "";
    const char *mfp = (r->flags & MTK_BSS_MFPR) ? " mfp-required" : "";
    snprintf(out, n, "%s%s%s%s", sec[r->security & 3], akm, grp, mfp);
}

static void print_ssid(const char *s, uint8_t len) {
    if (!len) { fputs("(hidden)", stdout); return; }
    for (int i = 0; i < len; i++) putchar((s[i] >= 0x20 && s[i] <= 0x7e) ? s[i] : '?');
}

static void json_str(const char *s, size_t len) {
    putchar('"');
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == '"' || ch == '\\') { putchar('\\'); putchar(ch); }
        else if (ch < 0x20 || ch > 0x7e) printf("\\u%04x", ch);
        else putchar(ch);
    }
    putchar('"');
}

static int cmd_status(io_connect_t c, int json) {
    struct mtk_status st;
    if (get_status(c, &st)) return 1;
    if (json) {
        printf("{\"state\":\"%s\",\"link_up\":%u,\"port_open\":%u,\"security\":%u,\"scanning\":%u,\"auto_open\":%u,"
               "\"want_active\":%u,\"front_end\":%u,\"channel\":%u,\"rssi\":%d,\"ssid\":", state_name(st.state), st.link_up,
               st.port_open, st.security, st.scanning, st.auto_open, st.want_active, st.front_end, st.channel, st.rssi);
        json_str(st.ssid, st.ssid_len);
        printf(",\"last_result\":\"%s\",\"bss_count\":%u,\"scans\":%u,\"joins\":%u,\"join_failures\":%u,\"rejoins\":%u,"
               "\"eapol\":{\"m1\":%u,\"m2\":%u,\"m3\":%u,\"m4\":%u,\"g1\":%u,\"g2\":%u,\"bad_mic\":%u,\"replays\":%u},"
               "\"rx_no_pn\":%u,\"speed\":%llu}\n",
               result_name(st.last_result), st.bss_count, st.scans, st.joins, st.join_failures, st.rejoins, st.m1, st.m2,
               st.m3, st.m4, st.g1, st.g2, st.bad_mic, st.eapol_replays, st.rx_no_pn, (unsigned long long)st.speed);
        return 0;
    }
    printf("state:      %s%s\n", state_name(st.state), st.scanning ? " (scanning)" : "");
    if (st.state == MTK_ST_CONNECTED || st.state == MTK_ST_HANDSHAKE || st.state == MTK_ST_JOINING) {
        printf("network:    ");
        print_ssid(st.ssid, st.ssid_len);
        printf("  ch %u  rssi %d dBm  %s\n", st.channel, st.rssi, st.security == MTK_SEC_RSN ? "wpa2-psk" : "open");
    }
    printf("link:       %s, port %s\n", st.link_up ? "associated" : "down", st.port_open ? "open" : "closed");
    printf("manager:    %s%s\n", st.want_active ? "network requested" : "no network requested",
           st.auto_open ? ", open-network fallback on" : "");
    printf("front end:  %s\n", st.front_end == MTK_FE_NATIVE ? "native (macOS Wi-Fi manages the joins)" : "ethernet");
    printf("last join:  %s\n", result_name(st.last_result));
    printf("counters:   bss %u scans %u joins %u failures %u rejoins %u\n", st.bss_count, st.scans, st.joins, st.join_failures, st.rejoins);
    printf("handshake:  m1 %u m2 %u m3 %u m4 %u g1 %u g2 %u bad mic %u replays %u\n", st.m1, st.m2, st.m3, st.m4, st.g1, st.g2,
           st.bad_mic, st.eapol_replays);
    return 0;
}

static int cmd_list(io_connect_t c, int json) {
    struct mtk_scan_result r[MTK_SCAN_MAX];
    int n = get_results(c, r, MTK_SCAN_MAX);
    if (n < 0) return 1;
    if (json) {
        printf("[");
        for (int i = 0; i < n; i++) {
            char sec[48];
            sec_text(&r[i], sec, sizeof(sec));
            printf("%s{\"ssid\":", i ? "," : "");
            json_str(r[i].ssid, r[i].ssid_len);
            printf(",\"channel\":%u,\"rssi\":%d,\"security\":\"%s\",\"joinable\":%s,\"current\":%s,\"age_ms\":%u}", r[i].channel,
                   r[i].rssi, sec, (r[i].flags & MTK_BSS_JOINABLE) ? "true" : "false",
                   (r[i].flags & MTK_BSS_CURRENT) ? "true" : "false", r[i].age_ms);
        }
        printf("]\n");
        return 0;
    }
    if (!n) { puts("no networks in the cache yet (run: sudo mtkwifi scan --wait)"); return 0; }
    printf("   %-32s %3s %5s  %-24s %s\n", "SSID", "ch", "rssi", "security", "age");
    for (int i = 0; i < n; i++) {
        char sec[48];
        sec_text(&r[i], sec, sizeof(sec));
        printf("%c%c ", (r[i].flags & MTK_BSS_CURRENT) ? '>' : ' ', (r[i].flags & MTK_BSS_JOINABLE) ? '*' : ' ');
        int w = 0;
        if (!r[i].ssid_len) { fputs("(hidden)", stdout); w = 8; }
        else { print_ssid(r[i].ssid, r[i].ssid_len); w = r[i].ssid_len; }
        for (; w < 32; w++) putchar(' ');
        printf(" %3u %5d  %-24s %us\n", r[i].channel, r[i].rssi, sec, r[i].age_ms / 1000);
    }
    puts("* = this driver can join it (open, or WPA2-PSK CCMP with a saved key); > = current");
    return 0;
}

// ---------------------------------------------------------------- saved networks (root-only plist)

static int hex2bin(const char *h, uint8_t *out, size_t n) {
    if (strlen(h) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int load_nets(void) {
    g_nnets = 0;
    int fd = open(kNetFile, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat sb;
    if (fstat(fd, &sb) || sb.st_size <= 0 || sb.st_size > 1 << 20) { close(fd); return -1; }
    uint8_t *buf = malloc((size_t)sb.st_size);
    ssize_t got = buf ? read(fd, buf, (size_t)sb.st_size) : -1;
    close(fd);
    if (got != sb.st_size) { free(buf); return -1; }
    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, buf, got, kCFAllocatorNull);
    CFPropertyListRef pl = data ? CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL) : NULL;
    if (data) CFRelease(data);
    if (!pl || CFGetTypeID(pl) != CFArrayGetTypeID()) { if (pl) CFRelease(pl); free(buf); return -1; }
    CFArrayRef arr = (CFArrayRef)pl;
    for (CFIndex i = 0; i < CFArrayGetCount(arr) && g_nnets < MAX_NETS; i++) {
        CFDictionaryRef d = CFArrayGetValueAtIndex(arr, i);
        if (CFGetTypeID(d) != CFDictionaryGetTypeID()) continue;
        CFStringRef ssid = CFDictionaryGetValue(d, CFSTR("ssid"));
        if (!ssid || CFGetTypeID(ssid) != CFStringGetTypeID()) continue;
        struct net *n = &g_nets[g_nnets];
        memset(n, 0, sizeof(*n));
        if (!CFStringGetCString(ssid, n->ssid, sizeof(n->ssid), kCFStringEncodingUTF8)) continue;
        CFBooleanRef open = CFDictionaryGetValue(d, CFSTR("open"));
        n->open = open && CFGetTypeID(open) == CFBooleanGetTypeID() && CFBooleanGetValue(open);
        CFStringRef pmk = CFDictionaryGetValue(d, CFSTR("pmk"));
        char hex[65];
        if (pmk && CFGetTypeID(pmk) == CFStringGetTypeID() && CFStringGetCString(pmk, hex, sizeof(hex), kCFStringEncodingASCII) &&
            !hex2bin(hex, n->pmk, 32))
            n->has_pmk = 1;
        if (n->open || n->has_pmk) g_nnets++;
    }
    CFRelease(pl);
    free(buf);
    return 0;
}

static int save_nets(void) {
    if (geteuid() != 0) die("saving networks needs root (sudo)");
    CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 0; i < g_nnets; i++) {
        CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFStringRef s = CFStringCreateWithCString(NULL, g_nets[i].ssid, kCFStringEncodingUTF8);
        if (!s) die("the SSID is not valid UTF-8; the saved list needs UTF-8 names (use `join --ask` for this one)");
        CFDictionarySetValue(d, CFSTR("ssid"), s);
        CFRelease(s);
        CFDictionarySetValue(d, CFSTR("open"), g_nets[i].open ? kCFBooleanTrue : kCFBooleanFalse);
        if (g_nets[i].has_pmk) {
            char hex[65];
            for (int k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", g_nets[i].pmk[k]);
            CFStringRef p = CFStringCreateWithCString(NULL, hex, kCFStringEncodingASCII);
            CFDictionarySetValue(d, CFSTR("pmk"), p);
            CFRelease(p);
            mtk_zero(hex, sizeof(hex));
        }
        CFArrayAppendValue(arr, d);
        CFRelease(d);
    }
    CFDataRef data = CFPropertyListCreateData(NULL, arr, kCFPropertyListXMLFormat_v1_0, 0, NULL);
    CFRelease(arr);
    if (!data) die("could not encode the networks list");
    if (mkdir(kNetDir, 0700) && errno != EEXIST) die("mkdir %s: %s", kNetDir, strerror(errno));
    (void)chmod(kNetDir, 0700);
    (void)chown(kNetDir, 0, 0);
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", kNetFile);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) die("open %s: %s", tmp, strerror(errno));
    (void)fchown(fd, 0, 0);
    ssize_t len = CFDataGetLength(data);
    if (write(fd, CFDataGetBytePtr(data), (size_t)len) != len) die("write %s: %s", tmp, strerror(errno));
    (void)fsync(fd);
    close(fd);
    CFRelease(data);
    if (rename(tmp, kNetFile)) die("rename %s: %s", kNetFile, strerror(errno));
    return 0;
}

static struct net *find_net(const char *ssid) {
    for (int i = 0; i < g_nnets; i++) if (!strcmp(g_nets[i].ssid, ssid)) return &g_nets[i];
    return NULL;
}

// Passphrase from the terminal (never from an argument or the environment), 8 to 63 characters, confirmed twice
static void ask_pmk(const char *ssid, uint8_t pmk[32], int confirm) {
    char p1[128], p2[128];
    if (!readpassphrase("WPA2 passphrase: ", p1, sizeof(p1), RPP_REQUIRE_TTY)) die("no terminal for the passphrase prompt");
    size_t l = strlen(p1);
    if (l < 8 || l > 63) { mtk_zero(p1, sizeof(p1)); die("a WPA2 passphrase has 8 to 63 characters"); }
    if (confirm) {
        if (!readpassphrase("again: ", p2, sizeof(p2), RPP_REQUIRE_TTY)) die("no terminal");
        if (strcmp(p1, p2)) { mtk_zero(p1, sizeof(p1)); mtk_zero(p2, sizeof(p2)); die("the passphrases differ"); }
        mtk_zero(p2, sizeof(p2));
    }
    mtk_wpa_pmk((const uint8_t *)p1, l, (const uint8_t *)ssid, strlen(ssid), pmk);
    mtk_zero(p1, sizeof(p1));
}

static void check_ssid(const char *ssid) {
    size_t l = strlen(ssid);
    if (l < 1 || l > 32) die("an SSID has 1 to 32 bytes");
}

// An MtkAutoNetworks entry for a machine without the native menu (installer, Recovery on another build). Needs no driver.
static int cmd_pmk(const char *ssid) {
    check_ssid(ssid);
    uint8_t pmk[32];
    ask_pmk(ssid, pmk, 1);
    printf("\t\t\t\t<dict>\n\t\t\t\t\t<key>Ssid</key>\n\t\t\t\t\t<string>");
    for (const char *p = ssid; *p; p++) {
        if (*p == '&') fputs("&amp;", stdout);
        else if (*p == '<') fputs("&lt;", stdout);
        else if (*p == '>') fputs("&gt;", stdout);
        else putchar(*p);
    }
    printf("</string>\n\t\t\t\t\t<key>Pmk</key>\n\t\t\t\t\t<string>");
    for (int i = 0; i < 32; i++) printf("%02x", pmk[i]);
    printf("</string>\n\t\t\t\t</dict>\n");
    mtk_zero(pmk, sizeof(pmk));
    fprintf(stderr, "paste it into the MtkAutoNetworks array of MtkWlan.kext/Contents/Info.plist; anyone who can read "
                    "that file can join this network\n");
    return 0;
}

static int cmd_add(const char *ssid, int open) {
    check_ssid(ssid);
    if (load_nets()) die("cannot read %s", kNetFile);
    struct net *n = find_net(ssid);
    if (!n) {
        if (g_nnets >= MAX_NETS) die("too many saved networks");
        n = &g_nets[g_nnets++];
        memset(n, 0, sizeof(*n));
        strlcpy(n->ssid, ssid, sizeof(n->ssid));
    }
    n->open = open;
    n->has_pmk = 0;
    mtk_zero(n->pmk, sizeof(n->pmk));
    if (!open) { ask_pmk(ssid, n->pmk, 1); n->has_pmk = 1; }
    save_nets();
    printf("saved %s (%s) in %s\n", ssid, open ? "open network" : "WPA2-PSK, PMK only", kNetFile);
    return 0;
}

static int cmd_forget(const char *ssid) {
    if (load_nets()) die("cannot read %s", kNetFile);
    int found = 0;
    for (int i = 0; i < g_nnets; i++) {
        if (strcmp(g_nets[i].ssid, ssid)) continue;
        memmove(&g_nets[i], &g_nets[i + 1], (size_t)(g_nnets - i - 1) * sizeof(g_nets[0]));
        g_nnets--;
        found = 1;
        break;
    }
    if (!found) die("%s is not saved", ssid);
    save_nets();
    printf("forgot %s\n", ssid);
    return 0;
}

static int cmd_networks(void) {
    if (load_nets()) die("cannot read %s (root only)", kNetFile);
    if (!g_nnets) { puts("no saved networks (sudo mtkwifi add <ssid>)"); return 0; }
    for (int i = 0; i < g_nnets; i++) printf("%d. %s (%s)\n", i + 1, g_nets[i].ssid, g_nets[i].open ? "open" : "wpa2-psk");
    return 0;
}

// ---------------------------------------------------------------- join

static int send_join(io_connect_t c, const char *ssid, const uint8_t *bssid, const uint8_t *pmk) {
    struct mtk_join_params p;
    memset(&p, 0, sizeof(p));
    p.version = MTK_USER_API_VERSION;
    p.ssid_len = (uint8_t)strlen(ssid);
    memcpy(p.ssid, ssid, p.ssid_len);
    if (bssid) memcpy(p.bssid, bssid, 6);
    if (pmk) { p.key_type = MTK_KEY_PMK; memcpy(p.pmk, pmk, 32); }
    kern_return_t kr = IOConnectCallStructMethod(c, kMtkUcJoin, &p, sizeof(p), NULL, NULL);
    mtk_zero(&p, sizeof(p));
    if (kr != KERN_SUCCESS) { fprintf(stderr, "mtkwifi: join refused: %s (0x%x)\n", kr_text(kr), kr); return -1; }
    return 0;
}

static void print_connected(const struct mtk_status *st, const char *prefix) {
    printf("%s", prefix);
    print_ssid(st->ssid, st->ssid_len);
    printf(" (ch %u, rssi %d dBm, %s)\n", st->channel, st->rssi, st->security == MTK_SEC_RSN ? "wpa2-psk" : "open");
}

// Wait for the join to settle: a new join connected, or a new failure. st0 = the status before the request;
// already = the request names the network we are already on (the driver answers "same", nothing changes).
static int wait_join(io_connect_t c, int timeout_s, const struct mtk_status *st0, int already) {
    struct mtk_status st;
    for (int i = 0; i < timeout_s * 10; i++) {
        sleep_ms(100);
        if (get_status(c, &st)) return -1;
        if (st.state == MTK_ST_CONNECTED && st.port_open) {
            if (st.joins > st0->joins) { print_connected(&st, "connected to "); return 0; }
            if (already && i >= 3) { print_connected(&st, "already connected to "); return 0; }
        }
        if (st.join_failures > st0->join_failures && st.state != MTK_ST_JOINING && st.state != MTK_ST_HANDSHAKE) {
            printf("join failed: %s\n", result_name(st.last_result));
            return 1;
        }
        // not in the cache: the driver rescans every 5 s and keeps trying; report after 15 s of looking
        if (i >= 150 && st.state == MTK_ST_WAITING && st.last_result == MTK_JOIN_NOT_FOUND) { puts("join failed: network not found (the driver keeps looking)"); return 1; }
        if (i >= 150 && st.state == MTK_ST_WAITING && st.last_result == MTK_JOIN_SECURITY) { puts("join failed: security mismatch (no key for a WPA2 network, or an unsupported one)"); return 1; }
    }
    puts("still joining (mtkwifi status shows the outcome)");
    return 2;
}

static int parse_bssid(const char *s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

static int cmd_join(io_connect_t c, const char *ssid, const char *bssid_s, int open, int ask) {
    check_ssid(ssid);
    uint8_t bssid[6], pmk[32];
    const uint8_t *pb = NULL, *pk = NULL;
    if (bssid_s) { if (parse_bssid(bssid_s, bssid)) die("bad BSSID"); pb = bssid; }
    if (ask) { ask_pmk(ssid, pmk, 0); pk = pmk; }
    else if (!open) {
        if (load_nets()) die("cannot read %s (root only)", kNetFile);
        struct net *n = find_net(ssid);
        if (!n) die("%s is not saved: use --open, --ask, or sudo mtkwifi add \"%s\"", ssid, ssid);
        if (!n->open) { memcpy(pmk, n->pmk, 32); pk = pmk; }
    }
    struct mtk_status st0;
    if (get_status(c, &st0)) return 1;
    int already = st0.state == MTK_ST_CONNECTED && st0.port_open && st0.ssid_len == strlen(ssid) && !memcmp(st0.ssid, ssid, st0.ssid_len);
    int rc = send_join(c, ssid, pb, pk);
    mtk_zero(pmk, sizeof(pmk));
    if (rc) return 1;
    return wait_join(c, 25, &st0, already);
}

static int cmd_disconnect(io_connect_t c) {
    kern_return_t kr = IOConnectCallStructMethod(c, kMtkUcDisconnect, NULL, 0, NULL, NULL);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "mtkwifi: disconnect refused: %s (0x%x)\n", kr_text(kr), kr); return 1; }
    puts("disconnected; the driver stays idle until the next join");
    return 0;
}

// The LaunchDaemon: scan, then join the first saved network (file order) that is in range and joinable
static int cmd_autojoin(io_connect_t c) {
    if (load_nets()) die("cannot read %s", kNetFile);
    if (!g_nnets) { puts("autojoin: no saved networks"); return 0; }
    struct mtk_status st;
    if (get_status(c, &st)) return 1;
    if (st.front_end == MTK_FE_NATIVE && !st.auto_open) { puts("autojoin: native front end active, macOS manages the joins"); return 0; }
    for (int i = 0; i < g_nnets; i++)
        if (st.state == MTK_ST_CONNECTED && st.port_open && st.want_active && st.ssid_len == strlen(g_nets[i].ssid) &&
            !memcmp(st.ssid, g_nets[i].ssid, st.ssid_len)) {
            print_connected(&st, "autojoin: already on ");
            return 0;
        }
    if (do_scan(c) || wait_scan(c, 25, st.scans)) return 1;
    struct mtk_scan_result r[MTK_SCAN_MAX];
    int n = get_results(c, r, MTK_SCAN_MAX);
    if (n < 0) return 1;
    for (int i = 0; i < g_nnets; i++) {
        for (int k = 0; k < n; k++) {
            if (r[k].ssid_len != strlen(g_nets[i].ssid) || memcmp(r[k].ssid, g_nets[i].ssid, r[k].ssid_len)) continue;
            // the driver's own rule (open, or WPA2-PSK CCMP without PMF required) decides what is joinable
            int ok = (r[k].flags & MTK_BSS_JOINABLE) && (g_nets[i].open ? r[k].security == MTK_SEC_OPEN : r[k].security == MTK_SEC_RSN);
            if (!ok) continue;
            printf("autojoin: %s (ch %u, rssi %d)\n", g_nets[i].ssid, r[k].channel, r[k].rssi);
            if (send_join(c, g_nets[i].ssid, NULL, g_nets[i].open ? NULL : g_nets[i].pmk)) return 1;
            return wait_join(c, 25, &st, 0) == 0 ? 0 : 1;
        }
    }
    puts("autojoin: no saved network in range");
    return 1;
}

// ---------------------------------------------------------------- main

static void usage(void) __attribute__((noreturn));
static void usage(void) {
    fputs("usage: mtkwifi status [--json] | scan [--wait] | list [--json] | join <ssid> [--bssid X] [--open|--ask] |\n"
          "       disconnect | add <ssid> [--open] | forget <ssid> | networks | autojoin [--wait SECONDS] | pmk <ssid>\n", stderr);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 2) usage();
    const char *cmd = argv[1];
    int json = 0, wait = 0, open = 0, ask = 0, wait_s = 0;
    const char *ssid = NULL, *bssid = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--wait")) { wait = 1; if (i + 1 < argc && argv[i + 1][0] != '-') wait_s = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--open")) open = 1;
        else if (!strcmp(argv[i], "--ask")) ask = 1;
        else if (!strcmp(argv[i], "--bssid") && i + 1 < argc) bssid = argv[++i];
        else if (argv[i][0] == '-') usage();
        else if (!ssid) ssid = argv[i];
        else usage();
    }
    if (!strcmp(cmd, "add")) { if (!ssid) usage(); return cmd_add(ssid, open); }
    if (!strcmp(cmd, "forget")) { if (!ssid) usage(); return cmd_forget(ssid); }
    if (!strcmp(cmd, "networks")) return cmd_networks();
    if (!strcmp(cmd, "pmk")) { if (!ssid) usage(); return cmd_pmk(ssid); }

    io_connect_t c = open_driver(!strcmp(cmd, "autojoin") ? (wait_s ? wait_s : 60) : 0);
    int rc = 0;
    if (!strcmp(cmd, "status")) rc = cmd_status(c, json);
    else if (!strcmp(cmd, "list")) rc = cmd_list(c, json);
    else if (!strcmp(cmd, "scan")) {
        struct mtk_status st0;
        rc = get_status(c, &st0) ? 1 : (do_scan(c) ? 1 : 0);
        if (!rc && wait) rc = wait_scan(c, 25, st0.scans) ? 1 : cmd_list(c, json);
    }
    else if (!strcmp(cmd, "join")) { if (!ssid) usage(); rc = cmd_join(c, ssid, bssid, open, ask); }
    else if (!strcmp(cmd, "disconnect")) rc = cmd_disconnect(c);
    else if (!strcmp(cmd, "autojoin")) rc = cmd_autojoin(c);
    else { IOServiceClose(c); usage(); }
    IOServiceClose(c);
    return rc;
}
