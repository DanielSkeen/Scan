#include "wifi_scan.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_SCAN_RANGES WIFI_SCAN_MAX_INTERFACES
#define MAX_PROBES_PER_RANGE 254
#define MAX_CONCURRENT_PROBES 32

typedef struct {
    uint32_t network;
    uint32_t broadcast;
    uint32_t self;
    int prefix_len;
} ScanRange;

static const char *range_strstr(const char *start, const char *end, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || end <= start || (size_t)(end - start) < needle_len) {
        return NULL;
    }
    for (const char *p = start; p + needle_len <= end; ++p) {
        if (strncmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return NULL;
}

static const char *find_closing_token(const char *open, char open_ch, char close_ch) {
    int depth = 0;
    for (const char *p = open; *p != '\0'; ++p) {
        if (*p == open_ch) {
            depth++;
        } else if (*p == close_ch) {
            depth--;
            if (depth == 0) {
                return p;
            }
        }
    }
    return NULL;
}

static int extract_json_string(
    const char *obj_start,
    const char *obj_end,
    const char *key,
    char *out,
    size_t out_len
) {
    const char *kp = range_strstr(obj_start, obj_end, key);
    if (!kp) {
        out[0] = '\0';
        return 0;
    }

    const char *colon = strchr(kp, ':');
    if (!colon || colon >= obj_end) {
        out[0] = '\0';
        return 0;
    }

    const char *q1 = strchr(colon, '"');
    if (!q1 || q1 >= obj_end) {
        out[0] = '\0';
        return 0;
    }
    q1++;
    const char *q2 = strchr(q1, '"');
    if (!q2 || q2 > obj_end) {
        out[0] = '\0';
        return 0;
    }

    size_t n = (size_t)(q2 - q1);
    if (n >= out_len) {
        n = out_len - 1;
    }
    memcpy(out, q1, n);
    out[n] = '\0';
    return 1;
}

static void parse_network_object(const char *obj_start, const char *obj_end, WifiNetworkInfo *info) {
    char ssid[256] = "";
    char channel[64] = "";
    char security[128] = "";
    char signal_noise[64] = "";
    char phy_mode[64] = "";

    extract_json_string(obj_start, obj_end, "\"_name\"", ssid, sizeof(ssid));
    extract_json_string(obj_start, obj_end, "\"spairport_network_channel\"", channel, sizeof(channel));
    extract_json_string(obj_start, obj_end, "\"spairport_security_mode\"", security, sizeof(security));
    extract_json_string(obj_start, obj_end, "\"spairport_signal_noise\"", signal_noise, sizeof(signal_noise));
    extract_json_string(obj_start, obj_end, "\"spairport_network_phymode\"", phy_mode, sizeof(phy_mode));

    snprintf(info->ssid, sizeof(info->ssid), "%s", ssid[0] ? ssid : "unknown");
    snprintf(info->channel, sizeof(info->channel), "%s", channel[0] ? channel : "n/a");
    snprintf(info->security, sizeof(info->security), "%s", security[0] ? security : "n/a");
    snprintf(info->signal_noise, sizeof(info->signal_noise), "%s", signal_noise[0] ? signal_noise : "n/a");
    snprintf(info->phy_mode, sizeof(info->phy_mode), "%s", phy_mode[0] ? phy_mode : "n/a");
}

static void parse_nearby_array(const char *json, WifiScanResult *result) {
    const char *key = "\"spairport_airport_other_local_wireless_networks\"";
    const char *p = strstr(json, key);
    if (!p) {
        return;
    }

    const char *open = strchr(p, '[');
    if (!open) {
        return;
    }

    const char *close = find_closing_token(open, '[', ']');
    if (!close) {
        return;
    }

    const char *cursor = open;
    while (cursor < close && result->count < WIFI_SCAN_MAX_NETWORKS) {
        const char *obj_start = strchr(cursor, '{');
        if (!obj_start || obj_start >= close) {
            break;
        }
        const char *obj_end = find_closing_token(obj_start, '{', '}');
        if (!obj_end || obj_end > close) {
            break;
        }

        WifiNetworkInfo *info = &result->networks[result->count];
        memset(info, 0, sizeof(*info));
        parse_network_object(obj_start, obj_end, info);
        info->connected = 0;

        if (strcmp(info->ssid, "<redacted>") == 0) {
            result->redacted_count++;
        }

        result->count++;
        cursor = obj_end + 1;
    }
}

static void parse_current_network(const char *json, WifiScanResult *result) {
    if (result->count >= WIFI_SCAN_MAX_NETWORKS) {
        return;
    }

    const char *key = "\"spairport_current_network_information\"";
    const char *p = strstr(json, key);
    if (!p) {
        return;
    }

    const char *open = strchr(p, '{');
    if (!open) {
        return;
    }
    const char *close = find_closing_token(open, '{', '}');
    if (!close) {
        return;
    }

    WifiNetworkInfo *info = &result->networks[result->count];
    memset(info, 0, sizeof(*info));
    parse_network_object(open, close, info);
    info->connected = 1;

    if (strcmp(info->ssid, "<redacted>") == 0) {
        result->redacted_count++;
    }

    result->count++;
}

static int parse_wifi_data(WifiScanResult *result) {
    const char *cmd = "/usr/sbin/system_profiler SPAirPortDataType -json 2>/dev/null";
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return -1;
    }

    size_t cap = 65536;
    size_t len = 0;
    char *json = (char *)malloc(cap);
    if (!json) {
        pclose(fp);
        return -1;
    }

    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        if (len + 2 >= cap) {
            cap *= 2;
            char *tmp = (char *)realloc(json, cap);
            if (!tmp) {
                free(json);
                pclose(fp);
                return -1;
            }
            json = tmp;
        }
        json[len++] = (char)ch;
    }
    json[len] = '\0';
    pclose(fp);

    parse_nearby_array(json, result);
    parse_current_network(json, result);

    free(json);
    result->wifi_available = (result->count > 0);
    return 0;
}

static int mask_prefix_len(uint32_t mask) {
    int bits = 0;
    for (int i = 31; i >= 0; --i) {
        if ((mask >> i) & 1U) {
            bits++;
        } else {
            break;
        }
    }
    return bits;
}

static int add_interface(
    ScanResult *result,
    ScanRange *ranges,
    size_t *range_count,
    const char *ifname,
    const struct in_addr *ip,
    const struct in_addr *netmask
) {
    if (result->interface_count >= WIFI_SCAN_MAX_INTERFACES || *range_count >= MAX_SCAN_RANGES) {
        return 0;
    }

    uint32_t ip_u32 = ntohl(ip->s_addr);
    uint32_t mask_u32 = ntohl(netmask->s_addr);
    uint32_t network_u32 = ip_u32 & mask_u32;
    uint32_t broadcast_u32 = network_u32 | (~mask_u32);

    if (ip_u32 == 0 || mask_u32 == 0) {
        return 0;
    }

    if ((ip_u32 & 0xFFFF0000U) == 0xA9FE0000U) {
        return 0;
    }

    LocalInterfaceInfo *out = &result->interfaces[result->interface_count];
    memset(out, 0, sizeof(*out));

    snprintf(out->interface, sizeof(out->interface), "%s", ifname);
    if (!inet_ntop(AF_INET, ip, out->ip, sizeof(out->ip))) {
        return 0;
    }
    if (!inet_ntop(AF_INET, netmask, out->netmask, sizeof(out->netmask))) {
        return 0;
    }

    out->prefix_len = mask_prefix_len(mask_u32);

    struct in_addr network_addr;
    network_addr.s_addr = htonl(network_u32);
    char network_buf[16] = "";
    if (!inet_ntop(AF_INET, &network_addr, network_buf, sizeof(network_buf))) {
        return 0;
    }
    snprintf(out->cidr, sizeof(out->cidr), "%s/%d", network_buf, out->prefix_len);

    ScanRange *range = &ranges[*range_count];
    range->network = network_u32;
    range->broadcast = broadcast_u32;
    range->self = ip_u32;
    range->prefix_len = out->prefix_len;

    result->interface_count++;
    (*range_count)++;
    return 1;
}

static size_t collect_interfaces(ScanResult *result, ScanRange *ranges, size_t *range_count) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        return 0;
    }

    size_t added = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_RUNNING) == 0) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }

        const struct sockaddr_in *ip = (const struct sockaddr_in *)ifa->ifa_addr;
        const struct sockaddr_in *mask = (const struct sockaddr_in *)ifa->ifa_netmask;
        added += (size_t)add_interface(result, ranges, range_count, ifa->ifa_name, &ip->sin_addr, &mask->sin_addr);
    }

    freeifaddrs(ifaddr);
    return added;
}

static int ip_in_range(uint32_t ip, const ScanRange *range) {
    return ip >= range->network && ip <= range->broadcast;
}

static int ip_in_any_range(uint32_t ip, const ScanRange *ranges, size_t range_count) {
    for (size_t i = 0; i < range_count; ++i) {
        if (ip_in_range(ip, &ranges[i])) {
            return 1;
        }
    }
    return 0;
}

static int is_host_address_in_any_range(uint32_t ip, const ScanRange *ranges, size_t range_count) {
    for (size_t i = 0; i < range_count; ++i) {
        const ScanRange *r = &ranges[i];
        if (!ip_in_range(ip, r)) {
            continue;
        }
        if (ip == r->network || ip == r->broadcast || ip == r->self) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static void wait_for_child(void) {
    int status = 0;
    while (wait(&status) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
}

static int spawn_ping_probe(const char *ip) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        FILE *null_out = fopen("/dev/null", "w");
        if (null_out) {
            dup2(fileno(null_out), STDOUT_FILENO);
            dup2(fileno(null_out), STDERR_FILENO);
            fclose(null_out);
        }
        execl("/sbin/ping", "ping", "-n", "-q", "-c", "1", "-W", "400", ip, (char *)NULL);
        _exit(127);
    }

    return 0;
}

static void probe_range(const ScanRange *range, ScanResult *result) {
    if (range->prefix_len < 24) {
        result->skipped_probe_networks++;
        return;
    }

    if (range->broadcast <= range->network + 1U) {
        return;
    }

    uint32_t host_count = range->broadcast - range->network - 1U;
    if (host_count > MAX_PROBES_PER_RANGE) {
        result->skipped_probe_networks++;
        return;
    }

    size_t active_children = 0;

    for (uint32_t ip = range->network + 1U; ip < range->broadcast; ++ip) {
        if (ip == range->self) {
            continue;
        }

        struct in_addr addr;
        addr.s_addr = htonl(ip);

        char ip_buf[16] = "";
        if (!inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf))) {
            continue;
        }

        if (spawn_ping_probe(ip_buf) == 0) {
            result->probe_count++;
            active_children++;
        }

        if (active_children >= MAX_CONCURRENT_PROBES) {
            wait_for_child();
            active_children--;
        }
    }

    while (active_children > 0) {
        wait_for_child();
        active_children--;
    }
}

static int find_device_index(const ScanResult *result, const char *ip) {
    for (size_t i = 0; i < result->device_count; ++i) {
        if (strcmp(result->devices[i].ip, ip) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void collect_default_gateway(ScanResult *result) {
    FILE *fp = popen("/sbin/route -n get default 2>/dev/null", "r");
    if (!fp) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        const char *key = "gateway:";
        char *p = strstr(line, key);
        if (!p) {
            continue;
        }

        p += strlen(key);
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        size_t n = 0;
        while (p[n] != '\0' && p[n] != '\n' && p[n] != '\r' && p[n] != ' ' && p[n] != '\t') {
            n++;
        }

        if (n > 0 && n < sizeof(result->default_gateway_ip)) {
            memcpy(result->default_gateway_ip, p, n);
            result->default_gateway_ip[n] = '\0';
        }
        break;
    }

    pclose(fp);
}

static void resolve_hostname(const char *ip, char *out, size_t out_len) {
    out[0] = '\0';

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_len = sizeof(sa);
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        return;
    }

    if (getnameinfo((const struct sockaddr *)&sa, sizeof(sa), out, (socklen_t)out_len, NULL, 0, NI_NAMEREQD) != 0) {
        out[0] = '\0';
    }
}

static void upsert_device(ScanResult *result, const char *ip, const char *mac, const char *ifname, int reachable) {
    int idx = find_device_index(result, ip);
    LocalDeviceInfo *dev = NULL;

    if (idx < 0) {
        if (result->device_count >= WIFI_SCAN_MAX_DEVICES) {
            return;
        }
        dev = &result->devices[result->device_count++];
        memset(dev, 0, sizeof(*dev));
        snprintf(dev->ip, sizeof(dev->ip), "%s", ip);
        resolve_hostname(ip, dev->hostname, sizeof(dev->hostname));
    } else {
        dev = &result->devices[idx];
    }

    if (mac && mac[0]) {
        snprintf(dev->mac, sizeof(dev->mac), "%s", mac);
    }
    if (ifname && ifname[0]) {
        snprintf(dev->interface, sizeof(dev->interface), "%s", ifname);
    }
    if (reachable) {
        dev->reachable = 1;
    }

    if (result->default_gateway_ip[0] != '\0' && strcmp(ip, result->default_gateway_ip) == 0) {
        dev->is_gateway = 1;
    }
}

static void collect_device_rtt(ScanResult *result) {
    for (size_t i = 0; i < result->device_count; ++i) {
        LocalDeviceInfo *d = &result->devices[i];
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "/sbin/ping -n -q -c 1 -W 300 %s 2>/dev/null", d->ip);

        FILE *fp = popen(cmd, "r");
        if (!fp) {
            continue;
        }

        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strstr(line, "round-trip") || strstr(line, "round trip")) {
                float min_ms = 0.0f;
                float avg_ms = 0.0f;
                float max_ms = 0.0f;
                float std_ms = 0.0f;
                int parsed = sscanf(
                    line,
                    "%*[^=]= %f/%f/%f/%f ms",
                    &min_ms,
                    &avg_ms,
                    &max_ms,
                    &std_ms
                );
                if (parsed == 4) {
                    d->has_rtt = 1;
                    d->rtt_ms = avg_ms;
                }
                break;
            }
        }

        pclose(fp);
    }
}

static void trim_token(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

static void parse_arp_line(const char *line, const ScanRange *ranges, size_t range_count, ScanResult *result) {
    const char *lp = strchr(line, '(');
    const char *rp = lp ? strchr(lp, ')') : NULL;
    if (!lp || !rp || rp <= lp + 1) {
        return;
    }

    char ip[16] = "";
    size_t ip_len = (size_t)(rp - lp - 1);
    if (ip_len >= sizeof(ip)) {
        return;
    }
    memcpy(ip, lp + 1, ip_len);
    ip[ip_len] = '\0';

    struct in_addr ip_addr;
    if (inet_pton(AF_INET, ip, &ip_addr) != 1) {
        return;
    }
    uint32_t ip_u32 = ntohl(ip_addr.s_addr);
    if (!ip_in_any_range(ip_u32, ranges, range_count)) {
        return;
    }
    if (!is_host_address_in_any_range(ip_u32, ranges, range_count)) {
        return;
    }

    const char *at = strstr(rp, " at ");
    const char *on = strstr(rp, " on ");
    if (!at || !on || on <= at + 4) {
        return;
    }

    char mac[32] = "";
    size_t mac_len = (size_t)(on - (at + 4));
    if (mac_len >= sizeof(mac)) {
        mac_len = sizeof(mac) - 1;
    }
    memcpy(mac, at + 4, mac_len);
    mac[mac_len] = '\0';
    trim_token(mac);

    char ifname[32] = "";
    const char *if_start = on + 4;
    size_t if_len = 0;
    while (if_start[if_len] != '\0' && if_start[if_len] != ' ' && if_start[if_len] != '\n') {
        if_len++;
    }
    if (if_len >= sizeof(ifname)) {
        if_len = sizeof(ifname) - 1;
    }
    memcpy(ifname, if_start, if_len);
    ifname[if_len] = '\0';

    int reachable = (strcmp(mac, "(incomplete)") != 0);
    if (!reachable) {
        return;
    }
    upsert_device(result, ip, mac, ifname, reachable);
}

static void collect_devices_from_arp(const ScanRange *ranges, size_t range_count, ScanResult *result) {
    FILE *fp = popen("/usr/sbin/arp -an", "r");
    if (!fp) {
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        parse_arp_line(line, ranges, range_count, result);
    }

    pclose(fp);
}

static uint32_t parse_ip_to_u32(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

static int lower_ascii(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle || needle[0] == '\0') {
        return 0;
    }

    size_t nlen = strlen(needle);
    for (size_t i = 0; haystack[i] != '\0'; ++i) {
        size_t j = 0;
        while (j < nlen && haystack[i + j] != '\0' && lower_ascii(haystack[i + j]) == lower_ascii(needle[j])) {
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }

    return 0;
}

static int is_weather_device(const LocalDeviceInfo *d) {
    return contains_case_insensitive(d->hostname, "weather") ||
           contains_case_insensitive(d->hostname, "weatherstation");
}

static void collect_weather_ping(ScanResult *result) {
    if (result->weather_station_ip[0] == '\0') {
        return;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/sbin/ping -n -q -c 4 -W 400 %s 2>/dev/null", result->weather_station_ip);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return;
    }

    char line[256];
    int loss_found = 0;
    int rtt_found = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "packet loss")) {
            int loss_pct = -1;
            if (sscanf(line, "%*d packets transmitted, %*d packets received, %d.%*d%% packet loss", &loss_pct) == 1 ||
                sscanf(line, "%*d packets transmitted, %*d packets received, %d%% packet loss", &loss_pct) == 1) {
                result->weather_ping_loss_pct = loss_pct;
                loss_found = 1;
            }
        }

        if (strstr(line, "round-trip") || strstr(line, "round trip")) {
            float min_ms = 0.0f;
            float avg_ms = 0.0f;
            float max_ms = 0.0f;
            float std_ms = 0.0f;
            int parsed = sscanf(line, "%*[^=]= %f/%f/%f/%f ms", &min_ms, &avg_ms, &max_ms, &std_ms);
            if (parsed == 4) {
                result->weather_ping_min_ms = min_ms;
                result->weather_ping_avg_ms = avg_ms;
                result->weather_ping_max_ms = max_ms;
                rtt_found = 1;
            }
        }
    }

    pclose(fp);
    result->weather_ping_available = (loss_found || rtt_found);
}

static int compare_devices_by_ip(const void *a, const void *b) {
    const LocalDeviceInfo *da = (const LocalDeviceInfo *)a;
    const LocalDeviceInfo *db = (const LocalDeviceInfo *)b;

    int wa = is_weather_device(da);
    int wb = is_weather_device(db);
    if (wa != wb) {
        return wb - wa;
    }

    uint32_t ia = parse_ip_to_u32(da->ip);
    uint32_t ib = parse_ip_to_u32(db->ip);
    if (ia < ib) {
        return -1;
    }
    if (ia > ib) {
        return 1;
    }
    return strcmp(da->ip, db->ip);
}

int wifi_scan_collect(ScanResult *result, char *err, size_t err_len) {
    ScanRange ranges[MAX_SCAN_RANGES];
    size_t range_count = 0;

    memset(result, 0, sizeof(*result));
    collect_default_gateway(result);

    collect_interfaces(result, ranges, &range_count);
    for (size_t i = 0; i < range_count; ++i) {
        probe_range(&ranges[i], result);
    }
    collect_devices_from_arp(ranges, range_count, result);
    collect_device_rtt(result);

    (void)parse_wifi_data(&result->wifi);

    if (result->device_count > 1) {
        qsort(result->devices, result->device_count, sizeof(result->devices[0]), compare_devices_by_ip);
    }

    for (size_t i = 0; i < result->device_count; ++i) {
        if (is_weather_device(&result->devices[i])) {
            snprintf(result->weather_station_ip, sizeof(result->weather_station_ip), "%s", result->devices[i].ip);
            break;
        }
    }

    collect_weather_ping(result);

    if (result->interface_count == 0 && result->wifi.count == 0) {
        if (err && err_len > 0) {
            snprintf(err, err_len, "no active local network interfaces found");
        }
        return -1;
    }

    if (err && err_len > 0) {
        err[0] = '\0';
    }
    return 0;
}

void wifi_scan_print(const ScanResult *result) {
    printf("Local networks: %zu\n", result->interface_count);
    if (result->default_gateway_ip[0] != '\0') {
        printf("Default gateway: %s\n", result->default_gateway_ip);
    }
    if (result->weather_station_ip[0] != '\0') {
        printf("Weather station IP: %s\n", result->weather_station_ip);
        if (result->weather_ping_available) {
            printf("Weather ping: loss=%d%%  min/avg/max=%.1f/%.1f/%.1f ms\n",
                   result->weather_ping_loss_pct,
                   result->weather_ping_min_ms,
                   result->weather_ping_avg_ms,
                   result->weather_ping_max_ms);
        }
    }
    for (size_t i = 0; i < result->interface_count; ++i) {
        const LocalInterfaceInfo *iface = &result->interfaces[i];
        printf("[%zu] %s  ip=%s  netmask=%s  subnet=%s\n", i + 1, iface->interface, iface->ip, iface->netmask, iface->cidr);
    }

    printf("\nDevice discovery: %zu hosts", result->device_count);
    if (result->probe_count > 0) {
        printf(" (active probes: %zu)", result->probe_count);
    }
    if (result->skipped_probe_networks > 0) {
        printf(" (skipped wide subnets: %zu)", result->skipped_probe_networks);
    }
    printf("\n");

    for (size_t i = 0; i < result->device_count; ++i) {
        const LocalDeviceInfo *d = &result->devices[i];
        printf("[%zu] ip=%s", i + 1, d->ip);
        if (d->is_gateway) {
            printf(" [gateway]");
        }
        printf("  host=%s", d->hostname[0] ? d->hostname : "n/a");
        printf("  mac=%s", d->mac[0] ? d->mac : "n/a");
        printf("  iface=%s", d->interface[0] ? d->interface : "n/a");
        if (d->has_rtt) {
            printf("  rtt=%.1fms", d->rtt_ms);
        }
        printf("  reachable=%s\n", d->reachable ? "yes" : "unknown");
    }

    printf("\nWi-Fi scan results: %zu networks\n", result->wifi.count);
    if (result->wifi.redacted_count > 0) {
        printf("Note: %zu SSID value(s) are redacted by macOS privacy controls.\n", result->wifi.redacted_count);
    }

    for (size_t i = 0; i < result->wifi.count; ++i) {
        const WifiNetworkInfo *n = &result->wifi.networks[i];
        printf("\n[%zu] %s%s\n", i + 1, n->connected ? "* CONNECTED: " : "  SSID: ", n->ssid);
        printf("    Channel: %s\n", n->channel);
        printf("    Security: %s\n", n->security);
        printf("    Signal/Noise: %s\n", n->signal_noise);
        printf("    PHY Mode: %s\n", n->phy_mode);
    }
}
