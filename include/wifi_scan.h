#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <stddef.h>

#define WIFI_SCAN_MAX_NETWORKS 128
#define WIFI_SCAN_MAX_INTERFACES 16
#define WIFI_SCAN_MAX_DEVICES 512

typedef struct {
    char ssid[256];
    char channel[64];
    char security[128];
    char signal_noise[64];
    char phy_mode[64];
    int connected;
} WifiNetworkInfo;

typedef struct {
    WifiNetworkInfo networks[WIFI_SCAN_MAX_NETWORKS];
    size_t count;
    size_t redacted_count;
    int wifi_available;
} WifiScanResult;

typedef struct {
    char interface[32];
    char ip[16];
    char netmask[16];
    char cidr[24];
    int prefix_len;
} LocalInterfaceInfo;

typedef struct {
    char ip[16];
    char hostname[256];
    char mac[32];
    char interface[32];
    int reachable;
    int is_gateway;
    int has_rtt;
    float rtt_ms;
} LocalDeviceInfo;

typedef struct {
    WifiScanResult wifi;
    LocalInterfaceInfo interfaces[WIFI_SCAN_MAX_INTERFACES];
    size_t interface_count;
    LocalDeviceInfo devices[WIFI_SCAN_MAX_DEVICES];
    size_t device_count;
    char default_gateway_ip[16];
    char weather_station_ip[16];
    int weather_ping_available;
    int weather_ping_loss_pct;
    float weather_ping_min_ms;
    float weather_ping_avg_ms;
    float weather_ping_max_ms;
    size_t probe_count;
    size_t skipped_probe_networks;
} ScanResult;

int wifi_scan_collect(ScanResult *result, char *err, size_t err_len);
void wifi_scan_print(const ScanResult *result);

#endif