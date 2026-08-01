#include "wifi_scan.h"

#include <stdio.h>
#include <string.h>

int wifi_scan_collect(ScanResult *result, char *err, size_t err_len) {
    memset(result, 0, sizeof(*result));
    if (err && err_len > 0) {
        snprintf(err, err_len, "wifi scan backend not implemented for this target yet");
    }
    return -1;
}

void wifi_scan_print(const ScanResult *result) {
    (void)result;
    puts("Wi-Fi scan backend not implemented for this target yet.");
}