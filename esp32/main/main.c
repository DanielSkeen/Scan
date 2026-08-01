#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "scan.h"
#include "scan_app.h"

static const char *TAG = "scan";

void app_main(void) {
    ScanAppState app;
    scan_app_init(&app);

    ESP_LOGI(TAG, "%s", scan_banner());
    ESP_LOGI(TAG, "ESP32 base target initialized (display backend comes next).");

    while (app.running) {
        scan_app_update(&app, 0.1f);
        ESP_LOGI(TAG, "uptime=%.1fs", (double)app.elapsed_seconds);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
