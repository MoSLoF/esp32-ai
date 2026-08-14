// Host test stub for ESP-IDF's nvs_flash.h.
#ifndef HOST_STUB_NVS_FLASH_H
#define HOST_STUB_NVS_FLASH_H

#include "nvs.h"

static inline esp_err_t nvs_flash_init(void) { return ESP_OK; }
static inline esp_err_t nvs_flash_erase(void) { host_nvs_wipe(); return ESP_OK; }

#endif
