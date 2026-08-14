// Host test stub for ESP-IDF's esp_ota_ops.h. Only esp_ota_get_running_partition()
// is used by ota_verify.h's recovery logic; the test drives what it returns
// directly via host_mock_running_partition, standing in for "which
// partition the bootloader actually chose and booted" -- the ground truth
// R5-03's recovery check compares the journaled target against.
#ifndef HOST_STUB_ESP_OTA_OPS_H
#define HOST_STUB_ESP_OTA_OPS_H

#include <stddef.h>
#include "esp_partition.h"

#ifndef HOST_STUB_ESP_ERR_T
#define HOST_STUB_ESP_ERR_T
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#endif

typedef uint32_t esp_ota_handle_t;

static esp_partition_t host_mock_running_partition = { 0, 0, 0, 0, "ota_0" };

static inline const esp_partition_t *esp_ota_get_running_partition(void) {
  return &host_mock_running_partition;
}

static inline const esp_partition_t *esp_ota_get_next_update_partition(const esp_partition_t *start) {
  (void)start;
  return NULL;
}

static inline esp_err_t esp_ota_begin(const esp_partition_t *p, size_t size, esp_ota_handle_t *out) {
  (void)p; (void)size; (void)out; return ESP_OK;
}
static inline esp_err_t esp_ota_write(esp_ota_handle_t h, const void *data, size_t size) {
  (void)h; (void)data; (void)size; return ESP_OK;
}
static inline esp_err_t esp_ota_end(esp_ota_handle_t h) { (void)h; return ESP_OK; }
static inline esp_err_t esp_ota_abort(esp_ota_handle_t h) { (void)h; return ESP_OK; }
static inline esp_err_t esp_ota_set_boot_partition(const esp_partition_t *p) { (void)p; return ESP_OK; }

#endif
