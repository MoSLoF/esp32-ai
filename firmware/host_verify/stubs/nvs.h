// Host test stub for ESP-IDF's nvs.h. Backs NVS with a small in-memory
// key/value store that persists for the life of the test process, which is
// exactly the persistence behavioral tests need: a simulated "reboot" is
// just calling the firmware's init function again in the same process, and
// this store -- unlike the real device's flash -- is never wiped in between,
// so the same handle/namespace behavior the real firmware relies on
// (values surviving across nvs_open calls) is preserved.
#ifndef HOST_STUB_NVS_H
#define HOST_STUB_NVS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef HOST_STUB_ESP_ERR_T
#define HOST_STUB_ESP_ERR_T
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#endif

#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define ESP_ERR_NVS_NO_FREE_PAGES 0x1103
#define ESP_ERR_NVS_NEW_VERSION_FOUND 0x1104

typedef uint32_t nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;

#define HOST_NVS_MAX_NS   8
#define HOST_NVS_MAX_KEYS 16

struct host_nvs_kv { char key[32]; uint32_t value; int used; };
struct host_nvs_ns { char name[32]; struct host_nvs_kv kv[HOST_NVS_MAX_KEYS]; int used; };
static struct host_nvs_ns host_nvs_store[HOST_NVS_MAX_NS];

static inline esp_err_t nvs_open(const char *name, nvs_open_mode_t mode, nvs_handle_t *out) {
  (void)mode;
  for (int i = 0; i < HOST_NVS_MAX_NS; i++) {
    if (host_nvs_store[i].used && strcmp(host_nvs_store[i].name, name) == 0) {
      *out = (nvs_handle_t)(i + 1);
      return ESP_OK;
    }
  }
  for (int i = 0; i < HOST_NVS_MAX_NS; i++) {
    if (!host_nvs_store[i].used) {
      host_nvs_store[i].used = 1;
      strncpy(host_nvs_store[i].name, name, sizeof(host_nvs_store[i].name) - 1);
      *out = (nvs_handle_t)(i + 1);
      return ESP_OK;
    }
  }
  return ESP_FAIL;
}

static inline esp_err_t nvs_get_u32(nvs_handle_t h, const char *key, uint32_t *out) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  for (int i = 0; i < HOST_NVS_MAX_KEYS; i++) {
    if (ns->kv[i].used && strcmp(ns->kv[i].key, key) == 0) {
      *out = ns->kv[i].value;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}

static inline esp_err_t nvs_get_u8(nvs_handle_t h, const char *key, uint8_t *out) {
  uint32_t v;
  esp_err_t e = nvs_get_u32(h, key, &v);
  if (e == ESP_OK) *out = (uint8_t)v;
  return e;
}

static inline esp_err_t nvs_set_u32(nvs_handle_t h, const char *key, uint32_t value) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  for (int i = 0; i < HOST_NVS_MAX_KEYS; i++) {
    if (ns->kv[i].used && strcmp(ns->kv[i].key, key) == 0) {
      ns->kv[i].value = value;
      return ESP_OK;
    }
  }
  for (int i = 0; i < HOST_NVS_MAX_KEYS; i++) {
    if (!ns->kv[i].used) {
      ns->kv[i].used = 1;
      strncpy(ns->kv[i].key, key, sizeof(ns->kv[i].key) - 1);
      ns->kv[i].value = value;
      return ESP_OK;
    }
  }
  return ESP_FAIL;
}

static inline esp_err_t nvs_set_u8(nvs_handle_t h, const char *key, uint8_t value) {
  return nvs_set_u32(h, key, value);
}

static inline esp_err_t nvs_erase_key(nvs_handle_t h, const char *key) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  for (int i = 0; i < HOST_NVS_MAX_KEYS; i++) {
    if (ns->kv[i].used && strcmp(ns->kv[i].key, key) == 0) {
      ns->kv[i].used = 0;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}

static inline esp_err_t nvs_commit(nvs_handle_t h) { (void)h; return ESP_OK; }
static inline void nvs_close(nvs_handle_t h) { (void)h; }

// Test-only helper: wipe the whole store to simulate a factory-erased flash.
static inline void host_nvs_wipe(void) {
  memset(host_nvs_store, 0, sizeof(host_nvs_store));
}

#endif
