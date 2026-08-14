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
#define HOST_NVS_MAX_BLOB_KEYS 4
#define HOST_NVS_MAX_BLOB_LEN  512

struct host_nvs_kv { char key[32]; uint32_t value; int used; };
struct host_nvs_blob_kv { char key[32]; uint8_t data[HOST_NVS_MAX_BLOB_LEN]; size_t len; int used; };
struct host_nvs_ns {
  char name[32];
  struct host_nvs_kv kv[HOST_NVS_MAX_KEYS];
  struct host_nvs_blob_kv blob[HOST_NVS_MAX_BLOB_KEYS];
  int used;
};
static struct host_nvs_ns host_nvs_store[HOST_NVS_MAX_NS];

// ---- Test-only fault injection --------------------------------------------
// Lets behavioral tests simulate NVS/flash failures at precise points, to
// verify fail-closed behavior (R5-01/R5-03 verification-memo hardening) --
// something that couldn't be tested at all before this existed, since the
// stub previously always succeeded. Each counter: 0 = never fail (default),
// N>0 = fail exactly the next N matching calls then stop failing, -1 = fail
// every matching call until reset (sticky). only_ns/only_key restrict which
// calls match; an empty string matches anything.
struct host_nvs_fault {
  int nvs_open_n;
  int nvs_set_u32_n;   // also covers nvs_set_u8 (implemented via set_u32)
  int nvs_set_blob_n;
  int nvs_commit_n;
  int nvs_erase_key_n;
  int nvs_get_u32_n;   // also covers nvs_get_u8
  int nvs_get_blob_n;
  char only_ns[32];
  char only_key[32];
};
static struct host_nvs_fault host_nvs_fault;

static inline int _host_nvs_fault_match(const char *ns, const char *key) {
  if (host_nvs_fault.only_ns[0] && (!ns || strcmp(host_nvs_fault.only_ns, ns) != 0)) return 0;
  if (host_nvs_fault.only_key[0] && (!key || strcmp(host_nvs_fault.only_key, key) != 0)) return 0;
  return 1;
}
static inline int _host_nvs_fault_consume(int *counter, const char *ns, const char *key) {
  if (*counter == 0 || !_host_nvs_fault_match(ns, key)) return 0;
  if (*counter > 0) (*counter)--;
  return 1;
}
// Test-only helper: clear all fault-injection state (independent of
// host_nvs_wipe() below -- tests reset each explicitly, since "wipe the
// data" and "stop injecting faults" are orthogonal concerns).
static inline void host_nvs_fault_reset(void) {
  memset(&host_nvs_fault, 0, sizeof(host_nvs_fault));
}

static inline esp_err_t nvs_open(const char *name, nvs_open_mode_t mode, nvs_handle_t *out) {
  (void)mode;
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_open_n, name, NULL)) return ESP_FAIL;
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
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_get_u32_n, ns->name, key)) return ESP_FAIL;
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
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_set_u32_n, ns->name, key)) return ESP_FAIL;
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

static inline esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_get_blob_n, ns->name, key)) return ESP_FAIL;
  for (int i = 0; i < HOST_NVS_MAX_BLOB_KEYS; i++) {
    if (ns->blob[i].used && strcmp(ns->blob[i].key, key) == 0) {
      size_t n = ns->blob[i].len < *len ? ns->blob[i].len : *len;
      memcpy(out, ns->blob[i].data, n);
      *len = ns->blob[i].len;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}

static inline esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *value, size_t len) {
  if (len > HOST_NVS_MAX_BLOB_LEN) return ESP_FAIL;
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_set_blob_n, ns->name, key)) return ESP_FAIL;
  for (int i = 0; i < HOST_NVS_MAX_BLOB_KEYS; i++) {
    if (ns->blob[i].used && strcmp(ns->blob[i].key, key) == 0) {
      memcpy(ns->blob[i].data, value, len);
      ns->blob[i].len = len;
      return ESP_OK;
    }
  }
  for (int i = 0; i < HOST_NVS_MAX_BLOB_KEYS; i++) {
    if (!ns->blob[i].used) {
      ns->blob[i].used = 1;
      strncpy(ns->blob[i].key, key, sizeof(ns->blob[i].key) - 1);
      memcpy(ns->blob[i].data, value, len);
      ns->blob[i].len = len;
      return ESP_OK;
    }
  }
  return ESP_FAIL;
}

static inline esp_err_t nvs_erase_key(nvs_handle_t h, const char *key) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_erase_key_n, ns->name, key)) return ESP_FAIL;
  for (int i = 0; i < HOST_NVS_MAX_KEYS; i++) {
    if (ns->kv[i].used && strcmp(ns->kv[i].key, key) == 0) {
      ns->kv[i].used = 0;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}

static inline esp_err_t nvs_commit(nvs_handle_t h) {
  struct host_nvs_ns *ns = &host_nvs_store[h - 1];
  if (_host_nvs_fault_consume(&host_nvs_fault.nvs_commit_n, ns->name, NULL)) return ESP_FAIL;
  return ESP_OK;
}
static inline void nvs_close(nvs_handle_t h) { (void)h; }

// Test-only helper: wipe the whole store to simulate a factory-erased flash.
// Does NOT reset fault-injection state (host_nvs_fault_reset() above) --
// "wipe the data" and "stop injecting faults" are orthogonal concerns, and
// tests must reset each explicitly.
static inline void host_nvs_wipe(void) {
  memset(host_nvs_store, 0, sizeof(host_nvs_store));
}

#endif
