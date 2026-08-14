// Host test stub for ESP-IDF's esp_now.h -- just enough of the API surface
// for espnow_comm.h to compile and its RX rate-limiting/replay logic to be
// driven directly. None of these need to actually talk to a radio: the
// behavioral tests call _espnow_rx()/espnow_provision_peer() etc. directly
// rather than going through espnow_begin()'s real init sequence.
#ifndef HOST_STUB_ESP_NOW_H
#define HOST_STUB_ESP_NOW_H

#include <stdint.h>

#ifndef HOST_STUB_ESP_ERR_T
#define HOST_STUB_ESP_ERR_T
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#endif

typedef struct {
  const uint8_t *src_addr;
  const uint8_t *des_addr;
} esp_now_recv_info_t;

typedef struct {
  uint8_t peer_addr[6];
  uint8_t channel;
  int ifidx;
  bool encrypt;
  uint8_t lmk[16];
} esp_now_peer_info_t;

typedef void (*esp_now_recv_cb_t)(const esp_now_recv_info_t *info,
                                   const uint8_t *data, int len);

static inline esp_err_t esp_now_init(void) { return ESP_OK; }
static inline esp_err_t esp_now_register_recv_cb(esp_now_recv_cb_t cb) { (void)cb; return ESP_OK; }
static inline esp_err_t esp_now_add_peer(const esp_now_peer_info_t *peer) { (void)peer; return ESP_OK; }
static inline esp_err_t esp_now_send(const uint8_t *dest, const uint8_t *data, int len) {
  (void)dest; (void)data; (void)len; return ESP_OK;
}

#endif
