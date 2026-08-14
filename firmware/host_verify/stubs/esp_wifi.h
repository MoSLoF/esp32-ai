// Host test stub for ESP-IDF's esp_wifi.h -- only what espnow_comm.h's
// espnow_begin() references at compile time (not exercised by the
// behavioral tests, which drive the RX path directly).
#ifndef HOST_STUB_ESP_WIFI_H
#define HOST_STUB_ESP_WIFI_H

#ifndef HOST_STUB_ESP_ERR_T
#define HOST_STUB_ESP_ERR_T
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#endif

typedef struct { int unused; } wifi_init_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() { 0 }

typedef enum { WIFI_MODE_NULL, WIFI_MODE_STA, WIFI_MODE_AP } wifi_mode_t;

static inline esp_err_t esp_wifi_init(const wifi_init_config_t *cfg) { (void)cfg; return ESP_OK; }
static inline esp_err_t esp_wifi_set_mode(wifi_mode_t mode) { (void)mode; return ESP_OK; }
static inline esp_err_t esp_wifi_start(void) { return ESP_OK; }

#endif
