// Host test stub for ESP-IDF's esp_mac.h.
#ifndef HOST_STUB_ESP_MAC_H
#define HOST_STUB_ESP_MAC_H

#include <stdint.h>
#include <string.h>

#define ESP_MAC_WIFI_STA 0

// The test drives this device's "own MAC" explicitly.
static uint8_t host_mock_own_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static inline int esp_read_mac(uint8_t *mac, int type) {
  (void)type;
  memcpy(mac, host_mock_own_mac, 6);
  return 0;
}

#endif
