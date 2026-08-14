// Host test stub for ESP-IDF's esp_random.h.
#ifndef HOST_STUB_ESP_RANDOM_H
#define HOST_STUB_ESP_RANDOM_H

#include <stdint.h>
#include <stdlib.h>

static inline uint32_t esp_random(void) { return (uint32_t)rand(); }

#endif
