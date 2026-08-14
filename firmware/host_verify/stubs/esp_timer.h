// Host test stub for ESP-IDF's esp_timer.h. Time is a plain global the test
// drives explicitly (esp_timer_get_time() never reads the real clock), so
// behavioral tests can deterministically simulate silence periods, epoch
// churn, and recovery delays without real sleeping.
#ifndef HOST_STUB_ESP_TIMER_H
#define HOST_STUB_ESP_TIMER_H

#include <stdint.h>

static int64_t host_mock_time_us = 0;

static inline int64_t esp_timer_get_time(void) { return host_mock_time_us; }

#endif
