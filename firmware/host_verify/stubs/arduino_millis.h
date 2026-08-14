// Host test stub for Arduino's millis(). Test-controlled, exactly like
// stubs/esp_timer.h's host_mock_time_us, so sender_replay.h's silence/
// staleness timers can be driven deterministically.
#ifndef HOST_STUB_ARDUINO_MILLIS_H
#define HOST_STUB_ARDUINO_MILLIS_H

static unsigned long host_mock_millis = 0;

static inline unsigned long millis(void) { return host_mock_millis; }

#endif
