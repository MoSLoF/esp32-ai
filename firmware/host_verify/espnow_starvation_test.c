// R5-02 behavioral regression test: MAC-rotation flooding must not starve
// a provisioned peer's receive/verification budget.
//
// This compiles and executes the ACTUAL espnow_comm.h RX rate-limiting
// state machine (via the ESP-IDF stubs in stubs/), driving _espnow_rx()
// directly with the exact "Validated starvation sequence" from the
// reassessment rather than re-implementing the budget logic in the test.
//
// Reassessment attack sequence (R5-02, MEDIUM):
//   1. Seed the table with the legitimate peer.
//   2. Transmit 500 frames using rotating unauthenticated MAC addresses;
//      the legitimate entry becomes the oldest and is evicted from the
//      8-slot untrusted-MAC cache.
//   3. Transmit 50 additional invalid frames after the global ceiling;
//      these consume the shared verification-overflow budget.
//   4. Send a valid frame from the legitimate peer -- in the vulnerable
//      design, global pre-auth fails, no protected peer entry exists, and
//      shared overflow is exhausted, so the frame is dropped before HMAC
//      verification even runs.
//
// Build: gcc -std=c11 -I stubs -o /tmp/espnow_starvation_test espnow_starvation_test.c
// Run:   /tmp/espnow_starvation_test   (exit 0 = pass, non-zero = fail)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

static int host_serial_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = vprintf(fmt, ap);
  va_end(ap);
  return r;
}
static int host_serial_println(const char *s) { return printf("%s\n", s); }
struct HostSerialClass { int (*printf)(const char *fmt, ...); int (*println)(const char *s); };
static struct HostSerialClass Serial = { host_serial_printf, host_serial_println };

// espnow_comm.h assumes the FreeRTOS portmux macros are already in scope
// (as they would be via the real Arduino/ESP-IDF headers). The prompt
// buffer spinlock they guard isn't exercised by this single-threaded test.
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))

#include "../esp32_p4/espnow_comm.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("  FAIL: %s\n", msg); g_failures++; } \
  else { printf("  ok:   %s\n", msg); } \
} while (0)

// Test-controlled fake HMAC verify: "valid" iff the payload's second byte
// is the marker below. This isolates the budget/rate-limiting state
// machine under test from crypto_peer.h's HMAC (covered by its own
// behavioral test) while still exercising the real accept/reject control
// flow in _espnow_rx() -- including which budget gates a frame before
// _espnow_verify_fn is even called.
#define VALID_MARKER 0xAA
static int g_verify_calls = 0;
static int fake_verify(const uint8_t *mac, const uint8_t *frame, int len) {
  (void)mac;
  g_verify_calls++;
  if (len >= 2 && frame[1] == VALID_MARKER) return len;
  return 0;
}
static int fake_sign(uint8_t *frame, int len) { return len; }

// Extension frame handler (type 0x05) -- records the last MAC whose frame
// actually made it through rate limiting AND verification to dispatch.
static uint8_t g_last_delivered_mac[6];
static int g_delivered_count = 0;
static void ext_handler(const uint8_t *mac, const uint8_t *data, int len) {
  (void)data; (void)len;
  memcpy(g_last_delivered_mac, mac, 6);
  g_delivered_count++;
}

static void send_frame(const uint8_t *mac, bool valid) {
  uint8_t frame[3] = { 0x05, (uint8_t)(valid ? VALID_MARKER : 0x00), 0 };
  esp_now_recv_info_t info;
  info.src_addr = mac;
  info.des_addr = NULL;
  _espnow_rx(&info, frame, 3);
  // Advance time by a small, realistic per-frame amount. Without this the
  // untrusted-MAC cache's "oldest window" eviction heuristic can't tell
  // slots apart (every frame would land in the same 0us instant), which
  // would understate the flood's effectiveness at evicting the legitimate
  // peer -- exactly the real-world timing the reassessment's attack
  // sequence relies on.
  host_mock_time_us += 100;
}

static bool mac_in_untrusted_cache(const uint8_t *mac) {
  for (int i = 0; i < ESPNOW_RX_MAC_SLOTS; i++) {
    if (_espnow_rx_mac[i].active && memcmp(_espnow_rx_mac[i].mac, mac, 6) == 0)
      return true;
  }
  return false;
}

int main(void) {
  printf("=== R5-02: MAC-rotation flooding must not starve a provisioned peer ===\n");

  memset(_espnow_rx_mac, 0, sizeof(_espnow_rx_mac));
  memset(_espnow_bonded, 0, sizeof(_espnow_bonded));
  espnow_register_peer_handler(ext_handler);
  espnow_set_crypto(fake_sign, fake_verify);
  host_mock_time_us = 0;

  static const uint8_t LEGIT_MAC[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};

  // ---- Step 1: seed the table with the legitimate peer --------------
  send_frame(LEGIT_MAC, true);
  CHECK(g_delivered_count == 1 && memcmp(g_last_delivered_mac, LEGIT_MAC, 6) == 0,
        "legitimate peer's first authenticated frame is delivered (and bonds it)");

  // ---- Step 2: 500 frames from rotating unauthenticated MACs --------
  // Distinct MACs, all failing HMAC, within the same 1-second window --
  // enough to evict the legitimate peer from the 8-slot untrusted cache
  // (ESPNOW_RX_MAC_SLOTS) many times over, and to trip the global ceiling
  // (ESPNOW_RX_GLOBAL_CEIL = 500).
  for (int i = 0; i < 500; i++) {
    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, (uint8_t)(i >> 8), (uint8_t)i};
    send_frame(mac, false);
  }
  // Confirm the attack's premise actually held: the legitimate peer really
  // was evicted from the untrusted cache, same as in the vulnerable design.
  CHECK(!mac_in_untrusted_cache(LEGIT_MAC),
        "sanity: the flood does evict the legitimate peer from the untrusted MAC cache");
  CHECK(_espnow_bonded_slot(LEGIT_MAC) >= 0,
        "legitimate peer's bonded slot survives the MAC-rotation flood");

  // ---- Step 3: 50 more invalid frames after the global ceiling ------
  for (int i = 0; i < 50; i++) {
    uint8_t mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFF, (uint8_t)i};
    send_frame(mac, false);
  }

  // ---- Step 4: legitimate peer sends a valid frame during the flood -
  int delivered_before = g_delivered_count;
  send_frame(LEGIT_MAC, true);
  CHECK(g_delivered_count == delivered_before + 1,
        "legitimate peer's frame is still delivered during active MAC-rotation flood + overflow exhaustion");
  CHECK(memcmp(g_last_delivered_mac, LEGIT_MAC, 6) == 0,
        "the delivered frame really is the legitimate peer's");

  // ---- Delivered throughput must still be finite overall (a guaranteed --
  // ---- minimum via the bonded reserve, not unlimited priority) -- once --
  // ---- both the bonded reserve (ESPNOW_BONDED_MIN_RATE) and the shared --
  // ---- authenticated-reserve fallback (ESPNOW_RX_AUTHED_RESERVE) are ---
  // ---- exhausted in the same congested window, further frames must be --
  // ---- dropped, not delivered forever. -----------------------------
  int accepted = 0;
  const int BURST = ESPNOW_BONDED_MIN_RATE + ESPNOW_RX_AUTHED_RESERVE + 20;
  for (int i = 0; i < BURST; i++) {
    int before = g_delivered_count;
    send_frame(LEGIT_MAC, true);
    if (g_delivered_count > before) accepted++;
  }
  CHECK(accepted < BURST,
        "delivered throughput is finite -- not every frame in an oversized burst gets through");

  // ---- An attacker MAC can never bond itself -- only a genuinely -----
  // ---- HMAC-verified sender can. -------------------------------------
  static const uint8_t ATTACKER_MAC[6] = {0x99, 0x99, 0x99, 0x99, 0x99, 0x99};
  for (int i = 0; i < 100; i++) send_frame(ATTACKER_MAC, false);
  CHECK(_espnow_bonded_slot(ATTACKER_MAC) < 0,
        "an unauthenticated attacker MAC is never granted a bonded slot");

  // ---- Post-review hardening: an attacker spoofing the LEGITIMATE ----
  // ---- peer's own (unauthenticated, radio-reported) source MAC with --
  // ---- garbage must not be able to drain that peer's reserved budget -
  // Move to a fresh rate-limit window, then re-trip the global ceiling
  // (with distinct, unrelated MACs) so preauth_ok is false throughout --
  // otherwise this scenario wouldn't exercise the reserved-budget path
  // at all, since normal (non-congested) traffic never touches it.
  host_mock_time_us += 1100000;
  for (int i = 0; i < 500; i++) {
    uint8_t mac[6] = {0xBA, 0xAD, 0xF0, 0x0D, (uint8_t)(i >> 8), (uint8_t)i};
    send_frame(mac, false);
  }
  int spoof_delivered_before = g_delivered_count;
  for (int i = 0; i < 200; i++) {
    // Claims LEGIT_MAC as its source address but is not signed with the
    // PSK -- exactly what an attacker spoofing the legitimate peer's own
    // MAC would send. Every one of these must fail HMAC.
    send_frame(LEGIT_MAC, false);
  }
  CHECK(g_delivered_count == spoof_delivered_before,
        "200 garbage frames spoofing the legitimate peer's own MAC deliver nothing");
  send_frame(LEGIT_MAC, true);
  CHECK(g_delivered_count == spoof_delivered_before + 1,
        "legitimate peer's genuinely-signed frame still delivered right after "
        "a flood of garbage spoofing its own MAC -- the spoofed flood did not "
        "drain its reserved budget");

  if (g_failures) {
    printf("\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nall checks passed (%d verify() calls total)\n", g_verify_calls);
  return 0;
}
