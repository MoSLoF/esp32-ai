// ESP-NOW peer-to-peer communication for the ESP32-P4.
//
// Receives prompt token IDs from any ESP-NOW peer (another ESP32 running a
// simple sender sketch) and makes them available to the inference loop. Also
// broadcasts generated tokens so nearby devices can display the output.
//
// On the P4, WiFi runs on the companion ESP32-C6 via SDIO. The ESP-IDF
// esp_wifi_remote component bridges the API transparently, so the standard
// esp_now_* calls work. Requires ESP-IDF v5.3+ with wifi_remote enabled in
// sdkconfig (the Waveshare BSP does this by default).
//
// Protocol (minimal, fixed-size frames):
//   TX: ESPNOW_MSG_TOKEN  { type=0x01, token_id:uint16 }
//   RX: ESPNOW_MSG_PROMPT { type=0x02, n_tokens:uint8, token_ids:uint16[n] }
//   RX: ESPNOW_MSG_TEXT   { type=0x03, len:uint8, utf8[len] }
//
// Usage in the main sketch:
//   #define USE_ESPNOW 1
//   #include "espnow_comm.h"
//   espnow_begin();                        // in setup(), after Serial.begin
//   int n = espnow_poll_prompt(ids, max);  // check for incoming prompt
//   espnow_send_token(tok);                // broadcast each generated token
#ifndef ESPNOW_COMM_H
#define ESPNOW_COMM_H

#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <string.h>

// Frame types.
#define ESPNOW_MSG_TOKEN  0x01
#define ESPNOW_MSG_PROMPT 0x02
#define ESPNOW_MSG_TEXT   0x03

// Max tokens in a single prompt message (ESP-NOW payload limit is 250 bytes).
#define ESPNOW_MAX_PROMPT 120

// Broadcast address (all peers).
static const uint8_t ESPNOW_BROADCAST[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Per-MAC rate limiting (EA-07): separate pre-auth and post-auth budgets.
// FR-06: reserved authenticated budget prevents unauthenticated traffic
// from starving verified peers.
// R3-03: overflow verification budget bounds HMAC attempts from unknown MACs.
// R4-02: tracked peers get per-MAC overflow budget; unknown MACs share global.
#define ESPNOW_RX_LIMIT           100
#define ESPNOW_RX_MAC_SLOTS       8
#define ESPNOW_RX_GLOBAL_CEIL     500
#define ESPNOW_RX_AUTHED_RESERVE  100
#define ESPNOW_RX_VERIFY_OVERFLOW 50
#define ESPNOW_RX_PEER_OVERFLOW   10
// R5-02: bonded (proven-authenticated) peer budget. Separate from
// ESPNOW_RX_MAC_SLOTS -- that cache is populated by ANY source MAC before
// authentication and is therefore attacker-evictable by MAC rotation.
#define ESPNOW_BONDED_SLOTS       4
#define ESPNOW_BONDED_MIN_RATE    20

static struct {
  uint8_t mac[6];
  uint16_t count;
  int64_t window;
  bool active;
  // R4-02: per-MAC overflow budget for tracked peers.
  uint16_t overflow_count;
  int64_t overflow_window;
} _espnow_rx_mac[ESPNOW_RX_MAC_SLOTS];
static uint32_t _espnow_rx_global = 0;
static int64_t _espnow_rx_global_window = 0;
static uint32_t _espnow_rx_authed_count = 0;
static int64_t _espnow_rx_authed_window = 0;
// R3-03: overflow verification budget — bounds HMAC attempts when pre-auth exhausted.
static uint32_t _espnow_rx_verify_overflow_count = 0;
static int64_t _espnow_rx_verify_overflow_window = 0;

// R5-02: bonded-peer table. A MAC is only ever added here after it has
// successfully passed HMAC verification at least once (see
// espnow_provision_peer(), called from the RX callback below on a
// successful verify) -- an attacker without the PSK cannot get an entry
// created no matter how many MACs it rotates through.
// Once bonded, a peer keeps a reserved receive/verification rate that is
// checked and consumed independently of the unknown-source global ceiling,
// the untrusted per-MAC cache, and the shared verification-overflow budget,
// so MAC-rotation flooding from unauthenticated senders cannot starve it.
static struct {
  uint8_t mac[6];
  bool active;
  uint16_t count;
  int64_t window;
  int64_t last_seen_us;
} _espnow_bonded[ESPNOW_BONDED_SLOTS];

// FR-06: diagnostic counters.
static uint32_t _espnow_diag_preauth_drop = 0;
static uint32_t _espnow_diag_authed_pass = 0;

// Prompt buffer spinlock for cross-core safety (V-09, V-15).
static portMUX_TYPE _espnow_prompt_mux = portMUX_INITIALIZER_UNLOCKED;

// Incoming prompt buffer (written by the RX callback, read by the main loop).
static volatile uint16_t _espnow_prompt[ESPNOW_MAX_PROMPT];
static volatile int _espnow_prompt_len = 0;
static volatile bool _espnow_prompt_ready = false;

// Extensible handler chain for extension frames (0x04+).
// Both peer_protocol.h and ota_espnow.h register here.
typedef void (*espnow_peer_handler_t)(const uint8_t *mac,
                                       const uint8_t *data, int len);
#define ESPNOW_MAX_HANDLERS 4
static espnow_peer_handler_t _espnow_ext[ESPNOW_MAX_HANDLERS];
static int _espnow_n_ext = 0;

static void espnow_register_peer_handler(espnow_peer_handler_t handler) {
  if (_espnow_n_ext < ESPNOW_MAX_HANDLERS)
    _espnow_ext[_espnow_n_ext++] = handler;
}

// Crypto hooks — set via espnow_set_crypto() when USE_CRYPTO is enabled.
// FR-02: verify callback receives source MAC for replay keying.
typedef int (*espnow_sign_fn_t)(uint8_t *frame, int len);
typedef int (*espnow_verify_fn_t)(const uint8_t *src_mac,
                                   const uint8_t *frame, int len);

static espnow_sign_fn_t _espnow_sign_fn = NULL;
static espnow_verify_fn_t _espnow_verify_fn = NULL;
// R3-02: when set, RX callback drops all frames until verify fn is installed.
static bool _espnow_crypto_required = false;

static void espnow_set_crypto(espnow_sign_fn_t sign_fn,
                                espnow_verify_fn_t verify_fn) {
  _espnow_sign_fn = sign_fn;
  _espnow_verify_fn = verify_fn;
  _espnow_crypto_required = true;
  Serial.println("[espnow] crypto hooks registered");
}

static void espnow_require_crypto() {
  _espnow_crypto_required = true;
}

// Mesh relay hook — set via espnow_set_relay() when USE_MESH is enabled (B5).
typedef void (*espnow_relay_fn_t)(const uint8_t *frame, int len);
static espnow_relay_fn_t _espnow_relay_fn = NULL;

static void espnow_set_relay(espnow_relay_fn_t fn) {
  _espnow_relay_fn = fn;
  Serial.println("[espnow] relay hook registered");
}

// Send a frame with crypto signing when enabled (EA-08: all frame types).
// Caller's buffer must have room for 16 extra bytes (CRYPTO_ENV_OVERHEAD).
static void espnow_send_secure(const uint8_t *dest, uint8_t *frame, int len) {
  int raw_len = len;
  if (_espnow_sign_fn && len > 0)
    len = _espnow_sign_fn(frame, len);
  esp_now_send(dest, frame, len);
  // Relay broadcast extension frames via mesh (skip relay envelopes 0x10+).
  if (_espnow_relay_fn && raw_len > 0
      && frame[0] >= 0x04 && frame[0] < 0x10
      && memcmp(dest, ESPNOW_BROADCAST, 6) == 0)
    _espnow_relay_fn(frame, raw_len);
}

// EA-07: per-source-MAC rate check. Returns true if this MAC is within budget.
static bool _espnow_mac_ratelimit(const uint8_t *mac, int64_t now_us) {
  // Global emergency ceiling — bounds MAC rotation attacks.
  if (now_us - _espnow_rx_global_window > 1000000) {
    _espnow_rx_global = 0;
    _espnow_rx_global_window = now_us;
  }
  if (++_espnow_rx_global > ESPNOW_RX_GLOBAL_CEIL) return false;

  // Per-MAC bucket lookup.
  int slot = -1, evict = 0;
  int64_t oldest = INT64_MAX;
  for (int i = 0; i < ESPNOW_RX_MAC_SLOTS; i++) {
    if (_espnow_rx_mac[i].active && memcmp(_espnow_rx_mac[i].mac, mac, 6) == 0) {
      slot = i; break;
    }
    if (!_espnow_rx_mac[i].active) { evict = i; oldest = 0; }
    else if (_espnow_rx_mac[i].window < oldest) {
      oldest = _espnow_rx_mac[i].window; evict = i;
    }
  }

  if (slot >= 0) {
    if (now_us - _espnow_rx_mac[slot].window > 1000000) {
      _espnow_rx_mac[slot].count = 0;
      _espnow_rx_mac[slot].window = now_us;
    }
    return (++_espnow_rx_mac[slot].count <= ESPNOW_RX_LIMIT);
  }

  // New MAC — allocate or evict.
  _espnow_rx_mac[evict].active = true;
  memcpy(_espnow_rx_mac[evict].mac, mac, 6);
  _espnow_rx_mac[evict].count = 1;
  _espnow_rx_mac[evict].window = now_us;
  return true;
}

// FR-06: check if authenticated traffic has reserved budget remaining.
static bool _espnow_authed_budget(int64_t now_us) {
  if (now_us - _espnow_rx_authed_window > 1000000) {
    _espnow_rx_authed_count = 0;
    _espnow_rx_authed_window = now_us;
  }
  return (++_espnow_rx_authed_count <= ESPNOW_RX_AUTHED_RESERVE);
}

// R3-03: overflow verification budget — bounds HMAC attempts from unverified traffic.
static bool _espnow_verify_overflow_budget(int64_t now_us) {
  if (now_us - _espnow_rx_verify_overflow_window > 1000000) {
    _espnow_rx_verify_overflow_count = 0;
    _espnow_rx_verify_overflow_window = now_us;
  }
  return (++_espnow_rx_verify_overflow_count <= ESPNOW_RX_VERIFY_OVERFLOW);
}

// R5-02: look up a bonded peer slot by MAC. Returns -1 if not bonded.
static int _espnow_bonded_slot(const uint8_t *mac) {
  for (int i = 0; i < ESPNOW_BONDED_SLOTS; i++) {
    if (_espnow_bonded[i].active && memcmp(_espnow_bonded[i].mac, mac, 6) == 0)
      return i;
  }
  return -1;
}

// R5-02: record a MAC as bonded after it has proven possession of the PSK
// via a successful HMAC verification. Only ever called with an
// already-authenticated MAC (see the RX callback below) -- unauthenticated
// traffic can never create or evict an entry here. When all slots are full, the
// least-recently-seen bonded peer is replaced; that eviction is still only
// reachable by another authenticated peer, never by unknown-source traffic.
static void espnow_provision_peer(const uint8_t *mac) {
  if (_espnow_bonded_slot(mac) >= 0) return;
  int slot = -1;
  int64_t oldest = INT64_MAX;
  for (int i = 0; i < ESPNOW_BONDED_SLOTS; i++) {
    if (!_espnow_bonded[i].active) { slot = i; break; }
    if (_espnow_bonded[i].last_seen_us < oldest) {
      oldest = _espnow_bonded[i].last_seen_us; slot = i;
    }
  }
  memcpy(_espnow_bonded[slot].mac, mac, 6);
  _espnow_bonded[slot].active = true;
  _espnow_bonded[slot].count = 0;
  _espnow_bonded[slot].window = 0;
  _espnow_bonded[slot].last_seen_us = esp_timer_get_time();
}

// R5-02: reserved receive budget for a bonded peer, independent of the
// global pre-auth ceiling and the untrusted-MAC cache's per-MAC budget.
static bool _espnow_bonded_budget(int slot, int64_t now_us) {
  if (now_us - _espnow_bonded[slot].window > 1000000) {
    _espnow_bonded[slot].count = 0;
    _espnow_bonded[slot].window = now_us;
  }
  _espnow_bonded[slot].last_seen_us = now_us;
  return (++_espnow_bonded[slot].count <= ESPNOW_BONDED_MIN_RATE);
}

// R4-02: per-MAC overflow budget for tracked peers.
static bool _espnow_peer_overflow_budget(const uint8_t *mac, int64_t now_us) {
  for (int i = 0; i < ESPNOW_RX_MAC_SLOTS; i++) {
    if (_espnow_rx_mac[i].active &&
        memcmp(_espnow_rx_mac[i].mac, mac, 6) == 0) {
      if (now_us - _espnow_rx_mac[i].overflow_window > 1000000) {
        _espnow_rx_mac[i].overflow_count = 0;
        _espnow_rx_mac[i].overflow_window = now_us;
      }
      return (++_espnow_rx_mac[i].overflow_count <= ESPNOW_RX_PEER_OVERFLOW);
    }
  }
  return false;
}

// RX callback -- runs in the WiFi task context, so keep it fast.
static void _espnow_rx(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (len < 1) return;

  // R3-02: fail closed — drop all frames if crypto is required but not yet installed.
  if (_espnow_crypto_required && !_espnow_verify_fn)
    return;

  // FR-06/R2-07 two-tier rate limiting:
  // 1. Pre-auth global ceiling applies to ALL traffic.
  // 2. R3-03: when pre-auth exhausted, check overflow verification budget
  //    to bound HMAC attempts, then verify, then check authed reserve.
  // R5-02: a bonded (previously-authenticated) peer's reserved budget is
  // checked independently and, when it grants the frame, bypasses the
  // shared global/overflow/authed-reserve gates entirely -- those are the
  // budgets an unauthenticated MAC-rotation flood can exhaust.
  int64_t now_us = esp_timer_get_time();
  bool preauth_ok = _espnow_mac_ratelimit(info->src_addr, now_us);
  int bonded_slot = _espnow_bonded_slot(info->src_addr);
  bool bonded_ok = (bonded_slot >= 0) && _espnow_bonded_budget(bonded_slot, now_us);

  // EA-08: when crypto is enabled, verify ALL frame types.
  int verified_len = len;
  if (_espnow_verify_fn) {
    // R4-02: when pre-auth exhausted, tracked peers use per-MAC overflow;
    // unknown MACs use global overflow budget.
    if (!preauth_ok && !bonded_ok) {
      bool overflow_ok = _espnow_peer_overflow_budget(info->src_addr, now_us);
      if (!overflow_ok && !_espnow_verify_overflow_budget(now_us)) {
        _espnow_diag_preauth_drop++;
        return;
      }
    }
    verified_len = _espnow_verify_fn(info->src_addr, data, len);
    if (verified_len <= 0) return;
    // R5-02: this MAC just proved PSK possession -- bond it so its future
    // traffic gets a reserved budget immune to unknown-MAC starvation.
    if (bonded_slot < 0) espnow_provision_peer(info->src_addr);
    // R3-03: only decrement authenticated reserve AFTER successful HMAC.
    if (!preauth_ok && !bonded_ok) {
      if (!_espnow_authed_budget(now_us)) {
        _espnow_diag_preauth_drop++;
        return;
      }
      _espnow_diag_authed_pass++;
    }
  } else {
    if (!preauth_ok && !bonded_ok) {
      _espnow_diag_preauth_drop++;
      return;
    }
  }

  uint8_t type = data[0];

  if (type == ESPNOW_MSG_PROMPT && verified_len >= 3) {
    int n = data[1];
    if (n > ESPNOW_MAX_PROMPT) n = ESPNOW_MAX_PROMPT;
    if (verified_len < 2 + n * 2) return;
    portENTER_CRITICAL(&_espnow_prompt_mux);
    for (int i = 0; i < n; i++) {
      uint16_t id;
      memcpy(&id, data + 2 + i * 2, 2);
      _espnow_prompt[i] = id;
    }
    _espnow_prompt_len = n;
    _espnow_prompt_ready = true;
    portEXIT_CRITICAL(&_espnow_prompt_mux);
  }

  if (type >= 0x04) {
    for (int _h = 0; _h < _espnow_n_ext; _h++)
      _espnow_ext[_h](info->src_addr, data, verified_len);
  }
}

// Initialize ESP-NOW. WiFi must be in STA mode (no AP needed).
static bool espnow_begin() {
  // WiFi init -- STA mode, no connection needed (ESP-NOW is connectionless).
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_err_t err = esp_wifi_init(&cfg);
  if (err != ESP_OK) { Serial.printf("wifi init failed: %d\n", err); return false; }
  err = esp_wifi_set_mode(WIFI_MODE_STA);
  if (err != ESP_OK) { Serial.printf("wifi set mode failed: %d\n", err); return false; }
  err = esp_wifi_start();
  if (err != ESP_OK) { Serial.printf("wifi start failed: %d\n", err); return false; }

  // ESP-NOW init.
  err = esp_now_init();
  if (err != ESP_OK) { Serial.printf("esp_now_init failed: %d\n", err); return false; }
  err = esp_now_register_recv_cb(_espnow_rx);
  if (err != ESP_OK) { Serial.printf("esp_now register rx failed: %d\n", err); return false; }

  // Add broadcast peer so espnow_send_token works without explicit pairing.
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, ESPNOW_BROADCAST, 6);
  peer.channel = 0;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  memset(_espnow_rx_mac, 0, sizeof(_espnow_rx_mac));
  memset(_espnow_bonded, 0, sizeof(_espnow_bonded));

  Serial.println("ESP-NOW ready (broadcast)");
  return true;
}

// Check if a prompt arrived from a peer. Returns token count (0 = nothing).
// Copies up to `max_ids` token IDs into `ids`. Clears the buffer atomically.
static int espnow_poll_prompt(int *ids, int max_ids) {
  portENTER_CRITICAL(&_espnow_prompt_mux);
  if (!_espnow_prompt_ready) {
    portEXIT_CRITICAL(&_espnow_prompt_mux);
    return 0;
  }
  int n = _espnow_prompt_len;
  if (n > max_ids) n = max_ids;
  for (int i = 0; i < n; i++) ids[i] = (int)_espnow_prompt[i];
  _espnow_prompt_ready = false;
  portEXIT_CRITICAL(&_espnow_prompt_mux);
  return n;
}

// Broadcast a generated token to all peers (EA-08: uses authenticated send).
static void espnow_send_token(int token_id) {
  uint8_t frame[3 + 16];
  frame[0] = ESPNOW_MSG_TOKEN;
  uint16_t id = (uint16_t)token_id;
  memcpy(frame + 1, &id, 2);
  espnow_send_secure(ESPNOW_BROADCAST, frame, 3);
}

// Broadcast raw UTF-8 bytes (EA-08: uses authenticated send).
static void espnow_send_text(const uint8_t *text, int len) {
  if (len > 232) len = 232;  // ESP-NOW 250 - 2B header - 16B crypto
  uint8_t frame[250];
  frame[0] = ESPNOW_MSG_TEXT;
  frame[1] = (uint8_t)len;
  memcpy(frame + 2, text, len);
  espnow_send_secure(ESPNOW_BROADCAST, frame, 2 + len);
}

#endif
