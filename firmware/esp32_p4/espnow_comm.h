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
#include <string.h>

// Frame types.
#define ESPNOW_MSG_TOKEN  0x01
#define ESPNOW_MSG_PROMPT 0x02
#define ESPNOW_MSG_TEXT   0x03

// Max tokens in a single prompt message (ESP-NOW payload limit is 250 bytes).
#define ESPNOW_MAX_PROMPT 120

// Broadcast address (all peers).
static const uint8_t ESPNOW_BROADCAST[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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
typedef int (*espnow_sign_fn_t)(uint8_t *frame, int len);
typedef int (*espnow_verify_fn_t)(const uint8_t *frame, int len);

static espnow_sign_fn_t _espnow_sign_fn = NULL;
static espnow_verify_fn_t _espnow_verify_fn = NULL;

static void espnow_set_crypto(espnow_sign_fn_t sign_fn,
                                espnow_verify_fn_t verify_fn) {
  _espnow_sign_fn = sign_fn;
  _espnow_verify_fn = verify_fn;
  Serial.println("[espnow] crypto hooks registered");
}

// Send an extension frame (type >= 0x04) with crypto signing when enabled.
// Caller's buffer must have room for 12 extra bytes (CRYPTO_OVERHEAD).
static void espnow_send_secure(const uint8_t *dest, uint8_t *frame, int len) {
  if (_espnow_sign_fn && len > 0 && frame[0] >= 0x04)
    len = _espnow_sign_fn(frame, len);
  esp_now_send(dest, frame, len);
}

// RX callback -- runs in the WiFi task context, so keep it fast.
static void _espnow_rx(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (len < 1) return;
  uint8_t type = data[0];

  if (type == ESPNOW_MSG_PROMPT && len >= 3) {
    int n = data[1];
    if (n > ESPNOW_MAX_PROMPT) n = ESPNOW_MAX_PROMPT;
    if (len < 2 + n * 2) return;
    for (int i = 0; i < n; i++) {
      uint16_t id;
      memcpy(&id, data + 2 + i * 2, 2);
      _espnow_prompt[i] = id;
    }
    _espnow_prompt_len = n;
    _espnow_prompt_ready = true;
  }
  // ESPNOW_MSG_TEXT: tokenize on-device (would need the tokenizer on-chip,
  // not practical at this model size). Ignored for now.

  if (type >= 0x04) {
    int ext_len = len;
    if (_espnow_verify_fn) {
      ext_len = _espnow_verify_fn(data, len);
      if (ext_len <= 0) return;
    }
    for (int _h = 0; _h < _espnow_n_ext; _h++)
      _espnow_ext[_h](info->src_addr, data, ext_len);
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

  Serial.println("ESP-NOW ready (broadcast)");
  return true;
}

// Check if a prompt arrived from a peer. Returns token count (0 = nothing).
// Copies up to `max_ids` token IDs into `ids`. Clears the buffer.
static int espnow_poll_prompt(int *ids, int max_ids) {
  if (!_espnow_prompt_ready) return 0;
  int n = _espnow_prompt_len;
  if (n > max_ids) n = max_ids;
  for (int i = 0; i < n; i++) ids[i] = (int)_espnow_prompt[i];
  _espnow_prompt_ready = false;
  return n;
}

// Broadcast a generated token to all peers.
static void espnow_send_token(int token_id) {
  uint8_t frame[3];
  frame[0] = ESPNOW_MSG_TOKEN;
  uint16_t id = (uint16_t)token_id;
  memcpy(frame + 1, &id, 2);
  esp_now_send(ESPNOW_BROADCAST, frame, sizeof(frame));
}

// Broadcast raw UTF-8 bytes (e.g., decoded token text for display peers).
static void espnow_send_text(const uint8_t *text, int len) {
  if (len > 248) len = 248;  // ESP-NOW max payload = 250, minus 2-byte header
  uint8_t frame[250];
  frame[0] = ESPNOW_MSG_TEXT;
  frame[1] = (uint8_t)len;
  memcpy(frame + 2, text, len);
  esp_now_send(ESPNOW_BROADCAST, frame, 2 + len);
}

#endif
