// Cryptographic hardening for ESP-NOW frames.
//
// Adds HMAC-SHA256 authentication and replay protection to all frames.
// Uses the shared crypto_envelope.h for signing/verification and adds
// per-sender replay tracking with session epochs.
//
// Design:
//   - Shared pre-shared key (PSK) for flock membership. Override at
//     compile time or at runtime via SD card.
//   - Each sender loads a persistent, NVS-backed monotonic boot counter
//     as its epoch (R5-01). The receiver tracks (sender_id, epoch, seq) —
//     a new epoch starts a new replay window, and because epoch values are
//     strictly increasing across the sender's lifetime, an epoch is never
//     valid again once superseded, with no bounded history to age out.
//   - 16-byte envelope: [epoch:u32][seq:u32][hmac_tag:8]
//
// Frame format:
//   Original:  [type][payload...]
//   Signed:    [type][payload...][epoch:u32][seq:u32][hmac_tag:8]

#ifndef CRYPTO_PEER_H
#define CRYPTO_PEER_H

#include "../common/crypto_envelope.h"
#include <esp_timer.h>
#include <esp_random.h>
#include <esp_mac.h>
#include <nvs_flash.h>
#include <nvs.h>

#define CRYPTO_TAG_LEN    CRYPTO_ENV_TAG_LEN
#define CRYPTO_OVERHEAD   CRYPTO_ENV_OVERHEAD

// Pre-shared key — all devices in the flock share this.
// R2-04: no default PSK — must be provisioned at compile time or via SD.
#ifndef CRYPTO_PSK
#error "CRYPTO_PSK must be defined — set via -DCRYPTO_PSK=\"...\" or load from SD card"
#endif

static const char *_crypto_psk = CRYPTO_PSK;
static bool _crypto_ready = false;

// Runtime PSK override buffer (S12: SD-configurable PSK).
static char _crypto_psk_buf[64];

static void crypto_set_psk(const char *psk) {
  strncpy(_crypto_psk_buf, psk, sizeof(_crypto_psk_buf) - 1);
  _crypto_psk_buf[sizeof(_crypto_psk_buf) - 1] = '\0';
  _crypto_psk = _crypto_psk_buf;
}

// Boot epoch — persistent monotonic counter, included in HMAC (R5-01).
static uint32_t _crypto_epoch = 0;

// This device's own MAC, bound into the HMAC as additional authenticated
// data (R5-02) so a captured valid frame can't be replayed under a
// different claimed source MAC.
static uint8_t _crypto_own_mac[6];

// Monotonic TX sequence counter.
static uint32_t _crypto_tx_seq = 0;

// FR-02/R2-02: MAC-based replay tracking.
#define CRYPTO_REPLAY_SLOTS 16
#define CRYPTO_EPOCH_SILENCE_US 5000000  // 5s silence before accepting new epoch
// R4-05: stale threshold for slot eviction (unrelated to epoch ordering).
#define CRYPTO_SLOT_STALE_US       60000000  // 60s stale threshold for slot eviction
static struct {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t last_seq;
  int64_t last_seen_us;
  bool active;
} _crypto_replay[CRYPTO_REPLAY_SLOTS];

// R5-01: persistent monotonic epoch. A random per-boot epoch has no
// ordering relation across reboots, which is what forced the old design
// into a bounded "retired epoch" ring that had to evict entries (and thus
// eventually re-admit them) to stay fail-closed. Loading a monotonically
// increasing, NVS-persisted counter instead means an epoch that has been
// superseded is invalid forever — comparison replaces bookkeeping. Falls
// back to a random, non-monotonic value only if NVS is entirely
// unavailable (logged, since it reopens the original weakness).
static uint32_t crypto_next_persistent_epoch() {
  nvs_handle_t h;
  if (nvs_open("crypto_ep", NVS_READWRITE, &h) == ESP_OK) {
    uint32_t epoch = 0;
    nvs_get_u32(h, "boot_ctr", &epoch);
    epoch++;
    esp_err_t e1 = nvs_set_u32(h, "boot_ctr", epoch);
    esp_err_t e2 = nvs_commit(h);
    nvs_close(h);
    if (e1 == ESP_OK && e2 == ESP_OK) return epoch;
  }
  Serial.println("[crypto] WARNING: persistent epoch counter unavailable — "
                 "falling back to a random, non-monotonic epoch");
  return esp_random();
}

static void crypto_init() {
  memset(_crypto_replay, 0, sizeof(_crypto_replay));
  _crypto_tx_seq = 0;
  _crypto_epoch = crypto_next_persistent_epoch();
  esp_read_mac(_crypto_own_mac, ESP_MAC_WIFI_STA);
  _crypto_ready = true;
  Serial.printf("[crypto] HMAC-SHA256 enabled (overhead=%d, epoch=0x%08X, replay_slots=%d)\n",
                CRYPTO_OVERHEAD, _crypto_epoch, CRYPTO_REPLAY_SLOTS);
}

// Sign a frame in-place. The caller must have room for CRYPTO_OVERHEAD
// extra bytes after the payload. Returns the new total length.
static int crypto_sign(uint8_t *frame, int len) {
  if (!_crypto_ready || len < 1 || len > 234) return len;
  uint32_t seq = _crypto_tx_seq++;
  return crypto_env_sign(_crypto_psk, _crypto_own_mac, frame, len, _crypto_epoch, seq);
}

// FR-02: verify and strip the crypto envelope. Uses source MAC as primary
// replay key so ALL frame sizes (including 3-byte tokens) get replay
// protection. Prevents epoch alternation attacks by requiring a silence
// period before accepting a new epoch and rejecting the previous epoch.
// R5-02: src_mac is also bound into the HMAC itself, so a frame captured
// from one sender can't be replayed under a different claimed source MAC.
static int crypto_verify(const uint8_t *src_mac,
                          const uint8_t *frame, int len) {
  if (!_crypto_ready) return len;

  uint32_t epoch, seq;
  int payload_len = crypto_env_verify(_crypto_psk, src_mac, frame, len, &epoch, &seq);
  if (payload_len <= 0) return 0;

  // FR-02: MAC-based replay tracking for all frame sizes.
  int slot = -1, evict = 0;
  int64_t oldest_us = INT64_MAX;
  for (int i = 0; i < CRYPTO_REPLAY_SLOTS; i++) {
    if (_crypto_replay[i].active &&
        memcmp(_crypto_replay[i].mac, src_mac, 6) == 0) {
      slot = i; break;
    }
    if (!_crypto_replay[i].active) { evict = i; oldest_us = 0; }
    else if (_crypto_replay[i].last_seen_us < oldest_us) {
      oldest_us = _crypto_replay[i].last_seen_us; evict = i;
    }
  }

  int64_t now_us = esp_timer_get_time();

  if (slot >= 0) {
    if (epoch == _crypto_replay[slot].epoch) {
      if (seq <= _crypto_replay[slot].last_seq)
        return 0;
      _crypto_replay[slot].last_seq = seq;
    } else if (epoch > _crypto_replay[slot].epoch) {
      // New epoch — require silence period before accepting, as
      // defense-in-depth against rapid epoch churn.
      int64_t silence = now_us - _crypto_replay[slot].last_seen_us;
      if (silence < CRYPTO_EPOCH_SILENCE_US)
        return 0;
      _crypto_replay[slot].epoch = epoch;
      _crypto_replay[slot].last_seq = seq;
    } else {
      // R5-01: epoch is a persistent monotonic sender boot counter, so any
      // epoch not strictly greater than the highest ever accepted from this
      // sender is permanently retired. Unlike the old bounded ring, there
      // is no eviction path that can make this epoch valid again later.
      return 0;
    }
    _crypto_replay[slot].last_seen_us = now_us;
  } else {
    // R3-01: fail closed — reject unknown MACs when all slots are active.
    // R4-05: authenticated stale eviction — if HMAC verified and oldest
    // slot is stale (inactive > CRYPTO_SLOT_STALE_US), evict it.
    if (_crypto_replay[evict].active) {
      int64_t age = now_us - _crypto_replay[evict].last_seen_us;
      if (age < CRYPTO_SLOT_STALE_US)
        return 0;
    }
    memcpy(_crypto_replay[evict].mac, src_mac, 6);
    _crypto_replay[evict].epoch = epoch;
    _crypto_replay[evict].last_seq = seq;
    _crypto_replay[evict].last_seen_us = now_us;
    _crypto_replay[evict].active = true;
  }

  return payload_len;
}

#endif
