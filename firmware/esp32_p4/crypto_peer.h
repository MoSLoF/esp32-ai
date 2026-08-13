// Cryptographic hardening for ESP-NOW frames.
//
// Adds HMAC-SHA256 authentication and replay protection to all frames.
// Uses the shared crypto_envelope.h for signing/verification and adds
// per-sender replay tracking with session epochs.
//
// Design:
//   - Shared pre-shared key (PSK) for flock membership. Override at
//     compile time or at runtime via SD card.
//   - Each sender generates a random boot epoch (EA-06). The receiver
//     tracks (sender_id, epoch, seq) — a new epoch starts a new replay
//     window without time-based resets.
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

// Boot epoch — random per session, included in HMAC (EA-06).
static uint32_t _crypto_epoch = 0;

// Monotonic TX sequence counter.
static uint32_t _crypto_tx_seq = 0;

// FR-02/R2-02: MAC-based replay tracking with bounded retired-epoch ring.
// Tracks up to CRYPTO_RETIRED_EPOCHS previous epochs per sender to prevent
// epoch cycling attacks (A→B→C→A where A's epoch would be accepted again).
#define CRYPTO_REPLAY_SLOTS 16
#define CRYPTO_EPOCH_SILENCE_US 5000000  // 5s silence before accepting new epoch
#define CRYPTO_RETIRED_EPOCHS 4
static struct {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t retired[CRYPTO_RETIRED_EPOCHS];
  int retired_count;
  uint32_t last_seq;
  int64_t last_seen_us;
  bool active;
} _crypto_replay[CRYPTO_REPLAY_SLOTS];

static void crypto_init() {
  memset(_crypto_replay, 0, sizeof(_crypto_replay));
  _crypto_tx_seq = 0;
  _crypto_epoch = esp_random();
  _crypto_ready = true;
  Serial.printf("[crypto] HMAC-SHA256 enabled (overhead=%d, epoch=0x%08X, replay_slots=%d)\n",
                CRYPTO_OVERHEAD, _crypto_epoch, CRYPTO_REPLAY_SLOTS);
}

// Sign a frame in-place. The caller must have room for CRYPTO_OVERHEAD
// extra bytes after the payload. Returns the new total length.
static int crypto_sign(uint8_t *frame, int len) {
  if (!_crypto_ready || len < 1 || len > 234) return len;
  uint32_t seq = _crypto_tx_seq++;
  return crypto_env_sign(_crypto_psk, frame, len, _crypto_epoch, seq);
}

// FR-02: verify and strip the crypto envelope. Uses source MAC as primary
// replay key so ALL frame sizes (including 3-byte tokens) get replay
// protection. Prevents epoch alternation attacks by requiring a silence
// period before accepting a new epoch and rejecting the previous epoch.
static int crypto_verify(const uint8_t *src_mac,
                          const uint8_t *frame, int len) {
  if (!_crypto_ready) return len;

  uint32_t epoch, seq;
  int payload_len = crypto_env_verify(_crypto_psk, frame, len, &epoch, &seq);
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
    } else {
      // R2-02: reject any retired epoch to prevent cycling attacks.
      for (int ri = 0; ri < _crypto_replay[slot].retired_count; ri++) {
        if (epoch == _crypto_replay[slot].retired[ri])
          return 0;
      }
      // New epoch — require silence period before accepting.
      int64_t silence = now_us - _crypto_replay[slot].last_seen_us;
      if (silence < CRYPTO_EPOCH_SILENCE_US)
        return 0;
      // R3-01: fail closed — reject when retired ring is full.
      if (_crypto_replay[slot].retired_count >= CRYPTO_RETIRED_EPOCHS)
        return 0;
      _crypto_replay[slot].retired[_crypto_replay[slot].retired_count++] =
          _crypto_replay[slot].epoch;
      _crypto_replay[slot].epoch = epoch;
      _crypto_replay[slot].last_seq = seq;
    }
    _crypto_replay[slot].last_seen_us = now_us;
  } else {
    // R3-01: fail closed — reject unknown MACs when all slots are active.
    if (_crypto_replay[evict].active)
      return 0;
    memcpy(_crypto_replay[evict].mac, src_mac, 6);
    _crypto_replay[evict].epoch = epoch;
    _crypto_replay[evict].retired_count = 0;
    memset(_crypto_replay[evict].retired, 0, sizeof(_crypto_replay[evict].retired));
    _crypto_replay[evict].last_seq = seq;
    _crypto_replay[evict].last_seen_us = now_us;
    _crypto_replay[evict].active = true;
  }

  return payload_len;
}

#endif
