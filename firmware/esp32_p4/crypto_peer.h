// Cryptographic hardening for the peer protocol.
//
// Adds HMAC-SHA256 authentication and replay protection to peer frames.
// Uses mbedtls (bundled with ESP-IDF) for cryptographic primitives.
//
// Design:
//   - Shared pre-shared key (PSK) compiled into firmware. All devices in
//     the same "flock" share the same key. Different flocks can't validate
//     each other — this is intentional (club membership).
//   - Each frame gets an HMAC-SHA256 tag (truncated to 8 bytes) appended.
//   - A 4-byte timestamp (seconds since boot, wrapping) is included in
//     the HMAC input for replay protection. Peers reject frames with
//     timestamps more than 30 seconds from their own clock.
//   - ECDH key exchange is deferred to a future revision — the PSK model
//     fits the "same firmware = same flock" design.
//
// Frame format with crypto envelope:
//   Original:  [type][payload...]
//   Signed:    [type][payload...][timestamp:u32][hmac_tag:8]
//
// The tag covers: type + payload + timestamp. Receivers strip the 12-byte
// trailer after verification.

#ifndef CRYPTO_PEER_H
#define CRYPTO_PEER_H

#include "mbedtls/md.h"
#include <string.h>
#include <esp_timer.h>

#define CRYPTO_TAG_LEN    8
#define CRYPTO_TS_LEN     4
#define CRYPTO_OVERHEAD   (CRYPTO_TAG_LEN + CRYPTO_TS_LEN)
#define CRYPTO_MAX_DRIFT  30

// Pre-shared key — all devices in the flock share this.
// Override at compile time with -DCRYPTO_PSK="..." for different flocks.
#ifndef CRYPTO_PSK
#define CRYPTO_PSK "ple-tinylm-default-flock-key-v1"
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

// Monotonic TX sequence counter (V-05: replaces boot-relative timestamps).
static uint32_t _crypto_tx_seq = 0;

// Per-sender replay tracking (V-05: no clock sync needed).
#define CRYPTO_REPLAY_SLOTS 16
static struct {
  uint32_t sender_id;
  uint32_t last_seq;
  int64_t last_seen_us;
  bool active;
} _crypto_replay[CRYPTO_REPLAY_SLOTS];

static void _crypto_hmac(const uint8_t *data, int len,
                           uint32_t ts, uint8_t *tag_out) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *)_crypto_psk,
                          strlen(_crypto_psk));
  mbedtls_md_hmac_update(&ctx, data, len);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)&ts, 4);
  uint8_t full[32];
  mbedtls_md_hmac_finish(&ctx, full);
  mbedtls_md_free(&ctx);
  memcpy(tag_out, full, CRYPTO_TAG_LEN);
}

static void crypto_init() {
  memset(_crypto_replay, 0, sizeof(_crypto_replay));
  _crypto_tx_seq = 0;
  _crypto_ready = true;
  Serial.printf("[crypto] HMAC-SHA256 enabled (tag=%d, replay_slots=%d)\n",
                CRYPTO_TAG_LEN, CRYPTO_REPLAY_SLOTS);
}

// Sign a frame in-place. The caller must have room for CRYPTO_OVERHEAD
// extra bytes after the payload. Returns the new total length.
static int crypto_sign(uint8_t *frame, int len) {
  if (!_crypto_ready || len < 1 || len > 238) return len;
  uint32_t seq = _crypto_tx_seq++;
  memcpy(frame + len, &seq, CRYPTO_TS_LEN);
  _crypto_hmac(frame, len, seq, frame + len + CRYPTO_TS_LEN);
  return len + CRYPTO_OVERHEAD;
}

// Verify and strip the crypto envelope. Returns the inner payload length
// (>0) on success, 0 on failure (bad tag or replay).
static int crypto_verify(const uint8_t *frame, int len) {
  if (!_crypto_ready) return len;
  if (len < (int)CRYPTO_OVERHEAD + 1) return 0;

  int payload_len = len - CRYPTO_OVERHEAD;
  uint32_t seq;
  memcpy(&seq, frame + payload_len, CRYPTO_TS_LEN);

  // Verify HMAC tag first (constant-time comparison).
  uint8_t expected[CRYPTO_TAG_LEN];
  _crypto_hmac(frame, payload_len, seq, expected);
  const uint8_t *received = frame + payload_len + CRYPTO_TS_LEN;
  uint8_t result = 0;
  for (int i = 0; i < CRYPTO_TAG_LEN; i++)
    result |= expected[i] ^ received[i];
  if (result != 0) return 0;

  // Per-sender replay check (V-05): extract sender_id from the payload
  // (extension frames always carry device_id at bytes 1-4).
  if (payload_len >= 5) {
    uint32_t sender_id;
    memcpy(&sender_id, frame + 1, 4);
    int64_t now_us = esp_timer_get_time();

    int slot = -1, evict = 0;
    uint32_t evict_seq = UINT32_MAX;
    for (int i = 0; i < CRYPTO_REPLAY_SLOTS; i++) {
      if (_crypto_replay[i].active && _crypto_replay[i].sender_id == sender_id) {
        slot = i; break;
      }
      if (!_crypto_replay[i].active) { evict = i; evict_seq = 0; }
      else if (_crypto_replay[i].last_seq < evict_seq) {
        evict_seq = _crypto_replay[i].last_seq; evict = i;
      }
    }

    if (slot >= 0) {
      // Allow counter reset after 60s silence (handles sender reboot).
      int64_t gap = now_us - _crypto_replay[slot].last_seen_us;
      if (gap > 60000000LL) {
        _crypto_replay[slot].last_seq = seq;
      } else if (seq <= _crypto_replay[slot].last_seq) {
        return 0;
      } else {
        _crypto_replay[slot].last_seq = seq;
      }
      _crypto_replay[slot].last_seen_us = now_us;
    } else {
      _crypto_replay[evict].sender_id = sender_id;
      _crypto_replay[evict].last_seq = seq;
      _crypto_replay[evict].last_seen_us = now_us;
      _crypto_replay[evict].active = true;
    }
  }

  return payload_len;
}

#endif
