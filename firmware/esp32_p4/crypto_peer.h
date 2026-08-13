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
static uint32_t _crypto_boot_sec = 0;
static bool _crypto_ready = false;

static uint32_t _crypto_now_sec() {
  return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

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
  _crypto_boot_sec = _crypto_now_sec();
  _crypto_ready = true;
  Serial.printf("[crypto] HMAC-SHA256 enabled (tag=%d, drift=%ds)\n",
                CRYPTO_TAG_LEN, CRYPTO_MAX_DRIFT);
}

// Sign a frame in-place. The caller must have room for CRYPTO_OVERHEAD
// extra bytes after the payload. Returns the new total length.
static int crypto_sign(uint8_t *frame, int len) {
  if (!_crypto_ready || len < 1 || len > 238) return len;
  uint32_t ts = _crypto_now_sec();
  memcpy(frame + len, &ts, CRYPTO_TS_LEN);
  _crypto_hmac(frame, len, ts, frame + len + CRYPTO_TS_LEN);
  return len + CRYPTO_OVERHEAD;
}

// Verify and strip the crypto envelope. Returns the inner payload length
// (>0) on success, 0 on failure (bad tag or replay).
static int crypto_verify(const uint8_t *frame, int len) {
  if (!_crypto_ready) return len;
  if (len < (int)CRYPTO_OVERHEAD + 1) return 0;

  int payload_len = len - CRYPTO_OVERHEAD;
  uint32_t ts;
  memcpy(&ts, frame + payload_len, CRYPTO_TS_LEN);

  // Replay check: reject if timestamp differs by more than CRYPTO_MAX_DRIFT.
  uint32_t now = _crypto_now_sec();
  int32_t diff = (int32_t)(now - ts);
  if (diff < 0) diff = -diff;
  if (diff > CRYPTO_MAX_DRIFT) return 0;

  // Verify HMAC tag.
  uint8_t expected[CRYPTO_TAG_LEN];
  _crypto_hmac(frame, payload_len, ts, expected);
  const uint8_t *received = frame + payload_len + CRYPTO_TS_LEN;

  // Constant-time comparison.
  uint8_t result = 0;
  for (int i = 0; i < CRYPTO_TAG_LEN; i++)
    result |= expected[i] ^ received[i];
  if (result != 0) return 0;

  return payload_len;
}

#endif
