// Shared HMAC-SHA256 envelope for ESP-NOW frame authentication.
//
// Both the P4 receiver and the sender sketch use this module for
// signing and tag verification. The receiver layers per-sender replay
// protection on top in crypto_peer.h.
//
// Envelope format (16-byte trailer appended to any frame):
//   [type][payload...][epoch:u32][seq:u32][hmac_tag:8]
//
// The HMAC covers: type + payload + epoch + seq.
// The epoch is a random value generated at boot, allowing receivers to
// distinguish sessions without time synchronization.

#ifndef CRYPTO_ENVELOPE_H
#define CRYPTO_ENVELOPE_H

#include "mbedtls/md.h"
#include <string.h>
#include <stdint.h>

#define CRYPTO_ENV_TAG_LEN    8
#define CRYPTO_ENV_SEQ_LEN    4
#define CRYPTO_ENV_EPOCH_LEN  4
#define CRYPTO_ENV_OVERHEAD   (CRYPTO_ENV_TAG_LEN + CRYPTO_ENV_SEQ_LEN + CRYPTO_ENV_EPOCH_LEN)

static void _crypto_env_hmac(const char *psk, const uint8_t *data, int len,
                              uint32_t epoch, uint32_t seq, uint8_t *tag_out) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *)psk, strlen(psk));
  mbedtls_md_hmac_update(&ctx, data, len);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)&epoch, 4);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)&seq, 4);
  uint8_t full[32];
  mbedtls_md_hmac_finish(&ctx, full);
  mbedtls_md_free(&ctx);
  memcpy(tag_out, full, CRYPTO_ENV_TAG_LEN);
}

// Sign a frame in-place. Buffer must have room for CRYPTO_ENV_OVERHEAD
// extra bytes after the payload. Returns the new total length.
static int crypto_env_sign(const char *psk, uint8_t *frame, int len,
                            uint32_t epoch, uint32_t seq) {
  if (len < 1 || len > 234) return len;
  memcpy(frame + len, &epoch, 4);
  memcpy(frame + len + 4, &seq, 4);
  _crypto_env_hmac(psk, frame, len, epoch, seq,
                    frame + len + CRYPTO_ENV_SEQ_LEN + CRYPTO_ENV_EPOCH_LEN);
  return len + CRYPTO_ENV_OVERHEAD;
}

// Verify the HMAC tag. Returns payload length (>0) on success, 0 on failure.
// Extracts epoch and seq into the output pointers. Does NOT check replay.
static int crypto_env_verify(const char *psk, const uint8_t *frame, int len,
                              uint32_t *epoch_out, uint32_t *seq_out) {
  if (len < (int)CRYPTO_ENV_OVERHEAD + 1) return 0;
  int payload_len = len - CRYPTO_ENV_OVERHEAD;
  uint32_t epoch, seq;
  memcpy(&epoch, frame + payload_len, 4);
  memcpy(&seq, frame + payload_len + 4, 4);

  uint8_t expected[CRYPTO_ENV_TAG_LEN];
  _crypto_env_hmac(psk, frame, payload_len, epoch, seq, expected);
  const uint8_t *received = frame + payload_len + CRYPTO_ENV_SEQ_LEN + CRYPTO_ENV_EPOCH_LEN;
  uint8_t diff = 0;
  for (int i = 0; i < CRYPTO_ENV_TAG_LEN; i++)
    diff |= expected[i] ^ received[i];
  if (diff != 0) return 0;

  if (epoch_out) *epoch_out = epoch;
  if (seq_out) *seq_out = seq;
  return payload_len;
}

#endif
