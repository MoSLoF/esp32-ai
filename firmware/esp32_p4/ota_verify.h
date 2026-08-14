// ECDSA P-256 firmware manifest verification for OTA updates (EA-01).
//
// Provides asymmetric verification of OTA firmware images independent
// of the flock PSK. The sender transmits a pre-signed manifest
// (OTA_MANIFEST frame 0x0C) before the OTA offer; the receiver
// verifies the ECDSA signature against a built-in public key and
// checks a monotonic NVS security counter for anti-rollback.
//
// After all chunks arrive, the receiver compares a streaming SHA-256
// of the received data against the manifest's hash before activating
// the new partition.
//
// Manifest binary format (packed, little-endian):
//   magic:u32        (0x4F544153 "OTAS")
//   version:u16      (1)
//   sec_counter:u32  (monotonic, >= stored value)
//   fw_size:u32      (expected firmware byte count)
//   product_id[12]   (must match OTA_PRODUCT_ID)
//   sha256[32]       (SHA-256 of the firmware binary)
//   sig_len:u8       (DER signature length, <= 72)
//   signature[72]    (ECDSA-P256 over bytes 0..OTA_MANIFEST_SIGNED_LEN)
//
// Frame type:
//   0x0C OTA_MANIFEST { type, manifest_bytes[...] }

#ifndef OTA_VERIFY_H
#define OTA_VERIFY_H

#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>
#include <stdint.h>

#define ESPNOW_MSG_OTA_MANIFEST 0x0C

#define OTA_MANIFEST_MAGIC   0x4F544153
#define OTA_MANIFEST_VERSION 1
#define OTA_PRODUCT_ID_LEN   12
#define OTA_SHA256_LEN       32
#define OTA_MAX_SIG_LEN      72

// Signed portion: magic(4) + version(2) + sec_counter(4) + fw_size(4)
//                 + product_id(12) + sha256(32) = 58 bytes.
#define OTA_MANIFEST_SIGNED_LEN 58

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint32_t sec_counter;
  uint32_t fw_size;
  char     product_id[OTA_PRODUCT_ID_LEN];
  uint8_t  sha256[OTA_SHA256_LEN];
  uint8_t  sig_len;
  uint8_t  signature[OTA_MAX_SIG_LEN];
} OtaManifest;

// Built-in ECDSA P-256 public key (PEM).
// Override at compile time for your release signing key.
// FR-01/FR-04: real ECDSA P-256 public key for OTA manifest verification.
// Override with -DOTA_VERIFY_PUBKEY_PEM="..." for your release signing key.
// Generate a key pair with: tools/ota_keygen.py
#ifndef OTA_VERIFY_PUBKEY_PEM
#error "OTA_VERIFY_PUBKEY_PEM must be defined — run tools/ota_keygen.py to generate a signing key pair"
#endif

#ifndef OTA_PRODUCT_ID
#define OTA_PRODUCT_ID "esp32-p4-ple"
#endif

static nvs_handle_t _otav_nvs;
static bool _otav_ready = false;

static struct {
  bool     valid;
  uint32_t fw_size;
  uint8_t  expected_sha256[OTA_SHA256_LEN];
  uint32_t sec_counter;
} _otav_manifest;

static mbedtls_sha256_context _otav_sha_ctx;
static bool _otav_sha_active = false;

// R4-03: recover pending counter on boot — if a staged counter exists
// from a power-loss between stage and commit, finalize it now.
static void _ota_verify_recover() {
  uint32_t pending = 0;
  esp_err_t err = nvs_get_u32(_otav_nvs, "ota_pending", &pending);
  if (err == ESP_OK && pending > 0) {
    uint32_t current = 0;
    nvs_get_u32(_otav_nvs, "sec_ctr", &current);
    if (pending > current) {
      nvs_set_u32(_otav_nvs, "sec_ctr", pending);
      nvs_commit(_otav_nvs);
      Serial.printf("[ota-verify] recovered pending counter %u\n", pending);
    }
    nvs_erase_key(_otav_nvs, "ota_pending");
    nvs_commit(_otav_nvs);
  }
}

static bool ota_verify_init() {
  esp_err_t err = nvs_open("ota_sec", NVS_READWRITE, &_otav_nvs);
  if (err != ESP_OK) {
    Serial.printf("[ota-verify] NVS open failed: %d\n", err);
    return false;
  }
  memset(&_otav_manifest, 0, sizeof(_otav_manifest));
  _otav_ready = true;

  // R4-03: check for pending counter from interrupted OTA.
  _ota_verify_recover();

  uint32_t ctr = 0;
  nvs_get_u32(_otav_nvs, "sec_ctr", &ctr);
  Serial.printf("[ota-verify] ECDSA P-256 ready (sec_counter=%u)\n", ctr);
  return true;
}

static uint32_t ota_verify_get_counter() {
  uint32_t c = 0;
  nvs_get_u32(_otav_nvs, "sec_ctr", &c);
  return c;
}

static bool ota_verify_manifest(const uint8_t *data, int len) {
  if (!_otav_ready) return false;
  if (len < (int)sizeof(OtaManifest)) {
    Serial.println("[ota-verify] manifest too short");
    return false;
  }

  OtaManifest m;
  memcpy(&m, data, sizeof(m));

  if (m.magic != OTA_MANIFEST_MAGIC) {
    Serial.println("[ota-verify] bad magic");
    return false;
  }
  if (m.version != OTA_MANIFEST_VERSION) {
    Serial.printf("[ota-verify] unsupported version %d\n", m.version);
    return false;
  }
  if (strncmp(m.product_id, OTA_PRODUCT_ID, OTA_PRODUCT_ID_LEN) != 0) {
    Serial.println("[ota-verify] product ID mismatch");
    return false;
  }

  // FR-08: strict increase — equal counter is also rejected.
  uint32_t stored = ota_verify_get_counter();
  if (m.sec_counter <= stored) {
    Serial.printf("[ota-verify] anti-rollback: manifest %u <= stored %u\n",
                  m.sec_counter, stored);
    return false;
  }

  if (m.sig_len == 0 || m.sig_len > OTA_MAX_SIG_LEN) {
    Serial.println("[ota-verify] invalid signature length");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  const char *pem = OTA_VERIFY_PUBKEY_PEM;
  int ret = mbedtls_pk_parse_public_key(&pk,
              (const unsigned char *)pem, strlen(pem) + 1);
  if (ret != 0) {
    Serial.printf("[ota-verify] pubkey parse failed: -0x%04X\n", -ret);
    mbedtls_pk_free(&pk);
    return false;
  }

  uint8_t hash[32];
  mbedtls_sha256(data, OTA_MANIFEST_SIGNED_LEN, hash, 0);

  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                           hash, 32, m.signature, m.sig_len);
  mbedtls_pk_free(&pk);

  if (ret != 0) {
    Serial.printf("[ota-verify] signature failed: -0x%04X\n", -ret);
    return false;
  }

  _otav_manifest.valid = true;
  _otav_manifest.fw_size = m.fw_size;
  _otav_manifest.sec_counter = m.sec_counter;
  memcpy(_otav_manifest.expected_sha256, m.sha256, OTA_SHA256_LEN);

  Serial.printf("[ota-verify] manifest OK: fw_size=%u sec_counter=%u\n",
                m.fw_size, m.sec_counter);
  return true;
}

static void ota_verify_sha_begin() {
  mbedtls_sha256_init(&_otav_sha_ctx);
  mbedtls_sha256_starts(&_otav_sha_ctx, 0);
  _otav_sha_active = true;
}

static void ota_verify_sha_update(const uint8_t *data, int len) {
  if (_otav_sha_active)
    mbedtls_sha256_update(&_otav_sha_ctx, data, len);
}

// FR-08: SHA-256 check only — does NOT commit the security counter.
// Call ota_verify_commit_counter() after CRC check and OTA finalization.
static bool ota_verify_sha_finish() {
  if (!_otav_sha_active || !_otav_manifest.valid) return false;
  uint8_t computed[OTA_SHA256_LEN];
  mbedtls_sha256_finish(&_otav_sha_ctx, computed);
  mbedtls_sha256_free(&_otav_sha_ctx);
  _otav_sha_active = false;

  uint8_t diff = 0;
  for (int i = 0; i < OTA_SHA256_LEN; i++)
    diff |= computed[i] ^ _otav_manifest.expected_sha256[i];

  if (diff != 0) {
    Serial.println("[ota-verify] SHA-256 mismatch");
    return false;
  }

  Serial.println("[ota-verify] SHA-256 verified");
  return true;
}

// R4-03: stage the counter to NVS as "pending" before changing boot partition.
static bool ota_verify_stage_counter() {
  if (!_otav_manifest.valid) return false;
  esp_err_t e1 = nvs_set_u32(_otav_nvs, "ota_pending", _otav_manifest.sec_counter);
  esp_err_t e2 = nvs_commit(_otav_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[ota-verify] stage counter failed: set=%d commit=%d\n", e1, e2);
    return false;
  }
  return true;
}

// FR-08: commit security counter AFTER all checks pass (CRC + SHA + OTA end).
// R4-03: also clears the pending key to complete the two-phase journal.
static bool ota_verify_commit_counter() {
  if (!_otav_manifest.valid) return false;
  esp_err_t e1 = nvs_set_u32(_otav_nvs, "sec_ctr", _otav_manifest.sec_counter);
  esp_err_t e2 = nvs_commit(_otav_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[ota-verify] NVS commit failed: set=%d commit=%d\n", e1, e2);
    return false;
  }
  // R4-03: clear pending key to complete two-phase journal.
  nvs_erase_key(_otav_nvs, "ota_pending");
  nvs_commit(_otav_nvs);
  Serial.printf("[ota-verify] counter updated to %u\n", _otav_manifest.sec_counter);
  return true;
}

static void ota_verify_reset() {
  _otav_manifest.valid = false;
  if (_otav_sha_active) {
    mbedtls_sha256_free(&_otav_sha_ctx);
    _otav_sha_active = false;
  }
}

static bool ota_verify_has_manifest(uint32_t fw_size) {
  return _otav_manifest.valid && _otav_manifest.fw_size == fw_size;
}

#endif
