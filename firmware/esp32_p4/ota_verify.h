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
#include "esp_partition.h"
#include "esp_ota_ops.h"
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

// R5-03: two-phase counter journal. Superseded the old single "ota_pending"
// key, which recorded only the counter -- recovery had no way to tell
// "staged but power lost before the boot partition was switched" (old
// image still running) apart from "boot partition was switched, only the
// final commit was lost" (new image now running). Journaling the target
// partition alongside the counter lets recovery ask ground truth (which
// partition actually booted?) instead of assuming the switch happened.
#define OTA_JOURNAL_PHASE_NONE   0
#define OTA_JOURNAL_PHASE_STAGED 1

// R5-03 (verification-memo hardening): set whenever a boot's recovery
// attempt observes durable state it can't safely resolve -- a counter
// commit failed, or the pending record was unreadable/incomplete. Cleared
// only by a LATER boot's recovery actually converging (see
// _ota_verify_recover() below); never cleared any other way.
// ota_verify_manifest() refuses to accept new manifests while this is set,
// which transitively blocks the whole OTA pipeline (staging, committing)
// since every later step requires a valid manifest first.
static bool _otav_recovery_blocked = false;

static bool ota_verify_recovery_blocked() { return _otav_recovery_blocked; }

// R5-03: erase the journal keys and check every result, returning success
// so callers can react to a cleanup failure. Used both to finish a
// successful commit and to abandon a staged-but-never-activated
// transaction (either right after esp_ota_set_boot_partition fails, or
// during boot recovery).
static bool _ota_verify_clear_journal(const char *ctx) {
  esp_err_t e1 = nvs_erase_key(_otav_nvs, "pend_phase");
  esp_err_t e2 = nvs_erase_key(_otav_nvs, "pend_ctr");
  esp_err_t e3 = nvs_erase_key(_otav_nvs, "pend_part");
  esp_err_t e4 = nvs_commit(_otav_nvs);
  bool ok = (e1 == ESP_OK || e1 == ESP_ERR_NVS_NOT_FOUND) &&
            (e2 == ESP_OK || e2 == ESP_ERR_NVS_NOT_FOUND) &&
            (e3 == ESP_OK || e3 == ESP_ERR_NVS_NOT_FOUND) &&
            e4 == ESP_OK;
  if (!ok)
    Serial.printf("[ota-verify] WARNING: journal cleanup (%s) failed "
                  "(erase=%d/%d/%d commit=%d) -- stale keys may remain\n",
                  ctx, e1, e2, e3, e4);
  return ok;
}

// R5-03: abandon a staged-but-not-yet-activated transaction immediately
// (e.g. esp_ota_set_boot_partition just failed) rather than waiting for a
// reboot for recovery to figure it out. The counter is left untouched so
// the same manifest can be retried.
static bool ota_verify_abandon_stage() {
  return _ota_verify_clear_journal("abandon");
}

// R4-03/R5-03: recover from a power loss during a previous OTA commit.
// Compares the journaled target partition against the partition that
// actually booted -- ground truth, not assumed intent -- to decide
// whether the update took effect.
//
// R5-03 (verification-memo hardening): the original version of this
// function unconditionally cleared the journal even when the recovery
// commit itself failed, destroying the only durable record of the pending
// transaction while leaving sec_ctr possibly stale -- a real anti-rollback
// consistency gap (a stale, too-low sec_ctr could let a captured
// lower-numbered signed manifest later pass the anti-rollback check, or
// needlessly block a legitimate retry). Fixed: every read this function
// depends on is now checked, and journal-destroying cleanup is skipped
// entirely whenever the record can't be fully and safely resolved --
// leaving it intact for an identical retry on the next boot instead.
static void _ota_verify_recover() {
  _otav_recovery_blocked = false;  // this boot's own outcome decides the flag

  uint8_t phase = OTA_JOURNAL_PHASE_NONE;
  if (nvs_get_u8(_otav_nvs, "pend_phase", &phase) != ESP_OK ||
      phase == OTA_JOURNAL_PHASE_NONE)
    return;

  uint32_t pend_ctr = 0;
  uint8_t pend_subtype = 0xFF;
  esp_err_t e_ctr = nvs_get_u32(_otav_nvs, "pend_ctr", &pend_ctr);
  esp_err_t e_part = nvs_get_u8(_otav_nvs, "pend_part", &pend_subtype);
  if (e_ctr != ESP_OK || e_part != ESP_OK) {
    // phase says STAGED but the record is incomplete/unreadable. Do not
    // guess: no counter burn, no journal clear, no activation decision.
    // Leave everything exactly as found for a retry on the next boot.
    Serial.printf("[ota-verify] CRITICAL: journal read incomplete (ctr=%d part=%d) "
                  "-- deferring recovery decision to next boot\n", e_ctr, e_part);
    _otav_recovery_blocked = true;
    return;
  }

  const esp_partition_t *running = esp_ota_get_running_partition();
  bool activated = running != NULL && running->subtype == pend_subtype;

  if (activated) {
    // The journaled target partition is the one that actually booted --
    // the switch took effect, so the update genuinely completed. Finish
    // committing the counter (this also covers a crash between
    // esp_ota_set_boot_partition succeeding and the final commit).
    uint32_t current = 0;
    esp_err_t e_cur = nvs_get_u32(_otav_nvs, "sec_ctr", &current);
    if (e_cur != ESP_OK && e_cur != ESP_ERR_NVS_NOT_FOUND) {
      // Can't safely compare pend_ctr against an unknown current value --
      // a silently-defaulted current=0 risks treating a rollback-unsafe
      // comparison as safe. Same fail-safe treatment as the reads above.
      Serial.printf("[ota-verify] CRITICAL: could not read current sec_ctr (err=%d) "
                    "-- deferring recovery decision to next boot\n", e_cur);
      _otav_recovery_blocked = true;
      return;
    }
    if (pend_ctr > current) {
      esp_err_t e1 = nvs_set_u32(_otav_nvs, "sec_ctr", pend_ctr);
      esp_err_t e2 = nvs_commit(_otav_nvs);
      if (e1 != ESP_OK || e2 != ESP_OK) {
        // R5-03: THE core fix -- do not fall through to clear the journal.
        // Leaving it intact means the exact same recovery decision is
        // retried, and can succeed, on the next boot.
        Serial.printf("[ota-verify] CRITICAL: recovery counter commit failed "
                      "(set=%d commit=%d) -- journal left intact for retry, "
                      "blocking further OTA acceptance\n", e1, e2);
        _otav_recovery_blocked = true;
        return;
      }
      Serial.printf("[ota-verify] recovered: activated partition confirmed, counter -> %u\n",
                    pend_ctr);
    }
  } else {
    // The running partition does NOT match the journaled target: power
    // was lost before esp_ota_set_boot_partition took effect (or it
    // failed), so the old image is still running. Do not burn the
    // counter for an update that never activated -- abandon the journal
    // so the same signed manifest can be retried at the same counter.
    Serial.println("[ota-verify] recovery: staged update was never activated "
                   "(old partition still running) -- abandoning, counter left untouched");
  }

  if (!_ota_verify_clear_journal("recover")) {
    // Same self-healing reasoning as ota_verify_commit_counter()'s cleanup
    // failure below: sec_ctr (activated branch) is already durably
    // correct, or (abandoned branch) untouched -- a stale pend_* record
    // just re-triggers the same ground-truth check next boot. Not blocked.
    Serial.println("[ota-verify] WARNING: journal cleanup after recovery failed "
                   "-- will retry cleanup on next boot");
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
  if (_otav_recovery_blocked) {
    Serial.println("[ota-verify] REJECTED: prior recovery attempt left durable "
                   "state unconverged -- refusing new manifests until a clean boot recovers");
    return false;
  }
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

// R4-03/R5-03: stage the full transaction journal (target partition +
// pending counter + explicit phase) to NVS BEFORE changing the boot
// partition, so a power loss before the switch takes effect can be told
// apart from one after, and the counter is never committed for an update
// that never actually activated.
//
// R5-03 (verification-memo hardening): pend_phase -- the "this record is
// complete" marker -- is written LAST, after pend_ctr and pend_part.
// ESP-IDF's NVS has no cross-key transactions, so a crash between two
// separate nvs_set_* calls is a real possibility; writing phase last means
// a crash mid-stage leaves phase at its prior value (normally NONE, since
// ota_verify_manifest() refuses to stage a new transaction while a prior
// one is unrecovered) rather than STAGED pointing at a mix of new and
// stale pend_ctr/pend_part from a previous transaction -- a case the
// read-failure checks in _ota_verify_recover() alone wouldn't catch,
// since those reads would succeed, just with the wrong generation's data.
static bool ota_verify_stage_counter(const esp_partition_t *target) {
  if (!_otav_manifest.valid || !target) return false;
  esp_err_t e1 = nvs_set_u32(_otav_nvs, "pend_ctr", _otav_manifest.sec_counter);
  esp_err_t e2 = nvs_set_u8(_otav_nvs, "pend_part", target->subtype);
  esp_err_t e3 = nvs_set_u8(_otav_nvs, "pend_phase", OTA_JOURNAL_PHASE_STAGED);
  esp_err_t e4 = nvs_commit(_otav_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK || e3 != ESP_OK || e4 != ESP_OK) {
    Serial.printf("[ota-verify] stage transaction failed: ctr=%d part=%d phase=%d commit=%d\n",
                  e1, e2, e3, e4);
    return false;
  }
  return true;
}

// FR-08: commit security counter AFTER all checks pass (CRC + SHA + OTA end)
// and the boot partition switch has already succeeded.
// R4-03/R5-03: also clears the journal to complete the two-phase transaction.
static bool ota_verify_commit_counter() {
  if (!_otav_manifest.valid) return false;
  esp_err_t e1 = nvs_set_u32(_otav_nvs, "sec_ctr", _otav_manifest.sec_counter);
  esp_err_t e2 = nvs_commit(_otav_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[ota-verify] NVS commit failed: set=%d commit=%d\n", e1, e2);
    return false;
  }
  // If cleanup below fails, the counter is already correctly committed to
  // match the partition that is about to boot, so the leftover journal is
  // merely stale: next boot's recovery will see running == pend_part,
  // re-commit the same (already-correct) counter, and clear it then. This
  // path is deliberately NOT treated as _otav_recovery_blocked -- unlike a
  // failed recovery commit, sec_ctr here is already correct.
  if (!_ota_verify_clear_journal("commit"))
    Serial.println("[ota-verify] WARNING: journal cleanup after commit failed (non-fatal, self-healing)");
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
