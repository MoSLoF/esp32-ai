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
// Known residual limitation: CRYPTO_REPLAY_SLOTS bounds how many distinct
// senders' epoch floors can be tracked/persisted at once. If a sender goes
// silent for over CRYPTO_SLOT_STALE_US while >= CRYPTO_REPLAY_SLOTS other
// *authenticated* senders are active, its slot (and persisted floor) can
// be evicted to make room; if that sender's MAC is then seen again, it is
// treated as a first sighting. Closing this fully would require unbounded
// per-sender storage; CRYPTO_REPLAY_SLOTS=16 is sized well above the
// expected flock size as a practical mitigation. Note this eviction still
// requires the evicting traffic to itself be HMAC-authenticated (fail
// closed for unknown MACs below), so an attacker without the PSK cannot
// trigger it.
#define CRYPTO_SLOT_STALE_US       60000000  // 60s stale threshold for slot eviction
// R5-01 (verification-memo hardening): size of the sequence range reserved
// (persisted) ahead of the live seq counter -- see the durable watermark
// design note above _crypto_persist_epoch_floor_candidate() below. Tunable:
// larger bounds fewer NVS writes at the cost of a bigger post-reboot
// legitimate-frame-rejection window; smaller does the reverse.
#define CRYPTO_SEQ_WINDOW 256
static struct {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t last_seq;
  // R5-01: durable seq watermark -- see below. Any seq <= this value is
  // guaranteed rejected even as the very first frame processed after a
  // receiver reboot, because it's what last_seq is restored to on load.
  uint32_t accepted_through;
  int64_t last_seen_us;
  bool active;
} _crypto_replay[CRYPTO_REPLAY_SLOTS];

// R5-01 (verification-memo hardening): a receiver-reboot replay bypass was
// found in the previous fix. That fix persisted each sender's epoch floor
// (mac+epoch) so a RETIRED epoch stays rejected forever across a reboot --
// but last_seq was never persisted (reset to 0 on every boot), so a
// captured frame from the sender's CURRENT, still-valid epoch with any
// seq > 0 was accepted again immediately after a reboot: seq > last_seq(0)
// trivially passes. Fix: persist a durable seq WATERMARK ("accepted_through")
// per slot, advanced in reserved chunks of CRYPTO_SEQ_WINDOW ahead of the
// live seq rather than on every packet (bounds flash writes to roughly one
// per CRYPTO_SEQ_WINDOW frames instead of one per frame), and restore
// last_seq from that watermark on load -- not from 0. Cost: a legitimate
// frame with seq in (actual last-accepted seq before the crash,
// accepted_through] is also rejected right after a reboot, until the live
// sender's seq naturally advances past the persisted watermark. That's a
// bounded, accepted availability tradeoff, not a security gap.
//
// The watermark must be persisted BEFORE a frame that requires advancing
// it is accepted, and the frame must be REJECTED if that persist fails --
// accepting on RAM-only state (as the previous _crypto_persist_epoch_floors()
// did, logging but not gating on failure) means a crash right after would
// have delivered a frame with no durable record of it, reopening the same
// class of bug the watermark exists to close. Only mac+epoch+watermark are
// persisted (not live seq/timestamps).
typedef struct __attribute__((packed)) {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t accepted_through;
  uint8_t active;
} CryptoFloorEntry;

// R5-01: bumped from "floors" -- the persisted record's layout changed
// (added accepted_through). A fresh key makes the schema change explicit
// instead of relying on the incidental struct-size check to catch it; a
// device upgrading firmware loses its persisted floors once (falls back to
// first-sighting semantics for previously-known senders), a one-time,
// openly-declared tradeoff rather than a silent bug.
#define CRYPTO_FLOOR_NVS_KEY "floors_v2"

static nvs_handle_t _crypto_floor_nvs;
static bool _crypto_floor_nvs_ready = false;

static void _crypto_load_epoch_floors() {
  if (nvs_open("crypto_floor", NVS_READWRITE, &_crypto_floor_nvs) != ESP_OK) {
    Serial.println("[crypto] WARNING: epoch-floor NVS unavailable — "
                   "sender epoch floors will not survive a receiver reboot");
    _crypto_floor_nvs_ready = false;
    return;
  }
  _crypto_floor_nvs_ready = true;

  CryptoFloorEntry buf[CRYPTO_REPLAY_SLOTS];
  size_t len = sizeof(buf);
  if (nvs_get_blob(_crypto_floor_nvs, CRYPTO_FLOOR_NVS_KEY, buf, &len) == ESP_OK &&
      len == sizeof(buf)) {
    for (int i = 0; i < CRYPTO_REPLAY_SLOTS; i++) {
      if (buf[i].active) {
        memcpy(_crypto_replay[i].mac, buf[i].mac, 6);
        _crypto_replay[i].epoch = buf[i].epoch;
        _crypto_replay[i].accepted_through = buf[i].accepted_through;
        // R5-01: restore last_seq from the durable watermark, not 0, so a
        // captured frame with seq <= accepted_through is rejected even as
        // the very first frame processed after reboot.
        _crypto_replay[i].last_seq = buf[i].accepted_through;
        _crypto_replay[i].active = true;
      }
    }
  }
}

// R5-01: persist the floors table with one slot's (mac, epoch,
// accepted_through) substituted for a CANDIDATE value, built entirely from
// current RAM state otherwise. Returns false -- and touches no RAM state
// in the caller -- if the write fails, so callers can fail closed (reject
// the frame) instead of accepting on state that never became durable.
static bool _crypto_persist_epoch_floor_candidate(int cand_slot,
                                                    const uint8_t *cand_mac,
                                                    uint32_t cand_epoch,
                                                    uint32_t cand_accepted_through) {
  if (!_crypto_floor_nvs_ready) return false;
  CryptoFloorEntry buf[CRYPTO_REPLAY_SLOTS];
  memset(buf, 0, sizeof(buf));
  for (int i = 0; i < CRYPTO_REPLAY_SLOTS; i++) {
    if (i == cand_slot) {
      memcpy(buf[i].mac, cand_mac, 6);
      buf[i].epoch = cand_epoch;
      buf[i].accepted_through = cand_accepted_through;
      buf[i].active = 1;
    } else if (_crypto_replay[i].active) {
      memcpy(buf[i].mac, _crypto_replay[i].mac, 6);
      buf[i].epoch = _crypto_replay[i].epoch;
      buf[i].accepted_through = _crypto_replay[i].accepted_through;
      buf[i].active = 1;
    }
  }
  esp_err_t e1 = nvs_set_blob(_crypto_floor_nvs, CRYPTO_FLOOR_NVS_KEY, buf, sizeof(buf));
  esp_err_t e2 = nvs_commit(_crypto_floor_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[crypto] CRITICAL: failed to persist epoch/watermark floor "
                  "(slot=%d set=%d commit=%d) -- rejecting frame (fail closed)\n",
                  cand_slot, e1, e2);
    return false;
  }
  return true;
}

// R5-01: given the seq that just triggered a watermark advance, compute
// the new durable watermark, with explicit uint32 overflow protection.
static uint32_t _crypto_next_watermark(uint32_t seq) {
  return (seq > UINT32_MAX - CRYPTO_SEQ_WINDOW) ? UINT32_MAX : seq + CRYPTO_SEQ_WINDOW;
}

// R5-01: persistent monotonic epoch. A random per-boot epoch has no
// ordering relation across reboots, which is what forced the old design
// into a bounded "retired epoch" ring that had to evict entries (and thus
// eventually re-admit them) to stay fail-closed. Loading a monotonically
// increasing, NVS-persisted counter instead means an epoch that has been
// superseded is invalid forever — comparison replaces bookkeeping.
// R5-01 (verification-memo hardening): the random-epoch fallback on NVS
// failure is REMOVED -- it silently reopened the exact non-monotonic-epoch
// weakness this design exists to close. If a monotonic epoch can't be
// durably allocated and committed, the caller must refuse to bring up
// crypto/ESP-NOW rather than come up "healthy" with a forgeable epoch.
// Also guards explicit uint32 overflow: an about-to-wrap counter is
// treated as unrecoverable exhaustion, not silently wrapped (which would
// violate monotonicity for the device's very next boot).
static bool crypto_next_persistent_epoch(uint32_t *out_epoch) {
  nvs_handle_t h;
  if (nvs_open("crypto_ep", NVS_READWRITE, &h) != ESP_OK) {
    Serial.println("[crypto] CRITICAL: persistent epoch counter NVS unavailable "
                   "-- refusing to start (no non-monotonic fallback)");
    return false;
  }
  uint32_t epoch = 0;
  nvs_get_u32(h, "boot_ctr", &epoch);  // NOT_FOUND on first-ever boot leaves epoch=0, fine
  if (epoch == UINT32_MAX) {
    Serial.println("[crypto] CRITICAL: persistent epoch counter exhausted "
                   "(would wrap to 0) -- refusing to start");
    nvs_close(h);
    return false;
  }
  epoch++;
  esp_err_t e1 = nvs_set_u32(h, "boot_ctr", epoch);
  esp_err_t e2 = nvs_commit(h);
  nvs_close(h);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[crypto] CRITICAL: persistent epoch counter commit failed "
                  "(set=%d commit=%d) -- refusing to start\n", e1, e2);
    return false;
  }
  *out_epoch = epoch;
  return true;
}

// R5-01 (verification-memo hardening): crypto_init() is now fallible. No
// random-epoch fallback exists anymore, and floor/watermark persistence
// failures must fail closed (see crypto_verify() below) -- so without
// durable NVS for either the epoch counter or the floor table, crypto
// would come up "ready" but be unable to accept any traffic at all.
// Refusing to start is more honest than that. Callers must check the
// return value and keep ESP-NOW/crypto disabled on failure.
static bool crypto_init() {
  memset(_crypto_replay, 0, sizeof(_crypto_replay));
  _crypto_tx_seq = 0;
  if (!crypto_next_persistent_epoch(&_crypto_epoch)) {
    _crypto_ready = false;
    return false;
  }
  esp_read_mac(_crypto_own_mac, ESP_MAC_WIFI_STA);
  _crypto_load_epoch_floors();
  if (!_crypto_floor_nvs_ready) {
    Serial.println("[crypto] CRITICAL: epoch-floor NVS unavailable -- refusing to start");
    _crypto_ready = false;
    return false;
  }
  _crypto_ready = true;
  Serial.printf("[crypto] HMAC-SHA256 enabled (overhead=%d, epoch=0x%08X, replay_slots=%d)\n",
                CRYPTO_OVERHEAD, _crypto_epoch, CRYPTO_REPLAY_SLOTS);
  return true;
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
      // R5-01: only need to touch NVS when seq actually crosses the
      // already-durable watermark -- the common case (seq within the
      // reserved window) is a pure RAM comparison, no flash write.
      if (seq > _crypto_replay[slot].accepted_through) {
        uint32_t new_watermark = _crypto_next_watermark(seq);
        if (!_crypto_persist_epoch_floor_candidate(slot, src_mac, epoch, new_watermark))
          return 0;  // fail closed: never accept ahead of durable state
        _crypto_replay[slot].accepted_through = new_watermark;
      }
      _crypto_replay[slot].last_seq = seq;
    } else if (epoch > _crypto_replay[slot].epoch) {
      // New epoch — require silence period before accepting, as
      // defense-in-depth against rapid epoch churn.
      int64_t silence = now_us - _crypto_replay[slot].last_seen_us;
      if (silence < CRYPTO_EPOCH_SILENCE_US)
        return 0;
      // R5-01: persist the new floor (epoch + fresh watermark) BEFORE
      // accepting -- fail closed if it doesn't durably land.
      uint32_t new_watermark = _crypto_next_watermark(seq);
      if (!_crypto_persist_epoch_floor_candidate(slot, src_mac, epoch, new_watermark))
        return 0;
      _crypto_replay[slot].epoch = epoch;
      _crypto_replay[slot].last_seq = seq;
      _crypto_replay[slot].accepted_through = new_watermark;
    } else {
      // R5-01: epoch is a persistent monotonic sender boot counter, so as
      // long as this slot's floor is remembered, any epoch not strictly
      // greater than it is permanently retired -- there is no ring or
      // time-based path that reopens it (see CRYPTO_SLOT_STALE_US above
      // for the one, bounded, authenticated-eviction-only exception).
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
    // R5-01: persist this sender's initial floor (epoch + fresh watermark)
    // BEFORE accepting -- fail closed if it doesn't durably land.
    uint32_t new_watermark = _crypto_next_watermark(seq);
    if (!_crypto_persist_epoch_floor_candidate(evict, src_mac, epoch, new_watermark))
      return 0;
    memcpy(_crypto_replay[evict].mac, src_mac, 6);
    _crypto_replay[evict].epoch = epoch;
    _crypto_replay[evict].last_seq = seq;
    _crypto_replay[evict].accepted_through = new_watermark;
    _crypto_replay[evict].last_seen_us = now_us;
    _crypto_replay[evict].active = true;
  }

  return payload_len;
}

#endif
