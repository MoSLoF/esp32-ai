// Sender-side epoch/replay state machine -- mirrors firmware/esp32_p4/crypto_peer.h's
// receiver-side logic exactly, extracted into its own header (rather than
// inline in espnow_sender.ino) so it can be compiled and executed directly
// by a host test the same way crypto_peer.h already is.
//
// R5-01 (verification-memo hardening): the sender previously had NO
// persisted epoch floor at all for the peer it verifies (_sender_replay[]
// was only memset, never saved/reloaded) -- worse than the analogous
// receiver-side gap the verification memo found, since a sender reboot
// forgot even the retired-epoch protection, not just the same-epoch
// sequence-watermark protection. This header brings the sender up to the
// same standard as crypto_peer.h: a persistent monotonic epoch (no random
// fallback), a persisted per-peer epoch floor, and a persisted seq
// watermark reserved ahead of the live counter -- see crypto_peer.h's
// design comments for the full rationale, which applies identically here.

#ifndef SENDER_REPLAY_H
#define SENDER_REPLAY_H

#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#define SENDER_REPLAY_SLOTS 4
#define SENDER_EPOCH_SILENCE_MS 5000
// R4-05: stale threshold for slot eviction (unrelated to epoch ordering).
#define SENDER_SLOT_STALE_MS 60000
// R5-01: mirrors crypto_peer.h's CRYPTO_SEQ_WINDOW -- see that file for
// the flash-wear/replay-window tradeoff this tunes.
#define SENDER_SEQ_WINDOW 256

static struct {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t last_seq;
  uint32_t accepted_through;
  unsigned long last_seen_ms;
  bool active;
} _sender_replay[SENDER_REPLAY_SLOTS];

typedef struct __attribute__((packed)) {
  uint8_t mac[6];
  uint32_t epoch;
  uint32_t accepted_through;
  uint8_t active;
} SenderFloorEntry;

#define SENDER_FLOOR_NVS_KEY "floors_v2"

static nvs_handle_t _sender_floor_nvs;
static bool _sender_floor_nvs_ready = false;

static void _sender_load_epoch_floors() {
  if (nvs_open("sender_floor", NVS_READWRITE, &_sender_floor_nvs) != ESP_OK) {
    Serial.println("[crypto] WARNING: sender epoch-floor NVS unavailable — "
                   "peer epoch floors will not survive a sender reboot");
    _sender_floor_nvs_ready = false;
    return;
  }
  _sender_floor_nvs_ready = true;

  SenderFloorEntry buf[SENDER_REPLAY_SLOTS];
  size_t len = sizeof(buf);
  if (nvs_get_blob(_sender_floor_nvs, SENDER_FLOOR_NVS_KEY, buf, &len) == ESP_OK &&
      len == sizeof(buf)) {
    for (int i = 0; i < SENDER_REPLAY_SLOTS; i++) {
      if (buf[i].active) {
        memcpy(_sender_replay[i].mac, buf[i].mac, 6);
        _sender_replay[i].epoch = buf[i].epoch;
        _sender_replay[i].accepted_through = buf[i].accepted_through;
        // R5-01: restore last_seq from the durable watermark, not 0.
        _sender_replay[i].last_seq = buf[i].accepted_through;
        _sender_replay[i].active = true;
      }
    }
  }
}

// R5-01: persist the floors table with one slot's (mac, epoch,
// accepted_through) substituted for a CANDIDATE value, built from current
// RAM state otherwise. Returns false -- and the caller must not mutate its
// own RAM state -- if the write fails, so a rejection can be issued
// instead of accepting on state that never became durable.
static bool _sender_persist_epoch_floor_candidate(int cand_slot,
                                                    const uint8_t *cand_mac,
                                                    uint32_t cand_epoch,
                                                    uint32_t cand_accepted_through) {
  if (!_sender_floor_nvs_ready) return false;
  SenderFloorEntry buf[SENDER_REPLAY_SLOTS];
  memset(buf, 0, sizeof(buf));
  for (int i = 0; i < SENDER_REPLAY_SLOTS; i++) {
    if (i == cand_slot) {
      memcpy(buf[i].mac, cand_mac, 6);
      buf[i].epoch = cand_epoch;
      buf[i].accepted_through = cand_accepted_through;
      buf[i].active = 1;
    } else if (_sender_replay[i].active) {
      memcpy(buf[i].mac, _sender_replay[i].mac, 6);
      buf[i].epoch = _sender_replay[i].epoch;
      buf[i].accepted_through = _sender_replay[i].accepted_through;
      buf[i].active = 1;
    }
  }
  esp_err_t e1 = nvs_set_blob(_sender_floor_nvs, SENDER_FLOOR_NVS_KEY, buf, sizeof(buf));
  esp_err_t e2 = nvs_commit(_sender_floor_nvs);
  if (e1 != ESP_OK || e2 != ESP_OK) {
    Serial.printf("[crypto] CRITICAL: failed to persist sender epoch/watermark floor "
                  "(slot=%d set=%d commit=%d) -- rejecting frame (fail closed)\n",
                  cand_slot, e1, e2);
    return false;
  }
  return true;
}

static uint32_t _sender_next_watermark(uint32_t seq) {
  return (seq > UINT32_MAX - SENDER_SEQ_WINDOW) ? UINT32_MAX : seq + SENDER_SEQ_WINDOW;
}

// R5-01: fallible, no random fallback, overflow-guarded -- mirrors
// crypto_peer.h's crypto_next_persistent_epoch() exactly.
static bool sender_next_persistent_epoch(uint32_t *out_epoch) {
  nvs_handle_t h;
  if (nvs_open("crypto_ep", NVS_READWRITE, &h) != ESP_OK) {
    Serial.println("[crypto] CRITICAL: persistent epoch counter NVS unavailable "
                   "-- refusing to start (no non-monotonic fallback)");
    return false;
  }
  uint32_t epoch = 0;
  nvs_get_u32(h, "boot_ctr", &epoch);
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

// R5-01: reset in-RAM replay state and reload the persisted floor table.
// Must be called during setup(), before the RX callback is registered.
static bool sender_replay_init() {
  memset(_sender_replay, 0, sizeof(_sender_replay));
  _sender_load_epoch_floors();
  return _sender_floor_nvs_ready;
}

// Returns 1 (accept) / 0 (reject). Mirrors crypto_peer.h's crypto_verify()
// replay branch exactly, factored out so it's independently host-testable
// without needing a full HMAC envelope (the caller has already verified
// the frame and extracted epoch/seq by this point).
static int sender_replay_check(const uint8_t *mac, uint32_t epoch, uint32_t seq) {
  int slot = -1, evict = 0;
  unsigned long oldest = ULONG_MAX;
  for (int i = 0; i < SENDER_REPLAY_SLOTS; i++) {
    if (_sender_replay[i].active && memcmp(_sender_replay[i].mac, mac, 6) == 0) {
      slot = i; break;
    }
    if (!_sender_replay[i].active) { evict = i; oldest = 0; }
    else if (_sender_replay[i].last_seen_ms < oldest) { oldest = _sender_replay[i].last_seen_ms; evict = i; }
  }
  unsigned long now_ms = millis();

  if (slot >= 0) {
    if (epoch == _sender_replay[slot].epoch) {
      if (seq <= _sender_replay[slot].last_seq) return 0;
      // R5-01: only touch NVS when seq crosses the already-durable
      // watermark -- the common case is a pure RAM comparison.
      if (seq > _sender_replay[slot].accepted_through) {
        uint32_t new_watermark = _sender_next_watermark(seq);
        if (!_sender_persist_epoch_floor_candidate(slot, mac, epoch, new_watermark))
          return 0;  // fail closed
        _sender_replay[slot].accepted_through = new_watermark;
      }
      _sender_replay[slot].last_seq = seq;
    } else if (epoch > _sender_replay[slot].epoch) {
      if (now_ms - _sender_replay[slot].last_seen_ms < SENDER_EPOCH_SILENCE_MS) return 0;
      uint32_t new_watermark = _sender_next_watermark(seq);
      if (!_sender_persist_epoch_floor_candidate(slot, mac, epoch, new_watermark))
        return 0;  // fail closed
      _sender_replay[slot].epoch = epoch;
      _sender_replay[slot].last_seq = seq;
      _sender_replay[slot].accepted_through = new_watermark;
    } else {
      // R5-01: epoch is a persistent monotonic counter, so any epoch not
      // strictly greater than the highest ever accepted is permanently
      // retired -- no eviction path can reopen it.
      return 0;
    }
    _sender_replay[slot].last_seen_ms = now_ms;
  } else {
    // R3-01: fail closed — reject unknown MACs when all slots active.
    // R4-05: authenticated stale eviction — evict oldest slot if stale.
    if (_sender_replay[evict].active &&
        now_ms - _sender_replay[evict].last_seen_ms < SENDER_SLOT_STALE_MS) return 0;
    uint32_t new_watermark = _sender_next_watermark(seq);
    if (!_sender_persist_epoch_floor_candidate(evict, mac, epoch, new_watermark))
      return 0;  // fail closed
    memcpy(_sender_replay[evict].mac, mac, 6);
    _sender_replay[evict].epoch = epoch;
    _sender_replay[evict].last_seq = seq;
    _sender_replay[evict].accepted_through = new_watermark;
    _sender_replay[evict].last_seen_ms = now_ms;
    _sender_replay[evict].active = true;
  }
  return 1;
}

#endif
