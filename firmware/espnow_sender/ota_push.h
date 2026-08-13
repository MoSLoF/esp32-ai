// OTA firmware push over ESP-NOW (sender side).
//
// Receives a firmware binary via serial from the host, stores it in
// heap/PSRAM, then serves it chunk-by-chunk to a requesting P4 peer.
// Pull-based: the receiver drives the transfer by requesting chunks.
//
// EA-01: Supports pre-signed OTA manifest upload and broadcast.
// EA-04: Signs all OTA frames with crypto_envelope.h when enabled.
//
// Serial protocol (host -> sender):
//   1. Host sends:  "ota <size_bytes>\n"
//   2. Sender replies: "READY\n"
//   3. Host sends:  <raw binary, exactly size_bytes>
//   4. Sender replies: "OK <crc32_hex>\n" or "ERR\n"
//   5. Host sends:  "manifest <size>\n" then raw manifest bytes
//   6. User types "push" to broadcast OTA_MANIFEST + OTA_OFFER.
//
// Use with tools/ota_push.py for automation.

#ifndef OTA_PUSH_H
#define OTA_PUSH_H

#include <esp_now.h>
#include <string.h>
#include "../common/crypto_envelope.h"

#define ESPNOW_MSG_OTA_OFFER    0x08
#define ESPNOW_MSG_OTA_REQUEST  0x09
#define ESPNOW_MSG_OTA_DATA     0x0A
#define ESPNOW_MSG_OTA_STATUS   0x0B
#define ESPNOW_MSG_OTA_MANIFEST 0x0C

#define OTA_PUSH_CHUNK 226

// EA-04: sender-side crypto state.
// R2-04: no default PSK — must be provisioned at compile time.
#ifndef CRYPTO_PSK
#error "CRYPTO_PSK must be defined — set via -DCRYPTO_PSK=\"...\""
#endif

static const char *_otap_psk = CRYPTO_PSK;
// R2-03: epoch and tx_seq are shared with the sender's prompt path
// to prevent sequence counter conflicts on the same MAC+epoch pair.
// These are set to point to the sender's shared counters in espnow_sender.ino.
static uint32_t *_otap_epoch_ptr = NULL;
static uint32_t *_otap_tx_seq_ptr = NULL;
static bool _otap_crypto_enabled = false;

static struct {
  uint8_t *fw;
  uint32_t fw_size;
  uint16_t n_chunks;
  uint32_t crc;
  uint16_t chunk_size;
  bool loaded;
  bool pushing;
  uint16_t last_served;
  uint32_t device_id;
  uint8_t *manifest;
  int manifest_len;
  uint8_t receiver_mac[6];  // R2-05: MAC of the receiver we're serving
  bool receiver_bound;
} _otap;

// ---- CRC32 -----------------------------------------------------------------
static uint32_t _otap_crc32(const uint8_t *d, uint32_t n) {
  uint32_t c = 0xFFFFFFFF;
  for (uint32_t i = 0; i < n; i++) {
    c ^= d[i];
    for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c;
}

// FR-07: SPSC ring buffers replace volatile compound state.
#define OTAP_RING 4

static struct {
  uint16_t seq; uint8_t mac[6];
} _otap_req_ring[OTAP_RING];
static int _otap_req_wr = 0, _otap_req_rd = 0;

static struct {
  uint8_t status; uint8_t mac[6];
} _otap_status_ring[OTAP_RING];
static int _otap_status_wr = 0, _otap_status_rd = 0;

// EA-04: sign and send a frame.
// R2-03: uses shared epoch/seq counters to prevent sequence conflicts.
static void _otap_send_signed(const uint8_t *dest, uint8_t *frame,
                               int len) {
  if (_otap_crypto_enabled && len > 0 && _otap_epoch_ptr && _otap_tx_seq_ptr) {
    uint32_t seq = (*_otap_tx_seq_ptr)++;
    len = crypto_env_sign(_otap_psk, frame, len, *_otap_epoch_ptr, seq);
  }
  esp_now_send(dest, frame, len);
}

// FR-07: RX handler uses SPSC ring buffers with acquire/release atomics.
static void _otap_rx(const esp_now_recv_info_t *info,
                      const uint8_t *d, int len) {
  if (len < 1) return;

  int verified_len = len;
  if (_otap_crypto_enabled) {
    uint32_t ep, sq;
    verified_len = crypto_env_verify(_otap_psk, d, len, &ep, &sq);
    if (verified_len <= 0) return;
  }

  if (d[0] == ESPNOW_MSG_OTA_REQUEST && verified_len >= 7) {
    int wr = __atomic_load_n(&_otap_req_wr, __ATOMIC_RELAXED);
    int next = (wr + 1) % OTAP_RING;
    if (next != __atomic_load_n(&_otap_req_rd, __ATOMIC_ACQUIRE)) {
      memcpy(&_otap_req_ring[wr].seq, d + 5, 2);
      memcpy(_otap_req_ring[wr].mac, info->src_addr, 6);
      __atomic_store_n(&_otap_req_wr, next, __ATOMIC_RELEASE);
    }
  }

  if (d[0] == ESPNOW_MSG_OTA_STATUS && verified_len >= 6) {
    int wr = __atomic_load_n(&_otap_status_wr, __ATOMIC_RELAXED);
    int next = (wr + 1) % OTAP_RING;
    if (next != __atomic_load_n(&_otap_status_rd, __ATOMIC_ACQUIRE)) {
      _otap_status_ring[wr].status = d[5];
      memcpy(_otap_status_ring[wr].mac, info->src_addr, 6);
      __atomic_store_n(&_otap_status_wr, next, __ATOMIC_RELEASE);
    }
  }
}

// ---- serial upload ---------------------------------------------------------
static bool ota_push_upload(uint32_t size) {
  if (_otap.fw) { free(_otap.fw); _otap.fw = NULL; }

  // Try PSRAM first, fall back to heap.
#ifdef MALLOC_CAP_SPIRAM
  _otap.fw = (uint8_t *)heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
#endif
  if (!_otap.fw) _otap.fw = (uint8_t *)malloc(size);
  if (!_otap.fw) {
    Serial.println("ERR: not enough memory");
    return false;
  }

  Serial.println("READY");
  uint32_t got = 0;
  unsigned long t0 = millis();
  while (got < size) {
    if (Serial.available()) {
      int n = Serial.readBytes((char *)_otap.fw + got, size - got);
      got += n;
      t0 = millis();
    }
    if (millis() - t0 > 10000) {
      Serial.println("ERR: timeout");
      free(_otap.fw); _otap.fw = NULL;
      return false;
    }
    delay(1);
  }

  _otap.fw_size = size;
  _otap.chunk_size = OTA_PUSH_CHUNK;
  _otap.n_chunks = (size + OTA_PUSH_CHUNK - 1) / OTA_PUSH_CHUNK;
  _otap.crc = _otap_crc32(_otap.fw, size);
  _otap.loaded = true;
  _otap.pushing = false;
  Serial.printf("OK %08X\n", _otap.crc);
  Serial.printf("firmware: %u bytes, %d chunks, CRC 0x%08X\n",
                size, _otap.n_chunks, _otap.crc);
  return true;
}

// EA-01: upload a pre-signed manifest via serial.
static bool ota_push_upload_manifest(uint32_t size) {
  if (size > 250 || size < 20) {
    Serial.println("ERR: invalid manifest size");
    return false;
  }
  if (_otap.manifest) { free(_otap.manifest); _otap.manifest = NULL; }
  _otap.manifest = (uint8_t *)malloc(size);
  if (!_otap.manifest) {
    Serial.println("ERR: not enough memory");
    return false;
  }

  Serial.println("READY");
  uint32_t got = 0;
  unsigned long t0 = millis();
  while (got < size) {
    if (Serial.available()) {
      int n = Serial.readBytes((char *)_otap.manifest + got, size - got);
      got += n;
      t0 = millis();
    }
    if (millis() - t0 > 5000) {
      Serial.println("ERR: timeout");
      free(_otap.manifest); _otap.manifest = NULL;
      return false;
    }
    delay(1);
  }

  _otap.manifest_len = size;
  Serial.printf("manifest loaded: %u bytes\n", size);
  return true;
}

// ---- broadcast OTA offer ---------------------------------------------------
static void ota_push_start() {
  if (!_otap.loaded) {
    Serial.println("no firmware loaded; use 'ota <size>' first");
    return;
  }

  // EA-01: broadcast manifest first if available.
  if (_otap.manifest && _otap.manifest_len > 0) {
    uint8_t mf[1 + 250 + CRYPTO_ENV_OVERHEAD];
    mf[0] = ESPNOW_MSG_OTA_MANIFEST;
    memcpy(mf + 1, _otap.manifest, _otap.manifest_len);
    _otap_send_signed(ESPNOW_BROADCAST, mf, 1 + _otap.manifest_len);
    Serial.println("[ota-push] manifest broadcast");
    delay(100);
  }

  uint8_t f[50 + CRYPTO_ENV_OVERHEAD];
  f[0] = ESPNOW_MSG_OTA_OFFER;
  memcpy(f + 1, &_otap.device_id, 4);
  memcpy(f + 5, &_otap.fw_size, 4);
  memcpy(f + 9, &_otap.n_chunks, 2);
  memcpy(f + 11, &_otap.crc, 4);
  memcpy(f + 15, &_otap.chunk_size, 2);
  const char *ver = "espnow-ota";
  int vlen = strlen(ver);
  memcpy(f + 17, ver, vlen + 1);
  _otap_send_signed(ESPNOW_BROADCAST, f, 18 + vlen);

  _otap.pushing = true;
  _otap.last_served = 0;
  _otap.receiver_bound = false;
  Serial.println("[ota-push] offer broadcast, waiting for requests...");
}

// FR-07: serve chunks from SPSC ring buffers.
static void ota_push_tick() {
  if (!_otap.pushing) return;

  // Drain request ring.
  for (;;) {
    int rd = __atomic_load_n(&_otap_req_rd, __ATOMIC_RELAXED);
    if (rd == __atomic_load_n(&_otap_req_wr, __ATOMIC_ACQUIRE)) break;

    uint16_t seq = _otap_req_ring[rd].seq;
    // R2-05: bind receiver MAC on first request.
    if (!_otap.receiver_bound) {
      memcpy(_otap.receiver_mac, _otap_req_ring[rd].mac, 6);
      _otap.receiver_bound = true;
    }
    if (seq < _otap.n_chunks) {
      uint32_t offset = (uint32_t)seq * _otap.chunk_size;
      uint32_t remaining = _otap.fw_size - offset;
      uint8_t dlen = (remaining < _otap.chunk_size)
                       ? (uint8_t)remaining : (uint8_t)_otap.chunk_size;
      uint8_t frame[8 + OTA_PUSH_CHUNK + CRYPTO_ENV_OVERHEAD];
      frame[0] = ESPNOW_MSG_OTA_DATA;
      memcpy(frame + 1, &_otap.device_id, 4);
      memcpy(frame + 5, &seq, 2);
      frame[7] = dlen;
      memcpy(frame + 8, _otap.fw + offset, dlen);

      esp_now_peer_info_t pi = {};
      memcpy(pi.peer_addr, _otap_req_ring[rd].mac, 6);
      pi.channel = 0; pi.encrypt = false;
      esp_now_add_peer(&pi);

      _otap_send_signed(_otap_req_ring[rd].mac, frame, 8 + dlen);
      _otap.last_served = seq;

      if ((seq & 0x3F) == 0 || seq + 1 >= _otap.n_chunks)
        Serial.printf("[ota-push] served %d/%d\n", seq + 1, _otap.n_chunks);
    }
    __atomic_store_n(&_otap_req_rd, (rd + 1) % OTAP_RING, __ATOMIC_RELEASE);
  }

  // R2-05: drain status ring — only accept status from the bound receiver.
  for (;;) {
    int rd = __atomic_load_n(&_otap_status_rd, __ATOMIC_RELAXED);
    if (rd == __atomic_load_n(&_otap_status_wr, __ATOMIC_ACQUIRE)) break;

    uint8_t st = _otap_status_ring[rd].status;
    bool from_receiver = _otap.receiver_bound &&
        memcmp(_otap_status_ring[rd].mac, _otap.receiver_mac, 6) == 0;
    if (from_receiver) {
      if (st == 1) {
        Serial.println("[ota-push] receiver confirmed update complete!");
        _otap.pushing = false;
      } else if (st == 0 || st == 2) {
        Serial.printf("[ota-push] receiver reported %s\n",
                      st == 0 ? "abort" : "error");
        _otap.pushing = false;
      }
    }
    __atomic_store_n(&_otap_status_rd, (rd + 1) % OTAP_RING, __ATOMIC_RELEASE);
  }
}

static void ota_push_init() {
  memset(&_otap, 0, sizeof(_otap));
  _otap_req_wr = _otap_req_rd = 0;
  _otap_status_wr = _otap_status_rd = 0;
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  _otap.device_id = _otap_crc32(mac, 6);
}

#endif
