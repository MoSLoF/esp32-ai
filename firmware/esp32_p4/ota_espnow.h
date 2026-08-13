// Over-the-air firmware update via ESP-NOW (receiver side).
//
// Pull-based protocol: the receiver drives the transfer by requesting
// chunks one at a time, so flow control is implicit and retransmits
// are simply re-requests. Any ESP-NOW peer running the OTA push sketch
// can supply firmware.
//
// Frame types (extending espnow_comm.h):
//   0x08 OTA_OFFER   { type, sender_id:u32, fw_size:u32, n_chunks:u16,
//                       crc32:u32, chunk_size:u16, version:cstr }
//   0x09 OTA_REQUEST { type, device_id:u32, chunk_seq:u16 }
//   0x0A OTA_DATA    { type, sender_id:u32, chunk_seq:u16, len:u8, data[] }
//   0x0B OTA_STATUS  { type, device_id:u32, status:u8 }
//   0x0C OTA_MANIFEST (handled by ota_verify.h)
//
// Requires the OTA partition table (partitions_ota.csv) with ota_0/ota_1.
// Enable with USE_OTA 1 in the main sketch (implies USE_ESPNOW).

#ifndef OTA_ESPNOW_H
#define OTA_ESPNOW_H

#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "esp_system.h"
#include <string.h>

#define ESPNOW_MSG_OTA_OFFER   0x08
#define ESPNOW_MSG_OTA_REQUEST 0x09
#define ESPNOW_MSG_OTA_DATA    0x0A
#define ESPNOW_MSG_OTA_STATUS  0x0B

#define OTA_STATUS_ABORT    0
#define OTA_STATUS_COMPLETE 1
#define OTA_STATUS_ERROR    2
#define OTA_STATUS_ACCEPT   3

#define OTA_CHUNK_SIZE      226
#define OTA_REQ_TIMEOUT_MS  3000
#define OTA_MAX_RETRIES     15
#define OTA_OFFER_COOLDOWN  30000

enum OtaRxState { OTA_IDLE, OTA_ACTIVE, OTA_DONE };

static struct {
  OtaRxState state;
  esp_ota_handle_t handle;
  const esp_partition_t *part;
  uint32_t sender_id;
  uint8_t sender_mac[6];
  uint32_t fw_size;
  uint16_t n_chunks;
  uint32_t expected_crc;
  uint16_t chunk_size;
  uint16_t next_seq;
  uint32_t written;
  uint32_t crc;
  int64_t last_req;
  int retries;
  int64_t last_offer_time;
  bool ready;
} _ota;

// ---- SPSC ring buffers (EA-09) ---------------------------------------------
#define OTA_RX_RING 4

static struct {
  uint32_t id; uint8_t mac[6];
  uint32_t fw_size; uint16_t n_chunks; uint32_t crc; uint16_t chunk_size;
} _ota_offer_ring[OTA_RX_RING];
static int _ota_offer_wr = 0, _ota_offer_rd = 0;

static struct {
  uint16_t seq; uint8_t len; uint8_t data[OTA_CHUNK_SIZE];
} _ota_data_ring[OTA_RX_RING];
static int _ota_data_wr = 0, _ota_data_rd = 0;

#ifdef OTA_VERIFY_H
static struct {
  uint8_t payload[sizeof(OtaManifest) + 1];
  int len;
} _ota_manifest_ring[OTA_RX_RING];
static int _ota_manifest_wr = 0, _ota_manifest_rd = 0;
#endif

// ---- CRC32 -----------------------------------------------------------------
static uint32_t _ota_crc32(uint32_t prev, const uint8_t *d, int n) {
  uint32_t c = ~prev;
  for (int i = 0; i < n; i++) {
    c ^= d[i];
    for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c;
}

static int64_t _ota_ms() { return esp_timer_get_time() / 1000; }

// ---- TX helpers ------------------------------------------------------------
static void _ota_tx_request(uint16_t seq) {
  uint8_t f[20];
  f[0] = ESPNOW_MSG_OTA_REQUEST;
  uint32_t id = 0;
  { uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    id = _ota_crc32(0, mac, 6); }
  memcpy(f + 1, &id, 4);
  memcpy(f + 5, &seq, 2);
  espnow_send_secure(_ota.sender_mac, f, 7);
}

static void _ota_tx_status(uint8_t status) {
  uint8_t f[20];
  f[0] = ESPNOW_MSG_OTA_STATUS;
  uint32_t id = 0;
  { uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    id = _ota_crc32(0, mac, 6); }
  memcpy(f + 1, &id, 4);
  f[5] = status;
  espnow_send_secure(_ota.sender_mac, f, 6);
}

// ---- RX handler (EA-09: SPSC ring buffers) ---------------------------------
static void _ota_rx(const uint8_t *mac, const uint8_t *d, int len) {
  if (len < 5) return;
  uint8_t type = d[0];

  switch (type) {
  case ESPNOW_MSG_OTA_OFFER:
    if (len >= 17 && _ota.state == OTA_IDLE) {
      int wr = __atomic_load_n(&_ota_offer_wr, __ATOMIC_RELAXED);
      int next = (wr + 1) % OTA_RX_RING;
      if (next != __atomic_load_n(&_ota_offer_rd, __ATOMIC_ACQUIRE)) {
        memcpy(&_ota_offer_ring[wr].id, d + 1, 4);
        memcpy(&_ota_offer_ring[wr].fw_size, d + 5, 4);
        memcpy(&_ota_offer_ring[wr].n_chunks, d + 9, 2);
        memcpy(&_ota_offer_ring[wr].crc, d + 11, 4);
        memcpy(&_ota_offer_ring[wr].chunk_size, d + 15, 2);
        memcpy(_ota_offer_ring[wr].mac, mac, 6);
        __atomic_store_n(&_ota_offer_wr, next, __ATOMIC_RELEASE);
      }
    }
    break;

  case ESPNOW_MSG_OTA_DATA:
    if (len >= 8 && _ota.state == OTA_ACTIVE) {
      uint16_t seq; memcpy(&seq, d + 5, 2);
      uint8_t dlen = d[7];
      if (dlen > OTA_CHUNK_SIZE) dlen = OTA_CHUNK_SIZE;
      if (len < 8 + dlen) break;
      int wr = __atomic_load_n(&_ota_data_wr, __ATOMIC_RELAXED);
      int next = (wr + 1) % OTA_RX_RING;
      if (next != __atomic_load_n(&_ota_data_rd, __ATOMIC_ACQUIRE)) {
        _ota_data_ring[wr].seq = seq;
        _ota_data_ring[wr].len = dlen;
        memcpy(_ota_data_ring[wr].data, d + 8, dlen);
        __atomic_store_n(&_ota_data_wr, next, __ATOMIC_RELEASE);
      }
    }
    break;

#ifdef OTA_VERIFY_H
  case ESPNOW_MSG_OTA_MANIFEST:
    if (len >= 2 && _ota.state == OTA_IDLE) {
      int payload_len = len - 1;
      if (payload_len > (int)sizeof(OtaManifest)) payload_len = sizeof(OtaManifest);
      int wr = __atomic_load_n(&_ota_manifest_wr, __ATOMIC_RELAXED);
      int next = (wr + 1) % OTA_RX_RING;
      if (next != __atomic_load_n(&_ota_manifest_rd, __ATOMIC_ACQUIRE)) {
        memcpy(_ota_manifest_ring[wr].payload, d + 1, payload_len);
        _ota_manifest_ring[wr].len = payload_len;
        __atomic_store_n(&_ota_manifest_wr, next, __ATOMIC_RELEASE);
      }
    }
    break;
#endif
  }
}

// ---- public API ------------------------------------------------------------

static void ota_init() {
  memset(&_ota, 0, sizeof(_ota));
  _ota_offer_wr = _ota_offer_rd = 0;
  _ota_data_wr = _ota_data_rd = 0;
#ifdef OTA_VERIFY_H
  _ota_manifest_wr = _ota_manifest_rd = 0;
#endif
  espnow_register_peer_handler(_ota_rx);
  _ota.ready = true;
  Serial.println("OTA receiver ready");
}

static void ota_tick() {
  if (!_ota.ready) return;
  int64_t now = _ota_ms();

#ifdef OTA_VERIFY_H
  // Process manifest frames.
  for (;;) {
    int rd = __atomic_load_n(&_ota_manifest_rd, __ATOMIC_RELAXED);
    if (rd == __atomic_load_n(&_ota_manifest_wr, __ATOMIC_ACQUIRE)) break;
    ota_verify_manifest(_ota_manifest_ring[rd].payload,
                        _ota_manifest_ring[rd].len);
    __atomic_store_n(&_ota_manifest_rd, (rd + 1) % OTA_RX_RING,
                     __ATOMIC_RELEASE);
  }
#endif

  // Process OTA offer (with cooldown to prevent DoS via repeated offers).
  {
    int rd = __atomic_load_n(&_ota_offer_rd, __ATOMIC_RELAXED);
    if (rd != __atomic_load_n(&_ota_offer_wr, __ATOMIC_ACQUIRE)
        && _ota.state == OTA_IDLE) {
      if (now - _ota.last_offer_time < OTA_OFFER_COOLDOWN) {
        __atomic_store_n(&_ota_offer_rd, (rd + 1) % OTA_RX_RING,
                         __ATOMIC_RELEASE);
        return;
      }

      uint32_t offer_fw_size = _ota_offer_ring[rd].fw_size;

#ifdef OTA_VERIFY_H
      // EA-01: require verified manifest before accepting OTA offer.
      if (!ota_verify_has_manifest(offer_fw_size)) {
        Serial.println("[ota] offer rejected: no verified manifest");
        __atomic_store_n(&_ota_offer_rd, (rd + 1) % OTA_RX_RING,
                         __ATOMIC_RELEASE);
        return;
      }
#endif

      _ota.last_offer_time = now;
      _ota.sender_id = _ota_offer_ring[rd].id;
      memcpy(_ota.sender_mac, _ota_offer_ring[rd].mac, 6);
      _ota.fw_size = offer_fw_size;
      _ota.n_chunks = _ota_offer_ring[rd].n_chunks;
      _ota.expected_crc = _ota_offer_ring[rd].crc;
      _ota.chunk_size = _ota_offer_ring[rd].chunk_size;
      if (_ota.chunk_size > OTA_CHUNK_SIZE) _ota.chunk_size = OTA_CHUNK_SIZE;

      __atomic_store_n(&_ota_offer_rd, (rd + 1) % OTA_RX_RING,
                       __ATOMIC_RELEASE);

      // Add sender as ESP-NOW peer for unicast.
      esp_now_peer_info_t pi = {};
      memcpy(pi.peer_addr, _ota.sender_mac, 6);
      pi.channel = 0; pi.encrypt = false;
      esp_now_add_peer(&pi);

      // Open OTA partition.
      _ota.part = esp_ota_get_next_update_partition(NULL);
      if (!_ota.part) {
        Serial.println("[ota] no OTA partition found");
        return;
      }
      esp_err_t e = esp_ota_begin(_ota.part, _ota.fw_size, &_ota.handle);
      if (e != ESP_OK) {
        Serial.printf("[ota] esp_ota_begin failed: %d\n", e);
        return;
      }

      _ota.state = OTA_ACTIVE;
      _ota.next_seq = 0;
      _ota.written = 0;
      _ota.crc = 0;
      _ota.retries = 0;

#ifdef OTA_VERIFY_H
      ota_verify_sha_begin();
#endif

      Serial.printf("[ota] accepted: %u bytes, %d chunks from 0x%08X\n",
                    _ota.fw_size, _ota.n_chunks, _ota.sender_id);
      _ota_tx_status(OTA_STATUS_ACCEPT);
      _ota_tx_request(0);
      _ota.last_req = now;
    } else if (rd != __atomic_load_n(&_ota_offer_wr, __ATOMIC_ACQUIRE)) {
      // Drain stale offers while not idle.
      __atomic_store_n(&_ota_offer_rd, (rd + 1) % OTA_RX_RING,
                       __ATOMIC_RELEASE);
    }
  }

  if (_ota.state != OTA_ACTIVE) {
    // Drain any stale data frames.
    int rd = __atomic_load_n(&_ota_data_rd, __ATOMIC_RELAXED);
    if (rd != __atomic_load_n(&_ota_data_wr, __ATOMIC_ACQUIRE))
      __atomic_store_n(&_ota_data_rd, (rd + 1) % OTA_RX_RING,
                       __ATOMIC_RELEASE);
    return;
  }

  // Process data chunk.
  {
    int rd = __atomic_load_n(&_ota_data_rd, __ATOMIC_RELAXED);
    if (rd != __atomic_load_n(&_ota_data_wr, __ATOMIC_ACQUIRE)) {
      if (_ota_data_ring[rd].seq == _ota.next_seq) {
        uint8_t dlen = _ota_data_ring[rd].len;
        esp_err_t e = esp_ota_write(_ota.handle,
                                     _ota_data_ring[rd].data, dlen);
        if (e != ESP_OK) {
          Serial.printf("[ota] write failed at chunk %d: %d\n",
                        _ota.next_seq, e);
          _ota_tx_status(OTA_STATUS_ERROR);
          esp_ota_abort(_ota.handle);
          _ota.state = OTA_IDLE;
#ifdef OTA_VERIFY_H
          ota_verify_reset();
#endif
          __atomic_store_n(&_ota_data_rd, (rd + 1) % OTA_RX_RING,
                           __ATOMIC_RELEASE);
          return;
        }
        _ota.crc = _ota_crc32(_ota.crc, _ota_data_ring[rd].data, dlen);
#ifdef OTA_VERIFY_H
        ota_verify_sha_update(_ota_data_ring[rd].data, dlen);
#endif
        _ota.written += dlen;
        _ota.next_seq++;
        _ota.retries = 0;

        if ((_ota.next_seq & 0x3F) == 0 || _ota.next_seq >= _ota.n_chunks)
          Serial.printf("[ota] %d/%d chunks  (%u/%u bytes)\n",
                        _ota.next_seq, _ota.n_chunks,
                        _ota.written, _ota.fw_size);

        if (_ota.next_seq >= _ota.n_chunks) {
          // All chunks received — verify and finalize.
          bool crc_ok = (_ota.crc == _ota.expected_crc);
#ifdef OTA_VERIFY_H
          bool sha_ok = ota_verify_sha_finish();
#else
          bool sha_ok = true;
#endif
          if (!crc_ok) {
            Serial.printf("[ota] CRC mismatch: got 0x%08X, expected 0x%08X\n",
                          _ota.crc, _ota.expected_crc);
            _ota_tx_status(OTA_STATUS_ERROR);
            esp_ota_abort(_ota.handle);
            _ota.state = OTA_IDLE;
          } else if (!sha_ok) {
            Serial.println("[ota] SHA-256 verification failed");
            _ota_tx_status(OTA_STATUS_ERROR);
            esp_ota_abort(_ota.handle);
            _ota.state = OTA_IDLE;
          } else {
            esp_err_t e2 = esp_ota_end(_ota.handle);
            if (e2 != ESP_OK) {
              Serial.printf("[ota] esp_ota_end failed: %d\n", e2);
              _ota_tx_status(OTA_STATUS_ERROR);
              _ota.state = OTA_IDLE;
            } else {
              esp_ota_set_boot_partition(_ota.part);
              _ota_tx_status(OTA_STATUS_COMPLETE);
              Serial.println("[ota] update complete, rebooting in 2s...");
              _ota.state = OTA_DONE;
              delay(2000);
              esp_restart();
            }
          }
        } else {
          _ota_tx_request(_ota.next_seq);
          _ota.last_req = now;
        }
      }
      __atomic_store_n(&_ota_data_rd, (rd + 1) % OTA_RX_RING,
                       __ATOMIC_RELEASE);
    }
  }

  // Timeout — re-request current chunk.
  if (_ota.state == OTA_ACTIVE &&
      now - _ota.last_req > OTA_REQ_TIMEOUT_MS) {
    _ota.retries++;
    if (_ota.retries > OTA_MAX_RETRIES) {
      Serial.println("[ota] too many retries, aborting");
      _ota_tx_status(OTA_STATUS_ABORT);
      esp_ota_abort(_ota.handle);
      _ota.state = OTA_IDLE;
#ifdef OTA_VERIFY_H
      ota_verify_reset();
#endif
    } else {
      _ota_tx_request(_ota.next_seq);
      _ota.last_req = now;
    }
  }
}

#endif
