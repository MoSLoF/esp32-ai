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

#define OTA_CHUNK_SIZE      230
#define OTA_REQ_TIMEOUT_MS  3000
#define OTA_MAX_RETRIES     15

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
  bool ready;
} _ota;

// ---- incoming frame buffers ------------------------------------------------
static volatile struct {
  bool pending; uint32_t id; uint8_t mac[6];
  uint32_t fw_size; uint16_t n_chunks; uint32_t crc; uint16_t chunk_size;
} _ota_in_offer;

static volatile struct {
  bool pending; uint16_t seq; uint8_t len; uint8_t data[OTA_CHUNK_SIZE];
} _ota_in_data;

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
  uint8_t f[7];
  f[0] = ESPNOW_MSG_OTA_REQUEST;
  uint32_t id = 0;
  { uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    id = _ota_crc32(0, mac, 6); }
  memcpy(f + 1, &id, 4);
  memcpy(f + 5, &seq, 2);
  esp_now_send(_ota.sender_mac, f, sizeof(f));
}

static void _ota_tx_status(uint8_t status) {
  uint8_t f[6];
  f[0] = ESPNOW_MSG_OTA_STATUS;
  uint32_t id = 0;
  { uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    id = _ota_crc32(0, mac, 6); }
  memcpy(f + 1, &id, 4);
  f[5] = status;
  esp_now_send(_ota.sender_mac, f, sizeof(f));
}

// ---- RX handler ------------------------------------------------------------
static void _ota_rx(const uint8_t *mac, const uint8_t *d, int len) {
  if (len < 5) return;
  uint8_t type = d[0];

  switch (type) {
  case ESPNOW_MSG_OTA_OFFER:
    if (len >= 17 && _ota.state == OTA_IDLE) {
      memcpy((void *)&_ota_in_offer.id, d + 1, 4);
      memcpy((void *)&_ota_in_offer.fw_size, d + 5, 4);
      memcpy((void *)&_ota_in_offer.n_chunks, d + 9, 2);
      memcpy((void *)&_ota_in_offer.crc, d + 11, 4);
      memcpy((void *)&_ota_in_offer.chunk_size, d + 15, 2);
      memcpy((void *)_ota_in_offer.mac, mac, 6);
      _ota_in_offer.pending = true;
    }
    break;

  case ESPNOW_MSG_OTA_DATA:
    if (len >= 8 && _ota.state == OTA_ACTIVE) {
      uint16_t seq; memcpy(&seq, d + 5, 2);
      uint8_t dlen = d[7];
      if (dlen > OTA_CHUNK_SIZE) dlen = OTA_CHUNK_SIZE;
      if (len < 8 + dlen) break;
      _ota_in_data.seq = seq;
      _ota_in_data.len = dlen;
      memcpy((void *)_ota_in_data.data, d + 8, dlen);
      _ota_in_data.pending = true;
    }
    break;
  }
}

// ---- public API ------------------------------------------------------------

static void ota_init() {
  memset(&_ota, 0, sizeof(_ota));
  memset((void *)&_ota_in_offer, 0, sizeof(_ota_in_offer));
  memset((void *)&_ota_in_data, 0, sizeof(_ota_in_data));
  espnow_register_peer_handler(_ota_rx);
  _ota.ready = true;
  Serial.println("OTA receiver ready");
}

static void ota_tick() {
  if (!_ota.ready) return;
  int64_t now = _ota_ms();

  // Process OTA offer.
  if (_ota_in_offer.pending && _ota.state == OTA_IDLE) {
    _ota.sender_id = _ota_in_offer.id;
    memcpy(_ota.sender_mac, (void *)_ota_in_offer.mac, 6);
    _ota.fw_size = _ota_in_offer.fw_size;
    _ota.n_chunks = _ota_in_offer.n_chunks;
    _ota.expected_crc = _ota_in_offer.crc;
    _ota.chunk_size = _ota_in_offer.chunk_size;
    if (_ota.chunk_size > OTA_CHUNK_SIZE) _ota.chunk_size = OTA_CHUNK_SIZE;

    // Add sender as ESP-NOW peer for unicast.
    esp_now_peer_info_t pi = {};
    memcpy(pi.peer_addr, _ota.sender_mac, 6);
    pi.channel = 0; pi.encrypt = false;
    esp_now_add_peer(&pi);

    // Open OTA partition.
    _ota.part = esp_ota_get_next_update_partition(NULL);
    if (!_ota.part) {
      Serial.println("[ota] no OTA partition found");
      _ota_in_offer.pending = false;
      return;
    }
    esp_err_t e = esp_ota_begin(_ota.part, _ota.fw_size, &_ota.handle);
    if (e != ESP_OK) {
      Serial.printf("[ota] esp_ota_begin failed: %d\n", e);
      _ota_in_offer.pending = false;
      return;
    }

    _ota.state = OTA_ACTIVE;
    _ota.next_seq = 0;
    _ota.written = 0;
    _ota.crc = 0;
    _ota.retries = 0;

    Serial.printf("[ota] accepted: %u bytes, %d chunks from 0x%08X\n",
                  _ota.fw_size, _ota.n_chunks, _ota.sender_id);
    _ota_tx_status(OTA_STATUS_ACCEPT);
    _ota_tx_request(0);
    _ota.last_req = now;
    _ota_in_offer.pending = false;
  }

  if (_ota.state != OTA_ACTIVE) {
    _ota_in_offer.pending = false;
    _ota_in_data.pending = false;
    return;
  }

  // Process data chunk.
  if (_ota_in_data.pending) {
    if (_ota_in_data.seq == _ota.next_seq) {
      uint8_t dlen = _ota_in_data.len;
      esp_err_t e = esp_ota_write(_ota.handle,
                                   (void *)_ota_in_data.data, dlen);
      if (e != ESP_OK) {
        Serial.printf("[ota] write failed at chunk %d: %d\n",
                      _ota.next_seq, e);
        _ota_tx_status(OTA_STATUS_ERROR);
        esp_ota_abort(_ota.handle);
        _ota.state = OTA_IDLE;
        _ota_in_data.pending = false;
        return;
      }
      _ota.crc = _ota_crc32(_ota.crc, (uint8_t *)_ota_in_data.data, dlen);
      _ota.written += dlen;
      _ota.next_seq++;
      _ota.retries = 0;

      if ((_ota.next_seq & 0x3F) == 0 || _ota.next_seq >= _ota.n_chunks)
        Serial.printf("[ota] %d/%d chunks  (%u/%u bytes)\n",
                      _ota.next_seq, _ota.n_chunks,
                      _ota.written, _ota.fw_size);

      if (_ota.next_seq >= _ota.n_chunks) {
        // All chunks received — verify and finalize.
        if (_ota.crc != _ota.expected_crc) {
          Serial.printf("[ota] CRC mismatch: got 0x%08X, expected 0x%08X\n",
                        _ota.crc, _ota.expected_crc);
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
    _ota_in_data.pending = false;
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
    } else {
      _ota_tx_request(_ota.next_seq);
      _ota.last_req = now;
    }
  }
}

#endif
