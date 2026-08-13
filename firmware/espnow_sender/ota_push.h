// OTA firmware push over ESP-NOW (sender side).
//
// Receives a firmware binary via serial from the host, stores it in
// heap/PSRAM, then serves it chunk-by-chunk to a requesting P4 peer.
// Pull-based: the receiver drives the transfer by requesting chunks.
//
// Serial protocol (host -> sender):
//   1. Host sends:  "ota <size_bytes>\n"
//   2. Sender replies: "READY\n"
//   3. Host sends:  <raw binary, exactly size_bytes>
//   4. Sender replies: "OK <crc32_hex>\n" or "ERR\n"
//   5. User types "push" to broadcast OTA_OFFER and begin serving.
//
// Use with tools/ota_push.py for automation.

#ifndef OTA_PUSH_H
#define OTA_PUSH_H

#include <esp_now.h>
#include <string.h>

#define ESPNOW_MSG_OTA_OFFER   0x08
#define ESPNOW_MSG_OTA_REQUEST 0x09
#define ESPNOW_MSG_OTA_DATA    0x0A
#define ESPNOW_MSG_OTA_STATUS  0x0B

#define OTA_PUSH_CHUNK 230

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

// ---- incoming request buffer -----------------------------------------------
static volatile struct {
  bool pending; uint16_t seq; uint8_t mac[6];
} _otap_req;

static volatile struct {
  bool pending; uint8_t status; uint8_t mac[6];
} _otap_status;

// ---- RX handler ------------------------------------------------------------
static void _otap_rx(const esp_now_recv_info_t *info,
                      const uint8_t *d, int len) {
  if (len < 1) return;

  if (d[0] == ESPNOW_MSG_OTA_REQUEST && len >= 7) {
    uint16_t seq; memcpy(&seq, d + 5, 2);
    _otap_req.seq = seq;
    memcpy((void *)_otap_req.mac, info->src_addr, 6);
    _otap_req.pending = true;
  }

  if (d[0] == ESPNOW_MSG_OTA_STATUS && len >= 6) {
    _otap_status.status = d[5];
    memcpy((void *)_otap_status.mac, info->src_addr, 6);
    _otap_status.pending = true;
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

// ---- broadcast OTA offer ---------------------------------------------------
static void ota_push_start() {
  if (!_otap.loaded) {
    Serial.println("no firmware loaded; use 'ota <size>' first");
    return;
  }
  uint8_t f[50];
  f[0] = ESPNOW_MSG_OTA_OFFER;
  memcpy(f + 1, &_otap.device_id, 4);
  memcpy(f + 5, &_otap.fw_size, 4);
  memcpy(f + 9, &_otap.n_chunks, 2);
  memcpy(f + 11, &_otap.crc, 4);
  memcpy(f + 15, &_otap.chunk_size, 2);
  const char *ver = "espnow-ota";
  int vlen = strlen(ver);
  memcpy(f + 17, ver, vlen + 1);
  esp_now_send(ESPNOW_BROADCAST, f, 18 + vlen);

  _otap.pushing = true;
  _otap.last_served = 0;
  Serial.println("[ota-push] offer broadcast, waiting for requests...");
}

// ---- serve chunks ----------------------------------------------------------
static void ota_push_tick() {
  if (!_otap.pushing) return;

  if (_otap_req.pending) {
    uint16_t seq = _otap_req.seq;
    if (seq < _otap.n_chunks) {
      uint32_t offset = (uint32_t)seq * _otap.chunk_size;
      uint32_t remaining = _otap.fw_size - offset;
      uint8_t dlen = (remaining < _otap.chunk_size)
                       ? (uint8_t)remaining : (uint8_t)_otap.chunk_size;
      uint8_t frame[8 + OTA_PUSH_CHUNK];
      frame[0] = ESPNOW_MSG_OTA_DATA;
      memcpy(frame + 1, &_otap.device_id, 4);
      memcpy(frame + 5, &seq, 2);
      frame[7] = dlen;
      memcpy(frame + 8, _otap.fw + offset, dlen);

      // Add requester as peer if not already.
      esp_now_peer_info_t pi = {};
      memcpy(pi.peer_addr, (void *)_otap_req.mac, 6);
      pi.channel = 0; pi.encrypt = false;
      esp_now_add_peer(&pi);

      esp_now_send((uint8_t *)_otap_req.mac, frame, 8 + dlen);
      _otap.last_served = seq;

      if ((seq & 0x3F) == 0 || seq + 1 >= _otap.n_chunks)
        Serial.printf("[ota-push] served %d/%d\n", seq + 1, _otap.n_chunks);
    }
    _otap_req.pending = false;
  }

  if (_otap_status.pending) {
    uint8_t st = _otap_status.status;
    if (st == 1) {
      Serial.println("[ota-push] receiver confirmed update complete!");
      _otap.pushing = false;
    } else if (st == 0 || st == 2) {
      Serial.printf("[ota-push] receiver reported %s\n",
                    st == 0 ? "abort" : "error");
      _otap.pushing = false;
    }
    _otap_status.pending = false;
  }
}

static void ota_push_init() {
  memset(&_otap, 0, sizeof(_otap));
  memset((void *)&_otap_req, 0, sizeof(_otap_req));
  memset((void *)&_otap_status, 0, sizeof(_otap_status));
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  _otap.device_id = _otap_crc32(mac, 6);
}

#endif
