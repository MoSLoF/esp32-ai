// LoRa <-> ESP-NOW bridge: relay peer protocol frames over 915 MHz.
//
// Runs on an ESP32 with a LoRa radio (Heltec WiFi LoRa 32, TTGO T-Beam,
// LilyGO T3, or any board with SX1276/SX1262). Bridges two clusters of
// ESP32-P4 boards that are beyond ESP-NOW range (~200m) so they can
// discover and validate each other over LoRa distances (1-10+ km).
//
// Anti-loop: only relays frames from devices discovered locally via
// ESP-NOW identity beacons. Frames re-broadcast from LoRa into ESP-NOW
// are not re-relayed because their originators aren't in the local list.
//
// Requires RadioLib: https://github.com/jgromes/RadioLib
//
// Board selection: set LORA_CHIP below.
//   LORA_SX1276  — Heltec V2, TTGO LoRa32 V1, T-Beam V0.7-1.0
//   LORA_SX1262  — Heltec V3, LilyGO T3 S3, T-Beam V1.1+
//
// Pin assignments are board-specific; defaults are for Heltec WiFi LoRa 32.
// Change them to match your board.

#include <RadioLib.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_mac.h>

// ---- board configuration ---------------------------------------------------
// Uncomment ONE chip line:
#define LORA_SX1276
// #define LORA_SX1262

// Heltec WiFi LoRa 32 V2 (SX1276) pin defaults:
#ifdef LORA_SX1276
#define PIN_CS    18
#define PIN_RST   14
#define PIN_DIO0  26
#define PIN_DIO1  33
SX1276 radio = new Module(PIN_CS, PIN_DIO0, PIN_RST, PIN_DIO1);
#endif

// Heltec WiFi LoRa 32 V3 (SX1262) pin defaults:
#ifdef LORA_SX1262
#define PIN_CS    8
#define PIN_RST   12
#define PIN_DIO1  14
#define PIN_BUSY  13
SX1262 radio = new Module(PIN_CS, PIN_DIO1, PIN_RST, PIN_BUSY);
#endif

// ---- LoRa parameters (915 MHz ISM, US) ------------------------------------
#define LORA_FREQ     915.0
#define LORA_BW       125.0
#define LORA_SF       7
#define LORA_CR       5
#define LORA_SYNC     0x12
#define LORA_POWER    17
#define LORA_PREAMBLE 8

// ---- relay configuration ---------------------------------------------------
#define RELAY_MAX_LOCAL   16
#define RELAY_MAGIC       0xA1
#define ESPNOW_MSG_IDENTITY 0x04

static const uint8_t BROADCAST[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// ---- local device table (heard directly via ESP-NOW) -----------------------
static struct {
  uint32_t id;
  int64_t last_seen;
} _local[RELAY_MAX_LOCAL];
static int _n_local = 0;

static uint32_t _bridge_id;

static uint32_t _relay_crc32(const uint8_t *d, int n) {
  uint32_t c = 0xFFFFFFFF;
  for (int i = 0; i < n; i++) {
    c ^= d[i];
    for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c;
}

static bool _is_local(uint32_t id) {
  for (int i = 0; i < _n_local; i++)
    if (_local[i].id == id) return true;
  return false;
}

static void _add_local(uint32_t id) {
  for (int i = 0; i < _n_local; i++)
    if (_local[i].id == id) {
      _local[i].last_seen = millis();
      return;
    }
  if (_n_local < RELAY_MAX_LOCAL) {
    _local[_n_local].id = id;
    _local[_n_local].last_seen = millis();
    _n_local++;
  }
}

// ---- LoRa packet format ----------------------------------------------------
// [0]    RELAY_MAGIC
// [1-4]  bridge_id (originating bridge)
// [5]    espnow frame type
// [6]    espnow frame length
// [7..]  original ESP-NOW frame data

// ---- ESP-NOW -> LoRa relay queue -------------------------------------------
#define RELAY_QUEUE_SIZE 8
static struct {
  uint8_t data[250];
  int len;
} _relay_queue[RELAY_QUEUE_SIZE];
static volatile int _rq_head = 0, _rq_tail = 0;

static void _enqueue_for_lora(const uint8_t *data, int len) {
  int next = (_rq_head + 1) % RELAY_QUEUE_SIZE;
  if (next == _rq_tail) return; // full
  memcpy(_relay_queue[_rq_head].data, data, len);
  _relay_queue[_rq_head].len = len;
  _rq_head = next;
}

// ---- ESP-NOW RX callback ---------------------------------------------------
static void _bridge_espnow_rx(const esp_now_recv_info_t *info,
                                const uint8_t *data, int len) {
  if (len < 1) return;
  uint8_t type = data[0];

  // Track local devices from identity beacons.
  if (type == ESPNOW_MSG_IDENTITY && len >= 5) {
    uint32_t id;
    memcpy(&id, data + 1, 4);
    if (!_is_local(id)) {
      int nlen = (len > 12) ? len - 12 : 0;
      if (nlen > 16) nlen = 16;
      Serial.printf("[bridge] local peer: %.*s (0x%08X)\n",
                    nlen, (len > 12) ? (const char *)(data + 12) : "?",
                    id);
    }
    _add_local(id);
  }

  // Relay peer protocol frames (0x04-0x0B) from local devices.
  if (type >= 0x04 && type <= 0x0B && len >= 5) {
    uint32_t sender_id;
    memcpy(&sender_id, data + 1, 4);
    if (_is_local(sender_id))
      _enqueue_for_lora(data, len);
  }
}

// ---- LoRa TX ---------------------------------------------------------------
static bool _lora_busy = false;

static void _lora_send_relay(const uint8_t *espnow_data, int espnow_len) {
  uint8_t pkt[7 + 250];
  pkt[0] = RELAY_MAGIC;
  memcpy(pkt + 1, &_bridge_id, 4);
  pkt[5] = espnow_data[0]; // frame type
  pkt[6] = (uint8_t)espnow_len;
  memcpy(pkt + 7, espnow_data, espnow_len);

  int state = radio.transmit(pkt, 7 + espnow_len);
  if (state != RADIOLIB_ERR_NONE)
    Serial.printf("[bridge] LoRa TX error: %d\n", state);
}

// ---- LoRa RX -> ESP-NOW re-broadcast ---------------------------------------
static void _lora_check_rx() {
  int len = radio.getPacketLength();
  if (len < 7) return;

  uint8_t pkt[260];
  int state = radio.readData(pkt, len);
  if (state != RADIOLIB_ERR_NONE) return;

  if (pkt[0] != RELAY_MAGIC) return;

  uint32_t origin_bridge;
  memcpy(&origin_bridge, pkt + 1, 4);
  if (origin_bridge == _bridge_id) return; // ignore own relays

  uint8_t frame_len = pkt[6];
  if (frame_len > 250 || 7 + frame_len > len) return;

  // Re-broadcast the original ESP-NOW frame locally.
  esp_now_send(BROADCAST, pkt + 7, frame_len);

  uint8_t ftype = pkt[5];
  Serial.printf("[bridge] LoRa->local: type=0x%02X, %d bytes, RSSI=%.0f\n",
                ftype, frame_len, radio.getRSSI());
}

// ---- setup -----------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ESP-NOW <-> LoRa Bridge ===");

  // Bridge identity.
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  _bridge_id = _relay_crc32(mac, 6);
  Serial.printf("bridge ID: 0x%08X\n", _bridge_id);

  // WiFi + ESP-NOW.
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed");
    return;
  }
  esp_now_register_recv_cb(_bridge_espnow_rx);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, BROADCAST, 6);
  peer.channel = 0; peer.encrypt = false;
  esp_now_add_peer(&peer);
  Serial.println("ESP-NOW ready");

  // LoRa.
  Serial.print("LoRa init... ");
  int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                           LORA_SYNC, LORA_POWER, LORA_PREAMBLE);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.printf("FAILED (%d)\n", state);
    Serial.println("check wiring and pin defines at top of sketch");
    return;
  }
  Serial.printf("ok (%.1f MHz, SF%d, BW%.0f)\n", LORA_FREQ, LORA_SF, LORA_BW);

  // Start LoRa receive mode.
  radio.startReceive();
  Serial.println("bridge active, relaying peer protocol frames\n");
}

// ---- loop ------------------------------------------------------------------
static unsigned long _last_status = 0;

void loop() {
  // Drain ESP-NOW -> LoRa relay queue.
  while (_rq_tail != _rq_head) {
    _lora_send_relay(_relay_queue[_rq_tail].data,
                     _relay_queue[_rq_tail].len);
    _rq_tail = (_rq_tail + 1) % RELAY_QUEUE_SIZE;
    radio.startReceive(); // back to RX after TX
  }

  // Check for incoming LoRa packets.
  if (radio.available()) {
    _lora_check_rx();
    radio.startReceive();
  }

  // Periodic status.
  if (millis() - _last_status > 30000) {
    Serial.printf("--- bridge 0x%08X | local peers: %d ---\n",
                  _bridge_id, _n_local);
    _last_status = millis();
  }

  delay(5);
}
