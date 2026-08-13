// Multi-hop mesh relay over ESP-NOW.
//
// Extends direct-range peer communication to multi-hop by rebroadcasting
// frames from neighbors. Each relayed frame carries a TTL (max 3 hops)
// and an origin device_id so loops are suppressed.
//
// Anti-loop: each node tracks the last N (origin, sequence) pairs it has
// seen and drops duplicates. This is the same approach used in AODV-lite
// and similar lightweight mesh protocols.
//
// Frame envelope (wraps any existing ESP-NOW frame):
//   0x10 RELAY { type=0x10, ttl:u8, origin_id:u32, seq:u16, payload... }
//
// When a node receives a relayed frame, it:
//   1. Checks if (origin, seq) was recently seen -> drop if so
//   2. Processes the inner payload locally (as if received directly)
//   3. Decrements TTL and rebroadcasts if TTL > 0
//
// Only frames >= 0x04 (peer protocol) are relayed. Low-level frames
// (token, prompt, text) are local-only for bandwidth reasons.

#ifndef MESH_RELAY_H
#define MESH_RELAY_H

#include <esp_now.h>
#include <string.h>

#define ESPNOW_MSG_RELAY  0x10
#define MESH_MAX_TTL      3
#define MESH_SEEN_SIZE    32

static struct {
  uint32_t origin;
  uint16_t seq;
  int64_t  ts;
} _mesh_seen[MESH_SEEN_SIZE];
static int _mesh_seen_idx = 0;
static uint16_t _mesh_seq = 0;
static uint32_t _mesh_self_id = 0;
static bool _mesh_ready = false;

static int64_t _mesh_ms() { return esp_timer_get_time() / 1000; }

static bool _mesh_is_seen(uint32_t origin, uint16_t seq) {
  int64_t now = _mesh_ms();
  for (int i = 0; i < MESH_SEEN_SIZE; i++) {
    if (_mesh_seen[i].origin == origin && _mesh_seen[i].seq == seq) {
      if (now - _mesh_seen[i].ts < 30000) return true;
    }
  }
  return false;
}

static void _mesh_mark_seen(uint32_t origin, uint16_t seq) {
  _mesh_seen[_mesh_seen_idx].origin = origin;
  _mesh_seen[_mesh_seen_idx].seq = seq;
  _mesh_seen[_mesh_seen_idx].ts = _mesh_ms();
  _mesh_seen_idx = (_mesh_seen_idx + 1) % MESH_SEEN_SIZE;
}

static void mesh_init(uint32_t self_id) {
  _mesh_self_id = self_id;
  memset(_mesh_seen, 0, sizeof(_mesh_seen));
  _mesh_seq = 0;
  _mesh_ready = true;
  Serial.println("[mesh] relay initialized (TTL=3, seen_buf=32)");
}

// Wrap a payload in a relay envelope and broadcast.
static void mesh_send(const uint8_t *payload, int len) {
  if (!_mesh_ready || len < 1 || len > 230) return;
  // Only relay peer-protocol and higher frames.
  if (payload[0] < 0x04) return;

  uint8_t frame[250];
  frame[0] = ESPNOW_MSG_RELAY;
  frame[1] = MESH_MAX_TTL;
  memcpy(frame + 2, &_mesh_self_id, 4);
  uint16_t seq = _mesh_seq++;
  memcpy(frame + 6, &seq, 2);
  memcpy(frame + 8, payload, len);
  _mesh_mark_seen(_mesh_self_id, seq);
  espnow_send_secure(ESPNOW_BROADCAST, frame, 8 + len);
}

// Handle an incoming relay frame. Returns the inner payload length (>0)
// if the frame should be processed locally, 0 if it's a duplicate.
// inner_out points to the inner payload on success.
static int mesh_rx(const uint8_t *data, int len,
                    const uint8_t **inner_out) {
  if (len < 9 || data[0] != ESPNOW_MSG_RELAY) return 0;

  uint8_t ttl = data[1];
  uint32_t origin;
  memcpy(&origin, data + 2, 4);
  uint16_t seq;
  memcpy(&seq, data + 6, 2);

  if (origin == _mesh_self_id) return 0;
  if (_mesh_is_seen(origin, seq)) return 0;
  _mesh_mark_seen(origin, seq);

  // Re-broadcast with decremented TTL (re-signed by espnow_send_secure).
  if (ttl > 1 && len <= 238) {
    uint8_t fwd[250];
    memcpy(fwd, data, len);
    fwd[1] = ttl - 1;
    espnow_send_secure(ESPNOW_BROADCAST, fwd, len);
  }

  *inner_out = data + 8;
  return len - 8;
}

// ESP-NOW handler for relay frames — registered alongside peer_protocol.
static void _mesh_espnow_handler(const uint8_t *mac,
                                   const uint8_t *data, int len) {
  if (len < 1 || data[0] != ESPNOW_MSG_RELAY) return;

  // Prevent re-entrant dispatch (stack overflow from nested relay frames).
  static bool _mesh_dispatching = false;
  if (_mesh_dispatching) return;

  const uint8_t *inner;
  int inner_len = mesh_rx(data, len, &inner);
  if (inner_len <= 0) return;

  // Reject nested relay frames — inner payload must not be another relay.
  if (inner[0] == ESPNOW_MSG_RELAY) return;

  _mesh_dispatching = true;
  extern espnow_peer_handler_t _espnow_ext[];
  extern int _espnow_n_ext;
  for (int h = 0; h < _espnow_n_ext; h++)
    _espnow_ext[h](mac, inner, inner_len);
  _mesh_dispatching = false;
}

#endif
