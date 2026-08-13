// Peer discovery and AI model validation over ESP-NOW.
//
// Two ESP32-P4 boards running the same model discover each other via
// broadcast beacons and verify mutual model identity through
// challenge-response inference. Both devices run identical firmware;
// the protocol is symmetric.
//
// Flow:
//   1. Both broadcast identity beacons every 3 seconds.
//   2. On discovering a new peer, wait briefly then send a CHALLENGE:
//      a prompt from the shared bank plus locally-computed expected output.
//   3. Peer runs inference on the challenge prompt and returns its tokens.
//   4. Challenger compares response against expected output.
//   5. When both peers validate each other -> BONDED.
//
// Each device gets a deterministic name from its MAC (e.g. "bold-spark").
// Encounter and bond counts persist across reboots via NVS.
//
// Requires espnow_comm.h (included first) for transport, and a
// peer_infer_fn_t callback that runs greedy inference on demand.
//
// Frame types (extending espnow_comm.h 0x01-0x03):
//   0x04 IDENTITY  { type, device_id:u32, encounters:u16, nonce:u32,
//                     flags:u8, name:cstr }
//   0x05 CHALLENGE { type, device_id:u32, chal_id:u16, n:u8, n_exp:u8,
//                     prompt:u16[n] }
//   0x06 RESPONSE  { type, device_id:u32, chal_id:u16, n:u8, tokens:u16[n] }
//   0x07 VALIDATE  { type, device_id:u32, chal_id:u16, result:u8, bonds:u16 }

#ifndef PEER_PROTOCOL_H
#define PEER_PROTOCOL_H

#include <esp_timer.h>
#include <esp_mac.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <string.h>
#include "peer_identity.h"

#define ESPNOW_MSG_IDENTITY  0x04
#define ESPNOW_MSG_CHALLENGE 0x05
#define ESPNOW_MSG_RESPONSE  0x06
#define ESPNOW_MSG_VALIDATE  0x07

#define PEER_BEACON_MS        3000
#define PEER_CHALLENGE_DELAY  2000
#define PEER_CHALLENGE_TIMEOUT 15000
#define PEER_STATUS_MS        10000
#define PEER_MAX              8
#define PEER_NAME_LEN         16
#define PEER_PROMPT_LEN       4
#define PEER_RESP_LEN         5

typedef int (*peer_infer_fn_t)(const int *prompt, int n_prompt,
                                int n_generate, int *out_tokens);

// ---- peer slot -------------------------------------------------------------
struct PeerSlot {
  bool active;
  uint32_t device_id;
  uint8_t mac[6];
  char name[PEER_NAME_LEN];
  bool i_validated;
  bool they_validated;
  bool bonded;
  bool challenge_sent;
  uint16_t challenge_id;
  int expected[PEER_RESP_LEN];
  int n_expected;
  int64_t first_seen;
  int64_t last_seen;
  int64_t challenge_time;
  uint16_t bond_count;
};

// ---- challenge prompt bank (identical on all peers) ------------------------
static const int CHALLENGE_BANK[][PEER_PROMPT_LEN] = {
  {433,  447,  259,  405},
  {1788, 539,  259,  464},
  {4189, 1039, 267,  539},
  {464,  433,  447,  259},
};
static const int N_CHAL_BANK =
    sizeof(CHALLENGE_BANK) / sizeof(CHALLENGE_BANK[0]);

// ---- name generation -------------------------------------------------------
static const char * const _PR_ADJ[] = {
  "swift","bright","deep","wild","calm","bold","keen","dark",
  "warm","cool","sharp","soft","quick","wise","pure","stark"
};
static const char * const _PR_NOUN[] = {
  "spark","wave","storm","frost","flame","stone","blade","drift",
  "pulse","glow","core","beam","edge","void","flux","node"
};

// ---- module state ----------------------------------------------------------
static struct {
  uint32_t device_id;
  char name[PEER_NAME_LEN];
  uint16_t total_encounters;
  uint16_t total_bonds;
  peer_infer_fn_t infer;
  nvs_handle_t nvs;
  int64_t last_beacon;
  int64_t last_status;
  uint16_t next_cid;
  bool ready;
} _pr;

static PeerSlot _pr_peers[PEER_MAX];

// ---- incoming frame buffers (RX callback writes, tick reads) ---------------
static volatile struct {
  bool pending; uint32_t id; uint8_t mac[6];
} _pri;

static volatile struct {
  bool pending; uint32_t id; uint8_t mac[6];
  uint16_t cid; int prompt[PEER_PROMPT_LEN]; int n; int n_exp;
} _prc;

static volatile struct {
  bool pending; uint32_t id; uint16_t cid;
  int tokens[PEER_RESP_LEN]; int n;
} _prr;

static volatile struct {
  bool pending; uint32_t id; uint16_t cid; bool pass;
} _prv;

// ---- utilities -------------------------------------------------------------

static uint32_t _pr_crc32(const uint8_t *d, int n) {
  uint32_t c = 0xFFFFFFFF;
  for (int i = 0; i < n; i++) {
    c ^= d[i];
    for (int j = 0; j < 8; j++) c = (c >> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c;
}

static void _pr_mkname(uint32_t id, char *out) {
  snprintf(out, PEER_NAME_LEN, "%s-%s",
           _PR_ADJ[(id >> 4) & 0xF], _PR_NOUN[id & 0xF]);
}

static int64_t _pr_ms() { return esp_timer_get_time() / 1000; }

// ---- peer table ------------------------------------------------------------

static PeerSlot *_pr_find(uint32_t id) {
  for (int i = 0; i < PEER_MAX; i++)
    if (_pr_peers[i].active && _pr_peers[i].device_id == id)
      return &_pr_peers[i];
  return NULL;
}

static PeerSlot *_pr_alloc(uint32_t id) {
  for (int i = 0; i < PEER_MAX; i++) {
    if (!_pr_peers[i].active) {
      memset(&_pr_peers[i], 0, sizeof(PeerSlot));
      _pr_peers[i].active = true;
      _pr_peers[i].device_id = id;
      _pr_mkname(id, _pr_peers[i].name);
      _pr_peers[i].first_seen = _pr_ms();
      _pr_peers[i].last_seen = _pr_ms();
      return &_pr_peers[i];
    }
  }
  return NULL;
}

// ---- frame TX --------------------------------------------------------------

static void _pr_tx_identity() {
  uint8_t f[32];
  f[0] = ESPNOW_MSG_IDENTITY;
  memcpy(f + 1, &_pr.device_id, 4);
  memcpy(f + 5, &_pr.total_encounters, 2);
  uint32_t nonce = (uint32_t)(_pr_ms() & 0xFFFFFFFF);
  memcpy(f + 7, &nonce, 4);
  f[11] = 0x01;
  int nlen = strlen(_pr.name);
  memcpy(f + 12, _pr.name, nlen + 1);
  esp_now_send(ESPNOW_BROADCAST, f, 13 + nlen);
}

static void _pr_tx_challenge(const uint8_t *mac, const int *prompt, int n,
                              uint16_t cid, int n_exp) {
  uint8_t f[64];
  f[0] = ESPNOW_MSG_CHALLENGE;
  memcpy(f + 1, &_pr.device_id, 4);
  memcpy(f + 5, &cid, 2);
  f[7] = (uint8_t)n;
  f[8] = (uint8_t)n_exp;
  for (int i = 0; i < n; i++) {
    uint16_t t = (uint16_t)prompt[i];
    memcpy(f + 9 + i * 2, &t, 2);
  }
  esp_now_send(mac, f, 9 + n * 2);
}

static void _pr_tx_response(const uint8_t *mac, uint16_t cid,
                              const int *tok, int n) {
  uint8_t f[64];
  f[0] = ESPNOW_MSG_RESPONSE;
  memcpy(f + 1, &_pr.device_id, 4);
  memcpy(f + 5, &cid, 2);
  f[7] = (uint8_t)n;
  for (int i = 0; i < n; i++) {
    uint16_t t = (uint16_t)tok[i];
    memcpy(f + 8 + i * 2, &t, 2);
  }
  esp_now_send(mac, f, 8 + n * 2);
}

static void _pr_tx_validate(const uint8_t *mac, uint16_t cid, bool pass) {
  uint8_t f[10];
  f[0] = ESPNOW_MSG_VALIDATE;
  memcpy(f + 1, &_pr.device_id, 4);
  memcpy(f + 5, &cid, 2);
  f[7] = pass ? 1 : 0;
  memcpy(f + 8, &_pr.total_bonds, 2);
  esp_now_send(mac, f, 10);
}

// ---- RX handler (called from espnow_comm.h) --------------------------------

static void _pr_rx(const uint8_t *mac, const uint8_t *d, int len) {
  if (len < 5) return;
  uint8_t type = d[0];
  uint32_t sender;
  memcpy(&sender, d + 1, 4);
  if (sender == _pr.device_id) return;

  switch (type) {
  case ESPNOW_MSG_IDENTITY:
    if (len >= 12) {
      _pri.id = sender;
      memcpy((void *)_pri.mac, mac, 6);
      _pri.pending = true;
    }
    break;

  case ESPNOW_MSG_CHALLENGE:
    if (len >= 9) {
      uint16_t ci; memcpy(&ci, d + 5, 2);
      int n = d[7], ne = d[8];
      if (n > PEER_PROMPT_LEN) n = PEER_PROMPT_LEN;
      if (ne > PEER_RESP_LEN) ne = PEER_RESP_LEN;
      if (len < 9 + n * 2) break;
      _prc.id = sender;
      memcpy((void *)_prc.mac, mac, 6);
      _prc.cid = ci; _prc.n = n; _prc.n_exp = ne;
      for (int i = 0; i < n; i++) {
        uint16_t t; memcpy(&t, d + 9 + i * 2, 2);
        _prc.prompt[i] = (int)t;
      }
      _prc.pending = true;
    }
    break;

  case ESPNOW_MSG_RESPONSE:
    if (len >= 8) {
      uint16_t ci; memcpy(&ci, d + 5, 2);
      int n = d[7];
      if (n > PEER_RESP_LEN) n = PEER_RESP_LEN;
      if (len < 8 + n * 2) break;
      _prr.id = sender; _prr.cid = ci; _prr.n = n;
      for (int i = 0; i < n; i++) {
        uint16_t t; memcpy(&t, d + 8 + i * 2, 2);
        _prr.tokens[i] = (int)t;
      }
      _prr.pending = true;
    }
    break;

  case ESPNOW_MSG_VALIDATE:
    if (len >= 8) {
      uint16_t ci; memcpy(&ci, d + 5, 2);
      _prv.id = sender; _prv.cid = ci;
      _prv.pass = (d[7] != 0);
      _prv.pending = true;
    }
    break;
  }
}

// ---- NVS -------------------------------------------------------------------

static void _pr_save() {
  nvs_set_u16(_pr.nvs, "enc", _pr.total_encounters);
  nvs_set_u16(_pr.nvs, "bnd", _pr.total_bonds);
  nvs_commit(_pr.nvs);
}

// ---- public API ------------------------------------------------------------

static void peer_init(peer_infer_fn_t infer) {
  memset(&_pr, 0, sizeof(_pr));
  memset(_pr_peers, 0, sizeof(_pr_peers));
  memset((void *)&_pri, 0, sizeof(_pri));
  memset((void *)&_prc, 0, sizeof(_prc));
  memset((void *)&_prr, 0, sizeof(_prr));
  memset((void *)&_prv, 0, sizeof(_prv));

  _pr.infer = infer;
  _pr.next_cid = 1;

  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  _pr.device_id = _pr_crc32(mac, 6);
  _pr_mkname(_pr.device_id, _pr.name);

  esp_err_t e = nvs_flash_init();
  if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  if (nvs_open("peer", NVS_READWRITE, &_pr.nvs) == ESP_OK) {
    nvs_get_u16(_pr.nvs, "enc", &_pr.total_encounters);
    nvs_get_u16(_pr.nvs, "bnd", &_pr.total_bonds);
  }

  espnow_register_peer_handler(_pr_rx);

  persona_auto(_pr.device_id);
  _pr.ready = true;
  Serial.printf("\n--- peer protocol ---\n");
  Serial.printf("identity: %s (0x%08X)\n", _pr.name, _pr.device_id);
  Serial.printf("history: %d encounters, %d bonds\n",
                _pr.total_encounters, _pr.total_bonds);
  persona_boot();
  Serial.printf("  %s  scanning for peers...\n\n", persona()->face_scanning);
}

static void peer_tick() {
  if (!_pr.ready) return;
  int64_t now = _pr_ms();

  // 1. Beacon.
  if (now - _pr.last_beacon >= PEER_BEACON_MS) {
    _pr_tx_identity();
    _pr.last_beacon = now;
  }

  // 2. Process identity beacon.
  if (_pri.pending) {
    uint32_t id = _pri.id;
    PeerSlot *p = _pr_find(id);
    if (!p) {
      p = _pr_alloc(id);
      if (p) {
        memcpy(p->mac, (void *)_pri.mac, 6);
        esp_now_peer_info_t pi = {};
        memcpy(pi.peer_addr, p->mac, 6);
        pi.channel = 0;
        pi.encrypt = false;
        esp_now_add_peer(&pi);
        _pr.total_encounters++;
        _pr_save();
        Serial.printf("  %s\n", persona()->face_found);
        Serial.printf("[!] discovered: %s (0x%08X)\n",
                      p->name, p->device_id);
        Serial.printf("    %s\n", persona()->quip_discover);
#if USE_SD
        sd_log_encounter(_pr.name, p->name, p->device_id, "DISCOVERED");
        sd_record_peer(p->name, p->device_id);
#endif
      }
    }
    if (p) p->last_seen = now;
    _pri.pending = false;
  }

  // 3. Initiate challenge (one per tick to bound latency).
  for (int i = 0; i < PEER_MAX; i++) {
    PeerSlot *p = &_pr_peers[i];
    if (!p->active || p->challenge_sent || p->i_validated) continue;
    if (now - p->first_seen < PEER_CHALLENGE_DELAY) continue;

    uint32_t h = _pr.device_id ^ p->device_id;

    // Prefer SD-loaded challenges when available, fall back to compiled-in bank.
    const int *prompt = NULL;
    int prompt_len = PEER_PROMPT_LEN;
#if USE_SD
    int n_sd = sd_challenge_count();
    if (n_sd > 0) {
      int idx = (_pr.device_id < p->device_id)
          ? (int)(h % n_sd)
          : (int)((h + 1) % n_sd);
      prompt = sd_challenge(idx, &prompt_len);
      if (prompt_len > PEER_PROMPT_LEN) prompt_len = PEER_PROMPT_LEN;
    }
#endif
    if (!prompt) {
      int idx = (_pr.device_id < p->device_id)
          ? (int)(h % N_CHAL_BANK)
          : (int)((h + 1) % N_CHAL_BANK);
      prompt = CHALLENGE_BANK[idx];
      prompt_len = PEER_PROMPT_LEN;
    }

    Serial.printf("[>] challenging %s...  %s\n",
                  p->name, persona()->quip_challenge);
    p->n_expected = _pr.infer(prompt, prompt_len,
                               PEER_RESP_LEN, p->expected);
    p->challenge_id = _pr.next_cid++;
    _pr_tx_challenge(p->mac, prompt, prompt_len,
                      p->challenge_id, PEER_RESP_LEN);
    p->challenge_sent = true;
    p->challenge_time = now;
    break;
  }

  // 4. Handle incoming challenge.
  if (_prc.pending) {
    PeerSlot *p = _pr_find(_prc.id);
    if (p) {
      Serial.printf("[<] challenge from %s, running inference...\n", p->name);
      int prompt[PEER_PROMPT_LEN];
      for (int i = 0; i < _prc.n; i++) prompt[i] = _prc.prompt[i];
      int np = _prc.n, ne = _prc.n_exp;
      uint16_t ci = _prc.cid;

      int resp[PEER_RESP_LEN];
      int nr = _pr.infer(prompt, np, ne, resp);
      _pr_tx_response(p->mac, ci, resp, nr);
      Serial.printf("[>] sent %d-token response to %s\n", nr, p->name);
    }
    _prc.pending = false;
  }

  // 5. Handle incoming response.
  if (_prr.pending) {
    PeerSlot *p = _pr_find(_prr.id);
    if (p && p->challenge_sent && _prr.cid == p->challenge_id) {
      int match = 0;
      int n = _prr.n < p->n_expected ? _prr.n : p->n_expected;
      for (int i = 0; i < n; i++)
        if (_prr.tokens[i] == p->expected[i]) match++;

      bool pass = (match == n && n > 0);
      _pr_tx_validate(p->mac, p->challenge_id, pass);

      if (pass) {
        p->i_validated = true;
        Serial.printf("  %s  %s\n", persona()->face_found,
                      persona()->quip_verified);
        Serial.printf("[*] %s VERIFIED (%d/%d tokens match)\n",
                      p->name, match, n);
        if (p->they_validated && !p->bonded) {
          p->bonded = true;
          p->bond_count++;
          _pr.total_bonds++;
          _pr_save();
          Serial.printf("  %s  %s\n", persona()->face_bonded,
                        persona()->quip_bonded);
          Serial.printf("[**] BONDED with %s! (bond #%d)\n",
                        p->name, _pr.total_bonds);
#if USE_SD
          sd_log_bond(_pr.name, p->name, p->device_id, _pr.total_bonds);
#endif
        }
      } else {
        Serial.printf("  %s  %s\n", persona()->face_rejected,
                      persona()->quip_failed);
        Serial.printf("[x] %s FAILED validation (%d/%d match)\n",
                      p->name, match, n);
      }
    }
    _prr.pending = false;
  }

  // 6. Handle incoming validation.
  if (_prv.pending) {
    PeerSlot *p = _pr_find(_prv.id);
    if (p && _prv.pass) {
      p->they_validated = true;
      Serial.printf("[*] %s validated us\n", p->name);
      if (p->i_validated && !p->bonded) {
        p->bonded = true;
        p->bond_count++;
        _pr.total_bonds++;
        _pr_save();
        Serial.printf("  %s  %s\n", persona()->face_bonded,
                      persona()->quip_bonded);
        Serial.printf("[**] BONDED with %s! (bond #%d)\n",
                      p->name, _pr.total_bonds);
#if USE_SD
        sd_log_bond(_pr.name, p->name, p->device_id, _pr.total_bonds);
#endif
      }
    } else if (p) {
      Serial.printf("  %s  %s\n", persona()->face_rejected,
                    persona()->quip_failed);
      Serial.printf("[x] %s rejected our response\n", p->name);
    }
    _prv.pending = false;
  }

  // 7. Challenge timeout -> retry.
  for (int i = 0; i < PEER_MAX; i++) {
    PeerSlot *p = &_pr_peers[i];
    if (!p->active || !p->challenge_sent || p->i_validated) continue;
    if (now - p->challenge_time > PEER_CHALLENGE_TIMEOUT) {
      Serial.printf("[?] challenge to %s timed out, retrying  %s\n",
                    p->name, persona()->quip_timeout);
      p->challenge_sent = false;
    }
  }

  // 8. Periodic status line.
  if (now - _pr.last_status >= PEER_STATUS_MS) {
    int na = 0, nb = 0;
    for (int i = 0; i < PEER_MAX; i++) {
      if (!_pr_peers[i].active) continue;
      na++;
      if (_pr_peers[i].bonded) nb++;
    }
    if (na > 0)
      Serial.printf("--- %s %s | peers: %d | bonded: %d | lifetime: %d ---\n",
                    persona()->face_idle, _pr.name, na, nb, _pr.total_bonds);
    else
      Serial.printf("--- %s %s  %s ---\n",
                    persona()->face_scanning, _pr.name,
                    persona()->quip_lonely);
    _pr.last_status = now;
  }
}

static void peer_print_status() {
  Serial.printf("\n=== %s  %s (0x%08X) ===\n",
                persona()->face_idle, _pr.name, _pr.device_id);
  Serial.printf("persona: %s \"%s\"\n", persona()->name, persona()->title);
  Serial.printf("encounters: %d  bonds: %d\n\n",
                _pr.total_encounters, _pr.total_bonds);
  bool any = false;
  for (int i = 0; i < PEER_MAX; i++) {
    PeerSlot *p = &_pr_peers[i];
    if (!p->active) continue;
    any = true;
    const char *st = "discovered";
    if (p->bonded) st = "BONDED";
    else if (p->i_validated) st = "I verified them";
    else if (p->they_validated) st = "they verified us";
    else if (p->challenge_sent) st = "challenging";
    int age = (_pr_ms() - p->last_seen) / 1000;
    Serial.printf("  %-16s 0x%08X  [%-18s]  %ds ago\n",
                  p->name, p->device_id, st, age);
  }
  if (!any) Serial.println("  (no peers)");
  Serial.println();
}

#endif
