// Companion app UART protocol for the ESP32-P4.
//
// Provides a JSON-over-UART interface for phone/dashboard monitoring.
// The P4 has no built-in BLE — the companion C6 handles wireless, but a
// direct UART/USB-CDC link to a host (phone via OTG, laptop, Raspberry Pi)
// is simpler for MVP and doesn't require the C6 to be present.
//
// Protocol:
//   - Each message is a single JSON line terminated by '\n'.
//   - TX (device -> host): status updates, events, inference output.
//   - RX (host -> device): commands (prompt, config, query).
//   - Uses Serial1 (UART1) to avoid conflicts with the debug console.
//   - Default: TX=GPIO17, RX=GPIO18, 115200 baud.
//
// Message types (TX):
//   {"t":"status","name":"...","persona":"...","peers":N,"bonded":N,...}
//   {"t":"token","text":"..."}
//   {"t":"event","event":"discovered","peer":"...","id":"0x..."}
//   {"t":"stats","tok_s":12.3,"ms_tok":81.2,"psram_free":12345}
//   {"t":"peer","name":"...","id":"0x...","state":"bonded","age":123}
//
// Message types (RX):
//   {"c":"prompt","text":"Once upon a time"}
//   {"c":"status"}
//   {"c":"generate","n":100}
//   {"c":"identity","idx":3}
//   {"c":"peers"}
//
// The RX parser is non-blocking and accumulates bytes until '\n'.

#ifndef COMPANION_UART_H
#define COMPANION_UART_H

#include <Arduino.h>
#include <string.h>

#ifndef COMPANION_TX_PIN
#define COMPANION_TX_PIN 17
#endif
#ifndef COMPANION_RX_PIN
#define COMPANION_RX_PIN 18
#endif
#ifndef COMPANION_BAUD
#define COMPANION_BAUD   115200
#endif

#define COMP_BUF_SIZE    512
#define COMP_CMD_MAX     256

// Callback types for host commands.
typedef void (*comp_status_cb_t)();
typedef void (*comp_prompt_cb_t)(const char *text);
typedef void (*comp_generate_cb_t)(int n_tokens);
typedef void (*comp_identity_cb_t)(int idx);
typedef void (*comp_peers_cb_t)();

static struct {
  bool ready;
  char rx_buf[COMP_CMD_MAX];
  int rx_len;
  comp_status_cb_t on_status;
  comp_prompt_cb_t on_prompt;
  comp_generate_cb_t on_generate;
  comp_identity_cb_t on_identity;
  comp_peers_cb_t on_peers;
} _comp;

// Minimal JSON string escape (for safe output).
static void _comp_esc(char *dst, int max, const char *src) {
  int i = 0;
  while (*src && i < max - 2) {
    if (*src == '"' || *src == '\\') { dst[i++] = '\\'; }
    if (*src == '\n') { dst[i++] = '\\'; dst[i++] = 'n'; src++; continue; }
    if (*src == '\r') { dst[i++] = '\\'; dst[i++] = 'r'; src++; continue; }
    dst[i++] = *src++;
  }
  dst[i] = '\0';
}

// ---- TX helpers (device -> host) -------------------------------------------

static void companion_send_status(const char *name, const char *persona_name,
                                    int n_peers, int n_bonded,
                                    int encounters, int bonds) {
  if (!_comp.ready) return;
  char esc_name[64], esc_persona[64];
  _comp_esc(esc_name, sizeof(esc_name), name);
  _comp_esc(esc_persona, sizeof(esc_persona), persona_name);
  char buf[COMP_BUF_SIZE];
  snprintf(buf, sizeof(buf),
    "{\"t\":\"status\",\"name\":\"%s\",\"persona\":\"%s\","
    "\"peers\":%d,\"bonded\":%d,\"encounters\":%d,\"bonds\":%d}\n",
    esc_name, esc_persona, n_peers, n_bonded, encounters, bonds);
  Serial1.print(buf);
}

static void companion_send_token(const unsigned char *bytes, int len) {
  if (!_comp.ready || len <= 0) return;
  char esc[128];
  char tmp[64];
  int n = len < 60 ? len : 60;
  memcpy(tmp, bytes, n);
  tmp[n] = '\0';
  _comp_esc(esc, sizeof(esc), tmp);
  char buf[COMP_BUF_SIZE];
  snprintf(buf, sizeof(buf), "{\"t\":\"token\",\"text\":\"%s\"}\n", esc);
  Serial1.print(buf);
}

static void companion_send_event(const char *event, const char *peer_name,
                                   uint32_t peer_id) {
  if (!_comp.ready) return;
  char esc_event[64], esc_peer[64];
  _comp_esc(esc_event, sizeof(esc_event), event);
  _comp_esc(esc_peer, sizeof(esc_peer), peer_name);
  char buf[COMP_BUF_SIZE];
  snprintf(buf, sizeof(buf),
    "{\"t\":\"event\",\"event\":\"%s\",\"peer\":\"%s\",\"id\":\"0x%08X\"}\n",
    esc_event, esc_peer, peer_id);
  Serial1.print(buf);
}

static void companion_send_stats(float tok_s, float ms_tok,
                                   uint32_t psram_free) {
  if (!_comp.ready) return;
  char buf[COMP_BUF_SIZE];
  snprintf(buf, sizeof(buf),
    "{\"t\":\"stats\",\"tok_s\":%.2f,\"ms_tok\":%.1f,\"psram_free\":%u}\n",
    tok_s, ms_tok, psram_free);
  Serial1.print(buf);
}

static void companion_send_peer(const char *name, uint32_t id,
                                  const char *state, int age_sec) {
  if (!_comp.ready) return;
  char esc_name[64], esc_state[32];
  _comp_esc(esc_name, sizeof(esc_name), name);
  _comp_esc(esc_state, sizeof(esc_state), state);
  char buf[COMP_BUF_SIZE];
  snprintf(buf, sizeof(buf),
    "{\"t\":\"peer\",\"name\":\"%s\",\"id\":\"0x%08X\","
    "\"state\":\"%s\",\"age\":%d}\n",
    esc_name, id, esc_state, age_sec);
  Serial1.print(buf);
}

// ---- RX parser (host -> device) --------------------------------------------

// Minimal JSON key extractor — finds "key":"value" or "key":number.
static bool _comp_json_str(const char *json, const char *key,
                             char *out, int max) {
  char needle[64];
  snprintf(needle, sizeof(needle), "\"%s\":\"", key);
  const char *p = strstr(json, needle);
  if (!p) return false;
  p += strlen(needle);
  int i = 0;
  while (*p && *p != '"' && i < max - 1) out[i++] = *p++;
  out[i] = '\0';
  return true;
}

static bool _comp_json_int(const char *json, const char *key, int *out) {
  char needle[64];
  snprintf(needle, sizeof(needle), "\"%s\":", key);
  const char *p = strstr(json, needle);
  if (!p) return false;
  p += strlen(needle);
  while (*p == ' ') p++;
  *out = atoi(p);
  return true;
}

static void _comp_process_cmd(const char *line) {
  char cmd[16];
  if (!_comp_json_str(line, "c", cmd, sizeof(cmd))) return;

  if (strcmp(cmd, "status") == 0) {
    if (_comp.on_status) _comp.on_status();
  } else if (strcmp(cmd, "prompt") == 0) {
    char text[128];
    if (_comp_json_str(line, "text", text, sizeof(text)) && _comp.on_prompt)
      _comp.on_prompt(text);
  } else if (strcmp(cmd, "generate") == 0) {
    int n = 100;
    _comp_json_int(line, "n", &n);
    if (_comp.on_generate) _comp.on_generate(n);
  } else if (strcmp(cmd, "identity") == 0) {
    int idx = 0;
    if (_comp_json_int(line, "idx", &idx) && _comp.on_identity)
      _comp.on_identity(idx);
  } else if (strcmp(cmd, "peers") == 0) {
    if (_comp.on_peers) _comp.on_peers();
  }
}

// ---- public API ------------------------------------------------------------

static bool companion_begin() {
  memset(&_comp, 0, sizeof(_comp));
  Serial1.begin(COMPANION_BAUD, SERIAL_8N1, COMPANION_RX_PIN, COMPANION_TX_PIN);
  _comp.ready = true;
  Serial.printf("[companion] UART1 ready (TX=%d, RX=%d, %d baud)\n",
                COMPANION_TX_PIN, COMPANION_RX_PIN, COMPANION_BAUD);
  Serial1.println("{\"t\":\"boot\",\"fw\":\"ple-tinylm-p4\"}");
  return true;
}

// Call from loop() — non-blocking, accumulates bytes until newline.
static void companion_tick() {
  if (!_comp.ready) return;
  while (Serial1.available()) {
    char c = Serial1.read();
    if (c == '\n') {
      _comp.rx_buf[_comp.rx_len] = '\0';
      if (_comp.rx_len > 2) _comp_process_cmd(_comp.rx_buf);
      _comp.rx_len = 0;
    } else if (_comp.rx_len < COMP_CMD_MAX - 1) {
      _comp.rx_buf[_comp.rx_len++] = c;
    }
  }
}

// Register command callbacks.
static void companion_on_status(comp_status_cb_t cb) { _comp.on_status = cb; }
static void companion_on_prompt(comp_prompt_cb_t cb) { _comp.on_prompt = cb; }
static void companion_on_generate(comp_generate_cb_t cb) { _comp.on_generate = cb; }
static void companion_on_identity(comp_identity_cb_t cb) { _comp.on_identity = cb; }
static void companion_on_peers(comp_peers_cb_t cb) { _comp.on_peers = cb; }

#endif
