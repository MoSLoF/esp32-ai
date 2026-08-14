// PLE TinyLM inference on the ESP32-P4.
// The 28.9M-param model (14.9MB, 4-bit) lives in a flash 'model' partition,
// memory-mapped so the 25M table is read a row at a time from flash; the hot
// tied head plus scratch and KV cache sit in PSRAM. Same llm.h that was verified
// against PyTorch on the host -- only the platform hooks differ here.
//
// P4 vs S3 differences:
//   - Dual RISC-V HP cores at 400 MHz (vs Xtensa LX7 at 240 MHz)
//   - 32 MB PSRAM (vs 8 MB), ~200 MB/s bandwidth (vs 60 MB/s OPI)
//   - 32 MB flash (vs 16 MB)
//   - 768 KB SRAM (vs 512 KB)
//   - No built-in WiFi/BLE (companion C6 via SDIO)

#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "pin_map.h"
#define LLM_PROFILE 1
#define LLM_PROFILE_NOW() esp_timer_get_time()
#include "../common/llm.h"
#include "../esp32_llm/vocab.h"   // shared tokenizer assets

// ---- feature flags ---------------------------------------------------------
#define USE_DISPLAY       0   // MIPI-DSI panel (display.h)
#define USE_ESPNOW        0   // ESP-NOW transport (espnow_comm.h)
#define USE_PEER_PROTOCOL 0   // peer discovery + validation (peer_protocol.h)
#define USE_OTA           0   // OTA updates over ESP-NOW (ota_espnow.h)
#define USE_SD            0   // SD card config/logging (sd_config.h)
#define USE_MESH          0   // multi-hop relay (mesh_relay.h)
#define USE_CRYPTO        0   // HMAC frame signing (crypto_peer.h)
#define USE_COMPANION     0   // UART JSON companion app (companion_uart.h)

// FR-01: OTA requires crypto — fail at compile time if misconfigured.
#if USE_OTA && !USE_CRYPTO
#error "USE_OTA requires USE_CRYPTO — firmware signing is mandatory"
#endif

// Auto-enable ESP-NOW when features that need it are on.
#if (USE_PEER_PROTOCOL || USE_OTA || USE_MESH) && !USE_ESPNOW
#undef USE_ESPNOW
#define USE_ESPNOW 1
#endif

// ---- conditional includes --------------------------------------------------
#if USE_DISPLAY
#include "display.h"
#endif
#if USE_ESPNOW
#include "espnow_comm.h"
#endif
#if USE_PEER_PROTOCOL
#include "peer_protocol.h"
#endif
// FR-01: ota_verify.h always included with OTA (crypto is mandatory).
#if USE_OTA
#include "ota_verify.h"
#include "ota_espnow.h"
#endif
#if USE_SD
#include "sd_config.h"
#endif
#if USE_MESH
#include "mesh_relay.h"
#endif
#if USE_CRYPTO
#include "crypto_peer.h"
#endif
#if USE_COMPANION
#include "companion_uart.h"
#endif

static const int PROMPT_IDS[] = {433, 447, 259, 405}; // "Once upon a time"
static const int N_GENERATE = 200;

// Current inference position (persists across generate calls).
static int _gen_pos = 0;

// Emit one token to every active output (serial always; display when enabled).
static void emit(int tok) {
  if (tok >= VOCAB_N) return;
  const unsigned char *bytes = VOCAB_BLOB + VOCAB_OFF[tok];
  int len = VOCAB_OFF[tok + 1] - VOCAB_OFF[tok];
  if ((int)Serial.availableForWrite() >= len) Serial.write(bytes, len);
#if USE_DISPLAY
  display_puts(bytes, len);
#endif
#if USE_ESPNOW
  espnow_send_token(tok);
#endif
#if USE_COMPANION
  companion_send_token(bytes, len);
#endif
}

Model model;
Scratch s;

// ---- inference helpers (shared by boot, generate command, peer protocol) ----

static void run_generate(const int *prompt_ids, int n_prompt, int n_gen) {
  _gen_pos = 0;
  int tok = 0;
  int64_t decode_us = 0;
  int decoded = 0;

  Serial.print(">>> ");
  for (int i = 0; i < n_prompt; i++) {
    tok = prompt_ids[i];
    emit(tok);
    llm_forward(&model, tok, _gen_pos++, &s);
  }

  llm_profile_reset(&s);
  int64_t t_start = esp_timer_get_time();

  for (int step = 0; step < n_gen && _gen_pos < model.c.seq_len; step++) {
    int best = 0; float bv = -1e30f;
    for (int v = 0; v < VOCAB_N; v++)
      if (s.logits[v] > bv) { bv = s.logits[v]; best = v; }
    tok = best;
    emit(tok);

    int64_t d0 = esp_timer_get_time();
    llm_forward(&model, tok, _gen_pos++, &s);
    decode_us += esp_timer_get_time() - d0;
    decoded++;
    if ((step & 7) == 0) delay(0);
  }
  int64_t total_us = esp_timer_get_time() - t_start;

  if (decoded > 0) {
    float tok_s = decoded * 1e6f / total_us;
    float ms_tok = decode_us / 1000.0f / decoded;
    Serial.printf("\n\n--- %d tokens in %.2f s ---\n", decoded, total_us / 1e6);
    Serial.printf("throughput: %.2f tok/s   (%.1f ms/token)\n", tok_s, ms_tok);
    if (s.profile.calls) {
      float n = (float)s.profile.calls * 1000.f;
      Serial.printf("profile ms/token: input %.1f | attn %.1f | ffn %.1f | ple %.1f | head %.1f\n",
                    s.profile.input_us / n, s.profile.attn_us / n,
                    s.profile.ffn_us / n, s.profile.ple_us / n,
                    s.profile.head_us / n);
    }
#if USE_DISPLAY
    display_stats(tok_s, ms_tok);
#endif
#if USE_COMPANION
    companion_send_stats(tok_s, ms_tok,
                         heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
#endif
  }
}

#if USE_PEER_PROTOCOL
static int peer_infer(const int *prompt, int n_prompt, int n_gen, int *out) {
  int pos = 0;
  for (int i = 0; i < n_prompt; i++)
    llm_forward(&model, prompt[i], pos++, &s);
  int generated = 0;
  for (int step = 0; step < n_gen && pos < model.c.seq_len; step++) {
    int best = 0; float bv = -1e30f;
    for (int v = 0; v < VOCAB_N; v++)
      if (s.logits[v] > bv) { bv = s.logits[v]; best = v; }
    out[generated++] = best;
    llm_forward(&model, best, pos++, &s);
  }
  return generated;
}
#endif

// ---- int8 output head (dual-core) ------------------------------------------
static int8_t *head_w8 = NULL;
static float  *head_scale8 = NULL;
static int head_rows, head_cols;

static int8_t head_actq[128];
static float  head_acts;

static inline int32_t dot_i8(const int8_t *a, const int8_t *b, int n) {
  int32_t acc = 0;
  for (int i = 0; i < n; i++) acc += (int32_t)a[i] * (int32_t)b[i];
  return acc;
}

static void head_rows_range(float *y, int r0, int r1) {
  for (int r = r0; r < r1; r++)
    y[r] = (float)dot_i8(head_actq, head_w8 + (size_t)r * head_cols, head_cols)
           * head_scale8[r] * head_acts;
}

static TaskHandle_t head_worker;
static TaskHandle_t inference_task;
static float *volatile head_job_y;
static volatile int head_job_split;

static void head_worker_main(void *) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    head_rows_range(head_job_y, 0, head_job_split);
    xTaskNotifyGive(inference_task);
  }
}

static void head_matvec_int8(const QT *t, const float *x, float *y) {
  (void)t;
  quantize_act(x, head_cols, head_actq, &head_acts);
  head_job_y = y;
  head_job_split = head_rows / 2;
  xTaskNotifyGive(head_worker);
  head_rows_range(y, head_job_split, head_rows);
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}

// R2-07: aggregate PSRAM allocation cap prevents runaway allocations.
#define PSRAM_ALLOC_CAP (24 * 1024 * 1024)  // 24 MB hard limit
static size_t _ps_total = 0;
// R3-06: setup_ok flag — guards inference calls after allocation failure.
static bool _setup_ok = false;

static void *ps(size_t n) {
  if (n > PSRAM_ALLOC_CAP || _ps_total + n > PSRAM_ALLOC_CAP) {
    Serial.printf("PSRAM cap exceeded (%u + %u > %u)\n",
                  (unsigned)_ps_total, (unsigned)n, (unsigned)PSRAM_ALLOC_CAP);
    return NULL;
  }
  void *p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
  if (!p) { Serial.printf("PSRAM alloc failed (%u bytes)\n", (unsigned)n); return NULL; }
  _ps_total += n;
  return p;
}

// R3-06: preflight check — verify KV cache sizes won't overflow 32-bit arithmetic.
static bool _psram_preflight(Cfg *c) {
  size_t kv_size;
  size_t ls = (size_t)c->n_layers * (size_t)c->seq_len;
  size_t lsd;
  if (_llm_mul_overflow(ls, (size_t)c->dim, &lsd)) return false;
  if (_llm_mul_overflow(lsd, 4, &kv_size)) return false;
  if (kv_size > PSRAM_ALLOC_CAP) return false;
  // Two KV caches + scratch must fit.
  if (kv_size > PSRAM_ALLOC_CAP / 2) return false;
  return true;
}

static void stage_head_int8(QT *t) {
  head_rows = t->rows; head_cols = t->cols;
  head_w8 = (int8_t *)ps((size_t)head_rows * head_cols);
  head_scale8 = (float *)ps((size_t)head_rows * sizeof(float));
  for (int r = 0; r < head_rows; r++) {
    const uint8_t *row = t->codes + (size_t)r * t->row_bytes;
    int8_t *dst = head_w8 + (size_t)r * head_cols;
    for (int j = 0; j < head_cols; j++) {
      uint8_t byte = row[j >> 1];
      int code = (j & 1) ? (byte >> 4) : (byte & 0xF);
      dst[j] = (int8_t)(code - 8);
    }
    head_scale8[r] = half2float(t->scales[(size_t)r * t->n_groups]);
  }
  Serial.printf("head staged int8: %.2f MB\n",
                ((size_t)head_rows * head_cols + (size_t)head_rows * 4) / 1e6);
}

// ---- companion app callbacks -----------------------------------------------
#if USE_COMPANION

static void _comp_cb_status() {
#if USE_PEER_PROTOCOL
  int np = 0, nb = 0;
  for (int i = 0; i < PEER_MAX; i++) {
    if (!_pr_peers[i].active) continue;
    np++;
    if (_pr_peers[i].bonded) nb++;
  }
  companion_send_status(_pr.name, persona()->name, np, nb,
                         _pr.total_encounters, _pr.total_bonds);
#else
  companion_send_status("p4-device", "none", 0, 0, 0, 0);
#endif
}

static void _comp_cb_generate(int n) {
  if (!_setup_ok) return;
  run_generate(PROMPT_IDS, sizeof(PROMPT_IDS) / sizeof(int), n);
}

static void _comp_cb_identity(int idx) {
#if USE_PEER_PROTOCOL
  persona_select(idx);
  persona_boot();
#else
  (void)idx;
#endif
}

static void _comp_cb_peers() {
#if USE_PEER_PROTOCOL
  for (int i = 0; i < PEER_MAX; i++) {
    PeerSlot *p = &_pr_peers[i];
    if (!p->active) continue;
    const char *st = "discovered";
    if (p->bonded) st = "bonded";
    else if (p->i_validated) st = "verified";
    else if (p->challenge_sent) st = "challenging";
    int age = (int)((_pr_ms() - p->last_seen) / 1000);
    companion_send_peer(p->name, p->device_id, st, age);
  }
#endif
}

#endif // USE_COMPANION

// ---- setup -----------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println("\n=== ESP32-P4 PLE TinyLM ===");

#if USE_COMPANION
  companion_begin();
#endif
#if USE_SD
  sd_begin();
#endif

  // Map the model partition.
  const esp_partition_t *part = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40, "model");
  if (!part) { Serial.println("model partition not found"); return; }
  const void *base;
  esp_partition_mmap_handle_t h;
  esp_err_t err = esp_partition_mmap(part, 0, part->size,
                                     ESP_PARTITION_MMAP_DATA, &base, &h);
  if (err != ESP_OK) { Serial.printf("mmap failed: %d\n", err); return; }

  if (llm_load((const uint8_t *)base, part->size, &model)) { Serial.println("bad model"); return; }
  Cfg *c = &model.c;
  Serial.printf("model: V=%d D=%d L=%d H=%d F=%d P=%d  (mapped %.1f MB)\n",
                c->vocab, c->dim, c->n_layers, c->n_heads, c->ffn, c->ple_dim,
                part->size / 1e6);

#if USE_DISPLAY
  display_begin();
#endif
#if USE_CRYPTO
  // R2-04: initialize crypto BEFORE espnow_begin so the RX callback
  // never processes frames under an unprovisioned key.
  crypto_init();
  // R2-04: load SD-based PSK before enabling ESP-NOW callbacks.
#if USE_SD
  {
    char psk_buf[64];
    int psk_n = sd_read_file(SD_CFG "/psk.txt", psk_buf, sizeof(psk_buf));
    if (psk_n > 0) {
      while (psk_n > 0 && (psk_buf[psk_n-1] == '\n' || psk_buf[psk_n-1] == '\r'))
        psk_buf[--psk_n] = '\0';
      if (psk_n >= 16) {
        crypto_set_psk(psk_buf);
        Serial.println("[crypto] PSK loaded from SD");
      }
    }
  }
#endif
#endif
#if USE_ESPNOW
  // R3-02: install crypto hooks BEFORE espnow_begin so the RX callback
  // never processes frames without authentication.
#if USE_CRYPTO
  espnow_set_crypto(crypto_sign, crypto_verify);
#endif
  if (!espnow_begin()) Serial.println("ESP-NOW init failed (continuing without)");
#endif

  // Cap head rows to the trained vocab BEFORE staging.
  model.tok_emb.rows = VOCAB_N;
  stage_head_int8(&model.tok_emb);
  inference_task = xTaskGetCurrentTaskHandle();
  if (xTaskCreatePinnedToCore(head_worker_main, "head", 8192, NULL, 2,
                             &head_worker, 0) != pdPASS) {
    Serial.println("head worker creation failed");
    return;
  }
  model.head_matvec = head_matvec_int8;

  // R3-06: preflight overflow check before any allocation.
  if (!_psram_preflight(c)) {
    Serial.println("PSRAM preflight failed: model dimensions overflow 32-bit");
    return;
  }

  int D = c->dim, L = c->n_layers, P = c->ple_dim, F = c->ffn, V = c->vocab, S = c->seq_len;
  s.x = (float *)ps(D * 4);
  s.h = (float *)ps((F > D ? F : D) * 4);
  s.qkv = (float *)ps(3 * D * 4);
  s.att = (float *)ps(D * 4);
  s.g1 = (float *)ps(F * 4);
  s.g2 = (float *)ps((P > F ? P : F) * 4);
  s.ple = (float *)ps(L * P * 4);
  s.tmpP = (float *)ps(L * P * 4);
  s.trow = (float *)ps(L * P * 4);
  s.logits = (float *)ps(V * 4);
  s.scores = (float *)ps(S * 4);
  s.kcache = (float *)ps((size_t)L * S * D * 4);
  s.vcache = (float *)ps((size_t)L * S * D * 4);
  if (!s.x || !s.h || !s.qkv || !s.att || !s.g1 || !s.g2 ||
      !s.ple || !s.tmpP || !s.trow || !s.logits || !s.scores ||
      !s.kcache || !s.vcache) {
    Serial.println("PSRAM allocation failed — inference disabled");
    return;
  }
  Serial.printf("PSRAM free after alloc: %u KB\n\n",
                heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024);

  _setup_ok = true;

  // ---- initial generation ----
  if (_setup_ok) {
    int prompt_buf[128];
    int n_prompt = sizeof(PROMPT_IDS) / sizeof(int);
    const int *prompt_ids = PROMPT_IDS;
#if USE_ESPNOW
    Serial.println("waiting for ESP-NOW prompt (or using default in 5s)...");
    for (int w = 0; w < 50 && !_espnow_prompt_ready; w++) delay(100);
    int espnow_n = espnow_poll_prompt(prompt_buf, 128);
    if (espnow_n > 0) {
      prompt_ids = prompt_buf;
      n_prompt = espnow_n;
      Serial.printf("received %d-token prompt via ESP-NOW\n", n_prompt);
    }
#endif
    run_generate(prompt_ids, n_prompt, N_GENERATE);
  }

#if USE_PEER_PROTOCOL
  peer_init(peer_infer);
#endif
#if USE_MESH
  mesh_init(
#if USE_PEER_PROTOCOL
    _pr.device_id
#else
    0
#endif
  );
  espnow_register_peer_handler(_mesh_espnow_handler);
#endif
#if USE_SD && USE_PEER_PROTOCOL
  sd_setup(_pr.device_id, _pr.name, _persona_idx);
  sd_load_name(_pr.name, PEER_NAME_LEN);
#elif USE_SD
  {
    uint8_t _mac[6]; esp_read_mac(_mac, ESP_MAC_WIFI_STA);
    uint32_t _did = 0; for (int i=0;i<6;i++) { _did ^= _mac[i]; _did = (_did>>1)^(0xEDB88320&-(_did&1)); }
    sd_setup(_did, "p4-device", 0);
  }
#endif
// FR-04: ensure NVS is initialized even when peer_protocol is disabled.
#if USE_OTA && !USE_PEER_PROTOCOL
  {
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      nvs_flash_erase();
      nvs_err = nvs_flash_init();
    }
    if (nvs_err != ESP_OK)
      Serial.printf("[nvs] init failed: %d\n", nvs_err);
  }
#endif
#if USE_OTA
  ota_verify_init();
  ota_init();
#endif
#if USE_DISPLAY && USE_PEER_PROTOCOL
  display_persona(persona()->face_idle, _pr.name, persona()->quip_boot);
#elif USE_DISPLAY
  display_persona("[-]", "p4-device", "ready");
#endif
// S10: NVS firmware version key for future migration paths.
#if USE_PEER_PROTOCOL
  {
    #define NVS_FW_VERSION 1
    uint8_t stored_ver = 0;
    nvs_get_u8(_pr.nvs, "fwver", &stored_ver);
    if (stored_ver < NVS_FW_VERSION) {
      Serial.printf("[nvs] schema v%d -> v%d\n", stored_ver, NVS_FW_VERSION);
      nvs_set_u8(_pr.nvs, "fwver", NVS_FW_VERSION);
      nvs_commit(_pr.nvs);
    }
  }
#endif
// S12: PSK loaded from SD before ESP-NOW init (R2-04 boot ordering).
// B5: Wire mesh relay into ESP-NOW broadcast path.
#if USE_MESH
  espnow_set_relay(mesh_send);
#endif
// S5: Wire peer events to companion app.
#if USE_COMPANION && USE_PEER_PROTOCOL
  peer_on_event([](const char *event, const char *name, uint32_t id) {
    companion_send_event(event, name, id);
  });
#endif
// S8: Register companion prompt callback.
#if USE_COMPANION
  companion_on_status(_comp_cb_status);
  companion_on_generate(_comp_cb_generate);
  companion_on_identity(_comp_cb_identity);
  companion_on_peers(_comp_cb_peers);
  companion_on_prompt([](const char *text) {
    Serial.printf("[companion] prompt: %s\n", text);
    if (_setup_ok)
      run_generate(PROMPT_IDS, sizeof(PROMPT_IDS) / sizeof(int), N_GENERATE);
    else
      Serial.println("inference disabled (setup failed)");
  });
#endif
}

// ---- loop ------------------------------------------------------------------

void loop() {
#if USE_PEER_PROTOCOL || USE_OTA || USE_SD || USE_COMPANION
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
#if USE_PEER_PROTOCOL
    if (cmd == "status" || cmd == "peers") peer_print_status();
    else if (cmd == "identity") persona_print_roster();
    else if (cmd.startsWith("identity ")) {
      int idx = cmd.substring(9).toInt();
      persona_select(idx);
      persona_boot();
    } else
#endif
#if USE_SD
    if (cmd == "ls") sd_list_dir(SD_MOUNT_POINT);
    else if (cmd == "ls config") sd_list_dir(SD_CFG);
    else if (cmd == "ls log") sd_list_dir(SD_LOG);
    else if (cmd == "log") sd_dump_log();
#if USE_PEER_PROTOCOL
    else if (cmd == "stats") {
      sd_save_stats(_pr.name, _pr.device_id,
                    _pr.total_encounters, _pr.total_bonds);
      Serial.println("[sd] stats saved");
    }
    else if (cmd == "provision") {
      sd_provision(_pr.device_id, _pr.name, _persona_idx);
    }
#endif
    else if (cmd.startsWith("cat ")) {
      String sub = cmd.substring(4);
      if (sub.indexOf("..") >= 0) {
        Serial.println("[sd] path traversal rejected");
      } else {
        char buf[1024];
        String path = String(SD_MOUNT_POINT "/") + sub;
        int n = sd_read_file(path.c_str(), buf, sizeof(buf));
        if (n > 0) Serial.println(buf);
        else Serial.println("[sd] file not found or empty");
      }
    } else
#endif
    // SD-loaded prompts: "generate" picks a random SD prompt, "generate N"
    // generates N tokens from the default prompt.
    if (cmd == "generate" || cmd.startsWith("generate ")) {
      if (!_setup_ok) { Serial.println("inference disabled (setup failed)"); }
      else {
        int n_tok = N_GENERATE;
        const int *p_ids = PROMPT_IDS;
        int p_n = sizeof(PROMPT_IDS) / sizeof(int);
#if USE_SD
        int sd_n = sd_prompt_count();
        if (sd_n > 0 && cmd == "generate") {
          int pick = (int)(millis() % sd_n);
          const char *txt = sd_prompt(pick);
          if (txt) {
            Serial.printf("[sd] prompt %d: %s\n", pick, txt);
          }
        }
#endif
        if (cmd.startsWith("generate ")) {
          int v = cmd.substring(9).toInt();
          if (v > 0 && v <= 2000) n_tok = v;
        }
        run_generate(p_ids, p_n, n_tok);
      }
    }
    else if (cmd == "help") {
      Serial.println("commands:");
      Serial.println("  generate [N]     — run inference (N tokens, default 200)");
#if USE_PEER_PROTOCOL
      Serial.println("  status / peers   — show peer table");
      Serial.println("  identity [N]     — show/set persona");
#endif
#if USE_SD
      Serial.println("  ls / ls config   — list SD card files");
      Serial.println("  log              — dump encounter/bond logs");
      Serial.println("  cat <path>       — print file from SD");
#if USE_PEER_PROTOCOL
      Serial.println("  stats            — save stats to SD");
      Serial.println("  provision        — re-provision SD card");
#endif
#endif
    }
  }
#if USE_PEER_PROTOCOL
  peer_tick();
#if USE_DISPLAY
  {
    static int64_t _last_disp = 0;
    int64_t now = esp_timer_get_time() / 1000;
    if (now - _last_disp >= 2000) {
      int np = 0, nb = 0;
      for (int i = 0; i < PEER_MAX; i++) {
        if (!_pr_peers[i].active) continue;
        np++;
        if (_pr_peers[i].bonded) nb++;
      }
      display_status(persona()->face_idle, _pr.name, np, nb,
                      _pr.total_encounters);
      int slot = 0;
      for (int i = 0; i < PEER_MAX && slot < (ZONE_BOT_ROWS - 1); i++) {
        PeerSlot *p = &_pr_peers[i];
        if (!p->active) continue;
        const char *st = "...";
        uint16_t col = COL_DIM;
        if (p->bonded) { st = "BONDED"; col = COL_BOND; }
        else if (p->i_validated) { st = "verified"; col = COL_FG; }
        else if (p->challenge_sent) { st = "challenging"; col = COL_WARN; }
        display_peer(slot++, p->name, st, col);
      }
      _last_disp = now;
    }
  }
#endif // USE_DISPLAY
#endif // USE_PEER_PROTOCOL
#if USE_OTA
  ota_tick();
#endif
#if USE_COMPANION
  companion_tick();
#endif
  delay(10);
#else
  delay(10000);
#endif
}
