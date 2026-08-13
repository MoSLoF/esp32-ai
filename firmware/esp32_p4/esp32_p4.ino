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
#define LLM_PROFILE 1
#define LLM_PROFILE_NOW() esp_timer_get_time()
#include "../common/llm.h"
#include "../esp32_llm/vocab.h"   // shared tokenizer assets

// Display support placeholder -- set to 1 once a MIPI-DSI driver is written.
// Phase 1 (MVP) runs serial-only.
#define USE_DISPLAY 0
#if USE_DISPLAY
#include "display.h"
#endif

// ESP-NOW: receive prompts from peers, broadcast generated tokens.
// Requires WiFi (routed through the companion C6 via SDIO on the P4).
#define USE_ESPNOW 0
#define USE_PEER_PROTOCOL 0
#define USE_OTA 0
#if (USE_PEER_PROTOCOL || USE_OTA) && !USE_ESPNOW
#undef USE_ESPNOW
#define USE_ESPNOW 1
#endif
#if USE_ESPNOW
#include "espnow_comm.h"
#endif
#if USE_PEER_PROTOCOL
#include "peer_protocol.h"
#endif
#if USE_OTA
#include "ota_espnow.h"
#endif

static const int PROMPT_IDS[] = {433, 447, 259, 405}; // "Once upon a time"
static const int N_GENERATE = 200;

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
}

Model model;
Scratch s;

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
// Same int8-staged approach as the S3 build. The P4's faster PSRAM (~200 MB/s
// vs 60 MB/s) cuts the bandwidth floor from ~40ms to ~12ms per token; the 400
// MHz RISC-V cores reduce per-row compute proportionally. The head is scanned
// in full every token and still dominates runtime -- just less so.
static int8_t *head_w8 = NULL;      // [rows * cols] unpacked int8 weights (-7..7)
static float  *head_scale8 = NULL;  // [rows] per-row dequant scale
static int head_rows, head_cols;

static int8_t head_actq[128];       // quantized activation, shared by both cores
static float  head_acts;            // its scale

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

// dual-core plumbing (worker does the first half of the rows on core 0)
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

// Matches Model.head_matvec (QT*, float*, float*); QT unused (weights staged).
static void head_matvec_int8(const QT *t, const float *x, float *y) {
  (void)t;
  quantize_act(x, head_cols, head_actq, &head_acts);
  head_job_y = y;
  head_job_split = head_rows / 2;
  xTaskNotifyGive(head_worker);
  head_rows_range(y, head_job_split, head_rows);
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}

static void *ps(size_t n) {
  void *p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM);
  if (!p) { Serial.printf("PSRAM alloc failed (%u bytes)\n", (unsigned)n); while (1) delay(1000); }
  return p;
}

// Unpack the (row-capped) head from int4 to int8 in PSRAM, once at boot.
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

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println("\n=== ESP32-P4 PLE TinyLM ===");

  // Map the model partition.
  const esp_partition_t *part = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40, "model");
  if (!part) { Serial.println("model partition not found"); return; }
  const void *base;
  esp_partition_mmap_handle_t h;
  esp_err_t err = esp_partition_mmap(part, 0, part->size,
                                     ESP_PARTITION_MMAP_DATA, &base, &h);
  if (err != ESP_OK) { Serial.printf("mmap failed: %d\n", err); return; }

  if (llm_load((const uint8_t *)base, &model)) { Serial.println("bad model magic"); return; }
  Cfg *c = &model.c;
  Serial.printf("model: V=%d D=%d L=%d H=%d F=%d P=%d  (mapped %.1f MB)\n",
                c->vocab, c->dim, c->n_layers, c->n_heads, c->ffn, c->ple_dim,
                part->size / 1e6);

#if USE_DISPLAY
  display_begin();
#endif
#if USE_ESPNOW
  if (!espnow_begin()) Serial.println("ESP-NOW init failed (continuing without)");
#endif

  // Cap head rows to the trained vocab BEFORE staging.
  model.tok_emb.rows = VOCAB_N;
  stage_head_int8(&model.tok_emb);
  inference_task = xTaskGetCurrentTaskHandle();
  // Pin head worker to core 0; setup() runs on core 1 (same convention as S3).
  // If the P4 Arduino core assigns setup() to a different core, swap the pin.
  if (xTaskCreatePinnedToCore(head_worker_main, "head", 8192, NULL, 2,
                             &head_worker, 0) != pdPASS) {
    Serial.println("head worker creation failed");
    return;
  }
  model.head_matvec = head_matvec_int8;

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
  Serial.printf("PSRAM free after alloc: %u KB\n\n",
                heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024);

  // ---- generate ----
  // Use ESP-NOW prompt if one arrived, otherwise fall back to the hardcoded one.
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
  Serial.print(">>> ");
  int pos = 0, tok = 0;
  int64_t t_start = 0;
  int64_t decode_us = 0;
  int decoded = 0;

  for (int i = 0; i < n_prompt; i++) {
    tok = prompt_ids[i];
    emit(tok);
    llm_forward(&model, tok, pos++, &s);
  }

  llm_profile_reset(&s);

  t_start = esp_timer_get_time();
  for (int step = 0; step < N_GENERATE && pos < model.c.seq_len; step++) {
    int best = 0; float bv = -1e30f;
    for (int v = 0; v < VOCAB_N; v++)
      if (s.logits[v] > bv) { bv = s.logits[v]; best = v; }
    tok = best;
    emit(tok);

    int64_t d0 = esp_timer_get_time();
    llm_forward(&model, tok, pos++, &s);
    decode_us += esp_timer_get_time() - d0;
    decoded++;
    if ((step & 7) == 0) delay(0);
  }
  int64_t total_us = esp_timer_get_time() - t_start;

  Serial.printf("\n\n--- %d tokens in %.2f s ---\n", decoded, total_us / 1e6);
  Serial.printf("throughput: %.2f tok/s   (%.1f ms/token)\n",
                decoded * 1e6 / total_us, decode_us / 1000.0 / decoded);
  if (s.profile.calls) {
    float n = (float)s.profile.calls * 1000.f;
    Serial.printf("profile ms/token: input %.1f | attn %.1f | ffn %.1f | ple %.1f | head %.1f\n",
                  s.profile.input_us / n, s.profile.attn_us / n,
                  s.profile.ffn_us / n, s.profile.ple_us / n,
                  s.profile.head_us / n);
  }
#if USE_DISPLAY
  display_stats(decoded * 1e6f / decode_us, decode_us / 1000.0f / decoded);
#endif

#if USE_PEER_PROTOCOL
  peer_init(peer_infer);
#endif
#if USE_OTA
  ota_init();
#endif
}

void loop() {
#if USE_PEER_PROTOCOL || USE_OTA
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
    }
#endif
  }
#if USE_PEER_PROTOCOL
  peer_tick();
#endif
#if USE_OTA
  ota_tick();
#endif
  delay(10);
#else
  delay(10000);
#endif
}
