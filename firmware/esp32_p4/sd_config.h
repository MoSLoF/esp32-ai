// SD card configuration: provisioning, loading, and encounter logging.
//
// First-run flow (blank or unconfigured card):
//   1. Firmware detects missing marker file (.p4cfg)
//   2. Writes all config files from compiled-in defaults
//   3. Creates .p4cfg marker with firmware version and device ID
//   4. Loads the files it just wrote — guaranteed format match
//
// Subsequent boots:
//   1. Detects .p4cfg — skips provisioning
//   2. Loads config files (user may have edited them on a PC)
//   3. Format is always valid because the firmware defined it
//
// Re-provision: serial command "provision" rewrites all defaults.
//
// File layout on the SD card (all written by firmware):
//
//   /sdcard/
//     .p4cfg              — marker: version, device_id, provision time
//     config/
//       identity.txt      — persona index (0-7)
//       name.txt          — device name
//       prompts.txt       — inference prompts, one per line
//       challenges.txt    — challenge token IDs (CSV, one per line)
//       peers.txt         — known peer names/IDs (auto-updated)
//     log/
//       encounters.log    — append-only event log
//       bonds.log         — bond-only log (subset of encounters)
//       stats.txt         — lifetime stats snapshot

#ifndef SD_CONFIG_H
#define SD_CONFIG_H

#include "sd_card.h"

#define SD_LINE_MAX  128
#define SD_CFG       SD_MOUNT_POINT "/config"
#define SD_LOG       SD_MOUNT_POINT "/log"
#define SD_MARKER    SD_MOUNT_POINT "/.p4cfg"
#define SD_FW_VER    "1.0.0"

// ---- provisioning (firmware writes defaults) --------------------------------

static void _sd_mkdir(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0)
    mkdir(path, 0755);
}

static void sd_provision(uint32_t device_id, const char *device_name,
                          int persona_idx) {
  if (!sd_mounted()) return;

  Serial.println("[sd] provisioning SD card...");

  _sd_mkdir(SD_CFG);
  _sd_mkdir(SD_LOG);

  // .p4cfg marker — firmware version + device identity.
  {
    char buf[128];
    snprintf(buf, sizeof(buf),
             "version=%s\ndevice_id=0x%08X\nname=%s\npersona=%d\n",
             SD_FW_VER, device_id, device_name, persona_idx);
    sd_write_file(SD_MARKER, buf);
    Serial.printf("[sd] wrote %s\n", SD_MARKER);
  }

  // config/identity.txt — current persona index.
  {
    char buf[4];
    snprintf(buf, sizeof(buf), "%d\n", persona_idx);
    sd_write_file(SD_CFG "/identity.txt", buf);
  }

  // config/name.txt — device name.
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s\n", device_name);
    sd_write_file(SD_CFG "/name.txt", buf);
  }

  // config/prompts.txt — default inference prompts.
  {
    sd_write_file(SD_CFG "/prompts.txt",
      "Once upon a time\n"
      "There was a\n"
      "One day there was a\n"
      "The\n"
      "In a land far away\n"
      "Deep in the forest\n");
  }

  // config/challenges.txt — write the compiled-in challenge bank.
  {
    FILE *f = fopen(SD_CFG "/challenges.txt", "w");
    if (f) {
      for (int i = 0; i < N_CHAL_BANK; i++) {
        for (int j = 0; j < PEER_PROMPT_LEN; j++) {
          if (j > 0) fputc(',', f);
          fprintf(f, "%d", CHALLENGE_BANK[i][j]);
        }
        fputc('\n', f);
      }
      fclose(f);
    }
  }

  // config/peers.txt — empty, populated as peers are discovered.
  if (!sd_exists(SD_CFG "/peers.txt"))
    sd_write_file(SD_CFG "/peers.txt", "# peer_name,device_id,first_seen\n");

  // log/ — create empty logs with headers.
  if (!sd_exists(SD_LOG "/encounters.log"))
    sd_write_file(SD_LOG "/encounters.log",
                  "# millis,our_name,peer_name,peer_id,event\n");
  if (!sd_exists(SD_LOG "/bonds.log"))
    sd_write_file(SD_LOG "/bonds.log",
                  "# millis,our_name,peer_name,peer_id,bond_num\n");

  // log/stats.txt — initial stats snapshot.
  {
    char buf[128];
    snprintf(buf, sizeof(buf),
             "encounters=0\nbonds=0\ndevice=%s\nid=0x%08X\n",
             device_name, device_id);
    sd_write_file(SD_LOG "/stats.txt", buf);
  }

  Serial.println("[sd] provisioning complete");
  sd_list_dir(SD_CFG);
  sd_list_dir(SD_LOG);
}

static bool sd_is_provisioned() {
  return sd_exists(SD_MARKER);
}

// ---- loading (firmware reads its own files back) ----------------------------

static int sd_load_identity() {
  char buf[8];
  int n = sd_read_file(SD_CFG "/identity.txt", buf, sizeof(buf));
  if (n <= 0) return -1;
  int idx = atoi(buf);
  if (idx < 0 || idx >= N_PERSONAS) return -1;
  Serial.printf("[sd] persona: %d (%s)\n", idx, PERSONAS[idx].name);
  return idx;
}

static bool sd_load_name(char *out, int max_len) {
  char buf[32];
  int n = sd_read_file(SD_CFG "/name.txt", buf, sizeof(buf));
  if (n <= 0) return false;
  while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' '))
    buf[--n] = '\0';
  if (n == 0 || n >= max_len) return false;
  strncpy(out, buf, max_len);
  out[max_len - 1] = '\0';
  Serial.printf("[sd] name: %s\n", out);
  return true;
}

// ---- prompts ----------------------------------------------------------------

#define SD_MAX_PROMPTS 16
#define SD_PROMPT_MAX_LEN 256

static char _sd_prompts[SD_MAX_PROMPTS][SD_PROMPT_MAX_LEN];
static int _sd_n_prompts = 0;

static int sd_load_prompts() {
  _sd_n_prompts = 0;
  FILE *f = fopen(SD_CFG "/prompts.txt", "r");
  if (!f) return 0;

  char line[SD_PROMPT_MAX_LEN];
  while (_sd_n_prompts < SD_MAX_PROMPTS && fgets(line, sizeof(line), f)) {
    int len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
      line[--len] = '\0';
    if (len == 0) continue;
    strncpy(_sd_prompts[_sd_n_prompts], line, SD_PROMPT_MAX_LEN);
    _sd_prompts[_sd_n_prompts][SD_PROMPT_MAX_LEN - 1] = '\0';
    _sd_n_prompts++;
  }
  fclose(f);

  if (_sd_n_prompts > 0)
    Serial.printf("[sd] loaded %d prompts\n", _sd_n_prompts);
  return _sd_n_prompts;
}

static int sd_prompt_count() { return _sd_n_prompts; }
static const char *sd_prompt(int i) {
  return (i >= 0 && i < _sd_n_prompts) ? _sd_prompts[i] : NULL;
}

// ---- challenges -------------------------------------------------------------

#define SD_MAX_CHALLENGES 8
#define SD_CHAL_TOK_MAX   8

static int _sd_chal[SD_MAX_CHALLENGES][SD_CHAL_TOK_MAX];
static int _sd_chal_len[SD_MAX_CHALLENGES];
static int _sd_n_chal = 0;

static int sd_load_challenges() {
  _sd_n_chal = 0;
  FILE *f = fopen(SD_CFG "/challenges.txt", "r");
  if (!f) return 0;

  char line[SD_LINE_MAX];
  while (_sd_n_chal < SD_MAX_CHALLENGES && fgets(line, sizeof(line), f)) {
    int len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
      line[--len] = '\0';
    if (len == 0 || line[0] == '#') continue;

    int ntok = 0;
    char *p = line;
    while (*p && ntok < SD_CHAL_TOK_MAX) {
      _sd_chal[_sd_n_chal][ntok++] = atoi(p);
      p = strchr(p, ',');
      if (!p) break;
      p++;
    }
    if (ntok > 0) {
      _sd_chal_len[_sd_n_chal] = ntok;
      _sd_n_chal++;
    }
  }
  fclose(f);

  if (_sd_n_chal > 0)
    Serial.printf("[sd] loaded %d challenges\n", _sd_n_chal);
  return _sd_n_chal;
}

static int sd_challenge_count() { return _sd_n_chal; }
static const int *sd_challenge(int i, int *len) {
  if (i < 0 || i >= _sd_n_chal) return NULL;
  if (len) *len = _sd_chal_len[i];
  return _sd_chal[i];
}

// ---- encounter & bond logging -----------------------------------------------

static bool sd_log_encounter(const char *our_name, const char *peer_name,
                              uint32_t peer_id, const char *event) {
  if (!sd_mounted()) return false;
  char line[SD_LINE_MAX];
  snprintf(line, sizeof(line), "%lu,%s,%s,0x%08X,%s",
           millis(), our_name, peer_name, peer_id, event);
  return sd_append_line(SD_LOG "/encounters.log", line);
}

static bool sd_log_bond(const char *our_name, const char *peer_name,
                          uint32_t peer_id, int bond_num) {
  if (!sd_mounted()) return false;
  char line[SD_LINE_MAX];
  snprintf(line, sizeof(line), "%lu,%s,%s,0x%08X,%d",
           millis(), our_name, peer_name, peer_id, bond_num);
  sd_append_line(SD_LOG "/bonds.log", line);
  char evt[32];
  snprintf(evt, sizeof(evt), "BONDED,#%d", bond_num);
  return sd_log_encounter(our_name, peer_name, peer_id, evt);
}

// Record a discovered peer in config/peers.txt (dedup by device_id).
static void sd_record_peer(const char *peer_name, uint32_t peer_id) {
  if (!sd_mounted()) return;

  // Check if already recorded.
  char id_str[16];
  snprintf(id_str, sizeof(id_str), "0x%08X", peer_id);
  char buf[512];
  int n = sd_read_file(SD_CFG "/peers.txt", buf, sizeof(buf));
  if (n > 0 && strstr(buf, id_str)) return;

  char line[SD_LINE_MAX];
  snprintf(line, sizeof(line), "%s,0x%08X,%lu", peer_name, peer_id, millis());
  sd_append_line(SD_CFG "/peers.txt", line);
}

// Update lifetime stats snapshot.
static void sd_save_stats(const char *name, uint32_t id,
                            uint16_t encounters, uint16_t bonds) {
  if (!sd_mounted()) return;
  char buf[128];
  snprintf(buf, sizeof(buf),
           "encounters=%d\nbonds=%d\ndevice=%s\nid=0x%08X\n",
           encounters, bonds, name, id);
  sd_write_file(SD_LOG "/stats.txt", buf);
}

static void sd_dump_log() {
  if (!sd_mounted()) { Serial.println("[sd] not mounted"); return; }
  const char *logs[] = { SD_LOG "/encounters.log", SD_LOG "/bonds.log" };
  const char *labels[] = { "encounter log", "bond log" };
  for (int l = 0; l < 2; l++) {
    if (!sd_exists(logs[l])) continue;
    FILE *f = fopen(logs[l], "r");
    if (!f) continue;
    Serial.printf("\n--- %s ---\n", labels[l]);
    char line[SD_LINE_MAX];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
      if (line[0] == '#') continue;
      Serial.printf("  %s", line);
      count++;
    }
    fclose(f);
    Serial.printf("--- %d entries ---\n", count);
  }
  Serial.println();
}

// ---- master init: provision if needed, then load ----------------------------

// Call once in setup() after sd_begin() and peer_init().
// Writes defaults on first run, then loads config every time.
static void sd_setup(uint32_t device_id, const char *device_name,
                      int persona_idx) {
  if (!sd_mounted()) return;

  if (!sd_is_provisioned()) {
    Serial.println("[sd] blank card detected — provisioning...");
    sd_provision(device_id, device_name, persona_idx);
  } else {
    Serial.println("[sd] card configured, loading...");
  }

  // Load config (reads back what provisioning wrote, or user edits).
  int idx = sd_load_identity();
  if (idx >= 0) persona_select(idx);
  sd_load_prompts();
  sd_load_challenges();
  sd_list_dir(SD_CFG);
}

#endif
