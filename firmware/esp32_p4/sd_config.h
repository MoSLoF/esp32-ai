// Load configuration from SD card into peer protocol and persona systems.
//
// File layout on the SD card (all optional — missing files use defaults):
//
//   /sdcard/
//     identity.txt       — persona index (single digit 0-7)
//     prompts.txt         — custom inference prompts, one per line
//     challenges.txt      — extra challenge token IDs (CSV, one prompt per line)
//     encounters.log      — append-only encounter/bond log (written by firmware)
//     persona/            — custom persona overrides
//       name.txt          — device name override
//       quips.txt          — key=value quip overrides
//
// Designed for field deployment: drop files on the SD card, insert, power on.
// No reflashing needed to change behavior.

#ifndef SD_CONFIG_H
#define SD_CONFIG_H

#include "sd_card.h"

#define SD_LINE_MAX 128

// ---- identity override -----------------------------------------------------

// Load persona index from /sdcard/identity.txt.
// Returns -1 if not found (use auto-select).
static int sd_load_identity() {
  char buf[8];
  int n = sd_read_file(SD_MOUNT_POINT "/identity.txt", buf, sizeof(buf));
  if (n <= 0) return -1;
  int idx = atoi(buf);
  if (idx < 0 || idx >= N_PERSONAS) return -1;
  Serial.printf("[sd] persona override: %d (%s)\n", idx, PERSONAS[idx].name);
  return idx;
}

// Load custom device name from /sdcard/persona/name.txt.
static bool sd_load_name(char *out, int max_len) {
  char buf[32];
  int n = sd_read_file(SD_MOUNT_POINT "/persona/name.txt", buf, sizeof(buf));
  if (n <= 0) return false;
  // Trim trailing whitespace.
  while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' '))
    buf[--n] = '\0';
  if (n == 0 || n >= max_len) return false;
  strncpy(out, buf, max_len);
  out[max_len - 1] = '\0';
  Serial.printf("[sd] name override: %s\n", out);
  return true;
}

// ---- custom prompts --------------------------------------------------------

#define SD_MAX_PROMPTS 16
#define SD_PROMPT_MAX_LEN 256

static char _sd_prompts[SD_MAX_PROMPTS][SD_PROMPT_MAX_LEN];
static int _sd_n_prompts = 0;

// Load text prompts from /sdcard/prompts.txt (one per line).
// These can be fed to the inference engine as raw text prompts
// for interactive generation or peer challenges.
static int sd_load_prompts() {
  _sd_n_prompts = 0;
  if (!sd_exists(SD_MOUNT_POINT "/prompts.txt")) return 0;

  FILE *f = fopen(SD_MOUNT_POINT "/prompts.txt", "r");
  if (!f) return 0;

  char line[SD_PROMPT_MAX_LEN];
  while (_sd_n_prompts < SD_MAX_PROMPTS &&
         fgets(line, sizeof(line), f)) {
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
    Serial.printf("[sd] loaded %d prompts from prompts.txt\n", _sd_n_prompts);
  return _sd_n_prompts;
}

static int sd_prompt_count() { return _sd_n_prompts; }
static const char *sd_prompt(int i) {
  return (i >= 0 && i < _sd_n_prompts) ? _sd_prompts[i] : NULL;
}

// ---- extra challenge token banks -------------------------------------------

#define SD_MAX_CHALLENGES 8
#define SD_CHAL_TOK_MAX   8

static int _sd_chal[SD_MAX_CHALLENGES][SD_CHAL_TOK_MAX];
static int _sd_chal_len[SD_MAX_CHALLENGES];
static int _sd_n_chal = 0;

// Load challenge token ID sequences from /sdcard/challenges.txt.
// Format: one challenge per line, comma-separated token IDs.
//   433,447,259,405
//   1788,539,259,464
static int sd_load_challenges() {
  _sd_n_chal = 0;
  if (!sd_exists(SD_MOUNT_POINT "/challenges.txt")) return 0;

  FILE *f = fopen(SD_MOUNT_POINT "/challenges.txt", "r");
  if (!f) return 0;

  char line[SD_LINE_MAX];
  while (_sd_n_chal < SD_MAX_CHALLENGES &&
         fgets(line, sizeof(line), f)) {
    int len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
      line[--len] = '\0';
    if (len == 0) continue;

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
    Serial.printf("[sd] loaded %d challenge prompts from challenges.txt\n",
                  _sd_n_chal);
  return _sd_n_chal;
}

static int sd_challenge_count() { return _sd_n_chal; }
static const int *sd_challenge(int i, int *len) {
  if (i < 0 || i >= _sd_n_chal) return NULL;
  if (len) *len = _sd_chal_len[i];
  return _sd_chal[i];
}

// ---- encounter logging -----------------------------------------------------

static bool sd_log_encounter(const char *our_name, const char *peer_name,
                              uint32_t peer_id, const char *event) {
  if (!sd_mounted()) return false;
  char line[SD_LINE_MAX];
  unsigned long ms = millis();
  snprintf(line, sizeof(line), "%lu,%s,%s,0x%08X,%s",
           ms, our_name, peer_name, peer_id, event);
  return sd_append_line(SD_MOUNT_POINT "/encounters.log", line);
}

static bool sd_log_bond(const char *our_name, const char *peer_name,
                          uint32_t peer_id, int bond_num) {
  if (!sd_mounted()) return false;
  char line[SD_LINE_MAX];
  unsigned long ms = millis();
  snprintf(line, sizeof(line), "%lu,%s,%s,0x%08X,BONDED,#%d",
           ms, our_name, peer_name, peer_id, bond_num);
  return sd_append_line(SD_MOUNT_POINT "/encounters.log", line);
}

// Print the encounter log to serial.
static void sd_dump_log() {
  if (!sd_mounted()) { Serial.println("[sd] not mounted"); return; }
  if (!sd_exists(SD_MOUNT_POINT "/encounters.log")) {
    Serial.println("[sd] no encounters logged yet");
    return;
  }
  FILE *f = fopen(SD_MOUNT_POINT "/encounters.log", "r");
  if (!f) return;
  Serial.println("\n--- encounter log ---");
  char line[SD_LINE_MAX];
  int count = 0;
  while (fgets(line, sizeof(line), f)) {
    Serial.print("  ");
    Serial.print(line);
    count++;
  }
  fclose(f);
  Serial.printf("--- %d entries ---\n\n", count);
}

// ---- master loader ---------------------------------------------------------

// Call once after sd_begin() and persona system init.
// Loads all config files that exist, applies overrides.
static void sd_load_config() {
  if (!sd_mounted()) return;
  Serial.println("[sd] loading config...");

  // Persona override.
  int idx = sd_load_identity();
  if (idx >= 0) persona_select(idx);

  // Prompts.
  sd_load_prompts();

  // Challenge bank extensions.
  sd_load_challenges();

  // List what's on the card.
  sd_list_dir(SD_MOUNT_POINT);
}

#endif
