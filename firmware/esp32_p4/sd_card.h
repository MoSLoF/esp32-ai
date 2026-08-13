// SD card filesystem layer for the ESP32-P4.
//
// Mounts a FAT-formatted SD card on SDMMC Slot 1 at /sdcard. After
// mounting, any code can use standard fopen/fread/fwrite. The P4's
// Slot 0 is reserved for the companion C6 SDIO bridge — don't touch it.
//
// Pin defaults are for the Waveshare ESP32-P4-NANO:
//   CLK=43, CMD=44, D0=39, D1=40, D2=41, D3=42
//
// Usage:
//   #define USE_SD 1
//   #include "sd_card.h"
//   sd_begin();                         // in setup(), mounts /sdcard
//   sd_read_file("/sdcard/foo.txt", buf, sizeof(buf));
//   sd_list_dir("/sdcard");
//
// Gracefully degrades: if no card is present, sd_begin() returns false
// and all read/write helpers return -1 or NULL. Callers fall back to
// compiled-in defaults.

#ifndef SD_CARD_H
#define SD_CARD_H

#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

#define SD_MOUNT_POINT "/sdcard"

// Waveshare ESP32-P4-NANO defaults (Slot 1).
#ifndef SD_PIN_CLK
#define SD_PIN_CLK  43
#endif
#ifndef SD_PIN_CMD
#define SD_PIN_CMD  44
#endif
#ifndef SD_PIN_D0
#define SD_PIN_D0   39
#endif
#ifndef SD_PIN_D1
#define SD_PIN_D1   40
#endif
#ifndef SD_PIN_D2
#define SD_PIN_D2   41
#endif
#ifndef SD_PIN_D3
#define SD_PIN_D3   42
#endif

static sdmmc_card_t *_sd_card = NULL;
static bool _sd_mounted = false;

static bool sd_begin() {
  if (_sd_mounted) return true;

  sdmmc_host_t host = SDMMC_HOST_DEFAULT();
  host.slot = SDMMC_HOST_SLOT_1;

  sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
  slot.clk = (gpio_num_t)SD_PIN_CLK;
  slot.cmd = (gpio_num_t)SD_PIN_CMD;
  slot.d0  = (gpio_num_t)SD_PIN_D0;
  slot.d1  = (gpio_num_t)SD_PIN_D1;
  slot.d2  = (gpio_num_t)SD_PIN_D2;
  slot.d3  = (gpio_num_t)SD_PIN_D3;
  slot.width = 4;

  esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {};
  mount_cfg.format_if_mount_failed = false;
  mount_cfg.max_files = 5;
  mount_cfg.allocation_unit_size = 16 * 1024;

  esp_err_t err = esp_vfs_fat_sdmmc_mount(
      SD_MOUNT_POINT, &host, &slot, &mount_cfg, &_sd_card);
  if (err != ESP_OK) {
    if (err == ESP_FAIL)
      Serial.println("[sd] mount failed (not FAT?)");
    else if (err == ESP_ERR_NOT_FOUND)
      Serial.println("[sd] no card detected");
    else
      Serial.printf("[sd] mount error: %d\n", err);
    return false;
  }

  _sd_mounted = true;
  Serial.printf("[sd] mounted: %s, %.1f MB\n",
                _sd_card->cid.name,
                (double)_sd_card->csd.capacity *
                _sd_card->csd.sector_size / (1024.0 * 1024.0));
  return true;
}

static void sd_end() {
  if (!_sd_mounted) return;
  esp_vfs_fat_sdmmc_unmount(SD_MOUNT_POINT, _sd_card);
  _sd_card = NULL;
  _sd_mounted = false;
}

static bool sd_mounted() { return _sd_mounted; }

// Read an entire file into a caller-supplied buffer. Returns bytes read,
// or -1 on error. Null-terminates if there's room.
static int sd_read_file(const char *path, char *buf, int buf_size) {
  if (!_sd_mounted || !buf || buf_size < 1) return -1;
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  int n = (int)fread(buf, 1, buf_size - 1, f);
  fclose(f);
  if (n >= 0) buf[n] = '\0';
  return n;
}

// Write a string to a file (creates or overwrites).
static bool sd_write_file(const char *path, const char *data) {
  if (!_sd_mounted) return false;
  FILE *f = fopen(path, "w");
  if (!f) return false;
  fputs(data, f);
  fclose(f);
  return true;
}

// Append a line to a file (creates if needed).
static bool sd_append_line(const char *path, const char *line) {
  if (!_sd_mounted) return false;
  FILE *f = fopen(path, "a");
  if (!f) return false;
  fputs(line, f);
  fputc('\n', f);
  fclose(f);
  return true;
}

// Check if a file exists.
static bool sd_exists(const char *path) {
  if (!_sd_mounted) return false;
  struct stat st;
  return stat(path, &st) == 0;
}

// Get file size in bytes, or -1 if not found.
static int sd_file_size(const char *path) {
  if (!_sd_mounted) return -1;
  struct stat st;
  if (stat(path, &st) != 0) return -1;
  return (int)st.st_size;
}

// List directory contents to serial.
static void sd_list_dir(const char *path) {
  if (!_sd_mounted) { Serial.println("[sd] not mounted"); return; }
  DIR *dir = opendir(path);
  if (!dir) { Serial.printf("[sd] can't open: %s\n", path); return; }
  Serial.printf("[sd] %s:\n", path);
  struct dirent *ent;
  while ((ent = readdir(dir)) != NULL) {
    char full[128];
    snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
    struct stat st;
    if (stat(full, &st) == 0)
      Serial.printf("  %-24s %8ld bytes\n", ent->d_name, (long)st.st_size);
    else
      Serial.printf("  %s\n", ent->d_name);
  }
  closedir(dir);
}

#endif
