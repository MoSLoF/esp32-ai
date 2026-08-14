// R5-03 behavioral regression test: the OTA counter/partition journal must
// stay consistent across power loss at every phase boundary.
//
// This compiles and executes the ACTUAL ota_verify.h journal/recovery
// state machine (via the ESP-IDF stubs in stubs/) -- ota_verify_stage_counter(),
// _ota_verify_recover() (invoked through ota_verify_init(), exactly as the
// real firmware calls it at boot), ota_verify_commit_counter(), and
// ota_verify_abandon_stage() -- rather than re-implementing the journal
// logic. "Reboot" is simulated by re-running ota_verify_init(); NVS state
// (stubs/nvs.h) persists across that call the same way real flash would,
// and which partition is "running" (stubs/esp_ota_ops.h) is driven
// explicitly by the test to represent ground truth the bootloader decided.
//
// Reassessment failure state (R5-03, MEDIUM):
//   running partition = old; sec_ctr = N; ota_pending = N+1. Boot recovery
//   promotes the pending value into sec_ctr and clears the pending record
//   without checking which partition is actually running -- burning the
//   counter for an update that never activated and permanently blocking a
//   retry of the same signed manifest (anti-rollback rejects sec_counter
//   <= stored).
//
// Build: gcc -std=c11 -I stubs -o /tmp/ota_journal_test ota_journal_test.c
// Run:   /tmp/ota_journal_test   (exit 0 = pass, non-zero = fail)

#define OTA_VERIFY_PUBKEY_PEM "unused-in-host-behavioral-test"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

static int host_serial_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = vprintf(fmt, ap);
  va_end(ap);
  return r;
}
static int host_serial_println(const char *s) { return printf("%s\n", s); }
struct HostSerialClass { int (*printf)(const char *fmt, ...); int (*println)(const char *s); };
static struct HostSerialClass Serial = { host_serial_printf, host_serial_println };

// esp32_p4.ino normally provides delay(); ota_verify.h itself doesn't need
// it, so nothing further to stub here.

#include "../esp32_p4/ota_verify.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("  FAIL: %s\n", msg); g_failures++; } \
  else { printf("  ok:   %s\n", msg); } \
} while (0)

#define SUBTYPE_OTA_0 0x10
#define SUBTYPE_OTA_1 0x11

static esp_partition_t OTA_0_PART = { 0, SUBTYPE_OTA_0, 0, 0, "ota_0" };
static esp_partition_t OTA_1_PART = { 0, SUBTYPE_OTA_1, 0, 0, "ota_1" };

static void fresh_device(uint8_t running_subtype) {
  host_nvs_wipe();
  host_mock_running_partition.subtype = running_subtype;
  ota_verify_init();
}

static void reboot(void) {
  // The real firmware re-opens the same NVS namespace and calls
  // _ota_verify_recover() from inside ota_verify_init() on every boot;
  // NVS state (unlike _otav_manifest, which is a RAM-only cache) survives.
  memset(&_otav_manifest, 0, sizeof(_otav_manifest));
  ota_verify_init();
}

int main(void) {
  printf("=== R5-03: OTA journal must stay consistent across power loss ===\n");

  // ---- Scenario A: power loss between stage and boot-partition switch --
  // Exactly the reassessment's failure state: staged, but the switch never
  // took effect, so the old partition is still what's running.
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 5;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario A: staging succeeds");
    // Simulated crash: esp_ota_set_boot_partition() is never called, so
    // host_mock_running_partition stays OTA_0.
    reboot();
    CHECK(ota_verify_get_counter() == 0,
          "scenario A: counter is NOT burned when the staged update never activated");
    uint8_t phase = 0xFF;
    esp_err_t e = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario A: journal is cleared (abandoned) after recovery, not left dangling");
  }

  // ---- Scenario A retry: the SAME manifest counter must still work -----
  // (proves the abandoned attempt didn't burn the counter and permanently
  // block retrying via anti-rollback.)
  {
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 5; // same counter as the abandoned attempt
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "retry: staging with the same counter succeeds");
    host_mock_running_partition.subtype = SUBTYPE_OTA_1; // this time the switch "takes"
    CHECK(ota_verify_commit_counter(), "retry: commit succeeds");
    CHECK(ota_verify_get_counter() == 5, "retry: counter reaches the manifest's value on a successful retry");
  }

  // ---- Scenario B: power loss AFTER boot-partition switch, before commit
  // The new partition genuinely IS running; recovery must finish the job.
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 7;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario B: staging succeeds");
    // Simulated: esp_ota_set_boot_partition() succeeded (bootloader will
    // boot OTA_1 next), but the process crashes before commit_counter().
    host_mock_running_partition.subtype = SUBTYPE_OTA_1;
    reboot();
    CHECK(ota_verify_get_counter() == 7,
          "scenario B: recovery finishes the commit when the target partition actually booted");
    uint8_t phase = 0xFF;
    esp_err_t e = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario B: journal is cleared after recovery completes the commit");
  }

  // ---- Scenario C: normal completion within the same boot, no crash ----
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 12;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario C: staging succeeds");
    host_mock_running_partition.subtype = SUBTYPE_OTA_1;
    CHECK(ota_verify_commit_counter(), "scenario C: commit succeeds");
    CHECK(ota_verify_get_counter() == 12, "scenario C: counter reflects the completed update");
    uint8_t phase = 0xFF;
    esp_err_t e = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario C: journal is cleared immediately on successful commit");
    // A subsequent reboot with a clean journal must be a pure no-op.
    reboot();
    CHECK(ota_verify_get_counter() == 12, "scenario C: reboot after a clean commit changes nothing");
  }

  // ---- Scenario D: esp_ota_set_boot_partition() itself fails -----------
  // Handled synchronously via ota_verify_abandon_stage(), no reboot needed.
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 20;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario D: staging succeeds");
    // Simulated: esp_ota_set_boot_partition() returned an error.
    ota_verify_abandon_stage();
    CHECK(ota_verify_get_counter() == 0,
          "scenario D: counter untouched when set_boot_partition failed and staging was abandoned");
    uint8_t phase = 0xFF;
    esp_err_t e = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario D: journal is cleared immediately, without waiting for a reboot");
    reboot();
    CHECK(ota_verify_get_counter() == 0, "scenario D: reboot after an abandoned stage changes nothing");
  }

  // ---- Scenario E: crash during final journal cleanup (after sec_ctr is
  // already committed) must still converge, since the counter is already
  // correct for the partition that's about to boot.
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 30;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario E: staging succeeds");
    host_mock_running_partition.subtype = SUBTYPE_OTA_1;
    // Simulate commit_counter()'s sec_ctr write succeeding but the crash
    // landing before the journal-cleanup erase calls, by driving the two
    // steps ota_verify_commit_counter() itself would take: this checks
    // recovery still converges even though we skip straight to reboot
    // instead of calling commit_counter() to clear the journal.
    nvs_set_u32(_otav_nvs, "sec_ctr", 30);
    nvs_commit(_otav_nvs);
    reboot();
    CHECK(ota_verify_get_counter() == 30,
          "scenario E: recovery re-derives the correct (already-committed) counter, doesn't double-apply or corrupt it");
  }

  if (g_failures) {
    printf("\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nall checks passed\n");
  return 0;
}
