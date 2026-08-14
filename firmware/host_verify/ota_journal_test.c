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

  // ---- Scenario F: the core verification-memo bug -- recovery's own -----
  // ---- counter-commit write fails. The journal must NOT be cleared. -----
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 40;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario F: staging succeeds");
    host_mock_running_partition.subtype = SUBTYPE_OTA_1; // target genuinely activated

    host_nvs_fault_reset();
    host_nvs_fault.nvs_set_u32_n = 1;
    strncpy(host_nvs_fault.only_ns, "ota_sec", sizeof(host_nvs_fault.only_ns) - 1);
    strncpy(host_nvs_fault.only_key, "sec_ctr", sizeof(host_nvs_fault.only_key) - 1);
    reboot(); // recovery's sec_ctr commit fails

    CHECK(ota_verify_get_counter() == 0,
          "scenario F: counter is NOT burned when recovery's own commit fails");
    CHECK(ota_verify_recovery_blocked(),
          "scenario F: further OTA acceptance is blocked after a failed recovery commit");
    uint8_t phase = 0xFF;
    uint32_t ctr = 0;
    uint8_t part = 0;
    CHECK(nvs_get_u8(_otav_nvs, "pend_phase", &phase) == ESP_OK && phase == OTA_JOURNAL_PHASE_STAGED,
          "scenario F: journal phase is still intact (NOT cleared) after the failed commit");
    CHECK(nvs_get_u32(_otav_nvs, "pend_ctr", &ctr) == ESP_OK && ctr == 40,
          "scenario F: journal pending counter is still intact");
    CHECK(nvs_get_u8(_otav_nvs, "pend_part", &part) == ESP_OK && part == SUBTYPE_OTA_1,
          "scenario F: journal target partition is still intact");

    host_nvs_fault_reset();
    reboot(); // retry with NVS healthy again
    CHECK(ota_verify_get_counter() == 40,
          "scenario F: retry on a later boot converges (counter now committed)");
    CHECK(!ota_verify_recovery_blocked(),
          "scenario F: OTA acceptance is unblocked once recovery converges");
    esp_err_t e = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario F: journal is cleared once recovery actually converges");
  }

  // ---- Scenario G: pend_ctr / pend_part read failures during recovery --
  {
    // G1: pend_ctr read fails.
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 41;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario G1: staging succeeds");

    host_nvs_fault_reset();
    host_nvs_fault.nvs_get_u32_n = 1;
    strncpy(host_nvs_fault.only_ns, "ota_sec", sizeof(host_nvs_fault.only_ns) - 1);
    strncpy(host_nvs_fault.only_key, "pend_ctr", sizeof(host_nvs_fault.only_key) - 1);
    reboot();

    CHECK(ota_verify_get_counter() == 0, "scenario G1: no counter burn on an unreadable pend_ctr");
    CHECK(ota_verify_recovery_blocked(), "scenario G1: recovery is blocked, not guessing");
    uint8_t phase = 0xFF;
    CHECK(nvs_get_u8(_otav_nvs, "pend_phase", &phase) == ESP_OK && phase == OTA_JOURNAL_PHASE_STAGED,
          "scenario G1: journal is untouched, not cleared");

    host_nvs_fault_reset();
    host_mock_running_partition.subtype = SUBTYPE_OTA_1; // target activated, for a clean retry
    reboot();
    CHECK(ota_verify_get_counter() == 41, "scenario G1: retry converges once the read succeeds");
    CHECK(!ota_verify_recovery_blocked(), "scenario G1: unblocked after convergence");

    // G2: pend_part read fails (same shape, different field).
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 42;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario G2: staging succeeds");

    host_nvs_fault_reset();
    host_nvs_fault.nvs_get_u32_n = 1; // nvs_get_u8 delegates through nvs_get_u32
    strncpy(host_nvs_fault.only_ns, "ota_sec", sizeof(host_nvs_fault.only_ns) - 1);
    strncpy(host_nvs_fault.only_key, "pend_part", sizeof(host_nvs_fault.only_key) - 1);
    reboot();

    CHECK(ota_verify_get_counter() == 0, "scenario G2: no counter burn on an unreadable pend_part");
    CHECK(ota_verify_recovery_blocked(), "scenario G2: recovery is blocked, not guessing");

    host_nvs_fault_reset();
    host_mock_running_partition.subtype = SUBTYPE_OTA_1;
    reboot();
    CHECK(ota_verify_get_counter() == 42, "scenario G2: retry converges once the read succeeds");
    CHECK(!ota_verify_recovery_blocked(), "scenario G2: unblocked after convergence");
  }

  // ---- Scenario H: a genuinely missing key (not fault-injected), with --
  // ---- phase == STAGED still present -- the distinct ESP_ERR_NVS_NOT_FOUND
  // ---- path, not just a generic injected failure. ----------------------
  {
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 43;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario H: staging succeeds");
    esp_err_t erased = nvs_erase_key(_otav_nvs, "pend_ctr"); // genuinely gone, no fault injection
    CHECK(erased == ESP_OK, "scenario H: pend_ctr genuinely erased (test setup)");

    reboot();
    CHECK(ota_verify_get_counter() == 0, "scenario H: no counter burn on a genuinely missing pend_ctr");
    CHECK(ota_verify_recovery_blocked(), "scenario H: recovery is blocked, not guessing");
    uint8_t phase = 0xFF;
    CHECK(nvs_get_u8(_otav_nvs, "pend_phase", &phase) == ESP_OK && phase == OTA_JOURNAL_PHASE_STAGED,
          "scenario H: journal phase is left intact even though pend_ctr is genuinely gone");
  }

  // ---- Scenario I: journal-cleanup failures converge correctly on both -
  // ---- the abandon path and the commit-success path -- and only the ----
  // ---- commit-success path is explicitly NOT blocked (self-heals). -----
  {
    // I1: abandon path.
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 50;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario I1: staging succeeds");

    host_nvs_fault_reset();
    host_nvs_fault.nvs_erase_key_n = -1; // sticky: every erase fails
    strncpy(host_nvs_fault.only_ns, "ota_sec", sizeof(host_nvs_fault.only_ns) - 1);
    CHECK(!ota_verify_abandon_stage(), "scenario I1: abandon reports cleanup failure");
    uint8_t phase = 0xFF;
    CHECK(nvs_get_u8(_otav_nvs, "pend_phase", &phase) == ESP_OK && phase == OTA_JOURNAL_PHASE_STAGED,
          "scenario I1: journal is left dangling immediately after the failed cleanup");

    host_nvs_fault_reset();
    reboot(); // running partition still OTA_0 -- never activated
    CHECK(ota_verify_get_counter() == 0, "scenario I1: counter still untouched after convergence");
    CHECK(!ota_verify_recovery_blocked(),
          "scenario I1: abandon-path cleanup failure never blocks recovery (self-healing)");
    esp_err_t e1 = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e1 != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario I1: journal converges (clears) once cleanup succeeds again");

    // I2: commit-success path.
    fresh_device(SUBTYPE_OTA_0);
    _otav_manifest.valid = true;
    _otav_manifest.sec_counter = 51;
    CHECK(ota_verify_stage_counter(&OTA_1_PART), "scenario I2: staging succeeds");
    host_mock_running_partition.subtype = SUBTYPE_OTA_1;

    host_nvs_fault_reset();
    host_nvs_fault.nvs_erase_key_n = -1;
    strncpy(host_nvs_fault.only_ns, "ota_sec", sizeof(host_nvs_fault.only_ns) - 1);
    CHECK(ota_verify_commit_counter(),
          "scenario I2: commit itself still succeeds even though cleanup will fail");
    CHECK(ota_verify_get_counter() == 51, "scenario I2: counter is committed immediately");
    CHECK(nvs_get_u8(_otav_nvs, "pend_phase", &phase) == ESP_OK && phase == OTA_JOURNAL_PHASE_STAGED,
          "scenario I2: journal is left dangling immediately after the failed cleanup");

    host_nvs_fault_reset();
    reboot();
    CHECK(ota_verify_get_counter() == 51, "scenario I2: counter is unchanged (already correct) after convergence");
    CHECK(!ota_verify_recovery_blocked(),
          "scenario I2: commit-success path was never blocked, unlike scenario F's recovery-commit failure");
    esp_err_t e2 = nvs_get_u8(_otav_nvs, "pend_phase", &phase);
    CHECK(e2 != ESP_OK || phase == OTA_JOURNAL_PHASE_NONE,
          "scenario I2: journal converges (clears) once cleanup succeeds again");
  }

  if (g_failures) {
    printf("\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nall checks passed\n");
  return 0;
}
