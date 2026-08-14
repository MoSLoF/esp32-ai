// R5-01 behavioral regression test: the SENDER's replay/epoch state
// machine (firmware/espnow_sender/sender_replay.h) must match
// crypto_peer.h's receiver-side guarantees exactly.
//
// Verification-memo finding (on top of the original R5-01 fix): the
// verification memo's finding was about the RECEIVER (P4) side, but the
// sender had the identical class of bug -- actually worse, since before
// this round the sender persisted NO epoch floor at all for its peer
// (_sender_replay[] was only memset, never saved/reloaded). This test
// mirrors crypto_replay_test.c's scenarios against sender_replay_check()
// directly (no HMAC envelope needed -- that function takes already-
// verified mac/epoch/seq, matching how on_rx() calls it after
// crypto_env_verify() succeeds).
//
// Build: gcc -std=c11 -I stubs -I ../espnow_sender -o /tmp/sender_replay_test sender_replay_test.c
// Run:   /tmp/sender_replay_test   (exit 0 = pass, non-zero = fail)

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

#include "arduino_millis.h"
#include "../espnow_sender/sender_replay.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("  FAIL: %s\n", msg); g_failures++; } \
  else { printf("  ok:   %s\n", msg); } \
} while (0)

int main(void) {
  static const uint8_t PEER_MAC[6]        = {0x10, 0x20, 0x30, 0x00, 0x00, 0x01};
  static const uint8_t RETIRED_MAC[6]     = {0x10, 0x20, 0x30, 0x00, 0x00, 0x02};
  static const uint8_t SAMEEPOCH_MAC[6]   = {0x10, 0x20, 0x30, 0x00, 0x00, 0x03};
  static const uint8_t FAULT_WATERMARK_MAC[6] = {0x10, 0x20, 0x30, 0x00, 0x00, 0x04};

  printf("=== R5-01: sender-side replay must not reopen a closed replay window ===\n");

  // ---- Sanity ------------------------------------------------------
  {
    CHECK(sender_replay_init(), "sanity: sender_replay_init() succeeds with healthy NVS");
    CHECK(sender_replay_check(PEER_MAC, 1, 0), "sanity: first frame from a peer is accepted");
  }

  // ---- Retired-epoch replay must be rejected forever, across reboots --
  host_mock_millis = 0;
  CHECK(sender_replay_init(), "retired-epoch: sender_replay_init() succeeds");
  {
    CHECK(sender_replay_check(RETIRED_MAC, 1, 0), "retired-epoch: epoch 1 accepted as first sighting");
    for (int gen = 2; gen <= 6; gen++) {
      host_mock_millis += 6000; // > SENDER_EPOCH_SILENCE_MS
      CHECK(sender_replay_check(RETIRED_MAC, (uint32_t)gen, 0),
            "retired-epoch: later epoch accepted");
    }
    // Captured epoch-1 frame must be rejected, both immediately and across
    // a simulated sender reboot.
    CHECK(!sender_replay_check(RETIRED_MAC, 1, 0),
          "retired-epoch: epoch 1 rejected after 5 later epochs");
    CHECK(sender_replay_init(), "retired-epoch: sender reboot succeeds");
    CHECK(!sender_replay_check(RETIRED_MAC, 1, 0),
          "retired-epoch: epoch 1 still rejected as the first frame after reboot");
  }

  // ---- Same-epoch replay across a sender reboot (the core fix) --------
  CHECK(sender_replay_init(), "same-epoch: sender_replay_init() succeeds");
  CHECK(sender_replay_check(SAMEEPOCH_MAC, 20, 50), "same-epoch: (epoch=20, seq=50) accepted first");
  CHECK(sender_replay_init(), "same-epoch: sender reboot succeeds (peer stays at epoch 20)");
  CHECK(!sender_replay_check(SAMEEPOCH_MAC, 20, 50),
        "same-epoch: captured (epoch=20, seq=50) rejected as the very first frame post-reboot");
  CHECK(!sender_replay_check(SAMEEPOCH_MAC, 20, 51),
        "same-epoch: seq=51 (inside the reserved window) also rejected post-reboot -- "
        "expected, bounded tradeoff");
  {
    uint32_t seq_beyond = 50 + SENDER_SEQ_WINDOW + 5;
    CHECK(sender_replay_check(SAMEEPOCH_MAC, 20, seq_beyond),
          "same-epoch: seq beyond the reserved window is accepted -- liveness preserved");
    CHECK(!sender_replay_check(SAMEEPOCH_MAC, 20, seq_beyond),
          "same-epoch: the just-accepted seq is rejected on replay");
  }

  // ---- Fault injection: epoch-counter allocation -----------------------
  {
    uint32_t before_fault;
    CHECK(sender_next_persistent_epoch(&before_fault),
          "fault injection (epoch): baseline allocation succeeds");

    host_nvs_fault_reset();
    host_nvs_fault.nvs_open_n = -1;
    strncpy(host_nvs_fault.only_ns, "crypto_ep", sizeof(host_nvs_fault.only_ns) - 1);

    uint32_t during_fault = 0xDEADBEEF;
    CHECK(!sender_next_persistent_epoch(&during_fault),
          "fault injection (epoch): allocation fails closed (no random-epoch fallback)");
    CHECK(during_fault == 0xDEADBEEF,
          "fault injection (epoch): out-param untouched on failure");

    host_nvs_fault_reset();
    uint32_t after_fault;
    CHECK(sender_next_persistent_epoch(&after_fault),
          "fault injection (epoch): allocation recovers once NVS is healthy again");
    CHECK(after_fault > before_fault,
          "fault injection (epoch): post-recovery epoch is strictly greater than baseline");
  }

  // ---- Fault injection: mid-session watermark advance must fail closed -
  {
    host_nvs_fault_reset();
    CHECK(sender_replay_init(), "fault injection (watermark): sender_replay_init() succeeds");
    CHECK(sender_replay_check(FAULT_WATERMARK_MAC, 5, 0),
          "fault injection (watermark): first frame establishes the floor");

    host_nvs_fault.nvs_set_blob_n = 1;
    strncpy(host_nvs_fault.only_ns, "sender_floor", sizeof(host_nvs_fault.only_ns) - 1);
    uint32_t seq_crossing = SENDER_SEQ_WINDOW + 1;
    CHECK(!sender_replay_check(FAULT_WATERMARK_MAC, 5, seq_crossing),
          "fault injection (watermark): frame crossing the watermark rejected when persist fails");

    host_nvs_fault_reset();
    CHECK(sender_replay_check(FAULT_WATERMARK_MAC, 5, seq_crossing),
          "fault injection (watermark): identical frame accepted once NVS recovers");
  }

  if (g_failures) {
    printf("\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nall checks passed\n");
  return 0;
}
