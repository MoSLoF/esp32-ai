// R5-01 behavioral regression test: replay recovery must not reopen a
// closed replay window -- neither a retired (superseded) epoch, nor a
// previously-used sequence number within the sender's CURRENT epoch.
//
// This compiles and executes the ACTUAL crypto_peer.h replay state machine
// (via the ESP-IDF/Arduino stubs in stubs/) rather than re-implementing its
// logic -- a fix or regression in the real firmware source shows up here.
// Time and NVS are test-controlled (see stubs/esp_timer.h, stubs/nvs.h) so
// multi-epoch, multi-reboot attack sequences -- and NVS fault injection
// (stubs/nvs.h's host_nvs_fault) -- can be reproduced deterministically
// without real delays or hardware.
//
// Reassessment attack sequence (R5-01, HIGH, original finding):
//   A sender progresses through epochs A, B, C, D, E. After the retired
//   ring (old design: 4 entries) fills and 30s of silence pass, the ring
//   FIFO-evicts A. An attacker then replays a frame captured under epoch A,
//   and after the ordinary new-epoch silence period, epoch A is accepted
//   again -- reopening its replay window. (Fixed by a persistent monotonic
//   epoch with no bounded/evictable history -- see the epoch-transition
//   scenarios below.)
//
// Verification-memo finding (R5-01, HIGH, on top of that fix):
//   The fix above persisted each sender's EPOCH floor (mac+epoch) across a
//   receiver reboot, but never persisted last_seq -- crypto_init() reset it
//   to 0 every boot. So a captured frame from the sender's CURRENT (still
//   valid, not retired) epoch, with any seq > 0, was accepted again
//   immediately after a receiver-only reboot: seq > last_seq(0) trivially
//   passes. Repro: accept (mac M, epoch 20, seq 50); reboot receiver only
//   (sender stays at epoch 20); replay the exact captured (epoch=20,
//   seq=50) frame first; it was accepted again. Fixed by persisting a
//   durable seq WATERMARK ("accepted_through") per sender, reserved ahead
//   of the live seq in chunks of CRYPTO_SEQ_WINDOW, and restoring last_seq
//   from that watermark (not 0) on load -- see the same-epoch scenarios
//   below.
//
// Build: gcc -std=c11 -I stubs -o /tmp/crypto_replay_test crypto_replay_test.c
// Run:   /tmp/crypto_replay_test   (exit 0 = pass, non-zero = fail)

#define CRYPTO_PSK "host-behavioral-test-psk-not-for-production"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// ---- minimal Arduino Serial shim (crypto_peer.h assumes it's already in
// scope, as it would be via the real Arduino.h in the .ino build) ----------
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

#include "../esp32_p4/crypto_peer.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { \
  if (!(cond)) { printf("  FAIL: %s\n", msg); g_failures++; } \
  else { printf("  ok:   %s\n", msg); } \
} while (0)

// Builds and signs a minimal test frame (type 0x02, no payload) under the
// given epoch/seq using the real crypto_envelope.h sign path, so verify()
// exercises genuine HMAC checks, not a shortcut.
static int sign_test_frame(uint8_t *frame, uint32_t epoch, uint32_t seq,
                            const uint8_t *sender_mac) {
  frame[0] = 0x02;
  return crypto_env_sign(_crypto_psk, sender_mac, frame, 1, epoch, seq);
}

int main(void) {
  // Each scenario below uses a MAC distinct from every other scenario's --
  // R5-01's persisted per-MAC floor/watermark means any frame accepted in
  // one scenario would otherwise establish state that a later scenario's
  // own fresh-start assumptions collide with.
  static const uint8_t SANITY_MAC[6]        = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const uint8_t SENDER_MAC[6]        = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01};
  static const uint8_t SAMEEPOCH_MAC[6]     = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02};
  static const uint8_t FAULT_WATERMARK_MAC[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x04};

  printf("=== R5-01: replay recovery must not reopen a closed replay window ===\n");

  // Sanity: envelope sign/verify round-trips before we rely on it below.
  {
    CHECK(crypto_init(), "sanity: crypto_init() succeeds with healthy NVS");
    uint8_t frame[32];
    int len = sign_test_frame(frame, 1, 0, SANITY_MAC);
    int vlen = crypto_verify(SANITY_MAC, frame, len);
    CHECK(vlen == 1, "sanity: a validly-signed first frame is accepted");
  }

  // ---- Attack sequence: retired-epoch replay (original R5-01 finding) --
  // Simulate the sender progressing through epochs A..F (six boots),
  // each separated by more than the epoch-silence period. This exceeds
  // the old design's 4-entry retired ring by two full generations.
  host_mock_time_us = 0;
  CHECK(crypto_init(), "attack sequence: crypto_init() succeeds");

  uint32_t epoch_A = 0;
  uint8_t frame_A[32];
  int frame_A_len = 0;

  const int64_t SILENCE = 6 * 1000000; // > CRYPTO_EPOCH_SILENCE_US (5s)
  const int64_t RECOVERY_SILENCE = 31 * 1000000; // > old 30s recovery threshold

  for (int gen = 0; gen < 6; gen++) {
    host_mock_time_us += SILENCE;
    uint32_t epoch = (uint32_t)(gen + 1); // monotonic, as crypto_next_persistent_epoch() would produce
    uint8_t frame[32];
    int len = sign_test_frame(frame, epoch, 0, SENDER_MAC);
    int vlen = crypto_verify(SENDER_MAC, frame, len);
    char label[64];
    snprintf(label, sizeof(label), "epoch #%d (value %u) accepted when first seen", gen, epoch);
    CHECK(vlen == 1, label);
    if (gen == 0) {
      epoch_A = epoch;
      frame_A_len = sign_test_frame(frame_A, epoch, 0, SENDER_MAC);
    }
  }

  // Wait out a long recovery-style silence window (what the old design's
  // FIFO-eviction recovery path required) and then replay the captured
  // epoch-A frame.
  host_mock_time_us += RECOVERY_SILENCE;
  {
    int vlen = crypto_verify(SENDER_MAC, frame_A, frame_A_len);
    CHECK(vlen == 0,
          "captured epoch-A frame is rejected after 5 later epochs + recovery-length silence");
  }

  // A fresh attempt at epoch A with a NEW sequence number must also be
  // rejected -- not just literal replay of the same bytes, but the epoch
  // value itself must be permanently unusable.
  {
    uint8_t frame[32];
    int len = sign_test_frame(frame, epoch_A, 999, SENDER_MAC);
    int vlen = crypto_verify(SENDER_MAC, frame, len);
    CHECK(vlen == 0, "epoch A is rejected even with a fresh sequence number");
  }

  // Push through many more epoch transitions and long silences -- the
  // permanent-rejection property must hold no matter how much further
  // time and epoch churn elapses (this is what "the old FIFO ring
  // eventually re-admits it" looked like).
  for (int gen = 6; gen < 20; gen++) {
    host_mock_time_us += RECOVERY_SILENCE;
    uint32_t epoch = (uint32_t)(gen + 1);
    uint8_t frame[32];
    int len = sign_test_frame(frame, epoch, 0, SENDER_MAC);
    crypto_verify(SENDER_MAC, frame, len);
  }
  host_mock_time_us += RECOVERY_SILENCE;
  {
    int vlen = crypto_verify(SENDER_MAC, frame_A, frame_A_len);
    CHECK(vlen == 0,
          "captured epoch-A frame remains rejected after 19 later epochs and extended silence");
  }

  // ---- Simulated RECEIVER restart -- attacker wins the race ------------
  // The in-RAM replay slot is cleared on every crypto_init() call, exactly
  // as it would be on a real reboot. Without persisting each sender's
  // epoch floor across that reboot, a captured old-epoch frame arriving
  // FIRST after the receiver restarts would be treated as a fresh "first
  // sighting" and accepted -- fully reopening the window this fix exists
  // to close, via nothing more than an ordinary receiver reboot (crash,
  // brownout, watchdog reset, OTA reboot -- all routine). This is the
  // adversarial ordering: the attacker's captured frame is presented
  // BEFORE any fresh legitimate frame re-establishes the floor.
  CHECK(crypto_init(), "receiver reboot: crypto_init() succeeds"); // receiver "reboots"
  {
    int vlen = crypto_verify(SENDER_MAC, frame_A, frame_A_len);
    CHECK(vlen == 0,
          "receiver reboot: captured epoch-A frame is REJECTED even as the very first "
          "frame seen post-reboot (persisted floor, not just in-RAM state)");
  }
  // A fresh, higher-epoch frame from the real sender must still work.
  {
    uint32_t epoch_new = 100;
    uint8_t frame[32];
    int len = sign_test_frame(frame, epoch_new, 0, SENDER_MAC);
    int vlen = crypto_verify(SENDER_MAC, frame, len);
    CHECK(vlen == 1, "receiver reboot: a genuinely fresh, higher epoch is still accepted");
  }
  // And a SECOND and THIRD receiver reboot must persist that advanced
  // floor too -- and, per the pattern above, the attacker's frame is
  // presented first each time, not just on the first reboot.
  CHECK(crypto_init(), "second receiver reboot: crypto_init() succeeds");
  {
    uint32_t epoch_between = 50; // > A(1), but < 100 -- still retired relative to the new floor
    uint8_t frame[32];
    int len = sign_test_frame(frame, epoch_between, 0, SENDER_MAC);
    int vlen = crypto_verify(SENDER_MAC, frame, len);
    CHECK(vlen == 0,
          "second receiver reboot: floor keeps advancing correctly, "
          "an epoch below the latest persisted floor is still rejected");
  }
  CHECK(crypto_init(), "third receiver reboot: crypto_init() succeeds");
  {
    int vlen = crypto_verify(SENDER_MAC, frame_A, frame_A_len);
    CHECK(vlen == 0,
          "third receiver reboot: original captured epoch-A frame, presented "
          "first again, is still rejected");
  }

  // ---- Same-epoch replay across a receiver reboot (verification-memo ---
  // ---- finding, the core bug this round closes) ------------------------
  CHECK(crypto_init(), "same-epoch scenario: crypto_init() succeeds");
  uint8_t frame_seq50[32];
  int frame_seq50_len = 0;
  {
    host_mock_time_us += SILENCE;
    uint8_t frame[32];
    int len = sign_test_frame(frame, 20, 50, SAMEEPOCH_MAC);
    int vlen = crypto_verify(SAMEEPOCH_MAC, frame, len);
    CHECK(vlen == 1, "same-epoch: (epoch=20, seq=50) accepted as the sender's first frame");
    frame_seq50_len = sign_test_frame(frame_seq50, 20, 50, SAMEEPOCH_MAC);
  }
  CHECK(crypto_init(), "same-epoch: receiver reboot succeeds (sender stays at epoch 20)");
  {
    int vlen = crypto_verify(SAMEEPOCH_MAC, frame_seq50, frame_seq50_len);
    CHECK(vlen == 0,
          "same-epoch: captured (epoch=20, seq=50) frame is REJECTED as the very "
          "first frame processed after reboot -- the exact verification-memo repro");
  }
  {
    // Boundary: seq=51 is inside the reserved window (accepted_through was
    // set to 50+CRYPTO_SEQ_WINDOW when seq=50 was first accepted), so it's
    // also rejected -- the documented, bounded post-reboot tradeoff, not a
    // separate bug. A genuinely fresh frame just past the watermark (below)
    // proves this doesn't block the sender forever.
    uint8_t frame[32];
    int len = sign_test_frame(frame, 20, 51, SAMEEPOCH_MAC);
    int vlen = crypto_verify(SAMEEPOCH_MAC, frame, len);
    CHECK(vlen == 0,
          "same-epoch: seq=51 (inside the reserved window) is also rejected post-reboot "
          "-- expected, bounded tradeoff, not unbounded denial of service");
  }
  {
    // Liveness: a seq beyond the persisted watermark (50 + CRYPTO_SEQ_WINDOW)
    // must be accepted -- the live sender isn't permanently locked out.
    uint32_t seq_beyond = 50 + CRYPTO_SEQ_WINDOW + 5;
    uint8_t frame[32];
    int len = sign_test_frame(frame, 20, seq_beyond, SAMEEPOCH_MAC);
    int vlen = crypto_verify(SAMEEPOCH_MAC, frame, len);
    CHECK(vlen == 1,
          "same-epoch: seq beyond the reserved window is accepted -- liveness preserved");
    // And THAT accepted seq, replayed again, must be rejected (ordinary
    // same-session replay, now also durably watermarked since accepting it
    // triggered a fresh persist).
    int vlen2 = crypto_verify(SAMEEPOCH_MAC, frame, len);
    CHECK(vlen2 == 0,
          "same-epoch: the just-accepted seq is rejected on replay");
  }

  // ---- Persistence-failure fault injection: epoch-counter allocation ---
  {
    uint32_t before_fault;
    CHECK(crypto_next_persistent_epoch(&before_fault),
          "fault injection (epoch): baseline allocation succeeds");

    host_nvs_fault_reset();
    host_nvs_fault.nvs_open_n = -1;
    strncpy(host_nvs_fault.only_ns, "crypto_ep", sizeof(host_nvs_fault.only_ns) - 1);

    uint32_t during_fault = 0xDEADBEEF; // sentinel: must stay unwritten on failure
    bool ok_epoch = crypto_next_persistent_epoch(&during_fault);
    CHECK(!ok_epoch, "fault injection (epoch): allocation fails closed when the "
                     "epoch-counter NVS namespace can't be opened (no random-epoch fallback)");
    CHECK(during_fault == 0xDEADBEEF,
          "fault injection (epoch): out-param is left untouched on failure, not "
          "silently filled with a random/garbage value");

    bool ok_init = crypto_init();
    CHECK(!ok_init, "fault injection (epoch): crypto_init() itself also fails closed "
                    "under the same fault (no random-epoch fallback anywhere in the init path)");

    host_nvs_fault_reset();
    // Recovery: a subsequent healthy allocation must be strictly greater
    // than the pre-fault baseline -- proving the counter kept advancing
    // monotonically (or at least never went backward/random) through the
    // failure, not that it silently reset or was replaced by esp_random().
    uint32_t after_fault;
    CHECK(crypto_next_persistent_epoch(&after_fault),
          "fault injection (epoch): allocation recovers once NVS is healthy again");
    CHECK(after_fault > before_fault,
          "fault injection (epoch): post-recovery epoch is strictly greater than the "
          "pre-fault baseline -- monotonicity held through the failure");
  }

  // ---- Persistence-failure fault injection: mid-session watermark ------
  // ---- advance must fail closed, not accept-then-fail-silently ---------
  {
    host_nvs_fault_reset();
    CHECK(crypto_init(), "fault injection (watermark): crypto_init() succeeds");
    uint8_t frame[32];
    int len = sign_test_frame(frame, 5, 0, FAULT_WATERMARK_MAC);
    int vlen = crypto_verify(FAULT_WATERMARK_MAC, frame, len);
    CHECK(vlen == 1, "fault injection (watermark): first frame (seq=0) establishes the floor");

    // Force the seq to cross the persisted watermark (0 + CRYPTO_SEQ_WINDOW)
    // while NVS blob writes are failing.
    host_nvs_fault.nvs_set_blob_n = 1;
    strncpy(host_nvs_fault.only_ns, "crypto_floor", sizeof(host_nvs_fault.only_ns) - 1);
    uint32_t seq_crossing = CRYPTO_SEQ_WINDOW + 1;
    uint8_t frame2[32];
    int len2 = sign_test_frame(frame2, 5, seq_crossing, FAULT_WATERMARK_MAC);
    int vlen2 = crypto_verify(FAULT_WATERMARK_MAC, frame2, len2);
    CHECK(vlen2 == 0,
          "fault injection (watermark): frame crossing the watermark is REJECTED "
          "when the persist fails -- not accepted on RAM-only state");

    host_nvs_fault_reset();
    int vlen3 = crypto_verify(FAULT_WATERMARK_MAC, frame2, len2);
    CHECK(vlen3 == 1,
          "fault injection (watermark): the identical frame is accepted once NVS "
          "recovers -- proving the earlier rejection didn't corrupt RAM state");
  }

  // ---- Persistent monotonic epoch survives a sender reboot -------------
  // This is the actual R5-01 fix: crypto_next_persistent_epoch() must
  // never hand out the same or a lower value across repeated boots,
  // because it's backed by a persistent (NVS-style) boot counter, not
  // esp_random() -- and must fail (not fall back to random) if it can't be
  // durably allocated.
  {
    uint32_t e1, e2, e3;
    CHECK(crypto_next_persistent_epoch(&e1), "epoch alloc 1 succeeds");
    CHECK(crypto_next_persistent_epoch(&e2), "epoch alloc 2 succeeds");
    CHECK(crypto_next_persistent_epoch(&e3), "epoch alloc 3 succeeds");
    CHECK(e2 > e1 && e3 > e2,
          "crypto_next_persistent_epoch() is strictly increasing across repeated boots");
  }

  if (g_failures) {
    printf("\n%d check(s) FAILED\n", g_failures);
    return 1;
  }
  printf("\nall checks passed\n");
  return 0;
}
