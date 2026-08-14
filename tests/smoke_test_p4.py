#!/usr/bin/env python3
"""
Smoke test for ESP32-P4 firmware feature flags.

Validates that the firmware source compiles (structurally) with each
feature-flag combination by parsing the preprocessor logic and checking
that all referenced headers, symbols, and guard patterns are consistent.

This is a static analysis test — it doesn't require hardware or the
ESP-IDF toolchain. It catches:
  - Missing headers for enabled features
  - Unguarded references to feature-specific symbols
  - Broken #if/#endif nesting
  - Circular or missing include dependencies
  - Feature flag combinations that would fail at compile time

Usage:
    python tests/smoke_test_p4.py
    python -m pytest tests/smoke_test_p4.py -v
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FIRMWARE_DIR = Path(__file__).parent.parent / "firmware" / "esp32_p4"
COMMON_DIR = Path(__file__).parent.parent / "firmware" / "common"
SENDER_DIR = Path(__file__).parent.parent / "firmware" / "espnow_sender"
HOST_VERIFY_DIR = Path(__file__).parent.parent / "firmware" / "host_verify"

# All feature flags and their required headers.
FEATURE_FLAGS = {
    "USE_DISPLAY":       "display.h",
    "USE_ESPNOW":        "espnow_comm.h",
    "USE_PEER_PROTOCOL": "peer_protocol.h",
    "USE_OTA":           "ota_espnow.h",
    "USE_SD":            "sd_config.h",
    "USE_MESH":          "mesh_relay.h",
    "USE_CRYPTO":        "crypto_peer.h",
    "USE_COMPANION":     "companion_uart.h",
}

# Headers that each feature header depends on (transitive).
HEADER_DEPS = {
    "peer_protocol.h": ["espnow_comm.h", "peer_identity.h"],
    "ota_espnow.h":    ["espnow_comm.h"],
    "sd_config.h":     ["sd_card.h"],
    "mesh_relay.h":    ["espnow_comm.h"],
}

# Symbols that must only appear inside their feature guard.
GUARDED_SYMBOLS = {
    "_pr.":           "USE_PEER_PROTOCOL",
    "_pr_peers":      "USE_PEER_PROTOCOL",
    "peer_init":      "USE_PEER_PROTOCOL",
    "peer_tick":      "USE_PEER_PROTOCOL",
    "peer_print_status": "USE_PEER_PROTOCOL",
    "persona()":      "USE_PEER_PROTOCOL",
    "persona_boot":   "USE_PEER_PROTOCOL",
    "persona_select": "USE_PEER_PROTOCOL",
    "sd_begin":       "USE_SD",
    "sd_setup":       "USE_SD",
    "sd_list_dir":    "USE_SD",
    "sd_load_name":   "USE_SD",
    "sd_dump_log":    "USE_SD",
    "sd_provision":   "USE_SD",
    "sd_save_stats":  "USE_SD",
    "display_begin":  "USE_DISPLAY",
    "display_puts":   "USE_DISPLAY",
    "display_stats":  "USE_DISPLAY",
    "display_status": "USE_DISPLAY",
    "display_persona":"USE_DISPLAY",
    "espnow_begin":   "USE_ESPNOW",
    "espnow_send_token": "USE_ESPNOW",
    "ota_init":       "USE_OTA",
    "ota_tick":       "USE_OTA",
    "mesh_init":      "USE_MESH",
    "crypto_init":    "USE_CRYPTO",
    "espnow_set_crypto": "USE_CRYPTO",
    "companion_begin":"USE_COMPANION",
    "companion_tick": "USE_COMPANION",
}


def read_file(name):
    path = FIRMWARE_DIR / name
    if not path.exists():
        return None
    return path.read_text()


def test_all_headers_exist():
    """Every feature flag's header file must exist."""
    missing = []
    for flag, header in FEATURE_FLAGS.items():
        if not (FIRMWARE_DIR / header).exists():
            missing.append(f"{flag} -> {header}")
    assert not missing, f"Missing headers: {missing}"


def test_header_dependencies_exist():
    """Transitive header dependencies must exist."""
    missing = []
    for header, deps in HEADER_DEPS.items():
        for dep in deps:
            if not (FIRMWARE_DIR / dep).exists():
                missing.append(f"{header} depends on {dep}")
    assert not missing, f"Missing dependencies: {missing}"


def test_include_guards():
    """Every .h file must have a proper include guard."""
    bad = []
    for h in FIRMWARE_DIR.glob("*.h"):
        content = h.read_text()
        name = h.stem.upper() + "_H"
        if f"#ifndef {name}" not in content:
            bad.append(f"{h.name}: missing #ifndef {name}")
        if f"#define {name}" not in content:
            bad.append(f"{h.name}: missing #define {name}")
        if "#endif" not in content:
            bad.append(f"{h.name}: missing #endif")
    assert not bad, "\n".join(bad)


def test_if_endif_balance():
    """#if/#ifdef/#ifndef must match #endif in every file."""
    for f in list(FIRMWARE_DIR.glob("*.h")) + list(FIRMWARE_DIR.glob("*.ino")):
        content = f.read_text()
        opens = len(re.findall(r'^\s*#\s*(?:if|ifdef|ifndef)\b', content, re.M))
        closes = len(re.findall(r'^\s*#\s*endif\b', content, re.M))
        assert opens == closes, (
            f"{f.name}: {opens} #if vs {closes} #endif"
        )


def test_ino_feature_flags_defined():
    """The .ino must define all feature flags."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None, "esp32_p4.ino not found"
    for flag in FEATURE_FLAGS:
        assert re.search(rf'#define\s+{flag}\s+', ino), (
            f"{flag} not defined in esp32_p4.ino"
        )


def test_ino_conditional_includes():
    """Each feature's header must be included under its guard."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    for flag, header in FEATURE_FLAGS.items():
        # FR-01: ota_espnow.h and ota_verify.h share one #if USE_OTA block.
        if header == "ota_espnow.h":
            pattern = rf'#if\s+{flag}\b.*?#include\s+"{header}"'
            assert re.search(pattern, ino, re.DOTALL), (
                f'{header} not conditionally included under {flag}'
            )
        else:
            pattern = rf'#if\s+{flag}\s*\n\s*#include\s+"{header}"'
            assert re.search(pattern, ino), (
                f'{header} not conditionally included under {flag}'
            )


def test_guarded_symbols_in_ino():
    """Feature-specific symbols in the .ino must appear inside guards."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None

    # Build a map of which lines are inside which guards.
    guard_stack = []
    line_guards = {}
    for i, line in enumerate(ino.split('\n'), 1):
        stripped = line.strip()
        m = re.match(r'#\s*if\b\s*(.*)', stripped)
        if m:
            guard_stack.append(m.group(1).strip())
        elif re.match(r'#\s*elif\b\s*(.*)', stripped):
            if guard_stack:
                guard_stack[-1] = re.match(r'#\s*elif\b\s*(.*)', stripped).group(1).strip()
        elif re.match(r'#\s*else\b', stripped):
            if guard_stack:
                guard_stack[-1] = "!" + guard_stack[-1]
        elif re.match(r'#\s*endif\b', stripped):
            if guard_stack:
                guard_stack.pop()

        line_guards[i] = list(guard_stack)

    errors = []
    for i, line in enumerate(ino.split('\n'), 1):
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
        for sym, required_flag in GUARDED_SYMBOLS.items():
            if sym in line:
                guards = line_guards.get(i, [])
                guard_str = ' '.join(guards)
                if required_flag not in guard_str:
                    errors.append(
                        f"line {i}: '{sym}' requires {required_flag} "
                        f"guard (active: {guards})"
                    )

    assert not errors, "Unguarded symbols:\n" + "\n".join(errors[:20])


def test_espnow_auto_enable():
    """USE_PEER_PROTOCOL/USE_OTA/USE_MESH must auto-enable USE_ESPNOW."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert re.search(
        r'#if\s+\(USE_PEER_PROTOCOL\s*\|\|\s*USE_OTA\s*\|\|\s*USE_MESH\)',
        ino
    ), "Auto-enable guard must include USE_MESH"


def test_peer_protocol_sd_challenge_integration():
    """peer_protocol.h should use SD challenges when USE_SD is defined."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    assert "sd_challenge_count" in pp, (
        "peer_protocol.h should reference sd_challenge_count for SD integration"
    )
    assert "sd_challenge(" in pp, (
        "peer_protocol.h should call sd_challenge() for SD-loaded challenges"
    )


def test_mesh_relay_frame_type():
    """mesh_relay.h must use frame type 0x10 (above peer/OTA range)."""
    mesh = read_file("mesh_relay.h")
    assert mesh is not None
    assert "0x10" in mesh, "Mesh relay frame type should be 0x10"
    assert "ESPNOW_MSG_RELAY" in mesh


def test_crypto_hmac():
    """crypto_peer.h must use HMAC-SHA256 via shared crypto_envelope.h."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "crypto_envelope.h" in crypto, (
        "crypto_peer.h must include shared crypto_envelope.h"
    )
    assert "crypto_sign" in crypto
    assert "crypto_verify" in crypto


def test_companion_uart_json():
    """companion_uart.h must send JSON messages on Serial1."""
    comp = read_file("companion_uart.h")
    assert comp is not None
    assert "Serial1" in comp
    assert '{"t":' in comp
    assert "companion_begin" in comp
    assert "companion_tick" in comp
    assert "companion_send_status" in comp
    assert "companion_send_token" in comp


def test_display_zones():
    """display.h must define top/mid/bot zone layout."""
    disp = read_file("display.h")
    assert disp is not None
    assert "ZONE_TOP_ROWS" in disp
    assert "ZONE_MID_ROWS" in disp
    assert "ZONE_BOT_ROWS" in disp
    assert "ZONE_BOT_START" in disp
    assert "display_puts" in disp
    assert "display_flush" in disp


def test_generate_command():
    """The .ino must support 'generate' and 'generate N' serial commands."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert 'cmd == "generate"' in ino or "cmd == \"generate\"" in ino
    assert 'cmd.startsWith("generate ")' in ino


def test_help_command():
    """The .ino must have a 'help' serial command."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert 'cmd == "help"' in ino


def test_run_generate_function():
    """run_generate() must exist as the shared inference entry point."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "run_generate(" in ino
    count = ino.count("run_generate(")
    assert count >= 3, (
        f"run_generate should be called in setup, generate cmd, and companion "
        f"callback (found {count} references)"
    )


def test_no_duplicate_frame_types():
    """Frame type constants must not collide across headers."""
    frame_types = {}
    for h in FIRMWARE_DIR.glob("*.h"):
        content = h.read_text()
        for m in re.finditer(r'#define\s+(ESPNOW_MSG_\w+)\s+(0x[0-9A-Fa-f]+)', content):
            name, val = m.group(1), m.group(2)
            val_int = int(val, 16)
            if val_int in frame_types and frame_types[val_int][0] != name:
                assert False, (
                    f"Frame type collision: {name}={val} in {h.name} "
                    f"vs {frame_types[val_int][0]}={val} in {frame_types[val_int][1]}"
                )
            frame_types[val_int] = (name, h.name)


def test_sd_card_pin_defaults():
    """sd_card.h must define all SDMMC pin defaults."""
    sd = read_file("sd_card.h")
    assert sd is not None
    for pin in ["SD_PIN_CLK", "SD_PIN_CMD", "SD_PIN_D0", "SD_PIN_D1",
                "SD_PIN_D2", "SD_PIN_D3"]:
        assert pin in sd, f"Missing {pin} in sd_card.h"


def test_companion_rx_commands():
    """companion_uart.h must handle all documented RX commands."""
    comp = read_file("companion_uart.h")
    assert comp is not None
    for cmd in ["status", "prompt", "generate", "identity", "peers"]:
        assert f'"{cmd}"' in comp, f"Missing RX command '{cmd}' in companion_uart.h"


def test_mesh_anti_loop():
    """mesh_relay.h must have anti-loop dedup logic."""
    mesh = read_file("mesh_relay.h")
    assert mesh is not None
    assert "MESH_SEEN_SIZE" in mesh
    assert "_mesh_is_seen" in mesh
    assert "_mesh_mark_seen" in mesh


def test_crypto_replay_protection():
    """crypto_peer.h must have epoch-based replay protection (EA-06)."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "CRYPTO_REPLAY_SLOTS" in crypto, (
        "crypto_peer.h must have per-sender replay slot tracking"
    )
    assert "_crypto_epoch" in crypto, (
        "crypto_peer.h must use boot epoch for session tracking"
    )
    assert "esp_random" in crypto, (
        "crypto_peer.h must generate epoch via esp_random()"
    )


def test_crypto_wired_to_espnow():
    """Crypto sign/verify must be wired into ESP-NOW via hooks."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "espnow_set_crypto" in ino, (
        "esp32_p4.ino must call espnow_set_crypto to wire crypto into ESP-NOW"
    )
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "espnow_set_crypto" in en
    assert "espnow_send_secure" in en
    assert "_espnow_verify_fn" in en


def test_extension_frames_use_secure_send():
    """Peer protocol, OTA, and mesh TX must use espnow_send_secure."""
    for header in ["peer_protocol.h", "ota_espnow.h", "mesh_relay.h"]:
        content = read_file(header)
        assert content is not None, f"{header} not found"
        assert "espnow_send_secure" in content, (
            f"{header} must use espnow_send_secure for signed frame TX"
        )


def test_mesh_rejects_nested_relay():
    """mesh_relay.h must reject nested relay frames to prevent stack overflow."""
    mesh = read_file("mesh_relay.h")
    assert mesh is not None
    assert "_mesh_dispatching" in mesh, (
        "mesh_relay.h must have re-entrant dispatch guard"
    )


def test_companion_json_escaping():
    """All companion TX functions must escape string params with _comp_esc."""
    comp = read_file("companion_uart.h")
    assert comp is not None
    for fn in ["companion_send_status", "companion_send_event",
               "companion_send_peer"]:
        start = comp.index(fn + "(")
        block = comp[start:comp.index("\n}\n", start)]
        assert "_comp_esc(" in block, (
            f"{fn} must escape string params with _comp_esc()"
        )


def test_sd_cat_path_traversal():
    """The 'cat' command must reject paths containing '..'."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert '".."' in ino or "'..' " in ino or 'indexOf("..")' in ino, (
        "cat command must check for path traversal (..)"
    )


def test_ota_offer_cooldown():
    """OTA must have a cooldown between offer acceptance."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    assert "OTA_OFFER_COOLDOWN" in ota, (
        "ota_espnow.h must define OTA_OFFER_COOLDOWN"
    )
    assert "last_offer_time" in ota, (
        "ota_espnow.h must track last offer time"
    )


def test_peer_table_eviction():
    """Peer table must evict stale peers when full."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    assert "victim" in pp or "evict" in pp, (
        "peer_protocol.h must have peer eviction logic"
    )


def test_sd_csv_sanitize():
    """SD log functions must sanitize CSV fields."""
    sd = read_file("sd_config.h")
    assert sd is not None
    assert "_sd_sanitize_csv" in sd, (
        "sd_config.h must have CSV sanitization function"
    )


def test_sd_without_peer_protocol():
    """sd_config.h must compile without peer_protocol.h (USE_SD=1, USE_PEER_PROTOCOL=0)."""
    sd = read_file("sd_config.h")
    assert sd is not None
    assert "PEER_IDENTITY_H" in sd or "PEER_PROTOCOL_H" in sd, (
        "sd_config.h must guard peer-protocol-specific symbols with include guards"
    )


def test_feature_flag_combos():
    """Feature flag combinations must produce valid configurations (T1)."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None

    # Key combo: USE_PEER_PROTOCOL implies USE_ESPNOW (auto-enable).
    assert re.search(r'USE_PEER_PROTOCOL.*USE_ESPNOW', ino, re.S), (
        "USE_PEER_PROTOCOL must trigger USE_ESPNOW auto-enable"
    )

    # USE_MESH implies USE_ESPNOW.
    assert re.search(r'USE_MESH.*!USE_ESPNOW', ino, re.S), (
        "USE_MESH must trigger USE_ESPNOW auto-enable"
    )

    # USE_CRYPTO + USE_ESPNOW must wire crypto hooks.
    assert "espnow_set_crypto" in ino, "crypto must be wired to ESP-NOW"

    # USE_MESH must wire relay hook.
    assert "espnow_set_relay" in ino, (
        "USE_MESH must wire mesh relay via espnow_set_relay"
    )

    # USE_SD + USE_CRYPTO must support PSK loading.
    assert "crypto_set_psk" in ino or "psk.txt" in ino, (
        "USE_SD + USE_CRYPTO should support SD-based PSK loading"
    )

    # USE_COMPANION + USE_PEER_PROTOCOL must wire peer events.
    assert "peer_on_event" in ino, (
        "USE_COMPANION + USE_PEER_PROTOCOL must wire peer event callback"
    )


def test_no_dead_event_functions():
    """Functions designed for integration must have call sites (T2)."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None

    # companion_send_event must be called (via peer_on_event or directly).
    comp = read_file("companion_uart.h")
    assert comp is not None
    assert "companion_send_event" in comp, "companion_send_event must exist"
    assert "companion_send_event" in ino or "peer_on_event" in ino, (
        "companion_send_event must be wired to peer events in esp32_p4.ino"
    )

    # mesh_send must be wired (via espnow_set_relay or direct call).
    mesh = read_file("mesh_relay.h")
    assert mesh is not None
    assert "mesh_send" in mesh, "mesh_send must exist"
    assert "espnow_set_relay" in ino or "mesh_send" in ino, (
        "mesh_send must be wired via espnow_set_relay in esp32_p4.ino"
    )

    # companion on_prompt callback must be registered.
    assert "companion_on_prompt" in ino, (
        "companion on_prompt callback must be registered in setup()"
    )


def test_nvs_version_key():
    """Firmware must track NVS schema version for migrations (S10)."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "fwver" in ino or "NVS_FW_VERSION" in ino, (
        "esp32_p4.ino must track NVS firmware version for migration"
    )


def test_pin_map_exists():
    """A central pin map header must exist (S9)."""
    pm = read_file("pin_map.h")
    assert pm is not None, "pin_map.h not found"
    assert "SD_PIN_CLK" in pm, "pin_map.h must define SD pin assignments"
    assert "COMPANION_TX_PIN" in pm, "pin_map.h must define companion UART pins"


def test_crypto_replay_per_sender():
    """crypto_peer.h must use per-sender replay tracking (V-05)."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "CRYPTO_REPLAY_SLOTS" in crypto, (
        "crypto_peer.h must have per-sender replay slot tracking"
    )
    assert "_crypto_tx_seq" in crypto, (
        "crypto_peer.h must use monotonic TX sequence counter"
    )


def test_espnow_rate_limiting():
    """espnow_comm.h must rate-limit RX callback per-MAC (EA-07)."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "ESPNOW_RX_LIMIT" in en, (
        "espnow_comm.h must define ESPNOW_RX_LIMIT"
    )
    assert "ESPNOW_RX_MAC_SLOTS" in en, (
        "espnow_comm.h must define per-MAC rate limiting slots"
    )
    assert "_espnow_mac_ratelimit" in en, (
        "espnow_comm.h must have per-MAC rate limit function"
    )
    assert "ESPNOW_RX_GLOBAL_CEIL" in en, (
        "espnow_comm.h must define global rate ceiling"
    )


def test_espnow_prompt_spinlock():
    """espnow_comm.h must use a spinlock for prompt buffer (V-09, V-15)."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "portENTER_CRITICAL" in en, (
        "espnow_comm.h must use portENTER_CRITICAL for prompt buffer"
    )
    assert "_espnow_prompt_mux" in en, (
        "espnow_comm.h must have a spinlock for prompt buffer"
    )


def test_peer_ring_buffers():
    """peer_protocol.h must use ring buffers for RX frames (B3)."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    assert "PEER_RX_RING" in pp, (
        "peer_protocol.h must define PEER_RX_RING for ring buffer size"
    )
    assert "_pri_ring" in pp, "identity ring buffer must exist"
    assert "_prc_ring" in pp, "challenge ring buffer must exist"
    assert "_prr_ring" in pp, "response ring buffer must exist"
    assert "_prv_ring" in pp, "validate ring buffer must exist"


def test_challenge_bank_size():
    """Challenge bank must have >= 8 entries to resist replay (V-12)."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    entries = re.findall(r'^\s*\{[\d,\s]+\}\s*,?\s*$', pp, re.M)
    assert len(entries) >= 8, (
        f"Challenge bank has {len(entries)} entries, need >= 8"
    )


def test_display_frees_fb_on_failure():
    """display.h must free framebuffer on init failure (S6)."""
    disp = read_file("display.h")
    assert disp is not None
    assert "heap_caps_free(_disp_fb)" in disp, (
        "display_begin must free framebuffer on init failure"
    )


def test_display_dcs_init():
    """display.h must send DCS init commands for real panels (S7)."""
    disp = read_file("display.h")
    assert disp is not None
    assert "esp_lcd_panel_io_tx_param" in disp or "dbi_io" in disp, (
        "display_begin must send DCS init commands (sleep out, display on)"
    )


def test_mesh_no_extern_linkage():
    """mesh_relay.h must not use extern for single-TU statics (B6)."""
    mesh = read_file("mesh_relay.h")
    assert mesh is not None
    assert "extern espnow_peer_handler_t" not in mesh, (
        "mesh_relay.h should not use extern for espnow_comm.h statics"
    )
    assert "ESPNOW_COMM_H" in mesh, (
        "mesh_relay.h must guard on ESPNOW_COMM_H being included first"
    )


def test_generate_bounds():
    """Generate command must enforce token count bounds (S11)."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "2000" in ino or "v <= " in ino, (
        "generate N command should cap token count"
    )


def test_crypto_psk_configurable():
    """crypto_peer.h must support runtime PSK override (S12)."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "crypto_set_psk" in crypto, (
        "crypto_peer.h must provide crypto_set_psk() for runtime PSK override"
    )


# ---- EA finding tests (adversarial reassessment) ---------------------------

def test_ea01_ota_manifest_verification():
    """EA-01: OTA must support ECDSA P-256 manifest verification."""
    ov = read_file("ota_verify.h")
    assert ov is not None, "ota_verify.h not found"
    assert "OTA_MANIFEST_MAGIC" in ov, "must define manifest magic"
    assert "mbedtls/pk.h" in ov, "must use mbedtls for ECDSA"
    assert "mbedtls_pk_verify" in ov, "must verify ECDSA signature"
    assert "sec_counter" in ov, "must have anti-rollback counter"
    assert "nvs_set_u32" in ov, "must persist counter in NVS"
    assert "mbedtls_sha256" in ov or "mbedtls/sha256.h" in ov, (
        "must compute SHA-256 of firmware"
    )
    assert "OTA_VERIFY_PUBKEY_PEM" in ov, "must have built-in public key"
    assert "OTA_PRODUCT_ID" in ov, "must validate product ID"


def test_ea01_manifest_frame_type():
    """EA-01: OTA_MANIFEST must use frame type 0x0C."""
    ov = read_file("ota_verify.h")
    assert ov is not None
    assert "ESPNOW_MSG_OTA_MANIFEST" in ov
    assert "0x0C" in ov


def test_ea01_anti_rollback():
    """EA-01: OTA must check sec_counter against NVS stored value."""
    ov = read_file("ota_verify.h")
    assert ov is not None
    assert "ota_verify_get_counter" in ov
    assert "m.sec_counter <= stored" in ov, (
        "must reject manifest with sec_counter at or below stored (FR-08)"
    )


def test_ea01_sha256_streaming():
    """EA-01: OTA must stream SHA-256 verification over chunks."""
    ov = read_file("ota_verify.h")
    assert ov is not None
    assert "ota_verify_sha_begin" in ov
    assert "ota_verify_sha_update" in ov
    assert "ota_verify_sha_finish" in ov


def test_ea01_manifest_required_before_offer():
    """EA-01: ota_espnow.h must require manifest before accepting offer."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    assert "ota_verify_has_manifest" in ota, (
        "ota_espnow.h must check for verified manifest before accepting offer"
    )
    # FR-01: manifest verification is now unconditional (no more OTA_VERIFY_H guards).
    assert "ota_verify_manifest" in ota, (
        "ota_espnow.h must call ota_verify_manifest directly"
    )


def test_ea01_ota_verify_wired():
    """EA-01: esp32_p4.ino must init ota_verify when OTA+CRYPTO enabled."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "ota_verify_init" in ino, (
        "esp32_p4.ino must call ota_verify_init()"
    )
    assert "ota_verify.h" in ino, (
        "esp32_p4.ino must include ota_verify.h"
    )


def test_ea02_exact_response_length():
    """EA-02: Peer validation must require exact response length."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    assert "resp_n == p->n_expected" in pp, (
        "peer_protocol.h must check exact response length match"
    )


def test_ea03_challenge_id_binding():
    """EA-03: VALIDATE frames must match inbound challenge CID."""
    pp = read_file("peer_protocol.h")
    assert pp is not None
    assert "inbound_cid" in pp, (
        "PeerSlot must track inbound challenge ID"
    )
    assert "inbound_responded" in pp, (
        "PeerSlot must track whether response was sent"
    )
    assert "val_cid == p->inbound_cid" in pp, (
        "VALIDATE handler must verify CID matches inbound challenge"
    )


def test_ea04_sender_crypto():
    """EA-04: Sender must sign OTA frames with crypto_envelope.h."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "crypto_envelope.h" in sender, (
        "espnow_sender.ino must include crypto_envelope.h"
    )
    assert "crypto_env_sign" in sender or "sender_send" in sender, (
        "sender must sign frames"
    )
    assert "_sender_epoch" in sender or "_otap_epoch" in sender, (
        "sender must have crypto epoch"
    )

    ota_push = (SENDER_DIR / "ota_push.h").read_text()
    assert "crypto_envelope.h" in ota_push, (
        "ota_push.h must include crypto_envelope.h"
    )
    assert "_otap_send_signed" in ota_push, (
        "ota_push.h must use signed send"
    )


def test_ea04_sender_verifies_rx():
    """EA-04: Sender must verify incoming frames when crypto enabled."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "crypto_env_verify" in sender, (
        "sender on_rx must verify incoming frames"
    )


def test_ea05_llm_load_bounds():
    """EA-05: llm_load must accept buf_len and validate dimensions."""
    llm = (COMMON_DIR / "llm.h").read_text()
    assert "buf_len" in llm, (
        "llm_load must accept buf_len parameter"
    )
    assert "bind_q" in llm and "end" in llm, (
        "bind_q must accept end pointer for bounds checking"
    )


def test_ea06_epoch_replay():
    """EA-06: crypto_peer.h must use random boot epoch, not time-based reset."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "_crypto_epoch" in crypto, "must have boot epoch"
    assert "esp_random" in crypto, "epoch must use esp_random()"
    assert "epoch != _crypto_replay" in crypto or "epoch" in crypto, (
        "replay check must compare epochs"
    )
    assert "CRYPTO_MAX_DRIFT" not in crypto, (
        "EA-06: must not use time-based drift (replaced by epoch)"
    )


def test_ea06_shared_crypto_envelope():
    """EA-06: crypto_envelope.h must exist as shared signing module."""
    env = (COMMON_DIR / "crypto_envelope.h").read_text()
    assert "CRYPTO_ENV_OVERHEAD" in env
    assert "crypto_env_sign" in env
    assert "crypto_env_verify" in env
    assert "epoch" in env, "envelope must include epoch field"
    assert "CRYPTO_ENV_TAG_LEN" in env


def test_ea07_per_mac_rate_limiting():
    """EA-07: espnow_comm.h must rate-limit per source MAC."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "ESPNOW_RX_MAC_SLOTS" in en, "must define per-MAC slot count"
    assert "_espnow_mac_ratelimit" in en, "must have per-MAC rate limit function"
    assert "_espnow_rx_mac" in en, "must have per-MAC tracking array"
    assert "ESPNOW_RX_GLOBAL_CEIL" in en, (
        "must have global ceiling against MAC rotation"
    )


def test_ea08_full_frame_auth():
    """EA-08: All frame types must be signed/verified (not just 0x04+)."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "espnow_send_token" in en
    assert "espnow_send_text" in en
    # Both must use espnow_send_secure — find the function definition.
    token_def = en[en.index("static void espnow_send_token"):]
    token_fn = token_def[:token_def.index("\n}\n") + 3]
    assert "espnow_send_secure" in token_fn, (
        "espnow_send_token must use espnow_send_secure"
    )
    text_def = en[en.index("static void espnow_send_text"):]
    text_fn = text_def[:text_def.index("\n}\n") + 3]
    assert "espnow_send_secure" in text_fn, (
        "espnow_send_text must use espnow_send_secure"
    )

    # RX callback must verify ALL frames, not just >= 0x04.
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    assert "_espnow_verify_fn" in rx_fn, (
        "RX callback must verify all frames when crypto is enabled"
    )
    assert ">= 0x04" not in rx_fn.split("_espnow_verify_fn")[0], (
        "Verify must happen before type dispatch, not gated on >= 0x04"
    )


def test_ea09_ota_spsc_ring_buffers():
    """EA-09: OTA must use SPSC ring buffers for RX frames."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    assert "OTA_RX_RING" in ota, (
        "ota_espnow.h must define ring buffer size"
    )
    assert "_ota_offer_ring" in ota, "offer ring buffer must exist"
    assert "_ota_data_ring" in ota, "data ring buffer must exist"
    assert "__atomic_load_n" in ota, (
        "must use atomic operations for ring buffer indices"
    )
    assert "__atomic_store_n" in ota, (
        "must use atomic stores for ring buffer indices"
    )
    assert "__ATOMIC_ACQUIRE" in ota, "must use acquire semantics"
    assert "__ATOMIC_RELEASE" in ota, "must use release semantics"


def test_ea09_no_volatile_pending():
    """EA-09: OTA must not use volatile .pending pattern for RX buffers."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    assert "volatile" not in ota or "_ota_in_offer" not in ota, (
        "ota_espnow.h must not use volatile .pending pattern (use SPSC ring)"
    )


def test_ota_chunk_size_crypto():
    """OTA chunk size must account for 16-byte crypto envelope overhead."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    m = re.search(r'#define\s+OTA_CHUNK_SIZE\s+(\d+)', ota)
    assert m is not None, "OTA_CHUNK_SIZE must be defined"
    chunk_size = int(m.group(1))
    assert chunk_size <= 226, (
        f"OTA_CHUNK_SIZE={chunk_size} too large for 250B ESP-NOW + 16B crypto + 8B header"
    )

    sender = (SENDER_DIR / "ota_push.h").read_text()
    m2 = re.search(r'#define\s+OTA_PUSH_CHUNK\s+(\d+)', sender)
    assert m2 is not None, "OTA_PUSH_CHUNK must be defined"
    push_chunk = int(m2.group(1))
    assert push_chunk <= 226, (
        f"OTA_PUSH_CHUNK={push_chunk} too large for crypto overhead"
    )


def test_sender_manifest_support():
    """EA-01: Sender must support manifest upload and broadcast."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "manifest" in sender, (
        "espnow_sender.ino must support manifest command"
    )
    ota_push = (SENDER_DIR / "ota_push.h").read_text()
    assert "ota_push_upload_manifest" in ota_push, (
        "ota_push.h must have manifest upload function"
    )
    assert "ESPNOW_MSG_OTA_MANIFEST" in ota_push, (
        "ota_push.h must define manifest frame type"
    )


# ---- FR (Fresh Reassessment) tests ----------------------------------------

def test_fr01_ota_verify_unconditional():
    """FR-01: OTA verify must be included unconditionally when USE_OTA is set."""
    ino = (FIRMWARE_DIR / "esp32_p4.ino").read_text()
    # Must not have USE_CRYPTO guard on ota_verify.h include.
    assert 'USE_OTA && USE_CRYPTO' not in ino or '#error' in ino, (
        "ota_verify.h include must not be guarded by USE_CRYPTO"
    )
    # Must have compile-time enforcement.
    assert '#error' in ino, (
        "must have #error for USE_OTA && !USE_CRYPTO"
    )


def test_fr01_no_placeholder_key():
    """FR-01: ota_verify.h must not contain a placeholder public key."""
    verify = read_file("ota_verify.h")
    assert verify is not None
    assert "AAAAAAAAAAAAA" not in verify, (
        "ota_verify.h must not contain the placeholder all-zeros public key"
    )
    assert "#error" in verify, (
        "ota_verify.h must require OTA_VERIFY_PUBKEY_PEM to be defined"
    )


def test_fr01_ota_espnow_no_ifdef_guard():
    """FR-01: ota_espnow.h must not conditionally guard manifest logic."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    assert "#ifdef OTA_VERIFY_H" not in ota, (
        "ota_espnow.h must not use #ifdef OTA_VERIFY_H guards"
    )


def test_fr02_mac_based_replay():
    """FR-02: Replay tracking must use source MAC as primary key."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "mac[6]" in crypto, (
        "replay table must store MAC address"
    )
    assert "src_mac" in crypto, (
        "crypto_verify must accept src_mac parameter"
    )
    assert "memcmp" in crypto and "mac" in crypto, (
        "replay lookup must compare MACs"
    )


def test_fr02_epoch_alternation_prevention():
    """FR-02/R2-02/R5-01: Must prevent epoch alternation/cycling attacks."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    # R5-01: upgraded from a bounded/time-evicted retired-epoch ring to a
    # persistent monotonic counter -- a strictly-greater-than comparison
    # replaces the ring, and a lesser-or-equal epoch is rejected forever.
    assert "crypto_next_persistent_epoch" in crypto, (
        "epoch must come from a persistent monotonic counter"
    )
    assert "epoch > _crypto_replay[slot].epoch" in crypto, (
        "a new epoch must be strictly greater than the last accepted epoch"
    )
    assert "CRYPTO_EPOCH_SILENCE_US" in crypto, (
        "must have silence period before accepting new epoch"
    )


def test_fr02_verify_fn_has_mac():
    """FR-02: espnow_verify_fn_t must accept source MAC."""
    en = read_file("espnow_comm.h")
    assert en is not None
    m = re.search(r'typedef\s+int\s+\(\*espnow_verify_fn_t\)\((.*?)\)',
                  en, re.DOTALL)
    assert m is not None, "espnow_verify_fn_t must be defined"
    params = m.group(1)
    assert "src_mac" in params, (
        "espnow_verify_fn_t must accept src_mac parameter"
    )


def test_fr02_sender_replay_table():
    """FR-02: Sender must have replay protection on RX path."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "_sender_replay" in sender, (
        "sender must have replay table"
    )
    assert "SENDER_REPLAY_SLOTS" in sender, (
        "sender must define replay slot count"
    )


def test_fr03_overflow_checked_mul():
    """FR-03: llm.h bind_q/bind_f must use overflow-checked multiplication."""
    llm = (COMMON_DIR / "llm.h").read_text()
    assert "_llm_mul_overflow" in llm, (
        "llm.h must define overflow-checked multiplication helper"
    )
    # Must use the helper in bind_q and bind_f.
    bind_q_start = llm.index("bind_q")
    bind_f_start = llm.index("bind_f")
    bind_q_section = llm[bind_q_start:bind_f_start]
    assert "_llm_mul_overflow" in bind_q_section, (
        "bind_q must use overflow-checked multiplication"
    )
    bind_f_section = llm[bind_f_start:bind_f_start + 500]
    assert "_llm_mul_overflow" in bind_f_section, (
        "bind_f must use overflow-checked multiplication"
    )


def test_fr03_safe_pointer_comparison():
    """FR-03: Must not use p + sz > end pattern (pointer overflow UB)."""
    llm = (COMMON_DIR / "llm.h").read_text()
    # The safe pattern is sz > (size_t)(end - p), not p + sz > end.
    assert "end - p" in llm, (
        "must use end - p pattern for safe bounds checking"
    )


def test_fr04_keygen_tool():
    """FR-04: tools/ota_keygen.py must exist."""
    keygen = Path(__file__).parent.parent / "tools" / "ota_keygen.py"
    assert keygen.exists(), "tools/ota_keygen.py must exist"
    content = keygen.read_text()
    assert "prime256v1" in content or "P-256" in content, (
        "keygen must generate P-256 keys"
    )


def test_fr04_sign_manifest_tool():
    """FR-04: tools/ota_sign_manifest.py must exist."""
    sign_tool = Path(__file__).parent.parent / "tools" / "ota_sign_manifest.py"
    assert sign_tool.exists(), "tools/ota_sign_manifest.py must exist"
    content = sign_tool.read_text()
    assert "OTA_MANIFEST_MAGIC" in content, (
        "sign tool must use OTA manifest magic"
    )


def test_fr04_ota_push_requires_manifest():
    """FR-04: ota_push.py must require --manifest for push."""
    push_py = Path(__file__).parent.parent / "tools" / "ota_push.py"
    content = push_py.read_text()
    assert "--manifest" in content, (
        "ota_push.py must accept --manifest argument"
    )


def test_fr04_nvs_init_standalone():
    """FR-04: NVS must be initialized even when peer_protocol is disabled."""
    ino = (FIRMWARE_DIR / "esp32_p4.ino").read_text()
    assert "nvs_flash_init" in ino, (
        "must have standalone NVS init for OTA without peer_protocol"
    )


def test_fr05_ota_data_sender_binding():
    """FR-05: OTA data callback must check sender MAC."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    # Find the OTA_DATA case and check for MAC binding.
    data_case = ota[ota.index("ESPNOW_MSG_OTA_DATA"):]
    data_section = data_case[:data_case.index("break;")]
    assert "sender_mac" in data_section, (
        "OTA data handler must verify sender MAC matches accepted sender"
    )


def test_fr06_two_tier_rate_limiting():
    """FR-06: Must have separate pre-auth and post-auth rate budgets."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "ESPNOW_RX_AUTHED_RESERVE" in en, (
        "must define reserved authenticated budget"
    )
    assert "_espnow_rx_authed_count" in en or "_espnow_authed_budget" in en, (
        "must have authenticated budget tracking"
    )


def test_fr06_diagnostic_counters():
    """FR-06: Must have diagnostic counters for rate limiting."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "_espnow_diag_preauth_drop" in en, (
        "must track pre-auth drops"
    )
    assert "_espnow_diag_authed_pass" in en, (
        "must track authenticated passes via reserved budget"
    )


def test_fr07_sender_spsc_rings():
    """FR-07: Sender ota_push.h must use SPSC ring buffers, not volatile."""
    push = (SENDER_DIR / "ota_push.h").read_text()
    # Strip comments before checking for volatile declarations.
    code_lines = [l for l in push.split('\n') if not l.strip().startswith('//')]
    code = '\n'.join(code_lines)
    assert "volatile" not in code, (
        "ota_push.h must not use volatile .pending pattern"
    )
    assert "OTAP_RING" in push, (
        "must define SPSC ring buffer size"
    )
    assert "__atomic_load_n" in push, (
        "must use atomic operations for ring buffer indices"
    )
    assert "__atomic_store_n" in push, (
        "must use atomic stores for ring buffer indices"
    )


def test_fr08_negative_validate_clears():
    """FR-08: Negative VALIDATE must clear inbound_responded."""
    peer = read_file("peer_protocol.h")
    assert peer is not None
    # Find the else branch after VALIDATE handling.
    else_idx = peer.index("rejected our response")
    else_section = peer[else_idx - 200:else_idx]
    assert "inbound_responded" in else_section, (
        "negative VALIDATE must clear inbound_responded"
    )


def test_fr08_strict_counter_increase():
    """FR-08: Anti-rollback must use strict increase (<=), not just (<)."""
    verify = read_file("ota_verify.h")
    assert verify is not None
    assert "sec_counter <= stored" in verify or "m.sec_counter <= stored" in verify, (
        "anti-rollback must reject equal counter values"
    )


def test_fr08_deferred_counter_commit():
    """FR-08: Security counter must be committed after all checks pass."""
    verify = read_file("ota_verify.h")
    assert verify is not None
    assert "ota_verify_commit_counter" in verify, (
        "must have separate counter commit function"
    )
    # sha_finish must NOT call nvs_set_u32 directly.
    sha_fn_start = verify.index("ota_verify_sha_finish")
    commit_fn_start = verify.index("ota_verify_commit_counter")
    sha_fn = verify[sha_fn_start:commit_fn_start]
    assert "nvs_set_u32" not in sha_fn, (
        "sha_finish must not commit counter directly"
    )

    # The commit must happen in ota_espnow.h after finalization.
    ota = read_file("ota_espnow.h")
    assert "ota_verify_commit_counter" in ota, (
        "ota_espnow.h must call commit_counter after finalization"
    )


def test_fr08_boot_partition_checked():
    """FR-08: esp_ota_set_boot_partition return must be checked."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    # Find set_boot_partition and ensure its return is used.
    boot_idx = ota.index("esp_ota_set_boot_partition")
    boot_section = ota[boot_idx - 30:boot_idx + 100]
    assert "esp_err_t" in boot_section or "eb" in boot_section, (
        "esp_ota_set_boot_partition return value must be checked"
    )


# ---- R2 (Remediation Reassessment Round 2) tests ---------------------------

def test_r2_01_stdbool_in_llm():
    """R2-01: llm.h must include <stdbool.h> for C host builds."""
    llm = (COMMON_DIR / "llm.h").read_text()
    assert "#include <stdbool.h>" in llm, (
        "llm.h must include <stdbool.h> for C portability"
    )


def test_r2_02_retired_epoch_ring():
    """R2-02/R5-01: crypto_peer.h must permanently reject superseded epochs.

    Originally via a bounded retired-epoch ring; R5-01 replaced that with a
    persistent monotonic counter, since a bounded/time-evicted ring could
    itself be forced to re-admit a retired epoch (see R5-01 tests below).
    """
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "crypto_next_persistent_epoch" in crypto, (
        "epoch must come from a persistent monotonic counter"
    )
    # R5-01: a lesser-or-equal epoch must be rejected unconditionally, with
    # no eviction/recovery path that can ever re-admit it.
    assert "epoch > _crypto_replay[slot].epoch" in crypto, (
        "epoch comparison must be strictly monotonic"
    )
    verify_fn = crypto[crypto.index("static int crypto_verify("):]
    monotonic_idx = verify_fn.index("epoch > _crypto_replay[slot].epoch")
    permanently_retired = verify_fn[monotonic_idx:monotonic_idx + 700]
    assert "R5-01" in permanently_retired and "return 0" in permanently_retired, (
        "the non-monotonic (retired epoch) branch must unconditionally reject"
    )


def test_r2_02_sender_epoch_silence():
    """R2-02: Sender replay must require silence period for new epochs."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "SENDER_EPOCH_SILENCE_MS" in sender, (
        "sender must define epoch silence period"
    )
    # R5-01: retired-epoch ring replaced with a persistent monotonic counter.
    assert "sender_next_persistent_epoch" in sender, (
        "sender epoch must come from a persistent monotonic counter"
    )
    assert "ep > _sender_replay[slot].epoch" in sender, (
        "sender epoch comparison must be strictly monotonic"
    )


def test_r2_03_unified_tx_counter():
    """R2-03: Sender OTA path must share TX counter with prompt path."""
    push = (SENDER_DIR / "ota_push.h").read_text()
    assert "_otap_tx_seq_ptr" in push, (
        "ota_push.h must use a shared TX seq pointer"
    )
    assert "_otap_epoch_ptr" in push, (
        "ota_push.h must use a shared epoch pointer"
    )
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "_otap_tx_seq_ptr = &_sender_tx_seq" in sender, (
        "sender setup must point OTA seq to shared counter"
    )
    assert "_otap_epoch_ptr = &_sender_epoch" in sender, (
        "sender setup must point OTA epoch to shared epoch"
    )


def test_r2_04_no_default_psk():
    """R2-04: crypto_peer.h and ota_push.h must not have a default PSK."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert '#error' in crypto, (
        "crypto_peer.h must #error when CRYPTO_PSK is not defined"
    )
    assert '"ple-tinylm-default-flock-key-v1"' not in crypto or '#error' in crypto, (
        "crypto_peer.h must not silently use a default PSK"
    )
    push = (SENDER_DIR / "ota_push.h").read_text()
    assert '#error' in push, (
        "ota_push.h must #error when CRYPTO_PSK is not defined"
    )


def test_r2_04_crypto_before_espnow():
    """R2-04: crypto_init must happen before espnow_begin in boot."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    crypto_pos = ino.index("crypto_init()")
    espnow_pos = ino.index("espnow_begin()")
    assert crypto_pos < espnow_pos, (
        "crypto_init() must be called before espnow_begin()"
    )


def test_r2_05_offer_mac_binding():
    """R2-05: Offer processing must compare sender MAC to manifest sender."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    offer_section = ota[ota.index("offer_fw_size"):]
    offer_section = offer_section[:offer_section.index("OTA_ACTIVE")]
    assert "sender_mac" in offer_section and "offer_ring" in offer_section, (
        "offer processing must verify sender MAC matches manifest sender"
    )


def test_r2_05_data_sender_id_check():
    """R2-05: OTA data callback must verify payload sender_id."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    data_case = ota[ota.index("ESPNOW_MSG_OTA_DATA"):]
    data_section = data_case[:data_case.index("break;")]
    assert "data_sender_id" in data_section or "sender_id" in data_section, (
        "OTA data handler must verify sender_id in payload"
    )


def test_r2_05_sender_status_mac_check():
    """R2-05: Sender status drain must check source MAC."""
    push = (SENDER_DIR / "ota_push.h").read_text()
    assert "receiver_bound" in push, (
        "sender must track receiver binding state"
    )
    assert "receiver_mac" in push, (
        "sender must store bound receiver MAC"
    )
    status_section = push[push.lower().index("drain status ring"):]
    assert "from_receiver" in status_section or "receiver_bound" in status_section, (
        "sender status drain must check MAC of status sender"
    )


def test_r2_06_counter_commit_checked():
    """R2-06: ota_verify_commit_counter return must be checked."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    # Find the commit_counter call and check its return is used.
    commit_idx = ota.index("ota_verify_commit_counter()")
    commit_context = ota[commit_idx - 10:commit_idx + 50]
    assert "if" in commit_context or "!" in commit_context, (
        "ota_verify_commit_counter() return must be checked with if"
    )


def test_r2_07_safe_bind_q_pointer():
    """R2-07: bind_q must not use p + N > end (pointer overflow UB)."""
    llm = (COMMON_DIR / "llm.h").read_text()
    bind_q_start = llm.index("bind_q(")
    bind_q = llm[bind_q_start:bind_q_start + 200]
    assert "p + 4 > end" not in bind_q, (
        "bind_q must not use p + 4 > end (use subtraction instead)"
    )
    assert "end - p" in bind_q, (
        "bind_q must use (end - p) < 4 pattern"
    )


def test_r2_07_reject_zero_layers():
    """R2-07: llm_load must reject L==0 (zero layers)."""
    llm = (COMMON_DIR / "llm.h").read_text()
    assert "L <= 0" in llm, (
        "llm_load must reject L==0 (use <= not <)"
    )


def test_r2_07_psram_allocation_cap():
    """R2-07: PSRAM allocations must have an aggregate cap."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "PSRAM_ALLOC_CAP" in ino, (
        "must define an aggregate PSRAM allocation cap"
    )
    assert "_ps_total" in ino, (
        "must track total PSRAM allocation"
    )


def test_r2_07_ratelimit_before_hmac():
    """R2-07/R3-03: Overflow verification budget must gate HMAC attempts."""
    en = read_file("espnow_comm.h")
    assert en is not None
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    # R3-03: overflow budget check must come BEFORE _espnow_verify_fn call.
    overflow_check = rx_fn.index("_espnow_verify_overflow_budget")
    verify_call = rx_fn.index("_espnow_verify_fn(")
    assert overflow_check < verify_call, (
        "overflow verification budget must gate HMAC attempts"
    )
    # R3-03: authed reserve must come AFTER successful HMAC.
    authed_check = rx_fn.index("_espnow_authed_budget")
    assert verify_call < authed_check, (
        "authenticated budget must be checked after HMAC verification"
    )


# ---- R3 (Remediation Reassessment Round 3) tests ---------------------------

def test_r3_01_fail_closed_retired_ring():
    """R3-01/R5-01: Replay must permanently reject a superseded epoch.

    R5-01 replaced the bounded/time-evicted retired-epoch ring (which this
    test used to check for fail-closed-when-full behavior) with a
    persistent monotonic counter, so there is no ring capacity to exhaust
    and no recovery window that can ever re-admit an old epoch.
    """
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "crypto_next_persistent_epoch" in crypto, (
        "epoch must come from a persistent monotonic counter"
    )
    assert "CRYPTO_RETIRED_EPOCHS" not in crypto, (
        "bounded retired-epoch ring must be removed (R5-01)"
    )
    assert "CRYPTO_RECOVERY_SILENCE_US" not in crypto, (
        "time-based retired-epoch recovery must be removed (R5-01)"
    )


def test_r3_01_fail_closed_replay_slots():
    """R3-01: Replay must reject unknown MACs when all slots are active (R4-05 adds stale eviction)."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    new_mac_idx = crypto.index("R3-01: fail closed")
    new_mac_section = crypto[new_mac_idx:new_mac_idx + 400]
    assert "_crypto_replay[evict].active" in new_mac_section, (
        "must check evict slot is inactive before accepting new MAC"
    )
    assert "return 0" in new_mac_section, (
        "must return 0 when all replay slots are active and not stale"
    )
    # R4-05: stale eviction must be gated by CRYPTO_SLOT_STALE_US.
    assert "CRYPTO_SLOT_STALE_US" in new_mac_section, (
        "stale eviction must use CRYPTO_SLOT_STALE_US threshold"
    )


def test_r3_01_sender_fail_closed():
    """R3-01/R5-01: Sender replay must permanently reject a superseded epoch
    and must still be fail-closed for unknown MACs when all slots are active.
    """
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "sender_next_persistent_epoch" in sender, (
        "sender epoch must come from a persistent monotonic counter"
    )
    assert "SENDER_RETIRED_EPOCHS" not in sender, (
        "bounded retired-epoch ring must be removed (R5-01)"
    )
    assert "SENDER_RECOVERY_SILENCE_MS" not in sender, (
        "time-based retired-epoch recovery must be removed (R5-01)"
    )
    assert "_sender_replay[evict].active" in sender, (
        "sender must reject unknown MACs when all slots active"
    )


def test_r3_02_crypto_required_flag():
    """R3-02: espnow_comm.h must have crypto_required fail-closed flag."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "_espnow_crypto_required" in en, (
        "must have _espnow_crypto_required flag"
    )
    assert "espnow_require_crypto" in en, (
        "must have espnow_require_crypto() function"
    )
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    assert "_espnow_crypto_required && !_espnow_verify_fn" in rx_fn, (
        "RX callback must drop frames when crypto required but not installed"
    )


def test_r3_02_crypto_before_begin():
    """R3-02: espnow_set_crypto must be called before espnow_begin."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    set_crypto_pos = ino.index("espnow_set_crypto(")
    begin_pos = ino.index("espnow_begin()")
    assert set_crypto_pos < begin_pos, (
        "espnow_set_crypto must be called before espnow_begin"
    )


def test_r3_02_sender_crypto_before_rx():
    """R3-02: Sender must init crypto before registering RX callback."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    crypto_pos = sender.index("_sender_epoch = sender_next_persistent_epoch()")
    rx_cb_pos = sender.index("esp_now_register_recv_cb(on_rx)")
    assert crypto_pos < rx_cb_pos, (
        "sender crypto init must happen before esp_now_register_recv_cb"
    )


def test_r3_03_overflow_verification_budget():
    """R3-03: Must have overflow verification budget to bound HMAC attempts."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "ESPNOW_RX_VERIFY_OVERFLOW" in en, (
        "must define ESPNOW_RX_VERIFY_OVERFLOW budget"
    )
    assert "_espnow_verify_overflow_budget" in en, (
        "must have overflow verification budget function"
    )
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    assert "_espnow_verify_overflow_budget" in rx_fn, (
        "RX callback must use overflow budget when pre-auth exhausted"
    )


def test_r3_03_authed_budget_after_hmac():
    """R3-03: Authenticated reserve must be checked AFTER successful HMAC."""
    en = read_file("espnow_comm.h")
    assert en is not None
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    verify_pos = rx_fn.index("_espnow_verify_fn(info->src_addr")
    authed_pos = rx_fn.index("_espnow_authed_budget(now_us)")
    assert verify_pos < authed_pos, (
        "authed budget check must come AFTER HMAC verification"
    )


def test_r3_04_boot_partition_rollback():
    """R3-04: Counter commit failure must restore boot partition."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    commit_idx = ota.index("ota_verify_commit_counter()")
    commit_section = ota[commit_idx:commit_idx + 400]
    assert "esp_ota_get_running_partition" in commit_section, (
        "counter commit failure must call esp_ota_get_running_partition"
    )
    assert "esp_ota_set_boot_partition(running)" in commit_section, (
        "counter commit failure must restore boot partition to running"
    )


def test_r3_05_sender_request_mac_filter():
    """R3-05: Sender must filter OTA requests by bound receiver MAC."""
    push = (SENDER_DIR / "ota_push.h").read_text()
    req_drain = push[push.index("Drain request ring"):]
    req_section = req_drain[:req_drain.index("drain status ring")]
    assert "memcmp(_otap_req_ring[rd].mac, _otap.receiver_mac, 6)" in req_section, (
        "request drain must compare request MAC against bound receiver"
    )


def test_r3_06_ps_returns_null():
    """R3-06: ps() must return NULL on failure, not enter infinite loop."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    ps_fn = ino[ino.index("static void *ps("):]
    ps_fn = ps_fn[:ps_fn.index("\n}\n") + 3]
    assert "while (1)" not in ps_fn, (
        "ps() must not hang in infinite loop on failure"
    )
    assert "return NULL" in ps_fn, (
        "ps() must return NULL on failure"
    )


def test_r3_06_psram_preflight():
    """R3-06: Setup must do overflow-checked preflight before allocation."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "_psram_preflight" in ino, (
        "must have _psram_preflight function"
    )
    assert "_llm_mul_overflow" in ino, (
        "preflight must use overflow-checked multiplication"
    )
    preflight_pos = ino.index("_psram_preflight(c)")
    first_ps_pos = ino.index("ps(D * 4)")
    assert preflight_pos < first_ps_pos, (
        "preflight check must happen before first ps() allocation"
    )


def test_r3_06_setup_ok_flag():
    """R3-06: inference must be guarded by _setup_ok flag."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "_setup_ok" in ino, (
        "must have _setup_ok flag"
    )
    assert "_setup_ok = true" in ino, (
        "must set _setup_ok after successful allocation"
    )
    # Verify run_generate calls are guarded.
    generate_cmd = ino[ino.index('cmd == "generate"'):]
    generate_section = generate_cmd[:generate_cmd.index("help")]
    assert "_setup_ok" in generate_section, (
        "generate command must check _setup_ok before calling run_generate"
    )


# ---- R4 (Remediation Reassessment Round 4) tests ---------------------------

def test_r4_01_vocab_invariant_validation():
    """R4-01: Preflight must validate V >= VOCAB_N."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    preflight_fn = ino[ino.index("_psram_preflight("):]
    preflight_fn = preflight_fn[:preflight_fn.index("\n}\n") + 3]
    assert "vocab" in preflight_fn and "VOCAB_N" in preflight_fn, (
        "preflight must validate model vocab against VOCAB_N"
    )


def test_r4_01_dim_invariant_validation():
    """R4-01: Preflight must validate D <= 128 (head_actq capacity)."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    preflight_fn = ino[ino.index("_psram_preflight("):]
    preflight_fn = preflight_fn[:preflight_fn.index("\n}\n") + 3]
    assert "dim" in preflight_fn and "128" in preflight_fn, (
        "preflight must validate model dim fits head_actq[128]"
    )


def test_r4_01_preflight_before_staging():
    """R4-01: Preflight must run BEFORE stage_head_int8 call in setup."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    preflight_pos = ino.index("_psram_preflight(c)")
    # Find the call site, not the function definition.
    stage_pos = ino.index("stage_head_int8(&model.tok_emb)")
    assert preflight_pos < stage_pos, (
        "preflight must run before stage_head_int8 call"
    )


def test_r4_01_stage_head_returns_bool():
    """R4-01: stage_head_int8 must return bool and check ps() for NULL."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    assert "static bool stage_head_int8(" in ino, (
        "stage_head_int8 must return bool, not void"
    )
    stage_fn = ino[ino.index("static bool stage_head_int8("):]
    stage_fn = stage_fn[:stage_fn.index("\n}\n") + 3]
    assert "!head_w8 || !head_scale8" in stage_fn, (
        "stage_head_int8 must NULL-check ps() results"
    )
    assert "return false" in stage_fn, (
        "stage_head_int8 must return false on allocation failure"
    )


def test_r4_01_head_budget_in_preflight():
    """R4-01: Preflight must check head staging allocation budget."""
    ino = read_file("esp32_p4.ino")
    assert ino is not None
    preflight_fn = ino[ino.index("_psram_preflight("):]
    preflight_fn = preflight_fn[:preflight_fn.index("\n}\n") + 3]
    assert "head_w_size" in preflight_fn or "head_s_size" in preflight_fn, (
        "preflight must include head allocation budget check"
    )


def test_r4_02_per_mac_overflow_budget():
    """R4-02: Tracked peers must have per-MAC overflow budget."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "ESPNOW_RX_PEER_OVERFLOW" in en, (
        "must define per-MAC overflow budget constant"
    )
    assert "overflow_count" in en, (
        "MAC struct must have overflow_count field"
    )
    assert "overflow_window" in en, (
        "MAC struct must have overflow_window field"
    )


def test_r4_02_peer_overflow_function():
    """R4-02: Must have _espnow_peer_overflow_budget function."""
    en = read_file("espnow_comm.h")
    assert en is not None
    assert "_espnow_peer_overflow_budget" in en, (
        "must have per-MAC overflow budget function"
    )
    peer_fn = en[en.index("_espnow_peer_overflow_budget"):]
    peer_fn = peer_fn[:peer_fn.index("\n}\n") + 3]
    assert "ESPNOW_RX_PEER_OVERFLOW" in peer_fn, (
        "per-MAC overflow function must use ESPNOW_RX_PEER_OVERFLOW limit"
    )


def test_r4_02_tracked_peer_fast_lane():
    """R4-02: RX callback must try per-MAC overflow before global overflow."""
    en = read_file("espnow_comm.h")
    assert en is not None
    rx_fn = en[en.index("_espnow_rx("):]
    rx_fn = rx_fn[:rx_fn.index("\n}\n") + 3]
    peer_pos = rx_fn.index("_espnow_peer_overflow_budget")
    global_pos = rx_fn.index("_espnow_verify_overflow_budget")
    assert peer_pos < global_pos, (
        "per-MAC overflow must be checked before global overflow in RX callback"
    )


def test_r4_03_two_phase_counter_journal():
    """R4-03/R5-03: OTA must use a two-phase journal (stage → boot → commit).

    R5-03 widened the journal from a single counter key to also record the
    target partition and an explicit phase, so recovery can tell "staged"
    apart from "activated" (see the R5-03 tests below).
    """
    verify = read_file("ota_verify.h")
    assert verify is not None
    assert "ota_verify_stage_counter" in verify, (
        "must have ota_verify_stage_counter function"
    )
    assert 'pend_phase' in verify and 'pend_ctr' in verify and 'pend_part' in verify, (
        "must journal an explicit phase, the pending counter, and the target partition"
    )


def test_r4_03_boot_time_recovery():
    """R4-03: OTA must recover pending counter at boot."""
    verify = read_file("ota_verify.h")
    assert verify is not None
    assert "_ota_verify_recover" in verify, (
        "must have _ota_verify_recover function"
    )
    init_fn = verify[verify.index("ota_verify_init()"):]
    init_fn = init_fn[:init_fn.index("\n}\n") + 3]
    assert "_ota_verify_recover()" in init_fn, (
        "ota_verify_init must call _ota_verify_recover"
    )


def test_r4_03_stage_before_boot_partition():
    """R4-03: Journal must be staged BEFORE set_boot_partition."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    finalize_section = ota[ota.index("esp_ota_end(_ota.handle)"):]
    stage_pos = finalize_section.index("ota_verify_stage_counter(_ota.part)")
    boot_pos = finalize_section.index("esp_ota_set_boot_partition(_ota.part)")
    assert stage_pos < boot_pos, (
        "journal must be staged (with the target partition) before set_boot_partition"
    )


def test_r4_03_commit_clears_pending():
    """R4-03/R5-03: Counter commit must clear the pending journal keys."""
    verify = read_file("ota_verify.h")
    assert verify is not None
    commit_fn = verify[verify.index("static bool ota_verify_commit_counter()"):]
    commit_fn = commit_fn[:commit_fn.index("\n}\n") + 3]
    assert '_ota_verify_clear_journal' in commit_fn, (
        "commit_counter must clear the pending journal"
    )
    clear_fn = verify[verify.index("static void _ota_verify_clear_journal("):]
    clear_fn = clear_fn[:clear_fn.index("\n}\n") + 3]
    for key in ("pend_phase", "pend_ctr", "pend_part"):
        assert f'"{key}"' in clear_fn and 'nvs_erase_key' in clear_fn, (
            f"journal cleanup must erase the {key} key"
        )


def test_r4_03_rollback_result_check():
    """R4-03: Boot partition rollback result must be checked."""
    ota = read_file("ota_espnow.h")
    assert ota is not None
    rollback_section = ota[ota.index("counter commit failed"):]
    rollback_section = rollback_section[:300]
    assert "esp_ota_set_boot_partition(running) != ESP_OK" in rollback_section, (
        "rollback esp_ota_set_boot_partition result must be checked"
    )


def test_r4_04_sender_init_ordering():
    """R4-04: Sender must init OTA and replay BEFORE registering RX callback."""
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    ota_init_pos = sender.index("ota_push_init()")
    replay_init_pos = sender.index("memset(_sender_replay")
    rx_cb_pos = sender.index("esp_now_register_recv_cb(on_rx)")
    assert ota_init_pos < rx_cb_pos, (
        "ota_push_init must happen before esp_now_register_recv_cb"
    )
    assert replay_init_pos < rx_cb_pos, (
        "memset(_sender_replay) must happen before esp_now_register_recv_cb"
    )


def test_r4_05_crypto_recovery_silence():
    """R4-05/R5-01: the old retired-ring recovery-silence eviction is gone.

    R5-01 found that CRYPTO_RECOVERY_SILENCE_US's FIFO eviction of the
    retired-epoch ring could itself be used to reopen a retired epoch after
    enough epoch churn plus a silence period -- exactly the reassessment's
    replay-recovery finding. It's removed, not reintroduced.
    """
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "CRYPTO_RECOVERY_SILENCE_US" not in crypto, (
        "time-based retired-epoch recovery must not be reintroduced (R5-01)"
    )


def test_r4_05_crypto_stale_eviction():
    """R4-05: Crypto must define stale slot eviction threshold."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "CRYPTO_SLOT_STALE_US" in crypto, (
        "must define CRYPTO_SLOT_STALE_US"
    )
    assert "60000000" in crypto, (
        "stale threshold must be 60s (60000000 us)"
    )


def test_r4_05_crypto_retired_recovery():
    """R4-05/R5-01: no FIFO eviction path can ever re-admit a retired epoch.

    Superseded by the R5-01 fix: epoch is a persistent monotonic counter,
    so "retired" means permanently retired -- there is nothing left to
    evict or recover.
    """
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "retired_count" not in crypto, (
        "bounded retired-epoch ring bookkeeping must be removed (R5-01)"
    )
    verify_fn = crypto[crypto.index("crypto_verify("):]
    verify_fn = verify_fn[:verify_fn.index("\n}\n") + 3]
    assert "epoch <= _crypto_replay[slot].epoch" not in verify_fn, (
        "epoch check should read as a positive strictly-greater-than test"
    )


def test_r4_05_sender_recovery():
    """R4-05/R5-01: sender must match crypto_peer.h's monotonic-epoch fix
    and must still evict stale, inactive replay slots (unrelated concern).
    """
    sender = (SENDER_DIR / "espnow_sender.ino").read_text()
    assert "SENDER_RECOVERY_SILENCE_MS" not in sender, (
        "time-based retired-epoch recovery must not be reintroduced (R5-01)"
    )
    assert "retired_count" not in sender, (
        "bounded retired-epoch ring bookkeeping must be removed (R5-01)"
    )
    assert "SENDER_SLOT_STALE_MS" in sender, (
        "sender must define SENDER_SLOT_STALE_MS"
    )


# ---- R5 (Remediation Reassessment Round 5) tests ----------------------
#
# The R5 reassessment's core critique of the earlier test suite was that it
# validated source strings, constants, and call ordering rather than
# executing the actual security state transitions under attack or power
# loss. The three tests below compile and RUN the real firmware source
# (firmware/host_verify/*_test.c, against host-side ESP-IDF/Arduino stubs
# in firmware/host_verify/stubs/) to reproduce each finding's exact attack
# or failure sequence, rather than re-implementing the logic in Python or
# grepping for keywords.
#
# Verification note: each test's attack/failure sequence was independently
# reproduced against the actual pre-fix source (commit 0784d57) -- with the
# runtime logic exercised and observed to fail, not merely a compile-time
# API mismatch -- by temporarily hand-adapting each test to the old
# function signatures. That scratch verification isn't checked in (the
# tests here target the current, fixed API and won't compile at all against
# the old one, since e.g. crypto_env_sign/crypto_env_verify gained a mac
# parameter and crypto_next_persistent_epoch/_espnow_bonded_slot/
# ota_verify_abandon_stage didn't exist yet). Compiling one of these tests
# against a reverted change is still a fast way to confirm that change is
# what the test depends on, even though the failure mode in that case is a
# compiler error rather than a runtime assertion.

def _find_c_compiler():
    for cc in ("cc", "gcc", "clang"):
        path = shutil.which(cc)
        if path:
            return path
    return None


def _compile_and_run_host_test(c_filename):
    """Compile a firmware/host_verify/*.c behavioral test against the host
    stubs and run it, returning (returncode, stdout+stderr)."""
    cc = _find_c_compiler()
    assert cc is not None, (
        "a C compiler (cc/gcc/clang) is required to run behavioral tests in "
        f"{HOST_VERIFY_DIR} -- install one or see firmware/host_verify/stubs/"
    )
    src = HOST_VERIFY_DIR / c_filename
    assert src.exists(), f"missing behavioral test source: {src}"
    with tempfile.TemporaryDirectory() as tmp:
        out_bin = os.path.join(tmp, "host_test_bin")
        compile_cmd = [
            cc, "-std=c11", "-I", str(HOST_VERIFY_DIR / "stubs"),
            "-o", out_bin, str(src),
        ]
        compile_result = subprocess.run(
            compile_cmd, capture_output=True, text=True, timeout=60
        )
        assert compile_result.returncode == 0, (
            f"failed to compile {c_filename}:\n{compile_result.stdout}\n{compile_result.stderr}"
        )
        run_result = subprocess.run(
            [out_bin], capture_output=True, text=True, timeout=60
        )
        return run_result.returncode, run_result.stdout + run_result.stderr


def test_r5_01_replay_epoch_behavioral():
    """R5-01 (HIGH): replay recovery must not reopen a retired epoch.

    Executes crypto_peer.h's actual replay state machine through the exact
    attack sequence from the reassessment: a sender progresses through six
    epochs (more than the old design's 4-entry retired ring), and a frame
    captured under the first epoch must remain rejected forever afterward
    -- through repeated recovery-length silences and a simulated receiver
    restart -- not just until the ring's FIFO eviction happens to age it out.
    """
    rc, output = _compile_and_run_host_test("crypto_replay_test.c")
    assert rc == 0, f"behavioral test failed:\n{output}"


def test_r5_02_mac_starvation_behavioral():
    """R5-02 (MEDIUM): MAC-rotation flooding must not starve a provisioned peer.

    Executes espnow_comm.h's actual RX rate-limiting state machine through
    the reassessment's "Validated starvation sequence": seed a legitimate
    peer, flood 500 frames from rotating unauthenticated MACs (evicting the
    legitimate peer from the untrusted-MAC cache and tripping the global
    ceiling), then 50 more invalid frames exhausting the shared
    verification-overflow budget -- and the legitimate peer's next valid
    frame must still get through, and continue to for as long as its own
    reserved (but finite) budget allows.
    """
    rc, output = _compile_and_run_host_test("espnow_starvation_test.c")
    assert rc == 0, f"behavioral test failed:\n{output}"


def test_r5_03_ota_journal_behavioral():
    """R5-03 (MEDIUM): the OTA counter/partition journal must stay
    consistent across power loss at every phase boundary.

    Executes ota_verify.h's actual staging/commit/recovery functions
    (including _ota_verify_recover(), invoked exactly as the real firmware
    calls it from ota_verify_init() at boot) across five scenarios: power
    loss before the boot-partition switch takes effect (must NOT burn the
    counter, and the same manifest must be retryable afterward), power loss
    after the switch but before commit (must finish committing), a clean
    same-boot completion, esp_ota_set_boot_partition() itself failing, and
    a crash during final journal cleanup after the counter is already
    committed.
    """
    rc, output = _compile_and_run_host_test("ota_journal_test.c")
    assert rc == 0, f"behavioral test failed:\n{output}"


if __name__ == "__main__":
    # Run all test_* functions and report.
    tests = [(name, obj) for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {name}: {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
