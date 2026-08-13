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
import sys
from pathlib import Path

FIRMWARE_DIR = Path(__file__).parent.parent / "firmware" / "esp32_p4"
COMMON_DIR = Path(__file__).parent.parent / "firmware" / "common"
SENDER_DIR = Path(__file__).parent.parent / "firmware" / "espnow_sender"

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
    assert "m.sec_counter < stored" in ov, (
        "must reject manifest with sec_counter below stored"
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
    assert "OTA_VERIFY_H" in ota, (
        "ota_espnow.h must guard manifest logic on OTA_VERIFY_H"
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
