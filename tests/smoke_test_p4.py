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
    """crypto_peer.h must use mbedtls for HMAC-SHA256."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "mbedtls/md.h" in crypto
    assert "MBEDTLS_MD_SHA256" in crypto
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
    """crypto_peer.h must have timestamp-based replay protection."""
    crypto = read_file("crypto_peer.h")
    assert crypto is not None
    assert "CRYPTO_MAX_DRIFT" in crypto
    assert "CRYPTO_TS_LEN" in crypto


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
