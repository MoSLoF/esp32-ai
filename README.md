# esp32-ai: a 28.9M-parameter LLM on ESP32 microcontrollers

[![CI](https://github.com/MoSLoF/esp32-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/MoSLoF/esp32-ai/actions/workflows/ci.yml)

A fork of [slvDev/esp32-llm](https://github.com/slvDev/esp32-llm), which runs a
28.9 million parameter language model entirely on an ESP32-S3. This fork ports
it to the ESP32-P4 and adds a networking layer so boards can find each other,
verify each other's models, and pass signed messages and firmware updates
around.

![28.9M-parameter LLM running on an ESP32-S3 (upstream demo)](media/esp32-ple-demo.gif)

## Status

Be clear-eyed about what has and hasn't been proven:

| Part | State |
| --- | --- |
| S3 inference (`firmware/esp32_llm`) | Measured on hardware upstream: ~9.5 tok/s on an ESP32-S3 N16R8 |
| P4 inference (`firmware/esp32_p4`) | Compiles in CI; not yet confirmed on hardware in this repo |
| P4 display, SD card, companion UART | Compile in CI; not hardware-tested |
| P4 ESP-NOW stack (peer protocol, OTA, mesh) | **Blocked**: doesn't build for the P4 (see below) |
| ESP-NOW sender, LoRa bridge | Compile in CI; not hardware-tested |
| Crypto, replay, and OTA-journal logic | Behavioral host tests in `firmware/host_verify/` |

**The P4 can't do ESP-NOW yet.** The P4 has no radio. Arduino-ESP32 reaches
its companion ESP32-C6 through `esp_wifi_remote`, which carries Wi-Fi but not
ESP-NOW, so `esp_now_*` never links. Espressif's own ESP-NOW library says the
same thing. Enabling `USE_ESPNOW`, `USE_PEER_PROTOCOL`, `USE_OTA` or
`USE_MESH` on the P4 stops the build with an explicit error. Likely ways
forward: run the ESP-NOW side on the C6 itself and bridge to the P4 over UART
or SDIO, or put the P4 networking on an S3 (which has native ESP-NOW).

## How the model fits (upstream's idea)

A microcontroller has very little fast memory: the ESP32-S3 has 512KB of SRAM.
Normally the whole model has to be reachable from there, which is why the
previous LLM on a chip like this had 260 thousand parameters.

The trick is that most of a language model's parameters sit in an embedding
table, which the model looks rows up in rather than computing on. So the
25-million-row table stays in slow flash, and each token pulls only the few rows
it needs (about 450 bytes), while the small part that does the actual work stays
in fast memory. This is Google's Per-Layer Embeddings design from Gemma 3n and
Gemma 4, applied to a microcontroller's memory layout.

```
  SRAM  (fast, tiny)   the "thinking" core, used on every token
  PSRAM (medium)       the output head and working memory
  FLASH (huge, slow)   the 25M-param table, about 6 rows read per token (~450 B)
```

|              |                                                               |
| ------------ | ------------------------------------------------------------- |
| Parameters   | 28.9M stored (25M of them in a flash lookup table)            |
| Speed (S3)   | about 9.5 tok/s end to end (9.7 tok/s of pure compute)        |
| Model size   | 14.9MB at 4-bit                                               |
| Connectivity | none needed: inference runs entirely on the device            |

The model is trained on TinyStories, so it writes short, simple stories. It
won't answer questions, follow instructions, or know facts. The interesting
part is the memory architecture, not what a 28.9M-parameter model can say.
The method, ablations and on-chip measurements are in [`RESULTS.md`](RESULTS.md).

## What this fork adds

All in `firmware/`, each P4 feature behind a `USE_*` flag in `esp32_p4.ino`
(default off; override with `-DUSE_X=1`):

- **ESP32-P4 port** (`esp32_p4/`): same model and `common/llm.h` runtime as
  the S3, with P4 platform plumbing. See [`esp32_p4/README.md`](firmware/esp32_p4/README.md).
- **Peer protocol** (`peer_protocol.h`, `peer_identity.h`): boards discover
  each other and challenge each other with prompts to check they run the same
  model.
- **Signed frames** (`crypto_peer.h`, `common/crypto_envelope.h`): HMAC with
  per-sender epochs and replay protection. `CRYPTO_PSK` must be provided at
  build time; there's no default key.
- **OTA over ESP-NOW** (`ota_espnow.h`, `ota_verify.h`): ECDSA P-256 signed
  manifests, anti-rollback, and a recovery journal. Keys come from
  `tools/ota_keygen.py`; manifests are signed with `tools/ota_sign_manifest.py`.
- **Mesh relay** (`mesh_relay.h`), **SD card config and logging**
  (`sd_config.h`), **companion UART JSON** (`companion_uart.h`), and a
  **MIPI-DSI display** driver (`display.h`).
- **Companion sketches**: `espnow_sender/` (prompt sender and OTA pusher for
  any ESP32 with native Wi-Fi) and `lora_bridge/` (links clusters beyond
  ESP-NOW range).

Several rounds of adversarial security review shaped the crypto and OTA code;
the commit history records each finding and fix.

## Layout

```
src/                 training, quantization, export (PyTorch)
data/                TinyStories preparation
experiments/         ablation and sweep runners
firmware/common/     portable C inference runtime + crypto envelope
firmware/esp32_llm/  S3 sketch (upstream)
firmware/esp32_p4/   P4 sketch and feature headers (this fork)
firmware/host_verify/  host-side C tests and golden verification
tests/               firmware smoke tests
tools/               OTA key/manifest tools, CI helpers
```

## Building and testing

The S3 build, flashing and model export are in
[`firmware/esp32_llm/README.md`](firmware/esp32_llm/README.md); the P4 build is
in [`firmware/esp32_p4/README.md`](firmware/esp32_p4/README.md).

CI runs on every push and pull request:

- `python tests/smoke_test_p4.py`: static checks on the firmware sources, plus
  the behavioral C tests in `firmware/host_verify/`. Needs only Python 3.12 and
  a C compiler.
- `tools/ci_compile.sh`: compiles every sketch with arduino-cli against
  Arduino-ESP32 3.3.10, including the P4 with all buildable features on. It
  writes a stub `vocab.h` and throwaway keys, so its binaries are for compile
  checking only. Never flash them.

## Credit

The model, training pipeline, S3 firmware and results are
[slvDev](https://github.com/slvDev)'s work in
[esp32-llm](https://github.com/slvDev/esp32-llm), MIT licensed (see
[`LICENSE`](LICENSE)). Upstream left its messy history in on purpose,
including a parameter-accounting bug found and corrected along the way;
`RESULTS.md` shows where the numbers moved and why.

Upstream builds on TinyStories (Ronen Eldan and Yuanzhi Li, Microsoft Research,
[arXiv:2305.07759](https://arxiv.org/abs/2305.07759)), Google's Per-Layer
Embeddings from the Gemma models, and Andrej Karpathy's
[llama2.c](https://github.com/karpathy/llama2.c).
