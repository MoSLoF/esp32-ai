# ESP32-P4 on-chip inference

This sketch runs the 28.9M-parameter PLE TinyLM on an ESP32-P4 development
board. Same model binary, same `llm.h` inference engine, same vocab as the S3
build — the P4 port changes only the platform plumbing.

Tested with the Waveshare ESP32-P4-Module and ESP32-P4-WIFI6 dev boards
(ESP32-P4NRW32 module, 32 MB flash, 32 MB PSRAM).

## What's different from the S3 build

| | ESP32-S3 | ESP32-P4 |
|---|---|---|
| CPU | 2x Xtensa LX7 @ 240 MHz | 2x RISC-V HP @ 400 MHz |
| SRAM | 512 KB | 768 KB |
| PSRAM | 8 MB OPI (~60 MB/s) | 32 MB (~200 MB/s) |
| Flash | 16 MB | 32 MB |
| Model partition | 14.875 MB | 30.875 MB |
| Display | SPI ST7789 / I2C OLED | MIPI-DSI (Phase 2) |
| WiFi/BLE | Built-in | Companion C6 via SDIO |

## Build and verify

Export and verify the model (identical to the S3 workflow):

```bash
cd src
uv run python export.py
cd ..
cc -O3 -o /tmp/esp32-llm-verify firmware/host_verify/verify.c -lm
/tmp/esp32-llm-verify firmware/model/model.bin firmware/model/golden.txt
```

Build with Arduino ESP32 core (requires P4 support, core 3.x+):

```bash
arduino-cli compile \
  --fqbn 'esp32:esp32:esp32p4:CPUFreq=400,FlashMode=qio,FlashSize=32M,PartitionScheme=custom,PSRAM=enabled' \
  --build-property compiler.optimization_flags=-O3 \
  --build-path /tmp/esp32-p4-build \
  firmware/esp32_p4
```

**Note:** The ESP32-P4 Arduino board package is evolving. If the FQBN above
doesn't match your installed board definitions, run `arduino-cli board details
--fqbn esp32:esp32:esp32p4` to list available options, and adjust `CPUFreq`,
`PSRAM`, and `FlashSize` accordingly. Alternatively, build with ESP-IDF
directly using `idf.py` (the code is ESP-IDF-compatible C).

## Flash and run

```bash
arduino-cli upload \
  -p /dev/ttyUSB0 \
  --fqbn 'esp32:esp32:esp32p4:CPUFreq=400,FlashMode=qio,FlashSize=32M,PartitionScheme=custom,PSRAM=enabled' \
  --input-dir /tmp/esp32-p4-build \
  firmware/esp32_p4

esptool.py --chip esp32p4 --port /dev/ttyUSB0 --baud 921600 \
  write_flash 0x110000 firmware/model/model.bin

arduino-cli monitor -p /dev/ttyUSB0 --config baudrate=115200
```

The model partition offset is the same as S3 (`0x110000`), but the partition
is larger (30.875 MB vs 14.875 MB) to accommodate future larger models.

## Expected output

```text
=== ESP32-P4 PLE TinyLM ===
model: V=32768 D=96 L=6 H=4 F=66 P=128  (mapped 14.9 MB)
head staged int8: 2.53 MB
PSRAM free after alloc: ~26000 KB

>>> Once upon a time ...
```

## Phase 2: MIPI-DSI display

The 7" 1024x600 IPS panel on the Waveshare ESP32-P4-WIFI6-Touch-LCD-7B
connects via MIPI-DSI, not SPI. A `display.h` for this panel is planned.
Set `USE_DISPLAY 1` once it's written — the sketch's display API
(`display_begin`, `display_puts`, `display_stats`) is identical to the S3
build.

## Phase 3: Voice output (TTS)

The Waveshare boards with the ES8311 audio codec and onboard microphones
support text-to-speech via ESP-IDF's `esp_tts`. Planned integration:
generated tokens stream to both serial and TTS, with the ES7210 echo
cancellation chip keeping the mic live during playback.
