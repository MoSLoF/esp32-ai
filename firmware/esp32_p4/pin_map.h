// Central pin assignments for the ESP32-P4.
//
// All pins can be overridden at compile time with -D flags.
// Defaults target the Waveshare ESP32-P4-NANO dev kit.
//
// Include this header early in esp32_p4.ino (before other module headers)
// to override defaults in one place rather than editing each header.

#ifndef PIN_MAP_H
#define PIN_MAP_H

// ---- SD card (SDMMC Slot 1) ------------------------------------------------
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

// ---- Companion UART (Serial1) ----------------------------------------------
#ifndef COMPANION_TX_PIN
#define COMPANION_TX_PIN 17
#endif
#ifndef COMPANION_RX_PIN
#define COMPANION_RX_PIN 18
#endif
#ifndef COMPANION_BAUD
#define COMPANION_BAUD   115200
#endif

#endif
