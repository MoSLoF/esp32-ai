#!/usr/bin/env python3
"""Push a firmware binary to an ESP-NOW OTA sender device over serial.

Usage:
    python tools/ota_push.py /dev/ttyUSB0 firmware.bin

The sender device must be running the espnow_sender sketch with OTA
support. This script uploads the binary, then tells the sender to
broadcast an OTA offer so nearby P4 boards can pull the update.
"""

import argparse
import os
import struct
import sys
import time

def crc32(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 & -(c & 1))
    return c ^ 0xFFFFFFFF

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", help="serial port (e.g. /dev/ttyUSB0, COM3)")
    ap.add_argument("firmware", help="firmware .bin file to push")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--manifest", help="signed manifest file (required for push)")
    ap.add_argument("--no-push", action="store_true",
                    help="upload only, don't auto-start the ESP-NOW push")
    args = ap.parse_args()

    fw_path = args.firmware
    if not os.path.isfile(fw_path):
        print(f"file not found: {fw_path}", file=sys.stderr)
        return 1

    fw = open(fw_path, "rb").read()
    fw_crc = crc32(fw)
    print(f"firmware: {len(fw)} bytes, CRC32: 0x{fw_crc:08X}")

    try:
        import serial
    except ImportError:
        print("pyserial required: pip install pyserial", file=sys.stderr)
        return 1

    ser = serial.Serial(args.port, args.baud, timeout=5)
    time.sleep(0.5)
    ser.reset_input_buffer()

    # Send upload command.
    cmd = f"ota {len(fw)}\n".encode()
    print(f"sending: {cmd.strip().decode()}")
    ser.write(cmd)

    # Wait for READY.
    deadline = time.time() + 10
    while time.time() < deadline:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            print(f"  < {line}")
        if line == "READY":
            break
    else:
        print("timeout waiting for READY", file=sys.stderr)
        ser.close()
        return 1

    # Stream firmware.
    print(f"uploading {len(fw)} bytes...")
    chunk = 4096
    sent = 0
    while sent < len(fw):
        n = min(chunk, len(fw) - sent)
        ser.write(fw[sent:sent + n])
        sent += n
        pct = sent * 100 // len(fw)
        print(f"\r  {sent}/{len(fw)} ({pct}%)", end="", flush=True)
    print()

    # Wait for OK.
    deadline = time.time() + 15
    ok = False
    while time.time() < deadline:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            print(f"  < {line}")
        if line.startswith("OK"):
            ok = True
            break
    if not ok:
        print("upload failed", file=sys.stderr)
        ser.close()
        return 1

    # FR-04: upload manifest if provided.
    if args.manifest:
        if not os.path.isfile(args.manifest):
            print(f"manifest not found: {args.manifest}", file=sys.stderr)
            ser.close()
            return 1
        manifest = open(args.manifest, "rb").read()
        print(f"uploading manifest: {len(manifest)} bytes")
        ser.write(f"manifest {len(manifest)}\n".encode())
        deadline = time.time() + 5
        while time.time() < deadline:
            line = ser.readline().decode(errors="replace").strip()
            if line:
                print(f"  < {line}")
            if line == "READY":
                break
        else:
            print("timeout waiting for manifest READY", file=sys.stderr)
            ser.close()
            return 1
        ser.write(manifest)
        deadline = time.time() + 5
        while time.time() < deadline:
            line = ser.readline().decode(errors="replace").strip()
            if line:
                print(f"  < {line}")
            if "manifest loaded" in line.lower():
                break

    if args.no_push:
        print("upload complete (--no-push: not starting ESP-NOW transfer)")
        ser.close()
        return 0

    # FR-04: require manifest for push.
    if not args.manifest:
        print("error: --manifest is required for OTA push (firmware signing is mandatory)",
              file=sys.stderr)
        ser.close()
        return 1

    # Start ESP-NOW push.
    print("starting ESP-NOW OTA push...")
    ser.write(b"push\n")
    time.sleep(0.5)

    # Monitor progress.
    try:
        while True:
            line = ser.readline().decode(errors="replace").strip()
            if line:
                print(f"  {line}")
            if "complete" in line.lower():
                break
    except KeyboardInterrupt:
        print("\ninterrupted")

    ser.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
