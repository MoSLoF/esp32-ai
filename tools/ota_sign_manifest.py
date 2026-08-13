#!/usr/bin/env python3
"""Sign an OTA firmware manifest with an ECDSA P-256 private key.

Produces a binary manifest file that the sender device broadcasts
before the OTA offer. The receiver verifies the signature against
its built-in public key.

Usage:
    python tools/ota_sign_manifest.py firmware.bin \
        --key ota_release.key \
        --counter 1 \
        --product esp32-p4-ple \
        -o manifest.bin
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

OTA_MANIFEST_MAGIC = 0x4F544153  # "OTAS"
OTA_MANIFEST_VERSION = 1
OTA_PRODUCT_ID_LEN = 12
OTA_SIGNED_LEN = 58  # magic(4) + version(2) + counter(4) + size(4) + product(12) + sha256(32)

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("firmware", help="firmware .bin file to sign")
    ap.add_argument("--key", required=True, help="ECDSA P-256 private key (PEM)")
    ap.add_argument("--counter", type=int, required=True,
                    help="monotonic security counter (must exceed device's stored value)")
    ap.add_argument("--product", default="esp32-p4-ple",
                    help="product ID (max 12 chars, default: esp32-p4-ple)")
    ap.add_argument("-o", "--output", default="manifest.bin",
                    help="output manifest file (default: manifest.bin)")
    args = ap.parse_args()

    if not os.path.isfile(args.firmware):
        print(f"firmware not found: {args.firmware}", file=sys.stderr)
        return 1
    if not os.path.isfile(args.key):
        print(f"key not found: {args.key}", file=sys.stderr)
        return 1

    fw = open(args.firmware, "rb").read()
    fw_sha256 = hashlib.sha256(fw).digest()

    product_id = args.product.encode()[:OTA_PRODUCT_ID_LEN]
    product_id = product_id.ljust(OTA_PRODUCT_ID_LEN, b'\x00')

    # Build the signed portion.
    signed_data = struct.pack("<IHI I",
                               OTA_MANIFEST_MAGIC,
                               OTA_MANIFEST_VERSION,
                               args.counter,
                               len(fw))
    signed_data += product_id
    signed_data += fw_sha256
    assert len(signed_data) == OTA_SIGNED_LEN

    # Sign with openssl.
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(signed_data)
        tf.flush()
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", args.key, tf.name],
            capture_output=True)
        os.unlink(tf.name)

    if r.returncode != 0:
        print(f"openssl sign failed: {r.stderr.decode()}", file=sys.stderr)
        return 1

    signature = r.stdout
    if len(signature) > 72:
        print(f"warning: signature is {len(signature)} bytes (max 72)", file=sys.stderr)
        return 1

    # Build the full manifest.
    manifest = signed_data
    manifest += struct.pack("B", len(signature))
    manifest += signature
    manifest += b'\x00' * (72 - len(signature))  # pad to fixed size

    with open(args.output, "wb") as f:
        f.write(manifest)

    print(f"manifest: {len(manifest)} bytes -> {args.output}")
    print(f"  firmware: {len(fw)} bytes, SHA-256: {fw_sha256.hex()[:16]}...")
    print(f"  counter:  {args.counter}")
    print(f"  product:  {args.product}")
    print(f"  sig len:  {len(signature)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
