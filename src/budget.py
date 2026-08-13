"""Three-tier memory accounting for an ESP32 target.

Deliberately separate from `model.py`. That module's `param_budget()` is what
`make_model()` binary-searches against to match core budgets across arms, so
changing its semantics would silently alter every model built afterwards and
break comparability with runs already completed. This file only *reports*.

The three tiers differ by access pattern, not just speed:

  core    dense, random access, every token.
          -> must be SRAM-resident. The genuinely scarce budget.
  stream  dense, but read as one sequential scan per token. The output head is
          the whole story: you need every logit, so you touch the entire matrix,
          but strictly start to finish.
          -> costs BANDWIDTH, not SRAM capacity. Flash and PSRAM are both decent
             at sequential reads, so this can live off-chip.
  table   sparse: one row per token.
          -> ideal for memory-mapped flash.

Treating `stream` as if it were `core` is what made large vocabularies look
unaffordable, when in fact they are merely slow.
"""

import argparse

# ---- Target profiles --------------------------------------------------------
TARGETS = {
    "s3": {
        "name": "ESP32-S3 N16R8",
        "sram": 320 * 1024,       # 512KB internal, minus IDF/stack/buffers
        "psram": 8 * 1024 * 1024,
        "flash": 15 * 1024 * 1024,  # 16MB minus ~1MB firmware
        "psram_bw": 60e6,         # measured 60.7 MB/s OPI
        "flash_bw": 60e6,
    },
    "p4": {
        "name": "ESP32-P4 (Waveshare P4NRW32)",
        "sram": 600 * 1024,       # 768KB internal, minus IDF/stack/buffers
        "psram": 32 * 1024 * 1024,
        "flash": 31 * 1024 * 1024,  # 32MB minus ~1MB firmware
        "psram_bw": 200e6,        # estimated, LPDDR-class
        "flash_bw": 120e6,
    },
}

# Default target for backward compatibility.
_T = TARGETS["s3"]
SRAM_BYTES = _T["sram"]
PSRAM_BYTES = _T["psram"]
FLASH_BYTES = _T["flash"]
PSRAM_BW = _T["psram_bw"]
FLASH_BW = _T["flash_bw"]


def tiers(vocab, d_model, n_layers, ple_dim, ffn_hidden, n_heads=4):
    """Parameter counts per tier for the `ple` architecture."""
    per_layer = (
        4 * d_model * d_model  # attn qkv + out proj
        + 3 * d_model * ffn_hidden  # SwiGLU
        + 2 * d_model * ple_dim  # per-layer gate + projection
    )
    core = n_layers * per_layer + d_model * n_layers * ple_dim  # + ple_model_proj
    stream = vocab * d_model  # output head
    table = vocab * n_layers * ple_dim
    return {"core": core, "stream": stream, "table": table}


def report(bits=4, **kw):
    t = tiers(**kw)
    b = bits / 8
    core_b, stream_b, table_b = (t[k] * b for k in ("core", "stream", "table"))

    # Per token: the whole head is scanned; only n_layers rows of the table are read.
    table_row_b = kw["n_layers"] * kw["ple_dim"] * b
    t_head = stream_b / FLASH_BW
    t_table = table_row_b / FLASH_BW

    print(f"  vocab={kw['vocab']} d={kw['d_model']} L={kw['n_layers']} "
          f"ple_dim={kw['ple_dim']} ffn={kw['ffn_hidden']}  @{bits}-bit")
    print(f"    core   {t['core']:>12,} params  {core_b / 1024:>8.0f} KB   "
          f"{'OK' if core_b <= SRAM_BYTES else 'DOES NOT FIT SRAM'}")
    print(f"    stream {t['stream']:>12,} params  {stream_b / 1024:>8.0f} KB   "
          f"{t_head * 1000:.1f} ms/token")
    print(f"    table  {t['table']:>12,} params  {table_b / 1024 / 1024:>8.2f} MB  "
          f"{'OK' if table_b <= FLASH_BYTES else 'EXCEEDS FLASH'}  "
          f"({table_row_b:.0f} B/token, {t_table * 1000:.3f} ms)")
    total = sum(t.values())
    ceiling = 1.0 / (t_head + t_table)
    print(f"    TOTAL  {total:>12,} params   ratio {total * b / SRAM_BYTES:.0f}x SRAM"
          f"   bandwidth ceiling ~{ceiling:.0f} tok/s (est, compute excluded)\n")
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=4)
    ap.add_argument("--target", choices=list(TARGETS), default=None,
                    help="Target board (default: show all targets)")
    args = ap.parse_args()

    targets = [args.target] if args.target else list(TARGETS)

    for tkey in targets:
        t = TARGETS[tkey]
        global SRAM_BYTES, PSRAM_BYTES, FLASH_BYTES, PSRAM_BW, FLASH_BW
        SRAM_BYTES = t["sram"]
        PSRAM_BYTES = t["psram"]
        FLASH_BYTES = t["flash"]
        PSRAM_BW = t["psram_bw"]
        FLASH_BW = t["flash_bw"]

        print(f"\n{'=' * 60}")
        print(f"{t['name']}: {SRAM_BYTES // 1024}KB usable SRAM, "
              f"{FLASH_BYTES // 1024 // 1024}MB usable flash, "
              f"{PSRAM_BYTES // 1024 // 1024}MB PSRAM\n")

        print("[validated config]")
        report(bits=args.bits, vocab=4096, d_model=128, n_layers=6, ple_dim=64, ffn_hidden=187)

        print("[deploy config]")
        report(bits=args.bits, vocab=32768, d_model=96, n_layers=6, ple_dim=128, ffn_hidden=66)

        if tkey == "p4":
            print("[P4-only: configs that exceed S3 flash]")
            for vocab, d, L, pd, ffn in [
                (32768, 256, 10, 512, 384),
                (32768, 192, 8, 384, 256),
            ]:
                report(bits=args.bits, vocab=vocab, d_model=d, n_layers=L,
                       ple_dim=pd, ffn_hidden=ffn)


if __name__ == "__main__":
    main()
