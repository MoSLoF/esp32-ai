"""Prepare training data: tokenize text into uint16 bins for train.py.

Data source (pick one via CLI flags):
  --input <path>      Local text file(s) or directory. Documents separated by
                      <|endoftext|> or one file per document. No downloads.
  (no --input)        Downloads a 300MB TinyStories slice from HuggingFace
                      (original behavior, requires `requests`).

Tokenizer backend (pick one):
  --backend hf        HuggingFace `tokenizers` library (fast, Rust-based, default)
  --backend sp        SentencePiece (Google, `pip install sentencepiece`)
  --backend json      Reload an existing bpe*.json without training (skip-only)

The vocab is deliberately fixed across every ablation arm: cross-entropy is only
comparable between models that share a tokenizer.
"""

import argparse
import glob
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "https://huggingface.co/datasets/roneneldan/TinyStories/resolve/main/TinyStories-train.txt"
RAW = os.path.join(HERE, "tinystories_slice.txt")
VOCAB_SIZE = 4096
SLICE_BYTES = 300 * 1024 * 1024
VAL_FRACTION = 0.005
EOT = "<|endoftext|>"


# ---- data loading -----------------------------------------------------------

def load_local(paths):
    """Load text from local file(s) or a directory. Returns one string with
    <|endoftext|> delimiters between documents."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "**", "*.txt"), recursive=True)))
        else:
            files.append(p)
    if not files:
        print(f"no .txt files found in {paths}", file=sys.stderr)
        sys.exit(1)
    parts = []
    for f in files:
        with open(f, "r", encoding="utf-8", errors="ignore") as fh:
            parts.append(fh.read())
        print(f"  loaded {f} ({os.path.getsize(f) / 1e6:.1f} MB)")
    text = EOT.join(parts)
    if not text.endswith(EOT):
        text += EOT
    return text


def download_tinystories():
    """Download a slice of TinyStories (requires `requests`)."""
    if os.path.exists(RAW) and os.path.getsize(RAW) >= SLICE_BYTES * 0.99:
        print(f"already have {RAW}")
    else:
        import requests
        print(f"downloading first {SLICE_BYTES / 1e6:.0f}MB of TinyStories...")
        got = 0
        with requests.get(URL, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(RAW, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 20):
                    f.write(chunk)
                    got += len(chunk)
                    if got >= SLICE_BYTES:
                        break
                    if got % (25 << 20) < (1 << 20):
                        print(f"  {got / 1e6:.0f}MB", flush=True)
        print(f"done, {got / 1e6:.0f}MB")
    with open(RAW, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    text = text[: text.rfind(EOT) + len(EOT)]
    return text


# ---- tokenizer backends ----------------------------------------------------

def train_tokenizer_hf(text):
    """HuggingFace `tokenizers` backend (the original)."""
    from tokenizers import Tokenizer, decoders, models, pre_tokenizers, trainers
    path = os.path.join(HERE, f"bpe{VOCAB_SIZE}.json")
    if os.path.exists(path):
        print(f"already have {path}")
        return Tokenizer.from_file(path)
    print(f"training BPE vocab={VOCAB_SIZE} (hf backend)...")
    tok = Tokenizer(models.BPE(unk_token=None))
    tok.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
    tok.decoder = decoders.ByteLevel()
    trainer = trainers.BpeTrainer(
        vocab_size=VOCAB_SIZE,
        special_tokens=[EOT],
        initial_alphabet=pre_tokenizers.ByteLevel.alphabet(),
        show_progress=True,
    )
    tok.train_from_iterator([text[: 40 * 1024 * 1024]], trainer=trainer)
    tok.save(path)
    return tok


def train_tokenizer_sp(text):
    """SentencePiece backend (no HuggingFace dependency)."""
    import sentencepiece as spm
    prefix = os.path.join(HERE, f"sp{VOCAB_SIZE}")
    model_path = prefix + ".model"
    if os.path.exists(model_path):
        print(f"already have {model_path}")
        sp = spm.SentencePieceProcessor(model_file=model_path)
        return _SPWrapper(sp)
    train_file = os.path.join(HERE, "_sp_train.txt")
    sample = text[: 40 * 1024 * 1024]
    with open(train_file, "w", encoding="utf-8") as f:
        f.write(sample)
    print(f"training BPE vocab={VOCAB_SIZE} (sentencepiece backend)...")
    spm.SentencePieceTrainer.train(
        input=train_file,
        model_prefix=prefix,
        vocab_size=VOCAB_SIZE,
        model_type="bpe",
        character_coverage=1.0,
        user_defined_symbols=[EOT],
        byte_fallback=True,
    )
    os.remove(train_file)
    sp = spm.SentencePieceProcessor(model_file=model_path)
    return _SPWrapper(sp)


class _SPWrapper:
    """Minimal wrapper so SentencePiece has the same interface as HF tokenizer."""
    def __init__(self, sp):
        self._sp = sp
        self._eot_id = sp.piece_to_id(EOT)

    def token_to_id(self, token):
        return self._sp.piece_to_id(token)

    def get_vocab_size(self):
        return self._sp.get_piece_size()

    def encode(self, text):
        return type("E", (), {"ids": self._sp.encode(text)})()

    def encode_batch(self, texts):
        return [self.encode(t) for t in texts]

    def decode(self, ids):
        return self._sp.decode(ids)

    def save(self, path):
        pass  # sentencepiece model is already saved during training


def load_tokenizer_json():
    """Reload an existing bpe*.json without training (for export/gen_assets)."""
    from tokenizers import Tokenizer
    path = os.path.join(HERE, f"bpe{VOCAB_SIZE}.json")
    if not os.path.exists(path):
        print(f"{path} not found; train a tokenizer first", file=sys.stderr)
        sys.exit(1)
    return Tokenizer.from_file(path)


# ---- main -------------------------------------------------------------------

def main():
    global VOCAB_SIZE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vocab", type=int, default=4096)
    ap.add_argument("--input", nargs="+", default=None,
                    help="local text file(s) or directory (skips HF download)")
    ap.add_argument("--backend", choices=["hf", "sp", "json"], default="hf",
                    help="tokenizer backend: hf (HuggingFace), sp (SentencePiece), "
                         "json (reload existing)")
    args = ap.parse_args()
    VOCAB_SIZE = args.vocab
    suffix = "" if VOCAB_SIZE == 4096 else f"_v{VOCAB_SIZE}"

    # Load text.
    if args.input:
        print(f"loading local data from {args.input}...")
        text = load_local(args.input)
    else:
        text = download_tinystories()
    print(f"total text: {len(text) / 1e6:.1f} MB, "
          f"{text.count(EOT):,} documents")

    # Train or load tokenizer.
    if args.backend == "hf":
        tok = train_tokenizer_hf(text)
    elif args.backend == "sp":
        tok = train_tokenizer_sp(text)
    else:
        tok = load_tokenizer_json()

    eot = tok.token_to_id(EOT)
    print(f"eot id = {eot}")

    # Encode.
    print("encoding...")
    docs = text.split(EOT)
    ids = []
    for i in range(0, len(docs), 20000):
        batch = [d for d in docs[i : i + 20000] if d.strip()]
        for enc in tok.encode_batch(batch):
            ids.extend(enc.ids)
            ids.append(eot)
        print(f"  {i + len(batch)}/{len(docs)} docs, {len(ids) / 1e6:.1f}M tokens", flush=True)

    dtype = np.uint16 if VOCAB_SIZE <= 65536 else np.uint32
    arr = np.array(ids, dtype=dtype)
    assert arr.max() < VOCAB_SIZE
    n_val = int(len(arr) * VAL_FRACTION)
    arr[:-n_val].tofile(os.path.join(HERE, f"train{suffix}.bin"))
    arr[-n_val:].tofile(os.path.join(HERE, f"val{suffix}.bin"))
    print(f"train {len(arr) - n_val:,} tokens / val {n_val:,} tokens")
    print(f"compression: {len(text) / len(arr):.2f} bytes/token")


if __name__ == "__main__":
    sys.exit(main())
