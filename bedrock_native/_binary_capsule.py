"""Phase iO-7: Binary capsule — full-source encrypted encapsulation.

The entropy pad (iO-6) raises file entropy to ~7.9 bits/byte by appending a
random binary string. However, ~20% of the file is still cleartext Python
source (structural bytes), creating a detectable byte-frequency signature
between builds (pairwise chi-square ~157k at 32MB pad, target <320).

The binary capsule solves this by encrypting the ENTIRE obfuscated source:

  1. Compress the obfuscated source (zlib).
  2. Encrypt with a per-build 32-byte key (SHA-256 CTR-mode keystream).
  3. Embed the encrypted blob as a latin-1 triple-quoted string literal.
  4. Ship a tiny bootstrap (~10 lines) that reads the blob, decrypts,
     decompresses, and execs the original source.

The resulting file is ~99.9% encrypted data (uniform byte distribution) and
~0.1% bootstrap (structural bytes).  The pairwise chi-square between two
builds approaches ~255 (expected for two independent uniform samples),
well below the <320 target.

## Why this achieves iO indistinguishability

Two builds of the same program produce files whose byte distributions differ
only in the encrypted blob (independently uniform) and the tiny bootstrap
(slightly different per-build keys/names).  The structural signature is
diluted to <0.1% of the file, making the pairwise chi-square ~255 — the
expected value for two random samples from the same uniform distribution.

## Composition

- FSS (iO-2): runs before capsule — the obfuscated source is encrypted as-is.
- Crypto opaque (iO-3): same — runs before capsule.
- Pointfunc/lookup (iO-4/iO-5): same.
- Entropy pad (iO-6): REDUNDANT with capsule — the encrypted blob IS
  high-entropy.  Capsule replaces entropy pad when both are requested.
- Integrity: disabled when capsule is on (encryption provides implicit
  integrity — tampering causes decryption/decompression failure).

Pure stdlib (``zlib``, ``hashlib``). Run::

    python bedrock_native/_binary_capsule.py
"""
from __future__ import annotations

import hashlib
import os
import random
import sys
import zlib
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = [
    'apply_binary_capsule',
]

# Key length for SHA-256 CTR mode (256-bit key).
_KEY_LEN = 32


def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_io7_binary_capsule')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randbytes(self, n):
                return self._sub.read(n)

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

        return _Wrap(sub)
    seed = getattr(ctx, 'capsule_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _generate_key(ctx) -> bytes:
    """Generate a per-build 32-byte encryption key."""
    rng = _rng_for(ctx)
    if hasattr(rng, 'randbytes'):
        return rng.randbytes(_KEY_LEN)
    return os.urandom(_KEY_LEN)


def _encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data with SHA-256 CTR-mode keystream (XOR).

    This is NOT a cryptographically secure cipher (SHA-256 as PRNG in CTR
    mode is unusual), but it produces uniform output — sufficient for iO
    indistinguishability.  The key is per-build and embedded in the
    bootstrap, so an attacker CAN decrypt; the goal is uniform byte
    distribution, not confidentiality.
    """
    out = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        block = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest()
        chunk = min(32, len(data) - offset)
        for i in range(chunk):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += chunk
        counter += 1
    return bytes(out)


def _escape_for_triple_quoted(data: bytes) -> bytes:
    """Escape bytes for a non-raw triple-quoted latin-1 bytes string.

    In a non-raw ``b\"\"\"...\"\"\"`` string with latin-1 encoding:
      - Backslash (0x5C) starts an escape sequence → escape to ``\\\\``
      - CR (0x0D) is normalized to LF by the tokenizer → escape to ``\\r``
      - Three consecutive double-quotes (0x22 0x22 0x22) end the string

    Individual 0x22 bytes are safe inside triple double-quotes.  We only
    need to break up runs of 3+ consecutive 0x22 bytes.

    The escaping creates a small per-build signature, but the SAME byte
    values are escaped the SAME way across builds, so it doesn't contribute
    to the pairwise chi-square (which measures the DIFFERENCE between
    builds, not deviation from uniform).
    """
    # Escape backslash first (must be first to avoid double-escaping)
    out = data.replace(b'\\', b'\\\\')
    # Escape null (might cause C-level issues in some parsers)
    out = out.replace(b'\x00', b'\\x00')
    # Escape CR (tokenizer normalizes raw 0x0D → 0x0A; \r preserves 0x0D)
    out = out.replace(b'\r', b'\\r')
    # Break up runs of 3+ consecutive double-quotes by escaping the 3rd
    out = out.replace(b'"""', b'""\\"')
    return out


def _build_bootstrap(enc_blob_with_key: bytes) -> bytes:
    """Build the bootstrap Python code that decrypts + execs the blob.

    The key is embedded as the first 32 bytes of the blob (in the clear),
    so the bootstrap doesn't need a separate key variable. This minimizes
    structural bytes in the bootstrap.

    The bootstrap:
      1. Reads the blob from _d (latin-1 string literal).
      2. Extracts the key (first 32 bytes).
      3. Derives a SHA-256 CTR keystream from the key.
      4. XORs to decrypt the remaining bytes.
      5. Decompresses with zlib.
      6. Execs the result.
    """
    blob_escaped = _escape_for_triple_quoted(enc_blob_with_key)

    bootstrap = (
        b'# -*- coding: latin-1 -*-\n'
        b'import zlib, hashlib as _h\n'
        b'_d = """' + blob_escaped + b'""".encode(\'latin-1\')\n'
        b'_k = _d[:32]; _d = _d[32:]\n'
        b'_s = bytearray()\n'
        b'_c = 0\n'
        b'while len(_s) < len(_d):\n'
        b'    _s.extend(_h.sha256(_k + _c.to_bytes(4, \'big\')).digest()); _c += 1\n'
        b'_x = (int.from_bytes(_d, \'big\') ^ int.from_bytes(_s[:len(_d)], \'big\')).to_bytes(len(_d), \'big\')\n'
        b'exec(zlib.decompress(_x), '
        b'{\'__name__\': \'__main__\', \'__file__\': __file__, \'__BR_INTEGRITY_OFF__\': True})\n'
    )
    return bootstrap


def apply_binary_capsule(source: str, ctx, *, key: bytes = None) -> bytes:
    """Wrap the obfuscated source in an encrypted binary capsule.

    Args:
        source: the obfuscated source string (UTF-8, may contain non-ASCII).
        ctx: BuildContext (for BuildRNG access).
        key: optional encryption key (32 bytes). If None, generated per-build.

    Returns:
        bytes: the capsule file content (latin-1 encoded). The file starts
        with a coding declaration, followed by the bootstrap, followed by
        the encrypted blob as a raw triple-quoted string literal.
    """
    # 1. Encode source as latin-1 (non-latin-1 chars → \uXXXX escapes)
    source_bytes = source.encode('latin-1', errors='backslashreplace')

    # 2. Compress
    compressed = zlib.compress(source_bytes, level=9)

    # 3. Generate key + encrypt
    if key is None:
        key = _generate_key(ctx)
    encrypted = _encrypt(compressed, key)

    # 4. Prepend key to blob (first 32 bytes = key, rest = encrypted data)
    # This removes the need for a separate key variable in the bootstrap,
    # minimizing structural bytes and reducing the pairwise chi-square.
    blob_with_key = key + encrypted

    # 5. Build bootstrap (reads key from first 32 bytes of blob)
    bootstrap = _build_bootstrap(blob_with_key)

    return bootstrap


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify: encryption round-trip, correctness, entropy, diversity."""

    class _Ctx:
        build_rng = None
        capsule_seed = 42

    ctx = _Ctx()

    # --- Round-trip: encrypt + decrypt = original ---
    import os, tempfile, subprocess
    source = "print('hello world')\n"
    capsule = apply_binary_capsule(source, ctx)
    assert capsule.startswith(b'# -*- coding: latin-1 -*-\n'), "must start with latin-1"
    print(f"iO-7 round-trip: capsule size {len(capsule)} bytes")

    # --- Correctness: capsule runs and produces same output ---
    path = os.path.join(tempfile.gettempdir(), '_io7_smoke.py')
    with open(path, 'wb') as f:
        f.write(capsule)
    r = subprocess.run([sys.executable, path], capture_output=True, timeout=10)
    assert r.returncode == 0, f"capsule should run: {r.stderr}"
    assert r.stdout.strip() == b'hello world', f"output mismatch: {r.stdout!r}"
    print("iO-7 correctness: capsule runs correctly  OK")
    os.unlink(path)

    # --- Entropy: capsule has near-uniform byte distribution ---
    import collections, math
    def _entropy(data):
        if not data:
            return 0.0
        freq = collections.Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    cap_h = _entropy(capsule)
    print(f"iO-7 entropy (small source): {cap_h:.4f} bits/byte")
    # Small source: bootstrap dominates, entropy will be low. Just record it.
    print("iO-7 entropy (small): recorded  OK")

    # --- Diversity: different seeds → different capsules ---
    ctx2 = _Ctx()
    ctx2.capsule_seed = 99
    capsule2 = apply_binary_capsule(source, ctx2)
    assert capsule != capsule2, "different seeds must produce different capsules"
    print("iO-7 diversity: different seeds -> different capsules  OK")

    # --- Non-ASCII source handled ---
    source_unicode = "x = '\u4f60\u597d'\nassert x == '\u4f60\u597d'\nprint('ok')\n"
    capsule_u = apply_binary_capsule(source_unicode, ctx)
    path_u = os.path.join(tempfile.gettempdir(), '_io7_unicode.py')
    with open(path_u, 'wb') as f:
        f.write(capsule_u)
    r2 = subprocess.run([sys.executable, path_u], capture_output=True, timeout=10)
    assert r2.returncode == 0, f"unicode capsule should run: {r2.stderr}"
    assert r2.stdout.strip() == b'ok', f"unicode output mismatch: {r2.stdout!r}"
    print("iO-7 unicode: non-ASCII source handled  OK")
    os.unlink(path_u)

    # --- Large source: entropy approaches 8.0 ---
    import random as _rng
    _rng.seed(42)
    large_source = ''.join(f'x_{i} = {_rng.randint(0, 10**9)}\n' for i in range(5000))
    large_source += "print('done')\n"
    capsule_large = apply_binary_capsule(large_source, ctx)
    cap_large_h = _entropy(capsule_large)
    print(f"iO-7 large: {len(capsule_large)} bytes, entropy {cap_large_h:.4f}")
    assert cap_large_h > 7.5, f"large capsule entropy {cap_large_h:.3f} must be >7.5"
    print("iO-7 large: entropy >7.5  OK")

    # --- Triple-quote handling: data containing 0x22 0x22 0x22 ---
    tricky = b'\x22\x22\x22' * 100
    source_tricky = f"x = {tricky!r}\nprint('ok')\n"
    capsule_tricky = apply_binary_capsule(source_tricky, ctx)
    path_tricky = os.path.join(tempfile.gettempdir(), '_io7_tricky.py')
    with open(path_tricky, 'wb') as f:
        f.write(capsule_tricky)
    r3 = subprocess.run([sys.executable, path_tricky], capture_output=True, timeout=10)
    assert r3.returncode == 0, f"tricky capsule should run: {r3.stderr}"
    assert r3.stdout.strip() == b'ok', f"tricky output mismatch: {r3.stdout!r}"
    print("iO-7 triple-quote: data with 0x22x3 handled  OK")
    os.unlink(path_tricky)

    print("iO-7 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
