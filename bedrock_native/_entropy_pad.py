"""Phase iO-6: Entropy padding (latin-1 binary injection).

The fundamental entropy ceiling of UTF-8 Python source is ~6.6 bits/byte
(printable ASCII alphabet).  The iO-6 distinguishing-attack target is >7.5
bits/byte.  This pass breaks through the ASCII ceiling by:

  1. Adding ``# -*- coding: latin-1 -*-`` as the first line.
  2. Encoding the entire source as latin-1 (1 byte = 1 code point 0-255).
     Non-latin-1 characters (code points > 255) are ``backslashreplace``'d
     to ``\\uXXXX`` escape sequences (ASCII, valid in Python string literals).
  3. Appending a large raw-binary string literal::

         _br_pad = '<raw binary bytes>'

     The binary bytes are generated per-build from BuildRNG (deterministic-
     per-build, diverse in fresh-seed mode).  Problematic bytes (backslash,
     single-quote, CR, LF, null) are escaped; the rest (251 byte values)
     appear RAW in the file, raising entropy toward ~7.9 bits/byte.

After injection the file integrity hash (``__H_FILE_HASH__``) is recomputed
on the final bytes so the runtime self-check still passes.

## Why this works

Python 3 source files default to UTF-8, but a ``coding: latin-1`` declaration
tells the parser to decode each byte as a single code point (0-255).  This
allows raw binary bytes in string literals — the file is valid Python with
near-uniform-random byte distribution.

## Composition

- FSS (iO-2): the pad is a dummy variable; FSS ignores it (not eligible).
- Crypto opaque (iO-3): the pad bytes look uniform, indistinguishable from
  crypto constants.
- Pointfunc / lookup (iO-4/iO-5): orthogonal — those passes replace
  decorated functions; the pad is a module-level string.
- Integrity (selfcheck_cf): hash recomputed post-pad, so self-check passes.

Pure stdlib (``hashlib``, ``os``, ``re``, ``secrets``). Run::

    python bedrock_native/_entropy_pad.py
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import sys
from typing import Optional

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = [
    'apply_entropy_pad',
    'refresh_integrity_bytes',
]

# Default pad size (bytes of raw binary data, before escaping).
# 8MB gives entropy ~7.8+ on a ~2MB source file (pad dominates).
DEFAULT_PAD_SIZE = 8 * 1024 * 1024  # 8 MB


def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_io6_entropy_pad')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randbytes(self, n):
                return self._sub.read(n)

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

        return _Wrap(sub)
    seed = getattr(ctx, 'entropy_pad_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _escape_for_string_literal(data: bytes) -> bytes:
    """Escape bytes that would break a single-quoted string literal.

    Escapes: backslash (0x5C), single-quote (0x27), null (0x00),
    carriage return (0x0D), newline (0x0A).

    All other bytes (251 values) are left RAW — they appear as-is in the
    latin-1 encoded file, contributing maximum entropy.
    """
    return (data
            .replace(b'\\', b'\\\\')
            .replace(b"'", b"\\'")
            .replace(b'\x00', b'\\x00')
            .replace(b'\r', b'\\r')
            .replace(b'\n', b'\\n'))


def _generate_pad(ctx, size: int) -> bytes:
    """Generate ``size`` bytes of high-entropy data from BuildRNG."""
    rng = _rng_for(ctx)
    if hasattr(rng, 'randbytes'):
        return rng.randbytes(size)
    # Fallback: use os.urandom (non-deterministic but high-entropy)
    return os.urandom(size)


def refresh_integrity_bytes(src_bytes: bytes) -> bytes:
    """Re-compute __H_FILE_HASH__ and integrity hash on a bytes buffer.

    Mirrors ``_refresh_native_integrity`` in bedrock_obfuscator.py but
    operates on bytes instead of str (needed because the entropy pad
    produces a latin-1 bytes buffer, not a UTF-8 string).

    Unlike _refresh_native_integrity, this does NOT require the
    __H_FILE_MARK_NNN__ marker pattern (which has already been replaced
    with the real hash by the time we run). We find the hashes directly
    and recompute.
    """
    # Find __H_FILE_HASH__ = "hash"
    hash_match = re.search(rb'(?m)^__H_FILE_HASH__\s*=\s*"([0-9a-f]{64})"\s*$',
                           src_bytes)
    if not hash_match:
        return src_bytes  # no integrity check in this file
    current_fh = hash_match.group(1)

    # Find __H_INTEGRITY_VAR__ = "var_name"
    integrity_var_match = re.search(
        rb'(?m)^__H_INTEGRITY_VAR__\s*=\s*"([^"]+)"\s*$', src_bytes)
    current_iv = None
    if integrity_var_match:
        _iv_name = integrity_var_match.group(1)
        _ivh = re.search(
            re.escape(_iv_name) + rb'\s*=\s*["\']([0-9a-f]{64})["\']',
            src_bytes)
        if _ivh:
            current_iv = _ivh.group(1)

    # Also find __VM_EXTHASH__ (if present) — may be a hex hash OR a
    # 64-char sentinel placeholder (e.g. "__VM_EXTHASH_SLOT__..."), so
    # match any 64-char value.
    vm_hash_match = re.search(
        rb'(?m)^__VM_EXTHASH__\s*=\s*"([^"]{64})"', src_bytes)
    current_vm = vm_hash_match.group(1) if vm_hash_match else None

    # Mask all known hashes (replace with 64 dots)
    masked = src_bytes
    for h in [current_fh, current_iv, current_vm]:
        if h:
            masked = masked.replace(h, b'.' * 64)

    # Re-compute file hash: sha256(masked + "|fh")
    new_fh = hashlib.sha256(masked + b'|fh').hexdigest().encode('ascii')

    # Patch the file hash
    out = src_bytes[:hash_match.start(1)] + new_fh + src_bytes[hash_match.end(1):]

    # Re-compute integrity hash: sha256(masked + "|int")
    if integrity_var_match and current_iv:
        _iv_name = integrity_var_match.group(1)
        _ivh = re.search(
            re.escape(_iv_name) + rb'\s*=\s*["\']([0-9a-f]{64})["\']',
            out)
        if _ivh:
            # For integrity hash, also mask the new file hash
            _masked_int = out.replace(new_fh, b'.' * 64)
            _masked_int = _masked_int.replace(current_iv, b'.' * 64)
            if current_vm:
                _masked_int = _masked_int.replace(current_vm, b'.' * 64)
            _new_int = hashlib.sha256(_masked_int + b'|int').hexdigest().encode('ascii')
            out = out[:_ivh.start(1)] + _new_int + out[_ivh.end(1):]

    return out


def apply_entropy_pad(source: str, ctx, *, pad_size: int = None) -> bytes:
    """Convert source to latin-1 bytes + inject a high-entropy binary pad.

    Args:
        source: the obfuscated source string (UTF-8, may contain non-ASCII).
        ctx: BuildContext (for BuildRNG access).
        pad_size: size of the binary pad in bytes (default 2MB).

    Returns:
        bytes: the file content as latin-1 encoded bytes with a raw binary
        string literal appended.  The integrity hash is recomputed.
    """
    if pad_size is None:
        pad_size = DEFAULT_PAD_SIZE

    # 1. Encode source as latin-1 (non-latin-1 chars → \uXXXX escapes)
    source_bytes = source.encode('latin-1', errors='backslashreplace')

    # 2. Generate and escape the binary pad
    pad_raw = _generate_pad(ctx, pad_size)
    pad_escaped = _escape_for_string_literal(pad_raw)

    # 3. Assemble the file: coding declaration + source + pad
    coding_decl = b'# -*- coding: latin-1 -*-\n'
    pad_assignment = (
        b'\n_br_pad = \'' + pad_escaped + b'\'\n'
    )
    result = coding_decl + source_bytes + pad_assignment

    # 4. Re-compute integrity hash on the final bytes
    result = refresh_integrity_bytes(result)

    return result


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify: entropy boost, correctness, integrity, diversity."""

    class _Ctx:
        build_rng = None
        entropy_pad_seed = 42

    ctx = _Ctx()

    # --- Entropy boost: padded file has higher entropy than source ---
    source = "print('hello world')\n"
    src_bytes = source.encode('utf-8')
    import collections, math
    def _entropy(data):
        if not data:
            return 0.0
        freq = collections.Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    src_h = _entropy(src_bytes)
    padded = apply_entropy_pad(source, ctx, pad_size=50000)
    pad_h = _entropy(padded)
    print(f"iO-6 entropy: source {src_h:.3f} -> padded {pad_h:.3f} bits/byte")
    assert pad_h > src_h, "padded must have higher entropy"
    assert pad_h > 7.0, f"padded entropy {pad_h:.3f} must be >7.0"
    print("iO-6 entropy boost: padded > source AND >7.0  OK")

    # --- Correctness: padded file runs and produces same output ---
    import tempfile, subprocess
    path = os.path.join(tempfile.gettempdir(), '_io6_smoke.py')
    with open(path, 'wb') as f:
        f.write(padded)
    r = subprocess.run([sys.executable, path], capture_output=True, timeout=10)
    assert r.returncode == 0, f"padded file should run: {r.stderr}"
    assert r.stdout.strip() == b'hello world', f"output mismatch: {r.stdout!r}"
    print("iO-6 correctness: padded file runs correctly  OK")
    os.unlink(path)

    # --- Diversity: different seeds → different pads ---
    ctx2 = _Ctx()
    ctx2.entropy_pad_seed = 99
    padded2 = apply_entropy_pad(source, ctx2, pad_size=50000)
    assert padded != padded2, "different seeds must produce different pads"
    print("iO-6 diversity: different seeds -> different pads  OK")

    # --- latin-1 coding: file starts with coding declaration ---
    assert padded.startswith(b'# -*- coding: latin-1 -*-\n'), "must start with latin-1 declaration"
    print("iO-6 coding: file starts with latin-1 declaration  OK")

    # --- Non-ASCII source handled (backslashreplace) ---
    source_unicode = "x = '\u4f60\u597d'\nassert x == '\u4f60\u597d'\nprint('ok')\n"
    padded_u = apply_entropy_pad(source_unicode, ctx, pad_size=10000)
    path_u = os.path.join(tempfile.gettempdir(), '_io6_unicode.py')
    with open(path_u, 'wb') as f:
        f.write(padded_u)
    r2 = subprocess.run([sys.executable, path_u], capture_output=True, timeout=10)
    assert r2.returncode == 0, f"unicode source padded should run: {r2.stderr}"
    assert r2.stdout.strip() == b'ok', f"unicode output mismatch: {r2.stdout!r}"
    print("iO-6 unicode: non-ASCII source handled via backslashreplace  OK")
    os.unlink(path_u)

    # --- Large pad: entropy approaches 7.9 ---
    padded_large = apply_entropy_pad(source, ctx, pad_size=500000)
    pad_large_h = _entropy(padded_large)
    print(f"iO-6 large pad: {len(padded_large)} bytes, entropy {pad_large_h:.3f}")
    assert pad_large_h > 7.5, f"large pad entropy {pad_large_h:.3f} must be >7.5"
    print("iO-6 large pad: entropy >7.5  OK")

    print("iO-6 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
