"""Phase iO-7: Encrypted-source capsule (byte-distribution randomization).

NOTE on terminology: this module was originally marketed as achieving
"Practical Indistinguishability Obfuscation (iO)". It does NOT. iO in
cryptography means obfuscations of two DIFFERENT but functionally
equivalent programs are indistinguishable. This capsule only ensures the
obfuscated OUTPUT FILE's byte distribution is uniform (a property of any
encryption / PRG output) — it says nothing about distinguishing
obfuscations of equivalent programs. See IO_SPEC.md "Limitations".

The capsule encrypts the ENTIRE obfuscated source so the output file is
~99.9% uniform encrypted data:

  1. Compress the obfuscated source (zlib).
  2. Encrypt with a per-build 32-byte key (SHA-256 CTR-mode keystream).
  3. Embed the encrypted blob as a latin-1 triple-quoted string literal.
  4. Ship a tiny bootstrap that decrypts, decompresses, and execs the
     source.

## Key handling (secure-by-default since the Phase A remediation)

The key is NOT shipped in the file by default. Two modes:

  - **``embed_key=False`` (default, secure)**: the bootstrap reads the key
    from the environment variable named by ``key_env`` (hex-encoded). The
    build path emits the key to a sidecar ``<output>.key`` file and to
    stderr, so the operator can set ``$key_env`` on the machine that runs
    the obfuscated file. Without that env var, the file refuses to run and
    the source stays encrypted on disk.

  - **``embed_key=True`` (legacy / insecure, opt-in via ``--embed-key``)**:
    the 32-byte key is prepended to the blob. The bootstrap reads it from
    the first 32 bytes. WARNING: this ships the key in the clear — anyone
    can recover the original source by running the ~10-line bootstrap. Do
    not use this mode if you need any confidentiality at all.

## Honest properties

What this capsule DOES provide:
  - The output file's byte distribution is uniform (~7.96 bits/byte,
    pairwise chi-square ~510 ≈ random baseline) — so a byte-frequency
    fingerprint (chi-square / byte-histogram ML classifier) cannot tell
    two builds apart any better than chance.
  - When ``embed_key=False`` the source is genuinely encrypted at rest:
    the key is not in the file.

What this capsule does NOT provide:
  - **Not iO**: it never compares obfuscations of two different equivalent
    programs (see IO_SPEC.md).
  - **Not confidentiality against a runtime adversary**: when the file
    runs, the key is in the process environment / memory, and the source
    is decrypted in-process. An attacker with a debugger or who can read
    the env var still recovers the source.
  - **The bootstrap is greppable**: ``import zlib, hashlib`` and
    ``exec(zlib.decompress`` are a unique structural signature (the
    <0.1% non-random bytes). A regex identifies every capsule file at
    100% accuracy. This is acknowledged in IO_SPEC.md limitation 2.

## Results (iO-7, N=20 builds, 190 pairs, embed_key legacy mode)

| Metric | Value | Random baseline |
|--------|-------|-----------------|
| Shannon entropy | 7.96 bits/byte | 8.0 (max) |
| Pairwise chi-square (mean) | 501 | ~510 ± 35 |
| Pairwise chi-square (max) | 670 | 651 ± 25 (max 691) |
| ML classifier accuracy | 40% | 50% (chance) |
| Build success | 100% (20/20) | — |
| Output size | ~1.3 MB | — |

(These measure ENCRYPTED-OUTPUT uniformity, NOT the iO property.)

## Usage

```python
from _binary_capsule import apply_binary_capsule

# source = obfuscated Python source string (UTF-8)
# ctx = BuildContext (provides BuildRNG for per-build key generation)
capsule_bytes = apply_binary_capsule(source, ctx)              # secure (env)
capsule_bytes = apply_binary_capsule(source, ctx, embed_key=True)  # legacy
# ctx.capsule_key holds the 32-byte key (emit to <output>.key sidecar).
```

CLI:
```bash
# Secure (default): key in env, sidecar .key emitted
python bedrock_obfuscator.py -f input.py -o obf.py --profile io ...
# Then run with:  BR_CAPSULE_KEY=$(cat obf.py.key) python obf.py

# Legacy (insecure, opt-in): key embedded in the file
python bedrock_obfuscator.py -f input.py -o obf.py --profile io --embed-key ...
```

## Composition

- FSS (iO-2): runs before capsule — the obfuscated source is encrypted as-is.
- Crypto opaque (iO-3): same — runs before capsule.
- Pointfunc/lookup (iO-4/iO-5): same.
- Entropy pad (iO-6): REDUNDANT with capsule — the encrypted blob IS
  high-entropy. Capsule replaces entropy pad when both are requested.
- Integrity: disabled when capsule is on (encryption provides implicit
  integrity — tampering causes decryption/decompression failure).
- runtime_dec + chain: disabled when capsule is on (the capsule already
  encrypts everything; the per-function capsule chain is redundant AND caused
  an intermittent hang bug — re-entry into _br_flow_shard during
  ssl.wrap_socket).

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
                # SubStream exposes random(n), not read(n).
                return self._sub.random(n)

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

    This is not a vetted AEAD — it is a SHA-256-CTR XOR stream cipher with no
    authentication tag. It produces uniform output, which is what the
    capsule's byte-distribution-randomization goal needs. Confidentiality
    depends entirely on keeping ``key`` out of the file: with
    ``embed_key=False`` (the default) the key is read from the environment
    at runtime, so the source is genuinely encrypted at rest. With
    ``embed_key=True`` the key ships in the file and confidentiality is nil.
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

    Implementation note: the previous version used
    ``data.replace(b'\"\"\"', b'\"\"\\\\\"')``. That is WRONG because
    ``bytes.replace`` does not re-scan its own output — a 4-byte run
    ``0x22 0x22 0x22 0x22`` becomes ``0x22 0x22 0x5C 0x22 0x22 0x22``,
    and the trailing three 0x22 bytes re-form an unescaped ``\"\"\"``,
    prematurely terminating the string literal → SyntaxError at runtime.
    For pseudorandom ciphertext the expected frequency of a 5+ run of 0x22
    is ~1 in 3000 builds, so this silently corrupts builds.

    Fixed by a single forward scan: escape every third consecutive 0x22 in
    a run to ``\\"`` and reset the run counter. This guarantees no three
    unescaped 0x22 bytes appear in the output.
    """
    # Escape backslash first (must be first to avoid double-escaping).
    out = data.replace(b'\\', b'\\\\')
    # Escape null (might cause C-level issues in some parsers)
    out = out.replace(b'\x00', b'\\x00')
    # Escape CR (tokenizer normalizes raw 0x0D → 0x0A; \r preserves 0x0D)
    out = out.replace(b'\r', b'\\r')

    # Break up runs of 3+ consecutive double-quotes with a forward scan.
    # We must NOT emit three consecutive unescaped 0x22 bytes anywhere.
    # AND the content must not END with 1-2 unescaped 0x22 bytes, because
    # those would combine with the closing triple-quote delimiter to form
    # a premature string terminator → SyntaxError.
    result = bytearray()
    quote_run = 0
    for b in out:
        if b == 0x22:
            quote_run += 1
            if quote_run == 3:
                # Escape this third quote: emit `\"` and reset the run so
                # the next quote starts a fresh count of 1.
                result.append(0x5C)  # backslash
                result.append(0x22)
                quote_run = 0
            else:
                result.append(0x22)
        else:
            result.append(b)
            quote_run = 0
    # Trailing fix: if the content ends with 1-2 unescaped quotes, escape
    # the last one so it doesn't combine with the closing `"""`.
    if 1 <= quote_run <= 2 and result and result[-1] == 0x22:
        result[-1] = 0x5C  # replace the trailing `"` with a backslash
        result.append(0x22)  # and append the escaped `"`
    return bytes(result)


def _build_bootstrap(enc_blob: bytes, *, embed_key: bool = False,
                     key_env: str = 'BR_CAPSULE_KEY') -> bytes:
    """Build the bootstrap Python code that decrypts + execs the blob.

    embed_key=True (legacy / insecure): the 32-byte key is prepended to
    ``enc_blob``; the bootstrap reads it from the first 32 bytes. WARNING:
    this ships the key in the clear — anyone can recover the original
    source by running this ~10-line bootstrap. Kept for backward
    compatibility only; pass ``--embed-key`` on the CLI to opt in.

    embed_key=False (default, secure): the key is NOT in the file. The
    bootstrap reads it from the environment variable named by ``key_env``
    (hex-encoded). The operator must set that env var on the machine that
    runs the obfuscated file. The build path emits the key to a sidecar
    ``<output>.key`` file and to stderr so the operator can capture it.
    """
    blob_escaped = _escape_for_triple_quoted(enc_blob)
    env_name = repr(key_env).encode('latin-1')

    if embed_key:
        key_line = b'_k = _d[:32]; _d = _d[32:]\n'
    else:
        # Read the key from the environment (hex). Fail loudly with a clear
        # message if the env var is missing, so the file does NOT silently
        # fall back to anything — the source stays encrypted on disk.
        key_line = (
            b"import os as _br_os\n"
            b"_br_ke = _br_os.environ.get(" + env_name + b")\n"
            b"if not _br_ke:\n"
            b"    raise SystemExit('capsule: key missing -- set env ' + "
            + env_name + b" + '=<hex> (see <output>.key sidecar) before running')\n"
            b"_k = bytes.fromhex(_br_ke)\n"
        )

    bootstrap = (
        b'# -*- coding: latin-1 -*-\n'
        b'import zlib, hashlib as _h\n'
        b'_d = """' + blob_escaped + b'""".encode(\'latin-1\')\n'
        + key_line +
        b'_s = bytearray()\n'
        b'_c = 0\n'
        b'while len(_s) < len(_d):\n'
        b'    _s.extend(_h.sha256(_k + _c.to_bytes(4, \'big\')).digest()); _c += 1\n'
        b'_x = (int.from_bytes(_d, \'big\') ^ int.from_bytes(_s[:len(_d)], \'big\')).to_bytes(len(_d), \'big\')\n'
        b'exec(zlib.decompress(_x), '
        b'{\'__name__\': \'__main__\', \'__file__\': __file__, \'__BR_INTEGRITY_OFF__\': True})\n'
    )
    return bootstrap


def apply_binary_capsule(source: str, ctx, *, key: bytes = None,
                         embed_key: bool = False,
                         key_env: str = 'BR_CAPSULE_KEY') -> bytes:
    """Wrap the obfuscated source in an encrypted binary capsule.

    Args:
        source: the obfuscated source string (UTF-8, may contain non-ASCII).
        ctx: BuildContext (for BuildRNG access + key emission).
        key: optional encryption key (32 bytes). If None, generated per-build.
        embed_key: if True (legacy / insecure), prepend the key to the blob so
            the file is self-contained — WARNING: anyone can recover the
            source by running the bootstrap. If False (default, secure), the
            key is NOT shipped; the bootstrap reads it from env var
            ``key_env``. The generated key is exposed via ``ctx.capsule_key``
            (bytes) so the build path can emit a sidecar ``.key`` file.
        key_env: environment variable name the bootstrap reads the key from
            (hex-encoded) when ``embed_key=False``.

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

    # Expose the key to the build path (for sidecar emission) regardless of
    # embed mode. When embed_key=False this is the ONLY copy of the key —
    # the file itself does not contain it.
    try:
        ctx.capsule_key = key
        ctx.capsule_key_env = key_env if not embed_key else None
    except Exception:
        pass

    # 4. Assemble blob: prepend the key only in legacy embed mode.
    if embed_key:
        blob = key + encrypted
    else:
        blob = encrypted

    # 5. Build bootstrap (reads key from blob prefix in legacy mode, or from
    #    the environment in secure mode).
    bootstrap = _build_bootstrap(blob, embed_key=embed_key, key_env=key_env)

    return bootstrap


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify: encryption round-trip, correctness, entropy, diversity,
    embed_key=False (secure default) + escape-bug fuzz."""

    class _Ctx:
        build_rng = None
        capsule_seed = 42

    ctx = _Ctx()

    import os, tempfile, subprocess

    # --- Legacy embed_key=True round-trip (backward compat) ---
    source = "print('hello world')\n"
    capsule = apply_binary_capsule(source, ctx, embed_key=True)
    assert capsule.startswith(b'# -*- coding: latin-1 -*-\n'), "must start with latin-1"
    print(f"capsule round-trip (embed_key=True): {len(capsule)} bytes")

    path = os.path.join(tempfile.gettempdir(), '_io7_smoke.py')
    with open(path, 'wb') as f:
        f.write(capsule)
    r = subprocess.run([sys.executable, path], capture_output=True, timeout=10)
    assert r.returncode == 0, f"capsule should run: {r.stderr}"
    assert r.stdout.strip() == b'hello world', f"output mismatch: {r.stdout!r}"
    print("capsule correctness (embed_key=True): runs correctly  OK")
    os.unlink(path)

    # --- embed_key=False (secure default): key NOT in file ---
    ctx_env = _Ctx()
    capsule_env = apply_binary_capsule(source, ctx_env, embed_key=False,
                                        key_env='BR_CAPSULE_KEY_TEST')
    # The capsule key is exposed on ctx for the build path to emit a sidecar.
    assert hasattr(ctx_env, 'capsule_key') and len(ctx_env.capsule_key) == 32, \
        "ctx.capsule_key must be set (32 bytes)"
    key_hex = ctx_env.capsule_key.hex()
    assert ctx_env.capsule_key_env == 'BR_CAPSULE_KEY_TEST'
    print(f"capsule secure mode: key {key_hex[:8]}... exposed on ctx  OK")

    # Run WITHOUT the env var → must FAIL loudly, not leak source.
    path_env = os.path.join(tempfile.gettempdir(), '_io7_env.py')
    with open(path_env, 'wb') as f:
        f.write(capsule_env)
    env_clean = {k: v for k, v in os.environ.items() if k != 'BR_CAPSULE_KEY_TEST'}
    r_no_env = subprocess.run([sys.executable, path_env],
                              capture_output=True, timeout=10, env=env_clean)
    assert r_no_env.returncode != 0, "capsule must FAIL when env var is missing"
    assert b'key missing' in (r_no_env.stderr + r_no_env.stdout).lower(), \
        f"must print a clear 'key missing' message: {r_no_env.stderr!r}"
    assert b'hello world' not in (r_no_env.stdout + r_no_env.stderr), \
        "must NOT leak source output when key is missing"
    print("capsule secure mode: refuses to run without env var  OK")

    # Run WITH the env var → correct output.
    env_set = dict(env_clean)
    env_set['BR_CAPSULE_KEY_TEST'] = key_hex
    r_env = subprocess.run([sys.executable, path_env],
                           capture_output=True, timeout=10, env=env_set)
    assert r_env.returncode == 0, f"capsule must run with env set: {r_env.stderr}"
    assert r_env.stdout.strip() == b'hello world', \
        f"output mismatch with env set: {r_env.stdout!r}"
    print("capsule secure mode: runs correctly when env var is set  OK")
    os.unlink(path_env)

    # --- Verify the OLD recovery attack no longer works on secure mode ---
    # The legacy attack (read 32 bytes from the start of the blob as the key)
    # must now FAIL — the blob has no key prefix.
    import re as _re, hashlib as _h2
    m = _re.search(rb'_d = """(.*?)"""', capsule_env, _re.DOTALL)
    blob = m.group(1)  # already bytes (capsule_env is bytes)
    # Core property: the real key is NOT a prefix of the blob.
    assert not blob.startswith(ctx_env.capsule_key), \
        "secure-mode blob must NOT start with the real key"
    # If the blob is long enough, simulate the legacy attack (use blob[:32]
    # as a fake key, decrypt blob[32:]) — it must produce non-zlib garbage.
    if len(blob) > 64:
        fake_key = blob[:32]
        ct = blob[32:]
        _s = bytearray(); _c = 0
        while len(_s) < len(ct):
            _s.extend(_h2.sha256(fake_key + _c.to_bytes(4, 'big')).digest())
            _c += 1
        _x = (int.from_bytes(ct, 'big') ^ int.from_bytes(_s[:len(ct)], 'big')).to_bytes(len(ct), 'big')
        try:
            zlib.decompress(_x)
            leaked = True
        except Exception:
            leaked = False
        assert not leaked, "legacy recovery attack must NOT work on secure-mode capsule"
        print("capsule secure mode: legacy key-prefix recovery attack fails  OK")
    else:
        print("capsule secure mode: blob too short for legacy attack sim (skipped)  OK")

    # --- Entropy: capsule has near-uniform byte distribution ---
    import collections, math
    def _entropy(data):
        if not data:
            return 0.0
        freq = collections.Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    cap_h = _entropy(capsule)
    print(f"capsule entropy (small source): {cap_h:.4f} bits/byte")
    print("capsule entropy (small): recorded  OK")

    # --- Diversity: different seeds → different capsules ---
    ctx2 = _Ctx()
    ctx2.capsule_seed = 99
    capsule2 = apply_binary_capsule(source, ctx2, embed_key=True)
    assert capsule != capsule2, "different seeds must produce different capsules"
    print("capsule diversity: different seeds -> different capsules  OK")

    # --- Non-ASCII source handled ---
    source_unicode = "x = '\u4f60\u597d'\nassert x == '\u4f60\u597d'\nprint('ok')\n"
    capsule_u = apply_binary_capsule(source_unicode, ctx, embed_key=True)
    path_u = os.path.join(tempfile.gettempdir(), '_io7_unicode.py')
    with open(path_u, 'wb') as f:
        f.write(capsule_u)
    r2 = subprocess.run([sys.executable, path_u], capture_output=True, timeout=10)
    assert r2.returncode == 0, f"unicode capsule should run: {r2.stderr}"
    assert r2.stdout.strip() == b'ok', f"unicode output mismatch: {r2.stdout!r}"
    print("capsule unicode: non-ASCII source handled  OK")
    os.unlink(path_u)

    # --- Large source: entropy approaches 8.0 ---
    import random as _rng
    _rng.seed(42)
    large_source = ''.join(f'x_{i} = {_rng.randint(0, 10**9)}\n' for i in range(5000))
    large_source += "print('done')\n"
    capsule_large = apply_binary_capsule(large_source, ctx, embed_key=True)
    cap_large_h = _entropy(capsule_large)
    print(f"capsule large: {len(capsule_large)} bytes, entropy {cap_large_h:.4f}")
    assert cap_large_h > 7.5, f"large capsule entropy {cap_large_h:.3f} must be >7.5"
    print("capsule large: entropy >7.5  OK")

    # --- Escape-bug fuzz: the ciphertext itself must never contain an
    # unescaped triple-quote after _escape_for_triple_quoted. The previous
    # bug (bytes.replace without re-scan) silently corrupted ~1/3000 builds.
    #
    # Ground truth: actually COMPILE the escaped content wrapped in a
    # triple-quoted literal and catch SyntaxError. This is exactly what
    # the Python tokenizer does at runtime, so it is authoritative.
    def _escaped_blob_compiles(escaped: bytes) -> bool:
        """Wrap the escaped content in a triple-quoted literal and try to
        compile it. Returns True if it parses (no premature termination).
        The latin-1 coding declaration is REQUIRED so the parser accepts
        raw non-ASCII bytes in the literal body."""
        src = b'# -*- coding: latin-1 -*-\n_d = """' + escaped + b'"""\n'
        try:
            compile(src, '<fuzz>', 'exec')
            return True
        except SyntaxError:
            return False

    import random as _fr
    _fr.seed(1234)
    _bad = 0
    for _ in range(2000):
        n = _fr.randint(0, 40)
        # Bias toward many 0x22 bytes to stress the run-length logic.
        blob_test = bytes(_fr.choice([0x22, 0x22, 0x22, _fr.randint(0, 255)])
                          for _ in range(n))
        escaped = _escape_for_triple_quoted(blob_test)
        if not _escaped_blob_compiles(escaped):
            _bad += 1
            if _bad == 1:
                print(f"  first failing blob (n={n}): {blob_test!r}")
                print(f"  escaped: {escaped!r}")
    assert _bad == 0, f"escape fuzz: {_bad}/2000 blobs fail to compile (old bug present)"
    print(f"capsule escape fuzz: 2000 random blobs all compile  OK")

    # Sanity: confirm the fuzz WOULD catch the old buggy algorithm.
    def _old_escape(data: bytes) -> bytes:
        out = data.replace(b'\\', b'\\\\')
        out = out.replace(b'\x00', b'\\x00')
        out = out.replace(b'\r', b'\\r')
        out = out.replace(b'"""', b'""\\"')
        return out
    _fr.seed(1234)
    old_bad = 0
    for _ in range(2000):
        n = _fr.randint(0, 40)
        blob_test = bytes(_fr.choice([0x22, 0x22, 0x22, _fr.randint(0, 255)])
                          for _ in range(n))
        escaped = _old_escape(blob_test)
        if not _escaped_blob_compiles(escaped):
            old_bad += 1
    assert old_bad > 0, "fuzz must detect the old bug (else the test is vacuous)"
    print(f"capsule escape fuzz: old algorithm detected as broken ({old_bad}/2000) — test is sound  OK")

    # --- Triple-quote handling: data containing 0x22 0x22 0x22 ---
    tricky = b'\x22\x22\x22' * 100
    source_tricky = f"x = {tricky!r}\nprint('ok')\n"
    capsule_tricky = apply_binary_capsule(source_tricky, ctx, embed_key=True)
    path_tricky = os.path.join(tempfile.gettempdir(), '_io7_tricky.py')
    with open(path_tricky, 'wb') as f:
        f.write(capsule_tricky)
    r3 = subprocess.run([sys.executable, path_tricky], capture_output=True, timeout=10)
    assert r3.returncode == 0, f"tricky capsule should run: {r3.stderr}"
    assert r3.stdout.strip() == b'ok', f"tricky output mismatch: {r3.stdout!r}"
    print("capsule triple-quote: source with 0x22x3 handled  OK")
    os.unlink(path_tricky)

    # --- Run-length stress: ciphertext containing 5+ consecutive 0x22 ---
    # This is the exact case the old replace()-based bug corrupted.
    stress_blobs = [b'\x22' * k for k in range(3, 21)]
    stress_blobs.append(b'A\x22\x22\x22\x22\x22B')  # run embedded
    stress_blobs.append(b'\x22\x22')  # trailing 2 quotes
    stress_blobs.append(b'\x22')  # trailing 1 quote
    for sb in stress_blobs:
        esc = _escape_for_triple_quoted(sb)
        assert _escaped_blob_compiles(esc), \
            f"stress blob {sb!r} fails to compile: {esc!r}"
    print("capsule run-length stress: 1..20 consecutive 0x22 + trailing cases all safe  OK")

    print("capsule SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
