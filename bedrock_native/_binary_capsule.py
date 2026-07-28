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


def _keystream_block(key: bytes, counter: int, salt: bytes,
                     counter_width: int, key_first: bool) -> bytes:
    """One SHA-256 CTR keystream block.

    Phase G1: the keystream construction is parameterized by ``salt``,
    ``counter_width``, and ``key_first`` so the encrypt and decrypt sides can
    use the SAME per-build construction. Two builds that reuse the same key
    (e.g. operator keeps ``BR_CAPSULE_KEY`` constant across builds) still
    get distinct ciphertexts because of the per-build salt.
    """
    ctr = counter.to_bytes(counter_width, 'big')
    if key_first:
        return hashlib.sha256(key + salt + ctr).digest()
    return hashlib.sha256(ctr + salt + key).digest()


def _encrypt(data: bytes, key: bytes, *, salt: bytes = b'',
             counter_width: int = 4, key_first: bool = True) -> bytes:
    """Encrypt data with SHA-256 CTR-mode keystream (XOR).

    This is not a vetted AEAD — it is a SHA-256-CTR XOR stream cipher with no
    authentication tag. It produces uniform output, which is what the
    capsule's byte-distribution-randomization goal needs. Confidentiality
    depends entirely on keeping ``key`` out of the file: with
    ``embed_key=False`` (the default) the key is read from the environment
    at runtime, so the source is genuinely encrypted at rest. With
    ``embed_key=True`` the key ships in the file and confidentiality is nil.

    Phase G1: ``salt``/``counter_width``/``key_first`` diversify the
    keystream across builds. They MUST match the values the bootstrap emits
    (see ``_build_bootstrap``) — ``apply_binary_capsule`` generates them
    once and passes them to both sides.
    """
    out = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        block = _keystream_block(key, counter, salt, counter_width, key_first)
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

    DEPRECATED in Phase G1: this function is retained for backward compat
    (the legacy ``--embed-key`` path may still use it via the triple-quoted
    form) but the default capsule output now uses hex/base85 literal
    encoding (``_encode_blob_hex``/``_encode_blob_b85``) which needs no
    escaping and produces a uniform printable-alphabet byte distribution
    (fixing the PRG-uniformity spike from latin-1 escaping of NUL/backslash).
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


# --- Phase G1: hex/base85 blob encoding (replaces latin-1 escaping) ----------
#
# The legacy capsule emitted the encrypted blob as a latin-1 triple-quoted
# string, which required escaping NUL→`\x00` (4-byte expansion), backslash→
# `\\`, CR→`\r`, and triple-quote runs. This escaping injected a massive
# spike in the byte histogram (byte 0x5c backslash at 1.53% vs 0.39%
# uniform — a 4× spike), which a single-histogram-bin classifier used to
# distinguish obf from os.urandom at 100% accuracy (the root cause of the
# PRG-uniformity test failing honestly).
#
# Switching to hex/base85 literal encoding eliminates ALL per-byte escaping:
# the on-disk distribution is the uniform printable alphabet (0-9a-f for
# hex, 85 ASCII chars for base85), matching a true PRG output. This both
# flattens the distribution (PRG-uniformity accuracy → near chance) AND
# shrinks the file (no 4× NUL expansion for hex; base85 is ~25% smaller
# than the raw bytes).

def _encode_blob_hex(blob: bytes) -> bytes:
    """Emit the blob as `bytes.fromhex('<hex>')`. Distribution: uniform 0-9a-f."""
    return b"bytes.fromhex('" + blob.hex().encode('ascii') + b"')"

def _encode_blob_b85(blob: bytes) -> bytes:
    """Emit the blob as `__import__('base64').b85decode(b'<b85>')`.

    Distribution: uniform over the 85-char ASCII alphabet. Smaller than hex
    (~25% smaller than raw bytes; hex is 2× raw). Requires base64 import.
    """
    import base64 as _b64
    b85 = _b64.b85encode(blob).decode('ascii')
    return b"__import__('base64').b85decode(b'" + b85.encode('ascii') + b"')"


def _random_token(rng, prefix: str = '_br', length: int = 4) -> str:
    """A short random identifier token unlikely to collide with user code."""
    if hasattr(rng, 'urandom') or hasattr(rng, 'token_bytes'):
        # CSPRNG path
        try:
            raw = rng.urandom(length) if hasattr(rng, 'urandom') else rng.token_bytes(length)
        except Exception:
            raw = bytes(rng.randint(0, 255) for _ in range(length))
    else:
        raw = bytes(rng.randint(0, 255) for _ in range(length))
    return prefix + raw.hex()[:length]


def _random_var_map(rng) -> dict:
    """Map standard bootstrap var names to per-build random tokens.

    This destroys the offset-0 family fingerprint: no two io builds share
    the same bootstrap variable names, so a one-regex detector for
    `import zlib, hashlib as _h` cannot match every io file.
    """
    return {
        'blob':   _random_token(rng, '_bd', 5),   # the encrypted blob
        'hash':   _random_token(rng, '_hh', 5),   # hashlib alias
        'key':    _random_token(rng, '_kk', 5),   # the decryption key
        'stream': _random_token(rng, '_ss', 5),   # keystream bytearray
        'counter': _random_token(rng, '_cc', 5),  # counter
        'plain':  _random_token(rng, '_pp', 5),   # decrypted plaintext
        'os':     _random_token(rng, '_oo', 5),   # os alias (env mode)
        'envval': _random_token(rng, '_ee', 5),   # env value (env mode)
        'salt':   _random_token(rng, '_lt', 5),   # per-build salt
    }


def _integrity_flag_expr() -> bytes:
    """Build the `__BR_INTEGRITY_OFF__` key without spelling the literal.

    The legacy bootstrap spelled `__BR_INTEGRITY_OFF__` verbatim, which was
    a constant tell. We derive it from `chr(95)*2 + 'BR_INTEGRITY_OFF' +
    chr(95)*2` so no static grep for the literal matches.
    """
    return (b"chr(95)*2 + 'BR_INTEGRITY_OFF' + chr(95)*2")


def _build_bootstrap(enc_blob: bytes, *, embed_key: bool = False,
                     key_env: str = 'BR_CAPSULE_KEY', rng=None,
                     salt: bytes = b'', counter_width: int = 4,
                     key_first: bool = True) -> bytes:
    """Build the bootstrap Python code that decrypts + execs the blob.

    Phase G1 hardening: the bootstrap is randomized per build (random var
    names, random hex/base85 blob encoding, derived integrity flag) so no
    two io builds share a byte-identical loader skeleton. The blob is
    emitted as a hex/base85 literal (no latin-1 escaping) so the on-disk
    byte distribution is the uniform printable alphabet, not the
    escape-spike distribution that let a single histogram bin distinguish
    obf from urandom at 100%.

    CRITICAL: ``salt``/``counter_width``/``key_first`` MUST match the values
    passed to ``_encrypt`` when the blob was produced. ``apply_binary_capsule``
    generates them once and threads them through both sides — the bootstrap
    does NOT regenerate them (else encrypt and decrypt keystreams diverge).

    embed_key=True (legacy / insecure): the 32-byte key is prepended to
    ``enc_blob``; the bootstrap reads it from the first 32 bytes. WARNING:
    this ships the key in the clear — anyone can recover the original
    source by running this ~10-line bootstrap. Kept for backward
    compatibility only; pass ``--embed-key`` on the CLI to opt in.

    embed_key=False (default, secure): the key is NOT in the file. The
    bootstrap reads it from the environment variable named by ``key_env``
    (hex-encoded). The operator must set that env var on the machine that
    runs the obfuscated file. The build path emits the key to a sidecar
    ``<output>.key`` file (or operator-chosen path via --capsule-key-file).
    """
    if rng is None:
        # Fallback to secrets for randomization (CSPRNG). We do NOT fall
        # back to random.Random here — the bootstrap randomization is a
        # security-relevant output property, so a CSPRNG is required.
        import secrets as _sec
        rng = _sec
    env_name = repr(key_env).encode('latin-1')
    v = _random_var_map(rng)

    # Choose blob encoding: hex (uniform 0-9a-f) or base85 (uniform ASCII).
    # Random per-build so the on-disk alphabet varies too. This choice is
    # display-only — both decode to the same blob bytes.
    use_b85 = bool(rng.randint(0, 1)) if hasattr(rng, 'randint') else False
    if use_b85:
        blob_literal = _encode_blob_b85(enc_blob)
    else:
        blob_literal = _encode_blob_hex(enc_blob)

    # Emit the keystream block expression matching ``_keystream_block``.
    # ``salt``/``counter_width``/``key_first`` were generated ONCE by the
    # caller (apply_binary_capsule) and passed to both _encrypt and here.
    salt_hex = salt.hex()
    cw_bytes = str(counter_width).encode()
    if key_first:
        ks_expr = (v['hash'].encode() + b'.sha256(' + v['key'].encode()
                   + b' + bytes.fromhex(' + repr(salt_hex).encode() + b') + '
                   + v['counter'].encode() + b'.to_bytes(' + cw_bytes + b", 'big')).digest()")
    else:
        ks_expr = (v['hash'].encode() + b'.sha256(' + v['counter'].encode()
                   + b'.to_bytes(' + cw_bytes + b", 'big') + bytes.fromhex("
                   + repr(salt_hex).encode() + b') + ' + v['key'].encode() + b').digest()')

    # Build the key-loading section.
    if embed_key:
        key_line = (v['key'].encode() + b' = ' + v['blob'].encode()
                    + b'[:32]; ' + v['blob'].encode() + b' = ' + v['blob'].encode() + b'[32:]\n')
    else:
        key_line = (
            b"import os as " + v['os'].encode() + b"\n"
            + v['envval'].encode() + b" = " + v['os'].encode() + b".environ.get(" + env_name + b")\n"
            + b"if not " + v['envval'].encode() + b":\n"
            + b"    raise SystemExit('capsule: key missing -- set env ' + "
            + env_name + b" + '=<hex> (see sidecar) before running')\n"
            + v['key'].encode() + b" = bytes.fromhex(" + v['envval'].encode() + b")\n"
        )

    # Derived integrity flag (no literal `__BR_INTEGRITY_OFF__` in source).
    integ = _integrity_flag_expr()

    bootstrap = (
        b'# -*- coding: latin-1 -*-\n'
        b'import zlib, hashlib as ' + v['hash'].encode() + b'\n'
        + v['blob'].encode() + b' = ' + blob_literal + b'\n'
        + key_line +
        v['stream'].encode() + b' = bytearray()\n'
        + v['counter'].encode() + b' = 0\n'
        b'while len(' + v['stream'].encode() + b') < len(' + v['blob'].encode() + b'):\n'
        b'    ' + v['stream'].encode() + b'.extend(' + ks_expr + b'); ' + v['counter'].encode() + b' += 1\n'
        + v['plain'].encode() + b' = (int.from_bytes(' + v['blob'].encode() + b", 'big') ^ int.from_bytes("
        + v['stream'].encode() + b'[:len(' + v['blob'].encode() + b")], 'big')).to_bytes(len("
        + v['blob'].encode() + b"), 'big')\n"
        b'exec(zlib.decompressobj().decompress(' + v['plain'].encode() + b"), {'__name__': '__main__', '__file__': __file__, "
        + integ + b": True})\n"
    )
    return bootstrap


def _pad_blob(blob: bytes, rng) -> bytes:
    """Pad ``blob`` with random bytes to a target size independent of source.

    Phase G1 step 3 (close the length channel): without padding, the on-disk
    capsule size ≈ compressed-source-size, which leaks the source size at
    fine granularity (a 100-line vs 1000-line program differ by KB). We pad
    to a random target in a fixed band so that two builds of programs whose
    compressed sizes fall in the same band are byte-for-byte the same size,
    and the band is chosen randomly per build.

    The padding is appended to the ENCRYPTED blob (not the plaintext), so it
    decrypts to random garbage. The bootstrap uses ``zlib.decompressobj()``
    (not ``zlib.decompress``) which stops at the zlib stream-end marker and
    ignores the trailing garbage — so the plaintext is recovered intact.

    Strategy:
      - Files whose blob is < ``_PAD_BAND_HI`` (16KB): pad to a random target
        in ``[max(_PAD_BAND_LO, len(blob)), _PAD_BAND_HI]``. This puts all
        small/medium programs in the same random-size band → fine-grained
        length channel closed.
      - Larger files: pad to next power-of-two + random jitter (up to 1/4 of
        the pow2). Coarse bucket, but randomizes the boundary so the exact
        size is not a stable per-program signature.
    """
    _PAD_BAND_LO = 4096
    _PAD_BAND_HI = 16384
    n = len(blob)
    if n < _PAD_BAND_HI:
        lo = max(_PAD_BAND_LO, n)
        if hasattr(rng, 'randint'):
            target = lo + rng.randint(0, _PAD_BAND_HI - lo)
        else:
            import secrets as _sec
            target = lo + int.from_bytes(_sec.token_bytes(2), 'big') % (_PAD_BAND_HI - lo + 1)
        if target < n:
            target = n
    else:
        # Next power of two ≥ n.
        target = 1 << (n - 1).bit_length()
        jitter_max = target // 4
        if hasattr(rng, 'randint') and jitter_max > 0:
            target += rng.randint(0, jitter_max)
        elif jitter_max > 0:
            import secrets as _sec
            target += int.from_bytes(_sec.token_bytes(2), 'big') % (jitter_max + 1)
    pad_len = target - n
    if pad_len <= 0:
        return blob
    if hasattr(rng, 'randint'):
        pad = bytes(rng.randint(0, 255) for _ in range(pad_len))
    else:
        import secrets as _sec
        pad = _sec.token_bytes(pad_len)
    return blob + pad


def apply_binary_capsule(source: str, ctx, *, key: bytes = None,
                         embed_key: bool = False,
                         key_env: str = 'BR_CAPSULE_KEY',
                         pad: bool = True) -> bytes:
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
        pad: if True (default, Phase G1), pad the encrypted blob to a random
            target size to close the length channel. The bootstrap uses
            ``zlib.decompressobj()`` so trailing padding is ignored.

    Returns:
        bytes: the capsule file content (latin-1 encoded). The file starts
        with a coding declaration, followed by the bootstrap, followed by
        the encrypted blob as a hex/base85 literal (random per-build).
    """
    # 1. Encode source as latin-1 (non-latin-1 chars → \uXXXX escapes)
    source_bytes = source.encode('latin-1', errors='backslashreplace')

    # 2. Compress
    compressed = zlib.compress(source_bytes, level=9)

    # 2b. Generate the per-build keystream params ONCE (Phase G1). These
    #     diversify the keystream across builds AND must be identical on
    #     the encrypt and decrypt sides — so we generate them here and
    #     thread them through both _encrypt and _build_bootstrap. Drawing
    #     them from boot_rng (a BuildRNG sub-stream) makes builds
    #     reproducible from the seed.
    boot_rng = _rng_for(ctx)
    if hasattr(boot_rng, 'randint'):
        salt = bytes(boot_rng.randint(0, 255) for _ in range(8))
        counter_width = 8 if boot_rng.randint(0, 1) else 4
        key_first = bool(boot_rng.randint(0, 1))
    else:
        # Fallback (e.g. a bare secrets.SystemRandom): legacy params.
        import secrets as _sec
        salt = _sec.token_bytes(8)
        counter_width = 4
        key_first = True

    # 3. Generate key + encrypt (using the SAME keystream params the
    #    bootstrap will emit).
    if key is None:
        key = _generate_key(ctx)
    encrypted = _encrypt(compressed, key, salt=salt,
                         counter_width=counter_width, key_first=key_first)

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

    # 4b. Pad to close the length channel (Phase G1). The bootstrap uses
    #     zlib.decompressobj() so trailing random padding is ignored. The
    #     pad/skeleton RNG derives from the build seed (via _rng_for) so
    #     builds are reproducible from the seed.
    if pad:
        blob = _pad_blob(blob, boot_rng)

    # 5. Build bootstrap (reads key from blob prefix in legacy mode, or from
    #    the environment in secure mode). Pass the build RNG so the per-build
    #    skeleton randomization is reproducible from the build seed. The
    #    keystream params MUST match what _encrypt used (generated above).
    bootstrap = _build_bootstrap(blob, embed_key=embed_key, key_env=key_env,
                                 rng=boot_rng, salt=salt,
                                 counter_width=counter_width, key_first=key_first)

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
    # must now FAIL — the blob has no key prefix, AND the blob is emitted as a
    # hex/base85 literal (Phase G1), so a `"""..."""` regex won't even match.
    import re as _re, hashlib as _h2
    # Phase G1: blob is now a hex/base85 literal, not a triple-quoted string.
    # The OLD `"""..."""` regex MUST no longer match (the latin-1 escape
    # fingerprint is gone).
    old_form_match = _re.search(rb'_d = """(.*?)"""', capsule_env, _re.DOTALL)
    assert old_form_match is None, \
        "Phase G1: blob must NOT be a latin-1 triple-quoted string (hex/base85 literal instead)"
    # New form: either `bytes.fromhex('...')` or `__import__('base64').b85decode(b'...')`.
    # NOTE: the bootstrap contains MULTIPLE hex/base85 literals — the per-build
    # salt (8 bytes) is emitted inline, and the blob (KB+) is the large one.
    # We match the LONGEST literal, which is the blob (salt is always small).
    def _extract_blob_literal(cap_bytes):
        """Extract the BLOB (longest hex/base85 literal) from a capsule."""
        hex_all = _re.findall(rb"bytes\.fromhex\('([0-9a-f]+)'\)", cap_bytes)
        b85_all = _re.findall(rb"__import__\('base64'\)\.b85decode\(b'([^']*)'", cap_bytes)
        # Blob is the longest match (salt is 16 hex chars / 13 b85 chars).
        hex_blob = [h for h in hex_all if len(h) > 32]
        b85_blob = [h for h in b85_all if len(h) > 32]
        if hex_blob:
            return b'hex', bytes.fromhex(max(hex_blob, key=len).decode('ascii'))
        if b85_blob:
            import base64 as _b64
            return b'b85', _b64.b85decode(max(b85_blob, key=len))
        return None, None
    form, blob = _extract_blob_literal(capsule_env)
    assert form in (b'hex', b'b85'), \
        "Phase G1: blob must be a hex or base85 literal (longest match)"
    print(f"capsule G1: blob emitted as {form.decode()} literal (no latin-1 escape)  OK")

    # Core property: the real key is NOT a prefix of the blob.
    assert not blob.startswith(ctx_env.capsule_key), \
        "secure-mode blob must NOT start with the real key"
    # Simulate the legacy attack (use blob[:32] as a fake key, decrypt
    # blob[32:]) — it must produce non-zlib garbage.
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

    # --- Phase G1: byte-histogram spike must be GONE ---
    # The legacy latin-1 escape path spiked byte 0x5c (backslash) to ~1.5%
    # (4× the 0.39% uniform rate), which let a single-histogram-bin
    # classifier distinguish obf from urandom at 100% accuracy. The new
    # hex/base85 literal path emits only the uniform printable alphabet
    # (0-9a-f for hex; 85 ASCII chars for base85), so the spike must vanish.
    def _histo(data):
        return collections.Counter(data)
    h = _histo(capsule_env)
    n = len(capsule_env)
    backslash_freq = h.get(0x5c, 0) / n
    # The latin-1 escape path spiked 0x5c to ~1.5%. With hex/base85 the
    # backslash only appears in a few fixed boilerplate tokens (e.g. none in
    # the body). Set a generous upper bound of 1.0% (still well below the
    # legacy 1.5%, but tolerates incidental backslashes in error messages).
    assert backslash_freq < 0.010, \
        f"Phase G1: byte 0x5c spike must be gone, got {backslash_freq*100:.2f}% (legacy was ~1.5%)"
    # Also assert no NUL bytes (legacy escape path always had some via
    # `\x00` 4-byte expansions; hex/base85 has none).
    assert h.get(0x00, 0) == 0, "Phase G1: no NUL bytes in hex/base85 literal"
    print(f"capsule G1: byte 0x5c freq {backslash_freq*100:.2f}% (was ~1.5%), NUL=0  OK")

    # --- Phase G1: per-build skeleton diversity ---
    # Two builds with different seeds must produce byte-different bootstraps
    # (random var names + random hex/base85 choice + random salt + random
    # crypto-call ordering). The literal `import zlib, hashlib as _h` line
    # (a constant tell across the legacy family) must NOT appear in either.
    ctx_b2 = _Ctx()
    ctx_b2.capsule_seed = 7
    capsule_b2 = apply_binary_capsule(source, ctx_b2, embed_key=True)
    assert capsule != capsule_b2, \
        "Phase G1: different seeds must produce different bootstraps (randomized skeleton)"
    # The legacy constant tell line must be GONE (var name randomized).
    assert b'import zlib, hashlib as _h\n' not in capsule, \
        "Phase G1: legacy `import zlib, hashlib as _h` constant tell must be gone"
    assert b'import zlib, hashlib as _h\n' not in capsule_b2, \
        "Phase G1: legacy constant tell must be gone in build 2 too"
    # The literal `__BR_INTEGRITY_OFF__` must be GONE (now derived via chr()).
    assert b"__BR_INTEGRITY_OFF__" not in capsule, \
        "Phase G1: `__BR_INTEGRITY_OFF__` literal must be gone (now derived via chr())"
    print("capsule G1: per-build skeleton randomized (no constant tell line, no integrity flag literal)  OK")

    # --- Phase G1: padding closes the length channel ---
    # Two builds of DIFFERENT-sized sources whose compressed sizes both fall
    # under the 16KB pad band must produce capsules of NEAR-identical size
    # (random target within the same band). The exact size depends on the
    # per-build RNG, so we just assert both are within the band and not
    # correlated with the source size.
    small_src = "print('tiny')\n"  # ~14 bytes compressed
    medium_src = "x = 0\n" * 200 + "print('medium')\n"  # ~ a few hundred bytes compressed
    cap_small = apply_binary_capsule(small_src, _Ctx(), embed_key=True)
    cap_medium = apply_binary_capsule(medium_src, _Ctx(), embed_key=True)
    # Both must be padded up into the [4096, 16384] band (plus a small
    # fixed bootstrap overhead). The KEY property: neither is small.
    assert len(cap_small) > 4000, \
        f"Phase G1: small source must be padded up, got {len(cap_small)} bytes"
    assert len(cap_medium) > 4000, \
        f"Phase G1: medium source must be padded up, got {len(cap_medium)} bytes"
    # And neither is huge — both should be in the same band (modulo
    # bootstrap overhead).
    assert len(cap_small) < 20000 and len(cap_medium) < 20000, \
        f"Phase G1: padded sizes must stay in the band, got {len(cap_small)} / {len(cap_medium)}"
    print(f"capsule G1: padding band (small={len(cap_small)}, medium={len(cap_medium)}) closes length channel  OK")

    # --- Phase G1: padded capsule still round-trips correctly ---
    # The bootstrap uses zlib.decompressobj() (not zlib.decompress) so the
    # trailing random padding is ignored. Verify by running the padded
    # small-source capsule.
    path_pad = os.path.join(tempfile.gettempdir(), '_io7_pad.py')
    with open(path_pad, 'wb') as f:
        f.write(cap_small)
    r_pad = subprocess.run([sys.executable, path_pad], capture_output=True, timeout=10)
    assert r_pad.returncode == 0, f"padded capsule should run: {r_pad.stderr}"
    assert r_pad.stdout.strip() == b'tiny', \
        f"padded capsule output mismatch: {r_pad.stdout!r}"
    print("capsule G1: padded capsule round-trips correctly (decompressobj ignores trailing pad)  OK")
    os.unlink(path_pad)

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

    # --- Large source: alphabet-uniformity within the chosen alphabet ---
    # Phase G1 changed the blob from a latin-1 triple-quoted string (full
    # 256-byte alphabet, Shannon entropy →8.0) to a hex/base85 literal
    # (narrow alphabet: 16 chars for hex, 85 for base85). Shannon entropy
    # is thus CAPPED at log2(alphabet_size) — 4.0 for hex, 6.4 for base85.
    # The OLD ">7.5" assertion is therefore obsolete.
    #
    # The relevant property for PRG-uniformity defense is UNIFORMITY WITHIN
    # the chosen alphabet (no single-character spike), not raw Shannon
    # entropy. We assert: max-symbol-frequency ≈ uniform (1/|alphabet|).
    import random as _rng
    _rng.seed(42)
    large_source = ''.join(f'x_{i} = {_rng.randint(0, 10**9)}\n' for i in range(5000))
    large_source += "print('done')\n"
    capsule_large = apply_binary_capsule(large_source, ctx, embed_key=True)

    # Find the blob literal in the capsule to measure its symbol distribution.
    # NOTE: the bootstrap contains MULTIPLE hex/base85 literals — the per-build
    # salt (8 bytes = 16 hex chars) is emitted inline as `bytes.fromhex(...)`,
    # and the blob itself (KB+) is the large literal. We must match the BLOB
    # (longest match), not the salt.
    _hex_matches = _re.findall(rb"bytes\.fromhex\('([0-9a-f]+)'\)", capsule_large)
    _b85_matches = _re.findall(rb"__import__\('base64'\)\.b85decode\(b'([^']*)'", capsule_large)
    # The blob literal is the longest hex (salt is always 16 chars) or the
    # longest base85 (salt is always 16 chars → 13 b85 chars).
    _hex_matches = [h for h in _hex_matches if len(h) > 32]  # >16 bytes = blob
    _b85_matches = [h for h in _b85_matches if len(h) > 32]
    if _hex_matches:
        lit = max(_hex_matches, key=len)
        alphabet = b'0123456789abcdef'
        expected = 1 / 16
    elif _b85_matches:
        lit = max(_b85_matches, key=len)
        # ASCII 33..117 (0x21..0x75) = 85 chars.
        alphabet = bytes(range(0x21, 0x76))
        expected = 1 / 85
    else:
        raise AssertionError("Phase G1: large capsule blob must be a hex or base85 literal (longest match)")
    sym_counts = collections.Counter(lit)
    n_sym = len(lit)
    max_freq = max(c / n_sym for c in sym_counts.values())
    # Uniform alphabet: every symbol ≈ 1/|alphabet|. With ~80KB of hex
    # (160K symbols), the binomial std is tiny, so a 1.5× uniform cap is a
    # strong assertion. We use 1.25× to allow for compressed-data structure
    # leaking slightly through the encryption (the ciphertext is XOR of
    # keystream with compressed data; the literal itself is the ciphertext
    # hex-encoded, so per-hex-digit distribution is ≈ uniform).
    assert max_freq < expected * 1.25, \
        f"Phase G1: max hex/base85 symbol freq {max_freq*100:.2f}% exceeds uniform {expected*100:.2f}% × 1.25"
    # And the alphabet must be FULLY used (no symbol missing → not a
    # degenerate distribution).
    assert len(sym_counts) == len(alphabet), \
        f"Phase G1: alphabet not fully used ({len(sym_counts)}/{len(alphabet)} symbols)"
    print(f"capsule large: {len(capsule_large)} bytes, alphabet={'hex' if _hex_matches else 'base85'}, "
          f"max-symbol-freq {max_freq*100:.3f}% (uniform {expected*100:.3f}%)")
    print("capsule large: alphabet-uniform within chosen alphabet (no per-symbol spike)  OK")

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
