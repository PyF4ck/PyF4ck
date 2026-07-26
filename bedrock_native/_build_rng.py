"""Per-build master CSPRNG stream + build manifest (Phase E, Layer 5).

UNIFIES every randomized transform in the obfuscator under one master
per-build CSPRNG stream. Replaces the decentralized ``random.Random`` /
``os.urandom`` calls (Mersenne Twister — state recoverable, NOT a CSPRNG)
scattered across the obfuscator passes after the source leak.

Threat model
------------
The obfuscator source leaked. Two consequences this module addresses:

1. **Per-build diversity** — two builds of the *same* input produce
   structurally different output (different opaque-predicate keys, MBA
   identities, CFF layouts), so a deobfuscator built from the leaked source
   does not transfer between builds.
2. **Traitor tracing** — every build embeds a stable ``build_id`` derived from
   a per-build master seed. A leaked ``.pyd`` can be tied back to the build
   that produced it via the manifest (``.bedrock_manifest.json``).

Design
------
* The master seed is 32 bytes. In **reproducible mode** (``fixed_seed`` set)
  it is derived deterministically as
  ``HKDF-SHA256(b"bedrock-build-v1" || input_sha256 || fixed_seed)`` so the
  same input + fixed seed reproduces the same obfuscation. In
  **non-reproducible mode** (``fixed_seed`` is None) it is minted fresh via
  ``secrets.token_bytes(32)`` so every build differs.
* Each obfuscation pass (``obf_vars`` / ``cff`` / ``mba`` / ...) draws from an
  INDEPENDENT sub-stream derived via HKDF-SHA256 from the master seed, keyed by
  a pass label. Two different labels never share keystream.
* The sub-stream keystream is **ChaCha20** (RFC 8439) — a CSPRNG with no
  recoverable state. Implemented here in pure Python (stdlib only) so the
  module has zero external dependencies and is import-safe on a bare host.
* HKDF (RFC 5869) is implemented on stdlib ``hmac`` + ``hashlib`` and is also
  exported for the watermark module.

This file is PURE PYTHON (stdlib only). No Cython, no C, no external deps.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass

__all__ = [
    'hkdf_sha256',
    'BuildRNG',
    'SubStream',
    'BuildManifest',
    'write_manifest',
    'read_manifest',
    'manifest_path',
]

# Domain-separation constant for the master-seed derivation.
_BUILD_LABEL = b'bedrock-build-v1'

# ChaCha20 constant "expand 32-byte k" as four little-endian 32-bit words.
_CHACHA_SIGMA = struct.unpack('<4I', b'expand 32-byte k')
_MASK32 = 0xFFFFFFFF
_BLOCK = 64  # ChaCha20 block size in bytes.


# ---------------------------------------------------------------------------
# HKDF-SHA256  (RFC 5869)
# ---------------------------------------------------------------------------
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Extract + HKDF-Expand over SHA-256 (RFC 5869).

    Args:
        ikm:    Input keying material.
        salt:   HKDF-Extract salt. Empty is allowed; RFC 5869 §2.1 maps an
                empty salt to a string of HashLen zero bytes.
        info:   HKDF-Expand context / application info.
        length: Number of output bytes (1 .. 255 * 32).

    Returns:
        ``length`` pseudorandom bytes.

    Raises:
        ValueError: if ``length`` is out of range.
    """
    if not (1 <= length <= 255 * 32):
        raise ValueError('length must be in 1..255*32')
    if salt is None:
        salt = b''
    # HKDF-Extract: PRK = HMAC-SHA256(salt, IKM). An empty salt is mapped to
    # HashLen zero bytes by hmac.new (empty key) per RFC 5869 §2.1.
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # HKDF-Expand: T(0)=empty; T(i)=HMAC-SHA256(PRK, T(i-1) | info | i).
    okm = bytearray()
    t = b''
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return bytes(okm[:length])


# ---------------------------------------------------------------------------
# ChaCha20  (RFC 8439) — pure-Python keystream generator
# ---------------------------------------------------------------------------
def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return the 64-byte ChaCha20 keystream block for one (key,counter,nonce)."""
    state = [
        _CHACHA_SIGMA[0], _CHACHA_SIGMA[1], _CHACHA_SIGMA[2], _CHACHA_SIGMA[3],
    ] + list(struct.unpack('<8I', key))
    state.append(counter & _MASK32)            # word 12: 32-bit block counter
    state += list(struct.unpack('<3I', nonce))  # words 13-15: 12-byte nonce
    work = state[:]
    for _ in range(10):  # 20 rounds = 10 double rounds.
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack('<16I', *out)


class SubStream:
    """Deterministic CSPRNG sub-stream backed by a ChaCha20 keystream.

    Same ``(key, nonce)`` plus the same call sequence yields the same bytes.
    The block counter starts at 1 (RFC 8439 §2.3 encryption convention).
    """

    def __init__(self, key: bytes, nonce: bytes):
        if len(key) != 32:
            raise ValueError('SubStream key must be 32 bytes')
        if len(nonce) != 12:
            raise ValueError('SubStream nonce must be 12 bytes')
        self._key = key
        self._nonce = nonce
        self._counter = 0       # next block generated will be 1
        self._block = b''
        self._pos = _BLOCK      # forces the first call to mint block 1

    def _next_block(self) -> None:
        self._counter += 1
        self._block = _chacha20_block(self._key, self._counter, self._nonce)
        self._pos = 0

    def random(self, n: int) -> bytes:
        """Return ``n`` keystream bytes; advances the internal counter."""
        if n < 0:
            raise ValueError('n must be non-negative')
        out = bytearray()
        while len(out) < n:
            if self._pos >= _BLOCK:
                self._next_block()
            take = min(_BLOCK - self._pos, n - len(out))
            out += self._block[self._pos:self._pos + take]
            self._pos += take
        return bytes(out)

    def bytes(self, n: int) -> bytes:  # noqa: A003 - spec API name
        """Alias for :meth:`random`."""
        return self.random(n)

    def randint(self, lo: int, hi: int) -> int:
        """Uniform random int in ``[lo, hi]`` inclusive (rejection sampling)."""
        span = hi - lo + 1
        if span <= 0:
            raise ValueError('empty range')
        if span == 1:
            return lo
        k = span.bit_length()
        mask = (1 << k) - 1
        nbytes = (k + 7) // 8
        while True:
            r = int.from_bytes(self.random(nbytes), 'little') & mask
            if r < span:
                return lo + r

    def choice(self, seq) -> object:
        """Return a random element of ``seq``."""
        if len(seq) == 0:
            raise IndexError('empty sequence')
        return seq[self.randint(0, len(seq) - 1)]

    def shuffle(self, seq) -> list:
        """Return a Fisher-Yates shuffled copy of ``seq`` (input untouched)."""
        out = list(seq)
        for i in range(len(out) - 1, 0, -1):
            j = self.randint(0, i)
            out[i], out[j] = out[j], out[i]
        return out


# ---------------------------------------------------------------------------
# BuildRNG — master per-build RNG
# ---------------------------------------------------------------------------
class BuildRNG:
    """Master per-build CSPRNG. One instance per obfuscator build."""

    def __init__(self, master_seed: bytes):
        if not master_seed:
            master_seed = secrets.token_bytes(32)
        if len(master_seed) != 32:
            raise ValueError('master_seed must be 32 bytes')
        self._master = master_seed

    @classmethod
    def create(cls, input_bytes: bytes,
               fixed_seed: bytes | None = None) -> 'BuildRNG':
        """Construct a BuildRNG.

        Args:
            input_bytes: The obfuscator input (its SHA-256 binds the master
                seed to a specific source version).
            fixed_seed: If given, REPRODUCIBLE mode — the master seed is
                ``HKDF-SHA256(b"bedrock-build-v1" || sha256(input) || fixed_seed)``
                so the same input + fixed seed reproduces the same build. If
                None, NON-REPRODUCIBLE mode — the master seed is fresh
                ``secrets.token_bytes(32)`` (per-build diversity).

        Returns:
            A new ``BuildRNG``.
        """
        if fixed_seed is not None:
            input_sha = hashlib.sha256(input_bytes).digest()
            ikm = _BUILD_LABEL + input_sha + fixed_seed
            # salt empty (RFC 5869 §2.1 -> HashLen zero bytes); info labels the
            # master-seed derivation so it cannot collide with a sub-stream.
            master = hkdf_sha256(ikm, b'', b'bedrock-master-seed/v1', 32)
            return cls(master)
        return cls(secrets.token_bytes(32))

    def stream(self, label: bytes) -> SubStream:
        """Derive an INDEPENDENT deterministic sub-stream for a pass label.

        Two different labels produce independent keystreams (different HKDF
        ``info`` -> different 32-byte ChaCha20 key + 12-byte nonce).

        Args:
            label: Pass identifier, e.g. ``b"obf_vars"`` / ``b"cff"`` / ``b"mba"``.

        Returns:
            A fresh ``SubStream``.
        """
        # Null byte separates the label to avoid prefix collisions.
        sub_key = hkdf_sha256(self._master, b'', b'bedrock-subkey\x00' + label, 32)
        sub_nonce = hkdf_sha256(self._master, b'', b'bedrock-subnonce\x00' + label, 12)
        return SubStream(sub_key, sub_nonce)

    def build_id(self) -> str:
        """Stable per-build identifier (hex of the master seed)."""
        return self._master.hex()

    def master_seed_hex(self) -> str:
        """Master seed as hex (for the manifest)."""
        return self._master.hex()


# ---------------------------------------------------------------------------
# Build manifest — traitor-tracing record
# ---------------------------------------------------------------------------
@dataclass
class BuildManifest:
    """Trait-tracing record written beside each obfuscated build.

    Attributes:
        build_id:        Stable per-build id (hex of the master seed).
        input_sha256:    SHA-256 of the obfuscator input.
        license_id:      Optional customer/license id this build was minted for.
        master_seed_hex: Master seed as hex (lets the issuer reproduce / verify).
        timestamp:       Build timestamp (ISO-8601 string, supplied by caller).
        passes:          Obfuscation passes applied (e.g. ["cff", "mba"]).
        profile:         Optional strength-profile name.
    """
    build_id: str
    input_sha256: str
    license_id: str | None
    master_seed_hex: str
    timestamp: str
    passes: list[str]
    profile: str | None


def manifest_path(out_dir: str) -> str:
    """Return the manifest path for an output dir (leading dot hides it)."""
    return os.path.join(out_dir, '.bedrock_manifest.json')


def write_manifest(manifest: BuildManifest, path: str) -> None:
    """Serialize ``manifest`` to ``path`` as pretty JSON (UTF-8)."""
    data = {
        'build_id': manifest.build_id,
        'input_sha256': manifest.input_sha256,
        'license_id': manifest.license_id,
        'master_seed_hex': manifest.master_seed_hex,
        'timestamp': manifest.timestamp,
        'passes': list(manifest.passes),
        'profile': manifest.profile,
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')


def read_manifest(path: str) -> BuildManifest:
    """Parse a manifest JSON file back into a ``BuildManifest``."""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return BuildManifest(
        build_id=data['build_id'],
        input_sha256=data['input_sha256'],
        license_id=data.get('license_id'),
        master_seed_hex=data['master_seed_hex'],
        timestamp=data['timestamp'],
        passes=list(data.get('passes', [])),
        profile=data.get('profile'),
    )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
def _smoke() -> None:
    # --- HKDF RFC 5869 Test Case 1 (SHA-256) ---
    okm = hkdf_sha256(bytes.fromhex('0b' * 22),
                      bytes.fromhex('000102030405060708090a0b0c'),
                      bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'), 42)
    assert okm.hex() == (
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865'), 'HKDF RFC 5869 TC1 mismatch'

    # --- ChaCha20 RFC 8439 ---
    cc_key = bytes.fromhex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    # §2.3.2 block-function vector: nonce 00000009|0000004a|00000000, ctr=1
    # (the "Serialized Block" verbatim from the RFC).
    assert _chacha20_block(
        cc_key, 1, bytes.fromhex('000000090000004a00000000')).hex() == (
        '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
        'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e'
    ), 'ChaCha20 §2.3.2 block mismatch'
    # §2.4.2 cipher vector: nonce 00000000|0000004a|00000000, initial ctr=1.
    cc_nonce = bytes.fromhex('000000000000004a00000000')
    block1 = _chacha20_block(cc_key, 1, cc_nonce)
    assert block1.hex() == (
        '224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf78'
        '8a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7'
    ), 'ChaCha20 §2.4.2 block1 mismatch'
    # Counter advances: block 2 (verbatim from RFC "Second block").
    block2 = _chacha20_block(cc_key, 2, cc_nonce)
    assert block2.hex() == (
        '69a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945'
        '398b6eda1a832c89c167eacd901d7e2bf363740373201aa188fbbce83991c4ed'
    ), 'ChaCha20 §2.4.2 block2 mismatch'
    # bytes() alias produces the same keystream as the block function.
    assert SubStream(cc_key, cc_nonce).bytes(64) == block1, 'bytes() alias mismatch'
    # End-to-end: keystream(ctr=1,2,..) XOR plaintext == RFC ciphertext.
    pt = b"Ladies and Gentlemen of the class of '99: If I could offer you " \
         b"only one tip for the future, sunscreen would be it."
    ss = SubStream(cc_key, cc_nonce)  # counter starts at 1
    ct = bytes(a ^ b for a, b in zip(ss.random(len(pt)), pt))
    assert ct.hex() == (
        '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b'
        'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8'
        '07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab779373'
        '65af90bbf74a35be6b40b8eedf2785e42874d'
    ), 'ChaCha20 §2.4.2 ciphertext mismatch'

    # --- Reproducible mode: same fixed_seed -> identical streams ---
    inp = b'traitor-tracing test input'
    fs = b'reproducible-seed-0xdeadbeef'
    r1 = BuildRNG.create(inp, fs)
    r2 = BuildRNG.create(inp, fs)
    assert r1.build_id() == r2.build_id(), 'reproducible build_id diverged'
    assert r1.master_seed_hex() == r2.master_seed_hex()
    assert r1.stream(b'obf_vars').random(64) == r2.stream(b'obf_vars').random(64)
    # --- Diversity: no fixed_seed -> different build_id ---
    assert BuildRNG.create(inp).build_id() != BuildRNG.create(inp).build_id(), \
        'non-reproducible build_id collided'
    # --- Different labels -> independent streams ---
    assert r1.stream(b'cff').random(64) != r1.stream(b'mba').random(64)
    assert r1.stream(b'cff').random(64) == r2.stream(b'cff').random(64)

    # --- randint/choice/shuffle reproducibility ---
    s1 = r1.stream(b'mba')
    s2 = r2.stream(b'mba')
    ir = [s1.randint(0, 9999) for _ in range(200)]
    ir2 = [s2.randint(0, 9999) for _ in range(200)]
    assert ir == ir2, 'randint not reproducible'
    assert all(0 <= x <= 9999 for x in ir), 'randint out of bounds'
    seq = list(range(50))
    sh1 = s1.shuffle(seq)
    sh2 = s2.shuffle(seq)
    assert sh1 == sh2, 'shuffle not reproducible'
    assert sorted(sh1) == seq, 'shuffle lost/duplicated elements'
    assert sh1 != seq, 'shuffle produced identity (implausible)'
    assert seq == list(range(50)), 'shuffle mutated its input'
    assert s1.choice(seq) == s2.choice(seq), 'choice not reproducible'
    assert 0 <= s1.choice(seq) <= 49

    # --- Manifest round-trip ---
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        m = BuildManifest(
            build_id=r1.build_id(),
            input_sha256=hashlib.sha256(inp).hexdigest(),
            license_id='cust-0001',
            master_seed_hex=r1.master_seed_hex(),
            timestamp='2026-07-16T00:00:00Z',
            passes=['cff', 'mba', 'obf_vars'],
            profile='native-tier',
        )
        mp = manifest_path(td)
        write_manifest(m, mp)
        m2 = read_manifest(mp)
        assert m2 == m, 'manifest round-trip mismatch'
        assert os.path.basename(mp) == '.bedrock_manifest.json'

    print('SMOKE PASS')


if __name__ == '__main__':
    _smoke()
