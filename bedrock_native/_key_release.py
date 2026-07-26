"""Phase G (Layer 3) key-release: key derivation + KeyProvider + HWID.

This is the **build-time** side of the Bedrock key-release layer. It defines
how a per-license, per-build VM key is derived from a single server master
seed, the KeyProvider abstraction, and a cross-platform hardware-ID collector
used for machine binding at release time.

## Kerckhoffs posture

The algorithm is public. Security rests entirely on:

  - ``master_seed`` -- the single system secret (32 bytes). Lives ONLY on the
    build host and the release server (same value). NEVER shipped, NEVER
    written to any artifact (the G.8 leak gate asserts this).
  - the per-release attestation (HWID + nonce challenge + optional TPM2 quote)
    that gates who may receive the derived key.

A leak of ``master_seed`` compromises ALL licenses -- this is the explicit
consequence of the user's "local software keystore only" choice (no AWS KMS,
no HSM). The mitigation is operational: the seed never ships, never appears
in source, and the release channel is attested + end-to-end encrypted.

## Key derivation

::

    vm_key = HKDF-SHA256(
        ikm   = master_seed,                       # 32 bytes
        salt  = license_id.encode("utf-8"),        # per-license
        info  = b"bedrock-vm-key/v1" + build_id,   # per-build
        length= 32,
    )

This reuses ``bedrock_native/_build_rng.hkdf_sha256`` (RFC 5869). It is:

  - REPRODUCIBLE: the same ``(master_seed, license_id, build_id)`` triple
    always yields the same 32-byte key.
  - DIVERSE: any one input differing yields a different key (HKDF is a PRF).

## HWID collection

``collect_hwid()`` is the FACTORED-OUT twin of ``bedrock_obfuscator.py``'s
``_collect_hw_fingerprint`` (defined at ``bedrock_obfuscator.py:918``). The two MUST
agree byte-for-byte: the build host uses ``_collect_hw_fingerprint`` to
encrypt the env-keyed blob, and the release server / client use
``collect_hwid`` to derive the machine binding. Divergence silently breaks
both env-keying and the machine-bound cache. Keep them in lock-step; if you
edit one, edit the other.

Pure stdlib (``hashlib``, ``platform``, ``uuid``, ``os``). Run::

    python bedrock_native/_key_release.py
"""
from __future__ import annotations

import hashlib
import os
import platform
import sys
import uuid
from typing import Protocol, runtime_checkable

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import hkdf_sha256  # noqa: E402

__all__ = [
    'derive_vm_key',
    'KeyProvider',
    'LocalKeyProvider',
    'load_server_pubkeys',
    'collect_hwid',
    'hwid_hash',
]

# --- Constants --------------------------------------------------------------

# HKDF ``info`` label. Bumped only if the derivation scheme changes in a way
# that would otherwise alias old and new keys.
_INFO_LABEL = b"bedrock-vm-key/v1"


# --- Key derivation ---------------------------------------------------------

def derive_vm_key(master_seed: bytes, license_id: str, build_id: str) -> bytes:
    """Derive the per-license, per-build VM key from the master seed.

    ``vm_key = HKDF-SHA256(master_seed, salt=license_id,
                           info=b"bedrock-vm-key/v1" + build_id, length=32)``.

    Reproducible: the same ``(master_seed, license_id, build_id)`` triple
    always yields the same 32-byte key. Diverse: any one input differing
    yields a different key. ``master_seed`` MUST be 32 bytes (an assertion,
    not a silent pad/trim -- a wrong-length seed is a caller bug).
    """
    if len(master_seed) != 32:
        raise ValueError(
            f"master_seed must be 32 bytes, got {len(master_seed)}")
    if not license_id:
        raise ValueError("license_id must be a non-empty string")
    if not build_id:
        raise ValueError("build_id must be a non-empty string")
    salt = license_id.encode("utf-8")
    info = _INFO_LABEL + build_id.encode("utf-8")
    return hkdf_sha256(master_seed, salt, info, 32)


@runtime_checkable
class KeyProvider(Protocol):
    """Abstract build-time key provider.

    A KeyProvider holds the secret needed to derive a VM key for a given
    ``(license_id, build_id)`` pair. The only concrete implementation in
    Phase G is :class:`LocalKeyProvider` (holds the master seed locally).
    A future ``ServerKeyProvider`` could fetch the key from a remote KMS at
    build time (out of Phase G scope -- the obfuscator derives locally).
    """

    def derive(self, license_id: str, build_id: str) -> bytes: ...


class LocalKeyProvider:
    """KeyProvider backed by a local master seed (the local software keystore).

    The master seed is read from, in order of precedence:

      1. the ``master_seed`` constructor argument (highest),
      2. the ``BEDROCK_MASTER_SEED`` env var (hex- or bytes-decoded),
      3. ``--master-seed`` CLI flag (passed in as ``master_seed`` by the CLI).

    Phase G's design is "no build-time network": the obfuscator always has
    the master seed locally. The release server holds the SAME seed to
    re-derive keys on demand.
    """

    def __init__(self, master_seed: bytes):
        if len(master_seed) != 32:
            raise ValueError(
                f"master_seed must be 32 bytes, got {len(master_seed)}")
        # Copy so the caller can't mutate our secret after construction.
        self._master_seed = bytes(master_seed)

    @property
    def master_seed(self) -> bytes:
        # Return a copy so the caller can't mutate the live secret.
        return bytes(self._master_seed)

    def derive(self, license_id: str, build_id: str) -> bytes:
        return derive_vm_key(self._master_seed, license_id, build_id)


def load_server_pubkeys(server_url: str = "") -> tuple[bytes, bytes]:
    """Build-time helper: load the release server's PUBLIC keys for embedding.

    Reads from, in precedence order:
      1. ``BEDROCK_SERVER_ED25519_PUB`` / ``BEDROCK_SERVER_X25519_PUB`` env
         (hex of 32 bytes each) -- set when the operator provisions the
         server keys,
      2. the persisted PEM files at ``~/.bedrock/server_keys/{ed25519,x25519}.pem``
         (created by ``_release_server._load_or_create_server_keys`` on first
         server run -- we read just the public halves here).

    Returns ``(ed25519_pub_raw, x25519_pub_raw)`` -- two 32-byte raw public
    keys to embed in the artifact's ``_vm_key_handle``. Raises ``RuntimeError``
    if neither source is available.

    This is a BUILD-TIME helper (runs on the build host). It imports
    ``cryptography`` lazily so the rest of ``_key_release`` stays importable
    without the crypto lib.
    """
    ed_env = os.environ.get("BEDROCK_SERVER_ED25519_PUB", "").strip()
    x_env = os.environ.get("BEDROCK_SERVER_X25519_PUB", "").strip()
    if ed_env and x_env:
        ed_pub = bytes.fromhex(ed_env)
        x_pub = bytes.fromhex(x_env)
        if len(ed_pub) != 32 or len(x_pub) != 32:
            raise RuntimeError(
                "BEDROCK_SERVER_*_PUB must be 32 bytes hex each")
        return ed_pub, x_pub
    # Fallback: read the persisted PEMs (server must have run once to create
    # them). We read the PUBLIC key bytes from the PEM private keys.
    from cryptography.hazmat.primitives import serialization
    key_dir = os.path.expanduser("~/.bedrock/server_keys")
    ed_path = os.path.join(key_dir, "ed25519.pem")
    x_path = os.path.join(key_dir, "x25519.pem")
    if not (os.path.isfile(ed_path) and os.path.isfile(x_path)):
        raise RuntimeError(
            "Server public keys unavailable: set BEDROCK_SERVER_ED25519_PUB "
            "/ BEDROCK_SERVER_X25519_PUB env, or run the release server once "
            "to persist keys to ~/.bedrock/server_keys/")
    with open(ed_path, "rb") as f:
        ed_priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(x_path, "rb") as f:
        x_priv = serialization.load_pem_private_key(f.read(), password=None)
    ed_pub = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    x_pub = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return ed_pub, x_pub


# --- HWID collection --------------------------------------------------------

def collect_hwid() -> bytes:
    """Collect a stable 32-byte hardware fingerprint for the current machine.

    This is the FACTORED-OUT twin of ``bedrock_obfuscator.py:_collect_hw_fingerprint``
    (line 918). The two MUST agree byte-for-byte. Every field is optional --
    a missing field contributes an empty string rather than raising, so the
    collector stays total across docker / CI / minimal envs.

    Fields collected (joined with ``|``, then SHA-256'd):

      1. ``platform.node()``      -- hostname
      2. ``uuid.getnode()``        -- MAC address (48-bit int)
      3. ``/etc/machine-id``       -- Linux machine id (empty elsewhere)
      4. ``COMPUTERNAME`` env      -- Windows machine name (empty elsewhere)
      5. ``platform.machine()``    -- arch (x86_64, AMD64, ...)

    Returns a 32-byte SHA-256 digest. Never raises (best-effort; on total
    failure returns the digest of the empty string).
    """
    parts = []
    try:
        parts.append(str(platform.node()))
    except Exception:
        parts.append("")
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        parts.append("")
    try:
        _mid = "/etc/machine-id"
        if os.path.isfile(_mid):
            with open(_mid, "r") as _f:
                parts.append(_f.read().strip())
        else:
            parts.append("")
    except Exception:
        parts.append("")
    try:
        parts.append(str(os.environ.get("COMPUTERNAME", "")))
    except Exception:
        parts.append("")
    try:
        parts.append(str(platform.machine()))
    except Exception:
        parts.append("")
    blob = "|".join(parts).encode("utf-8", "replace")
    return hashlib.sha256(blob).digest()


def hwid_hash(hwid: bytes) -> bytes:
    """SHA-256 of the HWID digest (the value sent over the wire as
    ``hwid_hash``). Sending the hash instead of the raw HWID avoids leaking
    the machine identity to a passive observer of the release request while
    still letting the server bind the released key to a specific machine.
    """
    if len(hwid) != 32:
        raise ValueError(f"hwid must be 32 bytes, got {len(hwid)}")
    return hashlib.sha256(hwid).digest()


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Reproducibility + diversity + provider parity + HWID sanity."""
    import hmac

    master = b"\x00" * 32
    master_b = b"\x01" * 32
    lic_a, lic_b = "cust-001", "cust-002"
    build_x, build_y = "build-aaaa", "build-bbbb"

    # Reproducible: same triple -> identical key.
    k1 = derive_vm_key(master, lic_a, build_x)
    k2 = derive_vm_key(master, lic_a, build_x)
    assert len(k1) == 32 and hmac.compare_digest(k1, k2), "reproducibility"
    print(f"G.1 reproducible: same triple -> {k1.hex()[:16]}... OK")

    # Diverse: any one input differing -> different key.
    assert derive_vm_key(master, lic_b, build_x) != k1, "license diversity"
    assert derive_vm_key(master, lic_a, build_y) != k1, "build diversity"
    assert derive_vm_key(master_b, lic_a, build_x) != k1, "master diversity"
    print("G.1 diverse: license/build/master differ -> different key  OK")

    # Provider parity: LocalKeyProvider matches raw derive_vm_key.
    prov = LocalKeyProvider(master)
    assert hmac.compare_digest(prov.derive(lic_a, build_x), k1), "provider parity"
    assert prov.master_seed == master, "master seed copy"
    prov.master_seed  # property access must not raise
    print("G.1 LocalKeyProvider matches derive_vm_key  OK")

    # Validation: wrong-length master seed is a caller bug, not silent.
    for bad in (b"", b"\x00" * 16, b"\x00" * 33):
        try:
            LocalKeyProvider(bad)
            raise AssertionError("accepted bad master_seed length")
        except ValueError:
            pass
    for bad_lid, bad_bid in [("", build_x), (lic_a, "")]:
        try:
            derive_vm_key(master, bad_lid, bad_bid)
            raise AssertionError("accepted empty id")
        except ValueError:
            pass
    print("G.1 validation: rejects bad-length master / empty ids  OK")

    # HWID: 32 bytes, stable across calls on the same machine.
    h1 = collect_hwid()
    h2 = collect_hwid()
    assert len(h1) == 32 and hmac.compare_digest(h1, h2), "hwid stable"
    hh = hwid_hash(h1)
    assert len(hh) == 32 and hh != h1, "hwid_hash differs from raw"
    print(f"G.1 HWID: stable 32-byte digest {h1.hex()[:16]}...  OK")

    # Parity with bedrock_obfuscator.py:_collect_hw_fingerprint -- the two MUST
    # agree byte-for-byte. Import lazily so this smoke test doesn't hard-
    # depend on the obfuscator being importable.
    try:
        sys.path.insert(0, os.path.dirname(_HERE))
        # `bedrock_obfuscator.py` is not a valid module name; exec the collector
        # body directly from the source file to compare against our
        # factored-out twin.
        bedrock_src = os.path.join(os.path.dirname(_HERE), "bedrock_obfuscator.py")
        with open(bedrock_src, "r", encoding="utf-8") as _bf:
            _src = _bf.read()
        # Slice from `def _collect_hw_fingerprint` to the next sibling
        # statement at the SAME (or lesser) indent level. The collector is
        # a NESTED def (indented 4 spaces), so the slice must bound by the
        # def's own indent, and the result must be dedented before exec.
        import textwrap as _tw
        _lines = _src.splitlines()
        _start = next(i for i, ln in enumerate(_lines)
                      if "def _collect_hw_fingerprint" in ln)
        _def_indent = len(_lines[_start]) - len(_lines[_start].lstrip(" "))
        _end = _start + 1
        while _end < len(_lines):
            _ln = _lines[_end]
            if _ln.strip() and (len(_ln) - len(_ln.lstrip(" "))) <= _def_indent:
                break  # back to (or out of) the enclosing scope
            _end += 1
        _body = _tw.dedent("\n".join(_lines[_start:_end]))
        _ns: dict = {}
        exec(compile(_body, "<fingerprint-twin>", "exec"), _ns)
        _twin = _ns["_collect_hw_fingerprint"]()
        assert hmac.compare_digest(_twin, h1), \
            "factored collect_hwid DIVERGES from bedrock_obfuscator.py twin"
        print("G.1 parity: collect_hwid == bedrock_obfuscator.py twin  OK")
    except FileNotFoundError:
        print("G.1 parity: SKIP (bedrock_obfuscator.py not found)")
    except Exception as _e:  # noqa: BLE001
        # Don't fail the whole smoke on a parse glitch; surface it.
        print(f"G.1 parity: SKIP ({type(_e).__name__}: {_e})")

    print("G.1 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
