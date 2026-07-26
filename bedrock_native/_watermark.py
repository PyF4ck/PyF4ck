"""Phase E (Layer 5) per-license semantic watermark -- traitor tracing.

Collusion-resistant customer fingerprinting for the leaked-source scenario.
When a protected binary is redistributed, this module answers "which
customer's license did this build come from?" -- and stripping the
fingerprint breaks the build.

Design (Boneh-Shaw intrinsic mark)::

    build_master_secret  (minted once per build, SAME across all licenses)
        |
        | HKDF-SHA256(salt=b"bedrock-license", info=b"license"||license_id)
        v
    license_master       (PER-LICENSE -- differs per customer)
        |
        | HKDF-SHA256(salt=b"bedrock-fn", info=fn_index||fn_name)
        v
    function_key         (per-function content-encryption key)

Two customers issued builds from the SAME input get DIFFERENT encrypted
content blobs, because their content keys are derived from different
``license_master`` values. A forensic diff of two dumped, decrypted
binaries reveals the diverging key-derivation constants and thus the
``license_id``.

The mark is INTRINSIC, not additive: the function keys ARE what decrypt the
protected code. Stripping the watermark = stripping the key derivation =
the build stops decrypting. There is no separable "watermark blob" to cut.

Forensic recovery (``forensic_lookup`` / ``extract_license_id``): given the
per-license master extracted from a leaked build and the issuance DB
(``build_master`` + ``license_id`` per row), recompute
``derive_license_master`` for every issued license and find the match.

Pure stdlib: ``hashlib`` + ``hmac`` for HKDF, ``json`` for the manifest,
``dataclasses`` for ``IssuedLicense``, ``os`` for the smoke-test RNG.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass

# --- HKDF-SHA256 (RFC 5869) -------------------------------------------------

_HASH = hashlib.sha256
_HASH_LEN = 32  # SHA-256 output length, in bytes


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 extract step: PRK = HMAC-SHA256(salt, IKM)."""
    return hmac.new(salt, ikm, _HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 expand: OKM = T(1)||T(2)|..., T(i)=HMAC(PRK, T(i-1)||info||i)."""
    if length > 255 * _HASH_LEN:
        raise ValueError("HKDF expand length exceeds 255*HashLen")
    n = (length + _HASH_LEN - 1) // _HASH_LEN
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), _HASH).digest()
        okm += t
    return bytes(okm[:length])


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF-SHA256: extract then expand. Returns ``length`` bytes."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# --- Per-license + per-function key derivation ------------------------------

def derive_license_master(build_master: bytes, license_id: str) -> bytes:
    """Derive the per-license master secret from the build master.

    HKDF-SHA256(build_master, salt=b"bedrock-license",
                info=b"license"||license_id.encode(), length=32).

    Two different ``license_id`` values yield different masters from the
    same ``build_master``; the same (build_master, license_id) pair is
    reproducible. This is the per-license root that all function keys
    derive under -- the collusion-resistant watermark.
    """
    info = b"license" + license_id.encode("utf-8")
    return _hkdf(build_master, b"bedrock-license", info, 32)


def derive_function_key(license_master: bytes, fn_index: int,
                        fn_name: str = "") -> bytes:
    """Derive a per-function content key under a per-license master.

    HKDF-SHA256(license_master, salt=b"bedrock-fn",
                info=fn_index.to_bytes(4,'big')||fn_name.encode(), length=32).

    Two functions get different keys; the same (license_master, fn_index,
    fn_name) triple is reproducible. Because ``license_master`` differs per
    customer, so do every customer's function keys -- this divergence is
    the forensic signal. Stripping it breaks decryption (intrinsic mark).
    """
    info = fn_index.to_bytes(4, "big") + fn_name.encode("utf-8")
    return _hkdf(license_master, b"bedrock-fn", info, 32)


# --- Issuance DB + forensic recovery ----------------------------------------

@dataclass
class IssuedLicense:
    """One row of the license-issuance database.

    Attributes:
      license_id: customer / license identifier (e.g. "cust-001").
      master_seed_hex: hex of the BUILD master secret minted at build time
        (the per-build seed, NOT the per-license master). The per-license
        master is derived from it via ``derive_license_master``.
    """

    license_id: str
    master_seed_hex: str


def forensic_lookup(leaked_master_hex: str,
                    issued: list[IssuedLicense]) -> str | None:
    """Identify which issued license a leaked build belongs to.

    Args:
      leaked_master_hex: hex of the per-license master extracted from the
        leaked/dumped build (the root its content keys were derived under).
      issued: the issuance DB -- one ``IssuedLicense`` per issued license,
        each carrying the build master and the ``license_id``.

    Recomputes ``derive_license_master(build_master, license_id)`` for every
    issued row and returns the first ``license_id`` whose derived master
    matches the leak (constant-time ``hmac.compare_digest``), or ``None``
    if no row matches.
    """
    leaked = bytes.fromhex(leaked_master_hex)
    for lic in issued:
        build_master = bytes.fromhex(lic.master_seed_hex)
        candidate = derive_license_master(build_master, lic.license_id)
        if hmac.compare_digest(candidate, leaked):
            return lic.license_id
    return None


def extract_license_id(manifest_path: str,
                       leaked_build_master_hex: str) -> str | None:
    """Forensic recovery straight from a build manifest file.

    Reads the issuance manifest -- a JSON list of objects of the form
    ``{"license_id": "...", "master_seed_hex": "..."}`` (i.e. serialized
    ``IssuedLicense`` rows) -- then delegates to ``forensic_lookup``.

    Args:
      manifest_path: path to the JSON manifest.
      leaked_build_master_hex: hex of the per-license master extracted from
        the leaked build (compared against each row's recomputed master).

    Returns the matching ``license_id``, or ``None`` if no row matches.
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    issued = [IssuedLicense(license_id=item["license_id"],
                            master_seed_hex=item["master_seed_hex"])
              for item in data]
    return forensic_lookup(leaked_build_master_hex, issued)


# --- Smoke test -------------------------------------------------------------
if __name__ == "__main__":
    build_master = os.urandom(32)
    license_A = "cust-001"
    license_B = "cust-002"

    master_A = derive_license_master(build_master, license_A)
    master_B = derive_license_master(build_master, license_B)
    assert master_A != master_B, "different licenses must yield different masters"

    fn_key_A0 = derive_function_key(master_A, 0, "license_check")
    fn_key_B0 = derive_function_key(master_B, 0, "license_check")
    assert fn_key_A0 != fn_key_B0, "per-function keys must differ per license"

    # Reproducibility: identical inputs yield an identical key.
    assert derive_function_key(master_A, 0, "license_check") == \
        derive_function_key(master_A, 0, "license_check")

    # Forensic recovery: both issued builds share build_master, but their
    # per-license masters differ. The leak is the per-license master.
    issued = [IssuedLicense("cust-001", build_master.hex()),
              IssuedLicense("cust-002", build_master.hex())]
    assert forensic_lookup(master_A.hex(), issued) == "cust-001"
    assert forensic_lookup(master_B.hex(), issued) == "cust-002"
    assert forensic_lookup(os.urandom(32).hex(), issued) is None

    print("SMOKE PASS")
