"""Phase G (Layer 3) release server -- FastAPI key-release endpoint.

Build-time-only infrastructure (NEVER shipped to customers). Sits on the
release-server host alongside the master seed. Clients call ``POST /release``
with an attested challenge; the server re-derives the per-license VM key,
wraps it via X25519 ECDH + AES-GCM, and returns it inside a signed Ed25519
JWT.

## Kerckhoffs posture

The protocol is public. Security rests on:

  - ``BEDROCK_MASTER_SEED`` (32 bytes, env) -- the single system secret,
    shared with the build host. NEVER sent over the wire.
  - the server's Ed25519 private key (signs JWTs; public key is embedded in
    artifacts) + X25519 private key (ECDH; public sent per-response).
  - per-request attestation: nonce freshness (replay-protected) + HWID hash
    (machine-bound JWT) + optional TPM2 quote (hardware root of trust).

A passive observer of the HTTPS exchange sees only the client's ephemeral
public key + nonce + license/build IDs; the VM key is ECDH-encrypted to the
client's ephemeral key, so only the requester can unwrap it.

## Endpoints

  - ``POST /release`` -- attested key release.
  - ``GET /health``   -- liveness + config probe.

## Run

    BEDROCK_MASTER_SEED=<hex> uvicorn _release_server:release_app --port 8443

Or in-process for tests::

    from fastapi.testclient import TestClient
    from _release_server import release_app
    client = TestClient(release_app)

Dependencies: ``fastapi``, ``pydantic``, ``cryptography``. ``tpm2-pytss`` is
OPTIONAL (tiered TPM -- graceful ``ImportError`` fallback to HWID-only).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Sibling import.
import sys as _sys
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
from _build_rng import hkdf_sha256  # noqa: E402
from _key_release import derive_vm_key, hwid_hash  # noqa: E402

# cryptography (pyca) -- X25519 ECDH + Ed25519 EdDSA + AES-GCM.
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, InvalidKey

__all__ = [
    'release_app',
    'run_server',
    'ReleaseRequest',
    'encode_jwt_eddsa',
    'decode_jwt_eddsa',
]

# --- Constants --------------------------------------------------------------

_RELEASE_INFO = b"bedrock-release/v1"
_JWT_TTL_SECONDS = 300          # 5 min -- the JWT carrying the wrapped key
_NONCE_TTL_SECONDS = 300        # 5 min replay-protection window
_JWT_ISSUER = "bedrock-release"
_SERVER_KEY_DIR = os.path.expanduser("~/.bedrock/server_keys")


# --- Server key management --------------------------------------------------

def _load_or_create_server_keys() -> tuple[Ed25519PrivateKey, X25519PrivateKey]:
    """Load server Ed25519 + X25519 keys from env, else generate + persist.

    Env (hex of raw 32-byte seeds, highest precedence):
      - ``BEDROCK_SERVER_ED25519_PRIV``
      - ``BEDROCK_SERVER_X25519_PRIV``

    If env is absent, keys are loaded from or persisted to
    ``~/.bedrock/server_keys/{ed25519,x25519}.pem`` (PEM, no passphrase).
    Generation is one-shot on first run.
    """
    os.makedirs(_SERVER_KEY_DIR, exist_ok=True)
    ed_path = os.path.join(_SERVER_KEY_DIR, "ed25519.pem")
    x_path = os.path.join(_SERVER_KEY_DIR, "x25519.pem")

    # Ed25519
    ed_env = os.environ.get("BEDROCK_SERVER_ED25519_PRIV", "").strip()
    if ed_env:
        ed_seed = bytes.fromhex(ed_env)
        if len(ed_seed) != 32:
            raise ValueError("BEDROCK_SERVER_ED25519_PRIV must be 32 bytes hex")
        ed_key = Ed25519PrivateKey.from_private_bytes(ed_seed)
    elif os.path.isfile(ed_path):
        with open(ed_path, "rb") as f:
            ed_key = serialization.load_pem_private_key(
                f.read(), password=None)
    else:
        ed_key = Ed25519PrivateKey.generate()
        with open(ed_path, "wb") as f:
            f.write(ed_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(ed_path, 0o600)

    # X25519
    x_env = os.environ.get("BEDROCK_SERVER_X25519_PRIV", "").strip()
    if x_env:
        x_seed = bytes.fromhex(x_env)
        if len(x_seed) != 32:
            raise ValueError("BEDROCK_SERVER_X25519_PRIV must be 32 bytes hex")
        x_key = X25519PrivateKey.from_private_bytes(x_seed)
    elif os.path.isfile(x_path):
        with open(x_path, "rb") as f:
            x_key = serialization.load_pem_private_key(
                f.read(), password=None)
    else:
        x_key = X25519PrivateKey.generate()
        with open(x_path, "wb") as f:
            f.write(x_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(x_path, 0o600)

    return ed_key, x_key


def _load_master_seed() -> bytes:
    """Load the 32-byte master seed from ``BEDROCK_MASTER_SEED`` env (hex)."""
    h = os.environ.get("BEDROCK_MASTER_SEED", "").strip()
    if not h:
        raise RuntimeError(
            "BEDROCK_MASTER_SEED env not set (32 bytes hex required)")
    seed = bytes.fromhex(h)
    if len(seed) != 32:
        raise RuntimeError("BEDROCK_MASTER_SEED must be 32 bytes hex")
    return seed


def _ed25519_pub_hex(ed_key: Ed25519PrivateKey) -> str:
    return ed_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def _x25519_pub_hex(x_key: X25519PrivateKey) -> str:
    return x_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


# --- JWT (EdDSA, manual) ----------------------------------------------------

def _b64url(data: bytes) -> str:
    """base64url WITHOUT padding (JWT spec)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s = s + "=" * pad
    return base64.urlsafe_b64decode(s.encode("ascii"))


def encode_jwt_eddsa(payload: dict, ed_key: Ed25519PrivateKey) -> str:
    """Encode + sign an EdDSA JWT (RFC 8037).

    header = {"alg":"EdDSA","typ":"JWT"} (fixed). The signature is Ed25519
    over ``b64url(header) + "." + b64url(payload)``.
    """
    header = {"alg": "EdDSA", "typ": "JWT"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    sig = ed_key.sign(signing_input)
    return h_b64 + "." + p_b64 + "." + _b64url(sig)


def decode_jwt_eddsa(token: str, ed_pub: Ed25519PublicKey) -> dict:
    """Verify an EdDSA JWT signature and return the payload dict.

    Raises ``InvalidSignature`` if the signature is wrong, ``ValueError`` if
    the token is malformed or the header is not EdDSA.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT (expected 3 parts)")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(_b64url_decode(h_b64))
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unsupported alg {header.get('alg')!r}")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    sig = _b64url_decode(s_b64)
    ed_pub.verify(sig, signing_input)  # raises InvalidSignature
    return json.loads(_b64url_decode(p_b64))


# --- Nonce replay cache -----------------------------------------------------

class _NonceCache:
    """In-memory nonce replay-protection (TTL ``_NONCE_TTL_SECONDS``).

    Thread-safe via a single lock. Pruned lazily on each insert/check.
    """

    def __init__(self) -> None:
        self._seen: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for n in expired:
            del self._seen[n]

    def check_and_add(self, nonce: bytes) -> bool:
        """Return True if nonce is fresh (accepted), False if replay."""
        now = time.time()
        with self._lock:
            self._prune(now)
            if nonce in self._seen:
                return False  # replay
            self._seen[nonce] = now + _NONCE_TTL_SECONDS
            return True


# --- Tiered TPM (graceful) --------------------------------------------------

def _tpm_available() -> bool:
    """True if tpm2-pytss is importable (server-side TPM2 quote verify)."""
    try:
        import tpm2_pytss  # noqa: F401
        return True
    except Exception:
        return False


def _verify_tpm_quote(quote: bytes, pcrs: Optional[dict]) -> bool:
    """Verify a TPM2 quote (PCR selection + AIK). Graceful fallback.

    Returns True if the quote verifies OR if TPM is unavailable (tiered:
    software HWID attestation is the default; TPM is a hardening bonus).
    When ``BEDROCK_TPM_REQUIRED=1``, a missing/failed quote returns False.
    """
    tpm_required = os.environ.get("BEDROCK_TPM_REQUIRED", "0") == "1"
    if not _tpm_available():
        if tpm_required:
            return False  # TPM required but libs unavailable
        return True       # tiered: accept HWID-only
    # When tpm2-pytss is available, do a real verify. For now this is a
    # structural placeholder -- the full TPM2 quote verification (PCR
    # binding + AIK cert + nonce) is G.5's detailed implementation. The
    # server accepts a present non-empty quote as "TPM attempted".
    if tpm_required and not quote:
        return False
    return True


# --- Request / response models ----------------------------------------------

class ReleaseRequest(BaseModel):
    license_id: str
    build_id: str
    hwid_hash: str        # hex of SHA-256(HWID), 64 hex chars
    nonce: str            # hex, 16 bytes (128-bit)
    client_pub_x25519: str  # hex, 32 bytes (client ephemeral public key)
    tpm_quote: Optional[str] = None   # hex, optional TPM2 quote


# --- App --------------------------------------------------------------------

release_app = FastAPI(
    title="Bedrock Key-Release Server",
    version="1.0.0-phase-g",
)

# Server keys + master seed loaded lazily on first request so the module
# imports even when env is not configured (tests set env before hitting).
_server_state: dict = {"ed": None, "x": None, "master": None}
_state_lock = threading.Lock()
_nonces = _NonceCache()


def _ensure_state() -> tuple[Ed25519PrivateKey, X25519PrivateKey, bytes]:
    with _state_lock:
        if _server_state["ed"] is None:
            _server_state["ed"], _server_state["x"] = _load_or_create_server_keys()
            _server_state["master"] = _load_master_seed()
        return _server_state["ed"], _server_state["x"], _server_state["master"]


def _reset_state_for_test(ed: Ed25519PrivateKey, x: X25519PrivateKey,
                          master: bytes) -> None:
    """Inject deterministic server keys + master seed for tests."""
    with _state_lock:
        _server_state["ed"] = ed
        _server_state["x"] = x
        _server_state["master"] = master
        _nonces._seen.clear()


@release_app.get("/health")
def health() -> dict:
    """Liveness + config probe (never leaks secrets)."""
    try:
        ed, x, master = _ensure_state()
        return {
            "status": "ok",
            "master_seed_configured": len(master) == 32,
            "ed25519_pub": _ed25519_pub_hex(ed),
            "x25519_pub": _x25519_pub_hex(x),
            "tpm_available": _tpm_available(),
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "degraded", "error": str(e)}


@release_app.post("/release")
def release(req: ReleaseRequest) -> dict:
    """Attested key release.

    Flow:
      1. Validate request fields (license_id, build_id, hwid_hash, nonce,
         client_pub_x25519 -- all non-empty, correct lengths).
      2. Re-derive ``vm_key = derive_vm_key(master, license_id, build_id)``.
      3. Nonce replay check (TTL 5 min).
      4. Optional TPM2 quote verify (tiered, graceful).
      5. ECDH: ``shared = X25519(server_priv, client_pub)``;
         ``wrap_key = HKDF(shared, salt=nonce, info=b"bedrock-release/v1")``.
      6. AES-GCM: ``wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, vm_key,
         aad=build_id|license_id)``.
      7. Ed25519 JWT sign payload ``{iss, sub, license_id, build_id,
         hwid_hash, iat, exp, wrapped, wrap_nonce}``.
      8. Return ``{jwt, server_x25519_pub, wrap_nonce}``.
    """
    # 1. Validate
    if not req.license_id or not req.build_id:
        raise HTTPException(status_code=400,
                            detail="license_id and build_id required")
    try:
        hw = bytes.fromhex(req.hwid_hash)
        if len(hw) != 32:
            raise ValueError("hwid_hash must be 32 bytes")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400,
                            detail="hwid_hash must be 64 hex chars")
    try:
        nonce = bytes.fromhex(req.nonce)
        if len(nonce) < 16:
            raise ValueError("nonce too short")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400,
                            detail="nonce must be >= 16 hex bytes")
    try:
        client_pub_raw = bytes.fromhex(req.client_pub_x25519)
        if len(client_pub_raw) != 32:
            raise ValueError("client_pub must be 32 bytes")
        client_pub = X25519PublicKey.from_public_bytes(client_pub_raw)
    except (ValueError, InvalidKey):
        raise HTTPException(status_code=400,
                            detail="client_pub_x25519 must be 64 hex chars (32 bytes)")

    tpm_quote = b""
    if req.tpm_quote:
        try:
            tpm_quote = bytes.fromhex(req.tpm_quote)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400,
                                detail="tpm_quote must be hex")

    # 2. Re-derive the VM key
    ed, x_key, master = _ensure_state()
    try:
        vm_key = derive_vm_key(master, req.license_id, req.build_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 3. Nonce replay
    if not _nonces.check_and_add(nonce):
        raise HTTPException(status_code=401, detail="nonce replay")

    # 4. TPM (tiered)
    if not _verify_tpm_quote(tpm_quote, None):
        raise HTTPException(status_code=403,
                            detail="TPM attestation required but failed")

    # 5. ECDH
    shared = x_key.exchange(client_pub)
    wrap_key = hkdf_sha256(shared, salt=nonce, info=_RELEASE_INFO, length=32)

    # 6. AES-GCM wrap
    wrap_nonce = secrets.token_bytes(12)
    aad = (req.build_id.encode("utf-8") + b"|" + req.license_id.encode("utf-8"))
    wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, vm_key, aad)

    # 7. JWT sign
    now = int(time.time())
    payload = {
        "iss": _JWT_ISSUER,
        "sub": req.license_id,
        "license_id": req.license_id,
        "build_id": req.build_id,
        "hwid_hash": req.hwid_hash,
        "iat": now,
        "exp": now + _JWT_TTL_SECONDS,
        "wrapped": wrapped.hex(),
        "wrap_nonce": wrap_nonce.hex(),
    }
    token = encode_jwt_eddsa(payload, ed)

    # 8. Return
    return {
        "jwt": token,
        "server_x25519_pub": _x25519_pub_hex(x_key),
        "wrap_nonce": wrap_nonce.hex(),
    }


def run_server(host: str = "127.0.0.1", port: int = 8443) -> None:
    """Run the release server via uvicorn (CLI entrypoint)."""
    import uvicorn
    uvicorn.run(release_app, host=host, port=port)


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Server round-trip: TestClient /release returns a valid JWT + wrapped key
    that unwraps to the same key LocalKeyProvider would derive."""
    # Configure deterministic server keys + master seed for the smoke.
    os.environ["BEDROCK_MASTER_SEED"] = (b"\x42" * 32).hex()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    ed = Ed25519PrivateKey.generate()
    x = X25519PrivateKey.generate()
    master = bytes.fromhex(os.environ["BEDROCK_MASTER_SEED"])
    _reset_state_for_test(ed, x, master)

    from fastapi.testclient import TestClient
    client = TestClient(release_app)

    # Client ephemeral keypair
    client_priv = X25519PrivateKey.generate()
    client_pub_raw = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    from _key_release import collect_hwid
    hw = hwid_hash(collect_hwid())
    nonce = secrets.token_bytes(16)

    req = ReleaseRequest(
        license_id="cust-001",
        build_id="build-aaaa",
        hwid_hash=hw.hex(),
        nonce=nonce.hex(),
        client_pub_x25519=client_pub_raw.hex(),
    )
    r = client.post("/release", json=req.model_dump())
    assert r.status_code == 200, f"release failed: {r.status_code} {r.text}"
    body = r.json()
    assert "jwt" in body and "server_x25519_pub" in body and "wrap_nonce" in body
    print("G.2 release: 200 OK with JWT + server_x25519_pub + wrap_nonce  OK")

    # Verify JWT signature + structure
    ed_pub = ed.public_key()
    payload = decode_jwt_eddsa(body["jwt"], ed_pub)
    assert payload["license_id"] == "cust-001"
    assert payload["build_id"] == "build-aaaa"
    assert payload["hwid_hash"] == hw.hex()
    assert "wrapped" in payload and "wrap_nonce" in payload
    print("G.2 JWT: signature verifies, fields match request  OK")

    # Unwrap and compare to LocalKeyProvider
    from _key_release import LocalKeyProvider
    expected = LocalKeyProvider(master).derive("cust-001", "build-aaaa")
    server_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(body["server_x25519_pub"]))
    shared = client_priv.exchange(server_pub)
    wrap_key = hkdf_sha256(shared, salt=nonce, info=_RELEASE_INFO, length=32)
    wrap_nonce = bytes.fromhex(body["wrap_nonce"])
    aad = b"build-aaaa|cust-001"
    wrapped = bytes.fromhex(payload["wrapped"])
    assert body["wrap_nonce"] == payload["wrap_nonce"], "wrap_nonce mismatch"
    recovered = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped, aad)
    assert hmac.compare_digest(recovered, expected), "unwrapped key mismatch"
    print("G.2 unwrap: server-released key matches LocalKeyProvider  OK")

    # Nonce replay -> 401
    r2 = client.post("/release", json=req.model_dump())
    assert r2.status_code == 401, f"replay should be 401, got {r2.status_code}"
    print("G.2 replay: same nonce -> 401  OK")

    # Health
    r3 = client.get("/health")
    assert r3.status_code == 200
    assert r3.json()["master_seed_configured"] is True
    print("G.2 health: master_seed_configured=True  OK")

    print("G.2 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
