"""Phase G (Layer 3) shipped client: release-fetch + on-disk encrypted cache.

This module is SHIPPED INSIDE the protected artifact (the loader stub calls
into it to resolve the VM key on first use). It uses ONLY:

  - stdlib ``urllib.request`` for the HTTP POST (no ``requests``/``httpx``
    runtime dep -- keeps the protected artifact light),
  - ``cryptography`` (pyca) for X25519 ECDH + Ed25519 JWT verify + AES-GCM
    (the one hard runtime dep, documented in the spec).

## Flow

``get_key(handle, ...)``:

  1. Build the cache path for ``(build_id, license_id)``.
  2. If a valid cached key exists and is within ``offline_grace_seconds``,
     return it (offline grace).
  3. Else ``fetch_key(handle, ...)``:
     a. Generate an ephemeral X25519 keypair.
     b. Collect HWID (+ optional TPM2 quote, tiered).
     c. Mint a 16-byte nonce.
     d. ``POST /release`` to ``server_url`` (stdlib urllib).
     e. Verify the returned Ed25519 JWT against the embedded
        ``server_ed25519_pub``; check ``exp`` + that ``build_id`` /
        ``license_id`` / ``hwid_hash`` match the handle (constant-time).
     f. ECDH: ``shared = X25519(client_priv, server_x25519_pub)``;
        ``wrap_key = HKDF(shared, salt=nonce, info=b"bedrock-release/v1")``.
     g. AES-GCM decrypt the wrapped key.
  4. Save the recovered key to the on-disk cache (AES-GCM under a
     HWID-derived key) and return it.

## Cache binding

The cache file is encrypted under::

    cache_key = HKDF-SHA256(HWID, salt=build_id, info=b"bedrock-cache/v1")

So copying the cache to a different machine (different HWID) yields a
different ``cache_key``, the AES-GCM tag fails, and the client re-fetches.
The cache is a convenience for offline grace, NOT a strong anti-theft
measure (the strong binding is the server-side attestation+nonce).

Run::

    python bedrock_native/_key_release_client.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
import urllib.request
import urllib.error
from typing import Optional, Tuple

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import hkdf_sha256  # noqa: E402
from _key_release import collect_hwid, hwid_hash  # noqa: E402

# cryptography (pyca).
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

__all__ = [
    'KeyHandle',
    'fetch_key',
    'get_key',
    'cache_path',
    'load_cache',
    'save_cache',
]

_RELEASE_INFO = b"bedrock-release/v1"
_CACHE_INFO = b"bedrock-cache/v1"
_DEFAULT_OFFLINE_GRACE = 7 * 24 * 3600   # 7 days
_HTTP_TIMEOUT = 15                       # seconds


# --- KeyHandle --------------------------------------------------------------

class KeyHandle:
    """The artifact-embedded handle: everything the client needs to fetch
    the VM key at runtime, with NO secret material.

    Fields:
      license_id, build_id   -- identifies which key to release.
      server_url             -- the release server's base URL.
      server_ed25519_pub     -- 32 raw bytes (verifies the JWT).
      server_x25519_pub      -- 32 raw bytes (ECDH; also returned per-response
                                but the embedded copy lets the client pin it
                                to defeat MITM key substitution).
      offline_grace_seconds  -- cache TTL.
    """

    __slots__ = (
        "license_id", "build_id", "server_url",
        "server_ed25519_pub", "server_x25519_pub", "offline_grace_seconds",
    )

    def __init__(self, license_id: str, build_id: str, server_url: str,
                 server_ed25519_pub: bytes, server_x25519_pub: bytes,
                 offline_grace_seconds: int = _DEFAULT_OFFLINE_GRACE) -> None:
        self.license_id = license_id
        self.build_id = build_id
        self.server_url = server_url.rstrip("/")
        if len(server_ed25519_pub) != 32:
            raise ValueError("server_ed25519_pub must be 32 bytes")
        if len(server_x25519_pub) != 32:
            raise ValueError("server_x25519_pub must be 32 bytes")
        self.server_ed25519_pub = bytes(server_ed25519_pub)
        self.server_x25519_pub = bytes(server_x25519_pub)
        self.offline_grace_seconds = int(offline_grace_seconds)

    @classmethod
    def from_tuple(cls, t: tuple) -> "KeyHandle":
        """Reconstruct from the loader-emitted literal tuple."""
        # Accept both 5- and 6-tuples (offline_grace optional).
        lid, bid, url, ed, x = t[:5]
        grace = t[5] if len(t) >= 6 else _DEFAULT_OFFLINE_GRACE
        return cls(lid, bid, url, ed, x, grace)

    def as_tuple(self) -> tuple:
        return (self.license_id, self.build_id, self.server_url,
                self.server_ed25519_pub, self.server_x25519_pub,
                self.offline_grace_seconds)


# --- JWT verify (manual EdDSA) ---------------------------------------------

def _b64url_decode(s: str) -> bytes:
    import base64
    pad = 4 - (len(s) % 4)
    if pad != 4:
        s = s + "=" * pad
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _verify_jwt(token: str, ed_pub: Ed25519PublicKey) -> dict:
    """Verify an EdDSA JWT and return the payload. Raises on any failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(_b64url_decode(h_b64))
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unsupported alg {header.get('alg')!r}")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    sig = _b64url_decode(s_b64)
    try:
        ed_pub.verify(sig, signing_input)
    except InvalidSignature:
        raise ValueError("JWT signature invalid")
    return json.loads(_b64url_decode(p_b64))


# --- Tiered TPM (client side, graceful) ------------------------------------

def _collect_tpm_quote(nonce: bytes) -> Optional[bytes]:
    """Collect a TPM2 quote if tpm2-pytss / Windows TBS is available.

    Returns the quote bytes (or None if unavailable). Tiered: software HWID
    attestation is always the default; TPM is a hardening bonus.
    """
    try:
        import tpm2_pytss  # noqa: F401
        # Full TPM2 quote collection (PCR selection + AIK + nonce binding)
        # is G.5's detailed impl. For now return None on Linux without a
        # real TPM context -- the server's tiered verify accepts HWID-only.
        return None
    except Exception:
        return None


# --- HTTP POST (stdlib urllib) ---------------------------------------------

def _post_release(server_url: str, payload: dict, timeout: int = _HTTP_TIMEOUT) -> dict:
    """POST the release request JSON and return the parsed response dict.

    Uses stdlib ``urllib.request`` -- no ``requests``/``httpx`` dep.
    Raises ``RuntimeError`` on any HTTP/transport error.
    """
    url = server_url.rstrip("/") + "/release"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace") if e.fp else ""
        raise RuntimeError(f"release server returned {e.code}: {detail}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"release server unreachable: {e.reason}") from None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"release server returned non-JSON: {raw!r}")


# --- fetch_key --------------------------------------------------------------

def fetch_key(handle: KeyHandle) -> bytes:
    """Fetch the VM key from the release server.

    Generates an ephemeral X25519 keypair, collects HWID (+ optional TPM2
    quote), mints a nonce, POSTs to ``handle.server_url``, verifies the
    returned Ed25519 JWT, ECDH-unwraps the AES-GCM-wrapped key. Returns
    the 32-byte VM key.

    Raises ``RuntimeError`` on any transport / attestation / crypto failure.
    """
    # a. Ephemeral X25519 keypair
    client_priv = X25519PrivateKey.generate()
    client_pub_raw = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    # b. HWID + optional TPM quote
    hw = collect_hwid()
    hh = hwid_hash(hw)
    tpm_quote = _collect_tpm_quote(secrets.token_bytes(16))

    # c. Nonce
    nonce = secrets.token_bytes(16)

    # d. POST
    payload = {
        "license_id": handle.license_id,
        "build_id": handle.build_id,
        "hwid_hash": hh.hex(),
        "nonce": nonce.hex(),
        "client_pub_x25519": client_pub_raw.hex(),
    }
    if tpm_quote is not None:
        payload["tpm_quote"] = tpm_quote.hex()
    resp = _post_release(handle.server_url, payload)

    # e. JWT verify
    token = resp.get("jwt")
    if not token:
        raise RuntimeError("release response missing 'jwt'")
    ed_pub = Ed25519PublicKey.from_public_bytes(handle.server_ed25519_pub)
    jwt_payload = _verify_jwt(token, ed_pub)

    # exp check
    now = int(time.time())
    exp = int(jwt_payload.get("exp", 0))
    if exp <= now:
        raise RuntimeError("JWT expired")
    if exp > now + 3600:
        # sanity: server shouldn't issue >1h validity
        raise RuntimeError("JWT exp implausibly far")

    # field binding (constant-time compare)
    if not hmac.compare_digest(str(jwt_payload.get("license_id", "")),
                               handle.license_id):
        raise RuntimeError("JWT license_id mismatch")
    if not hmac.compare_digest(str(jwt_payload.get("build_id", "")),
                               handle.build_id):
        raise RuntimeError("JWT build_id mismatch")
    if not hmac.compare_digest(str(jwt_payload.get("hwid_hash", "")),
                               hh.hex()):
        raise RuntimeError("JWT hwid_hash mismatch")

    # f. ECDH + HKDF
    server_x25519_pub_hex = resp.get("server_x25519_pub")
    if not server_x25519_pub_hex:
        raise RuntimeError("release response missing 'server_x25519_pub'")
    server_pub = X25519PublicKey.from_public_bytes(
        bytes.fromhex(server_x25519_pub_hex))
    # Pin: server's response X25519 pub must match the embedded one.
    if not hmac.compare_digest(
        server_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw),
        handle.server_x25519_pub):
        raise RuntimeError("server_x25519_pub does not match embedded pin")
    shared = client_priv.exchange(server_pub)
    wrap_key = hkdf_sha256(shared, salt=nonce, info=_RELEASE_INFO, length=32)

    # g. AES-GCM decrypt
    wrap_nonce = bytes.fromhex(resp["wrap_nonce"])
    if not hmac.compare_digest(jwt_payload["wrap_nonce"], resp["wrap_nonce"]):
        raise RuntimeError("wrap_nonce mismatch between JWT and response")
    aad = (handle.build_id.encode("utf-8") + b"|" +
           handle.license_id.encode("utf-8"))
    wrapped = bytes.fromhex(jwt_payload["wrapped"])
    try:
        vm_key = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped, aad)
    except InvalidTag:
        raise RuntimeError("wrapped key AES-GCM tag invalid")
    if len(vm_key) != 32:
        raise RuntimeError(f"unwrapped key wrong length {len(vm_key)}")
    return vm_key


# --- On-disk encrypted cache -----------------------------------------------

def _cache_dir() -> str:
    """Return the cache directory (platform-appropriate)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "Bedrock", "key_cache")
    return os.path.join(os.path.expanduser("~"), ".bedrock", "key_cache")


def cache_path(handle: KeyHandle, *, base_dir: Optional[str] = None) -> str:
    """Return the on-disk cache path for this (build_id, license_id)."""
    d = base_dir if base_dir is not None else _cache_dir()
    # Sanitize the IDs for the filename (build_id/license_id are caller-
    # supplied; hash to a fixed-length safe filename).
    safe = hashlib.sha256(
        (handle.build_id + "|" + handle.license_id).encode("utf-8")
    ).hexdigest()[:32]
    return os.path.join(d, f"{safe}.bin")


def _cache_key(handle: KeyHandle) -> bytes:
    """Derive the AES-GCM cache key from the live HWID."""
    hw = collect_hwid()
    return hkdf_sha256(hw, salt=handle.build_id.encode("utf-8"),
                       info=_CACHE_INFO, length=32)


def save_cache(handle: KeyHandle, vm_key: bytes,
               *, base_dir: Optional[str] = None,
               iat: Optional[int] = None) -> str:
    """Encrypt ``vm_key`` under the HWID-derived key and persist to disk.

    Cache format (all little-endian, AES-GCM of the body):
      plaintext body = struct.pack(">II", iat, len(vm_key)) + vm_key
      ciphertext = AESGCM(cache_key).encrypt(nonce, body, aad=build_id)
      file = magic(4) + nonce(12) + ciphertext

    Returns the path written.
    """
    if len(vm_key) != 32:
        raise ValueError("vm_key must be 32 bytes")
    if iat is None:
        iat = int(time.time())
    path = cache_path(handle, base_dir=base_dir)
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    key = _cache_key(handle)
    body = struct.pack(">II", iat, len(vm_key)) + vm_key
    nonce = secrets.token_bytes(12)
    aad = handle.build_id.encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, body, aad)
    blob = b"BRKC" + nonce + ct
    # Write atomically: temp + rename.
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_cache(handle: KeyHandle,
               *, base_dir: Optional[str] = None,
               offline_grace_seconds: Optional[int] = None,
               now: Optional[int] = None) -> Optional[bytes]:
    """Load + validate the cached key. Returns the 32-byte key, or None if:

      - the cache file does not exist,
      - it is malformed,
      - the AES-GCM tag fails (wrong HWID / corrupted),
      - the cache is older than ``offline_grace_seconds`` (expired).

    ``offline_grace_seconds`` defaults to ``handle.offline_grace_seconds``.
    Never raises on cache failure -- the caller falls back to ``fetch_key``.
    """
    if offline_grace_seconds is None:
        offline_grace_seconds = handle.offline_grace_seconds
    if now is None:
        now = int(time.time())
    path = cache_path(handle, base_dir=base_dir)
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        return None
    if len(blob) < 4 + 12 + 16 or blob[:4] != b"BRKC":
        return None
    nonce = blob[4:16]
    ct = blob[16:]
    key = _cache_key(handle)
    aad = handle.build_id.encode("utf-8")
    try:
        body = AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        return None
    if len(body) < 8:
        return None
    iat, klen = struct.unpack(">II", body[:8])
    if klen != 32 or len(body) != 8 + klen:
        return None
    vm_key = body[8:]
    # TTL check
    if now - iat > offline_grace_seconds:
        return None
    if now - iat < -60:
        # clock skew sanity -- don't trust a future-dated cache
        return None
    return vm_key


# --- get_key (cache-or-fetch) ----------------------------------------------

def get_key(handle: KeyHandle,
            *, base_dir: Optional[str] = None,
            allow_fetch: bool = True) -> bytes:
    """Resolve the VM key: cache first, then fetch.

    1. Try the on-disk cache (offline grace). If valid + within TTL, return.
    2. Else, if ``allow_fetch``, fetch from the server and persist to cache.
    3. Else raise (no cache + fetch disabled).

    Raises ``RuntimeError`` if fetch is required and fails.
    """
    cached = load_cache(handle, base_dir=base_dir)
    if cached is not None:
        return cached
    if not allow_fetch:
        raise RuntimeError("no cached key and fetch disabled (offline)")
    vm_key = fetch_key(handle)
    save_cache(handle, vm_key, base_dir=base_dir)
    return vm_key


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Full client round-trip against an in-process release server."""
    # Stand up the server in-process via TestClient. _release_server's smoke
    # already covers the server side; here we exercise the CLIENT against it.
    os.environ["BEDROCK_MASTER_SEED"] = (b"\x42" * 32).hex()
    from fastapi.testclient import TestClient
    from _release_server import release_app, _reset_state_for_test
    from _key_release import LocalKeyProvider
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed = Ed25519PrivateKey.generate()
    x = X25519PrivateKey.generate()
    master = bytes.fromhex(os.environ["BEDROCK_MASTER_SEED"])
    _reset_state_for_test(ed, x, master)
    client = TestClient(release_app)

    ed_pub_raw = ed.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    x_pub_raw = x.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    # Monkey-patch _post_release to route through the TestClient so we don't
    # need a real network listener.
    def _fake_post(server_url: str, payload: dict, timeout: int = 15) -> dict:
        r = client.post("/release", json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"release {r.status_code}: {r.text}")
        return r.json()
    global _post_release
    _post_release = _fake_post  # noqa: F811

    handle = KeyHandle(
        license_id="cust-001",
        build_id="build-aaaa",
        server_url="http://test-release",
        server_ed25519_pub=ed_pub_raw,
        server_x25519_pub=x_pub_raw,
        offline_grace_seconds=604800,
    )

    # Use an isolated cache dir so the smoke doesn't pollute the real one.
    import tempfile
    cache_dir = tempfile.mkdtemp(prefix="br_g3_")

    # Miss -> fetch -> matches LocalKeyProvider.
    vm_key = get_key(handle, base_dir=cache_dir)
    expected = LocalKeyProvider(master).derive("cust-001", "build-aaaa")
    assert hmac.compare_digest(vm_key, expected), "fetch returned wrong key"
    print("G.3 fetch: miss -> fetch -> matches LocalKeyProvider  OK")

    # Cache file exists.
    path = cache_path(handle, base_dir=cache_dir)
    assert os.path.isfile(path), "cache not written"
    print(f"G.3 cache: persisted to {os.path.basename(path)}  OK")

    # Hit: get_key again reads from cache (no fetch). Disable fetch to prove it.
    vm_key2 = get_key(handle, base_dir=cache_dir, allow_fetch=False)
    assert hmac.compare_digest(vm_key, vm_key2), "cache hit returned different key"
    print("G.3 cache hit: re-read with fetch disabled -> same key  OK")

    # Expiry: rewrite cache with an old iat -> TTL expired -> returns None.
    save_cache(handle, vm_key, base_dir=cache_dir,
               iat=int(time.time()) - 604800 - 1)
    assert load_cache(handle, base_dir=cache_dir) is None, "expired not detected"
    print("G.3 expiry: stale cache -> None (re-fetch needed)  OK")

    # Wrong-HWID binding: simulate by corrupting the cache file (wrong tag).
    with open(path, "rb") as f:
        good = f.read()
    with open(path, "wb") as f:
        f.write(good[:4 + 12] + bytes(16) + good[4 + 12 + 16:])
    assert load_cache(handle, base_dir=cache_dir) is None, "corrupt not detected"
    print("G.3 machine-bind: corrupted cache -> None (re-fetch needed)  OK")

    # Restore a good cache and verify offline mode (fetch disabled) works.
    save_cache(handle, vm_key, base_dir=cache_dir)
    vm_key3 = get_key(handle, base_dir=cache_dir, allow_fetch=False)
    assert hmac.compare_digest(vm_key, vm_key3), "offline restore failed"
    print("G.3 offline: restored cache -> works without fetch  OK")

    # Clean up.
    import shutil
    shutil.rmtree(cache_dir, ignore_errors=True)

    print("G.3 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
