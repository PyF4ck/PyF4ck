# Bedrock Key-Release — Server-Released VM Key (Layer 3)

> Kerckhoffs-compliant: the algorithm, protocol, and blob format below are
> public. Security rests on (a) the per-system master seed — the single secret
> shared between the build host and the release server, never shipped — and
> (b) the per-request attestation (HWID + nonce + optional TPM2 quote) that
> gates who may receive a derived key.

## 1. Scope

Phase G adds a **server key-release** layer: instead of embedding the VM key
as a literal in the protected artifact (the default `--native-vm` path), the
obfuscator derives the key from a server master seed, ships a **key handle**
tuple, and the protected module fetches the key on first VM call via an
attested, end-to-end-encrypted POST to a release server.

This converts the VM key from a static artifact secret into a runtime-released
secret gated by machine attestation, with an offline-grace cache so a
protected module can run for a configurable TTL without network access.

## 2. Decisions (locked)

- **Crypto lib**: pyca `cryptography` (Apache-2.0/BSD, license-clean) for
  X25519 (ECDH), Ed25519 (EdDSA JWT), AES-GCM (cache + key wrap).
- **TPM**: **Tiered** — software HWID attestation is the default; a real TPM2
  quote (PCR + AIK) is used only when `tpm2-pytss` is importable on the client.
  Graceful `ImportError` fallback. `BEDROCK_TPM_REQUIRED=1` forces TPM.
- **KMS**: **Local software keystore** only — no AWS KMS, no boto3. The
  per-license VM key is derived via HKDF-SHA256 from a server master seed
  (`BEDROCK_MASTER_SEED`). This is the explicit user choice over cloud KMS.
- **Offline grace**: full — encrypted on-disk cache, machine-bound
  (HWID-derived key), TTL default 7 days (`BEDROCK_OFFLINE_GRACE_SECONDS`).

## 3. Key derivation

```
vm_key = HKDF-SHA256(
    ikm    = master_seed,                          # 32 bytes (the system secret)
    salt   = license_id.encode("utf-8"),           # per-license
    info   = b"bedrock-vm-key/v1" + build_id,      # per-build
    length = 32,
)
```

Reuses `bedrock_native/_build_rng.hkdf_sha256` (RFC 5869).

- **Reproducible**: same `(master_seed, license_id, build_id)` → same 32-byte
  key. The build host and the release server hold the same `master_seed` and
  the same derivation, so the server can re-derive exactly the key the
  obfuscator used to encode the blob.
- **Diverse**: any one input differing yields a different key. Different
  customers (`license_id`) get different keys from the same build; the same
  customer across builds (`build_id`) gets different keys; different master
  seeds yield entirely disjoint keyspaces.

## 4. Protocol

### 4.1 Build time (on the build host — holds `BEDROCK_MASTER_SEED`)

1. Obfuscator reads `--master-seed` / `BEDROCK_MASTER_SEED` (32 bytes hex).
2. Mints a fresh `build_id` (16 random bytes hex).
3. `LocalKeyProvider(master_seed).derive(license_id, build_id) → vm_key`.
4. Encodes the VM blob with `vm_key` (same encoder as `--native-vm`).
5. **Ships the artifact WITHOUT `vm_key`** — instead emits:
   ```python
   _vm_key_handle = (license_id, build_id, server_url,
                     server_ed25519_pub, server_x25519_pub, offline_grace_seconds)
   ```
6. No build-time network call. `master_seed` stays on the build host.

### 4.2 Release flow (client → server)

```
client                                  server (holds master_seed)
  |                                        |
  | X25519 ephemeral keypair               |
  | HWID = collect_hwid()                  |
  | nonce = 16 random bytes                |
  | (optional TPM2 quote)                  |
  |                                        |
  | POST /release {                        |
  |   license_id, build_id,                |
  |   hwid_hash = SHA256(HWID),            |
  |   nonce,                                |
  |   client_pub_x25519,                    |
  |   tpm_quote?                            |
  | } ----------------------------->        |
  |                                        | vm_key = derive_vm_key(master, lic, build)
  |                                        | nonce replay check (LRU, 5 min TTL)
  |                                        | TPM verify (tiered, graceful)
  |                                        | shared = X25519(server_priv, client_pub)
  |                                        | wrap_key = HKDF(shared, salt=nonce, info=b"bedrock-release/v1")
  |                                        | wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, vm_key, aad=build_id|license_id)
  |                                        | JWT = EdDSA({iss,sub,license_id,build_id,hwid_hash,iat,exp,wrapped,wrap_nonce})
  |                                        |
  |  <----------------------------- {jwt, server_x25519_pub, wrap_nonce}
  |                                        |
  | verify JWT (Ed25519 pub embedded)      |
  | check exp + field binding (const-time) |
  | shared = X25519(client_priv, server_pub) [pinned to embedded pub]
  | wrap_key = HKDF(shared, salt=nonce, ...)|
  | vm_key = AESGCM(wrap_key).decrypt(...) |
  | cache vm_key (machine-bound, TTL)      |
  | run VM with vm_key                     |
```

### 4.3 Key derivations (release channel)

| Label            | Derivation                                    | Used for                |
|------------------|-----------------------------------------------|-------------------------|
| `master_seed`    | env `BEDROCK_MASTER_SEED` / `--master-seed`   | system secret (build + server) |
| `vm_key`         | `HKDF(master, salt=license_id, info=label+build_id)` | VM blob decryption |
| `wrap_key`       | `HKDF(X25519_shared, salt=nonce, info=b"bedrock-release/v1")` | AES-GCM key wrap |
| `cache_key`      | `HKDF(HWID, salt=build_id, info=b"bedrock-cache/v1")`     | on-disk cache encryption |

## 5. On-disk cache (offline grace + machine binding)

Cache path: `~/.bedrock/key_cache/<sha256(build_id|license_id)[:32]>.bin`
(POSIX) or `%LOCALAPPDATA%/Bedrock/key_cache/...` (Windows).

```
file = b"BRKC" + nonce(12) + AESGCM(cache_key).encrypt(nonce, body, aad=build_id)
body = struct.pack(">II", iat, 32) + vm_key
```

- **Machine-bound**: `cache_key = HKDF(HWID, salt=build_id, ...)`. Copying
  the cache file to a different machine → different HWID → `cache_key`
  differs → AES-GCM tag fails → re-fetch. (The strong binding is the
  server-side attestation; the cache is a convenience for offline grace.)
- **TTL**: on load, `now - iat > offline_grace_seconds` → re-fetch.
- **Corruption / wrong HWID**: any AES-GCM failure → `load_cache` returns
  `None` → `get_key` falls back to `fetch_key`. Never raises on cache failure.

## 6. Server keys

- `BEDROCK_SERVER_ED25519_PRIV` — signs JWTs. Public key embedded in
  artifacts (pins the JWT signer).
- `BEDROCK_SERVER_X25519_PRIV` — ECDH. Public key embedded in artifacts
  (pins the ECDH peer; defeats MITM key substitution).
- Both 32-byte seeds. If env absent, generated once via
  `Ed25519PrivateKey.generate()` / `X25519PrivateKey.generate()` and
  persisted to `~/.bedrock/server_keys/{ed25519,x25519}.pem` (PEM, 0600).
- Build host loads the **public** halves via `load_server_pubkeys()` (env
  `BEDROCK_SERVER_ED25519_PUB` / `BEDROCK_SERVER_X25519_PUB`, or the
  persisted PEMs).

## 7. Nonce replay protection

The server keeps an in-memory LRU of seen nonces (TTL 5 min). A replayed
nonce → HTTP 401. Pruned lazily on each check. Thread-safe via a single lock.

## 8. Tiered TPM attestation

- **Software path (default)**: HWID = SHA-256 of `platform.node() |
  uuid.getnode() | /etc/machine-id | COMPUTERNAME | platform.machine()`.
  `hwid_hash = SHA-256(HWID)` is sent over the wire (the raw HWID is not
  leaked to a passive observer).
- **TPM path (when `tpm2-pytss` importable on the client)**: the client
  collects a TPM2 quote (PCR selection + AIK + nonce binding) and includes
  it in the `/release` request. The server verifies it when `tpm2-pytss` is
  importable there too; if `BEDROCK_TPM_REQUIRED=1`, a missing/failed quote
  → HTTP 403. Otherwise graceful fallback to HWID-only.

`collect_hwid()` is the factored-out twin of `bedrock_obfuscator.py`'s
`_collect_hw_fingerprint` (line 918). The two MUST agree byte-for-byte;
divergence silently breaks both env-keying and the cache binding.

## 9. Loader stub (shipped inside the protected artifact)

When `release_on=True`, `get_loader_snippet` emits:

```python
_vm_resolved_key = None
def _vm_get_key(_handle):
    global _vm_resolved_key
    if _vm_resolved_key is None:
        from _key_release_client import get_key, KeyHandle
        _vm_resolved_key = get_key(KeyHandle.from_tuple(_handle))
    return _vm_resolved_key
def _vm_run(_blob, _perm, _handle, _args, _g, _perm_ext):
    return _vm_mod.run(_blob, _perm, _vm_get_key(_handle), _args, _g, _perm_ext)
```

Key points:
- The key is resolved **lazily on first VM call** (not at import time), so a
  protected module can be imported offline; the fetch happens only when a
  crown-jewel function is actually called.
- The resolved key is cached in a module-global (`_vm_resolved_key`), so
  subsequent calls within the same process skip the fetch.
- The on-disk cache (`_key_release_client.load_cache`) is the cross-process
  + cross-restart persistence layer.
- `release_on` **replaces** the env-key `_vm_derive_key` indirection
  (key-release and env-key are mutually exclusive; release is the stronger,
  machine-attested mechanism).

## 10. CLI flags

| Flag                          | Env                          | Purpose |
|-------------------------------|------------------------------|---------|
| `--release-server URL`        | —                            | Enable key-release; the artifact ships a handle instead of the raw key |
| `--license-id ID`             | —                            | Per-license salt for the HKDF derivation |
| `--master-seed HEX`           | `BEDROCK_MASTER_SEED`        | 32-byte system secret (build host + server share it) |
| `--offline-grace-seconds N`   | —                            | Cache TTL (default 604800 = 7 days) |
| (server)                      | `BEDROCK_SERVER_ED25519_PRIV` | Ed25519 signing seed (hex) |
| (server)                      | `BEDROCK_SERVER_X25519_PRIV`  | X25519 ECDH seed (hex) |
| (build)                       | `BEDROCK_SERVER_ED25519_PUB`  | Ed25519 public key to embed (hex) |
| (build)                       | `BEDROCK_SERVER_X25519_PUB`   | X25519 public key to embed (hex) |
| (server, optional)            | `BEDROCK_TPM_REQUIRED=1`      | Force TPM2 attestation |

## 11. Files

### New (4)
1. `bedrock_native/_key_release.py` — key derivation + `KeyProvider` /
   `LocalKeyProvider` + `collect_hwid` + `load_server_pubkeys`. Pure stdlib
   (+ lazy `cryptography` for the pubkey loader).
2. `bedrock_native/_release_server.py` — FastAPI release server. `release_app`,
   `run_server`, `POST /release`, `GET /health`. Tiered TPM, nonce LRU,
   Ed25519 JWT, X25519 ECDH + AES-GCM wrap.
3. `bedrock_native/_key_release_client.py` — shipped client. `KeyHandle`,
   `fetch_key`, `get_key`, `load_cache`, `save_cache`. stdlib `urllib.request`
   + `cryptography` (JWT verify + ECDH + AES-GCM) + machine-bound cache.
4. `bedrock_native/_phase_g_test.py` — integration test (Style A `run_all()`).

### Modified (3)
5. `bedrock_native/_build_system.py` — `get_loader_snippet(release_on=False)`
   emits the `_vm_get_key` + handle path when on.
6. `bedrock_obfuscator.py` — `BuildContext.{release_server,license_id,master_seed,
   offline_grace_seconds}` + `_resolve_master_seed` helper + CLI flags.
   `apply_native_vm`: derives `vm_key` via `LocalKeyProvider` when release
   on; emits `_vm_key_handle` instead of `_vm_key`; wrapper passes the
   handle.
7. `requirements.txt` — `cryptography>=41` (hard dep) + commented
   `tpm2-pytss` (optional).

## 12. Verification (`_phase_g_test.py`)

All 12 sections pass:

```
G.1 derivation: reproducible + diverse + provider parity  OK
G.2 server: roundtrip matches LocalKeyProvider; replay -> 401  OK
G.3 client: fetch + cache hit/miss/expiry/machine-bind  OK
G.4 loader: release snippet emits _vm_get_key + handle path  OK
G.4 emission: _vm_key_handle branch present in obfuscator  OK
G.5 TPM tiered: software accepts; TPM-required rejects empty  OK
G.6 JWT: tampered rejected; expired handled; replay 401; valid OK  OK
G.7 offline: cache survives restart (within TTL)  OK
G.8 leak gate: no _vm_key / master / priv keys in emitted source  OK
G.8 full pipeline: fib(10)=55 via release-fetched key  OK
G.8 license isolation: cust-001 != cust-002 keys  OK
G.8 anti-theft: corrupted cache -> None (re-fetch needed)  OK
PHASE G INTEGRATION TEST: PASS
```

### Leak-gate (G.8) assertions on emitted source

- NO `_vm_key = b'...'` literal (the raw key is NOT shipped).
- NO `master_seed` hex value (the system secret is NOT shipped).
- NO server Ed25519/X25519 **private** key bytes (only publics embedded).
- ONLY `_vm_key_handle` + `server_url` + public keys present.

## 13. Constraints / risks

- **`cryptography` is a hard runtime dep** for the shipped client (JWT verify
  + ECDH + AES-GCM). Must be available in the protected module's environment
  or vendored. License-clean (Apache-2.0/BSD).
- **`tpm2-pytss` is optional** — never a hard dep. Graceful `ImportError` →
  software HWID fallback. TPM path SKIPs in tests when absent.
- **`master_seed` is THE secret**. A leak compromises ALL licenses — this is
  inherent to a local software keystore (the user's explicit choice over AWS
  KMS). Mitigation: the seed never ships, never appears in artifacts
  (leak-gate G.8), and the release channel is attested + end-to-end encrypted.
- **HWID is soft binding** — a determined attacker on the SAME machine can
  spoof HWID. The strong binding is the server-side attestation + nonce at
  release time; the cache is a convenience for offline grace, not a strong
  anti-theft measure.
- **Offline grace window**: 7 days default. A stolen artifact + stolen cache
  works offline until expiry, then re-attestation is required. Tunable via
  `--offline-grace-seconds` / `BEDROCK_OFFLINE_GRACE_SECONDS`.
- **No build-time network**: the obfuscator always has `master_seed` locally
  and derives `vm_key` without a network call. The server is purely a
  RELEASE mechanism. A future `ServerKeyProvider` (build-time online fetch
  so build hosts need NOT hold the master seed) is out of Phase G scope.
- **Shipped client uses stdlib `urllib.request`** — no `requests`/`httpx`
  runtime dep for the protected artifact.
- **v1 runtime only**: Phase G targets the shipped `_xvm` v1 runtime
  (accepts `key` kwarg). No dependency on the deferred Phase-F v2-wiring.
- **Mutual exclusivity with `--env-key`**: key-release replaces the env-key
  `_vm_derive_key` XOR indirection. The two flags are not combined in the
  MVP (key-release is the stronger, server-attested mechanism).

## 14. Threat model summary

| Threat                              | Mitigation |
|-------------------------------------|------------|
| Artifact leaks (source dumped)      | No `vm_key` in artifact — only a handle (public keys + IDs) |
| Passive network observer            | Key is ECDH-encrypted to client's ephemeral key; only pubkeys + IDs visible |
| MITM key substitution               | Server X25519 pub pinned in artifact; substitution detected |
| License-key piracy (copy to 2nd machine) | HWID-derived cache key; different machine → cache fails → re-attest |
| Replay attack (replay a release)    | Nonce LRU (5 min TTL); replay → 401 |
| JWT tampering / forgery             | Ed25519 signature; embedded public key verifies |
| Master seed leak                    | (Inherent risk of local keystore) — seed never ships, never in artifacts |
| TPM spoofing                        | Tiered: TPM is a bonus; `BEDROCK_TPM_REQUIRED=1` for hard requirement |
| Offline cache theft                 | Machine-bound (HWID-derived AES-GCM key) + TTL expiry |
