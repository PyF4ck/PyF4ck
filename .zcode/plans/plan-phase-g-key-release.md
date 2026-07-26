# Phase G — Server key-release (Layer 3)

> **STATUS: COMPLETE (2026-07-17).** All 8 sub-phases (G.1-G.8) implemented and
> verified by `bedrock_native/_phase_g_test.py` → "PHASE G INTEGRATION TEST:
> PASS". Documentation: `bedrock_native/KEY_RELEASE_SPEC.md`.

## Quyết định user (đã chốt)
- **Crypto lib**: `cryptography` (pyca, Apache-2.0/BSD — license-clean). X25519
  (ECDH) + Ed25519 (EdDSA JWT) + AES-GCM (cache + key wrap).
- **TPM attestation**: **Tiered** — software HWID default; real TPM2 quote
  ONLY when `tpm2-pytss` importable. Graceful `ImportError` fallback.
- **KMS**: **Local software keystore only** — NO AWS KMS, NO boto3. Per-license
  VM key derived via HKDF-SHA256 from `BEDROCK_MASTER_SEED`.
- **Offline grace**: full — encrypted on-disk cache, machine-bound
  (HWID-derived key), TTL default 7 days.

## Contract (honor verbatim)
- `vm_key = HKDF-SHA256(master_seed, salt=license_id, info=b"bedrock-vm-key/v1"+build_id, 32)`.
  Reproducible (same triple → same key); diverse (any input differs → different key).
- Build-time: obfuscator derives `vm_key` locally via `LocalKeyProvider` (has
  `master_seed`). Ships artifact WITHOUT the key — emits `_vm_key_handle`
  tuple `(license_id, build_id, server_url, server_ed25519_pub,
  server_x25519_pub, offline_grace_seconds)`. No build-time network call.
- Release flow: client → `POST /release` → server re-derives `vm_key`, ECDH
  wraps (X25519 + HKDF + AES-GCM), Ed25519 JWT signs → client verifies JWT,
  ECDH unwraps, AES-GCM decrypts → `vm_key`.
- Cache: `~/.bedrock/key_cache/<sha256(build_id|license_id)[:32]>.bin`,
  AESGCM under `HKDF(HWID, salt=build_id, info=b"bedrock-cache/v1")`. TTL
  `offline_grace_seconds` (default 604800). Machine-bound (wrong HWID → tag
  fails → re-fetch).
- Server keys: `BEDROCK_SERVER_ED25519_PRIV` + `BEDROCK_SERVER_X25519_PRIV`
  (env hex, or generated+persisted to `~/.bedrock/server_keys/*.pem`).
- Nonce replay: in-memory LRU, TTL 5 min → 401.
- HTTP: stdlib `urllib.request` only (no `requests`/`httpx` runtime dep).
- Shipped runtime: v1 `_xvm` (accepts `key` kwarg). No F.x v2-wiring dep.

## Sub-phases (all COMPLETE)
| Sub-phase | Gate | Status |
|-----------|------|--------|
| G.1 | Key derivation + KeyProvider + HWID (`_key_release.py`) | PASS |
| G.2 | Release server FastAPI (`_release_server.py`) | PASS |
| G.3 | Client fetch + on-disk cache (`_key_release_client.py`) | PASS |
| G.4 | Loader stub integration (`_build_system.py` + `bedrock (2).py`) | PASS |
| G.5 | Tiered TPM attestation | PASS (software; TPM SKIPs gracefully) |
| G.6 | Ed25519 JWT + nonce replay | PASS |
| G.7 | Offline grace + machine-bound cache | PASS |
| G.8 | Integration test + leak gate (`_phase_g_test.py`) | PASS |

## Files
### New (4)
1. `bedrock_native/_key_release.py` — `derive_vm_key`, `LocalKeyProvider`,
   `collect_hwid` (twin of `bedrock (2).py:_collect_hw_fingerprint`),
   `load_server_pubkeys`.
2. `bedrock_native/_release_server.py` — FastAPI `release_app`,
   `POST /release`, `GET /health`, Ed25519 JWT, X25519 ECDH + AES-GCM wrap,
   nonce LRU, tiered TPM.
3. `bedrock_native/_key_release_client.py` — `KeyHandle`, `fetch_key`,
   `get_key`, `load_cache`, `save_cache`. stdlib `urllib.request` +
   `cryptography`. Machine-bound cache with TTL.
4. `bedrock_native/_phase_g_test.py` — integration test (12 sections PASS).

### Modified (3)
5. `bedrock_native/_build_system.py` — `get_loader_snippet(release_on=False)`
   emits `_vm_get_key` + handle path when on (replaces `_vm_derive_key`).
6. `bedrock (2).py` — `BuildContext.{release_server,license_id,master_seed,
   offline_grace_seconds}` + `_resolve_master_seed` + CLI flags
   (`--release-server`, `--license-id`, `--master-seed`,
   `--offline-grace-seconds`). `apply_native_vm` derives via
   `LocalKeyProvider` when release on; emits `_vm_key_handle` instead of
   `_vm_key`; wrapper passes the handle; loader call passes `release_on`.
7. `requirements.txt` — `cryptography>=41` (hard) + commented `tpm2-pytss`.

### Doc (1)
8. `bedrock_native/KEY_RELEASE_SPEC.md` — Phase G spec (mirrors `VM_V2_SPEC.md`).

## Verification (12/12 PASS)
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
