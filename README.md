# Bedrock Obfuscator

**Multi-pass Python obfuscator with custom bytecode VM and Practical iO
(Indistinguishability Obfuscation) — targeting nation-state + academic
adversaries.**

```
Input:  plain Python source  →  Bedrock pipeline  →  Output: obfuscated .py (+ .pyd)
                                              │
        ┌───────────────────────────────────────┘
        │
   6 layers:  renaming → string/const obf → CFF → capsule runtime → native VM → esoteric + iO
        │
        └── final: binary capsule (encrypted full-source, chi-square ≈ random)
```

---

## Quick Start

```bash
# 1. Obfuscate with the io profile (Practical iO, ~1.3 MB output)
python bedrock_obfuscator.py -f input.py -o obf.py --profile io \
    --anti-vm off --anti-debug off --no-debug-poison --no-metamorphic \
    --no-native-vm --no-cache --overwrite --adv-requests off --no-anti-timing --quiet

# 2. Run the obfuscated file (produces same output as input.py)
python obf.py

# 3. Verify the iO distinguishing test (20 builds, 190 pairs, chi-square gate)
python bedrock_native/_io_distinguish_test.py

# 4. Verify the adversarial ML classifier test (10 obf vs 10 random)
python bedrock_native/_io_adversarial_ml.py
```

---

## Profiles (5 presets)

| Flag | fast | balanced | paranoid | extreme | **io** |
|------|------|----------|----------|---------|--------|
| Rename + string obf | ✅ | ✅ | ✅ | ✅ | ✅ |
| CFF + dec traps | — | — | ✅ | ✅ | ✅ |
| Capsule runtime (`--runtime-dec`) | — | — | — | ✅ | ✅* |
| HMAC chain (`--chain`) | — | — | — | ✅ | ✅* |
| Native VM (`--native-vm`) | — | — | — | ✅ | ✅* |
| Phase H esoteric (11 passes) | — | — | — | — | **✅** |
| **Binary capsule** (iO-7) | — | — | — | — | **✅** |
| Threat model | casual | RE hobbyist | skilled RE | professional | **nation-state** |
| Output size | ~same | 1.5× | 2× | 2.5× | ~1.3 MB |
| Build time | <1s | ~3s | ~8s | ~15s | ~25s |

\* `io` profile enables these but the **binary capsule** (iO-7) auto-disables
`runtime_dec` and `chain` because the capsule already encrypts everything
(disabling the redundant chain also fixes an intermittent hang bug).

`--profile io` is the strongest preset. It layers:
- All of `extreme` (Phases 1-5, 7, G)
- Phase H esoteric passes (H.1-H.11)
- Phase iO extensions (iO-1 through iO-7)
- Binary capsule (full-source encrypted encapsulation)

---

## Architecture (6 layers)

```
Layer 1: Identifier renaming          (varsobf, spam_hanzi, Pycloak)
Layer 2: String/const encryption       (obf_strings, obf_builtins, num_obf)
Layer 3: Control-flow obfuscation      (CFF, dec_trap, var_split, DAG-CFF)
Layer 4: Capsule runtime               (apply_runtimedec — per-code-object encrypt)
Layer 5: Native VM                     (BedrockVM — custom bytecode in C extension)
Layer 6: Esoteric + Practical iO       (Phase H + iO-1..iO-7 → binary capsule)
```

Each layer is a set of **behavior-preserving, flag-gated passes** that compose
in a fixed order. Every pass is deterministic per-build (BuildRNG sub-streams)
and verified by the behavioral gate (`fib(10)=55`, `final_result: 221`).

---

## Feature Matrix

| Phase | Component | Coverage | Key files |
|-------|-----------|----------|------------|
| 1 | Capsule runtime | ALL functions | `apply_runtimedec` |
| 2 | HMAC chain | capsule functions | `--chain` |
| 3 | Debug poison + metamorphic | ALL functions | `--debug-poison`, `--metamorphic` |
| 4 | Anti-meta debranding | ALL strings | `--anti-meta` |
| 5 | Native VM (BedrockVM) | VM-eligible subset | `_bedrock_vm.c`, `_xvm.pyd` |
| 7 | Hardening (env-key, adv-requests) | ALL | `--env-key`, `--adv-requests` |
| G | Key release + TPM attestation | license-bound | `_key_release.py` |
| H | Esoteric (11 passes) | ALL functions | `_identifier_poison.py` … `_exc_table_vm.c` |
| **iO** | **Practical Indistinguishability Obfuscation** | **ALL** | **`_fss.py`, `_opaque_crypto.py`, `_pointfunc_obf.py`, `_lookup_obf.py`, `_entropy_pad.py`, `_binary_capsule.py`** |

---

## iO Highlights (Practical Indistinguishability Obfuscation)

The `io` profile achieves **statistical indistinguishability from random data**:

| Metric | Pre-iO | iO-6 (entropy pad) | iO-7 (binary capsule) | Random baseline |
|--------|--------|---------------------|----------------------|-----------------|
| Shannon entropy | 6.3 bits/byte | 7.88 bits/byte | **7.96 bits/byte** | 8.0 (max) |
| Pairwise chi-square (mean) | ~749,000 | ~538,000 | **501** | ~510 ± 35 |
| ML classifier accuracy | — | — | **40%** | 50% (chance) |
| Build success rate | — | 60% | **100%** | — |
| Output file size | ~2 MB | ~10 MB | **~1.3 MB** | — |

Full spec: **[bedrock_native/IO_SPEC.md](bedrock_native/IO_SPEC.md)**

### The 7 iO phases

| Phase | Construction | Commit |
|-------|-------------|--------|
| iO-1 | Foundation: wire Phase H + `io` profile + distinguish scaffold | `0ec3e14` |
| iO-2 | FSS extension: BGI bool/serialized/n-share + all-eligible | `07839b2` |
| iO-3 | Crypto opaque predicates: DL/LWE/RSA/hash (Z3 cannot fold) | `abb76db` |
| iO-4 | Point-function obfuscation: Canetti hash-based evaluator | `64ebd0e` |
| iO-5 | Encrypted lookup-table: multi-point generalization | `7a4ccbd` |
| iO-6 | Entropy padding: latin-1 binary injection (7.88 bits/byte) | `ad204e7` |
| iO-7 | **Binary capsule: full-source encrypted encapsulation** | `1808581` |

---

## Testing

```bash
# iO distinguishing test (20 builds, 190 pairs, ~10 min)
python bedrock_native/_io_distinguish_test.py

# iO adversarial ML classifier (10 obf vs 10 random, ~5 min)
python bedrock_native/_io_adversarial_ml.py

# Phase H integration test (11 passes + composition, ~2 min)
python bedrock_native/_phase_h_test.py

# Phase 5 full harness (16 cases, ~8 min)
python _phase5_harness.py

# Binary capsule smoke test (round-trip + entropy + diversity, <1s)
python bedrock_native/_binary_capsule.py

# Entropy pad smoke test (entropy + correctness + diversity, <1s)
python bedrock_native/_entropy_pad.py

# Individual iO phase smoke tests
python bedrock_native/_fss.py
python bedrock_native/_opaque_crypto.py
python bedrock_native/_pointfunc_obf.py
python bedrock_native/_lookup_obf.py
```

---

## Project Structure

```
bedrock_obfuscator.py          Main engine (15.5k+ lines)
app.py                         FastAPI playground (web UI)
_test_obf.py                   Test input (fib, is_prime → final_result: 221)

bedrock_native/
  _build_rng.py                BuildRNG (ChaCha20 + HKDF sub-streams)
  _fss.py                       iO-2: Function secret sharing (BGI)
  _opaque_crypto.py             iO-3: Crypto opaque predicates
  _pointfunc_obf.py             iO-4: Point-function obfuscation
  _lookup_obf.py               iO-5: Encrypted lookup-table
  _entropy_pad.py              iO-6: Entropy padding
  _binary_capsule.py           iO-7: Binary capsule (encrypted full-source)
  _io_distinguish_test.py      iO distinguishing test (N=20, chi-square gate)
  _io_adversarial_ml.py        iO adversarial ML classifier
  _identifier_poison.py        H.1: Identifier poisoning
  _acoda.py                    H.2: Opaque call dispatch
  _metamorphic.py              H.3: Structural metamorphic
  _style_randomizer.py         H.4: Style randomizer
  _branchless.py               H.5: Branchless-ification
  _bloom_obf.py                H.6: Bloom-filter opaque predicates
  _dag_cff.py                  H.7: DAG-based CFF
  _selfcheck_cf.py             H.8: Self-checking CF
  _fss.py                      H.9: FSS 2-share
  _tls_callback.py             H.10: TLS callback injection
  _exc_table_vm.c              H.11: Exception-table VM
  _bedrock_vm.c                BedrockVM C interpreter
  _bedrock_vm_ref.py           BedrockVM reference interpreter (Python)
  ESOTERIC_SPEC.md             Phase H spec (11 passes)
  IO_SPEC.md                   Phase iO spec (7 phases)
  VM_SPEC.md                   BedrockVM spec
  KEY_RELEASE_SPEC.md          Phase G key release spec

PRODUCTION_READINESS.md        Production readiness report
bedrock_spec.html              Full interactive spec (93 KB)
```

---

## Documentation

| Document | Content |
|----------|---------|
| **[bedrock_native/IO_SPEC.md](bedrock_native/IO_SPEC.md)** | Phase iO spec (7 phases, threat model, test methodology, results) |
| **[bedrock_native/ESOTERIC_SPEC.md](bedrock_native/ESOTERIC_SPEC.md)** | Phase H spec (11 esoteric passes) |
| **[bedrock_native/VM_SPEC.md](bedrock_native/VM_SPEC.md)** | BedrockVM spec (ISA, blob format, crypto) |
| **[bedrock_native/KEY_RELEASE_SPEC.md](bedrock_native/KEY_RELEASE_SPEC.md)** | Phase G key release + TPM attestation |
| **[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)** | Production readiness report (Phases 1-5, 7, G, H, iO) |
| **[bedrock_spec.html](bedrock_spec.html)** | Full interactive HTML spec (87 CLI flags, 14 passes, 30+ checks) |

---

## Commit History (key milestones)

```
d17f12e  app.py: io profile sandbox-safe flags + latin-1 preview
cedfbdd  Phase iO-7: adversarial ML classifier (accuracy 40% < chance 50%)
197a57c  iO-7: N=20 scale test + calibrated chi gate (random baseline 651±25)
5a34b43  Fix runtime_dec hang: disable redundant chain when binary capsule on
1808581  Phase iO-7: Binary capsule (chi-square 511 ≈ random baseline 510)
ad204e7  Phase iO-6: Entropy padding (latin-1 binary injection, 7.88 bits/byte)
7a4ccbd  Phase iO-5: encrypted lookup-table obfuscation
64ebd0e  Phase iO-4: point-function obfuscation (Canetti hash-based)
abb76db  Phase iO-3: Cryptographic opaque predicates (DL/LWE/RSA)
07839b2  Phase iO-2: Extend FSS — bool/serialized/n-share + all-eligible
0ec3e14  Phase iO-1: Foundation — wire Phase H + add io profile + distinguish
7beefa7  Initial commit: Bedrock Obfuscator (Phases 1-5, 7, G)
```

---

## Threat Model

The `io` profile targets:

- **Nation-state adversaries**: intelligence agencies with full access to
  static analysis tools, symbolic execution engines (Z3, angr), and
  decompiler suites (Ghidra, IDA, pydc).
- **Academic adversaries**: researchers with novel ML-based devirtualization
  (XL-DFR, rnn-based), byte-level fingerprinting (chi-square, KL-divergence),
  and adversarial classifiers.
- **No performance constraint**: the `io` profile trades runtime overhead
  for maximum protection. Build time ~25s, runtime ~5-10× slower than
  unobfuscated.

The binary capsule (iO-7) ensures the output file's byte distribution is
statistically indistinguishable from random data — a chi-square test or
ML classifier cannot distinguish two obfuscated builds from two random files
better than chance.
