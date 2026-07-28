# Bedrock Obfuscator

**Multi-pass Python obfuscator with custom bytecode VM and byte-distribution
randomization (encrypted-source capsule) — targeting skilled reverse
engineers.**

```
Input:  plain Python source  →  Bedrock pipeline  →  Output: obfuscated .py (+ .pyd)
                                              │
        ┌───────────────────────────────────────┘
        │
   6 layers:  renaming → string/const obf → CFF → capsule runtime → native VM → esoteric + encrypted capsule
        │
        └── final: encrypted-source capsule (byte distribution ≈ random; key NOT shipped by default)
```

> **Honesty note on "iO".** Earlier versions of this project marketed the
> `io` profile as achieving "Practical Indistinguishability Obfuscation
> (iO)". That claim was **incorrect**. iO in cryptography means obfuscations
> of two *different but functionally-equivalent* programs are
> indistinguishable. The capsule only ensures the *output file's byte
> distribution* is uniform — a property of any encryption/PRG output, which
> says nothing about distinguishing obfuscations of equivalent programs.
> The terminology has been corrected throughout; the metric is now labelled
> "encrypted-output uniformity". See `bedrock_native/IO_SPEC.md`
> "Limitations" for the full correction.

---

## Quick Start

```bash
# 1. Obfuscate with the io profile (encrypted-source capsule, ~1.3 MB output)
#    By default the capsule key is NOT embedded in the file — it is emitted
#    to a sidecar <output>.key and read from env at runtime (secure).
python bedrock_obfuscator.py -f input.py -o obf.py --profile io \
    --anti-vm off --anti-debug off --no-debug-poison --no-metamorphic \
    --no-native-vm --no-cache --overwrite --adv-requests off --no-anti-timing --quiet

# 2. Run the obfuscated file (must provide the key via env)
BR_CAPSULE_KEY=$(cat obf.py.key) python obf.py
#    Without the env var the file refuses to run and the source stays
#    encrypted on disk. (Pass --embed-key at build time for the legacy
#    insecure mode where the key ships in the file — NOT recommended.)

# 3. Verify the encrypted-output uniformity test (PRG + iO-property, ~30 min)
python bedrock_native/_io_distinguish_test.py
BR_ML_N=40 python bedrock_native/_io_adversarial_ml.py
```

> **What these tests measure.** `_io_distinguish_test.py` measures
> per-build diversity + ciphertext byte-uniformity (chi-square vs random
> baseline). `_io_adversarial_ml.py` runs TWO experiments: (a) a PRG-
> uniformity test (obf vs `os.urandom`) and (b) an **iO-property test**
> (`Obf(P0)` vs `Obf(P1)` for two functionally-equivalent but syntactically
> different programs P0, P1). Only (b) is the actual indistinguishability-
> of-obfuscation property. Both report a Wilson 95% confidence interval.
> Be aware: with the `--embed-key` flag these tests are self-contained but
> embed the key in every build (acceptable for a uniformity test, not for
> production).

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
- The 7 capsule phases (iO-1 through iO-7)
- The encrypted-source capsule (byte-distribution randomization). The
  capsule key is **read from env at runtime by default** (secure); pass
  `--embed-key` for the legacy insecure mode where the key ships in the
  file.

---

## Architecture (6 layers)

```
Layer 1: Identifier renaming          (varsobf, spam_hanzi, Pycloak)
Layer 2: String/const encryption       (obf_strings, obf_builtins, num_obf)
Layer 3: Control-flow obfuscation      (CFF, dec_trap, var_split, DAG-CFF)
Layer 4: Capsule runtime               (apply_runtimedec — per-code-object encrypt)
Layer 5: Native VM                     (BedrockVM — custom bytecode in C extension)
Layer 6: Esoteric + encrypted-source capsule  (Phase H + iO-1..iO-7 → binary capsule)
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
| G | Key release + TPM attestation | license-bound | `_key_release.py` (TPM is a placeholder) |
| H | Esoteric (11 passes) | ALL functions | `_identifier_poison.py` … `_exc_table_vm.c` |
| **io** | **Encrypted-source capsule + value secret sharing + opaque predicates** | **ALL** | **`_fss.py` (value secret sharing, NOT BGI FSS), `_opaque_crypto.py`, `_pointfunc_obf.py`, `_lookup_obf.py`, `_entropy_pad.py`, `_binary_capsule.py`** |

---

## Encrypted-output uniformity (formerly "iO Highlights")

The `io` profile encrypts the obfuscated source so the output file's byte
distribution approaches uniform. This is a **PRG-uniformity** property, not
the cryptographic iO property (see the honesty note above):

| Metric | Pre-capsule | Capsule | Random baseline |
|--------|--------|--------|-----------------|
| Shannon entropy | 6.3 bits/byte | **7.96 bits/byte** | 8.0 (max) |
| Pairwise chi-square (mean) | ~749,000 | **501** | ~510 ± 35 |
| ML PRG-uniformity accuracy | — | varies with N* | 50% (chance) |
| ML iO-property accuracy | — | not yet characterized | 50% (chance) |
| Build success rate | — | **100%** | — |
| Output file size | ~2 MB | **~1.3 MB** | — |

\* The previous test reported "40% accuracy" but was statistically vacuous
(N=10, gate inconsistent between docstring and code, byte-pair features
claimed but unimplemented). The rewritten test
(`bedrock_native/_io_adversarial_ml.py`) uses N≥40, Wilson 95% CIs, both
byte-histogram and byte-pair features, a stratified split, and an honest
PRG-uniformity gate. **It now sometimes FAILS** at the strict gate — which
is the correct behaviour, because the capsule's bootstrap (~0.1% of the
file, containing `import zlib, hashlib` and `exec(zlib.decompress`) is a
greppable structural signature that the bigram features can pick up.

Full spec: **[bedrock_native/IO_SPEC.md](bedrock_native/IO_SPEC.md)**

### The 7 phases (formerly "iO phases")

| Phase | Construction | Commit |
|-------|-------------|--------|
| iO-1 | Foundation: wire Phase H + `io` profile + distinguish scaffold | `0ec3e14` |
| iO-2 | Value secret sharing (additive/bool/serialized) — NOT BGI FSS | `07839b2` |
| iO-3 | Crypto opaque predicates (resist symbolic SMT; concrete-exec caveat) | `abb76db` |
| iO-4 | Point-function obfuscation (salted-hash equality check) | `64ebd0e` |
| iO-5 | Encrypted lookup-table: multi-point generalization | `7a4ccbd` |
| iO-6 | Entropy padding: latin-1 binary injection (7.88 bits/byte) | `ad204e7` |
| iO-7 | **Encrypted-source capsule (byte-distribution randomization)** | `1808581` |

---

## Testing

```bash
# Encrypted-output uniformity test (20 builds, 190 pairs, ~10 min)
python bedrock_native/_io_distinguish_test.py

# Adversarial ML classifier: PRG-uniformity + iO-property tests (~10 min at N=40)
# The iO-property test compares Obf(P0) vs Obf(P1) for two functionally-
# equivalent but syntactically different programs — the ACTUAL
# indistinguishability-of-obfuscation property. (Earlier versions only ran
# the PRG-uniformity test and called it "iO", which was incorrect.)
BR_ML_N=40 python bedrock_native/_io_adversarial_ml.py
# Larger N for publication-grade runs:
BR_ML_N=100 python bedrock_native/_io_adversarial_ml.py   # ~50 min

# Phase H integration test (11 passes + composition, ~2 min)
python bedrock_native/_phase_h_test.py

# Phase 5 full harness (16 cases, ~8 min)
python _phase5_harness.py

# Encrypted-source capsule smoke test (round-trip + secure-mode + escape fuzz, <1s)
python bedrock_native/_binary_capsule.py

# Entropy pad smoke test (entropy + correctness + diversity, <1s)
python bedrock_native/_entropy_pad.py

# Individual capsule-phase smoke tests
python bedrock_native/_fss.py
python bedrock_native/_opaque_crypto.py
python bedrock_native/_pointfunc_obf.py
python bedrock_native/_lookup_obf.py
```

---

## Project Structure

```
bedrock_obfuscator.py          Main engine (15.5k+ lines)
app.py                         FastAPI playground (web UI). native_vm defaults OFF
                               since Phase B (server-side RCE mitigation).
_test_obf.py                   Test input (fib, is_prime → final_result: 221)

bedrock_native/
  _build_rng.py                BuildRNG (ChaCha20 + HKDF sub-streams). Wired
                               into the build path since Phase C.2; replaces
                               the previous Mersenne-Twister fallback.
  _fss.py                       Value secret sharing (additive/bool/serialized).
                               NOT BGI FSS — see module docstring.
  _opaque_crypto.py             Crypto opaque predicates (resist symbolic SMT;
                               concrete-exec caveat noted in docstring).
  _pointfunc_obf.py             Point-function obfuscation (salted-hash check).
                               NOT Canetti's construction — see docstring.
  _lookup_obf.py               Encrypted lookup-table (master key ships in
                               the source; "protected by downstream passes").
  _entropy_pad.py              Entropy padding (latin-1 binary injection).
  _binary_capsule.py           Encrypted-source capsule (byte-distribution
                               randomization). Key NOT shipped by default
                               (env var); --embed-key for legacy insecure mode.
  _io_distinguish_test.py      Encrypted-output uniformity test (N=20, chi-square).
                               Measures ciphertext uniformity, NOT iO.
  _io_adversarial_ml.py        ML classifier: PRG-uniformity + iO-property tests.
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
  IO_SPEC.md                   Capsule-phase spec (7 phases) — includes the
                               "iO" terminology correction + limitations.
  VM_SPEC.md                   BedrockVM spec
  KEY_RELEASE_SPEC.md          Phase G key release spec

PRODUCTION_READINESS.md        Production readiness report
bedrock_spec.html              Full interactive spec (93 KB)
```

---

## Documentation

| Document | Content |
|----------|---------|
| **[bedrock_native/IO_SPEC.md](bedrock_native/IO_SPEC.md)** | Capsule-phase spec (7 phases, threat model, test methodology, results, and the "iO" terminology correction + limitations) |
| **[bedrock_native/ESOTERIC_SPEC.md](bedrock_native/ESOTERIC_SPEC.md)** | Phase H spec (11 esoteric passes) |
| **[bedrock_native/VM_SPEC.md](bedrock_native/VM_SPEC.md)** | BedrockVM spec (ISA, blob format, crypto) |
| **[bedrock_native/KEY_RELEASE_SPEC.md](bedrock_native/KEY_RELEASE_SPEC.md)** | Phase G key release + TPM attestation |
| **[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)** | Production readiness report (Phases 1-5, 7, G, H, io) |
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

- **Skilled reverse engineers**: hobbyists and analysts with static analysis
  tools, decompiler suites (pydc, uncompyle6) and willingness to write a
  custom disassembler for the BedrockVM bytecode.
- **NOT nation-state adversaries** in the default configuration. With the
  capsule key embedded in the file (legacy `--embed-key` mode, or any build
  before the Phase A remediation), an attacker recovers the original
  obfuscated source by running the file's own ~10-line bootstrap — this is
  trivial and defeats any adversary, nation-state or otherwise.

For a stronger posture the capsule key must NOT ship in the file. Two
options, both opt-in:

1. **Env-key (default since Phase A)**: the build emits a sidecar
   `<output>.key` and the bootstrap reads it from `$BR_CAPSULE_KEY` at
   runtime. The source is genuinely encrypted at rest; the key lives in
   the runtime environment, not the artifact. This raises the bar from
   "grep the file" to "read the process environment / dump the decrypted
   in-process source" — still defeatable by a debugger, but no longer
   trivially recoverable from the file alone.
2. **Release-server (Phase G, opt-in via `--release-server`)**: the master
   seed lives on a license server; the VM key is derived per-build and
   released only after license + (placeholder) TPM attestation. This is
   the strongest posture in the project, but the TPM attestation is
   currently a structural placeholder (see `_key_release.py`).

The byte-distribution uniformity (chi-square, ML) is a property of the
*ciphertext*, not of the protected *logic*. It defeats byte-frequency
fingerprinting between builds; it does **not** defeat an adversary who can
run the file and inspect the decrypted source in memory.
