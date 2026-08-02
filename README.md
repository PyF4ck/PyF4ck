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
#    encrypted on disk. (--embed-key ships the key in the file — INSECURE,
#    statically recoverable; requires --allow-insecure-embed-key to opt in.)

# 3. Verify the encrypted-output uniformity test (PRG + iO-property, ~30 min)
python bedrock_native/_io_distinguish_test.py
BR_ML_N=40 python bedrock_native/_io_adversarial_ml.py

# 4. Prefer a guided UI? `tui.py` is an interactive picker (Vietnamese) for
#    non-experts: pick a profile + anti-AI / anti-meta options, it builds and
#    runs the file for you. No flags to memorize.
python tui.py
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
  capsule key is **read from env at runtime by default** (secure); `--embed-key`
  ships the key in the file (INSECURE, statically recoverable — now requires
  `--allow-insecure-embed-key` to opt in).
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
| 7 | Hardening (env-key default, adv-requests) | ALL | `--env-key` (DEFAULT since G9), `--adv-requests` |
| G | Key release + TPM attestation | license-bound | `_key_release.py` (TPM is a placeholder) |
| H | Esoteric (11 passes) | ALL functions | `_identifier_poison.py` … `_exc_table_vm.c` |
| **H.A** | **Anti-AI deobfuscation: decoys + homoglyph twins + prompt-injection + EOS-tokens + zero-width/bidi + safety-trigger vocab + long-range weaving** | **ALL** | **`_anti_ai.py`** |
| **G** | **Deobf-hardening (G1-G9 + G1+): hex/base85 blob, anti-meta default, num_obf 4-form, capsule key delivery, DPF split, opaque structural mix, DPF PRG/domain, ML test features, env-key default** | **capsule + non-capsule** | **`_binary_capsule.py`, `_fss.py`, `_opaque_crypto.py`, `_pointfunc_obf.py`, `_io_adversarial_ml.py`** |
| **io hardening** | **T1 `--embed-key` double-opt-in + T2 before-load marshal re-verify + `compile` pin + T3 build-time-baked guard code-object digest (anti `CodeType.replace`)** | **io + extreme/paranoid loaders** | **`bedrock_obfuscator.py` (T1 gate L7071, T2 L1719+L3366, T3 verifier + L3569 build patch)** |
| **io** | **Encrypted-source capsule + value secret sharing + opaque predicates** | **ALL** | **`_fss.py` (value secret sharing, NOT BGI FSS), `_opaque_crypto.py`, `_pointfunc_obf.py`, `_lookup_obf.py`, `_entropy_pad.py`, `_binary_capsule.py`** |

## Phase G deobfuscation-hardening (G1-G9 + G1+)

A full hardening sweep against deobfuscation, driven by 3 independent
sub-agents that confirmed 12 findings (verified by 3 Explore agents).
**11 of 12 fixed; 1 deferred.** Default posture is now secure-by-default
(capsule key not in file, DPF k1 via env, env-key default for non-capsule
profiles) — outputs require env vars to run. This is intentional.

| Phase | Fix | Breaks backward-compat? |
|-------|-----|:---:|
| **G1** | Capsule blob as hex/base85 literal (kills the 0x5c byte spike that distinguished obf from urandom at 100%) + per-build bootstrap randomization + blob padding (closes length channel) | no |
| **G1+** | Bootstrap structural tells (`import zlib, hashlib`, `exec(zlib.decompressobj`) randomized: zlib aliased per-build, import/exec/XOR shapes vary across 4/3/2 forms — no single regex matches every io file | no |
| **G2** | `anti_meta` default ON for all profiles; sentinel prefixes (`_LCAN_`/`_MARK_`/`_SLOT_`) randomized | no |
| **G3** | `num_obf` rotates across 4 AST forms per byte — one fold rule no longer collapses every obfuscated literal | no |
| **G4** | `--capsule-key-file` (0600), `--no-capsule-sidecar`, `master_seed_hex` stripped from manifest (replaced by `master_seed_hash`) | no |
| **G5** | DPF key split DEFAULT: k0 in file, k1 via env `BR_DPF_K1` (`.dpfkey` sidecar) — 1-key adversary faces the GGM tree | **yes** |
| **G6** | Opaque predicates branch on `v & 1` between two different-shape tautologies (not foldable `v-v`/`f(x)==f(x)`) | no |
| **G7** | DPF PRG control bits from out-of-seed bytes (SHA-512, disjoint sL/sR/tL/tR); per-build domain salt; domain widened to 64/128 bits | no |
| **G8** | ML test keeps `len(data)` raw, adds entropy/positional/bootstrap-regex features, 3rd experiment (build-diversity), feature-importance report | no |
| **G9** | `--env-key` DEFAULT for fast/balanced/paranoid/extreme — payload key is HW-fingerprint-derived, not reversible cand/mark | **yes** |

**Recovery-attack posture (re-verified after Phase G):** cand/mark static
key-recovery FAILS (G9); capsule key from file prefix FAILS (G1+G4); DPF
reconstruct FAILS (G5); bootstrap signature regex GONE (G1+).

**Remaining deobf gaps (honest):** M4 (Vietnamese-identifier + sentinel
debrand, deferred — `Compile.ll` encoding constraint); CFF dispatch-table
structure not yet randomized (L3 — opaque predicates feeding it ARE hardened).

---

## Phase H.A: Anti-AI deobfuscation (against LLM / ML / AI-symbolic analysis)

A new defense pass against AI-assisted deobfuscation — the AI equivalent of
the existing anti-debug (against humans) and anti-RE (against static tools).
Makes obfuscated output resistant to **three classes of AI analysis**:

| Threat class | Adversary | Defense |
|--------------|-----------|---------|
| **LLM-semantic** | GPT/Claude/Copilot fed the `.py` as text, asked to explain / recover logic | Prompt-injection comments, EOS-token blocks, vulnerability-decoys, safety-trigger vocabulary (→ refusal/truncation) |
| **LLM-attention + tokenization** | Long-context burial, token-flooding | 200 decoy functions (lost-in-middle), homoglyph identifier twins, zero-width/bidi token fragmentation |
| **AI-symbolic + context exhaustion** | AI-guided symbolic execution, context-window overflow | Long-range dependency weaving, token-budget padding, false-comment counter-narrative |

**Grounded in published research:**
- **Acoda** (arXiv:2606.11755, ICSE 2026): adversarial code obfuscation vs
  LLM-based analysis — 70% attack-success-rate on GPT-4o/DeepSeek/Qwen/
  Llama/Gemma with cross-model transferability. The most-selected Acoda
  method is comment-layer prompt injection (triggers refusal *before*
  analysis completes). 7 of 8 Acoda methods are AST-implementable.
- **Lost in the Middle** (arXiv:2307.03172): U-shaped attention — relevant
  info at ~50% of a long context is least attended, even for long-context
  models. Decoy padding buries genuine logic in the low-recall middle.
- **Trojan Source** (CVE-2021-42574): homoglyph + bidi control chars. Python
  accepts confusable Unicode identifiers (PEP 3131); zero-width chars are
  fine in strings/comments (PEP 672 rejects them only in identifiers).
- **Bad Characters** (arXiv:2106.09898): invisible-char injection
  "functionally breaks" NLP models with a few injections.
- **"Do Machines Struggle Where Humans Do?"** (arXiv:2606.31725): adversarial
  identifier renaming disrupts LLM comprehension via "semantic displacement".

**Two-stage pass:**

| Stage | Function | Runs | What it injects |
|-------|----------|------|------------------|
| **AST** | `apply_anti_ai(tree, ctx)` | 'after' obf_vars | 200 decoy `def`s (B1), homoglyph twins (B3), long-range weave network (C2) |
| **Source** | `apply_anti_ai_source(code, ctx)` | post-compile (after `Compile.Obfuscate`, before integrity re-patch) | prompt-injection comments (A1), EOS-token block (A2), vuln decoys (A3), zero-width/bidi padding (B4), safety-trigger vocab (C1), token-budget header (C3), false-comment counter-narrative (C4) |

The source pass runs **after** `Compile.Obfuscate` (whose `compile()` would
otherwise strip comments) — mirroring the entropy-pad / binary-capsule
post-compile hook position. All payloads are comments or constant-false-
guarded dead literals → never execute → behavior-preserving.

**CLI:** `--h-anti-ai` (auto-on for `extreme`/`io`), `--anti-ai-count N`
(default 200 balanced / 80 extreme/io — tuned to avoid build timeout on the
heavy Phase G+H+iO pipeline; higher = stronger burial but slower build).

**Honest caveat:** This pass causes aligned LLMs to **REFUSE or TRUNCATE**
analysis (that is its goal). Consequence: do NOT run your own LLM-assisted
maintenance tooling on output built with `--h-anti-ai` — it will also
refuse/mislead. Build without the flag when you need AI-assisted review of
the output. Verified by heuristic checks only (no ML/LLM test harness — per
scope decision; the existing `_io_adversarial_ml.py` measures byte-uniformity,
not AI-deobf resistance).

## io capsule runtime-attack hardening (T1/T2/T3)

Three defenses against the runtime deobfuscation chain demonstrated in
`WALKTHROUGH.md` (an io-obfuscated 24 MB file was statically stripped +
dynamically traced + guard no-op'd — all three attacks confirmed working
against an actual io output):

| Tier | Attack closed | What changed |
|------|--------------|--------------|
| **T1** | static capsule strip via `--embed-key` (key = `blob[:32]` in file) | A bare `--embed-key` is now rejected; `--allow-insecure-embed-key` required to opt in. TUI no longer adds `--embed-key` for io — uses the secure default (key via `BR_CAPSULE_KEY` env + sidecar). Capsule crypto (SHA-256 CTR + zlib) is sound; only the insecure key-delivery mode was the gap. |
| **T2** | dynamic trace (hook `marshal.loads` after guard snapshot, before payload unmarshal) | Inline re-verify of `marshal.loads` attributes at `RemoveLayers` L1719 (the true before-load chokepoint, runs in the OUTER loader before any inner `_co_pl` guard fires) — hard-exit via `os._exit(1)` if spoofed. Also pins `compile`. |
| **T3** | `CodeType.replace(co_consts=...)` to no-op a guard | Build-time-baked SHA-256 digest of 5 critical guard functions' bytecode, patched into `_co_pl.co_consts` post-compile. Runtime verifier `__br_verify_guard_integrity__` re-hashes live `__code__` → mismatch → `__bedrock_self_destruct__` + `os._exit(1)`. Digest is a module-level string (not in any guard's `co_consts`), so no masking needed. Under capsule the digest is encrypted until runtime. |

**Honest limitation:** T1 is the real fix for the file-only attacker
(walkthrough vector). T2/T3 raise the bar for an operator-attacker who runs
the file (has the key) — encryption can't stop someone who has the key from
decrypting, but T2/T3 increase the cost of dynamic tracing and guard
neutralization.

---

## Encrypted-output uniformity (formerly "iO Highlights")

The `io` profile encrypts the obfuscated source so the output file's byte
distribution approaches uniform. This is a **PRG-uniformity** property, not
the cryptographic iO property (see the honesty note above). Phase G
deobf-hardening (G1-G9 + G1+) closes the bootstrap signature that used to
leak here — see the Phase G section below.

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
is the correct behaviour: at small N the strict Wilson gate has low
statistical power. The bootstrap itself is NO LONGER a constant
structural signature: Phase G1+ aliases `zlib` to a per-build random token
and randomizes the import-line / decompress-call / XOR-expression shapes
across 4 / 3 / 2 forms per build, so no single regex matches every io
file. (Before G1+ the bootstrap's `import zlib, hashlib` and
`exec(zlib.decompressobj().decompress(` were 100%-reliable tells — found
via a 6-layer deobf analysis of the released challenge. Both are GONE.)

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

# Anti-AI smoke test (round-trip + all 10 heuristics, <1s)
python bedrock_native/_anti_ai.py

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
  _anti_ai.py                  H.A: Anti-AI deobfuscation (decoys + homoglyph
                               twins + prompt-injection + EOS-tokens + zero-width/
                               bidi + safety-trigger vocab + long-range weaving).
                               Two stages: AST pass (apply_anti_ai) + post-compile
                               source pass (apply_anti_ai_source). Grounded in
                               Acoda (arXiv:2606.11755, 70% ASR cross-model).
  _bedrock_vm.c                BedrockVM C interpreter
  _bedrock_vm_ref.py           BedrockVM reference interpreter (Python)
  ESOTERIC_SPEC.md             Phase H spec (11 passes)
  IO_SPEC.md                   Capsule-phase spec (7 phases) — includes the
                               "iO" terminology correction + limitations.
  VM_SPEC.md                   BedrockVM spec
  KEY_RELEASE_SPEC.md          Phase G key release spec

tui.py                         Interactive TUI (Vietnamese) for non-experts.
                               Pick a profile + anti-AI / anti-meta options via
                               a guided menu; it builds and runs the file. Uses
                               rich + prompt_toolkit (no flags to memorize).

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
9b7766f  fix(G1+): randomize bootstrap structural tells (import line + exec call + xor shape)
9dd25a3  chore: gitignore Phase G build artifacts (vm_ref fallbacks, key sidecars, scratch dirs)
8e8aadf  fix(G9): default --env-key for non-capsule profiles + warn on --no-env-key
5f608b1  fix(G8): ML test add length/entropy/positional features + 3rd build-diversity experiment
045fd0a  fix(G7): DPF PRG control-bits fix + per-build domain salt + widen domain 64-128
238a231  fix(G6): opaque predicate structural mix - drop v-v / f(x)==f(x) tautologies
6b18371  fix(G5): DPF key split default - k0 in file, k1 via env BR_DPF_K1
7fe1ebc  fix(G4): capsule key delivery + strip master_seed_hex manifest
542c0d2  fix(G1-G3): capsule hardening + anti_meta default + num_obf diversify
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

For a stronger posture the capsule key must NOT ship in the file. This is
now the DEFAULT, not opt-in:

1. **Env-key (DEFAULT since Phase G9)**: the build emits a sidecar
   `<output>.key` and the bootstrap reads it from `$BR_CAPSULE_KEY` at
   runtime. The source is genuinely encrypted at rest; the key lives in
   the runtime environment, not the artifact. For non-capsule profiles
   (fast/balanced/paranoid/extreme) the payload key is likewise derived
   from the building machine's hardware fingerprint (G9) instead of the
   reversible cand/mark digest. This raises the bar from "grep the file"
   to "read the process environment / dump the decrypted in-process
   source" — still defeatable by a debugger, but no longer trivially
   recoverable from the file alone. Pass `--no-env-key` to opt back into
   the reversible cand/mark path (a warning is printed — NOT recommended).
2. **Release-server (Phase G, opt-in via `--release-server`)**: the master
   seed lives on a license server; the VM key is derived per-build and
   released only after license + (placeholder) TPM attestation. This is
   the strongest posture in the project, but the TPM attestation is
   currently a structural placeholder (see `_key_release.py`).

The byte-distribution uniformity (chi-square, ML) is a property of the
*ciphertext*, not of the protected *logic*. It defeats byte-frequency
fingerprinting between builds; it does **not** defeat an adversary who can
run the file and inspect the decrypted source in memory.
