# Phase io — Encrypted-Source Capsule Specification

**Status:** The 7 phases are implemented and smoke-tested. The
`_io_distinguish_test.py` ciphertext-uniformity harness passes its
chi-square gate. The `_io_adversarial_ml.py` harness was **rewritten in
Phase D** to fix methodological flaws in the original (N=10 vacuous,
inconsistent gate, unimplemented bigram features, unstratified split); it
now runs BOTH a PRG-uniformity experiment and an iO-property experiment
(`Obf(P0)` vs `Obf(P1)` for two functionally-equivalent programs), with
Wilson 95% CIs. The strict gate may now FAIL at small N — which is
correct behaviour, because the bootstrap's cleartext signature is greppable.

> **CORRECTION (Phases A/D/F remediation).** Earlier versions of this spec
> marketed the work as "Practical Indistinguishability Obfuscation (iO)".
> That was **incorrect**. iO in cryptography means obfuscations of two
> *different but functionally-equivalent* programs are indistinguishable.
> The capsule construction only ensures the obfuscated output *file's byte
> distribution* is uniform — a property of any encryption/PRG output, which
> says nothing about distinguishing obfuscations of equivalent programs.
> The metric is now labelled "encrypted-output uniformity". The rewrite of
> `_io_adversarial_ml.py` adds the actual iO-property test (Experiment 5b)
> that the original never had. See §9 "Limitations" for the full
> correction and what the tests do and do not measure.

**Date:** 2026-07-27

---

## 1. Overview

The `io` profile encrypts the obfuscated source so the output file's byte
distribution approaches uniform. This is a **PRG-uniformity / ciphertext-
uniformity** property, not the cryptographic iO property (see the
correction above). Two builds of the same program produce files whose byte
distributions differ only in the encrypted blob (independently uniform) and
the tiny bootstrap (slightly different per-build keys/names).

### Threat model

> **CORRECTION (Phase F remediation).** The "nation-state adversary"
> claim below applied to the legacy `--embed-key` mode, where the capsule
> key ships in the file in the clear — that mode is **trivially broken** by
> anyone (run the file's own ~10-line bootstrap to recover the source).
> It does not target nation-state adversaries.

The default since the Phase A remediation is **env-key mode**: the key is
emitted to a sidecar `<output>.key` and read from `$BR_CAPSULE_KEY` at
runtime, so the source is genuinely encrypted at rest. This raises the bar
from "grep the file" to "read the process environment / dump the decrypted
in-process source with a debugger" — stronger, but still defeatable by a
runtime adversary. The strongest posture is the opt-in release-server
mode (Phase G), where the master seed lives on a license server and the
VM key is derived per-build — though the TPM attestation there is currently
a structural placeholder (see `_key_release.py`).

The byte-distribution uniformity (chi-square, ML) is a property of the
*ciphertext*, not of the protected *logic*. It defeats byte-frequency
fingerprinting between builds; it does **not** defeat an adversary who can
run the file and inspect the decrypted source in memory.

### The "uniformity" property (formerly "the iO property")

Two builds of the same program produce files whose byte distributions differ
only in the encrypted blob (independently uniform) and the tiny bootstrap
(slightly different per-build keys/names). The structural signature is
diluted to <0.1% of the file, making the pairwise chi-square approach the
expected value for two independent random samples from the same distribution.

### Foundation

The `io` profile builds on:
- **Phase H** (esoteric + anti-pattern obfuscation, 11 passes): provides
  the `apply_X(tree, ctx)` pass framework, BuildRNG sub-streams, and the
  reverse-stack pass ordering convention.
- **Phases 1-5, 7, G**: capsule runtime, HMAC chain, native VM, key release.

The `_apply_extreme_overrides` function (dormant before io-1) is wired into
`run_build` to activate the full esoteric stack for both `extreme` and `io`
profiles.

---

## 2. The 7 Phases

### iO-1 — Foundation (commit `0ec3e14`)

**Goal:** Wire the dormant Phase H passes into the build pipeline, add the
`io` profile, and create the distinguishing-attack test scaffold.

**Implementation:**
- Wired `_apply_extreme_overrides(args)` into `run_build` after profile
  application (line ~5864). This function (defined at line ~5597) auto-enables
  the esoteric passes (`cff`, `bc_mutate`, `num_obf`, `import_obf`,
  `str_frag2`, `vm_extended`, `dec_trap`, `var_split`, `spoof_meta`,
  `anti_timing`, `homoglyph`, `runtime_dec`, `chain`, `debug_poison`,
  `metamorphic`, `anti_meta`, `native_vm`, `junk`, `bool_obf`, `lambda_enc`,
  `str_cipher`) for `extreme` and `io` profiles.
- Fixed 3 composition bugs in `_apply_extreme_overrides`:
  - `h_id_poison` / `homoglyph` / `lambda_enc` were gated OFF when
    `runtime_dec` is ON (they break VM-compiled recursion and capsule
    marshal+exec).
  - `anti_vm` / `anti_debugger_v2` now honour explicit `--anti-vm off` /
    `--no-anti-vm` CLI disables (previously clobbered by the override).
- Added `--profile io` to argparse choices and the PROFILES dict (line ~7165).
- Created `_io_distinguish_test.py`: builds N copies with fresh per-build
  RNG, verifies functional equivalence, measures pairwise chi-square and
  Shannon entropy.

**Files:**
- `bedrock_obfuscator.py` — `_apply_extreme_overrides` wired in, `io` profile
  added, 3 composition bugs fixed.
- `bedrock_native/_io_distinguish_test.py` — distinguishing test scaffold.

**Smoke test:** 8/8 PASS (N=2 builds, all functional, all distinct, entropy
measured, chi-square measured).

---

### iO-2 — FSS Extension (commit `07839b2`)

**Goal:** Extend Function Secret Sharing from 2-share additive int-only to a
BGI-style framework supporting multiple modes and collusion resistance.

**Construction:**

FSS splits a function `f(x)` into `n` shares `f_1(x, r), ..., f_n(x, r)`
such that:
- Combining all `n` shares recovers `f(x)`: `f_1 + ... + f_n = f(x)`.
- Any `n-1` shares reveal NOTHING about `f` (collusion-resistant up to `n-1`).

The BGI (Boyle-Gilboa-Ishai) construction uses a PRG-based evaluation tree.
For the obfuscator, we implement a simplified version:

| Mode | Return type | Shares | Combining |
|------|------------|--------|-----------|
| `additive` | int | 2 | `f_1(x) + f_2(x) = f(x)` |
| `additive_n` | int | n | `sum(f_i(x)) = f(x)` |
| `bool` | bool | 2 | `f_1(x) XOR f_2(x) = f(x)` |
| `serialized` | any (repr-safe) | 2 | `eval(f_1(x))` with `f_2` as key |
| `auto` | auto-detect | 2-3 | mode chosen by return type |

The `--fss-all-eligible` flag lifts the 3-5 function cap, sharing ALL
eligible functions (used by `io` profile).

**Files:**
- `bedrock_native/_fss.py` — extended from 2-share additive to BGI framework.
- `bedrock_obfuscator.py` — CLI flags `--fss-mode`, `--fss-shares`,
  `--fss-all-eligible`.

**Smoke test:** 9/9 PASS.

---

### iO-3 — Cryptographic Opaque Predicates (commit `abb76db`)

**Goal:** Replace algebraic opaque predicates (`x*(x-1)%2==0`, which Z3 folds
in seconds) with cryptographic constructions that symbolic execution engines
cannot solve.

**Constructions:**

| Type | Construction | Z3 solvable? |
|------|-------------|--------------|
| **DL** (discrete log) | `pow(g, x, p) == y` | No (DL hard) |
| **LWE** (lattice) | `A·s + e ≡ b (mod q)` | No (lattice hard) |
| **RSA** | `pow(m, e, n) == c` | No (factoring hard) |
| **Hash** | `sha256(x) == h` | No (preimage hard) |
| **Hybrid** | DL + LWE + hash combined | No |

The `--opaque-grade {algebra, crypto, hybrid}` flag controls which grade
is used. The `io` profile auto-sets `opaque_grade=crypto`.

Hash-chain predicates (n SHA-256 calls per evaluation) are excluded from
`gen_opaque_true` random selection — too slow at runtime.

**Files:**
- `bedrock_native/_opaque_crypto.py` — DL/LWE/RSA/hash/hybrid predicates.
- `bedrock_obfuscator.py` — CLI flag `--opaque-grade`, wired as Phase H pass
  (runs last after bloom).

**Smoke test:** 10/10 PASS.

---

### iO-4 — Point-Function Obfuscation (commit `64ebd0e`)

**Goal:** Obfuscate point functions `f_alpha(x) = 1 if x == alpha else 0`
without shipping `alpha`.

**Construction (Canetti):**

A point function `f_alpha` is obfuscated by:
1. Compute `h = SHA256(alpha)`.
2. The evaluator computes `SHA256(x)` and checks if it equals `h`.
3. `alpha` is NEVER shipped — only its hash.

The `@bedrock_pointfunc(alpha=...)` decorator marks a function for
obfuscation. The pass:
1. Detects the decorator (runs BEFORE `obf_vars` so the original name is
   visible — uses the `_insert_before_obf_vars` helper).
2. Evaluates the function at build time to compute `alpha`.
3. Replaces the body with a hash-based evaluator.

**Files:**
- `bedrock_native/_pointfunc_obf.py` — `@bedrock_pointfunc` decorator
  detection, `apply_pointfunc_obf` pass, `build_point_func_ast`.
- `bedrock_obfuscator.py` — CLI flag `--h-pointfunc`, `io` auto-on.

**Smoke test:** 6/6 PASS (test_pf.py → True/False/42, _test_obf.py → 221).

---

### iO-5 — Encrypted Lookup-Table Obfuscation (commit `7a4ccbd`)

**Goal:** Generalize iO-4 (single-point) to multi-point: obfuscate functions
defined by a lookup table without shipping the table.

**Construction:**

A function `f(x)` with domain `{0, 1, ..., N-1}` is obfuscated by:
1. At build time, evaluate `f(0), f(1), ..., f(N-1)` and store all outputs.
2. Encrypt each output with a per-entry key: `K_i = SHA256(master || b'lookup_entry' || i)`.
3. Ship the encrypted entries + a hash-based stream cipher for decryption.
4. At runtime, the evaluator decrypts only the entry for the requested `x`.

The `@bedrock_lookup(domain=N)` decorator marks a function for obfuscation.
The pass auto-computes all N outputs at build time.

**Files:**
- `bedrock_native/_lookup_obf.py` — `@bedrock_lookup` decorator detection,
  `apply_lookup_obf` pass, `build_lookup_ast`.
- `bedrock_obfuscator.py` — CLI flag `--h-lookup`, `io` auto-on.

**Smoke test:** 7/7 PASS (sbox 16-entry + perm 256-entry → all correct,
_test_obf.py → 221).

---

### iO-6 — Entropy Padding (commit `ad204e7`)

**Goal:** Raise file entropy from ~6.3 bits/byte (ASCII ceiling) to >7.5
bits/byte by injecting raw binary bytes.

**Construction:**

The fundamental entropy ceiling of UTF-8 Python source is ~6.6 bits/byte
(printable ASCII alphabet). iO-6 breaks through this by:

1. Adding `# -*- coding: latin-1 -*-` as the first line.
2. Encoding the entire source as latin-1 (1 byte = 1 code point 0-255).
   Non-latin-1 characters (code points > 255) are `backslashreplace`'d.
3. Appending a large raw-binary string literal: `_br_pad = '<2-8 MB random bytes>'`.
   The binary bytes are generated per-build from BuildRNG. Problematic bytes
   (backslash, single-quote, CR, LF, null) are escaped; the rest (251 byte
   values) appear RAW in the file.

**Integrity patch:** The runtime integrity check (`__h_check_self_integrity`)
was patched to decode as `latin-1` instead of `utf-8` (which drops latin-1
bytes). This is controlled by the `h_entropy_pad` global, which is set AFTER
profile overrides are applied.

**Force ASCII names:** When entropy pad is on, the `_FORCE_ASCII_NAMES` flag
replaces CJK/Arabic name pools with ASCII-only characters (letters + underscore,
no digits — leading digits cause SyntaxError in identifiers).

**Files:**
- `bedrock_native/_entropy_pad.py` — `apply_entropy_pad`, `refresh_integrity_bytes`.
- `bedrock_obfuscator.py` — CLI flags `--h-entropy-pad`, `--entropy-pad-size`,
  `io` auto-on (default 8 MB pad).

**Smoke test:** 7/7 PASS.

**Results:** Entropy 7.88 bits/byte, pairwise chi-square ~538k (improved from
~749k but still far from target <320 — the 20% structural bytes create a
detectable signature). This motivated iO-7.

---

### iO-7 — Binary Capsule (commit `1808581`)

**Goal:** Achieve statistical indistinguishability from random data by
encrypting the ENTIRE obfuscated source.

**Construction:**

1. **Compress** the obfuscated source (zlib level 9).
2. **Encrypt** with a per-build 32-byte key (SHA-256 CTR-mode XOR keystream).
3. **Prepend** the key to the encrypted blob (first 32 bytes = key, rest =
   encrypted data). This eliminates a separate key variable in the bootstrap,
   minimizing structural bytes.
4. **Embed** the blob as a latin-1 triple-quoted string literal.
5. **Ship** a tiny bootstrap (~10 lines) that:
   - Reads the blob from a string variable.
   - Extracts the key (first 32 bytes).
   - Derives a SHA-256 CTR keystream from the key.
   - XORs to decrypt.
   - Decompresses with zlib.
   - Execs the result with `__BR_INTEGRITY_OFF__ = True` (gates off the
     file-reading integrity checks that would fail on the capsule file).

**Why this achieves iO:**

The resulting file is ~99.9% encrypted data (uniform byte distribution) and
~0.1% bootstrap (structural bytes). The pairwise chi-square between two
builds approaches the expected value for two independent uniform random
samples — ~510, not the naive 255 (both f1 and f2 contribute variance).

**Composition:**
- FSS (iO-2), crypto opaque (iO-3), pointfunc (iO-4), lookup (iO-5): all
  run BEFORE the capsule. The capsule encrypts their output as-is.
- Entropy pad (iO-6): REDUNDANT with capsule — the encrypted blob IS
  high-entropy. Capsule disables entropy pad when both are on.
- Integrity: disabled when capsule is on (encryption provides implicit
  integrity — tampering causes decryption/decompression failure).
- `runtime_dec` + `chain`: disabled when capsule is on (the capsule already
  encrypts everything; the per-function capsule chain is redundant AND caused
  an intermittent hang bug — re-entry into `_br_flow_shard` during
  `ssl.wrap_socket` when the inner code imports `requests`/`ssl`).

**Key-in-blob optimization:**

The key is embedded as the first 32 bytes of the blob (in the clear) rather
than as a separate hex-encoded variable. This:
- Eliminates 64 hex characters from the bootstrap.
- Reduces the bootstrap to ~10 lines of code.
- Minimizes the structural byte signature.

The key is NOT a secret — an attacker CAN decrypt. The goal is uniform byte
distribution (iO indistinguishability), not confidentiality.

**Escape rules:**

In a non-raw triple-quoted `b"""..."""` string with latin-1 encoding:
- Backslash (0x5C) → `\\` (must be first to avoid double-escaping).
- Null (0x00) → `\x00` (C-level parser safety).
- CR (0x0D) → `\r` (tokenizer normalizes raw 0x0D → 0x0A).
- Three consecutive double-quotes (0x22 0x22 0x22) → escape the 3rd.

All other 251 byte values appear RAW. The escaping creates a small per-build
signature, but the SAME byte values are escaped the SAME way across builds,
so it doesn't contribute to the pairwise chi-square (which measures the
DIFFERENCE between builds, not deviation from uniform).

**Files:**
- `bedrock_native/_binary_capsule.py` — `apply_binary_capsule`,
  `_encrypt` (SHA-256 CTR XOR), `_build_bootstrap`, `_escape_for_triple_quoted`.
- `bedrock_obfuscator.py` — CLI flag `--h-binary-capsule`, `io` auto-on,
  post-compile hook (after `_refresh_native_integrity`), `__BR_INTEGRITY_OFF__`
  gate in integrity template.

**Smoke test:** 7/7 PASS.

**Results:** See §5 below.

---

## 3. Composition Rules

### Pass ordering

Phase iO passes follow the reverse-stack convention (declared LATER runs
EARLIER in the pipeline). The binary capsule runs LAST (post-compile, after
all AST passes and `_refresh_native_integrity`).

```
PRE-COMPILE (AST passes):
  obf_vars → obf_builtins → obf_strings → num_obf → cff →
  dec_trap → var_split → Phase H (H.1-H.11) → iO-2 (FSS) →
  iO-3 (crypto opaque) → iO-4 (pointfunc) → iO-5 (lookup) →
  runtime_dec → ...

POST-COMPILE:
  _refresh_native_integrity →
  iO-6 (entropy pad, if enabled) →
  iO-7 (binary capsule, if enabled) →
  file write
```

### Disable rules

| When ON | Disables | Reason |
|---------|----------|--------|
| `h_binary_capsule` | `h_entropy_pad` | Encrypted blob IS high-entropy |
| `h_binary_capsule` | `runtime_dec` | Capsule already encrypts; chain causes hang |
| `h_binary_capsule` | `chain` | Companion to runtime_dec |
| `h_binary_capsule` | `integrity` | Encryption provides implicit integrity |
| `h_entropy_pad` | `integrity` (runtime) | latin-1 codec patched instead |
| `runtime_dec` | `h_id_poison`, `homoglyph`, `lambda_enc` | Break VM-compiled recursion + capsule marshal |
| `native_vm` | `h_id_poison`, `homoglyph`, `lambda_enc` | Same as runtime_dec |

### Force ASCII names

When `h_entropy_pad` OR `h_binary_capsule` is ON, `_FORCE_ASCII_NAMES = True`
replaces CJK/Arabic name pools with ASCII-only characters. This ensures the
output can be encoded as latin-1 (raw binary in string literals).

---

## 4. Test Methodology

### 4.1 Distinguishing test (`_io_distinguish_test.py`)

**Protocol:**
1. Build N=20 obfuscated files with `--profile io` (fresh per-build RNG).
2. Verify all 20 are functionally equivalent (run → `final_result: 221`).
3. Verify all 20 have distinct SHA-256 hashes (per-build diversity).
4. Measure Shannon entropy of each file (gate: ≥ 7.5 bits/byte).
5. Compute pairwise chi-square for all 190 pairs (gate: max < 700).

**Chi-square calibration:**

For two independent random samples of size n from the same distribution,
the expected pairwise chi-square is ~2*(256-1) = 510 (NOT 255; both f1 and
f2 contribute variance), with SD ~35. For 190 pairs (N=20), the expected
MAX is ~651 ± 25 (verified empirically with 10 random trials of 20 files
× 1.26 MB each).

| Threshold | Random baseline | Our iO-7 result |
|-----------|----------------|-----------------|
| Max pairwise < 700 | mean 651, max 691 | max 670 ✅ |
| Mean pairwise ≈ 510 | mean 526 ± 10 | mean 501 ✅ |

**Retry logic:**

Before the `runtime_dec` hang fix (commit `5a34b43`), ~40% of builds hung in
`_br_decrypt` / `_br_flow_shard` (re-entry during `ssl.wrap_socket`). The
test retries each build up to 3 times. After the fix (binary capsule disables
`runtime_dec` + `chain`), 10/10 builds succeed without retries.

### 4.2 Adversarial ML classifier (`_io_adversarial_ml.py`)

**Protocol:**
1. Build N=10 obfuscated files with `--profile io`.
2. Generate N=10 random files of matching sizes (`os.urandom`).
3. Extract 256-dim byte-histogram features from all 20 files.
4. Split into train/test (50/50, stratified).
5. Train logistic regression (256 features, L2=0.01, 1000 iters) on the
   train set.
6. Evaluate accuracy on the test set.
7. Gate: accuracy < 70% (chance = 50%, generous margin for small N).

**Result:** Accuracy 40% — worse than chance. The classifier CANNOT
distinguish obfuscated files from random files.

The top discriminative features (by logistic regression weight):
- Byte 0x5C (backslash): slightly more in obfuscated (bootstrap escaping)
- Byte 0x30 ('0'): slightly more in obfuscated (hex key, bootstrap code)
- Byte 0x0D (CR): slightly more in random (obfuscated escapes it)
- Byte 0x00 (null): slightly more in random (obfuscated escapes it)

These differences are too small for the classifier to exploit at N=10.

---

## 5. Results

### Full results table

| Metric | Pre-iO | iO-6 (entropy pad) | iO-7 (binary capsule) | Random baseline |
|--------|--------|---------------------|----------------------|-----------------|
| Shannon entropy | 6.3 bits/byte | 7.88 bits/byte | **7.96 bits/byte** | 8.0 (max) |
| Pairwise chi-square (mean) | ~749,000 | ~538,000 | **501** | ~510 ± 35 |
| Pairwise chi-square (max, 190 pairs) | — | — | **670** | 651 ± 25 (max 691) |
| ML classifier accuracy | — | — | **40%** | 50% (chance) |
| Build success rate | — | 60% | **100%** | — |
| Output file size | ~2 MB | ~10 MB | **~1.3 MB** | — |
| Build time | ~15s | ~30s | **~25s** | — |
| Runtime overhead | ~3× | ~5× | **~5-10×** | — |

### iO-7 distinguishing test (N=20, 190 pairs)

```
=== Phase iO-7 distinguishing-attack test ===
  builds: 20, input: _test_obf.py

--- Gate 1: baseline reference output ---
  PASS  baseline reference produces final_result: 221

--- Gate 2: 20 builds, all functional (retry up to 3x) ---
  PASS  build 0 functional (final_result: 221)
  ...
  PASS  build 19 functional (final_result: 221)
  PASS  all 20 builds functionally equivalent to baseline

--- Gate 3: per-build byte diversity ---
  PASS  all 20 build hashes distinct
  PASS  size spread 432491B (34.3% of mean)

--- Gate 4: byte-distribution (entropy gate, chi measured) ---
  Shannon entropy (bits/byte): [7.963, 7.963, 7.964, ...]
  PASS  entropy >= 7.5: min=7.963 bits/byte

--- Gate 5: pairwise build-vs-build chi-square (iO-7 gate) ---
  max pairwise: 670, mean: 501 (190 pairs)
  PASS  pairwise chi-square < 700: max=670, mean=501
         (random baseline: mean 651, max 691)

============================================================
Phase iO-7 distinguish test: 27/27 passed
ALL PASS
```

### iO-7 adversarial ML test (N=10+10)

```
=== Phase iO-7 adversarial ML classifier test ===
--- Step 6: Evaluate classifier accuracy ---
  test accuracy: 40.0% (4/10)
  chance baseline: 50.0%

--- Step 7: Adversarial ML gate ---
  PASS  ML accuracy 40.0% < 70% (chance: 50%)

  Top-10 discriminative features (byte values):
    byte 0x5c ( 92): weight=-0.171633 (obfuscated)
    byte 0x30 ( 48): weight=-0.113866 (obfuscated)
    byte 0x0d ( 13): weight=+0.059013 (random)
    byte 0x00 (  0): weight=+0.058930 (random)

============================================================
Phase iO-7 adversarial ML: 5/5 passed
ALL PASS
```

---

## 6. CLI Reference

### io profile

```bash
python bedrock_obfuscator.py -f input.py -o obf.py --profile io \
    --anti-vm off --anti-debug off --no-debug-poison --no-metamorphic \
    --no-native-vm --no-cache --overwrite --adv-requests off \
    --no-anti-timing --quiet
```

Sandbox-safe flags (`--anti-vm off`, `--anti-debug off`, etc.) are required
for CI/sandbox environments. In production, remove these to enable the full
anti-VM/anti-debug stack.

### iO-specific CLI flags

| Flag | Default | io profile | Description |
|------|---------|------------|-------------|
| `--h-binary-capsule` / `--no-h-binary-capsule` | off | **on** | Binary capsule (iO-7): encrypts full source |
| `--h-entropy-pad` / `--no-h-entropy-pad` | off | on* | Entropy padding (iO-6); *disabled by capsule |
| `--entropy-pad-size N` | 0 (8 MB) | 8 MB | Pad size in bytes |
| `--h-pointfunc` / `--no-h-pointfunc` | off | **on** | Point-function obfuscation (iO-4) |
| `--h-lookup` / `--no-h-lookup` | off | **on** | Lookup-table obfuscation (iO-5) |
| `--opaque-grade {algebra,crypto,hybrid}` | algebra | **crypto** | Opaque predicate grade (iO-3) |
| `--fss-mode {auto,additive,additive_n,bool,serialized}` | auto | auto | FSS mode (iO-2) |
| `--fss-shares N` | 2 | 2 | FSS share count |
| `--fss-all-eligible` / `--no-fss-all-eligible` | off | **on** | Share all eligible functions |

---

## 7. Files

### New (Phase iO)

| File | Phase | Description |
|------|-------|-------------|
| `bedrock_native/_fss.py` | iO-2 | FSS (BGI bool/serialized/n-share) |
| `bedrock_native/_opaque_crypto.py` | iO-3 | Crypto opaque predicates (DL/LWE/RSA/hash) |
| `bedrock_native/_pointfunc_obf.py` | iO-4 | Point-function obfuscation (Canetti) |
| `bedrock_native/_lookup_obf.py` | iO-5 | Encrypted lookup-table |
| `bedrock_native/_entropy_pad.py` | iO-6 | Entropy padding (latin-1 binary) |
| `bedrock_native/_binary_capsule.py` | iO-7 | Binary capsule (encrypted full-source) |
| `bedrock_native/_io_distinguish_test.py` | iO-1/7 | Distinguishing test (N=20, chi-square) |
| `bedrock_native/_io_adversarial_ml.py` | iO-7 | Adversarial ML classifier test |
| `bedrock_native/IO_SPEC.md` | all | This file |

### Modified

| File | Changes |
|------|---------|
| `bedrock_obfuscator.py` | `io` profile, `_apply_extreme_overrides` wired, 7 iO CLI flags, BuildContext fields, post-compile hooks, integrity template patch, `__BR_INTEGRITY_OFF__` gate, `runtime_dec`/`chain` disable when capsule on |
| `bedrock_native/_io_distinguish_test.py` | N=20, retry logic, calibrated chi gate (700), entropy gate (7.5) |
| `app.py` | io profile sandbox-safe flags, latin-1 preview, capsule description |
| `PRODUCTION_READINESS.md` | iO row in production table, io profile usage section |
| `bedrock_spec.html` | io column in profiles table, io section, sidebar nav |
| `bedrock_native/ESOTERIC_SPEC.md` | iO link in §1 overview |

---

## 8. Known Limitations + Future Work

### Limitations

1. **Key in clear (CORRECTED in Phase A)**: The legacy `--embed-key` mode
   embeds the 32-byte encryption key as the first 32 bytes of the blob -
   an attacker CAN decrypt by running the ~10-line bootstrap. The **default
   since Phase A** reads the key from `$BR_CAPSULE_KEY` at runtime and emits
   it to a sidecar `<output>.key` during build, so the key is NOT in the
   file. The legacy mode is retained only for backward compatibility and is
   gated behind the explicit `--embed-key` flag (with a build-time warning).

2. **Bootstrap structural bytes**: The ~10-line bootstrap has structural
   bytes (Python keywords, import statements) that create a small signature.
   This is <0.1% of the file and doesn't affect the chi-square gate, but a
   dedicated adversary can fingerprint the bootstrap pattern with a regex
   (`import zlib, hashlib` + `exec(zlib.decompress`) at 100% accuracy. The
   rewritten `_io_adversarial_ml.py` (Phase D) uses byte-pair features that
   CAN pick this up; the strict gate now sometimes fails at small N as a
   result - which is correct.

3. **Build-time RNG (CORRECTED in Phase C.2)**: The per-build RNG seed
   determines the capsule key, pad bytes, and name choices. Two builds with
   the same `--fixed-seed` produce byte-identical capsule keys. The BuildRNG
   (ChaCha20 + HKDF, RFC-conformant) is now wired into the build path,
   replacing the previous Mersenne-Twister fallback. Note: full engine
   reproducibility (all 15k lines) is not yet achieved - a few bare
   `random.Random()` calls in non-core paths still draw from system entropy.

4. **runtime_dec hang (fixed)**: The `runtime_dec` capsule chain caused ~40%
   of builds to hang (re-entry into `_br_flow_shard` during `ssl.wrap_socket`).
   Fixed by disabling `runtime_dec` + `chain` when binary capsule is on
   (commit `5a34b43`). The hang bug still exists for `extreme` profile with
   `runtime_dec` on - future work to add re-entrancy guards to the shard
   functions themselves.

5. **ML test methodology (CORRECTED in Phase D)**: The original adversarial
   ML test used N=10+10 (statistically vacuous), an inconsistent gate
   (docstring said <55%, code said <70%), claimed byte-pair features that
   were never implemented, and used an unstratified split. The rewritten test
   uses N>=40 (override via `$BR_ML_N`), Wilson 95% CIs, actually-implemented
   byte-pair features, a genuinely stratified split, and a consistent gate.
   It now runs TWO experiments: (a) PRG-uniformity (obf vs urandom) and
   (b) the actual iO-property test (`Obf(P0)` vs `Obf(P1)` for two
   functionally-equivalent programs). Only (b) is the real iO test; the
   original never had it.

### Future work

1. **Stronger key separation**: Extend env-key mode to the per-function
   capsule runtime keys (currently `runtime_dec` ships per-capsule keys in
   a `_br_rd_keys` literal) and to the lookup-table master key. The
   release-server mode (Phase G) is the strongest posture but opt-in.

2. **Bootstrap obfuscation**: Obfuscate the bootstrap itself (currently
   ~10 lines of cleartext Python). Options: compile to bytecode + marshal,
   or transpile to native via Cython. This would close limitation 2.

3. **Stronger ML adversaries**: Add random forest, gradient-boosted trees,
   and small neural network classifiers. Test with N=100+ samples.

4. **Adaptive adversary**: Model an adversary that knows the bootstrap
   structure and tries to extract the encrypted blob, then distinguish
   builds by the blob's encrypted content.

5. **Runtime_dec hang root cause**: Fix the re-entrancy bug in
   `_br_flow_shard` so `runtime_dec` + `chain` can be safely re-enabled
   with the binary capsule (defense in depth).

6. **Real cryptographic constructions (Phase E)**: Replace the value
   secret-sharing "FSS" with actual BGI DPF/DCF, replace the constant-baked
   opaque predicates with runtime-variable ones, and replace the salted-hash
   point-function obfuscation with a DPF-based construction. These are
   phased; see the plan for details.
