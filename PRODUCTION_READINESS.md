# Bedrock Obfuscator — Production Readiness Report (Phases 1-5, 7, G, H, iO)

## Status: PRODUCTION-READY with documented limitations

The obfuscator (Phases 1-5 + Phase 7 hardening + Phase G deobf-hardening
(G1-G9 + G1+) + Phase H esoteric + Phase iO) is safe to deploy in production
with the flags and constraints documented below. The native VM (Phase 5) is
an opt-in enhancement layer; the core obfuscation (Phases 1-4) protects ALL
code regardless of VM eligibility. The io profile adds the encrypted-source
capsule (binary capsule) for the strongest protection.

NOTE: Phase G hardening (2026-07-28/29) is a full deobfuscation-hardening
sweep driven by 3 independent sub-agents that confirmed 12 findings,
verified by 3 Explore agents. 11 of 12 fixed (G1-G9 + G1+); 1 deferred
(M4: Vietnamese-identifier + sentinel debrand, blocked by a Compile.ll
encoding constraint). See the Phase G hardening section below.

## Phase G deobfuscation-hardening (G1-G9 + G1+)

A full hardening sweep against deobfuscation, driven by 3 independent
sub-agents that confirmed 12 findings (verified by 3 Explore agents).
11 of 12 fixed; 1 deferred (M4: Vietnamese-identifier + sentinel debrand,
blocked by a `Compile.ll` encoding constraint).

### What each phase fixes

| Phase | Finding(s) | What it does |
|-------|-----------|--------------|
| **G1** | C1, C6, M2 | Capsule blob emitted as hex/base85 literal (no latin-1 escaping) — kills the 0x5c/0x30/0x78 byte-distribution spike that let a single-histogram-bin classifier distinguish obf from urandom at 100%. Per-build bootstrap skeleton randomization + blob padding closes the length channel. |
| **G1+** | (G1 follow-up, found via 6-layer deobf analysis of the released challenge) | The bootstrap left `import zlib, hashlib` and `exec(zlib.decompressobj().decompress(` as **constant structural tells** (100%-reliable single-regex fingerprints). G1+ aliases `zlib` to a per-build random token (never bare) and randomizes the import-line / decompress-call / XOR-expression shapes across 4 / 3 / 2 forms per build — no single regex matches every io file. |
| **G2** | C7, M3 | `anti_meta` default ON for all profiles (not just extreme/io); extended debrand map; sentinel prefixes (`_LCAN_`/`_MARK_`/`_SLOT_`) randomized. `grep -c "bedrock\|baobg\|_LCAN_\|_MARK_\|_SLOT_"` = 0. |
| **G3** | M5 | `num_obf` now rotates across 4 AST forms per byte (lambda Call, `int.from_bytes`, bytearray-subscript, double-XOR) — one AST-fold rule no longer collapses every obfuscated literal. |
| **G4** | C4 | Capsule key delivery: `--capsule-key-file PATH` (0600 perms), `--no-capsule-sidecar` (print key to stderr once, no file), strip `master_seed_hex` from the manifest (replaced by `master_seed_hash` SHA-256 for traitor-tracing). |
| **G5** | C3 | DPF key split is the DEFAULT: k0 ships in the file, k1 is read from env `BR_DPF_K1` at runtime (`.dpfkey` sidecar). A 1-key adversary now faces the GGM pseudorandom tree. **Breaks backward-compat** (output won't run without the env var) — intentional posture-by-default. |
| **G6** | C5 | Opaque predicates no longer use foldable tautologies (`v-v`, `f(x)==f(x)`). They now branch on `v & 1` to pick between two different-shape tautologies — a CSE/peephole pass cannot fold because the two branches differ. |
| **G7** | M7, M1 | DPF PRG control bits drawn from out-of-seed bytes (switched to SHA-512 so sL/sR/tL/tR are disjoint); per-build domain-separation salt; domain widened from 16/32 bits to 64/128 bits (brute-force infeasible with G5's split key). |
| **G8** | M2, M9 | ML adversarial test now keeps `len(data)` as a raw feature (was normalized away), adds Shannon entropy + positional entropy + bootstrap-regex-count, and runs a 3rd experiment (build-diversity: classify build-A vs build-B of the same program). Feature-importance report labels scalar features by name. |
| **G9** | C2 | `--env-key` is now the DEFAULT for non-capsule profiles (fast/balanced/paranoid/extreme). The payload key is derived from the building machine's hardware fingerprint, NOT the reversible cand/mark digest. Agent 1's cand/mark unpacker now FAILS. `--no-env-key` opts back into the reversible path (with a warning). |

### Recovery-attack posture (re-verified after Phase G)

| Attack | Before Phase G | After Phase G |
|--------|----------------|---------------|
| cand/mark static key-recovery (Agent 1 unpacker) | recovers source in minutes | **FAILS** (G9: key now HW-fingerprint-derived, no cand/mark digest to match) |
| Capsule key from 32-byte file prefix | recovers source (embed-key mode) | **FAILS** by default (G1+G4: key not in file, hex/base85 encoding, sidecar 0600) |
| DPF reconstruct (Eval(0,k0,x) XOR Eval(1,k1,x)) | both keys in one file | **FAILS** (G5: k1 via env, missing → refuse-run) |
| Bootstrap signature regex (`import zlib, hashlib`) | 100%-reliable tell | **GONE** (G1+: zlib aliased, 4/3/2 shape randomization) |

### Known remaining gaps (honest)

1. **M4 (deferred)** — Vietnamese identifiers (`AnhOiDungCoDec`, `DitMeMayDungCoDec`, etc.) + sentinel debrand are not yet randomized. Blocked by a `Compile.ll` encoding constraint in the native-VM build path. Non-Vietnamese debrand (bedrock/baobg) IS randomized (G2).
2. **CFF dispatch signature (L3)** — control-flow flattening dispatch-table structure is not yet randomized. The opaque predicates feeding it ARE hardened (G6), but the dispatch table itself has a predictable shape.
3. **`--profile io` build time** — ~100-180s per build (full Phase G + Phase H + Phase iO pipeline). The ML test at N=40 takes ~48min. Use `--no-native-vm` or a smaller N for CI.

### Phase H.A: Anti-AI deobfuscation (LLM / ML / AI-symbolic)

A defense pass against AI-assisted deobfuscation — the AI equivalent of the
existing anti-debug (against humans) and anti-RE (against static tools).
Makes obfuscated output resistant to three classes of AI analysis: LLM-
semantic (refusal via prompt-injection comments, EOS-tokens, vulnerability
decoys, safety-trigger vocab), LLM-attention + tokenization (lost-in-middle
burial via 200 decoy functions, homoglyph identifier twins, zero-width/bidi
token fragmentation), and AI-symbolic + context exhaustion (long-range
dependency weaving, token-budget padding, false-comment counter-narrative).

Grounded in published research: Acoda (arXiv:2606.11755, ICSE 2026, 70% ASR
cross-model on GPT-4o/DeepSeek/Qwen/Llama/Gemma), Lost in the Middle
(arXiv:2307.03172), Trojan Source (CVE-2021-42574), Bad Characters
(arXiv:2106.09898), and "semantic displacement" (arXiv:2606.31725).

Two-stage pass: `apply_anti_ai` (AST, 'after' obf_vars) injects decoys +
homoglyph twins + weave network; `apply_anti_ai_source` (post-compile
source pass, after `Compile.Obfuscate` so comments survive) injects
prompt-injection comments + EOS-tokens + vuln decoys + zero-width/bidi +
safety-trigger vocab + false-comments. All payloads are comments or
constant-false-guarded dead literals, behavior-preserving. Auto-on for
`extreme`/`io`. CLI: `--h-anti-ai`, `--anti-ai-count N` (200 balanced /
80 extreme-io). Smoke test: `python bedrock_native/_anti_ai.py` (round-trip
+ 10 heuristics). Verified on balanced + extreme builds (behavioral gate
PASS, heuristics present, `--no-h-anti-ai` clean).

**Honest caveat:** causes aligned LLMs to REFUSE/TRUNCATE analysis (that
is its goal). Do NOT use `--h-anti-ai` output with your own LLM-assisted
maintenance tooling. Verified by heuristic checks only (no ML/LLM test
harness; the existing `_io_adversarial_ml.py` measures byte-uniformity,
not AI-deobf resistance).

### io capsule runtime-attack hardening (T1/T2/T3)

Three defenses against the runtime deobfuscation chain demonstrated in
`WALKTHROUGH.md` (where an io-obfuscated 24 MB file was statically stripped
+ dynamically traced + guard no-op'd):

**T1 — `--embed-key` now double-opt-in (closes the exploited vector).**
The walkthrough's "Layer 1" static strip was made possible exclusively by
`--embed-key` (key = `blob[:32]` in the plaintext file). A bare `--embed-key`
is now rejected with an error; `--allow-insecure-embed-key` is required to
opt in. The TUI no longer adds `--embed-key` for io — it uses the secure
default (key via `BR_CAPSULE_KEY` env var + sidecar file). Capsule crypto
itself (SHA-256 CTR + zlib) is sound; only the insecure key-delivery mode
was the gap.

**T2 — before-load marshal re-verify at the true chokepoint + `compile` pin.**
The payload unmarshals at `RemoveLayers` L1719 (`code = __sr_m.loads(code)`)
— this runs in the OUTER loader, BEFORE any guard in the inner `_co_pl`
fires. The existing `__bedrock_pin_callable__('marshal','loads')` guard
runs AFTER the unmarshal (inside `_co_pl`), so it can't defend it. T2 adds
an inline re-verify of `marshal.loads` attributes (callable / `__module__==
'marshal'` / no `__wrapped__` / `BuiltinFunctionType`) immediately before
L1719 — hard-exit via `os._exit(1)` if spoofed. Also pins `compile`
(2nd builtin the capsule+payload paths both use).

**T3 — build-time-baked guard code-object digest (defeats `CodeType.replace`).**
`co.replace(co_consts=...)` to no-op a guard was undefended (no code-object
integrity existed for the obfuscator's own guards). T3 bakes a SHA-256
digest of 5 critical guard functions' bytecode at build time, patched into
`_co_pl.co_consts` post-compile. The runtime verifier
`__br_verify_guard_integrity__` re-hashes the live `__code__` and compares
to the baked digest — mismatch → `__bedrock_self_destruct__` + `os._exit(1)`.
Under capsule the digest is encrypted until runtime, so the attacker can't
read the expected value. No masking needed (digest is a module-level string
referenced via global name lookup, not in any guard's `co_consts`).

**Honest limitation:** T2/T3 raise the bar for an operator-attacker who runs
the file (has the key). T1 is the real fix for the file-only attacker
(walkthrough vector). Encryption can't stop someone who has the key from
decrypting — T2/T3 increase the cost of dynamic tracing and guard
neutralization, not the crypto itself.

---

---

## What's production-ready (verified)

| Component | Coverage | Test gate |
|-----------|----------|-----------|
| **Phase 1: Capsule runtime** (`apply_runtimedec`) | ALL functions | 22/22 (Phase 4) |
| **Phase 2: HMAC chain** (`--chain`) | ALL capsule functions | 22/22 |
| **Phase 3: Debug poison + metamorphic** | ALL functions | 22/22 |
| **Phase 4: Anti-meta debranding** (`--anti-meta`) | ALL output strings | `grep -ic bedrock` = 0 |
| **Phase 5: Native VM** (`--native-vm`) | VM-eligible subset only | 16/16 harness + real-world (see Verification gates — `_c_interp_test` / `_integration_test` need an isolated `_xvm` build on `PYTHONPATH`) |
| **Phase H: Esoteric** (11 passes) | ALL functions | `_phase_h_test.py` 11 individual + combined-9 |
| **Phase iO: Practical iO** (`--profile io`) | ALL | `_io_distinguish_test.py` 27/27 (N=20, chi-square gate), `_io_adversarial_ml.py` 3 experiments (PRG-uniformity + iO-property + build-diversity) |
| **Phase G: deobf-hardening** (G1-G9 + G1+) | capsule + non-capsule | 6 module smoke tests PASS (capsule/fss/opaque/pointfunc/build_rng/io_ml); 3 recovery attacks FAIL (cand-mark, capsule key, DPF reconstruct) |

The core obfuscation (Phases 1-4) protects **every function** — capsule
runtime, encrypted const pool, HMAC chain, debug poison, metamorphic
rewrite, anti-meta debranding. This is the backbone; it works on ALL code.

The native VM (Phase 5) adds a **stronger protection layer** for functions
it can compile: logic is no longer Python bytecode but opaque BedrockVM
bytes interpreted by a compiled C extension. Functions the VM can't handle
fall back to the capsule runtime (Phase 1), which is still strong.

---

## Safe production flags

### Recommended (maximum protection, balanced overhead)
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile extreme --native-vm --anti-meta --adv-requests off
```

### If no C compiler at build site
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile extreme --anti-meta --adv-requests off
```
(VM falls back to pure-Python reference interpreter — protection degraded
to "custom bytecode in Python" but still functional. 73x slower than C;
avoid for high-frequency functions.)

### If performance-critical (VM off, capsule only)
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile balanced --anti-meta --adv-requests off
```

### Full stack (chained, metamorphic) — env-key is now the DEFAULT
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile extreme --native-vm --anti-meta --chain \
    --metamorphic --debug-poison --adv-requests off
```
NOTE: since Phase G9, `--env-key` is the DEFAULT for non-capsule profiles
(fast/balanced/paranoid/extreme). The payload key is derived from the
building machine's hardware fingerprint (machine-id + MAC + node + arch,
SHA-256'd), NOT the reversible cand/mark digest. Output now runs ONLY on
the building machine. Pass `--no-env-key` to opt back into the legacy
reversible cand/mark path (a warning is printed — NOT recommended). The
explicit `--env-key` flag is retained for clarity but is a no-op now.

⚠ env-key ties output to the building machine's hardware fingerprint.
Test on the TARGET machine, not just the build machine. A wrong
fingerprint produces silent garbage decrypt (by design).

### io profile (encrypted-source capsule + Phase G + Phase H)
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile io --anti-vm off --anti-debug off --no-debug-poison \
    --no-metamorphic --no-native-vm --no-cache --overwrite \
    --adv-requests off --no-anti-timing --quiet
```
The `io` profile layers all of `extreme` + **Phase G deobf-hardening
(G1-G9 + G1+)** + Phase H esoteric (11 passes) + the 7 capsule phases
(iO-1..iO-7: FSS, crypto opaque, pointfunc, lookup, entropy pad, binary
capsule). The binary capsule encrypts the entire source, achieving
encrypted-output uniformity (chi-square 501 ≈ random baseline 510; the
ML PRG-uniformity accuracy is no longer a single 40% number — Phase G8
rewrote the test to report 3 experiments with Wilson 95% CIs and
feature-importance breakdowns; see the table below).

Sandbox-safe flags (`--anti-vm off`, `--anti-debug off`) are required in
CI/sandbox. In production, remove them to enable the full anti-VM/anti-debug
stack. Full spec: `bedrock_native/IO_SPEC.md`.

⚠ The `io` profile auto-disables `runtime_dec` + `chain` when the binary
capsule is on (the capsule already encrypts everything; the redundant chain
caused an intermittent hang bug — fixed in commit `5a34b43`).

---

## VM coverage (what compiles to BedrockVM)

### ✅ VM-eligible (compiled to native-interpreted bytecode)
- Pure arithmetic + control flow (`if/elif/else`, `while`, `for`)
- Function calls (positional + keyword arguments)
- List comprehensions (single + multi-`for` + conditions)
- Generators (`yield`) — delegated to reference interpreter at runtime
- f-strings (`FORMAT_VALUE` + `BUILD_STRING`)
- Tuple/set/dict/slice building
- Attribute access (`LOAD_ATTR`/`STORE_ATTR`)
- Subscripting (`BINARY_SUBSCR`/`STORE_SUBSCR`)
- Unary ops (`-`, `not`, `~`, `+`)
- Binary ops (`+`, `-`, `*`, `/`, `%`, `//`, `**`, `<<`, `>>`, `&`, `|`, `^`)
- Comparisons (`<`, `<=`, `==`, `!=`, `>`, `>=`, `in`, `not in`, `is`, `is not`)
- Stack ops (`COPY`, `SWAP`, `DUP_TOP`, `POP_TOP`)
- Global/local/const load/store

### ❌ VM-ineligible (falls back to capsule runtime — still obfuscated)
- `try/except/finally` (exception table — silent wrong output risk → skip)
- `with` statements (`BEFORE_WITH`/`SETUP_WITH`)
- `async def` / `await` / `async for` / `async with`
- Class definitions (`class X:`) + methods with `self`
- Decorators (compile to wrapper, but `@decorator` itself may fail)
- `match` statements (3.10+)
- `LOAD_METHOD` / method calls (partial support)
- Closures with free-variable captures (flag set, binding incomplete)
- Walrus operator (`:=`) in some contexts

**These fall back SAFELY** — the function stays as obfuscated Python
(Phases 1-4 still apply). No silent wrong output. No crash.

---

## Performance characteristics

Benchmark: `fib(20)`, 10,000 calls, Python 3.11.15 / Windows x64:

| Runtime | Per-call cost | Overhead | Use case |
|---------|-------------|----------|----------|
| Plain Python | 4 µs | 1.0x | Baseline |
| **C interpreter** (`_xvm.pyd`) | **14 µs** | **3.6x** | **Production** |
| Reference interpreter | 291 µs | 73x | Fallback only |

**Recommendation**: VM-compile only **low-call-frequency entry points** and
**key-derivation functions**. Do NOT VM-compile hot loops or functions
called >10,000 times/second. The capsule runtime (Phase 1) has lower
per-call overhead for high-frequency functions (one-time marshal + swap,
not per-call decrypt).

---

## Platform support

| Platform | C extension | Reference fallback | Tested |
|----------|-------------|-------------------|--------|
| Windows x64 + Python 3.11 + MSVC 2022 | ✅ `.pyd` | ✅ | ✅ 16/16 |
| Windows x64 + Python 3.11 + MinGW gcc | ⚠ untested | ✅ | ❌ |
| Linux x64 + Python 3.10-3.13 + gcc | ⚠ should work | ✅ | ❌ |
| macOS arm64/x64 + clang | ⚠ should work | ✅ | ❌ |
| Python 3.12+ (adaptive opcodes) | ⚠ may skip more | ✅ | ❌ |

**Production constraint**: build on the SAME platform + Python version as
the target. The `.pyd`/`.so` is CPython-version-specific
(`_xvm.cp311-win_amd64.pyd` won't load on 3.12). If no compiler →
reference interpreter ships (73x slower but functional).

---

## Known limitations (Phase 5/7)

1. **Generator native not implemented** — generators delegate to the
   pure-Python reference interpreter (73x slower). Avoid VM-compiling
   generators in hot paths.

2. **`try/except` in VM** — skipped (exception table detection). The C
   interpreter's exception propagation is not wired. Functions with
   try/except fall back to capsule runtime. **This is a safety feature**,
   not a bug — silent wrong output is more dangerous than fallback.

3. **`MAKE_FUNCTION` closure binding** — defaults/kwdefaults/closure not
   fully wired in the C interpreter. Nested defs with captures may
   produce wrong results → the compiler skips functions with free vars
   that aren't simple comprehensions.

4. **CPython 3.12+ adaptive opcodes** — the compiler may skip more
   functions on 3.12+ (adaptive interpreter opcodes). Skip-on-unknown
   is safe (fallback). Test on the target Python version before deploy.

5. **`--env-key` machine binding (DEFAULT since G9)** — output runs
   only on machines with a matching hardware fingerprint
   (machine-id + MAC + node + arch, SHA-256'd). Test on the TARGET
   machine. A wrong fingerprint → silent garbage decrypt (by design).
   Pass `--no-env-key` to opt back into the reversible cand/mark path
   (a warning is printed — NOT recommended).

6. **Per-build RNG** — every build produces different bytecode + perm +
   key. Outputs are never byte-identical across builds. This is by
   design (anti-fingerprinting); regression tests compare behavior, not
   bytes.

7. **M4 (deferred Phase G finding)** — Vietnamese identifiers
   (`AnhOiDungCoDec`, `DitMeMayDungCoDec`, `ConCac`, `__tunnel`,
   `__getobject__`) + sentinel debrand are not yet randomized. Blocked
   by a `Compile.ll` encoding constraint in the native-VM build path.
   Non-Vietnamese debrand (bedrock/baobg) IS randomized (G2).

8. **CFF dispatch signature (L3)** — control-flow flattening
   dispatch-table structure is not yet randomized. The opaque
   predicates feeding it ARE hardened (G6, structural mix), but the
   dispatch table itself has a predictable shape — a structural
   signature is still detectable by a determined analyst.

9. **`--profile io` build time** — ~100-180s per build (full Phase G
   + Phase H + Phase iO pipeline). The ML adversarial test at N=40
   takes ~48min. Use `--no-native-vm` or a smaller N (BR_ML_N=8) for
   CI. This is a build-cost property, not a security gap.

---

## Verification gates (all must pass before deploy)

```bash
# 1. Native component tests (fast, ~10s)
#    NOTE: _c_interp_test.py and _integration_test.py `import _xvm`, which is
#    NOT checked into the tree. Build it first with build_and_ship() into a
#    temp dir and put that dir on PYTHONPATH (this mirrors how a real build
#    ships the .pyd next to obf.py). _oracle_bytecodes.py / _compiler_test.py
#    / _build_system_test.py do not need _xvm and run standalone.
cd bedrock_native
python _oracle_bytecodes.py        # 10/10
python _compiler_test.py           # 17/17
python _build_system_test.py       # 11/11  (also exercises a one-shot build)
# Build an isolated _xvm for the C-path tests:
python -c "import _build_system,os,tempfile,sys; d=tempfile.mkdtemp(); r=_build_system.build_and_ship(d); print(r['module_path'])" > _xvm_path.txt
$XVM_DIR=$(dirname $(cat _xvm_path.txt)); PYTHONPATH=$XVM_DIR:$PYTHONPATH python _c_interp_test.py     # 10/10
PYTHONPATH=$XVM_DIR:$PYTHONPATH python _integration_test.py    # 17/17
cd ..

# 2. Full Phase 5 harness (~5-8 min, 16 cases)
python _phase5_harness.py          # 16/16 ALL PASS (verified on Win11/Py3.11/MSVC after the v2 fix)

# 3. Real-world test (no silent wrong output)
python _test_realworld.py          # baseline
# build + run obfuscated, compare output — must match line-for-line
```

### Known harness caveats (as of this build)

- **Test K (reference fallback)** builds with `--vm-fallback auto` explicitly.
  The `extreme` profile otherwise auto-sets `--vm-fallback off` (fail-closed),
  which would poison+abort on the deleted `.pyd` and report a false failure.
  The fail-closed path itself is verified by test H (tamper → not 221).
- **Run timeout is 360s** (was 240s). Two cases (`extreme --no-native-vm`
  regression and `extreme --native-vm kwargs`) occasionally timed out at 240s
  when the harness ran many native builds back-to-back and the host was
  loaded; both pass in ~2-3s when run in isolation. 360s removes the flake
  without weakening the assertion.

### Fixed in this build: BedrockVM version 2 crash (critical)

The compiler (`bedrock_obfuscator.py` `_nativevm_build_key`) generates a 32-byte
encryption key on every `--native-vm` build, which made `_bedrock_vm_ref.encode`
emit **version 2** blobs (`out += bytes([2 if key else 1])`) — the code section
is OFB-encrypted with `code_key = sha256(key + b'|code')` (Phase F leak-
resilience). The C extension `_xvm` only accepted **version 1**, so every
production `--native-vm` build crashed at runtime with
`ValueError: unsupported BedrockVM version 2` whenever the native `_xvm`
loaded successfully (the bug was masked when `_xvm` failed to build and the
loader silently fell back to the pure-Python reference interpreter, which
accepts v1 and v2 — which is why earlier runs reported 13/16 instead of 0/16).

Fix: `_bedrock_vm.c` now accepts versions 1 and 2 and, for v2, decrypts the
code section with `code_key = sha256(key + b'|code')` via the existing OFB
primitive (mirrors `_bedrock_vm_ref.decode`). Verified: `_phase5_harness.py`
16/16 ALL PASS with real `.pyd` shipped on every `--native-vm` case; the
isolated smoke `add(3,4)=7` through a v2 blob confirms the C path.

---

## Deploy checklist

- [ ] Build on target platform + Python version
- [ ] Run `_phase5_harness.py` → 16/16 ALL PASS (harness builds its own `_xvm`)
- [ ] Run `_c_interp_test.py` + `_integration_test.py` with an isolated `_xvm` on `PYTHONPATH` (see Verification gates)
- [ ] Run real-world test on YOUR code → output matches baseline
- [ ] Run Phase G smoke tests (all 6 modules, ~30s): `python bedrock_native/_binary_capsule.py`, `bedrock_native/_fss.py`, `bedrock_native/_opaque_crypto.py`, `bedrock_native/_pointfunc_obf.py`, `bedrock_native/_build_rng.py`, `bedrock_native/_io_adversarial_ml.py` (the last at `BR_ML_N=8` for speed)
- [ ] Run the Phase G grep gate: `grep -c "bedrock\|baobg\|_LCAN_\|_MARK_\|_SLOT_\|import zlib, hashlib\|exec(zlib.decompressobj"` on output dir = 0
- [ ] env-key is the DEFAULT (since G9): test on the TARGET machine (not build machine). A wrong fingerprint → silent garbage decrypt. Pass `--no-env-key` only if you accept the reversible cand/mark path (warning printed).
- [ ] For the `io` profile: capture the capsule key sidecar (`<output>.key`, 0600) and set `BR_CAPSULE_KEY` at runtime. If DPF triggers (point-function equality), also capture `<output>.dpfkey` and set `BR_DPF_K1`.
- [ ] If no C compiler: verify reference fallback runs (73x slower)
- [ ] Benchmark hot functions — if >10k calls/sec, don't VM-compile them
- [ ] Ship: `out.py` + `_xvm*.pyd` (or `_bedrock_vm_ref.py`) in same dir

---

## TL;DR

**Safe to deploy** with `--profile extreme --native-vm --anti-meta --adv-requests off`
(env-key is now the default — output runs only on the building machine). Core
obfuscation (Phases 1-4) protects ALL code. VM (Phase 5) adds stronger
protection for the subset it can compile; the rest falls back safely. The
most dangerous failure mode (silent wrong output from try/except) is
prevented by exception-table detection.

**For maximum protection** (nation-state threat model, no perf constraint),
use `--profile io` (layers Phase G deobf-hardening G1-G9+G1+ + Phase H + the
encrypted-source capsule). The binary capsule encrypts the entire source; the
key is NOT shipped (read from `BR_CAPSULE_KEY` at runtime). The output's byte
distribution approaches uniform. Honest caveat: this is encrypted-output
uniformity (a PRG property), NOT the cryptographic iO property. Test on YOUR
code + YOUR platform before shipping. See `bedrock_native/IO_SPEC.md` for the
full threat model and the remaining deobf gaps (M4, CFF dispatch).
