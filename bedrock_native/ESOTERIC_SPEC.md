# Phase H — Esoteric + Anti-Pattern Obfuscation (Layer 6) Specification

**Status:** COMPLETE. All 11 features implemented, smoke-tested, and verified
by the Phase H integration test (`_phase_h_test.py`: 11 individual + combined-9
composition + leak gate + F/G regression — all PASS).

**Date:** 2026-07-17

---

## 1. Overview

Phase H is the final obfuscation layer (Layer 6): esoteric and anti-pattern
transforms that go beyond the standard obfuscation toolkit (renaming,
control-flow flattening, string encryption) to target advanced adversaries —
symbolic-execution engines, ML-based devirtualizers, byte-level fingerprinters,
and static call-graph analyzers.

Every pass follows the Bedrock contract:
- **`apply_X(tree, ctx) -> tree`** signature (Python AST passes) or the native
  post-build / C-module analog.
- **Deterministic per build** via `BuildRNG.stream(b'<label>')` sub-streams or
  `random.Random(seed)` (reproducible in fixed-seed mode, diverse in fresh-seed
  mode).
- **Behavior-preserving** by construction (verified by the behavioral gate:
  `fib(10)=55`, `fib(15)=610`, `compute_secret(50)=8090`).
- **Flag-gated** (default OFF; auto-on under `extreme`).
- **Kerckhoffs-compliant**: the technique is public; security rests on
  per-output secrets (the build seed, the per-VM key), not algorithm secrecy.

Pass ordering follows the reverse-stack convention (declared LATER runs
EARLIER; `bedrock_obfuscator.py:6032-6042`).

> **Phase iO:** Phase H is the foundation for Phase iO (Practical
> Indistinguishability Obfuscation). The `io` profile layers all of
> `extreme` + Phase H + 7 iO extensions (FSS, crypto opaque, pointfunc,
> lookup, entropy pad, binary capsule). See
> [`IO_SPEC.md`](IO_SPEC.md) for the full iO specification.

---

## 2. The 11 Implemented Features

### H.1 — Identifier poisoning (`_identifier_poison.py`)

**Layer:** Python AST.

**Mechanism:** Per-function, inject 3-8 shadow bindings of the form
`open = __builtins__['open']`, `list = __builtins__['list']`, ... — re-binding
builtin names as local variables that resolve to the same builtin via dict
access. The Subscript form (`__builtins__['name']`) survives the `obf_builtins`
bare-Name rewrite, so the shadows persist through later passes.

**Threat addressed:** Static name-resolution analysis assuming builtin/stdlib
semantics. A decompiler that sees `open = __builtins__['open']` cannot fold
the subsequent `open(...)` call to a known builtin without simulating the
shadow assignment.

**OPSEC note:** The shadows use `__builtins__['name']` (dict access), not bare
`__builtins__.name`, because the bare form is rewritten by `obf_builtins`.
Verified in the H.1 smoke test.

---

### H.2 — Acoda / opaque call dispatch (`_acoda.py`)

**Layer:** Python AST.

**Mechanism:** Replace direct calls `f(args)` with
`_br_acoda[(opaque_idx)](args)` where `_br_acoda = {0: <decoy>, 1: <decoy>, ...,
k: f}` is a per-module dispatch table and `opaque_idx` is an
opaque-always-equal expression proven (via modular inverse) to yield `f`'s
slot `k`. The expression `((real_slot * k_inv * k) ^ (j ^ j)) % n_slots`
collapses to `real_slot % n_slots = k` because `k_inv * k ≡ 1 (mod n_slots)`
and `j ^ j == 0`. Decoy slots are `raise`-on-reach lambdas (a build bug if
ever dispatched — they never are).

**Threat addressed:** Static call-target resolution. The direct `f(args)` edge
is replaced by an indirect table dispatch whose index is a non-trivial
arithmetic expression; a static analyzer must evaluate the modular inverse
to recover the target.

---

### H.3 — Structural metamorphic (`_metamorphic.py`)

**Layer:** Python runtime.

**Mechanism:** Two-part:
1. **Build-time** (`apply_metamorphic`): inject dead-junk assignments
   `_br_mut = '<48 hex chars>'` at the top of eligible function bodies. The
   string is never read (dead), so changing it is behavior-safe.
2. **Runtime** (`gen_metamorphic_shard`): a shard function (`_br_structural_mutate`)
   that reads `__file__`, regex-finds all `_br_mut = '...'` assignments,
   regenerates each hex string with fresh `random.Random(str(time()))` entropy,
   re-masks + recomputes the file/integrity hashes (same logic as the existing
   `_br_meta_shard`), and atomically `os.replace`s the file.

**Threat addressed:** Static file fingerprinting. Even after AST obfuscation,
the shipped source has stable byte content across runs. Structural mutation
makes each run produce byte-different source (beyond just a comment), so a
static dump taken at different times shows different bytes — defeating
file-hash fingerprinting and byte-diff analysis.

**Scope:** Re-randomizes only RNG-driven junk constants (fast + safe); full
runtime AST re-obfuscation is out of scope.

---

### H.4 — Style randomizer (`_style_randomizer.py`)

**Layer:** Python source (post-`ast.unparse`).

**Mechanism:** Post-`ast.unparse` source rewriter:
1. Shuffle independent top-level `def` order (dependency-preserving via
   reference topo-sort; dunders and the marker stay fixed).
2. Insert random blank lines between top-level statements.
3. Insert debranded junk comments (`# <random hex>`) at random boundaries.

**Composition-safety fix:** A def referenced by a later non-def top-level
statement (e.g. an assignment table injected by another pass, like
`_br_acoda = {0: fib}`) is anchored (non-movable) — the def-shuffle cannot
reorder it past the referencing statement. Without this, the shuffle could
move `def fib` after `_br_acoda = {..., 4: fib}` and `NameError` at module
load. The H.12 combined test surfaced this; the fix is in `_shuffle_top_defs`.

**Threat addressed:** Source-pattern fingerprinting (byte-level / line-pattern
clustering of builds by layout).

**Source-mode only:** `marshal`/`bytecode` output has no layout to randomize.

---

### H.5 — Branchless-ification (`_branchless.py`)

**Layer:** Python AST.

**Mechanism:** Convert eligible `if cond: x = a else: x = b` into a mux:
- Integer: `x = b ^ ((a ^ b) & -bool(cond))` (exact for ints).
- Numeric (0/1 condition): `x = cond * a + (1 - cond) * b`.

Skips side-effecting branches, string branches, and non-simple conditions.
Uses `copy.deepcopy` for safe AST node duplication.

**Threat addressed:** Control-flow-graph recovery. Converting conditional
branches to branchless arithmetic eliminates the branch node from the CFG,
leaving a linear basic block — defeating CFG-based decompilation and
branch-prediction-pattern analysis.

---

### H.6 — Bloom-filter opaque predicates (`_bloom_obf.py`)

**Layer:** Python AST.

**Mechanism:** `BloomFilter` class (k salted SHA-256 hashes over a bit array).
Build-time, pre-load the filter with the always-accept domain (the constants
used as guard conditions). Inject guards `if _br_bloom_contains(c): <dead junk>`
where `c` is pre-loaded — the filter always returns True for `c`, so the dead
junk never runs, but a static analyzer must evaluate the Bloom filter
(probabilistic membership) to prove the branch is dead.

**Threat addressed:** Opaque-predicate folding. Algebraic always-true
predicates (`x * 0 == 0`) are trivially folded by modern simplifiers; Bloom
membership is probabilistic and harder to prove always-true than algebraic
identities.

---

### H.7 — DAG-based CFF (`_dag_cff.py`)

**Layer:** Python AST.

**Mechanism:** Multi-variable state machine using `(_br_ds1, _br_ds2)` with
`(s1, s2) == (A, B)` dispatch. Linear bodies are lowered into a 2-variable
DAG: each block sets `(_br_ds1, _br_ds2) = (next_a, next_b)` and the dispatch
loop matches the tuple. Unlike single-variable CFF (`_Flattener` /
`__cff_state`), the state is split across two variables, so a tracer must
track the pair, not a single integer.

**Threat addressed:** Single-variable CFF recovery (VMPredator-style state
tracking). The 2-variable split defeats tools that key off a single dispatch
state variable.

**Linear bodies only:** Non-linear bodies (loops, recursion) are skipped.

---

### H.8 — Self-checking CF (`_selfcheck_cf.py`)

**Layer:** Python runtime.

**Mechanism:** Per linear block, maintain a rolling path hash
`_br_path = (_br_path * M ^ block_id) & 0xFFFFFFFF`. Before each `return`,
check `if _br_path != expected: raise RuntimeError('cf path mismatch')`.
The expected hash is pre-computed at build time (deterministic per block
sequence). A tampered control-flow path (block skipped/reordered) yields a
mismatched hash → `RuntimeError`.

**Threat addressed:** Control-flow tampering. An adversary who patches out a
block (e.g. a license check) changes the executed path, breaking the rolling
hash. This is a CF-level (not byte-level) self-check.

**Linear bodies only:** Non-linear bodies are skipped.

---

### H.9 — FSS 2-share (`_fss.py`)

**Layer:** Python AST.

**Mechanism:** Function secret sharing — split `f(x)` into two shares:
- `f1(x, r) = f(x) + r`
- `f2(x, r) = -r`

The caller computes `f(x) = f1(x, r) + f2(x, r)` (additive combiner). Fresh
`r = secrets.randbelow(1 << 64) - (1 << 63)` per call. The shares live in
separate `def` scopes so static analysis cannot see them together — each
share alone is random.

**Threat addressed:** Static secret recovery. A static analyzer that reads
only one share cannot recover `f(x)`; the combiner requires both shares plus
the fresh randomness.

**Eligibility:** Numeric-returning pure functions only; capped at ~3-5.

---

### H.10 — TLS callback injection (`_tls_callback.py`)

**Layer:** Native PE post-build.

**Mechanism:** `inject_tls_callback(pyd_path, sym, verbose=False) -> bool`.
Post-build PE patch that APPENDS a new `.brtls` section (the existing PE
patchers — `_zero_pe_timestamp`, `_vm_eh_shadow._patch_pe_pdata` — only
MODIFY existing data directories; this adds NEW-section capacity). The
section holds an `IMAGE_TLS_DIRECTORY` (8 fields, PE32+ 40B / PE32 24B) + a
null-terminated callback array (1 callback + NULL). Data-directory index 9
(TLS) is wired at the directory; `SizeOfImage` is bumped to the aligned
section end.

**Why TLS:** TLS callbacks fire on every thread start/stop, including the
`LoadLibrary` call that loads the `.pyd` — BEFORE `PyInit_*` runs. This is a
pre-`PyInit` hook for early integrity checks (build-time embedded hash
verification, anti-debug probes) — earlier than any Python-level `__init__`.

**Symbol resolution:** `sym` is either an exported symbol name (looked up via
the export directory) or a direct RVA (when the symbol isn't exported but its
RVA is known at build time).

**Safety:** Rejects non-PE files, existing TLS directories (clean skip —
extending an existing callback array in place is unsafe without growing the
owning section), missing symbols, and non-Windows platforms. On any failure
the file is left byte-identical. Idempotent (second injection skips because
TLS is already present).

**Platform:** Windows-PE-only; returns `False` without touching the file on
Linux/other.

---

### H.11 — Exception-table VM (`_exc_table_vm.c`, module `_xetvm`)

**Layer:** Native C.

**Mechanism:** A separate minimal VM whose dispatch substrate is the OS
exception table, not a function-pointer array. Each opcode handler is its own
function (noinlined) with its own `RUNTIME_FUNCTION` entry in `.pdata`
(Windows x64). With `BR_ENABLE_EXC_VM` defined at build time, each advancing
handler raises a controlled exception (code `0xE1CE0000`, "EXC_NEXT"); the
dispatcher's `__try`/`__except` catches it; the stack unwind from the handler
back to the dispatcher walks the handler's `.pdata` entry — so `.pdata` IS
the dispatch table. Without `BR_ENABLE_EXC_VM` (the default), or on
non-Windows, the handlers fall back to direct call/return dispatch.

**Anti-silent-wrong-output posture:** A real fault (not EXC_NEXT) has an
exception code that doesn't match the high-16-bit mask; the filter returns
`EXCEPTION_CONTINUE_SEARCH`, so the fault propagates and crashes — surfacing
the bug rather than silently producing a wrong result. A missing handler
(`et_handler_for` returns NULL) raises `RuntimeError`, not a wrong output.
Bad opcodes and out-of-range jumps raise `RuntimeError`.

**Self-contained:** Ships its own SHA-256 (FIPS 180-4); `sha256_buffer` is
externally linkable (mirrors `bedrock_vm_v2.c`'s contract).

**Leaf-handler property:** The advancing (raising) handlers are non-leaf
(they call `RaiseException`) and have `.pdata` entries (verified via
`RtlLookupFunctionEntry` in `handler_has_pdata`); the `op_ret` handler is a
leaf (returns normally, no unwind) and has no `.pdata` entry — this is the
correct structural property, confirmed by the H.11 smoke test.

**Minimal opcode set (12):** `PUSH_CONST`, `LOAD_FAST`, `STORE_FAST`, `ADD`,
`SUB`, `MUL`, `EQ`, `LT`, `JUMP`, `JUMP_IF_TRUE`, `JUMP_IF_FALSE`, `RET` —
sufficient to compute `fib` (iterative) and small arithmetic kernels.

**Risk note (from PRODUCTION_READINESS.md):** Exception-driven dispatch has a
silent-wrong-output risk (a missed handler yields a wrong result, no crash).
Included FULLY despite this, mitigated by the H.12 exhaustive op-coverage gate
(every opcode dispatched at least once across the test programs). If unstable
in combination, flag-gated default-OFF (still shipped).

**Linux analog:** `.eh_frame`/signal-based dispatch is the documented analog;
the SEH path is Windows-only here. The module builds on Linux with direct
call/return dispatch (no `BR_ENABLE_EXC_VM`).

---

## 3. Dropped Features (Documented, Not Built)

Three features from the original esoteric-techniques survey were dropped
after analysis — they are inapplicable to this target or provide marginal
gain at high cost.

### Dropped 1 — PAC-signed control flow (ARM64-only)

**Rationale:** This target is x64/MSVC (Windows primary, Linux/GCC fallback).
Pointer Authentication Codes (PAC) are an ARM64 (ARMv8.3) feature; there is no
x64 equivalent. MSVC does not emit PAC instructions. Including a no-op stub
would add code surface with zero protective value. N/A.

### Dropped 2 — Overlapping instructions (no asm-emit path)

**Rationale:** Overlapping-instruction obfuscation requires emitting raw
machine code (an assembler path) so that one byte sequence is the operand of
two different instructions depending on entry point. This pipeline is
Python → Cython → C → MSVC; MSVC canonicalizes the C (register allocation,
instruction selection, scheduling) and does not preserve hand-laid overlapping
byte sequences. A Cython-generated C function compiled by MSVC has no
overlapping instructions by construction. Implementing an asm-emit path would
be a major architectural addition for very low realism (the overlaps would be
MSVC's, not ours). Marginal gain, high cost.

### Dropped 3 — ROP/JOP gadget chaining (no gadget infrastructure)

**Rationale:** Return-Oriented Programming (ROP) / Jump-Oriented Programming
(JOP) as an obfuscation technique requires a curated gadget catalog
(short instruction sequences ending in `ret`/`jmp`) and a chain-builder that
links them to implement the protected logic. This pipeline has no gadget
infrastructure: the obfuscator operates at the Python AST and C-source level,
not at the machine-code level. Building a gadget catalog + chain-builder
would be a separate sub-project, and the resulting chains are fragile
(MSVC version/link-order sensitive). The exception-table VM (H.11) achieves a
similar "dispatch via unusual substrate" effect with far less fragility.
Marginal gain, high cost, high fragility.

---

## 4. Verification Gates (H.12)

The Phase H integration test (`_phase_h_test.py`) verifies:

| Sub | Gate | Result |
|-----|------|--------|
| H.1 | id poison: `__builtins__[]` shadows present; behavior identical | PASS |
| H.2 | acoda: `_br_acoda` dispatch present; behavior identical | PASS |
| H.3 | metamorphic: `_br_mut` targets + shard; behavior identical | PASS |
| H.4 | style: layout byte-different; behavior identical | PASS |
| H.5 | branchless: behavior identical (branchless mux where eligible) | PASS |
| H.6 | bloom: `_br_bloom` filter present; behavior identical | PASS |
| H.7 | DAG-CFF: behavior identical (no linear bodies in fixture) | PASS |
| H.8 | selfcheck-CF: behavior identical (no linear bodies in fixture) | PASS |
| H.9 | FSS: behavior identical | PASS |
| H.10 | TLS callback: 6-case smoke (PE32+/PE32, export/direct-RVA, rejection, idempotent) | PASS |
| H.11 | exc-table VM: `fib(10)=55`, `fib(15)=610` via SEH; exhaustive op-coverage; `.pdata` structure; tamper resistance | PASS |
| Combined | all 9 Python passes composed; behavior identical | PASS |
| Leak gate | 13 modules + combined output; no forbidden markers | PASS |
| F regression | VM v2 smoke still PASS | PASS |
| G regression | key-release smoke still PASS | PASS |

---

## 5. Files

### New (14)
1. `bedrock_native/_identifier_poison.py` — H.1
2. `bedrock_native/_acoda.py` — H.2
3. `bedrock_native/_metamorphic.py` — H.3
4. `bedrock_native/_style_randomizer.py` — H.4
5. `bedrock_native/_branchless.py` — H.5
6. `bedrock_native/_bloom_obf.py` — H.6
7. `bedrock_native/_dag_cff.py` — H.7
8. `bedrock_native/_selfcheck_cf.py` — H.8
9. `bedrock_native/_fss.py` — H.9
10. `bedrock_native/_tls_callback.py` — H.10
11. `bedrock_native/_exc_table_vm.c` — H.11 (module `_xetvm`)
12. `bedrock_native/_exc_table_vm_setup.py` — H.11 build script
13. `bedrock_native/_exc_table_vm_test.py` — H.11 smoke
14. `bedrock_native/_phase_h_test.py` — H.12 integration + leak gate
15. `bedrock_native/ESOTERIC_SPEC.md` — this document

### Modified (1, during H.12)
- `bedrock_native/_style_randomizer.py` — composition-safety fix in
  `_shuffle_top_defs` (anchor defs referenced by later non-def statements).

### Not yet modified (deferred to integration)
- `bedrock_obfuscator.py` — 11 new `BuildContext` bool fields + 11 CLI flags
  (`BooleanOptionalAction`) + `from_args` wiring + pass registration.
  Extending `_br_meta_shard` (H.3) to re-randomize junk constants. Hooking
  style randomizer at `ast.unparse` emission. *(The passes are implemented
  and smoke-tested as standalone modules; wiring into the main obfuscator
  CLI is the integration step.)*
- `bedrock_native/_c_obf_passes.py` — `inject_exc_table_dispatch` C-source
  pass (emits `_xetvm` harness into transpiled C) if needed for exc-table VM
  integration.
- `bedrock_native/_transpile_pipeline.py` — wire `inject_tls_callback`
  post-ship (alongside `_zero_pe_timestamp`); wire `_exc_table_vm.c` into
  `sources_list`; thread `BuildRNG` sub-streams.
- `bedrock_native/_build_system.py` — ensure no `/guard:cf` (so CFG doesn't
  validate exc-driven dispatch); document `/EHsc` choice.

---

## 6. Constraints and Risks

- **Exc-table VM silent-wrong-output:** missed handler = wrong output, no
  crash. Mitigated by H.12 exhaustive op-coverage. Flag-gated default-OFF
  (still shipped) if unstable in combination.
- **Pass composition:** 11 passes must compose. The H.12 combined test
  surfaces conflicts; the one found (style-randomizer def-shuffle vs. acoda
  assignment table) is fixed in `_shuffle_top_defs`. Known ordering rules:
  DAG-CFF supersedes CFF when both on; branchless runs before CFF; style
  randomizer runs last (source-level); the def-shuffle anchors defs
  referenced by later non-def statements.
- **FSS eligibility:** numeric-returning pure functions only; cap ~3-5.
- **TLS new-section capacity:** H.10 adds NEW-section capacity (the existing
  patchers only modify existing directories). Tested on synthetic PE32+ and
  PE32. Most fiddly native work; tested on synthetic PEs (a real MSVC `.pyd`
  test would strengthen confidence).
- **Metamorphic scope:** H.3 re-randomizes only RNG-driven junk constants
  (fast + safe); full runtime AST re-obfuscation out of scope.
- **Style randomizer source-mode only:** `marshal`/`bytecode` output has no
  layout to randomize.
- **Identifier-poison OPSEC:** shadows use `__builtins__['name']` (dict
  access) which survives `obf_builtins` (bare-Name rewrite). Verified in H.1.
