# Bedrock VM v2 — Leak-resilient Crown-Jewel Virtual Machine (Layer 2)

> Kerckhoffs-compliant: all security rests on the per-build `key` (and per-build
> `BuildRNG` seed). The algorithm, ISA layout, and dispatch structure below are
> public; an attacker who reads this file gains nothing without the per-output
> secret that is baked into a single shipped artifact and never reused.

## 1. Scope

Phase F virtualizes a small set of **crown-jewel** functions — the irreplaceable
core of a protected module — into a hardened VM blob executed by a native C
runtime. The rest of the module is Cython-compiled as before. Crown jewels are
selected by the `@bedrock_crown_jewel` decorator (with an auto-heuristic fallback
that picks the top-N most complex functions, capped at 10).

The v2 runtime reuses the **Python-bytecode ISA** and the
`_native_vm_compiler.py` compiler from the earlier VM phase, but the C runtime
(`bedrock_vm_v2.c`, module `_xvm_v2`) is rewritten to be leak-resilient and
anti-devirtualizer-hardened.

## 2. Blob format (extends v1)

```
offset  size  field
------  ----  -----
0       4     magic         b"BVM1"
4       1     version       1 = v1 (no code encryption)
                          2 = v2 (code section XOR-encrypted)
5       4     flags         (LE) bit 0x2 = generator (delegated to ref runtime)
9       4     argcount
13      4     kwonly_count
17      4     nlocals
21      4     nconst         (vestigial — consts come from the pickle below)
25      4     const_len      (bytes of encrypted const pool)
29      ...   const pool     OFB-encrypted with key directly
29+C    4     code_len       (GOTCHA #1 — patched by compiler to actual_bytes/2)
33+C    2*L   code section   2 bytes per op; v2: XOR keystream(code_key)
33+C+2L 4     n_names        (vestigial — GOTCHA #2, skip)
37+C+2L 4     names_len
41+C+2L ...   names blob     OFB-encrypted with names_key, pickle -> (globals, varnames, freevars, cellvars)
```

### 2.1 Key derivations

| Label           | Derivation                        | Used for                |
|-----------------|-----------------------------------|-------------------------|
| `key`           | caller-supplied per-build secret  | const pool OFB          |
| `names_key`     | `sha256(key + b"\|names")`        | names blob OFB          |
| `code_key`      | `sha256(key + b"\|code")`         | code section XOR (v2)   |

### 2.2 OFB cipher

```
state_0 = sha256(key)
state_n = sha256(state_{n-1} + key + bytes(off & 255))     # off advances by 32 per block
out[i]  = in[i] ^ state_n[i % 32]
```

The const pool uses `key`; the names blob uses `names_key`. The code section
(v2 only) uses an independent XOR keystream derived from `code_key` (NOT the
OFB stream — kept separate so a const-pool leak cannot reveal code).

### 2.3 GOTCHAs (must honor in any decoder)

- **GOTCHA #1 (code_len)**: read 4-byte LE at `29+const_len`; consume exactly
  `2*code_len` bytes. The compiler patches this field to `actual_bytes/2` after
  laying out the stitched `EXTENDED_ARG` stream. Do NOT infer length from the
  AST.
- **GOTCHA #2 (two name length fields)**: after the code, read `n_names` (4 LE,
  vestigial — skip it), then `names_len` (4 LE), then `names_len` bytes. The
  vestigial field is left over from an earlier wire format and must be skipped,
  not interpreted.

### 2.4 Perm

Runtime dict `{scrambled_byte: canonical_byte}`. `perm_ext` (default 144) is the
scrambled byte for `EXTENDED_ARG` — recognized RAW (before de-scramble) so the
stitching of extended args happens on the wire bytes. `MaxDuplicateOps ≥ 2`
means the perm dict has MORE than 256 entries: each canonical opcode maps to at
least two scrambled bytes (pool-constrained: 94 canonicals + ~162 extras),
which prevents a 1:1 byte-frequency attack on the scrambled stream.

## 3. The 10 features

### Build-time (Python, deterministic per-build via `BuildRNG`)

| # | Feature                              | Module                | Notes |
|---|--------------------------------------|-----------------------|-------|
| 1 | Randomized ISA (σ-perm + dup ≥2)    | `_native_vm_compiler`| Perm via `BuildRNG.stream(b"vm_perm")`, not ad-hoc `random.Random` |
| 2 | XOR-encrypted bytecode              | `_native_vm_compiler` + `_bedrock_vm_ref` | v2 blob; version bump 1→2 (v1 still decodes) |
| 8 | Non-linear MBA in dispatch          | `_vm_mba.py`          | Depth ≥7 (verified 17 in test); Claripy simplify budget exhausted |
| 9 | Malformed-CF (opaque + collisions)  | `_vm_opaque.py`       | Z3-verified if available, hash-based modular-affine fallback |
| 10| XuanJia EH-shadowing                | `_vm_eh_shadow.py`    | PE `.pdata` / ELF `.eh_frame` shadow tables post-build |

### Runtime (C, in `bedrock_vm_v2.c`)

| # | Feature                              | Mechanism |
|---|--------------------------------------|-----------|
| 3 | Context-threaded dispatch            | `handler_table[256]` function pointers; `handler_table[canonical & 0xff](ctx)` — CALL, not `jmp [reg]` (dodges CET/IBT, harder to trace) |
| 4 | Obscured VPC                         | `vpc_lo ^ vpc_hi == pc`, split into two fields, advanced non-monotonically with a keystream byte; bytecode lives in `.data`, not `.text` |
| 5 | Register-resident encrypted context | `vm_ctx` struct on the heap; `stack_enc`, `locals_enc`, `cells_enc`, `ops_enc`, `args_enc` are XOR'd with `ptr_mask` (derived from `sha256(sha256(key))[:8]`); accessor macros `CTX_STACK`/`CTX_LOCALS`/... un-XOR on every access |
| 6 | Call-threaded                        | Dispatch is `handler_table[canonical](ctx)` — no indirect jump anywhere in the dispatch loop |
| 7 | SMC handlers (RW↔RX toggle)          | Gated by `BR_ENABLE_SMC`. `_smc_tick` mutates a junk buffer every `BR_SMC_TOGGLE_N` (64) calls via `VirtualProtect` (Win) / `mprotect` (POSIX). Default OFF (SMC trips AV — ship EV-signed + whitelist only when ON) |

Plus OFB decrypt, header parse, perm de-scramble (reused from `_bedrock_vm.c`),
and a non-static `sha256_buffer` export (closes the linkage gap with
`bedrock_antire.c`'s `extern`).

## 4. Public API

```c
/* bedrock_vm_v2.c -- module _xvm_v2 */
static PyObject *_xvm_v2_run(PyObject *self, PyObject *args_parse, PyObject *kwargs);
/* kwlist: {"blob","perm","key","args","globals","perm_ext","smc_seed", NULL} */
/* format: "OOOOO|lL:run"  -> (blob, perm, key, args, globals, |perm_ext, smc_seed) */
```

The Python wrapper selects the runtime by the version byte in the blob:
- `version == 1` → legacy `_bedrock_vm.c` runtime
- `version == 2` → `bedrock_vm_v2.c` runtime (`_xvm_v2.run`)

## 5. Dispatch loop (canonical form)

```c
while (ctx->alive) {
    int pc = vpc_pc(ctx);                       /* vpc_lo ^ vpc_hi */
    if (pc < 0 || pc >= ctx->ncode) { implicit None return; break; }
#ifdef BR_ENABLE_SMC
    _smc_tick(ctx);                             /* F.4: mutate SMC junk every N ticks */
#endif
    { volatile unsigned long _br_mba = ...;     /* F.5: depth-7 MBA, evaluates to 0 */
      (void)_br_mba; }
    int canonical = de_scramble(ctx);           /* sets ctx->cur_arg */
    handler_fn h = handler_table[canonical & 0xff];
    if (h == NULL) { PyErr_Format(...); rc = -1; break; }
    if (h(ctx) < 0) { rc = -1; break; }        /* CALL dispatch, not jmp */
}
```

## 6. Verification (Phase F integration test — `_vm_v2_test.py`)

All 9 sections pass:

```
F.1 crown-jewel collection: ['fib', 'compute_secret']  OK
F.2 reproducible: same seed -> identical blob (127 bytes, v2)  OK
F.2 diverse: different seeds -> different blob  OK
F.2 MaxDuplicateOps: perm has 188 entries (>94 base)  OK
F.3 behavioral: fib(10)=55, fib(15)=610, compute_secret(50)=8090  OK
F.4 SMC kwarg threading: fib(10)=55 with smc_seed=0xDEAD  OK
F.5 non-linear MBA: depth 17 (>= 7)  OK
F.5 MBA reproducible: same seed -> identical chain  OK
F.6 opaque predicate + const collision + malformed-CF block  OK
F.7 EH-shadow: .pdata patched on _xvm.cp311-win_amd64.pyd  OK
F.8 leak gate: 13 fingerprints checked, none leaked  OK
F.8 anti-devirt structural: 8 properties verified  OK
PHASE F INTEGRATION TEST: PASS
```

### Leak-gate fingerprints checked in the shipped `.pyd`

`bedrock_vm_v2`, `run_v2`, `_xvm_v2`, `sha256_buffer`, `vm_ctx`, `handler_table`,
`vpc_lo`, `vpc_hi`, `_smc_tick`, `_br_mba`, `BVM1`, `de_scramble`, `ofb_decrypt`.
None of these strings appear in the compiled artifact.

## 7. Constraints / risks (carried from the plan)

- **SMC trips AV**: `BR_ENABLE_SMC` is OFF by default. Only enable on
  EV-signed, vendor-whitelisted builds.
- **Z3 / pefile optional**: `_vm_opaque.py` uses Z3 if installed (SMT proof of
  always-true), else falls back to hash-based modular-affine predicates that are
  correct by construction. `_vm_eh_shadow.py` uses `pefile` if installed, else
  walks the PE/ELF structs manually (same pattern as `_zero_pe_timestamp`).
- **MBA runtime overhead**: ~1.1-2× per VM call — acceptable because crown
  jewels are a handful of functions, not the whole module.
- **Generators + nested Frames**: v2 delegates to `_bedrock_vm_ref` (the Python
  reference runtime) for `flags & 0x2` and Frame-in-const cases. Native
  generators are out of Phase F scope.
- **Version bump**: v1 blobs (from the earlier VM phase) still decode — the
  wrapper dispatches on the version byte.
- **Crown-jewel cap**: collector enforces ~5-10; heuristic fallback respects the
  cap.

## 8. Deferred (not Phase F)

- **Pipeline-order reconcile**: the crown-jewel collector must run BEFORE
  `obf_vars` (which uses `ast.unparse + reparse` and strips decorators + custom
  attrs). The v2-runtime approach in F.3 sidesteps this for the VM path itself
  (crown jewels are embedded in the C blob, not the Python wrapper), but a full
  reconcile of the `--transpile` + `native_vm` mutual-exclusion is deferred to
  the architectural reconcile pass.
