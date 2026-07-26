# Bedrock Obfuscator — Production Readiness Report (Phase 5 + Phase 7)

## Status: PRODUCTION-READY with documented limitations

The obfuscator (Phases 1-5 + Phase 7 hardening) is safe to deploy in
production with the flags and constraints documented below. The native VM
(Phase 5) is an **opt-in enhancement layer**; the core obfuscation
(Phases 1-4) protects ALL code regardless of VM eligibility.

---

## What's production-ready (verified)

| Component | Coverage | Test gate |
|-----------|----------|-----------|
| **Phase 1: Capsule runtime** (`apply_runtimedec`) | ALL functions | 22/22 (Phase 4) |
| **Phase 2: HMAC chain** (`--chain`) | ALL capsule functions | 22/22 |
| **Phase 3: Debug poison + metamorphic** | ALL functions | 22/22 |
| **Phase 4: Anti-meta debranding** (`--anti-meta`) | ALL output strings | `grep -ic bedrock` = 0 |
| **Phase 5: Native VM** (`--native-vm`) | VM-eligible subset only | 16/16 harness + real-world (see Verification gates — `_c_interp_test` / `_integration_test` need an isolated `_xvm` build on `PYTHONPATH`) |

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

### Full stack (env-keyed, chained, metamorphic)
```
python "bedrock_obfuscator.py" -f input.py -o output.py \
    --profile extreme --native-vm --anti-meta --chain --env-key \
    --metamorphic --debug-poison --adv-requests off
```
⚠ `--env-key` ties output to the building machine's hardware fingerprint.
Test on the TARGET machine, not just the build machine.

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

5. **`--env-key` machine binding** — output runs only on machines with
   matching hardware fingerprint. Test on the TARGET machine. A wrong
   fingerprint → silent garbage decrypt (by design).

6. **Per-build RNG** — every build produces different bytecode + perm +
   key. Outputs are never byte-identical across builds. This is by
   design (anti-fingerprinting); regression tests compare behavior, not
   bytes.

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
- [ ] If `--env-key`: test on the TARGET machine (not build machine)
- [ ] If no C compiler: verify reference fallback runs (73x slower)
- [ ] Check `grep -ic bedrock` on output dir = 0 (with `--anti-meta`)
- [ ] Benchmark hot functions — if >10k calls/sec, don't VM-compile them
- [ ] Ship: `out.py` + `_xvm*.pyd` (or `_bedrock_vm_ref.py`) in same dir

---

## TL;DR

**Safe to deploy** with `--profile extreme --native-vm --anti-meta --adv-requests off`.
Core obfuscation (Phases 1-4) protects ALL code. VM (Phase 5) adds stronger
protection for the subset it can compile; the rest falls back safely. The
most dangerous failure mode (silent wrong output from try/except) is
prevented by exception-table detection. Test on YOUR code + YOUR platform
before shipping.
