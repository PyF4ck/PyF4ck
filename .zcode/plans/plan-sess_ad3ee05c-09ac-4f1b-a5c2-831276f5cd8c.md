# C-Level Code Obfuscation + Timing Anti-Debug

## Mục tiêu
Hardening `.pyd`/`.so` ở C level: (1) string obfuscation (XOR-encoded, decrypt-on-stack), (2) timing-based anti-debug (cross-platform, `clock()` only), (3) self-integrity checksum (SHA-256 `.text` section), (4) compiler flags (strip symbols). Không dùng OS-specific API → portable mọi platform.

## Cơ sở kỹ thuật
- `_bedrock_vm.c` (1632 dòng): switch dispatch, 1 exported symbol `PyInit__xvm`, SHA-256 đã có sẵn (lines 22-123, reuse được cho self-integrity)
- Build system: bare `Extension("_xvm", sources=["_bedrock_vm.c"])` — zero compiler flags hiện tại
- Plaintext leaks: `"BVM1"`, `"pickle"`, `"loads"`, `"builtins"`, `"__import__"`, `"|names"`, `"_bedrock_vm_ref"`, ~30 error messages, module docstring
- `PyInit__xvm` hiện chỉ `PyModule_Create` → injection point hoàn hảo cho anti-debug + integrity check

## Changes

### 1. String obfuscation — new file `_obf_c_strings.py` (build-time preprocessor)

Python script chạy TRƯỚC khi compile, XOR-encode mọi string literal trong `_bedrock_vm.c`:

**Cách hoạt động:**
- Parse C source, tìm mọi string literal `"..."` (skip comments, char literals, `#include`)
- Mỗi string → XOR với per-build random key (1 byte, seed từ `hashlib.sha256(c_source).digest()[0]`)
- Thay `"BVM1"` → `_DS(0xAB, ((uint8_t[]){0xF3, 0x29, 0x8C, 0xE7}))` (encoded bytes array)
- `_DS` = macro decrypt-on-stack: XOR từng byte → stack buffer → trả `const char*` → dùng xong wipe

**C helper (thêm vào `_bedrock_vm.c`):**
```c
/* Decrypt a stack string. XOR each byte with key, zero after use. */
#define _DS(KEY, ARR) _dec_str(ARR, sizeof(ARR), KEY)
static char* _dec_str(const uint8_t *enc, size_t len, uint8_t key) {
    static __thread char buf[512]; /* thread-local, tránh race */
    for (size_t i = 0; i < len && i < sizeof(buf)-1; i++)
        buf[i] = enc[i] ^ key;
    buf[len < sizeof(buf) ? len : sizeof(buf)-1] = '\0';
    return buf;
}
```
Sau khi dùng: caller wipe bằng `memset(buf, 0, len)` — thực tế `__thread static` buffer sẽ bị overwrite lần sau, đủ cho MVP.

**Exclusions (không encode):**
- `#include` directives
- `#define` preprocessor macros
- Format strings trong `PyErr_Format` → encode (vì chúng cũng leak). Nhưng `PyArg_ParseTupleAndKeywords` format codes (`"OOOOO|l:run"`) phải giữ plaintext (CPython parse trực tiếp) → whitelist.
- `PyMethodDef` name `"run"` + docstring → encode, decrypt trước khi register

**Build integration** (modify `_build_system.py` lines 190-199):
```python
# Pre-process: XOR-encode strings
from _obf_c_strings import obfuscate_c_strings
c_text = open(c_src, 'r', encoding='utf-8').read()
c_obf, obf_key = obfuscate_c_strings(c_text)
obf_path = os.path.join(tmpdir, c_basename)
with open(obf_path, 'w', encoding='utf-8') as f:
    f.write(c_obf)
# Pass key via -D compiler macro
extra_args = [f'/DBEDROCK_STR_KEY={obf_key}' if win else f'-DBEDROCK_STR_KEY={obf_key}']
```

### 2. Timing anti-debug — thêm vào `_bedrock_vm.c`

**a. `PyInit__xvm` gate (line 1630):** Measure `clock()` before/after a fixed-computation loop. Nếu delta > threshold (e.g. 50ms cho loop normally <1ms) → debugger attached → return `NULL` (module load fails).

```c
#include <time.h>

static int _anti_debug_timing(void) {
    clock_t t0 = clock();
    /* Fixed-work loop: SHA-256 of a constant (reuse existing sha256_buffer) */
    uint8_t out[32];
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 7 + 3);
    for (int r = 0; r < 200; r++)
        sha256_buffer(seed, 64, out);
    clock_t t1 = clock();
    double elapsed_ms = (double)(t1 - t0) / CLOCKS_PER_SEC * 1000.0;
    /* Normal: <5ms. Debugger single-step: >50ms. */
    return (elapsed_ms > 50.0) ? 1 : 0;
}

PyMODINIT_FUNC PyInit__xvm(void) {
    if (_anti_debug_timing()) {
        PyErr_SetString(PyExc_ImportError, "init failed");
        return NULL;  /* module load fails → loader fallback */
    }
    return PyModule_Create(&_xvm_module);
}
```

**b. Periodic check in `_xvm_run` (line 630, dispatch loop):** Every N instructions (e.g. N=5000), call `_anti_debug_timing()`. If triggered → `goto error` with a generic error (không reveal "debugger detected").

```c
/* Inside dispatch loop, after pc++ */
if ((pc & 0x1FFF) == 0) {  /* every ~8192 instructions */
    if (_anti_debug_timing()) {
        PyErr_SetString(PyExc_RuntimeError, "runtime error");
        goto error;
    }
}
```

### 3. Self-integrity checksum — thêm vào `_bedrock_vm.c`

**a. Build time** (modify `_build_system.py`): After compile, compute SHA-256 of the `.text` section. Tricky — PE/ELF section extraction needs parsing. Simpler MVP: SHA-256 of entire `.pyd` file (already computed as `ext_hash` at line 248). Pass first 8 bytes as `-DBEDROCK_SELF_HASH_0=0xABCD1234` etc.

Thực ra đơn giản hơn: **hash the C source itself** at build time, embed as compile-time constant. If attacker modifies C source → hash mismatch. But attacker modifies the .pyd binary, not source. So this doesn't help against binary patching.

**Better approach:** At `PyInit__xvm`, compute SHA-256 of the module's own memory range (`.text` section). Compare with build-time embedded hash. Cross-platform way: use `dladdr` (Unix) / `GetModuleHandle` + PE parsing (Windows) — but user said timing-only, no OS API.

**Simplest portable approach:** Skip self-integrity at C level. The Python loader already does SHA-256 of the entire `.pyd` (line 496 in loader snippet). That covers binary tampering. C-level self-integrity without OS APIs is impractical (can't get own .text bounds portably). → **Drop this from scope**, rely on existing Python-level `__VM_EXTHASH__` check.

### 4. Compiler flags — modify `_build_system.py` + `_bedrock_vm_setup.py`

**`_build_system.py` lines 193-197** — add platform-specific flags:
```python
if sys.platform == 'win32':
    extra_compile = ['/O2', '/GS-']  # optimize, no stack canary (smaller)
    extra_link = ['/INCREMENTAL:NO']  # deterministic build
else:
    extra_compile = ['-O2', '-fno-asynchronous-unwind-tables', '-fomit-frame-pointer']
    extra_link = ['-Wl,-s']  # strip symbols

setup_text = (
    "from setuptools import setup, Extension\n"
    f"setup(name={ext_name!r}, version='0.1',\n"
    f"      ext_modules=[Extension({ext_name!r}, sources=[{c_basename!r}],\n"
    f"        extra_compile_args={extra_compile!r},\n"
    f"        extra_link_args={extra_link!r})])\n"
)
```

**`_bedrock_vm_setup.py`** — mirror the same flags for standalone builds.

### 5. Control flow obfuscation (lightweight, C-level)

Add **opaque predicates** + **junk basic blocks** to `_xvm_run`:
- Before dispatch loop: insert 2-3 fake branches that always fall through (e.g. `if (sha256_buffer(seed, 64, out) != 0) { /* dead code */ }`)
- Inside `PyInit__xvm`: insert a bogus switch with fake cases
- These confuse static analysis (IDA graph becomes messier) without significant runtime cost

## File changes summary

| File | Change |
|------|--------|
| `bedrock_native/_obf_c_strings.py` | **NEW** — build-time string XOR preprocessor |
| `bedrock_native/_bedrock_vm.c` | Add `_dec_str` helper, timing anti-debug in `PyInit__xvm` + dispatch loop, opaque predicates, junk blocks |
| `bedrock_native/_build_system.py` | Call preprocessor before compile, add compiler flags (strip symbols, optimize), pass `-DBEDROCK_STR_KEY` |
| `bedrock_native/_bedrock_vm_setup.py` | Mirror compiler flags for standalone builds |

## Verification
1. **Build**: `python _bedrock_vm_setup.py build_ext --inplace` → compiles, no errors
2. **Functional**: obfuscate demo (check_license + fib) → run obf.py → `False`+`55` (no regression)
3. **Strings**: `strings _xvm.cp311-win_amd64.pyd | grep -i "BVM1\|pickle\|bedrock"` → empty (all encrypted)
4. **Anti-debug timing**: normal run → fast (<5ms). Simulate slow-step (sleep in a debug hook) → module fails to load
5. **P0 regression**: delete/tamper `.pyd` → still fail-closed (Python-level `__VM_EXTHASH__` intact)
6. **SaaS**: rebuild via `app.py` → works (preprocessor runs transparently in build pipeline)