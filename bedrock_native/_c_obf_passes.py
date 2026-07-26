"""C-source-level obfuscation passes for Cython-generated C (Phase C, Layer 1).

This is the C-source-level equivalent of the LLVM IR obfuscation passes
(`-irobf-cse`/`-cie`/`-cfe`/`-icall`/`-indbr`/`-indgv`/fla/mba/opaque) that
the research (Lot 2, agent 5) identified as the ideal IR-level protection.
Because no LLVM toolchain is installed at the build site, we apply the SAME
transforms at the C-source level — a Python preprocessor that rewrites
Cython's generated ``.c`` BEFORE the MSVC compile. This is strictly weaker
than the IR-level passes (the decryptor stub is visible in disasm; constant
folding happens at C-compile not IR) but achieves the PRIMARY goal: no
cleartext strings survive in the compiled ``.pyd`` ``strings`` output, and
the CFG is hardened with opaque predicates + junk blocks.

The IR-level passes (Polaris-based out-of-tree plugin + clang-cl) remain a
documented strength-tier upgrade: install an LLVM dev toolchain, build the
plugin, and route the pipeline through ``clang-cl -fpass-plugin=...`` instead
of MSVC. The transform names below mirror the IR pass names so the upgrade
is a drop-in.

Passes implemented here (C-source-level):
  - ``encrypt_cython_strings``  ≈ ``-irobf-cse`` (C-string encryption)
  - ``encrypt_cython_ints``     ≈ ``-irobf-cie`` (integer-const encryption, MVP)
  - ``inject_opaque_predicates`` ≈ ``-bcf`` (bogus control flow w/ opaque preds)
  - ``inject_junk_blocks``      ≈ junk basic blocks in PyInit
  - ``mba_substitute``          ≈ ``-mba`` (linear MBA on arithmetic, MVP)

All keyed by a per-build CSPRNG stream (Phase E, ``_build_rng.BuildRNG``).
Each pass draws from an INDEPENDENT labeled sub-stream so enabling/disabling
one pass does not perturb another's randomness. In **reproducible mode**
(``build_rng`` constructed with a ``fixed_seed``) the same input + seed
reproduces the same obfuscation; in **non-reproducible mode** (fresh master
seed) every build differs — per-build diversity that defeats a deobfuscator
built from the leaked source. When ``build_rng`` is None the passes fall back
to the legacy per-source ``sha256`` derivation (deterministic per source, kept
for the CLI smoke test + backward compatibility).
"""
import hashlib
import os
import re
import sys
from typing import Optional, Tuple

# Sibling import — same sys.path-injection pattern as _transpile_pipeline.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG, SubStream  # noqa: E402


# ---------------------------------------------------------------------------
# C-string encryption (Cython __pyx_k_* table)  ≈ -irobf-cse
# ---------------------------------------------------------------------------
# Cython emits two kinds of string constants:
#   static const char __pyx_k__NAME[] = "literal";   <- the BYTES (encrypt this)
#   static PyObject *__pyx_kp_u_NAME;                <- a pointer (filled at init)
# The pointer is filled at runtime by PyUnicode_FromString(__pyx_k__NAME),
# so encrypting the byte array + decrypting it in PyInit (BEFORE interning)
# covers both. We:
#   1. Find every `static const char __pyx_k_...[] = "...";`
#   2. Replace with `static char __pyx_k_...[] = "\xAB\xCD...";` (encrypted,
#      mutable — no `const` so the decrypt loop can XOR in place)
#   3. Inject a `_br_dec_strings()` call at the very START of PyInit_obf that
#      XOR-decrypts every __pyx_k_* array with the per-build key.

_PYX_K_DECL = re.compile(
    r'static\s+const\s+char\s+(__pyx_k_[A-Za-z0-9_]+)\[\]\s*=\s*'
    r'"((?:[^"\\]|\\.)*)"\s*;',
    re.DOTALL,
)

# The PyInit function name for module 'obf' is PyInit_obf. Cython 3.x emits it
# via the macro `__Pyx_PyMODINIT_FUNC` (which #defines to `PyMODINIT_FUNC`),
# so we accept both forms. With PEP 489 multi-phase init the opening brace is
# behind a `#if CYTHON_PEP489_MULTI_PHASE_INIT` directive, so the regex allows
# zero or more preprocessor lines between `)` and `{`. The body is tiny
# (`return PyModuleDef_Init(...)`); opaque predicates + the string decryptor
# inject before that return.
_PYINIT_RE = re.compile(
    r'(?:__Pyx_)?PyMODINIT_FUNC\s+PyInit_\w+\s*\([^)]*\)'
    r'(?:\s*#[^\n]*\n)*\s*\{'
)


def _xor_bytes(raw: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in raw)


def _c_escape_bytes(data: bytes) -> str:
    """Render bytes as a C string literal with hex escapes (no plaintext)."""
    out = []
    for b in data:
        out.append(f'\\x{b:02x}')
    return ''.join(out)


def encrypt_cython_strings(c_source: str, key: int = 0,
                           sub_stream: Optional[SubStream] = None
                           ) -> Tuple[str, int, list]:
    """XOR-encrypt every Cython ``__pyx_k_*`` C-string in *c_source*.

    Replaces ``static const char __pyx_k_NAME[] = "literal";`` with a mutable
    encrypted array and injects a decrypt loop at the start of ``PyInit_*``.

    Returns ``(modified_source, key, encrypted_names)`` where
    ``encrypted_names`` is the list of ``__pyx_k_*`` names that were encrypted
    (for the decrypt-loop emitter). If *key* is 0 a key is derived: from the
    per-build *sub_stream* (Phase E, 1..255) if given, else the legacy
    per-source ``sha256`` fallback.
    """
    if key == 0:
        if sub_stream is not None:
            key = sub_stream.randint(1, 255)
        else:
            key = hashlib.sha256(c_source.encode('utf-8')).digest()[0]
            if key == 0:
                key = 0x5A  # XOR with 0 is identity; pick a non-zero fallback

    encrypted = []  # (name, length) pairs for the decrypt loop

    def _replace_decl(m: re.Match) -> str:
        name = m.group(1)
        escaped = m.group(2)
        # Resolve C escape sequences to actual bytes, then re-encode as UTF-8.
        try:
            raw = escaped.encode('utf-8').decode('unicode_escape').encode('latin-1')
        except Exception:
            raw = escaped.encode('utf-8')
        # Null-terminate like a C string.
        enc = _xor_bytes(raw + b'\x00', key)
        encrypted.append((name, len(enc)))
        return (f'static char {name}[] = "{_c_escape_bytes(enc)}";'
                f' /* encrypted: {len(enc)} bytes */')

    new_source = _PYX_K_DECL.sub(_replace_decl, c_source)

    if not encrypted:
        # No __pyx_k_* found (e.g., pure-arithmetic module); nothing to do.
        return new_source, key, []

    # Inject the decrypt loop at the start of PyInit_*.
    decrypt_body = (
        '    /* Bedrock C-string decryptor (per-build XOR key 0x%02x) */\n'
        '    do {\n'
        '        unsigned int _br_i;\n'
        % key
    )
    for name, length in encrypted:
        decrypt_body += (
            f'        for (_br_i = 0; _br_i < {length}; _br_i++) '
            f'{name}[_br_i] ^= 0x{key:02x};\n'
        )
    decrypt_body += '    } while (0);\n'

    def _inject_pyinit(m: re.Match) -> str:
        # m.group(0) is the full PyInit header including the opening `{`
        # (and, on Cython 3.x, the intervening `#if` lines). Insert the
        # decryptor body right after the `{`.
        return m.group(0) + '\n' + decrypt_body

    if _PYINIT_RE.search(new_source):
        new_source = _PYINIT_RE.sub(_inject_pyinit, new_source, count=1)
    else:
        # No PyInit found — append a constructor-style decryptor as a fallback.
        # This shouldn't happen for a real Cython module, but be defensive.
        new_source += (
            f'\n/* Bedrock string decryptor fallback (no PyInit found) */\n'
            f'static void _br_dec_strings_fallback(void) __attribute__((constructor));\n'
            f'static void _br_dec_strings_fallback(void) {{\n'
            f'{decrypt_body}'
            f'}}\n'
        )

    return new_source, key, [n for n, _ in encrypted]


# ---------------------------------------------------------------------------
# Opaque predicates + junk basic blocks  ≈ -bcf
# ---------------------------------------------------------------------------
# Insert bogus control flow with a provably-always-true opaque predicate into
# PyInit, so the CFG has extra branches that static analysis must consider.
# We use a modular-affine fixed-point predicate (Polaris BogusControlFlow
# pattern):  x*(x-1) % 2 == 0  is always true for integers. We add a junk
# block behind the always-taken branch that computes a dummy value never used.

_OPAQUE_PRED = (
    '        /* opaque predicate: x*(x-1) is always even */\n'
    '        do {\n'
    '            volatile unsigned long _br_op = 0x%08xUL;\n'
    '            volatile unsigned long _br_oq = _br_op * (_br_op - 1UL);\n'
    '            if ((_br_oq %% 2UL) != 0UL) {\n'
    '                /* dead branch — never taken, junk computation */\n'
    '                volatile unsigned long _br_jk = 0x%08xUL;\n'
    '                _br_jk = (_br_jk * 0x9E3779B9UL) ^ _br_op;\n'
    '                (void)_br_jk;\n'
    '            }\n'
    '        } while (0);\n'
)


def inject_opaque_predicates(c_source: str, seed: int = 0,
                             antire_check: bool = False,
                             sub_stream: Optional[SubStream] = None) -> str:
    """Inject opaque-predicate bogus control flow into PyInit_*.

    The predicate ``x*(x-1) % 2 == 0`` is always true for any integer x
    (the product of two consecutive integers is even), so the dead branch
    never executes but the CFG has an extra branch a static analyzer must
    model. The junk constants are per-build-keyed: drawn from the per-build
    *sub_stream* (Phase E) if given, else the legacy per-source+seed
    ``sha256`` fallback — so the exact junk differs across builds.

    If *antire_check* is True, also emit a ``br_antire_check(NULL)`` call at
    the very start of PyInit (the leak-resilient timing core from
    bedrock_antire.c). The result is discarded here — the host vm_fallback
    policy decides what to do with a non-zero flags word. Linking
    bedrock_antire.c into the Extension is the caller's responsibility.
    """
    if sub_stream is not None:
        junk1 = sub_stream.randint(0, 0xFFFFFFFF)
        junk2 = sub_stream.randint(0, 0xFFFFFFFF)
    else:
        rng = hashlib.sha256(
            (c_source + str(seed)).encode('utf-8')
        ).digest()
        junk1 = int.from_bytes(rng[0:4], 'big')
        junk2 = int.from_bytes(rng[4:8], 'big')
    pred_block = _OPAQUE_PRED % (junk1, junk2)

    # Optional anti-RE timing check call (Phase D). Declared extern so the
    # linker resolves it from bedrock_antire.c compiled alongside obf.c.
    antire_prelude = ''
    if antire_check:
        antire_prelude = (
            '    /* Bedrock anti-RE timing check (Phase D). The portable timing\n'
            '     * core from bedrock_antire.c runs here; a non-zero flags word\n'
            '     * indicates a debugger/VM/tamper signal. The host vm_fallback\n'
            '     * policy decides the response (warn/degrade/fail-closed). */\n'
            '    extern unsigned int br_antire_check(const unsigned char *);\n'
            '    (void)br_antire_check((const unsigned char *)0);\n'
        )

    full_block = antire_prelude + pred_block

    if _PYINIT_RE.search(c_source):
        def _inject(m: re.Match) -> str:
            # Insert the opaque-predicate block right after the matched header
            # (which ends at the opening `{`). m.group(0) is the full header
            # incl. the preprocessor lines + `{` for the Cython 3.x form.
            return m.group(0) + '\n' + full_block
        return _PYINIT_RE.sub(_inject, c_source, count=1)
    return c_source


# ---------------------------------------------------------------------------
# Linear MBA instruction substitution  ≈ -mba (MVP)
# ---------------------------------------------------------------------------
# Replace simple integer arithmetic in the generated C with linear MBA
# equivalents. We only substitute in safe contexts (standalone expressions,
# not inside string literals / comments / format codes). The MVP uses the
# canonical linear identities:
#   a + b  ->  (a ^ b) + 2*(a & b)
#   a - b  ->  (a ^ b) - 2*(~a & b)         [NB: careful with ~ on signed]
#   a ^ b  ->  (a | b) - (a & b)            [NB: only for non-negative]
# We apply + substitution only (safest; the others have signedness edge
# cases). This is the weakest MBA form (SiMBA solves it) but it raises the
# bar against naive reading + the per-build keying (Phase E) will upgrade
# to non-linear.

# Match `X + Y` where X, Y are simple integer-typed identifiers/literals.
# This is conservative — we only substitute obvious integer adds to avoid
# breaking pointer arithmetic / float ops / string concat.
_ADD_MBA = re.compile(
    r'(?<![A-Za-z0-9_>])([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_(])'
)


def mba_substitute(c_source: str, max_substitutions: int = 50,
                   sub_stream: Optional[SubStream] = None) -> str:
    """Apply linear-MBA ``+`` substitution to *c_source* (conservative MVP).

    Replaces up to *max_substitutions* occurrences of ``ident + ident`` with
    ``(ident ^ ident) + 2*(ident & ident)``. Conservative: only matches
    bare-identifier + bare-identifier (no pointer derefs, no function calls,
    no array subscripts) to avoid breaking pointer arithmetic.

    If *sub_stream* is given (Phase E) the effective cap is randomized in
    ``[10, max_substitutions]`` so the substitution count differs per build.
    """
    if sub_stream is not None and max_substitutions > 10:
        cap = sub_stream.randint(10, max_substitutions)
    else:
        cap = max_substitutions
    count = [0]

    def _sub(m: re.Match) -> str:
        if count[0] >= cap:
            return m.group(0)
        a, b = m.group(1), m.group(2)
        # Skip if either operand looks like a pointer/call/subscript — the
        # regex already excludes trailing '(' but be extra-safe with leading.
        if a.startswith('__pyx') and 'n_s' in a:
            return m.group(0)  # don't touch interned-name pointers
        count[0] += 1
        return f'(({a} ^ {b}) + 2*({a} & {b}))'

    return _ADD_MBA.sub(_sub, c_source)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def apply_c_obfuscation(c_source: str, *, key: int = 0,
                        build_rng: Optional[BuildRNG] = None,
                        enable_strings: bool = True,
                        enable_opaque: bool = True,
                        enable_mba: bool = False,
                        antire_check: bool = False,
                        verbose: bool = False) -> Tuple[str, dict]:
    """Apply all C-source-level obfuscation passes to *c_source*.

    Returns ``(modified_source, stats)`` where ``stats`` reports what each
    pass did (encrypted string count, etc.).

    If *build_rng* (a Phase-E ``BuildRNG``) is given, each pass draws from an
    INDEPENDENT labeled sub-stream so the obfuscation differs per build
    (per-build diversity). Without it the passes fall back to the legacy
    per-source deterministic derivation (backward compatible).
    """
    stats = {'string_key': key, 'encrypted_strings': 0,
             'opaque_injected': False, 'mba_substitutions': 0,
             'antire_check': antire_check, 'build_id': None}
    if build_rng is not None:
        stats['build_id'] = build_rng.build_id()

    if enable_strings:
        ss = build_rng.stream(b'c_obf_strings') if build_rng else None
        c_source, key, names = encrypt_cython_strings(c_source, key,
                                                       sub_stream=ss)
        stats['string_key'] = key
        stats['encrypted_strings'] = len(names)
        if verbose:
            print(f"[c_obf] encrypted {len(names)} __pyx_k_* strings "
                  f"(key=0x{key:02x})")

    if enable_opaque:
        ss = build_rng.stream(b'c_obf_opaque') if build_rng else None
        new_src = inject_opaque_predicates(c_source, seed=key,
                                            antire_check=antire_check,
                                            sub_stream=ss)
        stats['opaque_injected'] = (new_src != c_source)
        c_source = new_src
        if verbose and stats['opaque_injected']:
            extras = ' + anti-RE timing check' if antire_check else ''
            print(f"[c_obf] injected opaque predicate + junk block{extras} "
                  f"into PyInit")

    if enable_mba:
        ss = build_rng.stream(b'c_obf_mba') if build_rng else None
        before = c_source
        c_source = mba_substitute(c_source, sub_stream=ss)
        # Count substitutions by diff is expensive; the pass tracks internally
        # but we approximate via length delta. For stats we re-run a counter.
        stats['mba_substitutions'] = -1  # MVP: not precisely counted
        if verbose:
            print("[c_obf] applied linear-MBA + substitution")

    return c_source, stats


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    # Synthetic Cython-like C with a __pyx_k_* table + PyInit.
    demo = (
        'static const char __pyx_k__pickle[] = "pickle";\n'
        'static const char __pyx_k__hello[] = "hello world";\n'
        'static PyObject *__pyx_kp_u_pickle;\n'
        'static PyObject *__pyx_n_s_hello;\n'
        '\n'
        'PyMODINIT_FUNC PyInit_obf(void) {\n'
        '    PyObject *__pyx_m = NULL;\n'
        '    __pyx_kp_u_pickle = PyUnicode_FromString(__pyx_k__pickle);\n'
        '    __pyx_n_s_hello = PyUnicode_FromString(__pyx_k__hello);\n'
        '    __pyx_m = PyModule_Create(&__pyx_moduledef);\n'
        '    return __pyx_m;\n'
        '}\n'
    )
    print('=== ORIGINAL ===')
    print(demo)
    out, stats = apply_c_obfuscation(demo, enable_mba=False, verbose=True)
    print('=== OBFUSCATED ===')
    print(out)
    print('=== STATS ===')
    print(stats)
    # Verify no cleartext STRING LITERAL survives. The interned-name pointer
    # variables (__pyx_kp_u_pickle etc.) contain the substring as part of
    # their NAME — that's a symbol, not the content; Layer 1's -irobf-indgv
    # (pointer-table obf) handles those, not the string-content pass.
    import re as _re
    _string_literal_re = _re.compile(r'=\s*"((?:[^"\\]|\\.)*)"')
    literals = [m.group(1) for m in _string_literal_re.finditer(out)]
    # Allow the encrypted hex-escape form (\xAB\xCD...) but reject cleartext
    # ASCII words.
    for lit in literals:
        # An encrypted literal is all \x.. escapes; if it has printable
        # runs >= 3 chars it's cleartext.
        printable = _re.sub(rb'\\x[0-9a-fA-F]{2}', b'', lit.encode('latin-1', 'replace'))
        if _re.search(rb'[\x20-\x7e]{3,}', printable):
            print(f"FAIL: cleartext in literal: {lit[:40]!r}")
            raise AssertionError(f"cleartext survived: {lit[:40]!r}")
    assert stats['encrypted_strings'] == 2, f"FAIL: expected 2, got {stats['encrypted_strings']}"
    print('SMOKE PASS: 2 strings encrypted, opaque injected, no cleartext literals')

    # --- Phase E: per-build diversity via BuildRNG ---
    # Two distinct non-reproducible builds of the SAME source must produce
    # DIFFERENT opaque-predicate junk constants (the diversity gap the
    # _diversity_test.py diagnostic found with the legacy per-source sha256
    # derivation). And reproducible mode (fixed_seed) must reproduce.
    from _build_rng import BuildRNG
    inp = demo.encode('utf-8')
    rng_a = BuildRNG.create(inp)  # fresh master seed
    rng_b = BuildRNG.create(inp)  # different fresh master seed
    out_a, st_a = apply_c_obfuscation(demo, build_rng=rng_a,
                                      enable_mba=False, verbose=False)
    out_b, st_b = apply_c_obfuscation(demo, build_rng=rng_b,
                                      enable_mba=False, verbose=False)
    assert st_a['build_id'] != st_b['build_id'], \
        'diversity: two fresh builds share build_id'
    # The opaque junk constant 0x........UL must differ between the two
    # builds (it is drawn from the per-build sub-stream).
    _junk_re = _re.compile(r'_br_op\s*=\s*0x([0-9a-fA-F]+)UL')
    ja = _junk_re.search(out_a).group(1)
    jb = _junk_re.search(out_b).group(1)
    assert ja != jb, f'diversity: opaque junk identical across builds ({ja})'
    print(f'diversity: opaque junk differs across builds  '
          f'(0x{ja} vs 0x{jb})  OK')

    # Reproducible: same fixed_seed -> identical output.
    fs = b'reproducible-seed-0xdeadbeef'
    rng_r1 = BuildRNG.create(inp, fixed_seed=fs)
    rng_r2 = BuildRNG.create(inp, fixed_seed=fs)
    out_r1, _ = apply_c_obfuscation(demo, build_rng=rng_r1,
                                    enable_mba=False, verbose=False)
    out_r2, _ = apply_c_obfuscation(demo, build_rng=rng_r2,
                                    enable_mba=False, verbose=False)
    assert out_r1 == out_r2, 'reproducible: same fixed_seed must match'
    print('reproducible: same fixed_seed -> identical output  OK')

    print('PHASE-E SMOKE PASS')
