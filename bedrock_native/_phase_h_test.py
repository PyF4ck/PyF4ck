"""Phase H (Layer 6) integration test + leak gate.

Verifies all 11 esoteric/anti-pattern features -- individually and combined --
against the canonical behavioral gate (``fib(10)=55``, ``fib(15)=610``,
``compute_secret(50)=8090``), plus a leak gate scanning the Phase H module
sources for forbidden key/seed material, and a regression check that Phase F
+ G smoke tests still pass after the H edits.

Style A ``run_all()`` runner, mirroring ``_phase_g_test.py``.

Run:
    python bedrock_native/_phase_h_test.py
"""
from __future__ import annotations

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# --- Canonical fixture (mirror _vm_v2_test.py) ------------------------------

FIXTURE_SRC = '''\
def fib(n):
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)

def compute_secret(x):
    acc = 0
    for i in range(x):
        acc = (acc * 31 + i) % 9973
    return acc

def plain_helper(x):
    return x + 1
'''

EXPECTED_FIB_10 = 55
EXPECTED_FIB_15 = 610
EXPECTED_SECRET_50 = 8090


def _run_behavior(ns):
    """Return (fib10, fib15, secret50, helper5) from an exec'd namespace."""
    return (ns['fib'](10), ns['fib'](15), ns['compute_secret'](50),
            ns['plain_helper'](5))


def _assert_behavior(ns, label):
    f10, f15, s50, h5 = _run_behavior(ns)
    assert f10 == EXPECTED_FIB_10, f"{label}: fib(10)={f10} != {EXPECTED_FIB_10}"
    assert f15 == EXPECTED_FIB_15, f"{label}: fib(15)={f15} != {EXPECTED_FIB_15}"
    assert s50 == EXPECTED_SECRET_50, f"{label}: compute_secret(50)={s50} != {EXPECTED_SECRET_50}"
    assert h5 == 6, f"{label}: plain_helper(5)={h5} != 6"


# --- Per-pass context --------------------------------------------------------

class _Ctx:
    """Minimal context satisfying every Phase H pass's attribute probes."""
    def __init__(self, seed=20260717):
        self.build_rng = None
        # per-pass seeds (deterministic per build)
        self.identifier_poison_seed = seed
        self.acoda_seed = seed + 1
        self.metamorphic_seed = seed + 2
        self.style_seed = seed + 3
        self.branchless_seed = seed + 4
        self.bloom_seed = seed + 5
        self.dag_cff_seed = seed + 6
        self.selfcheck_seed = seed + 7
        self.fss_seed = seed + 8
        # scratch attributes passes write back
        self.keep_names = set()


# --- Individual pass tests ----------------------------------------------------

def _apply_and_check(apply_fn_name, module_name, seed_attr, label):
    """Import *module*, call its ``apply_*`` on the fixture, exec, and assert
    behavior is preserved.  Returns the obfuscated source for leak scanning."""
    import importlib
    mod = importlib.import_module(module_name)
    # find the apply_* function
    apply_fn = getattr(mod, apply_fn_name)
    tree = ast.parse(FIXTURE_SRC)
    ctx = _Ctx()
    # set the pass-specific seed
    setattr(ctx, seed_attr, getattr(ctx, seed_attr))
    if apply_fn_name == 'apply_style_randomizer':
        # style randomizer takes (source, ctx), not (tree, ctx)
        out_src = apply_fn(FIXTURE_SRC, ctx)
        ns = {}
        exec(compile(ast.parse(out_src), '<style>', 'exec'), ns)
        _assert_behavior(ns, label)
        return out_src
    out_tree = apply_fn(tree, ctx)
    ast.fix_missing_locations(out_tree)
    out_src = ast.unparse(out_tree)
    ns = {}
    exec(compile(ast.Module(body=out_tree.body, type_ignores=[]), '<obf>', 'exec'), ns)
    _assert_behavior(ns, label)
    return out_src


def test_h1_identifier_poison():
    src = _apply_and_check('apply_identifier_poison', '_identifier_poison',
                           'identifier_poison_seed', 'H.1 id-poison')
    # The pass now emits getattr(__builtins__, '__dict__', __builtins__)['name']
    # (robust to the __builtins__ dict-vs-module dual nature). Match either the
    # robust form or the legacy __builtins__[...] form.
    assert ("getattr(__builtins__" in src or "__builtins__[" in src), \
        "H.1 should inject __builtins__ shadow bindings"
    print("H.1 integration: behavior preserved + __builtins__ shadows present  OK")


def test_h2_acoda():
    src = _apply_and_check('apply_acoda', '_acoda', 'acoda_seed', 'H.2 acoda')
    assert '_br_acoda' in src, "H.2 should inject _br_acoda dispatch function"
    # The pass now uses a dispatch FUNCTION (call form), not a table subscript.
    assert '_br_acoda(' in src, "H.2 should emit _br_acoda(...)() dispatch calls"
    print("H.2 integration: behavior preserved + _br_acoda dispatch present  OK")


def test_h3_metamorphic():
    src = _apply_and_check('apply_metamorphic', '_metamorphic',
                           'metamorphic_seed', 'H.3 metamorphic')
    assert '_br_mut' in src, "H.3 should inject _br_mut dead-junk targets"
    # shard generator present
    from _metamorphic import gen_metamorphic_shard
    shard = gen_metamorphic_shard(_Ctx())
    assert '_br_structural_mutate' in shard
    print("H.3 integration: behavior preserved + _br_mut targets + shard  OK")


def test_h4_style_randomizer():
    src = _apply_and_check('apply_style_randomizer', '_style_randomizer',
                           'style_seed', 'H.4 style')
    # byte-different layout from the fixture (whitespace/comment shuffle)
    assert src != FIXTURE_SRC, "H.4 should change source layout"
    print("H.4 integration: behavior preserved + layout byte-different  OK")


def test_h5_branchless():
    src = _apply_and_check('apply_branchless', '_branchless',
                           'branchless_seed', 'H.5 branchless')
    print("H.5 integration: behavior preserved  OK")


def test_h6_bloom():
    src = _apply_and_check('apply_bloom_obf', '_bloom_obf',
                           'bloom_seed', 'H.6 bloom')
    assert '_br_bloom' in src, "H.6 should inject _br_bloom filter"
    print("H.6 integration: behavior preserved + _br_bloom filter present  OK")


def test_h7_dag_cff():
    src = _apply_and_check('apply_dag_cff', '_dag_cff',
                           'dag_cff_seed', 'H.7 DAG-CFF')
    # H.7 only transforms LINEAR bodies; the fixture's functions are
    # recursive/looping, so the state vars may not appear.  Behavior
    # preservation (checked in _apply_and_check) is the real gate.
    print("H.7 integration: behavior preserved (DAG-CFF, no linear bodies in fixture)  OK")


def test_h8_selfcheck_cf():
    src = _apply_and_check('apply_selfcheck_cf', '_selfcheck_cf',
                           'selfcheck_seed', 'H.8 selfcheck-CF')
    # H.8 only instruments LINEAR bodies; the fixture's functions are
    # recursive/looping, so the path-hash var may not appear.  Behavior
    # preservation is the real gate.
    print("H.8 integration: behavior preserved (selfcheck-CF, no linear bodies in fixture)  OK")


def test_h9_fss():
    src = _apply_and_check('apply_fss', '_fss', 'fss_seed', 'H.9 FSS')
    print("H.9 integration: behavior preserved  OK")


def test_h10_tls_callback():
    """H.10 is a native PE post-build patcher; delegate to its smoke test."""
    import subprocess
    r = subprocess.run([sys.executable, '-c',
                        'import sys; sys.argv=["x"]; '
                        'import _tls_callback; _tls_callback._smoke()'],
                       cwd=_HERE, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"H.10 smoke failed:\n{r.stdout}\n{r.stderr}"
    assert 'H.10 SMOKE: PASS' in r.stdout, f"H.10 no PASS marker:\n{r.stdout}"
    print("H.10 integration: TLS callback smoke (6 cases) PASS  OK")


def test_h11_exc_table_vm():
    """H.11 is a native C VM; delegate to its smoke test."""
    import subprocess
    r = subprocess.run([sys.executable, '_exc_table_vm_test.py'],
                       cwd=_HERE, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"H.11 smoke failed:\n{r.stdout}\n{r.stderr}"
    assert 'H.11 SMOKE: PASS' in r.stdout, f"H.11 no PASS marker:\n{r.stdout}"
    print("H.11 integration: exc-table VM smoke (fib via SEH) PASS  OK")


# --- Combined pass test -------------------------------------------------------

def test_combined_all_nine():
    """Apply all 9 Python-AST passes in the declared order (later-declared runs
    earlier, mirroring bedrock_obfuscator.py:6032-6042 reverse-stack ordering) and
    verify behavior is preserved end-to-end."""
    # Declaration order in the plan: H.1 -> H.2 -> H.5 -> H.6 -> H.4 -> H.7
    # -> H.8 -> H.9 -> H.3.  Reverse-stack means H.3 runs first, H.1 last.
    # For the integration test we apply them in DECLARATION order (the order
    # they were built) -- composition is commutative for behavior preservation
    # (each pass is behavior-preserving on its own), so order doesn't affect
    # the behavioral gate; it only affects the obfuscated structure.
    import importlib
    passes = [
        ('apply_identifier_poison', '_identifier_poison'),
        ('apply_acoda', '_acoda'),
        ('apply_branchless', '_branchless'),
        ('apply_bloom_obf', '_bloom_obf'),
        ('apply_dag_cff', '_dag_cff'),
        ('apply_selfcheck_cf', '_selfcheck_cf'),
        ('apply_fss', '_fss'),
        ('apply_metamorphic', '_metamorphic'),
    ]
    tree = ast.parse(FIXTURE_SRC)
    ctx = _Ctx()
    for fn_name, mod_name in passes:
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, fn_name)
        tree = fn(tree, ctx)
        ast.fix_missing_locations(tree)
    # style randomizer runs last on the unparsed source (it's source-level)
    from _style_randomizer import apply_style_randomizer
    final_src = apply_style_randomizer(ast.unparse(tree), ctx)
    # final parse + exec
    final_tree = ast.parse(final_src)
    ns = {}
    exec(compile(ast.Module(body=final_tree.body, type_ignores=[]),
                 '<combined>', 'exec'), ns)
    _assert_behavior(ns, 'combined-all-9')
    # the combined source should be substantially different from the fixture
    assert len(final_src) > len(FIXTURE_SRC), \
        "combined obf should be larger than the fixture"
    print(f"H.12 combined-9: all 9 Python passes composed; behavior preserved  OK")
    return final_src


# --- Leak gate ----------------------------------------------------------------

# Markers that must NEVER appear in Phase H module sources or combined output.
# (The obfuscator's master seed and the VM's derived key are Phase G concerns;
# Phase H passes are pure-transformations and must not embed any key material.)
_FORBIDDEN_MARKERS = [
    b'-----BEGIN PRIVATE KEY-----',
    b'-----BEGIN ED25519 PRIVATE KEY-----',
    b'_vm_derive_key',         # the local key-derivation call (Phase G internal)
    b'__H_MASTER_SEED__',      # the master-seed global marker
]


def test_leak_gate(combined_src):
    """Scan all Phase H module sources + the combined obfuscated output for
    forbidden key/seed markers.  The master seed and per-VM key are Phase G
    concerns; Phase H passes are pure AST/source transforms and must not
    embed or leak them."""
    violations = []
    # 1. Combined obfuscated output.
    combined_bytes = combined_src.encode('utf-8', 'ignore')
    for marker in _FORBIDDEN_MARKERS:
        if marker in combined_bytes:
            violations.append(f"combined output: {marker!r}")
    # 2. Each Phase H module source.
    h_modules = [
        '_identifier_poison.py', '_acoda.py', '_metamorphic.py',
        '_style_randomizer.py', '_branchless.py', '_bloom_obf.py',
        '_dag_cff.py', '_selfcheck_cf.py', '_fss.py',
        '_tls_callback.py', '_exc_table_vm.c', '_exc_table_vm_setup.py',
        '_exc_table_vm_test.py',
    ]
    for fname in h_modules:
        path = os.path.join(_HERE, fname)
        if not os.path.exists(path):
            violations.append(f"missing module: {fname}")
            continue
        with open(path, 'rb') as f:
            data = f.read()
        for marker in _FORBIDDEN_MARKERS:
            if marker in data:
                violations.append(f"{fname}: {marker!r}")
    # 3. The master-seed hex string must not appear as a literal in any H module.
    #    (A 32-byte master seed would be a 64-hex-char literal; we don't have a
    #    specific one to scan for, but we assert no module defines a 64-hex-char
    #    string constant that looks like a seed -- heuristic.)
    import re
    seed_re = re.compile(rb"['\"]([0-9a-f]{64})['\"]")
    for fname in h_modules:
        path = os.path.join(_HERE, fname)
        if not os.path.exists(path):
            continue
        with open(path, 'rb') as f:
            data = f.read()
        for m in seed_re.finditer(data):
            # allow the SHA-256 known-answer test vector comments + the
            # _br_mut 48-hex pattern (those are 48, not 64).  A 64-hex literal
            # in a Phase H module is suspicious -- flag it.
            violations.append(f"{fname}: 64-hex literal (possible seed): {m.group(1)[:16].decode()}...")
    assert not violations, "leak gate violations:\n  " + "\n  ".join(violations)
    print(f"H.12 leak gate: {len(h_modules)} modules + combined output scanned; "
          f"no forbidden markers  OK")


# --- Phase F + G regression ---------------------------------------------------

def test_f_g_regression():
    """Run the Phase F (VM v2) and Phase G (key-release) integration tests to
    confirm the Phase H edits didn't regress them."""
    import subprocess

    # Phase F
    r = subprocess.run([sys.executable, '_vm_v2_test.py'],
                       cwd=_HERE, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"Phase F regression:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    assert 'PASS' in r.stdout, f"Phase F no PASS:\n{r.stdout[-1500:]}"
    print("H.12 Phase F regression: VM v2 smoke still PASS  OK")

    # Phase G
    r = subprocess.run([sys.executable, '_phase_g_test.py'],
                       cwd=_HERE, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"Phase G regression:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    assert 'PHASE G INTEGRATION TEST: PASS' in r.stdout, \
        f"Phase G no PASS:\n{r.stdout[-1500:]}"
    print("H.12 Phase G regression: key-release smoke still PASS  OK")


# --- Runner -------------------------------------------------------------------

def run_all():
    print("=" * 70)
    print("Phase H (Layer 6) Integration Test -- Esoteric + anti-pattern")
    print("=" * 70)
    print()
    # Individual passes
    test_h1_identifier_poison()
    test_h2_acoda()
    test_h3_metamorphic()
    test_h4_style_randomizer()
    test_h5_branchless()
    test_h6_bloom()
    test_h7_dag_cff()
    test_h8_selfcheck_cf()
    test_h9_fss()
    test_h10_tls_callback()
    test_h11_exc_table_vm()
    print()
    # Combined
    combined = test_combined_all_nine()
    print()
    # Leak gate
    test_leak_gate(combined)
    print()
    # F + G regression
    test_f_g_regression()
    print()
    print("=" * 70)
    print("PHASE H INTEGRATION TEST: PASS")
    print("=" * 70)


if __name__ == "__main__":
    run_all()
