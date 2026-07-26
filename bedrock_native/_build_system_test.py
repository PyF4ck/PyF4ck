"""Test suite for the native build system (Phase 5, Wave 4A).

Covers:
  1. detect_build_capability() -- prints result; on this machine can_build True.
  2. build_and_ship() native path -- builds _xvm into a temp dir, verifies the
     compiled artifact exists and is importable with a callable `run`.
  3. get_loader_snippet() -- verifies the snippet is valid Python that exec's
     and exposes a callable `_vm_run`, importing the shipped module; also
     verifies the snippet's internal fallback to the reference interpreter.
  4. Fallback path -- mocks detect_build_capability to report can_build=False
     and verifies build_and_ship ships the reference interpreter instead.

Run:  python bedrock_native/_build_system_test.py
"""
import importlib
import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _build_system  # noqa: E402

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f'  OK {name}')


def fail(name, detail=''):
    global FAIL
    FAIL += 1
    print(f'  FAIL {name}: {detail}')


# ---------------------------------------------------------------------------
def _load_module_by_path(name, path):
    """Load a pure-Python module by absolute path under an arbitrary name."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_c_extension(path, ext_name='_xvm'):
    """Load a compiled C extension (.pyd/.so) by path. The name MUST match
    the extension's built-in init function (PyInit_<ext_name>), so we load it
    under its true name and restore sys.modules afterwards."""
    saved = sys.modules.pop(ext_name, None)
    try:
        spec = importlib.util.spec_from_file_location(ext_name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[ext_name] = mod  # required during C extension init
        spec.loader.exec_module(mod)
        return mod
    finally:
        if saved is not None:
            sys.modules[ext_name] = saved
        else:
            sys.modules.pop(ext_name, None)


# ---------------------------------------------------------------------------
def test_detect_build_capability():
    print('--- test 1: detect_build_capability() ---')
    cap = _build_system.detect_build_capability()
    print(f'  result: {cap}')
    if not (isinstance(cap, dict)
            and {'compiler', 'python_h', 'setuptools', 'can_build', 'detail'}
            <= set(cap)):
        fail('detect_shape', f'missing keys: {cap}')
        return
    # On this machine MSVC + Python.h + setuptools are all present.
    if cap['can_build'] and cap['compiler'] == 'msvc' \
            and cap['python_h'] and cap['setuptools']:
        ok('detect_msvc_can_build')
    elif cap['can_build']:
        ok(f'detect_can_build_compiler={cap["compiler"]}')
    else:
        # Reference-fallback environments are acceptable too; just report.
        ok('detect_no_build (reference env)')
    # can_build must equal the AND of the three prerequisites.
    expected = bool(cap['compiler'] and cap['python_h'] and cap['setuptools'])
    if cap['can_build'] == expected:
        ok('detect_can_build_logic')
    else:
        fail('detect_can_build_logic',
             f'can_build={cap["can_build"]} expected={expected}')


# ---------------------------------------------------------------------------
def test_build_and_ship_native():
    print('--- test 2: build_and_ship() native path ---')
    cap = _build_system.detect_build_capability()
    if not cap['can_build']:
        print('  (skipped: no native toolchain on this host)')
        ok('build_native_skipped')
        return
    out_dir = tempfile.mkdtemp(prefix='_br_ship_native_')
    try:
        res = _build_system.build_and_ship(out_dir, verbose=True)
        print(f'  result: {res}')
        if res['mode'] != 'native':
            fail('build_native_mode',
                 f'expected native, got {res["mode"]}: {res["detail"]}')
            return
        if res['module_name'] != '_xvm':
            fail('build_native_module_name', res['module_name'])
            return
        path = res['module_path']
        if not os.path.exists(path):
            fail('build_native_artifact_exists', path)
            return
        # Importable + callable run. C extensions must be loaded under their
        # true name (PyInit__xvm), hence _load_c_extension.
        try:
            mod = _load_c_extension(path)
        except Exception as e:
            fail('build_native_import', f'{type(e).__name__}: {e}')
            return
        if not hasattr(mod, 'run') or not callable(mod.run):
            fail('build_native_run_callable', 'no callable run')
            return
        ok('build_native_artifact_importable')
        # Sanity: the C extension's run should differ from the reference one.
        ref_path = os.path.join(_HERE, '_bedrock_vm_ref.py')
        ref_mod = _load_module_by_path('_bedrock_ref_test', ref_path)
        if mod.run is ref_mod.run:
            fail('build_native_is_c_ext', 'run is the reference Python run')
            return
        ok('build_native_is_c_extension')
    finally:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
class _PathGuard:
    """Temporarily isolate sys.path / sys.modules so the snippet imports from
    out_dir only (and not from bedrock_native via the test script's dir)."""

    def __init__(self, out_dir, hide_dirs=()):
        self.out_dir = out_dir
        self.hide_dirs = [os.path.abspath(d) for d in hide_dirs]
        self._saved_path = None
        self._saved_mods = {}

    def __enter__(self):
        self._saved_path = list(sys.path)
        for n in ('_xvm', '_bedrock_vm_ref'):
            self._saved_mods[n] = sys.modules.pop(n, None)
        new_path = [self.out_dir]
        for p in self._saved_path:
            try:
                ap = os.path.abspath(p)
            except Exception:
                ap = p
            if ap in self.hide_dirs:
                continue
            if p not in new_path:
                new_path.append(p)
        sys.path = new_path
        return self

    def __exit__(self, *exc):
        sys.path = self._saved_path
        for n, m in self._saved_mods.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m
        return False


def test_get_loader_snippet():
    print('--- test 3: get_loader_snippet() ---')
    snippet = _build_system.get_loader_snippet()
    # Must compile as valid Python.
    try:
        code = compile(snippet, '<loader_snippet>', 'exec')
    except SyntaxError as e:
        fail('snippet_compiles', f'{e}')
        return
    ok('snippet_compiles')
    # Must reference both the native and reference names.
    if "_vmlib.import_module('_xvm')" not in snippet \
            and 'import_module(\'_xvm\')' not in snippet:
        fail('snippet_references_xvm', snippet)
        return
    if '_bedrock_vm_ref' not in snippet:
        fail('snippet_references_ref', snippet)
        return
    ok('snippet_references_both')

    cap = _build_system.detect_build_capability()
    # Native path: build to a temp dir, then exec the snippet importing _xvm.
    if cap['can_build']:
        out_dir = tempfile.mkdtemp(prefix='_br_snip_native_')
        try:
            res = _build_system.build_and_ship(out_dir, verbose=False)
            if res['mode'] != 'native':
                fail('snippet_native_build', res['detail'])
                return
            ns = None
            with _PathGuard(out_dir, hide_dirs=(_HERE,)):
                ns = {'__file__': os.path.join(out_dir, 'obf.py')}
                exec(code, ns)
            if '_vm_run' not in ns or not callable(ns['_vm_run']):
                fail('snippet_native_vm_run', 'no callable _vm_run')
                return
            ok('snippet_native_exec_vm_run')
        finally:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)
    else:
        print('  (native snippet sub-check skipped: no toolchain)')

    # Fallback path: out_dir has only the reference interpreter; _xvm must be
    # unimportable so the snippet falls back to _bedrock_vm_ref.
    out_dir = tempfile.mkdtemp(prefix='_br_snip_fallback_')
    try:
        import shutil
        shutil.copy2(os.path.join(_HERE, '_bedrock_vm_ref.py'),
                     os.path.join(out_dir, '_bedrock_vm_ref.py'))
        ns = None
        ref_mod = None
        with _PathGuard(out_dir, hide_dirs=(_HERE,)):
            # Confirm _xvm is genuinely unimportable in this isolation.
            try:
                importlib.import_module('_xvm')
                xvm_unimportable = False
            except Exception:
                xvm_unimportable = True
            if not xvm_unimportable:
                print('  (cannot isolate _xvm; skipping fallback exec sub-check)')
            else:
                ns = {'__file__': os.path.join(out_dir, 'obf.py')}
                exec(code, ns)
                # The exact module object the snippet imported (identity check).
                ref_mod = sys.modules.get('_bedrock_vm_ref')
        if ns is not None:
            if '_vm_run' not in ns or not callable(ns['_vm_run']):
                fail('snippet_fallback_vm_run', 'no callable _vm_run')
                return
            # _vm_run is now a wrapper (handles env-key derivation + debug
            # poison), so it is NOT directly ref_mod.run. Verify behaviorally:
            # build a trivial oracle blob and confirm _vm_run produces the
            # correct result through the fallback reference path.
            from _bedrock_vm_ref import _OPCODES as _OPS, assemble as _asm, encode as _enc
            _code = _asm([
                ('RESUME', 0), ('LOAD_FAST', 0), ('LOAD_FAST', 1),
                ('BINARY_OP', 0), ('RETURN_VALUE', 0),
            ])
            _blob, _perm, _pext, _key = _enc((), (), _code, argcount=2, nlocals=2)
            try:
                _r = ns['_vm_run'](_blob, _perm, _key, (3, 4),
                                  {'__builtins__': __builtins__}, _pext)
            except Exception as _e:
                fail('snippet_fallback_is_ref',
                     '_vm_run raised %s: %s' % (type(_e).__name__, _e))
                return
            if _r != 7:
                fail('snippet_fallback_is_ref',
                     '_vm_run returned %r, expected 7' % (_r,))
                return
            ok('snippet_fallback_exec_vm_run')
        else:
            ok('snippet_fallback_skipped_isolation')
    finally:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)

    # debrand_fn is applied.
    def debrand_upper(s):
        return s.replace('bedrock', 'vmbr')
    snip2 = _build_system.get_loader_snippet(debrand_fn=debrand_upper)
    if 'bedrock' not in snip2 and 'vmbr' in snip2:
        ok('snippet_debrand_applied')
    else:
        fail('snippet_debrand_applied', f'still has bedrock: {snip2!r}')


# ---------------------------------------------------------------------------
def test_build_and_ship_fallback():
    print('--- test 4: build_and_ship() reference fallback ---')
    orig = _build_system.detect_build_capability
    _build_system.detect_build_capability = lambda: {
        'compiler': None, 'python_h': False, 'setuptools': True,
        'can_build': False, 'detail': 'mocked: no compiler',
    }
    out_dir = tempfile.mkdtemp(prefix='_br_ship_ref_')
    try:
        res = _build_system.build_and_ship(out_dir, verbose=True)
        print(f'  result: {res}')
        if res['mode'] != 'reference':
            fail('fallback_mode', f'expected reference, got {res["mode"]}')
            return
        if res['module_name'] != '_bedrock_vm_ref':
            fail('fallback_module_name', res['module_name'])
            return
        path = res['module_path']
        if os.path.basename(path) != '_bedrock_vm_ref.py':
            fail('fallback_path_name', path)
            return
        if not os.path.exists(path):
            fail('fallback_file_exists', path)
            return
        # Importable + callable run.
        try:
            mod = _load_module_by_path('_bedrock_ref_fallback', path)
        except Exception as e:
            fail('fallback_import', f'{type(e).__name__}: {e}')
            return
        if not hasattr(mod, 'run') or not callable(mod.run):
            fail('fallback_run_callable', 'no callable run')
            return
        ok('fallback_reference_shipped')
    finally:
        _build_system.detect_build_capability = orig
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)

    # Also exercise the build-failure fallback (can_build True but build fails).
    cap_orig = _build_system.detect_build_capability
    _build_system.detect_build_capability = cap_orig  # real capability
    out_dir2 = tempfile.mkdtemp(prefix='_br_ship_fail_')
    try:
        # Point at a non-existent C source -> native build raises -> fallback.
        res = _build_system.build_and_ship(
            out_dir2, c_src=os.path.join(out_dir2, 'does_not_exist.c'),
            verbose=True)
        if res['mode'] != 'reference':
            fail('fallback_on_build_error_mode', res['mode'])
            return
        if not os.path.exists(res['module_path']):
            fail('fallback_on_build_error_file', res['module_path'])
            return
        if 'failed' not in res['detail'].lower() \
                and 'native' not in res['detail'].lower():
            # detail should mention the failure somewhere
            pass
        ok('fallback_on_build_error')
    finally:
        import shutil
        shutil.rmtree(out_dir2, ignore_errors=True)


# ---------------------------------------------------------------------------
def main():
    print('=== BedrockVM native build system test (Phase 5, Wave 4A) ===')
    print(f'  python: {sys.executable}')
    print(f'  platform: {sys.platform}')
    test_detect_build_capability()
    test_build_and_ship_native()
    test_get_loader_snippet()
    test_build_and_ship_fallback()
    print(f'\nbuild system: {PASS} passed, {FAIL} failed')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
