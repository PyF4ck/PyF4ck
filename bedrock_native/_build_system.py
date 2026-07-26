"""Native build system for the BedrockVM obfuscator (Phase 5, Wave 4A).

Standalone module that the main obfuscator calls to build and deploy the C
interpreter extension (``_xvm``) alongside the obfuscated output. When no
compiler / headers / setuptools are available, it transparently falls back to
shipping the pure-Python reference interpreter (``_bedrock_vm_ref``).

Public API
----------
detect_build_capability() -> dict
    Probe the host for the ability to build the C extension.

build_and_ship(out_dir, ...) -> dict
    Build the C extension and copy it to ``out_dir`` (native mode), or copy the
    reference interpreter there instead (reference mode). Never raises on build
    failure: it falls back to the reference interpreter with a warning.

get_loader_snippet(module_name='_xvm', debrand_fn=None) -> str
    Return the Python source the loader embeds into the obfuscated output to
    import the shipped module and expose ``_vm_run``.

Design notes
------------
* Detection uses ``vswhere.exe`` on Windows (MSVC) and ``shutil.which`` on
  Unix (gcc/cc/clang). The abstract ``distutils.ccompiler.new_compiler`` call
  succeeds even without a real compiler installed, so it is not a reliable
  signal on its own; the platform-specific real-toolchain checks are.
* The build runs ``<python> setup.py build_ext --inplace`` in a throwaway temp
  directory. ``setuptools`` resolves ``sources`` relative to the *cwd*, so the
  subprocess cwd MUST be the temp dir (not the setup.py's parent). The compiled
  artifact is globbed (``_xvm*.pyd`` / ``_xvm*.so``) and copied to ``out_dir``
  preserving its full ABI tag so CPython can import it.
* The reference fallback is always available as long as the reference source
  file exists, so the obfuscator build never crashes.
"""
from __future__ import annotations

import glob
import hashlib
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile

__all__ = ['detect_build_capability', 'build_and_ship', 'get_loader_snippet']

# Directory this module lives in (bedrock_native/).
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_C_SRC = os.path.join(_HERE, '_bedrock_vm.c')
_DEFAULT_REF_SRC = os.path.join(_HERE, '_bedrock_vm_ref.py')

# Default reference module name shipped alongside the obfuscated output.
_DEFAULT_REF_NAME = '_bedrock_vm_ref'


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------
def _detect_msvc():
    """Return 'msvc' if MSVC VC tools are installed, else None (Windows)."""
    program_files_x86 = os.environ.get('ProgramFiles(x86)') or r'C:\Program Files (x86)'
    vswhere = os.path.join(program_files_x86, 'Microsoft Visual Studio',
                           'Installer', 'vswhere.exe')
    if os.path.exists(vswhere):
        try:
            proc = subprocess.run(
                [vswhere, '-latest', '-products', '*',
                 '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                 '-property', 'installationPath'],
                capture_output=True, text=True, timeout=20)
            if proc.returncode == 0 and proc.stdout.strip():
                return 'msvc'
        except (OSError, subprocess.SubprocessError):
            pass
    # Fallback: cl.exe already on PATH (e.g. inside an activated vcvars shell).
    if shutil.which('cl'):
        return 'msvc'
    return None


def _detect_unix_compiler():
    """Return 'gcc' or 'clang' if a C compiler is on PATH, else None."""
    for tool, label in (('gcc', 'gcc'), ('clang', 'clang'), ('cc', 'gcc')):
        if shutil.which(tool):
            return label
    return None


def detect_build_capability() -> dict:
    """Detect whether we can build the C extension.

    Returns a dict with keys:
      - 'compiler': 'msvc' | 'gcc' | 'clang' | None
      - 'python_h': bool (Python.h found)
      - 'setuptools': bool
      - 'can_build': bool (compiler AND python_h AND setuptools all present)
      - 'detail': str (human-readable status)
    """
    # setuptools
    try:
        import setuptools  # noqa: F401
        has_setuptools = True
        setuptools_ver = getattr(setuptools, '__version__', '?')
    except Exception:
        has_setuptools = False
        setuptools_ver = None

    # Python.h
    inc = sysconfig.get_path('include') or ''
    has_python_h = bool(inc) and os.path.exists(os.path.join(inc, 'Python.h'))

    # compiler
    if sys.platform == 'win32':
        compiler = _detect_msvc()
    else:
        compiler = _detect_unix_compiler()

    can_build = bool(compiler and has_python_h and has_setuptools)

    parts = []
    parts.append(f"compiler={compiler!r}")
    parts.append(f"python_h={has_python_h}")
    if inc:
        parts.append(f"include={inc}")
    if has_setuptools:
        parts.append(f"setuptools={has_setuptools} (v{setuptools_ver})")
    else:
        parts.append(f"setuptools={has_setuptools}")
    detail = ('can build native extension: ' if can_build
              else 'cannot build native extension: ') + '; '.join(parts)

    return {
        'compiler': compiler,
        'python_h': has_python_h,
        'setuptools': has_setuptools,
        'can_build': can_build,
        'detail': detail,
    }


# ---------------------------------------------------------------------------
# Shipping helpers
# ---------------------------------------------------------------------------
def _ship_reference(out_dir, ref_src, ref_name, verbose, cap, warning=None):
    """Copy the pure-Python reference interpreter to out_dir. Never raises."""
    os.makedirs(out_dir, exist_ok=True)
    dest = os.path.join(out_dir, ref_name + '.py')
    detail = f"shipped reference interpreter ({ref_name}.py)"
    if not cap.get('can_build'):
        detail += f" [no native toolchain: {cap.get('detail', '')}]"
    if warning:
        detail += f" [native build failed: {warning}]"
    # Avoid copying a file onto itself.
    if os.path.abspath(dest) == os.path.abspath(ref_src):
        if verbose:
            print(f"[build_and_ship] reference mode (in-place, no copy) -> {dest}")
        return {
            'mode': 'reference',
            'module_name': ref_name,
            'module_path': dest,
            'ext_hash': None,  # no .pyd shipped in reference mode
            'detail': detail,
        }
    shutil.copy2(ref_src, dest)
    if verbose:
        print(f"[build_and_ship] reference mode -> {dest}")
    return {
        'mode': 'reference',
        'module_name': ref_name,
        'module_path': dest,
        'ext_hash': None,  # no .pyd shipped in reference mode
        'detail': detail,
    }


def _build_native_and_ship(out_dir, c_src, ext_name, verbose, cap, ref_src=None, ref_name='_bedrock_vm_ref'):
    """Build the C extension in a temp dir and copy the artifact to out_dir.

    Raises on failure; the caller (build_and_ship) falls back to the reference
    interpreter.
    """
    if not os.path.exists(c_src):
        raise FileNotFoundError(f"C source not found: {c_src}")

    tmpdir = tempfile.mkdtemp(prefix='_bedrock_build_')
    try:
        c_basename = os.path.basename(c_src)

        # C-level hardening: XOR-encode all _DS("...") string literals so
        # no plaintext survives in the compiled .pyd/.so strings window.
        # The preprocessor replaces _DS("literal") with a byte-array form
        # _DS((uint8_t[]){0xAB, ...}, N, 0xKEY).  At runtime the _dec_str
        # helper decrypts into a static buffer.  If the preprocessor import
        # fails, fall back to the plaintext source (build still succeeds).
        try:
            from _obf_c_strings import obfuscate_c_strings
            with open(c_src, 'r', encoding='utf-8') as _cf:
                _c_text = _cf.read()
            _c_obf, _str_key = obfuscate_c_strings(_c_text)
            _obf_path = os.path.join(tmpdir, c_basename)
            with open(_obf_path, 'w', encoding='utf-8') as _cf:
                _cf.write(_c_obf)
            if verbose:
                print(f"[build_and_ship] C strings XOR-encoded (key=0x{_str_key:02x})")
        except Exception as _e:
            if verbose:
                print(f"[build_and_ship] string obf skipped ({_e}), using plaintext")
            shutil.copy2(c_src, os.path.join(tmpdir, c_basename))

        # Compiler flags: optimize + strip symbols for harder RE.
        if sys.platform == 'win32':
            extra_compile = ['/O2', '/GS-']  # optimize, no stack canary
            extra_link = ['/INCREMENTAL:NO']  # deterministic link
        else:
            extra_compile = ['-O2', '-fno-asynchronous-unwind-tables',
                             '-fomit-frame-pointer']
            extra_link = ['-Wl,-s']  # strip symbol table

        # Generate a setup.py mirroring _bedrock_vm_setup.py.
        setup_text = (
            "from setuptools import setup, Extension\n"
            f"setup(name={ext_name!r}, version='0.1',\n"
            f"      ext_modules=[Extension({ext_name!r}, sources=[{c_basename!r}],\n"
            f"        extra_compile_args={extra_compile!r},\n"
            f"        extra_link_args={extra_link!r})])\n"
        )
        with open(os.path.join(tmpdir, 'setup.py'), 'w', encoding='utf-8') as f:
            f.write(setup_text)

        # Run the build. cwd MUST be tmpdir because setuptools resolves
        # `sources` relative to the cwd, not the setup.py location.
        cmd = [sys.executable, 'setup.py', 'build_ext', '--inplace']
        if verbose:
            print(f"[build_and_ship] building native extension in {tmpdir}")
        proc = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"build_ext failed (exit {proc.returncode})\n"
                f"--- stdout ---\n{proc.stdout}\n"
                f"--- stderr ---\n{proc.stderr}"
            )
        if verbose:
            tail = (proc.stdout or '').strip().splitlines()[-3:]
            for line in tail:
                print(f"  | {line}")

        # Locate the compiled artifact. --inplace places it in the tmpdir root.
        if sys.platform == 'win32':
            pattern = ext_name + '*.pyd'
        else:
            pattern = ext_name + '*.so'
        root_hits = glob.glob(os.path.join(tmpdir, pattern))
        if root_hits:
            built = root_hits[0]
        else:
            rec_hits = glob.glob(os.path.join(tmpdir, '**', pattern),
                                 recursive=True)
            if not rec_hits:
                raise RuntimeError(
                    f"build produced no artifact matching {pattern!r} in {tmpdir}\n"
                    f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
                )
            built = rec_hits[0]

        os.makedirs(out_dir, exist_ok=True)
        dest_name = os.path.basename(built)  # keep the full ABI tag
        dest = os.path.join(out_dir, dest_name)
        # Don't copy onto itself (e.g. out_dir is the source build dir).
        if os.path.abspath(dest) != os.path.abspath(built):
            shutil.copy2(built, dest)
        # Compute the SHA-256 of the shipped extension so the loader can
        # verify integrity at runtime (fail-closed when --vm-fallback off).
        # We hash the *destination* bytes (the actual artifact the loader
        # will import), not the temp build artifact.
        try:
            with open(dest, 'rb') as _eh:
                ext_hash = hashlib.sha256(_eh.read()).hexdigest()
        except Exception:
            ext_hash = None
        # The C interpreter delegates generator frames and Frame-in-const
        # (listcomp MAKE_FUNCTION) cases to the pure-Python reference
        # interpreter via PyImport_ImportModule("_bedrock_vm_ref"). We MUST
        # ship the reference alongside the .pyd so those code paths resolve
        # at runtime. (See _bedrock_vm.c lines 320-330 / 410-440.)
        if ref_src and os.path.exists(ref_src):
            ref_dest = os.path.join(out_dir, ref_name + '.py')
            if os.path.abspath(ref_dest) != os.path.abspath(ref_src):
                shutil.copy2(ref_src, ref_dest)
        if verbose:
            print(f"[build_and_ship] native mode -> {dest}")
        return {
            'mode': 'native',
            'module_name': ext_name,
            'module_path': dest,
            'ext_hash': ext_hash,
            'detail': (f"shipped native extension {dest_name} "
                       f"(compiler={cap.get('compiler')})"),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def build_and_ship(out_dir: str, c_src: str = None, ref_src: str = None,
                   verbose: bool = False, ext_name: str = '_xvm',
                   ref_name: str = '_bedrock_vm_ref') -> dict:
    """Build the C extension and ship it to out_dir. Falls back to the
    reference interpreter if no compiler is available (or the build fails).

    Args:
      out_dir: the output directory (where the obfuscated .py will live)
      c_src: path to the C source (default: bedrock_native/_bedrock_vm.c)
      ref_src: path to the reference interpreter (default: bedrock_native/_bedrock_vm_ref.py)
      verbose: print build progress
      ext_name: the extension module name (default '_xvm')
      ref_name: the reference fallback module name (default '_bedrock_vm_ref')

    Returns a dict with keys:
      - 'mode': 'native' | 'reference' (which path was taken)
      - 'module_name': the import name the loader should use ('_xvm' or '_bedrock_vm_ref')
      - 'module_path': the full path to the shipped module file
      - 'ext_hash': SHA-256 hex of the shipped .pyd (native mode) or None (reference)
      - 'detail': str (status/warnings)
    """
    if c_src is None:
        c_src = _DEFAULT_C_SRC
    if ref_src is None:
        ref_src = _DEFAULT_REF_SRC

    cap = detect_build_capability()

    if not cap['can_build']:
        return _ship_reference(out_dir, ref_src, ref_name, verbose, cap)

    try:
        return _build_native_and_ship(out_dir, c_src, ext_name, verbose, cap,
                                      ref_src=ref_src, ref_name=ref_name)
    except Exception as exc:
        # Never crash the obfuscator build: fall back to the reference path.
        if verbose:
            print(f"[build_and_ship] native build failed ({exc!r}); "
                  f"falling back to reference interpreter")
        return _ship_reference(out_dir, ref_src, ref_name, verbose, cap,
                               warning=f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Loader snippet
# ---------------------------------------------------------------------------
def get_loader_snippet(module_name: str = '_xvm', debrand_fn=None, *,
                       ref_fallback_name: str = _DEFAULT_REF_NAME,
                       env_key_on: bool = False,
                       envkey_var: str = '__BedrockEnvKey__',
                       debug_poison: bool = False,
                       poison_fn: str = '__h_poison',
                       vm_fallback: str = 'auto',
                       release_on: bool = False) -> str:
    """Return the Python source snippet that the loader imports the shipped
    module and exposes the VM entry points. The snippet is embedded into the
    obfuscated output.

    If debrand_fn is provided (a callable str->str), apply it to the snippet
    (for Phase 4 anti-meta debranding -- removes 'bedrock' literals). NOTE:
    the caller is responsible for passing already-debranded ``module_name``
    and ``ref_fallback_name`` (the import names must match the shipped
    filenames), so debrand_fn only cleans any *other* residual literals.

    The snippet:
      1. Ensures its own directory is importable (so the shipped module, which
         sits next to the obfuscated output, can be imported).
      2. Tries to import module_name. On failure, the ``vm_fallback`` policy
         applies: 'off' poisons + aborts (fail-closed); 'auto'/'dev' import the
         reference fallback (``ref_fallback_name``). After a successful native
         import, the shipped .pyd/.so is hash-verified against ``_vm_exthash``
         (a post-ship-patched SHA-256). A hash mismatch applies the same
         policy: 'off' aborts, 'auto' warns + falls back, 'dev' silently
         falls back. Reference-mode imports (.py) skip the hash check.
      3. Exposes ``_vm_run`` -- the VM entry point. When --env-key is on it
         re-derives the effective key by XOR-blinding the raw 32-byte key with
         the runtime env-key digest (same pattern as the capsule runtime).
         When --debug-poison is on it catches VM exceptions and routes them
         through the poison function (silent inert) instead of propagating.
      4. Exposes ``_vm_bind(args, kw, varnames)`` -- binds kwargs into the
         positional tuple using the frame's varnames (the C extension's
         ``run()`` does not take a separate kw dict).
      5. Is self-contained (stdlib + the shipped module only).

    The caller (apply_native_vm) emits ``_vm_perm``, ``_vm_key`` (raw 32
    bytes), ``_vm_perm_ext`` as module-level constants near the VM-compiled
    functions, and a ``_vm_g()`` helper that builds a globals dict augmented
    with builtins (the VM's LOAD_GLOBAL has no builtins fallback).
    """
    # NOTE: envkey_expr uses _vm_globals (the bound builtin) rather than bare
    # `globals()` because obf_builtins renames bare `globals` Name nodes to
    # the obfuscated scope-dict access form. The bound helper survives.
    envkey_expr = "_vm_globals().get(%r, b'')" % envkey_var
    # Bind the builtins the loader uses from __builtins__ (which is never
    # renamed by obf_builtins -- it only rewrites bare ``Name`` references to
    # the obfuscated scope dict). Binding them to private names here means the
    # loader keeps working even after obf_builtins mutates ``range``/``bytes``
    # /``zip``/``globals``/``len``/``max``/``tuple``/``enumerate`` etc. in the
    # surrounding module.
    bind_builtins = (
        "_vm_bb = __builtins__\n"
        "if isinstance(_vm_bb, dict):\n"
        "    _vm_range = _vm_bb['range']\n"
        "    _vm_bytes = _vm_bb['bytes']\n"
        "    _vm_zip = _vm_bb['zip']\n"
        "    _vm_globals = _vm_bb['globals']\n"
        "    _vm_len = _vm_bb['len']\n"
        "    _vm_max = _vm_bb['max']\n"
        "    _vm_tuple = _vm_bb['tuple']\n"
        "    _vm_enumerate = _vm_bb['enumerate']\n"
        "else:\n"
        "    _vm_range = _vm_bb.range\n"
        "    _vm_bytes = _vm_bb.bytes\n"
        "    _vm_zip = _vm_bb.zip\n"
        "    _vm_globals = _vm_bb.globals\n"
        "    _vm_len = _vm_bb.len\n"
        "    _vm_max = _vm_bb.max\n"
        "    _vm_tuple = _vm_bb.tuple\n"
        "    _vm_enumerate = _vm_bb.enumerate\n"
    )
    if env_key_on:
        derive = (
            "def _vm_derive_key(_raw):\n"
            "    _env = " + envkey_expr + "\n"
            "    if not _env:\n"
            "        return _raw\n"
            "    _env32 = _vm_bytes((_env[i % _vm_len(_env)] if _env else 0) for i in _vm_range(32))\n"
            "    return _vm_bytes((_a ^ _b) for _a, _b in _vm_zip(_raw, _env32))\n"
        )
    else:
        derive = (
            "def _vm_derive_key(_raw):\n"
            "    return _raw\n"
        )
    if debug_poison:
        run_wrap = (
            "def _vm_run(_blob, _perm, _key, _args, _g, _perm_ext):\n"
            "    try:\n"
            "        return _vm_mod.run(_blob, _perm, _vm_derive_key(_key), _args, _g, _perm_ext)\n"
            "    except Exception:\n"
            "        try:\n"
            "            " + poison_fn + "('vm_fail', 7)\n"
            "        except Exception:\n"
            "            pass\n"
            "        return None\n"
        )
    else:
        run_wrap = (
            "def _vm_run(_blob, _perm, _key, _args, _g, _perm_ext):\n"
            "    return _vm_mod.run(_blob, _perm, _vm_derive_key(_key), _args, _g, _perm_ext)\n"
        )
    # Phase G (Layer 3): when key-release mode is on, the artifact ships a
    # _vm_key_handle tuple INSTEAD OF the raw _vm_key bytes. The loader
    # resolves the key on first VM call by importing _key_release_client
    # (which ships alongside the artifact, like _xvm.pyd) and calling
    # get_key(KeyHandle.from_tuple(handle)). The resolved key is cached in
    # a module-global so subsequent calls skip the fetch. This replaces the
    # _vm_derive_key indirection (env-key XOR) -- key-release and env-key
    # are mutually exclusive in the MVP (key-release is the stronger,
    # machine-attested mechanism).
    if release_on:
        # The env-key _vm_derive_key is unused in release mode -- the key
        # arrives already machine-bound from the attested server fetch.
        derive = ""
        if debug_poison:
            run_wrap = (
                "_vm_resolved_key = None\n"
                "def _vm_get_key(_handle):\n"
                "    global _vm_resolved_key\n"
                "    if _vm_resolved_key is None:\n"
                "        from _key_release_client import get_key, KeyHandle\n"
                "        _vm_resolved_key = get_key(KeyHandle.from_tuple(_handle))\n"
                "    return _vm_resolved_key\n"
                "def _vm_run(_blob, _perm, _handle, _args, _g, _perm_ext):\n"
                "    try:\n"
                "        return _vm_mod.run(_blob, _perm, _vm_get_key(_handle), _args, _g, _perm_ext)\n"
                "    except Exception:\n"
                "        try:\n"
                "            " + poison_fn + "('vm_fail', 7)\n"
                "        except Exception:\n"
                "            pass\n"
                "        return None\n"
            )
        else:
            run_wrap = (
                "_vm_resolved_key = None\n"
                "def _vm_get_key(_handle):\n"
                "    global _vm_resolved_key\n"
                "    if _vm_resolved_key is None:\n"
                "        from _key_release_client import get_key, KeyHandle\n"
                "        _vm_resolved_key = get_key(KeyHandle.from_tuple(_handle))\n"
                "    return _vm_resolved_key\n"
                "def _vm_run(_blob, _perm, _handle, _args, _g, _perm_ext):\n"
                "    return _vm_mod.run(_blob, _perm, _vm_get_key(_handle), _args, _g, _perm_ext)\n"
            )
    # _vm_g() builds the globals dict the VM sees: the live module globals
    # augmented with builtins (the VM's LOAD_GLOBAL has no builtins fallback,
    # so any builtin the compiled function references -- range, print, sum,
    # len, ... -- must resolve here). We merge __builtins__'s exposed dict
    # into a shallow copy of globals() so name lookups succeed.
    vm_g = (
        "def _vm_g():\n"
        "    _g = dict(_vm_globals())\n"
        "    _bb = __builtins__\n"
        "    if isinstance(_bb, dict):\n"
        "        _g.update(_bb)\n"
        "    else:\n"
        "        _g.update(_bb.__dict__)\n"
        "    return _g\n"
    )
    # _vm_b85decode: bound at loader init so wrappers don't depend on a bare
    # `base64` Name being in scope (the obfuscator may strip/relocate imports).
    vm_b85 = (
        "_vm_b64mod = __import__('base64')\n"
        "_vm_b85decode = _vm_b64mod.b85decode\n"
    )
    snippet = (
        "import sys as _vmsys, os as _vmos, importlib as _vmlib\n"
        # Compute candidate directories: __file__'s dir, sys.argv[0]'s dir,
        # and cwd. Inside an exec'd marshalled blob __file__ may be a
        # synthetic compile name, so we also try argv[0] and cwd as
        # fallbacks and add ALL of them to sys.path.
        "_vm_cands = []\n"
        "for _vm_src in (__file__,):\n"
        "    try:\n"
        "        _vm_cands.append(_vmos.path.dirname(_vmos.path.abspath(_vm_src)))\n"
        "    except Exception:\n"
        "        pass\n"
        "try:\n"
        "    _vm_cands.append(_vmos.path.dirname(_vmos.path.abspath(_vmsys.argv[0])))\n"
        "except Exception:\n"
        "    pass\n"
        "try:\n"
        "    _vm_cands.append(_vmos.getcwd())\n"
        "except Exception:\n"
        "    pass\n"
        "for _c in _vm_cands:\n"
        "    if _c and _c not in _vmsys.path:\n"
        "        _vmsys.path.insert(0, _c)\n"
        + vm_b85
        + bind_builtins
        # _vm_fallback policy (off = fail-closed, auto = warn + reference,
        # dev = silent reference). _vm_exthash is read from the plaintext
        # header constant __VM_EXTHASH__ (patched post-ship by the obfuscator
        # with the shipped .pyd's SHA-256). The sentinel survives when no
        # hash is available (reference mode / injection failed / older build).
        + ("_vm_fallback = %r\n" % vm_fallback)
        + "_vm_exthash = _vm_globals().get('__VM_EXTHASH__', '')\n"
        "_vm_imp_err = None\n"
        "try:\n"
        f"    _vm_mod = _vmlib.import_module({module_name!r})\n"
        "except Exception as _vm_e:\n"
        "    _vm_imp_err = _vm_e\n"
        "    _vm_mod = None\n"
        # Integrity verification + fallback policy. Runs when the native
        # import either failed OR succeeded (we verify the .pyd hash in the
        # success path). Reference imports (.py) skip the hash check. The
        # ext hash is only verified when it's a valid 64-char hex string
        # (the sentinel/empty value skips verification, trusting the import).
        "_vm_verified = False\n"
        "if _vm_mod is not None:\n"
        "    _vm_fp = getattr(_vm_mod, '__file__', None)\n"
        "    if _vm_fp and (_vm_fp.endswith('.pyd') or _vm_fp.endswith('.so')):\n"
        "        if _vm_exthash and _vm_len(_vm_exthash) == 64 and all(_c in '0123456789abcdef' for _c in _vm_exthash):\n"
        "            try:\n"
        "                import hashlib as _vm_h\n"
        "                with open(_vm_fp, 'rb') as _vf:\n"
        "                    _vm_actual = _vm_h.sha256(_vf.read()).hexdigest()\n"
        "                _vm_verified = (_vm_actual == _vm_exthash)\n"
        "            except Exception:\n"
        "                _vm_verified = False\n"
        "        else:\n"
        "            _vm_verified = True  # no valid hash shipped, trust the import\n"
        "    else:\n"
        "        _vm_verified = True  # reference .py import, no integrity check\n"
        "if _vm_mod is None or not _vm_verified:\n"
        "    if _vm_fallback == 'off':\n"
        "        try:\n"
        "            " + poison_fn + "('vm_ext_tamper', 9)\n"
        "        except Exception:\n"
        "            pass\n"
        "        raise SystemExit('VM extension integrity check failed')\n"
        "    else:\n"
        "        if _vm_fallback == 'auto':\n"
        "            import sys as _vm_es\n"
        "            _vm_es.stderr.write('VM extension integrity check failed, falling back to reference\\n')\n"
        "        try:\n"
        f"            _vm_mod = _vmlib.import_module({ref_fallback_name!r})\n"
        "        except Exception:\n"
        "            if _vm_imp_err is not None:\n"
        "                raise _vm_imp_err\n"
        "            raise\n"
        + derive
        + "def _vm_bind(args, kw, varnames):\n"
        "    if not kw:\n"
        "        return _vm_tuple(args)\n"
        "    if not varnames:\n"
        "        return _vm_tuple(args)\n"
        "    nargs = _vm_len(args)\n"
        "    bound = list(args) + [None] * _vm_max(0, _vm_len(varnames) - nargs)\n"
        "    for i, vn in _vm_enumerate(varnames):\n"
        "        if vn in kw and i < _vm_len(bound):\n"
        "            bound[i] = kw[vn]\n"
        "    return _vm_tuple(bound)\n"
        + vm_g
        + run_wrap
    )
    if debrand_fn is not None:
        try:
            transformed = debrand_fn(snippet)
            if isinstance(transformed, str):
                snippet = transformed
        except Exception:
            # A debrand failure must not break snippet generation.
            pass
    return snippet


if __name__ == '__main__':
    # Quick CLI smoke check.
    import json
    print('--- detect_build_capability() ---')
    print(json.dumps(detect_build_capability(), indent=2))
    print('--- get_loader_snippet() ---')
    print(get_loader_snippet())
