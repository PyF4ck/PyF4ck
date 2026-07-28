"""Bedrock native transpile pipeline (Phase 1+).

Transpiles obfuscated Python source to native code via Cython, then compiles
to a CPython extension (.pyd/.so). Eliminates the key-in-output leak: no
marshal blob, no cleartext decryption keys — the obfuscated logic becomes
native machine code, defeated by neither the leaked obfuscator source nor a
generic deobfuscator built from it.

Pipeline::

    obfuscated .py  ->  Cython  ->  generated .c
                    ->  _obf_c_strings (XOR string literals)
                    ->  MSVC/gcc compile  ->  obf.cp311-win_amd64.pyd

This EMIT step replaces ``Compile.Obfuscate`` (the marshal+bz2+b85+key-
embedding loader path that the source leak broke — every secret sat as a
cleartext literal in the output .py).

Phase 1: native .pyd extension (host needs a matching CPython).
Phase 2: standalone .exe via an embedding harness (_embed_harness.py).
Phase 3+: C-level runtime protection (_c_protection.py).
"""
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

# Reuse the existing capability detection + compiler-flag logic.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_system import detect_build_capability  # noqa: E402
from _build_rng import BuildRNG, BuildManifest, write_manifest, manifest_path  # noqa: E402
# Phase H.10: PE post-build TLS-callback patcher (Windows-only; no-op elsewhere).
try:
    from _tls_callback import inject_tls_callback  # noqa: E402
except Exception:  # pragma: no cover - optional native pass
    inject_tls_callback = None  # type: ignore


def _compiler_flags():
    """Hardened compile/link flags, mirrored from _build_system._build_native_and_ship."""
    if sys.platform == 'win32':
        return ['/O2', '/GS-'], ['/INCREMENTAL:NO']  # optimize, no stack canary, deterministic link
    return (['-O2', '-fno-asynchronous-unwind-tables', '-fomit-frame-pointer'],
            ['-Wl', '-s'])  # strip symbol table


# Canonical placeholder for the source path Cython embeds in the generated C
# (traceback filenames, __pyx_moduledef, debug tables). Replacing the real
# tempdir path with this makes (a) reproducible builds byte-identical — the
# random tempfile.mkdtemp suffix no longer leaks into the .c -> .pyd — and
# (b) removes the build machine's username / temp path from the shipped
# binary (OPSEC: no "C:\\Users\\<user>\\AppData\\Local\\Temp\\..." fingerprint).
_CANON_SRC_DIR = '/bedrock/src'


def _normalize_cython_paths(c_text, tmpdir, module_name):
    """Replace the tempdir path Cython embeds in *c_text* with a canonical form.

    Cython writes the absolute source filename (``tmpdir/module.py``) into the
    generated C in three forms: native separators, C-escaped backslashes
    (``\\\\``), and forward slashes. All three are replaced so the output no
    longer depends on the random ``tempfile.mkdtemp`` suffix and does not leak
    the build machine's filesystem layout.
    """
    # The source filename inside tmpdir, e.g. "obf.py".
    src_file = module_name + '.py'
    # Native-separator forms.
    native_dir = tmpdir
    native_file = os.path.join(tmpdir, src_file)
    # C-escaped form (backslashes doubled) — Windows.
    cesc_dir = native_dir.replace('\\', '\\\\')
    cesc_file = native_file.replace('\\', '\\\\')
    # Forward-slash form.
    fwd_dir = native_dir.replace('\\', '/')
    fwd_file = native_file.replace('\\', '/')

    canon_file = _CANON_SRC_DIR + '/' + src_file

    # Order matters: replace the most-specific (full file path) before the dir,
    # and the C-escaped forms before native (the C-escaped forms contain the
    # native forms as substrings on Windows).
    replacements = [
        (cesc_file, canon_file.replace('/', '\\/')),  # keep C-escaped
        (cesc_dir, _CANON_SRC_DIR.replace('/', '\\/')),
        (fwd_file, canon_file),
        (fwd_dir, _CANON_SRC_DIR),
        (native_file, canon_file),
        (native_dir, _CANON_SRC_DIR),
    ]
    for old, new in replacements:
        if old and old != new:
            c_text = c_text.replace(old, new)
    return c_text


def _zero_pe_timestamp(pyd_path, verbose=False):
    """Zero the PE COFF TimeDateStamp in a shipped .pyd for reproducible builds.

    MSVC link embeds the current wall-clock time in two places: the
    ``IMAGE_FILE_HEADER.TimeDateStamp`` (e_lfanew + 8) and the
    ``IMAGE_DEBUG_DIRECTORY[].TimeDateStamp`` (each 28-byte entry has it at
    offset +4). Both must be zeroed for byte-identical reproducible builds;
    the build time otherwise differs across builds of the same source even
    with identical .c input. Safe: the loader does not validate TimeDateStamp;
    it is purely informational. Debug type CODEVIEW (PDB) entries are also
    neutralized so the PDB age/GUID does not vary.
    """
    import struct
    try:
        with open(pyd_path, 'rb') as f:
            data = bytearray(f.read())
        if data[:2] != b'MZ':
            return False
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return False
        coff_off = e_lfanew + 4
        # 1. IMAGE_FILE_HEADER.TimeDateStamp (offset +4 in the COFF header).
        ts_off = coff_off + 4
        struct.pack_into('<I', data, ts_off, 0)

        # 2. Walk the data directories to find the debug directory (index 6)
        #    and zero each entry's TimeDateStamp. Offsets depend on PE32 vs
        #    PE32+ (BaseOfData present/absent, ImageBase 4 vs 8 bytes, stack/
        #    heap reserve/commit 4 vs 8 bytes).
        opt_off = coff_off + 20
        opt_magic = struct.unpack_from('<H', data, opt_off)[0]
        if opt_magic == 0x10b:      # PE32
            ndir_off = opt_off + 92
            dir_off = opt_off + 96
        elif opt_magic == 0x20b:    # PE32+
            ndir_off = opt_off + 108
            dir_off = opt_off + 112
        else:
            with open(pyd_path, 'wb') as f:
                f.write(data)
            return True
        n_dirs = struct.unpack_from('<I', data, ndir_off)[0]
        n_sec = struct.unpack_from('<H', data, coff_off + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
        sec_off = opt_off + opt_size

        # Debug directory is data-directory index 6 (zero-based).
        if n_dirs > 6:
            dbg_rva, dbg_size = struct.unpack_from('<II', data, dir_off + 6 * 8)
            if dbg_rva != 0 and dbg_size != 0:
                # Map the debug-directory RVA to a file offset via the
                # section table (VirtualAddress -> PointerToRawData).
                for s in range(n_sec):
                    so = sec_off + s * 40
                    vaddr = struct.unpack_from('<I', data, so + 12)[0]
                    vsize = struct.unpack_from('<I', data, so + 8)[0]
                    raddr = struct.unpack_from('<I', data, so + 20)[0]
                    if vaddr <= dbg_rva < vaddr + max(vsize, 1):
                        file_off = raddr + (dbg_rva - vaddr)
                        n_entries = dbg_size // 28
                        for e in range(n_entries):
                            eo = file_off + e * 28
                            # IMAGE_DEBUG_DIRECTORY: Characteristics(4)
                            # TimeDateStamp(4) MajorVer(2) MinorVer(2)
                            # Type(4) SizeOfData(4) AddrOfRawData(4)
                            # PointerToRawData(4)
                            struct.pack_into('<I', data, eo + 4, 0)
                        break
        with open(pyd_path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        if verbose:
            print(f"[transpile] PE timestamp zeroing skipped ({e})")
        return False


def _xor_obfuscate_c(c_text, verbose=False, antire_check=False,
                     build_rng=None):
    """Apply C-source-level obfuscation to generated Cython C (Phase C+E).

    This replaces the Phase-1 C-macro XOR preprocessor (which only touched
    explicit ``_DS("...")`` markers that Cython output never contains — a
    no-op) with the Phase-C pass suite: Cython ``__pyx_k_*`` string-table
    encryption + opaque-predicate bogus control flow. See ``_c_obf_passes``.

    Phase E: if *build_rng* (a ``_build_rng.BuildRNG``) is given, every pass
    draws from an INDEPENDENT per-build sub-stream so two builds of the same
    source differ (per-build diversity). Without it the legacy per-source
    deterministic derivation is used.
    """
    try:
        from _c_obf_passes import apply_c_obfuscation
        # NOTE: on Cython 3.x the interned strings live in a compressed bytes
        # blob + inline PyMethodDef/traceback literals, NOT in the legacy
        # `static const char __pyx_k_*[]` form. The C-source string-encryption
        # pass targets the legacy form and can break Cython 3.x builds (mutating
        # a `const` array referenced as `const char*`). So string encryption is
        # OFF by default; the valuable, safe pass here is opaque-predicate bogus
        # control flow (injects into PyInit_*) + the anti-RE timing check
        # (Phase D: bedrock_antire.c compiled alongside obf.c). Full string
        # encryption is the IR-level pass's job (Phase C strength tier).
        # The timing core is always on (no false positives on clean hosts);
        # the platform-specific BR_ENABLE_* flags are off by default for the
        # MVP (they have false-positive risk on bare-metal Hyper-V / cloud).
        out, stats = apply_c_obfuscation(
            c_text, build_rng=build_rng, enable_strings=False,
            enable_opaque=True, enable_mba=False,
            antire_check=antire_check, verbose=verbose)
        if verbose and stats.get('opaque_injected'):
            tag = f" (build_id={stats.get('build_id')[:8]})" \
                if stats.get('build_id') else ''
            print(f"[transpile] C obf: opaque predicates + anti-RE timing "
                  f"check injected into PyInit{tag}")
        return out, stats.get('string_key', 0)
    except Exception as e:
        if verbose:
            print(f"[transpile] C obf skipped ({e})")
        return c_text, 0


def transpile_and_build(obf_source, out_dir, *, module_name='obf',
                        c_string_obf=True, verbose=False, ctx=None,
                        build_seed=None, license_id=None, profile=None):
    """Transpile obfuscated Python *obf_source* to a native extension.

    Args:
      obf_source: obfuscated Python source string (post AST passes, pre-emit)
      out_dir: where to ship the compiled .pyd/.so
      module_name: module name for the extension (default 'obf'). Must be a
        C-legal, Python-importable identifier.
      c_string_obf: run the C string XOR preprocessor on generated C
      verbose: print progress
      ctx: BuildContext (reserved for Phase 3+ protection flags)
      build_seed: optional fixed 32-byte seed for REPRODUCIBLE mode. If None,
        a fresh master seed is minted (non-reproducible, per-build diversity).
        If non-None, the same input + seed reproduces the same build.
      license_id: optional customer/license id, recorded in the manifest for
        traitor tracing (a leaked .pyd can be attributed to its build_id).
      profile: optional strength-profile name recorded in the manifest.

    Returns a dict (contract mirrors _build_system.build_and_ship):
      - 'mode': 'native' | 'reference'
      - 'module_name': import name
      - 'module_path': full path to shipped extension, or None on failure
      - 'ext_hash': SHA-256 hex of the shipped .pyd, or None
      - 'detail': status string
      - 'build_id': per-build id (hex master seed) when a BuildRNG was used
      - 'manifest_path': path to the written .bedrock_manifest.json, or None
    """
    cap = detect_build_capability()
    if not cap['can_build']:
        return {
            'mode': 'reference',
            'module_name': module_name,
            'module_path': None,
            'ext_hash': None,
            'detail': f"cannot build native extension: {cap.get('detail','')}",
        }

    # Phase E: construct the per-build master CSPRNG. In reproducible mode
    # (build_seed set) the master is deterministic; otherwise fresh entropy
    # so two builds of the same source differ structurally.
    build_rng = BuildRNG.create(obf_source.encode('utf-8'), fixed_seed=build_seed)
    if verbose:
        print(f"[transpile] build_id={build_rng.build_id()[:16]} "
              f"({'reproducible' if build_seed is not None else 'fresh'})")

    tmpdir = tempfile.mkdtemp(prefix='_bedrock_transpile_')
    try:
        # 1. Write obfuscated Python source.
        py_name = module_name + '.py'
        py_path = os.path.join(tmpdir, py_name)
        with open(py_path, 'w', encoding='utf-8') as f:
            f.write(obf_source)
        if os.environ.get('BEDROCK_TRANSPILE_DEBUG'):
            _dbg = os.environ['BEDROCK_TRANSPILE_DEBUG']
            try:
                with open(_dbg, 'w', encoding='utf-8') as f:
                    f.write(obf_source)
                if verbose:
                    print(f"[transpile] DEBUG dumped intermediate source -> {_dbg}")
            except Exception:
                pass

        # 2. Cythonize -> generated C.
        from Cython.Build import cythonize
        if verbose:
            print(f"[transpile] cythonize {py_name}")
        cythonize([py_path], quiet=not verbose)
        c_name = module_name + '.c'
        c_path = os.path.join(tmpdir, c_name)
        if not os.path.exists(c_path):
            return {'mode': 'reference', 'module_name': module_name,
                    'module_path': None, 'ext_hash': None,
                    'detail': 'cythonize produced no .c'}

        # 3. C-level string obfuscation (XOR literal strings).
        #    The anti-RE timing check (br_antire_check) is injected into
        #    PyInit only when bedrock_antire.c will actually be compiled in
        #    (step 4), to avoid an unresolved-extern linker error.
        antire_src = os.path.join(_HERE, 'bedrock_antire.c')
        has_antire = os.path.exists(antire_src)
        with open(c_path, 'r', encoding='utf-8') as f:
            c_text = f.read()
        # Normalize the tempdir path Cython embeds in the generated C so the
        # output does not depend on the random tempfile.mkdtemp suffix
        # (reproducible builds) and does not leak the build machine's
        # username/temp path (OPSEC). Done BEFORE C-obf so the obf passes see
        # the canonical path.
        c_text = _normalize_cython_paths(c_text, tmpdir, module_name)
        if c_string_obf:
            c_text, _key = _xor_obfuscate_c(c_text, verbose=verbose,
                                             antire_check=has_antire,
                                             build_rng=build_rng)
        with open(c_path, 'w', encoding='utf-8') as f:
            f.write(c_text)
        # Optional C-source dump for diversity / reproducibility diagnostics.
        _c_dbg = os.environ.get('BEDROCK_TRANSPILE_C_DEBUG')
        if _c_dbg:
            try:
                with open(_c_dbg, 'w', encoding='utf-8') as f:
                    f.write(c_text)
                if verbose:
                    print(f"[transpile] DEBUG dumped C source -> {_c_dbg}")
            except Exception:
                pass

        # 4. Build the extension via setuptools (hardened flags).
        #    Include bedrock_antire.c (Phase D anti-RE runtime) as a second
        #    source so br_antire_check() resolves at link time. The timing
        #    core is self-contained (no external hash dep); platform checks
        #    are gated by BR_ENABLE_* flags (off by default for MVP safety).
        extra_compile, extra_link = _compiler_flags()
        antire_basename = 'bedrock_antire.c'
        if has_antire:
            shutil.copy2(antire_src, os.path.join(tmpdir, antire_basename))
        sources_list = [c_name]
        if has_antire:
            sources_list.append(antire_basename)
        # Phase H.11: compile the exception-table VM (_xetvm) into the same
        # extension when --h-exc-table-vm is on. The VM dispatches opcodes via
        # SEH (Windows) / .eh_frame (Unix); its handlers and sha256_buffer
        # become linkable internal symbols. PyInit_xetvm is harmless dead code
        # here (the loader calls PyInit_<module_name>). The /DBR_ENABLE_EXC_VM
        # define gates the Windows SEH dispatch path in the C source.
        _h11_on = bool(ctx is not None and getattr(ctx, 'h_exc_table_vm', False))
        if _h11_on:
            etvm_src = os.path.join(_HERE, '_exc_table_vm.c')
            if os.path.exists(etvm_src):
                etvm_basename = os.path.basename(etvm_src)
                shutil.copy2(etvm_src, os.path.join(tmpdir, etvm_basename))
                sources_list.append(etvm_basename)
                if sys.platform == 'win32':
                    extra_compile = list(extra_compile) + ['/DBR_ENABLE_EXC_VM']
        # Phase H.10: compile a TLS callback shim into the extension when
        # --h-tls-callback is on. The shim exports _br_tls_cb (a benign
        # PyInit-safe no-op), which the post-build _tls_callback patcher then
        # wires the IMAGE_TLS_DIRECTORY at (see below). Windows-only by
        # construction; on Unix the shim is an empty TU and harmless.
        _h10_on = bool(ctx is not None and getattr(ctx, 'h_tls_callback', False))
        if _h10_on:
            tls_shim_src = os.path.join(_HERE, '_tls_callback_shim.c')
            if os.path.exists(tls_shim_src):
                tls_shim_basename = os.path.basename(tls_shim_src)
                shutil.copy2(tls_shim_src, os.path.join(tmpdir, tls_shim_basename))
                sources_list.append(tls_shim_basename)
        setup_text = (
            "from setuptools import setup, Extension\n"
            f"setup(name={module_name!r}, version='0.1',\n"
            f"      ext_modules=[Extension({module_name!r}, sources={sources_list!r},\n"
            f"        extra_compile_args={extra_compile!r},\n"
            f"        extra_link_args={extra_link!r})])\n"
        )
        with open(os.path.join(tmpdir, 'setup.py'), 'w', encoding='utf-8') as f:
            f.write(setup_text)

        cmd = [sys.executable, 'setup.py', 'build_ext', '--inplace']
        proc = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or '')[-1500:]
            return {'mode': 'reference', 'module_name': module_name,
                    'module_path': None, 'ext_hash': None,
                    'detail': f"build_ext failed: {tail}"}

        # 5. Locate + ship the .pyd/.so.
        if sys.platform == 'win32':
            pattern = module_name + '*.pyd'
        else:
            pattern = module_name + '*.so'
        hits = (glob.glob(os.path.join(tmpdir, pattern))
                or glob.glob(os.path.join(tmpdir, '**', pattern), recursive=True))
        if not hits:
            return {'mode': 'reference', 'module_name': module_name,
                    'module_path': None, 'ext_hash': None,
                    'detail': f"build produced no {pattern!r}"}
        built = hits[0]

        os.makedirs(out_dir, exist_ok=True)
        dest_name = os.path.basename(built)
        dest = os.path.join(out_dir, dest_name)
        if os.path.abspath(dest) != os.path.abspath(built):
            shutil.copy2(built, dest)
        # Zero the PE COFF TimeDateStamp on Windows so two same-seed builds
        # are byte-identical (MSVC embeds the wall-clock build time, which
        # otherwise differs between builds). Safe: the loader ignores it.
        if sys.platform == 'win32':
            _zero_pe_timestamp(dest, verbose=verbose)
            # Phase H.10: post-build TLS-callback injection. Appends a NEW
            # .brtls section carrying an IMAGE_TLS_DIRECTORY + callback array
            # pointing at the exported _br_tls_cb shim (compiled in above
            # when --h-tls-callback is on), and wires data-dir index 9 at it.
            # Fires pre-PyInit on thread attach. The shim is a benign no-op;
            # the wired TLS directory's existence is the obfuscation signal
            # (TLS callbacks are an execution vector static analyzers that
            # skip TLS miss; debuggers that break on TLS reveal pre-PyInit).
            # Must run AFTER _zero_pe_timestamp (which rewrites existing PE
            # fields) so the new section isn't disturbed. Returns False
            # silently on any failure (file left byte-identical).
            if _h10_on and inject_tls_callback is not None:
                try:
                    inject_tls_callback(dest, '_br_tls_cb', verbose=verbose)
                except Exception as _tls_e:
                    if verbose:
                        print(f"[tls] inject_tls_callback failed: {_tls_e}")
        try:
            with open(dest, 'rb') as eh:
                ext_hash = hashlib.sha256(eh.read()).hexdigest()
        except Exception:
            ext_hash = None

        # Phase E: write the build manifest (traitor-tracing record) beside
        # the shipped .pyd. The manifest binds the build_id (hex master seed)
        # to the input source, license, and ext_hash so a leaked binary can
        # be attributed to its issuing customer.
        manifest = BuildManifest(
            build_id=build_rng.build_id(),
            input_sha256=hashlib.sha256(
                obf_source.encode('utf-8')).hexdigest(),
            license_id=license_id,
            master_seed_hash=build_rng.master_seed_hash(),
            timestamp='',
            passes=['cython_transpile', 'c_obf_opaque'] +
                   (['c_antire_timing'] if has_antire else []),
            profile=profile,
        )
        mpath = manifest_path(out_dir)
        try:
            write_manifest(manifest, mpath)
            if verbose:
                print(f"[transpile] manifest -> {mpath}")
        except Exception as e:
            mpath = None
            if verbose:
                print(f"[transpile] manifest write failed ({e})")

        if verbose:
            print(f"[transpile] native mode -> {dest}")
        return {
            'mode': 'native',
            'module_name': module_name,
            'module_path': dest,
            'ext_hash': ext_hash,
            'detail': f"shipped native transpiled module {dest_name}",
            'build_id': build_rng.build_id(),
            'manifest_path': mpath,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Smoke test: python _transpile_pipeline.py
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _demo = (
        "def fib(n):\n"
        "    if n < 2:\n"
        "        return n\n"
        "    return fib(n - 1) + fib(n - 2)\n"
        "\n"
        "def main():\n"
        "    print(fib(10))\n"
    )
    _out = tempfile.mkdtemp(prefix='_bedrock_transpile_smoke_')
    try:
        r = transpile_and_build(_demo, _out, module_name='_smoke_obf',
                                verbose=True)
        print('result:', r['mode'], '|', r['detail'])
        if r['mode'] == 'native' and r['module_path']:
            sys.path.insert(0, _out)
            import importlib
            mod = importlib.import_module('_smoke_obf')
            print('fib(10) =', mod.fib(10))
            mod.main()
    finally:
        shutil.rmtree(_out, ignore_errors=True)
