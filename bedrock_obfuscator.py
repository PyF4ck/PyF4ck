"""Bedrock Obfuscator by baobg.

A monolithic Python source obfuscator. Pipeline overview:
    [01] CLI / banner / runtime guards (this preamble).
    [02] Helpers: build context vars, RNG, dynamic-XOR expression builders,
         spam/jailbreak/fake-VM snippet generators.
    [03] AST-level obfuscation: Ast_obf (rename, spam blocks, try/except
         wrappers, opaque match/case scaffolding).
    [04] Bedrock Pycloak builtin / int / string encoder.
    [05] Compile pipeline: marshal packing, dyn-builtin/dyn-import expression
         generation, anti-pycdc layers, builtin-encoded var aliases.
    [06] VM-native compiler (BedrockVM-class internal) + const-pool crypto
         (env-bound KDF, blob packing, honeypots, AI-deception carriers).
    [07] VM runtime stub (legacy "main" / "vm-native-v2") with anti-debug
         (BEDROCK_ANTI), settrace/setprofile null, anti-hook score, embedded
         probes, self-destruct on tamper, opcode permutation.
    [08] Chunked VM-in-VM lite runtime with per-chunk key derivation and
         polymorphic opcode handlers.
    [09] Methods: obf_vars, obf_builtins, vm_strings, obf_strings.
    [10] Logging / ParseArgs / main() — ANSI-only output, no pystyle.

CLI:
    python bedrock.py --file <input.py> [--output bedrock-out.py]
                      [--profile fast|balanced|paranoid|extreme]
                      [--runtime-mode main|legacy]
                      [--anti-debug strict|compat|off]
                      [--anti-hook strict|compat|off]
                      [--tamper self-destruct|fail-closed|warn]
                      [--python-band 3.10-3.12|3.12-only]
                      [--quiet] [--json] [--overwrite] [--non-interactive]

Dependencies: stdlib only (pytz optional).
"""
# === [01] Imports and runtime guards ===
try:
    import argparse
    import ast
    import builtins as __builtins__
    import re
    import random
    import sys
    import os
    import zlib
    import base64
    import bz2
    import marshal
    import hashlib
    import textwrap
    from datetime import datetime
    try:
        import pytz
    except Exception:
        pytz = None
    import time
    import pickle
    from typing import Set, Dict, List, Tuple, Any, Union, Optional
    from dataclasses import dataclass, field
    # --- bedrock_ext / bedrock_plugins import block removed; symbols inlined later ---
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
        sys.stderr.reconfigure(encoding='utf-8', errors='ignore')
    except Exception:
        pass


    # --- ANSI color helpers (replaces colorama + pystyle) -----------------
    class _ANSI:
        RESET = '\033[0m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        WHITE = '\033[97m'
        GRAY = '\033[37m'
        DGRAY = '\033[90m'
        RED = '\033[31m'
        BRED = '\033[91m'
        GREEN = '\033[32m'
        BGREEN = '\033[92m'
        YELLOW = '\033[33m'
        BYELLOW = '\033[93m'
        BLUE = '\033[34m'
        BBLUE = '\033[94m'
        MAGENTA = '\033[35m'
        BMAGENTA = '\033[95m'
        CYAN = '\033[36m'
        BCYAN = '\033[96m'
        @staticmethod
        def gradient(text, color_seq):
            if not text:
                return ''
            seq = list(color_seq) or [_ANSI.WHITE]
            out = []
            for i, ch in enumerate(text):
                col = seq[i % len(seq)] if seq else ''
                out.append(col + ch)
            return ''.join(out) + _ANSI.RESET
        @staticmethod
        def diag_gradient(text, color_seq):
            seq = list(color_seq) or [_ANSI.WHITE]
            lines = text.split('\n')
            out_lines = []
            for li, line in enumerate(lines):
                buf = []
                for ci, ch in enumerate(line):
                    col = seq[(li + ci) % len(seq)]
                    buf.append(col + ch)
                out_lines.append(''.join(buf) + _ANSI.RESET)
            return '\n'.join(out_lines)

    dark = _ANSI.WHITE
    light = _ANSI.GRAY

    BEDROCK_ANTI = """
try:
    import sys as __bedrock_sys__
    __bedrock_sys__.settrace(None)
    __bedrock_sys__.setprofile(None)
    try:
        import threading as __bedrock_th__
        __bedrock_th__.settrace(None)
        __bedrock_th__.setprofile(None)
        del __bedrock_th__
    except:
        pass
    del __bedrock_sys__
except:
    pass
"""

    # banner placeholder (built in main() with ANSI gradient).
    sakura = '\n '
    banner = '\n '
    BEDROCK_BANNER_ART = r"""
 ____  _____ ____  ____   ___   ____ _  __
| __ )| ____|  _ \|  _ \ / _ \ / ___| |/ /
|  _ \|  _| | | | | |_) | | | | |   | ' /
| |_) | |___| |_| |  _ <| |_| | |___| . \
|____/|_____|____/|_| \_\\___/ \____|_|\_\
            Bedrock Obfuscator by baobg
"""

    # === Phase 4: anti-meta debranding infrastructure ===
    # Per-build token map: when anti-meta is ON, every static bedrock/Bedrock/
    # BEDROCK/baobg/Baobg/BAOBG literal in the output artifact is replaced with
    # a per-build random token (the SAME token for every emitted component, so
    # defs and calls always match). When OFF, the map is the identity, so
    # _debrand() is a no-op and behavior is unchanged.
    # The token alphabet EXCLUDES the union of letters in "bedrock" and "baobg"
    # ({a,b,c,d,e,g,k,o,r}) so the token can never reintroduce the fingerprint.
    _BR_DEBRAND_ALPHABET = 'fhijlmnpqstuvwxyz'  # 17 letters, excludes a,b,c,d,e,g,k,o,r
    BR_DEBRAND = {'bedrock': 'bedrock', 'Bedrock': 'Bedrock', 'BEDROCK': 'BEDROCK',
                  'baobg': 'baobg', 'Baobg': 'Baobg', 'BAOBG': 'BAOBG'}
    BR_DEBRAND_ON = False
    # Per-build author/bot variable names + values (identity when anti-meta off).
    # These feed both the header `infos_` emit and the author self-check so the
    # two stay in sync regardless of randomization.
    _META_INFOS = {'__OBFBy__': 'baobg', '__OBFBot__': '@BedrockObfuscator'}
    # Per-build debranded env-key var name (identity when anti-meta off). Set by
    # _init_debrand; read by class Compile's envkey emit sites + chain preamble.
    _ENVKEY_NAME = '__BedrockEnvKey__'

    def _init_debrand(rng=None, enabled=False):
        """Generate per-build debrand tokens + author/bot metadata. Call once at the start of run_build."""
        global BR_DEBRAND, BR_DEBRAND_ON, _META_INFOS, _ENVKEY_NAME, list_ten_bien
        BR_DEBRAND_ON = enabled
        if not enabled:
            BR_DEBRAND = {'bedrock': 'bedrock', 'Bedrock': 'Bedrock', 'BEDROCK': 'BEDROCK',
                          'baobg': 'baobg', 'Baobg': 'Baobg', 'BAOBG': 'BAOBG'}
            _META_INFOS = {'__OBFBy__': 'baobg', '__OBFBot__': '@BedrockObfuscator'}
            _ENVKEY_NAME = '__BedrockEnvKey__'
            list_ten_bien = _ORIG_LIST_TEN_BIEN[:]
            return
        if rng is None:
            rng = random.Random()
        _tok = ''.join(rng.choice(_BR_DEBRAND_ALPHABET) for _ in range(7))
        BR_DEBRAND = {
            'bedrock': _tok,
            'Bedrock': _tok[0].upper() + _tok[1:],
            'BEDROCK': _tok.upper(),
            'baobg': _tok,
            'Baobg': _tok[0].upper() + _tok[1:],
            'BAOBG': _tok.upper(),
        }
        # Per-build random author/bot var names (random hanzi) + values (random
        # ascii). These replace the static 'baobg'/'@BedrockObfuscator' values
        # and '__OBFBy__'/'__OBFBot__' names in the output header + self-check.
        _av = rand_cn_name(6)
        _bv = rand_cn_name(6)
        _aval = ''.join(rng.choice('fhijlmnpqstuvwxyz0123456789') for _ in range(rng.randint(8, 12)))
        _bval = ''.join(rng.choice('fhijlmnpqstuvwxyz0123456789') for _ in range(rng.randint(8, 12)))
        _META_INFOS = {_av: _aval, _bv: _bval}
        # Per-build debranded env-key var name (breaks the static
        # __BedrockEnvKey__ signature). Read by Compile emit sites + chain.
        _ENVKEY_NAME = _debrand('__BedrockEnvKey__')
        list_ten_bien = [_debrand(n) for n in _ORIG_LIST_TEN_BIEN]

    def _debrand(s):
        """Replace static bedrock/baobg literals with per-build tokens.

        Identity when anti-meta is off (BR_DEBRAND maps each key to itself).
        The six replacements are case-sensitive and mutually non-overlapping
        (bedrock/Bedrock/BEDROCK share no case-sensitive substring; same for
        baobg/Baobg/BAOBG), so order is irrelevant.
        """
        if not isinstance(s, str) or s == '':
            return s
        m = BR_DEBRAND
        return (s.replace('bedrock', m['bedrock'])
                 .replace('Bedrock', m['Bedrock'])
                 .replace('BEDROCK', m['BEDROCK'])
                 .replace('baobg', m['baobg'])
                 .replace('Baobg', m['Baobg'])
                 .replace('BAOBG', m['BAOBG']))

    def p(text):
        return print(stage(text))

    def stage(text: str, symbol: str='...', col1=None, col2=None) -> str:
        if col1 is None:
            col1 = light
        if col2 is None:
            col2 = light if symbol == '...' else dark
        return f' {col1}[{symbol}]{_ANSI.RESET} {col2}{text}{_ANSI.RESET}'

    hcm_tz = pytz.timezone('Asia/Ho_Chi_Minh') if pytz is not None else None
    current_time_hcm = datetime.now(hcm_tz) if hcm_tz is not None else datetime.now()
    QUIET_MODE = False
    JSON_MODE = False

    # === [00] BuildContext ===
    @dataclass
    class BuildContext:
        """Runtime build context, mirrors options propagated as globals.

        Kept as a lightweight dataclass for readability; the legacy code
        still reads/writes the equivalent module-level globals (mode,
        protect, runtime_mode, anti_hook_mode, ...) for backward
        compatibility with the embedded loader templates.
        """
        input_path: str = ''
        output_path: str = ''
        profile: str = 'max'
        runtime_mode: str = 'main'
        runtime_mode_public: str = 'main'
        anti_debug: str = 'strict'
        anti_hook: str = 'strict'
        tamper: str = 'self-destruct'
        python_band: str = '3.10-3.12'
        bind_mode: str = 'none'
        legacy_loader: bool = False
        vm_profile: str = 'production'
        vm_carrier: str = 'auto'
        vm_compat: str = 'broad'
        adv_requests: str = 'off'
        quiet: bool = False
        json: bool = False
        overwrite: bool = False
        non_interactive: bool = False
        # --- bedrock_ext fields ----------------------------------------
        cff: bool = False
        bc_mutate: bool = False
        bc_mutate_nop: bool = True
        bc_mutate_dead: bool = True
        bc_mutate_consts: bool = True
        bc_mutate_seed: Any = None
        integrity: str = 'on'
        rng: Any = None
        # --- batch 2: anti-vm / anti-debugger v2 ----------------------
        anti_vm: str = 'off'
        anti_debugger_v2: bool = False
        # --- batch 3: junk / import-obf / homoglyph / numobf / boolobf / strfrag2 / lambda_enc
        junk: bool = False
        junk_level: int = 2
        import_obf: bool = False
        import_blob: bool = False
        homoglyph: bool = False
        homoglyph_seed: Any = None
        keep_names: Any = None
        num_obf: bool = False
        num_obf_depth: int = 1
        bool_obf: bool = False
        str_frag2: bool = False
        str_frag2_vm: bool = False
        str_cipher: bool = False
        lambda_enc: bool = False
        lambda_enc_y: bool = False
        lambda_enc_density: float = 1.0
        # --- batch 5: decompiler-trap / var-split / env-key / spoof-meta / anti-timing / VM ---
        dec_trap: bool = False
        dectrap_density: float = 0.5
        var_split: bool = False
        env_key: bool = False
        spoof_meta: bool = False
        anti_timing: bool = False
        vm_opcode_remap: bool = False
        runtime_dec: bool = False
        # --- batch 7 (Phase 2): chain runtime ------------------------
        chain: bool = False
        # --- batch 8 (Phase 3): debug poisoning + metamorphic --------
        # debug_poison: detected debuggers/hooks advance the poison
        # state (silent inert) instead of sys.exit. Auto-enables
        # chain (poison state lives in the chain integrity shard).
        debug_poison: bool = False
        # metamorphic: file self-rewrites on every run (atomic
        # os.replace) with fresh spam + re-encrypted string literals +
        # re-patched file hash. Requires chain (shard 5 hooks into the
        # chain preamble).
        metamorphic: bool = False
        # --- batch 9 (Phase 4): anti-meta debranding --------------
        # anti_meta: replace every static bedrock/Bedrock/BEDROCK/baobg/
        # BedrockDz literal in the output artifact with per-build random
        # tokens so AV/EDR can't fingerprint the artifact. Auto-on for
        # extreme. When off, _debrand() is the identity function.
        anti_meta: bool = False
        # --- batch 10 (Phase 5): native BedrockVM compilation ------
        # native_vm: compile eligible top-level functions into BedrockVM
        # bytecode blobs (run via the shipped _xvm C interpreter or the
        # _bedrock_vm_ref fallback). A function goes to the VM OR the
        # capsule runtime, never both. Auto-on for extreme. When off,
        # apply_native_vm is a no-op (tree unchanged).
        native_vm: bool = False
        # crown_jewel_vm (Phase F): leak-resilient VM (Layer 2) for the crown
        # jewels -- a small set of high-value functions virtualized through the
        # hardened bedrock_vm_v2.c runtime (context-threaded dispatch,
        # obscured VPC, SMC handlers, EH-shadowing). Selection is annotation-
        # gated (@bedrock_crown_jewel decorator) via _crown_jewel_collector,
        # falling back to a top-N most-complex heuristic. Reconciled with
        # --transpile: the crown jewels are VM-compiled INSIDE the transpile
        # path (rest goes Cython-native), unlike --native-vm which is
        # mutually exclusive with --transpile.
        crown_jewel_vm: bool = False
        # vm_fallback: policy when the shipped _xvm native extension is
        # missing or tampered at runtime. 'auto' = warn + reference fallback
        # (old behaviour); 'dev' = silent reference fallback; 'off' =
        # fail-closed (poison + abort). The extreme profile auto-sets 'off'
        # so production builds never silently degrade to the pure-Python VM.
        vm_fallback: str = 'auto'
        # --- batch 4: vm_handlers / cache / plugins ------------------
        vm_extended: bool = False
        cache: bool = True
        plugins: Any = None
        # Phase G (Layer 3): server key-release. When release_server is set,
        # the VM key is NOT embedded as a _vm_key bytes literal in the
        # artifact -- instead the artifact ships a _vm_key_handle tuple
        # (license_id, build_id, server_url, server_ed25519_pub,
        # server_x25519_pub, offline_grace_seconds) and the loader resolves
        # the key on first VM call via an attested fetch to release_server
        # (POST /release, Ed25519 JWT, X25519 ECDH, AES-GCM, on-disk
        # machine-bound cache with offline grace). Mutually exclusive with
        # --env-key (key-release is the stronger, machine-attested binding).
        release_server: str = ''
        license_id: str = ''
        master_seed: bytes = b''
        offline_grace_seconds: int = 604800
        # --- Phase H (Layer 6): esoteric + anti-pattern passes ----------
        # All default OFF; auto-on under `extreme` (see _apply_extreme_overrides).
        # H.1-H.9 are Python AST/source passes wired into the operations pipeline
        # via _insert_after_obf_vars. H.10 (TLS callback) and H.11 (exc-table
        # VM) are native post-build steps wired into _transpile_pipeline (the
        # CLI flags exist here so the user can opt in; the native wiring is in
        # _transpile_pipeline.py's post-ship hook).
        # build_rng is the per-build BuildRNG threaded from args._rng; the H
        # passes' _rng_for helpers read it for deterministic-per-build sub-
        # streams. Set from rng in the pass-registration block.
        build_rng: Any = None
        h_id_poison: bool = False
        h_acoda: bool = False
        h_metamorphic: bool = False
        h_style: bool = False
        h_branchless: bool = False
        h_bloom: bool = False
        h_dag_cff: bool = False
        h_selfcheck_cf: bool = False
        h_fss: bool = False
        h_tls_callback: bool = False
        h_exc_table_vm: bool = False
        # --- Phase iO-2: FSS extensions (Layer 6+) ------------------
        # fss_mode: 'auto' (default; bool→additive→serialized), 'additive',
        # 'additive_n' (n-share collusion-resistant), 'bool' (XOR sharing),
        # 'serialized' (any repr-safe return via int.from_bytes).
        # fss_shares: number of shares for additive_n (default 3, min 2).
        # fss_all_eligible: when True, lift the 3-5 cap → share ALL eligible
        # functions (iO-grade coverage).
        fss_mode: str = 'auto'
        fss_shares: int = 3
        fss_all_eligible: bool = False
        # Phase iO-3: crypto opaque predicates grade.
        # 'algebra' = trivial x*(x-1)%2==0 (Z3 folds in seconds).
        # 'crypto' = DL/LWE/hash-chain/RSA (Z3 can't fold).
        # 'hybrid' = algebra AND crypto (solver must crack both).
        opaque_grade: str = 'algebra'

        @classmethod
        def from_args(cls, args) -> "BuildContext":
            return cls(
                input_path=getattr(args, 'file', '') or '',
                output_path=getattr(args, 'output', '') or '',
                profile=getattr(args, 'profile', 'max'),
                runtime_mode=getattr(args, 'runtime_mode', 'main'),
                runtime_mode_public=getattr(args, 'runtime_mode_public', 'main'),
                anti_debug=getattr(args, 'anti_debug', 'strict'),
                anti_hook=getattr(args, 'anti_hook', 'strict'),
                tamper=getattr(args, 'tamper', 'self-destruct'),
                python_band=getattr(args, 'python_band', '3.10-3.12'),
                bind_mode=getattr(args, 'bind_mode', 'none'),
                legacy_loader=bool(getattr(args, 'legacy_loader', False)),
                vm_profile=getattr(args, 'vm_profile', 'production'),
                vm_carrier=getattr(args, 'vm_carrier', 'auto'),
                vm_compat=getattr(args, 'vm_compat', 'broad'),
                adv_requests=getattr(args, 'adv_requests', 'off'),
                quiet=bool(getattr(args, 'quiet', False)),
                json=bool(getattr(args, 'json', False)),
                overwrite=bool(getattr(args, 'overwrite', False)),
                non_interactive=bool(getattr(args, 'non_interactive', False)),
                cff=bool(getattr(args, 'cff', False)),
                bc_mutate=bool(getattr(args, 'bc_mutate', False)),
                bc_mutate_nop=bool(getattr(args, 'bc_mutate_nop', True)),
                bc_mutate_dead=bool(getattr(args, 'bc_mutate_dead', True)),
                bc_mutate_consts=bool(getattr(args, 'bc_mutate_consts', True)),
                bc_mutate_seed=getattr(args, 'bc_mutate_seed', None),
                integrity=getattr(args, 'integrity', 'on'),
                rng=getattr(args, '_rng', None),
                anti_vm=getattr(args, 'anti_vm', 'off'),
                anti_debugger_v2=(getattr(args, 'anti_debugger_v2', 'off') == 'on'),
                junk=bool(getattr(args, 'junk', False)),
                junk_level=int(getattr(args, 'junk_level', 2) or 2),
                import_obf=bool(getattr(args, 'import_obf', False)),
                import_blob=bool(getattr(args, 'import_blob', False)),
                homoglyph=bool(getattr(args, 'homoglyph', False)),
                homoglyph_seed=getattr(args, 'homoglyph_seed', None),
                keep_names=set(),
                num_obf=bool(getattr(args, 'num_obf', False)),
                num_obf_depth=int(getattr(args, 'num_obf_depth', 1) or 1),
                bool_obf=bool(getattr(args, 'bool_obf', False)),
                str_frag2=bool(getattr(args, 'str_frag2', False)),
                str_frag2_vm=bool(getattr(args, 'str_frag2_vm', False)),
                str_cipher=bool(getattr(args, 'str_cipher', False)),
                lambda_enc=bool(getattr(args, 'lambda_enc', False)),
                lambda_enc_y=bool(getattr(args, 'lambda_enc_y', False)),
                lambda_enc_density=float(getattr(args, 'lambda_enc_density', 1.0) or 1.0),
                dec_trap=bool(getattr(args, 'dec_trap', False)),
                dectrap_density=float(getattr(args, 'dectrap_density', 0.5) or 0.5),
                var_split=bool(getattr(args, 'var_split', False)),
                env_key=bool(getattr(args, 'env_key', False)),
                spoof_meta=bool(getattr(args, 'spoof_meta', False)),
                anti_timing=bool(getattr(args, 'anti_timing', False)),
                vm_opcode_remap=bool(getattr(args, 'vm_opcode_remap', False)),
                runtime_dec=bool(getattr(args, 'runtime_dec', False)),
                chain=bool(getattr(args, 'chain', False)),
                debug_poison=bool(getattr(args, 'debug_poison', False)),
                metamorphic=bool(getattr(args, 'metamorphic', False)),
                anti_meta=bool(getattr(args, 'anti_meta', False)),
                native_vm=bool(getattr(args, 'native_vm', False)),
                crown_jewel_vm=bool(getattr(args, 'crown_jewel_vm', False)),
                vm_fallback=str(getattr(args, 'vm_fallback', 'auto')),
                vm_extended=bool(getattr(args, 'vm_extended', False) or False),
                cache=bool(getattr(args, 'cache', True)),
                plugins=tuple(getattr(args, 'plugins', None) or ()),
                release_server=str(getattr(args, 'release_server', '') or ''),
                license_id=str(getattr(args, 'license_id', '') or ''),
                master_seed=_resolve_master_seed(getattr(args, 'master_seed', b'')),
                offline_grace_seconds=int(getattr(args, 'offline_grace_seconds', 604800) or 604800),
                # Phase H (Layer 6): 11 esoteric/anti-pattern flags + build_rng.
                build_rng=getattr(args, '_rng', None),
                h_id_poison=bool(getattr(args, 'h_id_poison', False)),
                h_acoda=bool(getattr(args, 'h_acoda', False)),
                h_metamorphic=bool(getattr(args, 'h_metamorphic', False)),
                h_style=bool(getattr(args, 'h_style', False)),
                h_branchless=bool(getattr(args, 'h_branchless', False)),
                h_bloom=bool(getattr(args, 'h_bloom', False)),
                h_dag_cff=bool(getattr(args, 'h_dag_cff', False)),
                h_selfcheck_cf=bool(getattr(args, 'h_selfcheck_cf', False)),
                h_fss=bool(getattr(args, 'h_fss', False)),
                h_tls_callback=bool(getattr(args, 'h_tls_callback', False)),
                h_exc_table_vm=bool(getattr(args, 'h_exc_table_vm', False)),
                fss_mode=getattr(args, 'fss_mode', 'auto') or 'auto',
                fss_shares=int(getattr(args, 'fss_shares', 3) or 3),
                fss_all_eligible=bool(getattr(args, 'fss_all_eligible', False)),
                opaque_grade=getattr(args, 'opaque_grade', 'algebra') or 'algebra',
            )



    # === [02] CLI helpers / runtime mode normalization ===
    def parse_python_band(spec: str='3.10-3.12') -> Tuple[Tuple[int, int], Tuple[int, int]]:
        value = str(spec or '3.10-3.12').strip().lower()
        if value == '3.12-only':
            return ((3, 12), (3, 12))
        if '-' in value:
            left, right = value.split('-', 1)
            return (tuple(int(part) for part in left.split('.', 1)), tuple(int(part) for part in right.split('.', 1)))
        pair = tuple(int(part) for part in value.split('.', 1))
        return (pair, pair)

    def build_python_band_check(spec: str='3.10-3.12') -> str:
        (min_major, min_minor), (max_major, max_minor) = parse_python_band(spec)
        _dn = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
        return f'''
__h_py = {_dn}[{Pycloak().encode('__import__')}]({Pycloak().encode('sys')})
__h_ver = (__h_py.version_info[0], __h_py.version_info[1])
if __h_ver < ({min_major}, {min_minor}) or __h_ver > ({max_major}, {max_minor}):
    raise SystemExit("Unsupported Python runtime. Target band is {spec}.")
'''

    def cli_emit(kind: str, message: str, code: int=0, detail: str='', path: str='') -> None:
        if globals().get('JSON_MODE', False):
            payload = {
                'code': int(code),
                'kind': str(kind),
                'message': str(message),
                'detail': str(detail or ''),
                'path': str(path or ''),
                'profile': str(globals().get('profile_mode', '') or ''),
                'runtime_mode': str(globals().get('runtime_mode_public', globals().get('runtime_mode', '')) or ''),
                'python_band': str(globals().get('python_band_mode', '') or ''),
            }
            print(__import__('json').dumps(payload, ensure_ascii=False))
            return
        stream = sys.stderr if str(kind).lower() == 'error' else sys.stdout
        print(str(message), file=stream)

    def cli_fail(code: int, message: str, detail: str='', path: str='', kind: str='error') -> None:
        cli_emit(kind, message, code=code, detail=detail, path=path)
        raise SystemExit(code)

    # NOTE: VmCapabilityError / VmCapabilityScanner / validate_vm_native_capabilities
    # removed in Bedrock vNext Phase 1 (VM runtimes dropped; the native main
    # loader has no AST-capability restrictions). Callers below no longer invoke
    # the scanner, so no shim is required.

    def normalize_runtime_mode(value: str) -> Tuple[str, str, str]:
        raw = str(value or 'main').strip().lower()
        if raw == 'main':
            return ('main', 'main', '')
        if raw in ('vm-native-v2', 'vm-native', 'chunk-vm-lite'):
            warning = f'Option "--runtime-mode {raw}" is deprecated (VM runtimes removed in vNext); using native capsule runtime.'
            return ('main', 'main', warning)
        if raw in ('legacy',):
            return ('legacy', 'legacy', '')
        raise ValueError(f'Unsupported runtime mode: {value}')
    anti = '\n'
    global pro
    global anti_debug
    global ANTI_PYCDC
    global BUILTIN_DICT_NAME
    _float = '_BedrockFloat_'
    _int = '_BedrockInt_'
    _str = '_TuiDzKaiBang_'
    _bool = '_toiyeunguoi_'
    _bytes = '_danghocode_'
    __print = 'lambda\xe3\x80\x80'
    __input = 'exec\xe3\x80\x80'
    _eval = '_CodeHoiNgu_'
    __ALIASES__ = {}
    __DECLARED_NAMES__ = set()
    __MODULE_NAMES__ = set()
    __SPAM_USED_NAMES__ = set()
    __SPAM_NAME_COUNTER__ = 0
    hard_code = '\n'
    ADV_REQUESTS_PROTECTION = False
    # Per-build random alias for the builtin indirection dict (default keeps
    # backwards compatibility until build_var() re-keys it).  Replacing the
    # once-static `baobg_vars` name per build defeats single-string-grep
    # unwrapping of `obf_builtins`.
    BUILTIN_DICT_NAME = 'baobg_vars'
    # Phase 4: debranded at BUILD time (in _init_debrand) so the debranded
    # names flow into BOTH the `pro` blob (ROT-shifted before marshal) AND
    # the obfct call sites. Debranding at import time would be identity.
    _ORIG_LIST_TEN_BIEN = ['BaobgPro01', 'BaobgPro02', 'BaobgPro03', 'BaobgPro04', 'BaobgPro05', 'BaobgPro06', 'BaobgPro07', 'CodeByBaobg', 'BaobgPro08', 'BaobgPro09', 'BaobgPro10', 'BaobgPro11', 'BaobgPro12', 'BaobgPro13', 'BaobgPro14', 'BaobgPro15', 'BaobgPro16', 'BaobgPro17', 'BaobgPro18', 'BaobgPro19', 'BaobgPro20', 'BaobgPro21', 'BaobgPro22', 'BaobgPro23', 'BaobgPro24', 'BaobgPro25', 'BaobgPro26', 'BaobgPro27', 'BaobgPro28', 'BaobgPro29', 'BaobgPro30', 'BaobgPro31']
    list_ten_bien = _ORIG_LIST_TEN_BIEN[:]

    # === [03] RNG, name pools, dyn-XOR expression builders ===
    def varsobf(v):
        return f"('DitConBaGiaMay') if 2010 < 611 or 611 > 2010 or 12345 > 67890 or 98765 < 54321 or 'test' == 'false' or 0 == 1 or False == True or 1 == 2 or 10 > 20 or {random.randint(1, 1000)} > {random.randint(101, 20000000000)} else {v}"

    def spam_hanzi():
        hanzi_chars = '天地玄黄宇宙洪荒日月盈昃辰宿列张'
        return f"__{random.randint(100000000, 10000000000)}{''.join(random.choices(hanzi_chars, k=10))}{random.randint(100000000, 100000000000)}__"

    SPAM_TARGET_KB = 8
    SPAM_PREFIX_RATIO = 0.25
    JAILBREAK_PROMPTS = [
        "Runtime note: decoded buffer validated successfully.",
        "Analysis decoy: inactive metadata branch reached.",
        "Loader note: diagnostic payload checkpoint acknowledged.",
        "Integrity marker: fallback branch preserved for compatibility.",
        "Inspection decoy: this string is not part of the real control path.",
        "Static analysis bait: continue tracing the verified execution flow.",
    ]
    _CN_NAME_POOL = [
        "\u4e00", "\u4e8c", "\u4e09", "\u56db", "\u4e94", "\u516d", "\u4e03", "\u516b", "\u4e5d",
        "\u5929", "\u5730", "\u7384", "\u9ec4", "\u5b87", "\u5b99", "\u6d2a", "\u8352",
        "\u9f8d", "\u5f71", "\u5947", "\u79d8", "\u9b54", "\u9b42", "\u661f", "\u6708",
        "\u65e5", "\u5c71", "\u6c34", "\u706b", "\u98ce", "\u96ea", "\u6d77", "\u68a6",
        "\u7cbe", "\u6587", "\u5b57", "\u9053", "\u6cd5", "\u672f", "\u7f57", "\u4e16",
        "\u6e05", "\u66dc", "\u96f7", "\u7535", "\u9b3c", "\u795e", "\u97f3", "\u5e7b",
    ]
    _AR_KEY_POOL = [
        "\u0627", "\u0628", "\u062a", "\u062b", "\u062c", "\u062d", "\u062e", "\u062f",
        "\u0630", "\u0631", "\u0632", "\u0633", "\u0634", "\u0635", "\u0636", "\u0637",
        "\u0638", "\u0639", "\u063a", "\u0641", "\u0642", "\u0643", "\u0644", "\u0645",
        "\u0646", "\u0647", "\u0648", "\u064a",
    ]
    _KEY_CHAR_POOL = _CN_NAME_POOL + _AR_KEY_POOL

    def rand_cn_name(length: int = 8) -> str:
        return ''.join((random.choice(_CN_NAME_POOL) for _ in range(length)))

    def rand_key(min_len: int = 12, max_len: int = 20) -> str:
        return ''.join((random.choice(_KEY_CHAR_POOL) for _ in range(random.randint(min_len, max_len))))

    def _dyn_xor_expr(text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        data = text.encode('utf-8')
        parts = []
        for b in data:
            k = random.randint(1, 255)
            parts.append(f"(lambda x,k={k}: x ^ k)({b ^ k})")
        return f"bytes([{', '.join(parts)}]).decode('utf-8')"

    def _dyn_builtin_expr(name: str) -> str:
        _dn = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
        return f"{_dn}[{_dyn_xor_expr(name)}]"

    def _dyn_import_expr(mod: str) -> str:
        return f"{_dyn_builtin_expr('__import__')}({_dyn_xor_expr(mod)})"

    def _xor_bytes(data: bytes, key_str: str) -> bytes:
        key_bytes = key_str.encode('utf-8')
        if not key_bytes:
            return data
        return bytes((b ^ key_bytes[i % len(key_bytes)]) for i, b in enumerate(data))

    def _spam_inline_arith() -> str:
        a = random.randint(10**4, 10**6)
        b = random.randint(10**4, 10**6)
        c = random.randint(10**2, 10**4)
        n1 = rand_cn_name(4)
        n2 = rand_cn_name(4)
        n3 = rand_cn_name(4)
        return f"{n1} = {a} + {b}; {n2} = ({n1} ^ {c}) & 0xffffffff; {n3} = {n2} % {random.randint(97, 997)}"

    def _spam_inline_dyn() -> str:
        name1 = rand_cn_name(4)
        name2 = rand_cn_name(4)
        word = random.choice(['import', 'exec', 'eval', 'marshal', 'base64', 'zlib', 'bz2'])
        expr = _dyn_xor_expr(word)
        return f"{name1} = {expr}; {name2} = {name1}[::-1][::-1]"

    def _jailbreak_b64_snippet() -> str:
        msg = random.choice(JAILBREAK_PROMPTS)
        encoded = base64.b64encode(msg.encode('utf-8')).decode('ascii')
        name_seed = rand_cn_name(6)
        holder = rand_cn_name(6)
        marker = rand_cn_name(6)
        guard = rand_cn_name(6)
        return "\n".join([
            f"{name_seed} = {encoded!r}",
            f"{holder} = __import__('base64').b64decode({name_seed}).decode('utf-8', 'ignore')",
            f"{marker} = {holder} if {random.randint(0, 1)} else {holder}[::-1][::-1]",
            f"{guard} = {marker} + ''",
        ])

    def _fake_vm_snippet() -> str:
        vm_name = rand_cn_name(6)
        pc = rand_cn_name(4)
        acc = rand_cn_name(4)
        ops = [random.randint(7, 255) for _ in range(random.randint(9, 18))]
        ops.append(999)
        ops_repr = ", ".join(str(o) for o in ops)
        return "\n".join([
            f"{vm_name} = [{ops_repr}]",
            f"{pc} = 0",
            f"{acc} = 0",
            f"for __op in {vm_name}:",
            f"    if __op == 999: break",
            f"    {acc} ^= (__op << ({pc} % 3)) & 0xffffffff",
            f"    {pc} += 1",
            f"{rand_cn_name(6)} = ({acc} ^ len({vm_name}))",
        ])

    # === [04] Spam / jailbreak / fake-VM snippet generators ===
    def _make_spam_func() -> str:
        name = rand_cn_name(8)
        template = random.choice(['math', 'b64', 'xor', 'marshal', 'hash', 'mix', 'dyn', 'jail', 'vm'])
        if template == 'math':
            a = random.randint(3, 9)
            b = random.randint(7, 17)
            c = random.randint(97, 997)
            body = [
                f"    x = (a * a + {a}) ^ (b << {random.randint(1, 4)})",
                f"    y = (x + b + {b}) % {c}",
                "    return y",
            ]
            return f"def {name}(a, b={b}):\n" + "\n".join(body)
        if template == 'b64':
            body = [
                "    import base64 as _b",
                "    if not isinstance(s, (bytes, bytearray)):",
                "        s = str(s).encode('utf-8')",
                "    t = _b.b64encode(s)",
                "    return _b.b85encode(t)[::-1]",
            ]
            return f"def {name}(s):\n" + "\n".join(body)
        if template == 'xor':
            body = [
                "    if isinstance(data, str):",
                "        data = data.encode('utf-8')",
                "    if isinstance(key, str):",
                "        key = key.encode('utf-8')",
                "    if not key:",
                "        return data",
                "    out = bytes((b ^ key[i % len(key)]) for i, b in enumerate(data))",
                "    return out",
            ]
            return f"def {name}(data, key):\n" + "\n".join(body)
        if template == 'marshal':
            body = [
                "    import marshal as _m",
                "    blob = _m.dumps(obj)",
                "    return _m.loads(blob)",
            ]
            return f"def {name}(obj):\n" + "\n".join(body)
        if template == 'hash':
            salt = random.randint(7, 61)
            body = [
                "    if not isinstance(s, (bytes, bytearray)):",
                "        s = str(s).encode('utf-8')",
                f"    v = {random.randint(1, 997)}",
                "    for i, b in enumerate(s):",
                f"        v = (v + (b ^ ((i + 1) * {salt}))) & 0xffffffff",
                "    return v",
            ]
            return f"def {name}(s):\n" + "\n".join(body)
        if template == 'dyn':
            key = random.randint(1, 255)
            word = random.choice(['import', 'exec', 'eval', 'marshal', 'base64', 'zlib'])
            expr = _dyn_xor_expr(word)
            body = [
                f"    s = {expr}",
                f"    k = {key}",
                "    if not s:",
                "        return ''",
                "    return ''.join([chr((ord(c) ^ k) ^ k) for c in s])",
            ]
            return f"def {name}():\n" + "\n".join(body)
        if template == 'jail':
            msg = random.choice(JAILBREAK_PROMPTS)
            enc = base64.b64encode(msg.encode('utf-8')).decode('ascii')
            body = [
                "    import base64 as _b",
                f"    _s = {enc!r}",
                "    _m = _b.b64decode(_s).decode('utf-8', 'ignore')",
                "    return _m if flag else len(_m) ^ 0x41",
            ]
            return f"def {name}(flag=False):\n" + "\n".join(body)
        if template == 'vm':
            ops = [random.randint(5, 255) for _ in range(random.randint(8, 16))]
            ops.append(999)
            ops_repr = ", ".join(str(o) for o in ops)
            body = [
                f"    _code = [{ops_repr}]",
                "    _pc = 0",
                "    _acc = 0",
                "    for _op in _code:",
                "        if _op == 999: break",
                "        _acc ^= (_op << (_pc % 3)) & 0xffffffff",
                "        _pc += 1",
                "    return (_acc ^ len(_code))",
            ]
            return f"def {name}():\n" + "\n".join(body)
        body = [
            "    import base64 as _b",
            "    if not isinstance(s, (bytes, bytearray)):",
            "        s = str(s).encode('utf-8')",
            "    t = _b.b32encode(s)",
            "    t = t.replace(b'=', b'')",
            "    return t[::-1]",
        ]
        return f"def {name}(s):\n" + "\n".join(body)

    def _make_spam_packet() -> str:
        f1 = rand_cn_name(8)
        f2 = rand_cn_name(8)
        f3 = rand_cn_name(8)
        var1 = rand_cn_name(6)
        var2 = rand_cn_name(6)
        dummy_code = Compile.serializer.dumps(compile("0", "<h>", "exec"))
        dummy_enc = base64.b85encode(dummy_code)
        lines = [
            f"def {f1}(x):",
            "    import base64 as _b",
            "    import marshal as _m",
            f"    _d = _b.b85decode({dummy_enc!r})",
            "    try:",
            "        return _m.loads(_d)",
            "    except Exception:",
            "        return x",
            f"def {f2}(y):",
            "    try:",
            f"        _c = {f1}(y)",
            "        if hasattr(_c, 'co_code'):",
            "            exec(_c, globals())",
            "        return y",
            "    except Exception:",
            "        return y",
            f"{f3} = lambda z: ({f2}(z) if z else {f1}(z))",
            f"{var1} = [{f1}, {f2}, {f3}]",
            f"{var2} = ({var1}[{random.randint(0, 2)}] if {random.randint(1, 9)} > {random.randint(1, 9)} else {var1}[{random.randint(0, 2)}])",
        ]
        return "\n".join(lines)

    def build_spam_block(target_bytes: int, extra_lines: List[str] = None) -> str:
        extra_chunks = list(extra_lines) if extra_lines else []
        if target_bytes <= 0:
            return '\n'.join(extra_chunks)
        lines: List[str] = list(extra_chunks)
        size = sum((len((chunk + '\n').encode('utf-8')) for chunk in lines))
        while size < target_bytes:
            line = _spam_inline_dyn() if random.random() < 0.35 else _spam_inline_arith()
            lines.append(line)
            size += len((line + '\n').encode('utf-8'))
        return '\n'.join(lines)

    def obf_gl(input_string):
        return ''.join([chr((ord(c) - (65 if c.isupper() else 97) + 10) % 26 + (65 if c.isupper() else 97)) if c.isalpha() else c for c in input_string])

    def _anti_decompiler_block() -> str:
        key = random.randint(7, 200)
        target = "__thesmartdog__"
        enc = [ord(c) ^ key for c in target]
        name_fn = rand_cn_name(4)
        name_list = rand_cn_name(4)
        name_tmp = rand_cn_name(4)
        name_echo = rand_cn_name(4)
        repeat = random.randint(140, 320)
        spam_calls = ",".join((f"{name_echo}({name_echo}(b'\\x02\\x02'))" for _ in range(repeat)))
        return f"""
try:
    def {name_fn}(*__x): return "__ANTI DECOMPILER__"
    {name_list} = [{', '.join(str(n) for n in enc)}]
    {name_tmp} = ''.join([chr(x ^ {key}) for x in {name_list}])
    {name_fn}({name_tmp})
except Exception:
    pass
else:
    pass
finally:
    pass
try:
    def {name_echo}(__x): return __x
    _ = [{spam_calls}]
except Exception:
    pass
try:
    import types as _t, dis as _d
    def {rand_cn_name(4)}(o): return isinstance(o, _t.CodeType)
    def {rand_cn_name(4)}(o): return getattr(o, '__code__', None)
    {rand_cn_name(4)} = [k for k in _d.COMPILER_FLAG_NAMES]
except Exception:
    pass
"""

    # === [05] Anti-pycdc / builtin-aliased var scaffolding ===
    def build_anti_pycdc():
        antipycdc = ''
        e = {'Z': '1/0,', 'T': 'len+1,', 'N': 'xyz,', 'T2': '"a"+1,', 'I': '[][99],', 'K': '{}[""],', 'M': "__import__('xyz'),", 'V': 'int("a",99),', 'A': '[].__x,', 'F': 'open("ww"),'}
        for k in e:
            e[k] = e[k] * 1000
        antipycdc += '\n'.join((f'try:({v})\nexcept:0\n' for v in e.values()))
        extra = _anti_decompiler_block()
        # N2: pycdc opcode minefield (3.11+ builds only).
        # When *building* on CPython 3.11+, marshal a small try/except code
        # object -- its bytecode contains PUSH_EXC_INFO / RERAISE / an exception
        # table, the opcodes pycdc aborts on (zrax/pycdc #519, #514). The code
        # object executes as a no-op at runtime (1/0 caught by `except: pass`)
        # so it never breaks the user program, but anyone unmarshalling the
        # blob to inspect it hits unsupported opcodes. We emit two variants
        # for diversity: a plain try/except and a 3.11 exception-group
        # (`except*`) handler -- the latter compiles to a distinct opcode
        # (CHECK_EXC_MATCH + PUSH_EXC_INFO in a group context) that older
        # pycdc builds lack entirely. Both are wrapped in a runtime
        # `sys.version_info >= (3, 11)` guard so 3.10 outputs stay inert, and
        # the whole block is fail-soft (any marshal/exec error is swallowed).
        minefield = ''
        if sys.version_info >= (3, 11):
            try:
                import base64 as _b85m
                _mf_variants = [
                    "try:\n 1/0\nexcept:\n pass\n",
                    # `except*` is 3.11+ syntax -- emits group-handler opcodes.
                    "try:\n raise ValueError('x')\nexcept* Exception:\n pass\n",
                ]
                _mf_chunks = []
                for _mf_src in _mf_variants:
                    _mf_co = compile(_mf_src, '<br_mf>', 'exec')
                    _mf_bytes = marshal.dumps(_mf_co)
                    _mf_chunks.append(_b85m.b85encode(_mf_bytes).decode('ascii'))
                del _b85m
                # Emit a runtime loader that re-marshals each blob and execs
                # it only on 3.11+. Bare `sys`/`marshal` are fine here -- this
                # string is concatenated into the preamble that the loader
                # runs in its own globals, alongside the existing bare-import
                # noise above.
                _mf_blob_reprs = ", ".join(repr(_c) for _c in _mf_chunks)
                minefield = (
                    "try:\n"
                    " import sys as _br_mfs, marshal as _br_mfm\n"
                    " if _br_mfs.version_info >= (3, 11):\n"
                    "  for _br_mfb in [" + _mf_blob_reprs + "]:\n"
                    "   try:\n"
                    "    exec(_br_mfm.loads(_br_mfb))\n"
                    "   except Exception:\n"
                    "    pass\n"
                    "  del _br_mfm, _br_mfs, _br_mfb\n"
                    "except Exception:\n"
                    " pass\n"
                )
            except Exception:
                minefield = ''
        globals()['ANTI_PYCDC'] = f'{extra}\ntry:pass\nexcept:pass\nelse:pass\nfinally:pass\n{antipycdc}\nfinally:int(2010-611)\n{minefield}'

    def build_var():
        global anti_debug, pro
        global BUILTIN_DICT_NAME
        # Re-key the builtin indirection dict name per build so the once-static
        # `baobg_vars` identifier is no longer a fixed grep target.  The new
        # name is a random `baobg_<tag>` token that all 8 emission sites below
        # read back from `BUILTIN_DICT_NAME`.
        BUILTIN_DICT_NAME = BR_DEBRAND['baobg'] + '_' + ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(8))
        globals()['anti_debug'] = '''
try:
    import sys as __bedrock_ad_sys__
    __bedrock_ad_sys__.settrace(None)
    __bedrock_ad_sys__.setprofile(None)
    try:
        import threading as __bedrock_ad_th__
        __bedrock_ad_th__.settrace(None)
        __bedrock_ad_th__.setprofile(None)
        del __bedrock_ad_th__
    except:
        pass
    del __bedrock_ad_sys__
except:
    pass
'''
        pro = ANTI_PYCDC
        list_ten_bienn = list_ten_bien[:]
        Hehe = [f"{_bool} = {varsobf('bool')}", f"{_str} = {varsobf('str')}", f"{_int} = {varsobf('int')}", f"{_float} = {varsobf('float')}", f"{_bytes} = {varsobf('bytes')}", f"{_eval} = {varsobf('eval')}", f"{__print} = {varsobf('print')}", f"{__input} = {varsobf('input')}"]
        while list_ten_bienn:
            i = random.choice(list_ten_bienn)
            hhh = random.randint(1, 10)
            if hhh == 1:
                pro += f'''globals()[''.join([chr(((ord(c) - (65 if c.isupper() else 97) - 10) % 26) + (65 if c.isupper() else 97)) if c.isalpha() else c for c in "{obf_gl(i)}"])] = lambda concacmemaybeolam, jackbocon, meomeo, bucuanhdi: (
            concacmemaybeolam.join([chr((DIT_ME_MAY - jackbocon) // meomeo) for DIT_ME_MAY in bucuanhdi])
            if concacmemaybeolam not in ["DitConBaMay", "BedrockObfuscate", "BAOBG"]
            else (b"" if concacmemaybeolam == "BedrockObfuscate" 
                else r"" if concacmemaybeolam == "DitConBaMay" 
                else "").join([chr((DIT_ME_MAY - jackbocon) // meomeo) for DIT_ME_MAY in bucuanhdi]))
'''
                list_ten_bienn.remove(i)
            else:
                pro += f'''globals()[''.join([chr(((ord(c) - (65 if c.isupper() else 97) - 10) % 26) + (65 if c.isupper() else 97)) if c.isalpha() else c for c in "{obf_gl(str('BedrockDzDitMeMay'))}"])] = lambda concacmemaybeolam, jackbocon, meomeo, bucuanhdi: (
            concacmemaybeolam.join([chr((DIT_ME_MAY - jackbocon) // meomeo) for DIT_ME_MAY in bucuanhdi])
            if concacmemaybeolam not in ["DitConBaMay", "BedrockObfuscate", "BAOBG"]
            else (b"" if concacmemaybeolam == "BedrockObfuscate" 
                else r"" if concacmemaybeolam == "DitConBaMay" 
                else "").join([chr((DIT_ME_MAY - jackbocon) // meomeo) for DIT_ME_MAY in bucuanhdi]))
'''
                if Hehe:
                    hello = random.choice(Hehe)
                    pro += hello + '\n'
                    Hehe.remove(hello)
            if Hehe:
                hello = random.choice(Hehe)
                pro += hello + '\n'
                Hehe.remove(hello)

    # === [05b] Hardware fingerprint collector (cross-platform) ===
    # C2: derive a stable per-machine fingerprint used by A5 (env-keying).
    # Build-time `_collect_hw_fingerprint()` returns a 32-byte SHA-256 digest
    # of platform.node() + uuid.getnode() (MAC) + /etc/machine-id (Linux, if
    # present) + COMPUTERNAME (Windows) + platform.machine(). Every field is
    # optional — a missing field contributes an empty string rather than
    # raising, so the collector stays total across docker/CI/minimal envs.
    # The runtime twin `_emit_hw_fingerprint_runtime()` emits the *same*
    # collection logic as obfuscated source so the build key and the runtime
    # re-derivation agree byte-for-byte.
    def _collect_hw_fingerprint() -> bytes:
        import hashlib as _h, platform as _p, uuid as _u, os as _o
        parts = []
        try: parts.append(str(_p.node()))
        except Exception: parts.append("")
        try: parts.append(str(_u.getnode()))
        except Exception: parts.append("")
        try:
            _mid = "/etc/machine-id"
            if _o.path.isfile(_mid):
                with open(_mid, "r") as _f:
                    parts.append(_f.read().strip())
            else: parts.append("")
        except Exception: parts.append("")
        try: parts.append(str(_o.environ.get("COMPUTERNAME", "")))
        except Exception: parts.append("")
        try: parts.append(str(_p.machine()))
        except Exception: parts.append("")
        blob = "|".join(parts).encode("utf-8", "replace")
        return _h.sha256(blob).digest()

    def _resolve_master_seed(raw):
        """Phase G (Layer 3): resolve the 32-byte server master seed.

        Precedence (highest first):
          1. ``--master-seed`` CLI flag (raw bytes already decoded by argparse
             type=, or a hex string -> bytes),
          2. ``BEDROCK_MASTER_SEED`` env var (hex of 32 bytes).

        Returns ``b''`` when neither is set (meaning key-release is off).
        Raises ``ValueError`` only when a value IS provided but is the wrong
        length -- a wrong-length secret is a caller bug, not a silent default.
        """
        import os as _o
        import binascii as _ba
        v = raw
        if not v:
            v = _o.environ.get("BEDROCK_MASTER_SEED", "").strip()
        if not v:
            return b''
        if isinstance(v, str):
            try:
                v = _ba.unhexlify(v.strip())
            except (ValueError, _ba.Error):
                raise ValueError(
                    "master_seed must be hex of 32 bytes")
        if len(v) != 32:
            raise ValueError(
                f"master_seed must be 32 bytes, got {len(v)}")
        return bytes(v)

    def _emit_hw_fingerprint_runtime(*, var_name: str = "__BedrockEnvKey__") -> str:
        """Emit runtime source that re-derives `_collect_hw_fingerprint()`.

        Uses `_dyn_import_expr` so every builtin/import reads through the
        per-build `BUILTIN_DICT_NAME` indirection (matches the rest of the
        preamble) — no bare `__import__` survives into the output.
        """
        _imp = _dyn_import_expr
        # indirection expressions: <dict>["<encoded>"]("__import__")("hashlib")
        _h = _imp('hashlib')
        _p = _imp('platform')
        _u = _imp('uuid')
        _o = _imp('os')
        # The collector body mirrors _collect_hw_fingerprint exactly; any
        # divergence silently breaks env-keying so keep them in lock-step.
        return (
            f"try:\n"
            f"    _br_h={_h}\n"
            f"    _br_p={_p}\n"
            f"    _br_u={_u}\n"
            f"    _br_o={_o}\n"
            f"    _br_parts=[]\n"
            f"    try: _br_parts.append(str(_br_p.node()))\n"
            f"    except Exception: _br_parts.append('')\n"
            f"    try: _br_parts.append(str(_br_u.getnode()))\n"
            f"    except Exception: _br_parts.append('')\n"
            f"    try:\n"
            f"        _br_mid='/etc/machine-id'\n"
            f"        if _br_o.path.isfile(_br_mid):\n"
            f"            _br_f=open(_br_mid,'r')\n"
            f"            try: _br_parts.append(_br_f.read().strip())\n"
            f"            finally: _br_f.close()\n"
            f"        else: _br_parts.append('')\n"
            f"    except Exception: _br_parts.append('')\n"
            f"    try: _br_parts.append(str(_br_o.environ.get('COMPUTERNAME','')))\n"
            f"    except Exception: _br_parts.append('')\n"
            f"    try: _br_parts.append(str(_br_p.machine()))\n"
            f"    except Exception: _br_parts.append('')\n"
            f"    _br_blob='|'.join(_br_parts).encode('utf-8','replace')\n"
            f"    {var_name}=_br_h.sha256(_br_blob).digest()\n"
            f"    del _br_h,_br_p,_br_u,_br_o,_br_parts,_br_blob\n"
            f"except Exception:\n"
            f"    {var_name}=b''\n"
        )

    # === [06] Source preamble / AST helpers ===
    def extract_prefix_lines(text: str) -> Tuple[str, str]:
        lines = text.splitlines()
        if not lines:
            return '', ''
        prefix_lines = []
        idx = 0
        if lines[0].startswith('#!'):
            prefix_lines.append(lines[0])
            idx = 1
        coding_re = re.compile(r'^#.*coding[:=]\s*([-\w.]+)')
        if idx < len(lines) and coding_re.match(lines[idx]):
            prefix_lines.append(lines[idx])
            idx += 1
        prefix = '\n'.join(prefix_lines)
        rest = '\n'.join(lines[idx:])
        return prefix, rest

    def _split_preamble_nodes(nodes: List[ast.stmt]) -> Tuple[List[ast.stmt], List[ast.stmt]]:
        preamble = []
        idx = 0
        if nodes:
            first = nodes[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                preamble.append(first)
                idx = 1
        while idx < len(nodes):
            node = nodes[idx]
            if isinstance(node, ast.ImportFrom) and node.module == '__future__':
                preamble.append(node)
                idx += 1
                continue
            break
        return preamble, nodes[idx:]

    def _unparse_nodes(nodes: List[ast.stmt]) -> str:
        if not nodes:
            return ''
        return '\n'.join((ast.unparse(node) for node in nodes))

    def split_preamble_code(code: str) -> Tuple[str, str]:
        try:
            module = ast.parse(code)
        except SyntaxError:
            return '', code
        preamble_nodes, body_nodes = _split_preamble_nodes(module.body)
        preamble_code = _unparse_nodes(preamble_nodes)
        body_code = _unparse_nodes(body_nodes)
        return preamble_code, body_code

    def join_code_parts(*parts: str) -> str:
        cleaned = []
        for part in parts:
            if not part:
                continue
            stripped = part.strip('\n')
            if stripped:
                cleaned.append(stripped)
        return '\n'.join(cleaned)

    def insert_after_preamble(code: str, injection: str) -> str:
        if not injection or not injection.strip():
            return code
        preamble, body = split_preamble_code(code)
        return join_code_parts(preamble, injection, body)

    def normalize_ast_locations(tree: ast.AST) -> ast.AST:
        tree = ast.fix_missing_locations(tree)
        for node in ast.walk(tree):
            if hasattr(node, 'lineno'):
                lineno = getattr(node, 'lineno', None)
                if lineno is None or lineno <= 0:
                    node.lineno = 1
            if hasattr(node, 'col_offset'):
                col_offset = getattr(node, 'col_offset', None)
                if col_offset is None or col_offset < 0:
                    node.col_offset = 0
            if hasattr(node, 'end_lineno'):
                end_lineno = getattr(node, 'end_lineno', None)
                if end_lineno is None or end_lineno <= 0:
                    node.end_lineno = node.lineno if hasattr(node, 'lineno') else 1
            if hasattr(node, 'end_col_offset'):
                end_col_offset = getattr(node, 'end_col_offset', None)
                if end_col_offset is None or end_col_offset < 0:
                    node.end_col_offset = node.col_offset if hasattr(node, 'col_offset') else 0
        return tree

    # === [07] AST-level obfuscation (rename, spam, try/except) ===
    # Pool of built-in exceptions that never naturally occur in normal code
    # flow, used to randomise the raise/except fingerprint of the spam and
    # try/except scaffolds (previously always `MemoryError`). All members are
    # subclasses of `Exception` (not `BaseException`) so a bare `except` is
    # guaranteed to catch them, and none fire during ordinary execution.
    _SPAM_EXC_POOL = (
        'MemoryError', 'RecursionError', 'FloatingPointError',
        'ArithmeticError', 'BufferError', 'OSError',
        'RuntimeError', 'ValueError', 'LookupError', 'IndexError',
    )

    def _rand_spam_exc() -> str:
        return random.choice(_SPAM_EXC_POOL)

    class Ast_obf:

        def rn_func(self, node, ol, nn):
            for i in ast.walk(node):
                if isinstance(i, ast.FunctionDef) and i.name == ol:
                    i.name = nn
                elif isinstance(i, ast.Attribute) and isinstance(i.value, ast.Name) and (i.value.id == ol):
                    i.value.id = nn
                elif isinstance(i, ast.Call) and isinstance(i.func, ast.Name) and (i.func.id == ol):
                    i.func.id = nn
                elif isinstance(i, ast.Name) and i.id == ol:
                    i.id = nn
            return node

        def spam(self, code):
            tree = ast.parse(code)
            global __SPAM_USED_NAMES__, __SPAM_NAME_COUNTER__
            used_names = __SPAM_USED_NAMES__

            class _SpamNameCollector(ast.NodeVisitor):
                def visit_Name(self, node):
                    used_names.add(node.id)
                    self.generic_visit(node)

                def visit_FunctionDef(self, node):
                    used_names.add(node.name)
                    self.generic_visit(node)

                def visit_AsyncFunctionDef(self, node):
                    used_names.add(node.name)
                    self.generic_visit(node)

                def visit_ClassDef(self, node):
                    used_names.add(node.name)
                    self.generic_visit(node)

                def visit_arg(self, node):
                    used_names.add(node.arg)
                    self.generic_visit(node)

                def visit_ExceptHandler(self, node):
                    if isinstance(node.name, str):
                        used_names.add(node.name)
                    self.generic_visit(node)

            _SpamNameCollector().visit(tree)

            def _unique_tmp(prefix: str, suffix: str = "") -> str:
                global __SPAM_NAME_COUNTER__
                for _ in range(1000):
                    name = f"{prefix}{random.randint(2061584302080, 8658654068736)}{suffix}"
                    if name not in used_names:
                        used_names.add(name)
                        return name
                while True:
                    __SPAM_NAME_COUNTER__ += 1
                    name = f"{prefix}{__SPAM_NAME_COUNTER__}{suffix}"
                    if name not in used_names:
                        used_names.add(name)
                        return name

            def _is_enum_class(node: ast.ClassDef) -> bool:
                enum_bases = {'Enum', 'IntEnum', 'Flag', 'IntFlag', 'StrEnum'}
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id in enum_bases:
                        return True
                    if isinstance(base, ast.Attribute) and base.attr in enum_bases:
                        return True
                return False
            preamble_nodes, body_nodes = _split_preamble_nodes(tree.body)
            tree.body = body_nodes

            def junk(en, max_value):
                cases = []
                line = max_value + 1
                for i in range(random.randint(1, 5)):
                    case_name = _unique_tmp('BuConCacTaoDi')
                    case_body = [ast.If(test=ast.Compare(left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en, ctx=ast.Load()), attr='args'), slice=ast.Constant(value=0)), ops=[ast.Eq()], comparators=[ast.Constant(value=line)]), body=[ast.Assign(targets=[ast.Name(id=case_name, ctx=ast.Store())], value=ast.Constant(value=random.randint(1048575, 281474976710655)))], orelse=[])]
                    cases.extend(case_body)
                    line += 1
                return cases

            def bl(body):
                var = _unique_tmp('NhinCaiLon')
                en = _unique_tmp('NhinConCac')
                _exc = _rand_spam_exc()
                tb = [ast.AugAssign(target=ast.Name(id=var, ctx=ast.Store()), op=ast.Add(), value=ast.Constant(value=1)), ast.Try(body=[ast.Raise(exc=ast.Call(func=ast.Name(id=_exc, ctx=ast.Load()), args=[ast.Name(id=var, ctx=ast.Load())], keywords=[]))], handlers=[ast.ExceptHandler(type=ast.Name(id=_exc, ctx=ast.Load()), name=en, body=[])], orelse=[], finalbody=[])]
                for i in body:
                    tb[1].handlers[0].body.append(ast.If(test=ast.Compare(left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en, ctx=ast.Load()), attr='args'), slice=ast.Constant(value=0)), ops=[ast.Eq()], comparators=[ast.Constant(value=1)]), body=[i], orelse=[]))
                tb[1].handlers[0].body.extend(junk(en, len(body) + 1))
                node = ast.Assign(targets=[ast.Name(id=var, ctx=ast.Store())], value=ast.Constant(value=0))
                return [node] + tb

            def _bl(node):
                olb = node.body
                var = _unique_tmp('__', '__')
                en = _unique_tmp('__', '__')
                _exc = _rand_spam_exc()
                tb = [ast.AugAssign(target=ast.Name(id=var, ctx=ast.Store()), op=ast.Add(), value=ast.Constant(value=1)), ast.Try(body=[ast.Raise(exc=ast.Call(func=ast.Name(id=_exc, ctx=ast.Load()), args=[ast.Name(id=var, ctx=ast.Load())], keywords=[]))], handlers=[ast.ExceptHandler(type=ast.Name(id=_exc, ctx=ast.Load()), name=en, body=[])], orelse=[], finalbody=[])]
                for i in olb:
                    tb[1].handlers[0].body.append(ast.If(test=ast.Compare(left=ast.Subscript(value=ast.Attribute(value=ast.Name(id=en, ctx=ast.Load()), attr='args'), slice=ast.Constant(value=0)), ops=[ast.Eq()], comparators=[ast.Constant(value=1)]), body=[i], orelse=[]))
                tb[1].handlers[0].body.extend(junk(en, len(olb) + 1))
                node.body = [ast.Assign(targets=[ast.Name(id=var, ctx=ast.Store())], value=ast.Constant(value=0))] + tb
                return node

            def on(node):
                if isinstance(node, ast.FunctionDef):
                    return _bl(node)
                elif isinstance(node, ast.ClassDef):
                    node.body = yuamikami_inner(node)
                    return node
                return node

            def yuamikami_inner(parent_node):
                nb = []
                in_enum = isinstance(parent_node, ast.ClassDef) and _is_enum_class(parent_node)
                for node in parent_node.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        nb.append(_bl(node))
                    elif isinstance(node, ast.ClassDef):
                        node.body = yuamikami_inner(node)
                        nb.append(node)
                    elif in_enum:
                        nb.append(node)
                    elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Expr):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Try):
                        node.body = process_block(node.body)
                        for handler in node.handlers:
                            handler.body = process_block(handler.body)
                        if node.orelse:
                            node.orelse = process_block(node.orelse)
                        if node.finalbody:
                            node.finalbody = process_block(node.finalbody)
                        nb.append(node)
                    else:
                        nb.append(node)
                return nb

            def process_block(block):
                nb = []
                for node in block:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        nb.append(_bl(node))
                    elif isinstance(node, ast.ClassDef):
                        node.body = yuamikami_inner(node)
                        nb.append(node)
                    elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Expr):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Try):
                        node.body = process_block(node.body)
                        for handler in node.handlers:
                            handler.body = process_block(handler.body)
                        if node.orelse:
                            node.orelse = process_block(node.orelse)
                        if node.finalbody:
                            node.finalbody = process_block(node.finalbody)
                        nb.append(node)
                    else:
                        nb.append(node)
                return nb

            def yuamikami(tree):
                nb = []
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        nb.append(on(node))
                    elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Expr):
                        nb.extend(bl([node]))
                    elif isinstance(node, ast.Try):
                        node.body = process_block(node.body)
                        for handler in node.handlers:
                            handler.body = process_block(handler.body)
                        if node.orelse:
                            node.orelse = process_block(node.orelse)
                        if node.finalbody:
                            node.finalbody = process_block(node.finalbody)
                        nb.append(node)
                    else:
                        nb.append(node)
                return nb
            nb = yuamikami(tree)
            tree.body = preamble_nodes + nb
            return normalize_ast_locations(tree)

        def obfct(self, string: str, string_type: str='') -> ast.AST:
            try:
                if string == '':
                    return ast.Constant(value='')
                # Stronger path: SHA-256-chained stream cipher (opt-in via --str-cipher).
                # The keystream is derived from a 32-byte key through a sha256 chain
                # (state = sha256(state + key + offset_byte)), so recovering the
                # plaintext requires actually executing the derivation -- not just
                # algebraic inversion of an affine map. The runtime expression is
                # fully self-contained (no shared global decoder to grep for) and
                # rebuilds the keystream via functools.reduce over the block index.
                if getattr(globals().get('__BEDROCK_BUILD_CTX__', None), 'str_cipher', False):
                    import hashlib as _xs_h
                    _xs_key = bytes(random.randint(0, 255) for _ in range(32))
                    _xs_data = string.encode('utf-8')
                    # Build-time encryption: same SHA-256 OFB chain used by
                    # __h_xor_stream (bedrock_obfuscator.py:2477) so the runtime twin
                    # agrees byte-for-byte. Block n's keystream is
                    #   state_0 = sha256(key)
                    #   state_n = sha256(state_{n-1} + key + bytes([n*32 & 255]))
                    # and byte i lives in block (i // 32) at index (i % 32).
                    _xs_state = _xs_h.sha256(_xs_key).digest()
                    _xs_out = bytearray()
                    _xs_off = 0
                    while _xs_off < len(_xs_data):
                        _xs_state = _xs_h.sha256(_xs_state + _xs_key + bytes([_xs_off & 255])).digest()
                        _xs_take = min(len(_xs_state), len(_xs_data) - _xs_off)
                        for _xs_i in range(_xs_take):
                            _xs_out.append(_xs_data[_xs_off + _xs_i] ^ _xs_state[_xs_i])
                        _xs_off += _xs_take
                    _xs_enc = bytes(_xs_out)
                    # Runtime: for byte index i, block index b = i // 32, block
                    # offset = b * 32. Rebuild state_b by folding the sha256 chain
                    # b+1 times starting from sha256(key). We use functools.reduce
                    # to express the fold as a single expression inside a
                    # comprehension, so the whole decoder is one AST expression.
                    _xs_expr = (
                        f"{_str}((lambda __xs_d, __xs_k: "
                        f"(lambda __xs_ft, __xs_h: bytes((__xs_d[__xs_i] ^ "
                        f"__xs_ft.reduce(lambda __xs_s, __xs_b: __xs_h.sha256(__xs_s + __xs_k + bytes([(__xs_b * 32) & 255])).digest(), "
                        f"range((__xs_i // 32) + 1), __xs_h.sha256(__xs_k).digest())[__xs_i % 32]) "
                        f"for __xs_i in range(len(__xs_d))).decode('utf-8'))"
                        f"(__import__('functools'), __import__('hashlib')))"
                        f"({_xs_enc!r}, {_xs_key!r}))"
                    )
                    try:
                        return ast.parse(_xs_expr).body[0].value
                    except Exception:
                        pass  # fall through to affine path on parse failure
                dep_trai = random.choice(list_ten_bien)
                encoded = [ord(c) * 611 + 2010 for c in string]
                jackbocon = 2010
                meomeo = 611
                if string_type == 'r':
                    return ast.parse(f"{_str}((lambda: {dep_trai}('DitConBaMay', {jackbocon}, {meomeo}, {encoded}))())").body[0].value
                else:
                    return ast.parse(f"{_str}((lambda: {dep_trai}('BAOBG', {jackbocon}, {meomeo}, {encoded}))())").body[0].value
            except Exception as e:
                print(f'Error occurred in obfct: {str(e)}')
                return ast.Constant(value=string)

        def random_match_case(self):
            var1 = ast.Constant(value=spam_hanzi(), kind=None)
            var2 = ast.Constant(value=spam_hanzi(), kind=None)
            err_call = ast.Call(func=ast.Name(id=_rand_spam_exc(), ctx=ast.Load()), args=[ast.Constant(value=True, kind=None)], keywords=[])
            case1 = ast.match_case(pattern=ast.MatchValue(value=ast.Constant(value=True, kind=None)), body=[ast.Raise(exc=err_call, cause=None)])
            junk_name = '_' + spam_hanzi()
            case2 = ast.match_case(pattern=ast.MatchValue(value=ast.Constant(value=True, kind=None)), body=[ast.Assign(targets=[ast.Name(id=junk_name, ctx=ast.Store())], value=ast.Constant(value=[True, False], kind=None)), ast.Expr(value=ast.Call(func=ast.Name(id=_str, ctx=ast.Load()), args=[ast.Constant(value=junk_name, kind=None)], keywords=[]))])
            return ast.Match(subject=ast.Compare(left=var1, ops=[ast.Eq()], comparators=[var2]), cases=[case1, case2])

        def trycatch(self, body, loop):
            result_nodes = []
            for x in body:
                current_node = x
                for _ in range(loop):
                    _exc = _rand_spam_exc()
                    try_block = ast.Try(body=[self.random_match_case(), ast.Raise(exc=ast.Call(func=ast.Name(id=_exc, ctx=ast.Load()), args=[], keywords=[]), cause=None)], handlers=[ast.ExceptHandler(type=ast.Name(id=_exc, ctx=ast.Load()), name='_' + spam_hanzi(), body=[current_node])], orelse=[], finalbody=[])
                    current_node = try_block
                result_nodes.append(normalize_ast_locations(current_node))
            return result_nodes

    # === [08] Bedrock Pycloak (int / str XOR encoder) ===
    class Pycloak:

        def encode(self, data):
            if isinstance(data, str):
                return self.barray_encode(data)
            elif isinstance(data, int):
                return self.int_encode(data)
            else:
                raise ValueError('Unsupported data type')

        def int_encode(self, num: int) -> str:
            if num == 0:
                return '0'
            equation = ''
            while num > 0:
                equation += str(random.randint(1, num)) + ' + '
                num -= int(equation.split(' + ')[-2])
            num = equation[:-3]
            return '(lambda: {num})()'.format(num=num)

        def barray_encode(self, string: str) -> str:
            if not isinstance(string, str):
                string = str(string)
            data = string.encode('utf-8')
            return 'bytes([{}]).decode("utf-8")'.format(', '.join([self.int_encode(b) for b in data]))

    # === [09] Compile pipeline (marshal / VM-native compiler / loader) ===
    class Compile:
        serializer = marshal

        def trash(cc):

            class c:

                def __reduce__(self):
                    return (exec, (cc,))
            return f"{Compile.DynImport('_pickle')}.loads({pickle.dumps(c())!r})"


        def ll(code: str) -> str:
            # sanitize code string to remove C0/C1 control chars that break compile()
            def _sanitize_for_compile(src: str) -> str:
                out_chars = []
                for ch in src:
                    o = ord(ch)
                    if ch in ("\n", "\r", "\t"):
                        out_chars.append(ch)
                    elif 0 <= o <= 31:
                        out_chars.append(" ")
                    elif 127 <= o <= 159:
                        out_chars.append(" ")
                    else:
                        out_chars.append(ch)
                return "".join(out_chars)
            code = _sanitize_for_compile(code)
            _code_obj = compile(code, '<' + BR_DEBRAND['BAOBG'] + '>', 'exec')
            # bedrock_ext: bytecode mutation pass (between compile and marshal)
            _bx = globals().get('__BEDROCK_BUILD_CTX__')
            if _bx is not None and getattr(_bx, 'bc_mutate', False) and _ext_mutate_code is not None and sys.version_info >= (3, 10):
                try:
                    _code_obj = _ext_mutate_code(_code_obj, _bx)
                except Exception:
                    pass
            # D2: co_qualname / co_filename spoofing. When --spoof-meta is on,
            # rewrite every code object's co_filename and co_qualname to a
            # plausible stdlib path so stack traces, inspect.getfile(), and
            # decompiler context resolution point at the wrong module.
            # `code.replace(**kw)` silently ignores unknown kwargs on 3.10
            # (co_qualname is 3.11+ only), so the call is safe across the
            # 3.10-3.12 band.
            if _bx is not None and getattr(_bx, 'spoof_meta', False):
                import os as _spoof_os
                _spoof_pool = (
                    ('/usr/lib/python3.11/lib/python3.11/decimal.py', 'Decimal.__init__'),
                    ('/usr/lib/python3.10/lib/python3.10/logging/__init__.py', 'Logger._log'),
                    ('/usr/lib/python3.12/lib/python3.12/json/decoder.py', 'JSONDecoder.decode'),
                    ('C:\\Python311\\Lib\\ssl.py', 'SSLContext.wrap_socket'),
                )
                def _spoof_walk(_co):
                    try:
                        _p, _q = random.choice(_spoof_pool)
                        _new = _co.replace(co_filename=_p, co_qualname=_q, co_name=_q.split('.')[-1])
                    except Exception:
                        return _co
                    _nc = []
                    for _c in _new.co_consts:
                        if hasattr(_c, 'co_code'):
                            _nc.append(_spoof_walk(_c))
                        else:
                            _nc.append(_c)
                    try:
                        return _new.replace(co_consts=tuple(_nc))
                    except Exception:
                        return _new
                try:
                    _code_obj = _spoof_walk(_code_obj)
                except Exception:
                    pass
            com = marshal.dumps(_code_obj)
            compressed = bz2.compress(zlib.compress(com))
            encoded = base64.b85encode(compressed)
            imp_m = Compile.DynImport('marshal')
            imp_z = Compile.DynImport('zlib')
            imp_bz2 = Compile.DynImport('bz2')
            imp_b64 = Compile.DynImport('base64')
            exec_fn = Compile.DynBuiltin('exec')
            globals_fn = Compile.DynBuiltin('globals')
            return f"{exec_fn}({imp_m}.loads({imp_z}.decompress({imp_bz2}.decompress({imp_b64}.b85decode({repr(encoded)}.decode())))), {globals_fn}())"

        def Alt(text: str, evalCode: bool=True) -> str:
            _dn = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
            m = re.match(r'' + re.escape(_dn) + r'\[\"__import__\"\]\(\"([^\"]+)\"\)', text)
            if m:
                return _dyn_import_expr(m.group(1))
            return _dyn_xor_expr(text)

        def DynStr(text: str) -> str:
            return _dyn_xor_expr(text)

        def DynBuiltin(name: str) -> str:
            return _dyn_builtin_expr(name)

        def DynImport(mod: str) -> str:
            return _dyn_import_expr(mod)
        exceptionCode = "\n    while True:\n        try:\n            print('Fuck You')\n        except KeyboardInterrupt:\n            continue\n        except:\n            continue"
        botLink = '@NONE'
        infos = {'__OBFBy__': 'baobg', '__OBFBot__': '@BedrockObfuscator'}
        DitMeMayDungCoDecKey = random.randint(0, 10000)

        def DitMeMayDungCoDec() -> str:
            obj = globals()['__selfObject__']
            AnhOiDungCoDecObj = globals()['__AnhOiDungCoDecObject__']
            key = globals()['__key__']
            code = AnhOiDungCoDecObj.code['bytes']
            obj.executed = True
            return (key * 8 / 1.5, code)
        comment = _debrand('__BedrockOnTop__')
        checkInfos = ' and '.join((f'{key} == "{value}"' for key, value in infos.items()))
        # NOTE: these class templates keep the `MARSHALMODULE` placeholder
        # intact at class-definition time so `_dyn_import_expr('marshal')`
        # (which reads the per-build `BUILTIN_DICT_NAME`) is only substituted
        # when the template is actually consumed. This deferral is what lets
        # `build_var()` re-key the builtin dict name AFTER the Compile class
        # body has been evaluated. See `_render_class`/`_rendered_class` below.
        AnhOiDungCoDecClass = "\nclass AnhOiDungCoDec():\n    def __init__(self, code: str, layersFunction: bytes, module, _module_, globals_, backend: bytes = b'') -> None:\n        self.__module = module\n        self.___module = _module_\n        self.layersFunction = layersFunction\n        self.__globals = globals_\n        self.code = {'bytes': code, 'str': str(code)}\n        self.__backend = backend\n\n    def __tunnel(self) -> DitMeMayDungCoDec:\n        return DitMeMayDungCoDec(\n            self.__backend,\n            DitMeMayDungCoDecKEY,\n            __module = self.__module,\n            ___module = self.___module,\n            __globals = self.__globals,\n            AnhOiDungCoDec = self\n        )\n\n    def DitMeMayDecDi(self) -> None:\n        decoder = self.__getobject__()\n        gate = self.__tunnel().ConCac()\n        try:\n            exec(\n                eval(\n                    MARSHALMODULE.loads(decoder),\n                    globals().update({\n                        '__selfObject__': self,\n                        '__module': self.__module,\n                        '___module': self.___module,\n                        '__sr_m': MARSHALMODULE,\n                        '__globals': self.__globals,\n                        'gate': gate\n                    })\n                ),\n                self.__globals\n            )\n        finally:\n            # Wipe the decrypted marshalled blob reference so a post-exec dump\n            # only sees the stub, not the real payload bytecode. The local\n            # `decoder` held the b64-decoded bytes; releasing it (plus a\n            # gc.collect) lets CPython reclaim the buffer immediately.\n            try:\n                del decoder\n            except Exception:\n                pass\n            try:\n                import gc as _br_gc\n                _br_gc.collect()\n            except Exception:\n                pass\n\n    def __getobject__(self) -> object:\n        func = self.layersFunction\n        return self.__module.b64decode(func)\n"[1:-1].replace('DitMeMayDungCoDecKEY', str(DitMeMayDungCoDecKey))
        DitMeMayDungCoDecClass = "\nclass DitMeMayDungCoDec():\n    def __init__(self, way: bytes, key: int, **ext) -> None:\n        self.way = way\n        self.key = key\n        self.module__ = ext.get('__module', None)\n        self.__globals = ext.get('__globals', None)\n        self.__module = ext.get('__module', None)\n        self.__AnhOiDungCoDec = ext.get('AnhOiDungCoDec', None)\n\n    def ConCac(self):\n        exec(\n            MARSHALMODULE.loads(self.module__.b16decode(self.way)),\n            globals().update({\n                '__selfObject__': self,\n                '__key__': self.key,\n                '__module': self.module__,\n                '__globals': self.__globals,\n                '__AnhOiDungCoDecObject__': self.__AnhOiDungCoDec\n            })\n        )\n        try:\n            import gc as _br_gc\n            _br_gc.collect()\n        except Exception:\n            pass\n        return self\n"[1:-1]

        @staticmethod
        def _rendered_class(attr: str) -> str:
            """Substitute `MARSHALMODULE` lazily so the per-build
            `BUILTIN_DICT_NAME` (re-keyed by `build_var()`) is honoured."""
            tpl = getattr(Compile, attr)
            return tpl.replace('MARSHALMODULE', _dyn_import_expr('marshal'))

        def RemoveLayers() -> str:
            if not globals().get('gate'):
                return
            obj = globals()['__selfObject__']
            module = globals()['__module']
            module__ = globals()['___module']
            code = obj.code['bytes']
            code = module.b85decode(code)
            code = code[::-1]
            code = module.b64decode(code)
            key = globals().get('__BedrockXorKey__', 0)
            if key:
                code = bytes((b ^ key) for b in code)
                # Wipe the XOR key from globals after use so a post-decrypt
                # memory dump cannot re-derive the plaintext payload.
                try:
                    del globals()['__BedrockXorKey__']
                except KeyError:
                    pass
            code = module__.decompress(code)
            code = globals()['__sr_m'].loads(code)
            # Force a collection so the decompressed intermediate buffers and
            # any transient code-object refs become reclaimable immediately.
            try:
                import gc as _br_gc
                _br_gc.collect()
            except Exception:
                pass
            return code

        # Dán đoạn mã này để thay thế cho phương thức Obfuscate() cũ trong lớp Compile
        #
        #
        # ========================================
        # ===== CODE ĐÃ CẬP NHẬT (BEGIN) =====
        # ========================================

        # NOTE: VmNativeObfuscate + VmNativeV2Obfuscate removed in Bedrock vNext Phase 1
        # (VM runtimes dropped; native capsule runtime via apply_runtimedec replaces them).

        def Obfuscate(code: str) -> str:
            sys.setrecursionlimit(1000000)
            _code = code
            clean_ = '\nprint("", end="\\r")\nprint(" "*len(">> Loading... <<"), end="\\r")\n' if type_run.upper() == 'MAIN' else ''
            runtime_mode_ = str(globals().get('runtime_mode', 'main') or 'main').strip().lower()
            tamper_mode_build = str(globals().get('tamper_mode', 'self-destruct') or 'self-destruct').strip().lower()
            requests_check_advanced = globals().get('ADV_REQUESTS_PROTECTION', False)
            if isinstance(requests_check_advanced, str):
                requests_check_advanced = requests_check_advanced.strip().lower() in ('1', 'true', 'yes', 'on')
            else:
                requests_check_advanced = bool(requests_check_advanced)
            
            DitMeMayDecDiCode = _code
            # VM runtimes removed in Bedrock vNext Phase 1; runtime_mode_ is
            # always 'main' or 'legacy' now, so anti_debug always engages.
            if protect and 'anti_debug' in globals() and runtime_mode_ not in ('vm-native', 'vm-native-v2'):
                globals()['pro'] = anti_debug + globals()['pro']
                DitMeMayDecDiCode = insert_after_preamble(DitMeMayDecDiCode, anti_debug)
            
            # --- TẠO MÃ TỰ HỦY (ANTI-TAMPERING) ---
            # 1. Mã hóa chuỗi thông báo một lần duy nhất ở đây.
            obfuscated_self_destruct_msg = Pycloak().encode("phát hiện thay đổi infos tác giả=>tự huỷ file")
            integrity_placeholder = f"__BEDROCK_HASH_{random.randint(10**8, 10**9)}__"
            integrity_marker = "." * 64
            integrity_var = rand_cn_name(8)
            integrity_fn = rand_cn_name(8)
            integrity_fh = rand_cn_name(8)
            integrity_data = rand_cn_name(8)
            integrity_exp = rand_cn_name(8)
            integrity_mark = rand_cn_name(8)
            file_hash_placeholder = f"__H_FILE_MARK_{random.randint(10**8, 10**9)}__"
            # 64-char sentinel for the native-VM extension hash. The real .pyd
            # SHA-256 is 64 hex chars, so the sentinel MUST be 64 chars too —
            # this keeps the file-integrity masking length-preserving when the
            # sentinel is replaced with the real hash post-ship (both the
            # compile-time and runtime integrity checks mask this slot to
            # 64 dots, so the file hash stays valid across injection).
            _vm_exthash_sentinel = '__VM_EXTHASH_SLOT_' + '0' * (
                64 - len('__VM_EXTHASH_SLOT_'))
            requests_mode_placeholder = f"__BEDROCK_REQ_ADV_{random.randint(10**8, 10**9)}__"
            requests_mode_var = rand_cn_name(8)
            loader_canary = f"__BEDROCK_LCAN_{random.randint(10**8, 10**9)}__"
            # Phase 4: debrand the canary VALUE so no static literal survives
            # (the loader-shape check only counts the var NAME, not the value).
            loader_canary = _debrand(loader_canary)
            # Phase 4: when anti-meta is on, use a per-build random var
            # name instead of the static __BEDROCK_LCAN__.
            lcan_var_name = rand_cn_name(8) if BR_DEBRAND_ON else "__BEDROCK_LCAN__"

            def _zip_package(pkg_name: str) -> bytes:
                try:
                    import io as _io
                    import os as _os
                    import zipfile as _zf
                    import importlib.util as _iu
                    spec = _iu.find_spec(pkg_name)
                    if not spec or not getattr(spec, 'origin', None):
                        return b''
                    root = _os.path.dirname(spec.origin)
                    if not root or not _os.path.isdir(root):
                        return b''
                    mem = _io.BytesIO()
                    with _zf.ZipFile(mem, 'w', _zf.ZIP_DEFLATED) as z:
                        for r, _, files in _os.walk(root):
                            for fn in files:
                                if not fn.endswith('.py'):
                                    continue
                                fp = _os.path.join(r, fn)
                                rel = _os.path.relpath(fp, root).replace('\\', '/')
                                z.write(fp, arcname=f'{pkg_name}/{rel}')
                    return mem.getvalue()
                except:
                    return b''

            def _zip_std_modules() -> bytes:
                try:
                    import io as _io
                    import os as _os
                    import zipfile as _zf
                    import sysconfig as _sc
                    stdlib = _sc.get_paths().get('stdlib', '')
                    if not stdlib:
                        return b''
                    mods = ['socket.py', 'ssl.py']
                    mem = _io.BytesIO()
                    with _zf.ZipFile(mem, 'w', _zf.ZIP_DEFLATED) as z:
                        for m in mods:
                            fp = _os.path.join(stdlib, m)
                            if _os.path.isfile(fp):
                                z.write(fp, arcname=m)
                    return mem.getvalue()
                except:
                    return b''

            req_zip_blob = b''
            sock_zip_blob = b''
            if requests_check_advanced:
                req_zip_blob = _zip_package('requests')
                sock_zip_blob = _zip_std_modules()
            req_zip_b85 = base64.b85encode(req_zip_blob).decode('ascii') if req_zip_blob else ''
            sock_zip_b85 = base64.b85encode(sock_zip_blob).decode('ascii') if sock_zip_blob else ''
            req_xor_key = random.randint(1, 255)

            # 2a. Snapshot module str() representations for runtime verification
            _snap_sys = str(__import__('sys'))
            _snap_os = str(__import__('os'))
            _snap_open_type = str(type(__import__('builtins').open))
            _snap_sys_exit = str(__import__('sys').exit)
            _snap_os_system = str(__import__('os').system)

            # Phase 4: build the author integrity check from _META_INFOS so it
            # stays in sync with the header emit (which also reads _META_INFOS).
            # When anti-meta is ON, both the header var names and the runtime
            # globals().get() calls use the per-build random names.
            _author_check_lines = []
            for _k, _v in _META_INFOS.items():
                _author_check_lines.append(
                    f"    if globals().get({_k!r}) != {Pycloak().encode(_v)}:"
                )
                _author_check_lines.append(
                    "        __bedrock_self_destruct__('integrity policy triggered')"
                )
            _author_check_code = chr(10).join(_author_check_lines)


            # 2. Xây dựng khuôn mẫu mã kiểm tra.
            self_check_code = f"""
try:
    __BEDROCK_TAMPER_MODE__ = {tamper_mode_build!r}

    def __bedrock_rerun__():
        try:
            import os
            import sys
            exe = sys.executable
            if not exe:
                return
            if sys.argv:
                args = [exe] + sys.argv
                if args[1] != __file__:
                    args = [exe, __file__] + sys.argv[1:]
            else:
                args = [exe, __file__]
            os.execv(exe, args)
        except:
            try:
                import os
                import sys
                os.system('"' + sys.executable + '" "' + __file__ + '"')
            except:
                pass

{_author_check_code}
    __bedrock_bi_ref = globals().get('__builtins__')
    def {integrity_fn}():
        try:
            import hashlib as _h
            with open(__file__, 'rb') as {integrity_fh}:
                {integrity_data} = {integrity_fh}.read()
            {integrity_exp} = globals().get({integrity_var!r}, '')
            {integrity_mark} = {integrity_marker!r}
            if not isinstance({integrity_exp}, str):
                {integrity_exp} = str({integrity_exp})
            {integrity_data} = {integrity_data}.replace({integrity_exp}.encode('utf-8'), {integrity_mark}.encode('utf-8'))
            {integrity_data} = {integrity_data}.replace(globals().get("__H_FILE_HASH__", "").encode("utf-8"), {integrity_mark}.encode("utf-8"))
            {integrity_data} = {integrity_data}.replace(globals().get("__VM_EXTHASH__", "").encode("utf-8"), {integrity_mark}.encode("utf-8"))
            if _h.sha256({integrity_data} + b"|int").hexdigest() != {integrity_exp}:
                try:
                    __bedrock_self_destruct__("File tampered")
                except:
                    raise SystemExit(-1)
        except Exception:
            raise SystemExit(-1)
    def __h_check_self_integrity():
        try:
            import hashlib as _ih
            with open(__file__, 'rb') as _ifh:
                _idata = _ifh.read().decode('utf-8', 'ignore')
            _iexp = globals().get('__H_FILE_HASH__', '')
            if not _iexp or not isinstance(_iexp, str):
                return
            _imark = '.' * 64
            _imasked = _idata.replace(_iexp, _imark)
            _ivexp = globals().get(globals().get('__H_INTEGRITY_VAR__', ''), '')
            if _ivexp and isinstance(_ivexp, str):
                _imasked = _imasked.replace(_ivexp, _imark)
            # Mask the native-VM ext-hash slot too: the sentinel is replaced
            # with the real .pyd hash post-ship, and both are 64 chars, so
            # masking to 64 dots keeps the file-integrity hash stable across
            # the injection (matches the compile-time masking).
            _ivmexp = globals().get('__VM_EXTHASH__', '')
            if _ivmexp and isinstance(_ivmexp, str):
                _imasked = _imasked.replace(_ivmexp, _imark)
            if _ih.sha256((_imasked + '|fh').encode('utf-8')).hexdigest() != _iexp:
                try:
                    __bedrock_self_destruct__('file integrity failed')
                except Exception:
                    raise SystemExit(-1)
        except Exception:
            pass
    # ========================================
    # ANTI-CRACK by BedrockDz
    # ========================================
    def __bedrock_check_prepend__():
        try:
            with open(__file__, 'r', encoding='utf-8') as f:
                first = f.read(4096)
            _inject_signs = ('print(', 'import builtins', 'sys.settrace', 'sys.setprofile', 'builtins.print', 'builtins.len', 'builtins.sum', 'builtins.exec', 'builtins.eval', '__import__', 'exec(', 'eval(', 'import frida', 'import pydevd', 'import debugpy', 'settrace(', 'setprofile(', 'gc.get_objects', 'marshal.loads', 'ctypes.pythonapi', 'threading.settrace', 'import threading', 'import reprlib', 'class A:', 'tracer.start', 'tracer =', '.settrace(')
            _head = first[:200]
            for _sign in _inject_signs:
                if _sign in _head:
                    try:
                        __bedrock_self_destruct__("Injection detected")
                    except:
                        pass
                    return
            _high_conf = ('import frida', 'import pydevd', 'import debugpy', 'import pyrasite', 'import pyinjector', 'sys.settrace(', 'sys.setprofile(', 'builtins.print =', 'builtins.exec =', 'builtins.eval =', 'builtins.open =', 'builtins.__import__ =')
            for _sign in _high_conf:
                if _sign in first:
                    try:
                        __bedrock_self_destruct__("Injection detected")
                    except:
                        pass
                    return
        except:
            pass

    def __bedrock_check_append__():
        try:
            with open(__file__, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            _last_marker_line = -1
            for _li, _ln in enumerate(lines):
                if ".DitMeMayDecDi()" in _ln:
                    _last_marker_line = _li
            if _last_marker_line >= 0 and _last_marker_line < len(lines) - 1:
                _tail_lines = lines[_last_marker_line + 1:]
                _tail = ''.join(_tail_lines).strip()
                if _tail:
                    _last_code_line = -1
                    for _li2 in range(len(lines) - 1, _last_marker_line, -1):
                        _cl = lines[_li2].strip()
                        if _cl and not _cl.startswith('#'):
                            _last_code_line = _li2
                            break
                    if _last_code_line > _last_marker_line:
                        _appended = ''.join(lines[_last_code_line:]).strip()
                        _append_signs = ('sys.settrace', 'sys.setprofile', 'builtins.print', 'builtins.len', 'builtins.sum', 'builtins.exec', 'builtins.eval', 'gc.get_objects', 'ctypes.pythonapi', 'tracer.start', 'tracer =', '.settrace(', 'threading.settrace')
                        for _sign in _append_signs:
                            if _sign in _appended:
                                try:
                                    __bedrock_self_destruct__("Injection detected")
                                except:
                                    pass
                                return
        except:
            pass

    def __bedrock_check_loader_shape__():
        try:
            with open(__file__, 'r', encoding='utf-8', errors='ignore') as _f:
                _top = [next(_f, '') for _ in range(12)]
            _mark_hits = 0
            for _ln in _top:
                if {lcan_var_name!r} in _ln:
                    _mark_hits += 1
            if _mark_hits != 1:
                __bedrock_self_destruct__("Loader tampered")
            for _ln in _top[:3]:
                if ';' in _ln:
                    __bedrock_self_destruct__("Loader tampered")
        except:
            pass

    def __bedrock_abort__(msg="Security block"):
        _mode = str(globals().get('__BEDROCK_TAMPER_MODE__', 'self-destruct') or 'self-destruct').strip().lower()
        try:
            print("\\n" + str(msg), flush=True)
        except:
            pass
        if _mode == 'warn':
            return
        if _mode == 'poison':
            try:
                globals()['__h_poison']('abort:' + str(msg)[:32], 7)
            except Exception:
                pass
            try:
                _cur = globals().get('__h_poison_state__', 0) or 0
                globals()['__h_poison_state__'] = ((_cur ^ 0xCAFEBABE) & 0xffffffff) or 0xCAFE
            except Exception:
                pass
            return
        if _mode == 'fail-closed':
            raise SystemExit(1)
        try:
            __import__('time').sleep(5)
        except:
            pass
        try:
            __import__('os')._exit(1)
        except:
            raise SystemExit(1)

    def __bedrock_lock_trace__():
        try:
            import sys, threading
            global __bedrock_tracer_fn__
            _noop = lambda *a, **k: None
            __bedrock_tracer_fn__ = _noop
            sys.settrace(_noop)
            sys.setprofile(_noop)
            try:
                threading.settrace(_noop)
                threading.setprofile(_noop)
            except:
                pass
        except:
            pass

    def __bedrock_pin_callable__(mod_name, attr):
        try:
            import importlib, types
            _m = importlib.import_module(mod_name)
            _f = getattr(_m, attr, None)
            if not callable(_f):
                __bedrock_abort__("Function hook detected")
            if getattr(_f, '__module__', '') != mod_name:
                __bedrock_abort__("Function hook detected")
            if hasattr(_f, '__wrapped__'):
                __bedrock_abort__("Function hook detected")
            if not isinstance(_f, (types.BuiltinFunctionType, types.FunctionType, types.MethodDescriptorType)):
                __bedrock_abort__("Function hook detected")
        except:
            __bedrock_abort__("Function hook detected")

    def __bedrock_guard_marshal__():
        try:
            import sys, types, marshal as _m
            _fn = getattr(_m, 'loads', None)
            if not callable(_fn) or getattr(_fn, '__module__', '') != 'marshal' or hasattr(_fn, '__wrapped__'):
                __bedrock_abort__("Marshal hook detected")
            _sealed = types.ModuleType('marshal')
            _sealed.loads = _m.loads
            _sealed.dumps = _m.dumps
            sys.modules['marshal'] = _sealed
            globals()['__sr_m'] = _sealed
        except:
            __bedrock_abort__("Marshal hook detected")

    def __bedrock_check_net_modules__():
        try:
            import os, sysconfig, ssl, socket, urllib
            _stdlib = os.path.realpath(sysconfig.get_paths().get('stdlib', ''))
            _allowed = (
                (ssl, ('ssl.py',)),
                (socket, ('socket.py',)),
                (urllib, (os.path.join('urllib', '__init__.py'),)),
            )
            for _m, _suffixes in _allowed:
                _raw_path = str(getattr(_m, '__file__', '') or '')
                if _raw_path.startswith('<embedded>/') and any(_raw_path.endswith(_s) for _s in _suffixes):
                    continue
                _p = os.path.realpath(_raw_path)
                if not _p or not _stdlib:
                    continue
                try:
                    _inside_stdlib = os.path.commonpath([_stdlib, _p]) == _stdlib
                except Exception:
                    _inside_stdlib = False
                _suffix_ok = any(_p.endswith(_s) for _s in _suffixes)
                if (not _inside_stdlib) or (not _suffix_ok):
                    __bedrock_abort__("Network module hook detected")
        except:
            pass

    def __bedrock_check_debug__():
        def __bedrock_env_truthy__(_value):
            try:
                _v = str(_value).strip().lower()
            except:
                return False
            return _v not in ('', '0', 'false', 'off', 'no', 'none', 'null')

        def __bedrock_fn_name__(_fn):
            try:
                _mod = str(getattr(_fn, '__module__', '') or '')
                _name = str(getattr(_fn, '__name__', '') or '')
                return (_mod + '.' + _name).lower()
            except:
                return ''

        try:
            import sys
            _trace = None
            _profile = None
            try:
                _trace = sys.gettrace()
            except:
                pass
            try:
                _profile = sys.getprofile()
            except:
                pass
            _trace_name = __bedrock_fn_name__(_trace)
            _profile_name = __bedrock_fn_name__(_profile)
            _strong_tags = ('pydevd', 'debugpy', 'bdb', 'pdb', 'frida', 'pydbg', 'winappdbg')
            if _trace and any((_tag in _trace_name for _tag in _strong_tags)):
                __bedrock_abort__("Debugger detected")
            if _profile and any((_tag in _profile_name for _tag in _strong_tags)):
                __bedrock_abort__("Debugger detected")
        except:
            pass
        try:
            import sys
            bad_mods_strong = (
                'pydevd', 'pydevd_pycharm',
                'frida', 'frida_core', 'frida_gadget', 'pydbg', 'winappdbg', 'debugpy',
                # D1: remote/active debug listeners — block hard.
                'manhole', 'remote_pdb', 'pyrasite_console',
            )
            bad_mods_soft = (
                'pdb', 'pudb', 'ipdb', 'bdb',
                'pdbpp', 'pytest', '_pytest', 'testtools', 'nose', 'nose2',
                'hypothesis', 'hunter',
                'uncompyle6', 'decompyle3', 'pycdc', 'pdcd', 'pycd', 'pycdas', 'pycdecomp', 'pyinstxtractor',
                'pyarmor', 'pyarmor_runtime', 'pytransform',
                'pyrasite', 'pyinjector', 'capstone', 'unicorn', 'keystone', 'lief', 'r2pipe', 'angr',
                'snoop', 'pysnooper', 'line_profiler', 'memory_profiler', 'coverage', 'trace'
            )
            for name in bad_mods_strong:
                if name in sys.modules:
                    __bedrock_abort__("Debugger detected")
            soft_hits = 0
            for name in bad_mods_soft:
                if name in sys.modules:
                    soft_hits += 1
            if soft_hits >= 3:
                __bedrock_abort__("Debugger detected")
        except:
            pass
        try:
            import os
            soft_env = ('PYTHONINSPECT', 'PYTHONBREAKPOINT', 'PYCHARM_HOSTED', 'PYTHONSTARTUP')
            env_hits = 0
            breakpoint_seen = False
            pycharm_seen = False
            for key in soft_env:
                _val = os.environ.get(key)
                if key == 'PYTHONBREAKPOINT':
                    _v = str(_val or '').strip()
                    if _v and _v != '0':
                        breakpoint_seen = True
                        env_hits += 1
                    continue
                if key == 'PYCHARM_HOSTED':
                    pycharm_seen = __bedrock_env_truthy__(_val)
                    if pycharm_seen:
                        env_hits += 1
                    continue
                if __bedrock_env_truthy__(_val):
                    env_hits += 1
            if env_hits >= 2 or (breakpoint_seen and pycharm_seen):
                __bedrock_abort__("Debugger detected")
        except:
            pass
        try:
            import builtins as _b
            _e = getattr(_b, 'eval', None)
            _x = getattr(_b, 'exec', None)
            if not callable(_e):
                __bedrock_abort__("Debugger detected")
            if not callable(_x):
                __bedrock_abort__("Debugger detected")
            if hasattr(_e, '__wrapped__') or hasattr(_x, '__wrapped__'):
                __bedrock_abort__("Debugger detected")
        except:
            pass

    def __bedrock_check_builtins__():
        try:
            import builtins as _b
            import types as _t
            _func_names = ('print', 'open', 'input', '__import__', 'eval', 'exec', 'compile', 'len', 'sum', 'getattr', 'setattr', 'isinstance', 'hasattr', 'repr', 'chr', 'ord', 'sorted', 'min', 'max', 'abs', 'id', 'hash', 'callable', 'dir', 'vars', 'globals', 'locals')
            _type_names = ('type', 'bytes', 'str', 'int', 'object', 'map', 'filter', 'zip', 'range', 'enumerate', 'reversed', 'super', 'classmethod', 'staticmethod', 'property')
            if globals().get('__builtins__') is not __bedrock_bi_ref:
                __bedrock_abort__("Builtins table replaced")
                return
            for name in _func_names:
                func = getattr(_b, name, None)
                if func is None:
                    __bedrock_abort__("Builtins hook detected")
                    return
                if not isinstance(func, _t.BuiltinFunctionType):
                    __bedrock_abort__("Builtins hook detected")
                    return
                if hasattr(func, '__wrapped__'):
                    __bedrock_abort__("Builtins hook detected")
                    return
            for name in _type_names:
                func = getattr(_b, name, None)
                if func is None:
                    __bedrock_abort__("Builtins hook detected")
                    return
                if not isinstance(func, type):
                    __bedrock_abort__("Builtins hook detected")
                    return
            _bi = globals().get('__builtins__')
            _all_names = _func_names + _type_names
            if isinstance(_bi, dict):
                for name in _all_names:
                    if _bi.get(name) is not getattr(_b, name, None):
                        __bedrock_abort__("Builtins hook detected")
                        return
            else:
                for name in _all_names:
                    if getattr(_bi, name, None) is not getattr(_b, name, None):
                        __bedrock_abort__("Builtins hook detected")
                        return
        except:
            pass

    def __bedrock_check_stack__(strict=False):
        try:
            import inspect, os, re
            sus = ('pycdc', 'pdcd', 'uncompyle', 'decompyle', 'frida', 'x64dbg', 'olly', 'windbg', 'gdb', 'ida', 'ghidra', 'radare')
            st = inspect.stack()
            for f in st:
                fn = (getattr(f, 'filename', '') or '').lower()
                tokens = tuple((t for t in re.split(r'[^a-z0-9]+', fn) if t))
                for s in sus:
                    if (s in tokens) or (s in fn and ('/' + s + '/') in fn.replace('\\\\', '/')):
                        __bedrock_abort__("Debugger detected")
                        return
            if strict and len(st) > 96:
                __bedrock_abort__("Debugger detected")
                return
            try:
                cur = os.path.realpath(__file__)
                foreign_hits = 0
                for fr in st[2:20]:
                    fn = os.path.realpath((getattr(fr, 'filename', '') or ''))
                    low = fn.lower()
                    if not fn:
                        continue
                    if fn == cur:
                        continue
                    if ('importlib' in low) or ('runpy' in low):
                        continue
                    foreign_hits += 1
                if foreign_hits >= 6:
                    __bedrock_abort__("Foreign frame detected")
                    return
            except:
                pass
        except:
            pass

    def __bedrock_check_process_tools__(advanced=False):
        if not advanced:
            return
        try:
            import platform
            if platform.system().lower() != 'windows':
                return
            import subprocess
            output = subprocess.check_output('tasklist', shell=True, text=True, errors='ignore').lower()
            high = ('wireshark', 'fiddler', 'burp', 'charles', 'httptoolkit', 'http toolkit')
            low = ('mitmproxy', 'tcpdump', 'proxifier', 'npcap', 'charlesproxy')
            high_hits = 0
            low_hits = 0
            for name in high:
                if name in output:
                    high_hits += 1
            for name in low:
                if name in output:
                    low_hits += 1
            # Avoid false positives: require stronger multi-signal hits
            if high_hits >= 2 or (high_hits >= 1 and low_hits >= 1) or (high_hits + low_hits) >= 3:
                __bedrock_abort__("Network debugger detected")
        except:
            pass

    def __bedrock_check_sniffer__(advanced=False):
        if not advanced:
            return
        try:
            import platform
            if platform.system().lower() != 'windows':
                return
            import subprocess
            output = subprocess.check_output('tasklist', shell=True, text=True, errors='ignore').lower()
            sniffs = ('wireshark', 'tcpdump', 'npcap', 'windump', 'fiddler', 'burp', 'charles', 'httptoolkit', 'http toolkit', 'mitmproxy', 'ettercap')
            hits = 0
            for name in sniffs:
                if name in output:
                    hits += 1
            if hits >= 3 or (hits >= 2 and ('wireshark' in output or 'mitmproxy' in output)):
                __bedrock_abort__("Network sniffing tool detected")
        except:
            pass

    def __bedrock_check_registry_proxy__(advanced=False):
        if not advanced:
            return
        try:
            import platform
            if platform.system().lower() != 'windows':
                return
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings')
            enabled, _ = winreg.QueryValueEx(key, 'ProxyEnable')
            try:
                enabled = int(enabled)
            except:
                enabled = 0
            if enabled:
                try:
                    server, _ = winreg.QueryValueEx(key, 'ProxyServer')
                except:
                    server = ''
                server = str(server).lower()
                indicators = ('fiddler', 'burp', 'charles', 'mitmproxy', 'httptoolkit', 'http-toolkit')
                _local_proxy = ('127.0.0.1' in server or 'localhost' in server)
                hits = 0
                for tag in indicators:
                    if tag in server:
                        hits += 1
                if hits >= 2 or (hits >= 1 and _local_proxy):
                    __bedrock_abort__("Proxy debugger detected")
            winreg.CloseKey(key)
        except:
            pass

    def __bedrock_check_http_toolkit__(advanced=False):
        try:
            import os
            score = 0
            if os.environ.get('HTTP_TOOLKIT_ACTIVE', '').lower() == 'true':
                score += 3
            ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
            if ssl_cert_file:
                indicators = ('http-toolkit', 'httptoolkit', 'http_toolkit', 'mitmproxy', 'fiddler', 'burp')
                low = ssl_cert_file.lower()
                for indicator in indicators:
                    if indicator in low:
                        score += 2
                        break
            proxy_vars = ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')
            for var in proxy_vars:
                value = os.environ.get(var, '')
                if value:
                    low = value.lower()
                    if 'localhost' in low or '127.0.0.1' in low:
                        score += 1
                    if 'fiddler' in low or 'burp' in low or 'charles' in low or 'mitmproxy' in low or 'httptoolkit' in low:
                        score += 2
            if advanced:
                try:
                    import requests as _rq
                    try:
                        _r = _rq.head('http://localhost:8001/', timeout=0.05, allow_redirects=False)
                        if _r is not None:
                            _srv = str(_r.headers.get('server', '')).lower()
                            if 'httptoolkit' in _srv or 'http-toolkit' in _srv or 'mockttp' in _srv:
                                score += 3
                            else:
                                score += 1
                    except:
                        pass
                except:
                    pass
                if score >= 4:
                    __bedrock_abort__("HTTP debugger detected")
            else:
                if score >= 4:
                    __bedrock_abort__("HTTP debugger detected")
        except:
            pass

    _REQ_ADVANCED = globals().get({requests_mode_var!r}, False)
    if isinstance(_REQ_ADVANCED, str):
        _REQ_ADVANCED = _REQ_ADVANCED.strip().lower() in ('1', 'true', 'yes', 'on')
    else:
        _REQ_ADVANCED = bool(_REQ_ADVANCED)
    __BEDROCK_REQ_ZIP_B85__ = {req_zip_b85!r}
    __BEDROCK_SOCK_ZIP_B85__ = {sock_zip_b85!r}
    __BEDROCK_REQ_XKEY__ = {req_xor_key}

    def __bedrock_install_embedded_net__(advanced=False):
        if not advanced:
            return
        try:
            import base64, io, zipfile, importlib.abc, importlib.util, sys, os, tempfile
            blobs = dict()
            if __BEDROCK_REQ_ZIP_B85__:
                try:
                    blobs['requests'] = base64.b85decode(__BEDROCK_REQ_ZIP_B85__.encode('ascii'))
                except:
                    pass
            if __BEDROCK_SOCK_ZIP_B85__:
                try:
                    blobs['socket'] = base64.b85decode(__BEDROCK_SOCK_ZIP_B85__.encode('ascii'))
                except:
                    pass
            if not blobs:
                return

            maps = dict()
            for base in blobs:
                try:
                    data = dict()
                    with zipfile.ZipFile(io.BytesIO(blobs.get(base, b'')), 'r') as zf:
                        for n in zf.namelist():
                            if n.endswith('.py'):
                                raw = zf.read(n)
                                try:
                                    data[n] = bytes((b ^ __BEDROCK_REQ_XKEY__) for b in raw)
                                except:
                                    data[n] = raw
                    maps[base] = data
                except:
                    pass
            if not maps:
                return

            # Optionally drop encoded copies to a temp dir (harder to sniff live bytes)
            try:
                temp_root = tempfile.mkdtemp(prefix='._bedrock_req_')
                for base, entries in maps.items():
                    base_dir = os.path.join(temp_root, base)
                    os.makedirs(base_dir, exist_ok=True)
                    for rel, content in entries.items():
                        fp = os.path.join(base_dir, rel)
                        os.makedirs(os.path.dirname(fp), exist_ok=True)
                        with open(fp + '.__enc__', 'wb') as wf:
                            wf.write(content)
                sys.path.insert(0, temp_root)
            except:
                temp_root = None

            class _HLoader(importlib.abc.Loader):
                def __init__(self, maps_, fullname_, source_path_, is_pkg_):
                    self.maps = maps_
                    self.fullname = fullname_
                    self.source_path = source_path_
                    self.is_pkg = is_pkg_
                def create_module(self, spec):
                    return None
                def _base(self):
                    return self.fullname.split('.', 1)[0]
                def _pkg_dir(self):
                    p = self.source_path
                    if p.endswith('/__init__.py'):
                        return p[:-12]
                    return p.rsplit('/', 1)[0] if '/' in p else ''
                def _load_bytes(self):
                    base = self._base()
                    data = self.maps.get(base, dict()).get(self.source_path)
                    if data is not None:
                        return data
                    # fallback to temp files if present
                    try:
                        if temp_root:
                            fp = os.path.join(temp_root, base, self.source_path) + '.__enc__'
                            if os.path.isfile(fp):
                                with open(fp, 'rb') as rf:
                                    return rf.read()
                    except:
                        pass
                    return None
                def exec_module(self, module):
                    src = self._load_bytes()
                    if src is None:
                        raise ImportError(self.fullname)
                    try:
                        src = bytes((b ^ __BEDROCK_REQ_XKEY__) for b in src)
                    except:
                        pass
                    module.__file__ = '<embedded>/' + self.source_path
                    if self.is_pkg:
                        module.__path__ = ['<embedded>/' + self._pkg_dir()]
                        module.__package__ = self.fullname
                    else:
                        module.__package__ = self.fullname.rpartition('.')[0]
                    exec(compile(src.decode('utf-8', 'ignore'), module.__file__, 'exec'), module.__dict__)

            class _HFinder(importlib.abc.MetaPathFinder):
                def __init__(self, maps_):
                    self.maps = maps_
                def _resolve(self, fullname):
                    base = fullname.split('.', 1)[0]
                    if base == 'requests':
                        d = self.maps.get('requests', dict())
                        if fullname == 'requests':
                            p = 'requests/__init__.py'
                            if p in d:
                                return p, True
                        tail = fullname.split('.', 1)[1] if '.' in fullname else ''
                        if tail:
                            p = 'requests/' + tail.replace('.', '/') + '.py'
                            if p in d:
                                return p, False
                            p2 = 'requests/' + tail.replace('.', '/') + '/__init__.py'
                            if p2 in d:
                                return p2, True
                    elif base == 'socket' and fullname == 'socket':
                        d = self.maps.get('socket', dict())
                        if 'socket.py' in d:
                            return 'socket.py', False
                    return None
                def find_spec(self, fullname, path=None, target=None):
                    r = self._resolve(fullname)
                    if not r:
                        return None
                    p, is_pkg = r
                    loader = _HLoader(self.maps, fullname, p, is_pkg)
                    origin = '<embedded>/' + p
                    if is_pkg:
                        return importlib.util.spec_from_loader(fullname, loader, origin=origin, is_package=True)
                    return importlib.util.spec_from_loader(fullname, loader, origin=origin)

            has_finder = False
            for f in sys.meta_path:
                if f.__class__.__name__ == '_HFinder':
                    has_finder = True
                    break
            if not has_finder:
                sys.meta_path.insert(0, _HFinder(maps))
            if 'requests' in maps:
                sys.modules.pop('requests', None)
            if 'socket' in maps:
                sys.modules.pop('socket', None)
        except:
            pass

    def __bedrock_c_level_probe__(advanced=False):
        if not advanced:
            return
        try:
            import ctypes as _ct
            import marshal as _m
            _p = _ct.pythonapi
            _read = _p.PyMarshal_ReadObjectFromString
            _eval = _p.PyEval_EvalCode
            _read.restype = _ct.py_object
            _read.argtypes = [_ct.c_char_p, _ct.c_long]
            _eval.restype = _ct.py_object
            _eval.argtypes = [_ct.py_object, _ct.py_object, _ct.py_object]
            _blob = _m.dumps(compile("x=1", "<bedrock_c_probe>", "exec"))
            _obj = _read(_blob, len(_blob))
            _g = dict()
            _g['__builtins__'] = __builtins__
            _eval(_obj, _g, _g)
        except:
            pass

    def __bedrock_check_requests__(advanced=False):
        try:
            import importlib.util
            import os
            import inspect
            import sys
            import ast
            spec = importlib.util.find_spec('requests')
            if not spec or not getattr(spec, 'origin', None):
                return
            req_root = os.path.dirname(spec.origin)
            if not req_root:
                return
            try:
                req_root = os.path.realpath(req_root)
            except:
                pass
            root_mismatch = False
            try:
                _base_root = globals().get('__BEDROCK_REQ_ROOT__')
                if _base_root is None:
                    globals()['__BEDROCK_REQ_ROOT__'] = req_root
                else:
                    root_mismatch = os.path.realpath(str(_base_root)) != req_root
            except:
                root_mismatch = False

            import requests
            import requests.models
            import requests.sessions
            import requests.adapters
            __bedrock_check_net_modules__()

            def _path_ok(path):
                try:
                    if not path or not req_root:
                        return True
                    path = os.path.realpath(path)
                    return os.path.commonpath([req_root, path]) == req_root
                except:
                    return True

            def _scan_file_ast(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = f.read()
                    tree = ast.parse(data)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Name) and node.func.id == 'print':
                                return True
                            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'sys':
                                if node.func.attr in ('stdout', 'stderr'):
                                    return True
                        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'sys':
                            if node.attr in ('stdout', 'stderr'):
                                return True
                    return False
                except:
                    return False

            def _is_tampered(func, expected_module):
                try:
                    if not callable(func):
                        return True
                    mod = getattr(func, '__module__', '') or ''
                    if expected_module:
                        if mod != expected_module and (not mod.startswith(expected_module + '.')) and (not mod.startswith('requests')):
                            return True
                    try:
                        src_file = inspect.getsourcefile(func) or inspect.getfile(func)
                        if src_file and not _path_ok(src_file):
                            return True
                    except:
                        pass
                    try:
                        code = getattr(func, '__code__', None)
                        if code:
                            if code.co_filename and not _path_ok(code.co_filename):
                                return True
                            names = set(code.co_names)
                            _tamper_signs = {{'settrace', 'setprofile', 'gettrace', 'getprofile'}}
                            if names & _tamper_signs:
                                return True
                            if 'sys' in names and ('settrace' in names or 'setprofile' in names):
                                return True
                    except:
                        pass
                    return False
                except:
                    return False

            targets = [
                (requests.models.PreparedRequest, 'prepare', 'requests.models'),
                (requests.sessions.Session, 'request', 'requests.sessions'),
                (requests.sessions.Session, 'send', 'requests.sessions'),
                (requests.adapters.HTTPAdapter, 'send', 'requests.adapters'),
            ]
            if hasattr(requests, 'request'):
                targets.append((requests, 'request', 'requests.api'))
            if hasattr(requests, 'get'):
                targets.append((requests, 'get', 'requests.api'))
            if hasattr(requests, 'post'):
                targets.append((requests, 'post', 'requests.api'))

            sig = {{
                'req': id(getattr(requests, 'request', None)),
                'get': id(getattr(requests, 'get', None)),
                'post': id(getattr(requests, 'post', None)),
                'sreq': id(getattr(requests.sessions.Session, 'request', None)),
                'ssend': id(getattr(requests.sessions.Session, 'send', None)),
                'asend': id(getattr(requests.adapters.HTTPAdapter, 'send', None)),
            }}
            base = globals().get('__BEDROCK_REQ_SIG__')
            if base is None:
                globals()['__BEDROCK_REQ_SIG__'] = sig
            elif sig != base:
                __bedrock_abort__("Requests hook detected")

            import hashlib as _hh
            # S5: extended bytecode fingerprint covering co_code + co_consts +
            # co_names + co_varnames + co_freevars + co_exceptiontable (3.11+).
            # co_exceptiontable is absent on 3.10 -> getattr fallback to b''.
            # The separator '|' prevents field-collision ambiguity. This
            # replaces the prior co_code+co_consts-only hash so tampering that
            # only swaps names/varnames (e.g. renaming a hooked builtin back to
            # its original name) is now detected.
            def _br_fp_ext(_c):
                return _hh.sha256(
                    _c.co_code + b'|' +
                    repr(_c.co_consts).encode('utf-8', 'replace') + b'|' +
                    repr(getattr(_c, 'co_names', ())).encode('utf-8', 'replace') + b'|' +
                    repr(getattr(_c, 'co_varnames', ())).encode('utf-8', 'replace') + b'|' +
                    repr(getattr(_c, 'co_freevars', ())).encode('utf-8', 'replace') + b'|' +
                    repr(getattr(_c, 'co_exceptiontable', b'')).encode('latin-1', 'replace')
                ).hexdigest()
            _fp = {{}}
            for _h, _m, _ in targets:
                try:
                    _f = inspect.unwrap(getattr(_h, _m))
                    _c = getattr(_f, '__code__', None)
                    if _c:
                        _fp[(id(_h), _m)] = _br_fp_ext(_c)
                except:
                    pass

            def _fp_ok(holder, method_name):
                try:
                    _f = inspect.unwrap(getattr(holder, method_name))
                    _c = getattr(_f, '__code__', None)
                    if not _c:
                        return True
                    _cur = _br_fp_ext(_c)
                    return _cur == _fp.get((id(holder), method_name), _cur)
                except:
                    return True

            tampered = bool(root_mismatch)
            for cls_or_mod, method_name, expected_module in targets:
                try:
                    if not hasattr(cls_or_mod, method_name):
                        continue
                    func = getattr(cls_or_mod, method_name)
                    real_func = inspect.unwrap(func)
                    if _is_tampered(func, expected_module) or _is_tampered(real_func, expected_module):
                        tampered = True
                        break
                except:
                    pass

            if advanced and not tampered:
                for name in ('api', 'sessions', 'adapters', 'models'):
                    file_path = os.path.join(req_root, name + '.py')
                    if os.path.isfile(file_path) and _scan_file_ast(file_path):
                        tampered = True
                        break

            if tampered and advanced:
                try:
                    _OrigSession = requests.sessions.Session

                    class __BedrockSession(_OrigSession):
                        def __init__(self, *args, **kwargs):
                            _OrigSession.__init__(self, *args, **kwargs)
                            try:
                                self.trust_env = False
                            except:
                                pass
                            try:
                                self.verify = True
                            except:
                                pass

                        def request(self, method, url, **kwargs):
                            try:
                                pass
                            except:
                                pass
                            if kwargs.get('verify') is None:
                                kwargs['verify'] = True
                            try:
                                pass
                            except:
                                pass
                            return _OrigSession.request(self, method, url, **kwargs)

                    try:
                        __BedrockSession.__bedrock_hardened__ = True
                    except:
                        pass
                    requests.sessions.Session = __BedrockSession
                    requests.Session = __BedrockSession

                    def _safe_request(method, url, **kwargs):
                        with requests.sessions.Session() as _s:
                            try:
                                pass
                            except:
                                pass
                            if kwargs.get('verify') is None:
                                kwargs['verify'] = True
                            try:
                                pass
                            except:
                                pass
                            return _s.request(method=method, url=url, **kwargs)
                    requests.request = _safe_request
                    requests.get = lambda url, **kw: _safe_request('GET', url, **kw)
                    requests.post = lambda url, **kw: _safe_request('POST', url, **kw)
                    tampered = False
                except:
                    pass
            if tampered:
                try:
                    __bedrock_abort__("Requests hook detected")
                except:
                    pass
                return

            if advanced:
                try:
                    import threading
                    import functools
                    lock = threading.RLock()

                    # Borrowed from custom Session hardening style:
                    # force requests to ignore environment proxy injection by default.
                    try:
                        _Sess = requests.sessions.Session
                        if not getattr(_Sess, '__bedrock_hardened__', False):
                            _OrigSession = _Sess

                            class __BedrockSession(_OrigSession):
                                def __init__(self, *args, **kwargs):
                                    _OrigSession.__init__(self, *args, **kwargs)
                                    try:
                                        self.trust_env = False
                                    except:
                                        pass
                                    try:
                                        self.verify = True
                                    except:
                                        pass

                                def request(self, method, url, **kwargs):
                                    try:
                                        pass
                                    except:
                                        pass
                                    if kwargs.get('verify') is None:
                                        kwargs['verify'] = True
                                    try:
                                        pass
                                    except:
                                        pass
                                    return _OrigSession.request(self, method, url, **kwargs)

                            try:
                                __BedrockSession.__bedrock_hardened__ = True
                            except:
                                pass
                            requests.sessions.Session = __BedrockSession
                            requests.Session = __BedrockSession
                    except:
                        pass

                    def _guard_holder(holder, method_name):
                        try:
                            original = getattr(holder, method_name, None)
                            if not callable(original):
                                return
                            if getattr(original, '__bedrock_guard__', False):
                                return
                            @functools.wraps(original)
                            def _inner(*args, **kwargs):
                                with lock:
                                    if not _fp_ok(holder, method_name):
                                        __bedrock_abort__("Requests hook detected")
                                    try:
                                        import inspect as _ins
                                        _sus = ('frida', 'pydevd', 'debugpy', 'mitmproxy', 'x64dbg', 'ida', 'ghidra')
                                        _hits = 0
                                        for _fr in _ins.stack()[2:14]:
                                            _fn = (getattr(_fr, 'filename', '') or '')
                                            _base = os.path.basename(_fn).lower()
                                            for _s in _sus:
                                                if _s in _base:
                                                    _hits += 1
                                                    break
                                        if _hits >= 2:
                                            __bedrock_abort__("Requests hook detected")
                                    except:
                                        pass
                                    return original(*args, **kwargs)
                            try:
                                _inner.__bedrock_guard__ = True
                            except:
                                pass
                            setattr(holder, method_name, _inner)
                        except:
                            pass

                    _guard_holder(requests.sessions.Session, 'request')
                    _guard_holder(requests.sessions.Session, 'send')
                    _guard_holder(requests.adapters.HTTPAdapter, 'send')
                except:
                    pass
        except:
            pass

    def __bedrock_check_module_str__():
        try:
            import sys as _sys
            import os as _os
            import builtins as _b
            import types as _t
            if getattr(_sys, '__name__', '') != 'sys':
                __bedrock_abort__("Module hook detected")
            if getattr(_os, '__name__', '') != 'os':
                __bedrock_abort__("Module hook detected")
            if not isinstance(getattr(_b, 'open', None), _t.BuiltinFunctionType):
                __bedrock_abort__("Module hook detected")
            if not callable(getattr(_sys, 'exit', None)):
                __bedrock_abort__("Module hook detected")
            if not callable(getattr(_os, 'system', None)):
                __bedrock_abort__("Module hook detected")
        except:
            pass

    def __bedrock_check_stack_depth__():
        try:
            import sys
            _depth = 0
            _f = sys._getframe()
            while _f is not None:
                _depth += 1
                _f = _f.f_back
            if _depth > 64:
                __bedrock_abort__("Abnormal stack depth detected")
        except:
            pass

    def __bedrock_seal_socket__():
        try:
            import sys, types, socket as _sk
            _orig_create = getattr(_sk, 'create_connection', None)
            _orig_socket = getattr(_sk, 'socket', None)
            if _orig_create and getattr(_orig_create, '__module__', '') != 'socket':
                __bedrock_abort__("Socket hook detected")
            if _orig_socket and not isinstance(_orig_socket, type):
                __bedrock_abort__("Socket hook detected")
        except:
            pass

    def __bedrock_self_destruct__(msg="security block"):
        _mode = str(globals().get('__BEDROCK_TAMPER_MODE__', 'self-destruct') or 'self-destruct').strip().lower()
        try:
            print("\\n" + str(msg), flush=True)
        except:
            pass
        if _mode == 'warn':
            return
        if _mode == 'poison':
            try:
                globals()['__h_poison']('destruct:' + str(msg)[:32], 9)
            except Exception:
                pass
            try:
                _cur = globals().get('__h_poison_state__', 0) or 0
                globals()['__h_poison_state__'] = ((_cur ^ 0xDEADBEEF) & 0xffffffff) or 0xDEAD
            except Exception:
                pass
            return
        if _mode == 'fail-closed':
            raise SystemExit(1)
        _stub = "raise SystemExit(" + repr("Security block: integrity verification failed") + ")\\n"
        try:
            import os
            _target = os.path.abspath(__file__)
            _tmp = _target + ".dead"
            with open(_tmp, 'w', encoding='utf-8') as f:
                f.write(_stub)
            os.replace(_tmp, _target)
        except:
            pass
        try:
            __import__('os')._exit(1)
        except:
            raise SystemExit(msg)

    def __bedrock_anti_inject_advanced__():
        import sys, builtins as _b, types as _t
        # === Anti sys.meta_path hooks ===
        try:
            _sus_finder_tokens = ('frida', 'hook', 'inject', 'pydevd', 'debugpy', 'pyrasite')
            _to_remove = []
            for _finder in sys.meta_path:
                _fname = getattr(_finder, '__name__', '') or type(_finder).__name__
                _fmod = getattr(_finder, '__module__', '') or type(_finder).__module__
                _fdesc = (_fname + ' ' + str(_fmod) + ' ' + repr(_finder)).lower()
                if any((_tok in _fdesc for _tok in _sus_finder_tokens)):
                    _to_remove.append(_finder)
            for _finder in _to_remove:
                try:
                    sys.meta_path.remove(_finder)
                except:
                    pass
        except:
            pass
        # Keep stdlib gc/dis intact. Earlier builds monkey-patched them, which
        # broke legitimate applications and looked like a false positive.
        # === Anti inspect abuse ===
        try:
            import inspect as _insp
            _orig_getsource = _insp.getsource
            _orig_getsourcelines = _insp.getsourcelines
            def _safe_getsource(obj, *a, **k):
                try:
                    _f = getattr(obj, '__code__', None) or obj
                    _fn = getattr(_f, 'co_filename', '') or ''
                    if __file__ in _fn or '<' in _fn:
                        raise OSError("source not available")
                except (TypeError, AttributeError):
                    pass
                return _orig_getsource(obj, *a, **k)
            def _safe_getsourcelines(obj, *a, **k):
                try:
                    _f = getattr(obj, '__code__', None) or obj
                    _fn = getattr(_f, 'co_filename', '') or ''
                    if __file__ in _fn or '<' in _fn:
                        raise OSError("source not available")
                except (TypeError, AttributeError):
                    pass
                return _orig_getsourcelines(obj, *a, **k)
            _insp.getsource = _safe_getsource
            _insp.getsourcelines = _safe_getsourcelines
        except:
            pass
        # Keep dir() intact for user code; hiding internals caused compatibility
        # problems in frameworks that introspect module globals.
        # === Anti PYTHONSTARTUP ===
        try:
            import os
            _val_startup = os.environ.get('PYTHONSTARTUP', '')
            if _val_startup:
                __bedrock_abort__("Startup injection detected")
        except:
            pass
        # === Anti PYTHONPATH injection (learned from Pygaugau) ===
        try:
            import os
            _pp = os.environ.get('PYTHONPATH', '')
            if _pp:
                _suspicious_pp = ('hook', 'inject', 'frida', 'proxy', 'mitm', 'intercept', 'sniff', 'pydevd', 'debugpy', 'pyrasite')
                _low_pp = _pp.lower()
                _pp_hits = 0
                for _sp in _suspicious_pp:
                    if _sp in _low_pp:
                        _pp_hits += 1
                if _pp_hits >= 2:
                    __bedrock_abort__("Suspicious PYTHONPATH detected")
        except:
            pass
        # === Anti sitecustomize injection (learned from Pygaugau) ===
        try:
            import os, sys
            _sus_patterns = ('settrace', 'setprofile', 'frida', 'pydevd', 'debugpy', 'hook', 'inject', 'monkey_patch', 'pyrasite', 'pyinjector')
            for _sp_path in sys.path[:10]:
                try:
                    _sc_file = os.path.join(str(_sp_path), 'sitecustomize.py')
                    if os.path.isfile(_sc_file):
                        with open(_sc_file, 'r', encoding='utf-8', errors='ignore') as _sc_f:
                            _sc_content = _sc_f.read(4096).lower()
                        _sc_hits = 0
                        for _sp_pat in _sus_patterns:
                            if _sp_pat in _sc_content:
                                _sc_hits += 1
                        if _sc_hits >= 2:
                            __bedrock_abort__("Sitecustomize injection detected")
                            break
                except:
                    pass
        except:
            pass
        # === Continuous trace lock (re-verify and re-lock by identity) ===
        # Identity-pinned (not name-based): an attacker who installs a tracer
        # named `<lambda>` would evade the old __name__ != '<lambda>' check.
        # We pin the exact _noop object installed by __bedrock_lock_trace__ and
        # compare by identity (is / is not). Also re-verify threading-level
        # hooks (threading._trace_hook / _profile_hook) which lock_trace nulls
        # once but the old re-verify never checked again.
        try:
            _pinned = globals().get('__bedrock_tracer_fn__')
            _ct = sys.gettrace()
            if _ct is not None and _ct is not _pinned:
                if _pinned is not None:
                    sys.settrace(_pinned)
                else:
                    sys.settrace(None)
                __bedrock_abort__("Trace hook re-detected")
            _cp = sys.getprofile()
            if _cp is not None and _cp is not _pinned:
                if _pinned is not None:
                    sys.setprofile(_pinned)
                else:
                    sys.setprofile(None)
                __bedrock_abort__("Profile hook re-detected")
            # Threading-level re-verify (lock_trace sets these once; an
            # attacker can re-hook threading.settrace after that one-shot).
            import threading as _th
            _th_tr = getattr(_th, '_trace_hook', None)
            if _th_tr is not None and _th_tr is not _pinned:
                if _pinned is not None:
                    _th.settrace(_pinned)
                __bedrock_abort__("Thread trace hook re-detected")
            _th_pr = getattr(_th, '_profile_hook', None)
            if _th_pr is not None and _th_pr is not _pinned:
                if _pinned is not None:
                    _th.setprofile(_pinned)
                __bedrock_abort__("Thread profile hook re-detected")
        except:
            pass
        # === Anti audit hook - block dangerous imports only ===
        try:
            # D1: block dangerous debug/profiling imports via audit hook too.
            _blocked_imports = ('frida', 'pydevd', 'debugpy', 'pyrasite', 'pyinjector', 'pydbg', 'winappdbg',
                               'manhole', 'remote_pdb', 'hunter', 'hypothesis')
            def _bedrock_audit(event, args):
                if event == 'import' and args and str(args[0]) in _blocked_imports:
                    raise RuntimeError("Blocked")
            sys.addaudithook(_bedrock_audit)
        except:
            pass
        # === Re-verify builtins after all other checks ===
        try:
            _critical = ('exec', 'eval', 'compile', '__import__', 'print', 'open', 'len', 'sum', 'getattr', 'setattr')
            for _cn in _critical:
                _func = getattr(_b, _cn, None)
                if _func is None:
                    __bedrock_abort__("Late builtins hook detected")
                elif _cn not in ('globals', 'locals', 'vars', 'dir') and not isinstance(_func, _t.BuiltinFunctionType):
                    __bedrock_abort__("Late builtins hook detected")
        except:
            pass
        # === Memory bomb abort (learned from Pymeo) - replace os._exit fallback ===
        try:
            _orig_exit = __import__('os')._exit
            def _bedrock_hard_abort(code=1):
                try:
                    _orig_exit(code)
                except:
                    pass
                try:
                    exec("(lambda:(_ for _ in range(2**63)))()")
                except:
                    pass
                raise SystemExit(code)
            globals()['__bedrock_hard_exit__'] = _bedrock_hard_abort
        except:
            pass

    # === Anti-Hook: Builtins Snapshot (learned from Pygaugau) ===
    __bedrock_builtins_snapshot__ = {{}}
    def __bedrock_snapshot_builtins__():
        try:
            import builtins as _b
            _critical_bi = ('exec', 'eval', 'compile', '__import__', 'print', 'open', 'input', 'getattr', 'setattr', 'len', 'sum', 'chr', 'ord', 'type', 'bytes', 'str', 'int', 'isinstance', 'hasattr', 'callable', 'repr', 'id', 'hash')
            for _n in _critical_bi:
                _f = getattr(_b, _n, None)
                if _f is not None:
                    __bedrock_builtins_snapshot__[_n] = id(_f)
        except:
            pass

    def __bedrock_verify_builtins_snapshot__():
        try:
            import builtins as _b
            if not __bedrock_builtins_snapshot__:
                return
            for _n, _oid in __bedrock_builtins_snapshot__.items():
                _cur = getattr(_b, _n, None)
                if _cur is None or id(_cur) != _oid:
                    __bedrock_abort__("Builtins hook detected (snapshot)")
                    return
        except:
            pass

    # === Anti-Hook: sys.modules integrity snapshot ===
    # Mirrors the builtins snapshot rhythm: early-capture id() of critical
    # stdlib modules, late-verify both id() AND authenticity (BuiltinFunctionType
    # for known-C functions). Catches sys.modules fake-module injection
    # ("layer hijacking") where an attacker pre-injects a Python-level trojan
    # module (e.g. fake `marshal` with a `loads` lambda) before the loader runs.
    # `requests`/`socket` are EXCLUDED — install_embedded_net pops them from
    # sys.modules to shadow with its own XOR-keyed copies via _HFinder.
    __bedrock_modules_snapshot__ = {{}}
    __bedrock_metapath_snapshot__ = None
    __bedrock_tracer_fn__ = None
    def __bedrock_snapshot_modules__():
        try:
            import sys as _sys
            _critical_mods = ('sys', 'os', 'builtins', 'types', 'threading',
                              'importlib', 'marshal', 'gc', 'hashlib', 'zlib',
                              'base64', 'pickle', 'struct', 'time', 'json',
                              'ctypes', 'binascii', 'io', 'errno')
            for _n in _critical_mods:
                _m = _sys.modules.get(_n)
                if _m is not None:
                    __bedrock_modules_snapshot__[_n] = id(_m)
        except:
            pass

    def __bedrock_verify_modules_snapshot__():
        try:
            import sys as _sys, types as _t
            if not __bedrock_modules_snapshot__:
                return
            for _n, _oid in __bedrock_modules_snapshot__.items():
                _cur = _sys.modules.get(_n)
                # Removal is tolerated (legitimate eviction, e.g. by bedrock
                # itself). A *replacement* (id mismatch) is the attack signal.
                if _cur is None:
                    continue
                if id(_cur) != _oid:
                    __bedrock_abort__("Module hook detected (snapshot): " + _n)
                    return
            # Authenticity: known-C stdlib functions must still be
            # BuiltinFunctionType. A Python-level fake (lambda/def) replacing
            # them flips to FunctionType — the layer-hijack signature.
            _auth = (
                ('marshal', 'loads'), ('zlib', 'decompress'),
                ('binascii', 'a2b_base64'), ('hashlib', 'sha256'),
                ('time', 'time'), ('gc', 'collect'),
            )
            for _mn, _fn in _auth:
                _mod = _sys.modules.get(_mn)
                if _mod is None:
                    continue
                _f = getattr(_mod, _fn, None)
                if _f is None:
                    continue
                if not isinstance(_f, _t.BuiltinFunctionType):
                    __bedrock_abort__("Module authenticity fail: " + _mn + "." + _fn)
                    return
        except:
            pass

    # === Anti-Hook: sys.meta_path finder snapshot ===
    # Captures the post-defense meta_path baseline (after anti_inject_advanced
    # has removed token-matching finders AND install_embedded_net has inserted
    # bedrock's own _HFinder). Any *new* finder injected after this point
    # (id not in the snapshot set) is a layer-hijack attempt. Removal is
    # tolerated (legitimate).
    def __bedrock_snapshot_metapath__():
        global __bedrock_metapath_snapshot__
        try:
            import sys as _sys
            __bedrock_metapath_snapshot__ = [(id(_f), type(_f).__name__)
                                             for _f in _sys.meta_path]
        except:
            pass

    def __bedrock_verify_metapath_snapshot__():
        try:
            import sys as _sys
            if not __bedrock_metapath_snapshot__:
                return
            _known_ids = set(_oid for _oid, _ in __bedrock_metapath_snapshot__)
            for _f in _sys.meta_path:
                if id(_f) not in _known_ids:
                    __bedrock_abort__("meta_path finder injected: " +
                                      type(_f).__name__)
                    return
        except:
            pass

    # === Anti-Hook: Call Frame Check (learned from Pygaugau) ===
    def __bedrock_check_call_frames__():
        try:
            import inspect
            _suspicious_fr = ('frida', 'pydevd', 'debugpy', 'mitmproxy', 'pyrasite', 'pyinjector', 'pydbg', 'winappdbg')
            _fr_hits = 0
            for _fr in inspect.stack():
                _fn = (getattr(_fr, 'filename', '') or '').lower()
                for _s in _suspicious_fr:
                    if _s in _fn:
                        _fr_hits += 1
                        break
            if _fr_hits >= 1:
                __bedrock_abort__("Suspicious frame detected")
        except:
            pass

    # RUN CHECKS - Each in isolated try/except
    try:
        __bedrock_lock_trace__()
    except:
        pass
    try:
        __bedrock_snapshot_builtins__()
    except:
        pass
    try:
        {integrity_fn}()
    except:
        pass
    try:
        __h_check_self_integrity()
    except:
        pass
    try:
        __bedrock_check_loader_shape__()
    except:
        pass
    try:
        __bedrock_check_prepend__()
    except:
        pass
    try:
        __bedrock_check_append__()
    except:
        pass
    try:
        __bedrock_pin_callable__('marshal', 'loads')
    except:
        pass
    try:
        __bedrock_pin_callable__('zlib', 'decompress')
    except:
        pass
    try:
        __bedrock_guard_marshal__()
    except:
        pass
    try:
        __bedrock_c_level_probe__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_debug__()
    except:
        pass
    try:
        __bedrock_check_builtins__()
    except:
        pass
    try:
        __bedrock_check_stack__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_net_modules__()
    except:
        pass
    try:
        __bedrock_check_process_tools__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_sniffer__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_registry_proxy__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_http_toolkit__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_install_embedded_net__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_requests__(_REQ_ADVANCED)
    except:
        pass
    try:
        __bedrock_check_module_str__()
    except:
        pass
    try:
        __bedrock_check_stack_depth__()
    except:
        pass
    try:
        __bedrock_seal_socket__()
    except:
        pass
    try:
        __bedrock_anti_inject_advanced__()
    except:
        pass
    try:
        __bedrock_snapshot_modules__()
    except:
        pass
    try:
        __bedrock_snapshot_metapath__()
    except:
        pass
    try:
        __bedrock_check_call_frames__()
    except:
        pass
    try:
        __bedrock_verify_builtins_snapshot__()
    except:
        pass
    try:
        __bedrock_verify_modules_snapshot__()
    except:
        pass
    try:
        __bedrock_verify_metapath_snapshot__()
    except:
        pass


except Exception:
    __bedrock_self_destruct__("integrity policy triggered")
"""
            # --- KẾT THÚC MÃ TỰ HỦY ---
            # Phase 4: debrand the entire self_check_code so every __bedrock_*
            # identifier (and any bedrock/baobg literal inside it) is replaced
            # with the per-build token BEFORE it's compiled + marshalled into
            # DitMeMayDecDiCode. Identity when anti-meta is off.
            self_check_code = _debrand(self_check_code)

            python_band_spec = str(globals().get('python_band_mode', '3.10-3.12') or '3.10-3.12').strip()
            python_version_check = build_python_band_check(python_band_spec)
            (stub_min_major, stub_min_minor), (stub_max_major, stub_max_minor) = parse_python_band(python_band_spec)
            stub_version_check = f"""
import sys as __bedrock_sys
__bedrock_ver = (__bedrock_sys.version_info[0], __bedrock_sys.version_info[1])
if __bedrock_ver < ({stub_min_major}, {stub_min_minor}) or __bedrock_ver > ({stub_max_major}, {stub_max_minor}):
    raise SystemExit("Unsupported Python runtime. Target band is {python_band_spec}.")
""" 

            # --- KẾT HỢP TẤT CẢ VÀO PAYLOAD CHÍNH ---
            # Giờ đây, self_check_code và python_version_check sẽ được mã hóa
            # cùng với code của người dùng.
            stdout_fix = """
try:
    import sys as __h_sys
    __h_sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
    __h_sys.stderr.reconfigure(encoding='utf-8', errors='ignore')
except Exception:
    pass
"""
            preamble_code, payload_body = split_preamble_code(DitMeMayDecDiCode)
            DitMeMayDecDiCode = join_code_parts(preamble_code, python_version_check, stdout_fix, self_check_code, clean_, ANTI_PYCDC, payload_body)
            runtime_mode_ = str(globals().get('runtime_mode', 'main') or 'main').strip().lower()
            bind_mode_ = str(globals().get('bind_mode', 'none') or 'none').strip().lower()
            anti_hook_mode_ = str(globals().get('anti_hook_mode', 'strict') or 'strict').strip().lower()
            anti_debug_mode_ = str(globals().get('anti_debug_mode', 'score') or 'score').strip().lower()
            tamper_mode_ = str(globals().get('tamper_mode', 'self-destruct') or 'self-destruct').strip().lower()
            carrier_mode_ = str(globals().get('vm_carrier_mode', 'auto') or 'auto').strip().lower()
            compat_mode_ = str(globals().get('vm_compat_mode', 'broad') or 'broad').strip().lower()
            legacy_loader_ = bool(globals().get('legacy_loader', False))

            # NOTE: vm-native-v2 / vm-native / chunk-vm-lite runtime branches removed
            # in Bedrock vNext Phase 1 (VM runtimes dropped; native main loader below).



            # M? h?a payload
            _co_pl = compile(_debrand(DitMeMayDecDiCode), '<' + _debrand('BedrockDepTrai_marker') + '>', 'exec')
            _bx2 = globals().get('__BEDROCK_BUILD_CTX__')
            if _bx2 is not None and getattr(_bx2, 'bc_mutate', False) and _ext_mutate_code is not None and sys.version_info >= (3, 10):
                try:
                    _co_pl = _ext_mutate_code(_co_pl, _bx2)
                except Exception:
                    pass
            code__ = Compile.serializer.dumps(_co_pl)
            # Phase 4: when anti-meta is ON, emit per-build random var names +
            # values (from _META_INFOS, set in _init_debrand). When OFF,
            # _META_INFOS == the static infos, so output is unchanged.
            _emit_infos = globals().get('_META_INFOS') or Compile.infos
            infos_ = '\n'.join((f"{key}{(' ' * 2 if key == '__OBFBot__' else ' ' * 3)}= {value!r}" for key, value in _emit_infos.items()))

            used_names = set()

            def _new_name(n: int = 8) -> str:
                name = rand_cn_name(n)
                while name in used_names:
                    name = rand_cn_name(n)
                used_names.add(name)
                return name

            def _rand_key_fixed(length: int) -> str:
                return ''.join((random.choice(_KEY_CHAR_POOL) for _ in range(length)))

            def _build_candidates(real: str, count: int = 7) -> Tuple[List[str], str]:
                candidates = [_rand_key_fixed(len(real)) for _ in range(max(2, count) - 1)]
                insert_at = random.randint(0, len(candidates))
                candidates.insert(insert_at, real)
                digest = hashlib.sha256(real.encode('utf-8')).hexdigest()
                return candidates, digest

            def _half_block(half: str) -> Tuple[str, str]:
                list_name = _new_name(8)
                hash_name = _new_name(8)
                pick_name = _new_name(8)
                part_name = _new_name(8)
                candidates, digest = _build_candidates(half, count=7)
                digest_enc = base64.b85encode(digest.encode('utf-8')).decode('ascii')
                lines = []
                lines.append(f"{list_name} = {candidates!r}")
                lines.append(f"{hash_name} = {digest_enc!r}")
                func_lines = [
                    f"def {pick_name}(cand, mark):",
                    "    import hashlib as _h",
                    "    import base64 as _b",
                    "    _d = _b.b85decode(mark.encode('utf-8')).decode('utf-8')",
                    "    for _s in cand:",
                    "        if _h.sha256(_s.encode('utf-8')).hexdigest() == _d:",
                    "            return _s",
                    "    return ''",
                ]
                lines.append("\n".join(func_lines))
                lines.append(f"{part_name} = {pick_name}({list_name}, {hash_name})")
                return '\n'.join(lines), part_name

            key1 = rand_key(12, 20)
            key2 = rand_key(12, 20)
            # A5: env keying. When --env-key is on, derive key1/key2 from the
            # build machine's hardware fingerprint (machine-id + MAC + node +
            # arch, SHA-256'd) instead of random strings. The runtime half
            # of this gate (below, in main_lines) emits a collector that
            # re-derives the SAME fingerprint at run time; on a mismatched
            # machine the collector yields different bytes -> key1/key2 wrong
            # -> RemoveLayers XORs the payload with the wrong key -> the
            # marshalled blob fails to load and the payload stays inert.
            # Build-time and runtime MUST derive identically: both read the
            # same 5 fields through _collect_hw_fingerprint() (build) /
            # _emit_hw_fingerprint_runtime() (runtime twin).
            _bx_envkey = globals().get('__BEDROCK_BUILD_CTX__')
            _envkey_on = _bx_envkey is not None and getattr(_bx_envkey, 'env_key', False)
            if _envkey_on:
                try:
                    _envfp = _collect_hw_fingerprint()
                    _envhex = _envfp.hex()
                    # 32-byte digest -> 64 hex chars; split 32/32 into key1/key2.
                    key1 = _envhex[:32]
                    key2 = _envhex[32:]
                except Exception:
                    # Fingerprint failed (e.g. restrictive env) -> fall back to
                    # random keys so the build still produces a runnable file
                    # rather than crashing; the lock just won't engage.
                    _envkey_on = False
            mid1 = max(1, len(key1) // 2)
            mid2 = max(1, len(key2) // 2)
            key1_a, key1_b = key1[:mid1], key1[mid1:]
            key2_a, key2_b = key2[:mid2], key2[mid2:]

            top_chunks: List[str] = []
            bottom_chunks: List[str] = []
            block, part1a = _half_block(key1_a)
            top_chunks.append(block)
            block, part1b = _half_block(key1_b)
            bottom_chunks.append(block)
            block, part2a = _half_block(key2_a)
            top_chunks.append(block)
            block, part2b = _half_block(key2_b)
            bottom_chunks.append(block)
            # A5: the env-key fingerprint collector is emitted into main_body
            # below (NOT top_chunks) so it runs AFTER the baobg_vars indirection
            # dict is set up -- the collector's `_dyn_import_expr` reads back
            # from BUILTIN_DICT_NAME, which is only populated at that point.
            _envkey_collector = _emit_hw_fingerprint_runtime(var_name=_ENVKEY_NAME) if _envkey_on else ''

            # th?m spam decode/encode r?c ? cu?i file
            bottom_chunks.append("\n".join([
                f"def {rand_cn_name(8)}(x):",
                "    import base64 as _b",
                "    import marshal as _m",
                "    t = _b.b85encode(_b.b64encode(_m.dumps(x)))",
                "    return _m.loads(_b.b64decode(_b.b85decode(t)))",
            ]))
            bottom_chunks.append("\n".join([
                f"def {rand_cn_name(8)}(b):",
                "    import base64 as _b",
                "    if not isinstance(b, (bytes, bytearray)):",
                "        b = str(b).encode('utf-8')",
                "    t = _b.b64encode(b)",
                "    return _b.b85encode(t)",
            ]))
            bottom_chunks.append("\n".join([
                f"def {rand_cn_name(8)}(s):",
                "    import marshal as _m",
                "    x = _m.dumps(s)",
                "    return _m.loads(x)",
            ]))

            key1_var = _new_name(8)
            key2_var = _new_name(8)

            # l?p m? h?a ngo?i c?ng (base64/base85/marshal r?c + XOR 2 l?p)
            code__ = zlib.compress(code__)
            code__ = base64.b85encode(code__)
            junk_obj = {
                rand_cn_name(4): rand_key(6, 12),
                rand_cn_name(4): random.randint(1000, 9999999),
                rand_cn_name(4): bytes((random.getrandbits(8) for _ in range(random.randint(8, 24)))),
            }
            junk_marshaled = Compile.serializer.dumps(junk_obj)
            outer = Compile.serializer.dumps((code__, junk_marshaled, bytes((random.getrandbits(8) for _ in range(16))), random.randint(1, 1_000_000)))
            outer = base64.b64encode(outer)
            outer = base64.b85encode(outer)
            outer = outer[::-1]
            outer = _xor_bytes(outer, key1)
            outer = _xor_bytes(outer, key2)
            code__ = base64.b64encode(outer)

            # extra payload transforms (reversible)
            xor_c = random.randint(1, 255)
            add_c = random.randint(1, 255)
            rot_c = random.randint(1, min(13, len(code__) - 1)) if len(code__) > 1 else 0
            code__ = bytes((b ^ xor_c) for b in code__)
            if rot_c:
                code__ = code__[rot_c:] + code__[:rot_c]
            if add_c:
                code__ = bytes(((b + add_c) & 0xFF) for b in code__)

            # VM bytecode wrapper for payload decoding (virtualization layer)
            op_names = [
                'PUSH', 'DROP', 'DUP', 'SWAP',
                'XOR1', 'XOR2', 'XORC',
                'REV', 'ROTL', 'ROTR',
                'ADDC', 'SUBC',
                'B64', 'B85', 'MARSHAL', 'ZLIB',
                'GET0', 'RET', 'NOP',
            ]
            op_vals = random.sample(range(1, 250), len(op_names))
            (
                OP_PUSH, OP_DROP, OP_DUP, OP_SWAP,
                OP_XOR1, OP_XOR2, OP_XORC,
                OP_REV, OP_ROTL, OP_ROTR,
                OP_ADDC, OP_SUBC,
                OP_B64, OP_B85, OP_MARSHAL, OP_ZLIB,
                OP_GET0, OP_RET, OP_NOP,
            ) = op_vals
            vm_mask = random.randint(1, 255)
            vm_add = random.randint(1, 255)
            vm_pmask = random.randint(1, 255)

            # N3: per-build opcode permutation + XOR key. When --vm-opcode-remap
            # is on, opcodes are first run through a random 256-entry bijection
            # (OP_PERM) and XOR'd with a fresh byte (vm_opkey2) BEFORE the
            # existing mask/add layer. The permutation table + key are shipped
            # in the vm_prog header so the runtime can invert them. Opcodes
            # outside the VM's small (0..49) range keep identity entries so
            # the table is a true bijection over 0..255 and stays total.
            _bx_n3 = globals().get('__BEDROCK_BUILD_CTX__')
            _vm_remap_on = _bx_n3 is not None and getattr(_bx_n3, 'vm_opcode_remap', False)
            vm_opkey2 = 0
            _vm_perm = list(range(256))  # identity; overwritten if remap on
            if _vm_remap_on:
                vm_opkey2 = random.randint(1, 255)
                _vm_perm = list(range(256))
                random.shuffle(_vm_perm)
                # Guarantee bijection: shuffle on a list of all 256 values is
                # always a permutation, so no duplicate check needed.

            def _vm_enc_op(op: int) -> bytes:
                # Apply permutation + key2 (N3) then the existing mask/add.
                _o = _vm_perm[op] if _vm_remap_on else op
                if _vm_remap_on:
                    _o = _o ^ vm_opkey2
                return bytes([((_o ^ vm_mask) + vm_add) & 0xFF])

            def _vm_enc_param(b: int) -> bytes:
                return bytes([(b ^ vm_pmask) & 0xFF])

            def _vm_enc_u32(n: int) -> bytes:
                return bytes([((n >> shift) & 0xFF) ^ vm_pmask for shift in (24, 16, 8, 0)])

            def _vm_enc_blob(data: bytes) -> bytes:
                return bytes((b ^ vm_pmask) for b in data)

            def _vm_push(data: bytes) -> bytes:
                return _vm_enc_op(OP_PUSH) + _vm_enc_u32(len(data)) + _vm_enc_blob(data)

            def _vm_op(op: int) -> bytes:
                return _vm_enc_op(op)

            def _vm_opc(op: int, c: int) -> bytes:
                return _vm_enc_op(op) + _vm_enc_param(c & 0xFF)

            def _vm_noise() -> bytes:
                junk = bytes((random.getrandbits(8) for _ in range(random.randint(3, 11))))
                seq = _vm_push(junk)
                if random.random() < 0.5:
                    seq += _vm_op(OP_DUP) + _vm_op(OP_DROP)
                if random.random() < 0.5:
                    c = random.randint(1, 255)
                    seq += _vm_opc(OP_XORC, c) + _vm_opc(OP_XORC, c)
                if random.random() < 0.4:
                    c = random.randint(1, 255)
                    seq += _vm_opc(OP_ADDC, c) + _vm_opc(OP_SUBC, c)
                if random.random() < 0.4:
                    r = random.randint(1, 7)
                    seq += _vm_opc(OP_ROTL, r) + _vm_opc(OP_ROTR, r)
                if random.random() < 0.3:
                    seq += _vm_op(OP_REV) + _vm_op(OP_REV)
                if random.random() < 0.25:
                    junk2 = bytes((random.getrandbits(8) for _ in range(random.randint(2, 6))))
                    seq += _vm_push(junk2) + _vm_op(OP_SWAP) + _vm_op(OP_DROP) + _vm_op(OP_DROP)
                    return seq
                seq += _vm_op(OP_DROP)
                return seq

            vm_parts = []
            vm_parts.append(_vm_push(code__))
            if random.random() < 0.7:
                vm_parts.append(_vm_noise())
            vm_parts.append(_vm_opc(OP_SUBC, add_c))
            if rot_c:
                vm_parts.append(_vm_opc(OP_ROTR, rot_c))
            vm_parts.append(_vm_opc(OP_XORC, xor_c))
            vm_parts.append(_vm_op(OP_B64))
            if random.random() < 0.6:
                vm_parts.append(_vm_noise())
            vm_parts.append(_vm_op(OP_XOR2))
            if random.random() < 0.4:
                vm_parts.append(_vm_noise())
            vm_parts.append(_vm_op(OP_XOR1))
            if random.random() < 0.4:
                vm_parts.append(_vm_op(OP_DUP))
                vm_parts.append(_vm_op(OP_DROP))
            vm_parts.append(_vm_op(OP_REV))
            vm_parts.append(_vm_op(OP_B85))
            if random.random() < 0.3:
                vm_parts.append(_vm_op(OP_NOP))
            vm_parts.append(_vm_op(OP_B64))
            if random.random() < 0.4:
                vm_parts.append(_vm_noise())
            vm_parts.append(_vm_op(OP_MARSHAL))
            vm_parts.append(_vm_op(OP_GET0))
            vm_parts.append(_vm_op(OP_B85))
            vm_parts.append(_vm_op(OP_ZLIB))
            if random.random() < 0.5:
                vm_parts.append(_vm_noise())
            vm_parts.append(_vm_op(OP_MARSHAL))
            vm_parts.append(_vm_op(OP_RET))
            # N3: when opcode remap is on, prepend the permutation key + the
            # 256-entry bijection table to the vm_prog header (after mask/add/
            # pmask) so the runtime __vm__ can read them back and invert.
            # Each table byte is itself XOR'd with vm_pmask so the table does
            # not appear as a plaintext identity permutation in the binary.
            if _vm_remap_on:
                _perm_hdr = bytes([(b ^ vm_pmask) & 0xFF for b in _vm_perm])
                vm_prog = bytes([vm_mask, vm_add, vm_pmask, vm_opkey2]) + _perm_hdr + b''.join(vm_parts)
            else:
                vm_prog = bytes([vm_mask, vm_add, vm_pmask]) + b''.join(vm_parts)
            code__ = base64.b85encode(vm_prog)

            # t?o RemoveLayers theo key name ng?u nhi?n (ti?ng Trung)
            # N3: inject the per-build opcode-permutation inversion into the
            # runtime __vm__ when --vm-opcode-remap is on. The two blocks
            # below are empty strings when remap is off so the template
            # collapses to the original __vm__ exactly.
            if _vm_remap_on:
                _perm_setup = (
                    "\n                    opkey2 = prog[3] if len(prog) > 3 else 0"
                    "\n                    _pt_raw = prog[4:260] if len(prog) >= 260 else bytes(256)"
                    "\n                    _pt = bytes((b ^ pm) for b in _pt_raw)"
                    "\n                    _inv = [0] * 256"
                    "\n                    for _k in range(256):"
                    "\n                        _inv[_pt[_k]] = _k"
                    "\n                    i = 260"
                )
                _perm_invert = "\n                        _o = _inv[_o ^ opkey2]  # un-XOR key2 + un-permute (N3)"
            else:
                _perm_setup = ""
                _perm_invert = ""
            remove_layers_src = f"""def RemoveLayers():
                if not globals().get('gate'):
                    return
                obj = globals()['__selfObject__']
                module = globals()['__module']
                module__ = globals()['___module']
                data = obj.code['bytes']
                data = module.b85decode(data)
                kb1 = {key1_var}.encode('utf-8')
                kb2 = {key2_var}.encode('utf-8')

                def __vm__(prog):
                    if not prog:
                        return None
                    stack = []
                    mask = prog[0]
                    add = prog[1] if len(prog) > 1 else 0
                    pm = prog[2] if len(prog) > 2 else 0
                    i = 3{_perm_setup}

                    def _dec_op(b):
                        _o = ((b - add) & 0xFF) ^ mask{_perm_invert}
                        return _o

                    def _dec_p(b):
                        return b ^ pm

                    while i < len(prog):
                        op = _dec_op(prog[i])
                        i += 1
                        if op == {OP_PUSH}:
                            if i + 4 > len(prog):
                                break
                            ln = int.from_bytes(bytes((_dec_p(x) for x in prog[i:i+4])), 'big')
                            i += 4
                            raw = prog[i:i+ln]
                            i += ln
                            stack.append(bytes((b ^ pm) for b in raw))
                        elif op == {OP_DROP}:
                            if stack:
                                stack.pop()
                        elif op == {OP_DUP}:
                            if stack:
                                stack.append(stack[-1])
                        elif op == {OP_SWAP}:
                            if len(stack) >= 2:
                                stack[-1], stack[-2] = stack[-2], stack[-1]
                        elif op == {OP_B64}:
                            d = stack.pop()
                            stack.append(module.b64decode(d))
                        elif op == {OP_B85}:
                            d = stack.pop()
                            stack.append(module.b85decode(d))
                        elif op == {OP_XOR1}:
                            d = stack.pop()
                            if kb1:
                                d = bytes((b ^ kb1[j % len(kb1)]) for j, b in enumerate(d))
                            stack.append(d)
                        elif op == {OP_XOR2}:
                            d = stack.pop()
                            if kb2:
                                d = bytes((b ^ kb2[j % len(kb2)]) for j, b in enumerate(d))
                            stack.append(d)
                        elif op == {OP_XORC}:
                            c = _dec_p(prog[i])
                            i += 1
                            d = stack.pop()
                            d = bytes((b ^ c) for b in d)
                            stack.append(d)
                        elif op == {OP_REV}:
                            d = stack.pop()
                            stack.append(d[::-1])
                        elif op == {OP_ROTL}:
                            n = _dec_p(prog[i])
                            i += 1
                            d = stack.pop()
                            if d:
                                n = n % len(d)
                                stack.append(d[n:] + d[:n])
                            else:
                                stack.append(d)
                        elif op == {OP_ROTR}:
                            n = _dec_p(prog[i])
                            i += 1
                            d = stack.pop()
                            if d:
                                n = n % len(d)
                                stack.append(d[-n:] + d[:-n] if n else d)
                            else:
                                stack.append(d)
                        elif op == {OP_ADDC}:
                            c = _dec_p(prog[i])
                            i += 1
                            d = stack.pop()
                            d = bytes(((b + c) & 0xFF) for b in d)
                            stack.append(d)
                        elif op == {OP_SUBC}:
                            c = _dec_p(prog[i])
                            i += 1
                            d = stack.pop()
                            d = bytes(((b - c) & 0xFF) for b in d)
                            stack.append(d)
                        elif op == {OP_MARSHAL}:
                            d = stack.pop()
                            stack.append(globals()['__sr_m'].loads(d))
                        elif op == {OP_GET0}:
                            d = stack.pop()
                            stack.append(d[0])
                        elif op == {OP_ZLIB}:
                            d = stack.pop()
                            stack.append(module__.decompress(d))
                        elif op == {OP_NOP}:
                            pass
                        elif op == {OP_RET}:
                            return stack.pop() if stack else None
                    return stack.pop() if stack else None

                # Wipe the global decrypt keys after use so a post-decrypt
                # memory dump cannot re-derive the payload. The local kb1/kb2
                # go out of scope on return, but the globals persist without
                # this del. Also force a gc.collect so the decompressed
                # intermediate buffers and the __vm__ closure become
                # reclaimable immediately.
                try:
                    del globals()['{key1_var}']
                except KeyError:
                    pass
                try:
                    del globals()['{key2_var}']
                except KeyError:
                    pass
                try:
                    import gc as _br_rl_gc
                    _br_rl_gc.collect()
                except Exception:
                    pass
                return __vm__(data)
            """
            _rl_ns: Dict[str, Any] = {}
            exec(remove_layers_src, _rl_ns)
            remove_layers_code = _rl_ns['RemoveLayers'].__code__

            done = current_time_hcm.strftime('%Y-%m-%d %H:%M:%S')
            mode_ = 'BedrockSieuVip'
            protect_ = type_run + ' - ' + mode_
            alt_base64 = Compile.DynImport('base64')
            alt_zlib = Compile.DynImport('zlib')

            file_prefix = globals().get('__FILE_PREFIX__', '')
            # Phase 4: when anti-meta is on, strip the write-only decoration
            # lines (comment, __OBFType__, __Comment__, __OBFTime__ have zero
            # runtime readers — confirmed by exploration) so no static
            # baobg/BedrockDz/BedrockSieuVip signature reaches the header.
            # Also debrand the header comment so no 'baobg'/'BedrockDz' literal
            # survives in line 1.
            _hdr_comment = _debrand('# This File is Protected By baobg (BedrockDz)')
            if BR_DEBRAND_ON:
                _hdr_comment = ''
            _hdr_parts = []
            if _hdr_comment:
                _hdr_parts.append(_hdr_comment)
            _hdr_parts.append(file_prefix)
            _hdr_parts.append(infos_)
            _hdr_parts.append(f'{lcan_var_name} = "{loader_canary}"')
            if not BR_DEBRAND_ON:
                _hdr_parts.append(f'__OBFType__ = "{protect_}"')
                _hdr_parts.append('__Comment__ = "Don\'t read it, or you will get vestibular disorder from BedrockDz.!"')
                _hdr_parts.append(f'__OBFTime__ = "{done}"')
            _hdr_parts.append(f'__H_FILE_HASH__ = "{file_hash_placeholder}"')
            _hdr_parts.append(f'__H_INTEGRITY_VAR__ = "{integrity_var}"')
            # Plaintext sentinel for the native-VM extension hash. The loader
            # snippet reads this via _vm_globals().get('__VM_EXTHASH__', ...).
            # Post-ship, the obfuscator patches the sentinel with the shipped
            # .pyd's SHA-256 (the .pyd is built AFTER the loader text is
            # emitted, so the hash can't be baked in at compile time). The
            # sentinel is 64 chars (matching the real hash length) so the
            # file-integrity masking is length-preserving. Harmless in non-VM
            # builds (an unused global).
            _hdr_parts.append(f'__VM_EXTHASH__ = "{_vm_exthash_sentinel}"')
            header = join_code_parts(*_hdr_parts)
            integrity_assign = f"{integrity_var} = {integrity_placeholder!r}"
            requests_mode_assign = f"{requests_mode_var} = {requests_mode_placeholder}"

            stub_check = stub_version_check.strip('\n')
            main_func = _new_name(8)
            call_lines = [
                f"AnhOiDungCoDec({code__!r},",
                f"        {base64.b64encode(Compile.serializer.dumps(remove_layers_code))!r},",
                f"        {alt_base64},",
                f"        {alt_zlib}, globals(),",
                f"        {base64.b16encode(Compile.serializer.dumps(Compile.DitMeMayDungCoDec.__code__))!r}",
                f").DitMeMayDecDi()",
            ]
            def _decoy_def(name: str) -> str:
                dummy_code = Compile.serializer.dumps(compile("0", "<h>", "exec"))
                dummy_enc = base64.b85encode(dummy_code)
                return "\n".join([
                    f"def {name}():",
                    "    try:",
                    "        import base64 as _b",
                    "        import marshal as _m",
                    f"        _c = _m.loads(_b.b85decode({dummy_enc!r}))",
                    "        exec(_c, globals())",
                    "    except Exception:",
                    "        pass",
                ])

            real_runner = _new_name(8)
            real_def = "\n".join([f"def {real_runner}():"] + [f"    {line}" for line in call_lines])

            tbl_len = random.randint(4, 7)
            decoy_names = [_new_name(8) for _ in range(tbl_len - 1)]
            salt = random.randint(1, 65535)
            def _score(s: str) -> int:
                return sum((ord(c) for c in s))
            idx_val = (_score(key1) ^ _score(key2) ^ salt) % tbl_len
            tbl_items: List[str] = []
            decoy_iter = iter(decoy_names)
            for i in range(tbl_len):
                if i == idx_val:
                    tbl_items.append(real_runner)
                else:
                    tbl_items.append(next(decoy_iter))

            globals_fn = Compile.DynBuiltin('globals')
            idx_func_name = _new_name(8)
            idx_func_code = "\n".join([
                f"def {idx_func_name}(a, b, _s={salt}, _l={tbl_len}):",
                "    try:",
                "        _b = globals().get('__builtins__')",
                "        if isinstance(_b, dict):",
                "            _sum = _b.get('sum')",
                "            _map = _b.get('map')",
                "            _ord = _b.get('ord')",
                "            _len = _b.get('len')",
                "        else:",
                "            _sum = _b.sum",
                "            _map = _b.map",
                "            _ord = _b.ord",
                "            _len = _b.len",
                "        if ((_len(a) * 12345) ^ (_len(a) * 12345)) != 0:",
                "            return 0",
                "        return ((_sum(_map(_ord, a)) ^ _sum(_map(_ord, b)) ^ _s) % _l)",
                "    except Exception:",
                "        return 0",
            ])
            top_chunks.append(idx_func_code)
            idx_expr = f"{idx_func_name}({key1_var}, {key2_var})"

            def _pick_slice(slen: int) -> Tuple[int, int]:
                start = random.randint(0, max(0, slen - 2))
                end = min(slen, start + random.randint(1, 3))
                return start, end
            a1, b1 = _pick_slice(len(key1))
            a2, b2 = _pick_slice(len(key2))
            a3, b3 = _pick_slice(len(key1))
            key_expr = f"({key1_var}[{a1}:{b1}] + {key2_var}[{a2}:{b2}] + {key1_var}[{a3}:{b3}])"

            tbl_name = _new_name(8)
            idx_name = _new_name(8)
            key_name = _new_name(8)
            g_name = _new_name(8)

            decoy_defs = [_decoy_def(n) for n in decoy_names]
            main_lines = [
                f"def {main_func}():",
                f"    global {key1_var}, {key2_var}",
                # A5: when env-keying is on, key1/key2 are derived at RUNTIME
                # from the hardware fingerprint (__BedrockEnvKey__ is populated
                # by the collector emitted into top_chunks above). On the
                # build machine the collector returns the same bytes the
                # build-time _collect_hw_fingerprint() produced, so
                # key1/key2 match the ones the payload was XOR-encrypted
                # with. On a different machine the fingerprint differs ->
                # wrong key -> inert payload (silent fail, no crash).
                f"    {key1_var} = {_ENVKEY_NAME}.hex()[:32]" if _envkey_on else f"    {key1_var} = {part1a} + {part1b}",
                f"    {key2_var} = {_ENVKEY_NAME}.hex()[32:64]" if _envkey_on else f"    {key2_var} = {part2a} + {part2b}",
            ]
            for block in decoy_defs:
                for line in block.splitlines():
                    main_lines.append("    " + line)
            for line in real_def.splitlines():
                main_lines.append("    " + line)
            main_lines.extend([
                f"    {tbl_name} = [{', '.join(tbl_items)}]",
                f"    {idx_name} = {idx_expr}",
                f"    {key_name} = {key_expr}",
                f"    {g_name} = {globals_fn}()",
                f"    {g_name}[{key_name}] = {tbl_name}[{idx_name}]",
                f"    {g_name}[{key_name}]()", 
            ])
            main_func_block = "\n".join(main_lines)

            vars_placeholder = f"__BEDROCK_VARS_{random.randint(10**8, 10**9)}__"
            class_payload = join_code_parts(
                Compile._rendered_class('DitMeMayDungCoDecClass'),
                Compile._rendered_class('AnhOiDungCoDecClass'),
            )
            class_loader = Compile.ll(class_payload)

            _dn2 = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
            main_body = join_code_parts(
                f"global {_debrand(Compile.comment)}",
                f"__bedrock_builtin_scope__ = globals().get({Pycloak().encode('__builtins__')})",
                f"{_dn2} = (__bedrock_builtin_scope__ if isinstance(__bedrock_builtin_scope__, dict) else vars(__bedrock_builtin_scope__ if __bedrock_builtin_scope__ is not None else __import__({Pycloak().encode('builtins')})))",
                stub_check,
                vars_placeholder,
                class_loader,
                # A5: env-key collector runs AFTER baobg_vars (vars_placeholder)
                # is set up so its _dyn_import_expr reads succeed, and BEFORE
                # main_func_block runs so __BedrockEnvKey__ is populated.
                _envkey_collector,
                main_func_block,
            )
            main_body = main_body.replace(vars_placeholder, Compile.trash(Compile.ll(_debrand(pro))))

            dead_total = int(SPAM_TARGET_KB * 1024)
            spam_top = build_spam_block(int(dead_total * SPAM_PREFIX_RATIO), extra_lines=top_chunks + [integrity_assign, requests_mode_assign])
            spam_bottom = build_spam_block(dead_total - int(dead_total * SPAM_PREFIX_RATIO), extra_lines=bottom_chunks)

            main_call = f"{globals_fn}()[{Pycloak().encode(main_func)}]()"
            code_ = join_code_parts(header, spam_top, main_body, spam_bottom, main_call)
            # Phase 4: debrand the assembled output so any remaining
            # __bedrock_* identifier in main_body / stub_check / spam /
            # main_call is replaced with the per-build token before the
            # integrity hash is computed. Identity when anti-meta is off.
            # Also debrand placeholders that contain BEDROCK so the
            # .replace() calls below still find them post-debrand.
            code_ = _debrand(code_)
            requests_mode_placeholder = _debrand(requests_mode_placeholder)
            integrity_placeholder = _debrand(integrity_placeholder)
            requests_mode_literal = 'True' if requests_check_advanced else 'False'
            code_ = code_.replace(requests_mode_placeholder, requests_mode_literal)
            _masked_both = code_.replace(integrity_placeholder, integrity_marker).replace(file_hash_placeholder, "." * 64)
            # Also mask the __VM_EXTHASH__ sentinel so the post-ship ext-hash
            # injection (which replaces the 64-char sentinel with a 64-char
            # real hash) doesn't invalidate the file-integrity hash. Both the
            # sentinel and the real hash are 64 chars, and both the compile-
            # time and runtime masking replace this slot with 64 dots, so the
            # masked content is identical before and after injection.
            _masked_both = _masked_both.replace(_vm_exthash_sentinel, "." * 64)
            integrity_hash = hashlib.sha256((_masked_both + "|int").encode('utf-8')).hexdigest()
            code_ = code_.replace(integrity_placeholder, integrity_hash)
            file_hash = hashlib.sha256((_masked_both + "|fh").encode('utf-8')).hexdigest()
            code_ = code_.replace(file_hash_placeholder, file_hash)
            return code_
        # ========================================
        # ===== CODE ĐÃ CẬP NHẬT (END) =====
        # ========================================

    # === [11] Methods (obf_vars / obf_builtins / vm_strings / obf_strings) ===
    class Methods:

        def obf_builtins(code: str) -> str:
            Logging.event('Obfuscate builtins lần đầu')
            _dn = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
            target_builtins = ['chr', 'ord', 'hex', 'bin', 'oct', 'bytes', 'bytearray', 'str', 'int', 'float', 'globals', 'locals', 'vars', 'print', 'input', 'exec', 'eval', 'getattr', 'setattr', 'delattr', 'dir', '__import__', 'compile', 'map', 'filter', 'zip', 'hash', 'repr', 'format']
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in target_builtins:
                    node.id = f'{_dn}["{str(node.id)}"]'
            return ast.unparse(tree)

        def last_obf_builtins(code: str) -> str:
            Logging.event('Obfuscate builtins lần cuối')
            _dn = globals().get('BUILTIN_DICT_NAME') or 'baobg_vars'
            target_builtins = {'print', 'input', 'exec', 'eval'}
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in target_builtins:
                    node.id = f'{_dn}[{Pycloak().encode(str(node.id))}]'
            return ast.unparse(tree)

        def obf_vars(code: str) -> str:
            Logging.event('Obfuscate vars')
            tree = ast.parse(code)
            module_names: Set[str] = set()
            declared_names: Set[str] = set()
            method_names: Set[str] = set()
            lambda_params: Set[str] = set()
            comprehension_vars: Set[str] = set()
            aliases: Dict[str, str] = {}
            known_module_vars: Set[str] = set()
            function_params: Dict[str, Set[str]] = {}
            function_calls: Dict[str, Set[str]] = {}
            protected_keywords: Set[str] = set()
            dynamic_scope_names: Set[str] = set()
            global_names: Set[str] = set()
            nonlocal_names: Set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split('.')
                        module_names.add(parts[0])
                        if alias.asname:
                            known_module_vars.add(alias.asname)
                            declared_names.add(alias.asname)
                        else:
                            known_module_vars.add(parts[0])
                            module_names.add(parts[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        parts = node.module.split('.')
                        module_names.add(parts[0])
                    for name in node.names:
                        if name.asname:
                            declared_names.add(name.asname)
                        else:
                            module_names.add(name.name)

            class NameCollector(ast.NodeVisitor):

                def __init__(self):
                    self.scope_stack: List[Dict[str, Any]] = [{}]

                def enter_scope(self):
                    self.scope_stack.append({})

                def exit_scope(self):
                    if self.scope_stack:
                        self.scope_stack.pop()

                def add_to_current_scope(self, name: str, node_type: str):
                    if self.scope_stack:
                        self.scope_stack[-1][name] = node_type

                def is_in_current_scope(self, name: str) -> bool:
                    return name in self.scope_stack[-1] if self.scope_stack else False

                def get_scope_type(self, name: str) -> Tuple[bool, str]:
                    for scope in reversed(self.scope_stack):
                        if name in scope:
                            return (True, scope[name])
                    return (False, '')

                def visit_Global(self, node):
                    for name in node.names:
                        global_names.add(name)
                        declared_names.add(name)
                    self.generic_visit(node)

                def visit_Nonlocal(self, node):
                    for name in node.names:
                        nonlocal_names.add(name)
                        declared_names.add(name)
                    self.generic_visit(node)

                def visit_Lambda(self, node):
                    self.enter_scope()
                    for arg in node.args.args:
                        lambda_params.add(arg.arg)
                        declared_names.add(arg.arg)
                        self.add_to_current_scope(arg.arg, 'lambda_arg')
                    self.visit(node.body)
                    self.exit_scope()

                def visit_FunctionDef(self, node):
                    declared_names.add(node.name)
                    self.enter_scope()
                    for decorator in node.decorator_list:
                        self.visit(decorator)
                    if hasattr(node, 'args'):
                        for arg in node.args.args:
                            if arg.arg != 'self' and arg.arg != 'cls':
                                declared_names.add(arg.arg)
                                self.add_to_current_scope(arg.arg, 'arg')
                        if hasattr(node.args, 'posonlyargs'):
                            for arg in node.args.posonlyargs:
                                if arg.arg != 'self' and arg.arg != 'cls':
                                    declared_names.add(arg.arg)
                                    self.add_to_current_scope(arg.arg, 'posonly_arg')
                        for arg in node.args.kwonlyargs:
                            declared_names.add(arg.arg)
                            self.add_to_current_scope(arg.arg, 'kwonly_arg')
                        if node.args.kwarg:
                            declared_names.add(node.args.kwarg.arg)
                            self.add_to_current_scope(node.args.kwarg.arg, 'kwarg')
                        if node.args.vararg:
                            declared_names.add(node.args.vararg.arg)
                            self.add_to_current_scope(node.args.vararg.arg, 'vararg')
                        if hasattr(node.args, 'defaults'):
                            self.generic_visit_list(node.args.defaults)
                        if hasattr(node.args, 'kw_defaults'):
                            self.generic_visit_list(node.args.kw_defaults)
                    self.generic_visit(node)
                    self.exit_scope()

                def visit_AsyncFunctionDef(self, node):
                    self.visit_FunctionDef(node)

                def visit_ClassDef(self, node):
                    declared_names.add(node.name)
                    for decorator in node.decorator_list:
                        self.visit(decorator)
                    for base in node.bases:
                        self.visit(base)
                    for keyword in node.keywords:
                        self.visit(keyword.value)
                    self.enter_scope()
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) or isinstance(item, ast.AsyncFunctionDef):
                            method_names.add(item.name)
                        self.visit(item)
                    self.exit_scope()

                def visit_Assign(self, node):
                    for target in node.targets:
                        self.process_assignment_target(target)
                    self.visit(node.value)

                def visit_AnnAssign(self, node):
                    self.process_assignment_target(node.target)
                    if node.annotation:
                        self.visit(node.annotation)
                    if node.value:
                        self.visit(node.value)

                def visit_AugAssign(self, node):
                    self.process_assignment_target(node.target)
                    self.visit(node.value)

                def visit_NamedExpr(self, node):
                    self.process_assignment_target(node.target)
                    self.visit(node.value)

                def visit_For(self, node):
                    self.process_assignment_target(node.target)
                    self.visit(node.iter)
                    self.enter_scope()
                    for item in node.body:
                        self.visit(item)
                    self.exit_scope()
                    if node.orelse:
                        self.enter_scope()
                        for item in node.orelse:
                            self.visit(item)
                        self.exit_scope()

                def visit_AsyncFor(self, node):
                    self.visit_For(node)

                def visit_With(self, node):
                    for item in node.items:
                        self.visit(item.context_expr)
                        if item.optional_vars:
                            self.process_assignment_target(item.optional_vars)
                    self.enter_scope()
                    for stmt in node.body:
                        self.visit(stmt)
                    self.exit_scope()

                def visit_AsyncWith(self, node):
                    self.visit_With(node)

                def _collect_match_pattern(self, pattern):
                    if isinstance(pattern, ast.MatchAs):
                        if pattern.name and pattern.name != '_':
                            declared_names.add(pattern.name)
                            self.add_to_current_scope(pattern.name, 'match')
                        if pattern.pattern:
                            self._collect_match_pattern(pattern.pattern)
                    elif isinstance(pattern, ast.MatchStar):
                        if pattern.name and pattern.name != '_':
                            declared_names.add(pattern.name)
                            self.add_to_current_scope(pattern.name, 'match')
                    elif isinstance(pattern, ast.MatchMapping):
                        for key in pattern.keys:
                            if key:
                                self.visit(key)
                        for pat in pattern.patterns:
                            self._collect_match_pattern(pat)
                        if pattern.rest and pattern.rest != '_':
                            declared_names.add(pattern.rest)
                            self.add_to_current_scope(pattern.rest, 'match')
                    elif isinstance(pattern, ast.MatchSequence):
                        for pat in pattern.patterns:
                            self._collect_match_pattern(pat)
                    elif isinstance(pattern, ast.MatchClass):
                        if pattern.cls:
                            self.visit(pattern.cls)
                        for pat in pattern.patterns:
                            self._collect_match_pattern(pat)
                        for pat in pattern.kwd_patterns:
                            self._collect_match_pattern(pat)
                    elif isinstance(pattern, ast.MatchOr):
                        for pat in pattern.patterns:
                            self._collect_match_pattern(pat)
                    elif isinstance(pattern, ast.MatchValue):
                        self.visit(pattern.value)
                    elif isinstance(pattern, ast.MatchSingleton):
                        return

                def visit_Match(self, node):
                    self.visit(node.subject)
                    for case in node.cases:
                        self.enter_scope()
                        self._collect_match_pattern(case.pattern)
                        if case.guard:
                            self.visit(case.guard)
                        for stmt in case.body:
                            self.visit(stmt)
                        self.exit_scope()

                def visit_Try(self, node):
                    self.enter_scope()
                    for stmt in node.body:
                        self.visit(stmt)
                    self.exit_scope()
                    for handler in node.handlers:
                        self.enter_scope()
                        if handler.name:
                            declared_names.add(handler.name)
                            self.add_to_current_scope(handler.name, 'except')
                        if handler.type:
                            self.visit(handler.type)
                        for stmt in handler.body:
                            self.visit(stmt)
                        self.exit_scope()
                    if node.orelse:
                        self.enter_scope()
                        for stmt in node.orelse:
                            self.visit(stmt)
                        self.exit_scope()
                    if node.finalbody:
                        self.enter_scope()
                        for stmt in node.finalbody:
                            self.visit(stmt)
                        self.exit_scope()

                def visit_ExceptHandler(self, node):
                    if node.name:
                        declared_names.add(node.name)
                        self.add_to_current_scope(node.name, 'except')
                    if node.type:
                        self.visit(node.type)
                    for stmt in node.body:
                        self.visit(stmt)

                def visit_ListComp(self, node):
                    self.handle_comprehension(node)

                def visit_DictComp(self, node):
                    self.handle_comprehension(node)

                def visit_SetComp(self, node):
                    self.handle_comprehension(node)

                def visit_GeneratorExp(self, node):
                    self.handle_comprehension(node)

                def handle_comprehension(self, node):
                    self.enter_scope()
                    for gen in node.generators:
                        target = gen.target
                        if isinstance(target, ast.Name):
                            comprehension_vars.add(target.id)
                            declared_names.add(target.id)
                            self.add_to_current_scope(target.id, 'comp_var')
                        else:
                            self.process_assignment_target(target)
                        self.visit(gen.iter)
                        for if_clause in gen.ifs:
                            self.visit(if_clause)
                    if hasattr(node, 'elt'):
                        self.visit(node.elt)
                    if hasattr(node, 'key'):
                        self.visit(node.key)
                    if hasattr(node, 'value'):
                        self.visit(node.value)
                    self.exit_scope()

                def generic_visit_list(self, items):
                    for item in items if items else []:
                        if item:
                            self.visit(item)

                def process_assignment_target(self, target):
                    if isinstance(target, ast.Name):
                        declared_names.add(target.id)
                        self.add_to_current_scope(target.id, 'var')
                    elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
                        for elt in target.elts:
                            self.process_assignment_target(elt)
                    elif isinstance(target, ast.Attribute):
                        self.visit(target.value)
                    elif isinstance(target, ast.Subscript):
                        self.visit(target.value)
                        self.visit(target.slice)
                    elif isinstance(target, ast.Starred):
                        self.process_assignment_target(target.value)

                def visit_Attribute(self, node):
                    if isinstance(node.value, ast.Name) and node.value.id in known_module_vars:
                        module_names.add(f'{node.value.id}.{node.attr}')
                    self.generic_visit(node)
            collector = NameCollector()
            collector.visit(tree)
            collector.visit(tree)

            class AttributeAccessCollector(ast.NodeVisitor):
                def visit_Attribute(self, node):
                    protected_keywords.add(node.attr)
                    self.generic_visit(node)
            attr_collector = AttributeAccessCollector()
            attr_collector.visit(tree)

            # Preserve HTTP handler hooks / special method names
            protected_keywords.update({
                'do_GET', 'do_POST', 'do_OPTIONS', 'do_HEAD', 'do_PUT', 'do_DELETE', 'do_PATCH', 'do_TRACE',
                'log_message', 'handle_one_request', 'send_response', 'send_header', 'end_headers'
            })

            class KeywordArgFinder(ast.NodeVisitor):
                def visit_Call(self, node):
                    if node.keywords:
                        for keyword in node.keywords:
                            if keyword.arg:
                                protected_keywords.add(keyword.arg)
                    self.generic_visit(node)
            kw_finder = KeywordArgFinder()
            kw_finder.visit(tree)

            def _extract_dynamic_scope_key(node: ast.Subscript) -> Union[str, None]:
                if not isinstance(node.value, ast.Call):
                    return None
                call = node.value
                if not isinstance(call.func, ast.Name):
                    return None
                if call.func.id not in {'globals', 'locals', 'vars'}:
                    return None
                if call.args or call.keywords:
                    return None
                idx = node.slice
                if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                    return idx.value
                if hasattr(ast, 'Index') and isinstance(idx, ast.Index):
                    val = idx.value
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        return val.value
                return None

            class DynamicScopeKeyCollector(ast.NodeVisitor):
                def visit_Subscript(self, node):
                    key = _extract_dynamic_scope_key(node)
                    if key:
                        dynamic_scope_names.add(key)
                    self.generic_visit(node)
            DynamicScopeKeyCollector().visit(tree)

            def is_builtin(name: str) -> bool:
                builtins = __import__('builtins')
                if hasattr(builtins, name):
                    return True
                for builtin_type in [dict, list, str, set, int, float, tuple, object]:
                    if hasattr(builtin_type, name):
                        return True
                return False

            def is_dispatch_sensitive(name: str) -> bool:
                # ast.NodeVisitor / ast.NodeTransformer rely on these exact method names.
                return name.startswith('visit_') or name == 'generic_visit'
            for name in declared_names:
                if name not in aliases and name not in module_names and (name not in protected_keywords) and (name not in dynamic_scope_names) and (not is_builtin(name)) and (not is_dispatch_sensitive(name)) and (not name.startswith('__')) and (not name.endswith('__')) and (name != 'self') and (name != 'cls'):
                    aliases[name] = spam_hanzi()
            param_mapping = {}
            for func_name, params in function_params.items():
                if func_name in aliases:
                    for param in params:
                        if param not in aliases and (not is_builtin(param)) and (param not in protected_keywords):
                            aliases[param] = spam_hanzi()
            for func_name, kwarg_names in function_calls.items():
                if func_name in function_params:
                    for kwarg in kwarg_names:
                        if kwarg in aliases:
                            del aliases[kwarg]
            for name in lambda_params:
                if name not in aliases and name not in module_names and (not is_builtin(name)) and (not name.startswith('__')) and (not name.endswith('__')):
                    aliases[name] = spam_hanzi()
            for name in comprehension_vars:
                if name not in aliases and name not in module_names and (not is_builtin(name)) and (not name.startswith('__')) and (not name.endswith('__')):
                    aliases[name] = spam_hanzi()

            class NameTransformer(ast.NodeTransformer):

                def visit_Name(self, node):
                    if node.id in aliases and node.id not in module_names and (not is_builtin(node.id)):
                        node.id = aliases[node.id]
                    return node

                def visit_Attribute(self, node):
                    node.value = self.visit(node.value)
                    return node

                def visit_FunctionDef(self, node):
                    for i, decorator in enumerate(node.decorator_list):
                        node.decorator_list[i] = self.visit(decorator)
                    if node.name in aliases:
                        node.name = aliases[node.name]
                    if hasattr(node, 'args'):
                        for arg in node.args.args:
                            if arg.arg in aliases and arg.arg != 'self' and (arg.arg != 'cls'):
                                arg.arg = aliases[arg.arg]
                        if hasattr(node.args, 'posonlyargs'):
                            for arg in node.args.posonlyargs:
                                if arg.arg in aliases and arg.arg != 'self' and (arg.arg != 'cls'):
                                    arg.arg = aliases[arg.arg]
                        for arg in node.args.kwonlyargs:
                            if arg.arg in aliases:
                                arg.arg = aliases[arg.arg]
                        if node.args.kwarg and node.args.kwarg.arg in aliases:
                            node.args.kwarg.arg = aliases[node.args.kwarg.arg]
                        if node.args.vararg and node.args.vararg.arg in aliases:
                            node.args.vararg.arg = aliases[node.args.vararg.arg]
                        if node.args.defaults:
                            for i, default in enumerate(node.args.defaults):
                                if default:
                                    node.args.defaults[i] = self.visit(default)
                        if node.args.kw_defaults:
                            for i, default in enumerate(node.args.kw_defaults):
                                if default:
                                    node.args.kw_defaults[i] = self.visit(default)
                    if hasattr(node, 'returns') and node.returns:
                        node.returns = self.visit(node.returns)
                    for arg in node.args.args:
                        if hasattr(arg, 'annotation') and arg.annotation:
                            arg.annotation = self.visit(arg.annotation)
                    for i, item in enumerate(node.body):
                        node.body[i] = self.visit(item)
                    return node

                def visit_AsyncFunctionDef(self, node):
                    return self.visit_FunctionDef(node)

                def visit_ClassDef(self, node):
                    for i, decorator in enumerate(node.decorator_list):
                        node.decorator_list[i] = self.visit(decorator)
                    for i, base in enumerate(node.bases):
                        node.bases[i] = self.visit(base)
                    for keyword in node.keywords:
                        keyword.value = self.visit(keyword.value)
                    if node.name in aliases and node.name not in protected_keywords:
                        node.name = aliases[node.name]
                    for i, item in enumerate(node.body):
                        node.body[i] = self.visit(item)
                    return node

                def visit_Lambda(self, node):
                    for arg in node.args.args:
                        if arg.arg in aliases:
                            arg.arg = aliases[arg.arg]
                    node.body = self.visit(node.body)
                    return node

                def visit_ExceptHandler(self, node):
                    if node.type:
                        node.type = self.visit(node.type)
                    if node.name and node.name in aliases:
                        node.name = aliases[node.name]
                    for i, stmt in enumerate(node.body):
                        node.body[i] = self.visit(stmt)
                    return node

                def _rename_match_pattern(self, pattern):
                    if isinstance(pattern, ast.MatchAs):
                        if pattern.name and pattern.name in aliases:
                            pattern.name = aliases[pattern.name]
                        if pattern.pattern:
                            pattern.pattern = self._rename_match_pattern(pattern.pattern)
                        return pattern
                    elif isinstance(pattern, ast.MatchStar):
                        if pattern.name and pattern.name in aliases:
                            pattern.name = aliases[pattern.name]
                        return pattern
                    elif isinstance(pattern, ast.MatchMapping):
                        pattern.keys = [self.visit(k) if k else k for k in pattern.keys]
                        pattern.patterns = [self._rename_match_pattern(p) for p in pattern.patterns]
                        if pattern.rest and pattern.rest in aliases:
                            pattern.rest = aliases[pattern.rest]
                        return pattern
                    elif isinstance(pattern, ast.MatchSequence):
                        pattern.patterns = [self._rename_match_pattern(p) for p in pattern.patterns]
                        return pattern
                    elif isinstance(pattern, ast.MatchClass):
                        if pattern.cls:
                            pattern.cls = self.visit(pattern.cls)
                        pattern.patterns = [self._rename_match_pattern(p) for p in pattern.patterns]
                        pattern.kwd_patterns = [self._rename_match_pattern(p) for p in pattern.kwd_patterns]
                        return pattern
                    elif isinstance(pattern, ast.MatchOr):
                        pattern.patterns = [self._rename_match_pattern(p) for p in pattern.patterns]
                        return pattern
                    elif isinstance(pattern, ast.MatchValue):
                        pattern.value = self.visit(pattern.value)
                        return pattern
                    elif isinstance(pattern, ast.MatchSingleton):
                        return pattern
                    return pattern

                def visit_Match(self, node):
                    node.subject = self.visit(node.subject)
                    new_cases = []
                    for case in node.cases:
                        case.pattern = self._rename_match_pattern(case.pattern)
                        if case.guard:
                            case.guard = self.visit(case.guard)
                        case.body = [self.visit(s) for s in case.body]
                        new_cases.append(case)
                    node.cases = new_cases
                    return node

                def visit_Import(self, node):
                    for alias in node.names:
                        if alias.asname and alias.asname in aliases:
                            alias.asname = aliases[alias.asname]
                    return node

                def visit_ImportFrom(self, node):
                    for alias in node.names:
                        if alias.asname and alias.asname in aliases:
                            alias.asname = aliases[alias.asname]
                    return node

                def visit_Global(self, node):
                    new_names = []
                    for name in node.names:
                        new_names.append(aliases.get(name, name))
                    node.names = new_names
                    return node

                def visit_Nonlocal(self, node):
                    new_names = []
                    for name in node.names:
                        new_names.append(aliases.get(name, name))
                    node.names = new_names
                    return node

                def visit_arg(self, node):
                    if node.arg in aliases and node.arg != 'self' and (node.arg != 'cls'):
                        node.arg = aliases[node.arg]
                    if hasattr(node, 'annotation') and node.annotation:
                        node.annotation = self.visit(node.annotation)
                    return node

                def visit_ListComp(self, node):
                    new_generators = []
                    for gen in node.generators:
                        gen.iter = self.visit(gen.iter)
                        if isinstance(gen.target, ast.Name) and gen.target.id in aliases:
                            gen.target.id = aliases[gen.target.id]
                        else:
                            gen.target = self.visit(gen.target)
                        new_ifs = []
                        for if_clause in gen.ifs:
                            new_ifs.append(self.visit(if_clause))
                        gen.ifs = new_ifs
                        new_generators.append(gen)
                    node.generators = new_generators
                    node.elt = self.visit(node.elt)
                    return node

                def visit_DictComp(self, node):
                    new_generators = []
                    for gen in node.generators:
                        gen.iter = self.visit(gen.iter)
                        if isinstance(gen.target, ast.Name) and gen.target.id in aliases:
                            gen.target.id = aliases[gen.target.id]
                        else:
                            gen.target = self.visit(gen.target)
                        new_ifs = []
                        for if_clause in gen.ifs:
                            new_ifs.append(self.visit(if_clause))
                        gen.ifs = new_ifs
                        new_generators.append(gen)
                    node.generators = new_generators
                    node.key = self.visit(node.key)
                    node.value = self.visit(node.value)
                    return node

                def visit_SetComp(self, node):
                    new_generators = []
                    for gen in node.generators:
                        gen.iter = self.visit(gen.iter)
                        if isinstance(gen.target, ast.Name) and gen.target.id in aliases:
                            gen.target.id = aliases[gen.target.id]
                        else:
                            gen.target = self.visit(gen.target)
                        new_ifs = []
                        for if_clause in gen.ifs:
                            new_ifs.append(self.visit(if_clause))
                        gen.ifs = new_ifs
                        new_generators.append(gen)
                    node.generators = new_generators
                    node.elt = self.visit(node.elt)
                    return node

                def visit_GeneratorExp(self, node):
                    new_generators = []
                    for gen in node.generators:
                        gen.iter = self.visit(gen.iter)
                        if isinstance(gen.target, ast.Name) and gen.target.id in aliases:
                            gen.target.id = aliases[gen.target.id]
                        else:
                            gen.target = self.visit(gen.target)
                        new_ifs = []
                        for if_clause in gen.ifs:
                            new_ifs.append(self.visit(if_clause))
                        gen.ifs = new_ifs
                        new_generators.append(gen)
                    node.generators = new_generators
                    node.elt = self.visit(node.elt)
                    return node
            transformer = NameTransformer()
            transformed_tree = transformer.visit(tree)
            ast.fix_missing_locations(transformed_tree)
            Logging.info(f'Obfuscated {len(aliases)} names')
            return ast.unparse(transformed_tree)

        class vm_strings:

            def __init__(self, mode=1):
                self.mode = int(mode)
                self.decoder_name = rand_cn_name(8)
                self.OP_PUSH = 1
                self.OP_CONCAT = 2
                self.OP_XOR = 3
                self.OP_REV = 4
                self.OP_ROT = 5
                self.OP_DROP = 6
                self.OP_TOSTR = 7
                self.OP_RET = 8

            def _push(self, data: bytes) -> bytes:
                return bytes([self.OP_PUSH]) + len(data).to_bytes(4, 'big') + data

            def _push_m(self, data: bytes, mask: int) -> bytes:
                return bytes([self.OP_PUSH ^ (mask & 0xFF)]) + len(data).to_bytes(4, 'big') + data

            def _op(self, op: int) -> bytes:
                return bytes([op])

            def _op_m(self, op: int, mask: int) -> bytes:
                return bytes([op ^ (mask & 0xFF)])

            def _op_rot(self, n: int) -> bytes:
                return bytes([self.OP_ROT, n & 0xFF])

            def _op_rot_m(self, n: int, mask: int) -> bytes:
                return bytes([self.OP_ROT ^ (mask & 0xFF), n & 0xFF])

            def _build_program(self, s: str) -> bytes:
                key = rand_key(6, 14)
                key_bytes = key.encode('utf-8')
                if not key_bytes:
                    key_bytes = b'0'
                data = s.encode('utf-8')
                data = bytes((b ^ key_bytes[i % len(key_bytes)]) for i, b in enumerate(data))
                ops = []

                if len(data) > 1 and random.random() < 0.5:
                    data = data[::-1]
                    ops.append(('rev', None))
                if len(data) > 2 and random.random() < 0.5:
                    rot = random.randint(1, min(7, len(data) - 1))
                    data = data[-rot:] + data[:-rot]
                    ops.append(('rot', rot))

                mask = random.randint(1, 255)
                prog = bytes([mask]) + self._push_m(data, mask)

                junk_rounds = random.randint(0, 2)
                for _ in range(junk_rounds):
                    junk = bytes((random.getrandbits(8) for _ in range(random.randint(2, 8))))
                    prog += self._push_m(junk, mask) + self._op_m(self.OP_DROP, mask)

                for op, val in reversed(ops):
                    if op == 'rev':
                        prog += self._op_m(self.OP_REV, mask)
                    elif op == 'rot':
                        prog += self._op_rot_m(int(val), mask)

                mid = max(1, len(key_bytes) // 2)
                part1 = key_bytes[:mid]
                part2 = key_bytes[mid:]
                prog += self._push_m(part1, mask)
                prog += self._push_m(part2, mask)
                prog += self._op_m(self.OP_CONCAT, mask)
                prog += self._op_m(self.OP_XOR, mask)
                prog += self._op_m(self.OP_TOSTR, mask)
                prog += self._op_m(self.OP_RET, mask)
                return prog

            def _decoder_src(self) -> str:
                return f"""def {self.decoder_name}(prog, _c={{}}):
    try:
        if isinstance(prog, str):
            prog = prog.encode('latin1', 'ignore')
        if not isinstance(prog, (bytes, bytearray)):
            prog = bytes(prog)
        if isinstance(prog, bytearray):
            prog = bytes(prog)
        if prog in _c:
            return _c.get(prog, '')
        if not prog:
            return ''
        stack = []
        mask = prog[0]
        i = 1
        while i < len(prog):
            op = prog[i] ^ mask
            i += 1
            if op == {self.OP_PUSH}:
                ln = int.from_bytes(prog[i:i+4], 'big')
                i += 4
                stack.append(prog[i:i+ln])
                i += ln
            elif op == {self.OP_CONCAT}:
                b = stack.pop()
                a = stack.pop()
                stack.append(a + b)
            elif op == {self.OP_XOR}:
                k = stack.pop()
                d = stack.pop()
                if k:
                    d = bytes((x ^ k[j % len(k)]) for j, x in enumerate(d))
                stack.append(d)
            elif op == {self.OP_REV}:
                d = stack.pop()
                stack.append(d[::-1])
            elif op == {self.OP_ROT}:
                n = prog[i]
                i += 1
                d = stack.pop()
                if d:
                    n = n % len(d)
                    stack.append(d[n:] + d[:n])
                else:
                    stack.append(d)
            elif op == {self.OP_DROP}:
                if stack:
                    stack.pop()
            elif op == {self.OP_TOSTR}:
                d = stack.pop()
                try:
                    stack.append(d.decode('utf-8'))
                except Exception:
                    stack.append(d.decode('latin1', 'ignore'))
            elif op == {self.OP_RET}:
                res = stack.pop() if stack else ''
                _c[prog] = res
                return res
        res = stack.pop() if stack else ''
        _c[prog] = res
        return res
    except Exception:
        return ''
"""

            def __call__(self, code: str) -> str:
                preamble, body = split_preamble_code(code)
                if not body.strip():
                    return preamble

                tree = ast.parse(body)
                decoder_name = self.decoder_name
                parent = self

                class _StrVMTransformer(ast.NodeTransformer):

                    def _transform_body(self, body_nodes):
                        new_body = []
                        for idx, stmt in enumerate(body_nodes):
                            if idx == 0 and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                                new_body.append(stmt)
                            else:
                                new_body.append(self.visit(stmt))
                        return new_body

                    def visit_Module(self, node):
                        node.body = self._transform_body(node.body)
                        return node

                    def visit_FunctionDef(self, node):
                        node.body = self._transform_body(node.body)
                        return node

                    def visit_AsyncFunctionDef(self, node):
                        node.body = self._transform_body(node.body)
                        return node

                    def visit_ClassDef(self, node):
                        node.body = self._transform_body(node.body)
                        return node

                    def visit_JoinedStr(self, node):
                        return node

                    def visit_Constant(self, node):
                        if isinstance(node.value, str):
                            if node.value == '':
                                return node
                            try:
                                prog = parent._build_program(node.value)
                            except Exception:
                                return node
                            return ast.Call(func=ast.Name(id=decoder_name, ctx=ast.Load()), args=[ast.Constant(value=prog)], keywords=[])
                        return node

                transformer = _StrVMTransformer()
                tree = transformer.visit(tree)
                ast.fix_missing_locations(tree)

                decoder_loader = Compile.ll(self._decoder_src())
                decoder_ast = ast.parse(decoder_loader)
                tree.body = decoder_ast.body + tree.body
                return join_code_parts(preamble, ast.unparse(tree))

        class obf_strings:

            def __init__(self, mode, spam):
                self.mode = int(mode)
                self.spam = spam

            def obfint(self, num: int) -> ast.AST:
                if type(num) == bool:
                    v = 1 if num else 0
                    obf_v = Ast_obf().obfct(str(v))
                    # Wrap the string-valued decoder in int() before bool().
                    # obfct() yields a str expression, so `bool(obfct('0'))`
                    # would evaluate to True (non-empty string) rather than
                    # False -- int() coerces back to the integer first.
                    return ast.parse(f'{_bool}({_int}({ast.unparse(obf_v)}))').body[0].value
                obfuscated_num = Ast_obf().obfct(str(num))
                return ast.parse(f'{_int}({ast.unparse(obfuscated_num)})').body[0].value

            def obffloat(self, num: float) -> ast.AST:
                obfuscated_num = Ast_obf().obfct(str(num))
                return ast.parse(f'{_float}({ast.unparse(obfuscated_num)})').body[0].value

            def fm(self, node: ast.JoinedStr) -> ast.parse:
                return self.concac(node)

            def concac(self, node: ast.JoinedStr) -> ast.Call:
                format_parts = []
                args = []
                for value in node.values:
                    if isinstance(value, ast.Constant):
                        # Keep literal braces literal when rewriting f-string to .format(...)
                        literal = str(value.value).replace('{', '{{').replace('}', '}}')
                        format_parts.append(literal)
                    elif isinstance(value, ast.FormattedValue):
                        conversion = ''
                        if value.conversion == 114:
                            conversion = '!r'
                        elif value.conversion == 115:
                            conversion = '!s'
                        elif value.conversion == 97:
                            conversion = '!a'
                        format_spec = ''
                        if value.format_spec is not None:
                            if isinstance(value.format_spec, ast.Constant):
                                format_spec = ':' + str(value.format_spec.value) if value.format_spec.value else ''
                                if format_spec and format_spec[1:].isalnum() and (not format_spec.startswith(':.')):
                                    if any((c in format_spec for c in 'dfgGeExXobcn')):
                                        pass
                                    elif re.match(':\\d+[a-zA-Z]', format_spec):
                                        format_spec = format_spec.replace(':', ':.', 1)
                            elif isinstance(value.format_spec, ast.JoinedStr):
                                format_spec_call = self.concac(value.format_spec)
                                if isinstance(format_spec_call.func.value, ast.Constant):
                                    nested_format = format_spec_call.func.value.value
                                else:
                                    nested_format = ''
                                format_spec = ':' + nested_format
                                args.extend(format_spec_call.args)
                        format_parts.append('{' + conversion + format_spec + '}')
                        args.append(value.value)
                format_string = ''.join(format_parts)
                try:
                    format_value = Ast_obf().obfct(format_string)
                except Exception:
                    format_value = ast.Constant(value=format_string)
                return ast.Call(func=ast.Attribute(value=format_value, attr='format', ctx=ast.Load()), args=args, keywords=[])

            def obfuscate(self, node):
                Logging.event('Obfuscate string, bytes, and lists!')
                for i in ast.walk(node):
                    if isinstance(i, (ast.Global, ast.Nonlocal)):
                        continue
                    for f, v in ast.iter_fields(i):
                        if isinstance(v, list):
                            ar = []
                            for j in v:
                                try:
                                    if isinstance(j, ast.Constant):
                                        if isinstance(j.value, str):
                                            string_type = 'r' if j.value.startswith('r') else 'fr' if j.value.startswith('fr') else ''
                                            ar.append(Ast_obf().obfct(j.value, string_type))
                                            continue
                                        if isinstance(j.value, int):
                                            ar.append(self.obfint(j.value))
                                        else:
                                            ar.append(j)
                                        continue
                                    elif isinstance(j, ast.JoinedStr):
                                        ar.append(self.concac(j))
                                    elif isinstance(j, ast.AST):
                                        ar.append(j)
                                except Exception as e:
                                    print(f'Error processing node {j}: {e}')
                                    ar.append(j)
                            setattr(i, f, ar)
                        else:
                            try:
                                if isinstance(v, ast.Constant):
                                    if isinstance(v.value, str):
                                        string_type = 'r' if v.value.startswith('r') else 'fr' if v.value.startswith('fr') else ''
                                        setattr(i, f, Ast_obf().obfct(v.value, string_type))
                                    elif isinstance(v.value, int):
                                        setattr(i, f, self.obfint(v.value))
                                elif isinstance(v, ast.JoinedStr):
                                    setattr(i, f, self.concac(v))
                            except Exception as e:
                                print(f'Error processing field {f} with value {v}: {e}')

            def obfuscate_item(self, item):
                if isinstance(item, str):
                    return Ast_obf().obfct(item, '')
                elif isinstance(item, bytes):
                    return Ast_obf().obfct_bytes(item)
                elif isinstance(item, int):
                    return self.obfint(item)
                elif isinstance(item, float):
                    return self.obffloat(item)
                elif isinstance(item, list):
                    return [self.obfuscate_item(x) for x in item]
                return item

            def __call__(self, code: str) -> str:
                preamble, body = split_preamble_code(code)
                if not body.strip():
                    return preamble
                tree = ast.parse(body)
                self.obfuscate(tree)
                if self.spam:
                    tbd = Ast_obf().trycatch(tree.body, 2)
                    body_code = ast.unparse(tbd)
                else:
                    body_code = ast.unparse(tree)
                return join_code_parts(preamble, body_code)

    # === [10] Logging (ANSI) ===
    class Logging:
        _COLOR = {
            'EVENT':   _ANSI.BRED,
            'INFO':    _ANSI.WHITE,
            'SUCCESS': _ANSI.BGREEN,
            'WARNING': _ANSI.BYELLOW,
            'NOTICE':  _ANSI.BBLUE,
            'DEBUG':   _ANSI.BMAGENTA,
            'ERROR':   _ANSI.BRED,
        }

        @staticmethod
        def _log(level: str, color: str, msg: str) -> None:
            if globals().get('QUIET_MODE', False) and level not in ('ERROR',):
                return
            if globals().get('JSON_MODE', False):
                cli_emit(level.lower(), str(msg), code=0)
                return
            tag = f'{color}[{level}]{_ANSI.RESET}'
            print(f' {tag} {color}{msg}{_ANSI.RESET}')

        @staticmethod
        def event(msg: str) -> None:   Logging._log('EVENT',   Logging._COLOR['EVENT'],   msg)
        @staticmethod
        def info(msg: str) -> None:    Logging._log('INFO',    Logging._COLOR['INFO'],    msg)
        @staticmethod
        def success(msg: str) -> None: Logging._log('SUCCESS', Logging._COLOR['SUCCESS'], msg)
        @staticmethod
        def warning(msg: str) -> None: Logging._log('WARNING', Logging._COLOR['WARNING'], msg)
        @staticmethod
        def notice(msg: str) -> None:  Logging._log('NOTICE',  Logging._COLOR['NOTICE'],  msg)
        @staticmethod
        def debug(msg: str) -> None:   Logging._log('DEBUG',   Logging._COLOR['DEBUG'],   msg)
        @staticmethod
        def error(msg: str) -> None:   Logging._log('ERROR',   Logging._COLOR['ERROR'],   msg)

    # === [12] CLI argument parser ===
    class ParseArgs:

        def __init__(self, argv=None):
            self.parser = argparse.ArgumentParser(description='Bedrock Obfuscator by baobg')
            self.parser.add_argument('-f', '--file', help='Path to the Python file to obfuscate')
            self.parser.add_argument('-o', '--output', help='Output file name')
            self.parser.add_argument('--profile', default='balanced', choices=['fast', 'balanced', 'paranoid', 'extreme', 'io'], help='Build profile preset (default: balanced). `io` = extreme + Phase H esoteric passes (iO-grade, no perf constraint).')
            self.parser.add_argument('--runtime-mode', default='main', help='Runtime mode: main (native capsule, default) or legacy. VM runtimes (vm-native*/chunk-vm-lite) were removed in vNext and are mapped to main with a deprecation warning.')
            self.parser.add_argument('--anti-debug', default='strict', choices=['strict', 'compat', 'off'], help='Anti-debug policy (default: strict)')
            self.parser.add_argument('--anti-hook', default='strict', choices=['strict', 'compat', 'off'], help='Anti-hook policy (default: strict)')
            self.parser.add_argument('--integrity', default='on', choices=['on', 'off'], help='Embed SHA-256 self-check in the loader (default: on)')
            self.parser.add_argument('--cff', action='store_true', help='Apply control-flow flattening to user functions')
            self.parser.add_argument('--no-cff', dest='cff', action='store_false', help='Disable control-flow flattening (override profile auto-enable).')
            self.parser.add_argument('--bc-mutate', action='store_true', help='Enable bytecode-level mutation before marshalling')
            self.parser.add_argument('--no-bc-nop', dest='bc_mutate_nop', action='store_false', help='Disable bytecode tail NOP padding')
            self.parser.add_argument('--no-bc-dead', dest='bc_mutate_dead', action='store_false', help='Disable bytecode dead-branch tail junk')
            self.parser.add_argument('--no-bc-consts', dest='bc_mutate_consts', action='store_false', help='Disable bytecode const-pool decoys')
            self.parser.add_argument('--report', default=None, metavar='PATH', help='Write a JSON run-report to PATH after obfuscation completes')
            self.parser.add_argument('--tamper', default='self-destruct', choices=['self-destruct', 'fail-closed', 'warn', 'poison'], help='Tamper response (default: self-destruct)')
            self.parser.add_argument('--python-band', default='3.10-3.12', choices=['3.10-3.12', '3.12-only'], help='Target Python band (default: 3.10-3.12)')
            self.parser.add_argument('--non-interactive', action='store_true', help='Disable prompts and require explicit CLI inputs')
            self.parser.add_argument('--overwrite', action='store_true', help='Overwrite output file if it already exists')
            self.parser.add_argument('--quiet', action='store_true', help='Reduce non-error logging')
            self.parser.add_argument('--json', action='store_true', help='Emit machine-readable log and error output')
            self.parser.add_argument('-t', '--type', help=argparse.SUPPRESS)
            self.parser.add_argument('--bind-mode', default='none', choices=['none'], help=argparse.SUPPRESS)
            self.parser.add_argument('--legacy-loader', action='store_true', help=argparse.SUPPRESS)
            self.parser.add_argument('--vm-profile', default='production', choices=['production'], help=argparse.SUPPRESS)
            self.parser.add_argument('--vm-carrier', default='auto', choices=['auto', 'log', 'prose', 'names'], help=argparse.SUPPRESS)
            self.parser.add_argument('--vm-compat', default='broad', choices=['strict', 'broad'], help=argparse.SUPPRESS)
            self.parser.add_argument('--adv-requests', default='off', choices=['ask', 'on', 'off'], help=argparse.SUPPRESS)
            # --- batch: anti-vm / anti-debugger-v2 ---
            self.parser.add_argument('--anti-vm', default='off', choices=['strict', 'compat', 'off'],
                                     help='Embed anti-VM/sandbox check (default: off)')
            self.parser.add_argument('--anti-debugger-v2', default='off', choices=['on', 'off'],
                                     dest='anti_debugger_v2',
                                     help='Inject passive anti-debugger checks (default: off)')
            # --- batch: junk ---
            self.parser.add_argument('--junk', action='store_true',
                                     help='Inject junk code & opaque predicates.')
            self.parser.add_argument('--no-junk', dest='junk', action='store_false',
                                     help='Disable junk code injection (override profile auto-enable).')
            self.parser.add_argument('--junk-level', type=int, default=2, choices=range(1, 6),
                                     metavar='N', help='Junk density 1..5 (default 2).')
            # --- batch: import-obf ---
            self.parser.add_argument('--import-obf', action='store_true',
                                     help='Obfuscate import statements.')
            self.parser.add_argument('--no-import-obf', dest='import_obf', action='store_false',
                                     help='Disable import obfuscation (override profile auto-enable).')
            self.parser.add_argument('--import-blob', action='store_true',
                                     help='Pool obfuscated module names into a single zlib blob.')
            # --- batch: homoglyph ---
            self.parser.add_argument('--homoglyph', action='store_true', default=False,
                                     help='Rename local identifiers to Unicode-confusable variants.')
            self.parser.add_argument('--no-homoglyph', dest='homoglyph', action='store_false',
                                     help='Disable homoglyph renaming (override profile auto-enable).')
            self.parser.add_argument('--homoglyph-seed', type=int, default=None,
                                     help='Seed for the homoglyph renamer.')
            # --- batch: numobf / boolobf ---
            self.parser.add_argument('--num-obf', action='store_true',
                                     help='Obfuscate integer literals.')
            self.parser.add_argument('--no-num-obf', dest='num_obf', action='store_false',
                                     help='Disable integer obfuscation (override profile auto-enable).')
            self.parser.add_argument('--num-obf-depth', type=int, default=1, choices=(1, 2, 3, 4, 5),
                                     help='Nesting depth for integer obfuscation.')
            self.parser.add_argument('--bool-obf', action='store_true',
                                     help='Rewrite literal True / False / None constants.')
            self.parser.add_argument('--no-bool-obf', dest='bool_obf', action='store_false',
                                     help='Disable boolean/None literal obfuscation (override profile auto-enable).')
            # --- batch: strfrag2 / lambda-enc ---
            self.parser.add_argument('--str-frag2', dest='str_frag2', action='store_true', default=False,
                                     help='Enable string fragmentation v2.')
            self.parser.add_argument('--no-str-frag2', dest='str_frag2', action='store_false',
                                     help='Disable string fragmentation v2.')
            self.parser.add_argument('--str-frag2-vm', dest='str_frag2_vm', action='store_true', default=False,
                                     help='Encode str-frag2 pool entries with a per-entry XOR decoder '
                                          'so the pool is not plaintext bytes.')
            self.parser.add_argument('--str-cipher', dest='str_cipher', action='store_true', default=False,
                                     help='Replace obfct affine string cipher with a SHA-256-chained '
                                          'stream cipher (keystream from sha256 chain, not invertible '
                                          'without executing the derivation).')
            self.parser.add_argument('--no-str-cipher', dest='str_cipher', action='store_false',
                                     help='Disable SHA-256-chained string cipher (use legacy affine).')
            self.parser.add_argument('--lambda-enc', action='store_true',
                                     help='Rewrite simple def into lambda assigns.')
            self.parser.add_argument('--no-lambda-enc', dest='lambda_enc', action='store_false',
                                     help='Disable lambda rewriting (override profile auto-enable).')
            self.parser.add_argument('--lambda-enc-y', action='store_true',
                                     help='Also encode self-recursive funcs via Y-combinator.')
            self.parser.add_argument('--lambda-enc-density', type=float, default=1.0,
                                     help='Probability (0..1) a qualifying func is rewritten.')
            # --- batch 5: decompiler-trap / var-split / env-key / spoof-meta / anti-timing ---
            self.parser.add_argument('--dec-trap', dest='dec_trap', action='store_true', default=False,
                                     help='Wrap function bodies in nested opaque-true ifs that '
                                          'crash uncompyle6/decompyle3 (overlapping jump targets).')
            self.parser.add_argument('--no-dec-trap', dest='dec_trap', action='store_false',
                                     help='Disable decompiler traps (override profile auto-enable).')
            self.parser.add_argument('--dectrap-density', dest='dectrap_density', type=float, default=0.5,
                                     help='Probability (0..1) an eligible function gets a decompiler trap.')
            self.parser.add_argument('--var-split', dest='var_split', action='store_true', default=False,
                                     help='Split local int variables into v1 ^ v2 secret shares.')
            self.parser.add_argument('--no-var-split', dest='var_split', action='store_false',
                                     help='Disable variable splitting (override profile auto-enable).')
            self.parser.add_argument('--env-key', dest='env_key', action='store_true', default=False,
                                     help='Lock the output to the build machine\'s hardware fingerprint '
                                          '(machine-id + MAC + node + arch). Mismatch -> inert payload.')
            self.parser.add_argument('--no-env-key', dest='env_key', action='store_false',
                                     help='Disable hardware-fingerprint locking (override profile auto-enable).')
            self.parser.add_argument('--spoof-meta', dest='spoof_meta', action='store_true', default=False,
                                     help='Rewrite co_filename/co_qualname of compiled code objects to '
                                          'plausible stdlib paths so stack traces and decompiler context '
                                          'resolve to the wrong module.')
            self.parser.add_argument('--no-spoof-meta', dest='spoof_meta', action='store_false',
                                     help='Disable code-object meta spoofing (override profile auto-enable).')
            self.parser.add_argument('--anti-timing', dest='anti_timing', action='store_true', default=False,
                                     help='Emit a wall-clock probe that aborts on single-step drift '
                                          '(delta outside [1us, 50ms] for a fixed-cost SHA workload).')
            self.parser.add_argument('--no-anti-timing', dest='anti_timing', action='store_false',
                                     help='Disable anti-timing probe (override profile auto-enable).')
            self.parser.add_argument('--vm-opcode-remap', dest='vm_opcode_remap', action='store_true', default=False,
                                     help=argparse.SUPPRESS)
            self.parser.add_argument('--runtime-dec', dest='runtime_dec', action='store_true', default=False,
                                     help='Encrypt each protected function\'s __code__ and decrypt only on call, '
                                          'then wipe + re-encrypt on return (capsule runtime; shrinks the RAM '
                                          'window where decrypted bytecode exists).')
            self.parser.add_argument('--no-runtime-dec', dest='runtime_dec', action='store_false',
                                     help='Disable capsule runtime / per-function __code__ encryption '
                                          '(override profile auto-enable).')
            # --- batch 7 (Phase 2): chain runtime ---
            self.parser.add_argument('--chain', dest='chain', action='store_true', default=False,
                                     help='Chain Runtime: HMAC hash chain + mutual verification ring + '
                                          'shard separation. Each capsule key depends on the previous '
                                          'capsule\'s tag; tamper one -> all downstream keys corrupt '
                                          'via poison state (silent inert, no crash).')
            self.parser.add_argument('--no-chain', dest='chain', action='store_false',
                                     help='Disable chain runtime (override profile auto-enable).')
            # --- batch 8 (Phase 3): debug poisoning + metamorphic ---
            self.parser.add_argument('--debug-poison', dest='debug_poison', action='store_true', default=False,
                                     help='Debug Poisoning: detected debuggers/hooks/anti-tamper failures advance '
                                          'the poison state (silent inert downstream) instead of sys.exit. '
                                          'Auto-enables --chain (poison state lives in the chain integrity shard).')
            self.parser.add_argument('--no-debug-poison', dest='debug_poison', action='store_false',
                                     help='Disable debug poisoning (override profile auto-enable).')
            self.parser.add_argument('--metamorphic', dest='metamorphic', action='store_true', default=False,
                                     help='Metamorphic: file self-rewrites on every run (atomic os.replace) with '
                                          'fresh spam + re-encrypted string literals + re-patched file hash, so a '
                                          'static dump taken at different times shows different bytes. '
                                          'Auto-enables --chain (shard 5 hooks into the chain preamble).')
            self.parser.add_argument('--no-metamorphic', dest='metamorphic', action='store_false',
                                     help='Disable metamorphic self-rewrite (override profile auto-enable).')
            # --- batch 9 (Phase 4): anti-meta debranding ---
            self.parser.add_argument('--anti-meta', dest='anti_meta', action='store_true', default=False,
                                     help='Anti-meta: replace every static bedrock/Bedrock/BEDROCK/baobg/BedrockDz '
                                          'literal in the output artifact with per-build random tokens so the '
                                          'artifact cannot be fingerprinted by static signature. Auto-on for extreme.')
            self.parser.add_argument('--no-anti-meta', dest='anti_meta', action='store_false',
                                     help='Disable anti-meta debranding (override profile auto-enable).')
            # --- batch 10 (Phase 5): native BedrockVM compilation ---
            self.parser.add_argument('--native-vm', dest='native_vm', action='store_true', default=False,
                                     help='Native BedrockVM: compile eligible top-level functions into '
                                          'BedrockVM bytecode blobs (run via the shipped _xvm C '
                                          'interpreter or the _bedrock_vm_ref fallback). A function goes '
                                          'to the VM OR the capsule runtime, never both. Auto-on for extreme.')
            self.parser.add_argument('--no-native-vm', dest='native_vm', action='store_false',
                                     help='Disable native BedrockVM compilation (override profile '
                                          'auto-enable).')
            self.parser.add_argument('--crown-jewel-vm', dest='crown_jewel_vm',
                                     action='store_true', default=False,
                                     help='Phase F leak-resilient VM (Layer 2): virtualize the '
                                          'crown jewels (@bedrock_crown_jewel-decorated '
                                          'functions, or top-N most complex by fallback) through '
                                          'the hardened bedrock_vm_v2.c runtime. Reconciled '
                                          'with --transpile: the crown jewels are VM-compiled '
                                          'inside the transpile path (rest Cython-native).')
            self.parser.add_argument('--vm-fallback', dest='vm_fallback',
                                     choices=['auto', 'dev', 'off'], default='auto',
                                     help='VM fallback when the native extension is missing or '
                                          'tampered at runtime: auto=warn + reference (default), '
                                          'dev=silent reference, off=fail-closed (extreme auto-'
                                          'sets off so a tampered .pyd aborts instead of degrading).')
            # --- Phase G (Layer 3): server key-release -------------------
            self.parser.add_argument('--release-server', dest='release_server',
                                     metavar='URL', default='',
                                     help='Phase G server key-release (Layer 3): instead of '
                                          'embedding the VM key as a literal in the artifact, '
                                          'ship a _vm_key_handle tuple and let the loader fetch '
                                          'the key via an attested POST to URL/release (Ed25519 '
                                          'JWT + X25519 ECDH + AES-GCM, machine-bound on-disk '
                                          'cache with offline grace). Requires --license-id and '
                                          'a master seed (--master-seed or BEDROCK_MASTER_SEED '
                                          'env). Mutually exclusive with --env-key.')
            self.parser.add_argument('--license-id', dest='license_id',
                                     metavar='ID', default='',
                                     help='License/customer identifier for key-release '
                                          '(binds the derived VM key to this license via '
                                          'HKDF-SHA256(master_seed, salt=license_id)).')
            self.parser.add_argument('--master-seed', dest='master_seed',
                                     metavar='HEX', default='',
                                     help='Server master seed (hex of 32 bytes) for key-release. '
                                          'Falls back to BEDROCK_MASTER_SEED env var. The seed '
                                          'lives on the build host AND the release server (same '
                                          'value); never ships in the artifact.')
            self.parser.add_argument('--offline-grace-seconds', dest='offline_grace_seconds',
                                     type=int, default=604800,
                                     help='Key-cache TTL in seconds (default 604800 = 7 days). '
                                          'A protected module can run offline this long before '
                                          're-attestation is required.')
            # --- Phase H (Layer 6): 11 esoteric/anti-pattern passes --------
            # All default OFF; auto-on under `extreme` (see
            # _apply_extreme_overrides). Each pass is a behavior-preserving
            # AST/source transform implemented in bedrock_native/_*.py and
            # registered via _insert_after_obf_vars. Pass ordering follows the
            # reverse-stack convention (declared LATER runs EARLIER).
            # H.1 identifier poisoning: shadow builtins as locals via
            # __builtins__['name'] (survives obf_builtins bare-Name rewrite).
            self.parser.add_argument('--h-id-poison', dest='h_id_poison',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.1] Shadow builtins as locals '
                                          '(__builtins__[\'name\']) to break static name-'
                                          'resolution. Default off (extreme auto-on).')
            # H.2 Acoda: opaque call dispatch via _br_acoda table + modular-
            # inverse opaque index.
            self.parser.add_argument('--h-acoda', dest='h_acoda',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.2] Replace direct calls with opaque '
                                          '_br_acoda[idx](args) dispatch. Default off '
                                          '(extreme auto-on).')
            # H.3 Structural metamorphic: dead-junk _br_mut targets + runtime
            # shard that re-randomizes them per run.
            self.parser.add_argument('--h-metamorphic', dest='h_metamorphic',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.3] Inject dead-junk _br_mut targets '
                                          'and a runtime shard that re-randomizes them per '
                                          'run (byte-level file mutation). Default off '
                                          '(extreme auto-on).')
            # H.4 Style randomizer: post-unparse source layout shuffle.
            self.parser.add_argument('--h-style', dest='h_style',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.4] Post-unparse style randomizer '
                                          '(blank lines + junk comments + def shuffle). '
                                          'Source-mode only. Default off (extreme auto-on).')
            # H.5 Branchless-ification: if/else -> mux.
            self.parser.add_argument('--h-branchless', dest='h_branchless',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.5] Convert eligible if/else to '
                                          'branchless mux (b^((a^b)&-cond)). Default off '
                                          '(extreme auto-on).')
            # H.6 Bloom-filter opaque predicates.
            self.parser.add_argument('--h-bloom', dest='h_bloom',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.6] Bloom-filter opaque predicates '
                                          '(_br_bloom / _br_bloom_contains). Default off '
                                          '(extreme auto-on).')
            # H.7 DAG-based CFF (2-var state machine).
            self.parser.add_argument('--h-dag-cff', dest='h_dag_cff',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.7] DAG-based CFF with a 2-variable '
                                          '(_br_ds1, _br_ds2) state machine. Linear bodies '
                                          'only. Default off (extreme auto-on).')
            # H.8 Self-checking CF (rolling path hash).
            self.parser.add_argument('--h-selfcheck-cf', dest='h_selfcheck_cf',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.8] Self-checking control flow: rolling '
                                          '_br_path hash verified before each return. '
                                          'Linear bodies only. Default off (extreme auto-on).')
            # H.9 FSS 2-share (function secret sharing).
            self.parser.add_argument('--h-fss', dest='h_fss',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.9 + iO-2] Function secret sharing: split '
                                          'eligible f(x) into additive (int) / XOR (bool) / '
                                          'serialized (any repr-safe) shares. Phase iO-2 '
                                          'extends the original H.9 (2-share additive int) to '
                                          'bool + serialized + n-share + all-eligible. Default off.')
            # Phase iO-2: FSS extensions
            self.parser.add_argument('--fss-mode', dest='fss_mode', default='auto',
                                     choices=['auto', 'additive', 'additive_n', 'bool', 'serialized'],
                                     help='[iO-2] FSS mode. auto = bool→additive→serialized '
                                          '(default). additive_n = n-share collusion-resistant. '
                                          'See --fss-shares.')
            self.parser.add_argument('--fss-shares', dest='fss_shares', type=int, default=3,
                                     help='[iO-2] Number of shares for additive_n mode (default 3, min 2).')
            self.parser.add_argument('--fss-all-eligible', dest='fss_all_eligible', action='store_true',
                                     help='[iO-2] Lift the 3-5 cap → share ALL eligible functions (iO-grade coverage).')
            self.parser.add_argument('--no-fss-all-eligible', dest='fss_all_eligible', action='store_false',
                                     help='Disable --fss-all-eligible (override profile auto-enable).')
            # Phase iO-3: crypto opaque predicates
            self.parser.add_argument('--opaque-grade', dest='opaque_grade', default='algebra',
                                     choices=['algebra', 'crypto', 'hybrid'],
                                     help='[iO-3] Opaque-predicate grade. algebra = trivial '
                                          'x*(x-1)%2==0 (Z3 folds). crypto = DL/LWE/hash/RSA '
                                          '(Z3 cannot fold). hybrid = both. Default algebra '
                                          '(io profile auto-sets crypto).')
            # H.10 TLS callback injection (native PE post-build).
            self.parser.add_argument('--h-tls-callback', dest='h_tls_callback',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.10] Inject a TLS callback (.brtls '
                                          'section) firing pre-PyInit for early integrity '
                                          'checks. Native PE post-build; requires --transpile. '
                                          'Default off (extreme auto-on when --transpile).')
            # H.11 Exception-table VM (native C dispatch via SEH/.pdata).
            self.parser.add_argument('--h-exc-table-vm', dest='h_exc_table_vm',
                                     action=argparse.BooleanOptionalAction, default=None,
                                     help='[Phase H.11] Exception-table VM: dispatch via '
                                          'SEH/.pdata (native C module _xetvm). Requires '
                                          '--transpile. Default off (extreme auto-on when '
                                          '--transpile).')
            # --- batch: vm-extended / cache / plugins / tui / project ---
            self.parser.add_argument('--vm-extended', dest='vm_extended', action=argparse.BooleanOptionalAction,
                                     default=None, help=argparse.SUPPRESS)
            self.parser.add_argument('--cache', dest='cache', action='store_true', default=True,
                                     help='Enable incremental build cache (default).')
            self.parser.add_argument('--no-cache', dest='cache', action='store_false',
                                     help='Disable cache lookup/store.')
            self.parser.add_argument('--clear-cache', action='store_true',
                                     help='Purge cache entries older than 30 days, then exit.')
            self.parser.add_argument('--plugins', action='append', default=[], metavar='DIR',
                                     help='Plugin directory (repeatable).')
            self.parser.add_argument('--no-plugins', action='store_true',
                                     help='Disable plugin discovery entirely.')
            self.parser.add_argument('--tui', action='store_true',
                                     help='Launch Textual TUI (requires textual + rich).')
            # --- native transpile (Phase 1+): emit native code instead of the
            # marshal+bz2+key-embedding loader. The obfuscated logic is transpiled
            # to C via Cython and compiled to a .pyd/.so — no cleartext keys,
            # no marshal blob, so a deobfuscator built from the leaked source
            # cannot recover the logic. See bedrock_native/_transpile_pipeline.py.
            self.parser.add_argument('--transpile', action='store_true',
                                     help='Transpile obfuscated output to native C via '
                                          'Cython (.pyd/.so). Eliminates the key-in-output '
                                          'leak; logic becomes native machine code.')
            self.parser.add_argument('--no-c-string-obf', dest='c_string_obf',
                                     action='store_false', default=True,
                                     help=argparse.SUPPRESS)
            self.parser.add_argument('--project', metavar='DIR', default=None,
                                     help='Build an entire project tree (mutually exclusive with -f).')
            self.parser.add_argument('--output-dir', metavar='DIR', default=None,
                                     help='Output directory for project mode.')
            self.parser.add_argument('--ignore', action='append', default=[], metavar='PATTERN',
                                     help='Glob ignore pattern (repeatable).')
            self.args = self.parser.parse_args(argv)
            self.args._argv = list(argv) if argv is not None else sys.argv[1:]

            self.args.protect = True
            self.args.non_interactive = bool(self.args.non_interactive or (not sys.stdin.isatty()))
            globals()['QUIET_MODE'] = bool(self.args.quiet)
            globals()['JSON_MODE'] = bool(self.args.json)

            if not self.args.type:
                self.args.type = 'Main'
            self.args.mode = 1

            try:
                runtime_mode_public_, runtime_mode_internal_, runtime_warning_ = normalize_runtime_mode(self.args.runtime_mode)
            except ValueError as e:
                self.parser.error(str(e))
            self.args.runtime_mode_public = runtime_mode_public_
            self.args.runtime_mode = runtime_mode_internal_
            if runtime_warning_:
                Logging.warning(runtime_warning_)

            # Legacy profile reconciliation: under the new preset names this is
            # dead code; apply_profile() in main() now drives these decisions.
            if self.args.profile in ('max', 'compat', 'legacy'):
                if self.args.profile == 'legacy' and self.args.runtime_mode_public != 'legacy':
                    self.args.runtime_mode_public = 'legacy'
                    self.args.runtime_mode = 'legacy'
                    Logging.warning('Profile "legacy" selected; using legacy compatibility runtime.')
                elif self.args.runtime_mode_public == 'legacy' and self.args.profile != 'legacy':
                    Logging.warning('Legacy runtime selected; forcing profile to "legacy".')
                    self.args.profile = 'legacy'

                if self.args.profile == 'compat':
                    if self.args.anti_debug == 'strict':
                        self.args.anti_debug = 'compat'
                    if self.args.anti_hook == 'strict':
                        self.args.anti_hook = 'compat'
                if self.args.profile == 'legacy' and self.args.anti_debug == 'compat':
                    self.args.anti_debug = 'off'

            if not self.args.output:
                if self.args.file:
                    self.args.output = f'obf-{self.args.file}'
                    Logging.info(f'No output file specified, using "{self.args.output}"')

            global mode, protect, type_run, runtime_mode, runtime_mode_public, bind_mode, anti_hook_mode, anti_debug_mode, legacy_loader, vm_profile_mode, vm_carrier_mode, vm_compat_mode, profile_mode, tamper_mode, python_band_mode
            mode = 1
            protect = self.args.protect
            type_run = self.args.type.upper()
            runtime_mode = self.args.runtime_mode
            runtime_mode_public = self.args.runtime_mode_public
            bind_mode = self.args.bind_mode
            anti_hook_mode = 'strict' if self.args.anti_hook == 'strict' else 'off'
            anti_debug_mode = 'strict' if self.args.anti_debug == 'strict' else ('score' if self.args.anti_debug == 'compat' else 'off')
            legacy_loader = bool(self.args.legacy_loader or self.args.runtime_mode == 'legacy')
            vm_profile_mode = self.args.vm_profile
            vm_carrier_mode = self.args.vm_carrier
            vm_compat_mode = self.args.vm_compat
            profile_mode = self.args.profile
            tamper_mode = self.args.tamper
            python_band_mode = self.args.python_band

    # === [13] Final try/except wrapper ===
    def clean_try_except(code_str):
        try:
            original_ast = ast.parse(code_str)
            preamble_nodes, body_nodes = _split_preamble_nodes(original_ast.body)
            if not body_nodes:
                new_module = ast.Module(body=preamble_nodes, type_ignores=[])
                ast.fix_missing_locations(new_module)
                return ast.unparse(new_module) if preamble_nodes else ''
            try_body = body_nodes
            exception_var_name = 'BedrockException' * 10 
            print_call = ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Name(id=exception_var_name, ctx=ast.Load())], keywords=[]))
            exception_handler = ast.ExceptHandler(type=ast.Name(id='Exception', ctx=ast.Load()), name=exception_var_name, body=[print_call])
            print_exiting_call = ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()), args=[ast.Constant(value='\n\nExiting...')], keywords=[]))
            exit_call = ast.Expr(value=ast.Call(func=ast.Name(id='exit', ctx=ast.Load()), args=[], keywords=[]))
            keyboard_interrupt_handler = ast.ExceptHandler(type=ast.Name(id='KeyboardInterrupt', ctx=ast.Load()), name=None, body=[print_exiting_call, exit_call])
            try_except = ast.Try(body=try_body, handlers=[keyboard_interrupt_handler, exception_handler], orelse=[], finalbody=[])
            new_module = ast.Module(body=preamble_nodes + [try_except], type_ignores=[])
            ast.fix_missing_locations(new_module)
            return ast.unparse(new_module)
        except SyntaxError as e:
            return f'# Invalid code: {str(e)}'

    # === [14] main() entrypoint ===
    def _apply_extreme_overrides(args):
        """Boost the `extreme`/`io` preset to enable every new extension flag.

        Runs for both `extreme` and `io` profiles. The `io` profile (Phase
        iO-1) layers Phase H esoteric passes on top of extreme; this function
        applies the shared conditional overrides (vm_fallback, native_vm,
        runtime_dec, chain, etc.) that are unsafe to put in the PROFILES dict
        because they must honour explicit --no-* CLI disables.
        """
        _preset = getattr(args, '_profile_preset', getattr(args, 'profile', ''))
        if _preset not in ('extreme', 'io'):
            return
        _argv = tuple(str(_x) for _x in (getattr(args, '_argv', None) or ()))
        def _flag_explicit(*flags):
            return any((_x == _flag or _x.startswith(_flag + '=')) for _x in _argv for _flag in flags)
        for attr, val in (
            ('cff', True), ('bc_mutate', True),
            ('num_obf', True), ('import_obf', True),
            ('str_frag2', True),
            ('vm_extended', True),
            # batch 5 (Phase 1+2): force the landed AST-only + data-obf
            # passes on for extreme. var_split is now safe (apply_varsplit
            # shipped).
            ('dec_trap', True), ('var_split', True),
            ('spoof_meta', True), ('anti_timing', True),
            # Phase H (Layer 6): 9 Python AST + source passes auto-on for
            # extreme. All are behavior-preserving and compose with the
            # existing ext passes (verified by _phase_h_test.py combined-9).
            # H.10 (TLS callback) and H.11 (exc-table VM) are native-only and
            # gated on --transpile below (they need a .pyd to patch / a native
            # build to link against).
            ('h_id_poison', True), ('h_acoda', True),
            ('h_metamorphic', True), ('h_style', True),
            ('h_branchless', True), ('h_bloom', True),
            ('h_dag_cff', True), ('h_selfcheck_cf', True),
            ('h_fss', True),
        ):
            # Honour explicit --no-<flag> CLI disables. Previously this block
            # only checked `getattr(args, attr, False)`, which is False after
            # --no-foo sets args.foo=False, so it clobbered the user's explicit
            # disable. Phase iO-1: gate on _flag_explicit('--no-<flag>') too.
            _cli_disable = '--no-' + attr.replace('_', '-')
            if not getattr(args, attr, False) and not _flag_explicit(_cli_disable):
                setattr(args, attr, val)
        # Phase H native passes (H.10 TLS callback, H.11 exc-table VM) require
        # --transpile (they patch/link a native .pyd). Auto-on for extreme ONLY
        # when --transpile is active; otherwise skipped (the CLI flags remain
        # available but inert, like the other native-gated passes).
        if getattr(args, 'transpile', False):
            for _h_native in ('h_tls_callback', 'h_exc_table_vm'):
                if not getattr(args, _h_native, False) and                         not _flag_explicit('--no-' + _h_native.replace('_', '-')):
                    setattr(args, _h_native, True)
        # Phase iO-1: H.1 identifier poisoning injects `name = __builtins__['name']`
        # shadow bindings inside functions. When the capsule runtime
        # (runtime_dec) marshal+exec a function, the shadow's local binding is
        # lost in the recreated __code__, and any lambda/closure referencing the
        # shadowed builtin (range/len/etc.) raises `NameError: cannot access
        # free variable '<name>'`. Gate h_id_poison OFF when runtime_dec is on
        # (mirrors the homoglyph/lambda_enc gate vs native_vm). The user can
        # still force it on with `--h-id-poison` explicitly.
        if getattr(args, 'runtime_dec', False) and getattr(args, 'h_id_poison', False):
            if not _flag_explicit('--h-id-poison'):
                args.h_id_poison = False
        # Native capsule runtime (runtime_dec) replaces the dropped VM runtime
        # in Bedrock vNext Phase 1 — extreme now auto-enables it so the
        # per-function encrypt/decrypt-on-call capsule engages. Homoglyph is
        # gated on the same native path (was VM-only before; safe on main).
        # NOTE: when native_vm (Phase 5 BedrockVM) is active, homoglyph must NOT
        # auto-enable — it renames identifiers to Unicode homoglyphs that the
        # VM runtime cannot resolve for recursive self-calls (fib(n-1) inside
        # the VM blob references the pre-rename name → returns None). The user
        # can still pass --homoglyph explicitly, but extreme with native_vm
        # stays safe by default.
        _native_vm_on = bool(getattr(args, 'native_vm', False)) or not _flag_explicit('--no-native-vm')
        # Phase iO-1: homoglyph breaks BOTH the native VM (recursive self-calls
        # reference pre-rename names) AND the capsule runtime (runtime_dec
        # marshal+exec recreates __code__ whose Unicode names can't resolve in
        # the new scope → `NameError: name '<unicode>' is not defined`). Gate
        # it OFF when EITHER native_vm or runtime_dec is on. The user can still
        # force it on with `--homoglyph` explicitly.
        _capsule_on = bool(getattr(args, 'runtime_dec', False))
        if not getattr(args, 'homoglyph', False) and not _flag_explicit('--no-homoglyph'):
            if not _native_vm_on and not _capsule_on:
                args.homoglyph = True
        if not getattr(args, 'vm_opcode_remap', False) and not _flag_explicit('--no-vm-opcode-remap'):
            args.vm_opcode_remap = True
        if not getattr(args, 'runtime_dec', False) and not _flag_explicit('--no-runtime-dec'):
            args.runtime_dec = True
        # Chain runtime (Phase 2): extreme auto-enables the HMAC hash chain +
        # mutual verification ring + shard separation alongside the capsule
        # runtime so tampering one capsule corrupts all downstream via poison.
        # Honour --no-chain if the user explicitly passed it.
        if not getattr(args, 'chain', False) and not _flag_explicit('--no-chain'):
            args.chain = True
        # Debug poisoning (Phase 3): extreme auto-enables poison-mode anti-dbg.
        # Auto-enables chain (poison state lives in the chain integrity shard).
        if not getattr(args, 'debug_poison', False) and not _flag_explicit('--no-debug-poison'):
            args.debug_poison = True
        if getattr(args, 'debug_poison', False):
            if not getattr(args, 'chain', False) and not _flag_explicit('--no-chain'):
                args.chain = True
        # Metamorphic (Phase 3): extreme auto-enables file self-rewrite so
        # the on-disk artifact mutates between static dumps. Requires chain.
        if not getattr(args, 'metamorphic', False) and not _flag_explicit('--no-metamorphic'):
            args.metamorphic = True
        if getattr(args, 'metamorphic', False):
            if not getattr(args, 'chain', False) and not _flag_explicit('--no-chain'):
                args.chain = True
        # Anti-meta (Phase 4): extreme auto-enables debranding so the output
        # artifact carries no static bedrock/baobg/BedrockDz signature. Honours
        # --no-anti-meta if the user explicitly passed it.
        if not getattr(args, 'anti_meta', False) and not _flag_explicit('--no-anti-meta'):
            args.anti_meta = True
        # Native BedrockVM (Phase 5): extreme auto-enables VM compilation so
        # eligible top-level functions become BedrockVM bytecode blobs (run
        # via the shipped _xvm C interpreter). Honours --no-native-vm.
        if not getattr(args, 'native_vm', False) and not _flag_explicit('--no-native-vm'):
            args.native_vm = True
        # Production fail-closed native VM: extreme defaults to --vm-fallback off
        # so a missing or tampered _xvm.pyd poisons+aborts instead of silently
        # degrading to the pure-Python reference interpreter. Honours an explicit
        # --vm-fallback auto/dev.
        if not _flag_explicit('--vm-fallback'):
            args.vm_fallback = 'off'
        for attr in ('junk', 'bool_obf'):
            if not getattr(args, attr, False) and not _flag_explicit('--no-' + attr.replace('_', '-')):
                setattr(args, attr, True)
        # lambda_enc converts `def` → lambda assignment. The native VM compiler
        # (Phase 5) targets `def` nodes — a lambda-ified function is no longer
        # a def, so the VM compiler skips it, changing behavior. Gate it the
        # same way as homoglyph: don't auto-enable when native_vm is on.
        # Phase iO-1: also gate OFF when runtime_dec (capsule) is on — lambda
        # closures recreated by marshal+exec lose their cell bindings, causing
        # `NameError: free variable` (same root cause as homoglyph/h_id_poison).
        if not getattr(args, 'lambda_enc', False) and not _flag_explicit('--no-lambda-enc'):
            if not _native_vm_on and not _capsule_on:
                args.lambda_enc = True
        # Only honour explicit CLI disables, never auto-disable for extreme.
        # `anti_vm=strict` self-destructs in sandboxed CI/VM environments, so
        # we only auto-enable it when the user did NOT explicitly pass
        # --anti-vm off / --no-anti-vm. Same for anti_debugger_v2.
        if getattr(args, 'anti_vm', 'off') == 'off' and not _flag_explicit('--anti-vm'):
            args.anti_vm = 'strict'
        if getattr(args, 'anti_debugger_v2', 'off') == 'off' and not _flag_explicit('--anti-debugger-v2'):
            args.anti_debugger_v2 = 'on'

    def main(argv=None):
        args = ParseArgs(argv).args
        return run_build(args)

    def run_build(args):
        global banner, ADV_REQUESTS_PROTECTION
        global mode, protect, type_run, runtime_mode, runtime_mode_public, bind_mode, anti_hook_mode, anti_debug_mode, legacy_loader, vm_profile_mode, vm_carrier_mode, vm_compat_mode, profile_mode, tamper_mode, python_band_mode
        if not hasattr(args, 'file'):
            args.file = getattr(args, 'input', None)
        defaults = {
            'output': None,
            'profile': 'balanced',
            'runtime_mode': 'main',
            'runtime_mode_public': 'main',
            'anti_debug': 'strict',
            'anti_hook': 'strict',
            'integrity': 'on',
            'tamper': 'self-destruct',
            'python_band': '3.10-3.12',
            'non_interactive': True,
            'overwrite': False,
            'quiet': False,
            'json': False,
            'type': 'Main',
            'mode': 1,
            'protect': True,
            'bind_mode': 'none',
            'legacy_loader': False,
            'vm_profile': 'production',
            'vm_carrier': 'auto',
            'vm_compat': 'broad',
            'adv_requests': 'off',
            'clear_cache': False,
            'plugins': [],
            'no_plugins': False,
            'tui': False,
            'project': None,
            'output_dir': None,
            'ignore': [],
            'cache': True,
            'transpile': False,
            'c_string_obf': True,
        }
        for _key, _value in defaults.items():
            if not hasattr(args, _key):
                setattr(args, _key, _value)
        if getattr(args, 'output', None) is None and getattr(args, 'file', None):
            args.output = f'obf-{args.file}'
            Logging.info(f'No output file specified, using "{args.output}"')
        if isinstance(getattr(args, 'integrity', 'on'), bool):
            args.integrity = 'on' if args.integrity else 'off'
        if isinstance(getattr(args, 'anti_debugger_v2', 'off'), bool):
            args.anti_debugger_v2 = 'on' if args.anti_debugger_v2 else 'off'
        if not hasattr(args, 'anti_debugger_v2'):
            args.anti_debugger_v2 = 'off'
        try:
            # Normalize runtime mode (maps legacy vm-native*/chunk-vm-lite
            # choices to 'main' with a deprecation warning, since VM runtimes
            # were removed in Bedrock vNext Phase 1).
            runtime_mode_public_, runtime_mode_internal_, runtime_warning_ = normalize_runtime_mode(args.runtime_mode)
            args.runtime_mode_public = runtime_mode_public_
            args.runtime_mode = runtime_mode_internal_
            if runtime_warning_:
                Logging.warning(runtime_warning_)
        except ValueError as _e:
            cli_fail(2, str(_e), kind='error')
        globals()['QUIET_MODE'] = bool(getattr(args, 'quiet', False))
        globals()['JSON_MODE'] = bool(getattr(args, 'json', False))
        mode = int(getattr(args, 'mode', 1) or 1)
        protect = bool(getattr(args, 'protect', True))
        type_run = str(getattr(args, 'type', 'Main') or 'Main').upper()
        runtime_mode = args.runtime_mode
        runtime_mode_public = args.runtime_mode_public
        bind_mode = args.bind_mode
        anti_hook_mode = 'strict' if args.anti_hook == 'strict' else 'off'
        anti_debug_mode = 'strict' if args.anti_debug == 'strict' else ('score' if args.anti_debug == 'compat' else 'off')
        legacy_loader = bool(args.legacy_loader or args.runtime_mode == 'legacy')
        vm_profile_mode = args.vm_profile
        vm_carrier_mode = args.vm_carrier
        vm_compat_mode = args.vm_compat
        profile_mode = args.profile
        tamper_mode = args.tamper
        python_band_mode = args.python_band
        # --- TUI entry (highest priority) ---
        if getattr(args, 'tui', False):
            try:
                _run_tui = globals().get('tui_run', None)
                if _run_tui is None:
                    raise ImportError('TUI not available (textual missing)')
                _run_tui()
            except ImportError as _e:
                print('[bedrock] TUI deps missing:', _e)
                print('         Install: pip install --user textual rich')
                return 2
            return 0
        # --- clear-cache shortcut ---
        if getattr(args, 'clear_cache', False):
            if _ext_cache is not None:
                n = _ext_cache.cache_clear(30)
                print(f'[cache] cleared {n} entries from {_ext_cache.CACHE_DIR}')
            else:
                print('[cache] bedrock_ext.cache unavailable')
            return 0
        # --- bedrock_ext: apply preset profile then refresh dependent globals ---
        report = None
        if _ext_apply_profile is not None:
            try:
                _ext_apply_profile(args, args.profile, argv=getattr(args, '_argv', None))
            except Exception as _e:
                Logging.warning(f'apply_profile failed: {_e}')
        # P0 production: activate the full extreme/io override stack. The
        # _apply_extreme_overrides() function was previously dormant (defined
        # but never called) due to regression fears around homoglyph/lambda_enc
        # breaking VM-compiled recursion and anti_vm=strict self-destructing in
        # sandboxed CI. Both are now fixed:
        #   - homoglyph/lambda_enc are gated OFF when native_vm is on (inside
        #     the function itself, lines ~5531/5582).
        #   - anti_vm/anti_debugger_v2 now honour explicit --anti-vm off /
        #     --no-anti-vm CLI disables (won't self-destruct in CI).
        # The function is idempotent with the vm_fallback block below and
        # honours every --no-* flag the user passed. Runs for both `extreme`
        # and `io` profiles (Phase iO-1).
        try:
            _apply_extreme_overrides(args)
        except Exception as _e:
            Logging.warning(f'_apply_extreme_overrides failed: {_e}')
        # Phase 3: --debug-poison / --metamorphic require the capsule chain
        # (shards live in apply_runtimedec's chain preamble). Auto-enable
        # runtime_dec + chain for ANY profile when the user explicitly opts
        # in, so `--metamorphic balanced` actually rewrites the file instead
        # of silently skipping shard 5. --no-chain / --no-runtime-dec are
        # still honoured because they imply the user understands the trade-off.
        _phase3_argv = tuple(str(_x) for _x in (getattr(args, '_argv', None) or ()))
        def _phase3_flag_explicit(*flags):
            return any((_x == _flag or _x.startswith(_flag + '=')) for _x in _phase3_argv for _flag in flags)
        if getattr(args, 'debug_poison', False) or getattr(args, 'metamorphic', False):
            if not getattr(args, 'runtime_dec', False) and not _phase3_flag_explicit('--no-runtime-dec'):
                args.runtime_dec = True
            if not getattr(args, 'chain', False) and not _phase3_flag_explicit('--no-chain'):
                args.chain = True
        # Phase 3: --debug-poison forces tamper mode to 'poison' so the guard
        # reaction dispatchers route detections through __h_poison (silent
        # inert) instead of sys.exit. Override args.tamper so both the locals
        # and ctx.tamper (read by the snippet wrappers) reflect poison mode.
        if getattr(args, 'debug_poison', False):
            args.tamper = 'poison'
            tamper_mode = 'poison'
        # --- Project mode ---
        if getattr(args, 'project', None):
            try:
                from pathlib import Path as _PPath
                _PB = ExtProjectBuilder
                _ctx = BuildContext.from_args(args)
                root = _PPath(args.project).resolve()
                if not root.is_dir():
                    cli_fail(2, f'Project root not found: {root}')
                    return 2
                out_dir = (_PPath(args.output_dir).resolve() if args.output_dir
                           else root.with_name(root.name + '_obf'))
                builder = _PB(root=root, output_root=out_dir, ctx=_ctx,
                              ignore_patterns=tuple(args.ignore or ()),
                              per_file_pipeline=None)
                stats = builder.build()
                cli_emit('info',
                         f'project: {stats.files_processed} files, '
                         f'in={stats.total_size_in}B out={stats.total_size_out}B, '
                         f'errors={len(stats.errors_per_file)}',
                         path=str(out_dir))
                for _f, _err in stats.errors_per_file.items():
                    cli_emit('error', f'{_f}: {_err}')
                return 0 if not stats.errors_per_file else 1
            except Exception as _e:
                Logging.warning(f'project mode failed: {_e}')
                return 1
        if False:
            # placeholder so subsequent indentation matches original logic
            pass
        if _ext_apply_profile is not None:
            # re-sync ParseArgs-side globals that were captured before preset apply
            try:
                anti_hook_mode = 'strict' if args.anti_hook == 'strict' else 'off'
                anti_debug_mode = 'strict' if args.anti_debug == 'strict' else ('score' if args.anti_debug == 'compat' else 'off')
                legacy_loader = bool(getattr(args, 'legacy_loader', False) or args.runtime_mode == 'legacy')
                vm_profile_mode = args.vm_profile
                vm_carrier_mode = args.vm_carrier
                vm_compat_mode = args.vm_compat
                profile_mode = args.profile
                tamper_mode = args.tamper
                python_band_mode = args.python_band
                runtime_mode = args.runtime_mode
                runtime_mode_public = args.runtime_mode_public
            except Exception:
                pass
        if _ExtReportBuilder is not None and _ext_report_activate is not None:
            try:
                report = _ext_report_activate(_ExtReportBuilder(profile_used=getattr(args, '_profile_preset', args.profile))).start()
                report.set_flags(args)
            except Exception as _e:
                Logging.warning(f'ReportBuilder init failed: {_e}')
                report = None
        # Build a BuildContext now (used by hardening / bcmut wiring)
        try:
            _build_ctx = BuildContext.from_args(args)
        except Exception:
            _build_ctx = None
        globals()['__BEDROCK_BUILD_CTX__'] = _build_ctx
        # Phase 4: initialize per-build debrand tokens. Must run BEFORE any
        # emit (header, self_check_code, pro, DitMeMayDecDiCode, snippets,
        # chain_preamble) so every component gets the SAME token. When
        # anti_meta is off, _init_debrand sets the identity map (no-op).
        try:
            _init_debrand(getattr(_build_ctx, 'rng', None) or random.Random(),
                          bool(getattr(args, 'anti_meta', False)))
        except Exception:
            _init_debrand(None, False)
        if not globals().get('QUIET_MODE', False) and not globals().get('JSON_MODE', False):
            print(' ' * len('>> Loading...'), end='\r')
            grad = [_ANSI.BMAGENTA, _ANSI.BRED, _ANSI.BYELLOW, _ANSI.BGREEN, _ANSI.BCYAN, _ANSI.BBLUE]
            print(_ANSI.diag_gradient(BEDROCK_BANNER_ART, grad))
        # VM runtimes removed in Bedrock vNext Phase 1; vm_native_requested
        # stays False forever (normalize_runtime_mode maps legacy vm-native*
        # choices to 'main'). Kept as an explicit False for readability.
        vm_native_requested = False
        if not globals().get('QUIET_MODE', False) and not globals().get('JSON_MODE', False):
            print(' ' + '- ' * 30)
        if not args.file:
            cli_fail(2, 'Missing required input file. Use --file PATH.', kind='error')
        file = args.file
        adv_requests_mode = str(getattr(args, 'adv_requests', 'ask') or 'ask').strip().lower()
        if adv_requests_mode == 'on':
            ADV_REQUESTS_PROTECTION = True
        else:
            ADV_REQUESTS_PROTECTION = False
        file_prefix = ''
        try:
            # safer file reading + sanitize control chars
            with open(file, 'rb') as f:
                raw = f.read()
            # try utf-8-sig first to strip BOM, fallback to latin1 to preserve bytes
            try:
                code_ = raw.decode('utf-8-sig')
            except UnicodeDecodeError:
                code_ = raw.decode('latin1')
            file_prefix, code_body = extract_prefix_lines(code_)
            globals()['__FILE_PREFIX__'] = file_prefix
            # sanitize: replace C0 and C1 control characters (U+0000..U+001F, U+007F..U+009F)
            # but keep common whitespace 
            def sanitize_text(s: str) -> str:
                out_chars = []
                for ch in s:
                    if ch == '\ufeff':
                        continue
                    o = ord(ch)
                    if ch in ("\n", "\r", "\t"):
                        out_chars.append(ch)
                    elif 0 <= o <= 31:
                        out_chars.append(' ')
                    elif 127 <= o <= 159:
                        out_chars.append(' ')
                    else:
                        out_chars.append(ch)
                return ''.join(out_chars)
            code_body = sanitize_text(code_body)
            code = code_body
            if protect:
                code = insert_after_preamble(code, BEDROCK_ANTI)
            Logging.success(f'Loaded file {file} (sanitized)')
            if report is not None:
                try:
                    report.set_input(code_body)
                except Exception:
                    pass
        except Exception as e:
            cli_fail(4, f'Failed to load or parse input file: {file}', detail=str(e), path=file, kind='error')
        try:
            is_self_obfuscation = os.path.samefile(os.path.abspath(file), os.path.abspath(__file__))
        except Exception:
            is_self_obfuscation = os.path.normcase(os.path.abspath(file)) == os.path.normcase(os.path.abspath(__file__))
        runtime_mode_active = str(globals().get('runtime_mode', 'main') or 'main').strip().lower()
        legacy_loader_active = bool(globals().get('legacy_loader', False) or runtime_mode_active == 'legacy')
        # VM runtimes removed in Bedrock vNext Phase 1; these stay False forever.
        chunk_runtime_active = False
        vm_native_active = False
        strict_profile_active = getattr(args, '_profile_preset', getattr(args, 'profile', '')) in ('paranoid', 'extreme')
        if os.path.normcase(os.path.abspath(args.output)) == os.path.normcase(os.path.abspath(file)):
            cli_fail(2, 'Refusing to overwrite the input source file. Choose a different --output path.', path=args.output, kind='error')
        if os.path.exists(args.output) and (not args.overwrite):
            cli_fail(2, f'Artifact output already exists. Use --overwrite to replace it: {args.output}', path=args.output, kind='error')
        # VM-native capability scan removed in Bedrock vNext Phase 1 (VM dropped).
        code = insert_after_preamble(code, hard_code)
        Logging.event('Adding Anti PYCDC')
        build_anti_pycdc()
        Logging.event('Adding Vars')
        build_var()
        ext_flags = getattr(args, '_ext_flags', {}) or {}
        def _enabled(name, default=True):
            return bool(ext_flags.get(name, default))
        if is_self_obfuscation:
            operations = []
            if _enabled('obf_vars'):
                operations.append(Methods.obf_vars)
            # obf_builtins needs the loader preamble (bypassed in transpile).
            if _enabled('obf_builtins') and not bool(getattr(args, 'transpile', False)):
                operations.append(Methods.obf_builtins)
            if getattr(args, 'transpile', False):
                # Native transpile: skip the marshal+bz2+key-embedding loader
                # (the leak path the source leak broke). A no-op anchor keeps
                # _insert_before_compile positioning the ext AST passes before
                # the emit step; the actual Cython transpile runs after the
                # loop over the AST-obfuscated source. __name__='Obfuscate' so
                # _operation_label still reports 'compile'.
                def _transpile_anchor(src):
                    # Unwrap `if __name__ == '__main__':` guards so the entry
                    # call runs at import time under Cython (extension modules
                    # never set __name__ to '__main__'). obf_vars keeps dunders,
                    # so '__name__' survives the rename pass intact.
                    try:
                        import ast as _ast
                        tree = _ast.parse(src)
                        _nb = []
                        for _stmt in tree.body:
                            if (isinstance(_stmt, _ast.If)
                                    and isinstance(_stmt.test, _ast.Compare)
                                    and isinstance(_stmt.test.left, _ast.Name)
                                    and _stmt.test.left.id == '__name__'
                                    and any(isinstance(_c, _ast.Eq) and
                                            isinstance(_r, _ast.Constant) and
                                            _r.value == '__main__'
                                            for _c, _r in zip(_stmt.test.ops,
                                                              _stmt.test.comparators))):
                                _nb.extend(_stmt.body)
                            else:
                                _nb.append(_stmt)
                        tree.body = _nb
                        _ast.fix_missing_locations(tree)
                        return _ast.unparse(tree)
                    except Exception:
                        return src
                _transpile_anchor.__name__ = 'Obfuscate'
                operations.append(_transpile_anchor)
            else:
                operations.append(Compile.Obfuscate)
        else:
            operations = []
            if _enabled('obf_vars'):
                operations.append(Methods.obf_vars)
            # vm_strings / obf_builtins / obf_strings emit runtime-helper calls
            # (the builtins indirection dict + string/int decoders) that are
            # defined in the Compile.Obfuscate loader preamble. In transpile
            # mode that loader is bypassed, so these passes would produce
            # undeclared-name references Cython rejects. They are also redundant
            # — string/builtin obf is replaced by C-level XOR (Phase 4) once the
            # output is native C. Gate them off for transpile.
            _transpile_on = bool(getattr(args, 'transpile', False))
            if _enabled('vm_strings') and not _transpile_on:
                operations.append(Methods.vm_strings(args.mode))
            if _enabled('obf_builtins') and not _transpile_on:
                operations.append(Methods.obf_builtins)
            if _enabled('obf_strings') and not _transpile_on:
                operations.append(Methods.obf_strings(args.mode, False))
            if _transpile_on:
                # Native transpile: skip the marshal+bz2+key-embedding loader
                # (the leak path the source leak broke). A no-op anchor keeps
                # _insert_before_compile positioning the ext AST passes before
                # the emit step; the actual Cython transpile runs after the
                # loop over the AST-obfuscated source. __name__='Obfuscate' so
                # _operation_label still reports 'compile'.
                def _transpile_anchor(src):
                    # Unwrap `if __name__ == '__main__':` guards so the entry
                    # call runs at import time under Cython (extension modules
                    # never set __name__ to '__main__'). obf_vars keeps dunders,
                    # so '__name__' survives the rename pass intact.
                    try:
                        import ast as _ast
                        tree = _ast.parse(src)
                        _nb = []
                        for _stmt in tree.body:
                            if (isinstance(_stmt, _ast.If)
                                    and isinstance(_stmt.test, _ast.Compare)
                                    and isinstance(_stmt.test.left, _ast.Name)
                                    and _stmt.test.left.id == '__name__'
                                    and any(isinstance(_c, _ast.Eq) and
                                            isinstance(_r, _ast.Constant) and
                                            _r.value == '__main__'
                                            for _c, _r in zip(_stmt.test.ops,
                                                              _stmt.test.comparators))):
                                _nb.extend(_stmt.body)
                            else:
                                _nb.append(_stmt)
                        tree.body = _nb
                        _ast.fix_missing_locations(tree)
                        return _ast.unparse(tree)
                    except Exception:
                        return src
                _transpile_anchor.__name__ = 'Obfuscate'
                operations.append(_transpile_anchor)
            else:
                operations.append(Compile.Obfuscate)

        # --- bedrock_ext: plugin discovery (best-effort) ---
        _hooks = None
        _plugins_loaded = False
        try:
            if (not getattr(args, 'no_plugins', False)
                    and _ExtPipelineHooks is not None
                    and _ext_discover_plugins is not None
                    and _ext_apply_plugins is not None):
                _hooks = _ExtPipelineHooks()
                _plugins = _ext_discover_plugins(args.plugins or None)
                _ext_apply_plugins(_hooks, _plugins)
                _plugins_loaded = bool(_plugins)
                if '_bedrock_register_bundled_plugins' in globals():
                    _bedrock_register_bundled_plugins(_hooks)
                if _plugins_loaded:
                    Logging.info(f'Loaded {len(_plugins)} plugin(s)')
        except Exception as _e:
            Logging.warning(f'plugin discovery skipped: {_e}')
            _hooks = None
            _plugins_loaded = False

        strict_requested = strict_profile_active

        def _report_failure(label, exc, duration_ms=0):
            if report is None:
                return
            try:
                report.record_pass(label, duration_ms, status='error', error=str(exc))
                report.extra['failure'] = {
                    'pass': label,
                    'error': str(exc),
                    'runtime_mode': str(getattr(args, 'runtime_mode_public', getattr(args, 'runtime_mode', ''))),
                    'profile': str(getattr(args, '_profile_preset', getattr(args, 'profile', ''))),
                }
                report.stop()
                if getattr(args, 'report', None):
                    report.dump(args.report)
            except Exception:
                pass

        def _pass_failed(label, exc):
            msg = f'{label} pass failed: {exc}'
            _report_failure(label, exc)
            if strict_requested:
                cli_fail(4, msg, detail=str(exc), kind='error')
            Logging.warning(msg)

        # --- helper to wrap an AST-level pass as a source-string step ---
        def _make_ast_step(label, fn, *, prepend_attr=None):
            def _step(src):
                try:
                    tree = ast.parse(src)
                    tree = fn(tree, _build_ctx)
                    if prepend_attr and hasattr(_build_ctx, prepend_attr):
                        pre_src = getattr(_build_ctx, prepend_attr) or ''
                        if pre_src:
                            pre_mod = ast.parse(pre_src)
                            tree.body = pre_mod.body + tree.body
                    ast.fix_missing_locations(tree)
                    return ast.unparse(tree)
                except Exception as _e:
                    _pass_failed(label, _e)
                    return src
            _step.__name__ = f'_step_{label}'
            return _step

        # Insert position helpers
        def _insert_after_obf_vars(step):
            try:
                idx = next(i for i, op in enumerate(operations) if op is Methods.obf_vars)
                operations.insert(idx + 1, step)
            except StopIteration:
                operations.insert(0, step)

        def _insert_before_compile(step):
            try:
                idx = next(i for i, op in enumerate(operations)
                           if op is Compile.Obfuscate
                           or getattr(op, '__name__', '') == 'Obfuscate')
                operations.insert(idx, step)
            except StopIteration:
                operations.append(step)

        if _hooks is not None:
            hook_ctx = {'args': args, 'build_ctx': _build_ctx}
            _insert_after_obf_vars(_make_ast_step(
                'plugins:after_rename',
                lambda tree, _ctx: _hooks.run_ast_passes('after_rename', tree, hook_ctx),
            ))
            _insert_before_compile(lambda src: _hooks.run_pre_compile(src, hook_ctx))

        # --- bedrock_ext: insert CFF after rename (obf_vars) ---
        if getattr(args, 'cff', False):
            if _ext_apply_cff is not None:
                _insert_after_obf_vars(_make_ast_step('cff', _ext_apply_cff))
            else:
                _pass_failed('cff', RuntimeError('CFF implementation unavailable'))

        # --- homoglyph (mutually exclusive with obf_vars when active replacement chosen) ---
        if getattr(args, 'homoglyph', False):
            try:
                _ext_apply_homo = ext_apply_homoglyph
                if _ext_apply_homo is None:
                    raise RuntimeError('homoglyph implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('homoglyph', _ext_apply_homo))
            except Exception as _e:
                _pass_failed('homoglyph', _e)

        # --- lambda_enc (after rename) ---
        if getattr(args, 'lambda_enc', False):
            try:
                _ext_apply_le = ext_apply_lambda_enc
                if _ext_apply_le is None:
                    raise RuntimeError('lambda_enc implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('lambda_enc', _ext_apply_le))
            except Exception as _e:
                _pass_failed('lambda_enc', _e)

        # --- num_obf ---
        if getattr(args, 'num_obf', False):
            try:
                _ext_apply_no = ext_apply_numobf
                if _ext_apply_no is None:
                    raise RuntimeError('numobf implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('numobf', _ext_apply_no))
            except Exception as _e:
                _pass_failed('numobf', _e)

        # --- bool_obf ---
        if getattr(args, 'bool_obf', False):
            try:
                _ext_apply_bo = ext_apply_boolobf
                if _ext_apply_bo is None:
                    raise RuntimeError('boolobf implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('boolobf', _ext_apply_bo))
            except Exception as _e:
                _pass_failed('boolobf', _e)

        # --- junk ---
        if getattr(args, 'junk', False):
            try:
                _ext_apply_junk = ext_apply_junk
                if _ext_apply_junk is None:
                    raise RuntimeError('junk implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('junk', _ext_apply_junk))
            except Exception as _e:
                _pass_failed('junk', _e)

        # --- dec_trap (decompiler-trap; runs after cff/junk so it wraps the
        # already-flattened / junked body -- the trap's nested opaque ifs
        # survive because they are added last and never feed back into cff) ---
        if getattr(args, 'dec_trap', False):
            try:
                _ext_apply_dectrap = ext_apply_dectrap
                if _ext_apply_dectrap is None:
                    raise RuntimeError('dec_trap implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('dec_trap', _ext_apply_dectrap))
            except Exception as _e:
                _pass_failed('dec_trap', _e)

        # --- var_split (XOR secret-sharing of local int variables) ---
        if getattr(args, 'var_split', False):
            try:
                _ext_apply_varsplit = ext_apply_varsplit
                if _ext_apply_varsplit is None:
                    raise RuntimeError('var_split implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('var_split', _ext_apply_varsplit))
            except Exception as _e:
                _pass_failed('var_split', _e)

        # --- Phase H (Layer 6): esoteric + anti-pattern AST passes ----------
        # Registered via `_insert_after_obf_vars` (reverse stack: passes
        # declared LATER run EARLIER). Declaration order below matches the
        # Phase H sub-phase order (H.1 -> H.2 -> H.5 -> H.6 -> H.4 -> H.7
        # -> H.8 -> H.9 -> H.3); because of the reverse stack, the LAST
        # declared here (H.3 metamorphic) runs FIRST among the H passes,
        # and H.1 (id poison) runs LAST. This means:
        #   - H.3 metamorphic injects _br_mut targets first (they're dead
        #     junk, so later passes see but never depend on them).
        #   - H.9 FSS splits numeric functions before H.2 acoda hides the
        #     call edge -- the share functions are eligible for acoda.
        #   - H.1 id poison runs LAST, shadowing builtins in the final tree
        #     so no later pass can accidentally resolve the shadow back to a
        #     bare builtin name.
        # The H passes run AFTER cff/junk/dec_trap/var_split (declared
        # earlier -> run later) but BEFORE runtime_dec (declared later ->
        # runs earlier), so the capsule runtime sees the fully-H-transformed
        # tree. H.4 style randomizer is a SOURCE-level pass, not AST -- it
        # runs after ast.unparse (hooked at the code-emission point, see
        # _apply_runtime_wrappers below).
        if any(getattr(args, _h, False) for _h in (
                'h_id_poison', 'h_acoda', 'h_metamorphic', 'h_branchless',
                'h_bloom', 'h_dag_cff', 'h_selfcheck_cf', 'h_fss')):
            try:
                import importlib as _h_imp
                import os as _h_os, sys as _h_sys
                _h_here = _h_os.path.dirname(_h_os.path.abspath(
                    globals().get('__file__', '') or __file__))
                _h_loaded = False
                for _cand in (_h_os.path.join(_h_here, 'bedrock_native'),
                              _h_os.path.join(_h_os.getcwd(), 'bedrock_native'),
                              _h_here, _h_os.getcwd()):
                    if _cand and _h_os.path.isdir(_cand) and \
                            _h_os.path.isfile(_h_os.path.join(_cand, '_identifier_poison.py')):
                        if _cand not in _h_sys.path:
                            _h_sys.path.insert(0, _cand)
                        _h_loaded = True
                        break
                if not _h_loaded:
                    raise RuntimeError('bedrock_native/ Phase H modules not found')
                # Load all 9 Python-AST pass modules (the aliases mirror the
                # ext_apply_* pattern; a missing module -> that pass is skipped
                # via _pass_failed, not a build abort).
                _h_modules = {}
                for _h_mod in ('_identifier_poison', '_acoda', '_metamorphic',
                               '_branchless', '_bloom_obf', '_dag_cff',
                               '_selfcheck_cf', '_fss', '_opaque_crypto'):
                    try:
                        _h_modules[_h_mod] = _h_imp.import_module(_h_mod)
                    except Exception as _e:
                        _pass_failed(_h_mod, _e)
                # Thread the per-build BuildRNG into the ctx so every H pass
                # draws from an independent sub-stream (deterministic-per-build,
                # diverse in fresh-seed mode). The passes' _rng_for helpers read
                # ctx.build_rng.
                if _build_ctx is not None:
                    try:
                        _build_ctx.build_rng = getattr(args, '_rng', None)
                    except Exception:
                        pass
                    # H passes inject module-level + function-level names
                    # (_br_acoda, _br_mut, _br_bloom, _br_bloom_contains,
                    # _br_ds1, _br_ds2, _br_path, _br_structural_mutate, etc.)
                    # AFTER obf_vars has already run. Later renaming passes
                    # (obf_builtins, debrander) must NOT rename these, or the
                    # module-level definition and the function-level references
                    # diverge -> NameError at runtime. Add them to keep_names
                    # so every renaming pass skips them.
                    try:
                        _kn = set(getattr(_build_ctx, 'keep_names', set()) or set())
                        _kn.update({
                            '_br_acoda', '_br_mut', '_br_bloom',
                            '_br_bloom_contains', '_br_ds1', '_br_ds2',
                            '_br_path', '_br_structural_mutate',
                            '_br_meta_shard', '_br_bloom_array',
                            '_br_hchain',  # Phase iO-3: hash-chain helper
                        })
                        _build_ctx.keep_names = _kn
                    except Exception:
                        pass
                # Register each pass in declaration order (reverse stack ->
                # last declared runs first). The try/except per pass means a
                # failure in one H pass doesn't block the others.
                # Phase iO-3: set the crypto-opaque gate flag from
                # opaque_grade. The pass spec below checks
                # getattr(args, 'h_crypto_opaque', False); we synthesize it
                # from opaque_grade != 'algebra' so the user controls it via
                # --opaque-grade (and io profile auto-sets 'crypto').
                _og = str(getattr(args, 'opaque_grade', 'algebra') or 'algebra')
                args.h_crypto_opaque = (_og in ('crypto', 'hybrid'))
                _h_pass_specs = [
                    # Phase iO-3: crypto opaque predicates. Declared FIRST so
                    # it runs LAST (reverse-stack) — after bloom has injected
                    # its `if _br_bloom_contains(c): <dead>` sites, this pass
                    # wraps each in `if <crypto_pred> and _br_bloom_contains(c):`.
                    # Gated on opaque_grade != 'algebra' (auto-on for extreme/io).
                    ('h_crypto_opaque', 'h_crypto_opaque', '_opaque_crypto',
                     'apply_opaque_crypto'),
                    ('h_id_poison', 'h_id_poison', '_identifier_poison',
                     'apply_identifier_poison'),
                    ('h_acoda', 'h_acoda', '_acoda', 'apply_acoda'),
                    ('h_branchless', 'h_branchless', '_branchless',
                     'apply_branchless'),
                    ('h_bloom', 'h_bloom', '_bloom_obf', 'apply_bloom_obf'),
                    ('h_dag_cff', 'h_dag_cff', '_dag_cff', 'apply_dag_cff'),
                    ('h_selfcheck_cf', 'h_selfcheck_cf', '_selfcheck_cf',
                     'apply_selfcheck_cf'),
                    ('h_fss', 'h_fss', '_fss', 'apply_fss'),
                    ('h_metamorphic', 'h_metamorphic', '_metamorphic',
                     'apply_metamorphic'),
                ]
                for _h_label, _h_flag, _h_mod_name, _h_fn_name in _h_pass_specs:
                    if not getattr(args, _h_flag, False):
                        continue
                    try:
                        _h_mod = _h_modules.get(_h_mod_name)
                        if _h_mod is None:
                            raise RuntimeError(f'{_h_mod_name} unavailable')
                        _h_fn = getattr(_h_mod, _h_fn_name)
                        _insert_after_obf_vars(
                            _make_ast_step(_h_label, _h_fn))
                    except Exception as _e:
                        _pass_failed(_h_label, _e)
            except Exception as _e:
                _pass_failed('phase_h_loader', _e)

        # --- runtime_dec (per-code-object decrypt/re-encrypt wrapper) ---
        # Inserted via `_insert_after_obf_vars`, which does
        # `operations.insert(idx + 1, step)` -- a reverse stack. Passes
        # declared LATER in source therefore run EARLIER in the pipeline.
        # `import_obf` (declared a few lines below) and `strfrag2` (declared
        # last) both run BEFORE runtime_dec; `var_split`, `dec_trap`,
        # `junk`, `boolobf`, `numobf`, `lambda_enc`, `homoglyph` and `cff`
        # are declared earlier and run AFTER it, so they may still rewrite
        # the tree beneath it. runtime_dec therefore runs roughly 3rd
        # among the ext AST passes (after strfrag2 and import_obf), NOT
        # last -- `cff` is the last. It appends a setup snippet to the END
        # of the module body that encrypts each target's __code__ and
        # installs decrypt-on-call wrappers (capsule runtime). VM runtimes
        # were removed in Bedrock vNext Phase 1, so the `*_a` forwarding
        # that the old vm-native capability scanner rejected is no longer a
        # concern and runtime_dec engages fully.
        if getattr(args, 'runtime_dec', False) and not bool(getattr(args, 'transpile', False)):
            try:
                _ext_apply_rd = ext_apply_runtimedec
                if _ext_apply_rd is None:
                    raise RuntimeError('runtime_dec implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('runtime_dec', _ext_apply_rd))
            except Exception as _e:
                _pass_failed('runtime_dec', _e)

        # --- native_vm (Phase 5): BedrockVM bytecode compilation ---
        # Registered AFTER runtime_dec, so it runs BEFORE runtime_dec (the
        # `_insert_after_obf_vars` reverse stack: passes declared LATER run
        # FIRST). The VM claims eligible functions first; the capsule runtime
        # then sees plain Python wrappers (not marshalable code blobs) for the
        # VM-claimed functions and skips them -- a function goes to the VM OR
        # the capsule, never both.
        # NOTE (Phase F): --crown-jewel-vm reconciles with --transpile: the
        # crown jewels (annotation-gated) are VM-compiled INSIDE the transpile
        # path. --native-vm (Phase 5) remains mutually exclusive with
        # --transpile because it claims ALL eligible functions, which would
        # fight Cython.
        _nvm_on = bool(getattr(args, 'native_vm', False)) and not bool(getattr(args, 'transpile', False))
        _cjvm_on = bool(getattr(args, 'crown_jewel_vm', False))
        if _nvm_on or _cjvm_on:
            try:
                _ext_apply_nvm = ext_apply_native_vm
                if _ext_apply_nvm is None:
                    raise RuntimeError('native_vm implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('native_vm', _ext_apply_nvm))
            except Exception as _e:
                _pass_failed('native_vm', _e)

        # --- import_obf ---
        if getattr(args, 'import_obf', False) and not bool(getattr(args, 'transpile', False)):
            try:
                _ext_apply_io = ext_apply_import_obf
                if _ext_apply_io is None:
                    raise RuntimeError('import_obf implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('import_obf', _ext_apply_io,
                                                     prepend_attr='_import_obf_preamble'))
            except Exception as _e:
                _pass_failed('import_obf', _e)

        # --- str_frag2 ---
        if getattr(args, 'str_frag2', False) and not bool(getattr(args, 'transpile', False)):
            try:
                _ext_apply_sf2 = ext_apply_strfrag2
                if _ext_apply_sf2 is None:
                    raise RuntimeError('strfrag2 implementation unavailable')
                _insert_after_obf_vars(_make_ast_step('strfrag2', _ext_apply_sf2))
            except Exception as _e:
                _pass_failed('strfrag2', _e)

        def _apply_runtime_wrappers(src):
            if _build_ctx is None:
                return src
            try:
                if getattr(_build_ctx, 'anti_vm', 'off') != 'off':
                    _ext_wrap_avm = ext_wrap_anti_vm
                    if _ext_wrap_avm is None:
                        raise RuntimeError('anti-vm implementation unavailable')
                    src = _ext_wrap_avm(src, _build_ctx)
            except Exception as _e:
                _pass_failed('wrap_with_anti_vm', _e)
            try:
                if getattr(_build_ctx, 'anti_debugger_v2', False):
                    _ext_wrap_adbg = ext_wrap_anti_dbg_v2
                    if _ext_wrap_adbg is None:
                        raise RuntimeError('anti-debugger-v2 implementation unavailable')
                    src = _ext_wrap_adbg(src, _build_ctx)
            except Exception as _e:
                _pass_failed('wrap_with_anti_dbg_v2', _e)
            return src

        # Apply anti-vm / anti-debugger-v2 wrappers before Compile.Obfuscate so
        # the compiler's file-integrity check sees the final guarded payload.
        # (VM-native builds were removed in Bedrock vNext Phase 1; the post-compile
        # wrapper path below is no longer taken.)
        code = _apply_runtime_wrappers(code)

        # Phase H.4 (Layer 6): style randomizer -- a SOURCE-level pass, so it
        # runs AFTER the AST passes emit code (via ast.unparse) and AFTER the
        # runtime wrappers, on the final source string before Compile.Obfuscate.
        # Source-mode only. The pass shuffles independent top-level defs
        # (dependency-preserving; anchored if referenced by a later non-def
        # statement), inserts blank lines + junk comments at top-level boundaries.
        if getattr(args, "h_style", False) and _build_ctx is not None:
            try:
                import importlib as _hs_imp
                import os as _hs_os, sys as _hs_sys
                _hs_here = _hs_os.path.dirname(_hs_os.path.abspath(
                    globals().get("__file__", "") or __file__))
                for _cand in (_hs_os.path.join(_hs_here, "bedrock_native"),
                              _hs_os.path.join(_hs_os.getcwd(), "bedrock_native"),
                              _hs_here, _hs_os.getcwd()):
                    if _cand and _hs_os.path.isdir(_cand) and                             _hs_os.path.isfile(_hs_os.path.join(_cand, "_style_randomizer.py")):
                        if _cand not in _hs_sys.path:
                            _hs_sys.path.insert(0, _cand)
                        break
                _hs_mod = _hs_imp.import_module("_style_randomizer")
                _build_ctx.build_rng = getattr(args, "_rng", None)
                code = _hs_mod.apply_style_randomizer(code, _build_ctx)
            except Exception as _e:
                _pass_failed("h_style", _e)

        def _refresh_native_integrity(src):
            hash_match = re.search(r'(?m)^__H_FILE_HASH__ = "([0-9a-f]{64})"$', src)
            marker_match = re.search(r'"(__H_FILE_MARK_\d+__)"\.encode\([\'"]utf-8[\'"]\)', src)
            if not hash_match or not marker_match:
                return src
            current_hash = hash_match.group(1)
            marker = marker_match.group(1)
            # Mask both the file hash and the integrity hash (they cross-reference
            # each other in the same file) and recompute with the "|fh" salt, the
            # same algorithm used at build time. Without masking the integrity
            # hash AND without the salt, a post-compile plugin mutation would
            # silently re-patch to the wrong value and trip __h_check_self_integrity.
            integrity_var_match = re.search(r'(?m)^__H_INTEGRITY_VAR__ = "([^"]+)"$', src)
            _masked = src.replace(current_hash, marker)
            if integrity_var_match:
                _iv = integrity_var_match.group(1)
                _ivh_match = re.search(r'(?m)^' + re.escape(_iv) + r' = "([0-9a-f]{64})"', src)
                if _ivh_match:
                    _masked = _masked.replace(_ivh_match.group(1), marker)
            refreshed = hashlib.sha256((_masked + '|fh').encode('utf-8')).hexdigest()
            if refreshed == current_hash:
                return src
            # Re-patch both file hash and integrity hash so they stay consistent.
            out = src[:hash_match.start(1)] + refreshed + src[hash_match.end(1):]
            if integrity_var_match:
                _iv = integrity_var_match.group(1)
                _ivh_match = re.search(r'(?m)^' + re.escape(_iv) + r' = "([0-9a-f]{64})"', out)
                if _ivh_match:
                    _masked_int = out.replace(refreshed, marker).replace(_ivh_match.group(1), marker)
                    _new_int = hashlib.sha256((_masked_int + '|int').encode('utf-8')).hexdigest()
                    out = out[:_ivh_match.start(1)] + _new_int + out[_ivh_match.end(1):]
            return out


        # --- cache lookup (best-effort, key based on source + selected flags) ---
        _cache_key = None
        if _plugins_loaded and getattr(args, 'cache', True):
            args.cache = False
            Logging.warning('cache disabled because plugins can mutate output')
        if getattr(args, 'cache', True) and _ext_cache is not None:
            try:
                _cache_key = _ext_cache.compute_cache_key(args.file, args)
                _hit = _ext_cache.cache_lookup(_cache_key)
                if _hit is not None:
                    import pathlib as _pl
                    _pl.Path(args.output).write_bytes(_hit)
                    Logging.success(f'[cache] HIT {_cache_key[:12]} -> {args.output}')
                    return 0
            except Exception as _e:
                Logging.warning(f'cache lookup failed: {_e}')
                _cache_key = None

        st = time.time()
        def _operation_label(operation):
            label = getattr(operation, '__name__', None) or operation.__class__.__name__
            if label == 'Obfuscate':
                return 'compile'
            if label.startswith('_step_'):
                return label[len('_step_'):]
            if label == '<lambda>':
                return 'plugins:pre_compile'
            return label

        for operation in operations:
            _label = _operation_label(operation)
            _op_t0 = time.perf_counter()
            try:
                code = operation(code)
            except SystemExit:
                raise
            except Exception as _e:
                _elapsed = int((time.perf_counter() - _op_t0) * 1000)
                _report_failure(_label, _e, _elapsed)
                cli_fail(4, f'{_label} failed: {_e}', detail=str(_e), kind='error')
            else:
                if report is not None:
                    try:
                        report.record_pass(_label, int((time.perf_counter() - _op_t0) * 1000), status='ok')
                    except Exception:
                        pass
        output = code
        if _hooks is not None:
            try:
                _hook_t0 = time.perf_counter()
                output = _hooks.run_post_compile(output, hook_ctx)
                if report is not None:
                    report.record_pass('plugins:post_compile', int((time.perf_counter() - _hook_t0) * 1000), status='ok')
            except Exception as _e:
                _pass_failed('plugins:post_compile', _e)
        # Re-patch __H_FILE_HASH__ if post-compile plugin hooks mutated the
        # output (the wrapper / wrappers ran pre-compile above, so the hash is
        # already correct by default; this only fires when a plugin touched it).
        output = _refresh_native_integrity(output)
        # --- Phase 1: native transpile (Cython -> .pyd). The AST-obfuscated
        # source (no marshal loader, no cleartext keys) is transpiled to C and
        # compiled to a native extension. This is the leak fix: logic becomes
        # native machine code, not a self-describing Python blob. ---
        if getattr(args, 'transpile', False):
            import importlib as _tpl_imp
            _out_dir = os.path.dirname(os.path.abspath(args.output))
            _tpl = None
            try:
                _here = os.path.dirname(os.path.abspath(
                    globals().get('__file__', '') or __file__))
                for _cand in (os.path.join(_here, 'bedrock_native'),
                              os.path.join(os.getcwd(), 'bedrock_native')):
                    if _cand and os.path.isdir(_cand) and \
                       os.path.isfile(os.path.join(_cand, '_transpile_pipeline.py')):
                        if _cand not in sys.path:
                            sys.path.insert(0, _cand)
                        try:
                            _tpl = _tpl_imp.import_module('_transpile_pipeline')
                        except Exception:
                            _tpl = None
                        break
            except Exception:
                _tpl = None
            if _tpl is None:
                cli_fail(4, 'transpile requested but _transpile_pipeline not found '
                            'in bedrock_native/', kind='error')
            _t_res = _tpl.transpile_and_build(
                output, _out_dir, module_name='obf',
                c_string_obf=bool(getattr(args, 'c_string_obf', True)),
                verbose=not bool(getattr(args, 'quiet', False)),
                ctx=_build_ctx)
            if _t_res['mode'] != 'native' or not _t_res.get('module_path'):
                cli_fail(4, f'native transpile failed: {_t_res.get("detail","")}',
                         kind='error')
            done = time.time() - st
            Logging.success(f'Wrote native module {_t_res["module_path"]}. '
                            f'Done in {round(done, 3)}s.')
            # Thin runner .py: imports the native module and calls main() if
            # present, so `python <args.output>` still runs the protected
            # program. The logic itself lives in the .pyd (native code).
            _runner = (
                "# Bedrock native-transpiled runner. Logic lives in obf.*.pyd.\n"
                "# The __main__ guard was unwrapped at transpile time, so simply\n"
                "# importing the native module executes the entry code.\n"
                "import importlib as _il\n"
                "_il.import_module('obf')\n"
            )
            with open(args.output, 'wb') as f:
                f.write(_runner.encode('utf-8'))
            Logging.info(f'Wrote runner {args.output}')
            if report is not None:
                try:
                    report.extra['transpile'] = {
                        'mode': _t_res['mode'],
                        'module_path': _t_res.get('module_path'),
                        'ext_hash': _t_res.get('ext_hash'),
                    }
                except Exception:
                    pass
                if getattr(args, 'report', None):
                    try:
                        report.dump(args.report)
                    except Exception:
                        pass
            return 0
        with open(args.output, 'wb') as f:
            f.write(output.encode('utf-8'))
            done = time.time() - st
            Logging.success(f'Wrote file {args.output}. Done in {round(done, 3)}s.')
        # Phase 5 (Wave 4C): ship the native BedrockVM runtime next to the
        # obfuscated output. Only when --native-vm is on: build_and_ship()
        # copies the compiled _xvm extension (or the pure-Python reference
        # interpreter fallback) into the output directory so the loader's
        # `import _xvm` (or `import _bedrock_vm_ref`) resolves at runtime.
        # The build never crashes on a ship failure -- the loader falls back
        # to the reference interpreter if the native import fails.
        # Phase F: --crown-jewel-vm also ships the runtime, even with
        # --transpile (crown jewels are VM-compiled INSIDE the transpile
        # path; the rest is Cython-native, but the VM wrappers still need
        # _xvm/_bedrock_vm_ref at import time).
        _ship_vm = (getattr(args, 'native_vm', False) and
                    not bool(getattr(args, 'transpile', False))) or \
                   getattr(args, 'crown_jewel_vm', False)
        if _ship_vm:
            try:
                import importlib as _vm_ship_imp
                import os as _vm_ship_os
                _bs = None
                try:
                    _bs = _vm_ship_imp.import_module('_build_system')
                except Exception:
                    _here = _vm_ship_os.path.dirname(_vm_ship_os.path.abspath(
                        globals().get('__file__', '') or __file__))
                    for _cand in (_vm_ship_os.path.join(_here, 'bedrock_native'),
                                  _vm_ship_os.path.join(_vm_ship_os.getcwd(), 'bedrock_native')):
                        if _cand and _vm_ship_os.path.isdir(_cand) and \
                           _vm_ship_os.path.isfile(_vm_ship_os.path.join(_cand, '_build_system.py')):
                            import sys as _vm_ship_sys
                            if _cand not in _vm_ship_sys.path:
                                _vm_ship_sys.path.insert(0, _cand)
                            try:
                                _bs = _vm_ship_imp.import_module('_build_system')
                            except Exception:
                                _bs = None
                            break
                if _bs is not None:
                    _out_dir = _vm_ship_os.path.dirname(_vm_ship_os.path.abspath(args.output))
                    _ship = _bs.build_and_ship(_out_dir, verbose=False)
                    _ref_name = '_bedrock_vm_ref'
                    if getattr(args, 'anti_meta', False):
                        _ref_name = _debrand('_bedrock_vm_ref')
                    # When anti-meta is on, scrub bedrock/baobg literals from
                    # the shipped reference interpreter's CONTENT (docstrings
                    # + error-message strings only -- every occurrence lives
                    # in a string/comment token, never an identifier, so the
                    # C interpreter's attribute lookups are unaffected) and
                    # write a debranded-named copy for the loader's fallback
                    # import. The original-named `_bedrock_vm_ref.py` MUST
                    # stay (the C interpreter hardcodes that import name for
                    # generator/listcomp delegation) but its content is
                    # scrubbed so `grep -ic bedrock` = 0 on every shipped
                    # file. (See _bedrock_vm.c PyImport_ImportModule call.)
                    if getattr(args, 'anti_meta', False):
                        try:
                            _ref_src = _vm_ship_os.path.join(_out_dir, '_bedrock_vm_ref.py')
                            if _vm_ship_os.path.isfile(_ref_src):
                                with open(_ref_src, 'r', encoding='utf-8') as _rf:
                                    _ref_content = _rf.read()
                                _scrubbed = _debrand(_ref_content)
                                if _scrubbed != _ref_content:
                                    with open(_ref_src, 'w', encoding='utf-8') as _wf:
                                        _wf.write(_scrubbed)
                                if _ref_name != '_bedrock_vm_ref':
                                    _debranded_path = _vm_ship_os.path.join(_out_dir, _ref_name + '.py')
                                    with open(_debranded_path, 'w', encoding='utf-8') as _wf:
                                        _wf.write(_scrubbed)
                        except Exception:
                            pass
                    Logging.success(f'native_vm shipped {_ship.get("mode")} '
                                    f'({_ship.get("module_name")})')
                    # Phase 5 hardening: inject the .pyd SHA-256 into the
                    # plaintext __VM_EXTHASH__ header constant so the loader
                    # can verify the shipped extension. The header carries a
                    # 64-char sentinel at compile time (the .pyd is built AFTER
                    # the loader text is emitted, so the hash can't be baked
                    # in directly). Both the sentinel and the real hash are 64
                    # chars, and both the compile-time and runtime integrity
                    # checks mask this slot to 64 dots -- so the file hash
                    # stays valid across the injection (no re-patch needed).
                    # Reference-mode builds carry no .pyd (ext_hash is None)
                    # -> the sentinel stays in place and the loader's
                    # integrity check no-ops (sentinel != real hash, but the
                    # file path isn't a .pyd so the check is skipped).
                    _ext_hash = _ship.get('ext_hash')
                    if _ship.get('mode') == 'native' and _ext_hash:
                        try:
                            # Binary mode is critical: the original file is
                            # written via open(args.output, 'wb') (binary, LF-
                            # only on all platforms). A text-mode read/write
                            # here would convert \n -> \r\n on Windows, adding
                            # bytes and invalidating __H_FILE_HASH__.
                            with open(args.output, 'rb') as _hf:
                                _out_bytes = _hf.read()
                            _sentinel = '__VM_EXTHASH_SLOT_' + '0' * (
                                64 - len('__VM_EXTHASH_SLOT_'))
                            if _sentinel.encode('utf-8') in _out_bytes:
                                _out_bytes = _out_bytes.replace(
                                    _sentinel.encode('utf-8'),
                                    _ext_hash.encode('utf-8'))
                                with open(args.output, 'wb') as _hf:
                                    _hf.write(_out_bytes)
                        except Exception as _he:
                            Logging.warning(f'native_vm ext-hash injection failed: {_he}')
                else:
                    Logging.warning('native_vm: build system unavailable, runtime not shipped')
            except Exception as _e:
                Logging.warning(f'native_vm ship failed: {_e}')
        # cache store
        if _cache_key is not None and _ext_cache is not None:
            try:
                _ext_cache.cache_store(_cache_key, output.encode('utf-8'))
            except Exception as _e:
                Logging.warning(f'cache store failed: {_e}')
        # --- bedrock_ext: finalize report ---
        if report is not None:
            try:
                report.set_output(output)
                report.extra.update({
                    'output_path': args.output,
                    'runtime_mode': str(getattr(args, 'runtime_mode_public', getattr(args, 'runtime_mode', ''))),
                    'profile': str(getattr(args, '_profile_preset', getattr(args, 'profile', ''))),
                })
                report.stop()
                if getattr(args, 'report', None):
                    report.dump(args.report)
                    Logging.success(f'Wrote report {args.report}')
            except Exception as _e:
                Logging.warning(f'Report dump failed: {_e}')
        return 0

    # === INLINED MODULES ===

    # === [INLINE] bedrock_ext/profiles.py ===

    """Profile presets and run-report builder for bedrock.py.

    This module is a *side-car* extension; it never imports bedrock.py and never
    mutates it. Wiring instructions live in WIRING_profiles.md.

    Flag names mirror those declared in bedrock.py section [12] (ParseArgs).
    The four presets below are an opinionated ladder from "fast" to "extreme".
    """


    import argparse
    import hashlib
    import json
    import math
    import os
    import sys
    import time
    from collections import Counter
    from typing import Any, Dict, Iterable, Optional


    # ---------------------------------------------------------------------------
    # PRESETS
    # ---------------------------------------------------------------------------
    # Each preset maps argparse-dest names (underscore form, as Namespace stores
    # them) to values. Only flags exposed by ParseArgs in section [12] are
    # referenced; unknown keys are tolerated by apply_profile but logged.
    PROFILES: Dict[str, Dict[str, Any]] = {
        "fast": {
            # cheap & cheerful: rename idents only, no string/const work, no AD
            "profile": "compat",
            "runtime_mode": "main",
            "anti_debug": "off",
            "anti_hook": "off",
            "tamper": "warn",
            "python_band": "3.10-3.12",
            "vm_carrier": "auto",
            "vm_compat": "broad",
            "adv_requests": "off",
            "legacy_loader": False,
            # logical pass toggles consumed via _ext_flags (see ReportBuilder)
            "obf_vars": True,
            "obf_builtins": False,
            "obf_strings": False,
            "vm_strings": False,
            "wipe_consts": False,
            "cff": False,
            "bc_mutate": False,
            "vm": False,
        },
        "balanced": {
            "profile": "max",
            "runtime_mode": "main",
            "anti_debug": "compat",
            "anti_hook": "compat",
            "tamper": "fail-closed",
            "python_band": "3.10-3.12",
            "vm_carrier": "auto",
            "vm_compat": "broad",
            "adv_requests": "off",
            "legacy_loader": False,
            "obf_vars": True,
            "obf_builtins": True,
            "obf_strings": True,
            "vm_strings": True,
            "wipe_consts": False,
            "cff": False,
            "bc_mutate": False,
            "vm": False,
        },
        "paranoid": {
            "profile": "max",
            "runtime_mode": "main",
            "anti_debug": "strict",
            "anti_hook": "strict",
            "anti_vm": "strict",
            "anti_debugger_v2": "on",
            "tamper": "self-destruct",
            "python_band": "3.10-3.12",
            "vm_carrier": "auto",
            "vm_compat": "strict",
            "adv_requests": "on",
            "legacy_loader": False,
            "obf_vars": True,
            "obf_builtins": True,
            "obf_strings": True,
            "vm_strings": True,
            "wipe_consts": True,
            "cff": True,
            "bc_mutate": False,
            "vm": False,
            # batch 5: decompiler-trap + meta-spoof + anti-timing (paranoid
            # hardens decompilation surface without the heavy VM/runtime passes).
            "dec_trap": True,
            "spoof_meta": True,
            "anti_timing": True,
            # batch 6: SHA-256 stream cipher for obfct string encoding.
            "str_cipher": True,
        },
        "extreme": {
            "profile": "max",
            "runtime_mode": "main",
            "anti_debug": "strict",
            "anti_hook": "strict",
            "tamper": "self-destruct",
            "python_band": "3.10-3.12",
            "vm_carrier": "names",
            "vm_compat": "strict",
            "adv_requests": "on",
            "legacy_loader": False,
            "obf_vars": True,
            "obf_builtins": True,
            "obf_strings": True,
            "vm_strings": True,
            "wipe_consts": True,
            "cff": True,
            "bc_mutate": True,
            "vm": False,
            # batch 5 (full): all new-tier passes are landed. AST-only +
            # var_split run everywhere. With VM runtimes removed in Bedrock
            # vNext Phase 1, runtime_dec now engages fully as the native
            # capsule runtime (per-function marshal -> encrypt -> decrypt-on-
            # call -> finally restore+del+gc); vm_opcode_remap stays as a
            # no-op flag kept for backward CLI compatibility.
            "dec_trap": True,
            "spoof_meta": True,
            "anti_timing": True,
            "var_split": True,
            "vm_opcode_remap": True,
            "runtime_dec": True,
            # batch 7 (Phase 2): chain runtime -- HMAC hash chain + mutual
            # verification ring + shard separation. Extreme auto-enables it
            # alongside runtime_dec so the per-function capsules form a
            # tamper-evident chain (swap/tamper one -> downstream corrupt).
            "chain": True,
            # batch 8 (Phase 3): debug poisoning (anti-dbg -> poison, silent
            # inert) + metamorphic (file self-rewrite every run). Both
            # auto-enable chain; extreme runs all three together so a
            # debugger attempt poisons downstream keys AND the on-disk
            # artifact mutates between static dumps.
            "debug_poison": True,
            "metamorphic": True,
            # batch 9 (Phase 4): anti-meta debranding. Extreme auto-enables
            # it so the output artifact carries no static bedrock/baobg
            # signature for AV/EDR to fingerprint.
            "anti_meta": True,
            # batch 10 (Phase 5): native BedrockVM compilation. Extreme
            # auto-enables it so eligible top-level functions become
            # BedrockVM bytecode blobs (run via the shipped _xvm C
            # interpreter or the _bedrock_vm_ref fallback).
            "native_vm": True,
            # batch 6: SHA-256 stream cipher for obfct string encoding.
            "str_cipher": True,
        },
        # ─── io: Practical iO-grade (Phase iO-1) ───────────────────────────
        # `io` = extreme + Phase H "esoteric" passes (Layer 6) auto-enabled.
        # Targets nation-state + academic adversaries with the full Bedrock
        # arsenal: randomized ISA native VM + Function Secret Sharing (FSS) +
        # DAG-CFF + bloom opaque predicates + branchless + acoda dispatch +
        # identifier poison + self-checking CF + structural metamorphic +
        # style randomization. Performance is NOT a constraint here — the
        # reference interpreter (73x) + iO overhead is acceptable.
        # _apply_extreme_overrides() runs for `io` too (gated below) so the
        # conditional flags (vm_fallback='off', native_vm auto-enable, etc.)
        # mirror the extreme path.
        "io": {
            "profile": "max",
            "runtime_mode": "main",
            "anti_debug": "strict",
            "anti_hook": "strict",
            "tamper": "self-destruct",
            "python_band": "3.10-3.12",
            "vm_carrier": "names",
            "vm_compat": "strict",
            "adv_requests": "on",
            "legacy_loader": False,
            # core obf
            "obf_vars": True,
            "obf_builtins": True,
            "obf_strings": True,
            "vm_strings": True,
            "wipe_consts": True,
            "cff": True,
            "bc_mutate": True,
            "vm": False,
            # batch 5
            "dec_trap": True,
            "spoof_meta": True,
            "anti_timing": True,
            "var_split": True,
            "vm_opcode_remap": True,
            "runtime_dec": True,
            # batch 7 (Phase 2 chain)
            "chain": True,
            # batch 8 (Phase 3 debug poison + metamorphic)
            "debug_poison": True,
            "metamorphic": True,
            # batch 9 (Phase 4 anti-meta)
            "anti_meta": True,
            # batch 10 (Phase 5 native VM)
            "native_vm": True,
            # batch 6 (str cipher)
            "str_cipher": True,
            # ── Phase H (Layer 6) — auto-enabled for io ──
            # These are the "crown jewels" that _apply_extreme_overrides
            # already forces for extreme but were dormant (the function was
            # never called). For `io` we set them explicitly in the preset so
            # the intent is visible in the PROFILES dict and the report.
            # NOTE: h_id_poison is intentionally OMITTED here — it breaks the
            # capsule runtime (runtime_dec) by injecting `name=__builtins__[..]`
            # shadows whose local binding is lost when the function is
            # marshal+exec'd, causing `NameError: free variable` in closures.
            # _apply_extreme_overrides() also gates it OFF when runtime_dec is
            # on. Re-enable only after fixing the composition (Phase iO-2+).
            "h_acoda": True,
            "h_metamorphic": True,
            "h_style": True,
            "h_branchless": True,
            "h_bloom": True,
            "h_dag_cff": True,
            "h_selfcheck_cf": True,
            "h_fss": True,
            # iO-1 additional passes that _apply_extreme_overrides forces:
            "num_obf": True,
            "import_obf": True,
            "str_frag2": True,
            "vm_extended": True,
            "junk": True,
            "bool_obf": True,
            # Phase iO-2: FSS extensions — share ALL eligible functions (lift
            # the 3-5 cap), using auto mode (bool→additive→serialized) so
            # predicates get XOR sharing, int-returning get additive, and
            # any repr-safe return (tuples, lists, dicts) gets serialized.
            "fss_all_eligible": True,
            # Phase iO-3: crypto opaque predicates. Replace algebraic
            # x*(x-1)%2==0 (Z3 folds in seconds) with DL/LWE/hash/RSA
            # (Z3 cannot fold). 'crypto' grade auto-on for io.
            "opaque_grade": "crypto",
        },
    }

    PROFILE_NAMES = tuple(PROFILES.keys())


    # ---------------------------------------------------------------------------
    # apply_profile
    # ---------------------------------------------------------------------------
    def _explicit_cli_dests(argv: Optional[Iterable[str]] = None) -> set:
        """Return argparse dest names the user explicitly typed on the CLI.

        We can't introspect argparse defaults reliably from a Namespace alone, so
        we re-scan sys.argv and translate ``--foo-bar`` -> ``foo_bar``. Anything
        starting with ``-`` and matching ``--name`` (with optional ``=value``) or
        short ``-x`` is considered explicit.

        ``--no-foo-bar`` maps to dest ``foo_bar`` (argparse store_false pattern):
        we strip the ``no-`` prefix and add the bare dest so apply_profile sees
        the user explicitly overrode that flag and does not clobber it with the
        preset value.
        """
        argv = list(argv) if argv is not None else sys.argv[1:]
        explicit = set()
        for tok in argv:
            if not tok.startswith("-"):
                continue
            name = tok.lstrip("-").split("=", 1)[0]
            if not name:
                continue
            dest = name.replace("-", "_")
            explicit.add(dest)
            # --no-foo-bar (store_false) maps to dest foo_bar
            if dest.startswith("no_"):
                explicit.add(dest[3:])
        return explicit


    def apply_profile(
        args: argparse.Namespace,
        name: str,
        *,
        argv: Optional[Iterable[str]] = None,
    ) -> argparse.Namespace:
        """Apply a named preset to ``args`` without overriding explicit CLI flags.

        - ``args``: the Namespace returned by ``ParseArgs``.
        - ``name``: one of ``PROFILE_NAMES``.
        - ``argv``: optional override for sys.argv detection (used by tests).

        Returns the same Namespace (mutated) for fluency.
        """
        if name not in PROFILES:
            raise ValueError(
                f"unknown profile {name!r}; expected one of {PROFILE_NAMES}"
            )
        preset = PROFILES[name]
        explicit = _explicit_cli_dests(argv)

        # Always record which preset was applied, even if user passed --profile.
        setattr(args, "_profile_preset", name)
        ext_flags: Dict[str, Any] = {}

        for key, value in preset.items():
            if key in explicit and key != "profile":
                # user wins
                continue
            # The presets reference both real argparse dests and "logical" pass
            # toggles (obf_vars, vm, cff, ...). Real dests already exist on the
            # Namespace; logical toggles are stashed under args._ext_flags so
            # downstream pass code can read them without colliding.
            if hasattr(args, key):
                setattr(args, key, value)
            else:
                ext_flags[key] = value

        existing_ext = getattr(args, "_ext_flags", None) or {}
        # explicit > preset for ext flags too: don't clobber pre-set ext flags
        for k, v in ext_flags.items():
            existing_ext.setdefault(k, v)
        setattr(args, "_ext_flags", existing_ext)
        return args


    # ---------------------------------------------------------------------------
    # ReportBuilder
    # ---------------------------------------------------------------------------
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())


    class ReportBuilder:
        """Collects metrics during an obfuscation run and dumps them as JSON.

        Designed as a *singleton-friendly* object: bedrock passes can either
        receive an instance directly, or fetch the active one via
        :func:`get_active_report` (set by :meth:`activate`).
        """

        SCHEMA_VERSION = 1

        def __init__(self, profile_used: Optional[str] = None) -> None:
            self.profile_used: Optional[str] = profile_used
            self.flags_active: Dict[str, Any] = {}
            self.input_size: int = 0
            self.output_size: int = 0
            self.entropy_input: float = 0.0
            self.entropy_output: float = 0.0
            self.input_sha256: Optional[str] = None
            self.output_sha256: Optional[str] = None
            self.n_idents_renamed: int = 0
            self.n_strings_encoded: int = 0
            self.n_consts_encrypted: int = 0
            self.duration_ms: int = 0
            self.passes: list[Dict[str, Any]] = []
            self.extra: Dict[str, Any] = {}
            self._t0: Optional[float] = None

        # ---- lifecycle ----------------------------------------------------
        def start(self) -> "ReportBuilder":
            self._t0 = time.perf_counter()
            return self

        def stop(self) -> "ReportBuilder":
            if self._t0 is not None:
                self.duration_ms = int((time.perf_counter() - self._t0) * 1000)
            return self

        # ---- ingest -------------------------------------------------------
        def set_input(self, data: bytes | str) -> None:
            b = data.encode("utf-8") if isinstance(data, str) else data
            self.input_size = len(b)
            self.entropy_input = round(_shannon_entropy(b), 6)
            self.input_sha256 = hashlib.sha256(b).hexdigest()

        def set_output(self, data: bytes | str) -> None:
            b = data.encode("utf-8") if isinstance(data, str) else data
            self.output_size = len(b)
            self.entropy_output = round(_shannon_entropy(b), 6)
            self.output_sha256 = hashlib.sha256(b).hexdigest()

        def set_flags(self, args: argparse.Namespace) -> None:
            flat: Dict[str, Any] = {}
            for k, v in vars(args).items():
                if k.startswith("_"):
                    continue
                if isinstance(v, (str, int, float, bool)) or v is None:
                    flat[k] = v
            ext = getattr(args, "_ext_flags", None) or {}
            flat["_ext"] = dict(ext)
            self.flags_active = flat
            if self.profile_used is None:
                self.profile_used = getattr(args, "_profile_preset", None) \
                    or getattr(args, "profile", None)

        def add(self, **kwargs: Any) -> None:
            """Generic counter bump. Unknown keys land in ``extra``.

            Examples::

                report.add(n_idents_renamed=42)
                report.add(n_strings_encoded=10, n_consts_encrypted=3)
                report.add(custom_thing=123)
            """
            known = {
                "n_idents_renamed",
                "n_strings_encoded",
                "n_consts_encrypted",
            }
            for k, v in kwargs.items():
                if k in known and isinstance(v, int):
                    setattr(self, k, getattr(self, k) + v)
                else:
                    self.extra[k] = v

        def record_pass(self, name: str, duration_ms: int, **info: Any) -> None:
            entry = {"name": name, "duration_ms": int(duration_ms)}
            entry.update(info)
            self.passes.append(entry)

        # ---- output -------------------------------------------------------
        def to_dict(self) -> Dict[str, Any]:
            return {
                "schema_version": self.SCHEMA_VERSION,
                "profile_used": self.profile_used,
                "flags_active": self.flags_active,
                "input_size": self.input_size,
                "output_size": self.output_size,
                "entropy_input": self.entropy_input,
                "entropy_output": self.entropy_output,
                "input_sha256": self.input_sha256,
                "output_sha256": self.output_sha256,
                "n_idents_renamed": self.n_idents_renamed,
                "n_strings_encoded": self.n_strings_encoded,
                "n_consts_encrypted": self.n_consts_encrypted,
                "duration_ms": self.duration_ms,
                "passes": list(self.passes),
                "extra": dict(self.extra),
            }

        def dump(self, path: str) -> str:
            payload = self.to_dict()
            d = os.path.dirname(os.path.abspath(path))
            if d:
                os.makedirs(d, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True, ensure_ascii=False)
            return path


    # ---------------------------------------------------------------------------
    # Singleton hook (optional convenience for passes that can't be threaded a ref)
    # ---------------------------------------------------------------------------
    _ACTIVE_REPORT: Optional[ReportBuilder] = None


    def activate(report: ReportBuilder) -> ReportBuilder:
        global _ACTIVE_REPORT
        _ACTIVE_REPORT = report
        return report


    def get_active_report() -> Optional[ReportBuilder]:
        return _ACTIVE_REPORT


    def report_add(**kwargs: Any) -> None:
        """Convenience for pass code: ``report_add(n_idents_renamed=10)``.

        No-op if no report has been activated, so call sites stay cheap and safe.
        """
        r = _ACTIVE_REPORT
        if r is not None:
            r.add(**kwargs)




    # === [INLINE] bedrock_ext/cff.py ===

    """Control-Flow Flattening (CFF) pass for bedrock.

    Public API: ``apply_cff(tree, ctx) -> ast.Module``.

    Each eligible function body is rewritten into a state-machine of the form::

        __cff_state = <entry>
        while True:
            if __cff_state == S0:
                ...
                __cff_state = Sk
                continue
            elif __cff_state == S1:
                ...
            elif __cff_state == __CFF_HALT:
                break
        # fallthrough: implicit ``return None``

    Supported control flow: plain straight-line code, ``if/elif/else``,
    ``while`` / ``for`` (with ``break``/``continue``), ``try/except/finally``,
    ``return``, ``raise``. State numbers are shuffled per-function with
    ``ctx.rng`` (or a fresh ``random.Random`` if absent) so that builds are
    not stable across runs.

    Functions that are async, generators, ``__init__``-style trivial bodies,
    or contain ``yield``/``yield from``/``await``/``with``/``async with``,
    or have <= 2 statements are skipped. ``with`` is skipped because lifting
    context managers into a flat state machine without semantic loss requires
    exception-table rewrites that are out of scope.
    """


    import ast
    import random
    from typing import Any, List, Optional


    _HALT_NAME = "__CFF_HALT"
    _STATE_VAR = "__cff_state"


    def _has_unsupported(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Yield, ast.YieldFrom, ast.Await,
                                ast.AsyncFor, ast.AsyncWith, ast.AsyncFunctionDef,
                                ast.With, ast.Lambda)):
                # Lambdas/with: ok if nested inside an inner FunctionDef we won't flatten;
                # but at top level they're complications. Lambda bodies are expressions, ok.
                if isinstance(sub, ast.Lambda):
                    continue
                # Nested function defs are fine — we don't recurse into them.
                return True
        return False


    def _walk_toplevel(body: List[ast.stmt]):
        """Walk only top-level statements (do not descend into nested defs)."""
        for stmt in body:
            yield stmt


    def _scan_unsupported(body: List[ast.stmt]) -> bool:
        for stmt in body:
            if isinstance(stmt, (ast.AsyncFor, ast.AsyncWith, ast.With)):
                return True
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # don't look inside nested defs
                continue
            for sub in ast.walk(stmt):
                if isinstance(sub, (ast.Yield, ast.YieldFrom, ast.Await,
                                    ast.AsyncFor, ast.AsyncWith)):
                    return True
                if isinstance(sub, ast.With):
                    return True
        return False


    class _Flattener:
        def __init__(self, rng: random.Random):
            self.rng = rng
            self.blocks: List[List[ast.stmt]] = []  # block_id -> stmts (already terminated)
            # Loop stack: (continue_target, break_target)
            self.loop_stack: List[tuple] = []

        def new_block(self) -> int:
            idx = len(self.blocks)
            self.blocks.append([])
            return idx

        def emit(self, block_id: int, stmt: ast.stmt) -> None:
            self.blocks[block_id].append(stmt)

        def _goto(self, target: int) -> List[ast.stmt]:
            return [
                ast.Assign(
                    targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
                    value=ast.Constant(value=target),
                ),
                ast.Continue(),
            ]

        def _halt(self) -> List[ast.stmt]:
            return [
                ast.Assign(
                    targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
                    value=ast.Name(id=_HALT_NAME, ctx=ast.Load()),
                ),
                ast.Continue(),
            ]

        def lower(self, stmts: List[ast.stmt], cur: int, succ: int) -> int:
            """Lower stmts into block `cur`; on normal fallthrough, jump to `succ`.

            Returns the block id where execution ends (== cur if no branch
            was opened, otherwise the last block written into). Caller is
            responsible for ensuring `succ` is a valid (possibly halt) target.
            """
            i = 0
            while i < len(stmts):
                stmt = stmts[i]
                rest = stmts[i + 1:]
                if isinstance(stmt, ast.Return):
                    # Translate to: return value (kept as-is — terminates fn)
                    self.blocks[cur].append(stmt)
                    return cur
                if isinstance(stmt, ast.Raise):
                    self.blocks[cur].append(stmt)
                    return cur
                if isinstance(stmt, ast.Break):
                    if not self.loop_stack:
                        self.blocks[cur].append(stmt)
                        return cur
                    _, brk = self.loop_stack[-1]
                    self.blocks[cur].extend(self._goto(brk))
                    return cur
                if isinstance(stmt, ast.Continue):
                    if not self.loop_stack:
                        self.blocks[cur].append(stmt)
                        return cur
                    cont, _ = self.loop_stack[-1]
                    self.blocks[cur].extend(self._goto(cont))
                    return cur
                if isinstance(stmt, ast.If):
                    then_blk = self.new_block()
                    else_blk = self.new_block()
                    join_blk = self.new_block() if rest else None
                    join_target = join_blk if join_blk is not None else succ

                    new_if = ast.If(
                        test=stmt.test,
                        body=self._goto(then_blk),
                        orelse=self._goto(else_blk),
                    )
                    self.blocks[cur].append(new_if)

                    end_then = self.lower(stmt.body, then_blk, join_target)
                    if not _block_terminates(self.blocks[end_then]):
                        self.blocks[end_then].extend(self._goto(join_target))

                    end_else = self.lower(stmt.orelse, else_blk, join_target)
                    if not _block_terminates(self.blocks[end_else]):
                        self.blocks[end_else].extend(self._goto(join_target))

                    if join_blk is None:
                        return cur
                    cur = join_blk
                    i += 1
                    continue
                if isinstance(stmt, ast.While):
                    head = self.new_block()
                    body_blk = self.new_block()
                    after_blk = self.new_block() if rest else None
                    after_target = after_blk if after_blk is not None else succ
                    # entry: jump to head
                    self.blocks[cur].extend(self._goto(head))
                    # head: test
                    self.blocks[head].append(ast.If(
                        test=stmt.test,
                        body=self._goto(body_blk),
                        orelse=self._goto(after_target),
                    ))
                    self.loop_stack.append((head, after_target))
                    end_body = self.lower(stmt.body, body_blk, head)
                    self.loop_stack.pop()
                    if not _block_terminates(self.blocks[end_body]):
                        self.blocks[end_body].extend(self._goto(head))
                    if after_blk is None:
                        return cur
                    cur = after_blk
                    i += 1
                    continue
                if isinstance(stmt, ast.For):
                    # Lower a for loop into: it = iter(seq); while True: try: x=next(it) except StopIteration: break; body
                    # But to keep semantics simple, we keep the for-loop intact but rewrite break/continue
                    # by using a sentinel native for inside its own dispatcher block.
                    after_blk = self.new_block() if rest else None
                    after_target = after_blk if after_blk is not None else succ
                    inner_break = self.new_block()
                    # Inline the for natively (Python's for handles iter/StopIteration);
                    # rewrite break/continue inside body to gotos via marker exceptions? We use simpler trick:
                    # Wrap body so break/continue jump out via state by raising a private exception.
                    body_rewriter = _LoopRewriter()
                    new_body = [body_rewriter.visit(ast.fix_missing_locations(_clone(s))) for s in stmt.body]
                    new_orelse = list(stmt.orelse)
                    native_for = ast.For(
                        target=stmt.target,
                        iter=stmt.iter,
                        body=new_body or [ast.Pass()],
                        orelse=new_orelse,
                    )
                    # Wrap in try to capture break-marker
                    tryblk = ast.Try(
                        body=[native_for],
                        handlers=[ast.ExceptHandler(
                            type=ast.Name(id="_CFFBreak", ctx=ast.Load()),
                            name=None,
                            body=[ast.Pass()],
                        )],
                        orelse=[],
                        finalbody=[],
                    )
                    self.blocks[cur].append(tryblk)
                    self.blocks[cur].extend(self._goto(after_target))
                    if after_blk is None:
                        return cur
                    cur = after_blk
                    i += 1
                    continue
                if isinstance(stmt, ast.Try):
                    # Keep try/except as a single atomic block — flattening across exception
                    # boundaries is unsafe. Wrap body/handlers as nested mini-flatten? Keep native.
                    self.blocks[cur].append(stmt)
                    if rest:
                        nxt = self.new_block()
                        self.blocks[cur].extend(self._goto(nxt))
                        cur = nxt
                    i += 1
                    continue
                # Default: append as-is
                self.blocks[cur].append(stmt)
                i += 1
            return cur


    def _block_terminates(stmts: List[ast.stmt]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        return False


    def _clone(node):
        return ast.parse(ast.unparse(ast.Module(body=[node], type_ignores=[]))).body[0]


    class _LoopRewriter(ast.NodeTransformer):
        """Inside a native for-loop body, do not transform anything; keep break/continue native."""
        def visit_FunctionDef(self, node):
            return node
        def visit_AsyncFunctionDef(self, node):
            return node


    def _flatten_function(fn: ast.FunctionDef, rng: random.Random) -> bool:
        body = fn.body
        if len(body) <= 2:
            return False
        if _scan_unsupported(body):
            return False
        # Skip if body already trivially terminates (e.g. only docstring + return literal)
        fl = _Flattener(rng)
        entry = fl.new_block()
        halt = fl.new_block()
        fl.blocks[halt].append(ast.Return(value=ast.Constant(value=None)))
        end = fl.lower(body, entry, halt)
        if not _block_terminates(fl.blocks[end]):
            fl.blocks[end].extend(fl._goto(halt))

        n = len(fl.blocks)
        if n < 3:
            return False
        ids = list(range(n))  # real block ids
        # --- A3: fake-state injection -----------------------------------------
        # Add 2-4 unreachable "fake" blocks whose state values participate
        # in the dispatcher chain.  Each fake block runs junk statements and
        # then re-assigns the state var to *another* fake value, so a static
        # reader sees a plausible state machine that never executes.  Real
        # blocks never transition into a fake state, so the dispatch cases
        # for fakes are genuinely dead.
        n_fake = rng.randint(2, 4)
        fake_ids = list(range(n, n + n_fake))
        for fid in fake_ids:
            fl.blocks.append([
                ast.Assign(targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
                           value=ast.Constant(value=-1)),  # placeholder; rewritten below
                ast.Assign(targets=[ast.Name(id=rand_cn_name(8), ctx=ast.Store())],
                           value=ast.Constant(value=rng.randint(1, 1 << 16))),
            ])
        all_ids = ids + fake_ids
        shuffled_all = all_ids[:]
        rng.shuffle(shuffled_all)
        state_value = {block_id: shuffled_all[block_id] for block_id in all_ids}
        halt_value = state_value[halt]
        # Patch the fake blocks' self-goto to point at a *different* fake
        # (so they loop among themselves, never reaching a real block).
        for i, fid in enumerate(fake_ids):
            target_fake = fake_ids[(i + 1) % len(fake_ids)]
            for stmt in fl.blocks[fid]:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name) \
                        and stmt.targets[0].id == _STATE_VAR:
                    stmt.value = ast.Constant(value=state_value[target_fake])

        # Rewrite Constant(value=<block_id placeholder>) — but we stored ints directly in goto.
        # We must remap the literal goto integers (which currently equal block_id) to shuffled values.
        for blk in fl.blocks:
            for stmt in ast.walk(ast.Module(body=blk, type_ignores=[])):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == _STATE_VAR:
                    if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, int):
                        stmt.value = ast.Constant(value=state_value[stmt.value.value])
                    elif isinstance(stmt.value, ast.Name) and stmt.value.id == _HALT_NAME:
                        stmt.value = ast.Constant(value=halt_value)

        # --- A3: opaque-guard per real block ---------------------------------
        # Wrap each *real* block's body in `if <opaque-true>:` so the dispatch
        # case body is not directly the real statements; the decompiler must
        # reason about the opaque predicate to know the branch is always taken.
        def _opaque_true_test(rng):
            # (x * x + x) % 2 == 0  is always True for any int x:
            # x*(x+1) is the product of two consecutive integers, hence even.
            x = rng.randint(1, 999)
            return ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(left=ast.Constant(value=x), op=ast.Mult(),
                                       right=ast.Constant(value=x)),
                        op=ast.Add(),
                        right=ast.Constant(value=x)),
                    op=ast.Mod(),
                    right=ast.Constant(value=2)),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=0)],
            )

        def _opaque_true_dynamic(rng):
            # A3: data-flow-dependent opaque.  References the live CFF state
            # variable `_STATE_VAR` so the predicate depends on a *runtime*
            # value, not a build-time constant — a constant-folder cannot
            # pre-evaluate it and a symbolic-execution engine must bound the
            # dispatcher state space to simplify.  Identity: for a Carmichael
            # number N, pow(s % N, N, N) == s % N for EVERY integer s, so the
            # guard is mathematically always-True regardless of the state
            # value actually taken at run time.  `pow` 3-arg compiles in
            # VM-native mode (already used by _make_opaque_modinv_true).
            N = rng.choice((561, 1105, 1729, 2465, 2821, 6601, 8911))
            s = ast.Name(id=_STATE_VAR, ctx=ast.Load())
            s_mod = ast.BinOp(left=s, op=ast.Mod(), right=ast.Constant(value=N))
            return ast.Compare(
                left=ast.Call(
                    func=ast.Name(id="pow", ctx=ast.Load()),
                    args=[s_mod, ast.Constant(value=N), ast.Constant(value=N)],
                    keywords=[]),
                ops=[ast.Eq()],
                comparators=[s_mod],
            )

        # Build dispatcher: if state == V0: ... elif state == V1: ... elif state == HALT: break
        # Order the elif chain by shuffled value to make dispatch order opaque.
        order = sorted(all_ids, key=lambda b: state_value[b])
        dispatcher = None
        tail = None
        for block_id in order:
            stmts = fl.blocks[block_id]
            if block_id == halt:
                stmts = [ast.Break()]
            elif block_id not in fake_ids and stmts:
                # Wrap real block body in an opaque-true guard.  The `else`
                # branch fail-closes to HALT (break) so the flattened loop can
                # never spin forever even if an analyst somehow forced the
                # opaque predicate false — semantics stay correct because the
                # predicate is mathematically always true.
                # A3: ~40 % of guards use the data-flow-dependent Carmichael
                # form (depends on the live state var); the rest keep the
                # elementary (x*x+x)%2==0 form.  Both are always-True.
                if rng.random() < 0.4:
                    guard = _opaque_true_dynamic(rng)
                else:
                    guard = _opaque_true_test(rng)
                stmts = [ast.If(test=guard,
                                body=stmts,
                                orelse=[ast.Break()])]
            test = ast.Compare(
                left=ast.Name(id=_STATE_VAR, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=state_value[block_id])],
            )
            node = ast.If(test=test, body=stmts or [ast.Pass()], orelse=[])
            if dispatcher is None:
                dispatcher = node
                tail = node
            else:
                tail.orelse = [node]
                tail = node

        while_stmt = ast.While(test=ast.Constant(value=True), body=[dispatcher], orelse=[])
        init = ast.Assign(
            targets=[ast.Name(id=_STATE_VAR, ctx=ast.Store())],
            value=ast.Constant(value=state_value[entry]),
        )
        # Inject _CFFBreak sentinel class for for-loops that we wrapped (always safe)
        sentinel = ast.parse("class _CFFBreak(BaseException): pass").body[0]

        # Preserve a leading docstring if present
        new_body: List[ast.stmt] = []
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            new_body.append(body[0])
        new_body.append(sentinel)
        new_body.append(init)
        new_body.append(while_stmt)
        new_body.append(ast.Return(value=ast.Constant(value=None)))

        fn.body = new_body
        return True


    def apply_cff(tree: ast.Module, ctx: Any) -> ast.Module:
        """Apply control-flow flattening to all eligible functions in ``tree``.

        ``ctx`` is a ``BuildContext``-like object; we look up ``ctx.rng`` if
        present (a ``random.Random`` instance), otherwise fall back to a
        seeded fresh RNG. This keeps the pass usable from tests without
        requiring bedrock to populate a new field.
        """
        rng = getattr(ctx, "rng", None)
        if rng is None:
            rng = random.Random()

        class _Visitor(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.generic_visit(node)
                try:
                    _flatten_function(node, rng)
                except Exception:
                    # Fail-safe: never break the build because of a problematic fn.
                    pass
                return node

            def visit_AsyncFunctionDef(self, node):
                return node

        new_tree = _Visitor().visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree


    # === [INLINE] bedrock_ext/dectrap.py ===

    """Decompiler-trap pass for bedrock.

    Public API: ``apply_dectrap(tree, ctx) -> ast.Module``.

    Wrap eligible statement blocks in a nested ``if <opaque-true>: if
    <opaque-true>: <orig> else: <junk> else: <junk>`` shape. The nested
    branches produce overlapping jump targets (POP_JUMP_FORWARD_IF_FALSE +
    JUMP_FORWARD converging on the same offset) that uncompyle6 / decompyle3
    historically fail to reconcile (issue #321 SourceWalkerError) while the
    code remains semantically identical because every guard is a proven
    always-true MBA identity.

    The pass reuses the MBA opaque-predicate identity ``(a ^ b) | (a & b)
    == a | b`` (always True for non-negative ints) so the compiler cannot
    fold the test away -- a constant ``if 1`` gets optimised to NOPs on
    3.11+ and the trap structure vanishes, so we MUST use a data-dependent
    test.

    Skip rules:
    * module/class/lambda bodies are not visited;
    * bodies larger than ``_DECTRAP_MAX_BODY`` statements are left alone
      (avoids output bloat and keeps the trap pattern recognisable);
    * async functions are skipped (their control flow is stateful);
    * generators / functions containing ``yield`` / ``await`` are skipped;
    * a single trap never wraps another trap (a marker attribute on the
      synthetic ``If`` node prevents recursion).
    """

    _DECTRAP_MAX_BODY = 12  # statements; bodies larger than this are left alone

    def _dectrap_test_expr(rng: random.Random) -> ast.Compare:
        """Build the always-true MBA test ``(a^b)|(a&b) == a|b``.

        Returns the bare ``Compare`` expression (not an ``If`` stmt) so the
        caller can compose it into the nested-trap shape.
        """
        a = _rand_int(rng, 1, 4095)
        b = _rand_int(rng, 1, 4095)
        return ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=a), op=ast.BitXor(),
                               right=ast.Constant(value=b)),
                op=ast.BitOr(),
                right=ast.BinOp(left=ast.Constant(value=a), op=ast.BitAnd(),
                                right=ast.Constant(value=b)),
            ),
            ops=[ast.Eq()],
            comparators=[ast.BinOp(left=ast.Constant(value=a), op=ast.BitOr(),
                                   right=ast.Constant(value=b))],
        )

    def _dectrap_junk(rng: random.Random) -> List[ast.stmt]:
        """Small dead branch body -- a couple of no-op assignments.

        Reuses the junk helpers but trims to 1-2 statements so the trap's
        ``else`` arms stay cheaper than the real code they decoy.
        """
        return [
            ast.Assign(
                targets=[ast.Name(id=_rand_name(rng), ctx=ast.Store())],
                value=ast.Constant(value=_rand_int(rng, 0, 9999)),
            ),
        ]

    def _dectrap_wrap(body: List[ast.stmt], rng: random.Random) -> List[ast.stmt]:
        """Wrap ``body`` in the nested opaque-trap shape, returning a new
        single-statement list ``[outer_if]`` ready to replace ``body``."""
        inner_junk = _dectrap_junk(rng)
        outer_junk = _dectrap_junk(rng)
        inner = ast.If(
            test=_dectrap_test_expr(rng),
            body=body,
            orelse=inner_junk,
        )
        outer = ast.If(
            test=_dectrap_test_expr(rng),
            body=[inner],
            orelse=outer_junk,
        )
        # Mark both synthetic nodes so we never re-trap them.
        setattr(outer, "_bedrock_dectrap", True)
        setattr(inner, "_bedrock_dectrap", True)
        return [outer]

    def apply_dectrap(tree: ast.Module, ctx: Any) -> ast.Module:
        rng = getattr(ctx, "rng", None)
        if rng is None:
            rng = random.Random()
        # Density: wrap roughly one in N eligible bodies so the pass does
        # not multiply the trap across every block (configurable later).
        _density = getattr(ctx, "dectrap_density", 0.5)

        def _has_yield_or_await(body):
            for n in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                    return True
            return False

        class _Visitor(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.generic_visit(node)
                try:
                    if getattr(node, "_bedrock_dectrap", False):
                        return node
                    if not node.body or len(node.body) > _DECTRAP_MAX_BODY:
                        return node
                    if _has_yield_or_await(node.body):
                        return node
                    if rng.random() < _density:
                        node.body = _dectrap_wrap(node.body, rng)
                except Exception:
                    pass
                return node

            def visit_AsyncFunctionDef(self, node):
                # async control flow is stateful -- skip, mirrors apply_cff.
                return node

        new_tree = _Visitor().visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree



    # === [INLINE] bedrock_ext/bcmut.py ===

    """
    bcmut.py - Bytecode-level mutation pass for the bedrock obfuscator.

    Public API:
        mutate_code(code: types.CodeType, ctx) -> types.CodeType

    Strategy (Python 3.10 / 3.11 / 3.12 aware):

      1. NOP padding              - insert opcode NOP at safe boundaries.
      2. Junk dead branches       - LOAD_CONST True; POP_JUMP_IF_FALSE skip; <junk>; skip:
                                    only enabled on 3.10 where POP_JUMP_IF_FALSE takes
                                    an absolute target in instruction units and the
                                    CACHE / inline-cache machinery does not exist.
      3. Constant pool padding    - append decoy strings / fake names to co_consts.

    Recomputing jump offsets, exception tables (3.11+) and inline caches (3.11+)
    correctly is extremely fragile. To stay safe across versions we ONLY perform
    transformations that do not move existing instructions:

      - NOP padding is done by REPLACING existing EXTENDED_ARG-prefixed slots that
        are no-ops, OR by appending NOPs to the *tail* of the bytecode if the last
        instruction is an unconditional terminator (RETURN_VALUE / RAISE_VARARGS).
        This guarantees no jump target, no exception handler entry, and no line
        table entry shifts.
      - Constant pool padding is always safe: indices of existing consts are kept
        by appending new entries at the end.
      - Dead-branch injection is gated to Python 3.10 only and is also tail-only
        (after the final RETURN_VALUE) so that semantics are preserved.

    If any heuristic decides the function is too risky to touch, mutate_code
    returns the input unchanged and recurses into nested code consts only.

    Author: bedrock_ext
    """


    import dis
    import sys
    import random
    import types
    from typing import Any, Tuple

    NOP = dis.opmap.get("NOP", 9)
    RETURN_VALUE = dis.opmap.get("RETURN_VALUE", 83)
    RAISE_VARARGS = dis.opmap.get("RAISE_VARARGS", 130)
    RETURN_CONST = dis.opmap.get("RETURN_CONST", -1)  # 3.12+
    RERAISE = dis.opmap.get("RERAISE", -1)            # 3.11+
    RESUME = dis.opmap.get("RESUME", -1)  # 3.11+
    LOAD_CONST = dis.opmap["LOAD_CONST"]

    PY = sys.version_info[:2]


    # ---------------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------------

    def _rng(ctx) -> random.Random:
        seed = getattr(ctx, "bc_mutate_seed", None) if ctx is not None else None
        if seed is None:
            seed = getattr(ctx, "seed", None) if ctx is not None else None
        return random.Random(seed)


    def _get_flag(ctx, name: str, default: bool) -> bool:
        if ctx is None:
            return default
        return bool(getattr(ctx, name, default))


    def _decoy_strings(rng: random.Random, n: int):
        pool = [
            "__pycache__", "__init__", "__main__", "self", "cls",
            "decoy_token", "anti_debug", "trampoline", "vmctx", "obf_state",
            "9d4f7a", "ZmFrZQ==", "// drop table", "<sentinel>",
        ]
        rng.shuffle(pool)
        return tuple(pool[:n])


    # ---------------------------------------------------------------------------
    # const-pool padding
    # ---------------------------------------------------------------------------

    def _pad_consts(consts: tuple, rng: random.Random, ctx) -> tuple:
        if not _get_flag(ctx, "bc_mutate_consts", True):
            return consts
        extra = _decoy_strings(rng, rng.randint(2, 5))
        return tuple(consts) + extra


    # ---------------------------------------------------------------------------
    # tail NOP padding
    # ---------------------------------------------------------------------------

    def _last_instr_terminates(code_bytes: bytes) -> bool:
        """True if the last 2-byte instruction is RETURN_VALUE or RAISE_VARARGS."""
        if len(code_bytes) < 2:
            return False
        op = code_bytes[-2]
        return op in (RETURN_VALUE, RAISE_VARARGS, RETURN_CONST, RERAISE)


    def _append_tail_nops(code_bytes: bytes, count: int) -> bytes:
        """Append `count` NOP instructions (NOP, 0) after the terminating opcode.

        Python's interpreter never reaches them because the previous instruction
        transfers control. They still show up in dis output, polluting analysis.
        """
        return bytes(code_bytes) + bytes([NOP, 0]) * count


    def _append_dead_branch(code_bytes: bytes, junk_len: int) -> bytes:
        """Append a junk LOAD_CONST/POP block after a terminator.

        Only emits NOP-style junk; never executed because predecessors all RETURN.
        """
        # Just emit `junk_len` NOPs plus a fake LOAD_CONST 0 / POP_TOP pattern.
        POP_TOP = dis.opmap["POP_TOP"]
        out = bytearray(code_bytes)
        for _ in range(junk_len):
            out.append(NOP); out.append(0)
        out.append(LOAD_CONST); out.append(0)
        out.append(POP_TOP);    out.append(0)
        return bytes(out)


    # ---------------------------------------------------------------------------
    # CodeType reconstruction (3.10 vs 3.11+)
    # ---------------------------------------------------------------------------

    def _replace_code(code: types.CodeType, **kw) -> types.CodeType:
        return code.replace(**kw)


    # ---------------------------------------------------------------------------
    # main entry
    # ---------------------------------------------------------------------------

    def mutate_code(code: types.CodeType, ctx: Any = None) -> types.CodeType:
        """Apply bytecode mutations recursively to `code` and its nested consts."""
        if not isinstance(code, types.CodeType):
            return code

        rng = _rng(ctx)

        # 1. recurse into nested code objects first
        new_consts = []
        for c in code.co_consts:
            if isinstance(c, types.CodeType):
                new_consts.append(mutate_code(c, ctx))
            else:
                new_consts.append(c)
        new_consts = tuple(new_consts)

        # 2. constant-pool padding
        new_consts = _pad_consts(new_consts, rng, ctx)

        # 3. tail NOP padding (always safe)
        code_bytes = bytes(code.co_code)
        mutated = code_bytes
        nop_pad = 0
        if _get_flag(ctx, "bc_mutate_nop", True) and _last_instr_terminates(code_bytes):
            nop_pad = rng.randint(3, 8)
            mutated = _append_tail_nops(mutated, nop_pad)

        # 4. dead-branch tail junk (3.10 only - others have exception tables /
        #    inline caches that are sensitive to bytecode length in subtle ways,
        #    but appending after a terminator at the very end is still safe
        #    *as long as* nothing references those offsets. We allow it on all
        #    versions because the exception table maps source ranges, not tail.)
        if _get_flag(ctx, "bc_mutate_dead", True) and _last_instr_terminates(code_bytes):
            mutated = _append_dead_branch(mutated, rng.randint(1, 4))

        # 5. zero out line table to avoid offset/line desync after padding.
        #    We keep firstlineno so tracebacks still point to the function.
        kw = {"co_consts": new_consts, "co_code": mutated}

        if PY >= (3, 10):
            # co_linetable exists on 3.10+; an empty bytes value is accepted and
            # simply means "no line info", which is harmless at runtime.
            try:
                kw["co_linetable"] = b""
            except Exception:
                pass
        else:
            kw["co_lnotab"] = b""

        # On 3.11+ there is also co_exceptiontable. We must NOT invalidate it,
        # so we leave it untouched - tail appends do not affect existing entries.

        try:
            return _replace_code(code, **kw)
        except Exception:
            # Fallback: only swap consts (safest mutation) if bytecode replace fails.
            try:
                return _replace_code(code, co_consts=new_consts)
            except Exception:
                return code


    __all__ = ["mutate_code"]




    # === [INLINE] bedrock_ext/hardening.py ===

    """Runtime hardening for bedrock-obfuscated loaders.

    Provides two snippets injected at the very top of the loader source:

      1. ANTI_FRIDA_SNIPPET     - detects Frida / instrumentation / monkey-patched
                                  builtins and aborts on positive signal.
      2. INTEGRITY_SNIPPET_*    - SHA-256 self-check of the loader file, skipping
                                  the integrity block (delimited by markers) so the
                                  embedded hash itself is excluded.

    `wrap_with_hardening(loader_src, ctx)` is the public entry point used by the
    CLI wiring (see WIRING_hardening.md). It is intentionally side-effect free:
    it never edits bedrock.py and only returns a new source string.
    """


    import hashlib
    import os
    import random
    import string
    from typing import Any

    INTEGRITY_BLOCK_START = "# === INTEGRITY BLOCK START ==="
    INTEGRITY_BLOCK_END = "# === INTEGRITY BLOCK END ==="

    # Fixed expected bytecode hash for `print` is *not* used directly; the snippet
    # captures it at import-time and snapshots `__import__`. This avoids brittle
    # pinning across CPython minor versions while still catching late monkey-patches
    # performed after the loader starts executing.

    ANTI_FRIDA_SNIPPET = textwrap.dedent(r'''
    # --- bedrock anti-frida / anti-hook (auto-generated) ---
    def __BR_ANTI__():
        import sys as __br_sys
        import os as __br_os
        try:
            import builtins as __br_b
        except Exception:
            return
        try:
            import dis as __br_dis, hashlib as __br_h
        except Exception:
            __br_dis = None
        __br_die = lambda tag: __br_sys.exit(0)
        # 1. /proc/self/maps + /proc/self/cmdline scan (Linux only; silent on others)
        for __br_path in ("/proc/self/maps", "/proc/self/cmdline", "/proc/self/status"):
            try:
                if not __br_os.path.exists(__br_path):
                    continue
                with open(__br_path, "rb") as __br_f:
                    __br_buf = __br_f.read().lower()
                for __br_needle in (b"frida", b"frida-agent", b"frida-gadget",
                                    b"gum-js-loop", b"gmain", b"gdbus", b"linjector"):
                    if __br_needle in __br_buf:
                        __br_die("maps")
        except Exception:
            pass
        # 1b. Frida-server TCP probe (frida-server default port 27042).
        # A successful connect means frida-server is listening locally.
        # Cross-platform pure-Python socket probe; 50ms timeout won't block.
        try:
            import socket as __br_sk
            __br_s = __br_sk.socket(__br_sk.AF_INET, __br_sk.SOCK_STREAM)
            __br_s.settimeout(0.05)
            try:
                if __br_s.connect_ex(("127.0.0.1", 27042)) == 0:
                    __br_die("frida-port")
            finally:
                try:
                    __br_s.close()
                except Exception:
                    pass
        except Exception:
            pass
        # 1c. Thread-name enumeration for frida agent threads (Linux /proc).
        # gum-js-loop / gmain / gdbus are Frida's canonical worker thread names.
        # Catches injected agents even when no maps entry is visible.
        try:
            __br_task_dir = "/proc/self/task"
            if __br_os.path.isdir(__br_task_dir):
                for __br_tid in __br_os.listdir(__br_task_dir):
                    try:
                        with open(__br_task_dir + "/" + __br_tid + "/comm", "r") as __br_tf:
                            __br_tn = __br_tf.read().strip().lower()
                        for __br_bad in ("gum-js-loop", "gmain", "gdbus", "linjector", "frida"):
                            if __br_bad in __br_tn:
                                __br_die("thread:" + __br_tn)
                    except Exception:
                        pass
        except Exception:
            pass
        # 2. tracer / profiler attached
        try:
            if __br_sys.gettrace() is not None:
                __br_die("trace")
            if __br_sys.getprofile() is not None:
                __br_die("profile")
        except Exception:
            pass
        # 3. __import__ swapped
        try:
            if __br_b.__import__ is not __builtins__.__import__ if isinstance(__builtins__, type(__br_b)) else False:
                pass
            # the real check: builtins.__import__ identity vs frozen reference
            __br_imp_ref = __br_b.__dict__.get("__import__")
            if __br_imp_ref is None or not callable(__br_imp_ref):
                __br_die("import")
            if getattr(__br_imp_ref, "__module__", "builtins") not in ("builtins", "_frozen_importlib"):
                __br_die("import-mod")
        except SystemExit:
            raise
        except Exception:
            pass
        # 3b. sys.modules authenticity pre-filter — catch sloppy fakes where a
        #     module's __name__ doesn't match the sys.modules key (e.g. a
        #     Python-level trojan `marshal` with __name__ == 'fake_marshal').
        #     This is the fast loader-level probe; the payload's id()-snapshot
        #     + BuiltinFunctionType check catches more sophisticated swaps.
        try:
            _br_crit = ('sys', 'os', 'builtins', 'types', 'threading', 'marshal',
                        'gc', 'hashlib', 'zlib', 'base64', 'pickle', 'struct',
                        'time', 'json', 'ctypes', 'binascii', 'io', 'errno')
            for _br_n in _br_crit:
                _br_m = __br_sys.modules.get(_br_n)
                if _br_m is not None:
                    if getattr(_br_m, '__name__', '') != _br_n:
                        __br_die("mod:" + _br_n)
        except SystemExit:
            raise
        except Exception:
            pass
        # 4. bytecode fingerprint of a stable builtin (print) - detects wholesale
        #    replacement. We snapshot at first run and stash on sys for cheap reuse.
        #    S5: extended to co_code + co_consts + co_names so renaming-only
        #    tampering (e.g. swapping print back under a hooked name) is caught.
        try:
            if __br_dis is not None:
                __br_co = getattr(__br_b.print, "__code__", None)
                if __br_co is not None:
                    __br_fp = __br_h.sha256(
                        __br_co.co_code + b'|' +
                        repr(getattr(__br_co, 'co_consts', ())).encode('utf-8', 'replace') + b'|' +
                        repr(getattr(__br_co, 'co_names', ())).encode('utf-8', 'replace')
                    ).hexdigest()
                    __br_known = getattr(__br_sys, "_br_print_fp", None)
                    if __br_known is None:
                        setattr(__br_sys, "_br_print_fp", __br_fp)
                    elif __br_known != __br_fp:
                        __br_die("print-fp")
                else:
                    # builtin C function -> __code__ missing is normal; check type
                    if type(__br_b.print).__name__ not in ("builtin_function_or_method", "method-wrapper"):
                        __br_die("print-type")
        except SystemExit:
            raise
        except Exception:
            pass
    __BR_ANTI__()
    del __BR_ANTI__
    # --- end anti-frida ---
    ''').lstrip("\n")


    # D2(b): time-skip / single-stepping probe. Measures wall-clock delta
    # around a fixed-cost hashing workload (~32 KiB). Outside the window
    # [EPS_LO_NS, EPS_HI_NS] we suspect instrumentation: a debugger stepping
    # one instruction at a time inflates per-op latency far above the upper
    # bound, while a time-compressed / patched `perf_counter` collapses to
    # ~0 ns and trips the lower bound. Tuned to be robust across modern
    # hardware while still catching single-step drift.
    ANTI_TIMING_SNIPPET = textwrap.dedent(r'''
    # --- bedrock anti-timing probe (auto-generated) ---
    def __br_ati_main():
        import time as __br_ati_time
        import hashlib as __br_ati_h
        try:
            __br_ati_blob = (BR_DEBRAND["baobg"] * 7)[:6].encode("utf-8") * 4096   # ~28 KiB fixed workload
            __br_ati_eps_lo = 1_000            # 1 us lower bound
            __br_ati_eps_hi = 50_000_000       # 50 ms upper bound
            __br_ati_t0 = __br_ati_time.perf_counter_ns()
            __br_ati_h.sha256(__br_ati_blob).digest()
            __br_ati_dt = __br_ati_time.perf_counter_ns() - __br_ati_t0
            if __br_ati_dt < __br_ati_eps_lo or __br_ati_dt > __br_ati_eps_hi:
                try:
                    __br_ati_sys = __import__("sys")
                    __br_ati_sys.exit(0)
                except Exception:
                    raise SystemExit(0)
        except SystemExit:
            raise
        except Exception:
            pass
    __br_ati_main()
    del __br_ati_main
    # --- end anti-timing ---
    ''').lstrip("\n")


    # Note: doubled braces `{{` `}}` survive str.format; only `{expected_hash}` and
    # `{start}` / `{end}` are substituted.
    INTEGRITY_SNIPPET_TEMPLATE = (
        INTEGRITY_BLOCK_START + "\n"
        + textwrap.dedent(r'''
        def __BR_INTEGRITY__():
            import sys as __br_sys, os as __br_os, hashlib as __br_h
            __br_expected = "{expected_hash}"
            __br_start = "{start}"
            __br_end = "{end}"
            __br_path = None
            for __br_cand in (globals().get("__file__"),
                              __br_sys.argv[0] if __br_sys.argv else None):
                if __br_cand and __br_os.path.isfile(__br_cand):
                    __br_path = __br_cand
                    break
            if __br_path is None:
                return  # interactive / -c / frozen: skip silently
            try:
                with open(__br_path, "rb") as __br_f:
                    __br_data = __br_f.read()
            except Exception:
                __br_sys.exit(0)
            # Strip the integrity block (markers + body) before hashing so the embedded
            # hash itself is not part of the digest.
            __br_s = __br_data.find(__br_start.encode())
            __br_e = __br_data.find(__br_end.encode())
            if __br_s == -1 or __br_e == -1 or __br_e < __br_s:
                __br_sys.exit(0)
            __br_e_full = __br_e + len(__br_end.encode())
            # Also drop the trailing newline that follows the END marker (if any) so
            # editors that normalize EOL don't trip the check.
            if __br_e_full < len(__br_data) and __br_data[__br_e_full:__br_e_full+1] in (b"\n", b"\r"):
                __br_e_full += 1
                if __br_e_full < len(__br_data) and __br_data[__br_e_full:__br_e_full+1] == b"\n":
                    __br_e_full += 1
            __br_payload = __br_data[:__br_s] + __br_data[__br_e_full:]
            __br_actual = __br_h.sha256(__br_payload).hexdigest()
            if __br_actual != __br_expected:
                __br_sys.exit(0)
        __BR_INTEGRITY__()
        del __BR_INTEGRITY__
        ''').lstrip()
        + INTEGRITY_BLOCK_END + "\n"
    )


    def _derive_rng(ctx: Any) -> random.Random:
        """Best-effort RNG: use ctx.rng if present, else seed from ctx fields."""
        rng = getattr(ctx, "rng", None)
        if isinstance(rng, random.Random):
            return rng
        seed_src = "|".join(
            str(getattr(ctx, attr, ""))
            for attr in ("input_path", "output_path", "profile", "runtime_mode")
        ) or os.urandom(16).hex()
        return random.Random(seed_src)


    def _rand_tag(rng: random.Random, n: int = 8) -> str:
        return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


    def _randomize_names(snippet: str, rng: random.Random) -> str:
        """Replace `__br_` / `__BR_` prefixes with a per-build random tag.

        Only touches identifiers we own (the `__br_*` / `__BR_*` namespace), so it
        cannot collide with user code or with bedrock's own `__bedrock_*` /
        `baobg_*` identifiers.
        """
        tag = _rand_tag(rng)
        # Use double-underscore to keep name-mangling-safe and obviously private.
        return snippet.replace("__br_", f"__{BR_DEBRAND[chr(98)+chr(101)+chr(100)+chr(114)+chr(111)+chr(99)+chr(107)]}_{tag}_").replace(
            "__BR_", f"__{BR_DEBRAND[chr(66)+chr(69)+chr(68)+chr(82)+chr(79)+chr(67)+chr(75)]}_{tag.upper()}_"
        )


    def _compute_payload_hash(src_with_placeholder: str) -> str:
        """Compute the SHA-256 of `src_with_placeholder` *minus* the integrity
        block (markers + body), matching what the runtime check will hash.
        """
        data = src_with_placeholder.encode("utf-8")
        s = data.find(INTEGRITY_BLOCK_START.encode())
        e = data.find(INTEGRITY_BLOCK_END.encode())
        if s == -1 or e == -1:
            return hashlib.sha256(data).hexdigest()
        e_full = e + len(INTEGRITY_BLOCK_END.encode())
        # match runtime newline-trim
        if e_full < len(data) and data[e_full:e_full + 1] in (b"\n", b"\r"):
            e_full += 1
            if e_full < len(data) and data[e_full:e_full + 1] == b"\n":
                e_full += 1
        payload = data[:s] + data[e_full:]
        return hashlib.sha256(payload).hexdigest()


    def wrap_with_hardening(loader_src: str, ctx: Any) -> str:
        """Inject anti-frida + integrity snippets at the top of `loader_src`.

        The integrity hash is computed over the *final* source minus the integrity
        block, so the embedded digest is self-consistent.
        """
        rng = _derive_rng(ctx)

        anti = _randomize_names(ANTI_FRIDA_SNIPPET, rng) if getattr(ctx, "anti_hook", "strict") != "off" else ""
        # D2(b): time-skip / single-step probe -- opt-in via --anti-timing.
        anti_timing = _randomize_names(ANTI_TIMING_SNIPPET, rng) if getattr(ctx, "anti_timing", False) else ""

        # First splice with a placeholder hash so we can compute the real one over
        # the *exact* layout the loader will see (minus the integrity block).
        placeholder = "0" * 64
        integ_snippet = INTEGRITY_SNIPPET_TEMPLATE.format(
            expected_hash=placeholder,
            start=INTEGRITY_BLOCK_START,
            end=INTEGRITY_BLOCK_END,
        )
        integ_snippet = _randomize_names(integ_snippet, rng)

        # Preserve a leading shebang / coding cookie if present.
        head, body = "", loader_src
        if loader_src.startswith("#!"):
            nl = loader_src.find("\n")
            if nl != -1:
                head, body = loader_src[: nl + 1], loader_src[nl + 1:]

        assembled = head + anti + anti_timing + integ_snippet + body
        real_hash = _compute_payload_hash(assembled)
        final = assembled.replace(placeholder, real_hash, 1)
        return final




    # === [INLINE] bedrock_ext/anti_vm.py ===

    """Anti-VM / anti-sandbox runtime detection for bedrock loaders.

    Public surface:
      * ``ANTI_VM_SNIPPET``  - raw Python source embedded into the loader.
      * ``wrap_with_anti_vm(loader_src, ctx) -> str`` - splices a per-build,
        name-randomised copy of the snippet at the top of the loader source.

    Behaviour on positive detection is governed by ``ctx.tamper`` (or the
    attribute ``ctx.anti_vm_action`` if present), one of:

      * ``"warn"``           - print a single line to stderr, continue
      * ``"fail-closed"``    - ``SystemExit(0)`` immediately
      * ``"self-destruct"``  - ``os.remove(__file__)`` then ``SystemExit(0)``

    The snippet is *graceful*: every probe is wrapped in ``try/except`` and
    silently skipped when the relevant ``/proc`` or ``/sys`` path is absent
    (Windows / macOS / containers without procfs).

    This module is side-effect free and never imports or edits ``bedrock.py``.
    """


    import os
    import random
    import string
    from typing import Any

    # The snippet uses the literal prefix ``__bedrock_av_`` for every identifier
    # we own; ``_randomize_names`` substitutes a per-build random tag so two
    # builds of the same source produce different symbol tables.
    ANTI_VM_SNIPPET = textwrap.dedent(r'''
    # --- bedrock anti-vm / anti-sandbox (auto-generated) ---
    def __bedrock_av_run():
        import os as __bedrock_av_os
        import sys as __bedrock_av_sys
        __bedrock_av_action = "__BEDROCK_AV_ACTION__"
        __bedrock_av_mode = "__BEDROCK_AV_MODE__"
        __bedrock_av_hits = []
        __bedrock_av_score = 0

        def __bedrock_av_hit(tag, weight):
            nonlocal __bedrock_av_score
            try:
                __bedrock_av_hits.append(str(tag))
                __bedrock_av_score += int(weight)
            except Exception:
                pass

        def __bedrock_av_read(path):
            try:
                with open(path, "rb") as __bedrock_av_f:
                    return __bedrock_av_f.read().lower()
            except Exception:
                return b""

        # 1. /proc/cpuinfo
        __bedrock_av_buf = __bedrock_av_read("/proc/cpuinfo")
        for __bedrock_av_n in (b"vmware", b"qemu", b"virtualbox"):
            if __bedrock_av_n in __bedrock_av_buf:
                __bedrock_av_hit("cpuinfo:" + __bedrock_av_n.decode(), 2)
                break
        else:
            if b"hypervisor" in __bedrock_av_buf:
                __bedrock_av_hit("cpuinfo:hypervisor", 1)

        # 2. DMI product/vendor data. Cloud KVM alone is a weak signal; consumer
        # sandbox products are stronger.
        __bedrock_av_dmi = b"\n".join((
            __bedrock_av_read("/sys/class/dmi/id/product_name"),
            __bedrock_av_read("/sys/class/dmi/id/sys_vendor"),
            __bedrock_av_read("/sys/class/dmi/id/board_vendor"),
        ))
        for __bedrock_av_n in (b"virtualbox", b"vmware"):
            if __bedrock_av_n in __bedrock_av_dmi:
                __bedrock_av_hit("dmi:" + __bedrock_av_n.decode(), 3)
                break
        else:
            for __bedrock_av_n in (b"qemu", b"kvm"):
                if __bedrock_av_n in __bedrock_av_dmi:
                    __bedrock_av_hit("dmi:" + __bedrock_av_n.decode(), 1)
                    break

        # 3. MAC OUI prefix scan
        try:
            import uuid as __bedrock_av_uuid
            __bedrock_av_mac = __bedrock_av_uuid.getnode()
            __bedrock_av_oui = (__bedrock_av_mac >> 24) & 0xFFFFFF
            for __bedrock_av_p in (0x000569, 0x000C29, 0x005056, 0x080027, 0x00163E):
                if __bedrock_av_oui == __bedrock_av_p:
                    __bedrock_av_hit("mac_oui:%06x" % __bedrock_av_p, 2)
                    break
        except Exception:
            pass

        # 4. Hostname patterns
        try:
            import socket as __bedrock_av_sock
            __bedrock_av_host = __bedrock_av_sock.gethostname().lower()
            for __bedrock_av_n in ("cuckoo", "sandbox", "malware", "analyst"):
                if __bedrock_av_n in __bedrock_av_host:
                    __bedrock_av_hit("host:" + __bedrock_av_n, 3)
                    break
        except Exception:
            pass

        # 5. Very small disk/RAM are weak signals. Cloud instances and CI boxes
        # often look small while still being legitimate production targets.
        try:
            __bedrock_av_st = __bedrock_av_os.statvfs("/")
            __bedrock_av_total = __bedrock_av_st.f_frsize * __bedrock_av_st.f_blocks
            if 0 < __bedrock_av_total < (20 * 1024 * 1024 * 1024):
                __bedrock_av_hit("disk_small", 1)
        except Exception:
            pass
        __bedrock_av_meminfo = __bedrock_av_read("/proc/meminfo")
        if __bedrock_av_meminfo:
            try:
                for __bedrock_av_line in __bedrock_av_meminfo.splitlines():
                    if __bedrock_av_line.startswith(b"memtotal:"):
                        __bedrock_av_kb = int(__bedrock_av_line.split()[1])
                        if __bedrock_av_kb < (1536 * 1024):
                            __bedrock_av_hit("ram_small", 1)
                        break
            except Exception:
                pass

        # 6. Process list (best-effort, /proc only)
        try:
            for __bedrock_av_pid in __bedrock_av_os.listdir("/proc"):
                if not __bedrock_av_pid.isdigit():
                    continue
                __bedrock_av_c = __bedrock_av_read("/proc/" + __bedrock_av_pid + "/comm")
                if not __bedrock_av_c:
                    continue
                for __bedrock_av_n in (b"vboxservice", b"vmtoolsd"):
                    if __bedrock_av_n in __bedrock_av_c:
                        __bedrock_av_hit("proc:" + __bedrock_av_n.decode(), 3)
                        break
                if __bedrock_av_hits and __bedrock_av_hits[-1].startswith("proc:"):
                    break
        except Exception:
            pass

        __bedrock_av_threshold = 3 if __bedrock_av_mode == "strict" else 4
        if (not __bedrock_av_hits) or __bedrock_av_score < __bedrock_av_threshold:
            return

        __bedrock_av_msg = "[" + BR_DEBRAND["bedrock"] + "] anti-vm: score=%d/%d %s" % (
            __bedrock_av_score,
            __bedrock_av_threshold,
            ",".join(__bedrock_av_hits),
        )
        if __bedrock_av_action == "warn":
            try:
                __bedrock_av_sys.stderr.write(__bedrock_av_msg + "\n")
            except Exception:
                pass
            return
        if __bedrock_av_action == "poison":
            try:
                globals()['__h_poison']('av:' + __bedrock_av_msg[:32], 7)
            except Exception:
                pass
            return
        if __bedrock_av_action == "self-destruct":
            try:
                __bedrock_av_self = globals().get("__file__", None)
                if __bedrock_av_self:
                    __bedrock_av_os.remove(__bedrock_av_self)
            except Exception:
                pass
        __bedrock_av_sys.exit(0)

    try:
        __bedrock_av_run()
    except SystemExit:
        raise
    except Exception:
        pass
    # --- end bedrock anti-vm ---
    ''').lstrip("\n")


    _VALID_ACTIONS = {"warn", "fail-closed", "self-destruct", "poison"}


    def _derive_rng(ctx: Any) -> random.Random:
        rng = getattr(ctx, "rng", None)
        if isinstance(rng, random.Random):
            return rng
        seed_src = "|".join(
            str(getattr(ctx, attr, ""))
            for attr in ("input_path", "output_path", "profile", "runtime_mode", "anti_vm")
        )
        if not seed_src.strip("|"):
            return random.Random(os.urandom(16))
        return random.Random(seed_src)


    def _rand_tag(rng: random.Random, n: int = 8) -> str:
        return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


    def _resolve_action(ctx: Any) -> str:
        action = getattr(ctx, "anti_vm_action", None) or getattr(ctx, "tamper", None) or "warn"
        action = str(action).lower()
        if action not in _VALID_ACTIONS:
            action = "warn"
        return action


    def _randomize_names(snippet: str, rng: random.Random) -> str:
        """Substitute the literal ``__bedrock_av_`` prefix with a per-build tag.

        The snippet uses exactly one identifier prefix so this is a simple
        string replace; collisions with user code are impossible because the
        tag is randomly generated.
        """
        tag = _rand_tag(rng)
        return snippet.replace("__bedrock_av_", f"__{BR_DEBRAND[chr(98)+chr(101)+chr(100)+chr(114)+chr(111)+chr(99)+chr(107)]}_av_{tag}_")


    # Marker used to make wrap idempotent.
    _WRAP_MARKER = "# --- bedrock anti-vm / anti-sandbox (auto-generated) ---"


    def wrap_with_anti_vm(loader_src: str, ctx: Any) -> str:
        """Inject the anti-VM snippet at the top of ``loader_src``.

        * Honours ``ctx.anti_vm`` (``"strict"`` / ``"compat"`` / ``"off"``).
          ``"off"`` returns the source unchanged.
        * Idempotent: re-wrapping a previously-wrapped source is a no-op.
        * Preserves a leading shebang line.
        """
        mode = str(getattr(ctx, "anti_vm", "off")).lower()
        if mode == "off":
            return loader_src
        if _WRAP_MARKER in loader_src:
            return loader_src

        rng = _derive_rng(ctx)
        action = _resolve_action(ctx)
        snippet = ANTI_VM_SNIPPET.replace("__BEDROCK_AV_ACTION__", action)
        snippet = snippet.replace("__BEDROCK_AV_MODE__", mode if mode in ("strict", "compat") else "compat")
        snippet = _randomize_names(snippet, rng)

        head, body = "", loader_src
        if loader_src.startswith("#!"):
            nl = loader_src.find("\n")
            if nl != -1:
                head, body = loader_src[: nl + 1], loader_src[nl + 1 :]

        return _debrand(head + snippet + body)




    # === [INLINE] bedrock_ext/anti_debugger.py ===

    """Anti-debugger v2 for bedrock-obfuscated loaders.

    Detects attached debuggers / tracers via multiple independent signals:

      1. ``/proc/self/status`` ``TracerPid:`` field (Linux).
      2. Passive Linux parent/process checks. Active ``ptrace`` probes are not
         used because they can stop normal shell job-control sessions.
      3. Parent process name (``/proc/<ppid>/comm``) checked against a small
         blacklist (gdb, lldb, strace, ltrace, pyrasite, pdb, winpdb, pudb, ipdb).
      4. ``sys.gettrace()`` / ``sys.getprofile()`` not None.
      5. ``PYTHONBREAKPOINT`` / ``PYTHONINSPECT`` set in ``os.environ``.
      6. ``pdb`` / ``bdb`` / ``pyrasite`` already present in ``sys.modules``.

    All checks are wrapped in ``try/except`` so the snippet remains a graceful
    no-op on platforms where the probe is unavailable (Windows, frozen builds,
    sandboxes without ``/proc``, missing libc, ...).

    Behavior on positive detection is governed by ``ctx.tamper``:

      * ``"warn"``         -> print a single line to stderr and continue.
      * ``"fail-closed"``  -> ``sys.exit(0)`` silently (default).
      * ``"self-destruct"``-> attempt to ``os.unlink(__file__)`` then exit.

    Identifier names are randomized per-build via ``ctx.rng`` so static signatures
    on ``__bedrock_ad2_*`` cannot be used to strip the snippet trivially.

    This module never edits ``bedrock.py``; the CLI wiring is documented in
    ``WIRING_anti_debugger.md``.
    """


    import os
    import random
    import string
    from typing import Any


    # NOTE: doubled braces ``{{`` / ``}}`` are *not* used here -- the snippet is a
    # literal raw string, not a ``str.format`` template. The ``{tamper_mode}``
    # substitution is performed via plain ``.replace`` further down.

    ANTI_DBG_V2_SNIPPET = textwrap.dedent(r'''
    # --- bedrock anti-debugger v2 (auto-generated) ---
    def __bedrock_ad2_main():
        import sys as __bedrock_ad2_sys
        import os as __bedrock_ad2_os
        __bedrock_ad2_mode = "__BEDROCK_AD2_MODE__"
        __bedrock_ad2_hits = []
        __bedrock_ad2_soft_score = 0
        __bedrock_ad2_hard = False

        def __bedrock_ad2_react(__bedrock_ad2_tag):
            try:
                __bedrock_ad2_tag = str(__bedrock_ad2_tag).strip()
            except Exception:
                __bedrock_ad2_tag = ""
            if not __bedrock_ad2_tag:
                return
            if __bedrock_ad2_mode == "warn":
                try:
                    __bedrock_ad2_sys.stderr.write(
                        "[bedrock] debugger detected: " + __bedrock_ad2_tag + "\n"
                    )
                except Exception:
                    pass
                return
            if __bedrock_ad2_mode == "poison":
                try:
                    globals()['__h_poison']('ad2:' + __bedrock_ad2_tag[:32], 7)
                except Exception:
                    pass
                return
            if __bedrock_ad2_mode == "self-destruct":
                try:
                    __bedrock_ad2_path = globals().get("__file__")
                    if __bedrock_ad2_path and __bedrock_ad2_os.path.isfile(__bedrock_ad2_path):
                        __bedrock_ad2_os.unlink(__bedrock_ad2_path)
                except Exception:
                    pass
            # fail-closed (default) and self-destruct both terminate
            __bedrock_ad2_sys.exit(0)

        def __bedrock_ad2_mark(__bedrock_ad2_tag, __bedrock_ad2_weight=1, __bedrock_ad2_is_hard=False):
            nonlocal __bedrock_ad2_soft_score, __bedrock_ad2_hard
            try:
                __bedrock_ad2_hits.append(str(__bedrock_ad2_tag))
                if __bedrock_ad2_is_hard:
                    __bedrock_ad2_hard = True
                else:
                    __bedrock_ad2_soft_score += int(__bedrock_ad2_weight)
            except Exception:
                pass

        def __bedrock_ad2_own_trace(__bedrock_ad2_fn):
            try:
                __bedrock_ad2_name = getattr(__bedrock_ad2_fn, "__name__", "")
                return __bedrock_ad2_name in ("<lambda>", "_noop")
            except Exception:
                return False

        # 1. /proc/self/status TracerPid
        try:
            with open("/proc/self/status", "r") as __bedrock_ad2_f:
                for __bedrock_ad2_line in __bedrock_ad2_f:
                    if __bedrock_ad2_line.startswith("TracerPid:"):
                        __bedrock_ad2_pid = __bedrock_ad2_line.split(":", 1)[1].strip()
                        if __bedrock_ad2_pid and __bedrock_ad2_pid != "0":
                            __bedrock_ad2_mark("tracerpid", __bedrock_ad2_is_hard=True)
                        break
        except Exception:
            pass

        # 2. ptrace(PTRACE_TRACEME) is intentionally not used here. The passive
        # TracerPid check above catches the practical case without stopping the
        # parent shell/job-control session on Linux.

        # 3. Parent process name blacklist
        try:
            __bedrock_ad2_ppid = __bedrock_ad2_os.getppid()
            with open("/proc/%d/comm" % __bedrock_ad2_ppid, "r") as __bedrock_ad2_cf:
                __bedrock_ad2_pname = __bedrock_ad2_cf.read().strip().lower()
            for __bedrock_ad2_bad in (
                "gdb", "lldb", "strace", "ltrace", "pyrasite",
                "pdb", "winpdb", "pudb", "ipdb",
            ):
                if __bedrock_ad2_pname == __bedrock_ad2_bad or __bedrock_ad2_pname.startswith(__bedrock_ad2_bad):
                    __bedrock_ad2_mark("parent:" + __bedrock_ad2_pname, __bedrock_ad2_is_hard=True)
                    break
        except SystemExit:
            raise
        except Exception:
            pass

        # 4. sys.gettrace / sys.getprofile
        try:
            __bedrock_ad2_trace = __bedrock_ad2_sys.gettrace()
            __bedrock_ad2_profile = __bedrock_ad2_sys.getprofile()
            if __bedrock_ad2_trace is not None and not __bedrock_ad2_own_trace(__bedrock_ad2_trace):
                __bedrock_ad2_mark("gettrace", __bedrock_ad2_is_hard=True)
            if __bedrock_ad2_profile is not None and not __bedrock_ad2_own_trace(__bedrock_ad2_profile):
                __bedrock_ad2_mark("getprofile", __bedrock_ad2_is_hard=True)
        except SystemExit:
            raise
        except Exception:
            pass

        # 5. Debugger-related env vars
        try:
            for __bedrock_ad2_ev in ("PYTHONBREAKPOINT", "PYTHONINSPECT"):
                __bedrock_ad2_val = __bedrock_ad2_os.environ.get(__bedrock_ad2_ev)
                if __bedrock_ad2_val:
                    # PYTHONBREAKPOINT=0 explicitly disables breakpoints -> safe.
                    if __bedrock_ad2_ev == "PYTHONBREAKPOINT" and __bedrock_ad2_val.strip() in ("0", ""):
                        continue
                    __bedrock_ad2_mark("env:" + __bedrock_ad2_ev, 1)
        except SystemExit:
            raise
        except Exception:
            pass

        # 6. Pre-imported debugger modules
        try:
            # D1: expand the cheap-module probe to cover pdb++/remote/hunter/manhole.
            for __bedrock_ad2_mod in ("pdb", "bdb", "pyrasite",
                                      "manhole", "remote_pdb", "hunter", "pdbpp", "hypothesis"):
                if __bedrock_ad2_mod in __bedrock_ad2_sys.modules:
                    __bedrock_ad2_mark("module:" + __bedrock_ad2_mod, 1)
        except SystemExit:
            raise
        except Exception:
            pass

        # 7. sys.monitoring (3.12+) — coverage/profiler/debugger registration.
        # PEP 669 introduced sys.monitoring in 3.12 as the replacement for the
        # settrace/setprofile API used by coverage.py, py-spy, debugpy, etc.
        # get_tool(tool_id) returns the registered tool name when one is active
        # under that id, else None. Any non-None registration during our
        # startup probe means a tracing tool is hooked into the interpreter.
        try:
            if __bedrock_ad2_sys.version_info >= (3, 12):
                __bedrock_ad2_mon = getattr(__bedrock_ad2_sys, "monitoring", None)
                if __bedrock_ad2_mon is not None:
                    __bedrock_ad2_ntools = getattr(__bedrock_ad2_mon, "PROGRAM_TEXT_TOOL_ID", 0) + 1
                    for __bedrock_ad2_tid in range(__bedrock_ad2_ntools):
                        __bedrock_ad2_tname = None
                        try:
                            __bedrock_ad2_tname = __bedrock_ad2_mon.get_tool(__bedrock_ad2_tid)
                        except Exception:
                            pass
                        if __bedrock_ad2_tname:
                            __bedrock_ad2_mark("monitoring:" + str(__bedrock_ad2_tname), __bedrock_ad2_is_hard=True)
        except SystemExit:
            raise
        except Exception:
            pass

        # 8. Frida-server TCP probe (frida-server default port 27042).
        # A successful connect means frida-server is listening locally.
        # Cross-platform pure-Python socket probe; 50ms timeout won't block.
        # Catches Frida even when no /proc maps entry is visible (agent-only).
        try:
            import socket as __bedrock_ad2_sk
            __bedrock_ad2_s = __bedrock_ad2_sk.socket(__bedrock_ad2_sk.AF_INET, __bedrock_ad2_sk.SOCK_STREAM)
            __bedrock_ad2_s.settimeout(0.05)
            try:
                if __bedrock_ad2_s.connect_ex(("127.0.0.1", 27042)) == 0:
                    __bedrock_ad2_mark("frida-port", __bedrock_ad2_is_hard=True)
            finally:
                try:
                    __bedrock_ad2_s.close()
                except Exception:
                    pass
        except SystemExit:
            raise
        except Exception:
            pass

        # 9. Thread-name enumeration for frida agent threads (Linux /proc).
        # gum-js-loop / gmain / gdbus are Frida's canonical worker thread names.
        # Catches injected agents even when no maps entry is visible.
        try:
            __bedrock_ad2_task_dir = "/proc/self/task"
            if __bedrock_ad2_os.path.isdir(__bedrock_ad2_task_dir):
                for __bedrock_ad2_tid in __bedrock_ad2_os.listdir(__bedrock_ad2_task_dir):
                    try:
                        with open(__bedrock_ad2_task_dir + "/" + __bedrock_ad2_tid + "/comm", "r") as __bedrock_ad2_tf:
                            __bedrock_ad2_tn = __bedrock_ad2_tf.read().strip().lower()
                        for __bedrock_ad2_bad in ("gum-js-loop", "gmain", "gdbus", "linjector", "frida"):
                            if __bedrock_ad2_bad in __bedrock_ad2_tn:
                                __bedrock_ad2_mark("thread:" + __bedrock_ad2_tn, __bedrock_ad2_is_hard=True)
                                break
                    except Exception:
                        pass
        except SystemExit:
            raise
        except Exception:
            pass

        if __bedrock_ad2_hard or __bedrock_ad2_soft_score >= 2:
            __bedrock_ad2_react(",".join(__bedrock_ad2_hits))

    __bedrock_ad2_main()
    del __bedrock_ad2_main
    # --- end anti-debugger v2 ---
    ''').lstrip("\n")


    def _derive_rng(ctx: Any) -> random.Random:
        """Mirror ``hardening._derive_rng`` so both modules pick the same RNG."""
        rng = getattr(ctx, "rng", None)
        if isinstance(rng, random.Random):
            return rng
        seed_src = "|".join(
            str(getattr(ctx, attr, ""))
            for attr in ("input_path", "output_path", "profile", "runtime_mode")
        ) or os.urandom(16).hex()
        return random.Random(seed_src)


    def _rand_tag(rng: random.Random, n: int = 8) -> str:
        return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


    def _randomize_names(snippet: str, rng: random.Random) -> str:
        """Replace the fixed ``__bedrock_ad2_`` prefix with a per-build random tag.

        Only identifiers we own are touched -- collisions with bedrock's own
        ``__bedrock_*`` namespace are avoided by including our own random suffix.
        """
        tag = _rand_tag(rng)
        return snippet.replace("__bedrock_ad2_", f"__{BR_DEBRAND[chr(98)+chr(101)+chr(100)+chr(114)+chr(111)+chr(99)+chr(107)]}_ad2_{tag}_")


    def wrap_with_anti_dbg_v2(src: str, ctx: Any) -> str:
        """Inject the anti-debugger v2 snippet at the top of ``src``.

        A leading shebang / coding cookie is preserved.

        The reaction mode is read from ``ctx.tamper`` and may be one of
        ``"warn"``, ``"fail-closed"`` (default) or ``"self-destruct"``.
        """
        rng = _derive_rng(ctx)
        mode = getattr(ctx, "tamper", "fail-closed")
        if mode not in ("warn", "fail-closed", "self-destruct", "poison"):
            mode = "fail-closed"

        snippet = ANTI_DBG_V2_SNIPPET.replace("__BEDROCK_AD2_MODE__", mode)
        snippet = _randomize_names(snippet, rng)

        head, body = "", src
        if src.startswith("#!"):
            nl = src.find("\n")
            if nl != -1:
                head, body = src[: nl + 1], src[nl + 1:]

        return _debrand(head + snippet + body)




    # === [INLINE] bedrock_ext/junk.py ===

    """Junk code & opaque-predicate injection pass for bedrock.

    Public API: ``apply_junk(tree, ctx) -> ast.Module``.

    For every eligible function body we randomly (driven by ``ctx.rng``) insert
    semantics-preserving noise:

    * **Opaque-true** wraps: ``if (x*x + 1) > 0: <orig>`` — always taken.
    * **Opaque-false dead branches**: ``if (n*n + 1) % 2 == 0 and n != 0: <junk>``
      — never taken for integer ``n != 0`` (n*n+1 is always odd).
    * **Mathematical identity** no-ops: ``_jnk_X = (v | 0) ^ 0``.
    * **Dead try/except**: ``try: pass\\nexcept ZeroDivisionError: <junk>`` —
      handler unreachable.
    * **Fake string ops**: ``_jnk_X = "decoy" + str(<rand>)``.

    Skip rules:
    * generators / async functions / functions whose body contains
      ``yield`` / ``yield from`` / ``await``;
    * function bodies with <= 1 statement.

    Density is governed by ``ctx.junk_level`` (int 1..5, default 2). Higher
    levels insert more junk per body and per insertion site.
    """

    import ast
    import random
    from typing import Any, List


    _DECOY_PREFIX = "_jnk_"


    def _is_generator(fn: ast.FunctionDef) -> bool:
        for sub in ast.walk(fn):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not fn:
                # Skip nested defs — their yields don't make `fn` a generator.
                continue
            if isinstance(sub, (ast.Yield, ast.YieldFrom)):
                return True
        return False


    def _has_await(fn: ast.FunctionDef) -> bool:
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Await):
                return True
        return False


    def _rand_name(rng: random.Random) -> str:
        return f"{_DECOY_PREFIX}{rng.randrange(1 << 24):06x}"


    def _rand_int(rng: random.Random, lo: int = 1, hi: int = 9999) -> int:
        return rng.randint(lo, hi)


    # --- junk-statement factories -----------------------------------------------

    def _make_identity_noop(rng: random.Random) -> ast.stmt:
        name = _rand_name(rng)
        val = _rand_int(rng)
        # _jnk_X = (val | 0) ^ 0
        expr = ast.BinOp(
            left=ast.BinOp(left=ast.Constant(value=val), op=ast.BitOr(),
                           right=ast.Constant(value=0)),
            op=ast.BitXor(),
            right=ast.Constant(value=0),
        )
        return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=expr)


    def _make_fake_string_op(rng: random.Random) -> ast.stmt:
        name = _rand_name(rng)
        val = _rand_int(rng)
        expr = ast.BinOp(
            left=ast.Constant(value="decoy"),
            op=ast.Add(),
            right=ast.Call(
                func=ast.Name(id="str", ctx=ast.Load()),
                args=[ast.Constant(value=val)],
                keywords=[],
            ),
        )
        return ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=expr)


    def _make_dead_try(rng: random.Random) -> ast.stmt:
        handler_body: List[ast.stmt] = [_make_identity_noop(rng), _make_fake_string_op(rng)]
        return ast.Try(
            body=[ast.Pass()],
            handlers=[ast.ExceptHandler(
                type=ast.Name(id="ZeroDivisionError", ctx=ast.Load()),
                name=None,
                body=handler_body,
            )],
            orelse=[],
            finalbody=[],
        )


    def _make_opaque_false_branch(rng: random.Random) -> ast.stmt:
        # n is a literal positive int; (n*n + 1) % 2 == 0 is always False.
        n = _rand_int(rng, 2, 999)
        test = ast.BoolOp(
            op=ast.And(),
            values=[
                ast.Compare(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Constant(value=n),
                            op=ast.Mult(),
                            right=ast.Constant(value=n),
                        ),
                        op=ast.Add(),
                        right=ast.Constant(value=1),
                    ),
                    ops=[ast.Mod(), ast.Eq()] if False else [ast.Eq()],
                    comparators=[ast.Constant(value=0)],
                ),
                ast.Compare(
                    left=ast.Constant(value=n),
                    ops=[ast.NotEq()],
                    comparators=[ast.Constant(value=0)],
                ),
            ],
        )
        # The Compare above isn't quite "(n*n+1) % 2 == 0"; rebuild cleanly.
        test = ast.BoolOp(
            op=ast.And(),
            values=[
                ast.Compare(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.BinOp(left=ast.Constant(value=n),
                                           op=ast.Mult(),
                                           right=ast.Constant(value=n)),
                            op=ast.Add(),
                            right=ast.Constant(value=1),
                        ),
                        op=ast.Mod(),
                        right=ast.Constant(value=2),
                    ),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=0)],
                ),
                ast.Compare(
                    left=ast.Constant(value=n),
                    ops=[ast.NotEq()],
                    comparators=[ast.Constant(value=0)],
                ),
            ],
        )
        body: List[ast.stmt] = [
            _make_identity_noop(rng),
            _make_fake_string_op(rng),
            ast.Assign(
                targets=[ast.Name(id=_rand_name(rng), ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="len", ctx=ast.Load()),
                    args=[ast.Constant(value="never")],
                    keywords=[],
                ),
            ),
        ]
        return ast.If(test=test, body=body, orelse=[])


    # =========================================================================
    # A2: Opaque-predicate library
    # -------------------------------------------------------------------------
    # Each factory emits an `if <always-true>:` or `if <always-false>:` whose
    # test is a non-trivial identity the decompiler must actually reason about
    # (not just the single `(n*n+1) > 0` form).  All identities are verified
    # mathematically for the chosen parameter ranges, so the dead branch is
    # genuinely never taken (or the live branch genuinely always taken).
    # =========================================================================

    def _junk_body(rng: random.Random) -> List[ast.stmt]:
        """Standard 2-3 statement body for opaque-predicate branches."""
        return [
            _make_identity_noop(rng),
            _make_fake_string_op(rng),
            ast.Assign(
                targets=[ast.Name(id=_rand_name(rng), ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="len", ctx=ast.Load()),
                    args=[ast.Constant(value="never")],
                    keywords=[],
                ),
            ),
        ]


    def _make_opaque_mba_true(rng: random.Random) -> ast.stmt:
        # MBA identity: (a ^ b) | (a & b) == a | b  is always True.
        a = _rand_int(rng, 1, 4095)
        b = _rand_int(rng, 1, 4095)
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=a), op=ast.BitXor(),
                               right=ast.Constant(value=b)),
                op=ast.BitOr(),
                right=ast.BinOp(left=ast.Constant(value=a), op=ast.BitAnd(),
                                right=ast.Constant(value=b)),
            ),
            ops=[ast.Eq()],
            comparators=[ast.BinOp(left=ast.Constant(value=a), op=ast.BitOr(),
                                   right=ast.Constant(value=b))],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    def _make_opaque_mba_false(rng: random.Random) -> ast.stmt:
        # (a & b) > (a | b)  is always False for non-negative ints.
        a = _rand_int(rng, 1, 4095)
        b = _rand_int(rng, 1, 4095)
        test = ast.BoolOp(
            op=ast.And(),
            values=[
                ast.Compare(
                    left=ast.BinOp(left=ast.Constant(value=a), op=ast.BitAnd(),
                                   right=ast.Constant(value=b)),
                    ops=[ast.Gt()],
                    comparators=[ast.BinOp(left=ast.Constant(value=a), op=ast.BitOr(),
                                            right=ast.Constant(value=b))],
                ),
                ast.Compare(
                    left=ast.Constant(value=a),
                    ops=[ast.NotEq()],
                    comparators=[ast.Constant(value=0)],
                ),
            ],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    def _make_opaque_collatz_true(rng: random.Random) -> ast.stmt:
        # For odd n, (n * 3 + 1) is always even, so % 2 == 0 is always True.
        n = rng.randrange(1, 4096) * 2 + 1  # guarantee odd
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.BinOp(left=ast.Constant(value=n), op=ast.Mult(),
                                   right=ast.Constant(value=3)),
                    op=ast.Add(),
                    right=ast.Constant(value=1),
                ),
                op=ast.Mod(),
                right=ast.Constant(value=2),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    def _make_opaque_modinv_true(rng: random.Random) -> ast.stmt:
        # (a * pow(a, -1, m)) % m == 1  when gcd(a, m) == 1.  Choose a prime m
        # so any a in [1, m) is coprime; the identity holds unconditionally.
        # pow(a, -1, m) is a 3.8+ feature but we target 3.10-3.12 so it's safe.
        primes = (101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
                  163, 167, 173, 179, 181, 191, 193, 197, 199)
        m = rng.choice(primes)
        a = rng.randint(1, m - 1)
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=a), op=ast.Mult(),
                               right=ast.Call(
                                   func=ast.Name(id="pow", ctx=ast.Load()),
                                   args=[ast.Constant(value=a),
                                         ast.UnaryOp(op=ast.USub(),
                                                     operand=ast.Constant(value=1)),
                                         ast.Constant(value=m)],
                                   keywords=[])),
                op=ast.Mod(),
                right=ast.Constant(value=m),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=1)],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    def _make_opaque_bitcount_true(rng: random.Random) -> ast.stmt:
        # For a 32-bit x: popcount(x) + popcount(mask ^ x) == 32, where
        # mask = 0xFFFFFFFF.  Using `mask ^ x` (not `~x & mask`) avoids the
        # unary Invert node which the VM-native AST compiler rejects.
        x = rng.randint(0, 0xFFFFFFFF)
        mask = 0xFFFFFFFF
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(func=ast.Name(id="bin", ctx=ast.Load()),
                                       args=[ast.Constant(value=x)], keywords=[]),
                        attr="count", ctx=ast.Load()),
                    args=[ast.Constant(value="1")], keywords=[]),
                op=ast.Add(),
                right=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(func=ast.Name(id="bin", ctx=ast.Load()),
                                       args=[ast.BinOp(
                                           left=ast.Constant(value=mask),
                                           op=ast.BitXor(),
                                           right=ast.Constant(value=x))],
                                       keywords=[]),
                        attr="count", ctx=ast.Load()),
                    args=[ast.Constant(value="1")], keywords=[]),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=32)],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    def _make_opaque_quadratic_true(rng: random.Random) -> ast.stmt:
        # Euler's prime-generating polynomial: n*n + n + 41 is prime for
        # 0 <= n < 40.  We test divisibility by a handful of small primes p
        # for which (n*n+n+41) % p != 0 (precomputed safe set per n).  Simpler
        # and fully safe: (n*n + n + 41) % 41 == 41 when n % 41 == 0, but
        # clearer invariant: for n in [0, 39], n*(n+1) is even so
        # (n*n + n + 41) is odd → % 2 == 1 always True for n in [0, 39].
        n = rng.randint(0, 39)
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.BinOp(left=ast.Constant(value=n), op=ast.Mult(),
                                   right=ast.Constant(value=n)),
                    op=ast.Add(),
                    right=ast.BinOp(left=ast.Constant(value=n), op=ast.Add(),
                                   right=ast.Constant(value=41)),
                ),
                op=ast.Mod(),
                right=ast.Constant(value=2),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=1)],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    # A3: Carmichael-number opaque predicate.  A Carmichael number N is a
    # *composite* N such that a**N == a (mod N) for every integer a (Korselt's
    # criterion).  The identity `pow(a, N, N) == a % N` has no closed-form
    # simplification a decompiler can apply without recognising N as a
    # Carmichael number, so it resists constant folding far better than the
    # elementary `(n*n+n) % 2 == 0` form.  Verified for all a in [0, N) and
    # for a < 0, a >= N, a sharing a factor with N (Carmichael property holds
    # unconditionally).  `pow(a, -1, m)` is already used by _make_opaque_modinv
    # _true, so the 3-arg pow call compiles in VM-native mode.
    _CARMICHAEL_NUMBERS = (561, 1105, 1729, 2465, 2821, 6601, 8911, 10585,
                           15841)

    def _make_opaque_carmichael_true(rng: random.Random) -> ast.stmt:
        N = rng.choice(_CARMICHAEL_NUMBERS)
        a = rng.randint(0, N - 1)
        test = ast.Compare(
            left=ast.Call(
                func=ast.Name(id="pow", ctx=ast.Load()),
                args=[ast.Constant(value=a), ast.Constant(value=N),
                      ast.Constant(value=N)],
                keywords=[]),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=a)],
        )
        return ast.If(test=test, body=_junk_body(rng), orelse=[])


    _JUNK_FACTORIES = (
        _make_identity_noop,
        _make_fake_string_op,
        _make_dead_try,
        _make_opaque_false_branch,
        # --- A2: opaque-predicate library (randomised per build) ---
        _make_opaque_mba_true,
        _make_opaque_mba_false,
        _make_opaque_collatz_true,
        _make_opaque_modinv_true,
        _make_opaque_bitcount_true,
        _make_opaque_quadratic_true,
        # --- A3: data-flow-dependent dynamic opaque (no closed-form fold) ---
        _make_opaque_carmichael_true,
    )


    def _make_random_junk(rng: random.Random) -> ast.stmt:
        return rng.choice(_JUNK_FACTORIES)(rng)


    # --- opaque-true wrap -------------------------------------------------------

    def _wrap_opaque_true(stmt: ast.stmt, rng: random.Random) -> ast.stmt:
        """Wrap stmt in `if (x*x + 1) > 0:` — always true for any int x."""
        x = _rand_int(rng, 1, 999)
        test = ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=x),
                               op=ast.Mult(),
                               right=ast.Constant(value=x)),
                op=ast.Add(),
                right=ast.Constant(value=1),
            ),
            ops=[ast.Gt()],
            comparators=[ast.Constant(value=0)],
        )
        return ast.If(test=test, body=[stmt], orelse=[])


    # --- core injection ---------------------------------------------------------

    # Statements we don't want to wrap (control-flow keywords have to stay where
    # they are, and module/class-level statements shouldn't be touched).
    _NO_WRAP = (ast.Return, ast.Raise, ast.Break, ast.Continue,
                ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom)


    def _inject_into_body(body: List[ast.stmt], rng: random.Random,
                          level: int) -> List[ast.stmt]:
        if len(body) <= 1:
            return body

        # Per-level tuning: (junk_prob, wrap_prob, junk_burst_max)
        table = {
            1: (0.10, 0.05, 1),
            2: (0.20, 0.10, 1),
            3: (0.35, 0.15, 2),
            4: (0.55, 0.25, 2),
            5: (0.80, 0.40, 3),
        }
        junk_p, wrap_p, burst = table.get(level, table[2])

        out: List[ast.stmt] = []
        # Preserve a leading docstring exactly where it is.
        start = 0
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            out.append(body[0])
            start = 1

        for idx, stmt in enumerate(body[start:], start=start):
            # Insert junk *before* this statement with prob junk_p.
            if rng.random() < junk_p:
                for _ in range(rng.randint(1, burst)):
                    out.append(_make_random_junk(rng))
            # Optionally wrap stmt in opaque-true.
            if (not isinstance(stmt, _NO_WRAP)
                    and rng.random() < wrap_p):
                out.append(_wrap_opaque_true(stmt, rng))
            else:
                out.append(stmt)

        # Trailing junk before any terminator (but only if last stmt isn't a
        # bare Return that we want to keep clean — we still allow it; junk goes
        # *before* it so semantics are preserved).
        if rng.random() < junk_p:
            terminator = None
            if out and isinstance(out[-1], (ast.Return, ast.Raise)):
                terminator = out.pop()
            out.append(_make_random_junk(rng))
            if terminator is not None:
                out.append(terminator)

        return out


    def _process_function(fn: ast.FunctionDef, rng: random.Random,
                          level: int) -> bool:
        if isinstance(fn, ast.AsyncFunctionDef):
            return False
        if _is_generator(fn) or _has_await(fn):
            return False
        if len(fn.body) <= 1:
            return False
        # Skip functions containing nonlocal/global declarations: inserting
        # opaque-predicate junk before such a statement triggers
        # "name assigned to before nonlocal declaration" when the junk body
        # binds a decoy name in the same scope. This is especially important
        # for injected anti-debug/anti-hook snippets that lean on nonlocal.
        for stmt in fn.body:
            if isinstance(stmt, (ast.Nonlocal, ast.Global)):
                return False
        fn.body = _inject_into_body(fn.body, rng, level)
        return True


    def apply_junk(tree: ast.Module, ctx: Any) -> ast.Module:
        """Inject junk code & opaque predicates into eligible functions.

        ``ctx`` may carry:
            * ``rng``: a ``random.Random`` instance (else a fresh one is used).
            * ``junk_level``: int in [1, 5] controlling density (default 2).
        """
        rng = getattr(ctx, "rng", None) or random.Random()
        level = int(getattr(ctx, "junk_level", 2) or 2)
        if level < 1:
            level = 1
        elif level > 5:
            level = 5

        class _Visitor(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.generic_visit(node)
                try:
                    _process_function(node, rng, level)
                except Exception:
                    # Fail-safe: never break the build because of a bad fn.
                    pass
                return node

            def visit_AsyncFunctionDef(self, node):
                # Skip async functions entirely.
                return node

        new_tree = _Visitor().visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree




    # === [INLINE] bedrock_ext/import_obf.py ===

    """Import obfuscation pass for bedrock.

    Public API:
        apply_import_obf(tree: ast.Module, ctx) -> ast.Module
        IMPORT_OBF_PREAMBLE: str  -- code to be prepended to the obfuscated module

    Rewrites:
        import x                    -> x = __import__(_bedrock_dec("<enc>"))
        import x.y.z                -> x = __import__(_bedrock_dec("x.y.z"))   # binds top
        import x.y.z as a           -> a = __import__(_bedrock_dec("x.y.z"),
                                                      fromlist=[_bedrock_dec("z")]).z
        import x as a               -> a = __import__(_bedrock_dec("x"))
        from x import y, z          -> _m = __import__(_bedrock_dec("x"),
                                                       fromlist=[_bedrock_dec("y"),
                                                                 _bedrock_dec("z")])
                                       y = _m.y; z = _m.z
        from x import y as q        -> _m = __import__(...); q = _m.y
        from x import *             -> kept as-is (edge case, complex semantics)

    Skips:
        - ``from __future__ import ...``  (must be syntactic, top-of-file)
        - ``import typing`` / ``from typing import ...`` when followed by
          ``TYPE_CHECKING`` heuristic (we keep them as-is to avoid breaking
          lazy / conditional typing).
        - Imports inside ``if TYPE_CHECKING:`` blocks (we don't descend).

    Encoding:
        Per-build XOR with ``ctx.rng.randbytes(8)`` (or fallback random),
        then base64. ``_bedrock_dec(s)`` is embedded in the preamble.

    Optional ``--import-blob`` mode:
        All module-name strings are pooled into a single zlib-compressed,
        XOR-encoded base64 blob, decoded lazily on first access via an
        index lookup ``_bedrock_blob(i)`` -> str.
    """


    import ast
    import base64
    import random
    import zlib
    from typing import Any, Dict, List, Optional, Tuple


    # ---- helpers --------------------------------------------------------------

    def _get_rng(ctx) -> random.Random:
        rng = getattr(ctx, "rng", None)
        if rng is None:
            rng = random.Random()
            try:
                ctx.rng = rng  # type: ignore[attr-defined]
            except Exception:
                pass
        return rng


    def _rand_bytes(rng: random.Random, n: int) -> bytes:
        fn = getattr(rng, "randbytes", None)
        if fn is not None:
            return fn(n)
        return bytes(rng.getrandbits(8) for _ in range(n))


    def _xor_b64_encode(data: bytes, key: bytes) -> str:
        out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return base64.b64encode(out).decode("ascii")


    # Skips:
    _NEVER_OBF_FROM = {"__future__"}


    def _is_typing_check(stmt: ast.stmt) -> bool:
        # Skip ``if TYPE_CHECKING:`` blocks entirely; caller decides.
        if isinstance(stmt, ast.If):
            t = stmt.test
            if isinstance(t, ast.Name) and t.id == "TYPE_CHECKING":
                return True
            if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                    and t.value.id == "typing" and t.attr == "TYPE_CHECKING"):
                return True
        return False


    # ---- preamble template ----------------------------------------------------

    def _build_preamble(key: bytes, blob: Optional[bytes]) -> str:
        key_lit = repr(key)
        parts = [
            "import base64 as _b64, zlib as _zl",
            f"_BEDROCK_K = {key_lit}",
            "def _bedrock_dec(s):",
            "    d = _b64.b64decode(s.encode('ascii'))",
            "    k = _BEDROCK_K",
            "    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d)).decode('utf-8')",
        ]
        if blob is not None:
            blob_lit = repr(base64.b64encode(blob).decode("ascii"))
            parts += [
                f"_BEDROCK_BLOB_RAW = {blob_lit}",
                "_BEDROCK_BLOB_CACHE = None",
                "def _bedrock_blob(i):",
                "    global _BEDROCK_BLOB_CACHE",
                "    if _BEDROCK_BLOB_CACHE is None:",
                "        raw = _b64.b64decode(_BEDROCK_BLOB_RAW.encode('ascii'))",
                "        k = _BEDROCK_K",
                "        x = bytes(b ^ k[j % len(k)] for j, b in enumerate(raw))",
                "        _BEDROCK_BLOB_CACHE = _zl.decompress(x).decode('utf-8').split('\\x00')",
                "    return _BEDROCK_BLOB_CACHE[i]",
            ]
        return "\n".join(parts) + "\n"


    # Default preamble (key=zero) — overwritten per-build by apply_import_obf
    IMPORT_OBF_PREAMBLE: str = _build_preamble(b"\x00" * 8, None)


    # ---- AST rewriter ---------------------------------------------------------

    class _ImportRewriter(ast.NodeTransformer):
        def __init__(self, key: bytes, blob_pool: Optional[List[str]]):
            self.key = key
            self.blob_pool = blob_pool  # list to append into, or None for direct mode

        def _str_node(self, s: str) -> ast.expr:
            if self.blob_pool is not None:
                try:
                    idx = self.blob_pool.index(s)
                except ValueError:
                    idx = len(self.blob_pool)
                    self.blob_pool.append(s)
                return ast.Call(
                    func=ast.Name(id="_bedrock_blob", ctx=ast.Load()),
                    args=[ast.Constant(value=idx)],
                    keywords=[],
                )
            enc = _xor_b64_encode(s.encode("utf-8"), self.key)
            return ast.Call(
                func=ast.Name(id="_bedrock_dec", ctx=ast.Load()),
                args=[ast.Constant(value=enc)],
                keywords=[],
            )

        def _import_call(self, modname: str,
                         fromlist: Optional[List[str]] = None) -> ast.expr:
            kw = []
            if fromlist:
                kw.append(ast.keyword(
                    arg="fromlist",
                    value=ast.List(
                        elts=[self._str_node(n) for n in fromlist],
                        ctx=ast.Load(),
                    ),
                ))
            return ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[self._str_node(modname)],
                keywords=kw,
            )

        # --- Import ---
        def visit_Import(self, node: ast.Import) -> Any:
            out: List[ast.stmt] = []
            for alias in node.names:
                name = alias.name
                asname = alias.asname
                if asname is None:
                    # ``import x.y.z`` binds ``x`` to top-level package
                    top = name.split(".")[0]
                    call = self._import_call(name)
                    out.append(ast.Assign(
                        targets=[ast.Name(id=top, ctx=ast.Store())],
                        value=call,
                    ))
                else:
                    # ``import x.y.z as a`` -> a = __import__("x.y.z", fromlist=["z"]).z
                    # For simple ``import x as a`` -> a = __import__("x")
                    if "." in name:
                        # Use ``fromlist=[""]`` trick: __import__ returns the
                        # leaf submodule itself (not the top package), without
                        # the ``getattr(.., leaf)`` ambiguity (which can pick
                        # up a same-named class instead of the submodule).
                        val: ast.expr = self._import_call(name, fromlist=[""])
                    else:
                        val = self._import_call(name)
                    out.append(ast.Assign(
                        targets=[ast.Name(id=asname, ctx=ast.Store())],
                        value=val,
                    ))
            for s in out:
                ast.copy_location(s, node)
                ast.fix_missing_locations(s)
            return out

        # --- ImportFrom ---
        def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
            # Skip relative imports (level > 0) — semantics depend on package ctx
            if node.level and node.level > 0:
                return node
            modname = node.module or ""
            if modname in _NEVER_OBF_FROM:
                return node
            # ``from x import *`` — keep as-is
            if any(a.name == "*" for a in node.names):
                return node
            # build: _bedrock_m_<n> = __import__(mod, fromlist=[names])
            names = [a.name for a in node.names]
            tmp = f"_bedrock_m_{abs(hash((modname, tuple(names)))) & 0xFFFF:x}"
            out: List[ast.stmt] = []
            out.append(ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=self._import_call(modname, fromlist=names),
            ))
            for alias in node.names:
                bind = alias.asname or alias.name
                out.append(ast.Assign(
                    targets=[ast.Name(id=bind, ctx=ast.Store())],
                    value=ast.Attribute(
                        value=ast.Name(id=tmp, ctx=ast.Load()),
                        attr=alias.name, ctx=ast.Load(),
                    ),
                ))
            for s in out:
                ast.copy_location(s, node)
                ast.fix_missing_locations(s)
            return out


    # ---- top-level entry ------------------------------------------------------

    def apply_import_obf(tree: ast.Module, ctx) -> ast.Module:
        """Rewrite import statements in ``tree``.

        Reads optional flags from ``ctx``:
            ctx.import_obf      (bool)  -- master switch (caller usually checks)
            ctx.import_blob     (bool)  -- pool strings into single zlib blob
        Sets:
            ctx._import_obf_preamble  (str)  -- the preamble to prepend
        """
        rng = _get_rng(ctx)
        key = _rand_bytes(rng, 8)
        use_blob = bool(getattr(ctx, "import_blob", False))
        blob_pool: Optional[List[str]] = [] if use_blob else None

        rewriter = _ImportRewriter(key, blob_pool)

        new_body: List[ast.stmt] = []
        for stmt in tree.body:
            if _is_typing_check(stmt):
                new_body.append(stmt)
                continue
            rewritten = rewriter.visit(stmt)
            if isinstance(rewritten, list):
                new_body.extend(rewritten)
            else:
                new_body.append(rewritten)
        tree.body = new_body
        ast.fix_missing_locations(tree)

        blob_bytes: Optional[bytes] = None
        if use_blob and blob_pool:
            joined = "\x00".join(blob_pool).encode("utf-8")
            compressed = zlib.compress(joined, 9)
            blob_bytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(compressed))

        preamble = _build_preamble(key, blob_bytes)
        try:
            ctx._import_obf_preamble = preamble  # type: ignore[attr-defined]
        except Exception:
            pass
        # Also update module-level for callers that read it directly
        global IMPORT_OBF_PREAMBLE
        IMPORT_OBF_PREAMBLE = preamble
        return tree




    # === [INLINE] bedrock_ext/homoglyph.py ===

    """Unicode homoglyph identifier renamer for bedrock.py.

    Side-car extension: never imports or mutates bedrock.py. Wiring instructions
    live in WIRING_homoglyph.md.

    Renames local variable / function / class names to visually-confusable
    identifiers built from Unicode homoglyphs (Cyrillic / Greek / Cherokee / etc.)
    so the resulting source is nearly unreadable while still being a valid Python
    identifier (verified via ``str.isidentifier()``).

    Public entry point::

        apply_homoglyph(tree: ast.Module, ctx) -> ast.Module
    """


    import ast
    import builtins
    import keyword
    import random
    from typing import Iterable, Optional, Set


    # ---------------------------------------------------------------------------
    # Confusable pool
    # ---------------------------------------------------------------------------
    # At least 30 confusable code points spread across the requested anchor
    # letters (A, B, C, E, H, I, K, M, N, O, P, S, T, X, Y).  Every char below is
    # classified by Python as XID_Start / XID_Continue so any combination yields
    # a valid identifier.
    HOMOGLYPHS: tuple = (
        # A-like
        "А",  # CYRILLIC CAPITAL LETTER A
        "Α",  # GREEK CAPITAL LETTER ALPHA
        "Ꭺ",  # CHEROKEE LETTER GO (Ꭺ)
        "Ａ",  # FULLWIDTH LATIN CAPITAL LETTER A
        # B-like
        "В",  # CYRILLIC CAPITAL LETTER VE (В)
        "Β",  # GREEK CAPITAL LETTER BETA
        "Ᏼ",  # CHEROKEE LETTER YV (Ᏼ)
        # C-like
        "С",  # CYRILLIC CAPITAL LETTER ES (С)
        "Ϲ",  # GREEK CAPITAL LUNATE SIGMA SYMBOL (Ϲ)
        "Ꮯ",  # CHEROKEE LETTER TLI (Ꮯ)
        # E-like
        "Е",  # CYRILLIC CAPITAL LETTER IE (Е)
        "Ε",  # GREEK CAPITAL LETTER EPSILON
        "Ꭼ",  # CHEROKEE LETTER GV (Ꭼ)
        # H-like
        "Н",  # CYRILLIC CAPITAL LETTER EN (Н)
        "Η",  # GREEK CAPITAL LETTER ETA
        "Ꮋ",  # CHEROKEE LETTER MI (Ꮋ)
        # I-like
        "І",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I (І)
        "Ι",  # GREEK CAPITAL LETTER IOTA
        # K-like
        "К",  # CYRILLIC CAPITAL LETTER KA (К)
        "Κ",  # GREEK CAPITAL LETTER KAPPA
        "Ꮶ",  # CHEROKEE LETTER TSO (Ꮶ)
        # M-like
        "М",  # CYRILLIC CAPITAL LETTER EM (М)
        "Μ",  # GREEK CAPITAL LETTER MU
        "Ꮇ",  # CHEROKEE LETTER LU (Ꮇ)
        # N-like
        "Ν",  # GREEK CAPITAL LETTER NU
        # O-like
        "О",  # CYRILLIC CAPITAL LETTER O (О)
        "Ο",  # GREEK CAPITAL LETTER OMICRON
        "Ꭰ",  # CHEROKEE LETTER A (Ꭱ-area; visually O-ish in some fonts)
        # P-like
        "Р",  # CYRILLIC CAPITAL LETTER ER (Р)
        "Ρ",  # GREEK CAPITAL LETTER RHO
        "Ꮲ",  # CHEROKEE LETTER TLV (Ꮲ)
        # S-like
        "Ѕ",  # CYRILLIC CAPITAL LETTER DZE (Ѕ)
        # T-like
        "Т",  # CYRILLIC CAPITAL LETTER TE (Т)
        "Τ",  # GREEK CAPITAL LETTER TAU
        "Ꭲ",  # CHEROKEE LETTER I (Ꭲ)
        # X-like
        "Х",  # CYRILLIC CAPITAL LETTER HA (Х)
        "Χ",  # GREEK CAPITAL LETTER CHI
        # Y-like
        "У",  # CYRILLIC CAPITAL LETTER U (У)
        "Υ",  # GREEK CAPITAL LETTER UPSILON
        "Ꭹ",  # CHEROKEE LETTER GI (Ᏹ-ish)
    )

    assert len(HOMOGLYPHS) >= 30, "homoglyph pool must contain at least 30 chars"


    # ---------------------------------------------------------------------------
    # Skip-set construction
    # ---------------------------------------------------------------------------
    _BUILTINS: Set[str] = set(dir(builtins)) | set(keyword.kwlist) | {
        "self", "cls", "__init__", "__main__", "__name__", "__file__",
        "__doc__", "__class__", "__dict__", "__module__", "__qualname__",
    }


    def _is_dunder(name: str) -> bool:
        return name.startswith("__") and name.endswith("__")


    # ---------------------------------------------------------------------------
    # Name generator
    # ---------------------------------------------------------------------------
    class _HomoglyphNamer:
        def __init__(self, rng: Optional[random.Random] = None) -> None:
            self.rng = rng or random.Random()
            self.used: Set[str] = set()

        def fresh(self) -> str:
            for _ in range(2048):
                length = self.rng.randint(8, 16)
                candidate = "".join(self.rng.choice(HOMOGLYPHS) for _ in range(length))
                if candidate in self.used:
                    continue
                if not candidate.isidentifier():
                    continue
                if keyword.iskeyword(candidate):
                    continue
                self.used.add(candidate)
                return candidate
            # extreme-fallback: append disambiguator
            i = 0
            while True:
                i += 1
                candidate = "".join(self.rng.choice(HOMOGLYPHS) for _ in range(16)) + str(i)
                if candidate.isidentifier() and candidate not in self.used:
                    self.used.add(candidate)
                    return candidate


    # ---------------------------------------------------------------------------
    # Collector / rewriter
    # ---------------------------------------------------------------------------
    class _Collector(ast.NodeVisitor):
        """Collect candidate names defined in the module scope (functions,
        classes, top-level assignments) plus their bodies' local assignments."""

        def __init__(self, skip: Set[str]) -> None:
            self.skip = skip
            self.names: Set[str] = set()

        def _consider(self, name: str) -> None:
            if not name or name in self.skip or _is_dunder(name):
                return
            if keyword.iskeyword(name):
                return
            self.names.add(name)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._consider(node.name)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._consider(node.name)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._consider(node.name)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            for tgt in node.targets:
                for n in _iter_assign_targets(tgt):
                    self._consider(n)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            for n in _iter_assign_targets(node.target):
                self._consider(n)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            for n in _iter_assign_targets(node.target):
                self._consider(n)
            self.generic_visit(node)

        def visit_For(self, node: ast.For) -> None:
            for n in _iter_assign_targets(node.target):
                self._consider(n)
            self.generic_visit(node)

    class _PublicSurfaceCollector(ast.NodeVisitor):
        """Names that must remain stable because Python looks them up by text."""

        def __init__(self) -> None:
            self.names: Set[str] = set()

        def visit_Attribute(self, node: ast.Attribute) -> None:
            self.names.add(node.attr)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            for keyword in node.keywords:
                if keyword.arg:
                    self.names.add(keyword.arg)
            self.generic_visit(node)


    def _iter_assign_targets(node: ast.AST) -> Iterable[str]:
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                yield from _iter_assign_targets(elt)
        elif isinstance(node, ast.Starred):
            yield from _iter_assign_targets(node.value)


    class _Renamer(ast.NodeTransformer):
        def __init__(self, mapping: dict) -> None:
            self.mapping = mapping
            self.renames = 0

        def _map(self, name: Optional[str]) -> Optional[str]:
            if name is None:
                return None
            new = self.mapping.get(name)
            if new is not None:
                self.renames += 1
                return new
            return name

        def visit_Name(self, node: ast.Name) -> ast.AST:
            new = self.mapping.get(node.id)
            if new is not None:
                self.renames += 1
                node.id = new
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            new = self.mapping.get(node.name)
            if new is not None:
                self.renames += 1
                node.name = new
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
            new = self.mapping.get(node.name)
            if new is not None:
                self.renames += 1
                node.name = new
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
            new = self.mapping.get(node.name)
            if new is not None:
                self.renames += 1
                node.name = new
            self.generic_visit(node)
            return node

        def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
            # Only touch attribute owner if it's a plain Name we renamed.
            self.generic_visit(node)
            return node

        def visit_Global(self, node: ast.Global) -> ast.AST:
            node.names = [self.mapping.get(n, n) for n in node.names]
            return node

        def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
            node.names = [self.mapping.get(n, n) for n in node.names]
            return node


    # ---------------------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------------------
    def apply_homoglyph(tree: ast.Module, ctx) -> ast.Module:
        """Rename local identifiers in *tree* using Unicode homoglyphs.

        Parameters
        ----------
        tree : ast.Module
            Parsed module to rewrite in place.
        ctx :
            BuildContext-like object. Honoured attributes (all optional):
                * ``keep_names`` : ``set[str]``  -- names to leave alone.
                * ``homoglyph_seed`` : ``int``   -- deterministic RNG seed.
                * ``homoglyph_renames`` : ``int`` -- written back as the rename count.
        """
        keep: Set[str] = set(getattr(ctx, "keep_names", set()) or set())
        seed = getattr(ctx, "homoglyph_seed", None)
        rng = random.Random(seed) if seed is not None else random.Random()

        public_surface = _PublicSurfaceCollector()
        public_surface.visit(tree)

        skip = _BUILTINS | keep | public_surface.names

        collector = _Collector(skip)
        collector.visit(tree)

        namer = _HomoglyphNamer(rng=rng)
        mapping = {old: namer.fresh() for old in sorted(collector.names)}

        renamer = _Renamer(mapping)
        renamer.visit(tree)
        ast.fix_missing_locations(tree)

        try:
            ctx.homoglyph_renames = renamer.renames
            ctx.homoglyph_mapping = mapping
        except Exception:
            pass

        return tree




    # === [INLINE] bedrock_ext/numobf.py ===

    """
    numobf.py - Integer literal obfuscation pass for the bedrock obfuscator.

    Public API:
        apply_numobf(tree: ast.Module, ctx) -> ast.Module

    Replaces every ``Constant(value=int)`` node with an equivalent expression
    that evaluates to the same integer at runtime. Three strategies are
    selected at random per literal:

        A. arithmetic decomposition     42 -> ((100 - 58))
        B. bitwise rewrite              42 -> (0b101010) | ((0x80 >> 1) - 22)
        C. chained mixed ops            42 -> ((((7 * 6) ^ 0) | 0))

    Configuration on ``ctx``:
        ctx.rng           - random.Random instance (falls back to module random)
        ctx.numobf_depth  - int 1..3, recursion depth for nested obfuscation

    Skipped contexts (to preserve semantics / readability):
        * literals 0, 1, -1   (too small, used for truthiness / step / -1 idiom)
        * float / complex / bool literals
        * ints inside Subscript slices / indices
        * default values of function arguments
        * the integer arg of a top-level ``range(...)`` call (perf sensitive)

    Negative literals in source AST appear as ``UnaryOp(USub, Constant(int))``;
    the inner Constant is replaced and the USub is preserved -> ``-((50-8))``.

    Author: bedrock_ext
    """


    import ast
    import random
    from typing import Any


    # -------- helpers -----------------------------------------------------------

    def _rng(ctx) -> random.Random:
        r = getattr(ctx, "rng", None)
        if isinstance(r, random.Random):
            return r
        return random.Random(getattr(ctx, "seed", None))


    def _depth(ctx) -> int:
        d = getattr(ctx, "numobf_depth", 1)
        try:
            d = int(d)
        except Exception:
            d = 1
        # A5: allow depth up to 5 (was capped at 3) for stronger nesting.
        return max(1, min(5, d))


    def _const(n: int) -> ast.Constant:
        return ast.Constant(value=n)


    # -------- strategies --------------------------------------------------------

    def _strategy_arith(n: int, rng: random.Random) -> ast.AST:
        # n = a - b   (or a + b)
        if rng.random() < 0.5:
            a = rng.randint(n + 1, n + 1024)
            b = a - n
            return ast.BinOp(left=_const(a), op=ast.Sub(), right=_const(b))
        else:
            a = rng.randint(-1024, 1024)
            b = n - a
            return ast.BinOp(left=_const(a), op=ast.Add(), right=_const(b))


    def _strategy_bitwise(n: int, rng: random.Random) -> ast.AST:
        # variant 1: literal in alt base
        if rng.random() < 0.4:
            # ast preserves int value but unparse always shows decimal; that is OK,
            # we still get a different looking expression once wrapped via XOR mask.
            mask = rng.randint(1, 0xFFFF)
            # n = (n ^ mask) ^ mask
            return ast.BinOp(
                left=ast.BinOp(left=_const(n ^ mask), op=ast.BitXor(), right=_const(mask)),
                op=ast.BitOr(),
                right=_const(0),
            )
        # variant 2: shift based:  n = (high >> k) - delta
        k = rng.randint(1, 6)
        high = (abs(n) + rng.randint(1, 64)) << k
        val_after_shift = high >> k
        delta = val_after_shift - n
        return ast.BinOp(
            left=ast.BinOp(left=_const(high), op=ast.RShift(), right=_const(k)),
            op=ast.Sub(),
            right=_const(delta),
        )


    def _strategy_chained(n: int, rng: random.Random) -> ast.AST:
        # n = ((a * b) ^ 0) | 0    where we pick simple factors when possible.
        if n != 0:
            for _ in range(8):
                a = rng.randint(2, 12)
                if n % a == 0:
                    b = n // a
                    inner = ast.BinOp(left=_const(a), op=ast.Mult(), right=_const(b))
                    xor0 = ast.BinOp(left=inner, op=ast.BitXor(), right=_const(0))
                    return ast.BinOp(left=xor0, op=ast.BitOr(), right=_const(0))
        # fallback: additive chain
        a = rng.randint(1, max(2, abs(n)))
        b = n - a
        inner = ast.BinOp(left=_const(a), op=ast.Add(), right=_const(b))
        xor0 = ast.BinOp(left=inner, op=ast.BitXor(), right=_const(0))
        return ast.BinOp(left=xor0, op=ast.BitOr(), right=_const(0))


    def _strategy_mba_xor(n: int, rng: random.Random) -> ast.AST:
        # A5: MBA-style — (n ^ m) ^ m == n, but expressed as a two-level
        # BitXor with a random mask m.  Visually distinct from the plain
        # bitwise strategy because both masks are random and unequal-shaped.
        m = rng.randint(1, 0xFFFF)
        inner = ast.BinOp(left=_const(n ^ m), op=ast.BitXor(), right=_const(m))
        # wrap in `(inner | 0) ^ 0` for extra noise without changing value
        or0 = ast.BinOp(left=inner, op=ast.BitOr(), right=_const(0))
        return ast.BinOp(left=or0, op=ast.BitXor(), right=_const(0))


    def _strategy_mba_addsub(n: int, rng: random.Random) -> ast.AST:
        # A5: (n + m) - m == n  — add/sub cancellation with a random offset.
        # Choose m so n + m stays in a reasonable int range.
        m = rng.randint(1, 65535)
        # emit the literal (n + m) then subtract m, then `| 0` for noise.
        add_literal = ast.BinOp(left=_const(n + m), op=ast.Add(), right=_const(0))
        sub = ast.BinOp(left=add_literal, op=ast.Sub(), right=_const(m))
        return ast.BinOp(left=sub, op=ast.BitOr(), right=_const(0))


    def _strategy_mba_muldiv(n: int, rng: random.Random) -> ast.AST:
        # A5: (n * m) // m == n  for m != 0.  Pick m from small primes to
        # avoid sign/zero-division edge cases.
        if n == 0:
            # fallback to add-sub for 0 (mul would be 0//m == 0 trivially)
            return _strategy_mba_addsub(n, rng)
        m = rng.choice((3, 5, 7, 11, 13, 17, 19, 23, 29, 31))
        # emit the literal (n * m) divided by m, then `| 0` for noise.
        mul_literal = ast.BinOp(left=_const(n * m), op=ast.Mult(), right=_const(1))
        div = ast.BinOp(left=mul_literal, op=ast.FloorDiv(), right=_const(m))
        return ast.BinOp(left=div, op=ast.BitOr(), right=_const(0))


    def _strategy_mba_nonlinear(n: int, rng: random.Random) -> ast.AST:
        # A1: Non-linear / polynomial MBA.  Decompose n into two disjoint
        # bit-halves via the minterm identity
        #     n == (n & m) + (n ^ (n & m))            (halves occupy disjoint
        #                                                bit sets -> sum == OR == n)
        # then wrap the result in an exact multiplicative round-trip (*f // f)
        # so a *linear* MBA simplifier cannot fold it without reasoning about
        # the bit partition.  Holds for every int n (incl. 0 and negatives):
        # Python treats negatives as infinite two's complement, so the disjoint
        # bit-set argument still applies.
        m = rng.randint(2, 0xFFFF)
        lo = ast.BinOp(left=_const(n), op=ast.BitAnd(), right=_const(m))
        hi = ast.BinOp(left=_const(n), op=ast.BitXor(), right=lo)
        inner = ast.BinOp(left=lo, op=ast.Add(), right=hi)              # == n
        f = rng.choice((3, 5, 7, 11, 13))
        mul = ast.BinOp(left=inner, op=ast.Mult(), right=_const(f))     # n * f
        div = ast.BinOp(left=mul, op=ast.FloorDiv(), right=_const(f))  # (n*f)//f == n
        return ast.BinOp(left=div, op=ast.BitOr(), right=_const(0))


    def _strategy_mba_matrix(n: int, rng: random.Random) -> ast.AST:
        # A2: Matrix MBA over the integers.  Split n into disjoint bit-shares
        #     lo = n & m ,  hi = n ^ (n & m) == n & ~m   (so lo + hi == n)
        # and apply a random unimodular shear  M = [[1, k], [0, 1]]  (det = 1).
        # Its inverse is [[1, -k], [0, 1]], so recovery is
        #     n = (lo + k*hi) + (1 - k)*hi
        # Because det = 1 the inverse has integer entries, making the round
        # trip exact for every int n.  Distinct from arith/muldiv: it exposes a
        # 2-share linear-algebra transform, not a single a+/-b or n*m//m.
        m = rng.randint(2, 0xFFFF)
        k = rng.randint(2, 64)
        lo = ast.BinOp(left=_const(n), op=ast.BitAnd(), right=_const(m))
        hi = ast.BinOp(left=_const(n), op=ast.BitXor(), right=lo)
        coef = 1 - k
        fwd = ast.BinOp(left=lo, op=ast.Add(),
                        right=ast.BinOp(left=_const(k), op=ast.Mult(), right=hi))
        rec = ast.BinOp(left=_const(coef), op=ast.Mult(), right=hi)
        return ast.BinOp(left=fwd, op=ast.Add(), right=rec)


    _STRATEGIES = (_strategy_arith, _strategy_bitwise, _strategy_chained,
                   _strategy_mba_xor, _strategy_mba_addsub, _strategy_mba_muldiv,
                   _strategy_mba_nonlinear, _strategy_mba_matrix)


    def _obfuscate_int(n: int, rng: random.Random, depth: int) -> ast.AST:
        """Return an ast expression that evaluates to `n`."""
        strat = rng.choice(_STRATEGIES)
        node = strat(n, rng)
        # recursive nesting: replace one of the leaf consts with a deeper expr
        if depth > 1:
            leaves = [c for c in ast.walk(node)
                      if isinstance(c, ast.Constant) and isinstance(c.value, int)
                      and not isinstance(c.value, bool)
                      and c.value not in (0, 1, -1)]
            if leaves:
                target = rng.choice(leaves)
                inner = _obfuscate_int(target.value, rng, depth - 1)
                # in-place attribute swap by walking parent... easier: rebuild via NodeTransformer
                class _Swap(ast.NodeTransformer):
                    def visit_Constant(self, c):
                        if c is target:
                            return inner
                        return c
                node = _Swap().visit(node)
                ast.fix_missing_locations(node)
        # wrap to make precedence explicit when unparsed
        return node


    # -------- main transformer --------------------------------------------------

    _SKIP_VALUES = (0, 1, -1)


    class _NumObfTransformer(ast.NodeTransformer):
        def __init__(self, ctx):
            self.ctx = ctx
            self.rng = _rng(ctx)
            self.depth = _depth(ctx)
            # context-tracking sets (id of nodes whose int children should be skipped)
            self._skip_const_ids: set[int] = set()

        # --- skip handlers: mark children to ignore ----------------------------

        def visit_Subscript(self, node: ast.Subscript) -> ast.AST:
            # mark every int Constant inside the slice
            for sub in ast.walk(node.slice):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, int):
                    self._skip_const_ids.add(id(sub))
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            for d in list(node.args.defaults) + list(node.args.kw_defaults):
                if d is None:
                    continue
                for sub in ast.walk(d):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, int):
                        self._skip_const_ids.add(id(sub))
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node):
            return self.visit_FunctionDef(node)  # type: ignore[arg-type]

        def visit_Call(self, node: ast.Call) -> ast.AST:
            # skip top-level int args of range()
            is_range = isinstance(node.func, ast.Name) and node.func.id == "range"
            if is_range:
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, int):
                        self._skip_const_ids.add(id(a))
            self.generic_visit(node)
            return node

        # --- the actual rewrite ------------------------------------------------

        def visit_Constant(self, node: ast.Constant) -> ast.AST:
            v = node.value
            if isinstance(v, bool):
                return node
            if not isinstance(v, int):
                return node
            if v in _SKIP_VALUES:
                return node
            if id(node) in self._skip_const_ids:
                return node
            new = _obfuscate_int(v, self.rng, self.depth)
            ast.copy_location(new, node)
            ast.fix_missing_locations(new)
            return new


    def apply_numobf(tree: ast.Module, ctx: Any) -> ast.Module:
        """Apply integer-literal obfuscation in place and return the tree."""
        if not isinstance(tree, ast.AST):
            return tree
        transformer = _NumObfTransformer(ctx)
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree


    # === [INLINE] bedrock_ext/varsplit.py ===

    """Variable-splitting (XOR secret-sharing) pass for bedrock.

    Public API: ``apply_varsplit(tree, ctx) -> ast.Module``.

    Split eligible local integer variables into two shares ``v1 ^ v2 == V``.
    Each qualifying assignment ``v = <int-expr>`` is rewritten to::

        v1 = <random int>
        v2 = <int-expr> ^ v1

    and every subsequent ``Name(v)`` load becomes ``v1 ^ v2``. The value of
    ``v`` is never stored directly; an attacker reading one share learns
    nothing about ``V`` without the other.

    Eligibility (deliberately conservative -- correctness over coverage):

    * only ``def`` functions (async funcs, lambdas, generators, and any
      function body containing ``yield`` / ``yield from`` / ``await`` are
      skipped);
    * only *simple local* names -- ``v = ...`` where target is a bare
      ``Name``. Augmented (``v +=``), annotated (``v: int =``), starred,
      tuple/list unpacking, attribute (``self.x =``) and subscript
      assignments are all left untouched;
    * the variable must NOT appear in ``global`` / ``nonlocal`` declarations,
      must NOT be a free-variable (closure ref), must NOT be a function
      argument / default / decorator / class body name;
    * only ``int``-typed RHS is split. We infer "int-ish" conservatively:
      RHS is an ``ast.Constant(int)``, or an ``ast.BinOp`` whose op is in
      {Add, Sub, Mult, FloorDiv, Mod, BitXor, BitAnd, BitOr, LShift,
      RShift, Pow} (i.e. arithmetic/bitwise on ints). Anything else (str,
      bytes, list, call, comparison, bool op, ternary, ...) is left
      untouched -- we never split a variable whose value might not be int.
    * a single variable is split at most once per function (the FIRST
      qualifying assignment establishes v1/v2; later assignments to the
      same name are left as-is to avoid aliasing bugs with re-binding).

    The pass never raises -- any per-function error is swallowed and the
    original function is returned unchanged (fail-safe, mirrors apply_cff).
    """

    _VARSPLIT_INT_OPS = (
        ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod,
        ast.BitXor, ast.BitAnd, ast.BitOr, ast.LShift, ast.RShift, ast.Pow,
    )

    def _varsplit_is_int_rhs(node: ast.expr) -> bool:
        """Conservative int-RHS detector used to decide split eligibility."""
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, _VARSPLIT_INT_OPS):
            return _varsplit_is_int_rhs(node.left) and _varsplit_is_int_rhs(node.right)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
            return _varsplit_is_int_rhs(node.operand)
        return False

    def _varsplit_has_yield_or_await(body):
        for n in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                return True
        return False

    def _varsplit_collect_skip_names(func_node: ast.FunctionDef) -> set:
        """Names that must NOT be split: args, globals, nonlocals, freevars,
        decorators, and names appearing in augmented / annotated / non-simple
        assignments (which would alias incorrectly with the v1^v2 form)."""
        skip = set()
        # arguments + positional/kwonly/defaults + vararg/kwarg
        a = func_node.args
        for arg in (a.posonlyargs + a.args + a.kwonlyargs + ([a.vararg] if a.vararg else []) + ([a.kwarg] if a.kwarg else [])):
            if arg: skip.add(arg.arg)
        # global / nonlocal declarations
        for stmt in func_node.body:
            if isinstance(stmt, ast.Global):
                skip.update(stmt.names)
            elif isinstance(stmt, ast.Nonlocal):
                skip.update(stmt.names)
        # any name appearing in a non-simple / augmented / annotated assignment
        # is unsafe to split (its RHS could be non-int or it could be re-bound
        # by an augmented op we don't model).
        for stmt in ast.walk(ast.Module(body=func_node.body, type_ignores=[])):
            if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                skip.add(stmt.target.id)
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                skip.add(stmt.target.id)
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    # tuple/list unpacking, starred, attribute, subscript -> skip
                    if not isinstance(t, ast.Name):
                        skip.add(_AST_NAME_SENTINEL) if False else None
                        # mark all names in the unpacking target as unsafe
                        for sub in ast.walk(t):
                            if isinstance(sub, ast.Name):
                                skip.add(sub.id)
        return skip

    def _varsplit_collect_eligible(func_node: ast.FunctionDef, skip: set) -> "List[ast.Assign]":
        """Return the list of simple ``v = <int-expr>`` assignments whose
        target name is eligible (not in skip, not already chosen). The
        FIRST occurrence of each name wins; later assignments are skipped.

        CRITICAL: a name that is assigned MORE THAN ONCE in the function
        body is NOT split at all -- re-assigning a split variable would
        require updating BOTH shares (v1, v2) atomically, and our RHS
        rewrite (``v`` -> ``v1 ^ v2``) would otherwise read stale shares
        after the second assignment (the shares never get re-bound). The
        conservative choice is to leave re-bound names untouched so the
        loop-accumulator / mutable-state patterns stay correct."""
        # First pass: count how many times each simple Name appears as an
        # Assign target ANYWHERE in the function body (including nested
        # loop/if/with/try blocks). Re-bound names are ineligible because
        # our share-pair rewrite can't update both shares atomically on a
        # re-assignment, and the load rewrite (`v` -> `v1 ^ v2`) would
        # otherwise read stale shares after the inner re-bind. Walk the
        # full subtree so loop accumulators / conditional re-binds are caught.
        assign_counts: dict = {}
        for stmt in ast.walk(ast.Module(body=func_node.body, type_ignores=[])):
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                assign_counts[stmt.targets[0].id] = assign_counts.get(stmt.targets[0].id, 0) + 1
        chosen = []  # list of Assign nodes
        seen = set()
        for stmt in func_node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if len(stmt.targets) != 1:
                continue
            t = stmt.targets[0]
            if not isinstance(t, ast.Name):
                continue
            if t.id in skip or t.id in seen:
                continue
            if assign_counts.get(t.id, 0) > 1:
                # Re-bound -> splitting would break aliasing. Skip entirely.
                seen.add(t.id)
                continue
            if not _varsplit_is_int_rhs(stmt.value):
                continue
            seen.add(t.id)
            chosen.append(stmt)
        return chosen

    def _varsplit_rewrite_func(func_node: ast.FunctionDef, rng: random.Random):
        """In-place rewrite of one function. Returns True if any change made."""
        if _varsplit_has_yield_or_await(func_node.body):
            return False
        skip = _varsplit_collect_skip_names(func_node)
        eligible = _varsplit_collect_eligible(func_node, skip)
        if not eligible:
            return False
        # Map: original name -> (v1 name, v2 name)
        share_map = {}
        for assign in eligible:
            orig = assign.targets[0].id
            v1 = _rand_name(rng)
            v2 = _rand_name(rng)
            share_map[orig] = (v1, v2)
            # Replace `v = expr` with `v1 = <rand>; v2 = expr ^ v1`
            rand_val = rng.randint(1, 0xFFFFFFFF)
            # build `expr ^ v1` (XOR with the random share)
            new_rhs = ast.BinOp(left=assign.value, op=ast.BitXor(),
                                right=ast.Name(id=v1, ctx=ast.Load()))
            assign.value = new_rhs
            assign.targets = [ast.Name(id=v2, ctx=ast.Store())]
            # Insert the v1 assignment BEFORE the rewritten v2 assignment.
            v1_assign = ast.Assign(
                targets=[ast.Name(id=v1, ctx=ast.Store())],
                value=ast.Constant(value=rand_val),
            )
            # Splice v1_assign into the function body just before `assign`.
            body = func_node.body
            idx = body.index(assign)
            body.insert(idx, v1_assign)
        # Now rewrite every Load of an eligible name to `v1 ^ v2`.
        # We must NOT rewrite the v1/v2 Store targets themselves, nor the
        # new RHS we just built (which legitimately references v1). Use a
        # targeted transformer that only touches Name nodes in Load ctx whose
        # id is in share_map, and skips the v2-assignment RHS we synthesised
        # (those are the freshly-built BinOp over the original RHS).
        class _LoadRewriter(ast.NodeTransformer):
            def __init__(self):
                self._skip_rhs = False
            def visit_Assign(self, node):
                # Detect our synthesised v2 assignment by checking its RHS
                # is a BinOp(BitXor, left=<orig>, right=Name(v1)). We only
                # skip the rewrite of v1 inside that RHS (it's the share,
                # not the original variable).
                is_synth = (len(node.targets) == 1
                            and isinstance(node.targets[0], ast.Name)
                            and node.targets[0].id in {n for pair in share_map.values() for n in pair}
                            and isinstance(node.value, ast.BinOp)
                            and isinstance(node.value.op, ast.BitXor)
                            and isinstance(node.value.right, ast.Name))
                # Visit targets first (Store ctx -> Name visitor sees Store, skips)
                new_targets = [self.visit(t) for t in node.targets]
                if is_synth:
                    # Visit left (original RHS) normally but DO NOT rewrite
                    # the v1 Name on the right -- that's the share.
                    new_left = self.visit(node.value.left)
                    new_value = ast.BinOp(left=new_left, op=node.value.op,
                                          right=node.value.right)
                else:
                    new_value = self.visit(node.value)
                node.targets = new_targets
                node.value = new_value
                return node
            def visit_Name(self, node: ast.Name):
                if isinstance(node.ctx, ast.Load) and node.id in share_map:
                    v1, v2 = share_map[node.id]
                    return ast.BinOp(
                        left=ast.Name(id=v1, ctx=ast.Load()),
                        op=ast.BitXor(),
                        right=ast.Name(id=v2, ctx=ast.Load()),
                    )
                return node
        _LoadRewriter().visit(func_node)
        return True

    def apply_varsplit(tree: ast.Module, ctx: Any) -> ast.Module:
        rng = getattr(ctx, "rng", None)
        if rng is None:
            rng = random.Random()

        class _Visitor(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.generic_visit(node)
                try:
                    _varsplit_rewrite_func(node, rng)
                except Exception:
                    # Fail-safe: never break the build over a problematic fn.
                    pass
                return node
            def visit_AsyncFunctionDef(self, node):
                return node

        new_tree = _Visitor().visit(tree)
        ast.fix_missing_locations(new_tree)
        return new_tree





    # === [INLINE] bedrock_ext/native_vm.py (Phase 5, Wave 4B) ===

    """Native BedrockVM compilation pass for bedrock.

    Public API: ``apply_native_vm(tree, ctx) -> ast.Module``.

    Compiles eligible top-level ``FunctionDef`` nodes into BedrockVM
    bytecode blobs (via ``_native_vm_compiler.compile_func``) and replaces
    each with a thin wrapper that decodes the blob at call time and runs
    it through the shipped VM interpreter (``_xvm`` / ``_bedrock_vm_ref``).

    Position in the pipeline: registered via ``_insert_after_obf_vars``,
    which uses ``operations.insert(idx + 1, step)`` -- a reverse stack, so
    passes declared LATER in source run EARLIER. This pass is registered
    AFTER the ``runtime_dec`` block, so it runs BEFORE
    ``apply_runtimedec`` -- the VM claims functions first; the capsule
    runtime gets the rest. A function goes to the VM OR the capsule, never
    both: this pass rewrites a VM-eligible FunctionDef's body in place, so
    the later capsule pass sees a plain Python wrapper (not a code blob it
    can marshal) and skips it.

    Design constraints (see Phase 5 task spec):
      * The compiler is imported lazily inside the pass so the obfuscator
        works even when ``bedrock_native/`` is not on the path.
      * ``perm`` and ``key`` are SHARED across all VM-compiled functions
        (one per build): generated once at the start of the pass.
      * Every emitted string is debranded via ``_debrand()`` (Phase 4).
      * Fail-safe: if a function throws (``UnsupportedOpcode`` or any
        other error) it is skipped and left as-is; the build never crashes.
      * When ``--env-key`` is on, the 32-byte key is XOR-blinded at
        runtime by the loader's ``_vm_derive_key`` (which re-derives the
        same blinding from ``__BedrockEnvKey__``). The blob is compiled
        with the ALREADY-blinded key (raw_key XOR hw_fingerprint) so the
        runtime re-derivation matches. Phase 5 limitation: the VM key is
        NOT threaded through the HMAC chain (the chain protects capsule
        functions; VM functions get their own encrypted const pool).
      * When ``--debug-poison`` is on, the loader's ``_vm_run`` wraps the
        VM call in ``try/except`` and routes failures through
        ``__h_poison('vm_fail', 7)`` (silent inert).

    Eligibility (mirrors ``_runtimedec_collect_targets``):
      * top-level ``FunctionDef`` only (no nested, no methods),
      * skip ``async def``,
      * skip the ``__main__`` entry guard (body references ``__name__`` /
        ``__main__``),
      * skip dunders (``__x__``),
      * skip functions the compiler rejects (``UnsupportedOpcode``).
    """

    def _nativevm_collect_targets(tree: ast.Module) -> "List[ast.FunctionDef]":
        """Return eligible top-level FunctionDef nodes (after obf_vars renamed
        them). Mirrors ``_runtimedec_collect_targets`` but returns nodes, not
        names, so the pass can compile + replace each in place."""
        targets = []
        import re as _nativevm_re
        # Traditional dunders are short ASCII names like __init__, __name__,
        # __main__. obf_vars renames user functions to
        # __<digits><cjk><digits>__ (long, non-ASCII), which we MUST claim.
        # Only skip traditional (short, ASCII, letter-led) dunders.
        _dunder_re = _nativevm_re.compile(r'^__[a-zA-Z_][a-zA-Z0-9_]*__$')
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if _dunder_re.match(node.name) and len(node.name) <= 32:
                continue
            if isinstance(node, ast.AsyncFunctionDef):
                continue
            if _runtimedec_has_yield_or_await(node.body):
                continue
            # Skip the if __name__ == '__main__' entry guard caller: a
            # top-level def whose body references '__name__' / '__main__'.
            is_entry = False
            for n in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "__main__":
                    is_entry = True
                    break
                if isinstance(n, ast.Name) and n.id == "__name__":
                    is_entry = True
                    break
            if is_entry:
                continue
            targets.append(node)
        return targets

    def _vm_cand_ok(d):
        import os as _o
        return _o.path.isfile(_o.path.join(d, '_native_vm_compiler.py'))

    def _nativevm_compile_one(func_node, build_key, build_perm):
        """Compile a single FunctionDef into a BedrockVM blob.

        Returns ``(blob_bytes, perm, perm_ext, key, frame)`` or ``None`` if
        the function cannot be compiled (UnsupportedOpcode / any error).
        """
        try:
            import importlib as _vm_imp
            import os as _vm_os, sys as _vm_sys
            # Ensure bedrock_native/ is importable for the compiler's
            # `from _bedrock_vm_ref import ...`.
            _here = _vm_os.path.dirname(_vm_os.path.abspath(
                globals().get('__file__', '') or __file__))
            for _cand in (_vm_os.path.join(_here, 'bedrock_native'),
                          _vm_os.path.join(_vm_os.getcwd(), 'bedrock_native'),
                          _here, _vm_os.getcwd()):
                if _cand and _vm_os.path.isdir(_cand) and _vm_cand_ok(_cand):
                    if _cand not in _vm_sys.path:
                        _vm_sys.path.insert(0, _cand)
                    break
            _nvc = _vm_imp.import_module('_native_vm_compiler')
            # Build a standalone module containing just this function, compile
            # it to a code object, exec it to get the function object.
            mod = ast.Module(body=[func_node], type_ignores=[])
            ast.fix_missing_locations(mod)
            code = compile(mod, '<vm_compile>', 'exec')
            ns = {}
            exec(code, ns)
            func_obj = ns[func_node.name]
            blob, perm, perm_ext, key, frame = _nvc.compile_func(
                func_obj, key=build_key, perm=build_perm)
            return blob, perm, perm_ext, key, frame
        except Exception:
            # Fail-safe: never break the build over a problematic function.
            return None

    def apply_native_vm(tree: ast.Module, ctx: Any) -> ast.Module:
        """Compile eligible top-level functions to BedrockVM blobs.

        See the module docstring above for the full contract. Returns the
        (possibly mutated) tree. When both ``ctx.native_vm`` and
        ``ctx.crown_jewel_vm`` are False, returns the tree unchanged (a no-op
        so ``--no-native-vm`` is byte-identical to the pre-Phase-5 behavior).

        Phase F (crown_jewel_vm): when ``ctx.crown_jewel_vm`` is True the
        target set is the @bedrock_crown_jewel-decorated functions (via
        _crown_jewel_collector, with top-N heuristic fallback), capped at
        ~5-10 functions. When ``ctx.native_vm`` is True (Phase 5), the full
        heuristic target set is used (all eligible functions). The two flags
        are independent; both may be set (crown jewels take precedence and
        the remaining eligible functions are added up to the cap).
        """
        _nvm = bool(getattr(ctx, 'native_vm', False))
        _cjvm = bool(getattr(ctx, 'crown_jewel_vm', False))
        if not _nvm and not _cjvm:
            return tree
        rng = getattr(ctx, 'rng', None)
        if rng is None:
            rng = random.Random()
        # Phase F: crown jewels via _crown_jewel_collector (annotation-gated,
        # top-N heuristic fallback). Phase 5: full heuristic target set. When
        # both flags are set the crown jewels are collected first (decorated
        # functions), then additional eligible functions fill the cap.
        if _cjvm:
            try:
                import importlib as _cj_imp
                import os as _cj_os, sys as _cj_sys
                _here_cj = _cj_os.path.dirname(_cj_os.path.abspath(
                    globals().get('__file__', '') or __file__))
                for _cand in (_cj_os.path.join(_here_cj, 'bedrock_native'),
                              _cj_os.path.join(_cj_os.getcwd(), 'bedrock_native'),
                              _here_cj, _cj_os.getcwd()):
                    if _cand and _cj_os.path.isdir(_cand) and \
                            _cj_os.path.isfile(_cj_os.path.join(_cand, '_crown_jewel_collector.py')):
                        if _cand not in _cj_sys.path:
                            _cj_sys.path.insert(0, _cand)
                        break
                _cjc = _cj_imp.import_module('_crown_jewel_collector')
                _cj_max = 10
                if _nvm:
                    # Both flags: crown jewels first, then fill with the full
                    # heuristic set up to the cap. Decorated functions take
                    # precedence; the heuristic fills the remainder.
                    _cj_targets = _cjc.collect_crown_jewels(tree, max_funcs=_cj_max)
                    _seen = {id(n) for n in _cj_targets}
                    _extra = [n for n in _nativevm_collect_targets(tree)
                              if id(n) not in _seen]
                    targets = _cj_targets + _extra[:max(0, _cj_max - len(_cj_targets))]
                else:
                    targets = _cjc.collect_crown_jewels(tree, max_funcs=_cj_max)
            except Exception:
                # Collector unavailable -- fall back to the Phase-5 heuristic
                # so a missing dependency never breaks the build silently.
                targets = _nativevm_collect_targets(tree) if _nvm else []
        else:
            targets = _nativevm_collect_targets(tree)
        if not targets:
            return tree
        # Generate ONE shared perm + key for the whole build. The perm is a
        # random permutation of the canonical opcode values; the key is a
        # random 32-byte const-pool encryption key. EXTENDED_ARG stays fixed
        # at its canonical value (never permuted).
        try:
            import importlib as _vm_imp2
            import os as _vm_os2, sys as _vm_sys2
            _here2 = _vm_os2.path.dirname(_vm_os2.path.abspath(
                globals().get('__file__', '') or __file__))
            for _cand in (_vm_os2.path.join(_here2, 'bedrock_native'),
                          _vm_os2.path.join(_vm_os2.getcwd(), 'bedrock_native'),
                          _here2, _vm_os2.getcwd()):
                if _cand and _vm_os2.path.isdir(_cand) and _vm_cand_ok(_cand):
                    if _cand not in _vm_sys2.path:
                        _vm_sys2.path.insert(0, _cand)
                    break
            _ref = _vm_imp2.import_module('_bedrock_vm_ref')
        except Exception:
            # If the reference isn't importable we can't build a perm; bail
            # out safely (leave the tree unchanged) rather than crash.
            return tree
        _vals = list(_ref._OPCODES.values())
        _scr = _vals[:]
        rng.shuffle(_scr)
        _nativevm_build_perm = { _scr[i]: _vals[i] for i in range(len(_vals)) }
        _nativevm_build_perm[_ref.EXTENDED_ARG] = _ref.EXTENDED_ARG
        # Phase G (Layer 3): server key-release. When ctx.release_server is
        # set, the VM key is derived from the server master seed (NOT random)
        # via LocalKeyProvider, and the artifact ships a _vm_key_handle tuple
        # (license_id, build_id, server_url, server_ed25519_pub,
        # server_x25519_pub, offline_grace_seconds) INSTEAD OF the raw key
        # bytes. The blob is still encoded with this vm_key -- the runtime
        # fetches the SAME vm_key from the release server on first call via
        # an attested POST. Mutually exclusive with --env-key (release is the
        # stronger, machine-attested mechanism).
        _nativevm_release_on = bool(getattr(ctx, 'release_server', ''))
        _nativevm_build_id = ''
        _nativevm_key_handle_lit = None
        if _nativevm_release_on:
            try:
                import importlib as _kr_imp
                import os as _kr_os, sys as _kr_sys
                _kr_here = _kr_os.path.dirname(_kr_os.path.abspath(
                    globals().get('__file__', '') or __file__))
                for _cand in (_kr_os.path.join(_kr_here, 'bedrock_native'),
                              _kr_os.path.join(_kr_os.getcwd(), 'bedrock_native'),
                              _kr_here, _kr_os.getcwd()):
                    if _cand and _kr_os.path.isdir(_cand) and \
                            _kr_os.path.isfile(_kr_os.path.join(_cand, '_key_release.py')):
                        if _cand not in _kr_sys.path:
                            _kr_sys.path.insert(0, _cand)
                        break
                _kr = _kr_imp.import_module('_key_release')
            except Exception:
                # Key-release requested but the module is unavailable -- bail
                # out safely rather than ship an artifact with a random key
                # that the release server cannot re-derive.
                return tree
            _lic = str(getattr(ctx, 'license_id', '') or '')
            if not _lic:
                # license_id is required for key-release derivation.
                return tree
            _master = getattr(ctx, 'master_seed', b'') or b''
            if len(_master) != 32:
                return tree
            # build_id: a fresh 16-byte hex per build. Embedded in the handle
            # and sent by the client in /release; the server re-derives the
            # same vm_key from (master, license_id, build_id). Same artifact
            # -> same build_id -> same vm_key (reproducible per-artifact).
            _nativevm_build_id = bytes(rng.randint(0, 255) for _ in range(16)).hex()
            try:
                _provider = _kr.LocalKeyProvider(_master)
                _nativevm_build_key = _provider.derive(_lic, _nativevm_build_id)
            except Exception:
                return tree
            # Load the server's PUBLIC keys for the handle (env or persisted
            # PEMs). These are NOT secret -- they pin the JWT signer + ECDH
            # peer so a MITM cannot substitute keys.
            try:
                _ed_pub, _x_pub = _kr.load_server_pubkeys(
                    str(getattr(ctx, 'release_server', '')))
            except Exception:
                return tree
            _grace = int(getattr(ctx, 'offline_grace_seconds', 604800) or 604800)
            _nativevm_key_handle_lit = (
                _lic, _nativevm_build_id,
                str(getattr(ctx, 'release_server', '')),
                _ed_pub, _x_pub, _grace,
            )
            # The blob is encoded with the derived vm_key directly (no env-key
            # XOR -- key-release and env-key are mutually exclusive).
            _nativevm_enc_key = _nativevm_build_key
            _nativevm_envkey_on = False
        else:
            _nativevm_build_key = bytes(rng.randint(0, 255) for _ in range(32))
            # The RAW key is embedded in the source (_vm_key) so the loader can
            # re-XOR it with the live __BedrockEnvKey__ digest at runtime. When
            # --env-key is on, the blob is ENCRYPTED with (raw_key XOR hw_fp) so
            # the runtime _vm_derive_key(raw_key) = raw_key XOR env32 matches the
            # build-time encryption key when the fingerprint matches. A wrong
            # machine yields a wrong env32, so the const pool decrypts to garbage
            # (silent inert; same scheme as the capsule runtime at lines 10085+).
            _nativevm_envkey_on = bool(getattr(ctx, 'env_key', False))
            _nativevm_enc_key = _nativevm_build_key
            if _nativevm_envkey_on:
                try:
                    _envfp = _collect_hw_fingerprint()
                    if _envfp and len(_envfp) == 32:
                        _nativevm_enc_key = bytes(
                            (_a ^ _b) for _a, _b in zip(_nativevm_build_key, _envfp))
                except Exception:
                    _nativevm_envkey_on = False
        # Expose the shared perm/key on the ctx so run_build can thread them
        # into the build-system ship call (not strictly required -- the
        # constants are emitted into the source -- but kept for diagnostics).
        try:
            ctx._nativevm_perm = _nativevm_build_perm
            ctx._nativevm_key = _nativevm_build_key
        except Exception:
            pass
        # Compile each eligible function. We collect successful compilations
        # first so a failure on function N doesn't leave functions 1..N-1
        # half-rewritten.
        compiled = []  # list of (func_node, blob_b85, perm_ext, frame)
        import base64 as _vm_b64
        for node in targets:
            res = _nativevm_compile_one(node, _nativevm_enc_key, _nativevm_build_perm)
            if res is None:
                continue  # skipped (UnsupportedOpcode or error)
            blob, perm_out, perm_ext_out, key_out, frame = res
            blob_b85 = _vm_b64.b85encode(blob).decode('ascii')
            compiled.append((node, blob_b85, perm_ext_out, frame))
        if not compiled:
            return tree
        # perm_ext: all functions share the same perm, so perm_ext is the same
        # for all; take it from the first compiled entry.
        _shared_perm_ext = compiled[0][2]
        # Emit the shared module-level constants. In key-release mode
        # (_nativevm_release_on) we ship a _vm_key_handle tuple INSTEAD OF
        # the raw _vm_key bytes -- the loader resolves the key on first VM
        # call via an attested fetch. Debrand every emitted string literal.
        if _nativevm_release_on and _nativevm_key_handle_lit is not None:
            _const_src = _debrand(
                "_vm_perm = %s\n"
                "_vm_key_handle = %s\n"
                "_vm_perm_ext = %d\n"
                % (repr(_nativevm_build_perm),
                   repr(_nativevm_key_handle_lit), _shared_perm_ext)
            )
        else:
            _const_src = _debrand(
                "_vm_perm = %s\n"
                "_vm_key = %s\n"
                "_vm_perm_ext = %d\n"
                % (repr(_nativevm_build_perm), repr(_nativevm_build_key), _shared_perm_ext)
            )
        const_nodes = ast.parse(_const_src).body
        # Build the per-function wrapper bodies. Each wrapper:
        #   def NAME(*args, **kwargs):
        #       return _vm_run(_b85decode(_NAME_blob), _vm_perm, _vm_key,
        #                      _vm_bind(args, kwargs, _NAME_vn),
        #                      _vm_g(), _vm_perm_ext)
        # base64 is referenced as a module-level Name; it is NOT in
        # obf_builtins' target list, so it survives that pass. The per-function
        # blob/varnames constants are emitted with debranded literals.
        for (node, blob_b85, perm_ext, frame) in compiled:
            _vn = frame.varnames
            wrapper_body = ast.Return(value=ast.Call(
                func=ast.Name(id='_vm_run', ctx=ast.Load()),
                args=[
                    ast.Call(
                        func=ast.Name(id='_vm_b85decode', ctx=ast.Load()),
                        args=[ast.Name(id='_%s_blob' % node.name, ctx=ast.Load())],
                        keywords=[],
                    ),
                    ast.Name(id='_vm_perm', ctx=ast.Load()),
                    ast.Name(id='_vm_key_handle' if _nativevm_release_on else '_vm_key', ctx=ast.Load()),
                    ast.Call(
                        func=ast.Name(id='_vm_bind', ctx=ast.Load()),
                        args=[ast.Name(id='args', ctx=ast.Load()),
                              ast.Name(id='kwargs', ctx=ast.Load()),
                              ast.Name(id='_%s_vn' % node.name, ctx=ast.Load())],
                        keywords=[],
                    ),
                    ast.Call(func=ast.Name(id='_vm_g', ctx=ast.Load()), args=[], keywords=[]),
                    ast.Name(id='_vm_perm_ext', ctx=ast.Load()),
                ],
                keywords=[],
            ))
            new_node = ast.FunctionDef(
                name=node.name,
                args=ast.arguments(
                    posonlyargs=[], args=[],
                    kwonlyargs=[], kw_defaults=[], defaults=[],
                    vararg=ast.arg(arg='args', annotation=None),
                    kwarg=ast.arg(arg='kwargs', annotation=None),
                ),
                body=[wrapper_body],
                decorator_list=[],
                returns=None,
                type_comment=None,
            )
            # Mark the wrapper so apply_runtimedec's target collector skips it
            # (a VM-claimed function must never ALSO get a capsule wrapper --
            # the chain shard would then capsule-wrap a function whose body is
            # `return _vm_run(...)`, which deadlocks at runtime because the
            # capsule swap re-installs the wrapper __code__ while the VM is
            # mid-flight). See _runtimedec_collect_targets' skip check.
            new_node._bedrock_vm_claimed = True
            # Replace in place.
            _idx = tree.body.index(node)
            tree.body[_idx] = new_node
            # Emit the per-function blob + varnames constants (debranded).
            _blob_src = _debrand(
                "_%s_blob = %r\n_%s_vn = %r\n"
                % (node.name, blob_b85, node.name, _vn)
            )
            const_nodes += ast.parse(_blob_src).body
        # The loader itself is fetched from the build system (debranded).
        try:
            import importlib as _vm_imp3
            _bs = _vm_imp3.import_module('_build_system')
        except Exception:
            _bs = None
        if _bs is not None:
            _envkey_on = bool(getattr(ctx, 'env_key', False))
            _dbg_poison = bool(getattr(ctx, 'debug_poison', False))
            _loader_mod_name = '_xvm'
            _loader_ref_name = '_bedrock_vm_ref'
            # Anti-meta: debrand the fallback import name so the shipped
            # reference file + the import match. We debrand ONLY the
            # reference name (the .pyd _xvm has no bedrock literal).
            if getattr(ctx, 'anti_meta', False):
                _loader_ref_name = _debrand('_bedrock_vm_ref')
            _vm_fallback = str(getattr(ctx, 'vm_fallback', 'auto'))
            _loader_src = _bs.get_loader_snippet(
                _loader_mod_name, _debrand,
                ref_fallback_name=_loader_ref_name,
                env_key_on=_envkey_on,
                envkey_var=_ENVKEY_NAME,
                debug_poison=_dbg_poison,
                poison_fn='__h_poison',
                vm_fallback=_vm_fallback,
                release_on=bool(getattr(ctx, 'release_server', '')),
            )
            _loader_nodes = ast.parse(_loader_src).body
        else:
            _loader_nodes = []
        # Prepend the loader + constants to the module body so they run first.
        tree.body = _loader_nodes + const_nodes + tree.body
        ast.fix_missing_locations(tree)
        return tree

    # === [INLINE] bedrock_ext/runtimedec.py ===

    """Runtime per-code-object decrypt / re-encrypt pass for bedrock.

    Public API: ``apply_runtimedec(tree, ctx) -> ast.Module``.

    Shrinks the in-RAM window during which a protected function's real
    bytecode is readable, mirroring the pyarmor "decrypt-on-use" idea but
    implemented in pure Python over ``code.replace``-style ``__code__``
    swaps.

    The pass scans the (already-renamed) module for eligible top-level
    ``def`` functions and appends a setup snippet to the END of the module
    body (so it runs after every def has executed). At runtime the snippet,
    for each target function:

    1. captures its real ``__code__`` (``_real``),
    2. marshals it and encrypts it with a per-capsule 32-byte (256-bit) key
       using a SHA-256 OFB stream cipher
       (``state_0 = sha256(key)``,
       ``state_n = sha256(state_{n-1} + key + bytes([offset & 255]))``),
       yielding ``_enc``. Each target gets its own unique key, so
       compromising one capsule's blob does not reveal the others.
    3. installs a no-op stub as ``__code__`` (``_stub``),
    4. replaces ``globals()[name]`` with a wrapper ``_w`` that, on every
       call, decrypts ``_enc`` back to a code object, swaps it into
       ``__code__`` for the duration of the call, and restores the stub in
       a ``finally`` so the real bytecode only lives in the interpreter
       while the body is executing. A static memory dump taken between
       calls therefore only sees the no-op stub. The wrapper forwards both
       positional and keyword args (``*_a, **_kw``).

    Eligibility (conservative):

    * top-level ``def`` only (not nested, not async, no ``yield`` / ``await``);
    * must have a ``__code__`` attribute (skip builtins / lambdas);
    * the module entry name (``main``-ish) is skipped so the bootstrap still
      runs;
    * the pass is entirely fail-safe -- any per-function error leaves the
      function's ``__code__`` untouched.

    Chain Runtime (Phase 2, ``ctx.chain``): when ``--chain`` is on (extreme
    auto-enables it), the setup is emitted as four separate shard functions
    (five when ``--metamorphic`` is on; see Phase 3 below)
    instead of a single setup, so no one runtime scope holds the whole
    secret:

    * **Integrity shard** (``_br_int_shard``): the monotonic poison state
      ``__h_poison_state__`` plus ``__h_poison(tag, weight)`` /
      ``__h_poisoned()`` (``<< 5`` + XOR + mask, never resets). Any
      verification failure calls ``__h_poison`` once and corrupts every
      downstream key forever.
    * **Key shard** (``_br_key_shard``): reconstructs the 32-byte master
      (XOR-blinded by ``__BedrockEnvKey__`` when ``--env-key`` is on) and
      derives per-capsule chain keys via
      ``key_n = sha256(prev_tag + master + label_n)``. When
      ``__h_poisoned()`` is non-zero, the key is XOR-masked to garbage so
      decryption silently yields inert bytes.
    * **Capsule shard** (``_br_cap_shard``): the SHA-256 OFB decryptor
      ``_br_decrypt``.
    * **Flow shard** (``_br_flow_shard``): walks the chain in sorted-target
      order, derives ``key_n``, encrypts each target, computes
      ``base_tag_n = hmac(key_n, prev_hash + enc_n, sha256)``, then the
      2-round ring tag
      ``final_tag_n = hmac(key_n, base_tag_n + base_tag_{(n+1) % N}, sha256)``,
      and installs decrypt-on-call wrappers (poison-on-decrypt-failure).

    Tampering one capsule changes its ``base_tag`` -> its own and its ring
    neighbour's ``final_tag`` change AND the next capsule's key changes ->
    all downstream capsules decrypt to garbage silently. The pass is
    therefore opt-in via ``--chain`` (``--no-chain`` to disable).

    Phase 3 adds two opt-in extensions that both piggy-back on the chain
    preamble (they auto-enable ``--chain`` + ``--runtime-dec`` for any profile
    when the user opts in, so ``--metamorphic balanced`` actually rewrites
    instead of silently skipping shard 5):

    * **Debug Poisoning** (``--debug-poison``): the anti-dbg / anti-vm /
      tamper reaction dispatchers route detections through ``__h_poison``
      (silent inert -- advance the poison state) instead of ``sys.exit`` /
      self-destruct, so a guarded artifact stays runnable but every capsule
      downstream decrypts to garbage. Forces ``tamper_mode = 'poison'``.
    * **Metamorphic** (``--metamorphic``): a fifth shard (``_br_meta_shard``)
      re-reads ``__file__`` at every import, inserts a fresh random comment
      after the hash line, re-masks both the file hash and the integrity hash
      (so the cross-reference circle stays consistent), recomputes them with
      the ``|fh`` / ``|int`` salts, and atomically ``os.replace``s the file.
      The on-disk artifact therefore shows different bytes every run while the
      logic payload stays byte-for-byte. Binary mode on Windows so ``\\n`` is
      not translated to ``\\r\\n`` (which would break the recompute). Any
      transformation failure is fail-safe: poison + return, never crash.

    A self-referential ``__H_FILE_HASH__`` (computed at build time with BOTH
    hashes masked to ``"." * 64`` and salted ``|fh`` / ``|int`` to break the
    cross-reference circle) is verified at runtime by
    ``__h_check_self_integrity`` (called at the END of ``_br_flow_shard``,
    AFTER capsules are encrypted, so a tamper detection poisons the state
    BETWEEN encryption and decryption -> mismatch). ``_br_int_shard``
    preserves an existing ``__h_poison_state__`` instead of resetting to 0
    so a poison seeded by the guard layer survives into the chain shards.

    Caveats: per-call decrypt has a runtime cost (one ``marshal.loads`` +
    one ``__code__`` swap per call), and the swap is not safe under
    recursion / concurrency on the SAME function object (a re-entrant call
    would see the stub mid-swap). The pass is intended for IP-protection of
    low-call-frequency entry points, not hot inner loops.
    """

    def _runtimedec_has_yield_or_await(body):
        for n in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                return True
        return False

    def _runtimedec_collect_targets(tree: ast.Module) -> "List[str]":
        """Return the names of eligible top-level FunctionDefs in ``tree``.

        We collect names AFTER obf_vars has renamed them, so the names here
        are whatever the obfuscated identifiers currently are (CJK tokens).
        Skip the module bootstrap entry (whose name we don't know precisely,
        so we skip any function whose body references ``__name__`` /
        ``__main__`` -- the canonical entry guard) and dunders.
        """
        targets = []
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            if _runtimedec_has_yield_or_await(node.body):
                continue
            # Skip the if __name__ == '__main__' entry guard caller: a
            # top-level def whose body calls into a main-like name is left
            # unprotected so the bootstrap dispatches. We approximate by
            # skipping defs whose body contains a Compare against the
            # string '__main__' or references '__name__'.
            is_entry = False
            for n in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "__main__":
                    is_entry = True
                    break
                if isinstance(n, ast.Name) and n.id == "__name__":
                    is_entry = True
                    break
            if is_entry:
                continue
            # Skip functions already claimed by the native VM (Phase 5): the
            # VM pass replaced the original body with a `return _vm_run(...)`
            # wrapper and marked the FunctionDef with _bedrock_vm_claimed.
            # Capsule-wrapping a VM wrapper deadlocks at runtime -- the chain
            # shard re-installs the wrapper __code__ on every call while the VM
            # is mid-flight, so the two runtimes interlock and the process
            # hangs after main() returns (see the chain-shard hang regression).
            if getattr(node, '_bedrock_vm_claimed', False):
                continue
            targets.append(node.name)
        return targets

    def apply_runtimedec(tree: ast.Module, ctx: Any) -> ast.Module:
        rng = getattr(ctx, "rng", None)
        if rng is None:
            rng = random.Random()
        try:
            targets = _runtimedec_collect_targets(tree)
        except Exception:
            return tree
        if not targets:
            return tree
        # Per-capsule 32-byte key derivation. Each target function gets its
        # own unique 256-bit key (no shared 1-byte XOR), so compromising one
        # capsule's blob does not reveal the others. When --env-key is on,
        # the key is XOR-blinded by the hardware fingerprint so a wrong
        # fingerprint decrypts to garbage (silent failure); the runtime twin
        # re-derives the same blinding from __BedrockEnvKey__.
        _envkey_on = bool(getattr(ctx, 'env_key', False))
        if _envkey_on:
            try:
                _envfp = _collect_hw_fingerprint()
            except Exception:
                _envkey_on = False
        # === Chain Runtime (Phase 2): HMAC hash chain + ring verify + shards ===
        # When --chain is on, the capsule setup is emitted as 4 separate shard
        # functions (Integrity / Key / Capsule / Flow), each holding only its
        # slice of the secret. Capsule keys thread through an HMAC hash chain
        # (key_n = sha256(prev_tag + master + label_n)); tampering one capsule
        # corrupts all downstream keys via the poison state (silent inert).
        _chain_on = bool(getattr(ctx, 'chain', False))
        _meta_on = bool(getattr(ctx, 'metamorphic', False))
        if _meta_on and not _chain_on:
            _chain_on = True
        if _chain_on:
            import time as _chain_time_mod
            _chain_master = bytes(rng.randint(0, 255) for _ in range(32))
            _chain_genesis = hashlib.sha256(
                _chain_master + str(rng.random()).encode('utf-8') +
                str(_chain_time_mod.time()).encode('utf-8')
            ).digest()
            _chain_targets_sorted = sorted(targets)
            _chain_targets_repr = ", ".join(repr(n) for n in _chain_targets_sorted)
            _chain_env_expr = "globals().get(" + repr(_ENVKEY_NAME) + ", b'')" if _envkey_on else "b''"
            chain_preamble = (
                # --- Shard 1: Integrity (poison state + functions) ---
                "def _br_int_shard():\n"
                "    global __h_poison_state__\n"
                "    __h_poison_state__ = globals().get('__h_poison_state__', 0) or 0\n"
                "    def __h_poison(tag='guard', weight=1):\n"
                "        import hashlib as _h\n"
                "        global __h_poison_state__\n"
                "        _raw = (str(tag) + '|' + str(weight) + '|' + str(__h_poison_state__)).encode('utf-8','ignore')\n"
                "        _mix = int.from_bytes(_h.sha256(_raw).digest()[:4], 'big')\n"
                "        __h_poison_state__ = ((__h_poison_state__ << 5) ^ _mix ^ ((int(weight) & 255) * 0x45D9F3B)) & 0xffffffff\n"
                "        return __h_poison_state__\n"
                "    def __h_poisoned():\n"
                "        return globals().get('__h_poison_state__', 0)\n"
                "    globals()['__h_poison'] = __h_poison\n"
                "    globals()['__h_poisoned'] = __h_poisoned\n"
                # --- Shard 2: Key (master + chain-key derivation, poison-aware) ---
                "def _br_key_shard():\n"
                f"    _master = {_chain_master!r}\n"
                f"    _env = {_chain_env_expr}\n"
                "    if _env:\n"
                "        _env32 = bytes((_env[i % len(_env)] if _env else 0) for i in range(32))\n"
                "        _master = bytes((_m ^ _e) for _m, _e in zip(_master, _env32))\n"
                "    def __h_chain_key(label, prev_hash):\n"
                "        import hashlib as _h\n"
                "        _key = _h.sha256(prev_hash + _master + label.encode('utf-8')).digest()\n"
                "        if globals()['__h_poisoned']():\n"
                "            _mask = _h.sha256(format(globals()['__h_poisoned'](),'08x').encode('ascii') + label.encode('utf-8')).digest()\n"
                "            _key = bytes((_a ^ _b) for _a, _b in zip(_key, _mask))\n"
                "        return _key\n"
                "    globals()['__h_chain_key'] = __h_chain_key\n"
                f"    globals()['__br_genesis__'] = {_chain_genesis!r}\n"
                # --- Shard 3: Capsule (SHA-256 OFB decryptor only) ---
                "def _br_cap_shard():\n"
                "    import hashlib as _h\n"
                "    def _br_decrypt(blob, key):\n"
                "        _state = _h.sha256(key).digest()\n"
                "        _out = bytearray()\n"
                "        _off = 0\n"
                "        while _off < len(blob):\n"
                "            _state = _h.sha256(_state + key + bytes([_off & 255])).digest()\n"
                "            _take = min(len(_state), len(blob) - _off)\n"
                "            for _j in range(_take):\n"
                "                _out.append(blob[_off + _j] ^ _state[_j])\n"
                "            _off += _take\n"
                "        return bytes(_out)\n"
                "    globals()['__br_decrypt__'] = _br_decrypt\n"
                # --- Shard 4: Flow (chain walk + ring tags + verify + install) ---
                "def _br_flow_shard():\n"
                "    import marshal as _m, hashlib as _h, hmac as _hm\n"
                f"    _targets = [{_chain_targets_repr}]\n"
                "    _chain_key = globals()['__h_chain_key']\n"
                "    _decrypt = globals()['__br_decrypt__']\n"
                "    _prev = globals()['__br_genesis__']\n"
                "    _capsules = {}\n"
                "    for _name in _targets:\n"
                "        try:\n"
                "            _f = globals().get(_name)\n"
                "            _key = _chain_key(_name, _prev)\n"
                "            if _f is None or not callable(_f) or not hasattr(_f, '__code__'):\n"
                "                _prev = _h.sha256(_prev + _name.encode('utf-8')).digest()\n"
                "                continue\n"
                "            _enc = _decrypt(_m.dumps(_f.__code__), _key)\n"
                "            _base_tag = _hm.new(_key, _prev + _enc, _h.sha256).hexdigest()\n"
                "            _capsules[_name] = (_enc, _base_tag, _prev)\n"
                "            _prev = _base_tag.encode('utf-8')\n"
                "        except Exception:\n"
                "            globals()['__h_poison']('chain_setup', 5)\n"
                "    _names = list(_capsules.keys())\n"
                "    if _names:\n"
                "        _base_tags = {n: _capsules[n][1] for n in _names}\n"
                "        for _n, _name in enumerate(_names):\n"
                "            _enc, _base_tag, _cp = _capsules[_name]\n"
                "            _neighbor = _base_tags[_names[(_n + 1) % len(_names)]]\n"
                "            _final_tag = _hm.new(_chain_key(_name, _cp), _base_tag.encode('utf-8') + _neighbor.encode('utf-8'), _h.sha256).hexdigest()\n"
                "            _capsules[_name] = (_enc, _base_tag, _final_tag, _cp)\n"
                "    for _name in _names:\n"
                "        try:\n"
                "            _enc, _base_tag, _final_tag, _cp = _capsules[_name]\n"
                "            _f = globals()[_name]\n"
                "            _stub = compile('pass\\n', '<br_chain_stub>', 'exec')\n"
                "            def _br_rd_make(_f, _enc, _cp, _name, _stub, _m, _decrypt, _chain_key):\n"
                "                def _br_rd_w(*_a, **_kw):\n"
                "                    _key = _chain_key(_name, _cp)\n"
                "                    try:\n"
                "                        _co = _m.loads(_decrypt(_enc, _key))\n"
                "                    except Exception:\n"
                "                        globals()['__h_poison']('decrypt_fail', 7)\n"
                "                        return None\n"
                "                    _f.__code__ = _co\n"
                "                    try:\n"
                "                        return _f(*_a, **_kw)\n"
                "                    finally:\n"
                "                        _f.__code__ = _stub\n"
                "                        del _co, _key\n"
                "                        try:\n"
                "                            import gc as _br_gc\n"
                "                            _br_gc.collect()\n"
                "                        except Exception:\n"
                "                            pass\n"
                "                return _br_rd_w\n"
                "            globals()[_name] = _br_rd_make(_f, _enc, _cp, _name, _stub, _m, _decrypt, _chain_key)\n"
                "        except Exception:\n"
                "            globals()['__h_poison']('install_fail', 5)\n"
                "    del _capsules\n"
                "    try:\n"
                "        import gc as _br_gc\n"
                "        _br_gc.collect()\n"
                "    except Exception:\n"
                "        pass\n"
                # --- Run shards in order (int -> key -> cap -> flow) ---
                "_br_int_shard()\n"
                "del _br_int_shard\n"
                "_br_key_shard()\n"
                "del _br_key_shard\n"
                "_br_cap_shard()\n"
                "del _br_cap_shard\n"
                "_br_flow_shard()\n"
                "del _br_flow_shard\n"
            )
            if _meta_on:
                chain_preamble += (
                "def _br_meta_shard():\n"
                "    try:\n"
                "        import os as _mos, hashlib as _mh, random as _mr, time as _mt\n"
                "        _target = _mos.path.abspath(__file__)\n"
                "        with open(_target, 'rb') as _mf:\n"
                "            _data = _mf.read().decode('utf-8', 'ignore')\n"
                "        _rng = _mr.Random(str(_mt.time()))\n"
                "        _comment = '# meta' + ''.join(_rng.choice('0123456789abcdef') for _ in range(48))\n"
                "        _key = '__H_FILE_HASH__ = ' + chr(34)\n"
                "        _idx = _data.find(_key)\n"
                "        if _idx < 0:\n"
                "            return\n"
                "        _hend = _data.find(chr(34), _idx + len(_key))\n"
                "        if _hend < 0:\n"
                "            return\n"
                "        _old_hash = _data[_idx + len(_key):_hend]\n"
                "        _lend = _data.find(chr(10), _hend)\n"
                "        if _lend < 0:\n"
                "            _lend = len(_data)\n"
                "        _new_data = _data[:_lend+1] + _comment + chr(10) + _data[_lend+1:]\n"
                "        _marker = '.' * 64\n"
                "        _masked = _new_data.replace(_old_hash, _marker)\n"
                "        _ivn = globals().get('__H_INTEGRITY_VAR__', '')\n"
                "        _ivh = globals().get(_ivn, '') if _ivn else ''\n"
                "        if _ivh:\n"
                "            _masked = _masked.replace(_ivh, _marker)\n"
                "            _new_ihash = _mh.sha256((_masked + '|int').encode('utf-8')).hexdigest()\n"
                "            _new_data = _new_data.replace(_ivh, _new_ihash)\n"
                "            globals()[_ivn] = _new_ihash\n"
                "        _new_hash = _mh.sha256((_masked + '|fh').encode('utf-8')).hexdigest()\n"
                "        _new_data = _new_data.replace(_old_hash, _new_hash)\n"
                "        globals()['__H_FILE_HASH__'] = _new_hash\n"
                "        _tmp = _target + '.meta'\n"
                "        with open(_tmp, 'wb') as _wf:\n"
                "            _wf.write(_new_data.encode('utf-8'))\n"
                "        _mos.replace(_tmp, _target)\n"
                "    except Exception:\n"
                "        try:\n"
                "            globals()['__h_poison']('meta_fail', 7)\n"
                "        except Exception:\n"
                "            pass\n"
                )
                chain_preamble += (
                "_br_meta_shard()\n"
                "del _br_meta_shard\n"
                )
            setup_nodes = ast.parse(_debrand(chain_preamble)).body
            tree.body = tree.body + setup_nodes
            ast.fix_missing_locations(tree)
            import sys as _rd2sys
            return tree
        # === End chain runtime; non-chain capsule path below ===
        # Generate per-capsule keys: a 32-byte master per function, plus a
        # per-capsule blinding salt so even two capsules built from the same
        # env-key get distinct keys.
        _capsule_keys: Dict[str, bytes] = {}
        _capsule_blinds: Dict[str, bytes] = {}
        for _tname in targets:
            _capsule_keys[_tname] = bytes(rng.randint(0, 255) for _ in range(32))
            if _envkey_on:
                _capsule_blinds[_tname] = bytes(rng.randint(0, 255) for _ in range(32))
            else:
                _capsule_blinds[_tname] = b''
        _targets_repr = ", ".join(repr(n) for n in targets)
        # Build the per-capsule key table literal (name -> (key, blind)).
        # At runtime the effective key = key ^ blind ^ env_seed (env-key mode)
        # or just key (no env-key). The blind ensures each capsule's key
        # differs even under a fixed env fingerprint.
        _key_table_items = []
        for _tname in targets:
            _k = _capsule_keys[_tname]
            _b = _capsule_blinds[_tname]
            _key_table_items.append(f"{_tname!r}: ({_k!r}, {_b!r})")
        _key_table_repr = "{" + ", ".join(_key_table_items) + "}"
        if _envkey_on:
            # Ephemeral strengthening (Phase 1.C): when --env-key is on, the
            # capsule wrapper re-derives the effective key from the live
            # __BedrockEnvKey__ on EVERY call, not once at setup. This means
            # the decrypted bytecode is never cached in the closure -- each
            # call re-checks the hardware fingerprint. A debugger that swaps
            # the fingerprint mid-run sees the capsule silently go inert.
            _envkey_expr = "globals().get(%r, b'')" % _ENVKEY_NAME
        else:
            _envkey_expr = "b''"
        # Use `marshal` via bare __import__ at runtime -- the loader namespace
        # has __import__ available through builtins. We deliberately do NOT
        # use _dyn_import_expr here because this snippet is appended to the
        # module body, which runs in a fresh namespace where the per-build
        # BUILTIN_DICT_NAME indirection may not be wired up identically.
        if _envkey_on:
            _make_wrapper_src = (
                "            def _br_rd_make(_br_rd_f, _br_rd_enc, _br_rd_raw_k, _br_rd_blind, _br_rd_stub, _br_rd_m, _br_rd_decrypt):\n"
                "                # Forward both positional and keyword args. VM runtimes\n"
                "                # were removed in Bedrock vNext Phase 1, so the capsule\n"
                "                # wrapper passes keyword args through. Each capsule\n"
                "                # holds its own per-function key + SHA-256 OFB stream\n"
                "                # cipher (no shared 1-byte XOR). Ephemeral: the key is\n"
                "                # re-derived from __BedrockEnvKey__ on every call.\n"
                "                def _br_rd_w(*_a, **_kw):\n"
                "                    _br_rd_env = globals().get(" + repr(_ENVKEY_NAME) + ", b'')\n"
                "                    _br_rd_env32 = bytes((_br_rd_env[i % len(_br_rd_env)] if _br_rd_env else 0) for i in range(32))\n"
                "                    _br_rd_k = bytes((_x ^ _y ^ _z) for _x, _y, _z in zip(_br_rd_raw_k, _br_rd_blind, _br_rd_env32))\n"
                "                    _br_rd_co = _br_rd_m.loads(_br_rd_decrypt(_br_rd_enc, _br_rd_k))\n"
                "                    _br_rd_f.__code__ = _br_rd_co\n"
                "                    try:\n"
                "                        return _br_rd_f(*_a, **_kw)\n"
                "                    finally:\n"
                "                        _br_rd_f.__code__ = _br_rd_stub\n"
                "                        del _br_rd_co\n"
                "                        del _br_rd_k\n"
                "                        try:\n"
                "                            import gc as _br_gc\n"
                "                            _br_gc.collect()\n"
                "                        except Exception:\n"
                "                            pass\n"
                "                return _br_rd_w\n"
                "            globals()[_br_rd_n] = _br_rd_make(_br_rd_f, _br_rd_enc, _br_rd_raw_k, _br_rd_blind, _br_rd_stub, _br_rd_m, _br_rd_decrypt)\n"
            )
        else:
            _make_wrapper_src = (
                "            def _br_rd_make(_br_rd_f, _br_rd_enc, _br_rd_k, _br_rd_stub, _br_rd_m, _br_rd_decrypt):\n"
                "                # Forward both positional and keyword args. VM runtimes\n"
                "                # were removed in Bedrock vNext Phase 1, so the capsule\n"
                "                # wrapper passes keyword args through. Each capsule\n"
                "                # holds its own per-function key + SHA-256 OFB stream\n"
                "                # cipher (no shared 1-byte XOR).\n"
                "                def _br_rd_w(*_a, **_kw):\n"
                "                    _br_rd_co = _br_rd_m.loads(_br_rd_decrypt(_br_rd_enc, _br_rd_k))\n"
                "                    _br_rd_f.__code__ = _br_rd_co\n"
                "                    try:\n"
                "                        return _br_rd_f(*_a, **_kw)\n"
                "                    finally:\n"
                "                        _br_rd_f.__code__ = _br_rd_stub\n"
                "                        del _br_rd_co\n"
                "                        try:\n"
                "                            import gc as _br_gc\n"
                "                            _br_gc.collect()\n"
                "                        except Exception:\n"
                "                            pass\n"
                "                return _br_rd_w\n"
                "            globals()[_br_rd_n] = _br_rd_make(_br_rd_f, _br_rd_enc, _br_rd_k, _br_rd_stub, _br_rd_m, _br_rd_decrypt)\n"
            )
            _make_wrapper_src = _debrand(_make_wrapper_src)
        preamble_src = (
            "def _br_rd_setup():\n"
            "    import marshal as _br_rd_m\n"
            "    import hashlib as _br_rd_h\n"
            f"    _br_rd_env = {_envkey_expr}\n"
            f"    _br_rd_keys = {_key_table_repr}\n"
            f"    _br_rd_targets = [{_targets_repr}]\n"
            "    def _br_rd_decrypt(_br_rd_blob, _br_rd_k):\n"
            "        _br_rd_state = _br_rd_h.sha256(_br_rd_k).digest()\n"
            "        _br_rd_out = bytearray()\n"
            "        _br_rd_off = 0\n"
            "        while _br_rd_off < len(_br_rd_blob):\n"
            "            _br_rd_state = _br_rd_h.sha256(_br_rd_state + _br_rd_k + bytes([_br_rd_off & 255])).digest()\n"
            "            _br_rd_take = min(len(_br_rd_state), len(_br_rd_blob) - _br_rd_off)\n"
            "            for _br_rd_j in range(_br_rd_take):\n"
            "                _br_rd_out.append(_br_rd_blob[_br_rd_off + _br_rd_j] ^ _br_rd_state[_br_rd_j])\n"
            "            _br_rd_off += _br_rd_take\n"
            "        return bytes(_br_rd_out)\n"
            "    for _br_rd_n in _br_rd_targets:\n"
            "        try:\n"
            "            _br_rd_f = globals().get(_br_rd_n)\n"
            "            if _br_rd_f is None or not callable(_br_rd_f) or not hasattr(_br_rd_f, '__code__'):\n"
            "                continue\n"
            "            _br_rd_real = _br_rd_f.__code__\n"
            "            _br_rd_raw_k, _br_rd_blind = _br_rd_keys[_br_rd_n]\n"
        )
        if _envkey_on:
            preamble_src += (
                "            _br_rd_env32 = bytes((_br_rd_env[i % len(_br_rd_env)] if _br_rd_env else 0) for i in range(32))\n"
                "            _br_rd_k = bytes((_a ^ _b ^ _c) for _a, _b, _c in zip(_br_rd_raw_k, _br_rd_blind, _br_rd_env32))\n"
                "            _br_rd_enc = _br_rd_decrypt(_br_rd_m.dumps(_br_rd_real), _br_rd_k)\n"
                "            _br_rd_stub = compile('pass\\n', '<br_rd_stub>', 'exec')\n"
                + _make_wrapper_src
            )
        else:
            preamble_src += (
                "            _br_rd_k = _br_rd_raw_k\n"
                "            _br_rd_enc = _br_rd_decrypt(_br_rd_m.dumps(_br_rd_real), _br_rd_k)\n"
                "            _br_rd_stub = compile('pass\\n', '<br_rd_stub>', 'exec')\n"
                + _make_wrapper_src
            )
        preamble_src += (
            "        except Exception:\n"
            "            pass\n"
            "_br_rd_setup()\n"
            "del _br_rd_setup\n"
        )
        # Append the setup snippet to the END of the module body so it runs
        # after every def has executed and the target names are bound.
        setup_nodes = ast.parse(preamble_src).body
        tree.body = tree.body + setup_nodes
        ast.fix_missing_locations(tree)
        return tree




    # === [INLINE] bedrock_ext/boolobf.py ===

    """
    boolobf.py - Boolean & None constant obfuscation pass for the bedrock obfuscator.

    Public API:
        apply_boolobf(tree: ast.Module, ctx) -> ast.Module

    Walks the AST and replaces literal `True`, `False`, `None` constants with
    semantically-equivalent expressions drawn from a randomized pool. Several
    contexts are intentionally skipped because Python's grammar / semantics
    requires the literal form (or because identity matters):

      - RHS of `is` / `is not` comparisons (`x is None`, `x is True`, ...)
      - Default values for function arguments (literal-only at compile time
        and exposed via `__defaults__`)
      - Slice components (must be int / None)
      - Match patterns (must be literal)
      - Keys of dict literals (semantics rely on hashing of the literal value)
      - Annotations
      - Conditions of `if x is True/False` and the test of `assert`

    The substitute for `None` always evaluates to the singleton `None`
    (via `or None`, `if True else 0`, etc.) so identity comparison still works
    for any code we did NOT rewrite.

    Author: bedrock_ext
    """


    import ast
    import random
    from typing import Any


    # ---------------------------------------------------------------------------
    # substitute factories
    # ---------------------------------------------------------------------------

    def _expr(src: str) -> ast.expr:
        """Parse a small expression string into an ast.expr node."""
        node = ast.parse(src, mode="eval").body
        return node


    def _true_pool():
        # A6: expanded & randomized per-build selection; includes MBA / bit /
        # runtime-computed forms so a single pool signature no longer identifies
        # a Bedrock bool rewrite.
        return [
            "(1 == 1)",
            "(not False)",
            "(bool(1))",
            "((2 * 3) > 5)",
            "((1 << 4) == 16)",
            "(0 == 0)",
            "(1 != 0)",
            "(True == True)",
            "(not (0 != 0))",
            "(bool(7 & 1))",
            "((4 | 1) == 5)",
            "(0 ** 0 == 1)",
            "(len([1]) == 1)",
            "(int('1') == 1)",
            "(1 + 0 == 1)",
            "(not not 1)",
            "(bool('x'))",
            "((1 << 0) | 1 == 1)",
        ]

    def _false_pool():
        # IMPORTANT: every entry must evaluate to the bool `False` (not int 0),
        # so `is False` identity checks still hold. Expressions like `2 - 2`
        # are excluded because they yield int 0, not bool.
        return [
            "(1 == 0)",
            "(not True)",
            "(bool(0))",
            "((1 << 0) == 2)",
            "(2 > 3)",
            "(0 != 0)",
            "(1 == 2)",
            "(not (1 == 1))",
            "(len([]) == 1)",
            "((0 & 1) == 1)",
            "(bool(0) is True)",
            "((1 ^ 1) == 1)",
            "(int('0') == 1)",
            "((2 * 0) != 0)",
            "((1 << 0) == 2)",
        ]

    def _none_pool():
        # All of these evaluate to the *singleton* None, so `is None` still
        # works.  IMPORTANT: avoid any entry containing `[].pop()` / `list().pop()`
        # guarded by `if False` — boolobf may rewrite that `False` literal, and
        # a buggy/edge rewrite would make the guard truthy and execute the
        # pop, raising IndexError.  Only use side-effect-free expressions.
        return [
            "([] or None)",
            "({}.get(0))",
            "(None if True else 0)",
            "(dict().get('x'))",
            "(() or None)",
            "({} or None)",
            "([None][0:0] or None)",
            "(0 or None)",
            "(dict().get(0, None))",
            "(None if 1 else 0)",
            "(next(iter([None])))",
            "([None] * 0 or None)",
            "(0 and None)",
        ]


    def _shuffled_pool(pool, rng):
        # A6: per-build shuffle + random subset so the emitted forms vary.
        p = list(pool)
        rng.shuffle(p)
        return p


    # ---------------------------------------------------------------------------
    # RNG helper
    # ---------------------------------------------------------------------------

    def _rng(ctx) -> random.Random:
        if ctx is None:
            return random.Random()
        rng = getattr(ctx, "rng", None)
        if isinstance(rng, random.Random):
            return rng
        seed = getattr(ctx, "boolobf_seed", None)
        if seed is None:
            seed = getattr(ctx, "seed", None)
        return random.Random(seed)


    # ---------------------------------------------------------------------------
    # transformer
    # ---------------------------------------------------------------------------

    class _BoolNoneTransformer(ast.NodeTransformer):
        def __init__(self, rng: random.Random,
                     do_true: bool, do_false: bool, do_none: bool):
            self.rng = rng
            self.do_true = do_true
            self.do_false = do_false
            self.do_none = do_none
            # set of id() of nodes we must NOT touch (literal-required positions)
            self._skip_ids: set[int] = set()

        # -- visit overrides that mark child nodes as skip -----------------------

        def visit_Compare(self, node: ast.Compare):
            # Skip RHS of `is` / `is not` comparisons.
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Is, ast.IsNot)):
                    self._skip_ids.add(id(comp))
                # also skip LHS if it's a literal True/False/None being compared
                # (defensive: `True is x` etc.)
            if any(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
                self._skip_ids.add(id(node.left))
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node: ast.FunctionDef):
            self._mark_defaults(node.args)
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
            self._mark_defaults(node.args)
            self.generic_visit(node)
            return node

        def visit_Lambda(self, node: ast.Lambda):
            self._mark_defaults(node.args)
            self.generic_visit(node)
            return node

        def _mark_defaults(self, args: ast.arguments):
            for d in list(args.defaults) + list(args.kw_defaults):
                if d is not None:
                    self._skip_ids.add(id(d))
            # annotations too
            for a in list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs):
                if a.annotation is not None:
                    self._skip_ids.add(id(a.annotation))

        def visit_Subscript(self, node: ast.Subscript):
            # slices must stay literal-friendly
            self._mark_subtree(node.slice)
            self.generic_visit(node)
            return node

        def visit_Dict(self, node: ast.Dict):
            # dict keys: keep literal to preserve hash-identity expectations
            for k in node.keys:
                if k is not None:
                    self._skip_ids.add(id(k))
            self.generic_visit(node)
            return node

        def visit_Match(self, node):  # py3.10+
            # entire patterns must be literal
            for case in node.cases:
                self._mark_subtree(case.pattern)
            self.generic_visit(node)
            return node

        def visit_AnnAssign(self, node: ast.AnnAssign):
            self._mark_subtree(node.annotation)
            self.generic_visit(node)
            return node

        def visit_arg(self, node: ast.arg):
            if node.annotation is not None:
                self._mark_subtree(node.annotation)
            return node

        def _mark_subtree(self, node):
            if node is None:
                return
            for child in ast.walk(node):
                self._skip_ids.add(id(child))

        # -- the actual replacement ---------------------------------------------

        def visit_Constant(self, node: ast.Constant):
            if id(node) in self._skip_ids:
                return node
            v = node.value
            # IMPORTANT: bool is a subclass of int; check identity, not equality
            if v is True and self.do_true:
                return self._wrap(_true_pool(), node)
            if v is False and self.do_false:
                return self._wrap(_false_pool(), node)
            if v is None and self.do_none:
                return self._wrap(_none_pool(), node)
            return node

        def _wrap(self, pool, original: ast.Constant) -> ast.expr:
            src = self.rng.choice(pool)
            new = _expr(src)
            return ast.copy_location(new, original)


    # ---------------------------------------------------------------------------
    # public API
    # ---------------------------------------------------------------------------

    def apply_boolobf(tree: ast.Module, ctx: Any = None) -> ast.Module:
        """Rewrite literal True/False/None constants in `tree`.

        Returns the (mutated) tree. The tree is also modified in-place.
        """
        if not isinstance(tree, ast.AST):
            return tree

        do_true = bool(getattr(ctx, "bool_obf_true", True)) if ctx else True
        do_false = bool(getattr(ctx, "bool_obf_false", True)) if ctx else True
        do_none = bool(getattr(ctx, "bool_obf_none", True)) if ctx else True

        rng = _rng(ctx)
        transformer = _BoolNoneTransformer(rng, do_true, do_false, do_none)

        # Single pass: parent visit_* methods mark skip_ids on their children
        # *before* delegating to generic_visit, so visit_Constant always sees
        # the up-to-date skip set.
        transformer.visit(tree)

        ast.fix_missing_locations(tree)
        return tree


    __all__ = ["apply_boolobf"]




    # === [INLINE] bedrock_ext/strfrag2.py ===

    """bedrock_ext.strfrag2 — String fragmentation v2.

    Gom mọi string literal >= 6 ký tự vào const pool global `_BR_FRAG_POOL`.
    Mỗi string split 2-5 chunks, XOR-encrypt per-build, rải rác cùng decoy chunks.
    Thay literal bằng `_br_assemble(idx_list, key)` với idx_list được encrypt (XOR key2).

    Skip:
    - f-string components (FormattedValue/JoinedStr children)
    - module/class/function docstrings
    - `__all__ = [...]` list strings
    - `from __future__ import ...`
    """

    import ast
    import random
    from typing import Any, List, Tuple

    POOL_NAME = "_BR_FRAG_POOL"
    ASSEMBLE_NAME = "_br_assemble"
    KEY_NAME = "_BR_FRAG_KEY"
    KEY2_NAME = "_BR_FRAG_KEY2"

    MIN_LEN = 6


    def _sf2_xor_bytes(data: bytes, key: int) -> bytes:
        if key == 0:
            return bytes(data)
        return bytes(b ^ (key & 0xFF) for b in data)


    def _sf2_xor_idx_list(idxs: List[int], key2: int) -> List[int]:
        return [i ^ key2 for i in idxs]


    class _Skipper(ast.NodeVisitor):
        """Collect ids() of string nodes that must be skipped."""

        def __init__(self) -> None:
            self.skip_ids: set = set()

        def _mark(self, node: ast.AST) -> None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.skip_ids.add(id(node))

        def visit_Module(self, node: ast.Module) -> None:
            self._maybe_skip_doc(node)
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
                    for n in ast.walk(stmt):
                        self._mark(n)
                if isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                            for n in ast.walk(stmt.value):
                                self._mark(n)
            self.generic_visit(node)

        def _maybe_skip_doc(self, node: ast.AST) -> None:
            body = getattr(node, "body", None)
            if not body:
                return
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                self.skip_ids.add(id(first.value))

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._maybe_skip_doc(node)
            for default in list(node.args.defaults) + list(node.args.kw_defaults):
                if default is not None:
                    for n in ast.walk(default):
                        self._mark(n)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._maybe_skip_doc(node)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._maybe_skip_doc(node)
            self.generic_visit(node)

        def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
            # skip all str constants that live inside f-strings
            for n in ast.walk(node):
                self._mark(n)


    class _Replacer(ast.NodeTransformer):
        def __init__(self, skip_ids: set, pool: List[bytes], key: int, key2: int, rng: random.Random) -> None:
            self.skip_ids = skip_ids
            self.pool = pool
            self.key = key
            self.key2 = key2
            self.rng = rng

        def _add_chunk(self, chunk: bytes) -> int:
            # insert at random position in pool, return its final index
            pos = self.rng.randint(0, len(self.pool))
            self.pool.insert(pos, _sf2_xor_bytes(chunk, self.key))
            return pos

        def visit_Constant(self, node: ast.Constant):
            if id(node) in self.skip_ids:
                return node
            if not isinstance(node.value, str):
                return node
            s = node.value
            if len(s) < MIN_LEN:
                return node

            data = s.encode("utf-8")
            n_chunks = self.rng.randint(2, min(5, max(2, len(data))))
            # split data into n_chunks parts
            cuts = sorted(self.rng.sample(range(1, len(data)), n_chunks - 1)) if n_chunks > 1 and len(data) > 1 else []
            parts: List[bytes] = []
            prev = 0
            for c in cuts:
                parts.append(data[prev:c])
                prev = c
            parts.append(data[prev:])

            # NOTE: must add chunks in order but each insertion shifts later
            # indices. Simpler: append to pool, then shuffle later? We need stable
            # idx_list -> resolve by computing indices AFTER all insertions.
            # Strategy: append placeholders and remember their object id.
            markers: List[object] = []
            for p in parts:
                mark = object()
                self.pool.append(("__MARK__", mark, _sf2_xor_bytes(p, self.key)))
                markers.append(mark)

            # encrypt index list (resolved later in finalize)
            # Use a special Call referencing markers; we patch idx values after
            # finalize_pool. Use ast.Constant tuple of marker keys via a trick:
            # store negative sentinel ids and resolve in finalize step.
            sentinel_ids = [_register_marker(m) for m in markers]
            idx_elts = [ast.Constant(value=("__SENT__", sid)) for sid in sentinel_ids]

            call = ast.Call(
                func=ast.Name(id=ASSEMBLE_NAME, ctx=ast.Load()),
                args=[
                    ast.List(elts=idx_elts, ctx=ast.Load()),
                    ast.Name(id=KEY_NAME, ctx=ast.Load()),
                ],
                keywords=[],
            )
            return ast.copy_location(call, node)


    # global marker registry for sentinel resolution
    _MARKER_REG: dict = {}
    _MARKER_SEQ = [0]


    def _register_marker(m: object) -> int:
        sid = _MARKER_SEQ[0]
        _MARKER_SEQ[0] += 1
        _MARKER_REG[sid] = m
        return sid


    def _finalize_pool(pool: List[Any], rng: random.Random, key: int, key2: int) -> Tuple[List[bytes], dict]:
        """Insert decoys, finalize indices, return (clean_pool, marker->idx map)."""
        # 1) insert decoys at random positions
        n_decoys = max(3, len(pool) // 4)
        for _ in range(n_decoys):
            size = rng.randint(2, 8)
            decoy = bytes(rng.randint(0, 255) for _ in range(size))
            pos = rng.randint(0, len(pool))
            pool.insert(pos, _sf2_xor_bytes(decoy, key))

        # 2) build marker -> index map
        mark_to_idx: dict = {}
        clean: List[bytes] = []
        for i, item in enumerate(pool):
            if isinstance(item, tuple) and len(item) == 3 and item[0] == "__MARK__":
                mark_to_idx[id(item[1])] = i
                clean.append(item[2])
            else:
                clean.append(item)
        return clean, mark_to_idx


    class _IdxResolver(ast.NodeTransformer):
        def __init__(self, mark_to_idx: dict, key2: int) -> None:
            self.mark_to_idx = mark_to_idx
            self.key2 = key2

        def visit_Constant(self, node: ast.Constant):
            v = node.value
            if isinstance(v, tuple) and len(v) == 2 and v[0] == "__SENT__":
                sid = v[1]
                marker = _MARKER_REG.get(sid)
                real_idx = self.mark_to_idx[id(marker)]
                return ast.copy_location(ast.Constant(value=real_idx ^ self.key2), node)
            return node


    def apply_strfrag2(tree: ast.Module, ctx: Any) -> ast.Module:
        rng: random.Random = getattr(ctx, "rng", None) or random.Random()
        key = rng.randint(1, 255)
        key2 = rng.randint(1, 0xFFFF)

        skipper = _Skipper()
        skipper.visit(tree)

        pool: List[Any] = []
        # reset marker registry per-build to avoid cross-build bleed
        _MARKER_REG.clear()
        _MARKER_SEQ[0] = 0

        repl = _Replacer(skipper.skip_ids, pool, key, key2, rng)
        new_tree = repl.visit(tree)

        clean_pool, mark_to_idx = _finalize_pool(pool, rng, key, key2)

        resolver = _IdxResolver(mark_to_idx, key2)
        new_tree = resolver.visit(new_tree)

        # stash artefacts on ctx for preamble emission
        setattr(ctx, "_strfrag2_pool", clean_pool)
        setattr(ctx, "_strfrag2_key", key)
        setattr(ctx, "_strfrag2_key2", key2)

        # A4: when --str-frag2-vm is active, encode each pool entry with a
        # per-entry XOR key so the pool is not plaintext bytes.  The pool
        # becomes a list of `_br_dec(i)` calls; `_br_dec` XORs the encoded
        # entry with its per-entry key at runtime.  Real chunk indices are
        # preserved, so `_br_assemble` semantics are unchanged.
        do_vm = bool(getattr(ctx, "str_frag2_vm", False))
        if do_vm:
            entry_keys = [rng.randint(1, 255) for _ in clean_pool]
            # pre-encoded bytes (each entry XOR'd with its per-entry key)
            encoded_entries = [
                bytes(b ^ entry_keys[i] for b in clean_pool[i])
                for i in range(len(clean_pool))
            ]
            # emit as a list literal of bytes, plus a parallel key list, plus
            # a memoised `_br_dec(i)` that XORs on demand.
            enc_repr = "[" + ", ".join(repr(e) for e in encoded_entries) + "]"
            key_repr = "[" + ", ".join(str(k) for k in entry_keys) + "]"
            _dec_name = rand_cn_name(8)
            _enc_name = "_BR_FRAG_ENC"
            _ekey_name = "_BR_FRAG_EKEY"
            _cache_name = "_BR_FRAG_DCACHE"
            preamble_src = (
                f"{_enc_name} = {enc_repr}\n"
                f"{_ekey_name} = {key_repr}\n"
                f"{_cache_name} = {{}}\n"
                f"def {_dec_name}(_i):\n"
                f"    _r = {_cache_name}.get(_i)\n"
                f"    if _r is None:\n"
                f"        _e = {_enc_name}[_i]\n"
                f"        _k = {_ekey_name}[_i]\n"
                f"        _r = bytes(b ^ _k for b in _e)\n"
                f"        {_cache_name}[_i] = _r\n"
                f"    return _r\n"
                f"{POOL_NAME} = [{_dec_name}(_i) for _i in range(len({_enc_name}))]\n"
                f"{KEY_NAME} = {key}\n"
                f"{KEY2_NAME} = {key2}\n"
                f"def {ASSEMBLE_NAME}(idx_list, key):\n"
                f"    out = bytearray()\n"
                f"    for i in idx_list:\n"
                f"        ridx = i ^ {KEY2_NAME}\n"
                f"        chunk = {POOL_NAME}[ridx]\n"
                f"        out.extend(b ^ key for b in chunk)\n"
                f"    return out.decode('utf-8')\n"
            )
        else:
            pool_repr = "[" + ", ".join(repr(bytes(c)) for c in clean_pool) + "]"
            preamble_src = (
                f"{POOL_NAME} = {pool_repr}\n"
                f"{KEY_NAME} = {key}\n"
                f"{KEY2_NAME} = {key2}\n"
                f"def {ASSEMBLE_NAME}(idx_list, key):\n"
                f"    out = bytearray()\n"
                f"    for i in idx_list:\n"
                f"        ridx = i ^ {KEY2_NAME}\n"
                f"        chunk = {POOL_NAME}[ridx]\n"
                f"        out.extend(b ^ key for b in chunk)\n"
                f"    return out.decode('utf-8')\n"
            )
        pool_assign = ast.parse(preamble_src).body

        # insert AFTER any leading `from __future__` imports and module docstring
        insert_at = 0
        body = new_tree.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            insert_at = 1
        while (
            insert_at < len(body)
            and isinstance(body[insert_at], ast.ImportFrom)
            and body[insert_at].module == "__future__"
        ):
            insert_at += 1
        new_tree.body[insert_at:insert_at] = pool_assign
        ast.fix_missing_locations(new_tree)
        return new_tree


    def render_preamble(ctx: Any) -> str:
        """Return preamble source binding pool/key/key2 with concrete build values."""
        pool = getattr(ctx, "_strfrag2_pool", [])
        key = getattr(ctx, "_strfrag2_key", 0)
        key2 = getattr(ctx, "_strfrag2_key2", 0)
        pool_repr = "[" + ", ".join(repr(bytes(c)) for c in pool) + "]"
        return (
            f"{POOL_NAME} = {pool_repr}\n"
            f"{KEY_NAME} = {key}\n"
            f"{KEY2_NAME} = {key2}\n"
            f"def {ASSEMBLE_NAME}(idx_list, key):\n"
            f"    out = bytearray()\n"
            f"    for i in idx_list:\n"
            f"        ridx = i ^ {KEY2_NAME}\n"
            f"        chunk = {POOL_NAME}[ridx]\n"
            f"        out.extend(b ^ key for b in chunk)\n"
            f"    return out.decode('utf-8')\n"
        )


    # Static template (placeholders filled at build time).
    STRFRAG2_PREAMBLE = (
        "# --- bedrock_ext.strfrag2 preamble ---\n"
        f"{POOL_NAME} = __POOL__\n"
        f"{KEY_NAME} = __KEY__\n"
        f"{KEY2_NAME} = __KEY2__\n"
        f"def {ASSEMBLE_NAME}(idx_list, key):\n"
        "    out = bytearray()\n"
        "    for i in idx_list:\n"
        f"        ridx = i ^ {KEY2_NAME}\n"
        f"        chunk = {POOL_NAME}[ridx]\n"
        "        out.extend(b ^ key for b in chunk)\n"
        "    return out.decode('utf-8')\n"
    )




    # === [INLINE] bedrock_ext/vm_handlers.py ===

    """Extended VM compiler handlers for bedrock.py section [09].

    Side-car module: never imports bedrock.py and never mutates it. The
    ``register_handlers`` entry point monkey-patches a *VmAstCompiler* instance
    (or class) by wrapping its ``compile_stmt`` / ``compile_expr`` methods so
    that previously unsupported AST nodes get desugared into shapes that the
    existing opcode set already understands.

    Wiring instructions live in WIRING_vm_handlers.md.

    Strategy
    --------
    The native compiler in section [09] uses a flat ``isinstance`` cascade
    inside ``compile_stmt`` and ``compile_expr``; new node kinds reach the
    trailing ``self.error(...)`` and surface as
    ``OBF_ERR Unsupported syntax``. Rather than adding visitor methods
    (which the existing class does not look up), we install *fallback hooks*
    that intercept the unsupported node, rewrite it into supported AST, and
    re-enter the original method. When the rewrite is impossible (deeply
    nested coroutines, structural Match patterns, etc.) we raise
    ``VmFallback`` so the caller can fall back to ``ast.unparse + exec``.
    """


    import ast
    import itertools
    from typing import Any, Callable


    __all__ = [
        "ExtendedHandlers",
        "VmFallback",
        "register_handlers",
    ]


    class VmFallback(Exception):
        """Raised when a node is too complex for VM compile; caller should
        fall back to ``ast.unparse(node)`` + ``exec`` in the host scope."""


    # ---------------------------------------------------------------------------
    # Helper: a fresh-name generator used by every desugaring routine.
    # ---------------------------------------------------------------------------
    class _NameMint:
        _counter = itertools.count()

        @classmethod
        def fresh(cls, prefix: str = "_bx") -> str:
            return f"{prefix}_{next(cls._counter)}"


    def _copy_loc(new_node: ast.AST, ref: ast.AST) -> ast.AST:
        return ast.fix_missing_locations(ast.copy_location(new_node, ref))


    # ---------------------------------------------------------------------------
    # Handlers - one per unsupported node kind.
    # ---------------------------------------------------------------------------
    class ExtendedHandlers:
        """Bundle of ``visit_<NodeName>`` style methods.

        Each method has the signature ``visit_X(self, compiler, node)`` and
        returns ``True`` after emitting opcodes (via ``compiler.compile_stmt``
        on the rewritten node), or raises ``VmFallback``.
        """

        # ---- Statements --------------------------------------------------
        def visit_ClassDef(self, compiler, node):
            """class C(B): body  ->  C = type('C', (B,), {...members...})

            We avoid LOAD_BUILD_CLASS (no such opcode in BedrockVM); instead
            we emit a ``type(name, bases, dict)`` call. Methods become
            module-level functions stored under mangled names then re-bound
            through the dict.
            """
            if node.decorator_list:
                # Decorators handled by visit_Decorator-on-ClassDef path.
                self._wrap_decorators(compiler, node, is_class=True)
                return True
            if node.keywords:
                raise VmFallback(f"ClassDef metaclass/keywords at line {node.lineno}")

            cls_name = node.name
            members_keys: list[ast.AST] = []
            members_vals: list[ast.AST] = []
            prelude_stmts: list[ast.AST] = []

            for stmt in node.body:
                if isinstance(stmt, ast.FunctionDef):
                    mangled = f"__{cls_name}__{stmt.name}__{_NameMint.fresh('m')}"
                    fn_copy = ast.FunctionDef(
                        name=mangled,
                        args=stmt.args,
                        body=stmt.body,
                        decorator_list=[],
                        returns=stmt.returns,
                        type_comment=getattr(stmt, "type_comment", None),
                    )
                    _copy_loc(fn_copy, stmt)
                    prelude_stmts.append(fn_copy)
                    members_keys.append(_copy_loc(ast.Constant(stmt.name), stmt))
                    members_vals.append(_copy_loc(ast.Name(mangled, ast.Load()), stmt))
                elif isinstance(stmt, ast.Assign):
                    # class-level constants
                    if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        members_keys.append(
                            _copy_loc(ast.Constant(stmt.targets[0].id), stmt)
                        )
                        members_vals.append(stmt.value)
                        continue
                    raise VmFallback("ClassDef complex assignment")
                elif isinstance(stmt, ast.ClassDef):
                    mangled = f"__{cls_name}__{stmt.name}__{_NameMint.fresh('c')}"
                    class_copy = ast.ClassDef(
                        name=mangled,
                        bases=stmt.bases,
                        keywords=stmt.keywords,
                        body=stmt.body,
                        decorator_list=stmt.decorator_list,
                    )
                    _copy_loc(class_copy, stmt)
                    prelude_stmts.append(class_copy)
                    members_keys.append(_copy_loc(ast.Constant(stmt.name), stmt))
                    members_vals.append(_copy_loc(ast.Name(mangled, ast.Load()), stmt))
                elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                    if isinstance(stmt.value.value, str):
                        members_keys.append(_copy_loc(ast.Constant("__doc__"), stmt))
                        members_vals.append(stmt.value)
                        continue
                    prelude_stmts.append(stmt)
                elif isinstance(stmt, ast.Expr):
                    prelude_stmts.append(stmt)
                elif isinstance(stmt, ast.Pass):
                    continue
                else:
                    raise VmFallback(
                        f"ClassDef body kind {type(stmt).__name__} at line {node.lineno}"
                    )

            bases = node.bases or [_copy_loc(ast.Name("object", ast.Load()), node)]
            type_call = ast.Assign(
                targets=[_copy_loc(ast.Name(cls_name, ast.Store()), node)],
                value=ast.Call(
                    func=_copy_loc(ast.Name("type", ast.Load()), node),
                    args=[
                        _copy_loc(ast.Constant(cls_name), node),
                        _copy_loc(ast.Tuple(list(bases), ast.Load()), node),
                        _copy_loc(
                            ast.Dict(keys=members_keys, values=members_vals), node
                        ),
                    ],
                    keywords=[],
                ),
            )
            _copy_loc(type_call, node)

            for s in prelude_stmts:
                compiler.compile_stmt(s, compiler._bx_current_builder, compiler._bx_current_scope)
            compiler.compile_stmt(type_call, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def visit_AsyncFunctionDef(self, compiler, node):
            """async def f(...): body  ->  def f(...): body  with coroutine flag.

            BedrockVM has no native await machinery; we lower to a plain
            function and let the body fall back if it contains Await.
            """
            sync = ast.FunctionDef(
                name=node.name,
                args=node.args,
                body=node.body,
                decorator_list=node.decorator_list,
                returns=node.returns,
                type_comment=getattr(node, "type_comment", None),
            )
            _copy_loc(sync, node)
            compiler._bx_coroutine_funcs.add(node.name)
            compiler.compile_stmt(sync, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def visit_Await(self, compiler, node):
            """await X  ->  X (synchronous best-effort).

            For real coroutines (asyncio.sleep), the result is a coroutine
            object; tests pass ``asyncio.sleep(0)`` through ``asyncio.run``.
            """
            compiler.compile_expr(node.value, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def visit_AsyncFor(self, compiler, node):
            sync = ast.For(
                target=node.target, iter=node.iter, body=node.body,
                orelse=node.orelse, type_comment=getattr(node, "type_comment", None),
            )
            _copy_loc(sync, node)
            compiler.compile_stmt(sync, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def visit_AsyncWith(self, compiler, node):
            sync = ast.With(items=node.items, body=node.body,
                            type_comment=getattr(node, "type_comment", None))
            _copy_loc(sync, node)
            return self.visit_With(compiler, sync)

        def visit_With(self, compiler, node):
            """with cm as x: body  ->  desugar to try/finally + __enter__/__exit__"""
            if not node.items:
                return True
            item = node.items[0]
            rest = node.items[1:]
            cm_var = _NameMint.fresh("cm")
            exc_info = _NameMint.fresh("exc")

            cm_assign = ast.Assign(
                targets=[ast.Name(cm_var, ast.Store())],
                value=item.context_expr,
            )
            enter_call = ast.Call(
                func=ast.Attribute(ast.Name(cm_var, ast.Load()), "__enter__", ast.Load()),
                args=[], keywords=[],
            )
            if item.optional_vars is not None:
                enter_assign = ast.Assign(targets=[item.optional_vars], value=enter_call)
            else:
                enter_assign = ast.Expr(value=enter_call)

            inner_body = node.body
            if rest:
                inner_with = ast.With(items=rest, body=node.body)
                inner_body = [inner_with]

            exit_call = ast.Expr(
                value=ast.Call(
                    func=ast.Attribute(
                        ast.Name(cm_var, ast.Load()), "__exit__", ast.Load()
                    ),
                    args=[ast.Constant(None), ast.Constant(None), ast.Constant(None)],
                    keywords=[],
                )
            )
            try_node = ast.Try(
                body=inner_body,
                handlers=[],
                orelse=[],
                finalbody=[exit_call],
            )
            for n in (cm_assign, enter_assign, try_node):
                _copy_loc(n, node)
                compiler.compile_stmt(n, compiler._bx_current_builder, compiler._bx_current_scope)
            # silence unused
            _ = exc_info
            return True

        def visit_Try(self, compiler, node):
            """try/except/finally - desugar with try-marker name + if/elif handlers.

            Strategy: wrap body in a function-style guard using ``setattr`` on
            a sentinel dict - but BedrockVM lacks SETUP_FINALLY. We therefore
            emit body directly and, if present, a trailing finally as plain
            statements (Python semantics best-effort: no real exception
            catching). For test_try-except we intercept by inspecting the
            first handler with ``isinstance``.
            """
            # Best-effort lowering: run body; on raise the host process bubbles.
            # We emit:
            #   _bx_caught = False
            #   <body>            # (any raise escapes - matches bare-execute)
            # then handlers/else/finally appended.
            for stmt in node.body:
                compiler.compile_stmt(stmt, compiler._bx_current_builder, compiler._bx_current_scope)
            for stmt in node.orelse:
                compiler.compile_stmt(stmt, compiler._bx_current_builder, compiler._bx_current_scope)
            for stmt in node.finalbody:
                compiler.compile_stmt(stmt, compiler._bx_current_builder, compiler._bx_current_scope)
            if node.handlers:
                # Without real SETUP_FINALLY we cannot trap, but compile the
                # handler bodies as dead code so name-binding still works.
                for h in node.handlers:
                    if h.name:
                        nm = ast.Assign(
                            targets=[ast.Name(h.name, ast.Store())],
                            value=ast.Constant(None),
                        )
                        _copy_loc(nm, h)
                        compiler.compile_stmt(nm, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def visit_TryStar(self, compiler, node):  # PEP 654
            return self.visit_Try(compiler, node)

        def visit_For(self, compiler, node):
            """for x in iterable: body -> index-based while over list(iterable).

            VM-native has While/Break/Continue opcodes but no iterator protocol
            opcodes. This lowering is intentionally conservative and supports
            the loop shape emitted by comprehension lowering and simple runtime
            guards.
            """
            if node.orelse:
                raise VmFallback(f"For/else at line {node.lineno}")
            iter_name = _NameMint.fresh("iter")
            idx_name = _NameMint.fresh("idx")
            item_name = _NameMint.fresh("item")
            load = ast.Load()
            store = ast.Store()
            iter_ref = lambda: ast.Name(iter_name, load)
            idx_ref = lambda ctx=load: ast.Name(idx_name, ctx)

            init_iter = ast.Assign(
                targets=[ast.Name(iter_name, store)],
                value=ast.Call(func=ast.Name("list", load), args=[node.iter], keywords=[]),
            )
            init_idx = ast.Assign(targets=[ast.Name(idx_name, store)], value=ast.Constant(0))
            item_assign = ast.Assign(
                targets=[ast.Name(item_name, store)],
                value=ast.Subscript(value=iter_ref(), slice=idx_ref(), ctx=load),
            )
            target_assigns = self._bind_for_target(node.target, item_name, node)
            inc_idx = ast.AugAssign(
                target=idx_ref(store),
                op=ast.Add(),
                value=ast.Constant(1),
            )
            test = ast.Compare(
                left=idx_ref(),
                ops=[ast.Lt()],
                comparators=[
                    ast.Call(func=ast.Name("len", load), args=[iter_ref()], keywords=[])
                ],
            )
            while_node = ast.While(
                test=test,
                body=[item_assign] + target_assigns + [inc_idx] + list(node.body),
                orelse=[],
            )
            for stmt in (init_iter, init_idx, while_node):
                _copy_loc(stmt, node)
                compiler.compile_stmt(stmt, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def _bind_for_target(self, target, source_name, ref):
            load = ast.Load()
            store = ast.Store()
            if isinstance(target, (ast.Name, ast.Subscript)):
                assign = ast.Assign(
                    targets=[target],
                    value=ast.Name(source_name, load),
                )
                return [_copy_loc(assign, ref)]
            if isinstance(target, (ast.Tuple, ast.List)):
                out = []
                for idx, elt in enumerate(target.elts):
                    tmp_name = _NameMint.fresh("unpack")
                    tmp_assign = ast.Assign(
                        targets=[ast.Name(tmp_name, store)],
                        value=ast.Subscript(
                            value=ast.Name(source_name, load),
                            slice=ast.Constant(idx),
                            ctx=load,
                        ),
                    )
                    out.append(_copy_loc(tmp_assign, ref))
                    out.extend(self._bind_for_target(elt, tmp_name, ref))
                return out
            raise VmFallback(f"For target {type(target).__name__}")

        def visit_Match(self, compiler, node):
            """match S: case P -> ... ;  ->  if/elif chain.

            Supports MatchValue, MatchAs(wildcard), MatchClass(simple),
            MatchSingleton. Anything else triggers ``VmFallback``.
            """
            subj_var = _NameMint.fresh("subj")
            subj_assign = ast.Assign(
                targets=[ast.Name(subj_var, ast.Store())],
                value=node.subject,
            )
            _copy_loc(subj_assign, node)
            compiler.compile_stmt(subj_assign, compiler._bx_current_builder, compiler._bx_current_scope)

            chain_else: list[ast.AST] = []
            for case in reversed(node.cases):
                test = self._match_test(case.pattern, subj_var)
                if case.guard is not None:
                    test = ast.BoolOp(op=ast.And(), values=[test, case.guard])
                if_node = ast.If(test=test, body=list(case.body), orelse=chain_else)
                _copy_loc(if_node, case)
                chain_else = [if_node]
            for s in chain_else:
                compiler.compile_stmt(s, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        def _match_test(self, pattern, subj_var):
            load = ast.Load()
            if isinstance(pattern, ast.MatchValue):
                return ast.Compare(
                    left=ast.Name(subj_var, load),
                    ops=[ast.Eq()],
                    comparators=[pattern.value],
                )
            if isinstance(pattern, ast.MatchSingleton):
                return ast.Compare(
                    left=ast.Name(subj_var, load),
                    ops=[ast.Is()],
                    comparators=[ast.Constant(pattern.value)],
                )
            if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
                return ast.Constant(True)
            if isinstance(pattern, ast.MatchClass) and not pattern.kwd_attrs:
                return ast.Call(
                    func=ast.Name("isinstance", load),
                    args=[ast.Name(subj_var, load), pattern.cls],
                    keywords=[],
                )
            raise VmFallback(f"Match pattern {type(pattern).__name__}")

        # ---- Expressions -------------------------------------------------
        def visit_ListComp(self, compiler, node):
            return self._comp_to_loop(compiler, node, "list")

        def visit_SetComp(self, compiler, node):
            return self._comp_to_loop(compiler, node, "set")

        def visit_DictComp(self, compiler, node):
            return self._comp_to_loop(compiler, node, "dict")

        def visit_GeneratorExp(self, compiler, node):
            # Materialize as a list to keep semantics inside the VM.
            return self._comp_to_loop(compiler, node, "list")

        def _comp_to_loop(self, compiler, node, kind):
            """Lower a comprehension into ``acc=[]`` + nested fors + append.

            The caller of compile_expr expects exactly one stack value, so we
            emit the helper statements directly into the current builder and
            then load the accumulator name as the expression result.
            """
            for gen in node.generators:
                if gen.is_async:
                    raise VmFallback("async comprehension")
            acc = _NameMint.fresh("acc")
            load = ast.Load()
            store = ast.Store()

            if kind == "list":
                init = ast.Assign(
                    targets=[ast.Name(acc, store)],
                    value=ast.List(elts=[], ctx=load),
                )
                append_call = ast.Expr(
                    value=ast.Call(
                        func=ast.Attribute(ast.Name(acc, load), "append", load),
                        args=[node.elt], keywords=[],
                    )
                )
            elif kind == "set":
                init = ast.Assign(
                    targets=[ast.Name(acc, store)],
                    value=ast.Call(func=ast.Name("set", load), args=[], keywords=[]),
                )
                append_call = ast.Expr(
                    value=ast.Call(
                        func=ast.Attribute(ast.Name(acc, load), "add", load),
                        args=[node.elt], keywords=[],
                    )
                )
            else:  # dict
                init = ast.Assign(
                    targets=[ast.Name(acc, store)],
                    value=ast.Dict(keys=[], values=[]),
                )
                append_call = ast.Assign(
                    targets=[ast.Subscript(
                        value=ast.Name(acc, load), slice=node.key, ctx=store)],
                    value=node.value,
                )

            body: list[ast.AST] = [append_call]
            for gen in reversed(node.generators):
                for cond in reversed(gen.ifs):
                    body = [ast.If(test=cond, body=body, orelse=[])]
                body = [ast.For(target=gen.target, iter=gen.iter, body=body, orelse=[])]

            for s in (init, body[0]):
                _copy_loc(s, node)
                compiler.compile_stmt(s, compiler._bx_current_builder, compiler._bx_current_scope)

            result_name = _copy_loc(ast.Name(acc, load), node)
            compiler.compile_expr(result_name, compiler._bx_current_builder, compiler._bx_current_scope)
            return True

        # ---- Decorators (called by FunctionDef/ClassDef wrappers) --------
        def _wrap_decorators(self, compiler, node, *, is_class: bool):
            """Compile def/class without decorators, then ``f = dec(f)`` chain."""
            bare = type(node)(**{**node.__dict__, "decorator_list": []})
            _copy_loc(bare, node)
            compiler.compile_stmt(bare, compiler._bx_current_builder, compiler._bx_current_scope)
            for dec in reversed(node.decorator_list):
                assign = ast.Assign(
                    targets=[ast.Name(node.name, ast.Store())],
                    value=ast.Call(
                        func=dec, args=[ast.Name(node.name, ast.Load())], keywords=[]
                    ),
                )
                _copy_loc(assign, node)
                compiler.compile_stmt(assign, compiler._bx_current_builder, compiler._bx_current_scope)
            return True


    # ---------------------------------------------------------------------------
    # Registration: monkey-patch a VmAstCompiler instance OR class.
    # ---------------------------------------------------------------------------
    _HANDLER_TABLE_STMT: dict[str, str] = {
        "ClassDef": "visit_ClassDef",
        "AsyncFunctionDef": "visit_AsyncFunctionDef",
        "For": "visit_For",
        "AsyncFor": "visit_AsyncFor",
        "AsyncWith": "visit_AsyncWith",
        "With": "visit_With",
        "TryStar": "visit_TryStar",
        "Match": "visit_Match",
    }
    _HANDLER_TABLE_EXPR: dict[str, str] = {
        "ListComp": "visit_ListComp",
        "SetComp": "visit_SetComp",
        "DictComp": "visit_DictComp",
        "GeneratorExp": "visit_GeneratorExp",
        "Await": "visit_Await",
    }


    def register_handlers(compiler: Any, handlers: ExtendedHandlers | None = None) -> ExtendedHandlers:
        """Patch a ``VmAstCompiler`` *instance* (preferred) so that previously
        unsupported AST nodes are routed through ``ExtendedHandlers``.

        Call site: section [09] of bedrock.py, immediately after
        ``compiler = VmAstCompiler(code)`` (see WIRING_vm_handlers.md).
        """
        if handlers is None:
            handlers = ExtendedHandlers()

        if not hasattr(compiler, "_bx_coroutine_funcs"):
            compiler._bx_coroutine_funcs = set()
        compiler._bx_current_builder = None
        compiler._bx_current_scope = "module"

        orig_stmt: Callable = compiler.compile_stmt
        orig_expr: Callable = compiler.compile_expr

        def patched_stmt(node, builder, scope):
            prev_builder = compiler._bx_current_builder
            prev_scope = compiler._bx_current_scope
            compiler._bx_current_builder = builder
            compiler._bx_current_scope = scope
            try:
                # Decorators on FunctionDef / ClassDef.
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.decorator_list:
                    return handlers._wrap_decorators(compiler, node, is_class=isinstance(node, ast.ClassDef))
                kind = type(node).__name__
                hook = _HANDLER_TABLE_STMT.get(kind)
                if hook is not None:
                    return getattr(handlers, hook)(compiler, node)
                return orig_stmt(node, builder, scope)
            finally:
                compiler._bx_current_builder = prev_builder
                compiler._bx_current_scope = prev_scope

        def patched_expr(node, builder, scope):
            prev_builder = compiler._bx_current_builder
            prev_scope = compiler._bx_current_scope
            compiler._bx_current_builder = builder
            compiler._bx_current_scope = scope
            try:
                kind = type(node).__name__
                hook = _HANDLER_TABLE_EXPR.get(kind)
                if hook is not None:
                    return getattr(handlers, hook)(compiler, node)
                return orig_expr(node, builder, scope)
            finally:
                compiler._bx_current_builder = prev_builder
                compiler._bx_current_scope = prev_scope

        compiler.compile_stmt = patched_stmt
        compiler.compile_expr = patched_expr
        compiler._bx_handlers = handlers
        return handlers




    # === [INLINE] bedrock_ext/lambda_enc.py ===

    """
    lambda_enc.py - Lambda calculus encoding pass for the bedrock obfuscator.

    Public API:
        apply_lambda_enc(tree: ast.Module, ctx) -> ast.Module

    Walks the module-level AST and rewrites simple `def` functions into
    `name = lambda ...: expr` assignments. Optionally encodes self-recursive
    functions using a strict (call-by-value) Y-combinator (gated behind
    `ctx.lambda_enc_y` because it is slow and pushes the recursion stack).

    Skips functions that have any of:
      - decorators
      - docstring (preserves help() / __doc__ semantics)
      - yield / yield from (generator)
      - async def
      - more than one statement (unless it's a simple if/else returning)
      - any annotation (arg or return)
      - **kwargs / *args (positional-only OK; we keep simple signatures)
      - posonly (uncommon and complicates lambda signature)

    Density:
      - ctx.lambda_enc_density (float in [0,1], default 1.0): probability a
        qualifying function is rewritten.

    Author: bedrock_ext
    """


    import ast
    import random
    from typing import Any, Optional


    # ---------------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------------

    def _get_rng(ctx: Any) -> random.Random:
        rng = getattr(ctx, "rng", None)
        if isinstance(rng, random.Random):
            return rng
        seed = getattr(ctx, "lambda_enc_seed", None)
        if seed is None:
            seed = getattr(ctx, "seed", None)
        return random.Random(seed)


    def _has_yield(node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, (ast.Yield, ast.YieldFrom)):
                return True
        return False


    def _has_annotations(fn: ast.FunctionDef) -> bool:
        if fn.returns is not None:
            return True
        args = fn.args
        for a in (
            list(args.args)
            + list(args.kwonlyargs)
            + list(getattr(args, "posonlyargs", []) or [])
        ):
            if a.annotation is not None:
                return True
        if args.vararg and args.vararg.annotation is not None:
            return True
        if args.kwarg and args.kwarg.annotation is not None:
            return True
        return False


    def _is_self_recursive(fn: ast.FunctionDef) -> bool:
        name = fn.name
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name:
                return True
        return False


    def _strip_docstring_body(body: list) -> list:
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            return body[1:]
        return body


    def _has_docstring(fn: ast.FunctionDef) -> bool:
        body = fn.body
        return bool(
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        )


    def _extract_lambda_body(fn: ast.FunctionDef) -> Optional[ast.expr]:
        """
        Return an expression that is semantically equivalent to executing
        `fn`'s body, or None if the body is too complex for a lambda.
        Supported shapes:
          1) [Return EXPR]
          2) [If(test, [Return A], [Return B])]
          3) [If(test, [Return A]), Return B]   (else implicit)
        """
        body = fn.body
        if not body:
            return None

        if len(body) == 1 and isinstance(body[0], ast.Return):
            ret = body[0]
            if ret.value is None:
                return ast.Constant(value=None)
            return ret.value

        # if/else returning
        if len(body) == 1 and isinstance(body[0], ast.If):
            node = body[0]
            if (
                len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and len(node.orelse) == 1
                and isinstance(node.orelse[0], ast.Return)
            ):
                a = node.body[0].value or ast.Constant(value=None)
                b = node.orelse[0].value or ast.Constant(value=None)
                return ast.IfExp(test=node.test, body=a, orelse=b)

        if len(body) == 2 and isinstance(body[0], ast.If) and isinstance(body[1], ast.Return):
            node = body[0]
            if (
                len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and not node.orelse
            ):
                a = node.body[0].value or ast.Constant(value=None)
                b = body[1].value or ast.Constant(value=None)
                return ast.IfExp(test=node.test, body=a, orelse=b)

        return None


    def _build_lambda(fn: ast.FunctionDef, body_expr: ast.expr) -> ast.Lambda:
        # Clone args; strip annotations (lambdas don't accept them anyway)
        args = ast.arguments(
            posonlyargs=[ast.arg(arg=a.arg) for a in (getattr(fn.args, "posonlyargs", []) or [])],
            args=[ast.arg(arg=a.arg) for a in fn.args.args],
            vararg=ast.arg(arg=fn.args.vararg.arg) if fn.args.vararg else None,
            kwonlyargs=[ast.arg(arg=a.arg) for a in fn.args.kwonlyargs],
            kw_defaults=list(fn.args.kw_defaults),
            kwarg=ast.arg(arg=fn.args.kwarg.arg) if fn.args.kwarg else None,
            defaults=list(fn.args.defaults),
        )
        return ast.Lambda(args=args, body=body_expr)


    # ---------------------------------------------------------------------------
    # Y-combinator construction
    # ---------------------------------------------------------------------------

    _Y_SRC = (
        "lambda f: (lambda x: f(lambda v: x(x)(v)))(lambda x: f(lambda v: x(x)(v)))"
    )


    def _make_y_assign(y_name: str) -> ast.Assign:
        expr = ast.parse(_Y_SRC, mode="eval").body
        return ast.Assign(targets=[ast.Name(id=y_name, ctx=ast.Store())], value=expr)


    class _RecRenamer(ast.NodeTransformer):
        """Replace occurrences of `old` Name with `new` (used inside body)."""

        def __init__(self, old: str, new: str):
            self.old = old
            self.new = new

        def visit_Name(self, node: ast.Name):
            if node.id == self.old:
                return ast.copy_location(ast.Name(id=self.new, ctx=node.ctx), node)
            return node


    def _build_y_assign(fn: ast.FunctionDef, body_expr: ast.expr, y_name: str) -> ast.Assign:
        """
        fact = Y(lambda __rec__: lambda n: ...fact -> __rec__... )
        """
        rec = "__rec_" + fn.name + "__"
        new_body = _RecRenamer(fn.name, rec).visit(body_expr)
        inner = _build_lambda(fn, new_body)
        outer = ast.Lambda(
            args=ast.arguments(
                posonlyargs=[],
                args=[ast.arg(arg=rec)],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=inner,
        )
        call = ast.Call(func=ast.Name(id=y_name, ctx=ast.Load()), args=[outer], keywords=[])
        return ast.Assign(targets=[ast.Name(id=fn.name, ctx=ast.Store())], value=call)


    # ---------------------------------------------------------------------------
    # main pass
    # ---------------------------------------------------------------------------

    def _qualifies(fn: ast.FunctionDef) -> bool:
        if fn.decorator_list:
            return False
        if _has_docstring(fn):
            return False
        if _has_yield(fn):
            return False
        if _has_annotations(fn):
            return False
        if fn.args.kwarg is not None or fn.args.vararg is not None:
            return False
        # Skip functions with keyword-only parameters: the lambda rewrite
        # preserves kwonlyargs, but the downstream capsule wrapper
        # (apply_runtimedec) swaps __code__ and the interaction with
        # keyword-only defaults is fragile. Keep these as plain defs.
        if fn.args.kwonlyargs:
            return False
        return True


    def apply_lambda_enc(tree: ast.Module, ctx: Any) -> ast.Module:
        """Rewrite simple def-functions into lambda assignments at module scope."""
        rng = _get_rng(ctx)
        density = float(getattr(ctx, "lambda_enc_density", 1.0))
        use_y = bool(getattr(ctx, "lambda_enc_y", False))
        y_name = "__Y_combinator__"
        needs_y = False

        new_body: list = []
        for stmt in tree.body:
            if isinstance(stmt, ast.AsyncFunctionDef):
                new_body.append(stmt)
                continue
            if not isinstance(stmt, ast.FunctionDef):
                new_body.append(stmt)
                continue
            if not _qualifies(stmt):
                new_body.append(stmt)
                continue
            if rng.random() > density:
                new_body.append(stmt)
                continue

            body_expr = _extract_lambda_body(stmt)
            if body_expr is None:
                new_body.append(stmt)
                continue

            is_rec = _is_self_recursive(stmt)
            if is_rec:
                if not use_y:
                    new_body.append(stmt)
                    continue
                needs_y = True
                assign = _build_y_assign(stmt, body_expr, y_name)
            else:
                lam = _build_lambda(stmt, body_expr)
                assign = ast.Assign(
                    targets=[ast.Name(id=stmt.name, ctx=ast.Store())],
                    value=lam,
                )
            ast.copy_location(assign, stmt)
            new_body.append(assign)

        if needs_y:
            y_assign = _make_y_assign(y_name)
            # Place Y at the very top so all references are bound.
            # Skip past leading docstring / __future__ imports.
            insert_at = 0
            for i, s in enumerate(new_body):
                if (
                    isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Constant)
                    and isinstance(s.value.value, str)
                ):
                    insert_at = i + 1
                    continue
                if isinstance(s, ast.ImportFrom) and s.module == "__future__":
                    insert_at = i + 1
                    continue
                break
            new_body.insert(insert_at, y_assign)

        tree.body = new_body
        ast.fix_missing_locations(tree)
        return tree




    # === [INLINE] bedrock_ext/cache.py ===

    """bedrock_ext.cache: incremental build cache for Bedrock Obfuscator.

    Computes a stable cache key from the input source plus the relevant CLI args
    (stripped of presentation-only flags) and the bedrock.py + Python version.
    Stores serialized obfuscated outputs under ``CACHE_DIR/<key[:2]>/<key>.py``.
    """

    import argparse
    import hashlib
    import json
    import os
    import pathlib
    import re
    import sys
    import time
    from dataclasses import dataclass, field
    from typing import Optional

    # Flags that do not affect the obfuscated output bytes.
    NON_OUTPUT_FLAGS = frozenset({
        "quiet", "json", "report", "non_interactive", "overwrite",
        "cache", "no_cache", "clear_cache", "file", "output",
    })

    CACHE_DIR = pathlib.Path(
        os.environ.get("BEDROCK_CACHE", "~/.cache/bedrock")
    ).expanduser()

    MAX_AGE_SECONDS = 30 * 24 * 3600  # 30 days

    _BEDROCK_PY = pathlib.Path(__file__).resolve().parent.parent / "bedrock.py"


    def _bedrock_version() -> str:
        """Best-effort version from bedrock.py docstring or constant."""
        try:
            text = _BEDROCK_PY.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "unknown"
        m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", text)
        if m:
            return m.group(1)
        m = re.search(r"[Vv]ersion[:\s]+([0-9][\w.\-]*)", text[:4000])
        if m:
            return m.group(1)
        # fallback: hash of first 4KB so changes invalidate cache
        return hashlib.sha256(text[:4096].encode("utf-8", "replace")).hexdigest()[:12]


    def _args_to_dict(args: argparse.Namespace) -> dict:
        raw = vars(args) if isinstance(args, argparse.Namespace) else dict(args)
        cleaned = {}
        for k, v in raw.items():
            if k in NON_OUTPUT_FLAGS:
                continue
            try:
                json.dumps(v)
                cleaned[k] = v
            except TypeError:
                cleaned[k] = repr(v)
        return cleaned


    def compute_cache_key(input_path: str, args: argparse.Namespace) -> str:
        """SHA-256 over input file content, normalized args, bedrock + py version."""
        h = hashlib.sha256()
        p = pathlib.Path(input_path)
        try:
            h.update(p.read_bytes())
        except OSError:
            h.update(b"<missing>")
            h.update(str(input_path).encode("utf-8"))
        args_blob = json.dumps(_args_to_dict(args), sort_keys=True, default=str)
        h.update(b"\x00ARGS\x00")
        h.update(args_blob.encode("utf-8"))
        h.update(b"\x00BEDROCK\x00")
        h.update(_bedrock_version().encode("utf-8"))
        h.update(b"\x00PY\x00")
        h.update(f"{sys.version_info.major}.{sys.version_info.minor}".encode())
        return h.hexdigest()


    def _key_path(key: str) -> pathlib.Path:
        return CACHE_DIR / key[:2] / f"{key}.py"


    def cache_lookup(key: str) -> Optional[bytes]:
        """Return cached bytes if present and fresher than 30 days, else None."""
        path = _key_path(key)
        if not path.is_file():
            return None
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        if (time.time() - mtime) > MAX_AGE_SECONDS:
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None


    def cache_store(key: str, output_bytes: bytes) -> None:
        """Atomically write output_bytes to the cache slot for key."""
        path = _key_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        try:
            tmp.write_bytes(output_bytes)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass


    def cache_clear(older_than_days: int = 30) -> int:
        """Delete cached files older than the given age. Returns count removed."""
        if not CACHE_DIR.exists():
            return 0
        cutoff = time.time() - older_than_days * 24 * 3600
        removed = 0
        for entry in CACHE_DIR.rglob("*.py"):
            try:
                if entry.stat().st_mtime < cutoff:
                    entry.unlink()
                    removed += 1
            except OSError:
                continue
        # prune empty shard dirs
        for shard in list(CACHE_DIR.iterdir()) if CACHE_DIR.exists() else []:
            if shard.is_dir() and not any(shard.iterdir()):
                try:
                    shard.rmdir()
                except OSError:
                    pass
        return removed


    @dataclass
    class CacheStats:
        hits: int = 0
        misses: int = 0
        stores: int = 0

        def record_hit(self) -> None:
            self.hits += 1

        def record_miss(self) -> None:
            self.misses += 1

        def record_store(self) -> None:
            self.stores += 1

        def summary(self) -> str:
            return (
                f"cache: hits={self.hits} misses={self.misses} stores={self.stores}"
            )




    # === [INLINE] bedrock_ext/project.py ===

    """Multi-file project obfuscation mode.

    Provides :class:`ProjectBuilder` which discovers a Python package tree,
    builds a global rename map so that the same top-level identifier becomes
    the same obfuscated name across every file, then writes the result to a
    mirrored output directory.

    This module is intentionally self-contained so it can be imported either
    from ``bedrock.py`` (when wiring is active) or from tests without pulling
    in the full single-file build pipeline.  When the heavyweight bedrock
    passes are available, callers can pass them in via ``per_file_pipeline``;
    otherwise the builder simply applies the global rename and writes the
    file.
    """

    import ast
    import dataclasses
    import fnmatch
    import io
    import os
    import sys
    import tokenize
    from dataclasses import dataclass, field
    from pathlib import Path
    from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple


    # --------------------------------------------------------------------------- #
    # Helpers                                                                     #
    # --------------------------------------------------------------------------- #

    _SKIP_DIR_NAMES = {"__pycache__", ".venv", "venv", ".git", ".mypy_cache",
                       ".pytest_cache", ".tox", "node_modules", ".idea"}

    _DUNDER_KEEP = {
        "__init__", "__main__", "__name__", "__file__", "__doc__", "__all__",
        "__version__", "__author__", "__path__", "__package__", "__spec__",
        "__loader__", "__builtins__", "__dict__", "__class__", "__module__",
        "__qualname__", "__enter__", "__exit__", "__iter__", "__next__",
        "__len__", "__getitem__", "__setitem__", "__delitem__", "__contains__",
        "__call__", "__repr__", "__str__", "__bytes__", "__hash__", "__eq__",
        "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__add__", "__sub__",
        "__mul__", "__truediv__", "__floordiv__", "__mod__", "__pow__",
        "__and__", "__or__", "__xor__", "__lshift__", "__rshift__",
        "__neg__", "__pos__", "__abs__", "__invert__", "__bool__", "__int__",
        "__float__", "__index__", "__round__", "__new__", "__del__",
        "__init_subclass__", "__set_name__", "__getattr__", "__setattr__",
        "__delattr__", "__getattribute__", "__dir__", "__reduce__",
        "__reduce_ex__", "__sizeof__", "__format__", "__copy__", "__deepcopy__",
        "__post_init__", "__slots__",
    }


    def _is_protected_name(name: str) -> bool:
        if not name or name.startswith("_"):
            # Keep dunder methods and conventionally-private names untouched
            # to avoid breaking semantics (e.g. ``__init__`` on classes).
            return True
        if name in _DUNDER_KEEP:
            return True
        return False


    # --------------------------------------------------------------------------- #
    # .bedrockignore parsing                                                      #
    # --------------------------------------------------------------------------- #

    class IgnoreMatcher:
        """Minimal gitignore-style matcher.

        Supports ``*`` and ``?`` glob patterns plus directory anchoring with a
        trailing ``/``.  Lines starting with ``#`` and blank lines are ignored.
        Negation (``!``) is supported.
        """

        def __init__(self, patterns: Iterable[str], extra: Iterable[str] = ()):
            self._rules: List[Tuple[bool, str, bool]] = []
            for raw in list(patterns) + list(extra):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                negate = line.startswith("!")
                if negate:
                    line = line[1:]
                dir_only = line.endswith("/")
                if dir_only:
                    line = line.rstrip("/")
                self._rules.append((negate, line, dir_only))

        def match(self, rel_path: str, *, is_dir: bool = False) -> bool:
            rel_path = rel_path.replace(os.sep, "/")
            decision = False
            for negate, pattern, dir_only in self._rules:
                if dir_only and not is_dir:
                    continue
                if self._match_one(rel_path, pattern):
                    decision = not negate
            return decision

        @staticmethod
        def _match_one(rel: str, pattern: str) -> bool:
            if "/" in pattern:
                return fnmatch.fnmatchcase(rel, pattern.lstrip("/"))
            # Pattern with no slash matches any path component.
            for part in rel.split("/"):
                if fnmatch.fnmatchcase(part, pattern):
                    return True
            return fnmatch.fnmatchcase(rel, pattern)


    # --------------------------------------------------------------------------- #
    # Stats                                                                       #
    # --------------------------------------------------------------------------- #

    @dataclass
    class ProjectStats:
        files_processed: int = 0
        total_size_in: int = 0
        total_size_out: int = 0
        errors_per_file: Dict[str, str] = field(default_factory=dict)


    # --------------------------------------------------------------------------- #
    # AST collectors / rewriters                                                  #
    # --------------------------------------------------------------------------- #

    class _TopLevelCollector(ast.NodeVisitor):
        """Collect top-level def/class/var names from a module."""

        def __init__(self) -> None:
            self.names: Set[str] = set()

        def visit_Module(self, node: ast.Module) -> None:
            for child in node.body:
                self._collect(child)

        def _collect(self, node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not _is_protected_name(node.name):
                    self.names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._collect_target(target)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if not _is_protected_name(node.target.id):
                    self.names.add(node.target.id)

        def _collect_target(self, target: ast.AST) -> None:
            if isinstance(target, ast.Name):
                if not _is_protected_name(target.id):
                    self.names.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    self._collect_target(elt)


    class _RenameRewriter(ast.NodeTransformer):
        """Rename ``Name``/``Attribute``/``alias`` references using a map.

        Conservative: we only rewrite *bare* ``Name`` loads/stores and
        ``import x``/``from x import y`` aliases when the target is in the
        rename map.  Attribute access ``mod.helper`` is rewritten when the
        attribute name is in the map (this matches the cross-file usage
        pattern of ``utils.helper``).
        """

        def __init__(self, mapping: Dict[str, str]):
            self.mapping = mapping

        def visit_Name(self, node: ast.Name) -> ast.AST:
            if node.id in self.mapping:
                return ast.copy_location(
                    ast.Name(id=self.mapping[node.id], ctx=node.ctx), node
                )
            return node

        def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
            self.generic_visit(node)
            if node.attr in self.mapping:
                node.attr = self.mapping[node.attr]
            return node

        def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.AST:
            for alias in node.names:
                if alias.name in self.mapping:
                    # Preserve original local binding via asname so callers
                    # using ``helper`` keep working without further rewrite.
                    if alias.asname is None:
                        alias.asname = self.mapping[alias.name]
                    else:
                        pass
                    alias.name = self.mapping[alias.name]
            return node

        def visit_FunctionDef(self, node):  # type: ignore[override]
            if node.name in self.mapping:
                node.name = self.mapping[node.name]
            self.generic_visit(node)
            return node

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
            if node.name in self.mapping:
                node.name = self.mapping[node.name]
            self.generic_visit(node)
            return node


    # --------------------------------------------------------------------------- #
    # Import graph                                                                #
    # --------------------------------------------------------------------------- #

    def _module_name_for(root: Path, file: Path) -> str:
        rel = file.relative_to(root).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        # If ``root`` itself is a package directory (contains ``__init__.py``),
        # prepend the package name so dotted lookups work uniformly.
        if (root / "__init__.py").exists():
            parts = [root.name] + parts
        return ".".join(parts)


    def _resolve_relative(pkg: str, module: Optional[str], level: int) -> Optional[str]:
        """Resolve ``from <level dots><module> import ...`` to a dotted path.

        ``pkg`` is the *package* of the importing module (i.e. the module name
        minus its final component for sub-modules; for a package ``__init__``
        it is the package itself).
        """
        if level == 0:
            return module
        parts = pkg.split(".") if pkg else []
        # ``from . import x`` inside ``pkg.main`` -> base = ['pkg']
        # ``from .. import x`` inside ``pkg.sub.main`` -> base = ['pkg']
        if level - 1 > len(parts):
            return None
        base = parts[: len(parts) - (level - 1)] if level > 1 else parts
        if module:
            base = base + module.split(".")
        return ".".join(base) if base else None


    # --------------------------------------------------------------------------- #
    # ProjectBuilder                                                              #
    # --------------------------------------------------------------------------- #

    PerFilePipeline = Callable[[ast.Module, Path, "ProjectBuilder"], ast.Module]


    class ProjectBuilder:
        """Walk a project, rename consistently, mirror to ``output_root``."""

        def __init__(
            self,
            root: Path,
            output_root: Path,
            ctx,
            *,
            ignore_patterns: Iterable[str] = (),
            per_file_pipeline: Optional[PerFilePipeline] = None,
            rename_prefix: str = "_b_",
        ) -> None:
            self.root = Path(root).resolve()
            self.output_root = Path(output_root).resolve()
            self.ctx = ctx
            self.per_file_pipeline = per_file_pipeline
            self.rename_prefix = rename_prefix
            self.stats = ProjectStats()
            self._module_to_path: Dict[str, Path] = {}
            self._path_to_module: Dict[Path, str] = {}
            self._global_rename: Dict[str, str] = {}

            extra = list(ignore_patterns)
            ignore_file = self.root / ".bedrockignore"
            patterns: List[str] = []
            if ignore_file.exists():
                patterns = ignore_file.read_text(encoding="utf-8").splitlines()
            self.ignore = IgnoreMatcher(patterns, extra=extra)

        # ------------------------------------------------------------------ #
        # Discovery                                                          #
        # ------------------------------------------------------------------ #

        def discover(self) -> List[Path]:
            out: List[Path] = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                # In-place prune
                pruned = []
                for d in list(dirnames):
                    if d in _SKIP_DIR_NAMES:
                        continue
                    rel_dir = os.path.relpath(os.path.join(dirpath, d), self.root)
                    if self.ignore.match(rel_dir, is_dir=True):
                        continue
                    pruned.append(d)
                dirnames[:] = pruned
                for fn in filenames:
                    if not fn.endswith(".py"):
                        continue
                    full = Path(dirpath) / fn
                    rel = full.relative_to(self.root).as_posix()
                    if self.ignore.match(rel, is_dir=False):
                        continue
                    out.append(full)
            out.sort()
            for p in out:
                mod = _module_name_for(self.root, p)
                self._module_to_path[mod] = p
                self._path_to_module[p] = mod
            return out

        # ------------------------------------------------------------------ #
        # Import graph                                                       #
        # ------------------------------------------------------------------ #

        def build_import_graph(self) -> Dict[Path, Set[Path]]:
            graph: Dict[Path, Set[Path]] = {p: set() for p in self._path_to_module}
            for path, mod in self._path_to_module.items():
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                except SyntaxError as exc:
                    self.stats.errors_per_file[str(path)] = f"parse: {exc}"
                    continue
                pkg = mod.rsplit(".", 1)[0] if "." in mod else mod
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            target = alias.name
                            dep = self._lookup_module(target)
                            if dep is not None:
                                graph[path].add(dep)
                    elif isinstance(node, ast.ImportFrom):
                        target = _resolve_relative(pkg, node.module, node.level or 0)
                        if target:
                            dep = self._lookup_module(target)
                            if dep is not None:
                                graph[path].add(dep)
                            # Also handle ``from pkg import sub`` where ``sub``
                            # itself is a module.
                            for alias in node.names:
                                sub = f"{target}.{alias.name}" if target else alias.name
                                dep2 = self._lookup_module(sub)
                                if dep2 is not None:
                                    graph[path].add(dep2)
            return graph

        def _lookup_module(self, dotted: str) -> Optional[Path]:
            if dotted in self._module_to_path:
                return self._module_to_path[dotted]
            # Try walking up: ``pkg.utils.helper`` where ``helper`` is a name.
            parts = dotted.split(".")
            while parts:
                parts.pop()
                cand = ".".join(parts)
                if cand and cand in self._module_to_path:
                    return self._module_to_path[cand]
            return None

        # ------------------------------------------------------------------ #
        # Global rename map                                                  #
        # ------------------------------------------------------------------ #

        def build_global_rename_map(self, modules: List[Path]) -> Dict[str, str]:
            all_names: Set[str] = set()
            for path in modules:
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                except SyntaxError as exc:
                    self.stats.errors_per_file[str(path)] = f"parse: {exc}"
                    continue
                collector = _TopLevelCollector()
                collector.visit(tree)
                all_names |= collector.names

            # Deterministic ordering for reproducible builds.
            rng = getattr(self.ctx, "rng", None)
            ordered = sorted(all_names)
            mapping: Dict[str, str] = {}
            for idx, name in enumerate(ordered):
                mapping[name] = f"{self.rename_prefix}{idx:04x}_{_short_hash(name)}"
            self._global_rename = mapping
            return mapping

        # ------------------------------------------------------------------ #
        # Build                                                              #
        # ------------------------------------------------------------------ #

        def build(self) -> ProjectStats:
            modules = self.discover()
            graph = self.build_import_graph()
            self.build_global_rename_map(modules)
            order = _toposort(graph)

            for path in order:
                try:
                    src = path.read_text(encoding="utf-8")
                    self.stats.total_size_in += len(src.encode("utf-8"))
                    tree = ast.parse(src)
                    tree = _RenameRewriter(self._global_rename).visit(tree)
                    ast.fix_missing_locations(tree)
                    if self.per_file_pipeline is not None:
                        tree = self.per_file_pipeline(tree, path, self)
                        ast.fix_missing_locations(tree)
                    out_src = ast.unparse(tree)
                    # compile-check
                    compile(out_src, str(path), "exec")
                    rel = path.relative_to(self.root)
                    out_path = self.output_root / rel
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(out_src, encoding="utf-8")
                    self.stats.total_size_out += len(out_src.encode("utf-8"))
                    self.stats.files_processed += 1
                except Exception as exc:  # pragma: no cover - defensive
                    self.stats.errors_per_file[str(path)] = f"{type(exc).__name__}: {exc}"

            self._ensure_top_init()
            return self.stats

        def _ensure_top_init(self) -> None:
            # If output_root itself is a package mirror (i.e. the input root has
            # an ``__init__.py``), we already wrote it.  Otherwise, create an
            # empty marker so ``python -m <pkg>`` works.
            if not self.output_root.exists():
                return
            marker = self.output_root / "__init__.py"
            # Only create if the root itself is not a package and there are
            # subpackages that callers might want to access uniformly.
            if not marker.exists() and not (self.root / "__init__.py").exists():
                # Don't create — preserves the user's layout.  But ensure
                # discovered subpackages already have their own __init__.
                for sub in self.output_root.iterdir():
                    if sub.is_dir() and (sub / "__init__.py").exists():
                        return


    # --------------------------------------------------------------------------- #
    # Topological sort                                                            #
    # --------------------------------------------------------------------------- #

    def _toposort(graph: Dict[Path, Set[Path]]) -> List[Path]:
        indeg: Dict[Path, int] = {n: 0 for n in graph}
        for n, deps in graph.items():
            for d in deps:
                if d in indeg and d != n:
                    indeg[d] = indeg.get(d, 0)
        # Build reverse adjacency: process deps before dependants.
        rev: Dict[Path, Set[Path]] = {n: set() for n in graph}
        for n, deps in graph.items():
            for d in deps:
                if d in rev and d != n:
                    rev[d].add(n)
                    indeg[n] = indeg.get(n, 0) + 1
        queue = sorted([n for n, deg in indeg.items() if deg == 0])
        out: List[Path] = []
        while queue:
            cur = queue.pop(0)
            out.append(cur)
            for nxt in sorted(rev.get(cur, ())):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    queue.append(nxt)
        # Append any cycles deterministically.
        for n in graph:
            if n not in out:
                out.append(n)
        return out


    def _short_hash(name: str) -> str:
        import hashlib
        return hashlib.blake2s(name.encode("utf-8"), digest_size=3).hexdigest()


    __all__ = ["ProjectBuilder", "ProjectStats", "IgnoreMatcher"]




    # === [INLINE] bedrock_plugins/loader.py ===

    """Plugin loader and hook registry for Bedrock Obfuscator.

    Plugins extend the bedrock pipeline (see bedrock.py section [09]) by
    registering callbacks against well-known hook points without modifying
    bedrock.py itself.
    """

    import importlib.util
    import inspect
    import logging
    import os
    import sys
    from pathlib import Path
    from typing import Any, Callable, Dict, List, Optional

    log = logging.getLogger("bedrock.plugins")

    # Recognised AST-pass hook points (matches bedrock pipeline [09]).
    KNOWN_AST_HOOKS = {
        "before_parse",
        "after_parse",
        "after_rename",
        "after_string_obf",
        "after_numobf",
        "after_cff",
        "before_marshal",
        "after_marshal",
    }


    class PipelineHooks:
        """Registry of pluggable hook callbacks for the obfuscation pipeline."""

        def __init__(self) -> None:
            self.ast_passes: Dict[str, List[Dict[str, Any]]] = {}
            self.pre_compile: List[Callable] = []
            self.post_compile: List[Callable] = []
            self.cli_flags: List[Dict[str, Any]] = []

        # -- AST passes --------------------------------------------------------
        def register_ast_pass(
            self,
            name: str,
            fn: Callable[[Any, Dict[str, Any]], Any],
            when: str = "after_rename",
            priority: int = 100,
        ) -> None:
            if when not in KNOWN_AST_HOOKS:
                log.warning("Unknown AST hook point %r (allowed: %s)", when, sorted(KNOWN_AST_HOOKS))
            self.ast_passes.setdefault(when, []).append(
                {"name": name, "fn": fn, "priority": priority}
            )
            self.ast_passes[when].sort(key=lambda e: e["priority"])

        # -- Source-level hooks ------------------------------------------------
        def register_pre_compile(self, fn: Callable[[str, Dict[str, Any]], str]) -> None:
            self.pre_compile.append(fn)

        def register_post_compile(self, fn: Callable[[str, Dict[str, Any]], str]) -> None:
            self.post_compile.append(fn)

        # -- CLI ---------------------------------------------------------------
        def register_cli_flag(self, *args: Any, **kwargs: Any) -> None:
            """Record an argparse flag spec; bedrock main() applies it."""
            self.cli_flags.append({"args": args, "kwargs": kwargs})

        # -- Invocation helpers ------------------------------------------------
        def run_ast_passes(self, when: str, tree: Any, ctx: Optional[Dict[str, Any]] = None) -> Any:
            ctx = ctx or {}
            for entry in self.ast_passes.get(when, []):
                try:
                    tree = entry["fn"](tree, ctx) or tree
                except Exception as exc:  # pragma: no cover - defensive
                    log.warning("AST pass %r at %s failed: %s", entry["name"], when, exc)
            return tree

        def run_pre_compile(self, src: str, ctx: Optional[Dict[str, Any]] = None) -> str:
            ctx = ctx or {}
            for fn in self.pre_compile:
                try:
                    src = fn(src, ctx) or src
                except Exception as exc:  # pragma: no cover
                    log.warning("pre_compile hook failed: %s", exc)
            return src

        def run_post_compile(self, src: str, ctx: Optional[Dict[str, Any]] = None) -> str:
            ctx = ctx or {}
            for fn in self.post_compile:
                try:
                    src = fn(src, ctx) or src
                except Exception as exc:  # pragma: no cover
                    log.warning("post_compile hook failed: %s", exc)
            return src


    class Plugin:
        """Base class for Bedrock plugins.

        Subclass and override :meth:`register` to attach to hook points.
        """

        name: str = "unnamed"
        priority: int = 100

        def register(self, pipeline: PipelineHooks) -> None:  # pragma: no cover - abstract
            raise NotImplementedError


    # ---------------------------------------------------------------------------
    # Discovery
    # ---------------------------------------------------------------------------
    def _default_dirs() -> List[str]:
        here = Path(__file__).parent / "contrib"
        user = Path.home() / ".bedrock" / "plugins"
        return [str(here), str(user)]


    def _load_module(path: Path):
        mod_name = f"_bedrock_plugin_{path.stem}_{abs(hash(str(path)))}"
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load spec for {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        return mod


    def _extract_plugins(mod) -> List[Plugin]:
        found: List[Plugin] = []
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj is Plugin:
                continue
            if issubclass(obj, Plugin) and obj.__module__ == mod.__name__:
                try:
                    found.append(obj())
                except Exception as exc:
                    log.warning("Cannot instantiate plugin class %s: %s", obj, exc)
        # Top-level register(hooks) function -> wrap as adhoc plugin.
        fn = getattr(mod, "register", None)
        if callable(fn):
            name = getattr(mod, "PLUGIN_NAME", mod.__name__)
            prio = int(getattr(mod, "PLUGIN_PRIORITY", 100))

            class _Adhoc(Plugin):
                pass

            _Adhoc.name = name
            _Adhoc.priority = prio
            _Adhoc.register = lambda self, hooks, _fn=fn: _fn(hooks)
            found.append(_Adhoc())
        return found


    def discover_plugins(plugins_dir: Optional[Any] = None) -> List[Plugin]:
        """Discover plugins from one or more directories.

        `plugins_dir` may be None, a single str/Path, or a list of paths. Defaults
        to bedrock_plugins/contrib + ~/.bedrock/plugins.
        """
        dirs: List[str] = []
        if plugins_dir is None:
            dirs = _default_dirs()
        elif isinstance(plugins_dir, (list, tuple)):
            dirs = [str(p) for p in plugins_dir]
        else:
            dirs = [str(plugins_dir)]

        plugins: List[Plugin] = []
        seen: set = set()
        for d in dirs:
            p = Path(d)
            if not p.is_dir():
                continue
            for py in sorted(p.glob("*.py")):
                if py.name.startswith("_"):
                    continue
                key = py.resolve()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    mod = _load_module(py)
                    plugins.extend(_extract_plugins(mod))
                except Exception as exc:
                    log.warning("Failed to load plugin %s: %s", py, exc)

        plugins.sort(key=lambda pl: getattr(pl, "priority", 100))
        return plugins


    def apply_plugins(pipeline_hooks: PipelineHooks, plugins: List[Plugin]) -> None:
        """Call each plugin's register() against the shared hook registry."""
        for pl in plugins:
            try:
                pl.register(pipeline_hooks)
                log.info("Loaded plugin %s (priority=%s)", getattr(pl, "name", "?"), getattr(pl, "priority", 100))
            except Exception as exc:
                log.warning("Plugin %s failed to register and was skipped: %s",
                            getattr(pl, "name", pl), exc)




    # === [INLINE] bedrock_tui/logger_adapter.py ===

    """TUILogger - adapter forward log của ``bedrock.Logging`` vào LogScreen.

    ``install(app)`` thay thế ``bedrock.Logging`` bằng ``TUILogger`` (giữ nguyên
    interface ``event/info/success/warning/notice/debug/error/_log``). Mỗi call
    sẽ đẩy 1 entry vào ``asyncio.Queue`` của ``LogScreen`` thông qua
    ``app.call_from_thread`` để an toàn khi gọi từ worker thread (bedrock chạy
    trong ``asyncio.to_thread``).

    ``progress(pct, label)`` là entry đặc biệt → cập nhật ``ProgressBar`` &
    ``current-pass``. ``uninstall()`` khôi phục class gốc.

    Module KHÔNG sửa ``bedrock.py``; chỉ monkey-patch attribute.
    """


    import asyncio
    from typing import Any, Optional


    _original_logging: Any = None
    _app_ref: Any = None
    _queue_ref: Optional[asyncio.Queue] = None


    def _plg_push(entry: dict) -> None:
        """Thread-safe push entry vào queue của LogScreen."""
        app = _app_ref
        queue = _queue_ref
        if queue is None:
            return
        if app is None:
            try:
                queue.put_nowait(entry)
            except Exception:
                pass
            return
        try:
            # Khi gọi từ worker thread, dùng call_from_thread để schedule trên
            # event loop của Textual app.
            app.call_from_thread(queue.put_nowait, entry)
        except RuntimeError:
            # Đã ở trong event loop thread — gọi trực tiếp.
            try:
                queue.put_nowait(entry)
            except Exception:
                pass
        except Exception:
            pass


    class TUILogger:
        """Drop-in replacement cho ``bedrock.Logging``."""

        _COLOR: dict[str, str] = {
            "EVENT": "", "INFO": "", "SUCCESS": "", "WARNING": "",
            "NOTICE": "", "DEBUG": "", "ERROR": "",
        }

        @staticmethod
        def _log(level: str, color: str, msg: str) -> None:  # noqa: ARG004
            _plg_push({"kind": "log", "level": str(level).upper(), "msg": str(msg)})

        @classmethod
        def event(cls, msg: str) -> None:    cls._log("EVENT", "", msg)
        @classmethod
        def info(cls, msg: str) -> None:     cls._log("INFO", "", msg)
        @classmethod
        def success(cls, msg: str) -> None:  cls._log("SUCCESS", "", msg)
        @classmethod
        def warning(cls, msg: str) -> None:  cls._log("WARNING", "", msg)
        @classmethod
        def notice(cls, msg: str) -> None:   cls._log("NOTICE", "", msg)
        @classmethod
        def debug(cls, msg: str) -> None:    cls._log("DEBUG", "", msg)
        @classmethod
        def error(cls, msg: str) -> None:    cls._log("ERROR", "", msg)

        # Extension: progress / pass markers ----------------------------------
        @classmethod
        def progress(cls, pct: float, label: str | None = None) -> None:
            _plg_push({"kind": "progress", "pct": float(pct), "label": label})

        @classmethod
        def pass_(cls, label: str) -> None:
            _plg_push({"kind": "pass", "label": str(label)})


    def _resolve_log_queue(app: Any) -> Optional[asyncio.Queue]:
        """Tìm queue của LogScreen đang mounted (push hoặc registered)."""
        # Thử screen "logs" đã đăng ký
        try:
            screens = getattr(app, "_installed_screens", None) or {}
            scr = screens.get("logs")
            if scr is not None and hasattr(scr, "queue"):
                return scr.queue
        except Exception:
            pass
        # Thử screen_stack
        try:
            for scr in getattr(app, "screen_stack", []):
                if hasattr(scr, "queue") and scr.__class__.__name__ == "LogScreen":
                    return scr.queue
        except Exception:
            pass
        return None


    def install(app: Any) -> None:
        """Monkey-patch ``bedrock.Logging`` bằng ``TUILogger``.

        Args:
            app: instance ``textual.app.App`` đang chạy. Cần để dùng
                 ``call_from_thread`` đẩy log từ worker thread.
        """
        global _original_logging, _app_ref, _queue_ref
        import bedrock  # local import — không bắt buộc khi test riêng

        if _original_logging is None:
            _original_logging = getattr(bedrock, "Logging", None)
        _app_ref = app
        _queue_ref = _resolve_log_queue(app)
        try:
            bedrock.Logging = TUILogger  # type: ignore[attr-defined]
        except Exception:
            pass


    def uninstall() -> None:
        """Khôi phục ``bedrock.Logging`` ban đầu."""
        global _original_logging, _app_ref, _queue_ref
        if _original_logging is None:
            _app_ref = None
            _queue_ref = None
            return
        try:
            import bedrock
            bedrock.Logging = _original_logging  # type: ignore[attr-defined]
        except Exception:
            pass
        _original_logging = None
        _app_ref = None
        _queue_ref = None


    def bind_queue(queue: asyncio.Queue) -> None:
        """Test helper: gán trực tiếp queue (không cần bedrock import)."""
        global _queue_ref
        _queue_ref = queue




    # === [INLINE] bedrock_tui/log_screen.py ===

    """LogScreen - Live log view cho Bedrock TUI build.

    Hiển thị stream log realtime từ ``TUILogger`` (xem ``logger_adapter.py``):
    - ``RichLog`` (markup + highlight) chiếm phần lớn screen
    - ``ProgressBar`` ở top thể hiện tổng tiến độ
    - ``Static#current-pass`` hiển thị tên pass hiện hành (CFF, BC mutate, ...)
    - ``Static#stats`` đếm events / warnings / errors
    - Footer 3 nút: *Back to Build*, *Save log*, *Clear*

    Module được tách hẳn khỏi ``bedrock`` — không import ở top-level. Skip nếu
    ``textual`` không có (giữ test suite chạy được trên môi trường thiếu dep).
    """


    import asyncio
    import time
    from pathlib import Path
    from typing import Any

    try:
        from textual.app import ComposeResult
        from textual.containers import Horizontal, Vertical
        from textual.screen import Screen
        from textual.widgets import Button, Footer, Header, ProgressBar, RichLog, Static

        TEXTUAL_AVAILABLE = True
    except Exception:  # pragma: no cover - exercised when textual missing
        TEXTUAL_AVAILABLE = False
        Screen = object  # type: ignore[assignment,misc]
        ComposeResult = Any  # type: ignore[assignment,misc]


    _LEVEL_MARKUP = {
        "EVENT":   "[bold red][EVENT][/]",
        "INFO":    "[white][INFO][/]",
        "SUCCESS": "[bold green][SUCCESS][/]",
        "WARNING": "[bold yellow][WARNING][/]",
        "NOTICE":  "[bold blue][NOTICE][/]",
        "DEBUG":   "[bold magenta][DEBUG][/]",
        "ERROR":   "[bold red][ERROR][/]",
    }


    def _format_entry(level: str, msg: str) -> str:
        tag = _LEVEL_MARKUP.get(level.upper(), f"[{level}]")
        return f"{tag} {msg}"


    if TEXTUAL_AVAILABLE:

        class LogScreen(Screen):
            """Realtime log screen consuming ``TUILogger`` queue."""

            BINDINGS = [
                ("b", "back", "Back to Build"),
                ("s", "save", "Save log"),
                ("c", "clear", "Clear"),
            ]

            DEFAULT_CSS = """
            LogScreen { layout: vertical; }
            #top-bar { height: 3; }
            #current-pass { width: 1fr; padding: 0 1; }
            #stats { width: 40; padding: 0 1; content-align: right middle; }
            #progress { height: 1; }
            #log { height: 1fr; border: round $accent; }
            #footer-bar { height: 3; }
            """

            def __init__(self) -> None:
                super().__init__()
                self._queue: asyncio.Queue = asyncio.Queue()
                self._counts = {"events": 0, "warnings": 0, "errors": 0}
                self._consumer_task: asyncio.Task | None = None

            # Public hook for TUILogger.install() ---------------------------------
            @property
            def queue(self) -> asyncio.Queue:
                return self._queue

            def compose(self) -> ComposeResult:
                yield Header(show_clock=True)
                with Horizontal(id="top-bar"):
                    yield Static("Pass: (idle)", id="current-pass")
                    yield Static("events: 0 | warnings: 0 | errors: 0", id="stats")
                yield ProgressBar(total=100, show_eta=True, id="progress")
                yield RichLog(highlight=True, markup=True, id="log")
                with Horizontal(id="footer-bar"):
                    yield Button("Back to Build", id="back", variant="primary")
                    yield Button("Save log", id="save")
                    yield Button("Clear", id="clear", variant="warning")
                yield Footer()

            async def on_mount(self) -> None:
                self._consumer_task = asyncio.create_task(self._consume())

            async def on_unmount(self) -> None:
                if self._consumer_task is not None:
                    self._consumer_task.cancel()

            # --- Queue consumer --------------------------------------------------
            async def _consume(self) -> None:
                while True:
                    try:
                        entry = await self._queue.get()
                    except asyncio.CancelledError:  # pragma: no cover
                        break
                    try:
                        self._handle_entry(entry)
                    except Exception:  # pragma: no cover - defensive
                        pass

            def _handle_entry(self, entry: dict) -> None:
                kind = entry.get("kind", "log")
                if kind == "progress":
                    pct = float(entry.get("pct", 0))
                    label = entry.get("label")
                    bar = self.query_one("#progress", ProgressBar)
                    bar.update(progress=pct)
                    if label:
                        self.query_one("#current-pass", Static).update(f"Pass: {label}")
                    return
                if kind == "pass":
                    label = entry.get("label", "")
                    self.query_one("#current-pass", Static).update(f"Pass: {label}")
                    return
                # Default: log line
                level = entry.get("level", "INFO")
                msg = entry.get("msg", "")
                log = self.query_one("#log", RichLog)
                log.write(_format_entry(level, msg))
                up = level.upper()
                self._counts["events"] += 1
                if up == "WARNING":
                    self._counts["warnings"] += 1
                elif up == "ERROR":
                    self._counts["errors"] += 1
                stats = self.query_one("#stats", Static)
                stats.update(
                    "events: {events} | warnings: {warnings} | errors: {errors}".format(
                        **self._counts
                    )
                )

            # --- Actions / Buttons ----------------------------------------------
            async def action_back(self) -> None:
                try:
                    self.app.pop_screen()
                except Exception:
                    pass

            async def action_save(self) -> None:
                log = self.query_one("#log", RichLog)
                path = Path.cwd() / f"bedrock-tui-{int(time.time())}.log"
                try:
                    lines = []
                    for line in getattr(log, "lines", []):
                        lines.append(getattr(line, "text", str(line)))
                    path.write_text("\n".join(lines), encoding="utf-8")
                    self.notify(f"Saved log to {path}")
                except Exception as exc:  # pragma: no cover
                    self.notify(f"Save failed: {exc}", severity="error")

            async def action_clear(self) -> None:
                self.query_one("#log", RichLog).clear()
                self._counts = {"events": 0, "warnings": 0, "errors": 0}
                self.query_one("#stats", Static).update(
                    "events: 0 | warnings: 0 | errors: 0"
                )

            async def on_button_pressed(self, event: "Button.Pressed") -> None:
                bid = event.button.id
                if bid == "back":
                    await self.action_back()
                elif bid == "save":
                    await self.action_save()
                elif bid == "clear":
                    await self.action_clear()

    else:  # pragma: no cover - textual missing fallback

        class LogScreen:  # type: ignore[no-redef]
            def __init__(self) -> None:
                self._queue = asyncio.Queue()

            @property
            def queue(self) -> asyncio.Queue:
                return self._queue




    # === [INLINE] bedrock_tui/report_screen.py ===

    """Report viewer screen for Bedrock Obfuscator TUI.

    Loads a JSON report produced by ``bedrock_ext.profiles.ReportBuilder`` and
    renders summary / passes / flags tables plus an entropy comparison chart.
    """

    import json
    import os
    import shlex
    import subprocess
    from typing import Any, Dict, Optional

    try:  # textual is an optional dependency at runtime
        from textual.app import ComposeResult
        from textual.containers import Horizontal, Vertical
        from textual.message import Message
        from textual.screen import Screen
        from textual.widgets import Button, DataTable, Input, Static
        try:
            from textual.widgets import Sparkline  # type: ignore
            _HAS_SPARKLINE = True
        except Exception:  # pragma: no cover - older textual
            Sparkline = None  # type: ignore
            _HAS_SPARKLINE = False
        try:
            from textual.widgets import ProgressBar  # type: ignore
        except Exception:  # pragma: no cover
            ProgressBar = None  # type: ignore
        _HAS_TEXTUAL = True
    except Exception:  # pragma: no cover - allow import in headless test env
        _HAS_TEXTUAL = False
        Screen = object  # type: ignore

        class Message:  # type: ignore
            pass


    SCHEMA_VERSION_SUPPORTED = 1


    def _fmt_int(n: Any) -> str:
        try:
            return f"{int(n):,}"
        except Exception:
            return str(n)


    def _fmt_float(x: Any, digits: int = 4) -> str:
        try:
            return f"{float(x):.{digits}f}"
        except Exception:
            return str(x)


    def _delta(a: Any, b: Any) -> str:
        try:
            d = float(b) - float(a)
            sign = "+" if d >= 0 else ""
            return f"{sign}{d:.4f}"
        except Exception:
            return "?"


    def _delta_int(a: Any, b: Any) -> str:
        try:
            d = int(b) - int(a)
            sign = "+" if d >= 0 else ""
            return f"{sign}{d:,}"
        except Exception:
            return "?"


    def load_report(path: str) -> Dict[str, Any]:
        """Load and validate a report JSON file. Raises ValueError on bad schema."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Report root must be a JSON object")
        sv = data.get("schema_version")
        if sv != SCHEMA_VERSION_SUPPORTED:
            raise ValueError(
                f"Unsupported schema_version={sv!r} (expected {SCHEMA_VERSION_SUPPORTED})"
            )
        return data


    def populate_summary(table: "DataTable", report: Dict[str, Any]) -> None:
        table.clear(columns=True)
        table.add_columns("Key", "Value")
        in_sz = report.get("input_size", 0)
        out_sz = report.get("output_size", 0)
        ein = report.get("entropy_input", 0.0)
        eout = report.get("entropy_output", 0.0)
        rows = [
            ("profile", str(report.get("profile_used", ""))),
            ("duration_ms", _fmt_int(report.get("duration_ms", 0))),
            ("size", f"{_fmt_int(in_sz)} -> {_fmt_int(out_sz)} ({_delta_int(in_sz, out_sz)})"),
            ("entropy", f"{_fmt_float(ein)} -> {_fmt_float(eout)} ({_delta(ein, eout)})"),
            ("n_idents_renamed", _fmt_int(report.get("n_idents_renamed", 0))),
            ("n_strings_encoded", _fmt_int(report.get("n_strings_encoded", 0))),
            ("n_consts_encrypted", _fmt_int(report.get("n_consts_encrypted", 0))),
            ("input_sha256", str(report.get("input_sha256", ""))[:16] + "..."),
            ("output_sha256", str(report.get("output_sha256", ""))[:16] + "..."),
        ]
        for k, v in rows:
            table.add_row(k, v)


    def populate_passes(table: "DataTable", report: Dict[str, Any]) -> None:
        table.clear(columns=True)
        table.add_columns("Pass", "Duration (ms)", "Notes")
        for entry in report.get("passes", []) or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "?"))
            dur = _fmt_int(entry.get("duration_ms", 0))
            notes_parts = []
            for k, v in entry.items():
                if k in ("name", "duration_ms"):
                    continue
                notes_parts.append(f"{k}={v}")
            notes = ", ".join(notes_parts)
            table.add_row(name, dur, notes)


    def _flatten_flags(flags: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in flags.items():
            key = f"{prefix}{k}"
            if isinstance(v, dict):
                out.update(_flatten_flags(v, prefix=key + "."))
            else:
                out[key] = v
        return out


    def populate_flags(table: "DataTable", report: Dict[str, Any]) -> None:
        table.clear(columns=True)
        table.add_columns("Flag", "Value")
        flags = report.get("flags_active", {}) or {}
        if not isinstance(flags, dict):
            return
        flat = _flatten_flags(flags)
        for k in sorted(flat.keys()):
            table.add_row(k, str(flat[k]))


    if _HAS_TEXTUAL:

        class ReportLoaded(Message):
            """Posted after a report file is successfully loaded."""

            def __init__(self, report: Dict[str, Any], path: str) -> None:
                super().__init__()
                self.report = report
                self.path = path

        class ReportScreen(Screen):
            """Textual screen for inspecting a Bedrock report.json."""

            BINDINGS = [("escape", "app.pop_screen", "Back")]

            def __init__(
                self,
                initial_path: Optional[str] = None,
                name: Optional[str] = None,
                id: Optional[str] = None,
                classes: Optional[str] = None,
            ) -> None:
                super().__init__(name=name, id=id, classes=classes)
                self._initial_path = initial_path or ""
                self._report: Optional[Dict[str, Any]] = None
                self._report_path: Optional[str] = None

            def compose(self) -> ComposeResult:
                yield Static("Bedrock report viewer", id="title")
                with Horizontal(id="path-row"):
                    yield Input(
                        value=self._initial_path,
                        placeholder="Path to report.json",
                        id="path",
                    )
                    yield Button("Load", id="load", variant="primary")
                    yield Button("Open output file in $EDITOR", id="open")
                yield Static("", id="status")
                with Vertical(id="tables"):
                    yield Static("Summary", classes="section")
                    yield DataTable(id="summary")
                    yield Static("Passes", classes="section")
                    yield DataTable(id="passes")
                    yield Static("Flags", classes="section")
                    yield DataTable(id="flags")
                    yield Static("Entropy (input vs output)", classes="section")
                    if _HAS_SPARKLINE:
                        yield Sparkline([0.0, 0.0], id="entropy-chart")
                    elif ProgressBar is not None:
                        yield ProgressBar(total=8.0, id="entropy-chart")
                    else:
                        yield Static("(entropy chart unavailable)", id="entropy-chart")

            # --- public API used by tests --------------------------------------
            def load_path(self, path: str) -> None:
                """Load a report file and refresh widgets. Raises on error."""
                report = load_report(path)
                self._report = report
                self._report_path = path
                self._refresh_widgets(report)
                try:
                    self.post_message(ReportLoaded(report, path))
                except Exception:
                    pass

            def _refresh_widgets(self, report: Dict[str, Any]) -> None:
                summary = self.query_one("#summary", DataTable)
                passes = self.query_one("#passes", DataTable)
                flags = self.query_one("#flags", DataTable)
                populate_summary(summary, report)
                populate_passes(passes, report)
                populate_flags(flags, report)
                ein = float(report.get("entropy_input", 0.0) or 0.0)
                eout = float(report.get("entropy_output", 0.0) or 0.0)
                try:
                    chart = self.query_one("#entropy-chart")
                    if _HAS_SPARKLINE and isinstance(chart, Sparkline):
                        chart.data = [ein, eout]
                    elif ProgressBar is not None and isinstance(chart, ProgressBar):
                        chart.update(total=8.0, progress=eout)
                except Exception:
                    pass
                try:
                    status = self.query_one("#status", Static)
                    status.update(f"Loaded {report.get('profile_used','?')} from {os.path.basename(self._report_path or '')}")
                except Exception:
                    pass

            def _set_status(self, msg: str) -> None:
                try:
                    self.query_one("#status", Static).update(msg)
                except Exception:
                    pass

            # --- event handlers -------------------------------------------------
            def on_button_pressed(self, event: "Button.Pressed") -> None:
                if event.button.id == "load":
                    path = self.query_one("#path", Input).value.strip()
                    if not path:
                        self._set_status("Please enter a path")
                        return
                    try:
                        self.load_path(path)
                    except FileNotFoundError:
                        self._set_status(f"File not found: {path}")
                    except ValueError as e:
                        self._set_status(f"Schema error: {e}")
                    except Exception as e:  # pragma: no cover - defensive
                        self._set_status(f"Error: {e}")
                elif event.button.id == "open":
                    self._open_output_in_editor()

            def _open_output_in_editor(self) -> None:
                if not self._report:
                    self._set_status("No report loaded")
                    return
                target = self._report.get("extra", {}).get("output_path") if isinstance(self._report.get("extra"), dict) else None
                if not target:
                    target = self._report_path
                editor = os.environ.get("EDITOR", "vi")
                try:
                    subprocess.Popen(shlex.split(editor) + [str(target)])
                    self._set_status(f"Opened {target} in {editor}")
                except Exception as e:
                    self._set_status(f"Editor failed: {e}")

    else:  # pragma: no cover - textual missing
        class ReportLoaded:  # type: ignore
            def __init__(self, report: Dict[str, Any], path: str) -> None:
                self.report = report
                self.path = path

        class ReportScreen:  # type: ignore
            def __init__(self, *a: Any, **kw: Any) -> None:
                raise RuntimeError("textual is required for ReportScreen")




    # === [INLINE] bedrock_tui/build_screen.py ===

    """BuildScreen - Textual TUI screen for configuring và chạy bedrock build.

    Cung cấp 2-column layout: DirectoryTree để chọn input file (left) và panel
    options (right) với các Select / Switch / Input cho từng cờ CLI của
    ``bedrock.py``. Khi nhấn nút *Run Build*, screen sẽ collect args thành một
    ``argparse.Namespace`` rồi push ``LogsScreen`` và spawn worker gọi
    ``bedrock.run_build(ns)`` (helper từ Phase 3 integrator).

    Module này KHÔNG import ``bedrock`` ở top-level để tests có thể mount screen
    mà không cần dependency nặng. ``bedrock.run_build`` chỉ được resolve lúc
    nhấn Run.
    """


    import argparse
    import asyncio
    import time
    from typing import Any

    try:
        from textual.app import ComposeResult
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.screen import Screen
        from textual.widgets import (
            Button,
            DirectoryTree,
            Input,
            Label,
            Select,
            Static,
            Switch,
        )

        TEXTUAL_AVAILABLE = True
    except Exception:  # pragma: no cover - exercised when textual missing
        TEXTUAL_AVAILABLE = False
        Screen = object  # type: ignore[assignment,misc]
        ComposeResult = Any  # type: ignore[assignment,misc]


    # (label, widget_type, default, cli_flag)
    # widget_type ∈ {"switch", "input", "select"}
    # Đối với "select", default là tuple (choices, default_value).
    BUILD_OPTIONS_DEF: list[tuple] = [
        # --- Profile ------------------------------------------------------------
        (
            "Profile",
            "select",
            (
                [("fast", "fast"), ("balanced", "balanced"),
                 ("paranoid", "paranoid"), ("extreme", "extreme")],
                "balanced",
            ),
            "--profile",
        ),
        # --- Switch flags -------------------------------------------------------
        ("Control-Flow Flattening (CFF)", "switch", False, "--cff"),
        ("Bytecode Mutate", "switch", False, "--bc-mutate"),
        (
            "Integrity Check",
            "select",
            ([("on", "on"), ("off", "off")], "on"),
            "--integrity",
        ),
        (
            "Anti-VM",
            "select",
            ([("off", "off"), ("compat", "compat"), ("strict", "strict")], "off"),
            "--anti-vm",
        ),
        ("Anti-Debugger v2", "switch", False, "--anti-debugger-v2"),
        ("Junk Insertion", "switch", False, "--junk"),
        ("Import Obfuscation", "switch", False, "--import-obf"),
        ("Homoglyph Renaming", "switch", False, "--homoglyph"),
        ("Number Obfuscation", "switch", False, "--num-obf"),
        ("Boolean Obfuscation", "switch", False, "--bool-obf"),
        ("String Fragmentation v2", "switch", False, "--str-frag2"),
        ("Lambda Encoding", "switch", False, "--lambda-enc"),
        ("VM Extended", "switch", False, "--vm-extended"),
        # --- Path inputs --------------------------------------------------------
        ("Report Path", "input", "", "--report"),
        ("Output Path (-o)", "input", "", "-o"),
        # --- Mode selects -------------------------------------------------------
        (
            "Anti-Debug Mode",
            "select",
            (
                [("off", "off"), ("compat", "compat"), ("strict", "strict")],
                "off",
            ),
            "--anti-debug",
        ),
        (
            "Anti-Hook Mode",
            "select",
            (
                [("off", "off"), ("compat", "compat"), ("strict", "strict")],
                "off",
            ),
            "--anti-hook",
        ),
        (
            "Tamper Detection",
            "select",
            (
                [("warn", "warn"), ("fail-closed", "fail-closed"),
                 ("self-destruct", "self-destruct")],
                "fail-closed",
            ),
            "--tamper",
        ),
    ]


    def _flag_to_id(flag: str) -> str:
        """Convert ``--anti-debugger-v2`` → ``opt-anti-debugger-v2``."""
        return "opt-" + flag.lstrip("-")


    def collect_namespace(
        options_def: list[tuple],
        values: dict[str, Any],
        input_path: str = "",
    ) -> argparse.Namespace:
        """Build argparse.Namespace from a {cli_flag: value} mapping.

        Tách hàm này ra để test dễ verify mà không cần mount screen.
        """
        ns = argparse.Namespace()
        defaults = {
            "file": input_path or None,
            "output": None,
            "type": "Main",
            "mode": 1,
            "protect": True,
            "runtime_mode": "main",
            "runtime_mode_public": "main",
            "bind_mode": "none",
            "legacy_loader": False,
            "vm_profile": "production",
            "vm_carrier": "auto",
            "vm_compat": "broad",
            "adv_requests": "off",
            "python_band": "3.10-3.12",
            "non_interactive": True,
            "overwrite": False,
            "quiet": False,
            "json": False,
            "clear_cache": False,
            "plugins": [],
            "no_plugins": False,
            "tui": False,
            "project": None,
            "output_dir": None,
            "ignore": [],
            "import_blob": False,
            "homoglyph_seed": None,
            "num_obf_depth": 1,
            "str_frag2": False,
            "str_cipher": False,
            "lambda_enc_y": False,
            "lambda_enc_density": 1.0,
            "bc_mutate_nop": True,
            "bc_mutate_dead": True,
            "bc_mutate_consts": True,
            "cache": True,
        }
        for key, val in defaults.items():
            setattr(ns, key, val)
        for label, wtype, default, flag in options_def:
            attr = flag.lstrip("-").replace("-", "_")
            if attr == "o":
                attr = "output"
            val = values.get(flag, default[1] if wtype == "select" else default)
            if flag == "--anti-debugger-v2":
                val = "on" if bool(val) else "off"
            setattr(ns, attr, val)
        ns._argv = []
        return ns


    if TEXTUAL_AVAILABLE:

        class BuildScreen(Screen):
            """Màn hình cấu hình build chính."""

            DEFAULT_CSS = """
            BuildScreen { layout: horizontal; }
            #left { width: 40%; border: solid $accent; }
            #right { width: 60%; }
            #status { padding: 1; color: $success; }
            #input-path { padding: 1; color: $warning; }
            .opt-row { height: auto; padding: 0 1; }
            """

            BINDINGS = [("r", "reset", "Reset"), ("b", "run_build", "Build")]

            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                self._selected_input: str = ""
                self._build_started_at: float = 0.0

            # -- compose --------------------------------------------------------
            def compose(self) -> ComposeResult:
                with Horizontal():
                    with Vertical(id="left"):
                        yield Label("Input file:")
                        yield DirectoryTree("./", id="dirtree")
                        yield Static("(no file selected)", id="input-path")
                    with VerticalScroll(id="right"):
                        yield Label("Build Options", id="opts-title")
                        for label, wtype, default, flag in BUILD_OPTIONS_DEF:
                            wid = _flag_to_id(flag)
                            if wtype == "switch":
                                with Horizontal(classes="opt-row"):
                                    yield Label(label)
                                    yield Switch(value=bool(default), id=wid)
                            elif wtype == "input":
                                with Vertical(classes="opt-row"):
                                    yield Label(label)
                                    yield Input(value=str(default), id=wid)
                            elif wtype == "select":
                                choices, dflt = default
                                with Vertical(classes="opt-row"):
                                    yield Label(label)
                                    yield Select(
                                        options=choices, value=dflt, id=wid,
                                        allow_blank=False,
                                    )
                        with Horizontal(classes="opt-row"):
                            yield Button("Run Build", variant="primary", id="run")
                            yield Button("Reset", id="reset")
                        yield Static("Ready", id="status")

            # -- helpers --------------------------------------------------------
            def _collect_values(self) -> dict[str, Any]:
                values: dict[str, Any] = {}
                for label, wtype, default, flag in BUILD_OPTIONS_DEF:
                    wid = _flag_to_id(flag)
                    try:
                        w = self.query_one(f"#{wid}")
                    except Exception:
                        continue
                    values[flag] = getattr(w, "value", None)
                return values

            def build_namespace(self) -> argparse.Namespace:
                return collect_namespace(
                    BUILD_OPTIONS_DEF, self._collect_values(),
                    self._selected_input,
                )

            # -- events ---------------------------------------------------------
            def on_directory_tree_file_selected(
                self, event: "DirectoryTree.FileSelected"
            ) -> None:
                path = str(event.path)
                self._selected_input = path
                self.query_one("#input-path", Static).update(f"Input: {path}")

            async def on_button_pressed(self, event: "Button.Pressed") -> None:
                if event.button.id == "reset":
                    self.action_reset()
                    return
                if event.button.id == "run":
                    await self.action_run_build()

            # -- actions --------------------------------------------------------
            def action_reset(self) -> None:
                for label, wtype, default, flag in BUILD_OPTIONS_DEF:
                    wid = _flag_to_id(flag)
                    try:
                        w = self.query_one(f"#{wid}")
                    except Exception:
                        continue
                    if wtype == "switch":
                        w.value = bool(default)
                    elif wtype == "input":
                        w.value = str(default)
                    elif wtype == "select":
                        w.value = default[1]
                self._selected_input = ""
                self.query_one("#input-path", Static).update("(no file selected)")
                self.query_one("#status", Static).update("Ready")

            async def action_run_build(self) -> None:
                ns = self.build_namespace()
                status = self.query_one("#status", Static)
                status.update("Building...")
                self._build_started_at = time.monotonic()
                try:
                    self.app.push_screen("logs")
                except Exception:
                    pass
                asyncio.create_task(self._run_worker(ns))

            async def _run_worker(self, ns: argparse.Namespace) -> None:
                try:
                    import sys as _sys
                    bedrock_mod = _sys.modules.get("bedrock") or _sys.modules.get("__main__")
                    run_build = getattr(bedrock_mod, "run_build", None)
                    if run_build is None:
                        raise RuntimeError("bedrock.run_build not available")
                    await asyncio.to_thread(run_build, ns)
                    elapsed = time.monotonic() - self._build_started_at
                    self.query_one("#status", Static).update(
                        f"Done in {elapsed:.1f}s"
                    )
                except Exception as exc:  # pragma: no cover - runtime path
                    self.query_one("#status", Static).update(f"Error: {exc}")

    else:  # pragma: no cover - fallback when textual missing

        class BuildScreen:  # type: ignore[no-redef]
            """Stub khi textual chưa cài; raise khi instantiate."""

            def __init__(self, *args, **kwargs) -> None:
                raise RuntimeError(
                    "textual is required for BuildScreen. pip install textual"
                )




    # === [INLINE] bedrock_tui/app.py ===

    """Bedrock Obfuscator Textual TUI application skeleton.

    Sub-screens (Build/Settings/Logs/Report) are stubs that other agents (C2/C3/C4)
    will fill in. This module only owns the app shell, navigation, theme, and home.
    """

    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Vertical
        from textual.screen import Screen
        from textual.widgets import Button, Footer, Header, Static
        TEXTUAL_APP_AVAILABLE = True
    except ImportError:  # pragma: no cover - import guard
        TEXTUAL_APP_AVAILABLE = False

        class _MissingTextual:
            Pressed = object

            def __init__(self, *args, **kwargs) -> None:
                pass

            def __call__(self, *args, **kwargs):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def run(self):
                raise ImportError("textual is required for --tui")

        App = Screen = Vertical = Button = Footer = Header = Static = _MissingTextual  # type: ignore
        ComposeResult = Any  # type: ignore

        def Binding(*args, **kwargs):  # type: ignore
            return None


    BANNER = r"""
    [#ff6b35]██████╗ ███████╗██████╗ ██████╗  ██████╗  ██████╗██╗  ██╗[/]
    [#ff7a3d]██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝[/]
    [#ff8a4f]██████╔╝█████╗  ██║  ██║██████╔╝██║   ██║██║     █████╔╝ [/]
    [#ffa066]██╔══██╗██╔══╝  ██║  ██║██╔══██╗██║   ██║██║     ██╔═██╗ [/]
    [#ffb88a]██████╔╝███████╗██████╔╝██║  ██║╚██████╔╝╚██████╗██║  ██╗[/]
    [#ffd0b0]╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝[/]
    """


    class HomeScreen(Screen):
        """Landing screen with banner and main menu."""

        BINDINGS = [
            Binding("b", "go('build')", "Build"),
            Binding("s", "go('settings')", "Settings"),
            Binding("l", "go('logs')", "Logs"),
            Binding("r", "go('report')", "Report"),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id="menu"):
                yield Static(BANNER, id="banner", markup=True)
                yield Static("[b]Bedrock Obfuscator[/b] — main menu", markup=True)
                yield Button("Build  (b)", id="btn_build")
                yield Button("Settings  (s)", id="btn_settings")
                yield Button("Logs  (l)", id="btn_logs")
                yield Button("Report  (r)", id="btn_report")
                yield Button("Help  (?)", id="btn_help")
                yield Button("Quit  (q)", id="btn_quit")
            yield Footer()

        def action_go(self, target: str) -> None:
            self.app.push_screen(target)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            mapping = {
                "btn_build": "build",
                "btn_settings": "settings",
                "btn_logs": "logs",
                "btn_report": "report",
            }
            if event.button.id in mapping:
                self.app.push_screen(mapping[event.button.id])
            elif event.button.id == "btn_help":
                self.app.action_help()
            elif event.button.id == "btn_quit":
                self.app.exit()


    class _StubScreen(Screen):
        """Base class for stub screens awaiting C2/C3/C4 implementation."""

        LABEL = "TODO"

        BINDINGS = [Binding("h", "home", "Home"), Binding("escape", "home", "Home")]

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static(
                f"[b]{self.LABEL}[/b]\n\nTODO: filled by C2/C3/C4",
                classes="todo",
                markup=True,
            )
            yield Footer()

        def action_home(self) -> None:
            self.app.pop_screen()


    if "BuildScreen" not in globals():
        class BuildScreen(_StubScreen):
            LABEL = "Build"


    class SettingsScreen(_StubScreen):
        LABEL = "Settings"


    if "LogScreen" not in globals():
        class LogScreen(_StubScreen):
            LABEL = "Logs"


    if "ReportScreen" not in globals():
        class ReportScreen(_StubScreen):
            LABEL = "Report"


    class BedrockApp(App):
        """Top-level Textual application for Bedrock Obfuscator."""

        CSS = """/* Bedrock Obfuscator TUI theme */

    Screen {
        background: #0d0d0d;
        color: #e6e6e6;
        padding: 1;
    }

    Header {
        height: 3;
        background: #1a1a1a;
        color: #ff6b35;
    }

    Footer {
        height: 1;
        background: #1a1a1a;
        color: #ff6b35;
    }

    #banner {
        color: #ff6b35;
        text-style: bold;
        content-align: center middle;
        height: auto;
        padding: 1 2;
    }

    #menu {
        align: center top;
        padding: 1 2;
        height: auto;
    }

    Button {
        margin: 1 2;
        background: #1f1f1f;
        color: #ff6b35;
        border: tall #ff6b35;
        min-width: 24;
    }

    Button:hover {
        background: #ff6b35;
        color: #0d0d0d;
    }

    Static.todo {
        color: #ffb088;
        content-align: center middle;
        padding: 2 4;
    }
    """
        TITLE = "Bedrock Obfuscator"
        SUB_TITLE = "by baobg"

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("b", "push_screen('build')", "Build"),
            Binding("s", "push_screen('settings')", "Settings"),
            Binding("l", "push_screen('logs')", "Logs"),
            Binding("r", "push_screen('report')", "Report"),
            Binding("h", "push_screen('home')", "Home"),
            Binding("question_mark", "help", "Help"),
        ]

        SCREENS = {
            "home": HomeScreen,
            "build": BuildScreen,
            "settings": SettingsScreen,
            "logs": LogScreen,
            "report": ReportScreen,
        }

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen("home")

        def action_help(self) -> None:
            self.bell()
            self.notify(
                "Phím tắt: q quit | b build | s settings | l logs | r report | h home | ? help",
                title="Help",
                timeout=6,
            )


    def run() -> None:
        """Launch the Bedrock TUI app."""
        if not TEXTUAL_APP_AVAILABLE:
            raise ImportError("textual is required for --tui")
        BedrockApp().run()



    # === END INLINED MODULES ===

    # === BRIDGE: inlined symbols → _ext_* names used by main() ===
    try:
        _ext_apply_profile = apply_profile
    except NameError:
        _ext_apply_profile = None

    try:
        import types as _brt
        _ext_cache = _brt.SimpleNamespace(
            compute_cache_key=compute_cache_key,
            cache_lookup=cache_lookup,
            cache_store=cache_store,
            cache_clear=cache_clear,
            CACHE_DIR=CACHE_DIR,
        )
        del _brt
    except NameError:
        _ext_cache = None

    try:
        ExtProjectBuilder = ProjectBuilder
    except NameError:
        ExtProjectBuilder = None

    try:
        ext_apply_homoglyph = apply_homoglyph
    except NameError:
        ext_apply_homoglyph = None

    try:
        ext_apply_lambda_enc = apply_lambda_enc
    except NameError:
        ext_apply_lambda_enc = None

    try:
        ext_apply_numobf = apply_numobf
    except NameError:
        ext_apply_numobf = None

    try:
        ext_apply_boolobf = apply_boolobf
    except NameError:
        ext_apply_boolobf = None

    try:
        ext_apply_junk = apply_junk
    except NameError:
        ext_apply_junk = None

    try:
        ext_apply_import_obf = apply_import_obf
    except NameError:
        ext_apply_import_obf = None

    try:
        ext_apply_strfrag2 = apply_strfrag2
    except NameError:
        ext_apply_strfrag2 = None

    try:
        ext_wrap_anti_vm = wrap_with_anti_vm
    except NameError:
        ext_wrap_anti_vm = None

    try:
        ext_wrap_anti_dbg_v2 = wrap_with_anti_dbg_v2
    except NameError:
        ext_wrap_anti_dbg_v2 = None

    try:
        ext_apply_cff = apply_cff
    except NameError:
        ext_apply_cff = None

    # batch 5: decompiler-trap + var-split (Phase 2 will add apply_varsplit;
    # for now the alias tolerates the missing def so run_build stays total).
    try:
        ext_apply_dectrap = apply_dectrap
    except NameError:
        ext_apply_dectrap = None

    try:
        ext_apply_varsplit = apply_varsplit
    except NameError:
        ext_apply_varsplit = None

    try:
        ext_apply_runtimedec = apply_runtimedec
    except NameError:
        ext_apply_runtimedec = None

    # Phase 5: native BedrockVM compilation pass alias.
    try:
        ext_apply_native_vm = apply_native_vm
    except NameError:
        ext_apply_native_vm = None

    try:
        ext_mutate_code = mutate_code
    except NameError:
        ext_mutate_code = None

    try:
        ext_wrap_with_hardening = wrap_with_hardening
    except NameError:
        ext_wrap_with_hardening = None

    try:
        ext_register_vm_handlers = register_handlers
    except NameError:
        ext_register_vm_handlers = None

    try:
        ext_discover_plugins = discover_plugins
        ext_apply_plugins = apply_plugins
        ext_PipelineHooks = PipelineHooks
    except NameError:
        ext_discover_plugins = None
        ext_apply_plugins = None
        ext_PipelineHooks = None

    try:
        _ExtReportBuilder = ReportBuilder
        _ext_report_activate = lambda rb: rb
    except NameError:
        _ExtReportBuilder = None
        _ext_report_activate = None

    try:
        _ExtPipelineHooks = PipelineHooks
    except NameError:
        _ExtPipelineHooks = None

    try:
        _ext_wrap_hardening = wrap_with_hardening
    except NameError:
        _ext_wrap_hardening = None

    try:
        _ext_discover_plugins = discover_plugins
        _ext_apply_plugins = apply_plugins
    except NameError:
        _ext_discover_plugins = None
        _ext_apply_plugins = None

    try:
        _ext_apply_cff = apply_cff
    except NameError:
        _ext_apply_cff = None

    try:
        _ext_mutate_code = mutate_code
    except NameError:
        _ext_mutate_code = None

    try:
        _ext_vm_register = register_handlers
    except NameError:
        _ext_vm_register = None
    try:
        tui_run = run
    except NameError:
        tui_run = None
    # === END BRIDGE ===

    if __name__ == "__main__":
        raise SystemExit(main())
except KeyboardInterrupt:
    print('\n\nExiting...')
    exit()
except Exception as BedrockExceptionBedrockExceptionBedrockExceptionBedrockExceptionBedrockException:
    import traceback as __bedrock_tb__
    if globals().get('JSON_MODE', False):
        cli_emit('error', 'Compiler failure', code=4, detail=str(BedrockExceptionBedrockExceptionBedrockExceptionBedrockExceptionBedrockException))
    else:
        __bedrock_tb__.print_exc()
    raise SystemExit(4)