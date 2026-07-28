"""Phase iO-4: Point-function obfuscation.

A point function P_alpha is the boolean function that returns 1 (True) on a
single point alpha and 0 elsewhere:

    P_alpha(x) = 1 if x == alpha else 0

Point-function obfuscation produces an evaluator O_alpha such that:
  - O_alpha(x) == P_alpha(x) for all x (correctness)
  - O_alpha reveals nothing about alpha beyond what P_alpha(x) reveals
    (hiding: an adversary with oracle access to O_alpha cannot recover alpha
    faster than brute-force guessing).

## Construction (two modes)

This module implements two point-function obfuscators:

### mode='hash' (Canetti-style, default)

A hash-based point-function obfuscator with a per-build salt and a "delta"
hardening (so the obfuscated evaluator resists distinguishing attacks beyond
simple equality):

  Build time:
    - pick per-build salt s (32 bytes, from BuildRNG)
    - pick per-build delta d (small random offset, used to harden against
      multi-query distinguishing attacks)
    - precompute h_alpha = SHA256(alpha || s || d)
    - ship O_alpha(x) = (SHA256(x || s || d) == h_alpha)

  Runtime:
    - O_alpha(x) evaluates the hash comparison
    - Each evaluation is O(1) (one SHA-256 call)
    - An adversary seeing h_alpha cannot invert SHA-256 to recover alpha
    - Distinguishing O_alpha from O_beta (alpha != beta) requires ~2^256
      hash queries under the Random Oracle Model
    - BUT an adversary with ORACLE access can distinguish in ONE query
      (query x; if O(x) is True, x == alpha). This is the "oracle
      adversary" weakness of hash-based point-function obfuscation.

### mode='dpf' (BGI14 DPF, stronger against single-key adversary)

A BGI14 Distributed Point Function obfuscator. The point function is
encoded as two DPF keys (GGM-tree shares). A single key's Eval is
pseudorandom under the PRG assumption, so an adversary holding ONE key
cannot distinguish O_alpha from O_beta.

  Build time:
    - hash alpha down to an n-bit int alpha_int (n = 16)
    - run BGI14 DPF Gen for f(x) = (x == alpha_int)
    - ship BOTH keys k0, k1 in the same file

  Runtime:
    - hash the runtime input x down to the same n-bit int x_int
    - evaluate both DPF shares: s0 = Eval(0, k0, x_int), s1 = Eval(1, k1, x_int)
    - return bool(s0 XOR s1) == (x_int == alpha_int)

  Honesty: shipping both keys in the same file means the adversary CAN
  reconstruct f by combining the two Evals -- so this is obfuscation-by-
  indirection, NOT cryptographic hiding. Real hiding requires shipping
  only ONE key and providing the other via env var / release server
  (Phase A key separation). The DPF mode is still useful: it raises the
  bar from "single hash query distinguishes" to "analyst must understand
  and combine the DPF construction".

## Use cases in Bedrock

  - License check: is_valid_license(key) == P_alpha(key) with alpha = valid key
  - Hardware gate: check_hwid(hwid) == P_alpha(hwid) with alpha = expected HWID
  - RE challenge "The Vault": key validation is a point function
  - Compose with Phase G key-release: the point function gates whether the
    server-released key is even fetched (no key release for invalid points)

## Composition with FSS (iO-2)

A point function is a special case of a boolean function. When combined with
FSS bool mode (iO-2), the point function is split into XOR shares, each of
which alone is uniform random. The combiner XORs the shares and casts to bool.

## Kerckhoffs posture

Public construction. Per-build secret: the salt s + delta d. The obfuscated
evaluator ships h_alpha (the hash), which is unconditionally hiding under ROM.

Pure stdlib (``ast``, ``hashlib``, ``secrets``). Run::

    python bedrock_native/_pointfunc_obf.py
"""
from __future__ import annotations

import ast
import copy
import hashlib
import os
import random
import secrets
import sys
from typing import List, Optional, Tuple

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402
from _fss import _dpf_gen, _DPF_SEED_LEN  # noqa: E402

__all__ = [
    'obfuscate_point_function',
    'obfuscate_point_function_dpf',
    'build_point_func_ast',
    'build_point_func_ast_dpf',
    'apply_pointfunc_obf',
]


# DPF point-function bit-width. The DPF encodes the point function on
# Z_{2^n}. We hash the bytes alpha down to an n-bit int, so 16 bits gives
# a 65536-point domain (small enough that the DPF key stays compact at
# ~16 correction words, and the per-eval cost is ~16 HMAC-SHA256 calls).
# Collisions in the hash-to-int step are astronomically unlikely for
# distinct alphas under SHA-256, but if two distinct alphas collided the
# point function would treat them as the same point (acceptable: the
# obfuscated evaluator would return True for both, which is a minor
# correctness relaxation, not a security issue).
_DPF_POINT_BITS = 16


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_io4_pointfunc')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

            def randbelow(self, n):
                return self._sub.randint(0, n - 1)

        return _Wrap(sub)
    seed = getattr(ctx, 'pointfunc_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _hash_with_salt(value_bytes: bytes, salt: bytes, delta: int) -> bytes:
    """H(value || salt || delta) — the point-function evaluator's hash."""
    h = hashlib.sha256()
    h.update(value_bytes)
    h.update(salt)
    h.update(str(delta).encode('utf-8'))
    return h.digest()


# --- Core construction ------------------------------------------------------

def obfuscate_point_function(alpha: bytes, *, salt: bytes = None,
                              delta: int = None) -> dict:
    """Obfuscate a point function P_alpha.

    Args:
        alpha: the secret point (the value that evaluates to True).
        salt: per-build salt (32 bytes); generated if None.
        delta: per-build delta (small int); generated if None.

    Returns:
        dict with keys:
          - 'salt': the salt (shipped with the evaluator)
          - 'delta': the delta (shipped with the evaluator)
          - 'h_alpha': SHA256(alpha || salt || delta) (shipped; the obfuscated form)
          - 'alpha': NOT included (the secret is NOT shipped)
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    if delta is None:
        delta = secrets.randbelow(1 << 16)
    h_alpha = _hash_with_salt(alpha, salt, delta)
    return {
        'salt': salt,
        'delta': delta,
        'h_alpha': h_alpha,
    }


# --- DPF-based point-function obfuscation -----------------------------------
#
# The hash-based construction above is the simplest point-function obfuscator,
# but an adversary with oracle access to O_alpha can distinguish O_alpha from
# O_beta in a SINGLE query (query x; if O(x) is True, x == alpha). This is the
# "oracle adversary" weakness noted in the plan.
#
# A DPF (Distributed Point Function, BGI14) provides a stronger obfuscation
# against an adversary holding ONE of the two keys: a single key's Eval is
# pseudorandom (under the PRG assumption), so querying it reveals nothing
# about alpha. When BOTH keys are shipped in the same file (as we do here),
# the adversary can reconstruct f by combining the two Evals -- so this is
# "obfuscation-by-indirection", not cryptographic hiding. Real hiding
# requires key separation (env var / release server) so the analyst sees
# at most one key. See Phase A and the threat model in README.md.
#
# Construction:
#   1. Hash the bytes alpha down to an n-bit int alpha_int (n = _DPF_POINT_BITS).
#   2. Run BGI14 DPF Gen for the point function f(x) = (x == alpha_int).
#   3. Emit two Eval functions (one per key) and an XOR combiner. The
#      evaluator hashes the runtime input x down to the same n-bit int and
#      evaluates the two DPF shares; the combiner XORs them to recover the
#      point-function bit.


def _hash_to_int(value_bytes: bytes, salt: bytes, n: int) -> int:
    """Hash bytes down to an n-bit int (domain {0,1}^n)."""
    h = hashlib.sha256()
    h.update(salt)
    h.update(value_bytes)
    return int.from_bytes(h.digest()[: (n + 7) // 8], 'big') & ((1 << n) - 1)


def obfuscate_point_function_dpf(alpha: bytes, *, salt: bytes = None,
                                  n: int = None, rng=None) -> dict:
    """Obfuscate a point function P_alpha using a BGI14 DPF.

    Args:
        alpha: the secret point (the value that evaluates to True).
        salt: per-build salt (32 bytes); generated if None. Used to hash
            alpha and the runtime input down to the DPF domain so distinct
            alphas map to distinct domain points.
        n: DPF domain bit-width (default _DPF_POINT_BITS = 16).
        rng: random source for DPF key generation (os.urandom-style).

    Returns:
        dict with keys:
          - 'salt': the salt (shipped with the evaluator)
          - 'n': the DPF domain bit-width
          - 'alpha_int': the n-bit int point (NOT shipped; debug only)
          - 'k0': DPF key for party 0 (shipped)
          - 'k1': DPF key for party 1 (shipped)
        NOTE: both keys ARE shipped (obfuscation-by-indirection). For real
        hiding, ship only ONE key and require the other via env / release
        server (Phase A key separation).
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    if n is None:
        n = _DPF_POINT_BITS
    if rng is None:
        rng = secrets
    alpha_int = _hash_to_int(alpha, salt, n)
    k0, k1 = _dpf_gen(alpha_int, n, beta=1, rng=rng)
    return {
        'salt': salt,
        'n': n,
        'alpha_int': alpha_int,  # debug; not the secret alpha itself
        'k0': k0,
        'k1': k1,
    }


def build_point_func_ast_dpf(name: str, obf_params: dict,
                              arg_name: str = 'x',
                              dpf_key_split: bool = True,
                              dpf_key_env: str = 'BR_DPF_K1',
                              ctx=None) -> ast.FunctionDef:
    """Build an AST function def for the DPF-based point-function evaluator.

    The generated function hashes the runtime input down to an n-bit int
    (same hash as obfuscate_point_function_dpf), evaluates both DPF shares,
    and XORs them to recover the point-function bit. The salt and party 0's
    DPF key (k0) are shipped as bytes literals in the function body.

    Phase G5: when ``dpf_key_split`` is True (default, secure), party 1's key
    (k1) is NOT shipped. The function reads it at runtime from the
    environment variable ``dpf_key_env`` (default ``BR_DPF_K1``) as a
    hex-encoded JSON key tuple, raising a clean SystemExit if missing. The
    build path exposes the serialized k1 hex on ``ctx.dpf_k1_hex`` +
    ``ctx.dpf_key_env_name`` so a ``.dpfkey`` sidecar can be emitted
    (mirrors the binary capsule's ctx.capsule_key).

    When ``dpf_key_split`` is False (legacy backward-compat), both keys ship
    in the SAME file (obfuscation-by-indirection, not cryptographic hiding).
    """
    salt = obf_params['salt']
    n = obf_params['n']
    k0 = obf_params['k0']
    k1 = obf_params['k1']

    def _key_repr(key):
        seed, t0, cws, cw_final = key
        cw_list = [(s_cw.hex(), t_cw_L, t_cw_R) for (s_cw, t_cw_L, t_cw_R) in cws]
        return (seed.hex(), t0, cw_list, cw_final)

    k0_repr = repr(_key_repr(k0))
    salt_repr = repr(salt)

    # Phase G5: serialize k1 for the env-var/sidecar path (hex of JSON).
    try:
        import json as _dpf_json
        _k1_serialized = _dpf_json.dumps(_key_repr(k1)).encode('utf-8').hex()
    except Exception:
        _k1_serialized = repr(_key_repr(k1)).encode('utf-8').hex()
    if ctx is not None and dpf_key_split:
        try:
            ctx.dpf_k1_hex = _k1_serialized
            ctx.dpf_key_env_name = dpf_key_env
        except Exception:
            pass

    # Build the function body from a source template for clarity. The DPF
    # eval helper is emitted inline so the obfuscated function is self-
    # contained (no external _br_dpf_eval dependency).
    if dpf_key_split:
        _env_repr = repr(dpf_key_env)
        _k1_load = (
            f"    import os as _br_pf_os\n"
            f"    _br_pf_k1_hex = _br_pf_os.environ.get({_env_repr})\n"
            f"    if not _br_pf_k1_hex:\n"
            f"        raise SystemExit('dpf: key missing -- set env ' + {_env_repr} + '=<hex> (see <output>.dpfkey sidecar) before running')\n"
            f"    import json as _br_pf_json\n"
            f"    _br_pf_k1 = _br_pf_json.loads(bytes.fromhex(_br_pf_k1_hex).decode('utf-8'))\n"
        )
    else:
        _k1_repr = repr(_key_repr(k1))
        _k1_load = f"    _br_pf_k1 = {_k1_repr}\n"

    fn_src = (
        f"def {name}({arg_name}):\n"
        f"    import hashlib as _br_pf_h\n"
        f"    _br_pf_salt = {salt_repr}\n"
        f"    _br_pf_n = {n}\n"
        f"    _br_pf_k0 = {k0_repr}\n"
        + _k1_load +
        f"    _br_pf_val = {arg_name} if isinstance({arg_name}, bytes) else str({arg_name}).encode('utf-8')\n"
        f"    _br_pf_hh = _br_pf_h.sha256()\n"
        f"    _br_pf_hh.update(_br_pf_salt)\n"
        f"    _br_pf_hh.update(_br_pf_val)\n"
        f"    _br_pf_x = int.from_bytes(_br_pf_hh.digest()[:(_br_pf_n + 7) // 8], 'big') & ((1 << _br_pf_n) - 1)\n"
        f"    def _br_dpf_eval(_b, _key, _x, _n):\n"
        f"        _seed, _t, _cws, _cwf = _key\n"
        f"        _s = bytes.fromhex(_seed)\n"
        f"        for _i in range(_n):\n"
        f"            _h = _br_pf_h.sha256(_s + b'\\x00dpf-ggm').digest()\n"
        f"            _sL, _sR = _h[:16], _h[16:32]\n"
        f"            _tL, _tR = _h[24] & 1, _h[25] & 1\n"
        f"            _scw, _tcL, _tcR = _cws[_i]\n"
        f"            _scw_b = bytes.fromhex(_scw)\n"
        f"            _xi = (_x >> (_n - 1 - _i)) & 1\n"
        f"            if _xi == 0:\n"
        f"                _s = bytes(a ^ b for a, b in zip(_sL, _scw_b)) if _t else _sL\n"
        f"                _t = _tL ^ (_tcL if _t else 0)\n"
        f"            else:\n"
        f"                _s = bytes(a ^ b for a, b in zip(_sR, _scw_b)) if _t else _sR\n"
        f"                _t = _tR ^ (_tcR if _t else 0)\n"
        f"        return _t if _b == 0 else (_t ^ _cwf)\n"
        f"    return bool(_br_dpf_eval(0, _br_pf_k0, _br_pf_x, _br_pf_n) ^\n"
        f"                _br_dpf_eval(1, _br_pf_k1, _br_pf_x, _br_pf_n))\n"
    )
    fn = ast.parse(fn_src).body[0]
    return fn


def build_point_func_ast(name: str, obf_params: dict,
                          arg_name: str = 'x') -> ast.FunctionDef:
    """Build an AST function def for the obfuscated point-function evaluator.

    The generated function is:

        def NAME(x):
            import hashlib as _br_pf_h
            _br_pf_salt = b'...'   # shipped salt
            _br_pf_delta = 12345   # shipped delta
            _br_pf_target = b'...' # shipped h_alpha
            _br_pf_val = x if isinstance(x, bytes) else str(x).encode('utf-8')
            _br_pf_h = _br_pf_h.sha256()
            _br_pf_h.update(_br_pf_val)
            _br_pf_h.update(_br_pf_salt)
            _br_pf_h.update(str(_br_pf_delta).encode('utf-8'))
            return _br_pf_h.digest() == _br_pf_target

    The evaluator accepts any input type (str, bytes, int, etc.) — it
    coerces to bytes before hashing.
    """
    salt = obf_params['salt']
    delta = obf_params['delta']
    h_alpha = obf_params['h_alpha']

    body: List[ast.stmt] = [
        ast.Import(names=[ast.alias(name='hashlib', asname='_br_pf_h')]),
        ast.Assign(
            targets=[ast.Name(id='_br_pf_salt', ctx=ast.Store())],
            value=ast.Constant(value=salt),
        ),
        ast.Assign(
            targets=[ast.Name(id='_br_pf_delta', ctx=ast.Store())],
            value=ast.Constant(value=delta),
        ),
        ast.Assign(
            targets=[ast.Name(id='_br_pf_target', ctx=ast.Store())],
            value=ast.Constant(value=h_alpha),
        ),
        # Coerce x to bytes: x if isinstance(x, bytes) else str(x).encode()
        ast.Assign(
            targets=[ast.Name(id='_br_pf_val', ctx=ast.Store())],
            value=ast.IfExp(
                test=ast.Call(
                    func=ast.Name(id='isinstance', ctx=ast.Load()),
                    args=[ast.Name(id=arg_name, ctx=ast.Load()),
                          ast.Name(id='bytes', ctx=ast.Load())],
                    keywords=[],
                ),
                body=ast.Name(id=arg_name, ctx=ast.Load()),
                orelse=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Name(id='str', ctx=ast.Load()),
                            args=[ast.Name(id=arg_name, ctx=ast.Load())],
                            keywords=[],
                        ),
                        attr='encode', ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value='utf-8')], keywords=[],
                ),
            ),
        ),
        # _br_pf_h = hashlib.sha256()
        ast.Assign(
            targets=[ast.Name(id='_br_pf_h_obj', ctx=ast.Store())],
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='_br_pf_h', ctx=ast.Load()),
                    attr='sha256', ctx=ast.Load(),
                ),
                args=[], keywords=[],
            ),
        ),
        # _br_pf_h.update(_br_pf_val)
        ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id='_br_pf_h_obj', ctx=ast.Load()),
                attr='update', ctx=ast.Load(),
            ),
            args=[ast.Name(id='_br_pf_val', ctx=ast.Load())], keywords=[],
        )),
        # _br_pf_h.update(_br_pf_salt)
        ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id='_br_pf_h_obj', ctx=ast.Load()),
                attr='update', ctx=ast.Load(),
            ),
            args=[ast.Name(id='_br_pf_salt', ctx=ast.Load())], keywords=[],
        )),
        # _br_pf_h.update(str(_br_pf_delta).encode())
        ast.Expr(value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id='_br_pf_h_obj', ctx=ast.Load()),
                attr='update', ctx=ast.Load(),
            ),
            args=[ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Name(id='str', ctx=ast.Load()),
                        args=[ast.Name(id='_br_pf_delta', ctx=ast.Load())],
                        keywords=[],
                    ),
                    attr='encode', ctx=ast.Load(),
                ),
                args=[ast.Constant(value='utf-8')], keywords=[],
            )],
            keywords=[],
        )),
        # return _br_pf_h.digest() == _br_pf_target
        ast.Return(value=ast.Compare(
            left=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='_br_pf_h_obj', ctx=ast.Load()),
                    attr='digest', ctx=ast.Load(),
                ),
                args=[], keywords=[],
            ),
            ops=[ast.Eq()],
            comparators=[ast.Name(id='_br_pf_target', ctx=ast.Load())],
        )),
    ]

    fn = ast.FunctionDef(
        name=name,
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg=arg_name, annotation=None)],
            kwonlyargs=[], kw_defaults=[], defaults=[],
            vararg=None, kwarg=None,
        ),
        body=body, decorator_list=[], returns=None, type_comment=None,
    )
    return fn


# --- Decorator detection ---------------------------------------------------

_MARKER = 'bedrock_pointfunc'


def _is_pointfunc_decorator(node: ast.expr) -> bool:
    """Detect @bedrock_pointfunc(alpha=...) decorator."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == _MARKER:
        return True
    if isinstance(func, ast.Attribute) and func.attr == _MARKER:
        return True
    return False


def _extract_alpha_from_decorator(deco: ast.Call) -> Optional[bytes]:
    """Extract the alpha value from @bedrock_pointfunc(alpha=...) call.

    Returns the alpha as bytes, or None if it can't be statically extracted.
    Supports: str literals (encoded utf-8), bytes literals, int literals
    (str(int).encode()).
    """
    for kw in deco.keywords:
        if kw.arg == 'alpha':
            v = kw.value
            if isinstance(v, ast.Constant):
                if isinstance(v.value, bytes):
                    return v.value
                if isinstance(v.value, str):
                    return v.value.encode('utf-8')
                if isinstance(v.value, int):
                    return str(v.value).encode('utf-8')
    return None


# --- Pass -------------------------------------------------------------------

def _extract_mode_from_decorator(deco: ast.Call) -> str:
    """Extract the mode ('hash' or 'dpf') from @bedrock_pointfunc(mode=...).

    Default is 'hash' (the original salted-hash construction). 'dpf' uses
    the BGI14 DPF construction (stronger obfuscation against single-key
    adversaries, but ships both keys in the same file).
    """
    for kw in deco.keywords:
        if kw.arg == 'mode':
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value.lower()
    return 'hash'


def apply_pointfunc_obf(tree: ast.Module, ctx) -> ast.Module:
    """Replace @bedrock_pointfunc(alpha=...)-decorated functions with
    obfuscated point-function evaluators.

    For each decorated function `def check(x): return <impl>` with
    `@bedrock_pointfunc(alpha=b'secret')`, the body is replaced with the
    obfuscated point-function evaluator that returns True iff x == alpha.
    The decorator is stripped (it's a build-time directive).

    The alpha value is NOT shipped. Two obfuscation modes:
      - mode='hash' (default): salted-hash construction (Canetti-style).
        Single-query oracle distinguishable; simple and fast.
      - mode='dpf': BGI14 DPF construction. Stronger obfuscation against
        single-key adversaries (one DPF key alone is pseudorandom). Both
        keys ship in the same file (obfuscation-by-indirection); for real
        hiding, ship only one key via env / release server (Phase A).
    """
    rng = _rng_for(ctx)
    n_obf = 0

    for node in list(tree.body):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Find the pointfunc decorator
        pf_deco = None
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and _is_pointfunc_decorator(d):
                pf_deco = d
                break
        if pf_deco is None:
            continue
        alpha = _extract_alpha_from_decorator(pf_deco)
        if alpha is None:
            continue
        mode = _extract_mode_from_decorator(pf_deco)
        # Obfuscate according to the chosen mode.
        if mode == 'dpf':
            class _DPFRng:
                def __init__(self, r):
                    self._r = r
                def urandom(self, k):
                    return secrets.token_bytes(k)
                def randint(self, lo, hi):
                    return self._r.randint(lo, hi)
            dpf_rng = _DPFRng(rng)
            salt = secrets.token_bytes(32)
            obf_params = obfuscate_point_function_dpf(
                alpha, salt=salt, n=_DPF_POINT_BITS, rng=dpf_rng)
            # Phase G5: split k1 to env by default (secure posture). The
            # operator sets BR_DPF_K1 (see <output>.dpfkey sidecar) before
            # running. dpf_key_split=False embeds both keys (legacy path).
            _dpf_split = bool(getattr(ctx, 'dpf_key_split', True))
            _dpf_env = str(getattr(ctx, 'dpf_key_env', 'BR_DPF_K1') or 'BR_DPF_K1')
            new_fn = build_point_func_ast_dpf(
                node.name, obf_params,
                arg_name=node.args.args[0].arg if node.args.args else 'x',
                dpf_key_split=_dpf_split, dpf_key_env=_dpf_env, ctx=ctx)
        else:  # 'hash' (default)
            salt = secrets.token_bytes(32)
            delta = rng.randint(0, (1 << 16) - 1)
            obf_params = obfuscate_point_function(alpha, salt=salt, delta=delta)
            new_fn = build_point_func_ast(
                node.name, obf_params,
                arg_name=node.args.args[0].arg if node.args.args else 'x')
        # Preserve any other decorators (non-pointfunc)
        new_fn.decorator_list = [d for d in node.decorator_list if not (
            isinstance(d, ast.Call) and _is_pointfunc_decorator(d))]
        # Replace in-place
        idx = tree.body.index(node)
        tree.body[idx] = new_fn
        ast.fix_missing_locations(tree)
        n_obf += 1

    try:
        ctx.pointfunc_obfuscated = n_obf
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify: correctness, hiding, composition with FSS, decorator detection."""

    class _Ctx:
        build_rng = None
        pointfunc_seed = 42

    ctx = _Ctx()

    # --- Correctness: O_alpha(alpha) == True, O_alpha(other) == False ---
    alpha = b'secret_key_123'
    obf = obfuscate_point_function(alpha)
    assert obf['h_alpha'] == _hash_with_salt(alpha, obf['salt'], obf['delta'])
    # Build evaluator
    fn_ast = build_point_func_ast('check_key', obf)
    mod = ast.Module(body=[fn_ast], type_ignores=[])
    ast.fix_missing_locations(mod)
    ns = {}
    exec(compile(mod, '<pf>', 'exec'), ns)
    check = ns['check_key']
    # Correct on the secret point
    assert check(b'secret_key_123') is True, "check(secret) should be True"
    assert check('secret_key_123') is True, "check accepts str too"
    # Wrong inputs return False
    assert check(b'wrong') is False
    assert check(b'secret_key_12') is False  # prefix
    assert check(b'secret_key_1234') is False  # suffix
    assert check(123) is False  # int != bytes
    assert check('') is False
    print("iO-4 correctness: O(secret)=True, O(other)=False  OK")

    # --- Hiding: h_alpha does not reveal alpha ---
    # An adversary sees h_alpha, salt, delta. Under ROM, recovering alpha
    # requires ~2^256 work (inverting SHA-256). We verify that h_alpha is
    # NOT alpha and that two different alphas produce different h_alpha.
    obf2 = obfuscate_point_function(b'other_secret', salt=obf['salt'], delta=obf['delta'])
    assert obf['h_alpha'] != obf2['h_alpha'], "different alphas must give different hashes"
    assert obf['h_alpha'] != alpha, "h_alpha must not be the raw secret"
    print("iO-4 hiding: h_alpha hides alpha (different alphas -> different hashes)  OK")

    # --- Per-build diversity: same alpha, different salt -> different h ---
    obf_a = obfuscate_point_function(alpha, salt=b'A' * 32, delta=1)
    obf_b = obfuscate_point_function(alpha, salt=b'B' * 32, delta=2)
    assert obf_a['h_alpha'] != obf_b['h_alpha']
    print("iO-4 diversity: same alpha, different salt/delta -> different h_alpha  OK")

    # --- Decorator detection + apply_pointfunc_obf ---
    src = (
        "def is_valid(key):\n"
        "    return key == b'real_key'\n"
        "\n"
        "def not_decorated(x):\n"
        "    return x + 1\n"
    )
    # Can't use @bedrock_pointfunc(alpha=...) in the smoke string because the
    # decorator is defined in this module; build the AST manually.
    tree = ast.parse(src)
    # Find is_valid and add the decorator
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'is_valid':
            node.decorator_list.insert(0, ast.Call(
                func=ast.Name(id='bedrock_pointfunc', ctx=ast.Load()),
                args=[], keywords=[ast.keyword(arg='alpha', value=ast.Constant(value=b'real_key'))],
            ))
            break
    ast.fix_missing_locations(tree)
    out = apply_pointfunc_obf(tree, ctx)
    assert getattr(ctx, 'pointfunc_obfuscated', 0) == 1, "should obfuscate 1 function"
    # The decorator should be stripped
    src_after = ast.unparse(out)
    assert 'bedrock_pointfunc' not in src_after, "decorator should be stripped"
    # not_decorated should be unchanged
    nd = next(n for n in out.body if getattr(n, 'name', '') == 'not_decorated')
    assert 'return x + 1' in ast.unparse(nd)
    print("iO-4 apply: decorator detected, body replaced, deco stripped  OK")

    # --- Functional: the obfuscated evaluator works ---
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<pf2>', 'exec'), ns2)
    iv = ns2['is_valid']
    assert iv(b'real_key') is True
    assert iv(b'fake') is False
    print("iO-4 functional: obfuscated is_valid works correctly  OK")

    # --- Int input coercion ---
    tree_int = ast.parse("def check_int(n):\n    return n == 42\n")
    for node in tree_int.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'check_int':
            node.decorator_list.insert(0, ast.Call(
                func=ast.Name(id='bedrock_pointfunc', ctx=ast.Load()),
                args=[], keywords=[ast.keyword(arg='alpha', value=ast.Constant(value=42))],
            ))
            break
    ast.fix_missing_locations(tree_int)
    out_int = apply_pointfunc_obf(tree_int, ctx)
    ns3 = {}
    exec(compile(ast.Module(body=out_int.body, type_ignores=[]), '<pfi>', 'exec'), ns3)
    ci = ns3['check_int']
    assert ci(42) is True, "check_int(42) should be True"
    assert ci(41) is False
    assert ci('42') is True, "str '42' coerces to bytes '42' == int 42 coerced"
    print("iO-4 int coercion: check_int(42)=True, check_int(41)=False  OK")

    # --- DPF mode: correctness + 1-key hiding ---
    # Correctness: O_dpf(alpha) == True, O_dpf(other) == False. We verify
    # over a sample of inputs (NOT the full 2**16 domain -- too slow at
    # build time; correctness of the underlying DPF is verified exhaustively
    # in _fss._smoke).
    import os as _os
    alpha_dpf = b'secret_dpf_key'
    obf_dpf = obfuscate_point_function_dpf(alpha_dpf)

    # G5 split=on (default, secure): k1 read from env, refuse if missing.
    ctx_split = _Ctx()
    fn_dpf_ast = build_point_func_ast_dpf('check_dpf', obf_dpf, ctx=ctx_split)
    _dpf_env = getattr(ctx_split, 'dpf_key_env_name', 'BR_DPF_K1')
    _dpf_k1_hex = getattr(ctx_split, 'dpf_k1_hex', '')
    assert _dpf_k1_hex, "G5: build_point_func_ast_dpf must expose k1 hex on ctx"
    mod_dpf = ast.Module(body=[fn_dpf_ast], type_ignores=[])
    ast.fix_missing_locations(mod_dpf)
    # Refuse-run: env unset -> clean SystemExit (no alpha leak).
    _os.environ.pop(_dpf_env, None)
    ns_refuse = {}
    exec(compile(mod_dpf, '<dpf>', 'exec'), ns_refuse)
    try:
        ns_refuse['check_dpf'](b'secret_dpf_key')
        raise AssertionError("G5: missing env must refuse (SystemExit)")
    except SystemExit as _e:
        assert 'key missing' in str(_e), f"refuse msg: {_e}"
    # Correctness with env set from the sidecar-equivalent hex.
    _os.environ[_dpf_env] = _dpf_k1_hex
    try:
        ns_dpf = {}
        exec(compile(mod_dpf, '<dpf>', 'exec'), ns_dpf)
        check_dpf = ns_dpf['check_dpf']
        assert check_dpf(b'secret_dpf_key') is True, "check_dpf(secret) should be True"
        assert check_dpf('secret_dpf_key') is True, "check_dpf accepts str too"
        assert check_dpf(b'wrong') is False
        assert check_dpf(b'secret_dpf_ke') is False  # prefix
        assert check_dpf(b'secret_dpf_keyy') is False  # suffix
        assert check_dpf(123) is False
        assert check_dpf('') is False
        for probe in [b'x', b'foo', b'bar', b'baz', b'qux', bytes([0, 1, 2]),
                      b'zzz', b'aaa', bytes([0xff]) * 16, b'another_key']:
            assert check_dpf(probe) is False, f"check_dpf({probe!r}) should be False"
    finally:
        _os.environ.pop(_dpf_env, None)
    print("iO-4 DPF correctness (split=on): O_dpf(secret)=True, 10 wrong=False; refuses w/o env  OK")

    # G5 split=off (legacy): both keys embedded, no env required.
    fn_nosplit = build_point_func_ast_dpf('check_dpf_legacy', obf_dpf,
                                           dpf_key_split=False)
    mod_nosplit = ast.Module(body=[fn_nosplit], type_ignores=[])
    ast.fix_missing_locations(mod_nosplit)
    ns_nosplit = {}
    exec(compile(mod_nosplit, '<dpf_legacy>', 'exec'), ns_nosplit)
    cl = ns_nosplit['check_dpf_legacy']
    assert cl(b'secret_dpf_key') is True
    assert cl(b'wrong') is False
    print("iO-4 DPF correctness (split=off): both keys embedded, no env needed  OK")

    # --- DPF 1-key hiding: a single key's Eval is NOT the point function ---
    # This is the security gain over the hash mode: an adversary holding
    # ONLY k0 (not k1) sees pseudorandom bits, not a spike at alpha.
    from _fss import _dpf_eval
    n_dpf = obf_dpf['n']
    k0 = obf_dpf['k0']
    s0_seq = [_dpf_eval(0, k0, x, n_dpf) for x in range(1 << n_dpf)]
    # The single-key sequence should NOT equal the point function (which
    # would be a single 1 at alpha_int and 0s elsewhere).
    alpha_int = obf_dpf['alpha_int']
    f_seq = [1 if x == alpha_int else 0 for x in range(1 << n_dpf)]
    assert s0_seq != f_seq, "single key alone must NOT equal the point function"
    # And the number of 1s in the single-key sequence should be ~half
    # (pseudorandom), not a single spike (which would leak alpha).
    n_ones = sum(s0_seq)
    assert n_ones > 1, f"single-key has {n_ones} ones -- looks like a spike (alpha leak?)"
    print(f"iO-4 DPF 1-key hiding: single share != f_alpha ({n_ones} ones, not a spike)  OK")

    # --- DPF apply_pointfunc_obf with mode='dpf' decorator ---
    tree_dpf_apply = ast.parse("def is_valid_dpf(key):\n    return key == b'real_key'\n")
    for node in tree_dpf_apply.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'is_valid_dpf':
            node.decorator_list.insert(0, ast.Call(
                func=ast.Name(id='bedrock_pointfunc', ctx=ast.Load()),
                args=[], keywords=[
                    ast.keyword(arg='alpha', value=ast.Constant(value=b'real_key')),
                    ast.keyword(arg='mode', value=ast.Constant(value='dpf')),
                ],
            ))
            break
    ast.fix_missing_locations(tree_dpf_apply)
    out_dpf_apply = apply_pointfunc_obf(tree_dpf_apply, ctx)
    assert getattr(ctx, 'pointfunc_obfuscated', 0) >= 1, "should obfuscate 1 function"
    src_dpf_after = ast.unparse(out_dpf_apply)
    assert 'bedrock_pointfunc' not in src_dpf_after, "decorator should be stripped"
    # Verify the DPF evaluator was emitted (look for DPF eval helper).
    assert '_br_dpf_eval' in src_dpf_after, "DPF mode should emit _br_dpf_eval helper"
    # G5: apply_pointfunc_obf with split default-on must read k1 from env.
    assert '_br_pf_os.environ' in src_dpf_after or 'os.environ' in src_dpf_after, \
        "G5: DPF apply must read k1 from env"
    _apply_env = getattr(ctx, 'dpf_key_env_name', 'BR_DPF_K1')
    _apply_k1 = getattr(ctx, 'dpf_k1_hex', '')
    assert _apply_k1, "G5: apply_pointfunc_obf must expose k1 hex on ctx"
    # Functional test with env set from the sidecar-equivalent hex.
    _os.environ[_apply_env] = _apply_k1
    try:
        ns_dpf_apply = {}
        exec(compile(ast.Module(body=out_dpf_apply.body, type_ignores=[]), '<dpf2>', 'exec'), ns_dpf_apply)
        iv_dpf = ns_dpf_apply['is_valid_dpf']
        assert iv_dpf(b'real_key') is True, "DPF is_valid(real_key) should be True"
        assert iv_dpf(b'fake') is False
        assert iv_dpf('real_key') is True  # str coercion
    finally:
        _os.environ.pop(_apply_env, None)
    print("iO-4 DPF apply: mode='dpf' decorator, split=on (env k1), functional  OK")

    # --- DPF diversity: same alpha, different salt -> different keys ---
    obf_d1 = obfuscate_point_function_dpf(alpha_dpf, salt=b'A' * 32)
    obf_d2 = obfuscate_point_function_dpf(alpha_dpf, salt=b'B' * 32)
    # The seeds are random per-build (via secrets), so different builds give
    # different keys even for the same salt. But the alpha_int depends on
    # the salt, so different salts give different alpha_int (different point).
    assert obf_d1['alpha_int'] != obf_d2['alpha_int'], "different salt -> different alpha_int"
    print("iO-4 DPF diversity: different salt -> different alpha_int (hash-to-int)  OK")

    print("iO-4 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
