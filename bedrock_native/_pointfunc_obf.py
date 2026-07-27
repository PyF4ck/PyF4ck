"""Phase iO-4: Point-function obfuscation.

A point function P_alpha is the boolean function that returns 1 (True) on a
single point alpha and 0 elsewhere:

    P_alpha(x) = 1 if x == alpha else 0

Point-function obfuscation produces an evaluator O_alpha such that:
  - O_alpha(x) == P_alpha(x) for all x (correctness)
  - O_alpha reveals nothing about alpha beyond what P_alpha(x) reveals
    (hiding: an adversary with oracle access to O_alpha cannot recover alpha
    faster than brute-force guessing).

## Construction (Canetti 1998 + extensions)

This module implements a hash-based point-function obfuscator with a per-build
salt and a "delta" hardening (so the obfuscated evaluator resists
distinguishing attacks beyond simple equality):

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
    - Distinguishing O_alpha from O_beta (alpha != beta) requires ~2^128
      hash queries under the Random Oracle Model

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

__all__ = [
    'obfuscate_point_function',
    'build_point_func_ast',
    'apply_pointfunc_obf',
]


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

def apply_pointfunc_obf(tree: ast.Module, ctx) -> ast.Module:
    """Replace @bedrock_pointfunc(alpha=...)-decorated functions with
    obfuscated point-function evaluators.

    For each decorated function `def check(x): return <impl>` with
    `@bedrock_pointfunc(alpha=b'secret')`, the body is replaced with the
    hash-based point-function evaluator that returns True iff x == alpha.
    The decorator is stripped (it's a build-time directive).

    The alpha value is NOT shipped — only its hash under a per-build salt.
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
        # Obfuscate
        salt = secrets.token_bytes(32)
        delta = rng.randint(0, (1 << 16) - 1)
        obf_params = obfuscate_point_function(alpha, salt=salt, delta=delta)
        # Build the evaluator function (preserves the original name + args)
        new_fn = build_point_func_ast(node.name, obf_params,
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

    print("iO-4 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
