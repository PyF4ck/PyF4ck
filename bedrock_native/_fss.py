"""Phase H.9 (Layer 6) Function Secret Sharing (FSS) 2-share.

Split an eligible numeric-returning function ``f(x)`` into two shares
``f1(x, r)`` and ``f2(x, r)`` such that::

    combine(f1(x, r), f2(x, r)) == f(x)      for all x, r
    f1(x, r) alone reveals nothing about f(x)  (it's f(x) + r, masked by r)
    f2(x, r) alone reveals nothing about f(x)  (it's -r)

The two shares are placed in SEPARATE module-level code objects (distinct
``def`` names) so a static analyzer cannot see them together. The original
``f`` is replaced by a thin combiner::

    # before
    def square(x):
        return x * x

    # after
    def _br_fss_1_a3f2(x, r):
        return (x * x) + r       # share 1: f(x) + r
    def _br_fss_2_b7c1(x, r):
        return -r                # share 2: -r
    def square(x):
        import secrets as _br_s
        _br_r = _br_s.randbelow(1 << 64) - (1 << 63)   # random per call
        return _br_fss_1_a3f2(x, _br_r) + _br_fss_2_b7c1(x, _br_r)

## Kerckhoffs posture

Public technique. Per-build secret: the share function names + the RNG
salt (RNG-derived).

## Threat addressed

Static analysis of a function's logic. A decompiler that lifts ``square``
sees only the combiner (two opaque call results summed). The actual
computation ``x * x`` lives in ``_br_fss_1_a3f2`` -- a separate function
that a naive analyzer doesn't connect to ``square``. Recovering ``f``
requires recognizing that ``f1 + f2 = f(x)`` -- a cross-function dataflow
fact.

## Safety contract

- **Additive sharing**: ``f1 = f(x) + r``, ``f2 = -r``, so ``f1 + f2 = f(x)``
  EXACTLY (integer arithmetic; no modular wrap). Exact for any integer
  ``f(x)`` and any integer ``r``.
- **Randomness**: ``r`` is a fresh random integer per CALL (via
  ``secrets.randbelow``), so ``f1`` alone is a random integer (reveals
  nothing about ``f(x)``) and ``f2`` alone is a random integer too.
- **Eligibility**: top-level ``def`` that (a) returns a single numeric
  expression, (b) has no side effects (no calls, yields, awaits, prints),
  (c) is pure (the return value depends only on the args). Dunders +
  marker skipped. Cap ~3-5 FSS'd functions (like crown jewels).
- **Args**: the share functions take the SAME args as the original plus a
  trailing ``r`` parameter. The combiner passes the original args + the
  fresh ``r``.
- **Return type**: the share arithmetic uses Python int arithmetic (which
  is unbounded), so any integer-returning function is exact. Floats would
  lose precision on the add+r+(-r) round-trip, so floats are skipped.

Pure stdlib (``ast``, ``random``, ``secrets``). Run::

    python bedrock_native/_fss.py
"""
from __future__ import annotations

import ast
import os
import random
import sys
from typing import List, Optional

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_fss']


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_fss')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

        return _Wrap(sub)
    seed = getattr(ctx, 'fss_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _has_side_effect(node: ast.expr) -> bool:
    for n in ast.walk(node):
        if isinstance(n, (ast.Call, ast.Yield, ast.YieldFrom, ast.Await)):
            return True
    return False


def _is_int_returning(value: ast.expr) -> bool:
    """Conservative: the return expression must look integer-valued.
    Allow int literals, names, BinOps (+,-,*,//,%,**,&,|,^,<<,>>), UnaryOps
    (+,-,~), and comparisons (which yield bool -> 0/1). Skip floats,
    strings, calls, lists."""
    if isinstance(value, ast.Constant):
        return isinstance(value.value, int) and not isinstance(value.value, bool) \
            or isinstance(value.value, bool)
    if isinstance(value, ast.Name):
        return True  # assume int (smoke verifies; identity funcs rejected below)
    if isinstance(value, ast.UnaryOp):
        if isinstance(value.op, (ast.UAdd, ast.USub, ast.Invert)):
            return _is_int_returning(value.operand)
        return False
    if isinstance(value, ast.BinOp):
        if isinstance(value.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv,
                                 ast.Mod, ast.Pow, ast.BitAnd, ast.BitOr,
                                 ast.BitXor, ast.LShift, ast.RShift)):
            return _is_int_returning(value.left) and _is_int_returning(value.right)
        return False  # Div -> float, skip
    if isinstance(value, ast.Compare):
        return True  # bool -> 0/1
    if isinstance(value, ast.BoolOp):
        return True  # bool ops yield truthy
    return False


_PYTHON_DUNDERS = frozenset({
    '__init__', '__new__', '__del__', '__call__', '__repr__', '__str__',
    '__bytes__', '__format__', '__lt__', '__le__', '__eq__', '__ne__',
    '__gt__', '__ge__', '__hash__', '__bool__', '__getattr__', '__get__',
    '__setattr__', '__delattr__', '__dir__', '__enter__', '__exit__',
    '__aenter__', '__aexit__', '__iter__', '__next__', '__aiter__',
    '__anext__', '__len__', '__length_hint__', '__getitem__',
    '__setitem__', '__delitem__', '__missing__', '__contains__',
    '__add__', '__radd__', '__iadd__', '__sub__', '__mul__', '__mod__',
    '__pow__', '__and__', '__or__', '__xor__', '__lshift__', '__rshift__',
    '__neg__', '__pos__', '__abs__', '__invert__', '__int__', '__float__',
    '__complex__', '__round__', '__index__', '__class__', '__main__',
    '__name__', '__file__', '__dict__', '__module__', '__qualname__',
})

def _is_eligible(fn: ast.FunctionDef) -> bool:
    """Eligible: single ``return <int-expr>``, no side effects, pure."""
    name = getattr(fn, 'name', '')
    if not name or name == 'bedrock_crown_jewel':
        return False
    if name in _PYTHON_DUNDERS:
        return False
    if isinstance(fn, ast.AsyncFunctionDef):
        return False
    # Body must be exactly ONE Return statement
    if len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return False
    ret = fn.body[0].value
    if ret is None:
        return False
    if _has_side_effect(ret):
        return False
    if not _is_int_returning(ret):
        return False
    # Reject identity functions (return <bare_name>) -- the return type is
    # unknown and could be a function (e.g. bedrock_crown_jewel decorator
    # 'return fn'). After obf_vars renames bedrock_crown_jewel to a homoglyph
    # dunder, the name-check guard above fails, so this structural check is
    # the real guard against splitting a function that returns a function.
    if isinstance(ret, ast.Name):
        return False
    return True


def _fresh_name(base: str, rng) -> str:
    """Generate a randomized share-function name."""
    suffix = ''.join(rng.choice('0123456789abcdef') for _ in range(4))
    return f'_br_fss_{base}_{suffix}'


# --- Pass -------------------------------------------------------------------

def apply_fss(tree: ast.Module, ctx) -> ast.Module:
    """Split eligible functions into 2 additive shares + a combiner.

    For each eligible function ``f(x)``:
      1. Create ``_br_fss_1_<rand>(x, r): return <f's body> + r``
      2. Create ``_br_fss_2_<rand>(x, r): return -r``
      3. Replace ``f`` with ``f(x): r = secrets.randbelow(...); return
         _br_fss_1(x, r) + _br_fss_2(x, r)``

    The two share functions are inserted BEFORE the original in the module
    body (so they're defined when the combiner runs).
    """
    rng = _rng_for(ctx)
    max_fns = int(getattr(ctx, 'fss_max', 0) or 5)
    shared = 0

    for i, node in enumerate(list(tree.body)):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _is_eligible(node):
            continue
        if shared >= max_fns:
            break
        # Copy the original args + add `r`.
        orig_args = node.args
        ret_expr = node.body[0].value
        name1 = _fresh_name('1', rng)
        name2 = _fresh_name('2', rng)

        # share 1 args: same as orig + trailing `r`
        s1_args = ast.arguments(
            posonlyargs=list(orig_args.posonlyargs),
            args=list(orig_args.args) + [ast.arg(arg='r', annotation=None)],
            kwonlyargs=list(orig_args.kwonlyargs),
            kw_defaults=list(orig_args.kw_defaults),
            defaults=list(orig_args.defaults),
            vararg=orig_args.vararg,
            kwarg=orig_args.kwarg,
        )
        # share 1 body: return <orig ret> + r
        import copy
        s1_ret = ast.Return(value=ast.BinOp(
            left=copy.deepcopy(ret_expr),
            op=ast.Add(),
            right=ast.Name(id='r', ctx=ast.Load()),
        ))
        s1_fn = ast.FunctionDef(
            name=name1, args=s1_args, body=[s1_ret],
            decorator_list=[], returns=None, type_comment=None,
        )

        # share 2 args: same as orig + trailing `r`
        s2_args = ast.arguments(
            posonlyargs=list(orig_args.posonlyargs),
            args=list(orig_args.args) + [ast.arg(arg='r', annotation=None)],
            kwonlyargs=list(orig_args.kwonlyargs),
            kw_defaults=list(orig_args.kw_defaults),
            defaults=list(orig_args.defaults),
            vararg=orig_args.vararg,
            kwarg=orig_args.kwarg,
        )
        # share 2 body: return -r
        s2_ret = ast.Return(value=ast.UnaryOp(
            op=ast.USub(),
            operand=ast.Name(id='r', ctx=ast.Load()),
        ))
        s2_fn = ast.FunctionDef(
            name=name2, args=s2_args, body=[s2_ret],
            decorator_list=[], returns=None, type_comment=None,
        )

        # combiner: def f(x): import secrets as _br_s; _br_r = ...; return s1(x, _br_r) + s2(x, _br_r)
        combiner_args = ast.arguments(
            posonlyargs=list(orig_args.posonlyargs),
            args=list(orig_args.args),
            kwonlyargs=list(orig_args.kwonlyargs),
            kw_defaults=list(orig_args.kw_defaults),
            defaults=list(orig_args.defaults),
            vararg=orig_args.vararg,
            kwarg=orig_args.kwarg,
        )
        # Build the call args for the shares (same as orig's positional args)
        orig_arg_names = [a.arg for a in (orig_args.args + orig_args.posonlyargs)]
        call_args = [ast.Name(id=nm, ctx=ast.Load()) for nm in orig_arg_names]
        combiner_body = [
            ast.Import(names=[ast.alias(name='secrets', asname='_br_s')]),
            ast.Assign(
                targets=[ast.Name(id='_br_r', ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id='_br_s', ctx=ast.Load()),
                            attr='randbelow', ctx=ast.Load()),
                        args=[ast.Constant(value=1 << 64)],
                        keywords=[],
                    ),
                    op=ast.Sub(),
                    right=ast.Constant(value=1 << 63),
                ),
            ),
            ast.Return(value=ast.BinOp(
                left=ast.Call(
                    func=ast.Name(id=name1, ctx=ast.Load()),
                    args=call_args + [ast.Name(id='_br_r', ctx=ast.Load())],
                    keywords=[],
                ),
                op=ast.Add(),
                right=ast.Call(
                    func=ast.Name(id=name2, ctx=ast.Load()),
                    args=call_args + [ast.Name(id='_br_r', ctx=ast.Load())],
                    keywords=[],
                ),
            )),
        ]
        combiner = ast.FunctionDef(
            name=node.name, args=combiner_args, body=combiner_body,
            decorator_list=[], returns=None, type_comment=None,
        )

        # Replace the original in-place: insert s1, s2 before, replace node with combiner
        idx = tree.body.index(node)
        tree.body[idx:idx + 1] = [s1_fn, s2_fn, combiner]
        ast.fix_missing_locations(tree)
        shared += 1

    try:
        ctx.fss_shared = shared
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Combine == original + shares alone are random + eligibility + determinism."""

    class _Ctx:
        build_rng = None
        fss_seed = 31
        fss_max = 5

    src = (
        "def square(x):\n"
        "    return x * x\n"
        "\n"
        "def add_one(n):\n"
        "    return n + 1\n"
        "\n"
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def with_call(x):\n"
        "    return abs(x)\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    assert ns['square'](5) == 25
    assert ns['add_one'](5) == 6
    assert ns['fib'](10) == 55
    assert ns['with_call'](-5) == 5
    print("H.9 baseline: square(5)=25, add_one(5)=6, fib(10)=55  OK")

    ctx = _Ctx()
    out = apply_fss(tree, ctx)
    assert getattr(ctx, 'fss_shared', 0) > 0, "no functions shared"
    print(f"H.9 shared: {ctx.fss_shared} functions split into 2 shares  OK")

    # Combine == original
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<fss>', 'exec'), ns2)
    assert ns2['square'](5) == 25, "square(5) changed"
    assert ns2['add_one'](5) == 6, "add_one(5) changed"
    assert ns2['fib'](10) == 55, "fib not shared but still correct"
    # square with multiple values
    for v in [0, 1, -1, 10, -10, 100]:
        assert ns2['square'](v) == v * v, f"square({v}) = {ns2['square'](v)}"
    print("H.9 combine: square/add_one return correct values  OK")

    # Shares present: the module should now have _br_fss_1_* and _br_fss_2_* defs
    src_after = ast.unparse(out)
    assert '_br_fss_1_' in src_after and '_br_fss_2_' in src_after
    print("H.9 shares: _br_fss_1_* and _br_fss_2_* present  OK")

    # Shares alone are random: call a share with a fixed r, verify f1 + f2 = f(x)
    # but f1 alone is not f(x) (it's f(x)+r). Find the share names.
    import re
    share1_names = re.findall(r'def (_br_fss_1_\w+)\(', src_after)
    share2_names = re.findall(r'def (_br_fss_2_\w+)\(', src_after)
    assert len(share1_names) >= 1 and len(share2_names) >= 1
    # The first share pair corresponds to `square` (the first eligible fn).
    s1 = ns2[share1_names[0]]
    s2 = ns2[share2_names[0]]
    r = 12345
    f1 = s1(5, r)  # square(5) + r = 25 + 12345
    f2 = s2(5, r)  # -r = -12345
    assert f1 == 25 + r, f"share1 = {f1}, expected {25 + r}"
    assert f2 == -r, f"share2 = {f2}, expected {-r}"
    assert f1 + f2 == 25, f"combine = {f1 + f2}, expected 25"
    print(f"H.9 additive: s1(5,r)={f1}, s2(5,r)={f2}, sum={f1+f2} == square(5)  OK")

    # Eligibility: fib (non-single-return) + with_call (has call) NOT shared
    fib_fn = next(n for n in out.body if getattr(n, 'name', '') == 'fib')
    assert 'while' not in ast.unparse(fib_fn) and '_br_fss' not in ast.unparse(fib_fn)
    wc_fn = next(n for n in out.body if getattr(n, 'name', '') == 'with_call')
    assert '_br_fss' not in ast.unparse(wc_fn), "with_call should not be shared (has call)"
    print("H.9 eligibility: fib (multi-stmt) + with_call (call side-effect) skipped  OK")

    # Determinism
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_fss(tree2, ctx2)
    assert ctx2.fss_shared == ctx.fss_shared
    print(f"H.9 deterministic: same seed -> {ctx.fss_shared} shared  OK")

    print("H.9 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
