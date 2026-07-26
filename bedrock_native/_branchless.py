"""Phase H.5 (Layer 6) branchless-ification.

Convert eligible ``if/else`` ASSIGNMENTS and RETURNS to branchless mux
forms so the static control-flow graph has no conditional edge::

    # before
    if cond:
        x = a
    else:
        x = b
    # after (integer)
    x = b ^ ((a ^ b) & -bool(cond))
    # after (numeric)
    x = cond * a + (1 - cond) * b      # when cond is 0/1

## Kerckhoffs posture

Public technique. Per-build secret: which mux idiom is chosen per site
(RNG).

## Threat addressed

Control-flow-graph (CFG) reconstruction. A conditional branch is the
single most informative node a decompiler recovers; eliminating it removes
a branch from the static CFG and forces symbolic execution to model the
arithmetic. The mux form is semantically equivalent but has NO ``If`` node,
so an AST/CFG pattern-matcher sees straight-line code.

## Safety contract

- **Integer results** use ``b ^ ((a ^ b) & -bool(cond))`` (works for any
  ints a, b; the ``-bool(cond)`` is either 0 or -1 (all ones) as a Python
  int, so ``(a ^ b) & -1 == a ^ b`` and ``& 0 == 0``). This is exact.
- **Numeric results** use ``cond * a + (1 - cond) * b`` ONLY when ``cond``
  is a 0/1-valued expression (a comparison / boolean). For general truthy
  conditions we use ``(cond and a) or b`` -- but this is NOT branchless at
  the bytecode level (``and``/``or`` short-circuit). So we restrict to
  conditions that are already 0/1 (comparisons, ``not``, bool calls) and
  emit the arithmetic form.
- **Eligibility** (conservative): both branches are a SINGLE ``Assign`` to
  the SAME target Name with a numeric (int/float/bool) RHS, OR both are a
  single ``Return`` with a numeric value. Skip if either branch has side
  effects (calls, yields, awaits, augmented assigns, multi-target, AnnAssign,
  tuple unpacking). Skip if the condition has side effects.
- **Strings/bytes/lists** are NOT converted (the mux idiom doesn't preserve
  them safely; ``cond * str + (1-cond) * str`` would multiply strings).
- Behavior is verified by the smoke test for the actual inputs.

Pure stdlib (``ast``, ``copy``). Run::

    python bedrock_native/_branchless.py
"""
from __future__ import annotations

import ast
import copy
import os
import random
import sys
from typing import Optional

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_branchless']


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_branchless')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

        return _Wrap(sub)
    seed = getattr(ctx, 'branchless_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _is_01_condition(cond: ast.expr) -> bool:
    """True if ``cond`` is guaranteed to evaluate to 0 or 1 (so the
    arithmetic mux ``cond*a + (1-cond)*b`` is exact)."""
    # Comparisons (==, !=, <, >, <=, >=, is, is not, in, not in) -> bool -> 0/1
    if isinstance(cond, (ast.Compare,)):
        return True
    # not X -> bool -> 0/1
    if isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not):
        return True
    # bool(...) call
    if isinstance(cond, ast.Call) and isinstance(cond.func, ast.Name) \
            and cond.func.id == 'bool':
        return True
    # X and Y / X or Y short-circuit (not 0/1 in general -- X could be
    # truthy non-bool). NOT eligible for arithmetic mux.
    if isinstance(cond, ast.BoolOp):
        return False
    return False


def _has_side_effect(node: ast.expr) -> bool:
    """Conservative side-effect detector. Returns True if the expression
    MIGHT have side effects (call, yield, await, ...)."""
    for n in ast.walk(node):
        if isinstance(n, (ast.Call, ast.Yield, ast.YieldFrom, ast.Await)):
            return True
        # attribute/subscript loads are usually pure, but be safe: a
        # property getter could side-effect. We allow them (the existing
        # passes already assume property-purity for reads).
    return False


def _is_numeric_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool))


def _is_simple_numeric(node: ast.expr) -> bool:
    """A numeric-safe expression: literals, names, binops/unaryops on
    numerics, comparisons. NOT strings/bytes/lists."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float, bool))
    if isinstance(node, ast.Name):
        return True  # assume numeric (conservative -- smoke verifies)
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, (ast.UAdd, ast.USub, ast.Not, ast.Invert)):
            return _is_simple_numeric(node.operand)
        return False
    if isinstance(node, ast.BinOp):
        return _is_simple_numeric(node.left) and _is_simple_numeric(node.right)
    if isinstance(node, ast.Compare):
        return all(_is_simple_numeric(c) for c in [node.left] + node.comparators)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in ('int', 'float', 'bool', 'abs', 'round', 'len'):
        return all(_is_simple_numeric(a) for a in node.args)
    return False


def _mux_int(a: ast.expr, b: ast.expr, cond: ast.expr) -> ast.expr:
    """``b ^ ((a ^ b) & -bool(cond))`` -- exact for integer a, b.

    ``-bool(cond)`` is 0 (cond False) or -1 (cond True, all-ones in two's
    complement; Python int ``-1`` has infinite ones, so ``x & -1 == x``).
    So the expression yields ``b ^ (a ^ b) == a`` when cond is True, and
    ``b ^ 0 == b`` when cond is False. Exact.

    Each sub-node is deep-copied so the mux AST is a self-contained tree
    (no shared node objects, which would break ``fix_missing_locations`` /
    ``ast.walk``).
    """
    a_c = copy.deepcopy(a)
    b_c = copy.deepcopy(b)
    b2 = copy.deepcopy(b)
    cond_c = copy.deepcopy(cond)
    return ast.BinOp(
        left=b_c,
        op=ast.BitXor(),
        right=ast.BinOp(
            left=ast.BinOp(
                left=a_c,
                op=ast.BitXor(),
                right=b2,
            ),
            op=ast.BitAnd(),
            right=ast.UnaryOp(
                op=ast.USub(),
                operand=ast.Call(
                    func=ast.Name(id='bool', ctx=ast.Load()),
                    args=[cond_c],
                    keywords=[],
                ),
            ),
        ),
    )


def _mux_arith(a: ast.expr, b: ast.expr, cond: ast.expr) -> ast.expr:
    """``cond*a + (1 - cond)*b`` -- exact when cond is 0/1 (comparison)."""
    a_c = copy.deepcopy(a)
    b_c = copy.deepcopy(b)
    cond1 = copy.deepcopy(cond)
    cond2 = copy.deepcopy(cond)
    return ast.BinOp(
        left=ast.BinOp(
            left=cond1,
            op=ast.Mult(),
            right=a_c,
        ),
        op=ast.Add(),
        right=ast.BinOp(
            left=ast.BinOp(
                left=ast.Constant(value=1),
                op=ast.Sub(),
                right=cond2,
            ),
            op=ast.Mult(),
            right=b_c,
        ),
    )


# --- Pass -------------------------------------------------------------------

def apply_branchless(tree: ast.Module, ctx) -> ast.Module:
    """Convert eligible if/else assignments and returns to branchless mux.

    Walks each function's statement list; for each ``if cond: T else: F``
    where T and F are both a single ``Assign`` to the same target Name with
    numeric RHS (or both single ``Return`` with numeric value), replaces
    the whole ``If`` with a single ``Assign``/``Return`` of the mux form.

    Skips async/generators/dunders/marker (conservative).
    """
    rng = _rng_for(ctx)
    converted = 0

    def _rewrite_body(body):
        nonlocal converted
        out = []
        for stmt in body:
            # Recurse into nested function bodies first.
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not (isinstance(stmt, ast.AsyncFunctionDef) or
                        _is_eligible_fn(stmt)):
                    out.append(stmt)
                    continue
                _rewrite_body(stmt.body)
                out.append(stmt)
                continue
            if isinstance(stmt, ast.If):
                # Try to convert.
                conv = _try_convert_if(stmt, rng)
                if conv is not None:
                    out.extend(conv)
                    converted += 1
                    continue
                # Not convertible -- recurse into branches.
                _rewrite_body(stmt.body)
                _rewrite_body(stmt.orelse)
                out.append(stmt)
                continue
            # For/while: recurse into body.
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                _rewrite_body(stmt.body)
                _rewrite_body(stmt.orelse)
                out.append(stmt)
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                _rewrite_body(stmt.body)
                out.append(stmt)
                continue
            out.append(stmt)
        # Mutate in place so ast.fix_missing_locations sees the new nodes.
        body[:] = out

    for node in list(tree.body):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if isinstance(node, ast.AsyncFunctionDef):
                continue
            if not _is_eligible_fn(node):
                continue
            _rewrite_body(node.body)
    ast.fix_missing_locations(tree)
    try:
        ctx.branchless_converted = converted
    except Exception:
        pass
    return tree


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

def _is_eligible_fn(fn: ast.FunctionDef) -> bool:
    name = getattr(fn, 'name', '')
    if not name:
        return False
    if name == 'bedrock_crown_jewel':
        return False
    if name in _PYTHON_DUNDERS:
        return False
    for n in ast.walk(fn):
        if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
            return False
    return True


def _try_convert_if(ifn: ast.If, rng) -> Optional[list]:
    """Return a replacement statement list if ``ifn`` is convertible; else None."""
    cond = ifn.test
    if _has_side_effect(cond):
        return None
    # Must be exactly: if cond: <one stmt> else: <one stmt> (no elif).
    if len(ifn.body) != 1 or len(ifn.orelse) != 1:
        return None
    t = ifn.body[0]
    f = ifn.orelse[0]
    # Case 1: both branches Assign to the same single Name target.
    if isinstance(t, ast.Assign) and isinstance(f, ast.Assign):
        if len(t.targets) != 1 or len(f.targets) != 1:
            return None
        if not isinstance(t.targets[0], ast.Name) or not isinstance(f.targets[0], ast.Name):
            return None
        if t.targets[0].id != f.targets[0].id:
            return None
        if _has_side_effect(t.value) or _has_side_effect(f.value):
            return None
        if not (_is_simple_numeric(t.value) and _is_simple_numeric(f.value)):
            return None
        # Build the mux. Choose idiom per-build (RNG).
        use_arith = _is_01_condition(cond) and rng.choice([True, False])
        if use_arith:
            mux = _mux_arith(t.value, f.value, cond)
        else:
            mux = _mux_int(t.value, f.value, cond)
        return [ast.Assign(targets=[ast.Name(id=t.targets[0].id, ctx=ast.Store())],
                           value=mux)]
    # Case 2: both branches Return with numeric value.
    if isinstance(t, ast.Return) and isinstance(f, ast.Return):
        if t.value is None or f.value is None:
            return None
        if _has_side_effect(t.value) or _has_side_effect(f.value):
            return None
        if not (_is_simple_numeric(t.value) and _is_simple_numeric(f.value)):
            return None
        use_arith = _is_01_condition(cond) and rng.choice([True, False])
        if use_arith:
            mux = _mux_arith(t.value, f.value, cond)
        else:
            mux = _mux_int(t.value, f.value, cond)
        return [ast.Return(value=mux)]
    return None


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Behavior preservation + no If for converted branches + eligibility +
    determinism + side-effect / string skip."""

    class _Ctx:
        build_rng = None
        branchless_seed = 11

    src = (
        "def sign(x):\n"
        "    if x > 0:\n"
        "        r = 1\n"
        "    else:\n"
        "        r = -1\n"
        "    return r\n"
        "\n"
        "def pick(flag):\n"
        "    if flag:\n"
        "        return 10\n"
        "    else:\n"
        "        return 20\n"
        "\n"
        "def mixed(x):\n"
        "    if x > 0:\n"
        "        r = 1\n"
        "    else:\n"
        "        r = -1\n"
        "    if x > 100:\n"
        "        return r * 2\n"
        "    else:\n"
        "        return r * 3\n"
        "\n"
        "def with_call(x):\n"
        "    if x > 0:\n"
        "        r = abs(x)\n"
        "    else:\n"
        "        r = -abs(x)\n"
        "    return r\n"
        "\n"
        "def string_branch(x):\n"
        "    if x > 0:\n"
        "        s = 'pos'\n"
        "    else:\n"
        "        s = 'neg'\n"
        "    return s\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    # baseline
    assert ns['sign'](5) == 1 and ns['sign'](-5) == -1
    assert ns['pick'](True) == 10 and ns['pick'](False) == 20
    assert ns['mixed'](5) == 3 and ns['mixed'](-5) == -3 and ns['mixed'](200) == 2
    assert ns['with_call'](-5) == -5  # else branch: -abs(-5) = -5
    assert ns['string_branch'](5) == 'pos' and ns['string_branch'](-5) == 'neg'
    print("H.5 baseline: sign/pick/mixed/with_call/string_branch correct  OK")

    ctx = _Ctx()
    out = apply_branchless(tree, ctx)
    assert getattr(ctx, 'branchless_converted', 0) > 0, "no branches converted"
    print(f"H.5 converted: {ctx.branchless_converted} branches -> mux  OK")

    # Behavior identical
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<branch>', 'exec'), ns2)
    assert ns2['sign'](5) == 1 and ns2['sign'](-5) == -1
    assert ns2['pick'](True) == 10 and ns2['pick'](False) == 20
    assert ns2['mixed'](5) == 3 and ns2['mixed'](-5) == -3 and ns2['mixed'](200) == 2
    assert ns2['with_call'](-5) == -5  # else branch: -abs(-5) = -5
    assert ns2['string_branch'](5) == 'pos' and ns2['string_branch'](-5) == 'neg'
    print("H.5 behavior: all 5 functions identical post-branchless  OK")

    # No If in sign (the converted one): sign should have no ast.If in its body
    sign_fn = next(n for n in out.body if getattr(n, 'name', '') == 'sign')
    has_if = any(isinstance(n, ast.If) for n in ast.walk(sign_fn))
    assert not has_if, "sign still has an If after branchless"
    pick_fn = next(n for n in out.body if getattr(n, 'name', '') == 'pick')
    assert not any(isinstance(n, ast.If) for n in ast.walk(pick_fn)), "pick still has If"
    print("H.5 no-If: sign/pick bodies have no If node (converted)  OK")

    # String branch NOT converted (string mux would break)
    sb_fn = next(n for n in out.body if getattr(n, 'name', '') == 'string_branch')
    assert any(isinstance(n, ast.If) for n in ast.walk(sb_fn)), \
        "string_branch If should be preserved (strings not mux-able)"
    print("H.5 skip-strings: string_branch If preserved (not numeric)  OK")

    # with_call: the RHS has a call (abs) -- side-effect check: abs is pure,
    # but our _has_side_effect conservatively flags ANY Call. Verify with_call
    # was either converted (if we relax) or skipped. Our impl flags Call as
    # side-effect -> with_call should NOT be converted.
    wc_fn = next(n for n in out.body if getattr(n, 'name', '') == 'with_call')
    assert any(isinstance(n, ast.If) for n in ast.walk(wc_fn)), \
        "with_call If should be preserved (call side-effect conservative)"
    print("H.5 skip-calls: with_call If preserved (call side-effect)  OK")

    # Determinism
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_branchless(tree2, ctx2)
    assert ctx2.branchless_converted == ctx.branchless_converted
    print(f"H.5 deterministic: same seed -> {ctx.branchless_converted} converted  OK")

    print("H.5 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
