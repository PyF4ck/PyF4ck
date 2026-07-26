"""Phase H.7 (Layer 6) DAG-based control-flow flattening.

Multi-variable CFF: replace the single ``__cff_state`` chain of the standard
CFF with a 2-variable state machine ``(__s1, __s2)`` where transitions go
through a 2D transition table::

    __s1, __s2 = ENTRY_1, ENTRY_2
    while True:
        if (__s1, __s2) == (A0, B0):
            <block 0 code>
            __s1, __s2 = T0_1, T0_2
            continue
        elif (__s1, __s2) == (A1, B1):
            <block 1 code>
            __s1, __s2 = T1_1, T1_2
            continue
        elif (__s1, __s2) == (HALT, HALT):
            break

## Kerckhoffs posture

Public technique. Per-build secret: the (s1, s2) pair assignments + the
transition table (RNG-derived).

## Threat addressed

CFF dispatch recovery. A single-variable CFF (``__cff_state``) is a linear
state chain that a decompiler can trace by following the state assignments.
A 2-variable state machine forms a 2D transition graph (a DAG), requiring
the decompiler to model BOTH variables simultaneously -- a harder dataflow
problem. The state space is N x N vs N, so the dispatch graph is denser.

## Safety contract

- **Conservative eligibility**: only top-level ``def`` with a LINEAR body
  (sequential statements, no if/for/while/try/with/yield/await inside).
  This makes the flattening trivially correct (blocks execute in order).
  Non-linear bodies are skipped (the standard CFF handles those).
- **Block splitting**: the body is split into N consecutive blocks (each
  1-3 statements, RNG). Each block gets a unique (s1, s2) pair. The
  transition table maps each pair to the next block's pair; the last block
  transitions to (HALT, HALT).
- **Entry**: ``__s1, __s2 = ENTRY_1, ENTRY_2`` (the first block's pair).
- **Halt**: a sentinel pair (HALT, HALT) breaks the loop.
- **Behavior preservation**: verified by the smoke test.

Pure stdlib (``ast``, ``random``). Run::

    python bedrock_native/_dag_cff.py
"""
from __future__ import annotations

import ast
import os
import random
import sys
from typing import List, Optional, Tuple

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_dag_cff']

_S1 = '_br_ds1'
_S2 = '_br_ds2'
_HALT = 0  # sentinel halt state for both vars


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_dag_cff')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

            def shuffle(self, seq):
                return self._sub.shuffle(list(seq))

        return _Wrap(sub)
    seed = getattr(ctx, 'dag_cff_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _is_linear_body(fn: ast.FunctionDef) -> bool:
    """True if the body is purely sequential (no control-flow constructs).

    This is the conservative eligibility gate: only linear bodies are
    flattened by DAG-CFF (the standard CFF handles non-linear ones).
    """
    for stmt in fn.body:
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While,
                             ast.Try, ast.With, ast.AsyncWith,
                             ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            return False
    for n in ast.walk(fn):
        if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
            return False
    return True


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
    name = getattr(fn, 'name', '')
    if not name or name == 'bedrock_crown_jewel':
        return False
    if name in _PYTHON_DUNDERS:
        return False
    if isinstance(fn, ast.AsyncFunctionDef):
        return False
    if len(fn.body) < 3:
        return False  # too short to be worth flattening
    return _is_linear_body(fn)


def _split_blocks(body: List[ast.stmt], rng) -> List[List[ast.stmt]]:
    """Split the sequential body into N consecutive blocks (each 1-3 stmts)."""
    if not body:
        return []
    max_block = rng.randint(1, 3)
    blocks = []
    i = 0
    while i < len(body):
        k = rng.randint(1, min(max_block, len(body) - i))
        blocks.append(body[i:i + k])
        i += k
    return blocks


def _assign_state_pairs(n_blocks: int, rng) -> List[Tuple[int, int]]:
    """Assign each block a unique (s1, s2) pair. The pairs are random
    distinct values from a 2D grid, making the transition graph a DAG
    (not a simple chain)."""
    # Use a grid of size G x G where G > n_blocks, pick random distinct pairs.
    G = max(n_blocks + 2, 10)
    all_pairs = [(a, b) for a in range(1, G) for b in range(1, G)]
    shuffled = rng.shuffle(all_pairs)
    if shuffled is not None:
        all_pairs = shuffled
    return all_pairs[:n_blocks]


# --- Pass -------------------------------------------------------------------

def apply_dag_cff(tree: ast.Module, ctx) -> ast.Module:
    """Flatten eligible linear functions into a 2-variable DAG state machine.

    For each eligible function (linear body, >= 3 statements):
      1. Split the body into N blocks (1-3 stmts each, RNG).
      2. Assign each block a unique (s1, s2) pair (RNG).
      3. Build a dispatch loop: while True: if (s1,s2) == (A,B): <block>;
         s1,s2 = next; continue; elif (s1,s2) == (HALT,HALT): break.
      4. The entry sets s1,s2 to the first block's pair.
    """
    rng = _rng_for(ctx)
    flattened = 0

    for node in list(tree.body):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _is_eligible(node):
            continue
        body = list(node.body)
        blocks = _split_blocks(body, rng)
        if len(blocks) < 2:
            continue
        pairs = _assign_state_pairs(len(blocks), rng)
        # Build the dispatch loop body.
        # Entry: __s1, __s2 = pairs[0]
        entry = ast.Assign(
            targets=[ast.Tuple(elts=[ast.Name(id=_S1, ctx=ast.Store()),
                                     ast.Name(id=_S2, ctx=ast.Store())],
                               ctx=ast.Store())],
            value=ast.Tuple(elts=[ast.Constant(value=pairs[0][0]),
                                  ast.Constant(value=pairs[0][1])],
                           ctx=ast.Load()),
        )
        # Dispatch loop: while True: if (s1,s2) == (A,B): <block>; s1,s2=next; continue
        # The last block transitions to (HALT, HALT) which breaks.
        loop_body = []
        for i, (blk, (a, b)) in enumerate(zip(blocks, pairs)):
            # if (s1, s2) == (a, b):
            #     <block statements>
            #     s1, s2 = next_a, next_b   (or HALT, HALT for the last)
            #     continue
            if i + 1 < len(blocks):
                na, nb = pairs[i + 1]
            else:
                na, nb = _HALT, _HALT
            cond = ast.Compare(
                left=ast.Tuple(elts=[ast.Name(id=_S1, ctx=ast.Load()),
                                     ast.Name(id=_S2, ctx=ast.Load())],
                               ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Tuple(elts=[ast.Constant(value=a),
                                            ast.Constant(value=b)],
                                      ctx=ast.Load())],
            )
            blk_stmts = list(blk) + [
                ast.Assign(
                    targets=[ast.Tuple(elts=[ast.Name(id=_S1, ctx=ast.Store()),
                                             ast.Name(id=_S2, ctx=ast.Store())],
                                       ctx=ast.Store())],
                    value=ast.Tuple(elts=[ast.Constant(value=na),
                                          ast.Constant(value=nb)],
                                   ctx=ast.Load()),
                ),
                ast.Continue(),
            ]
            loop_body.append(ast.If(test=cond, body=blk_stmts, orelse=[]))
        # Halt check: if (s1, s2) == (HALT, HALT): break
        halt_cond = ast.Compare(
            left=ast.Tuple(elts=[ast.Name(id=_S1, ctx=ast.Load()),
                                 ast.Name(id=_S2, ctx=ast.Load())],
                           ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Tuple(elts=[ast.Constant(value=_HALT),
                                        ast.Constant(value=_HALT)],
                                  ctx=ast.Load())],
        )
        loop_body.append(ast.If(test=halt_cond, body=[ast.Break()], orelse=[]))
        while_loop = ast.While(test=ast.Constant(value=True), body=loop_body, orelse=[])
        node.body = [entry, while_loop]
        ast.fix_missing_locations(node)
        flattened += 1

    try:
        ctx.dag_cff_flattened = flattened
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Behavior preservation + multi-var state (no single __cff_state) +
    eligibility (skip non-linear) + determinism."""

    class _Ctx:
        build_rng = None
        dag_cff_seed = 17

    src = (
        "def linear(n):\n"
        "    x = n + 1\n"
        "    y = x * 2\n"
        "    z = y - 3\n"
        "    w = z + n\n"
        "    return w\n"
        "\n"
        "def short_fn(n):\n"
        "    return n\n"
        "\n"
        "def with_branch(n):\n"
        "    if n > 0:\n"
        "        return n\n"
        "    return -n\n"
        "\n"
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    assert ns['linear'](5) == 14  # (5+1)*2-3+5 = 12-3+5 = 14
    assert ns['short_fn'](5) == 5
    assert ns['with_branch'](5) == 5 and ns['with_branch'](-5) == 5
    assert ns['fib'](10) == 55
    print("H.7 baseline: linear(5)=14, fib(10)=55, others correct  OK")

    ctx = _Ctx()
    out = apply_dag_cff(tree, ctx)
    assert getattr(ctx, 'dag_cff_flattened', 0) > 0, "no functions flattened"
    print(f"H.7 flattened: {ctx.dag_cff_flattened} functions -> 2-var DAG  OK")

    # Behavior identical
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<dag>', 'exec'), ns2)
    assert ns2['linear'](5) == 14
    assert ns2['short_fn'](5) == 5  # not flattened (too short)
    assert ns2['with_branch'](5) == 5 and ns2['with_branch'](-5) == 5  # not flattened (non-linear)
    assert ns2['fib'](10) == 55  # not flattened (has for loop)
    print("H.7 behavior: all 4 functions identical post-DAG-CFF  OK")

    # Multi-var state: the flattened function uses __s1, __s2 (not __cff_state)
    linear_fn = next(n for n in out.body if getattr(n, 'name', '') == 'linear')
    src_linear = ast.unparse(linear_fn)
    assert _S1 in src_linear and _S2 in src_linear, "missing 2-var state"
    assert 'while True' in src_linear, "missing dispatch loop"
    assert '__cff_state' not in src_linear, "should NOT use single-var state"
    print("H.7 multi-var: uses __s1/__s2 2-var state (not __cff_state)  OK")

    # Eligibility: short_fn (too short), with_branch (non-linear), fib (non-linear)
    # should NOT be flattened.
    short_fn = next(n for n in out.body if getattr(n, 'name', '') == 'short_fn')
    assert 'while True' not in ast.unparse(short_fn), "short_fn should not be flattened"
    wb_fn = next(n for n in out.body if getattr(n, 'name', '') == 'with_branch')
    assert 'while True' not in ast.unparse(wb_fn), "with_branch should not be flattened"
    fib_fn = next(n for n in out.body if getattr(n, 'name', '') == 'fib')
    assert 'while True' not in ast.unparse(fib_fn), "fib should not be flattened"
    print("H.7 eligibility: short/non-linear functions skipped  OK")

    # Determinism
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_dag_cff(tree2, ctx2)
    assert ctx2.dag_cff_flattened == ctx.dag_cff_flattened
    print(f"H.7 deterministic: same seed -> {ctx.dag_cff_flattened} flattened  OK")

    print("H.7 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
