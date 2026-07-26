"""Phase H.8 (Layer 6) self-checking control flow (path-hash verification).

Inject a rolling path-hash into each eligible function so that a diverted
or skipped block produces a wrong hash at function exit, triggering self-destruct.

## Kerckhoffs posture

Public technique. Per-build secret: the block IDs + the hash multiplier
(RNG-derived).

## Threat addressed

Control-flow tampering / patching. Static byte-integrity checks verify the
CODE is unchanged; CF-level self-checking verifies the EXECUTION PATH is
unchanged. An attacker who patches a branch to skip a check will produce a
wrong path hash and trigger self-destruct.

## Safety contract

- Path hash variable _br_path is a local int, initialized to 0. Each block
  XORs/multiplies its block ID into the hash. The hash does NOT affect the
  return value.
- Expected hash: pre-computed at build time for the legit path.
- Check placement: before any return statement. If mismatch, raise RuntimeError.
- Eligibility: top-level def with a LINEAR body (sequential statements, no
  if/for/while/try/yield/await).

Pure stdlib (ast, random). Run:

    python bedrock_native/_selfcheck_cf.py
"""
from __future__ import annotations

import ast
import os
import random
import sys
from typing import List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ["apply_selfcheck_cf"]

_PATH_VAR = "_br_path"
_CHECK_FN = "_br_cf_check"


def _rng_for(ctx):
    brng = getattr(ctx, "build_rng", None) or getattr(ctx, "_build_rng", None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b"phase_h_selfcheck")

        class _Wrap:
            __slots__ = ("_sub",)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

        return _Wrap(sub)
    seed = getattr(ctx, "selfcheck_seed", None)
    return random.Random(seed) if seed is not None else random.Random()


def _is_linear_body(fn):
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


def _is_eligible(fn):
    name = getattr(fn, "name", "")
    if not name or name == "bedrock_crown_jewel":
        return False
    if name.startswith("__") and name.endswith("__"):
        return False
    if isinstance(fn, ast.AsyncFunctionDef):
        return False
    if len(fn.body) < 2:
        return False
    return _is_linear_body(fn)


def _compute_expected_hash(block_ids, multiplier):
    h = 0
    for bid in block_ids:
        h = ((h * multiplier) ^ bid) & 0xFFFFFFFF
    return h


def apply_selfcheck_cf(tree, ctx):
    """Inject a rolling path-hash + exit verification into eligible functions."""
    rng = _rng_for(ctx)
    multiplier = rng.randint(17, 127)
    if multiplier % 2 == 0:
        multiplier += 1
    instrumented = 0

    for node in list(tree.body):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _is_eligible(node):
            continue
        body = list(node.body)
        n = len(body)
        block_ids = [rng.randint(1, 1 << 30) for _ in range(n)]
        expected = _compute_expected_hash(block_ids, multiplier)

        new_body = [
            ast.Assign(
                targets=[ast.Name(id=_PATH_VAR, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )
        ]
        for i, (stmt, bid) in enumerate(zip(body, block_ids)):
            hash_update = ast.Assign(
                targets=[ast.Name(id=_PATH_VAR, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Name(id=_PATH_VAR, ctx=ast.Load()),
                        op=ast.Mult(),
                        right=ast.Constant(value=multiplier),
                    ),
                    op=ast.BitXor(),
                    right=ast.Constant(value=bid),
                ),
            )
            hash_update.value = ast.BinOp(
                left=hash_update.value,
                op=ast.BitAnd(),
                right=ast.Constant(value=0xFFFFFFFF),
            )
            new_body.append(hash_update)
            new_body.append(stmt)

        check_stmt = ast.If(
            test=ast.Compare(
                left=ast.Name(id=_PATH_VAR, ctx=ast.Load()),
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=expected)],
            ),
            body=[ast.Raise(
                exc=ast.Call(
                    func=ast.Name(id="RuntimeError", ctx=ast.Load()),
                    args=[ast.Constant(value="cf path mismatch")],
                    keywords=[],
                ),
                cause=None,
            )],
            orelse=[],
        )
        if isinstance(new_body[-1], ast.Return):
            new_body.insert(-1, check_stmt)
        else:
            new_body.append(check_stmt)

        node.body = new_body
        ast.fix_missing_locations(node)
        instrumented += 1

    if instrumented > 0:
        check_stub = ast.parse("def %s(_h, _e):\n    pass\n" % _CHECK_FN).body[0]
        tree.body.append(check_stub)
        ast.fix_missing_locations(tree)

    try:
        ctx.selfcheck_instrumented = instrumented
        ctx.selfcheck_multiplier = multiplier
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke():
    """Legit path passes + behavior identical + tampered path triggers
    self-destruct + eligibility + determinism."""

    class _Ctx:
        build_rng = None
        selfcheck_seed = 23

    src = (
        "def compute(n):\n"
        "    x = n + 1\n"
        "    y = x * 2\n"
        "    z = y - 3\n"
        "    return z\n"
        "\n"
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def short(n):\n"
        "    return n\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), "<base>", "exec"), ns)
    assert ns["compute"](5) == 9
    assert ns["fib"](10) == 55
    assert ns["short"](5) == 5
    print("H.8 baseline: compute(5)=9, fib(10)=55, short(5)=5  OK")

    ctx = _Ctx()
    out = apply_selfcheck_cf(tree, ctx)
    assert getattr(ctx, "selfcheck_instrumented", 0) > 0
    print(f"H.8 instrumented: {ctx.selfcheck_instrumented} funcs, mult={ctx.selfcheck_multiplier}  OK")

    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), "<sc>", "exec"), ns2)
    assert ns2["compute"](5) == 9
    assert ns2["fib"](10) == 55
    assert ns2["short"](5) == 5
    print("H.8 legit path: behavior identical  OK")

    compute_fn = next(n for n in out.body if getattr(n, "name", "") == "compute")
    src_c = ast.unparse(compute_fn)
    assert _PATH_VAR in src_c
    assert "cf path mismatch" in src_c
    print("H.8 path-hash: _br_path + check present  OK")

    fib_fn = next(n for n in out.body if getattr(n, "name", "") == "fib")
    assert _PATH_VAR not in ast.unparse(fib_fn)
    short_fn = next(n for n in out.body if getattr(n, "name", "") == "short")
    assert _PATH_VAR not in ast.unparse(short_fn)
    print("H.8 eligibility: fib (non-linear) + short skipped  OK")

    import copy
    tampered = copy.deepcopy(out)
    for n in ast.walk(tampered):
        if isinstance(n, ast.If) and isinstance(n.test, ast.Compare):
            if isinstance(n.test.comparators[0], ast.Constant):
                n.test.comparators[0].value = 0xDEADBEEF
    ns3 = {}
    exec(compile(ast.Module(body=tampered.body, type_ignores=[]), "<t>", "exec"), ns3)
    try:
        ns3["compute"](5)
        raise AssertionError("tampered path should raise")
    except RuntimeError as e:
        assert "cf path mismatch" in str(e)
    print("H.8 tampered: mismatched hash -> RuntimeError  OK")

    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_selfcheck_cf(tree2, ctx2)
    assert ctx2.selfcheck_multiplier == ctx.selfcheck_multiplier
    print(f"H.8 deterministic: same seed -> mult={ctx.selfcheck_multiplier}  OK")
    print("H.8 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
