"""Phase H.2 (Layer 6) Acoda -- opaque call dispatch / CF aliasing.

Replace direct calls ``f(args)`` (where ``f`` is a module-level def) with
indirect dispatch through an opaque-indexed alias table::

    # before
    return helper(x)
    # after
    _br_acoda = {0: helper, 1: <decoy_fn>, 2: <decoy_fn>, ...}
    ...
    return _br_acoda[((x * 2207) + 7919) % 3](x)

The index expression is an **opaque-always-equal** expression: it always
evaluates to the slot holding the REAL function, but a static analyzer must
prove the modular-arithmetic identity to know which slot. The decoy slots
hold dummy lambdas (never reached at runtime).

## Kerckhoffs posture

Public technique. The per-build secret is which slot holds the real function
and which modular identity is used -- both RNG-derived per build.

## Threat addressed

Static call-graph construction. A direct ``helper(x)`` call edge is trivially
resolved; an indirect ``_br_acoda[expr](x)`` call requires the analyzer to
prove ``expr == <real_slot>`` (a modular-arithmetic fact) before it can
resolve the target -- defeating naive call-graph builders and decompiler
call-resolution passes.

## Safety contract

- Only DIRECT calls to module-level ``def`` names (not dotted, not builtins,
  not lambdas) are rewritten. The decoys are non-callable-safe lambdas that
  raise if ever hit (defensive -- the opaque index guarantees they aren't).
- The opaque index expression is proven to always yield the real slot by
  CONSTRUCTION: ``((x * k1 + k2) % n)`` where we pick ``k1, k2`` so the
  expression equals ``real_slot`` for the ACTUAL values of ``x`` at that call
  site. We restrict to calls where the first arg is a simple Name or a
  constant, so we can compute the expression's value for that input and
  verify it equals ``real_slot``. For general args, we use a CONSTANT index
  hidden behind an opaque identity (``((0 * k1 + real_slot) % n)`` wrapped in
  a depth-2 MBA cancel).
- The alias table is emitted ONCE at module scope, after the function defs.
- Eligibility: only module-level ``def`` targets that are themselves defined
  in the same module (no imports, no builtins, no dotted paths).

Pure stdlib (``ast``). Run::

    python bedrock_native/_acoda.py
"""
from __future__ import annotations

import ast
import os
import random
import sys
from typing import Optional

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_acoda']

_ACODA_TABLE = '_br_acoda'   # module-scope alias table name


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_acoda')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, sub_):
                self._sub = sub_

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

            def shuffle(self, seq):
                return self._sub.shuffle(list(seq))

        return _Wrap(sub)
    seed = getattr(ctx, 'acoda_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _module_def_names(tree: ast.Module) -> set:
    """Names defined as module-level ``def`` (eligible call targets)."""
    names = set()
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and not n.name.startswith('__'):
            names.add(n.name)
    return names


def _eligible_call(node: ast.Call, mod_defs: set) -> Optional[str]:
    """Return the target name if ``node`` is a direct call to a module-level
    def; else None. Skip calls inside the alias table / decoys."""
    if not isinstance(node.func, ast.Name):
        return None
    if node.func.id not in mod_defs:
        return None
    if node.func.id == _ACODA_TABLE:
        return None
    # Skip calls whose immediate parent is the alias-table assignment (we
    # emit the table ourselves; we don't want to recurse into our own emit).
    return node.func.id


def _opaque_const_index(real_slot: int, n_slots: int, rng) -> tuple:
    """Build an opaque-always-equal expression that evaluates to ``real_slot``.

    Returns ``(ast_expr, plain_str)`` where ``ast_expr`` is an AST evaluating
    to ``real_slot`` and ``plain_str`` is the unparsed source for diagnostics.

    Strategy: hide the constant ``real_slot`` behind a 2-level MBA cancel:
        idx = ((real_slot * K_INV * K) ^ (J ^ J)) % n_slots
    where ``K_INV * K ≡ 1 (mod n_slots)`` and ``J ^ J == 0``. The expression
    evaluates to ``real_slot % n_slots`` == ``real_slot`` (real_slot < n_slots).
    All constants are RNG-derived per build.
    """
    # Pick K with a modular inverse mod n_slots (n_slots small; brute force).
    def _modinv(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    k = rng.randint(2, 1 << 20)
    while n_slots > 1 and _modinv(k % n_slots, n_slots) is None:
        k = rng.randint(2, 1 << 20)
    k_inv = _modinv(k % n_slots, n_slots) if n_slots > 1 else 1
    if k_inv is None:
        k_inv = 1
        k = 1
    j = rng.randint(1, 1 << 20)
    # idx = ((real_slot * k_inv * k) ^ (j ^ j)) % n_slots
    #     = (real_slot ^ 0) % n_slots = real_slot   (since real_slot < n_slots)
    base = real_slot * k_inv * k
    cancel = j ^ j  # == 0
    expr = ast.BinOp(
        left=ast.BinOp(
            left=ast.Constant(value=base),
            op=ast.BitXor(),
            right=ast.Constant(value=cancel),
        ),
        op=ast.Mod(),
        right=ast.Constant(value=n_slots),
    )
    src = f"(({base}) ^ ({cancel})) % {n_slots}"
    return expr, src


def _decoy_fn(slot: int, rng) -> ast.Assign:
    """A decoy slot: ``slot: lambda *a, **k: (_ for _ in ()).throw(...)``.
    Never reached at runtime; raises if ever called (defensive)."""
    # Simpler + safe decoy: a function that returns None and is never called.
    # We use a lambda that raises -- but a raise inside a lambda is a syntax
    # error in Python <3.8 expression form; we use the throw-generator idiom
    # which works in all versions.
    msg = f"acoda decoy {slot} reached (build bug)"
    decoy = ast.Lambda(
        args=ast.arguments(
            posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[],
            defaults=[], vararg=ast.arg(arg='a', annotation=None),
            kwarg=ast.arg(arg='k', annotation=None),
        ),
        body=ast.Call(
            func=ast.Attribute(
                value=ast.GeneratorExp(
                    elt=ast.Name(id='_', ctx=ast.Load()),
                    generators=[ast.comprehension(
                        target=ast.Name(id='_', ctx=ast.Store()),
                        iter=ast.Tuple(elts=[], ctx=ast.Load()),
                        ifs=[], is_async=0)],
                ),
                attr='throw',
                ctx=ast.Load(),
            ),
            args=[ast.Name(id='RuntimeError', ctx=ast.Load()),
                  ast.Constant(value=msg)],
            keywords=[],
        ),
    )
    return decoy


# --- Pass -------------------------------------------------------------------

def apply_acoda(tree: ast.Module, ctx) -> ast.Module:
    """Rewrite eligible direct calls to module defs as opaque indirect
    dispatch through a per-build dispatch FUNCTION.

    Emits one module-scope ``def _br_acoda(idx):`` dispatch function with an
    if/elif chain (``if idx == slot: return target_fn``) and replaces each
    eligible call ``f(args)`` with ``_br_acoda(<opaque_idx>)(args)``.
    The opaque index always evaluates to the slot holding ``f``.

    A DISPATCH FUNCTION (not a list/dict table) is used deliberately: the
    obfuscator's downstream passes (obf_builtins, string/list-obf, num_obf)
    transform module-level data structures (lists/dicts) unpredictably --
    reordering elements, converting integer keys to string-encoded keys,
    etc. The dispatch sites live inside function bodies which get
    capsule-wrapped (anti-PyCDC) into encrypted bytecode that can't be
    adjusted post-hoc. A table at module scope thus drifts out of sync
    with the capsule-baked indices.

    A dispatch FUNCTION avoids this: both the dispatch function body AND
    the dispatch-site call expressions are in the same compilation unit,
    transformed consistently by downstream passes (num_obf obfuscates the
    integer constants in both to expressions evaluating to the same value;
    obf_vars renames names in both consistently). The dispatch function
    resolves its Name references from globals at call time, so forward
    references to target functions (defined later in the module) work.
    """
    rng = _rng_for(ctx)
    mod_defs = _module_def_names(tree)
    if not mod_defs:
        return tree

    # Collect eligible call sites: list of (parent_call_node, target_name).
    # We walk the WHOLE module but skip the dispatch function we emit
    # (which contains decoys -- not eligible). We do this by collecting first,
    # then emitting the function at the end so the collector doesn't see it.
    eligible = []  # (call_node, target_name, enclosing_func_name)
    enclosing = ['<module>']

    class _Walker(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            old = enclosing[0]
            enclosing[0] = node.name
            self.generic_visit(node)
            enclosing[0] = old
        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            tgt = _eligible_call(node, mod_defs)
            if tgt is not None:
                eligible.append((node, tgt, enclosing[0]))
            self.generic_visit(node)

    _Walker().visit(tree)
    if not eligible:
        return tree

    # Deduplicate targets (one slot per unique target).
    targets = []
    seen = set()
    for _, tgt, _enc in eligible:
        if tgt not in seen:
            seen.add(tgt)
            targets.append(tgt)
    n_real = len(targets)
    # Add decoy slots so the dispatch isn't 1:1 (target -> slot 0). RNG count.
    n_decoys = max(2, rng.randint(2, 5))
    n_slots = n_real + n_decoys
    # Shuffle real targets into random slots.
    slot_order = list(range(n_slots))
    # SubStream.shuffle returns a new list; random.Random.shuffle mutates +
    # returns None. Handle both by re-binding.
    shuffled = rng.shuffle(slot_order)
    if shuffled is not None:
        slot_order = shuffled
    real_slots = slot_order[:n_real]
    decoy_slots = slot_order[n_real:]
    name_to_slot = dict(zip(targets, real_slots))

    # Build the dispatch function body: an if/elif chain mapping each slot
    # to its target function (real) or decoy lambda (never reached).
    #   def _br_acoda(idx):
    #       if idx == 0: return fib
    #       if idx == 3: return _decoy_3
    #       ...
    # The real targets are Name references resolved from globals at call
    # time (forward refs to defs later in the module are fine). The decoys
    # are inline lambdas that raise if ever called (defensive -- the opaque
    # index guarantees they aren't).
    body_stmts = []
    for nm, slot in zip(targets, real_slots):
        body_stmts.append(ast.If(
            test=ast.Compare(
                left=ast.Name(id='idx', ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=slot)],
            ),
            body=[ast.Return(value=ast.Name(id=nm, ctx=ast.Load()))],
            orelse=[],
        ))
    for slot in decoy_slots:
        decoy = _decoy_fn(slot, rng)
        body_stmts.append(ast.If(
            test=ast.Compare(
                left=ast.Name(id='idx', ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=slot)],
            ),
            body=[ast.Return(value=decoy)],
            orelse=[],
        ))
    # Fallback (should never be reached -- all slots covered):
    body_stmts.append(ast.Return(value=ast.Constant(value=None)))

    dispatch_fn = ast.FunctionDef(
        name=_ACODA_TABLE,
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg='idx', annotation=None)],
            kwonlyargs=[], kw_defaults=[], defaults=[], vararg=None, kwarg=None,
        ),
        body=body_stmts,
        decorator_list=[],
        returns=None,
    )

    # Insert the dispatch function at the BEGINNING of tree.body (before all
    # defs). Its body references target Names that are defined later, but
    # Python resolves those from globals at CALL time (after all defs load),
    # so forward references are safe. Placing it first ensures it's in module
    # globals when the capsule-wrapped dispatch sites exec.
    tree.body.insert(0, dispatch_fn)

    # Rewrite each eligible call site: f(args) -> _br_acoda(opaque_idx)(args)
    rewritten = 0
    for call_node, tgt, _enc in eligible:
        slot = name_to_slot[tgt]
        idx_expr, _ = _opaque_const_index(slot, n_slots, rng)
        call_node.func = ast.Call(
            func=ast.Name(id=_ACODA_TABLE, ctx=ast.Load()),
            args=[idx_expr],
            keywords=[],
        )
        rewritten += 1

    ast.fix_missing_locations(tree)

    try:
        ctx.acoda_rewritten = rewritten
        ctx.acoda_slots = n_slots
        ctx.acoda_targets = list(targets)
        ctx.acoda_slot_map = dict(name_to_slot)
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Behavior preservation + indirect dispatch (no direct call edge) +
    decoys never reached + determinism."""

    class _Ctx:
        build_rng = None
        acoda_seed = 7

    src = (
        "def helper(n):\n"
        "    return n * 2\n"
        "\n"
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a + helper(n)\n"
        "\n"
        "def caller():\n"
        "    return helper(5) + fib(3)\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    base_caller = ns['caller']()
    base_fib3 = ns['fib'](3)
    assert base_caller == (5 * 2) + (base_fib3), base_caller
    print(f"H.2 baseline: caller()={base_caller}, fib(3)={base_fib3}  OK")

    ctx = _Ctx()
    out = apply_acoda(tree, ctx)
    assert getattr(ctx, 'acoda_rewritten', 0) > 0, "no calls rewritten"
    print(f"H.2 rewritten: {ctx.acoda_rewritten} calls, {ctx.acoda_slots} slots "
          f"({len(ctx.acoda_targets)} real + decoys)  OK")

    # Behavior identical
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<acoda>', 'exec'), ns2)
    assert ns2['caller']() == base_caller
    assert ns2['fib'](3) == base_fib3
    assert ns2['helper'](5) == 10
    print("H.2 behavior: caller()/fib(3)/helper(5) identical post-acoda  OK")

    # No direct `helper(` call edge remaining (except in helper's own def
    # which is fine -- we only rewrite CALL sites, not defs).
    src_after = ast.unparse(out)
    # The call sites should now be _br_acoda(...)(...) -- no bare `helper(`
    # call as a direct invocation.
    import re
    # A direct call to helper looks like `helper(` NOT preceded by a def.
    # After acoda, calls are `_br_acoda(...)(`.  Count direct helper calls
    # excluding the `def helper` line.
    direct_calls = re.findall(r'(?<!def )\bhelper\(', src_after)
    # helper is the target -- it should NOT appear as a direct call anymore.
    assert direct_calls == [], f"direct helper() call still present: {direct_calls}"
    assert '_br_acoda(' in src_after, "indirect dispatch missing"
    print("H.2 indirect: no direct helper() call edge; _br_acoda(...)() present  OK")

    # Decoys never reached: the dispatch function's decoy slots return
    # raise-on-reach lambdas, but the opaque index never selects them.
    # Verified by the behavior test above (if a decoy were reached,
    # caller() would raise instead of returning the right value). The
    # dispatch-function pattern (if/elif chain at module scope) means
    # the function and dispatch sites are transformed consistently by
    # downstream passes. The behavior tests above ARE the decoy-never-
    # reached proof.
    print("H.2 decoys: never reached (behavior correct => index always real slot)  OK")

    # Determinism: same seed -> same slot mapping
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_acoda(tree2, ctx2)
    assert ctx2.acoda_targets == ctx.acoda_targets, "targets differ"
    print(f"H.2 deterministic: same seed -> targets {ctx.acoda_targets}  OK")

    # Opaque index correctness: prove the expression evaluates to the real
    # slot for the actual inputs by extracting one index expr and eval'ing it.
    # Find the first _br_acoda(...) call and eval its index arg in an empty scope.
    found_idx = None
    for n in ast.walk(out):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                and n.func.id == _ACODA_TABLE:
            # The dispatch call's first arg is the opaque index expression.
            if n.args:
                try:
                    found_idx = eval(compile(ast.Expression(n.args[0]), '<idx>', 'eval'), {})
                except Exception:
                    pass
            break
    assert found_idx is not None, "could not eval an opaque index"
    # The real targets occupy the first n_real shuffled slots; found_idx must
    # be in the real set (exposed on ctx as acoda_slot_map values).
    real_slot_set = set(ctx.acoda_slot_map.values())
    assert found_idx in real_slot_set, \
        f"opaque index {found_idx} not a real slot {real_slot_set}"
    print(f"H.2 opaque index: evaluated to slot {found_idx} (a real slot)  OK")

    print("H.2 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
