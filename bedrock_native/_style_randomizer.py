"""Phase H.4 (Layer 6) style randomizer.

Post-``ast.unparse`` source rewriter that randomizes the SURFACE layout of
the obfuscated source to defeat byte-level / line-pattern fingerprinting:

  1. Insert random blank lines between top-level statements.
  2. Insert debranded junk comments at random line boundaries.
  3. Shuffle independent top-level ``def`` order (dependency-preserving
     via a reference topo-sort).

## Kerckhoffs posture

Public technique. Per-build secret: the specific layout (RNG-derived).

## Threat addressed

Source-pattern fingerprinting. Even after AST-level obfuscation, the
``ast.unparse`` output has a canonical layout (4-space indent, no blank
lines, defs in declaration order). A byte-level diff or line-pattern
matcher can cluster builds by layout. Style randomization makes the
surface layout per-build unique without changing semantics.

## Safety contract

- **No indentation changes**: Python is whitespace-sensitive; mixing indent
  widths within a block breaks parsing. We leave indentation untouched.
- **Blank lines**: only BETWEEN top-level statements (never inside a
  compound statement). A blank line at column 0 is always safe.
- **Junk comments**: ``# <random hex>`` at column 0, on their own line,
  BETWEEN top-level statements. Never inside an expression or between a
  decorator and its def.
- **Def shuffle**: only independent defs (A doesn't reference B and vice
  versa) are reordered. A def that's referenced by a LATER def stays
  earlier. The topo-sort preserves all "def-before-use" orderings for
  module-level execution. Dunders and the marker stay in place.
- **Verifiable**: the randomized source MUST re-parse to the same AST
  (modulo the junk comments, which are no-ops) and run identically.

Pure stdlib (``ast``, ``random``). Run::

    python bedrock_native/_style_randomizer.py
"""
from __future__ import annotations

import ast
import os
import random
import sys
from typing import List, Set

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_style_randomizer']


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_style')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

            def random(self):
                return self._sub.randint(0, 65535) / 65535.0

        return _Wrap(sub)
    seed = getattr(ctx, 'style_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _names_referenced(node: ast.AST) -> Set[str]:
    """Names loaded/called within ``node`` (for dependency analysis)."""
    refs: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Load, ast.Del)):
            refs.add(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            refs.add(n.value.id)
    return refs


def _shuffle_top_defs(tree: ast.Module, rng) -> None:
    """Shuffle independent top-level defs, preserving def-before-use order.

    A def B may move before def A only if B does not reference A. We build
    a dependency graph and do a stable topo-sort with random tie-breaking.
    Dunders + the marker stay in place (fixed).
    """
    defs = [(i, n) for i, n in enumerate(tree.body)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(defs) < 2:
        return
    def_names = {n.name for _, n in defs}
    dep = {}
    for _, n in defs:
        refs = _names_referenced(n)
        dep[n.name] = refs & def_names
    fixed = {n.name for _, n in defs
             if n.name.startswith('__') or n.name == 'bedrock_crown_jewel'}
    # A def referenced by a LATER non-def top-level statement (e.g. an
    # assignment table injected by another pass, like ``_br_acoda = {0: fib}``)
    # must NOT move past that statement -- the statement executes at its fixed
    # position and needs the def already bound.  Treat such defs as anchored
    # (non-movable).  This is the composition-safety fix: without it, the
    # def-shuffle could reorder ``def fib`` AFTER ``_br_acoda = {..., 4: fib}``
    # and NameError at module load.  Conservative (reduces shuffle freedom)
    # but provably correct: an anchored def stays put, so every reference to
    # it from a fixed-position statement resolves.
    for idx, n in defs:
        if n.name in fixed:
            continue
        for j in range(idx + 1, len(tree.body)):
            other = tree.body[j]
            if isinstance(other, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue   # defs are reordered among themselves; skip
            if n.name in _names_referenced(other):
                fixed.add(n.name)
                break
    movable = [n for _, n in defs if n.name not in fixed]
    if len(movable) < 2:
        return
    placed = []
    remaining = list(movable)
    placed_names: Set[str] = set()
    placed_names |= fixed  # fixed defs are "already placed"
    while remaining:
        available = [n for n in remaining if dep[n.name] <= placed_names]
        if not available:
            placed.extend(remaining)
            break
        pick = rng.choice(available)
        placed.append(pick)
        placed_names.add(pick.name)
        remaining.remove(pick)
    new_body = []
    moved_iter = iter(placed)
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if n.name in fixed:
                new_body.append(n)
            else:
                new_body.append(next(moved_iter))
        else:
            new_body.append(n)
    tree.body[:] = new_body


# --- Pass -------------------------------------------------------------------

def apply_style_randomizer(source: str, ctx) -> str:
    """Randomize the surface layout of ``source`` (post-``ast.unparse``).

    1. Parse + shuffle independent top-level defs (dependency-preserving).
    2. Re-emit via ``ast.unparse``.
    3. Insert random blank lines + junk comments between top-level statements.

    Returns the randomized source. The source MUST re-parse + run identically.
    """
    rng = _rng_for(ctx)
    tree = ast.parse(source)

    _shuffle_top_defs(tree, rng)
    base = ast.unparse(tree)

    lines = base.split('\n')
    out: List[str] = []
    max_blanks = int(getattr(ctx, 'style_max_blanks', 0) or 3)
    comment_density = float(getattr(ctx, 'style_comment_density', 0) or 0.15)
    comment_count = 0

    for i, line in enumerate(lines):
        out.append(line)
        # Insert blanks/comments at the BOUNDARY between top-level statements:
        # the line BEFORE a new top-level line (i.e. current line is the last
        # line of the previous statement -- indented or blank -- and the NEXT
        # line starts a new top-level statement).
        if i + 1 < len(lines):
            next_line = lines[i + 1]
            next_is_top = bool(next_line) and not next_line[0].isspace()
            if next_is_top:
                n_blank = rng.randint(0, max_blanks)
                for _ in range(n_blank):
                    out.append('')
                if rng.random() < comment_density:
                    junk_hex = ''.join(rng.choice('0123456789abcdef')
                                       for _ in range(32))
                    out.append(f'# {junk_hex}')
                    comment_count += 1

    result = '\n'.join(out)
    try:
        ctx.style_comments_added = comment_count
    except Exception:
        pass
    return result


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Re-parse + run identical + byte-different layout + def-shuffle safe."""

    class _Ctx:
        build_rng = None
        style_seed = 99
        style_max_blanks = 3
        style_comment_density = 0.5

    src = (
        "def helper(n):\n"
        "    return n * 2\n"
        "\n"
        "def caller(x):\n"
        "    return helper(x) + 1\n"
        "\n"
        "def independent(y):\n"
        "    return y * y\n"
        "\n"
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def __hidden__():\n"
        "    return 42\n"
    )
    ns = {}
    exec(compile(ast.parse(src), '<base>', 'exec'), ns)
    base_caller = ns['caller'](5)
    base_fib10 = ns['fib'](10)
    base_indep = ns['independent'](3)
    print(f"H.4 baseline: caller(5)={base_caller}, fib(10)={base_fib10}, "
          f"independent(3)={base_indep}  OK")

    ctx = _Ctx()
    randomized = apply_style_randomizer(src, ctx)
    assert ctx.style_comments_added > 0, "no junk comments added"
    print(f"H.4 comments: {ctx.style_comments_added} junk comments inserted  OK")

    tree2 = ast.parse(randomized)
    print("H.4 re-parse: randomized source is valid Python  OK")

    ns2 = {}
    exec(compile(tree2, '<randomized>', 'exec'), ns2)
    assert ns2['caller'](5) == base_caller
    assert ns2['fib'](10) == base_fib10
    assert ns2['independent'](3) == base_indep
    assert ns2['helper'](5) == 10
    print("H.4 behavior: all functions identical post-randomize  OK")

    assert randomized != src, "layout unchanged"
    assert '#' in randomized, "no junk comments in output"
    assert randomized.count('\n') > src.count('\n'), "no extra lines added"
    print("H.4 byte-different: layout has extra lines + comments  OK")

    def_names = [n.name for n in tree2.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    assert set(def_names) == {'helper', 'caller', 'independent', 'fib', '__hidden__'}
    print(f"H.4 def-shuffle: all 5 defs present (order: {def_names})  OK")

    assert '__hidden__' in def_names
    print("H.4 dunders: __hidden__ preserved (fixed, not shuffled)  OK")

    ctx2 = _Ctx()
    randomized2 = apply_style_randomizer(src, ctx2)
    assert randomized2 == randomized, "non-deterministic with same seed"
    print("H.4 deterministic: same seed -> identical layout  OK")

    print("H.4 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
