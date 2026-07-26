"""Phase H.3 (Layer 6) structural metamorphic engine.

Extends the existing ``_br_meta_shard`` (which only re-randomizes a comment
+ re-patches the file/integrity hashes) with TRUE STRUCTURAL MUTATION:
on each run, the shard re-randomizes embedded dead-junk string literals,
changing actual code bytes (not just comments).

## How it works

### Build-time (``apply_metamorphic``)

Inject dead-junk string assignments into eligible functions::

    def fib(n):
        _br_mut = 'aaa...48 hex chars...'   # dead junk, result discarded
        a, b = 0, 1
        ...

Each ``_br_mut`` assignment is a dead string literal — its value is never
used, so changing it doesn't affect behavior. But it's a real code byte
that changes on every run.

### Runtime (``gen_metamorphic_shard``)

A shard function (emitted as a setup node) that:
  1. Reads ``__file__``.
  2. Finds all ``_br_mut = '...'`` assignments via regex.
  3. Regenerates each hex string with fresh ``random.Random(str(time()))``.
  4. Re-masks the old file/integrity hashes (same as the existing shard).
  5. Recomputes + re-patches the hashes.
  6. Atomically ``os.replace``s the file.

## Kerckhoffs posture

Public technique. The mutation targets are visible (dead junk strings);
the per-run secret is the fresh random values (time-seeded, not build-seeded).

## Threat addressed

Static file fingerprinting. Even after AST-level obfuscation, the shipped
source has stable byte content across runs. Structural mutation makes each
run produce byte-different source (beyond just a comment), so a static
dump taken at different times shows different bytes — defeating file-hash
fingerprinting and byte-diff analysis.

## Safety contract

- The ``_br_mut`` assignments are DEAD (the string is never read). Changing
  the string content is behavior-preserving by construction.
- The hash re-patching follows the EXACT same logic as the existing
  ``_br_meta_shard`` (mask old hash → recompute → replace), so file/integrity
  self-checks stay consistent.
- The shard is fail-safe: any exception → poison state (no crash).

Pure stdlib (``ast``, ``random``, ``re``). Run::

    python bedrock_native/_metamorphic.py
"""
from __future__ import annotations

import ast
import os
import random
import re
import sys
from typing import List

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_metamorphic', 'gen_metamorphic_shard']

_MUT_VAR = '_br_mut'
_MUT_PATTERN = r"_br_mut\s*=\s*'([0-9a-f]{48})'"


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_metamorphic')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

        return _Wrap(sub)
    seed = getattr(ctx, 'metamorphic_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


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
    if len(fn.body) < 1:
        return False
    for n in ast.walk(fn):
        if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
            return False
    return True


# --- Build-time pass --------------------------------------------------------

def apply_metamorphic(tree: ast.Module, ctx) -> ast.Module:
    """Inject dead-junk ``_br_mut = '...'`` assignments into eligible functions.

    These are the mutation targets that the runtime shard re-randomizes on
    each run. They're dead (never read), so changing them is behavior-safe.
    """
    rng = _rng_for(ctx)
    injected = 0

    for node in list(tree.body):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _is_eligible(node):
            continue
        # Generate a 48-hex-char dead-junk string.
        junk_hex = ''.join(rng.choice('0123456789abcdef') for _ in range(48))
        mut_assign = ast.Assign(
            targets=[ast.Name(id=_MUT_VAR, ctx=ast.Store())],
            value=ast.Constant(value=junk_hex),
        )
        # Insert at the top of the function body.
        node.body.insert(0, mut_assign)
        ast.fix_missing_locations(node)
        injected += 1

    try:
        ctx.metamorphic_injected = injected
    except Exception:
        pass
    return tree


# --- Runtime shard generator ------------------------------------------------

def gen_metamorphic_shard(ctx) -> str:
    """Return the source of the structural-mutation shard function.

    The shard:
      1. Reads __file__.
      2. Finds all _br_mut = '<48 hex>' assignments.
      3. Regenerates each hex string.
      4. Re-masks + recomputes the file/integrity hashes (same logic as
         the existing _br_meta_shard).
      5. Atomically os.replace's the file.

    This is emitted as a setup node (or chain shard) in the obfuscated output.
    """
    return (
        "def _br_structural_mutate():\n"
        "    try:\n"
        "        import os as _mos, hashlib as _mh, random as _mr, time as _mt, re as _mre\n"
        "        _target = _mos.path.abspath(__file__)\n"
        "        with open(_target, 'rb') as _mf:\n"
        "            _data = _mf.read().decode('utf-8', 'ignore')\n"
        "        _rng = _mr.Random(str(_mt.time()))\n"
        "        # Structural mutation: re-randomize all _br_mut = '...' dead-junk strings.\n"
        "        _pat = _mre.compile(r\"_br_mut\\s*=\\s*'([0-9a-f]{48})'\")\n"
        "        _n_mut = [0]\n"
        "        def _repl(_m):\n"
        "            _n_mut[0] += 1\n"
        "            _new = ''.join(_rng.choice('0123456789abcdef') for _ in range(48))\n"
        "            return \"_br_mut = '\" + _new + \"'\"\n"
        "        _data = _pat.sub(_repl, _data)\n"
        "        # Also inject a fresh metamorphic comment (existing behavior).\n"
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


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Build-time injection + runtime mutation + behavior preservation +
    determinism (build) + per-run freshness (runtime)."""

    class _Ctx:
        build_rng = None
        metamorphic_seed = 41

    src = (
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def compute(n):\n"
        "    return n * 2 + 1\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    assert ns['fib'](10) == 55
    assert ns['compute'](5) == 11
    print("H.3 baseline: fib(10)=55, compute(5)=11  OK")

    ctx = _Ctx()
    out = apply_metamorphic(tree, ctx)
    assert getattr(ctx, 'metamorphic_injected', 0) > 0, "no mutation targets injected"
    print(f"H.3 injected: {ctx.metamorphic_injected} _br_mut dead-junk targets  OK")

    # Behavior identical (the _br_mut assignments are dead)
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<mut>', 'exec'), ns2)
    assert ns2['fib'](10) == 55
    assert ns2['compute'](5) == 11
    print("H.3 behavior: fib(10)/compute(5) identical (dead junk)  OK")

    # Mutation targets present in source
    src_after = ast.unparse(out)
    muts = re.findall(_MUT_PATTERN, src_after)
    assert len(muts) >= 2, f"expected >= 2 _br_mut targets, got {len(muts)}"
    print(f"H.3 targets: {len(muts)} _br_mut = '<48 hex>' assignments present  OK")

    # Runtime shard: simulate the mutation (regex replacement)
    shard_src = gen_metamorphic_shard(ctx)
    assert '_br_structural_mutate' in shard_src
    assert '_br_mut' in shard_src
    print("H.3 shard: gen_metamorphic_shard emits _br_structural_mutate  OK")

    # Simulate the mutation: replace all _br_mut hex strings with fresh values
    # and verify the source is byte-different but still valid.
    rng_sim = random.Random(99999)
    def _sim_repl(m):
        new_hex = ''.join(rng_sim.choice('0123456789abcdef') for _ in range(48))
        return f"_br_mut = '{new_hex}'"
    mutated_src = re.sub(_MUT_PATTERN, _sim_repl, src_after)
    assert mutated_src != src_after, "mutation didn't change source"
    # Re-parse: mutated source must be valid
    tree3 = ast.parse(mutated_src)
    ns3 = {}
    exec(compile(ast.Module(body=tree3.body, type_ignores=[]), '<mutated>', 'exec'), ns3)
    assert ns3['fib'](10) == 55 and ns3['compute'](5) == 11
    print("H.3 mutation: re-randomized source is valid + behavior identical  OK")

    # Per-run freshness: two different RNG seeds produce different mutations
    rng_a = random.Random(1)
    rng_b = random.Random(2)
    mut_a = re.sub(_MUT_PATTERN, lambda m: f"_br_mut = '{''.join(rng_a.choice('0123456789abcdef') for _ in range(48))}'", src_after)
    mut_b = re.sub(_MUT_PATTERN, lambda m: f"_br_mut = '{''.join(rng_b.choice('0123456789abcdef') for _ in range(48))}'", src_after)
    assert mut_a != mut_b, "different seeds should produce different mutations"
    print("H.3 per-run freshness: different seeds -> different byte content  OK")

    # Determinism (build-time): same seed -> same injected targets
    tree4 = ast.parse(src)
    ctx4 = _Ctx()
    apply_metamorphic(tree4, ctx4)
    muts4 = re.findall(_MUT_PATTERN, ast.unparse(tree4))
    assert muts4 == muts, "build-time non-deterministic"
    print("H.3 build deterministic: same seed -> same targets  OK")

    print("H.3 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
