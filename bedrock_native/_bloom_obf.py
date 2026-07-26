"""Phase H.6 (Layer 6) bloom-filter opaque predicates.

Replace/extend the algebraic opaque predicates used by ``apply_junk`` with
bloom-filter-based always-true guards::

    _br_bloom = <bytes bit-array>   # pre-loaded with the "always-accept" set
    ...
    if _br_bloom_contains(<const>):   # const was added at build -> always True
        <dead junk>

A bloom filter is a probabilistic membership structure: ``contains(x)`` is
either "definitely absent" or "maybe present". We CONSTRUCT the filter so
every value we'll actually test at that guard site WAS added -- so
``contains`` always returns True -- but a static analyzer must reason about
the k hash functions + bit array to PROVE it's always-true, which is harder
than dismissing ``(x*x+x)%2 == 0`` (a trivial algebraic identity).

## Kerckhoffs posture

Public technique. The per-build secret is which constants are pre-loaded
and the k/salt values (RNG-derived).

## Threat addressed

Opaque-predicate dismissal. SMT solvers and decompiler constant folders
trivially prove ``x*(x-1) % 2 == 0`` is always-true (it's an algebraic
identity). A bloom-membership test ``contains(c)`` where ``c`` IS in the
filter is also always-true, but proving it requires modeling k hash
functions over a bit array -- beyond a typical constant-folder's budget.

## Safety contract

- The filter is constructed so EVERY value tested at a guard site was
  pre-loaded -> ``contains`` is always True for those values. Verified by
  construction (we add the constant BEFORE embedding the filter) + by the
  smoke test.
- The guarded block is DEAD JUNK (never changes behavior): it's a pure
  computation whose result is discarded (``_ = <expr>``). So even if the
  guard were somehow False, behavior is unchanged.
- The bloom ``contains`` impl is pure-Python stdlib (``hashlib``).

Pure stdlib (``ast``, ``hashlib``). Run::

    python bedrock_native/_bloom_obf.py
"""
from __future__ import annotations

import ast
import hashlib
import os
import random
import sys
from typing import List

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_bloom_obf', 'BloomFilter', 'build_bloom_literal']

_BLOOM_ARRAY = '_br_bloom'
_BLOOM_CONTAINS = '_br_bloom_contains'

# Real Python magic methods that obfuscation passes must preserve. Renamed
# functions (__<hex>...__ from obf_vars) are NOT in this set, so they remain
# eligible obfuscation targets.
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


# --- BloomFilter (pure stdlib) ---------------------------------------------

class BloomFilter:
    """A simple k-hash bloom filter over a bit array (``bytes``).

    ``contains(x)`` checks k bit positions derived from k salted SHA-256
    hashes of ``x``. False positives possible (by design); false negatives
    impossible (a value that was ``add``-ed always reports ``contains==True``).
    """

    def __init__(self, size_bits: int, n_hashes: int):
        if size_bits <= 0 or n_hashes <= 0:
            raise ValueError("size_bits and n_hashes must be positive")
        self.size_bits = size_bits
        self.n_hashes = n_hashes
        # bit array as a bytearray (1 bit per cell)
        self._bits = bytearray((size_bits + 7) // 8)

    def _positions(self, x) -> List[int]:
        """Yield k bit positions for value x (k salted SHA-256 hashes)."""
        xb = x if isinstance(x, bytes) else repr(x).encode('utf-8')
        positions = []
        for i in range(self.n_hashes):
            h = hashlib.sha256(bytes([i]) + xb).digest()
            # Use first 8 bytes as a uint64, mod size_bits
            pos = int.from_bytes(h[:8], 'little') % self.size_bits
            positions.append(pos)
        return positions

    def add(self, x) -> None:
        for pos in self._positions(x):
            self._bits[pos // 8] |= (1 << (pos % 8))

    def contains(self, x) -> bool:
        for pos in self._positions(x):
            if not (self._bits[pos // 8] & (1 << (pos % 8))):
                return False
        return True

    def to_bytes(self) -> bytes:
        return bytes(self._bits)

    @classmethod
    def from_bytes(cls, raw: bytes, size_bits: int, n_hashes: int) -> 'BloomFilter':
        bf = cls(size_bits, n_hashes)
        bf._bits = bytearray(raw)
        return bf


def build_bloom_literal(values, size_bits: int = 256, n_hashes: int = 4) -> tuple:
    """Build a bloom filter pre-loaded with ``values``.

    Returns ``(bytes_array, size_bits, n_hashes)`` -- enough to emit a
    literal + reconstruct for ``contains``.
    """
    bf = BloomFilter(size_bits, n_hashes)
    for v in values:
        bf.add(v)
    return bf.to_bytes(), size_bits, n_hashes


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_bloom')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

        return _Wrap(sub)
    seed = getattr(ctx, 'bloom_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


# --- Pass -------------------------------------------------------------------

def apply_bloom_obf(tree: ast.Module, ctx) -> ast.Module:
    """Inject bloom-guarded dead-junk blocks into eligible functions.

    For each eligible function, pick ``k`` (1-3, RNG) sites, and for each:
      1. Pick a constant ``c`` (RNG int) to test.
      2. Build a bloom filter pre-loaded with ``c`` (so ``contains(c)`` is
         always True).
      3. Inject ``if _br_bloom_contains(c): <dead junk>``.
    The bloom array + contains function are emitted ONCE at module scope.

    The dead junk is a pure computation whose result is discarded
    (``_ = <expr>``), so the guard's truth value doesn't affect behavior.
    """
    rng = _rng_for(ctx)
    n_hashes = int(getattr(ctx, 'bloom_hashes', 0) or 4)
    size_bits = int(getattr(ctx, 'bloom_size', 0) or 256)

    # Collect the constants we'll test (pre-load them into one shared bloom).
    test_constants = []
    injected = 0

    def _eligible(fn):
        name = getattr(fn, 'name', '')
        if not name or name == 'bedrock_crown_jewel':
            return False
        if name in _PYTHON_DUNDERS:
            return False
        for n in ast.walk(fn):
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
                return False
        return len(fn.body) >= 1

    for node in list(tree.body):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        if not _eligible(node):
            continue
        k = rng.randint(1, 3)
        for _ in range(k):
            c = rng.randint(0, 1 << 30)
            test_constants.append(c)
            # Build the dead-junk guard: if _br_bloom_contains(c): _ = <junk>
            junk = rng.randint(1, 1 << 20)
            guard = ast.If(
                test=ast.Call(
                    func=ast.Name(id=_BLOOM_CONTAINS, ctx=ast.Load()),
                    args=[ast.Constant(value=c)],
                    keywords=[],
                ),
                body=[ast.Assign(
                    targets=[ast.Name(id='_', ctx=ast.Store())],
                    value=ast.BinOp(
                        left=ast.Constant(value=c),
                        op=ast.BitXor(),
                        right=ast.Constant(value=junk),
                    ),
                )],
                orelse=[],
            )
            # Insert the guard at the top of the function body (before the
            # real body). It's dead junk -- position doesn't matter.
            node.body.insert(0, guard)
            injected += 1
        ast.fix_missing_locations(node)

    if not test_constants:
        return tree

    # Build the shared bloom filter pre-loaded with ALL test constants.
    raw, sb, nh = build_bloom_literal(test_constants, size_bits, n_hashes)
    # Emit module-scope: _br_bloom = <bytes>, _br_bloom_contains(c): ...
    bloom_array_assign = ast.Assign(
        targets=[ast.Name(id=_BLOOM_ARRAY, ctx=ast.Store())],
        value=ast.Constant(value=raw),
    )
    # _br_bloom_contains(c): check k bit positions.
    # We emit a compact Python impl using hashlib.
    contains_fn_src = (
        f"def {_BLOOM_CONTAINS}(_v):\n"
        f"    import hashlib as _bh\n"
        f"    _xb = _v if isinstance(_v, bytes) else repr(_v).encode('utf-8')\n"
        f"    for _i in range({nh}):\n"
        f"        _h = _bh.sha256(bytes([_i]) + _xb).digest()[:8]\n"
        f"        _pos = int.from_bytes(_h, 'little') % {sb}\n"
        f"        if not ({_BLOOM_ARRAY}[_pos // 8] & (1 << (_pos % 8))):\n"
        f"            return False\n"
        f"    return True\n"
    )
    contains_fn = ast.parse(contains_fn_src).body[0]
    # Insert at the BEGINNING of tree.body (before any function defs), so the
    # bloom filter + contains function are defined before the obfuscator's
    # anti-PyCDC capsule runtime encrypts function bodies. The capsule execs
    # function bodies with module globals; if _br_bloom + _br_bloom_contains
    # are defined after the functions, the capsule namespace may not include
    # them -> NameError at call time. Defining them first ensures they're in
    # globals() before any capsule is created.
    tree.body.insert(0, contains_fn)
    tree.body.insert(0, bloom_array_assign)
    ast.fix_missing_locations(tree)

    try:
        ctx.bloom_injected = injected
        ctx.bloom_size_bits = sb
        ctx.bloom_hashes = nh
        ctx.bloom_test_constants = list(test_constants)
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Behavior preservation + guards always-True + dead-junk safe +
    determinism."""

    class _Ctx:
        build_rng = None
        bloom_seed = 3
        bloom_hashes = 4
        bloom_size = 256

    src = (
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def compute_secret(seed):\n"
        "    total = 0\n"
        "    for x in range(seed):\n"
        "        total = total + x\n"
        "    return total\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    assert ns['fib'](10) == 55
    assert ns['compute_secret'](50) == 1225
    print("H.6 baseline: fib(10)=55, compute_secret(50)=1225  OK")

    ctx = _Ctx()
    out = apply_bloom_obf(tree, ctx)
    assert getattr(ctx, 'bloom_injected', 0) > 0, "no guards injected"
    print(f"H.6 injected: {ctx.bloom_injected} bloom guards, "
          f"filter {ctx.bloom_size_bits} bits / {ctx.bloom_hashes} hashes  OK")

    # Behavior identical (the guards are dead junk)
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<bloom>', 'exec'), ns2)
    assert ns2['fib'](10) == 55
    assert ns2['compute_secret'](50) == 1225
    print("H.6 behavior: fib(10)/compute_secret(50) identical  OK")

    # Guards always-True: every test constant must report contains==True
    # via the EMITTED contains function (not our Python BloomFilter class).
    test_consts = ctx.bloom_test_constants
    for c in test_consts:
        assert ns2[_BLOOM_CONTAINS](c) is True, \
            f"contains({c}) = False (should be True -- pre-loaded)"
    print(f"H.6 always-true: all {len(test_consts)} test constants -> contains=True  OK")

    # A random non-pre-loaded constant should be False (or a false positive,
    # but definitely not guaranteed True). Just verify contains doesn't crash.
    ns2[_BLOOM_CONTAINS](999999999)
    print("H.6 robust: contains(non-member) doesn't crash  OK")

    # Determinism
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_bloom_obf(tree2, ctx2)
    assert ctx2.bloom_test_constants == ctx.bloom_test_constants
    print(f"H.6 deterministic: same seed -> {len(test_consts)} guards  OK")

    # BloomFilter unit: add then contains; no false negatives.
    bf = BloomFilter(128, 3)
    for v in [1, 42, 100, 'hello', b'world']:
        bf.add(v)
    for v in [1, 42, 100, 'hello', b'world']:
        assert bf.contains(v), f"false negative on {v!r}"
    print("H.6 BloomFilter unit: no false negatives  OK")

    print("H.6 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
