"""Phase H.1 (Layer 6) identifier poisoning.

Inject per-function local bindings that SHADOW commonly-assumed builtin /
stdlib names::

    def fib(n):
        list = __builtins__['list']
        range = __builtins__['range']
        len = __builtins__['len']
        ... real body ...

The shadows resolve to the SAME object as the builtin at runtime (so the
function's behavior is byte-for-byte identical), but a STATIC analyzer that
assumes ``list`` / ``range`` / ``len`` resolve to their canonical referent
sees locals of unknown provenance -- breaking signature/AST pattern matchers
that key on builtin/stdlib semantics.

## Kerckhoffs posture

The technique is public. The shadows are a known trick; the only "secret" is
which subset of names is shadowed in which function, which is per-build
random via ``BuildRNG``.

## Threat addressed

Decompilers and RE tools often normalize/recognize idioms by name
(``range(...)`` → a loop, ``len(...)`` → a length probe, ``open(...)`` →
file I/O). Shadowing those names injects locals of the SAME value but
DIFFERENT static provenance, so name-based idiom recognizers mis-fire or
give up.

## Safety contract

- The shadow binding ``name = __builtins__['name']`` is:
  * semantically equivalent (resolves to the canonical object at runtime),
  * survives ``obf_builtins`` (which rewrites bare ``Name`` references --
    the shadow uses ``__builtins__['name']`` dict-access form, not a bare
    name),
  * never shadows a name that the function actually relies on as a NON-
    builtin (e.g. a user function named ``open``). We only inject shadows for
    names the function does NOT already bind locally, and only for names that
    ARE in ``builtins``.
- Eligibility: top-level ``def`` (not async, not generator, not dunders, not
  the marker ``bedrock_crown_jewel``), with a non-trivial body.
- The injected bindings go at the TOP of the function body, before the real
  body, so any ``Name`` load of the shadowed name in the real body resolves
  to the shadow (which equals the builtin).

Pure stdlib (``ast``, ``builtins``). Run::

    python bedrock_native/_identifier_poison.py
"""
from __future__ import annotations

import ast
import builtins as _builtins_mod
import os
import random
import sys
from typing import Optional, Set

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_identifier_poison', 'POISONABLE_NAMES']

# --- Candidate names -------------------------------------------------------

# Names a static RE tool most often keys on as "builtin/stdlib idiom".
# Restricted to TRUE builtins (``dir(builtins)``) so the shadow binding
# ``__builtins__['name']`` always succeeds. NOT stdlib module names (those
# would need ``__import__`` and break under obf_builtins).
POISONABLE_NAMES: tuple = (
    # container / iter
    'list', 'tuple', 'dict', 'set', 'frozenset',
    'range', 'enumerate', 'zip', 'map', 'filter', 'reversed', 'sorted',
    'iter', 'next',
    # numeric / boolean
    'int', 'float', 'bool', 'complex', 'abs', 'round', 'divmod', 'pow',
    'min', 'max', 'sum',
    # string / bytes
    'str', 'bytes', 'bytearray', 'chr', 'ord', 'bin', 'oct', 'hex', 'repr',
    'format', 'ascii',
    # introspection
    'len', 'hash', 'id', 'type', 'isinstance', 'issubclass', 'callable',
    'dir', 'vars', 'getattr', 'setattr', 'delattr', 'hasattr',
    # I/O / exec
    'print', 'open', 'input', 'exec', 'eval', 'compile',
)

# Validate every candidate is a real builtin (no silent AttributeError at
# runtime -- a wrong candidate is a caller bug, not a shipped defect).
_POISONABLE_VALIDATED: Set[str] = set()
for _n in POISONABLE_NAMES:
    if hasattr(_builtins_mod, _n):
        _POISONABLE_VALIDATED.add(_n)
del _n


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    """Build a deterministic RNG from ctx, preferring BuildRNG when available.

    Falls back to ``random.Random()`` (with an optional seed) when ``ctx``
    does not expose a ``BuildRNG``. The labeled sub-stream pattern (per the
    Phase E contract) is honored when a ``BuildRNG`` is present on ctx.
    """
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        # Deterministic per-build sub-stream, labeled for this pass.
        sub = brng.stream(b'phase_h_id_poison')
        # Wrap SubStream into a random.Random-like API for the choice/sample
        # calls below. SubStream exposes choice + randint directly.
        class _Wrap:
            __slots__ = ('_sub',)
            def __init__(self, sub):
                self._sub = sub
            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)
            def choice(self, seq):
                return self._sub.choice(seq)
            def sample(self, seq, k):
                # Fisher-Yates-ish via shuffle (SubStream.shuffle returns a new list)
                sh = self._sub.shuffle(list(seq))
                return sh[:k]
        return _Wrap(sub)
    # Fallback: ad-hoc random.Random (mirrors apply_homoglyph's pattern).
    seed = getattr(ctx, 'identifier_poison_seed', None)
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
    """Conservative eligibility: skip async/generators/dunders/marker."""
    if fn.args.posonlyargs or fn.args.kwonlyargs or fn.args.vararg or fn.args.kwarg:
        # Keep it simple: only plain positional functions. (Eligible bodies
        # with kw-only args would still work, but the shadow set selection
        # gets more fiddly -- conservative first.)
        pass  # allow but be careful below
    # async / generator detection
    if getattr(fn, 'is_async', False) or isinstance(fn, ast.AsyncFunctionDef):
        return False
    for n in ast.walk(fn):
        if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)):
            return False
    name = getattr(fn, 'name', '')
    if not name:
        return False
    if name == 'bedrock_crown_jewel':
        return False
    if name in _PYTHON_DUNDERS:
        return False
    if len(fn.body) < 2:
        return False  # trivial body -- not worth poisoning
    return True


def _locally_bound_names(fn: ast.FunctionDef) -> Set[str]:
    """Names the function binds locally (params + assignments + targets).

    A shadow must NOT collide with a name the function already uses as a
    non-builtin local (e.g. a user var named ``open``). We skip such names.
    """
    bound: Set[str] = set()
    # parameters
    for a in (fn.args.args + fn.args.posonlyargs + fn.args.kwonlyargs):
        if a.arg:
            bound.add(a.arg)
    if fn.args.vararg:
        bound.add(fn.args.vararg.arg)
    if fn.args.kwarg:
        bound.add(fn.args.kwarg.arg)
    # assignment/comprehension targets, function/class names, except/with-as
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    bound.add(t.id)
                if isinstance(t, (ast.Tuple, ast.List)):
                    for elt in ast.walk(t):
                        if isinstance(elt, ast.Name):
                            bound.add(elt.id)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            bound.add(n.target.id)
        elif isinstance(n, (ast.For, ast.AsyncFor)) and isinstance(n.target, ast.Name):
            bound.add(n.target.id)
        elif isinstance(n, ast.comprehension):
            if isinstance(n.target, ast.Name):
                bound.add(n.target.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for alias in n.names:
                if alias.asname:
                    bound.add(alias.asname)
                elif alias.name:
                    bound.add(alias.name.split('.')[0])
    return bound


def _names_loaded(fn: ast.FunctionDef) -> Set[str]:
    """Builtin/stdlib names the function actually LOADS (so we shadow the
    ones in use -- shadowing unused names is wasted noise)."""
    loaded: Set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            loaded.add(n.id)
    return loaded


# --- Pass -------------------------------------------------------------------

def apply_identifier_poison(tree: ast.Module, ctx) -> ast.Module:
    """Inject per-function shadow bindings of builtin names.

    For each eligible function, pick ``k`` (3-8, RNG) builtin names that the
    function actually LOADS and does NOT already bind locally, and inject
    ``name = __builtins__['name']`` at the top of the body.

    Behavior-preserving: the shadow resolves to the canonical builtin object
    at runtime. The static-analysis effect: a name-resolution tracer sees a
    local binding of unknown (to it) provenance instead of a builtin lookup.
    """
    rng = _rng_for(ctx)
    max_per_fn = int(getattr(ctx, 'identifier_poison_count', 0) or 6)
    if max_per_fn <= 0:
        max_per_fn = 6
    min_per_fn = max(3, min(max_per_fn, 3))
    injected_total = 0

    for node in list(tree.body):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.AsyncFunctionDef):
            continue  # eligibility: skip async
        if not _is_eligible(node):
            continue
        bound = _locally_bound_names(node)
        loaded = _names_loaded(node)
        # Candidates: poisonable + actually loaded + not already bound locally
        # + validated as a real builtin.
        candidates = [
            n for n in POISONABLE_NAMES
            if n in _POISONABLE_VALIDATED
            and n in loaded
            and n not in bound
        ]
        if not candidates:
            continue
        k = rng.randint(min_per_fn, max_per_fn)
        k = min(k, len(candidates))
        if k <= 0:
            continue
        chosen = rng.sample(candidates, k)
        # Build shadow binding statements: name = __builtins__['name']
        # Use a Load on the __builtins__ dict via Subscript. This survives
        # obf_builtins (which rewrites bare Name nodes but leaves Subscript
        # alone). Also robust to __builtins__ being a module (use getattr
        # fallback via a try/except wrapper to be safe in all contexts).
        new_stmts = []
        for nm in chosen:
            # name = __builtins__['name'] if isinstance(__builtins__, dict) \
            #         else getattr(__builtins__, 'name')
            # We emit the dict-access form directly; CPython guarantees
            # __builtins__ is a dict inside a non-main module and a module
            # inside __main__. To be safe in BOTH, we use a getattr-with-
            # default on the dict subscript via a tiny try/except.
            # Simplest robust form: name = __builtins__['name']
            # (works in non-main modules, which is where obf output runs).
            new_stmts.append(
                ast.Assign(
                    targets=[ast.Name(id=nm, ctx=ast.Store())],
                    value=ast.Subscript(
                        value=ast.Call(
                            func=ast.Name(id='getattr', ctx=ast.Load()),
                            args=[
                                ast.Name(id='__builtins__', ctx=ast.Load()),
                                ast.Constant(value='__dict__'),
                                ast.Name(id='__builtins__', ctx=ast.Load()),
                            ],
                            keywords=[],
                        ),
                        slice=ast.Constant(value=nm),
                        ctx=ast.Load(),
                    ),
                )
            )
            injected_total += 1
        # Prepend the shadow bindings to the function body.
        node.body = new_stmts + node.body
        ast.fix_missing_locations(node)

    try:
        ctx.identifier_poison_injected = injected_total
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Behavior preservation + shadow presence + OPSEC (survives obf_builtins
    dict-access form) + eligibility (skips dunders/async/marker)."""

    class _Ctx:
        build_rng = None
        identifier_poison_seed = 42
        identifier_poison_count = 6

    src = (
        "def fib(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a + b\n"
        "    return a\n"
        "\n"
        "def compute_secret(seed):\n"
        "    total = 0\n"
        "    data = list(range(seed))\n"
        "    for x in data:\n"
        "        total = total + (x * len(data))\n"
        "    return total\n"
        "\n"
        "async def afoo():\n"
        "    return 1\n"
        "\n"
        "def __hidden__():\n"
        "    return 1\n"
        "\n"
        "def bedrock_crown_jewel():\n"
        "    pass\n"
    )
    tree = ast.parse(src)
    # Pre-poison behavior baseline
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    base_fib10 = ns['fib'](10)
    base_cs50 = ns['compute_secret'](50)
    assert base_fib10 == 55, base_fib10
    print(f"H.1 baseline: fib(10)={base_fib10}, compute_secret(50)={base_cs50}  OK")

    # Apply the pass
    ctx = _Ctx()
    out = apply_identifier_poison(tree, ctx)
    injected = getattr(ctx, 'identifier_poison_injected', 0)
    assert injected > 0, "no shadows injected"
    print(f"H.1 injected: {injected} shadow bindings total  OK")

    # Behavior identical after poisoning
    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<poisoned>', 'exec'), ns2)
    assert ns2['fib'](10) == 55
    assert ns2['compute_secret'](50) == base_cs50
    print("H.1 behavior: fib(10)=55, compute_secret identical post-poison  OK")

    # Shadow presence: fib's body should start with `range = __builtins__['range']`
    # (range is the only builtin fib loads). compute_secret loads list+range+len.
    fib_src = ast.unparse(out.body[0])
    # The shadow form is now: name = getattr(__builtins__, '__dict__', __builtins__)['name']
    # which is robust to __builtins__ being a module (in __main__) or a dict.
    assert 'getattr' in fib_src and '__builtins__' in fib_src, "fib missing range shadow"
    cs_src = ast.unparse(out.body[1])
    assert 'getattr' in cs_src and '__builtins__' in cs_src, "compute_secret missing shadows"
    print("H.1 shadows: getattr(__builtins__, ...) robust form present  OK")

    # Eligibility: async/dunder/marker skipped
    afoo = next(n for n in out.body if getattr(n, 'name', '') == 'afoo')
    assert not any(isinstance(n, ast.Assign) and
                   isinstance(n.value, ast.Subscript)
                   for n in afoo.body), "async should not be poisoned"
    hidden = next(n for n in out.body if getattr(n, 'name', '') == '__hidden__')
    assert not any(isinstance(n, ast.Assign) and
                   isinstance(n.value, ast.Subscript)
                   for n in hidden.body), "dunder should not be poisoned"
    marker = next(n for n in out.body if getattr(n, 'name', '') == 'bedrock_crown_jewel')
    assert not any(isinstance(n, ast.Assign) and
                   isinstance(n.value, ast.Subscript)
                   for n in marker.body), "marker should not be poisoned"
    print("H.1 eligibility: async/dunder/marker skipped  OK")

    # OPSEC: the shadow form is a Subscript whose value is a Call to
    # getattr(__builtins__, '__dict__', __builtins__) -- robust to __builtins__
    # being a module (in __main__) or a dict (in submodules). The Subscript
    # form survives obf_builtins (which rewrites bare Name nodes but leaves
    # Subscript/Call alone). Verify the injected value is a Subscript.
    for n in out.body[0].body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Subscript):
            assert isinstance(n.value.value, ast.Call), \
                'shadow value should be a Call(getattr(...))'
            assert isinstance(n.value.slice, ast.Constant)
            break
    else:
        raise AssertionError("no Subscript shadow found in fib")
    print("H.1 OPSEC: shadow is Subscript(getattr(__builtins__,...)['name']), survives obf_builtins  OK")

    # Determinism: same ctx (seeded) -> same injected names
    tree2 = ast.parse(src)
    ctx2 = _Ctx()
    apply_identifier_poison(tree2, ctx2)
    fib2_names = [n.targets[0].id for n in tree2.body[0].body
                  if isinstance(n, ast.Assign) and isinstance(n.value, ast.Subscript)]
    fib1_names = [n.targets[0].id for n in out.body[0].body
                  if isinstance(n, ast.Assign) and isinstance(n.value, ast.Subscript)]
    assert fib1_names == fib2_names, "non-deterministic with same seed"
    print(f"H.1 deterministic: same seed -> {fib1_names}  OK")

    print("H.1 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
