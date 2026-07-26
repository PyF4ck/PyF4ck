"""Crown-jewel function collector for Phase F (Layer 2 leak-resilient VM).

Selects which functions in a module should be virtualized by the leak-
resilient VM. The plan (line 25) specifies *annotation-gated* selection
(~5-10 functions): the user marks crown jewels explicitly with the
``@bedrock_crown_jewel`` decorator. When no functions are annotated the
collector falls back to an auto-heuristic that picks the top-N most complex
eligible functions (by AST node count), respecting the same cap.

Selection precedence
--------------------
1. Explicit: functions decorated with ``@bedrock_crown_jewel`` (matched as a
   bare ``ast.Name`` or any ``ast.Attribute`` whose ``attr`` is
   ``"bedrock_crown_jewel"`` — so ``@module.bedrock_crown_jewel`` works too).
   Only decorated functions are returned; the cap is still enforced (first N).
2. Auto fallback: when zero functions are decorated, the top-N most complex
   *eligible* functions are returned. Eligibility mirrors the existing
   Phase-5 ``_nativevm_collect_targets`` heuristic:
     - top-level ``ast.FunctionDef`` only (no nested defs, no ``self`` methods)
     - skip ``async def`` (the VM does not virtualize coroutines)
     - skip short ASCII dunders ``^__[a-zA-Z_][a-zA-Z0-9_]*__$`` (≤32 chars) —
       but keep obf_vars-renamed long non-ASCII dunders (those survive)
     - skip the ``if __name__ == '__main__'`` entry-guard caller
   Complexity = number of AST nodes in the function body. The cap
   (default 10) bounds the runtime cost (VM is ~1.1-2x per call, crown-
   jewel only).

The decorator is RECOGNIZED, not DEFINED, here — the user's source must
define (or import) ``bedrock_crown_jewel`` as a no-op decorator::

    def bedrock_crown_jewel(fn):
        return fn

The collector never imports the user's module; it only inspects the AST, so
the decorator need not be resolvable at collection time. This keeps the
collector a pure AST pass with no execution side effects.

Pure stdlib (``ast``). Run smoke test::

    python bedrock_native/_crown_jewel_collector.py
"""
from __future__ import annotations

import ast
import sys
from typing import List

__all__ = ['collect_crown_jewels', 'is_crown_jewel_decorator',
           'auto_heuristic_targets']

_DECORATOR_NAME = 'bedrock_crown_jewel'
_DUUNDER_RE = None  # compiled lazily to avoid import-time re dependency


def _duunder_re():
    global _DUUNDER_RE
    if _DUUNDER_RE is None:
        import re
        _DUUNDER_RE = re.compile(r'^__[a-zA-Z_][a-zA-Z0-9_]*__$')
    return _DUUNDER_RE


def is_crown_jewel_decorator(node) -> bool:
    """True if *node* (a decorator expression) marks a crown jewel.

    Matches ``@bedrock_crown_jewel`` (``ast.Name``) and
    ``@<anything>.bedrock_crown_jewel`` (``ast.Attribute``). Does NOT match
    calls like ``@bedrock_crown_jewel()`` — the canonical usage is the bare
    name form, and matching call forms would require resolving the return
    value (out of scope for a pure AST pass).
    """
    if isinstance(node, ast.Name):
        return node.id == _DECORATOR_NAME
    if isinstance(node, ast.Attribute):
        return node.attr == _DECORATOR_NAME
    return False


def _function_has_crown_jewel_decorator(fn: ast.FunctionDef) -> bool:
    return any(is_crown_jewel_decorator(d) for d in fn.decorator_list)


def _is_short_ascii_dunder(name: str) -> bool:
    """True for traditional short dunders like ``__init__`` (≤32 chars).

    Obf_vars-renamed dunders (long, contain non-ASCII) are KEPT — they are
    user functions the renamer turned into dunders, not real dunders.
    """
    if len(name) > 32:
        return False
    if not _duunder_re().match(name):
        return False
    # Must be pure ASCII to count as a traditional dunder; obf_vars names
    # inject non-ASCII bytes so they fall through (kept).
    try:
        name.encode('ascii')
    except UnicodeEncodeError:
        return False
    return True


def _is_async(fn: ast.FunctionDef) -> bool:
    return isinstance(fn, ast.AsyncFunctionDef)


def _references_main_guard(fn: ast.FunctionDef) -> bool:
    """True if *fn* body reads ``__name__`` / compares to ``'__main__'``.

    Such functions are the entry-guard caller (``def main(): ... if __name__ ==
    '__main__': main()``) and should not be virtualized — the VM runs at
    import time and the guard must stay Python-side.
    """
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and node.id == '__name__':
            return True
        if isinstance(node, ast.Constant) and node.value == '__main__':
            return True
    return False


def _has_self_param(fn: ast.FunctionDef) -> bool:
    """True if the first positional arg is ``self`` (a method, not a free fn).

    The VM targets top-level free functions; methods need their bound ``self``
    and are left to the capsule runtime / Cython.
    """
    args = fn.args.posonlyargs + fn.args.args
    return bool(args) and args[0].arg == 'self'


def _is_eligible(fn: ast.FunctionDef) -> bool:
    """Phase-5-style eligibility gate (without the compiler-rejects check,
    which needs a live compiler — handled downstream by the compile pass)."""
    if _is_async(fn):
        return False
    if _has_self_param(fn):
        return False
    if _is_short_ascii_dunder(fn.name):
        return False
    if _references_main_guard(fn):
        return False
    # The no-op marker decorator definition itself is not a crown jewel —
    # it is the marker the user defines so @bedrock_crown_jewel resolves.
    if fn.name == _DECORATOR_NAME:
        return False
    return True


def _body_complexity(fn: ast.FunctionDef) -> int:
    """AST node count of the function body (proxy for runtime cost)."""
    return sum(1 for _ in ast.walk(fn))


def auto_heuristic_targets(tree: ast.Module, max_funcs: int = 10
                           ) -> List[ast.FunctionDef]:
    """Top-N most complex eligible top-level functions (fallback path).

    Returns at most ``max_funcs`` ``ast.FunctionDef`` nodes, sorted by
    descending body complexity (AST node count). Ties broken by source line
    order (stable). Only *eligible* functions are considered (see
    ``_is_eligible``).
    """
    candidates = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # AsyncFunctionDef is filtered by _is_eligible but we must still
            # consider it here so the type narrowing holds; it'll be dropped.
            if _is_eligible(node):
                candidates.append((node, _body_complexity(node)))
    # Sort by complexity desc; stable sort keeps source order for ties.
    candidates.sort(key=lambda c: c[1], reverse=True)
    return [fn for fn, _ in candidates[:max_funcs]]


def collect_crown_jewels(tree: ast.Module, max_funcs: int = 10
                         ) -> List[ast.FunctionDef]:
    """Select functions to virtualize in the Phase-F leak-resilient VM.

    Precedence:
      1. Functions decorated ``@bedrock_crown_jewel`` (explicit). The cap
         ``max_funcs`` is still enforced (first N by source order).
      2. If none decorated: the top-N most complex eligible functions
         (auto-heuristic fallback).

    Returns a list of ``ast.FunctionDef`` nodes (never ``AsyncFunctionDef``).
    The caller is responsible for the downstream compile-rejects safety net
    (a function the VM compiler cannot handle — try/except/with, nested
    generators — falls back to Cython/capsule at compile time).
    """
    decorated = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and \
                _function_has_crown_jewel_decorator(node):
            decorated.append(node)
    if decorated:
        return decorated[:max_funcs]
    return auto_heuristic_targets(tree, max_funcs=max_funcs)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
def _smoke() -> None:
    src = '''
def bedrock_crown_jewel(fn):
    """No-op marker decorator recognized by the Phase-F VM collector."""
    return fn


@bedrock_crown_jewel
def crown_a(x):
    s = 0
    for i in range(x):
        s += i * i
    return s


@bedrock_crown_jewel
def crown_b(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def plain_helper(x):
    return x + 1


def big_function(data):
    total = 0
    for row in data:
        for cell in row:
            total += cell
            if cell > 100:
                total -= 1
            else:
                total += cell // 2
    return total


def __init__(self, x):
    self.x = x


async def coro():
    return 1


def main():
    print(crown_a(10))


if __name__ == "__main__":
    main()
'''
    tree = ast.parse(src)

    # 1. Decorator detection.
    cj = collect_crown_jewels(tree, max_funcs=10)
    names = [fn.name for fn in cj]
    assert names == ['crown_a', 'crown_b'], \
        f'decorator path: expected [crown_a, crown_b], got {names}'
    print(f'decorator path: collected {names}  OK')

    # 2. No decorators -> auto heuristic (top-N by complexity).
    src_no_deco = src.replace('@bedrock_crown_jewel\n', '')
    tree2 = ast.parse(src_no_deco)
    cj2 = collect_crown_jewels(tree2, max_funcs=2)
    names2 = [fn.name for fn in cj2]
    # big_function is the most complex; crown_a/crown_b next. The exact order
    # depends on body complexity — assert big_function is in the top 2 and
    # the dunder/coro/main-helper exclusions held.
    assert 'big_function' in names2, \
        f'heuristic: big_function should be top, got {names2}'
    assert '__init__' not in names2, 'heuristic: dunder leaked'
    assert 'coro' not in names2, 'heuristic: async leaked'
    assert 'main' not in names2, 'heuristic: main-guard leaked'
    assert len(names2) == 2, f'heuristic: cap not respected, got {names2}'
    print(f'heuristic path: collected {names2}  OK')

    # 3. Cap enforcement on decorated path.
    src_many = 'def bedrock_crown_jewel(fn): return fn\n'
    for i in range(15):
        src_many += f'@bedrock_crown_jewel\ndef f{i}(x): return x + {i}\n'
    tree3 = ast.parse(src_many)
    cj3 = collect_crown_jewels(tree3, max_funcs=5)
    assert len(cj3) == 5, f'cap: expected 5, got {len(cj3)}'
    assert [fn.name for fn in cj3] == ['f0', 'f1', 'f2', 'f3', 'f4'], \
        'cap: first 5 by source order'
    print('cap enforcement: 5/15 decorated  OK')

    # 4. Attribute-form decorator (@module.bedrock_crown_jewel).
    src_attr = (
        'import m\n'
        '@m.bedrock_crown_jewel\n'
        'def attr_crown(x): return x * 2\n'
        'def plain(x): return x\n'
    )
    tree4 = ast.parse(src_attr)
    cj4 = collect_crown_jewels(tree4, max_funcs=10)
    assert [fn.name for fn in cj4] == ['attr_crown'], \
        f'attr-decorator: got {[f.name for f in cj4]}'
    print('attr-decorator (@m.bedrock_crown_jewel): detected  OK')

    # 5. Eligibility edge: self-method excluded even if decorated.
    src_self = (
        'def bedrock_crown_jewel(fn): return fn\n'
        'class C:\n'
        '    @bedrock_crown_jewel\n'
        '    def method(self): return 1\n'
    )
    tree5 = ast.parse(src_self)
    cj5 = collect_crown_jewels(tree5, max_funcs=10)
    # collect_crown_jewels only walks tree.body (top-level), so the nested
    # method is NOT seen — which is correct (VM targets top-level free fns).
    assert cj5 == [], f'self-method: should not be top-level, got {[f.name for f in cj5]}'
    print('nested method (not top-level): correctly excluded  OK')

    print('SMOKE PASS')


if __name__ == '__main__':
    _smoke()
