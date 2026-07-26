"""Compiler test harness for _native_vm_compiler (Phase 5, Wave 2A).

Compiles each non-async function in the test modules, runs the resulting
BedrockVM blob through the reference interpreter, and asserts the output
matches calling the original Python function directly.

Run:  python bedrock_native/_compiler_test.py
"""
import io
import sys
import contextlib

import os
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)   # working dir -- holds the _test_* modules
sys.path.insert(0, _HERE)
sys.path.insert(0, _PARENT)

from _native_vm_compiler import compile_func, UnsupportedOpcode  # noqa: E402
from _bedrock_vm_ref import run, run_func, decode  # noqa: E402

# The reference interpreter's LOAD_GLOBAL does a direct dict lookup with no
# builtins fallback, so any builtin a function references (range, sum, print,
# ...) must be present in the globals dict directly.
import builtins as _builtins_mod
_BUILTIN_GLOBALS = {name: getattr(_builtins_mod, name)
                    for name in dir(_builtins_mod)}
_BUILTIN_GLOBALS['__builtins__'] = _builtins_mod

# Import the test modules (their globals carry the sibling functions + builtins
# we hand to the reference interpreter when running a compiled `main`).
import _test_obf
import _smoke_input
import _test_kwargs_simple
import _test_async

passed = 0
failed = 0
skipped = []


def _run_compiled(func, args=(), kw=None, globals_=None):
    """Compile `func`, run it through the reference interpreter, return result.

    Uses run() for the no-kwarg case and run_func() (with kw) when kwargs are
    supplied (run() does not accept kwargs)."""
    blob, perm, perm_ext, key, frame = compile_func(func)
    if globals_ is None:
        g = dict(_BUILTIN_GLOBALS)
    else:
        g = globals_
    if kw:
        fr = decode(blob, perm, key, perm_ext)
        return run_func(fr, args, dict(kw), g)
    return run(blob, perm, key, args, g, perm_ext)


def _capture(func, *args, **kw):
    """Run a Python function capturing its stdout, returning (ret, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = func(*args, **kw)
    return ret, buf.getvalue()


def _capture_compiled(func, args=(), kw=None, globals_=None):
    """Run the compiled blob capturing its stdout, returning (ret, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = _run_compiled(func, args=args, kw=kw, globals_=globals_)
    return ret, buf.getvalue()


def check(label, got_ret, want_ret, got_out, want_out):
    global passed, failed
    ok = (got_ret == want_ret) and (got_out == want_out)
    if ok:
        passed += 1
        print('  OK  %-38s ret=%r' % (label, got_ret))
    else:
        failed += 1
        print('  FAIL %-38s' % label)
        print('       ret: got=%r want=%r' % (got_ret, want_ret))
        print('       out: got=%r want=%r' % (got_out, want_out))


def check_val(label, got, want):
    global passed, failed
    if got == want:
        passed += 1
        print('  OK  %-38s -> %r' % (label, got))
    else:
        failed += 1
        print('  FAIL %-38s got=%r want=%r' % (label, got, want))


# ---- _test_obf ------------------------------------------------------------
print('=== _test_obf ===')

# add / multiply / fib / is_prime: pure-value functions (no I/O, no globals).
check_val('add(3,4)', _run_compiled(_test_obf.add, (3, 4)), 7)
check_val('multiply(5,6)', _run_compiled(_test_obf.multiply, (5, 6)), 30)
check_val('fib(10)', _run_compiled(_test_obf.fib, (10,)), 55)
check_val('is_prime(17)', _run_compiled(_test_obf.is_prime, (17,)), True)
check_val('is_prime(18)', _run_compiled(_test_obf.is_prime, (18,)), False)
check_val('is_prime(2)', _run_compiled(_test_obf.is_prime, (2,)), True)
check_val('is_prime(1)', _run_compiled(_test_obf.is_prime, (1,)), False)

# main(): calls add/multiply/fib/sum/print and uses a list comprehension that
# references the global is_prime. Provide the originals (incl. builtins) so the
# compiled main's globals resolve; the listcomp itself is compiled recursively.
obf_globals = {
    'add': _test_obf.add, 'multiply': _test_obf.multiply,
    'fib': _test_obf.fib, 'is_prime': _test_obf.is_prime,
    'range': range, 'sum': sum, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_obf.main)
got_ret, got_out = _capture_compiled(_test_obf.main, globals_=obf_globals)
check('main() [listcomp + calls]', got_ret, want_ret, got_out, want_out)


# ---- _smoke_input ---------------------------------------------------------
print('=== _smoke_input ===')
smoke_globals = {
    'add': _smoke_input.add, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_smoke_input.main)
got_ret, got_out = _capture_compiled(_smoke_input.main, globals_=smoke_globals)
check('main() [add + print]', got_ret, want_ret, got_out, want_out)


# ---- _test_kwargs_simple --------------------------------------------------
print('=== _test_kwargs_simple ===')
# greet is compiled directly. greet("World") relies on the kwonly default
# ("Hello"), so the compiler's default prologue is exercised.
check_val('greet("World")',
          _run_compiled(_test_kwargs_simple.greet, ('World',)), 'Hello, World')
check_val('greet("Bob", greeting="Hi")',
          _run_compiled(_test_kwargs_simple.greet, ('Bob',),
                        kw={'greeting': 'Hi'}),
          'Hi, Bob')

# main() calls greet twice (once with a kwarg via CALL_KW) and print.
kw_globals = {
    'greet': _test_kwargs_simple.greet, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_kwargs_simple.main)
got_ret, got_out = _capture_compiled(_test_kwargs_simple.main,
                                    globals_=kw_globals)
check('main() [CALL_KW kwargs]', got_ret, want_ret, got_out, want_out)


# ---- _test_async ----------------------------------------------------------
print('=== _test_async ===')

# fetch is an async coroutine -> must raise UnsupportedOpcode.
try:
    compile_func(_test_async.fetch)
    failed += 1
    print('  FAIL fetch: expected UnsupportedOpcode, got success')
except UnsupportedOpcode as e:
    passed += 1
    skipped.append('fetch (%s)' % e)
    print('  OK  fetch -> UnsupportedOpcode (skipped): %s' % e)

# gen: a real generator (CO_GENERATOR). Exercises the generator path.
gen_blob = compile_func(_test_async.gen)
gen_result = _run_compiled(_test_async.gen, (5,),
                           globals_={'range': range, '__builtins__': __builtins__})
check_val('list(gen(5))', list(gen_result), [0, 1, 2, 3, 4])

# kwargs_func: kwonly params b (required) and c (default 10).
check_val('kwargs_func(1,b=2,c=3)',
          _run_compiled(_test_async.kwargs_func, (1,),
                        kw={'b': 2, 'c': 3}),
          6)
check_val('kwargs_func(1,b=2) [c default]',
          _run_compiled(_test_async.kwargs_func, (1,), kw={'b': 2}),
          13)

# main(): sum(gen(5)) + kwargs_func(...) + print. Uses CALL_KW.
async_globals = {
    'sum': sum, 'gen': _test_async.gen,
    'kwargs_func': _test_async.kwargs_func, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_async.main)
got_ret, got_out = _capture_compiled(_test_async.main, globals_=async_globals)
check('main() [gen + CALL_KW]', got_ret, want_ret, got_out, want_out)


# ---- summary --------------------------------------------------------------
total = passed + failed
print()
print('=== Compiler: %d/%d functions match reference ===' % (passed, total))
if skipped:
    print('Skipped (UnsupportedOpcode):')
    for s in skipped:
        print('  -', s)
sys.exit(1 if failed else 0)
