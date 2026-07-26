"""Wave 3 integration test: compiler output → C interpreter.

The critical end-to-end gate: compile each test function with
_native_vm_compiler.compile_func(), then run the resulting blob through the
COMPILED C extension (_xvm.run), NOT the reference interpreter. This catches
divergences between the compiler's bytecode (adapted to reference quirks) and
the C interpreter (built to match reference oracle bytecodes).

Run:  python bedrock_native/_integration_test.py
Exit 0 if all pass; non-zero on failure.
"""
import io
import sys
import contextlib
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _PARENT)

from _native_vm_compiler import compile_func, UnsupportedOpcode  # noqa: E402
import _xvm  # the compiled C extension  # noqa: E402

# Builtins: the reference/C LOAD_GLOBAL has no builtins fallback, so any
# builtin a function references (range, sum, print, ...) must be in globals.
import builtins as _builtins_mod
_BUILTIN_GLOBALS = {name: getattr(_builtins_mod, name)
                    for name in dir(_builtins_mod)}
_BUILTIN_GLOBALS['__builtins__'] = _builtins_mod

import _test_obf
import _smoke_input
import _test_kwargs_simple
import _test_async

passed = 0
failed = 0
skipped = []


def _bind_kwargs(func, args, kw):
    """Bind args + kw into a positional tuple for the C extension's run(),
    which does not accept a separate kw parameter. The compiler bakes kwonly
    defaults into a bytecode prologue, so unbound kwonly slots stay None and
    the prologue fills them."""
    if not kw:
        return tuple(args)
    varnames = func.__code__.co_varnames
    nargs = func.__code__.co_argcount + func.__code__.co_kwonlyargcount
    bound = list(args) + [None] * max(0, nargs - len(args))
    for i, vn in enumerate(varnames[:nargs]):
        if vn in kw:
            if i < len(bound):
                bound[i] = kw[vn]
            else:
                bound.append(kw[vn])
    return tuple(bound)


def _run_compiled_c(func, args=(), kw=None, globals_=None):
    """Compile `func`, run the blob through the C extension _xvm.run()."""
    blob, perm, perm_ext, key, frame = compile_func(func)
    if globals_ is None:
        g = dict(_BUILTIN_GLOBALS)
    else:
        g = globals_
    bound_args = _bind_kwargs(func, args, kw or {})
    return _xvm.run(blob, perm, key, bound_args, g, perm_ext)


def _capture(func, *args, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = func(*args, **kw)
    return ret, buf.getvalue()


def _capture_compiled_c(func, args=(), kw=None, globals_=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        ret = _run_compiled_c(func, args=args, kw=kw, globals_=globals_)
    return ret, buf.getvalue()


def check(label, got_ret, want_ret, got_out, want_out):
    global passed, failed
    ok = (got_ret == want_ret) and (got_out == want_out)
    if ok:
        passed += 1
        print('  OK  %-42s ret=%r' % (label, got_ret))
    else:
        failed += 1
        print('  FAIL %-42s' % label)
        print('       ret: got=%r want=%r' % (got_ret, want_ret))
        print('       out: got=%r want=%r' % (got_out, want_out))


def check_val(label, got, want):
    global passed, failed
    if got == want:
        passed += 1
        print('  OK  %-42s -> %r' % (label, got))
    else:
        failed += 1
        print('  FAIL %-42s got=%r want=%r' % (label, got, want))


# ---- _test_obf ------------------------------------------------------------
print('=== _test_obf (compiler → C interpreter) ===')

check_val('add(3,4)', _run_compiled_c(_test_obf.add, (3, 4)), 7)
check_val('multiply(5,6)', _run_compiled_c(_test_obf.multiply, (5, 6)), 30)
check_val('fib(10)', _run_compiled_c(_test_obf.fib, (10,)), 55)
check_val('is_prime(17)', _run_compiled_c(_test_obf.is_prime, (17,)), True)
check_val('is_prime(18)', _run_compiled_c(_test_obf.is_prime, (18,)), False)
check_val('is_prime(2)', _run_compiled_c(_test_obf.is_prime, (2,)), True)
check_val('is_prime(1)', _run_compiled_c(_test_obf.is_prime, (1,)), False)

# main(): listcomp + nested calls + print + sum.
obf_globals = {
    'add': _test_obf.add, 'multiply': _test_obf.multiply,
    'fib': _test_obf.fib, 'is_prime': _test_obf.is_prime,
    'range': range, 'sum': sum, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_obf.main)
got_ret, got_out = _capture_compiled_c(_test_obf.main, globals_=obf_globals)
check('main() [listcomp + calls] → 221', got_ret, want_ret, got_out, want_out)


# ---- _smoke_input ---------------------------------------------------------
print('=== _smoke_input (compiler → C interpreter) ===')
smoke_globals = {
    'add': _smoke_input.add, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_smoke_input.main)
got_ret, got_out = _capture_compiled_c(_smoke_input.main, globals_=smoke_globals)
check('main() [add + print]', got_ret, want_ret, got_out, want_out)


# ---- _test_kwargs_simple --------------------------------------------------
print('=== _test_kwargs_simple (compiler → C interpreter) ===')
check_val('greet("World") [kwonly default]',
          _run_compiled_c(_test_kwargs_simple.greet, ('World',)),
          'Hello, World')
check_val('greet("Bob", greeting="Hi") [kwarg]',
          _run_compiled_c(_test_kwargs_simple.greet, ('Bob',),
                          kw={'greeting': 'Hi'}),
          'Hi, Bob')

kw_globals = {
    'greet': _test_kwargs_simple.greet, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_kwargs_simple.main)
got_ret, got_out = _capture_compiled_c(_test_kwargs_simple.main,
                                       globals_=kw_globals)
check('main() [CALL_KW kwargs]', got_ret, want_ret, got_out, want_out)


# ---- _test_async ----------------------------------------------------------
print('=== _test_async (compiler → C interpreter) ===')

# fetch: async → UnsupportedOpcode (should be skipped at the apply pass level).
try:
    compile_func(_test_async.fetch)
    failed += 1
    print('  FAIL fetch: expected UnsupportedOpcode, got success')
except UnsupportedOpcode as e:
    passed += 1
    skipped.append('fetch (%s)' % e)
    print('  OK  fetch -> UnsupportedOpcode (skipped): %s' % e)

# gen: generator — C extension delegates generators to the reference interpreter.
gen_result = _run_compiled_c(_test_async.gen, (5,),
                             globals_={'range': range, '__builtins__': __builtins__})
check_val('list(gen(5)) [generator, C→ref delegate]',
          list(gen_result), [0, 1, 2, 3, 4])

# kwargs_func: required kwonly b + defaulted kwonly c.
check_val('kwargs_func(1,b=2,c=3)',
          _run_compiled_c(_test_async.kwargs_func, (1,), kw={'b': 2, 'c': 3}),
          6)
check_val('kwargs_func(1,b=2) [c default]',
          _run_compiled_c(_test_async.kwargs_func, (1,), kw={'b': 2}),
          13)

async_globals = {
    'sum': sum, 'gen': _test_async.gen,
    'kwargs_func': _test_async.kwargs_func, 'print': print,
    '__builtins__': __builtins__,
}
want_ret, want_out = _capture(_test_async.main)
got_ret, got_out = _capture_compiled_c(_test_async.main, globals_=async_globals)
check('main() [gen + CALL_KW]', got_ret, want_ret, got_out, want_out)


# ---- summary --------------------------------------------------------------
total = passed + failed
print()
print('=== Wave 3 integration (compiler → C interpreter): %d/%d pass ===' % (passed, total))
if skipped:
    print('Skipped (UnsupportedOpcode):')
    for s in skipped:
        print('  -', s)
sys.exit(1 if failed else 0)
