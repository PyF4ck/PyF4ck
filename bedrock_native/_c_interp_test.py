"""C interpreter test for BedrockVM (Wave 2B).

Routes every oracle bytecode program through BOTH the pure-Python reference
interpreter (`_bedrock_vm_ref`) and the compiled C extension (`_xvm`), then
asserts the two produce identical results.

The oracle programs in `_oracle_bytecodes.py` drive the reference interpreter
via `build_and_run()` / `run_func()`. The C extension `_xvm.run()` consumes a
*blob* (no Frame, no kw dict), so this test:

  * defines `build_and_run_ref`  -> reference interpreter (oracle path)
  * defines `build_and_run_c`    -> C extension (`_xvm.run`)
  * re-runs each oracle program through both and compares.

Special cases:
  - oracle_kwargs: the C `run()` has no kw parameter, so keyword values are
    bound positionally into the args tuple at their `varnames` index (exactly
    what the reference's `run_func` does internally).
  - oracle_listcomp: builds an inner `Frame` directly. To run it through C we
    re-encode that frame to a blob with `encode()` and call `_xvm.run`.
  - oracle_permutation: uses a custom non-identity perm; we pass the same perm
    dict + perm_ext to both interpreters.

Run:  python bedrock_native/_c_interp_test.py
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from _bedrock_vm_ref import (  # noqa: E402
    _OPCODES as OP, encode, decode, run as ref_run, run_func as ref_run_func,
    Frame, assemble,
)
import _xvm  # noqa: E402  (the compiled C extension)


def _O(name):
    return OP[name]


# ---- reference-path helper (mirrors _oracle_bytecodes.build_and_run) --------
def build_and_run_ref(items, consts, names, *, argcount=0, kwonly_count=0,
                      nlocals=0, flags=0, args=(), kw=None, globals_=None,
                      varnames=(), freevars=(), cellvars=(), key=b''):
    code = assemble(items)
    if globals_ is None:
        globals_ = {'__builtins__': __builtins__}
    blob, perm, perm_ext, key2 = encode(
        consts, names, code,
        argcount=argcount, kwonly_count=kwonly_count, nlocals=nlocals,
        flags=flags, key=key, varnames=varnames, freevars=freevars,
        cellvars=cellvars)
    if kw is not None:
        frame = decode(blob, perm, key2, perm_ext)
        return ref_run_func(frame, args, kw, globals_)
    return ref_run(blob, perm, key2, args, globals_, perm_ext)


# ---- bind kwargs positionally into args at their varnames index -------------
def _bind_kw(args, kw, varnames):
    if not kw:
        return tuple(args)
    local = list(args) + [None] * max(0, len(varnames) - len(args))
    for name, val in kw.items():
        idx = varnames.index(name)
        local[idx] = val
    return tuple(local)


# ---- C-extension-path helper ------------------------------------------------
def build_and_run_c(items, consts, names, *, argcount=0, kwonly_count=0,
                    nlocals=0, flags=0, args=(), kw=None, globals_=None,
                    varnames=(), freevars=(), cellvars=(), key=b''):
    code = assemble(items)
    if globals_ is None:
        globals_ = {'__builtins__': __builtins__}
    blob, perm, perm_ext, key2 = encode(
        consts, names, code,
        argcount=argcount, kwonly_count=kwonly_count, nlocals=nlocals,
        flags=flags, key=key, varnames=varnames, freevars=freevars,
        cellvars=cellvars)
    # The C extension's run() has no kw parameter; bind kwargs positionally.
    bound_args = _bind_kw(args, kw, varnames) if kw else tuple(args)
    return _xvm.run(blob, perm, key2, bound_args, globals_, perm_ext)


# ---- run an inner Frame through the C extension (encode -> blob -> C run) ----
def run_frame_c(frame, args, globals_=None):
    if globals_ is None:
        globals_ = {'__builtins__': __builtins__}
    blob, perm, perm_ext, key = encode(
        frame.consts, frame.names, frame.code,
        argcount=frame.argcount, kwonly_count=frame.kwonly_count,
        nlocals=frame.nlocals, flags=frame.flags,
        varnames=frame.varnames, freevars=frame.freevars,
        cellvars=frame.cellvars)
    return _xvm.run(blob, perm, key, tuple(args), globals_, perm_ext)


def run_frame_ref(frame, args, globals_=None):
    if globals_ is None:
        globals_ = {'__builtins__': __builtins__}
    return ref_run_func(frame, args, {}, globals_)


# ===========================================================================
# Oracle programs (bytecode copied verbatim from _oracle_bytecodes.py, but
# each is run through BOTH reference and C extension and compared).
# ===========================================================================

PASS = 0
FAIL = 0


def check(name, ref_result, c_result):
    global PASS, FAIL
    # Normalize: compare via repr so generator/list/etc. compare structurally,
    # but also do a direct == first.
    ok = False
    try:
        ok = (ref_result == c_result) or (repr(ref_result) == repr(c_result))
    except Exception:
        ok = repr(ref_result) == repr(c_result)
    if ok:
        PASS += 1
        print(f'  OK {name}: C matches reference ({ref_result!r})')
    else:
        FAIL += 1
        print(f'  FAIL {name}: ref={ref_result!r} C={c_result!r}')


def oracle_stack_add():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 0),
        ('RETURN_VALUE', 0),
    ]
    r = build_and_run_ref(items, consts=(), names=(), argcount=2,
                          nlocals=2, args=(3, 4))
    c = build_and_run_c(items, consts=(), names=(), argcount=2,
                       nlocals=2, args=(3, 4))
    check('oracle_stack_add', r, c)


def oracle_multiply():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 2),
        ('RETURN_VALUE', 0),
    ]
    r = build_and_run_ref(items, consts=(), names=(), argcount=2,
                          nlocals=2, args=(5, 6))
    c = build_and_run_c(items, consts=(), names=(), argcount=2,
                       nlocals=2, args=(5, 6))
    check('oracle_multiply', r, c)


def oracle_factorial():
    items = [
        ('RESUME', 0),
        ('LOAD_CONST', 0), ('STORE_FAST', 1),
        ('LOAD_CONST', 1), ('STORE_FAST', 2),
        ('LABEL', 'loop'),
        ('LOAD_FAST', 2), ('LOAD_FAST', 0),
        ('COMPARE_OP', 1), ('JUMP_IF_FALSE', 'end'),
        ('LOAD_FAST', 1), ('LOAD_FAST', 2),
        ('BINARY_OP', 2), ('STORE_FAST', 1),
        ('LOAD_FAST', 2), ('LOAD_CONST', 0),
        ('BINARY_OP', 0), ('STORE_FAST', 2),
        ('JUMP', 'loop'),
        ('LABEL', 'end'),
        ('LOAD_FAST', 1), ('RETURN_VALUE', 0),
    ]
    r = build_and_run_ref(items, consts=(1, 2), names=(), argcount=1,
                          nlocals=3, args=(5,))
    c = build_and_run_c(items, consts=(1, 2), names=(), argcount=1,
                       nlocals=3, args=(5,))
    check('oracle_factorial', r, c)


def oracle_fib_loop():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_CONST', 0),
        ('COMPARE_OP', 0), ('JUMP_IF_FALSE', 'init'),
        ('LOAD_FAST', 0), ('RETURN_VALUE', 0),
        ('LABEL', 'init'),
        ('LOAD_CONST', 1), ('UNPACK_SEQUENCE', 2),
        ('STORE_FAST', 2), ('STORE_FAST', 1),
        ('LOAD_GLOBAL', 0), ('LOAD_CONST', 0),
        ('LOAD_FAST', 0), ('LOAD_CONST', 2),
        ('BINARY_OP', 0), ('CALL', 2), ('GET_ITER', 0),
        ('LABEL', 'for'),
        ('FOR_ITER', 'after'), ('STORE_FAST', 3),
        ('LOAD_FAST', 1), ('LOAD_FAST', 2),
        ('BINARY_OP', 0), ('STORE_FAST', 4),
        ('LOAD_FAST', 2), ('STORE_FAST', 1),
        ('LOAD_FAST', 4), ('STORE_FAST', 2),
        ('JUMP', 'for'),
        ('LABEL', 'after'),
        ('LOAD_FAST', 2), ('RETURN_VALUE', 0),
    ]
    g = {'range': range}
    r = build_and_run_ref(items, consts=(2, (0, 1), 1), names=('range',),
                         argcount=1, nlocals=5, args=(10,), globals_=g)
    c = build_and_run_c(items, consts=(2, (0, 1), 1), names=('range',),
                       argcount=1, nlocals=5, args=(10,), globals_=g)
    check('oracle_fib_loop', r, c)


def oracle_is_prime():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_CONST', 0), ('COMPARE_OP', 0),
        ('JUMP_IF_FALSE', 'chk2'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),
        ('LABEL', 'chk2'),
        ('LOAD_FAST', 0), ('LOAD_CONST', 1), ('COMPARE_OP', 0),
        ('JUMP_IF_FALSE', 'chk3'),
        ('LOAD_CONST', 3), ('RETURN_VALUE', 0),
        ('LABEL', 'chk3'),
        ('LOAD_FAST', 0), ('LOAD_CONST', 0), ('BINARY_OP', 4),
        ('LOAD_CONST', 5), ('COMPARE_OP', 2),
        ('JUMP_IF_FALSE', 'initi'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),
        ('LABEL', 'initi'),
        ('LOAD_CONST', 4), ('STORE_FAST', 1),
        ('LABEL', 'wloop'),
        ('LOAD_FAST', 1), ('LOAD_FAST', 1), ('BINARY_OP', 2),
        ('LOAD_FAST', 0), ('COMPARE_OP', 1),
        ('JUMP_IF_FALSE', 'ret_true'),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1), ('BINARY_OP', 4),
        ('LOAD_CONST', 5), ('COMPARE_OP', 2),
        ('JUMP_IF_FALSE', 'incr'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),
        ('LABEL', 'incr'),
        ('LOAD_FAST', 1), ('LOAD_CONST', 0), ('BINARY_OP', 0),
        ('STORE_FAST', 1),
        ('JUMP', 'wloop'),
        ('LABEL', 'ret_true'),
        ('LOAD_CONST', 3), ('RETURN_VALUE', 0),
    ]
    consts = (2, 4, False, True, 3, 0)
    cases = [(17, True), (18, False), (2, True), (1, False), (13, True), (25, False)]
    ok_all = True
    detail = []
    for n, expected in cases:
        r = build_and_run_ref(items, consts=consts, names=(), argcount=1,
                              nlocals=2, args=(n,))
        c = build_and_run_c(items, consts=consts, names=(), argcount=1,
                           nlocals=2, args=(n,))
        if not (r is expected and c is expected and r is c):
            ok_all = False
            detail.append((n, r, c, expected))
    if ok_all:
        check('oracle_is_prime', '17=T,18=F,2=T,1=F,13=T,25=F',
              '17=T,18=F,2=T,1=F,13=T,25=F')
    else:
        global FAIL
        FAIL += 1
        print(f'  FAIL oracle_is_prime: {detail}')


def oracle_kwargs():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 1), ('LOAD_CONST', 0),
        ('BINARY_OP', 0), ('LOAD_FAST', 0),
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    kw = {'greeting': 'Hi'}
    vn = ('name', 'greeting')
    r = build_and_run_ref(items, consts=(', ',), names=(), argcount=1,
                         kwonly_count=1, nlocals=2, varnames=vn,
                         args=('Bob',), kw=kw)
    # kw dict was mutated by ref run_func (pop); rebuild for C.
    c = build_and_run_c(items, consts=(', ',), names=(), argcount=1,
                       kwonly_count=1, nlocals=2, varnames=vn,
                       args=('Bob',), kw={'greeting': 'Hi'})
    check('oracle_kwargs', r, c)


def oracle_listcomp():
    inner_items = [
        ('RESUME', 0),
        ('BUILD_LIST', 0), ('STORE_FAST', 2),
        ('LABEL', 'for'),
        ('LOAD_FAST', 0), ('FOR_ITER', 'done'),
        ('STORE_FAST', 1),
        ('LOAD_FAST', 1), ('LOAD_CONST', 0),
        ('BINARY_OP', 4),
        ('LOAD_CONST', 1), ('COMPARE_OP', 2),
        ('JUMP_IF_FALSE', 'skip'),
        ('LOAD_FAST', 1), ('LIST_APPEND', 2),
        ('LABEL', 'skip'),
        ('JUMP', 'for'),
        ('LABEL', 'done'),
        ('LOAD_FAST', 2), ('RETURN_VALUE', 0),
    ]
    inner_code = assemble(inner_items)
    inner_frame = Frame(
        code=inner_code, consts=(2, 0), names=(),
        argcount=1, kwonly_count=0, nlocals=3, flags=0,
        varnames=('.0', 'n', 'lst'), freevars=(), cellvars=())
    g = {'__builtins__': __builtins__}
    # Reference result
    r = run_frame_ref(inner_frame, (iter(range(2, 8)),), g)
    # C result (re-encode the inner frame to a blob)
    c = run_frame_c(inner_frame, (iter(range(2, 8)),), g)
    check('oracle_listcomp', r, c)


def oracle_generator():
    items = [
        ('RESUME', 0),
        ('RETURN_GENERATOR', 0),
        ('LOAD_GLOBAL', 0), ('LOAD_FAST', 0),
        ('CALL', 1), ('GET_ITER', 0),
        ('LABEL', 'for'),
        ('FOR_ITER', 'end'), ('STORE_FAST', 1),
        ('LOAD_FAST', 1), ('YIELD_VALUE', 0),
        ('JUMP', 'for'),
        ('LABEL', 'end'),
        ('LOAD_CONST', 0), ('RETURN_VALUE', 0),
    ]
    g = {'range': range}
    # Generator: C extension delegates to the reference interpreter (fallback).
    # Both should return a generator object; materialize via list() and compare.
    r = build_and_run_ref(items, consts=(None,), names=('range',),
                         argcount=1, nlocals=2, flags=0x2,
                         varnames=('n', 'i'), args=(5,), globals_=g)
    c = build_and_run_c(items, consts=(None,), names=('range',),
                       argcount=1, nlocals=2, flags=0x2,
                       varnames=('n', 'i'), args=(5,), globals_=g)
    r_list = list(r)
    c_list = list(c)
    check('oracle_generator', r_list, c_list)


def oracle_encrypted_consts():
    items = [
        ('RESUME', 0),
        ('LOAD_CONST', 0), ('LOAD_CONST', 1),
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    key = b'\x42' * 32
    r = build_and_run_ref(items, consts=(3, 4), names=(), argcount=0,
                         nlocals=0, key=key)
    c = build_and_run_c(items, consts=(3, 4), names=(), argcount=0,
                       nlocals=0, key=key)
    check('oracle_encrypted_consts', r, c)


def oracle_permutation():
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    code = assemble(items)
    from _bedrock_vm_ref import _OPCODES as OPS
    perm = {}
    for name, val in OPS.items():
        perm[(val + 10) % 256] = val
    perm[154] = 144   # EXTENDED_ARG scrambled byte = 154
    perm_ext_byte = 154
    blob, _, _, key = encode((), (), code, argcount=2, nlocals=2,
                             perm=perm, perm_ext=perm_ext_byte)
    g = {'__builtins__': __builtins__}
    r = ref_run(blob, perm, key, (3, 4), g, perm_ext_byte)
    c = _xvm.run(blob, perm, key, (3, 4), g, perm_ext_byte)
    check('oracle_permutation', r, c)


ORACLES = [
    oracle_stack_add, oracle_multiply, oracle_factorial, oracle_fib_loop,
    oracle_is_prime, oracle_kwargs, oracle_listcomp, oracle_generator,
    oracle_encrypted_consts, oracle_permutation,
]


def main():
    print('=== BedrockVM C interpreter test (Wave 2B) ===')
    print('  C extension:', _xvm.__file__)
    for fn in ORACLES:
        try:
            fn()
        except Exception as e:
            global FAIL
            FAIL += 1
            print(f'  FAIL {fn.__name__}: {type(e).__name__}: {e}')
            import traceback
            traceback.print_exc()
    print(f'C interpreter: {PASS}/10 oracles match reference')
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
