"""Oracle bytecodes for BedrockVM (Wave 1).

Hand-built BedrockVM programs proving the reference interpreter runs correctly
on representative user-code shapes. These become the gold standard that the C
interpreter (Wave 2B) and the Python compiler (Wave 2A) must match.

All bytecodes use the label-based `assemble()` helper — no manual instruction
index counting, so no off-by-one jump bugs.

Run:  python bedrock_native/_oracle_bytecodes.py
Exits 0 if all pass; non-zero with a failure summary otherwise.
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from _bedrock_vm_ref import (  # noqa: E402
    _OPCODES as OP, encode, decode, run, Frame, run_func, assemble,
)


def _O(name):
    return OP[name]


# ---- helpers ---------------------------------------------------------------
def build_and_run(items, consts, names, *, argcount=0, kwonly_count=0,
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
        return run_func(frame, args, kw, globals_)
    return run(blob, perm, key2, args, globals_, perm_ext)


# ---- oracle 1: stack add (a + b) ------------------------------------------
def oracle_stack_add():
    """def add(a, b): return a + b   →  add(3, 4) == 7"""
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 0),
        ('RETURN_VALUE', 0),
    ]
    result = build_and_run(items, consts=(), names=(), argcount=2, nlocals=2,
                           args=(3, 4))
    assert result == 7, f'oracle_stack_add: got {result!r}'
    print('  OK oracle_stack_add: add(3,4) =', result)


# ---- oracle 2: multiply (a * b) -------------------------------------------
def oracle_multiply():
    """def multiply(a, b): return a * b   →  multiply(5, 6) == 30"""
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 2),
        ('RETURN_VALUE', 0),
    ]
    result = build_and_run(items, consts=(), names=(), argcount=2, nlocals=2,
                          args=(5, 6))
    assert result == 30, f'oracle_multiply: got {result!r}'
    print('  OK oracle_multiply: multiply(5,6) =', result)


# ---- oracle 3: factorial loop (while) -------------------------------------
def oracle_factorial():
    """def fact(n):
           r = 1
           i = 2
           while i <= n:
               r = r * i
               i = i + 1
           return r
       fact(5) == 120"""
    # locals: 0=n, 1=r, 2=i
    items = [
        ('RESUME', 0),
        ('LOAD_CONST', 0), ('STORE_FAST', 1),     # r = 1
        ('LOAD_CONST', 1), ('STORE_FAST', 2),     # i = 2
        ('LABEL', 'loop'),
        ('LOAD_FAST', 2), ('LOAD_FAST', 0),       # i, n
        ('COMPARE_OP', 1), ('JUMP_IF_FALSE', 'end'),  # i <= n ?
        ('LOAD_FAST', 1), ('LOAD_FAST', 2),       # r, i
        ('BINARY_OP', 2), ('STORE_FAST', 1),      # r = r * i
        ('LOAD_FAST', 2), ('LOAD_CONST', 0),      # i, 1 (const[0]=1, the init r value)
        ('BINARY_OP', 0), ('STORE_FAST', 2),      # i = i + 1
        ('JUMP', 'loop'),
        ('LABEL', 'end'),
        ('LOAD_FAST', 1), ('RETURN_VALUE', 0),
    ]
    result = build_and_run(items, consts=(1, 2), names=(),
                          argcount=1, nlocals=3, args=(5,))
    assert result == 120, f'oracle_factorial: got {result!r}'
    print('  OK oracle_factorial: fact(5) =', result)


# ---- oracle 4: fibonacci with for loop ------------------------------------
def oracle_fib_loop():
    """def fib(n):
           if n < 2: return n
           a, b = 0, 1
           for _ in range(2, n + 1):
               temp = a + b
               a = b
               b = temp
           return b
       fib(10) == 55"""
    # locals: 0=n, 1=a, 2=b, 3=_, 4=temp
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_CONST', 0),      # n, 2
        ('COMPARE_OP', 0), ('JUMP_IF_FALSE', 'init'),  # n < 2 ?
        ('LOAD_FAST', 0), ('RETURN_VALUE', 0),     # return n
        ('LABEL', 'init'),
        ('LOAD_CONST', 1), ('UNPACK_SEQUENCE', 2),  # (0, 1)
        ('STORE_FAST', 2), ('STORE_FAST', 1),      # b=1, a=0  (top=b popped first)
        ('LOAD_GLOBAL', 0), ('LOAD_CONST', 0),     # range, 2
        ('LOAD_FAST', 0), ('LOAD_CONST', 2),       # n, 1
        ('BINARY_OP', 0), ('CALL', 2), ('GET_ITER', 0),  # range(2, n+1), iter
        ('LABEL', 'for'),
        ('FOR_ITER', 'after'), ('STORE_FAST', 3),  # for _ in ...
        ('LOAD_FAST', 1), ('LOAD_FAST', 2),         # a, b
        ('BINARY_OP', 0), ('STORE_FAST', 4),        # temp = a + b
        ('LOAD_FAST', 2), ('STORE_FAST', 1),         # a = b
        ('LOAD_FAST', 4), ('STORE_FAST', 2),         # b = temp
        ('JUMP', 'for'),
        ('LABEL', 'after'),
        ('LOAD_FAST', 2), ('RETURN_VALUE', 0),       # return b
    ]
    result = build_and_run(items, consts=(2, (0, 1), 1), names=('range',),
                          argcount=1, nlocals=5, args=(10,),
                          globals_={'range': range})
    assert result == 55, f'oracle_fib_loop: got {result!r}'
    print('  OK oracle_fib_loop: fib(10) =', result)


# ---- oracle 5: is_prime with nested if + while + modulo -------------------
def oracle_is_prime():
    """def is_prime(n):
           if n < 2: return False
           if n < 4: return True
           if n % 2 == 0: return False
           i = 3
           while i * i <= n:
               if n % i == 0: return False
               i += 2
           return True
       is_prime(17) == True, is_prime(18) == False, is_prime(2)==True, is_prime(1)==False"""
    # locals: 0=n, 1=i
    # consts: idx0=2, idx1=4, idx2=False, idx3=True, idx4=3, idx5=0
    items = [
        ('RESUME', 0),
        # if n < 2: return False
        ('LOAD_FAST', 0), ('LOAD_CONST', 0), ('COMPARE_OP', 0),     # n < 2
        ('JUMP_IF_FALSE', 'chk2'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),                      # return False
        ('LABEL', 'chk2'),
        # if n < 4: return True
        ('LOAD_FAST', 0), ('LOAD_CONST', 1), ('COMPARE_OP', 0),      # n < 4
        ('JUMP_IF_FALSE', 'chk3'),
        ('LOAD_CONST', 3), ('RETURN_VALUE', 0),                      # return True
        ('LABEL', 'chk3'),
        # if n % 2 == 0: return False
        ('LOAD_FAST', 0), ('LOAD_CONST', 0), ('BINARY_OP', 4),       # n % 2
        ('LOAD_CONST', 5), ('COMPARE_OP', 2),                        # == 0
        ('JUMP_IF_FALSE', 'initi'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),                      # return False
        ('LABEL', 'initi'),
        # i = 3
        ('LOAD_CONST', 4), ('STORE_FAST', 1),
        # while i * i <= n:
        ('LABEL', 'wloop'),
        ('LOAD_FAST', 1), ('LOAD_FAST', 1), ('BINARY_OP', 2),         # i * i
        ('LOAD_FAST', 0), ('COMPARE_OP', 1),                         # <= n
        ('JUMP_IF_FALSE', 'ret_true'),
        # if n % i == 0: return False
        ('LOAD_FAST', 0), ('LOAD_FAST', 1), ('BINARY_OP', 4),         # n % i
        ('LOAD_CONST', 5), ('COMPARE_OP', 2),                         # == 0
        ('JUMP_IF_FALSE', 'incr'),
        ('LOAD_CONST', 2), ('RETURN_VALUE', 0),                       # return False
        ('LABEL', 'incr'),
        # i += 2
        ('LOAD_FAST', 1), ('LOAD_CONST', 0), ('BINARY_OP', 0),       # i + 2
        ('STORE_FAST', 1),
        ('JUMP', 'wloop'),
        ('LABEL', 'ret_true'),
        ('LOAD_CONST', 3), ('RETURN_VALUE', 0),                       # return True
    ]
    consts = (2, 4, False, True, 3, 0)
    for n, expected in [(17, True), (18, False), (2, True), (1, False), (13, True), (25, False)]:
        result = build_and_run(items, consts=consts, names=(),
                              argcount=1, nlocals=2, args=(n,))
        assert result is expected, f'oracle_is_prime({n}): got {result!r}, want {expected!r}'
    print('  OK oracle_is_prime: 17=T,18=F,2=T,1=F,13=T,25=F')


# ---- oracle 6: kwargs call (greet with keyword) ---------------------------
def oracle_kwargs():
    """def greet(name, *, greeting='Hello'): return greeting + ', ' + name
       greet('Bob', greeting='Hi') == 'Hi, Bob'"""
    # locals: 0=name, 1=greeting
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 1), ('LOAD_CONST', 0),     # greeting, ', '
        ('BINARY_OP', 0), ('LOAD_FAST', 0),       # greeting+', ', name
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    result = build_and_run(items, consts=(', ',), names=(),
                          argcount=1, kwonly_count=1, nlocals=2,
                          varnames=('name', 'greeting'),
                          args=('Bob',), kw={'greeting': 'Hi'})
    assert result == 'Hi, Bob', f'oracle_kwargs: got {result!r}'
    print('  OK oracle_kwargs: greet("Bob", greeting="Hi") =', repr(result))


# ---- oracle 7: list comprehension (nested frame) --------------------------
def oracle_listcomp():
    """[n for n in range(2, 8) if n % 2 == 0]  →  [2, 4, 6]

    Models a comprehension: the inner listcomp function takes the iterator
    (.0) and builds a list, appending n where n % 2 == 0."""
    # Inner listcomp frame: locals 0=.0 (iter), 1=n, 2=lst
    inner_items = [
        ('RESUME', 0),
        ('BUILD_LIST', 0), ('STORE_FAST', 2),       # lst = []
        ('LABEL', 'for'),
        ('LOAD_FAST', 0), ('FOR_ITER', 'done'),     # iter
        ('STORE_FAST', 1),                            # n
        ('LOAD_FAST', 1), ('LOAD_CONST', 0),         # n, 2
        ('BINARY_OP', 4),                             # n % 2
        ('LOAD_CONST', 1), ('COMPARE_OP', 2),        # == 0
        ('JUMP_IF_FALSE', 'skip'),
        ('LOAD_FAST', 1), ('LIST_APPEND', 2),        # lst.append(n)
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
    it = iter(range(2, 8))
    result = run_func(inner_frame, (it,), {},
                      {'__builtins__': __builtins__})
    assert result == [2, 4, 6], f'oracle_listcomp: got {result!r}'
    print('  OK oracle_listcomp: [n for n in range(2,8) if n%2==0] =', result)


# ---- oracle 8: generator (yield in loop) -----------------------------------
def oracle_generator():
    """def gen(n):
           for i in range(n):
               yield i
       list(gen(5)) == [0, 1, 2, 3, 4]"""
    # locals: 0=n, 1=i
    items = [
        ('RESUME', 0),
        ('RETURN_GENERATOR', 0),
        ('LOAD_GLOBAL', 0), ('LOAD_FAST', 0),       # range, n
        ('CALL', 1), ('GET_ITER', 0),                 # iter(range(n))
        ('LABEL', 'for'),
        ('FOR_ITER', 'end'), ('STORE_FAST', 1),      # for i
        ('LOAD_FAST', 1), ('YIELD_VALUE', 0),         # yield i
        ('JUMP', 'for'),
        ('LABEL', 'end'),
        ('LOAD_CONST', 0), ('RETURN_VALUE', 0),
    ]
    result = build_and_run(items, consts=(None,), names=('range',),
                          argcount=1, nlocals=2, flags=0x2,  # is_generator
                          varnames=('n', 'i'), args=(5,),
                          globals_={'range': range})
    result = list(result)
    assert result == [0, 1, 2, 3, 4], f'oracle_generator: got {result!r}'
    print('  OK oracle_generator: list(gen(5)) =', result)


# ---- oracle 9: const-pool encryption -------------------------------------
def oracle_encrypted_consts():
    """Same as oracle_stack_add but with an encrypted const pool. Proves the
    OFB decrypt path works end-to-end."""
    items = [
        ('RESUME', 0),
        ('LOAD_CONST', 0), ('LOAD_CONST', 1),
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    key = b'\x42' * 32
    result = build_and_run(items, consts=(3, 4), names=(),
                          argcount=0, nlocals=0, key=key)
    assert result == 7, f'oracle_encrypted_consts: got {result!r}'
    print('  OK oracle_encrypted_consts: encrypted add(3,4) =', result)


# ---- oracle 10: opcode permutation ----------------------------------------
def oracle_permutation():
    """Same as oracle_stack_add but with a non-identity permutation. Proves
    de-scrambling works."""
    items = [
        ('RESUME', 0),
        ('LOAD_FAST', 0), ('LOAD_FAST', 1),
        ('BINARY_OP', 0), ('RETURN_VALUE', 0),
    ]
    code = assemble(items)
    # Build a bijection: shift every canonical value by +10 mod 256,
    # keep EXTENDED_ARG's scrambled byte fixed at 154.
    from _bedrock_vm_ref import _OPCODES as OPS
    perm = {}
    for name, val in OPS.items():
        perm[(val + 10) % 256] = val
    perm[154] = 144   # EXTENDED_ARG scrambled byte = 154
    perm_ext_byte = 154
    blob, _, _, key = encode(
        (), (), code, argcount=2, nlocals=2, perm=perm, perm_ext=perm_ext_byte)
    result = run(blob, perm, key, (3, 4),
                 {'__builtins__': __builtins__}, perm_ext_byte)
    assert result == 7, f'oracle_permutation: got {result!r}'
    print('  OK oracle_permutation: scrambled add(3,4) =', result)


# ---- runner ----------------------------------------------------------------
ORACLES = [
    oracle_stack_add, oracle_multiply, oracle_factorial, oracle_fib_loop,
    oracle_is_prime, oracle_kwargs, oracle_listcomp, oracle_generator,
    oracle_encrypted_consts, oracle_permutation,
]


def main():
    print('=== BedrockVM oracle bytecodes (Wave 1) ===')
    failures = 0
    for fn in ORACLES:
        try:
            fn()
        except Exception as e:
            failures += 1
            print(f'  FAIL {fn.__name__}: {type(e).__name__}: {e}')
            import traceback
            traceback.print_exc()
    print(f'=== {len(ORACLES) - failures}/{len(ORACLES)} passed ===')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
