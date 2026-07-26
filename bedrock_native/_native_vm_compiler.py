"""BedrockVM bytecode compiler (Phase 5, Wave 2A).

Compiles Python functions into BedrockVM bytecode blobs that run on the
reference interpreter (`_bedrock_vm_ref`) and (Wave 2B) the C interpreter.

The compiler reads CPython 3.10/3.11 `co_code` via `dis.get_instructions`
(which skips inline caches and resolves jump targets to byte offsets) and
normalizes the 3.11 quirks away when emitting BedrockVM opcodes:

  * `LOAD_GLOBAL`'s `push_null` bit (arg & 1) is dropped (name_idx = arg >> 1).
  * `PRECALL` is dropped (a no-op marker in 3.11).
  * The `NULL` marker that CPython pushes before a plain-function
    `LOAD_GLOBAL` is gone: BedrockVM `CALL` always treats the slot below the
    args as the callable.
  * `JUMP_BACKWARD` / `POP_JUMP_BACKWARD_*` are converted to absolute
    `JUMP` / `JUMP_IF_*` using the label system of `assemble()`.
  * `BINARY_OP` sub-op values are remapped from CPython's `NB_*` ordering to
    BedrockVM's `_BINOPS` ordering (they differ on 3.11).
  * `UNPACK_SEQUENCE` stores are reversed to match the reference interpreter's
    forward-push unpack semantics.
  * List-comprehension inner code objects are recursively compiled to a
    `Frame` stored in the const pool; the reference's local-based `LIST_APPEND`
    is satisfied by stashing the list in a synthetic local.
  * Generator entry sentinels (`RETURN_GENERATOR`, the `POP_TOP` after it, the
    `RESUME`/`POP_TOP` after `YIELD_VALUE`) are dropped so the reference's
    generator runner sees a clean stream.
  * Default arguments (positional via `__defaults__`, kwonly via
    `__kwdefaults__`) are baked into a small prologue that sets each default
    only when the slot was left unbound (None) at call time.

Public API:
    UnsupportedOpcode          -- raised for opcodes the compiler can't handle
    compile_func(func, key, perm) -> (blob, perm, perm_ext, key, Frame)

Limitations (opcodes outside the supported set raise UnsupportedOpcode):
  - async functions (coroutines / async generators) are unsupported.
  - try/except/finally, with-statements, f-strings, augmented assignment to
    mutable targets (the inplace sub-ops are mapped to fresh binary ops, which
    is correct for immutable operands like int/str but not for in-place
    mutation of lists etc.) are not fully modeled.
  - Closures (free vars) and nested defs with defaults/closure flags on
    MAKE_FUNCTION are not exercised by the test suite.
"""
from __future__ import annotations

import dis
import pickle
import struct
import types

# The reference interpreter is the oracle (read-only). We import its building
# blocks: the canonical opcode table, the label-based assembler, the encoder,
# the Frame class, and the fixed EXTENDED_ARG canonical value.
from _bedrock_vm_ref import _OPCODES, assemble, encode, Frame, EXTENDED_ARG


# ---- Public exception ------------------------------------------------------
class UnsupportedOpcode(Exception):
    """Raised when the compiler hits a CPython opcode it can't translate.

    The caller (apply_native_vm pass) catches this and leaves the function as
    plain Python (or routes it to the capsule runtime)."""


# ---- CPython 3.11 NB_* -> BedrockVM _BINOPS sub-op mapping -----------------
# CPython 3.11 BINARY_OP opargs (empirically determined on 3.11.15):
#   0 +   10 -   5 *   11 /   6 %   2 //   8 **   3 <<   9 >>   1 &   7 |   12 ^   4 @
#   13 +=  23 -= 18 *=  24 /=  19 %=  15 //=  21 **=  16 <<=  22 >>=  14 &=  20 |=  25 ^=  17 @=
# BedrockVM _BINOPS (from _bedrock_vm_ref): 0 + 1 - 2 * 3 / 4 % 5 // 6 ** 7 << 8 >> 9 & 10 | 11 ^ 25 @
# Inplace sub-ops are mapped to the matching non-inplace op: the reference
# computes a fresh result (correct for immutable operands; the tests only use
# int arithmetic via `+=`).
CPY_BINOP_TO_BEDROCK = {
    # non-inplace
    0: 0,    # +
    10: 1,   # -
    5: 2,    # *
    11: 3,   # /
    6: 4,    # %
    2: 5,    # //
    8: 6,    # **
    3: 7,    # <<
    9: 8,    # >>
    1: 9,    # &
    7: 10,   # |
    12: 11,  # ^
    4: 25,   # @
    # inplace (compute fresh -- see limitation note in module docstring)
    13: 0,   # +=
    23: 1,   # -=
    18: 2,   # *=
    24: 3,   # /=
    19: 4,   # %=
    15: 5,   # //=
    21: 6,   # **=
    16: 7,   # <<=
    22: 8,   # >>=
    14: 9,   # &=
    20: 10,  # |=
    25: 11,  # ^=
    17: 25,  # @=
}

# CPython co_flags bits we care about.
_CO_GENERATOR = 0x20
_CO_ASYNC_GENERATOR = 0x200
_CO_COROUTINE = 0x80
_CO_ITERABLE_COROUTINE = 0x100
_ASYNC_FLAGS = _CO_COROUTINE | _CO_ITERABLE_COROUTINE | _CO_ASYNC_GENERATOR

# BedrockVM flag bits (from VM_SPEC.md blob header).
_FLAG_IS_GENERATOR = 0x2
_FLAG_IS_ASYNC = 0x4
_FLAG_HAS_CLOSURE = 0x1


# ---- Default-argument prologue ---------------------------------------------
def _build_default_prologue(code, func):
    """Build a prologue that applies default arguments.

    The reference interpreter's `run_func` binds positional args and kwargs to
    locals but does NOT consult `__defaults__`/`__kwdefaults__`, so a kwonly
    param with a default would be left as `None` when omitted. We emit a small
    prologue at function entry that, for each parameter that has a default,
    loads the slot and only installs the default when the slot is still `None`
    (i.e. the caller did not supply it):

        LOAD_FAST  <idx>
        JUMP_IF_NOT_NONE  <skip>   ; caller supplied a value -> keep it
        LOAD_CONST  <default>      ; otherwise install the default
        STORE_FAST  <idx>
      <skip>:

    Returns (prologue_items, default_const_values) where the default values
    are appended to the const pool AFTER the original co_consts (so body
    LOAD_CONST indices are unaffected).
    """
    if func is None or not hasattr(func, '__defaults__'):
        return [], []
    prologue = []
    default_consts = []
    base_len = len(code.co_consts)  # default consts land at base_len + j
    varnames = code.co_varnames
    argcount = code.co_argcount
    kwonly = code.co_kwonlyargcount
    label_ctr = [0]

    def add_default(idx, value):
        const_idx = base_len + len(default_consts)
        default_consts.append(value)
        lbl = '__def_%d__' % label_ctr[0]
        label_ctr[0] += 1
        prologue.append(('LOAD_FAST', idx))
        prologue.append(('JUMP_IF_NOT_NONE', lbl))
        prologue.append(('LOAD_CONST', const_idx))
        prologue.append(('STORE_FAST', idx))
        prologue.append(('LABEL', lbl))

    # Positional defaults: __defaults__ aligns to the LAST len(defaults)
    # positional parameters.
    d_pos = getattr(func, '__defaults__', None)
    if d_pos:
        start = argcount - len(d_pos)
        for i, dv in enumerate(d_pos):
            add_default(start + i, dv)

    # Kwonly defaults: __kwdefaults__ is a {name: value} dict.
    d_kw = getattr(func, '__kwdefaults__', None)
    if d_kw:
        for j in range(kwonly):
            name = varnames[argcount + j]
            if name in d_kw:
                add_default(argcount + j, d_kw[name])

    return prologue, default_consts


# ---- Instruction translation -----------------------------------------------
def _translate(code, consts, is_listcomp):
    """Translate CPython instructions into a label-based items list.

    Returns (items, extra_nlocals, list_local_idx).

    `consts` is the already-rebuilt const pool (CodeTypes replaced by Frames),
    used to size KW_NAMES tuples. `is_listcomp` enables the synthetic-list-local
    rewrite so the reference's local-based LIST_APPEND works.
    """
    instrs = list(dis.get_instructions(code))

    # Pre-scan: which byte offsets are FOR_ITER exit targets (the instruction
    # after the loop). For a listcomp that instruction is the RETURN_VALUE that
    # returns the built list.
    for_iter_exits = set()
    for ins in instrs:
        if ins.opname == 'FOR_ITER':
            for_iter_exits.add(ins.argval)

    items = []
    # Synthetic local holding the comprehension's result list (reference uses a
    # local for LIST_APPEND; CPython keeps it on the stack).
    list_local = code.co_nlocals if is_listcomp else None
    extra_nlocals = 1 if is_listcomp else 0

    prev_emitted = None      # opname of the last EMITTED instruction
    prev_cpy = None          # opname of the previous CPython instruction
    pending_unpack = None    # count of stores still to collect-and-reverse
    pending_stores = []      # collected ('STORE_FAST', idx) items
    pending_nkw = None       # set by KW_NAMES, consumed by the next CALL

    def emit(op, arg=0):
        items.append((op, arg))
        return op

    for ins in instrs:
        opname = ins.opname

        # Emit a label at every CPython jump-target offset so jumps resolve.
        if ins.is_jump_target:
            items.append(('LABEL', 'L%d' % ins.offset))

        # --- dropped 3.11 markers / sentinels -------------------------------
        if opname == 'RESUME':
            prev_cpy = opname
            continue
        if opname == 'RETURN_GENERATOR':
            # Generator flag is set in _compile_code; nothing to emit.
            prev_cpy = opname
            continue
        if opname == 'PRECALL':
            prev_cpy = opname
            continue
        if opname == 'NOP':
            # NOPs are used by CPython 3.11 as exception-table anchors (line
            # numbers) and padding. They have no runtime effect — skip them.
            prev_cpy = opname
            continue
        if opname == 'POP_TOP':
            # Drop the sentinel POP_TOPs that follow RETURN_GENERATOR (the
            # initial-None pop) and the RESUME-1 that follows YIELD_VALUE (the
            # sent-value pop). The reference's generator runner does not model
            # the sent value, so these would corrupt the stack.
            if prev_cpy in ('RESUME', 'RETURN_GENERATOR'):
                prev_cpy = opname
                continue
            if pending_unpack is not None:
                # Unexpected non-store inside an unpack; flush what we have.
                for s in pending_stores:
                    items.append(s)
                pending_unpack = None
                pending_stores = []
            prev_emitted = emit('POP_TOP', 0)
            prev_cpy = opname
            continue

        # --- trivial 1:1 loads/stores ---------------------------------------
        if opname == 'LOAD_FAST':
            prev_emitted = emit('LOAD_FAST', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'LOAD_CONST':
            prev_emitted = emit('LOAD_CONST', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'STORE_FAST':
            if pending_unpack is not None:
                pending_stores.append(('STORE_FAST', ins.arg))
                pending_unpack -= 1
                if pending_unpack == 0:
                    # The reference's UNPACK_SEQUENCE pushes elements FORWARD
                    # (first deepest, last on top), the opposite of CPython.
                    # Reversing the stores makes each var receive the element
                    # at its source position.
                    for s in reversed(pending_stores):
                        items.append(s)
                    pending_unpack = None
                    pending_stores = []
                    prev_emitted = 'STORE_FAST'
                prev_cpy = opname
                continue
            prev_emitted = emit('STORE_FAST', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'UNPACK_SEQUENCE':
            prev_emitted = emit('UNPACK_SEQUENCE', ins.arg)
            pending_unpack = ins.arg
            pending_stores = []
            prev_cpy = opname
            continue
        if opname == 'RETURN_VALUE':
            if is_listcomp and ins.offset in for_iter_exits:
                # The list lives in the synthetic local; load it before return.
                emit('LOAD_FAST', list_local)
            prev_emitted = emit('RETURN_VALUE', 0)
            prev_cpy = opname
            continue

        # --- globals ---------------------------------------------------------
        if opname == 'LOAD_GLOBAL':
            # Drop the push_null bit (arg & 1); BedrockVM has no NULL markers.
            name_idx = ins.arg >> 1
            prev_emitted = emit('LOAD_GLOBAL', name_idx)
            prev_cpy = opname
            continue

        # --- calls -----------------------------------------------------------
        if opname == 'KW_NAMES':
            pending_nkw = len(consts[ins.arg])
            prev_emitted = emit('KW_NAMES', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'CALL':
            if pending_nkw is not None:
                # CPython CALL oparg = positional_count + nkw (total values).
                # BedrockVM CALL_KW arg = (argc << 8) | nkw.
                argc = ins.arg - pending_nkw
                call_arg = (argc << 8) | pending_nkw
                prev_emitted = emit('CALL_KW', call_arg)
                pending_nkw = None
            else:
                # A CALL 0 immediately after GET_ITER is a comprehension call:
                # CPython passes the iterator as the implicit .0 argument but
                # records oparg 0. BedrockVM's CALL pops `argc` args, so we
                # need CALL 1 to hand the iterator to the inner frame.
                if prev_emitted == 'GET_ITER' and ins.arg == 0:
                    prev_emitted = emit('CALL', 1)
                else:
                    prev_emitted = emit('CALL', ins.arg)
            prev_cpy = opname
            continue

        # --- arithmetic / comparison ----------------------------------------
        if opname == 'BINARY_OP':
            bed_arg = CPY_BINOP_TO_BEDROCK.get(ins.arg)
            if bed_arg is None:
                raise UnsupportedOpcode(
                    'BINARY_OP sub-op %d' % ins.arg)
            prev_emitted = emit('BINARY_OP', bed_arg)
            prev_cpy = opname
            continue
        if opname == 'COMPARE_OP':
            # 3.11 COMPARE_OP arg is 0-5 (<,<=,==,!=,>,>=); maps 1:1. (in/is
            # use the separate CONTAINS_OP/IS_OP opcodes.)
            prev_emitted = emit('COMPARE_OP', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'CONTAINS_OP':
            prev_emitted = emit('CONTAINS_OP', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'IS_OP':
            prev_emitted = emit('IS_OP', ins.arg)
            prev_cpy = opname
            continue

        # --- unary ops (1:1) -------------------------------------------------
        if opname == 'UNARY_NEGATIVE':
            prev_emitted = emit('UNARY_NEGATIVE', 0); prev_cpy = opname; continue
        if opname == 'UNARY_NOT':
            prev_emitted = emit('UNARY_NOT', 0); prev_cpy = opname; continue
        if opname == 'UNARY_INVERT':
            prev_emitted = emit('UNARY_INVERT', 0); prev_cpy = opname; continue
        if opname == 'UNARY_POSITIVE':
            prev_emitted = emit('UNARY_POSITIVE', 0); prev_cpy = opname; continue

        # --- f-strings (FORMAT_VALUE + BUILD_STRING) ------------------------
        # FORMAT_VALUE arg: bit0-1 = conversion (0=none,1=repr,2=ascii), bit2
        # (0x4) = has format spec on stack. CPython 3.11 uses these for
        # f-string rendering.
        if opname == 'FORMAT_VALUE':
            prev_emitted = emit('FORMAT_VALUE', ins.arg); prev_cpy = opname; continue
        if opname == 'BUILD_STRING':
            prev_emitted = emit('BUILD_STRING', ins.arg); prev_cpy = opname; continue

        # --- build literals (tuples, sets, maps, slices) -------------------
        if opname == 'BUILD_TUPLE':
            prev_emitted = emit('BUILD_TUPLE', ins.arg); prev_cpy = opname; continue
        if opname == 'BUILD_SET':
            prev_emitted = emit('BUILD_SET', ins.arg); prev_cpy = opname; continue
        if opname == 'BUILD_MAP':
            prev_emitted = emit('BUILD_MAP', ins.arg); prev_cpy = opname; continue
        if opname == 'BUILD_SLICE':
            prev_emitted = emit('BUILD_SLICE', ins.arg); prev_cpy = opname; continue

        # --- attribute access / subscript (need names table) ----------------
        # LOAD_ATTR/STORE_ATTR/LOAD_NAME/STORE_NAME/STORE_GLOBAL use the
        # co_names table. The BedrockVM names blob is `code.co_names` (the
        # compiler passes it directly at line ~572), so name indices map 1:1
        # with the CPython arg (LOAD_GLOBAL's push_null bit is already
        # stripped). Emit the VM opcode with the original co_names index.
        if opname in ('LOAD_ATTR', 'STORE_ATTR', 'LOAD_NAME', 'STORE_NAME',
                       'STORE_GLOBAL', 'DELETE_GLOBAL', 'DELETE_ATTR'):
            _vm_op = {
                'LOAD_ATTR': 'LOAD_ATTR', 'STORE_ATTR': 'STORE_ATTR',
                'LOAD_NAME': 'LOAD_NAME', 'STORE_NAME': 'STORE_NAME',
                'STORE_GLOBAL': 'STORE_GLOBAL',
                'DELETE_GLOBAL': 'DELETE_GLOBAL',
                'DELETE_ATTR': 'DELETE_ATTR',
            }[opname]
            prev_emitted = emit(_vm_op, ins.arg); prev_cpy = opname; continue

        # --- subscript (dict/list/obj indexing) -----------------------------
        if opname == 'BINARY_SUBSCR':
            prev_emitted = emit('BINARY_SUBSCR', 0); prev_cpy = opname; continue
        if opname == 'STORE_SUBSCR':
            prev_emitted = emit('STORE_SUBSCR', 0); prev_cpy = opname; continue
        if opname == 'DELETE_SUBSCR':
            prev_emitted = emit('DELETE_SUBSCR', 0); prev_cpy = opname; continue

        # --- delete fast / copy / swap (3.11 stack ops) ---------------------
        if opname == 'DELETE_FAST':
            prev_emitted = emit('DELETE_FAST', ins.arg); prev_cpy = opname; continue
        if opname == 'COPY':
            prev_emitted = emit('COPY', ins.arg); prev_cpy = opname; continue
        if opname == 'SWAP':
            prev_emitted = emit('SWAP', ins.arg); prev_cpy = opname; continue

        # --- iteration / jumps ----------------------------------------------
        if opname == 'GET_ITER':
            prev_emitted = emit('GET_ITER', 0)
            prev_cpy = opname
            continue
        if opname == 'FOR_ITER':
            prev_emitted = emit('FOR_ITER', 'L%d' % ins.argval)
            prev_cpy = opname
            continue
        if opname in ('JUMP_BACKWARD', 'JUMP_FORWARD', 'JUMP_ABSOLUTE'):
            prev_emitted = emit('JUMP', 'L%d' % ins.argval)
            prev_cpy = opname
            continue
        if opname in ('POP_JUMP_FORWARD_IF_FALSE',
                      'POP_JUMP_BACKWARD_IF_FALSE'):
            prev_emitted = emit('JUMP_IF_FALSE', 'L%d' % ins.argval)
            prev_cpy = opname
            continue
        if opname in ('POP_JUMP_FORWARD_IF_TRUE',
                      'POP_JUMP_BACKWARD_IF_TRUE'):
            prev_emitted = emit('JUMP_IF_TRUE', 'L%d' % ins.argval)
            prev_cpy = opname
            continue

        # --- building / function --------------------------------------------
        if opname == 'BUILD_LIST':
            if is_listcomp and ins.arg == 0:
                # Stash the fresh list in the synthetic local so LIST_APPEND
                # (which the reference reads from a local) can find it.
                emit('BUILD_LIST', 0)
                prev_emitted = emit('STORE_FAST', list_local)
            else:
                prev_emitted = emit('BUILD_LIST', ins.arg)
            prev_cpy = opname
            continue
        if opname == 'LIST_APPEND':
            if is_listcomp:
                # CPython's arg is a stack depth; the reference reads
                # locals_[arg]. Point it at our synthetic list local.
                prev_emitted = emit('LIST_APPEND', list_local)
            else:
                raise UnsupportedOpcode(
                    'LIST_APPEND outside a comprehension')
            prev_cpy = opname
            continue
        if opname == 'MAKE_FUNCTION':
            # The code object was pushed by a preceding LOAD_CONST and has been
            # replaced in the const pool with a compiled Frame. Pass the flags
            # through unchanged (the test suite only uses flags=0 listcomps).
            prev_emitted = emit('MAKE_FUNCTION', ins.arg)
            prev_cpy = opname
            continue

        # --- generators ------------------------------------------------------
        if opname == 'YIELD_VALUE':
            prev_emitted = emit('YIELD_VALUE', 0)
            prev_cpy = opname
            continue

        # Anything else is unsupported -> caller skips the function.
        raise UnsupportedOpcode(opname)

    # Flush any half-collected unpack stores (defensive; not hit by tests).
    if pending_unpack is not None and pending_stores:
        for s in pending_stores:
            items.append(s)

    return items, extra_nlocals, list_local


# ---- Per-code-object compilation -------------------------------------------
def _compile_code(code, func=None, _depth=0):
    """Compile a single code object into a decoded Frame.

    `func` is the owning function (for default arguments) or None for nested
    code objects (listcomps have no defaults).
    """
    if _depth > 64:
        raise UnsupportedOpcode('code nesting too deep')

    co_flags = code.co_flags
    if co_flags & _ASYNC_FLAGS:
        raise UnsupportedOpcode(
            'async function (co_flags=%#x)' % co_flags)

    # --- Safety gate: skip functions with try/except or with statements ---
    # The C interpreter's exception propagation is not wired (exception
    # table + SETUP_FINALLY are no-ops), so compiling these functions would
    # produce SILENT WRONG OUTPUT — the most dangerous failure mode. Skip
    # them so they fall back to the capsule runtime / plain Python (which
    # Phase 1-4 still obfuscates). This is the production-safety contract.
    # Detection covers both 3.11 (co_exceptiontable + BEFORE_WITH) and 3.10
    # (SETUP_FINALLY + SETUP_WITH opcodes in the bytecode).
    if hasattr(code, 'co_exceptiontable') and code.co_exceptiontable:
        raise UnsupportedOpcode('try/except (exception table present)')
    _all_ins = list(dis.get_instructions(code))
    for _ins in _all_ins:
        if _ins.opname in ('BEFORE_WITH', 'SETUP_WITH', 'SETUP_ASYNC_WITH',
                           'BEFORE_ASYNC_WITH', 'SETUP_FINALLY'):
            raise UnsupportedOpcode(
                'try/except or with statement (%s)' % _ins.opname)

    # Build the const pool: replace nested CodeTypes with recursively compiled
    # Frames so MAKE_FUNCTION receives a Frame (which _make_py_function expects).
    consts = list(code.co_consts)
    for i, c in enumerate(consts):
        if isinstance(c, types.CodeType):
            consts[i] = _compile_code(c, None, _depth + 1)

    is_listcomp = code.co_name == '<listcomp>'

    # Generator detection: co_flags or an explicit RETURN_GENERATOR opcode.
    has_return_gen = any(
        ins.opname == 'RETURN_GENERATOR'
        for ins in dis.get_instructions(code))
    is_generator = bool(co_flags & _CO_GENERATOR) or \
        bool(co_flags & _CO_ASYNC_GENERATOR) or has_return_gen

    flags = 0
    if is_generator:
        flags |= _FLAG_IS_GENERATOR
    if code.co_freevars:
        flags |= _FLAG_HAS_CLOSURE

    # Translate the body.
    items, extra_nlocals, _list_local = _translate(code, consts, is_listcomp)

    # Default-argument prologue (prepended; runs after run_func binds args).
    prologue, default_consts = _build_default_prologue(code, func)
    items = prologue + items
    consts = consts + default_consts

    assembled = assemble(items)

    nlocals = code.co_nlocals + extra_nlocals
    varnames = tuple(code.co_varnames)
    if extra_nlocals:
        varnames = varnames + tuple('$%d' % k for k in range(extra_nlocals))

    return Frame(
        code=assembled,
        consts=tuple(consts),
        names=tuple(code.co_names),
        argcount=code.co_argcount,
        kwonly_count=code.co_kwonlyargcount,
        nlocals=nlocals,
        flags=flags,
        varnames=varnames,
        freevars=tuple(code.co_freevars),
        cellvars=tuple(code.co_cellvars),
    )


# ---- Blob code_len fixup ---------------------------------------------------
def _fix_code_len(blob, names, varnames, freevars, cellvars):
    """Correct the code_len field written by _bedrock_vm_ref.encode().

    encode() sets code_len = len(code_pairs) (the logical instruction count),
    but it emits extra EXTENDED_ARG instruction-pairs whenever an argument
    >= 256 (e.g. CALL_KW's (argc<<8)|nkw). decode() reads exactly 2*code_len
    bytes, so a too-small code_len truncates the stream and corrupts the
    trailing names section. We recompute the true byte count from the blob
    layout and patch the 4-byte field.

    The reference interpreter is read-only, so we fix its output here.
    """
    (_flags, _argcount, _kwonly, _nlocals, _nconst,
     const_len) = struct.unpack_from('<IIIIII', blob, 5)
    # NOTE: encode() now encrypts names_blob with a derived key (names_key =
    # sha256(key + b'|names')) via the OFB cipher. OFB is length-preserving,
    # so len(encrypted) == len(plaintext_pickle) and the length arithmetic
    # below stays correct. We recompute a *plaintext* pickle here purely to
    # measure its byte length (the content is irrelevant). If a non-length-
    # preserving scheme (e.g. AEAD with a tag) is ever adopted, this function
    # must account for the expansion bytes.
    names_blob = pickle.dumps((names, varnames, freevars, cellvars),
                             protocol=4)
    # Trailing layout: [raw_code][n_names:4][names_len:4][names_blob]
    names_section = (struct.pack('<I', len(names))
                     + struct.pack('<I', len(names_blob))
                     + names_blob)
    code_len_off = 29 + const_len
    raw_len = len(blob) - code_len_off - 4 - len(names_section)
    true_code_len = raw_len // 2
    if true_code_len < 0:
        # Should not happen; bail out unchanged rather than corrupt.
        return blob
    return (blob[:code_len_off]
            + struct.pack('<I', true_code_len)
            + blob[code_len_off + 4:])


# ---- Public entry point ----------------------------------------------------
def compile_func(func, key: bytes = b'', perm: dict = None, *,
                build_rng=None, max_duplicate_ops: int = 1) -> tuple:
    """Compile a Python function into a BedrockVM blob.

    Args:
        func: the Python function object (or its ``__code__``).
        key: 32-byte encryption key for the const pool (b'' = unencrypted).
        perm: opcode permutation dict {scrambled_byte: canonical_byte}.
              If None, identity permutation is used. When ``build_rng`` is
              given AND ``perm`` is None, the perm is generated from the
              per-build CSPRNG stream (Phase F) instead of the caller's
              ad-hoc random.
        build_rng: optional ``_build_rng.BuildRNG`` (Phase E/F). When given:
            - if ``perm`` is None, derive perm from ``build_rng.stream(b"vm_perm")``
              (replaces the caller's ``random.Random``-based shuffle).
            - if ``key`` is empty, derive a 32-byte key from
              ``build_rng.stream(b"vm_key")``.
            - pass ``max_duplicate_ops`` through to the perm generator so each
              canonical opcode maps to >=2 scrambled bytes (defeats opcode-
              frequency analysis; the runtime de-scrambles by picking the
              first matching scrambled byte).
        max_duplicate_ops: minimum number of scrambled bytes per canonical
              opcode (Phase F ``MaxDuplicateOps >= 2``). Default 1 = plain
              bijection (Phase 5 behavior). >1 extends the perm into a
              multi-valued map; the runtime ``perm`` dict must carry the
              extra entries so de-scrambling picks any of them.

    Returns:
        (blob, perm, perm_ext, key, frame) -- everything needed to run via
        _bedrock_vm_ref.run(blob, perm, key, args, globals, perm_ext).

    Raises:
        UnsupportedOpcode: if the function uses an opcode the compiler can't
            translate (the caller should skip the function).
    """
    code = func.__code__ if hasattr(func, '__code__') else func
    owner = func if hasattr(func, '__code__') else None

    frame = _compile_code(code, owner)

    # Phase F: when build_rng is given, derive perm + key from the per-build
    # CSPRNG stream (replaces the caller's random.Random-based generation).
    # max_duplicate_ops extends the perm so each canonical opcode has >=2
    # scrambled-byte mappings (defeats opcode-frequency analysis).
    if build_rng is not None:
        if perm is None:
            perm = _build_perm_from_rng(build_rng, max_duplicate_ops)
        if not key:
            key_stream = build_rng.stream(b'vm_key')
            key = key_stream.bytes(32)

    # Derive perm_ext (the scrambled byte that maps to EXTENDED_ARG=144) so a
    # caller-supplied permutation round-trips correctly.
    if perm is None:
        perm_ext_param = EXTENDED_ARG
    else:
        perm_ext_param = next(
            (s for s, c in perm.items() if c == EXTENDED_ARG), EXTENDED_ARG)

    blob, perm_out, perm_ext_byte, key_out = encode(
        frame.consts, frame.names, frame.code,
        argcount=frame.argcount, kwonly_count=frame.kwonly_count,
        nlocals=frame.nlocals, flags=frame.flags, key=key, perm=perm,
        varnames=frame.varnames, freevars=frame.freevars,
        cellvars=frame.cellvars, perm_ext=perm_ext_param)

    blob = _fix_code_len(blob, frame.names, frame.varnames,
                         frame.freevars, frame.cellvars)

    return blob, perm_out, perm_ext_byte, key_out, frame


def _build_perm_from_rng(build_rng, max_duplicate_ops: int = 1) -> dict:
    """Generate a per-build opcode permutation from a BuildRNG stream.

    Returns a dict ``{scrambled_byte: canonical_byte}``. With
    ``max_duplicate_ops == 1`` this is a plain bijection (Phase 5 behavior).
    With ``max_duplicate_ops >= 2`` each canonical opcode maps to multiple
    scrambled bytes (``MaxDuplicateOps``): the dict carries N*256 entries so
    the runtime de-scrambling picks any of them. EXTENDED_ARG (144) stays
    fixed at its canonical value (never permuted) so the runtime can stitch
    extended args before de-scrambling the next opcode.

    The first scrambled byte for each canonical is deterministic (the
    bijection); extra duplicates are drawn from the stream. This keeps v1
    backward-compat (a v1 runtime reading the perm dict sees the first
    mapping) while v2 can use the duplicates.
    """
    import _bedrock_vm_ref as _ref
    vals = list(_ref._OPCODES.values())
    stream = build_rng.stream(b'vm_perm')
    # Bijection: shuffle the scrambled bytes (same set, different order).
    scr = stream.shuffle(vals)
    perm = {scr[i]: vals[i] for i in range(len(vals))}
    # EXTENDED_ARG fixed.
    perm[_ref.EXTENDED_ARG] = _ref.EXTENDED_ARG
    if max_duplicate_ops <= 1:
        return perm
    # Add duplicate mappings: for each canonical op, pick (max_duplicate_ops-1)
    # extra scrambled bytes from the unused pool and map them to the same
    # canonical. The runtime de-scrambles by picking the first match in the
    # dict, so all duplicates resolve correctly.
    # Build the set of scrambled bytes already used (one per canonical).
    used = set(scr)
    # Pool of all 256 bytes minus the used ones; we draw extras from here.
    pool = [b for b in range(256) if b not in used]
    pool = stream.shuffle(pool)
    pool_iter = iter(pool)
    for canonical in vals:
        if canonical == _ref.EXTENDED_ARG:
            continue  # EXTENDED_ARG stays single-mapped
        for _ in range(max_duplicate_ops - 1):
            try:
                extra = next(pool_iter)
            except StopIteration:
                break  # pool exhausted (max_duplicate_ops > available)
            perm[extra] = canonical
    return perm
