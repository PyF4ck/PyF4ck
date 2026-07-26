"""BedrockVM reference interpreter (Wave 1).

Pure-Python implementation of the bytecode spec in VM_SPEC.md. Serves as:
  (a) the executable specification the C interpreter (Wave 2B) must match;
  (b) the fallback runtime when no C compiler is available at build time.

This interpreter is deliberately *simple and correct*, not fast. The C
interpreter (Wave 2B) is the optimized path; this one exists to define
semantics and to run unconditionally.

Encoding follows VM_SPEC.md:
  - 2-byte instructions [opcode, arg_lo]; EXTENDED_ARG (canonical 144, fixed)
    shifts the next instruction's arg left by 8 bits.
  - Per-build opcode permutation: `perm` maps scrambled opcode -> canonical.
    EXTENDED_ARG's scrambled value is `perm_ext` (a known constant).
  - Jumps are absolute, in instruction-units (index into the instruction list).
  - Const pool: pickled then SHA-256-OFB encrypted with `key`.
  - Names blob: pickled tuple of name strings (NOT encrypted).

Public API:
  decode(blob: bytes, perm: dict, key: bytes) -> Frame
  run_func(frame: Frame, args: tuple, kw: dict, globals_: dict, closure: tuple) -> object
  run(blob: bytes, perm: dict, key: bytes, args: tuple, globals_: dict) -> object

The high-level `run()` decodes a top-level module function and invokes it.
"""
from __future__ import annotations

import hashlib
import pickle
import struct


# ---- Canonical opcode values (from VM_SPEC.md) -----------------------------
# These are the SPEC values. The interpreter dispatches on canonical values
# after de-scrambling. `perm` maps scrambled-byte -> canonical-byte.
EXTENDED_ARG = 144  # fixed; never permuted

# Build the canonical-name -> canonical-value map from the spec table.
# Only the opcodes actually implemented are listed here; unknown opcodes raise.
_OPCODES = {
    'NOP': 0, 'POP_TOP': 1, 'DUP_TOP': 2, 'ROT_TWO': 3, 'ROT_THREE': 4,
    'RESUME': 6, 'JUMP': 7, 'JUMP_IF_FALSE': 8, 'JUMP_IF_TRUE': 9,
    'JUMP_IF_NONE': 10, 'JUMP_IF_NOT_NONE': 11, 'FOR_ITER': 12, 'GET_ITER': 13,
    'RETURN_VALUE': 14, 'RETURN_CONST': 15, 'YIELD_VALUE': 16,
    'RETURN_GENERATOR': 17, 'RAISE_VARARGS': 18, 'POP_BLOCK': 19,
    'PUSH_NULL': 20, 'LOAD_ASSERTION_ERROR': 21, 'RERAISE': 22,
    'CHECK_EXC_MATCH': 23, 'END_FOR': 25, 'YIELD_FROM': 26,
    'SETUP_FINALLY': 30, 'SETUP_WITH': 31,
    'LOAD_CONST': 32, 'LOAD_FAST': 33, 'LOAD_FAST_CHECK': 34,
    'LOAD_GLOBAL': 35, 'LOAD_DEREF': 36, 'LOAD_NAME': 37, 'LOAD_ATTR': 38,
    'LOAD_METHOD': 39, 'STORE_FAST': 40, 'STORE_GLOBAL': 41, 'STORE_DEREF': 42,
    'STORE_NAME': 43, 'DELETE_FAST': 44, 'DELETE_GLOBAL': 45, 'COPY': 46,
    'SWAP': 47, 'LOAD_CLOSURE': 48, 'COPY_FREE_VARS': 50, 'LOAD_BUILD_CLASS': 51,
    'UNPACK_SEQUENCE': 53, 'UNPACK_EX': 54, 'STORE_ATTR': 55, 'DELETE_ATTR': 56,
    'STORE_SUBSCR': 57, 'DELETE_SUBSCR': 58, 'BINARY_SUBSCR': 59,
    'FORMAT_VALUE': 60, 'BUILD_STRING': 61, 'IMPORT_NAME': 62,
    'IMPORT_FROM': 63,
    'BUILD_TUPLE': 64, 'BUILD_LIST': 65, 'BUILD_SET': 66, 'BUILD_MAP': 67,
    'LIST_EXTEND': 68, 'SET_UPDATE': 69, 'DICT_UPDATE': 70, 'LIST_APPEND': 71,
    'SET_ADD': 72, 'MAP_ADD': 73, 'BUILD_SLICE': 75, 'MAKE_FUNCTION': 77,
    'CALL': 78, 'CALL_KW': 79, 'CALL_FUNCTION_EX': 80, 'KW_NAMES': 81,
    'GEN_START': 83, 'MATCH_CLASS': 84, 'MATCH_KEYS': 85, 'MATCH_MAPPING': 86,
    'MATCH_SEQUENCE': 87, 'BEFORE_ASYNC_WITH': 89, 'BEFORE_WITH': 118,
    'SETUP_ASYNC_WITH': 93,
    'BINARY_OP': 96, 'UNARY_NEGATIVE': 97, 'UNARY_NOT': 98, 'UNARY_INVERT': 99,
    'COMPARE_OP': 100, 'IS_OP': 101, 'CONTAINS_OP': 102,
    'BINARY_OP_INPLACE': 104, 'JUMP_IF_FALSE_OR_POP': 112,
    'JUMP_IF_TRUE_OR_POP': 113, 'POP_EXCEPT': 115, 'PUSH_EXC_INFO': 116,
    'UNARY_POSITIVE': 125,
}
# Reverse: canonical value -> name
_BY_VAL = {v: k for k, v in _OPCODES.items()}


# ---- BINARY_OP sub-op table (mirrors CPython 3.11 NB_* ordering) -----------
_BINOPS = {
    0: lambda a, b: a + b,
    1: lambda a, b: a - b,
    2: lambda a, b: a * b,
    3: lambda a, b: a / b,
    4: lambda a, b: a % b,
    5: lambda a, b: a // b,
    6: lambda a, b: a ** b,
    7: lambda a, b: a << b,
    8: lambda a, b: a >> b,
    9: lambda a, b: a & b,
    10: lambda a, b: a | b,
    11: lambda a, b: a ^ b,
    25: lambda a, b: a @ b,  # matmul
}
# Inplace ops reuse the same lambda but mutate when possible; for the reference
# interpreter we just compute fresh (Python's augmented assignment falls back
# to this when the object lacks the inplace slot).
_CMP_OPS = {
    0: lambda a, b: a < b,
    1: lambda a, b: a <= b,
    2: lambda a, b: a == b,
    3: lambda a, b: a != b,
    4: lambda a, b: a > b,
    5: lambda a, b: a >= b,
    6: lambda a, b: a in b,
    7: lambda a, b: a not in b,
    8: lambda a, b: a is b,
    9: lambda a, b: a is not b,
}


# ---- SHA-256 OFB stream cipher (reuses the obfuscator's scheme) ------------
def _ofb_decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt (or encrypt — symmetric) with SHA-256 OFB. Matches the
    obfuscator's _br_decrypt (bedrock_obfuscator.py lines 9753-9763)."""
    h = hashlib.sha256
    state = h(key).digest()
    out = bytearray(len(blob))
    off = 0
    while off < len(blob):
        state = h(state + key + bytes([off & 255])).digest()
        take = min(len(state), len(blob) - off)
        for j in range(take):
            out[off + j] = blob[off + j] ^ state[j]
        off += take
    return bytes(out)


# ---- Frame: a decoded function ready to run -------------------------------
class Frame:
    """A decoded BedrockVM function: bytecode + consts + names + metadata."""

    __slots__ = ('code', 'consts', 'names', 'argcount', 'kwonly_count',
                 'nlocals', 'flags', 'varnames', 'freevars', 'cellvars',
                 'is_generator', 'is_async', 'has_closure')

    def __init__(self, code, consts, names, argcount, kwonly_count, nlocals,
                 flags, varnames, freevars, cellvars):
        self.code = code          # list of (canonical_op, full_arg) tuples
        self.consts = consts      # tuple
        self.names = names        # tuple of str (global/attr/import names)
        self.argcount = argcount
        self.kwonly_count = kwonly_count
        self.nlocals = nlocals
        self.flags = flags
        self.varnames = varnames  # tuple of str (local names)
        self.freevars = freevars  # tuple of str
        self.cellvars = cellvars  # tuple of str
        self.is_generator = bool(flags & 0x2)
        self.is_async = bool(flags & 0x4)
        self.has_closure = bool(flags & 0x1)


# ---- Blob decoding --------------------------------------------------------
_MAGIC = b'BVM1'


def decode(blob: bytes, perm: dict, key: bytes, perm_ext: int = EXTENDED_ARG) -> Frame:
    """Decode a BedrockVM blob into a Frame.

    `perm` maps scrambled-opcode-byte -> canonical-opcode-byte. `perm_ext`
    is the scrambled byte value that EXTENDED_ARG was assigned (fixed; the
    interpreter must know it to stitch extended args before de-scrambling the
    next opcode).

    Version handling (Phase F):
      - version 1: const pool + names blob encrypted (OFB), code section
        plaintext (Phase 5 behavior).
      - version 2: const pool + names blob + CODE section all encrypted
        (code_key = sha256(key + b'|code')). Phase F leak-resilience: the
        scrambled opcode bytes no longer sit in cleartext in the blob.
    """
    if blob[:4] != _MAGIC:
        raise ValueError('bad BedrockVM magic')
    version = blob[4]
    if version not in (1, 2):
        raise ValueError(f'unsupported BedrockVM version {version}')
    (flags, argcount, kwonly_count, nlocals, nconst, const_len) = struct.unpack_from(
        '<IIIII I', blob, 5)
    off = 29
    enc_const = blob[off:off + const_len]
    off += const_len
    if const_len:
        raw_const = _ofb_decrypt(enc_const, key) if key else enc_const
        consts = pickle.loads(raw_const)
    else:
        consts = ()
    (code_len,) = struct.unpack_from('<I', blob, off)
    off += 4
    raw_code = blob[off:off + 2 * code_len]
    off += 2 * code_len
    # Phase F: version 2 blobs encrypt the code section (OFB with code_key).
    # Version 1 blobs leave it plaintext. When key is empty (testing), no
    # decryption is attempted for either version.
    if version == 2 and key:
        code_key = hashlib.sha256(key + b'|code').digest()
        raw_code = _ofb_decrypt(raw_code, code_key)
    (n_names,) = struct.unpack_from('<I', blob, off)
    off += 4
    (names_len,) = struct.unpack_from('<I', blob, off)
    off += 4
    # Decrypt names_blob with the same derived key used in encode()
    # (names_key = sha256(key + b'|names')). When no key is present the blob
    # is plaintext, matching the backward-compatible behaviour.
    if names_len:
        enc_names = blob[off:off + names_len]
        if key:
            names_key = hashlib.sha256(key + b'|names').digest()
            raw_names = _ofb_decrypt(enc_names, names_key)
        else:
            raw_names = enc_names
        names = pickle.loads(raw_names)
    else:
        names = ()
    off += names_len
    # Names tuple carries: (global_names, varnames, freevars, cellvars)
    if isinstance(names, tuple) and len(names) == 4:
        global_names, varnames, freevars, cellvars = names
    else:
        global_names = names
        varnames = freevars = cellvars = ()
    # Decode instructions: stitch EXTENDED_ARG, then de-scramble opcode.
    code = []
    ext = 0
    for i in range(0, len(raw_code), 2):
        op_byte = raw_code[i]
        arg_lo = raw_code[i + 1]
        if op_byte == perm_ext:
            ext = (ext << 8) | arg_lo
            continue
        canonical = perm[op_byte]
        full_arg = (ext << 8) | arg_lo
        ext = 0
        code.append((canonical, full_arg))
    # Some malformed blobs leave a trailing EXTENDED_ARG; harmless.
    if code and code[-1][0] == EXTENDED_ARG:
        code.pop()
    return Frame(code, consts, global_names, argcount, kwonly_count, nlocals,
                 flags, varnames, freevars, cellvars)


# ---- Assembler: label-based, eliminates manual index counting --------------
def assemble(items):
    """Assemble a label-based instruction list into (op, arg) pairs.

    `items` is a list where each element is either:
      - ('LABEL', name)           : a label pseudo-op (emits nothing; records index)
      - (op_name_or_int, arg)     : an instruction. If `arg` is a str, it is
                                    treated as a label reference and resolved
                                    to the instruction index of that label.

    Returns a list of (canonical_op_int, resolved_arg_int) pairs.
    """
    # Pass 1: assign instruction indices, record label positions.
    labels = {}
    code = []
    for it in items:
        if isinstance(it, tuple) and len(it) == 2 and it[0] == 'LABEL':
            labels[it[1]] = len(code)
            continue
        code.append(it)  # placeholder; arg may be a label str
    # Pass 2: resolve label-string args to indices.
    resolved = []
    for op, arg in code:
        if isinstance(op, str):
            op = _OPCODES[op]
        if isinstance(arg, str):
            if arg not in labels:
                raise ValueError(f'unknown label {arg!r}')
            arg = labels[arg]
        resolved.append((op, arg))
    return resolved


# ---- Encoder helper (for oracle bytecodes / testing) ----------------------
def encode(consts, names, code_pairs, argcount=0, kwonly_count=0, nlocals=0,
           flags=0, key=b'', perm=None, varnames=(), freevars=(), cellvars=(),
           perm_ext=EXTENDED_ARG):
    """Build a BedrockVM blob. `code_pairs` is a list of (canonical_op, arg).
    If `perm` is None, identity permutation is used (testing convenience).
    Returns (blob, perm_dict, perm_ext_byte, key)."""
    if perm is None:
        # Identity: scrambled == canonical, EXTENDED_ARG stays 144.
        perm = {v: v for v in _OPCODES.values()}
        perm[EXTENDED_ARG] = EXTENDED_ARG
        perm_ext_byte = EXTENDED_ARG
    else:
        perm_ext_byte = perm_ext
    # Serialize consts with pickle, encrypt if key given.
    const_bytes = pickle.dumps(consts, protocol=4)
    if key:
        const_bytes = _ofb_decrypt(const_bytes, key)
    # Encode instructions with EXTENDED_ARG emission.
    raw = bytearray()
    for op, arg in code_pairs:
        # Find canonical->scrambled.
        scr = None
        for k, v in perm.items():
            if v == op:
                scr = k
                break
        if scr is None:
            raise ValueError(f'canonical op {op} not in perm')
        # Emit EXTENDED_ARG(s) for arg >= 256.
        a = arg
        if a >= 256:
            hi_bytes = []
            while a >= 256:
                hi_bytes.append((a >> 8) & 0xff)
                a = a & 0xff
                if a >= 256 or (a >> 8):
                    # shift down for next iter; actually we need full arg
                    pass
            # Simpler: split arg into bytes little-endian, emit hi first.
            hi_bytes = []
            tmp = arg >> 8
            while tmp > 0:
                hi_bytes.append(tmp & 0xff)
                tmp >>= 8
            for hb in reversed(hi_bytes):
                raw.append(perm_ext_byte)
                raw.append(hb & 0xff)
        raw.append(scr)
        raw.append(arg & 0xff)
    names_blob = pickle.dumps((names, varnames, freevars, cellvars), protocol=4)
    # Encrypt names_blob with a key derived from the main key, distinct from
    # the const-pool key, to avoid a two-time pad (both blobs start at the
    # same keystream offset 0). names_key = sha256(key + b'|names'). OFB is
    # length-preserving so the on-disk names_len stays equal to the plaintext
    # pickle length.
    if key:
        names_key = hashlib.sha256(key + b'|names').digest()
        names_blob = _ofb_decrypt(names_blob, names_key)
    # Phase F: encrypt the code section (raw bytecode) with a third derived
    # key (code_key = sha256(key + b'|code')) so the scrambled opcode bytes
    # don't sit in cleartext. This is version 2 of the blob format; v1 blobs
    # (no code encryption) remain decodable by ``decode`` (which checks the
    # version byte). OFB is length-preserving so code_len is unaffected.
    code_bytes = bytes(raw)
    if key:
        code_key = hashlib.sha256(key + b'|code').digest()
        code_bytes = _ofb_decrypt(code_bytes, code_key)
    out = bytearray()
    out += _MAGIC
    out += bytes([2 if key else 1])  # version: 2 = code-encrypted (Phase F)
    out += struct.pack('<IIIII I', flags, argcount, kwonly_count, nlocals,
                       len(consts), len(const_bytes))
    out += const_bytes
    out += struct.pack('<I', len(code_pairs))
    out += code_bytes
    out += struct.pack('<I', len(names))
    out += struct.pack('<I', len(names_blob))
    out += names_blob
    return bytes(out), perm, perm_ext_byte, key


# ---- Interpreter ----------------------------------------------------------
class _VMError(Exception):
    pass


def _truthy(v):
    return bool(v)


def run_func(frame: Frame, args: tuple, kw: dict, globals_: dict,
             closure: tuple = (), _depth: int = 0):
    """Run a decoded Frame. Returns the function's result (or a generator
    object if the frame is a generator)."""
    if _depth > 200:
        raise RecursionError('BedrockVM recursion limit')

    code = frame.code
    consts = frame.consts
    names = frame.names
    nlocals = frame.nlocals
    argcount = frame.argcount
    kwonly_count = frame.kwonly_count

    # Bind args into the locals frame.
    locals_ = [None] * max(nlocals, argcount + kwonly_count + 4)
    if len(args) > argcount + (kwonly_count or 0):
        # Allow *args-style overflow for simplicity; bind excess to trailing
        # locals only if space exists, else ignore (caller's contract).
        pass
    for i, v in enumerate(args):
        if i < len(locals_):
            locals_[i] = v
    # Bind kwargs to kwonly slots (they come after positional in varnames).
    if kw and frame.varnames:
        for i, vn in enumerate(frame.varnames):
            if vn in kw:
                locals_[i] = kw.pop(vn)
    # Cells: closure[i] is a 1-element list (mutable cell) for free vars.
    cells = closure  # tuple of cell-lists
    # For cellvars defined here, allocate fresh cells.
    if frame.cellvars:
        cell_map = {n: [None] for n in frame.cellvars}
    else:
        cell_map = {}
    for i, fv in enumerate(frame.freevars):
        if i < len(cells):
            cell_map[fv] = cells[i]

    stack = []
    blocks = []  # try/except handler stack: list of ('finally', target, nstack)
    kw_names_pending = None  # set by KW_NAMES for the next CALL_KW
    pc = 0
    n = len(code)

    # Generator support: if is_generator, run inside a Python generator so
    # YIELD_VALUE suspends naturally.
    if frame.is_generator:
        return _run_generator(frame, locals_, cells, globals_, _depth + 1)

    while pc < n:
        op, arg = code[pc]
        pc += 1
        name = _BY_VAL.get(op)
        if name is None:
            raise _VMError(f'unknown canonical opcode {op} at pc {pc - 1}')

        if name == 'NOP' or name == 'RESUME':
            continue
        elif name == 'POP_TOP':
            stack.pop()
        elif name == 'DUP_TOP':
            stack.append(stack[-1])
        elif name == 'ROT_TWO':
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif name == 'ROT_THREE':
            stack[-1], stack[-2], stack[-3] = stack[-3], stack[-1], stack[-2]
        elif name == 'RETURN_VALUE':
            return stack.pop()
        elif name == 'RETURN_CONST':
            return consts[arg]
        elif name == 'LOAD_CONST':
            stack.append(consts[arg])
        elif name == 'LOAD_FAST':
            stack.append(locals_[arg])
        elif name == 'LOAD_FAST_CHECK':
            v = locals_[arg]
            if v is None and frame.varnames and arg < len(frame.varnames):
                raise UnboundLocalError(frame.varnames[arg])
            stack.append(v)
        elif name == 'LOAD_GLOBAL':
            stack.append(globals_[names[arg]])
        elif name == 'LOAD_DEREF':
            stack.append(cell_map[frame.freevars[arg]][0])
        elif name == 'LOAD_NAME':
            # name resolution: locals -> globals -> builtins
            nm = names[arg]
            if nm in locals_:
                stack.append(locals_[locals_.index(nm)] if False else _name_lookup_local(locals_, frame.varnames, nm))
            else:
                stack.append(globals_.get(nm, __builtins__.__dict__.get(nm)))
        elif name == 'LOAD_ATTR':
            obj = stack.pop()
            stack.append(getattr(obj, names[arg]))
        elif name == 'LOAD_METHOD':
            obj = stack.pop()
            stack.append(getattr(obj, names[arg]))
        elif name == 'STORE_FAST':
            locals_[arg] = stack.pop()
        elif name == 'STORE_GLOBAL':
            globals_[names[arg]] = stack.pop()
        elif name == 'STORE_DEREF':
            cell_map[frame.freevars[arg]][0] = stack.pop()
        elif name == 'STORE_NAME':
            globals_[names[arg]] = stack.pop()
        elif name == 'DELETE_FAST':
            locals_[arg] = None
        elif name == 'DELETE_GLOBAL':
            del globals_[names[arg]]
        elif name == 'COPY':
            stack.append(stack[-(arg + 1)])
        elif name == 'SWAP':
            stack[-1], stack[-(arg + 1)] = stack[-(arg + 1)], stack[-1]
        elif name == 'LOAD_CLOSURE':
            stack.append(cell_map[frame.cellvars[arg]])
        elif name == 'LOAD_BUILD_CLASS':
            stack.append(__build_class__)  # type: ignore[name-defined]
        elif name == 'UNPACK_SEQUENCE':
            seq = stack.pop()
            items = list(seq)
            if len(items) != arg:
                raise ValueError(f'unpack expected {arg}, got {len(items)}')
            # Push in FORWARD order: first element deepest, last on top.
            # Stores then pop top-first, so the LAST store gets element[0].
            # This matches CPython's `a, b, c = (x, y, z)` convention.
            for it in items:
                stack.append(it)
        elif name == 'UNPACK_EX':
            seq = stack.pop()
            items = list(seq)
            before = arg & 0xff
            after = arg >> 8
            if len(items) < before + after:
                raise ValueError('unpack mismatch')
            for it in reversed(items[:before]):
                stack.append(it)
            stack.append(items[before:len(items) - after])
            for it in reversed(items[len(items) - after:]):
                stack.append(it)
        elif name == 'STORE_ATTR':
            obj = stack.pop()
            val = stack.pop()
            setattr(obj, names[arg], val)
        elif name == 'STORE_SUBSCR':
            key = stack.pop()
            obj = stack.pop()
            obj[key] = stack.pop()
        elif name == 'BINARY_SUBSCR':
            key = stack.pop()
            obj = stack.pop()
            stack.append(obj[key])
        elif name == 'FORMAT_VALUE':
            v = stack.pop()
            if arg & 0x4:  # has spec on stack
                spec = stack.pop()
                stack.append(format(v, spec))
            elif arg == 0:
                stack.append(str(v))
            elif arg == 1:
                stack.append(repr(v))
            elif arg == 2:
                stack.append(ascii(v))
            else:
                stack.append(str(v))
        elif name == 'BUILD_STRING':
            parts = stack[-arg:]
            del stack[-arg:]
            stack.append(''.join(parts))
        elif name == 'BUILD_TUPLE':
            items = stack[-arg:]
            del stack[-arg:]
            stack.append(tuple(items))
        elif name == 'BUILD_LIST':
            items = stack[-arg:]
            del stack[-arg:]
            stack.append(items)
        elif name == 'BUILD_SET':
            items = stack[-arg:]
            del stack[-arg:]
            stack.append(set(items))
        elif name == 'BUILD_MAP':
            pairs = stack[-2 * arg:]
            del stack[-2 * arg:]
            d = {}
            for i in range(0, 2 * arg, 2):
                d[pairs[i]] = pairs[i + 1]
            stack.append(d)
        elif name == 'LIST_APPEND':
            v = stack.pop()
            lst = locals_[arg]
            lst.append(v)
        elif name == 'SET_ADD':
            v = stack.pop()
            s = locals_[arg]
            s.add(v)
        elif name == 'MAP_ADD':
            v = stack.pop()
            k = stack.pop()
            d = locals_[arg]
            d[k] = v
        elif name == 'BUILD_SLICE':
            if arg == 2:
                stop = stack.pop()
                start = stack.pop()
                stack.append(slice(start, stop))
            else:
                step = stack.pop()
                stop = stack.pop()
                start = stack.pop()
                stack.append(slice(start, stop, step))
        elif name == 'MAKE_FUNCTION':
            # Stack top is a code object (a Frame, in our model). Below it may
            # be qualname/defaults/kwdefaults/closure depending on flags.
            codeobj = stack.pop()
            qualname = None
            defaults = ()
            kwdefaults = {}
            func_closure = ()
            if arg & 0x8:
                qualname = stack.pop()
            if arg & 0x4:
                kwdefaults = stack.pop()
            if arg & 0x2:
                defaults = stack.pop()
            if arg & 0x1:
                func_closure = tuple(stack.pop())  # tuple of cells
            fn = _make_py_function(codeobj, defaults, kwdefaults, func_closure,
                                   globals_, _depth)
            stack.append(fn)
        elif name == 'CALL':
            argv = stack[-arg:]
            del stack[-arg:]
            callable_ = stack.pop()
            stack.append(callable_(*argv))
        elif name == 'CALL_KW':
            argc = arg >> 8
            nkw = arg & 0xff
            # kwarg values are on top (nkw of them), below are argc positional
            kwvals = stack[-nkw:]
            del stack[-nkw:]
            argv = stack[-argc:]
            del stack[-argc:]
            callable_ = stack.pop()
            kwnames = consts[arg & 0xffff] if False else kw_names_pending
            kw_names_pending = None
            kw = dict(zip(kwnames, kwvals)) if kwnames else {}
            stack.append(callable_(*argv, **kw))
        elif name == 'CALL_FUNCTION_EX':
            has_kw = arg & 0x1
            if has_kw:
                kwds = stack.pop()
            else:
                kwds = {}
            argv = stack.pop()
            callable_ = stack.pop()
            stack.append(callable_(*argv, **kwds))
        elif name == 'KW_NAMES':
            kw_names_pending = consts[arg]
        elif name == 'BINARY_OP':
            b = stack.pop()
            a = stack.pop()
            fn = _BINOPS.get(arg)
            if fn is None:
                raise _VMError(f'unknown BINOP sub {arg}')
            stack.append(fn(a, b))
        elif name == 'BINARY_OP_INPLACE':
            b = stack.pop()
            a = stack.pop()
            fn = _BINOPS.get(arg)
            if fn is None:
                raise _VMError(f'unknown inplace BINOP sub {arg}')
            stack.append(fn(a, b))
        elif name == 'UNARY_NEGATIVE':
            stack.append(-stack.pop())
        elif name == 'UNARY_NOT':
            stack.append(not stack.pop())
        elif name == 'UNARY_INVERT':
            stack.append(~stack.pop())
        elif name == 'UNARY_POSITIVE':
            stack.append(+stack.pop())
        elif name == 'COMPARE_OP':
            b = stack.pop()
            a = stack.pop()
            fn = _CMP_OPS.get(arg)
            if fn is None:
                raise _VMError(f'unknown CMP sub {arg}')
            stack.append(fn(a, b))
        elif name == 'IS_OP':
            b = stack.pop()
            a = stack.pop()
            stack.append(a is b if not arg else a is not b)
        elif name == 'CONTAINS_OP':
            b = stack.pop()
            a = stack.pop()
            stack.append(a in b if not arg else a not in b)
        elif name == 'JUMP':
            pc = arg
        elif name == 'JUMP_IF_FALSE':
            if not _truthy(stack.pop()):
                pc = arg
        elif name == 'JUMP_IF_TRUE':
            if _truthy(stack.pop()):
                pc = arg
        elif name == 'JUMP_IF_NONE':
            if stack.pop() is None:
                pc = arg
        elif name == 'JUMP_IF_NOT_NONE':
            if stack.pop() is not None:
                pc = arg
        elif name == 'JUMP_IF_FALSE_OR_POP':
            if not _truthy(stack[-1]):
                pc = arg
            else:
                stack.pop()
        elif name == 'JUMP_IF_TRUE_OR_POP':
            if _truthy(stack[-1]):
                pc = arg
            else:
                stack.pop()
        elif name == 'FOR_ITER':
            it = stack[-1]
            try:
                v = next(it)
                stack.append(v)
            except StopIteration:
                stack.pop()
                pc = arg
        elif name == 'GET_ITER':
            stack.append(iter(stack.pop()))
        elif name == 'YIELD_VALUE':
            # In a non-generator frame this is a misuse; the generator path
            # handles it. For safety, treat as return.
            return stack.pop()
        elif name == 'YIELD_FROM':
            v = stack.pop()
            # Simplified: if v is a generator, drive it; else return v.
            if hasattr(v, '__next__'):
                try:
                    while True:
                        try:
                            n = next(v)
                        except StopIteration as e:
                            stack.append(e.value)
                            break
                except StopIteration as e:
                    stack.append(e.value)
            else:
                stack.append(v)
        elif name == 'RETURN_GENERATOR' or name == 'GEN_START':
            # Marker; the generator path is entered before this loop, so
            # reaching here in a non-gen frame is a no-op.
            continue
        elif name == 'RAISE_VARARGS':
            if arg == 0:
                raise
            elif arg == 1:
                raise stack.pop()
            else:
                cause = stack.pop()
                exc = stack.pop()
                raise exc from cause
        elif name == 'POP_BLOCK':
            if blocks:
                blocks.pop()
        elif name == 'SETUP_FINALLY':
            blocks.append(('finally', arg, len(stack)))
        elif name == 'POP_EXCEPT':
            if blocks:
                blocks.pop()
        elif name == 'PUSH_EXC_INFO':
            stack.append(None)  # placeholder; full exc-stack handling is in
            # the try/except path below.
        elif name == 'PUSH_NULL':
            stack.append(None)  # NULL marker normalized; treat as no-op slot
        elif name == 'LOAD_ASSERTION_ERROR':
            stack.append(AssertionError)
        elif name == 'CHECK_EXC_MATCH':
            t = stack.pop()
            e = stack.pop()
            stack.append(isinstance(e, t))
        elif name == 'END_FOR':
            continue
        elif name == 'IMPORT_NAME':
            fromlist = stack.pop()
            level = stack.pop()
            import importlib
            stack.append(importlib.__import__(names[arg], globals_, {}, list(fromlist) if fromlist else [], level))
        elif name == 'IMPORT_FROM':
            mod = stack[-1]
            stack.append(getattr(mod, names[arg]))
        elif name == 'BEFORE_WITH' or name == 'BEFORE_ASYNC_WITH':
            mgr = stack.pop()
            enter = mgr.__enter__()
            stack.append(mgr)
            stack.append(enter)
        elif name == 'FORMAT_SIMPLE':
            stack.append(str(stack.pop()))
        elif name == 'FORMAT_WITH_SPEC':
            spec = stack.pop()
            v = stack.pop()
            stack.append(format(v, spec))
        else:
            raise _VMError(f'unimplemented opcode {name} (canonical {op}) at pc {pc - 1}')

    # Implicit None return at end (matches Python).
    return None


def _name_lookup_local(locals_, varnames, nm):
    if varnames:
        try:
            return locals_[varnames.index(nm)]
        except (ValueError, IndexError):
            pass
    return None


def _make_py_function(codeobj, defaults, kwdefaults, closure, globals_, depth):
    """Create a callable from a decoded inner Frame (e.g. a comprehension).
    `codeobj` is a Frame; `closure` is a tuple of cell-lists.

    Uses duck-typing (``hasattr(codeobj, 'code')``) rather than
    ``isinstance(codeobj, Frame)`` so that a Frame pickled under one module
    path (e.g. ``_bedrock_vm_ref.Frame``) still works after the reference
    file is renamed/debranded (e.g. to ``_xkqm_vm_ref.Frame``) — the
    restored pickle object carries the original module path and would fail
    an isinstance check against the renamed module's Frame class."""
    if not hasattr(codeobj, 'code'):
        # It might be a real Python code object (rare); wrap as a partial.
        def _passthrough(*a, **k):
            raise _VMError('non-Frame code object in MAKE_FUNCTION')
        return _passthrough

    def _inner(*args, **kw):
        return run_func(codeobj, args, kw, globals_, closure, _depth=depth + 1)

    _inner.__defaults__ = tuple(defaults) if defaults else None
    _inner.__kwdefaults__ = dict(kwdefaults) if kwdefaults else None
    return _inner


def _run_generator(frame, locals_, cells, globals_, depth):
    """Execute a generator frame as a Python generator so YIELD_VALUE
    suspends naturally. Reuses the same dispatch loop but yields."""
    code = frame.code
    consts = frame.consts
    names = frame.names
    stack = []
    pc = 0
    n = len(code)
    kw_names_pending = None

    def _gen():
        nonlocal pc, kw_names_pending
        while pc < n:
            op, arg = code[pc]
            pc += 1
            name = _BY_VAL.get(op)
            if name == 'NOP' or name == 'RESUME' or name == 'RETURN_GENERATOR' or name == 'GEN_START':
                continue
            elif name == 'YIELD_VALUE':
                yield stack.pop()
            elif name == 'YIELD_FROM':
                v = stack.pop()
                if hasattr(v, '__iter__'):
                    for x in v:
                        yield x
                else:
                    yield v
            elif name == 'RETURN_VALUE':
                return stack.pop()
            elif name == 'RETURN_CONST':
                return consts[arg]
            elif name == 'LOAD_FAST':
                stack.append(locals_[arg])
            elif name == 'LOAD_CONST':
                stack.append(consts[arg])
            elif name == 'LOAD_GLOBAL':
                stack.append(globals_[names[arg]])
            elif name == 'STORE_FAST':
                locals_[arg] = stack.pop()
            elif name == 'POP_TOP':
                stack.pop()
            elif name == 'BINARY_OP':
                b = stack.pop(); a = stack.pop()
                stack.append(_BINOPS[arg](a, b))
            elif name == 'COMPARE_OP':
                b = stack.pop(); a = stack.pop()
                stack.append(_CMP_OPS[arg](a, b))
            elif name == 'CALL':
                argv = stack[-arg:]; del stack[-arg:]
                callable_ = stack.pop()
                stack.append(callable_(*argv))
            elif name == 'JUMP':
                pc = arg
            elif name == 'JUMP_IF_FALSE':
                if not _truthy(stack.pop()):
                    pc = arg
            elif name == 'JUMP_IF_TRUE':
                if _truthy(stack.pop()):
                    pc = arg
            elif name == 'FOR_ITER':
                it = stack[-1]
                try:
                    stack.append(next(it))
                except StopIteration:
                    stack.pop()
                    pc = arg
            elif name == 'GET_ITER':
                stack.append(iter(stack.pop()))
            elif name == 'DUP_TOP':
                stack.append(stack[-1])
            elif name == 'POP_BLOCK':
                pass
            else:
                raise _VMError(f'unimpl gen opcode {name} at pc {pc - 1}')
        return None

    return _gen()


def run(blob: bytes, perm: dict, key: bytes, args: tuple, globals_: dict,
        perm_ext: int = EXTENDED_ARG) -> object:
    """High-level entry: decode a top-level function blob and run it with
    `args` against `globals_`. Returns the function result (or a generator
    object if the frame is a generator)."""
    frame = decode(blob, perm, key, perm_ext)
    return run_func(frame, args, {}, globals_, closure=())
