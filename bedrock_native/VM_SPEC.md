# BedrockVM Bytecode Specification (Phase 5)

BedrockVM is a stack-machine ISA distinct from CPython opcodes. Eligible user
functions are compiled to BedrockVM bytecode; a compiled C extension
(`_xvm.pyd` / `_xvm.so`) interprets that bytecode via the CPython C-API. A
pure-Python reference interpreter (`_bedrock_vm_ref.py`) is the executable spec
and the fallback when no C compiler is available.

## Design rationale

BedrockVM is a *translation target*, not a clone of CPython bytecode. The
compiler (Wave 2A) reads CPython 3.10/3.11 `co_code` (including inline caches,
`PRECALL`, `LOAD_GLOBAL`'s `push_null` bit, `KW_NAMES`) and **normalizes** those
quirks away when emitting BedrockVM opcodes. Consequences:

- **No inline caches.** CPython 3.11 `CACHE` entries are dropped by the
  compiler. BedrockVM instructions are dense (no padding).
- **No `NULL` markers on the value stack.** CPython pushes `NULL` before a
  plain-function `LOAD_GLOBAL` so `CALL` can tell function-call from
  method-call. BedrockVM collapses this: `LOAD_GLOBAL` always pushes the value,
  and `CALL` always treats the slot below the args as the callable. Method calls
  are lowered by the compiler to `LOAD_ATTR` + `CALL` (the bound method carries
  `self`).
- **No `PRECALL`.** It is a no-op marker in 3.11; the compiler drops it.
- **Jumps are absolute, in instruction units.** Each BedrockVM instruction is
  one logical unit (see "Instruction encoding" below). Jump operands are
  indices into the instruction stream, not byte offsets. This sidesteps the
  cache-padding arithmetic that makes CPython's relative jumps fiddly.

## Instruction encoding

Each instruction is **2 bytes** in the canonical (un-permuted) form:

```
[ opcode ] [ arg_lo ]
```

`opcode` is 1 byte (canonical value 0..255; see opcode table below).
`arg_lo` is 1 byte (0..255).

For operands exceeding 255, an `EXTENDED_ARG` instruction precedes the
consuming instruction and shifts its argument left by 8 bits, exactly like
CPython's `EXTENDED_ARG`. Two `EXTENDED_ARG`s give 24-bit operands (sufficient
for const-pool indices and jump targets up to ~16M instructions).

## Per-build opcode permutation

At build time a bijection `perm: canonical_opcode -> scrambled_opcode` is
generated per build (random `random.sample`). The bytecode blob carries
**scrambled** opcodes; the interpreter holds `perm` (compiled into the C
extension, passed as a parameter to the reference interpreter) and de-scrambles
on dispatch. The permutation table is **not** in the blob — it lives in native
code, so reversing requires RE'ing the binary.

`EXTENDED_ARG`'s canonical value is fixed (it must be recognizable before
de-scrambling so the interpreter can stitch arguments). Implementation: the
interpreter treats `EXTENDED_ARG`'s *scrambled* value as a known constant baked
into both the table and the interpreter.

## Bytecode blob format

All multi-byte integers are **little-endian**. The blob is what gets base85'd
into the output `.py` loader.

```
offset  size  field
  0      4    magic        = b'BVM1'
  4      1    version      = 1
  5      4    flags        = bit0: has_closure, bit1: is_generator, bit2: is_async
  9      4    argcount     = number of positional parameters
 13      4    kwonly_count = number of keyword-only parameters (0 if none)
 17      4    nlocals      = size of the locals frame (args + locals + cells)
 21      4    nconst       = number of constants
 25      4    const_len    = byte length of the encrypted const pool
 29      N    const_pool   = encrypted (see "Const pool encryption")
29+N     4    code_len     = number of instructions (NOT bytes; = bytes/2)
33+N     2*code_len  code = scrambled bytecode
33+N+2*code_len   4   n_names  = number of global/cell name strings
37+N+2*code_len   S   names_blob = pickled tuple of name strings (length-prefixed below)
```

The names blob is itself length-prefixed: 4 bytes length + (encrypted) pickled bytes.
Names are needed at runtime for `LOAD_GLOBAL`/`STORE_GLOBAL`/`IMPORT_NAME`
resolution and for closure cell binding. They ARE encrypted, with a key
derived from the main blob key so the names keystream is distinct from the
const-pool keystream (both would otherwise start at OFB offset 0, producing
a two-time-pad XOR relationship between the two ciphertexts):

```
names_key = sha256(key + b'|names').digest()
```

The cipher is the same SHA-256 OFB stream cipher used for the const pool,
applied to the `pickle.dumps((names, varnames, freevars, cellvars), protocol=4)`
bytes. OFB is length-preserving, so the on-disk `names_len` equals the
plaintext pickle length (important: `_fix_code_len` measures a *plaintext*
pickle to back-compute `code_len` and stays correct under this scheme).

## Const pool encryption

The const pool holds the constants (`co_consts` equivalents: ints, strings,
tuples, code objects for nested comprehensions, etc.). It is serialized with
`pickle.dumps(consts_tuple, protocol=4)` then encrypted with the **SHA-256 OFB
stream cipher** (reusing `_br_decrypt` from the main obfuscator, lines 9753-9763
in `bedrock_obfuscator.py`):

```
state_0 = sha256(key).digest()
state_n = sha256(state_{n-1} + key + bytes([offset & 255])).digest()
ciphertext[i] = plaintext[i] ^ state_n[i % 32]
```

`key` is 32 bytes. Its derivation:
- **Plain mode**: random 32 bytes, embedded in the C extension at build time
  (passed to the reference interpreter as a parameter).
- **Chain mode** (`--chain`): `key = sha256(prev_tag + master + label).digest()`
  where `label` is the function name — same derivation as the capsule keys
  (Phase 2, line 9743). Threading through the HMAC chain means tampering one
  VM function corrupts its tag + neighbour's + downstream keys.
- **Env-key mode** (`--env-key`): `key ^= env32` where `env32` is the 32-byte
  hardware fingerprint digest (`__BedrockEnvKey__`), same XOR-blinding pattern
  as lines 9738-9740.

Decryption happens in the interpreter (C: a small SHA-256 OFB loop; Python ref:
the same loop). The key never appears in the blob.

Both the const pool and the names blob are encrypted with the OFB cipher, but
with **distinct keys**: the const pool uses `key` directly, while the names blob
uses `names_key = sha256(key + b'|names')`. This prevents the two ciphertexts
(starting at the same OFB offset 0) from being XOR'd together to recover
`const_pickle XOR names_pickle`.

## Opcode table (canonical values)

Canonical opcodes 0..255. The interpreter dispatches on the **de-scrambled**
canonical value. `EXTENDED_ARG` (canonical 144, matching CPython) is the one
fixed value.

### Stack / control (canonical 0..31)

| val | name              | arg         | stack effect (before → after)                          | semantics |
|-----|-------------------|-------------|--------------------------------------------------------|-----------|
|  0  | NOP               | —           | —                                                      | no-op |
|  1  | POP_TOP           | —           | TOS →                                                  | discard top |
|  2  | DUP_TOP           | —           | TOS → TOS TOS                                          | duplicate top |
|  3  | ROT_TWO          | —           | a b → b a                                              | swap top 2 |
|  4  | ROT_THREE         | —           | a b c → c a b                                          | rotate top 3 |
|  5  | EXTENDED_ARG      | hi          | (sets high byte of next instr's arg)                   | fixed value, NOT permuted |
|  6  | RESUME            | —           | —                                                      | no-op marker (function entry) |
|  7  | JUMP              | target      | —                                                      | absolute jump to instr `target` |
|  8  | JUMP_IF_FALSE     | target      | TOS → (TOS consumed)                                   | pop; if falsy, jump |
|  9  | JUMP_IF_TRUE      | target      | TOS →                                                  | pop; if truthy, jump |
| 10  | JUMP_IF_NONE      | target      | TOS →                                                  | pop; if is None, jump |
| 11  | JUMP_IF_NOT_NONE  | target      | TOS →                                                  | pop; if not None, jump |
| 12  | FOR_ITER          | target      | iterator → value  (or jump to `target` on StopIter)    | advance iterator; push next or jump |
| 13  | GET_ITER          | —           | iterable → iterator                                    | `iter(iterable)` |
| 14  | RETURN_VALUE      | —           | TOS → (return)                                         | pop and return |
| 15  | RETURN_CONST      | const_idx   | → (return consts[idx])                                 | return constant (common tail) |
| 16  | YIELD_VALUE       | —           | TOS → (yield)                                          | pop and yield (generator) |
| 17  | RETURN_GENERATOR  | —           | —                                                      | mark frame as generator; early return |
| 18  | RAISE_VARARGS     | argc        | exc/(exc,cause) → (raise)                              | argc 0/1/2 |
| 19  | POP_BLOCK         | —           | —                                                      | pop try/except block (loop block in 3.10 compat) |
| 20  | PUSH_NULL         | —           | → NULL                                                 | push NULL sentinel (rare; compiler emits for compatibility) |
| 21  | LOAD_ASSERTION_ERR| —           | → AssertionError                                        | for assert lowering |
| 22  | RERAISE          | argc        | —                                                      | re-raise current exception |
| 23  | CHECK_EXC_MATCH   | —           | exc, type → bool                                       | `isinstance(exc, type)` |
| 24  | CHECK_EG_MATCH    | —           | —                                                      | exception group match (3.11+) |
| 25  | END_FOR           | —           | iterator →                                              | loop-end marker (3.12 compat; in 3.10 maps to NOP) |
| 26  | YIELD_FROM        | —           | TOS → (yield from)                                     | `yield from TOS` |
| 27  | GET_AITER         | —           | async-iterable → async-iterator                        | async `GET_ITER` (rare) |
| 28  | GET_AWAITABLE     | —           | TOS → awaitable                                        | make awaitable |
| 29  | SEND              | target      | iterator, value → (iter.next or jump)                  | generator `send` |
| 30  | SETUP_FINALLY     | target      | —                                                      | push try-block (handler at `target`) |
| 31  | SETUP_WITH        | target      | manager → exit_fn                                      | push with-block |

### Load / store (canonical 32..63)

| val | name              | arg         | stack effect             | semantics |
|-----|-------------------|-------------|--------------------------|-----------|
| 32  | LOAD_CONST         | idx         | → consts[idx]            | push constant |
| 33  | LOAD_FAST          | idx         | → locals[idx]            | push local (incl. args/cells) |
| 34  | LOAD_FAST_CHECK    | idx         | → locals[idx]            | like LOAD_FAST; raises UnboundLocalError if unset (compiler emits when safe) |
| 35  | LOAD_GLOBAL        | name_idx    | → globals[names[idx]]   | push global (NULL marker normalized away) |
| 36  | LOAD_DEREF         | idx         | → closure[idx]           | push closure cell |
| 37  | LOAD_NAME          | name_idx    | → name lookup            | name resolution (used in module/class exec) |
| 38  | LOAD_ATTR          | name_idx    | obj → value              | `getattr(obj, names[idx])` |
| 39  | LOAD_METHOD        | name_idx    | obj → method_or_self+method | like LOAD_ATTR; compiler normalizes method-call into LOAD_ATTR+CALL |
| 40  | STORE_FAST         | idx         | TOS →                    | locals[idx] = pop |
| 41  | STORE_GLOBAL       | name_idx    | TOS →                    | globals[names[idx]] = pop |
| 42  | STORE_DEREF        | idx         | TOS →                    | closure[idx] = pop |
| 43  | STORE_NAME         | name_idx    | TOS →                    | names[idx] = pop (module/class exec) |
| 44  | DELETE_FAST       | idx         | —                        | `del locals[idx]` |
| 45  | DELETE_GLOBAL     | name_idx    | —                        | `del globals[names[idx]]` |
| 46  | COPY              | depth       | ... → ... TOS            | `stack[-depth-1]` pushed (3.11) |
| 47  | SWAP              | depth       | ... → (swap top & stack[-depth]) | |
| 48  | LOAD_CLOSURE      | idx         | → cell                   | push cell object |
| 49  | MAKE_CELL         | idx         | —                        | (rare; for comprehension cells) |
| 50  | COPY_FREE_VARS    | n           | —                        | copy free vars into frame (closure setup) |
| 51  | LOAD_BUILD_CLASS  | —           | → __build_class__        | classdef |
| 52  | LOAD_ASSERTION_ERROR | —        | → AssertionError         | (alias of 21) |
| 53  | UNPACK_SEQUENCE   | count       | seq → seq[0]..seq[count-1] | unpack; raises if len != count |
| 54  | UNPACK_EX         | count       | seq → items+splat        | `a, *b, c = seq` |
| 55  | STORE_ATTR        | name_idx    | obj, TOS →               | `setattr(obj, names[idx], pop)` |
| 56  | DELETE_ATTR       | name_idx    | obj →                    | `delattr(obj, names[idx])` |
| 57  | STORE_SUBSCR      | —           | obj, key, TOS →          | `obj[key] = pop` |
| 58  | DELETE_SUBSCR     | —           | obj, key →               | `del obj[key]` |
| 59  | BINARY_SUBSCR     | —           | obj, key → obj[key]      | subscript get |
| 60  | FORMAT_VALUE      | flags       | TOS → str                | flags: 0=str(), 1=repr(), 2=ascii(), 4=!s f-string, has str_conv bit |
| 61  | BUILD_STRING      | count       | str*count → str          | f-string join |
| 62  | IMPORT_NAME       | name_idx    | fromlist, level → module | `__import__(names[idx], ...)` |
| 63  | IMPORT_FROM       | name_idx    | module → attr            | `getattr(module, names[idx])` |

### Building / function (canonical 64..95)

| val | name              | arg         | stack effect             | semantics |
|-----|-------------------|-------------|--------------------------|-----------|
| 64  | BUILD_TUPLE       | count       | items → tuple            | pop `count`, push tuple |
| 65  | BUILD_LIST       | count       | items → list             | pop `count`, push list |
| 66  | BUILD_SET        | count       | items → set              | pop `count`, push set |
| 67  | BUILD_MAP        | count       | pairs → dict             | pop `2*count` key/value pairs |
| 68  | LIST_EXTEND      | idx         | list, iter → list        | list.extend(iter); iter from locals[idx] in 3.10 variant |
| 69  | SET_UPDATE       | idx         | set, iter → set           | analogous |
| 70  | DICT_UPDATE      | idx         | dict, mapping → dict     | analogous |
| 71  | LIST_APPEND      | idx         | list, value → list        | append value to list (comprehension) |
| 72  | SET_ADD          | idx         | set, value → set          | add to set (comprehension) |
| 73  | MAP_ADD          | idx         | dict, key, value → dict   | add to dict (comprehension) |
| 74  | LIST_TO_TUPLE    | —           | list → tuple              | (rare) |
| 75  | BUILD_SLICE      | count       | start, stop[, step] → slice | 2 or 3 args |
| 76  | BUILD_CONST_KEY_MAP | count     | keys, vals → dict         | const keys |
| 77  | MAKE_FUNCTION    | flags       | code_obj[, qualname, defaults, kwdefaults, closure] → func | flags bit0=set_closure bit1=set_annotations bit2=kw_defaults |
| 78  | CALL             | argc        | callable, args*argc → result | `callable(*args)`; NULL-marker normalized away by compiler |
| 79  | CALL_KW          | (argc<<8)|nkw_idx | callable, args*argc, kwvals*nkw → result | kwarg NAMES are a const-pool tuple at const_idx `nkw_idx` |
| 80  | CALL_FUNCTION_EX | flags       | callable, args_tuple[, kwargs_dict] → result | flags bit0=has_kwargs |
| 81  | KW_NAMES         | const_idx   | → (stored for next CALL_KW) | records kwarg names tuple for the next CALL_KW (compat alias) |
| 82  | LOAD_CLASSDEREF   | idx         | → cell/classvar           | classdef |
| 83  | GEN_START        | kind        | —                         | generator/async-gen entry marker |
| 84  | MATCH_CLASS       | count       | subject, cls → attrs       | 3.10+ match |
| 85  | MATCH_KEYS        | —           | subject, keys → values, bool | 3.10+ match |
| 86  | MATCH_MAPPING     | —           | subject, map → bool        | 3.10+ match |
| 87  | MATCH_SEQUENCE    | —           | subject → bool              | 3.10+ match |
| 88  | KW_NAMES_LEN      | n           | —                          | (alias use of KW_NAMES with explicit length) |
| 89  | BEFORE_ASYNC_WITH | —           | mgr → exit_fn              | async-with setup |
| 90  | WITH_EXCEPT_START | —           | —                          | with-exit invocation |
| 91  | WITH_CLEANUP_START| —           | exc →                       | with cleanup |
| 92  | WITH_CLEANUP_FINISH| —          | —                          | with cleanup |
| 93  | SETUP_ASYNC_WITH  | target      | mgr → exit_fn               | async-with block |
| 94  | RESUME_GEN        | —           | —                          | generator resume (3.11 RESUME type 1) |
| 95  | LOAD_SUPER_ATTR   | name_idx    | —                          | super() attr |

### Binary / unary (canonical 96..127)

| val | name              | arg     | stack effect             | semantics |
|-----|-------------------|---------|---------------------------|-----------|
| 96  | BINARY_OP         | sub_op  | a, b → (a OP b)           | sub_op table below |
| 97  | UNARY_NEGATIVE    | —       | a → -a                    | |
| 98  | UNARY_NOT         | —       | a → not a                 | |
| 99  | UNARY_INVERT      | —       | a → ~a                    | |
|100  | COMPARE_OP        | cmp_op  | a, b → bool               | sub-op: 0-5 = <, <=, ==, !=, >, >= |
|101  | IS_OP             | —       | a, b → bool               | `a is b` |
|102  | CONTAINS_OP       | invert  | a, b → bool               | `b in a` (invert → `b not in a`) |
|103  | BINARY_SUBSCR_TUPLE| —      | tuple, idx → value        | fast-path |
|104  | BINARY_OP_INPLACE | sub_op  | target_ref, value → result | augmented assign |
|105  | GET_LEN           | —       | obj → len(obj)            | |
|106  | MATCH_MAPPING_KEYS| —       | —                         | match helper |
|107  | LOAD_SUPER_METHOD | name_idx| —                         | super method |
|108  | LOAD_METHOD_SUPER | name_idx| —                         | |
|109  | BUILD_LIST_TO_TUPLE| —       | —                         | |
|110  | FORMAT_SIMPLE     | —       | TOS → str                 | str() conversion |
|111  | FORMAT_WITH_SPEC  | —       | value, spec → str         | format(value, spec) |
|112  | JUMP_IF_FALSE_OR_POP | target | TOS →                     | if falsy: jump (keep TOS); else pop |
|113  | JUMP_IF_TRUE_OR_POP  | target | TOS →                     | if truthy: jump (keep TOS); else pop |
|114  | JUMP_IF_NOT_EXC_MATCH | —    | exc, type → bool          | |
|115  | POP_EXCEPT        | —       | —                         | pop except handler |
|116  | PUSH_EXC_INFO     | —       | —                         | push current exc info |
|117  | LOAD_ASSERTION_ERROR_ALT| —  | —                         | alias |
|118  | BEFORE_WITH      | —       | mgr → exit_fn             | with-enter (3.11) |
|119  | LOAD_BUILD_CLASS_ALT| —     | —                         | alias |
|120  | LIST_EXTEND_TOP  | —       | list, iter → list         | list.extend(iter) where iter is on stack |
|121  | DICT_MERGE       | —       | dict, mapping → dict      | dict merge |
|122  | DICT_INSERT      | —       | —                         | |
|123  | COPY_DICT        | —       | —                         | |
|124  | JUMP_IF_FALSE_POP_KEEP | target | TOS →                  | variant |
|125  | UNARY_POSITIVE   | —       | a → +a                    | |
|126  | NULL_PUSH        | —       | —                         | internal NULL marker (compat) |
|127  | END_SEND         | —       | —                         | end of send (3.11) |

`BINARY_OP` sub_op table (mirrors CPython 3.11 `NB_*`):
```
 0  +      1  -      2  *      3  /      4  %      5  //
 6  **     7  <<     8  >>     9  &     10  |     11  ^
12  << (alt)  13  +=   14  -=   15  *=   16  /=   17  %=
18  //=   19  **=   20  <<=   21  >>=  22  &=    23  |=
24  ^=    25  @     26  @=
```
`COMPARE_OP` cmp_op: `0 <, 1 <=, 2 ==, 3 !=, 4 >, 5 >=` (also 6-9 for `in`/`not in`/`is`/`is not` mapped by the compiler).

### Reserved (canonical 128..255)

128..143 reserved for future expansion (collections/async helpers).
144 = `EXTENDED_ARG` (FIXED — never permuted).
145..255 reserved.

## Function metadata

For each compiled function, the loader builds a Python function object whose
`__code__` is a stub `pass`, but whose actual logic is the bytecode blob. The
wrapper (emitted by the compiler into the user module) calls
`_xvm.run(blob, perm, key, args, globals_)`. The function's `co_argcount`,
`co_kwonlyargcount`, `co_nlocals`, `co_varnames`, `co_freevars`, `co_cellvars`,
`co_flags` (generator/async) are captured at compile time and encoded in the
blob header (argcount, kwonly_count, nlocals, flags) and in the names blob
(varnames/freevars/cellvars tuples).

## Generator semantics

When `flags & is_generator`: the interpreter, on first call, runs until the
first `YIELD_VALUE`/`RETURN_GENERATOR`, returning a generator object that
resumes on subsequent `next()`/`send()`. The reference interpreter implements
this with a Python generator (the simplest correct model); the C interpreter
implements it with a `PyGen_New`-style coroutine that suspends at `YIELD_VALUE`
by stashing the frame state and returning, resuming on the next `tp_iternext`.

## Closure semantics

When `flags & has_closure`: the compiled function references free variables in
enclosing scopes (comprehension inner code objects, nested defs). The compiler
emits `LOAD_DEREF`/`STORE_DEREF`/`LOAD_CLOSURE` for these; the loader binds the
cells at function-creation time. Comprehension inner code objects are compiled
recursively and stored in the const pool; the `MAKE_FUNCTION` for a listcomp
attaches the captured cells (typically the iterator in `.0`).

## Error semantics

- Any opcode may raise (e.g. `LOAD_GLOBAL` → `NameError`, `BINARY_OP` →
  `TypeError`, `CALL` → propagate callee exception). The interpreter must
  propagate the exception out via the normal CPython exception machinery
  (`PyErr_*` in C; `raise` in the reference). `try/except` in the user code is
  lowered to `SETUP_FINALLY` + a try-block stack; on exception the interpreter
  unwinds to the nearest `SETUP_FINALLY` target.
- `--debug-poison` (Phase 3): tamper detection (wrong key → garbage decrypt →
  likely `pickle.loads`/dispatch error) routes through `__h_poison` instead of
  raising, yielding silent inert behavior. The loader wraps the interpreter
  call in a `try/except Exception: __h_poison('vm_fail', 7); return None`.

## Out of scope for Wave 1

- The C interpreter (Wave 2B).
- The compiler (Wave 2A).
- Chain/env-key key derivation (Wave 4C).
- The build system + CLI (Wave 4A/4B).

Wave 1 delivers: this spec, the reference interpreter implementing every opcode
above, and oracle bytecode programs proving the interpreter runs correctly on
representative user-code shapes (arithmetic, loop, closure/comprehension,
try/except, kwargs, generator).
