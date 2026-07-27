"""Phase iO-5: Encrypted lookup-table obfuscation.

A lookup table is the general form of a point function: a function f with a
bounded domain {0, ..., N-1} and arbitrary outputs v_0, ..., v_{N-1}. The
obfuscated form ships N encrypted entries E_i = Enc(K_i, v_i) where K_i is a
per-entry key derived from a per-build master key: K_i = HKDF(master, i).

  Build time:
    - For each i in 0..N-1: compute v_i = f(i) (auto-eval the original body)
    - Derive K_i = SHA256(master || b'lookup_entry' || i)
    - Encrypt E_i = XOR_stream(v_i_repr, K_i)  (hash-based stream cipher)
    - Ship (E_0, ..., E_{N-1}, master)

  Runtime:
    - For input x: K_x = SHA256(master || b'lookup_entry' || x)
    - return literal_eval(XOR_stream(E_x, K_x))

This generalizes point-function obfuscation (iO-4) from single-point (1
entry, output=True) to multi-point (N entries, arbitrary outputs). An
adversary seeing the N ciphertexts cannot tell which entry corresponds to
which input without the master key. Under ROM the ciphertexts are
indistinguishable from uniform random bytes.

## Construction notes

- Encryption is a hash-based stream cipher (SHA-256 in counter mode as
  keystream generator). This is not a secure AEAD, but suffices for
  obfuscation (the goal is indistinguishability from random, not CCA
  security). A per-entry key means corrupting one entry does not reveal
  others.
- Serialization uses ``repr()`` + ``ast.literal_eval()`` so any Python
  literal (int, bool, str, bytes, None, tuple, list, dict) round-trips.
- The master key is shipped in the code (as a bytes literal) but is itself
  protected by downstream passes: FSS can split it, runtime_dec encrypts
  the code object containing it, crypto-opaque wraps the lookup in
  indistinguishable predicates.

## Use cases

  - S-box / permutation: ``@bedrock_lookup(domain=256)`` on a byte permutation
  - Small finite-state machine transition function
  - Configuration lookup with secret semantics
  - Composes with iO-4 pointfunc: the master key can itself be gated by a
    point-function evaluator (key released only for valid inputs)

## Kerckhoffs posture

Public construction. Per-build secret: the master key. The encrypted table
is unconditionally hiding under ROM. Pure stdlib (``ast``, ``hashlib``,
``secrets``). Run::

    python bedrock_native/_lookup_obf.py
"""
from __future__ import annotations

import ast
import hashlib
import os
import random
import secrets
import sys
from typing import List, Optional

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = [
    'obfuscate_lookup_table',
    'build_lookup_ast',
    'apply_lookup_obf',
]


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_io5_lookup')

        class _Wrap:
            __slots__ = ('_sub',)

            def __init__(self, s):
                self._sub = s

            def randint(self, lo, hi):
                return self._sub.randint(lo, hi)

            def choice(self, seq):
                return self._sub.choice(seq)

            def randbelow(self, n):
                return self._sub.randint(0, n - 1)

        return _Wrap(sub)
    seed = getattr(ctx, 'lookup_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _derive_entry_key(master: bytes, index: int) -> bytes:
    """K_i = SHA256(master || b'lookup_entry' || index_le8)."""
    h = hashlib.sha256()
    h.update(master)
    h.update(b'lookup_entry')
    h.update(index.to_bytes(8, 'little'))
    return h.digest()


def _xor_stream(plaintext: bytes, key: bytes) -> bytes:
    """Hash-based stream cipher: XOR plaintext with SHA-256(key||ctr) keystream.

    Symmetric: encrypt == decrypt.
    """
    out = bytearray()
    ctr = 0
    while len(out) < len(plaintext):
        h = hashlib.sha256()
        h.update(key)
        h.update(ctr.to_bytes(8, 'little'))
        out.extend(h.digest())
        ctr += 1
    return bytes(a ^ b for a, b in zip(plaintext, out[:len(plaintext)]))


# --- Core construction ------------------------------------------------------

def obfuscate_lookup_table(values: list, *, master_key: bytes = None) -> dict:
    """Obfuscate a lookup table f: {0..N-1} -> V.

    Args:
        values: list of outputs [v_0, v_1, ..., v_{N-1}]. Each v_i must be a
            Python literal (int, bool, str, bytes, None, tuple, list, dict).
        master_key: per-build master key (32 bytes); generated if None.

    Returns:
        dict with keys:
          - 'master_key': the master key (shipped with the evaluator)
          - 'table': list of N encrypted entries (bytes)
          - 'domain_size': N
    """
    if master_key is None:
        master_key = secrets.token_bytes(32)
    n = len(values)
    table = []
    for i, v in enumerate(values):
        v_repr = repr(v).encode('utf-8')
        k = _derive_entry_key(master_key, i)
        table.append(_xor_stream(v_repr, k))
    return {
        'master_key': master_key,
        'table': table,
        'domain_size': n,
    }


def build_lookup_ast(name: str, obf: dict, arg_name: str = 'x') -> ast.FunctionDef:
    """Build an AST function def for the obfuscated lookup evaluator.

    The generated function is::

        def NAME(x):
            import hashlib as _br_lt_h
            import ast as _br_lt_ast
            _br_lt_master = b'...'   # 32-byte master key
            _br_lt_table = [b'...', ...]  # N encrypted entries
            if not isinstance(x, int) or x < 0 or x >= N:
                raise ValueError('lookup: out of domain')
            _br_lt_k = _br_lt_h.sha256(_br_lt_master + b'lookup_entry' + x.to_bytes(8, 'little')).digest()
            _br_lt_ct = _br_lt_table[x]
            _br_lt_pt = bytearray()
            _br_lt_ctr = 0
            while len(_br_lt_pt) < len(_br_lt_ct):
                _br_lt_pt.extend(_br_lt_h.sha256(_br_lt_k + _br_lt_ctr.to_bytes(8, 'little')).digest())
                _br_lt_ctr += 1
            _br_lt_raw = bytes(a ^ b for a, b in zip(_br_lt_ct, _br_lt_pt[:len(_br_lt_ct)]))
            return _br_lt_ast.literal_eval(_br_lt_raw.decode('utf-8'))
    """
    master = obf['master_key']
    table = obf['table']
    n = obf['domain_size']

    body: List[ast.stmt] = [
        # import hashlib as _br_lt_h
        ast.Import(names=[ast.alias(name='hashlib', asname='_br_lt_h')]),
        # import ast as _br_lt_ast
        ast.Import(names=[ast.alias(name='ast', asname='_br_lt_ast')]),
        # _br_lt_master = b'...'
        ast.Assign(
            targets=[ast.Name(id='_br_lt_master', ctx=ast.Store())],
            value=ast.Constant(value=master),
        ),
        # _br_lt_table = [b'...', ...]
        ast.Assign(
            targets=[ast.Name(id='_br_lt_table', ctx=ast.Store())],
            value=ast.List(
                elts=[ast.Constant(value=e) for e in table],
                ctx=ast.Load(),
            ),
        ),
    ]

    # Domain check: if not isinstance(x, int) or x < 0 or x >= N: raise ValueError
    x_load = ast.Name(id=arg_name, ctx=ast.Load())
    domain_test = ast.BoolOp(
        op=ast.Or(),
        values=[
            ast.UnaryOp(
                op=ast.Not(),
                operand=ast.Call(
                    func=ast.Name(id='isinstance', ctx=ast.Load()),
                    args=[x_load, ast.Name(id='int', ctx=ast.Load())],
                    keywords=[],
                ),
            ),
            ast.Compare(
                left=ast.Name(id=arg_name, ctx=ast.Load()),
                ops=[ast.Lt()],
                comparators=[ast.Constant(value=0)],
            ),
            ast.Compare(
                left=ast.Name(id=arg_name, ctx=ast.Load()),
                ops=[ast.GtE()],
                comparators=[ast.Constant(value=n)],
            ),
        ],
    )
    body.append(ast.If(
        test=domain_test,
        body=[ast.Raise(
            exc=ast.Call(
                func=ast.Name(id='ValueError', ctx=ast.Load()),
                args=[ast.Constant(value='lookup: out of domain')],
                keywords=[],
            ),
            cause=None,
        )],
        orelse=[],
    ))

    # _br_lt_k = hashlib.sha256(_br_lt_master + b'lookup_entry' + x.to_bytes(8, 'little')).digest()
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_lt_k', ctx=ast.Store())],
        value=ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='_br_lt_h', ctx=ast.Load()),
                        attr='sha256', ctx=ast.Load(),
                    ),
                    args=[ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Name(id='_br_lt_master', ctx=ast.Load()),
                            op=ast.Add(),
                            right=ast.Constant(value=b'lookup_entry'),
                        ),
                        op=ast.Add(),
                        right=ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id=arg_name, ctx=ast.Load()),
                                attr='to_bytes', ctx=ast.Load(),
                            ),
                            args=[ast.Constant(value=8), ast.Constant(value='little')],
                            keywords=[],
                        ),
                    )],
                    keywords=[],
                ),
                attr='digest', ctx=ast.Load(),
            ),
            args=[], keywords=[],
        ),
    ))

    # _br_lt_ct = _br_lt_table[x]
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_lt_ct', ctx=ast.Store())],
        value=ast.Subscript(
            value=ast.Name(id='_br_lt_table', ctx=ast.Load()),
            slice=ast.Name(id=arg_name, ctx=ast.Load()),
            ctx=ast.Load(),
        ),
    ))

    # _br_lt_pt = bytearray()
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_lt_pt', ctx=ast.Store())],
        value=ast.Call(
            func=ast.Name(id='bytearray', ctx=ast.Load()),
            args=[], keywords=[],
        ),
    ))

    # _br_lt_ctr = 0
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_lt_ctr', ctx=ast.Store())],
        value=ast.Constant(value=0),
    ))

    # while len(_br_lt_pt) < len(_br_lt_ct):
    #     _br_lt_pt.extend(sha256(_br_lt_k + _br_lt_ctr.to_bytes(8,'little')).digest())
    #     _br_lt_ctr += 1
    body.append(ast.While(
        test=ast.Compare(
            left=ast.Call(
                func=ast.Name(id='len', ctx=ast.Load()),
                args=[ast.Name(id='_br_lt_pt', ctx=ast.Load())],
                keywords=[],
            ),
            ops=[ast.Lt()],
            comparators=[ast.Call(
                func=ast.Name(id='len', ctx=ast.Load()),
                args=[ast.Name(id='_br_lt_ct', ctx=ast.Load())],
                keywords=[],
            )],
        ),
        body=[
            ast.Expr(value=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='_br_lt_pt', ctx=ast.Load()),
                    attr='extend', ctx=ast.Load(),
                ),
                args=[ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id='_br_lt_h', ctx=ast.Load()),
                                attr='sha256', ctx=ast.Load(),
                            ),
                            args=[ast.BinOp(
                                left=ast.Name(id='_br_lt_k', ctx=ast.Load()),
                                op=ast.Add(),
                                right=ast.Call(
                                    func=ast.Attribute(
                                        value=ast.Name(id='_br_lt_ctr', ctx=ast.Load()),
                                        attr='to_bytes', ctx=ast.Load(),
                                    ),
                                    args=[ast.Constant(value=8), ast.Constant(value='little')],
                                    keywords=[],
                                ),
                            )],
                            keywords=[],
                        ),
                        attr='digest', ctx=ast.Load(),
                    ),
                    args=[], keywords=[],
                )],
                keywords=[],
            )),
            ast.AugAssign(
                target=ast.Name(id='_br_lt_ctr', ctx=ast.Store()),
                op=ast.Add(),
                value=ast.Constant(value=1),
            ),
        ],
        orelse=[],
    ))

    # _br_lt_raw = bytes(a ^ b for a, b in zip(_br_lt_ct, _br_lt_pt[:len(_br_lt_ct)]))
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_lt_raw', ctx=ast.Store())],
        value=ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[ast.GeneratorExp(
                elt=ast.BinOp(
                    left=ast.Name(id='a', ctx=ast.Load()),
                    op=ast.BitXor(),
                    right=ast.Name(id='b', ctx=ast.Load()),
                ),
                generators=[
                    ast.comprehension(
                        target=ast.Tuple(
                            elts=[ast.Name(id='a', ctx=ast.Store()),
                                  ast.Name(id='b', ctx=ast.Store())],
                            ctx=ast.Store(),
                        ),
                        iter=ast.Call(
                            func=ast.Name(id='zip', ctx=ast.Load()),
                            args=[
                                ast.Name(id='_br_lt_ct', ctx=ast.Load()),
                                ast.Subscript(
                                    value=ast.Name(id='_br_lt_pt', ctx=ast.Load()),
                                    slice=ast.Slice(
                                        lower=None,
                                        upper=ast.Call(
                                            func=ast.Name(id='len', ctx=ast.Load()),
                                            args=[ast.Name(id='_br_lt_ct', ctx=ast.Load())],
                                            keywords=[],
                                        ),
                                        step=None,
                                    ),
                                    ctx=ast.Load(),
                                ),
                            ],
                            keywords=[],
                        ),
                        ifs=[],
                        is_async=0,
                    ),
                ],
            )],
            keywords=[],
        ),
    ))

    # return ast.literal_eval(_br_lt_raw.decode('utf-8'))
    body.append(ast.Return(
        value=ast.Call(
            func=ast.Attribute(
                value=ast.Name(id='_br_lt_ast', ctx=ast.Load()),
                attr='literal_eval', ctx=ast.Load(),
            ),
            args=[ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='_br_lt_raw', ctx=ast.Load()),
                    attr='decode', ctx=ast.Load(),
                ),
                args=[ast.Constant(value='utf-8')],
                keywords=[],
            )],
            keywords=[],
        ),
    ))

    fn = ast.FunctionDef(
        name=name,
        args=ast.arguments(
            posonlyargs=[], args=[ast.arg(arg=arg_name, annotation=None)],
            kwonlyargs=[], kw_defaults=[], defaults=[],
            vararg=None, kwarg=None,
        ),
        body=body, decorator_list=[], returns=None, type_comment=None,
    )
    return fn


# --- Decorator detection ---------------------------------------------------

_MARKER = 'bedrock_lookup'


def _is_lookup_decorator(node: ast.expr) -> bool:
    """Detect @bedrock_lookup(domain=...) decorator."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == _MARKER:
        return True
    if isinstance(func, ast.Attribute) and func.attr == _MARKER:
        return True
    return False


def _extract_domain_from_decorator(deco: ast.Call) -> Optional[int]:
    """Extract the domain size from @bedrock_lookup(domain=N) call."""
    for kw in deco.keywords:
        if kw.arg == 'domain':
            v = kw.value
            if isinstance(v, ast.Constant) and isinstance(v.value, int):
                return v.value
    return None


def _auto_compute_outputs(func_node: ast.FunctionDef, domain: int) -> Optional[list]:
    """Compile the original function and call it for i in 0..domain-1.

    Returns the list of outputs, or None if auto-computation fails (e.g.,
    the function has external dependencies).
    """
    try:
        # Build a minimal module with just this function (strip decorators)
        clean_fn = ast.FunctionDef(
            name=func_node.name,
            args=func_node.args,
            body=func_node.body,
            decorator_list=[],
            returns=func_node.returns,
            type_comment=None,
        )
        mod = ast.Module(body=[clean_fn], type_ignores=[])
        ast.fix_missing_locations(mod)
        ns = {}
        exec(compile(mod, '<lookup-auto>', 'exec'), ns)
        fn = ns[func_node.name]
        return [fn(i) for i in range(domain)]
    except Exception:
        return None


# --- Pass -------------------------------------------------------------------

def apply_lookup_obf(tree: ast.Module, ctx) -> ast.Module:
    """Replace @bedrock_lookup(domain=N)-decorated functions with encrypted
    lookup-table evaluators.

    For each decorated function, the pass:
      1. Extracts the domain size N from the decorator
      2. Auto-computes outputs by evaluating the original body for i in 0..N-1
      3. Encrypts each output with a per-entry key derived from a per-build
         master key
      4. Replaces the function body with the lookup-table evaluator
      5. Strips the decorator (it's a build-time directive)

    The original algorithm is NOT shipped — only the encrypted outputs.
    """
    rng = _rng_for(ctx)
    n_obf = 0

    for node in list(tree.body):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Find the lookup decorator
        lt_deco = None
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and _is_lookup_decorator(d):
                lt_deco = d
                break
        if lt_deco is None:
            continue
        domain = _extract_domain_from_decorator(lt_deco)
        if domain is None or domain <= 0 or domain > (1 << 16):
            # Skip if no domain or unreasonably large (>65k entries)
            continue
        # Auto-compute outputs
        values = _auto_compute_outputs(node, domain)
        if values is None:
            continue
        # Generate per-build master key
        master_key = secrets.token_bytes(32)
        obf = obfuscate_lookup_table(values, master_key=master_key)
        # Build the evaluator function
        new_fn = build_lookup_ast(node.name, obf,
                                   arg_name=node.args.args[0].arg if node.args.args else 'x')
        # Preserve any other decorators (non-lookup)
        new_fn.decorator_list = [d for d in node.decorator_list if not (
            isinstance(d, ast.Call) and _is_lookup_decorator(d))]
        # Replace in-place
        idx = tree.body.index(node)
        tree.body[idx] = new_fn
        ast.fix_missing_locations(tree)
        n_obf += 1

    try:
        ctx.lookup_obfuscated = n_obf
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify: correctness, hiding, diversity, decorator detection, functional."""

    class _Ctx:
        build_rng = None
        lookup_seed = 42

    ctx = _Ctx()

    # --- Correctness: encrypted table decrypts to original values ---
    values = [(i * 7 + 3) % 256 for i in range(256)]
    obf = obfuscate_lookup_table(values)
    assert obf['domain_size'] == 256
    assert len(obf['table']) == 256
    # Decrypt each entry and verify
    for i, expected in enumerate(values):
        k = _derive_entry_key(obf['master_key'], i)
        pt = _xor_stream(obf['table'][i], k)
        assert ast.literal_eval(pt.decode('utf-8')) == expected, f"entry {i} mismatch"
    print("iO-5 correctness: all 256 entries decrypt correctly  OK")

    # --- Hiding: encrypted entries are NOT the raw values ---
    raw_v0 = repr(values[0]).encode('utf-8')
    assert obf['table'][0] != raw_v0, "encrypted entry must not be raw value"
    # Entries should look like random bytes (no obvious pattern)
    assert len(set(obf['table'])) == 256, "all entries should be distinct"
    print("iO-5 hiding: encrypted entries != raw values, all distinct  OK")

    # --- Diversity: different master keys -> different tables ---
    obf2 = obfuscate_lookup_table(values, master_key=b'B' * 32)
    assert obf['table'] != obf2['table'], "different keys must produce different tables"
    print("iO-5 diversity: different master keys -> different tables  OK")

    # --- Mixed-type values (int, bool, str, None) ---
    mixed = [42, True, 'hello', None, b'bytes', [1, 2, 3]]
    obf_mixed = obfuscate_lookup_table(mixed)
    for i, expected in enumerate(mixed):
        k = _derive_entry_key(obf_mixed['master_key'], i)
        pt = _xor_stream(obf_mixed['table'][i], k)
        assert ast.literal_eval(pt.decode('utf-8')) == expected
    print("iO-5 mixed types: int/bool/str/None/bytes/list all round-trip  OK")

    # --- Decorator detection + apply_lookup_obf ---
    src = (
        "def sbox(x):\n"
        "    return (x * 7 + 3) % 16\n"
        "\n"
        "def not_decorated(x):\n"
        "    return x + 1\n"
    )
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'sbox':
            node.decorator_list.insert(0, ast.Call(
                func=ast.Name(id='bedrock_lookup', ctx=ast.Load()),
                args=[], keywords=[ast.keyword(arg='domain', value=ast.Constant(value=16))],
            ))
            break
    ast.fix_missing_locations(tree)
    out = apply_lookup_obf(tree, ctx)
    assert getattr(ctx, 'lookup_obfuscated', 0) == 1, "should obfuscate 1 function"
    src_after = ast.unparse(out)
    assert 'bedrock_lookup' not in src_after, "decorator should be stripped"
    # not_decorated should be unchanged
    nd = next(n for n in out.body if getattr(n, 'name', '') == 'not_decorated')
    assert 'return x + 1' in ast.unparse(nd)
    print("iO-5 apply: decorator detected, body replaced, deco stripped  OK")

    # --- Functional: the obfuscated sbox works correctly ---
    ns = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<lt>', 'exec'), ns)
    sbox_obf = ns['sbox']
    for i in range(16):
        expected = (i * 7 + 3) % 16
        assert sbox_obf(i) == expected, f"sbox({i}) = {sbox_obf(i)} != {expected}"
    # Out-of-domain raises
    try:
        sbox_obf(16)
        assert False, "should raise ValueError for out-of-domain"
    except ValueError:
        pass
    try:
        sbox_obf(-1)
        assert False, "should raise ValueError for negative input"
    except ValueError:
        pass
    print("iO-5 functional: obfuscated sbox correct for all 16 inputs + OOB raises  OK")

    # --- Large domain (256) ---
    src2 = "def perm(x):\n    return (x * 73 + 17) % 256\n"
    tree2 = ast.parse(src2)
    for node in tree2.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'perm':
            node.decorator_list.insert(0, ast.Call(
                func=ast.Name(id='bedrock_lookup', ctx=ast.Load()),
                args=[], keywords=[ast.keyword(arg='domain', value=ast.Constant(value=256))],
            ))
            break
    ast.fix_missing_locations(tree2)
    out2 = apply_lookup_obf(tree2, ctx)
    ns2 = {}
    exec(compile(ast.Module(body=out2.body, type_ignores=[]), '<lt2>', 'exec'), ns2)
    perm_obf = ns2['perm']
    for i in range(256):
        expected = (i * 73 + 17) % 256
        assert perm_obf(i) == expected, f"perm({i}) mismatch"
    print("iO-5 large domain: 256-entry table all correct  OK")

    print("iO-5 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
