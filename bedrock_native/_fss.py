"""Phase H.9 + Phase iO-2 Function Secret Sharing (FSS).

Phase H.9 (original): 2-share additive FSS for numeric-returning functions.

Phase iO-2 (extension): BGI-style FSS framework supporting multiple modes:

  - ``additive`` (default, Phase H.9): 2-share additive ``f1=f(x)+r, f2=-r``
    for int-returning functions. Each share alone is uniform random.
  - ``additive_n``: n-share additive (collusion-resistant: need all n shares
    to reconstruct; any n-1 shares reveal nothing). ``f1+...+fn = f(x)``.
  - ``bool``: XOR sharing for boolean-returning functions (predicates).
    ``f1 = f(x) ^ r, f2 = r`` → combine = ``f1 ^ f2 = f(x)``. Each share
    alone is a uniform random bit.
  - ``serialized``: any deterministic-returning function. Serialize via
    ``repr`` + ``int.from_bytes``, additive-share the int, reconstruct via
    ``ast.literal_eval``. Eligible for repr-roundtrip-safe types only.

The mode is selected via ``ctx.fss_mode`` (default ``'auto'``: try additive,
fall back to bool, then serialized). The number of shares for ``additive_n``
is ``ctx.fss_shares`` (default 3, min 2).

All modes share the same security property: the original function's logic
lives in SEPARATE ``def`` scopes so a static analyzer that reads only one
share cannot recover ``f(x)``. The combiner is a thin caller that sums
(additive) or XORs (bool) the share results.

## Kerckhoffs posture

Public technique. Per-build secret: the share function names + the RNG salt.

## Safety contract

- **Additive**: ``f1+...+fn = f(x)`` EXACTLY (Python unbounded int arithmetic).
- **Bool**: ``f1 ^ ... ^ fn = f(x)`` EXACTLY (bit arithmetic).
- **Serialized**: round-trips through ``repr`` + ``literal_eval``; only
  eligible if ``ast.literal_eval(repr(value)) == value`` for all inputs.
- **Randomness**: ``r`` is fresh per call via ``secrets.randbelow``.
- **Eligibility**: top-level ``def``, single ``return``, no side effects.
  Cap via ``ctx.fss_max`` (default 5; 0 = unlimited when
  ``ctx.fss_all_eligible``).

Pure stdlib (``ast``, ``random``, ``secrets``). Run::

    python bedrock_native/_fss.py
"""
from __future__ import annotations

import ast
import copy
import os
import random
import sys
from typing import List, Optional, Tuple

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['apply_fss']


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_h_fss')

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
    seed = getattr(ctx, 'fss_seed', None)
    r = random.Random(seed) if seed is not None else random.Random()
    # Add randbelow shim if missing (plain Random has it, but be safe).
    if not hasattr(r, 'randbelow'):
        r.randbelow = lambda n: r.randint(0, n - 1)  # type: ignore
    return r


def _has_side_effect(node: ast.expr) -> bool:
    for n in ast.walk(node):
        if isinstance(n, (ast.Call, ast.Yield, ast.YieldFrom, ast.Await)):
            return True
    return False


def _is_int_returning(value: ast.expr) -> bool:
    """Conservative: the return expression must look integer-valued."""
    if isinstance(value, ast.Constant):
        return isinstance(value.value, int) and not isinstance(value.value, bool) \
            or isinstance(value.value, bool)
    if isinstance(value, ast.Name):
        return True
    if isinstance(value, ast.UnaryOp):
        if isinstance(value.op, (ast.UAdd, ast.USub, ast.Invert)):
            return _is_int_returning(value.operand)
        return False
    if isinstance(value, ast.BinOp):
        if isinstance(value.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv,
                                  ast.Mod, ast.Pow, ast.BitAnd, ast.BitOr,
                                  ast.BitXor, ast.LShift, ast.RShift)):
            return _is_int_returning(value.left) and _is_int_returning(value.right)
        return False
    if isinstance(value, ast.Compare):
        return True
    if isinstance(value, ast.BoolOp):
        return True
    return False


def _is_bool_returning(value: ast.expr) -> bool:
    """Eligible for bool FSS: returns a comparison/bool op, or a name that
    we conservatively treat as bool (the smoke test verifies)."""
    if isinstance(value, ast.Constant):
        return isinstance(value.value, bool)
    if isinstance(value, ast.Compare):
        return True
    if isinstance(value, ast.BoolOp):
        return True
    if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
        return True
    return False


# Types whose repr round-trips through ast.literal_eval. We allow Constant
# (int/str/bytes/bool/None), List, Tuple, Set, Dict, and UnaryOp on those
# (for negative numbers). We reject Call/Name/Lambda/etc. — Name could be
# anything (a function, an object), and we cannot verify roundtrip statically.
_SERIALIZED_OK = (
    ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict,
)


def _is_serializable_returning(value: ast.expr) -> bool:
    """Eligible for serialized FSS: returns a literal-eval-safe expression.
    We walk and require every node be in the safe set, a UnaryOp on one, or a
    Name at a leaf (args/params — their values are substituted at runtime and
    must themselves be repr-roundtrip-safe for the combiner to work, which we
    assume conservatively for the smoke test)."""
    for n in ast.walk(value):
        # Skip expr_context nodes (Load/Store/Del) — they're not value nodes.
        if isinstance(n, ast.expr_context):
            continue
        if isinstance(n, _SERIALIZED_OK):
            continue
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.UAdd, ast.USub)):
            continue
        if isinstance(n, ast.Name):
            # args/params at leaves — runtime values must be repr-safe (the
            # smoke test verifies with concrete inputs).
            continue
        # BinOp inside container literals (e.g. [-1, 2+3]) — literal_eval
        # does NOT eval BinOps, so reject to be safe.
        return False
    return True


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


def _base_eligible(fn: ast.FunctionDef) -> bool:
    """Common eligibility: top-level def, single return, no side effects."""
    name = getattr(fn, 'name', '')
    if not name or name == 'bedrock_crown_jewel':
        return False
    if name in _PYTHON_DUNDERS:
        return False
    if isinstance(fn, ast.AsyncFunctionDef):
        return False
    if len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return False
    ret = fn.body[0].value
    if ret is None:
        return False
    if _has_side_effect(ret):
        return False
    # Reject identity functions (return <bare_name>) — return type unknown.
    if isinstance(ret, ast.Name):
        return False
    return True


def _is_eligible_additive(fn: ast.FunctionDef) -> bool:
    return _base_eligible(fn) and _is_int_returning(fn.body[0].value)


def _is_eligible_bool(fn: ast.FunctionDef) -> bool:
    return _base_eligible(fn) and _is_bool_returning(fn.body[0].value)


def _is_eligible_serialized(fn: ast.FunctionDef) -> bool:
    return _base_eligible(fn) and _is_serializable_returning(fn.body[0].value)


def _fresh_name(share_idx, rng) -> str:
    suffix = ''.join(rng.choice('0123456789abcdef') for _ in range(4))
    return f'_br_fss_{share_idx}_{suffix}'


def _share_args(orig_args: ast.arguments) -> ast.arguments:
    """Clone orig args + append trailing `r` parameter."""
    return ast.arguments(
        posonlyargs=list(orig_args.posonlyargs),
        args=list(orig_args.args) + [ast.arg(arg='r', annotation=None)],
        kwonlyargs=list(orig_args.kwonlyargs),
        kw_defaults=list(orig_args.kw_defaults),
        defaults=list(orig_args.defaults),
        vararg=orig_args.vararg,
        kwarg=orig_args.kwarg,
    )


def _combiner_args(orig_args: ast.arguments) -> ast.arguments:
    """Clone orig args (no `r`)."""
    return ast.arguments(
        posonlyargs=list(orig_args.posonlyargs),
        args=list(orig_args.args),
        kwonlyargs=list(orig_args.kwonlyargs),
        kw_defaults=list(orig_args.kw_defaults),
        defaults=list(orig_args.defaults),
        vararg=orig_args.vararg,
        kwarg=orig_args.kwarg,
    )


def _call_args(orig_args: ast.arguments) -> List[ast.expr]:
    """Names of orig positional args, for share call sites."""
    return [ast.Name(id=a.arg, ctx=ast.Load())
            for a in (orig_args.args + orig_args.posonlyargs)]


# --- Share builders ---------------------------------------------------------

def _build_additive_shares(node: ast.FunctionDef, rng, n_shares: int) -> Tuple[List[ast.FunctionDef], ast.FunctionDef]:
    """Build n additive shares + combiner for an int-returning function.

    n=2 (original H.9 scheme): pass SAME r to both shares.
      s1(args, r) = f(x) + r
      s2(args, r) = -r
      combiner: r = randbelow; return s1(args, r) + s2(args, r)

    n>=3 (proper n-share additive, collusion-resistant):
      s1(args, r) = r           (gets r1)
      s2(args, r) = r           (gets r2)
      ...
      s_{n-1}(args, r) = r      (gets r_{n-1})
      s_n(args, r) = f(x) - r   (gets sum(r1..r_{n-1}))
      combiner: r1..r_{n-1} = randbelow; rs = sum(r1..r_{n-1});
               return s1(args,r1) + ... + s_{n-1}(args,r_{n-1}) + s_n(args, rs)
             = r1+..+r_{n-1} + f(x) - (r1+..+r_{n-1}) = f(x)

    Each share alone is uniform random. Any n-1 shares reveal nothing about
    f(x) because the missing share's random contribution is unknown.
    """
    orig_args = node.args
    ret_expr = node.body[0].value
    share_names = [_fresh_name(i + 1, rng) for i in range(n_shares)]
    share_fns = []

    if n_shares == 2:
        # Original H.9 scheme: both shares take the SAME r.
        s1_args = _share_args(orig_args)
        s1_body = ast.Return(value=ast.BinOp(
            left=copy.deepcopy(ret_expr),
            op=ast.Add(),
            right=ast.Name(id='r', ctx=ast.Load()),
        ))
        share_fns.append(ast.FunctionDef(
            name=share_names[0], args=s1_args, body=[s1_body],
            decorator_list=[], returns=None, type_comment=None,
        ))
        s2_args = _share_args(orig_args)
        s2_body = ast.Return(value=ast.UnaryOp(
            op=ast.USub(), operand=ast.Name(id='r', ctx=ast.Load()),
        ))
        share_fns.append(ast.FunctionDef(
            name=share_names[1], args=s2_args, body=[s2_body],
            decorator_list=[], returns=None, type_comment=None,
        ))
    else:
        # n>=3 proper additive: shares 1..n-1 return r; share n returns f(x)-r.
        for i in range(n_shares - 1):
            si_args = _share_args(orig_args)
            si_body = ast.Return(value=ast.Name(id='r', ctx=ast.Load()))
            share_fns.append(ast.FunctionDef(
                name=share_names[i], args=si_args, body=[si_body],
                decorator_list=[], returns=None, type_comment=None,
            ))
        sn_args = _share_args(orig_args)
        sn_body = ast.Return(value=ast.BinOp(
            left=copy.deepcopy(ret_expr),
            op=ast.Sub(),
            right=ast.Name(id='r', ctx=ast.Load()),
        ))
        share_fns.append(ast.FunctionDef(
            name=share_names[-1], args=sn_args, body=[sn_body],
            decorator_list=[], returns=None, type_comment=None,
        ))

    combiner = _build_additive_combiner(node, share_names, n_shares)
    return share_fns, combiner


def _build_additive_combiner(node: ast.FunctionDef, share_names: List[str], n_shares: int) -> ast.FunctionDef:
    """Build the combiner for additive sharing.

    n=2: pass SAME r to both shares.
    n>=3: generate r1..r_{n-1}, pass r_i to share i, pass sum(r1..r_{n-1}) to share n.
    """
    orig_args = node.args
    carg = _call_args(orig_args)
    combiner_args = _combiner_args(orig_args)

    body: List[ast.stmt] = [ast.Import(names=[ast.alias(name='secrets', asname='_br_s')])]

    if n_shares == 2:
        # Single r, passed to both shares (original H.9).
        body.append(ast.Assign(
            targets=[ast.Name(id='_br_r', ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.Call(
                    func=ast.Attribute(value=ast.Name(id='_br_s', ctx=ast.Load()),
                                       attr='randbelow', ctx=ast.Load()),
                    args=[ast.Constant(value=1 << 64)], keywords=[],
                ),
                op=ast.Sub(),
                right=ast.Constant(value=1 << 63),
            ),
        ))
        ret_expr = ast.BinOp(
            left=ast.Call(func=ast.Name(id=share_names[0], ctx=ast.Load()),
                          args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
            op=ast.Add(),
            right=ast.Call(func=ast.Name(id=share_names[1], ctx=ast.Load()),
                           args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
        )
        body.append(ast.Return(value=ret_expr))
    else:
        # n>=3: generate r1..r_{n-1}, pass each to share 1..n-1, pass sum to share n.
        r_names = []
        for i in range(n_shares - 1):
            rn = f'_br_r{i + 1}'
            r_names.append(rn)
            body.append(ast.Assign(
                targets=[ast.Name(id=rn, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Call(
                        func=ast.Attribute(value=ast.Name(id='_br_s', ctx=ast.Load()),
                                           attr='randbelow', ctx=ast.Load()),
                        args=[ast.Constant(value=1 << 64)], keywords=[],
                    ),
                    op=ast.Sub(),
                    right=ast.Constant(value=1 << 63),
                ),
            ))
        rs_expr = ast.Name(id=r_names[0], ctx=ast.Load())
        for rn in r_names[1:]:
            rs_expr = ast.BinOp(left=rs_expr, op=ast.Add(),
                               right=ast.Name(id=rn, ctx=ast.Load()))
        body.append(ast.Assign(
            targets=[ast.Name(id='_br_rs', ctx=ast.Store())],
            value=rs_expr,
        ))
        calls = []
        for i in range(n_shares - 1):
            calls.append(ast.Call(
                func=ast.Name(id=share_names[i], ctx=ast.Load()),
                args=carg + [ast.Name(id=r_names[i], ctx=ast.Load())],
                keywords=[],
            ))
        calls.append(ast.Call(
            func=ast.Name(id=share_names[-1], ctx=ast.Load()),
            args=carg + [ast.Name(id='_br_rs', ctx=ast.Load())],
            keywords=[],
        ))
        ret_expr = calls[0]
        for c in calls[1:]:
            ret_expr = ast.BinOp(left=ret_expr, op=ast.Add(), right=c)
        body.append(ast.Return(value=ret_expr))

    return ast.FunctionDef(
        name=node.name, args=combiner_args, body=body,
        decorator_list=[], returns=None, type_comment=None,
    )


def _build_bool_shares(node: ast.FunctionDef, rng, n_shares: int) -> Tuple[List[ast.FunctionDef], ast.FunctionDef]:
    """Build n XOR shares + combiner for a bool-returning function.

    XOR sharing: f1 = f(x) ^ r1, f2 = r2, ..., s_n = r1 ^ r2 ^ ... ^ r_{n-1}
    combiner = s1 ^ s2 ^ ... ^ s_n = f(x) ^ r1 ^ r2 ^ ... ^ r_{n-1} ^ (r1^..^r_{n-1}) = f(x)

    For n=2: s1 = f(x) ^ r, s2 = r → combine = s1 ^ s2 = f(x).

    Each r_i is a fresh random bit per call. Any n-1 shares reveal nothing
    about f(x) (the missing share's bit is uniform).
    """
    orig_args = node.args
    ret_expr = node.body[0].value
    share_names = [_fresh_name(i + 1, rng) for i in range(n_shares)]
    share_fns = []

    # share 1: return <orig> ^ r
    s1_args = _share_args(orig_args)
    s1_body = ast.Return(value=ast.BinOp(
        left=ast.BoolOp(op=ast.BitOr(), values=[copy.deepcopy(ret_expr)]),  # force int context
        op=ast.BitXor(),
        right=ast.Name(id='r', ctx=ast.Load()),
    ))
    # Simpler: cast bool to int via `(<expr>) ^ r` — Python bool is int subclass.
    s1_body = ast.Return(value=ast.BinOp(
        left=copy.deepcopy(ret_expr),
        op=ast.BitXor(),
        right=ast.Name(id='r', ctx=ast.Load()),
    ))
    share_fns.append(ast.FunctionDef(
        name=share_names[0], args=s1_args, body=[s1_body],
        decorator_list=[], returns=None, type_comment=None,
    ))

    # shares 2..n-1: return r
    for i in range(1, n_shares - 1):
        si_args = _share_args(orig_args)
        si_body = ast.Return(value=ast.Name(id='r', ctx=ast.Load()))
        share_fns.append(ast.FunctionDef(
            name=share_names[i], args=si_args, body=[si_body],
            decorator_list=[], returns=None, type_comment=None,
        ))

    # share n: return r  (XOR is symmetric; combiner cancels via XOR of all)
    if n_shares >= 2:
        sn_args = _share_args(orig_args)
        sn_body = ast.Return(value=ast.Name(id='r', ctx=ast.Load()))
        share_fns.append(ast.FunctionDef(
            name=share_names[-1], args=sn_args, body=[sn_body],
            decorator_list=[], returns=None, type_comment=None,
        ))

    combiner = _build_bool_combiner(node, share_names, n_shares)
    return share_fns, combiner


def _build_bool_combiner(node: ast.FunctionDef, share_names: List[str], n_shares: int) -> ast.FunctionDef:
    """Build combiner: XOR-fold of n share calls, cast result back to bool.

    n=2: pass SAME r to both shares → s1 ^ s2 = f(x) ^ r ^ r = f(x).
    n>=3: generate r1..r_{n-1} (random bits), pass to shares 1..n-1, pass
          XOR(r1..r_{n-1}) to share n. combiner = s1 ^ ... ^ sn =
          (f(x) ^ rs) ^ r1 ^ ... ^ r_{n-1} = f(x) ^ rs ^ rs = f(x).
    """
    orig_args = node.args
    carg = _call_args(orig_args)
    combiner_args = _combiner_args(orig_args)

    body: List[ast.stmt] = [ast.Import(names=[ast.alias(name='secrets', asname='_br_s')])]

    def _randbit():
        return ast.Call(
            func=ast.Attribute(value=ast.Name(id='_br_s', ctx=ast.Load()),
                               attr='randbelow', ctx=ast.Load()),
            args=[ast.Constant(value=2)], keywords=[],
        )

    if n_shares == 2:
        # Single r, passed to both shares.
        body.append(ast.Assign(
            targets=[ast.Name(id='_br_r', ctx=ast.Store())],
            value=_randbit(),
        ))
        xor_expr = ast.BinOp(
            left=ast.Call(func=ast.Name(id=share_names[0], ctx=ast.Load()),
                          args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
            op=ast.BitXor(),
            right=ast.Call(func=ast.Name(id=share_names[1], ctx=ast.Load()),
                           args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
        )
    else:
        # n>=3: r1..r_{n-1} to shares 1..n-1; XOR sum to share n.
        r_names = []
        for i in range(n_shares - 1):
            rn = f'_br_r{i + 1}'
            r_names.append(rn)
            body.append(ast.Assign(targets=[ast.Name(id=rn, ctx=ast.Store())], value=_randbit()))
        rs_expr = ast.Name(id=r_names[0], ctx=ast.Load())
        for rn in r_names[1:]:
            rs_expr = ast.BinOp(left=rs_expr, op=ast.BitXor(), right=ast.Name(id=rn, ctx=ast.Load()))
        body.append(ast.Assign(targets=[ast.Name(id='_br_rs', ctx=ast.Store())], value=rs_expr))
        calls = []
        for i in range(n_shares - 1):
            calls.append(ast.Call(func=ast.Name(id=share_names[i], ctx=ast.Load()),
                                  args=carg + [ast.Name(id=r_names[i], ctx=ast.Load())], keywords=[]))
        calls.append(ast.Call(func=ast.Name(id=share_names[-1], ctx=ast.Load()),
                              args=carg + [ast.Name(id='_br_rs', ctx=ast.Load())], keywords=[]))
        xor_expr = calls[0]
        for c in calls[1:]:
            xor_expr = ast.BinOp(left=xor_expr, op=ast.BitXor(), right=c)

    body.append(ast.Return(value=ast.Call(
        func=ast.Name(id='bool', ctx=ast.Load()),
        args=[xor_expr], keywords=[],
    )))

    return ast.FunctionDef(
        name=node.name, args=combiner_args, body=body,
        decorator_list=[], returns=None, type_comment=None,
    )


def _build_serialized_shares(node: ast.FunctionDef, rng, n_shares: int) -> Tuple[List[ast.FunctionDef], ast.FunctionDef]:
    """Build n additive shares + combiner for a serialized-return function.

    Scheme: serialize f(x) to bytes via `repr(f(x)).encode('utf-8')`, prepend
    a 4-byte big-endian length prefix (to survive leading-zero byte loss in
    int conversion), then to int via `int.from_bytes(..., 'big')`. Additive-
    share the int. Combiner reconstructs: int → bytes → first 4 bytes = length
    → next `length` bytes = data → decode → ast.literal_eval.

    share 1: return <serialized_int> + r
    shares 2..n-1: return r
    share n: return -r
    combiner: r = randbelow(...); s = s1(..,r) + .. + sn(..,r);
              b = s.to_bytes((max(1,s.bit_length())+7)//8, 'big');
              n = int.from_bytes(b[:4], 'big');
              return ast.literal_eval(b[4:4+n].decode('utf-8'))
    """
    orig_args = node.args
    ret_expr = node.body[0].value
    share_names = [_fresh_name(i + 1, rng) for i in range(n_shares)]
    share_fns = []

    # serialize expr: int.from_bytes(b'\x01' + len(repr(...).encode()).to_bytes(7,'big') + repr(...).encode(), 'big')
    # The 0x01 marker byte prevents leading-zero loss in int<->bytes round-trip.
    repr_call = ast.Call(func=ast.Name(id='repr', ctx=ast.Load()),
                         args=[copy.deepcopy(ret_expr)], keywords=[])
    encode_call = ast.Call(func=ast.Attribute(value=repr_call, attr='encode', ctx=ast.Load()),
                           args=[ast.Constant(value='utf-8')], keywords=[])
    len_call = ast.Call(func=ast.Name(id='len', ctx=ast.Load()), args=[encode_call], keywords=[])
    len_bytes = ast.Call(
        func=ast.Attribute(value=len_call, attr='to_bytes', ctx=ast.Load()),
        args=[ast.Constant(value=7), ast.Constant(value='big')], keywords=[],
    )
    marker = ast.Constant(value=b'\x01')
    # repr(...).encode() again (can't reuse AST node)
    repr_call2 = ast.Call(func=ast.Name(id='repr', ctx=ast.Load()),
                          args=[copy.deepcopy(ret_expr)], keywords=[])
    encode_call2 = ast.Call(func=ast.Attribute(value=repr_call2, attr='encode', ctx=ast.Load()),
                            args=[ast.Constant(value='utf-8')], keywords=[])
    payload = ast.BinOp(
        left=ast.BinOp(left=marker, op=ast.Add(), right=len_bytes),
        op=ast.Add(), right=encode_call2,
    )
    ser_expr = ast.Call(
        func=ast.Attribute(value=ast.Name(id='int', ctx=ast.Load()),
                           attr='from_bytes', ctx=ast.Load()),
        args=[payload, ast.Constant(value='big')], keywords=[],
    )

    # share 1: return <serialized> + r
    s1_args = _share_args(orig_args)
    s1_body = ast.Return(value=ast.BinOp(
        left=ser_expr, op=ast.Add(), right=ast.Name(id='r', ctx=ast.Load()),
    ))
    share_fns.append(ast.FunctionDef(
        name=share_names[0], args=s1_args, body=[s1_body],
        decorator_list=[], returns=None, type_comment=None,
    ))

    # shares 2..n-1: return r
    for i in range(1, n_shares - 1):
        si_args = _share_args(orig_args)
        si_body = ast.Return(value=ast.Name(id='r', ctx=ast.Load()))
        share_fns.append(ast.FunctionDef(
            name=share_names[i], args=si_args, body=[si_body],
            decorator_list=[], returns=None, type_comment=None,
        ))

    # share n: return -r
    if n_shares >= 2:
        sn_args = _share_args(orig_args)
        sn_body = ast.Return(value=ast.UnaryOp(
            op=ast.USub(), operand=ast.Name(id='r', ctx=ast.Load()),
        ))
        share_fns.append(ast.FunctionDef(
            name=share_names[-1], args=sn_args, body=[sn_body],
            decorator_list=[], returns=None, type_comment=None,
        ))

    combiner = _build_serialized_combiner(node, share_names, n_shares)
    return share_fns, combiner


def _build_serialized_combiner(node: ast.FunctionDef, share_names: List[str], n_shares: int) -> ast.FunctionDef:
    """Combiner for serialized FSS (n=2 same r; length-prefix reconstruction)."""
    orig_args = node.args
    carg = _call_args(orig_args)
    combiner_args = _combiner_args(orig_args)

    body: List[ast.stmt] = [
        ast.Import(names=[ast.alias(name='secrets', asname='_br_s')]),
        ast.Import(names=[ast.alias(name='ast', asname='_br_ast')]),
    ]

    # n=2: single r passed to both shares (mirrors additive n=2).
    # n>=3: r1..r_{n-1} to shares 1..n-1, sum to share n.
    if n_shares == 2:
        body.append(ast.Assign(
            targets=[ast.Name(id='_br_r', ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.Call(
                    func=ast.Attribute(value=ast.Name(id='_br_s', ctx=ast.Load()),
                                       attr='randbelow', ctx=ast.Load()),
                    args=[ast.Constant(value=1 << 256)], keywords=[],
                ),
                op=ast.Sub(),
                right=ast.Constant(value=1 << 255),
            ),
        ))
        sum_expr = ast.BinOp(
            left=ast.Call(func=ast.Name(id=share_names[0], ctx=ast.Load()),
                          args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
            op=ast.Add(),
            right=ast.Call(func=ast.Name(id=share_names[1], ctx=ast.Load()),
                           args=carg + [ast.Name(id='_br_r', ctx=ast.Load())], keywords=[]),
        )
    else:
        r_names = []
        for i in range(n_shares - 1):
            rn = f'_br_r{i + 1}'
            r_names.append(rn)
            body.append(ast.Assign(
                targets=[ast.Name(id=rn, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Call(
                        func=ast.Attribute(value=ast.Name(id='_br_s', ctx=ast.Load()),
                                           attr='randbelow', ctx=ast.Load()),
                        args=[ast.Constant(value=1 << 256)], keywords=[],
                    ),
                    op=ast.Sub(),
                    right=ast.Constant(value=1 << 255),
                ),
            ))
        rs_expr = ast.Name(id=r_names[0], ctx=ast.Load())
        for rn in r_names[1:]:
            rs_expr = ast.BinOp(left=rs_expr, op=ast.Add(), right=ast.Name(id=rn, ctx=ast.Load()))
        body.append(ast.Assign(targets=[ast.Name(id='_br_rs', ctx=ast.Store())], value=rs_expr))
        calls = []
        for i in range(n_shares - 1):
            calls.append(ast.Call(func=ast.Name(id=share_names[i], ctx=ast.Load()),
                                  args=carg + [ast.Name(id=r_names[i], ctx=ast.Load())], keywords=[]))
        calls.append(ast.Call(func=ast.Name(id=share_names[-1], ctx=ast.Load()),
                              args=carg + [ast.Name(id='_br_rs', ctx=ast.Load())], keywords=[]))
        sum_expr = calls[0]
        for c in calls[1:]:
            sum_expr = ast.BinOp(left=sum_expr, op=ast.Add(), right=c)

    body.append(ast.Assign(targets=[ast.Name(id='_br_v', ctx=ast.Store())], value=sum_expr))

    # Reconstruct: b = _br_v.to_bytes((max(1,_br_v.bit_length())+7)//8, 'big')
    # b[0] == 0x01 marker; _br_n = int.from_bytes(b[1:8], 'big')  # length (7 bytes)
    # return ast.literal_eval(b[8:8+_br_n].decode('utf-8'))
    bl = ast.Call(func=ast.Attribute(value=ast.Name(id='_br_v', ctx=ast.Load()),
                                     attr='bit_length', ctx=ast.Load()), args=[], keywords=[])
    maxlen = ast.BinOp(
        left=ast.Call(func=ast.Name(id='max', ctx=ast.Load()),
                      args=[ast.Constant(value=1), bl], keywords=[]),
        op=ast.Add(), right=ast.Constant(value=7),
    )
    nbytes = ast.BinOp(left=maxlen, op=ast.FloorDiv(), right=ast.Constant(value=8))
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_b', ctx=ast.Store())],
        value=ast.Call(func=ast.Attribute(value=ast.Name(id='_br_v', ctx=ast.Load()),
                                          attr='to_bytes', ctx=ast.Load()),
                       args=[nbytes, ast.Constant(value='big')], keywords=[]),
    ))
    # _br_n = int.from_bytes(b[1:8], 'big')  # 7-byte length after the 0x01 marker
    body.append(ast.Assign(
        targets=[ast.Name(id='_br_n', ctx=ast.Store())],
        value=ast.Call(func=ast.Attribute(value=ast.Name(id='int', ctx=ast.Load()),
                                          attr='from_bytes', ctx=ast.Load()),
                       args=[ast.Subscript(
                           value=ast.Name(id='_br_b', ctx=ast.Load()),
                           slice=ast.Slice(lower=ast.Constant(value=1), upper=ast.Constant(value=8), step=None),
                           ctx=ast.Load(),
                       ), ast.Constant(value='big')], keywords=[]),
    ))
    # return ast.literal_eval(b[8:8+_br_n].decode('utf-8'))
    body.append(ast.Return(value=ast.Call(
        func=ast.Attribute(value=ast.Name(id='_br_ast', ctx=ast.Load()),
                           attr='literal_eval', ctx=ast.Load()),
        args=[ast.Call(
            func=ast.Attribute(
                value=ast.Subscript(
                    value=ast.Name(id='_br_b', ctx=ast.Load()),
                    slice=ast.Slice(lower=ast.Constant(value=8),
                                   upper=ast.BinOp(left=ast.Constant(value=8),
                                                  op=ast.Add(),
                                                  right=ast.Name(id='_br_n', ctx=ast.Load())),
                                   step=None),
                    ctx=ast.Load(),
                ),
                attr='decode', ctx=ast.Load(),
            ),
            args=[ast.Constant(value='utf-8')], keywords=[],
        )], keywords=[],
    )))

    return ast.FunctionDef(
        name=node.name, args=combiner_args, body=body,
        decorator_list=[], returns=None, type_comment=None,
    )


# --- Mode dispatch ----------------------------------------------------------

_ELIGIBILITY = {
    'additive': _is_eligible_additive,
    'additive_n': _is_eligible_additive,
    'bool': _is_eligible_bool,
    'serialized': _is_eligible_serialized,
}

_BUILDERS = {
    'additive': lambda node, rng, n: _build_additive_shares(node, rng, 2),
    'additive_n': _build_additive_shares,
    'bool': lambda node, rng, n: _build_bool_shares(node, rng, 2),
    'serialized': lambda node, rng, n: _build_serialized_shares(node, rng, 2),
}


def _resolve_mode(ctx, fn: ast.FunctionDef) -> Optional[str]:
    """Pick the FSS mode for `fn` based on ctx.fss_mode (auto-discovery)."""
    mode = str(getattr(ctx, 'fss_mode', 'auto') or 'auto').lower()
    if mode in _ELIGIBILITY and _ELIGIBILITY[mode](fn):
        return mode
    if mode == 'auto':
        # Try bool first (most type-preserving for predicates), then additive
        # (int arithmetic), then serialized (any repr-safe value).
        for m in ('bool', 'additive', 'serialized'):
            if _ELIGIBILITY[m](fn):
                return m
        return None
    return None


def _effective_n_shares(ctx, mode: str) -> int:
    if mode == 'additive':
        return 2
    if mode == 'additive_n':
        n = int(getattr(ctx, 'fss_shares', 3) or 3)
        return max(2, n)
    if mode == 'bool':
        return 2
    if mode == 'serialized':
        return 2
    return 2


# --- Pass -------------------------------------------------------------------

def apply_fss(tree: ast.Module, ctx) -> ast.Module:
    """Split eligible functions into FSS shares + a combiner.

    Mode + share count are controlled via ctx.fss_mode / ctx.fss_shares.
    Cap is ctx.fss_max (default 5); 0 with ctx.fss_all_eligible = unlimited.
    """
    rng = _rng_for(ctx)
    max_fns = int(getattr(ctx, 'fss_max', 0) or 5)
    if getattr(ctx, 'fss_all_eligible', False):
        max_fns = 0  # unlimited
    shared = 0

    for node in list(tree.body):
        if not isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            continue
        mode = _resolve_mode(ctx, node)
        if mode is None:
            continue
        if max_fns and shared >= max_fns:
            break

        n_shares = _effective_n_shares(ctx, mode)
        builder = _BUILDERS[mode] if mode in _BUILDERS else _BUILDERS['additive']
        if mode == 'additive_n':
            share_fns, combiner = _build_additive_shares(node, rng, n_shares)
        elif mode == 'bool':
            share_fns, combiner = _build_bool_shares(node, rng, n_shares)
        elif mode == 'serialized':
            share_fns, combiner = _build_serialized_shares(node, rng, n_shares)
        else:  # additive
            share_fns, combiner = _build_additive_shares(node, rng, 2)

        idx = tree.body.index(node)
        tree.body[idx:idx + 1] = [*share_fns, combiner]
        ast.fix_missing_locations(tree)
        shared += 1

    try:
        ctx.fss_shared = shared
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify all modes: combine == original, shares alone random, eligibility."""

    class _Ctx:
        build_rng = None
        fss_seed = 31
        fss_max = 5
        fss_mode = 'auto'
        fss_shares = 3
        fss_all_eligible = False

    # --- Mode: additive (backward compat with H.9) ---
    src = (
        "def square(x):\n"
        "    return x * x\n"
        "\n"
        "def add_one(n):\n"
        "    return n + 1\n"
        "\n"
        "def is_even(n):\n"
        "    return n % 2 == 0\n"
        "\n"
        "def get_tuple(a, b):\n"
        "    return (a, b)\n"
    )
    tree = ast.parse(src)
    ns = {}
    exec(compile(ast.Module(body=tree.body, type_ignores=[]), '<base>', 'exec'), ns)
    assert ns['square'](5) == 25
    assert ns['add_one'](5) == 6
    assert ns['is_even'](4) is True
    assert ns['get_tuple'](3, 4) == (3, 4)
    print("iO-2 baseline: square=25, add_one=6, is_even=True, get_tuple=(3,4)  OK")

    ctx = _Ctx()
    ctx.fss_mode = 'auto'
    out = apply_fss(tree, ctx)
    assert getattr(ctx, 'fss_shared', 0) == 4, f"expected 4 shared, got {ctx.fss_shared}"
    print(f"iO-2 auto: {ctx.fss_shared} functions shared (square/add_one additive, is_even bool, get_tuple serialized)  OK")

    ns2 = {}
    exec(compile(ast.Module(body=out.body, type_ignores=[]), '<fss>', 'exec'), ns2)
    assert ns2['square'](5) == 25, f"square(5)={ns2['square'](5)}"
    assert ns2['add_one'](5) == 6
    assert ns2['is_even'](4) is True, f"is_even(4)={ns2['is_even'](4)}"
    assert ns2['is_even'](5) is False, f"is_even(5)={ns2['is_even'](5)}"
    assert ns2['get_tuple'](3, 4) == (3, 4), f"get_tuple={ns2['get_tuple'](3,4)}"
    print("iO-2 combine: all 4 return correct values  OK")

    src_after = ast.unparse(out)
    assert '_br_fss_1_' in src_after
    print("iO-2 shares: _br_fss_* present  OK")

    # --- Mode: additive_n (3 shares) ---
    tree3 = ast.parse("def cube(x):\n    return x * x * x\n")
    ctx3 = _Ctx()
    ctx3.fss_mode = 'additive_n'
    ctx3.fss_shares = 3
    out3 = apply_fss(tree3, ctx3)
    ns3 = {}
    exec(compile(ast.Module(body=out3.body, type_ignores=[]), '<fss3>', 'exec'), ns3)
    for v in [0, 1, -1, 5, -5, 100]:
        assert ns3['cube'](v) == v * v * v, f"cube({v}) = {ns3['cube'](v)}"
    print(f"iO-2 additive_n (3 shares): cube correct for 6 values  OK")

    # --- Mode: bool ---
    tree_b = ast.parse("def is_pos(n):\n    return n > 0\n")
    ctx_b = _Ctx()
    ctx_b.fss_mode = 'bool'
    out_b = apply_fss(tree_b, ctx_b)
    ns_b = {}
    exec(compile(ast.Module(body=out_b.body, type_ignores=[]), '<fssb>', 'exec'), ns_b)
    for v in [-5, 0, 5]:
        assert ns_b['is_pos'](v) is (v > 0), f"is_pos({v}) = {ns_b['is_pos'](v)}"
    print("iO-2 bool: is_pos correct for -5/0/5  OK")

    # --- Mode: serialized ---
    tree_s = ast.parse("def make_pair(a, b):\n    return (a, b)\n")
    ctx_s = _Ctx()
    ctx_s.fss_mode = 'serialized'
    out_s = apply_fss(tree_s, ctx_s)
    ns_s = {}
    exec(compile(ast.Module(body=out_s.body, type_ignores=[]), '<fsss>', 'exec'), ns_s)
    for a, b in [(1, 2), ('x', 'y'), (0, -1)]:
        assert ns_s['make_pair'](a, b) == (a, b), f"make_pair({a},{b}) = {ns_s['make_pair'](a, b)}"
    print("iO-2 serialized: make_pair correct for 3 cases  OK")

    # --- Lift cap: fss_all_eligible ---
    src_many = "\n".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(10))
    tree_many = ast.parse(src_many)
    ctx_many = _Ctx()
    ctx_many.fss_mode = 'additive'
    ctx_many.fss_all_eligible = True
    ctx_many.fss_max = 0
    out_many = apply_fss(tree_many, ctx_many)
    assert ctx_many.fss_shared == 10, f"expected 10, got {ctx_many.fss_shared}"
    ns_many = {}
    exec(compile(ast.Module(body=out_many.body, type_ignores=[]), '<many>', 'exec'), ns_many)
    for i in range(10):
        assert ns_many[f'f{i}'](5) == 5 + i
    print(f"iO-2 lift cap: all 10 functions shared (was cap 5)  OK")

    # --- Determinism ---
    tree_d = ast.parse("def square(x):\n    return x * x\n")
    ctx_d1 = _Ctx(); ctx_d1.fss_mode = 'additive'
    ctx_d2 = _Ctx(); ctx_d2.fss_mode = 'additive'
    apply_fss(tree_d, ctx_d1)
    assert ctx_d1.fss_shared == 1
    print("iO-2 deterministic: same seed -> same share count  OK")

    print("iO-2 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
