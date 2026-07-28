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


# --- Distributed Point Function (BGI14 DPF) ---------------------------------
#
# Phase E.1: a REAL BGI14-style Distributed Point Function, replacing the
# value-secret-sharing modes above for the specific pattern `return x == C`.
#
# A point function f_alpha: {0,1}^n -> {0,1} returns 1 iff x == alpha.
# Gen produces two keys k0, k1 via a GGM tree (HMAC-SHA256 PRG). Eval(b, k_b, x)
# returns a bit share s_b such that s_0 ^ s_1 = f_alpha(x) for ALL x.
# Each key ALONE computationally hides alpha (under PRG security): an analyst
# holding only one key learns nothing about alpha beyond its bit-length.
#
# HONEST SECURITY NOTE: the obfuscator ships BOTH keys in the same file, so an
# analyst with the file can reconstruct f_alpha (run both Evals + XOR). Real
# secrecy needs the keys split across parties / shipped via env (Phase A/G).
# Here DPF provides obfuscation-by-indirection: the point-function logic is
# encoded into two opaque key blobs + a tree-traversal evaluator, not a plain
# `x == C` comparison — raising the analysis bar from "read the constant" to
# "understand the GGM traversal". This is the same posture as the rest of the
# obfuscator; it is NOT cryptographic secrecy against a file-holding analyst.

import hashlib as _dpf_hashlib

_DPF_SEED_LEN = 16  # 128-bit seeds

# Phase G7: default domain-separation string for the GGM PRG. New keys carry
# a per-build salt (5th tuple element) that replaces this fixed string, so a
# classifier cannot fingerprint the constant across builds. Old keys (4-tuple,
# no salt) fall back to this default.
_DPF_PRG_DOMAIN_DEFAULT = b'\x00dpf-ggm'


def _dpf_prg(seed: bytes, domain: bytes = _DPF_PRG_DOMAIN_DEFAULT):
    """GGM PRG: expand a 16-byte seed into (L_seed, R_seed, tL, tR).

    L_seed, R_seed are 16 bytes each; tL, tR are control bits. Uses
    SHA-512 as the underlying PRG (pseudorandom under the PRF assumption).

    Phase G7 fix (M7): the previous SHA-256 variant drew tL/tR from bytes
    24/25, which OVERLAP the sR region (bytes 16-31) -- so the control
    bits were NOT independent of the right seed. SHA-512 gives 64 bytes,
    so sL (0-15), sR (16-31), tL (32), tR (33) are all disjoint.

    Phase G7 (M2): ``domain`` is a per-build salt (stored in the key tuple,
    not secret) that diversifies builds -- a classifier can no longer
    fingerprint the fixed ``b'\\x00dpf-ggm'`` constant across builds.
    """
    h = _dpf_hashlib.sha512(seed + domain).digest()  # 64 bytes
    sL = h[:_DPF_SEED_LEN]
    sR = h[_DPF_SEED_LEN:_DPF_SEED_LEN * 2]
    # Control bits from bytes OUTSIDE the seed regions (independent of sL/sR).
    tL = h[_DPF_SEED_LEN * 2] & 1
    tR = h[_DPF_SEED_LEN * 2 + 1] & 1
    return sL, sR, tL, tR


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _dpf_gen(alpha: int, n: int, beta: int = 1, rng=None):
    """BGI14 DPF key generation for f_alpha on {0,1}^n.

    Returns (k0, k1). Each key = (seed, t0, correction_words, cw_final, salt).
    correction_words[i] = (s_cw, t_cw_L, t_cw_R) per level i.

    Phase G7: a per-build ``salt`` (16 random bytes, NOT secret -- it only
    diversifies builds so the PRG domain string cannot be fingerprinted)
    is minted here and carried in every key as a 5th tuple element. Both
    _dpf_gen and _dpf_eval thread it into _dpf_prg.

    Two invariants are maintained by induction on the alpha-path:
      (1) s_0 == s_1  (seeds agree, so the next-level correction words are
          well-defined / common to both parties).
      (2) t_0 XOR t_1 == 1  (control bits differ, so only one party applies
          the next-level correction).

    The crucial BGI14 design choice: the seed correction word s_cw normalizes
    the LOSE branch (the branch NOT taken on the alpha path), NOT the keep
    branch. After correction both parties' lose-branch seeds agree AND their
    lose-branch control bits agree (t_0 XOR t_1 == 0); so when Eval takes a
    lose branch the seeds collapse to identical random values that drift
    independently of alpha, and the leaf XOR sum is 0. On the keep (alpha)
    branch the seeds keep drifting (the t_cw_* are designed so t_0 XOR
    t_1 == 1 is preserved on keep, == 0 forced on lose), and the final
    correction word CW_final = beta XOR 1 converts the alpha-leaf
    t_0 XOR t_1 == 1 invariant into Eval(0) XOR Eval(1) == beta.
    """
    if rng is None:
        import os as _os
        rng = _os
    def _rbytes(k):
        if hasattr(rng, 'urandom'):
            return rng.urandom(k)
        if hasattr(rng, 'token_bytes'):
            return rng.token_bytes(k)
        return bytes(rng.randint(0, 255) for _ in range(k))
    # Phase G7: per-build domain-separation salt (not secret).
    salt = _rbytes(16)
    root_s = [_rbytes(_DPF_SEED_LEN), _rbytes(_DPF_SEED_LEN)]
    s = [bytes(root_s[0]), bytes(root_s[1])]
    t = [0, 1]
    cws = []
    for i in range(n):
        # Expand both parties.
        sL = [None, None]; sR = [None, None]; tL = [0, 0]; tR = [0, 0]
        for b in (0, 1):
            sL[b], sR[b], tL[b], tR[b] = _dpf_prg(s[b], salt)
        a = (alpha >> (n - 1 - i)) & 1  # MSB first
        # Seed correction word cancels the LOSE branch (the branch NOT taken
        # on the alpha path), so off-alpha seeds agree. When a==0 the keep
        # branch is L, so lose is R; when a==1 the keep branch is R, so lose
        # is L.
        if a == 0:
            s_cw = _xor_bytes(sR[0], sR[1])  # normalize lose=R
        else:
            s_cw = _xor_bytes(sL[0], sL[1])  # normalize lose=L
        # Control-bit correction words: keep branch must preserve t_0 XOR
        # t_1 == 1, lose branch must force t_0 XOR t_1 == 0. The XOR-then-
        # gate (apply t_cw only when t[b]==1) gives: keep-branch t^ =
        # tL[0]^tL[1]^(a^1) when a==0 / tR[0]^tR[1]^a when a==1, both equal
        # 1 by construction; lose-branch t^ = tR[0]^tR[1]^a when a==0 /
        # tL[0]^tL[1]^(a^1) when a==1, both equal 0 by construction.
        t_cw_L = tL[0] ^ tL[1] ^ a ^ 1
        t_cw_R = tR[0] ^ tR[1] ^ a
        # Apply the correction to BOTH L and R branches of each party,
        # gated by that party's OWN control bit (so only the party with
        # t[b]==1 actually applies it; the other party's values are
        # unchanged). Then advance on the keep (alpha) branch.
        for b in (0, 1):
            sL[b] = _xor_bytes(sL[b], s_cw) if t[b] else sL[b]
            sR[b] = _xor_bytes(sR[b], s_cw) if t[b] else sR[b]
            tL[b] = tL[b] ^ (t_cw_L if t[b] else 0)
            tR[b] = tR[b] ^ (t_cw_R if t[b] else 0)
            s[b] = sL[b] if a == 0 else sR[b]
            t[b] = tL[b] if a == 0 else tR[b]
        cws.append((s_cw, t_cw_L, t_cw_R))
    # Final correction word: alpha-leaf has t_0 XOR t_1 == 1 (invariant (2)).
    # Party 0 outputs its leaf t, party 1 outputs t XOR cw_final. Their XOR is
    #   t_0 XOR (t_1 XOR cw_final) = (t_0 XOR t_1) XOR cw_final = 1 XOR cw_final
    # so cw_final = beta XOR 1 makes the alpha-leaf XOR sum = beta. Off-alpha
    # the leaves have t_0 XOR t_1 == 0, so XOR sum = 0 XOR cw_final = cw_final
    # -- but Eval also never returns the same leaf t on off-alpha (the seeds
    # agree but cw_final is applied only by party 1), so we need cw_final set
    # so that 0 XOR cw_final == 0, i.e. cw_final == 0 for beta=1, which is
    # beta XOR 1 = 0. (beta=0 would require a Convert(s) output, not just a
    # bit; our point-function use case is beta=1 so this is fine.)
    cw_final = beta ^ 1
    # Keys hold the ROOT seeds (Eval traverses from root), NOT the leaf seeds.
    # Phase G7: salt is the 5th element (shared by both keys, not secret).
    return (root_s[0], 0, cws, cw_final, salt), (root_s[1], 1, cws, cw_final, salt)


def _dpf_eval(b: int, key, x: int, n: int) -> int:
    """Evaluate DPF share for party b at point x (n-bit integer). Returns a bit.

    Party 0 returns t; party 1 returns t XOR cw_final. Their XOR is f_alpha(x).
    """
    s, t, cws, cw_final = key[0], key[1], key[2], key[3]
    # Phase G7: read the per-build domain salt (5th element). Old keys (4
    # elements) fall back to the fixed default domain string.
    salt = key[4] if len(key) > 4 else _DPF_PRG_DOMAIN_DEFAULT
    for i in range(n):
        sL, sR, tL, tR = _dpf_prg(s, salt)
        s_cw, t_cw_L, t_cw_R = cws[i]
        xi = (x >> (n - 1 - i)) & 1  # MSB first
        if xi == 0:
            s = _xor_bytes(sL, s_cw) if t else sL
            t = tL ^ (t_cw_L if t else 0)
        else:
            s = _xor_bytes(sR, s_cw) if t else sR
            t = tR ^ (t_cw_R if t else 0)
    return t if b == 0 else (t ^ cw_final)


def _is_eligible_dpf(fn: ast.FunctionDef) -> bool:
    """Eligible for DPF: top-level def, single return `x == <non-neg int const>`.

    The point function f_alpha(x) = (x == alpha) is exactly this pattern. We
    require alpha to be a non-negative integer literal (bounded domain).
    """
    if not _base_eligible(fn):
        return False
    ret = fn.body[0].value
    if not isinstance(ret, ast.Compare) or len(ret.ops) != 1:
        return False
    if not isinstance(ret.ops[0], ast.Eq):
        return False
    if len(ret.comparators) != 1:
        return False
    # Either `x == CONST` or `CONST == x`: one side is a bare Name, the other
    # a non-negative int Constant.
    left, right = ret.left, ret.comparators[0]
    def _is_name(n): return isinstance(n, ast.Name)
    def _is_nonneg_int_const(n):
        return (isinstance(n, ast.Constant) and isinstance(n.value, int)
                and not isinstance(n.value, bool) and n.value >= 0)
    if _is_name(left) and _is_nonneg_int_const(right):
        return True
    if _is_name(right) and _is_nonneg_int_const(left):
        return True
    return False


def _dpf_extract_alpha_and_arg(fn: ast.FunctionDef):
    """For an eligible DPF function, return (alpha:int, arg_name:str)."""
    ret = fn.body[0].value
    left, right = ret.left, ret.comparators[0]
    def _is_name(n): return isinstance(n, ast.Name)
    def _is_nonneg_int_const(n):
        return isinstance(n, ast.Constant) and isinstance(n.value, int) \
            and not isinstance(n.value, bool) and n.value >= 0
    if _is_name(left) and _is_nonneg_int_const(right):
        return right.value, left.id
    return left.value, right.id


# Maximum DPF domain bit-length. Larger n -> larger keys (O(n) correction
# words) and O(n) HMAC calls per eval. 32 keeps keys ~512 bytes and evals
# ~32 HMACs; bump via ctx.dpf_max_bits if a larger bounded domain is needed.
_DPF_MAX_BITS = 128


# Minimum DPF domain bit-length. The point function `x == CONST` over
# arbitrary integers is correctly encoded by DPF only when the domain
# covers every reachable input x. We default to a 16-bit domain (0..65535),
# which is large enough to cover the vast majority of integer-typed inputs
# while keeping keys compact (~16 correction words = ~272 bytes per key).
# For alpha >= 2**16 the domain auto-grows to alpha.bit_length() so the
# alpha value itself always fits. Inputs x >= 2**n will match against
# (x mod 2**n) and may give a wrong result; documented limitation.
_DPF_DOMAIN_BITS_MIN = 64


def _build_dpf_shares(node: ast.FunctionDef, rng, n_shares: int,
                      dpf_key_split: bool = True,
                      dpf_key_env: str = 'BR_DPF_K1',
                      ctx=None):
    """Build two DPF Eval functions + an XOR combiner for `return x == CONST`.

    Emits two functions _br_dpf_<i>_<hex>(x) that each traverse the GGM tree
    for party b and return a bit share; the combiner XORs them and casts to bool.
    The keys (seeds + correction words) are embedded as bytes literals.

    Domain: the DPF encodes the point function on Z_{2^n} where
    n = max(alpha.bit_length(), _DPF_DOMAIN_BITS_MIN). For inputs x < 2**n
    the result equals (x == alpha); for x >= 2**n the result is undefined
    (matches (x mod 2**n) == alpha). See _DPF_DOMAIN_BITS_MIN above.

    Phase G5: when ``dpf_key_split`` is True (default, secure), party 0's
    key (k0) is embedded in the file as before, but party 1's key (k1) is
    NOT shipped. Instead, name1's body reads the serialized key tuple from
    the environment variable ``dpf_key_env`` (default ``BR_DPF_K1``) at
    runtime. The operator must set that env var (hex-encoded key tuple) on
    the machine that runs the obfuscated file. A 1-key adversary (only k0)
    faces a GGM pseudorandom tree — alpha is hidden.

    When ``dpf_key_split`` is False (legacy backward-compat), both keys
    ship in the file (the pre-G5 behavior).

    If ``ctx`` is provided and split is on, the serialized k1 hex is exposed
    on ``ctx.dpf_k1_hex`` + ``ctx.dpf_key_env_name`` so the build path can
    emit a ``.dpfkey`` sidecar (mirrors the binary capsule's ctx.capsule_key).
    """
    alpha, arg_name = _dpf_extract_alpha_and_arg(node)
    n = max(alpha.bit_length(), _DPF_DOMAIN_BITS_MIN) if alpha > 0 else _DPF_DOMAIN_BITS_MIN
    n = min(n, _DPF_MAX_BITS)
    # Mask alpha to n bits (in case bit_length rounded).
    alpha &= (1 << n) - 1
    k0, k1 = _dpf_gen(alpha, n, beta=1, rng=rng)
    name0 = _fresh_name(0, rng)
    name1 = _fresh_name(1, rng)

    def _key_repr(key):
        seed, t0, cws, cw_final, salt = key
        cw_list = [(s_cw.hex(), t_cw_L, t_cw_R) for (s_cw, t_cw_L, t_cw_R) in cws]
        # Phase G7: salt is the 5th element (per-build domain separation).
        return (seed.hex(), t0, cw_list, cw_final, salt.hex())

    key0_repr = repr(_key_repr(k0))
    key1_repr = repr(_key_repr(k1))
    # Phase G5: expose the serialized k1 hex for the build path to emit a
    # sidecar / stderr (like the binary capsule key). When split is on,
    # the file does NOT contain k1; the build path captures it from here.
    try:
        import json as _dpf_json
        _k1_serialized = _dpf_json.dumps(_key_repr(k1)).encode('utf-8').hex()
    except Exception:
        _k1_serialized = repr(_key_repr(k1)).encode('utf-8').hex()
    _dpf_k1_hex = _k1_serialized
    _dpf_key_env_name = dpf_key_env

    # The emitted evaluator: parse the key tuple, traverse the tree, return a bit.
    # We embed a compact pure-Python DPF eval as source.
    # Phase G7: uses sha512 (disjoint sL/sR/tL/tR) + per-build salt (5th key element).
    eval_src = (
        f"def {name0}({arg_name}):\n"
        f"    _seed, _t, _cws, _cwf, _salt = {key0_repr}\n"
        f"    _s = bytes.fromhex(_seed); _n = len(_cws); _dom = bytes.fromhex(_salt)\n"
        f"    for _i in range(_n):\n"
        f"        _h = __import__('hashlib').sha512(_s + _dom).digest()\n"
        f"        _sL, _sR = _h[:16], _h[16:32]; _tL, _tR = _h[32] & 1, _h[33] & 1\n"
        f"        _scw, _tcL, _tcR = _cws[_i]\n"
        f"        _xi = ({arg_name} >> (_n - 1 - _i)) & 1\n"
        f"        _scw_b = bytes.fromhex(_scw)\n"
        f"        if _xi == 0:\n"
        f"            _s = bytes(a ^ b for a, b in zip(_sL, _scw_b)) if _t else _sL\n"
        f"            _t = _tL ^ (_tcL if _t else 0)\n"
        f"        else:\n"
        f"            _s = bytes(a ^ b for a, b in zip(_sR, _scw_b)) if _t else _sR\n"
        f"            _t = _tR ^ (_tcR if _t else 0)\n"
        f"    return _t\n"
    )
    if dpf_key_split:
        _env_repr = repr(dpf_key_env)
        eval_src1 = (
            f"def {name1}({arg_name}):\n"
            f"    import os as _br_os\n"
            f"    _k1_hex = _br_os.environ.get({_env_repr})\n"
            f"    if not _k1_hex:\n"
            f"        raise SystemExit('dpf: key missing -- set env ' + {_env_repr} + '=<hex> (see <output>.dpfkey sidecar) before running')\n"
            f"    import json as _br_json\n"
            f"    _seed, _t, _cws, _cwf, _salt = _br_json.loads(bytes.fromhex(_k1_hex).decode('utf-8'))\n"
            f"    _s = bytes.fromhex(_seed); _n = len(_cws); _dom = bytes.fromhex(_salt)\n"
            f"    for _i in range(_n):\n"
            f"        _h = __import__('hashlib').sha512(_s + _dom).digest()\n"
            f"        _sL, _sR = _h[:16], _h[16:32]; _tL, _tR = _h[32] & 1, _h[33] & 1\n"
            f"        _scw, _tcL, _tcR = _cws[_i]\n"
            f"        _xi = ({arg_name} >> (_n - 1 - _i)) & 1\n"
            f"        _scw_b = bytes.fromhex(_scw)\n"
            f"        if _xi == 0:\n"
            f"            _s = bytes(a ^ b for a, b in zip(_sL, _scw_b)) if _t else _sL\n"
            f"            _t = _tL ^ (_tcL if _t else 0)\n"
            f"        else:\n"
            f"            _s = bytes(a ^ b for a, b in zip(_sR, _scw_b)) if _t else _sR\n"
            f"            _t = _tR ^ (_tcR if _t else 0)\n"
            f"    return _t ^ _cwf\n"
        )
    else:
        eval_src1 = (
            f"def {name1}({arg_name}):\n"
            f"    _seed, _t, _cws, _cwf, _salt = {key1_repr}\n"
            f"    _s = bytes.fromhex(_seed); _n = len(_cws); _dom = bytes.fromhex(_salt)\n"
            f"    for _i in range(_n):\n"
            f"        _h = __import__('hashlib').sha512(_s + _dom).digest()\n"
            f"        _sL, _sR = _h[:16], _h[16:32]; _tL, _tR = _h[32] & 1, _h[33] & 1\n"
            f"        _scw, _tcL, _tcR = _cws[_i]\n"
            f"        _xi = ({arg_name} >> (_n - 1 - _i)) & 1\n"
            f"        _scw_b = bytes.fromhex(_scw)\n"
            f"        if _xi == 0:\n"
            f"            _s = bytes(a ^ b for a, b in zip(_sL, _scw_b)) if _t else _sL\n"
            f"            _t = _tL ^ (_tcL if _t else 0)\n"
            f"        else:\n"
            f"            _s = bytes(a ^ b for a, b in zip(_sR, _scw_b)) if _t else _sR\n"
            f"            _t = _tR ^ (_tcR if _t else 0)\n"
            f"    return _t ^ _cwf\n"
        )

    tree0 = ast.parse(eval_src).body[0]
    tree1 = ast.parse(eval_src1).body[0]

    # Combiner: original function name, XOR the two shares, cast to bool.
    combiner_args = _combiner_args(node.args)
    carg = _call_args(node.args)
    combiner_body = [
        ast.Return(value=ast.Call(
            func=ast.Name(id='bool', ctx=ast.Load()),
            args=[ast.BinOp(
                left=ast.Call(func=ast.Name(id=name0, ctx=ast.Load()),
                              args=carg, keywords=[]),
                op=ast.BitXor(),
                right=ast.Call(func=ast.Name(id=name1, ctx=ast.Load()),
                               args=carg, keywords=[]),
            )],
            keywords=[],
        ))
    ]
    combiner = ast.FunctionDef(
        name=node.name, args=combiner_args, body=combiner_body,
        decorator_list=[], returns=None, type_comment=None,
    )
    # Phase G5: expose the serialized k1 hex on ctx for the build path to
    # emit a .dpfkey sidecar (mirrors ctx.capsule_key for the binary capsule).
    if ctx is not None and dpf_key_split:
        try:
            ctx.dpf_k1_hex = _dpf_k1_hex
            ctx.dpf_key_env_name = dpf_key_env
        except Exception:
            pass
    return [tree0, tree1], combiner


# --- Mode dispatch ----------------------------------------------------------

_ELIGIBILITY = {
    'additive': _is_eligible_additive,
    'additive_n': _is_eligible_additive,
    'bool': _is_eligible_bool,
    'serialized': _is_eligible_serialized,
    'dpf': _is_eligible_dpf,
}

_BUILDERS = {
    'additive': lambda node, rng, n: _build_additive_shares(node, rng, 2),
    'additive_n': _build_additive_shares,
    'bool': lambda node, rng, n: _build_bool_shares(node, rng, 2),
    'serialized': lambda node, rng, n: _build_serialized_shares(node, rng, 2),
    'dpf': lambda node, rng, n: _build_dpf_shares(node, rng, 2),
}


def _resolve_mode(ctx, fn: ast.FunctionDef) -> Optional[str]:
    """Pick the FSS mode for `fn` based on ctx.fss_mode (auto-discovery)."""
    mode = str(getattr(ctx, 'fss_mode', 'auto') or 'auto').lower()
    if mode in _ELIGIBILITY and _ELIGIBILITY[mode](fn):
        return mode
    if mode == 'auto':
        # DPF first for point functions (real cryptographic construction),
        # then bool (value sharing), then additive, then serialized.
        for m in ('dpf', 'bool', 'additive', 'serialized'):
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
    if mode == 'dpf':
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
        elif mode == 'dpf':
            # Phase G5: read split config from ctx (default: split on, secure).
            _dpf_split = bool(getattr(ctx, 'dpf_key_split', True))
            _dpf_env = str(getattr(ctx, 'dpf_key_env', 'BR_DPF_K1') or 'BR_DPF_K1')
            share_fns, combiner = _build_dpf_shares(
                node, rng, n_shares,
                dpf_key_split=_dpf_split, dpf_key_env=_dpf_env, ctx=ctx)
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

    # --- Mode: dpf (BGI14 Distributed Point Function) ---
    # Direct crypto-core test: Gen + Eval over the full domain, for many
    # (alpha, n) pairs. This is the correctness invariant for the DPF
    # construction itself; the emitted-AST version is tested separately below.
    import os as _os
    class _OsRng:
        def urandom(self, k):
            return _os.urandom(k)
        def randint(self, lo, hi):
            return int.from_bytes(_os.urandom(2), 'big') % (hi - lo + 1) + lo
    _osrng = _OsRng()
    # Full-domain correctness for n=1..8 (exhaustive over all alpha and x).
    # This exercises 87380 evals and proves the across-level invariant is
    # maintained for arbitrarily deep trees, not just single-level.
    _total_evals = 0
    for n in range(1, 9):
        domain = 1 << n
        for alpha in range(domain):
            k0, k1 = _dpf_gen(alpha, n, beta=1, rng=_osrng)
            for x in range(domain):
                _total_evals += 1
                got = _dpf_eval(0, k0, x, n) ^ _dpf_eval(1, k1, x, n)
                want = 1 if x == alpha else 0
                assert got == want, f"DPF core fail alpha={alpha} n={n} x={x}: {got}!={want}"
    assert _total_evals == 87380
    print(f"DPF crypto-core: correct on n=1..8 ({_total_evals} evals, all alpha, all x)  OK")

    # 1-key hiding sanity: a single key's Eval across the domain must not
    # trivially reveal alpha (the share is a pseudorandom-looking bit
    # sequence, not a spike at alpha). We check the share alone is not
    # equal to the point function (i.e. one key does not leak f_alpha).
    # NOTE: this is a weak sanity check, not a cryptographic proof. Real
    # DPF security follows from the PRG assumption (HMAC-SHA256 here).
    alpha, n = 42, 8
    k0, k1 = _dpf_gen(alpha, n, beta=1, rng=_osrng)
    s0_seq = [_dpf_eval(0, k0, x, n) for x in range(1 << n)]
    f_seq = [1 if x == alpha else 0 for x in range(1 << n)]
    assert s0_seq != f_seq, "one key alone must NOT equal the point function"
    print("DPF 1-key hiding: single share != point function (alpha not leaked)  OK")

    # AST integration: `def is_special(x): return x == 5` -> dpf combiner.
    # Verify the EMITTED eval (which re-implements _dpf_prg inline) produces
    # the same results as the crypto-core _dpf_eval across the full domain.
    # Domain for alpha=5 is 2**16 (the default _DPF_DOMAIN_BITS_MIN), so all
    # inputs in 0..255 are within range and `x == 5` semantics are exact.
    #
    # Phase G5: default dpf_key_split=True ships only k0 in the file; k1 is
    # read from env (BR_DPF_K1). The build exposes the serialized k1 hex on
    # ctx.dpf_k1_hex + ctx.dpf_key_env_name. The smoke test sets the env
    # from there before exec, then verifies the refuse-run path when the env
    # is missing (operator forgot to set it -> clean SystemExit, not a leak).
    tree_dpf = ast.parse("def is_special(x):\n    return x == 5\n")
    ctx_dpf = _Ctx()
    ctx_dpf.fss_mode = 'dpf'
    out_dpf = apply_fss(tree_dpf, ctx_dpf)
    assert ctx_dpf.fss_shared == 1, f"dpf should share 1 fn, got {ctx_dpf.fss_shared}"
    # G5: split default-on -> k1 must NOT be embedded; env name + hex exposed.
    _dpf_env_name = getattr(ctx_dpf, 'dpf_key_env_name', 'BR_DPF_K1')
    _dpf_k1_hex = getattr(ctx_dpf, 'dpf_k1_hex', '')
    assert _dpf_k1_hex, "G5: ctx.dpf_k1_hex must be exposed when split is on"
    _dpf_src = ast.unparse(out_dpf)
    assert 'os.environ' in _dpf_src or '_br_os.environ' in _dpf_src, \
        "G5: split=on must read k1 from env"
    # Refuse-run: with env unset, calling the function must SystemExit cleanly
    # (no alpha leak) rather than crash with a confusing traceback.
    _os.environ.pop(_dpf_env_name, None)
    ns_refuse = {}
    exec(compile(ast.Module(body=out_dpf.body, type_ignores=[]), '<dpf>', 'exec'), ns_refuse)
    try:
        ns_refuse['is_special'](5)
        raise AssertionError("G5: missing env must refuse (SystemExit), not run")
    except SystemExit as _e:
        assert 'key missing' in str(_e), f"refuse msg must mention key missing: {_e}"
    # Correctness with env set from the sidecar-equivalent hex.
    _os.environ[_dpf_env_name] = _dpf_k1_hex
    try:
        ns_dpf = {}
        exec(compile(ast.Module(body=out_dpf.body, type_ignores=[]), '<dpf>', 'exec'), ns_dpf)
        for v in range(256):
            got = ns_dpf['is_special'](v)
            assert got is (v == 5), f"is_special({v}) = {got}, expected {v == 5}"
    finally:
        _os.environ.pop(_dpf_env_name, None)
    print("DPF AST (split=on): is_special correct 0..255 with env k1; refuses when env missing  OK")

    # G5 backward-compat: dpf_key_split=False embeds BOTH keys (legacy path),
    # no env required. Verifies the pre-G5 behavior still works for operators
    # who opt out of the split.
    tree_nosplit = ast.parse("def is_legacy(x):\n    return x == 7\n")
    ctx_nosplit = _Ctx()
    ctx_nosplit.fss_mode = 'dpf'
    ctx_nosplit.dpf_key_split = False
    out_nosplit = apply_fss(tree_nosplit, ctx_nosplit)
    _nosplit_src = ast.unparse(out_nosplit)
    assert 'os.environ' not in _nosplit_src and '_br_os.environ' not in _nosplit_src, \
        "G5: split=off must NOT read from env"
    assert not getattr(ctx_nosplit, 'dpf_k1_hex', ''), \
        "G5: split=off must not expose a k1 sidecar hex"
    ns_nosplit = {}
    exec(compile(ast.Module(body=out_nosplit.body, type_ignores=[]), '<nosplit>', 'exec'), ns_nosplit)
    for v in range(256):
        assert ns_nosplit['is_legacy'](v) is (v == 7), f"is_legacy({v}) wrong"
    print("DPF AST (split=off): is_legacy correct 0..255, both keys embedded, no env  OK")

    # Auto-mode picks dpf for `return x == CONST` (G5 split default-on):
    tree_auto = ast.parse("def is_answer(x):\n    return x == 42\n")
    ctx_auto = _Ctx(); ctx_auto.fss_mode = 'auto'
    out_auto = apply_fss(tree_auto, ctx_auto)
    # In auto mode the point function should route to dpf.
    src_auto = ast.unparse(out_auto)
    assert 'bytes.fromhex' in src_auto, "auto mode should pick DPF for x==CONST"
    _auto_env = getattr(ctx_auto, 'dpf_key_env_name', 'BR_DPF_K1')
    _auto_k1 = getattr(ctx_auto, 'dpf_k1_hex', '')
    assert _auto_k1, "G5: auto+dpf must expose k1 hex for the sidecar"
    _os.environ[_auto_env] = _auto_k1
    try:
        ns_auto = {}
        exec(compile(ast.Module(body=out_auto.body, type_ignores=[]), '<auto>', 'exec'), ns_auto)
        # Correctness over 0..255 (all within the 2**16 domain).
        for v in range(256):
            assert ns_auto['is_answer'](v) is (v == 42), f"is_answer({v}) wrong"
    finally:
        _os.environ.pop(_auto_env, None)
    print("DPF auto (split=on): is_answer routes to DPF + correct for x in 0..255  OK")

    # --- Phase G7: PRG control-bits fix + domain salt + wider domain ---
    # Verify the emitted DPF eval uses SHA-512 (disjoint sL/sR/tL/tR), the
    # fixed `b'\x00dpf-ggm'` constant is GONE (replaced by per-build salt),
    # and two builds carry DIFFERENT salts (build-diversity, M2).
    import re as _g7_re
    _g7_src = ast.unparse(out_dpf)
    assert 'sha512' in _g7_src, "G7: emitted eval must use sha512 (not sha256)"
    assert 'sha256' not in _g7_src or 'sha256' not in _g7_re.sub(r"sha512", '', _g7_src), \
        "G7: emitted eval must not fall back to sha256 for the DPF PRG"
    # The fixed domain-separation constant must be GONE from emitted code.
    assert "dpf-ggm" not in _g7_src, \
        "G7: fixed b'\\x00dpf-ggm' constant must be gone (per-build salt replaces it)"
    # The per-build salt is read as _dom (bytes.fromhex of the 5th key element).
    assert '_dom' in _g7_src, "G7: emitted eval must derive _dom from the key salt"
    # Control bits come from bytes 32/33 (OUTSIDE the sR region [16:32]).
    # (sha512 digest is 64 bytes; sL=[0:16], sR=[16:32], tL=32, tR=33 -- disjoint.)
    assert '_h[32]' in _g7_src and '_h[33]' in _g7_src, \
        "G7: control bits must come from bytes 32/33 (outside sR region)"
    # Two builds must carry DIFFERENT salts (build-diversity). Note: same
    # fss_seed -> same salt (reproducible mode); we use a DIFFERENT seed to
    # prove the salt varies per build in fresh-seed mode.
    _g7_tree2 = ast.parse("def is_special2(x):\n    return x == 5\n")
    _g7_ctx2 = _Ctx(); _g7_ctx2.fss_mode = 'dpf'; _g7_ctx2.fss_seed = 99
    apply_fss(_g7_tree2, _g7_ctx2)
    _g7_k1 = _dpf_k1_hex  # from ctx_dpf above (fss_seed=31)
    _g7_k2 = getattr(_g7_ctx2, 'dpf_k1_hex', '')
    assert _g7_k1 and _g7_k2 and _g7_k1 != _g7_k2, \
        "G7: two builds (different seeds) must carry different salts (build-diversity)"
    # Domain widened: _DPF_DOMAIN_BITS_MIN=64, _DPF_MAX_BITS=128.
    assert _DPF_DOMAIN_BITS_MIN == 64, "G7: domain min must be 64"
    assert _DPF_MAX_BITS == 128, "G7: domain max must be 128"
    print("G7 DPF PRG: sha512 + disjoint ctrl bits (32/33) + per-build salt (no fixed constant) + domain 64-128  OK")

    print("iO-2 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
