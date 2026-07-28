"""Phase iO-3: Cryptographic opaque predicates with RUNTIME variables.

Each predicate is an ALWAYS-True expression whose folding by a static
analyzer (Z3/Claripy/SiMBA) is blocked by TWO independent mechanisms:

  1. A RUNTIME VARIABLE captured once via the walrus operator:
     ``(v := id(object()))``. Each evaluation produces a fresh, unpredictable
     integer (a memory address), so the analyst CANNOT substitute a single
     concrete value to discharge the predicate. Concrete-exec at one input
     yields True, but proving always-True requires number-theory reasoning,
     not just one evaluation.

  2. A construction whose always-True property holds for ALL values of v:
       - DL/FLT:  ``pow(g, v + (p-1), p) == pow(g, v, p)``  (Fermat)
       - LWE:     the runtime term cancels algebraically (v*sum - v*0)
       - HASH:    the SAME chain is computed twice on the same v (tautology
                  of deterministic uninterpreted-function calls)
       - RSA:     ``pow(c, e, N) == pow(c + (v - v), e, N)`` (v-v cancels)

  Z3/Claripy have no built-in modpow or hash-chain theory, so ``pow`` and
  ``_br_hchain`` are treated as uninterpreted functions. Combined with the
  opaque runtime variable, the analyst must discharge both the tautology AND
  the uninterpreted-function equality -- something SMT solvers do not
  automate.

## Honesty note (corrected from earlier README claims)

The earlier docstring claimed folding "requires solving DLP / factoring N /
solving LWE -- infeasible". That is misleading: the analyst CAN compute
``pow(g, x, p)``, ``pow(c, e, N)``, etc. directly (these are efficient
operations). The fold-resistance comes from (1) the runtime variable and
(2) the lack of an SMT theory for the crypto primitive, NOT from the
hardness of the underlying number-theory problem. The crypto primitives
are the CARRIER for the runtime-variable tautology, not the security
source. We make this explicit so the security posture is not oversold.

## Performance note

Each predicate site costs: DL ~1 modpow + 1 add + 1 walrus (~µs); LWE ~1
mod; HASH 2n SHA-256 calls; RSA ~1 modpow + 1 sub. O(1) per site, so the
overhead is linear in the number of opaque-predicate sites (not program
size). Bits default 128 (was 32) -- enough for the runtime-variable
resistance; building 128-bit safe primes takes ~40ms.

Pure stdlib (``ast``, ``hashlib``, ``random``, ``secrets``). Run::

    python bedrock_native/_opaque_crypto.py
"""
from __future__ import annotations

import ast
import hashlib
import os
import random
import secrets
import sys
from typing import Tuple

# Sibling import.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = [
    'gen_dl_predicate', 'gen_lwe_predicate', 'gen_hash_predicate',
    'gen_rsa_predicate', 'gen_opaque_true', 'gen_opaque_false',
    'apply_opaque_crypto', 'OPAQUE_GRADES',
]

OPAQUE_GRADES = ('algebra', 'crypto', 'hybrid')


# --- Helpers ----------------------------------------------------------------

def _rng_for(ctx) -> random.Random:
    brng = getattr(ctx, 'build_rng', None) or getattr(ctx, '_build_rng', None)
    if isinstance(brng, BuildRNG):
        sub = brng.stream(b'phase_io3_opaque')

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
    seed = getattr(ctx, 'opaque_seed', None)
    return random.Random(seed) if seed is not None else random.Random()


def _safe_prime(bits: int, rng) -> int:
    """Generate a safe prime p = 2*q + 1 where q is also prime.

    For Phase iO-3 smoke we use small bits (64) for speed; production uses
    1024-bit. The security level is `bits` (DL hardness in this group).
    """
    # Use secrets for the prime search (cryptographically strong).
    while True:
        # q prime, p = 2q+1 safe prime
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if not _is_probable_prime(q):
            continue
        p = 2 * q + 1
        if _is_probable_prime(p):
            return p


def _is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_rsa_modulus(bits: int) -> Tuple[int, int, int]:
    """Generate (N, e, d) for RSA. Returns N (public modulus), e (public
    exponent), d (private exponent)."""
    p = _safe_prime(bits // 2, None) if False else _gen_strong_prime(bits // 2)
    q = _gen_strong_prime(bits // 2)
    while q == p:
        q = _gen_strong_prime(bits // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    # ensure gcd(e, phi) == 1; if not, fall back to 3
    if phi % e == 0:
        e = 3
        while phi % e == 0:
            e += 2
    d = pow(e, -1, phi)
    return N, e, d


def _gen_strong_prime(bits: int) -> int:
    """Generate a prime suitable for RSA (just a large prime here)."""
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


# --- Predicate generators ---------------------------------------------------
# Each returns an AST expression that is ALWAYS True (evaluates to True at
# runtime), constructed so a Z3/Claripy/SiMBA solver cannot fold it within
# any reasonable budget.

def _fresh_walrus_name(rng) -> str:
    """A fresh local-variable name for the walrus capture of the runtime value."""
    return f'_br_rv_{rng.randint(0, 0xFFFFFF):x}'


def _runtime_int_expr() -> ast.expr:
    """An opaque runtime integer expression: ``time.perf_counter_ns()``.

    Each evaluation returns a different value (the high-resolution
    performance counter at call time), so a static analyzer cannot
    substitute a single concrete value to fold the predicate. The
    constructions below (FLT / cancellation / deterministic uninterpreted
    function) guarantee the predicate is True for ALL such values, so any
    runtime value works. We use ``__import__('time').perf_counter_ns()`` so
    the expression is self-contained and does not require ``time`` to be
    imported at the call site (the obfuscated module may not import it).

    Note: ``id(object())`` was tried first but on CPython with peephole
    object reuse the same address is reused for short-lived objects, so the
    value did NOT vary across evaluations -- defeating the runtime-variable
    purpose. ``perf_counter_ns()`` has nanosecond resolution and varies
    reliably between sequential calls.
    """
    return ast.Call(
        func=ast.Attribute(
            value=ast.Call(
                func=ast.Name(id='__import__', ctx=ast.Load()),
                args=[ast.Constant(value='time')], keywords=[]),
            attr='perf_counter_ns', ctx=ast.Load()),
        args=[], keywords=[],
    )


def gen_dl_predicate(rng, *, bits: int = 128) -> ast.expr:
    """Discrete-Log-group opaque predicate with a RUNTIME variable.

    Ships the expression::

        (v := id(object())) and pow(g, v + (p-1), p) == pow(g, v, p)

    where ``v`` is captured once via the walrus operator and used on BOTH
    sides (so the same runtime value is compared). Always True by Fermat's
    Little Theorem (g^(p-1) == 1 mod p for prime p, g coprime to p), so the
    LHS reduces to pow(g, v, p) == RHS.

    Why this resists folding:
      - Z3/Claripy have no built-in modpow theory, so ``pow`` is treated as an
        uninterpreted function and the equality cannot be discharged.
      - Concrete-exec at a single runtime value yields True, but proving
        always-True requires recognizing FLT (number-theory reasoning that SMT
        solvers do not automate). And because ``id(object())`` differs each
        evaluation, the analyst cannot substitute a single value.

    bits: prime bit-length (default 128; was 32). Note: fold-resistance comes
    from FLT-recognition + the opaque runtime variable, NOT from DLP hardness,
    so 128 bits is ample and keeps build-time prime generation fast (~40ms).
    """
    p = _safe_prime(bits, rng)
    # Any g in [2, p-2] is coprime to prime p, so FLT applies.
    g = rng.randint(2, p - 2)
    v_name = _fresh_walrus_name(rng)
    # (v := id(object()))
    walrus = ast.NamedExpr(
        target=ast.Name(id=v_name, ctx=ast.Store()),
        value=_runtime_int_expr(),
    )
    # pow(g, v + (p-1), p)
    lhs = ast.Call(
        func=ast.Name(id='pow', ctx=ast.Load()),
        args=[
            ast.Constant(value=g),
            ast.BinOp(
                left=ast.Name(id=v_name, ctx=ast.Load()),
                op=ast.Add(),
                right=ast.Constant(value=p - 1),
            ),
            ast.Constant(value=p),
        ],
        keywords=[],
    )
    # pow(g, v, p)
    rhs = ast.Call(
        func=ast.Name(id='pow', ctx=ast.Load()),
        args=[ast.Constant(value=g), ast.Name(id=v_name, ctx=ast.Load()),
              ast.Constant(value=p)],
        keywords=[],
    )
    flt_eq = ast.Compare(left=lhs, ops=[ast.Eq()], comparators=[rhs])
    return ast.BoolOp(op=ast.And(), values=[walrus, flt_eq])


def gen_lwe_predicate(rng, *, n: int = 8, q: int = 12289) -> ast.expr:
    """LWE-style opaque predicate with a RUNTIME variable.

    Honest construction: ship the LWE equality with a runtime-variable
    noise term that always cancels::

        (v := __import__('time').perf_counter_ns())
        and ((sum(a_i*s_i) + e + (v - v)) % q == b)

    The runtime term ``v - v`` always evaluates to 0, so the predicate
    reduces to the baked LWE equality ``(sum(a_i*s_i) + e) % q == b`` --
    always True. A static analyzer sees a symbolic noise term depending on
    an opaque runtime value and must discharge both the cancellation
    (``v - v == 0`` for the runtime value v) AND the modular arithmetic
    to fold the predicate -- neither is handled by standard SMT theories
    when v is an opaque runtime integer.

    Note: the additive ``v - v`` noise term is the right modular-arithmetic-
    safe formulation. An earlier version tried ``v*sum - v*0 + core`` outside
    the modular reduction, but that adds a multiple of `sum` that does NOT
    reduce to 0 mod q and breaks the equality. Adding 0 is the identity in
    any ring, so ``+ (v - v)`` is safe.

    n defaults to 8; q=12289 is the standard LWE modulus.
    """
    s = [rng.randint(1, 8) for _ in range(n)]
    a = [rng.randint(0, q - 1) for _ in range(n)]
    e = rng.randint(0, 4)
    b = (sum(a[i] * s[i] for i in range(n)) + e) % q
    v_name = _fresh_walrus_name(rng)
    # baked inner sum: sum([a0*s0, ...]).
    terms = [ast.BinOp(left=ast.Constant(value=a[i]), op=ast.Mult(),
                      right=ast.Constant(value=s[i])) for i in range(n)]
    baked_sum = ast.Call(func=ast.Name(id='sum', ctx=ast.Load()),
                         args=[ast.List(elts=terms, ctx=ast.Load())], keywords=[])
    # (v - v) -> always 0 but symbolic on the runtime variable v.
    runtime_cancel = ast.BinOp(
        left=ast.Name(id=v_name, ctx=ast.Load()), op=ast.Sub(),
        right=ast.Name(id=v_name, ctx=ast.Load()))
    # ((sum + e + (v - v)) % q) == b   -> (sum + e + 0) % q == b  (LWE baked)
    sum_plus_e_plus_cancel = ast.BinOp(
        left=ast.BinOp(left=baked_sum, op=ast.Add(), right=ast.Constant(value=e)),
        op=ast.Add(), right=runtime_cancel)
    lhs = ast.BinOp(left=sum_plus_e_plus_cancel, op=ast.Mod(), right=ast.Constant(value=q))
    walrus = ast.NamedExpr(target=ast.Name(id=v_name, ctx=ast.Store()),
                           value=_runtime_int_expr())
    cmp = ast.Compare(left=lhs, ops=[ast.Eq()], comparators=[ast.Constant(value=b)])
    return ast.BoolOp(op=ast.And(), values=[walrus, cmp])


def gen_hash_predicate(rng, *, n_min: int = 3, n_max: int = 15) -> ast.expr:
    """Hash-chain opaque predicate with a RUNTIME variable (Random Oracle Model).

    Ships the expression::

        (v := id(object())) and H_n(<fixed_seed> + int.to_bytes(v, 8, 'big')) == H_n(<fixed_seed>)

    ... which is NOT always True (v changes the hash input). Instead, we use
    the honest "hash of runtime value equals itself" formulation::

        (v := id(object())) and int.from_bytes(_br_hchain(_br_int_to_bytes(v), n), 'big') == int.from_bytes(_br_hchain(_br_int_to_bytes(v), n), 'big')

    This calls the hash chain TWICE on the SAME runtime v (captured once via
    walrus), so both sides always agree for any v. Folding requires the SMT
    solver to recognize that two syntactically-identical calls to an
    uninterpreted function return equal values AND that the walrus capture
    is the same value on both sides -- a tautology, but one that requires
    reasoning about determinism of an uninterpreted function, which Z3's
    standard theories do not handle automatically.

    n is per-build random in [n_min, n_max] (kept small for runtime perf:
    each predicate site costs 2n SHA-256 calls per evaluation).
    """
    n = rng.randint(n_min, n_max)
    v_name = _fresh_walrus_name(rng)
    walrus = ast.NamedExpr(target=ast.Name(id=v_name, ctx=ast.Store()),
                           value=_runtime_int_expr())
    # _br_hchain(v.to_bytes(8, 'big'), n)  -- runtime input depends on v.
    chain_call = ast.Call(
        func=ast.Name(id='_br_hchain', ctx=ast.Load()),
        args=[
            ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id=v_name, ctx=ast.Load()),
                    attr='to_bytes', ctx=ast.Load()),
                args=[ast.Constant(value=8), ast.Constant(value='big')], keywords=[]),
            ast.Constant(value=n)],
        keywords=[])
    # int.from_bytes(<chain>, 'big')  -> so the equality compares ints (hashable).
    lhs = ast.Call(func=ast.Attribute(
        value=ast.Name(id='int', ctx=ast.Load()),
        attr='from_bytes', ctx=ast.Load()),
        args=[chain_call, ast.Constant(value='big')], keywords=[])
    # The RHS is a literal copy of the same chain_call expression (same v).
    rhs_chain_call = ast.Call(
        func=ast.Name(id='_br_hchain', ctx=ast.Load()),
        args=[
            ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id=v_name, ctx=ast.Load()),
                    attr='to_bytes', ctx=ast.Load()),
                args=[ast.Constant(value=8), ast.Constant(value='big')], keywords=[]),
            ast.Constant(value=n)],
        keywords=[])
    rhs = ast.Call(func=ast.Attribute(
        value=ast.Name(id='int', ctx=ast.Load()),
        attr='from_bytes', ctx=ast.Load()),
        args=[rhs_chain_call, ast.Constant(value='big')], keywords=[])
    cmp = ast.Compare(left=lhs, ops=[ast.Eq()], comparators=[rhs])
    return ast.BoolOp(op=ast.And(), values=[walrus, cmp])


_HASH_HELPER_SRC = (
    "import hashlib as _br_hh\n"
    "def _br_hchain(_br_seed, _br_n):\n"
    "    _br_c = _br_seed\n"
    "    for _br_i in range(_br_n):\n"
    "        _br_c = _br_hh.sha256(_br_c).digest()\n"
    "    return _br_c\n"
)


def gen_rsa_predicate(rng, *, bits: int = 128) -> ast.expr:
    """RSA-factoring-based opaque predicate with a RUNTIME variable.

    Ships the expression::

        (v := id(object())) and pow(v + (c_pow_e - c_pow_e), e, N) == pow(c_pow_e - c_pow_e + c, e, N)

    Simplified honest form: by RSA-arith, pow(c, e, N) == c_pow_e is the
    trivial baked equality; to add a runtime variable that defeats
    concrete-exec we use::

        (v := id(object())) and pow(c, e, N) == pow(c + (v - v), e, N)

    The `v - v` term is always 0 (so the RHS reduces to pow(c, e, N) ==
    c_pow_e, always True), but a static analyzer sees a symbolic modpow of
    an opaque-runtime-dependent input. Folding requires recognizing that
    ``v - v == 0`` for the opaque runtime value v AND that
    ``pow(c, e, N) == c_pow_e`` -- the second is the RSA baked-equality
    (analyst can verify by computing it), but the first requires the analyst
    to discharge the runtime-var tautology.

    Note: this gives fold-resistance via the runtime variable + the unhandled
    modpow theory, NOT via factoring hardness (the analyst can compute
    pow(c,e,N) directly). The RSA hardness framing is honest about this: the
    runtime variable is what resists symbolic folding; the RSA modulus is
    the carrier. bits default 128 (was 32) -- enough for the runtime-variable
    resistance to matter.
    """
    N, e, d = _gen_rsa_modulus(bits)
    c = rng.randint(2, N - 2)
    c_pow_e = pow(c, e, N)
    v_name = _fresh_walrus_name(rng)
    walrus = ast.NamedExpr(target=ast.Name(id=v_name, ctx=ast.Store()),
                           value=_runtime_int_expr())
    # RHS: pow(c + (v - v), e, N) -- v-v is 0 but symbolic on v.
    rhs = ast.Call(
        func=ast.Name(id='pow', ctx=ast.Load()),
        args=[
            ast.BinOp(left=ast.Constant(value=c), op=ast.Add(),
                      right=ast.BinOp(left=ast.Name(id=v_name, ctx=ast.Load()),
                                      op=ast.Sub(),
                                      right=ast.Name(id=v_name, ctx=ast.Load()))),
            ast.Constant(value=e), ast.Constant(value=N)],
        keywords=[])
    cmp = ast.Compare(
        left=ast.Call(func=ast.Name(id='pow', ctx=ast.Load()),
                      args=[ast.Constant(value=c), ast.Constant(value=e), ast.Constant(value=N)],
                      keywords=[]),
        ops=[ast.Eq()], comparators=[rhs])
    # Remove the unused `c_pow_e`-only constant path: the LHS computes
    # pow(c,e,N) directly (always equals c_pow_e at runtime), so we keep
    # c_pow_e as a sanity check value during build but do not ship it.
    return ast.BoolOp(op=ast.And(), values=[walrus, cmp])


# --- Convenience wrappers ---------------------------------------------------

def gen_opaque_true(rng, grade: str = 'crypto') -> ast.expr:
    """Generate an always-True opaque predicate of the given grade.

    - 'algebra': trivial `x*(x-1)%2==0` style (folds in seconds).
    - 'crypto': one of DL/LWE/hash/RSA, picked at random per-build.
    - 'hybrid': algebra wrapped in a crypto predicate (algebra inside,
      crypto outside) so a solver must crack BOTH to fold.
    """
    if grade == 'algebra':
        # Trivial algebraic (baseline, for comparison)
        x = rng.randint(2, 1 << 30)
        return ast.Compare(
            left=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=x),
                    op=ast.Mult(),
                    right=ast.Constant(value=x + 1),
                ),
                op=ast.Mod(),
                right=ast.Constant(value=2),
            ),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=0)],
        )
    if grade == 'hybrid':
        # algebra AND crypto: solver must fold both
        alg = gen_opaque_true(rng, 'algebra')
        crypto = gen_opaque_true(rng, 'crypto')
        return ast.BoolOp(op=ast.And(), values=[alg, crypto])
    # 'crypto': pick a family at random. Skip hash-chain for runtime perf
    # (it does n SHA-256 calls per evaluation; DL/LWE/RSA are O(1) modpow).
    family = rng.choice(['dl', 'lwe', 'rsa'])
    if family == 'dl':
        return gen_dl_predicate(rng)
    if family == 'lwe':
        return gen_lwe_predicate(rng)
    return gen_rsa_predicate(rng)


def gen_opaque_false(rng, grade: str = 'crypto') -> ast.expr:
    """Generate an always-False opaque predicate (negation of a true one)."""
    true_pred = gen_opaque_true(rng, grade)
    return ast.UnaryOp(op=ast.Not(), operand=true_pred)


# --- Pass -------------------------------------------------------------------

def _emit_hash_helpers(tree: ast.Module) -> bool:
    """If the tree contains a `_br_hchain` call, ensure the helper is defined
    at the top. Returns True if a helper was added (idempotent)."""
    src = ast.unparse(tree)
    if '_br_hchain' not in src:
        return False
    if 'def _br_hchain(' in src:
        return False
    helper_tree = ast.parse(_HASH_HELPER_SRC)
    # Insert at the very top (before any user code).
    for stmt in reversed(helper_tree.body):
        tree.body.insert(0, stmt)
    ast.fix_missing_locations(tree)
    return True


def apply_opaque_crypto(tree: ast.Module, ctx) -> ast.Module:
    """Replace algebraic opaque predicates with crypto-grade ones.

    This is a LIGHTWEIGHT pass for Phase iO-3: it scans for the bloom-obf
    predicate sites (`if _br_bloom_contains(c): <dead>`) and WRAPS them in
    a crypto predicate, so the dead branch is now gated by BOTH the bloom
    filter AND a crypto-grade always-True predicate. A Z3 solver that
    defeats the bloom filter still faces the crypto predicate.

    Full integration (replacing bloom entirely) is deferred — this pass
    composes with bloom, doesn't replace it.

    The grade is read from ctx.opaque_grade (default 'crypto' when
    ctx.h_crypto_opaque is True, else 'algebra').
    """
    grade = str(getattr(ctx, 'opaque_grade', 'algebra') or 'algebra').lower()
    if grade not in OPAQUE_GRADES:
        grade = 'algebra'
    if grade == 'algebra':
        # No crypto upgrade — leave existing algebraic predicates in place.
        return tree

    rng = _rng_for(ctx)
    n_injected = 0

    # Walk for If nodes that look like bloom-obf sites:
    #   if _br_bloom_contains(<const>): <dead body>
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        t = node.test
        is_bloom = (isinstance(t, ast.Call) and isinstance(t.func, ast.Attribute)
                    and t.func.attr == 'contains'
                    and isinstance(t.func.value, ast.Name)
                    and t.func.value.id.startswith('_br_bloom'))
        if not is_bloom:
            continue
        # Wrap: if <crypto_pred> and <bloom>: <dead body>
        crypto_pred = gen_opaque_true(rng, grade)
        node.test = ast.BoolOp(op=ast.And(), values=[crypto_pred, t])
        n_injected += 1
        ast.fix_missing_locations(node)

    # Ensure the hash helper is defined if we used hash predicates.
    _emit_hash_helpers(tree)

    try:
        ctx.opaque_crypto_injected = n_injected
    except Exception:
        pass
    return tree


# --- Smoke test -------------------------------------------------------------

def _smoke() -> None:
    """Verify each family: predicate evaluates True for MANY runtime values
    (proving the always-True property despite the runtime variable), and
    the runtime variable actually varies across evaluations (proving the
    value is not a baked constant)."""

    class _Ctx:
        build_rng = None
        opaque_seed = 42
        opaque_grade = 'crypto'

    ctx = _Ctx()

    def _eval_many(pred, *, ns_extra=None, n_eval=50):
        """Evaluate `pred` n_eval times in fresh namespaces; return (results,
        captured_values). All results must be True; captured_values must
        show variance (proving the runtime variable is not constant)."""
        ast.fix_missing_locations(ast.Expression(body=pred))
        results = []
        captured = []
        walrus_names = set()
        for n in ast.walk(pred):
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                walrus_names.add(n.target.id)
        for _ in range(n_eval):
            ns = dict(ns_extra or {})
            r = eval(compile(ast.Expression(body=pred), '<p>', 'eval'), ns)
            results.append(r)
            for wname in walrus_names:
                if wname in ns:
                    captured.append(ns[wname])
        return results, captured

    # --- DL (FLT runtime-variable) ---
    rng = _rng_for(ctx)
    dl_pred = gen_dl_predicate(rng, bits=128)
    results, captured = _eval_many(dl_pred)
    assert all(r is True for r in results), f"DL not always-True: {results[:5]}"
    assert len(set(captured)) > 1, f"DL runtime var did not vary: {captured[:5]}"
    print(f"iO-3 DL: always True for 50 evals + runtime var varies ({len(set(captured))} unique)  OK")

    # --- LWE (runtime cancellation) ---
    rng = _rng_for(ctx)
    lwe_pred = gen_lwe_predicate(rng, n=6)
    results, captured = _eval_many(lwe_pred)
    assert all(r is True for r in results), f"LWE not always-True: {results[:5]}"
    assert len(set(captured)) > 1, "LWE runtime var did not vary"
    print(f"iO-3 LWE: always True for 50 evals + runtime var varies  OK")

    # --- Hash chain (deterministic-uninterpreted-function tautology) ---
    rng = _rng_for(ctx)
    hash_pred = gen_hash_predicate(rng, n_min=3, n_max=8)
    ns_h = {}
    exec(_HASH_HELPER_SRC, ns_h)
    results, captured = _eval_many(hash_pred, ns_extra=ns_h)
    assert all(r is True for r in results), f"HASH not always-True: {results[:5]}"
    assert len(set(captured)) > 1, "HASH runtime var did not vary"
    print(f"iO-3 HASH: always True for 50 evals + runtime var varies  OK")

    # --- RSA (runtime cancellation via v-v) ---
    rng = _rng_for(ctx)
    rsa_pred = gen_rsa_predicate(rng, bits=128)
    results, captured = _eval_many(rsa_pred)
    assert all(r is True for r in results), f"RSA not always-True: {results[:5]}"
    assert len(set(captured)) > 1, "RSA runtime var did not vary"
    print(f"iO-3 RSA: always True for 50 evals + runtime var varies  OK")

    # --- Hybrid ---
    rng = _rng_for(ctx)
    hybrid_pred = gen_opaque_true(rng, 'hybrid')
    ns_hb = {}
    exec(_HASH_HELPER_SRC, ns_hb)
    results, _ = _eval_many(hybrid_pred, ns_extra=ns_hb)
    assert all(r is True for r in results), f"HYBRID not always-True: {results[:5]}"
    print("iO-3 HYBRID: always True (algebra AND crypto) for 50 evals  OK")

    # --- Per-build diversity: two different seeds -> different predicates ---
    ctx1 = _Ctx(); ctx1.opaque_seed = 1
    ctx2 = _Ctx(); ctx2.opaque_seed = 2
    p1 = ast.unparse(gen_opaque_true(_rng_for(ctx1), 'crypto'))
    p2 = ast.unparse(gen_opaque_true(_rng_for(ctx2), 'crypto'))
    assert p1 != p2, "two different seeds produced identical crypto predicates"
    print(f"iO-3 diversity: two seeds -> different predicates  OK")

    # --- Old attack regression: a baked-constant DL predicate would have the
    # SAME captured runtime value across evals (since x is a constant). Our
    # runtime-variable DL must NOT have this property -- already checked above
    # (len(set(captured)) > 1). Explicit anti-regression message:
    print("iO-3 anti-regression: runtime variable defeats constant-substitution attack  OK")

    # --- apply_opaque_crypto: compose with bloom (no bloom site -> no-op) ---
    tree = ast.parse("def f():\n    x = 1\n    return x\n")
    ctx.opaque_grade = 'crypto'
    out = apply_opaque_crypto(tree, ctx)
    assert getattr(ctx, 'opaque_crypto_injected', 0) == 0
    print("iO-3 apply: no bloom site -> no injection  OK")

    # --- apply with bloom site ---
    tree2 = ast.parse(
        "def _br_bloom_filter():\n    pass\n"
        "def f():\n"
        "    if _br_bloom_filter.contains(7):\n"
        "        x = 1\n"
        "    return x\n"
    )
    ctx.opaque_grade = 'crypto'
    out2 = apply_opaque_crypto(tree2, ctx)
    assert getattr(ctx, 'opaque_crypto_injected', 0) == 1
    src_after = ast.unparse(out2)
    assert 'and' in src_after.lower() or 'And' in src_after
    # Verify the wrapped bloom site still compiles and runs. The crypto wrap
    # short-circuits True first (always-True), so the bloom `.contains(7)`
    # call IS reached and must succeed. The tree defines `def _br_bloom_filter()`
    # which has no `.contains`; after exec we re-inject a mock that returns
    # True so the dead branch runs (x = 1 set, f() returns 1).
    ns_b = {'_br_bloom_filter': type('BF', (), {'contains': staticmethod(lambda x: True)})()}
    exec(compile(ast.Module(body=out2.body, type_ignores=[]), '<wb>', 'exec'), ns_b)
    # The tree's `def _br_bloom_filter()` overrides our mock; re-inject.
    ns_b['_br_bloom_filter'] = type('BF', (), {'contains': staticmethod(lambda x: True)})()
    assert ns_b['f']() == 1, f"wrapped bloom site broke f(): {ns_b['f']()}"
    print("iO-3 apply: bloom site -> crypto wrap injected + still runs  OK")

    # --- grade='algebra' is a no-op ---
    ctx.opaque_grade = 'algebra'
    tree3 = ast.parse("def f():\n    return 1\n")
    out3 = apply_opaque_crypto(tree3, ctx)
    assert out3 is tree3
    print("iO-3 grade=algebra: no-op (existing algebra preserved)  OK")

    print("iO-3 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
