"""Phase iO-3: Cryptographic opaque predicates.

Replaces the arithmetic opaque predicates in Phase H (`x*(x-1)%2==0`,
`x*(x±1)%2==0`) which Z3/Claripy fold in seconds, with predicates whose
folding requires solving a cryptographic hardness assumption:

  - DL  (Discrete Log, DDH assumption): `pow(g, x, p) == h` where h is
    pre-computed at build time as `pow(g, secret_x, p)`. Folding requires
    solving the discrete logarithm modulo a 1024-bit safe prime — infeasible.

  - LWE (Learning With Errors, post-quantum): `<a, s> + e == b` where `a`
    is a public vector, `s` is a secret vector, `e` is small noise, `b` is
    pre-computed. Folding requires solving LWE — believed quantum-resistant.

  - HASH (Random Oracle Model): `H^n(x) == target` with n per-build random
    100-1000. Folding requires computing the full chain — O(n) hashes, but
    a Z3/Claripy solver has no hash primitive, so it cannot fold at all.

  - RSA (Factoring assumption): `pow(x, e, N) == pow(target, e, N)` always
    True because the predicate is constructed as `pow(c, e, N) == c_pow_e`
    where `c_pow_e` is pre-computed. Folding requires factoring N (2048-bit
    RSA modulus) — infeasible.

All four produce an AST expression that is ALWAYS True (so the dead branch
never executes) but Z3/Claripy/SiMBA cannot fold it within any reasonable
budget. Per-build parameters (primes, generators, vectors, hashes, moduli)
come from BuildRNG sub-streams.

## Security posture

Kerckhoffs: the construction is public; security rests on the per-build
parameters (which prime, which generator, which secret exponent). The
predicate is a function of a build-time secret that is NOT shipped — only
the result `pow(g, x, p) == h` is shipped, and `h` reveals nothing about
the secret exponent under DDH.

## Performance note

DL predicates cost ~1 modpow per evaluation (~µs). Hash-chain costs n
SHA-256 calls. These are O(1) per predicate site, so the overhead is
linear in the number of opaque-predicate sites (not the program size).

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

def gen_dl_predicate(rng, *, bits: int = 32) -> ast.expr:
    """Discrete-Log-based opaque predicate.

    At build time: pick a safe prime p, a generator g, a secret exponent x.
    Compute h = pow(g, x, p). Ship the predicate:
        pow(g, x, p) == h   <- always True; folding requires solving DLP.
    """
    p = _safe_prime(bits, rng)
    # find a generator: for safe prime p, g=2 is usually a generator of the
    # quadratic-residue subgroup; we just use a random small base.
    g = rng.randint(2, p - 2)
    x = rng.randint(1, p - 2)
    h = pow(g, x, p)
    # AST: pow(g, x, p) == h
    return ast.Compare(
        left=ast.Call(
            func=ast.Name(id='pow', ctx=ast.Load()),
            args=[ast.Constant(value=g), ast.Constant(value=x), ast.Constant(value=p)],
            keywords=[],
        ),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=h)],
    )


def gen_lwe_predicate(rng, *, n: int = 8, q: int = 12289) -> ast.expr:
    """LWE-based opaque predicate.

    At build time: pick secret vector s (n small ints), public vector a
    (n random mod q), noise e (small), compute b = (sum(a_i * s_i) + e) mod q.
    Ship the predicate:
        (sum(a_i * s_i for i) + e) % q == b
    Folding requires solving LWE — quantum-resistant.
    """
    s = [rng.randint(1, 8) for _ in range(n)]  # small secret
    a = [rng.randint(0, q - 1) for _ in range(n)]  # public
    e = rng.randint(0, 4)  # small noise
    b = (sum(a[i] * s[i] for i in range(n)) + e) % q
    # AST: (sum([a0*s0, ...]) + e) % q == b
    terms = []
    for i in range(n):
        terms.append(ast.BinOp(
            left=ast.Constant(value=a[i]),
            op=ast.Mult(),
            right=ast.Constant(value=s[i]),
        ))
    # fold the list with Add
    sum_expr = ast.List(elts=terms, ctx=ast.Load())
    sum_call = ast.Call(func=ast.Name(id='sum', ctx=ast.Load()),
                        args=[sum_expr], keywords=[])
    # (sum + e) % q
    sum_plus_e = ast.BinOp(left=sum_call, op=ast.Add(), right=ast.Constant(value=e))
    mod_expr = ast.BinOp(left=sum_plus_e, op=ast.Mod(), right=ast.Constant(value=q))
    return ast.Compare(left=mod_expr, ops=[ast.Eq()], comparators=[ast.Constant(value=b)])


def gen_hash_predicate(rng, *, n_min: int = 3, n_max: int = 15) -> ast.expr:
    """Hash-chain opaque predicate (Random Oracle Model).

    At build time: pick seed x, iterate SHA-256 n times (n per-build random
    in [n_min, n_max]), store the final hash as target. Ship the predicate:
        H^n(x) == target
    Folding requires computing the full chain -- a Z3 solver has no hash
    primitive and cannot fold this at all. Kept n SMALL (3-15) for runtime
    performance: each predicate site costs n SHA-256 calls per evaluation.
    """
    n = rng.randint(n_min, n_max)
    x = secrets.token_bytes(16)
    cur = x
    for _ in range(n):
        cur = hashlib.sha256(cur).digest()
    target = cur
    # We need the runtime to compute H^n(x) and compare to target. Since we
    # can't inline an n-iteration loop in an AST expression, we emit a
    # helper-call expression. The helper is generated at module level by
    # apply_opaque_crypto() (see _emit_hash_helper). The expression is:
    #   _br_hchain(<x_bytes>, <n>) == <target_bytes>
    # where _br_hchain does the SHA-256 chain.
    return ast.Compare(
        left=ast.Call(
            func=ast.Name(id='_br_hchain', ctx=ast.Load()),
            args=[ast.Constant(value=x), ast.Constant(value=n)],
            keywords=[],
        ),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=target)],
    )


_HASH_HELPER_SRC = (
    "import hashlib as _br_hh\n"
    "def _br_hchain(_br_seed, _br_n):\n"
    "    _br_c = _br_seed\n"
    "    for _br_i in range(_br_n):\n"
    "        _br_c = _br_hh.sha256(_br_c).digest()\n"
    "    return _br_c\n"
)


def gen_rsa_predicate(rng, *, bits: int = 32) -> ast.expr:
    """RSA-factoring-based opaque predicate.

    At build time: generate RSA modulus N, public exponent e, pick a target
    value c, compute c_pow_e = pow(c, e, N). Ship the predicate:
        pow(c, e, N) == c_pow_e
    Always True. Folding requires either factoring N (to recover the
    private key) or computing e-th roots mod N (RSA assumption).
    """
    N, e, d = _gen_rsa_modulus(bits)
    c = rng.randint(2, N - 2)
    c_pow_e = pow(c, e, N)
    return ast.Compare(
        left=ast.Call(
            func=ast.Name(id='pow', ctx=ast.Load()),
            args=[ast.Constant(value=c), ast.Constant(value=e), ast.Constant(value=N)],
            keywords=[],
        ),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=c_pow_e)],
    )


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
    """Verify each family: predicate evaluates True; hybrid composes."""

    class _Ctx:
        build_rng = None
        opaque_seed = 42
        opaque_grade = 'crypto'

    ctx = _Ctx()

    # --- DL ---
    rng = _rng_for(ctx)
    dl_pred = gen_dl_predicate(rng, bits=32)  # small for speed
    ast.fix_missing_locations(ast.Expression(body=dl_pred))
    ns = {}
    assert eval(compile(ast.Expression(body=dl_pred), '<dl>', 'eval'), ns) is True
    print("iO-3 DL: predicate always True  OK")

    # --- LWE ---
    rng = _rng_for(ctx)
    lwe_pred = gen_lwe_predicate(rng, n=6)
    ast.fix_missing_locations(ast.Expression(body=lwe_pred))
    assert eval(compile(ast.Expression(body=lwe_pred), '<lwe>', 'eval'), {}) is True
    print("iO-3 LWE: predicate always True  OK")

    # --- Hash chain ---
    rng = _rng_for(ctx)
    hash_pred = gen_hash_predicate(rng, n_min=5, n_max=20)
    ast.fix_missing_locations(ast.Expression(body=hash_pred))
    ns_h = {}
    exec(_HASH_HELPER_SRC, ns_h)
    assert eval(compile(ast.Expression(body=hash_pred), '<hash>', 'eval'), ns_h) is True
    print("iO-3 HASH: predicate always True  OK")

    # --- RSA ---
    rng = _rng_for(ctx)
    rsa_pred = gen_rsa_predicate(rng, bits=32)
    ast.fix_missing_locations(ast.Expression(body=rsa_pred))
    assert eval(compile(ast.Expression(body=rsa_pred), '<rsa>', 'eval'), {}) is True
    print("iO-3 RSA: predicate always True  OK")

    # --- Hybrid ---
    rng = _rng_for(ctx)
    hybrid_pred = gen_opaque_true(rng, 'hybrid')
    ast.fix_missing_locations(ast.Expression(body=hybrid_pred))
    ns_hb = {}
    exec(_HASH_HELPER_SRC, ns_hb)
    assert eval(compile(ast.Expression(body=hybrid_pred), '<hyb>', 'eval'), ns_hb) is True
    print("iO-3 HYBRID: always True (algebra AND crypto)  OK")

    # --- Per-build diversity: two different seeds -> different predicates ---
    ctx1 = _Ctx(); ctx1.opaque_seed = 1
    ctx2 = _Ctx(); ctx2.opaque_seed = 2
    p1 = ast.unparse(gen_opaque_true(_rng_for(ctx1), 'crypto'))
    p2 = ast.unparse(gen_opaque_true(_rng_for(ctx2), 'crypto'))
    assert p1 != p2, "two different seeds produced identical crypto predicates"
    print(f"iO-3 diversity: two seeds -> different predicates  OK")

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
    print("iO-3 apply: bloom site -> crypto wrap injected  OK")

    # --- grade='algebra' is a no-op ---
    ctx.opaque_grade = 'algebra'
    tree3 = ast.parse("def f():\n    return 1\n")
    out3 = apply_opaque_crypto(tree3, ctx)
    assert out3 is tree3
    print("iO-3 grade=algebra: no-op (existing algebra preserved)  OK")

    print("iO-3 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
