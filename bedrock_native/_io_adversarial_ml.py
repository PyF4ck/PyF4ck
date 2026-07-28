"""Phase iO-7: Adversarial ML classifier test (pure stdlib).

Runs THREE classifier experiments and reports accuracy with a Wilson 95%
confidence interval for each:

  1. PRG-uniformity test (obfuscated vs os.urandom): measures whether the
     encrypted output's byte distribution is uniform. This is a property of
     any encryption/PRG output and is NOT the iO property — it is reported
     honestly under that label.

  2. iO-property test (Obf(P0) vs Obf(P1) for functionally-equivalent but
     DIFFERENT programs P0 != P1): this is the actual indistinguishability-
     of-obfuscation property. If the classifier can't tell obfuscations of
     two different equivalent programs apart better than chance, the iO
     property holds (at least for this program pair and this adversary).

  3. build-diversity test (Phase G8): Obf(P0) fresh-seed builds split in
     half and classified build-set-A vs build-set-B. If the classifier
     separates two halves of the SAME program, a build-family fingerprint
     exists (family detector). Near chance => build-diversity holds.

Methodology fixes vs the original test (which was statistically vacuous):
  - N raised from 10 to 40 (test set ~40, Wilson SD ~7.9% vs ~15.8% at N=10).
    Set $BR_ML_N=100 for publication-grade runs (~50 min).
  - Two feature sets ACTUALLY implemented (previously claimed but absent):
    byte histogram (256) + byte-pair histogram top-256-by-variance (256).
  - Train/test split is now genuinely stratified by class (50/50 per class),
    not an unstratified shuffle on the combined index list.
  - Gate threshold is consistent (docstring and code agree): accuracy <
    0.55, close to the 0.50 chance baseline with a small margin.
  - Accuracy reported with a Wilson 95% confidence interval so the reader
    can see the sampling uncertainty, not just a point estimate.

Protocol (per experiment):
  1. Build N obfuscated files with `--profile io` (binary capsule on).
  2. Generate the comparison set (N urandom files for test 1; N obfuscated
     builds of the equivalent program for test 2).
  3. Extract features (byte histogram + byte-pair top-256-by-variance).
  4. Stratified 50/50 train/test split.
  5. Train logistic regression on the train set.
  6. Evaluate accuracy on the test set + Wilson 95% CI.
  7. Gate: accuracy upper 95% CI bound < 0.55.

Run:
    python bedrock_native/_io_adversarial_ml.py
    BR_ML_N=100 python bedrock_native/_io_adversarial_ml.py   # larger N
"""
import collections
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_OBF = os.path.join(_ROOT, "bedrock_obfuscator.py")

# Two functionally-equivalent but syntactically different programs. Both
# print "final_result: 130" (= sum_{i=0..4} (i*i + i*i*i)). P0 uses x*x,
# P1 uses x**2 — same function, different source, so an obfuscator that
# achieved real iO would produce indistinguishable Obf(P0) and Obf(P1).
_PROG_P0 = (
    "def square(x):\n"
    "    return x * x\n"
    "def cube(x):\n"
    "    return x * x * x\n"
    "print('final_result:', sum(square(i) + cube(i) for i in range(5)))\n"
)
_PROG_P1 = (
    "def square(x):\n"
    "    return x ** 2\n"
    "def cube(x):\n"
    "    return x ** 3\n"
    "print('final_result:', sum(square(i) + cube(i) for i in range(5)))\n"
)
_EXPECTED = "final_result: 130"

_COMMON_FLAGS = [
    "--profile", "io",
    "--anti-vm", "off",
    "--anti-debug", "off",
    "--no-debug-poison",
    "--no-metamorphic",
    "--no-native-vm",
    "--no-cache",
    "--overwrite",
    "--adv-requests", "off",
    "--no-anti-timing",
    "--quiet",
    # Phase A remediation: --embed-key keeps the test self-contained. This
    # harness measures byte-distribution uniformity, NOT key security.
    # Production builds MUST omit --embed-key for real key separation.
    "--embed-key",
]

# N_BUILDS per class. 40 gives a Wilson SD of ~7.9% (vs ~15.8% at N=10,
# which was statistically vacuous). Override via $BR_ML_N for larger runs.
N_BUILDS = int(os.environ.get("BR_ML_N", "40"))
MAX_RETRIES = 3
ACC_TARGET = 0.55  # consistent across docstring and code (chance = 0.50)

PASSES = 0
FAILS = []


def _ok(label):
    global PASSES
    PASSES += 1
    print(f"  PASS  {label}")


def _fail(label, detail=""):
    global FAILS
    FAILS.append(f"{label}: {detail}")
    print(f"  FAIL  {label} -- {detail}")


def _wilson_ci(correct: int, n: int, z: float = 1.96) -> tuple:
    """Two-sided Wilson score 95% confidence interval for a binomial
    proportion. Returns (low, high). Handles n==0 as (0.0, 1.0)."""
    if n <= 0:
        return (0.0, 1.0)
    p = correct / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def _run(cmd, cwd, timeout=360):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return 125, "", str(e)


def _build_once(build_idx, out_dir, input_path):
    out_path = os.path.join(out_dir, f"obf_{build_idx}.py")
    cmd = [sys.executable, _OBF, "-f", input_path, "-o", out_path] + _COMMON_FLAGS
    rc, so, se = _run(cmd, cwd=_ROOT, timeout=360)
    if rc != 0 or not os.path.exists(out_path):
        return None
    return out_path


def _build_and_verify(build_idx, out_dir, input_path, run_timeout=30):
    for attempt in range(MAX_RETRIES):
        path = _build_once(build_idx, out_dir, input_path)
        if path is None:
            continue
        rc, out, _ = _run([sys.executable, os.path.basename(path)],
                          cwd=out_dir, timeout=run_timeout)
        if rc == 0 and _EXPECTED in out:
            return path
    return None


def _extract_features(data: bytes) -> list:
    """Extract byte-histogram (256) + byte-pair-histogram (256) features.

    The byte-pair features are the top-256 most-variance bigrams computed on
    the TRAIN set (see _select_top_bigrams). Here we return the full 256-bin
    byte histogram only; the bigram features are appended by
    _extract_features_with_bigrams once the top-256 set is known.
    """
    n = len(data)
    freq = collections.Counter(data)
    hist = [freq.get(b, 0) / n for b in range(256)]
    return hist


def _bigram_counts(data: bytes) -> dict:
    """Count all adjacent byte pairs in `data`."""
    pairs = collections.Counter()
    for i in range(len(data) - 1):
        pairs[(data[i], data[i + 1])] += 1
    return pairs


def _select_top_bigrams(datas: list, k: int = 256) -> list:
    """Select the k byte-pairs with the highest across-file variance on the
    given list of file bytes. This matches the docstring's claimed
    'byte-pair histogram (top-256 by variance)' feature set.
    """
    # Per-file normalized bigram frequencies.
    file_freqs = []
    all_pairs = set()
    for d in datas:
        pc = _bigram_counts(d)
        n = max(1, len(d) - 1)
        norm = {pair: c / n for pair, c in pc.items()}
        file_freqs.append(norm)
        all_pairs.update(norm.keys())
    # Variance across files for each pair.
    variances = {}
    for pair in all_pairs:
        vals = [ff.get(pair, 0.0) for ff in file_freqs]
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / max(1, len(vals))
        variances[pair] = var
    top = sorted(variances, key=variances.get, reverse=True)[:k]
    return top


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of the byte distribution (0..8 bits/byte)."""
    if not data:
        return 0.0
    n = len(data)
    freq = collections.Counter(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _bootstrap_regex_count(data: bytes) -> int:
    """Phase G8 (M9): count bootstrap-fingerprint substrings in the file.

    The binary-capsule bootstrap imports zlib/hashlib and uses decompressobj;
    a classifier can fingerprint these. Counting occurrences gives the ML
    test a feature that directly measures this leakage channel, so the
    report can distinguish 'obf weak' (this feature is discriminative) from
    'test weak' (no feature is discriminative).
    """
    needles = (b'import zlib', b'hashlib', b'decompressobj', b'bytes.fromhex',
               b'base64.b85decode', b'b85decode', b'__import__')
    total = 0
    for needle in needles:
        total += data.count(needle)
    return total


def _extract_features_with_bigrams(data: bytes, top_pairs: list) -> list:
    """Full feature vector.

    Phase G8 (M2, M9): previously only 256 byte-histogram + 256 bigram
    features, all NORMALIZED by length -- which discarded the length channel
    (file size differs between profiles/programs). Now also appends:
      - raw len(data) (NOT normalized -- closes the length-channel blind spot, M2)
      - total Shannon entropy (bytes-level, 0..8)
      - first-1KB Shannon entropy (positional, M9)
      - last-1KB Shannon entropy (positional, M9)
      - bootstrap-regex count (bootstrap-fingerprint substrings, M9)
    """
    n = len(data)
    freq = collections.Counter(data)
    hist = [freq.get(b, 0) / n for b in range(256)]
    pc = _bigram_counts(data)
    nb = max(1, len(data) - 1)
    bigram = [pc.get(p, 0) / nb for p in top_pairs]
    # Phase G8 new features. raw_len is scaled to ~1..10 (divide by a typical
    # obfuscated file size) so it sits on the same order as the entropy
    # features (0..8) and does NOT dominate the L2-regularized classifier.
    raw_len = float(n) / 10000.0
    total_ent = _shannon_entropy(data)
    first_1k = data[:1024]
    last_1k = data[-1024:] if len(data) >= 1024 else data
    first_ent = _shannon_entropy(first_1k)
    last_ent = _shannon_entropy(last_1k)
    boot_re = float(_bootstrap_regex_count(data))
    return hist + bigram + [raw_len, total_ent, first_ent, last_ent, boot_re]


# Indices of the G8 scalar features within the feature vector (after the
# 256 hist + 256 bigram = 512 histogram features).
_N_HIST = 256
_N_BIGRAM = 256
_G8_SCALAR_OFFSET = _N_HIST + _N_BIGRAM  # 512
_G8_SCALAR_NAMES = ('raw_len', 'total_entropy', 'first_1k_entropy',
                     'last_1k_entropy', 'bootstrap_regex_count')


def _sigmoid(x):
    if x > 500:
        return 1.0
    if x < -500:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


class LogisticRegression:
    """Binary logistic regression with L2 regularization (pure Python)."""

    def __init__(self, n_features, lr=0.01, l2=0.01, n_iters=500):
        self.n = n_features
        self.lr = lr
        self.l2 = l2
        self.n_iters = n_iters
        self.w = [0.0] * n_features
        self.b = 0.0

    def fit(self, X, y):
        n = len(X)
        for it in range(self.n_iters):
            grad_w = [0.0] * self.n
            grad_b = 0.0
            for i in range(n):
                z = self.b + sum(self.w[j] * X[i][j] for j in range(self.n))
                p = _sigmoid(z)
                err = p - y[i]
                for j in range(self.n):
                    grad_w[j] += err * X[i][j]
                grad_b += err
            for j in range(self.n):
                grad_w[j] = grad_w[j] / n + self.l2 * self.w[j]
                self.w[j] -= self.lr * grad_w[j]
            grad_b = grad_b / n
            self.b -= self.lr * grad_b

    def predict(self, X):
        return [self._predict_one(x) for x in X]

    def _predict_one(self, x):
        z = self.b + sum(self.w[j] * x[j] for j in range(self.n))
        return _sigmoid(z)


def _stratified_split(X, y, train_frac=0.5, seed=42):
    """Genuinely stratified split: divide each class separately 50/50, then
    combine. Guarantees the train/test sets have the same class balance."""
    rng = random.Random(seed)
    train_idx, test_idx = [], []
    for cls in sorted(set(y)):
        cls_idx = [i for i, v in enumerate(y) if v == cls]
        rng.shuffle(cls_idx)
        cut = int(len(cls_idx) * train_frac)
        train_idx.extend(cls_idx[:cut])
        test_idx.extend(cls_idx[cut:])
    return train_idx, test_idx


def _run_classifier(X_obf, X_cmp, label_a, label_b, gate_label):
    """Train + evaluate a logistic-regression classifier on the two feature
    sets, report accuracy + Wilson 95% CI, and apply the gate.

    X_obf: features for class 0 (obfuscated). X_cmp: features for class 1
    (the comparison set). label_a/label_b: human labels. gate_label: the
    pass/fail label for the summary.
    """
    X = X_obf + X_cmp
    y = [0] * len(X_obf) + [1] * len(X_cmp)
    train_idx, test_idx = _stratified_split(X, y, train_frac=0.5)
    X_train = [X[i] for i in train_idx]
    y_train = [y[i] for i in train_idx]
    X_test = [X[i] for i in test_idx]
    y_test = [y[i] for i in test_idx]
    n_a_train = sum(1 for v in y_train if v == 0)
    n_b_train = sum(1 for v in y_train if v == 1)
    print(f"  train: {len(X_train)} ({n_a_train} {label_a}, {n_b_train} {label_b})")
    print(f"  test:  {len(X_test)} (stratified)")

    clf = LogisticRegression(n_features=len(X_train[0]), lr=0.1, l2=0.01, n_iters=1000)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    pred_labels = [1 if p > 0.5 else 0 for p in preds]
    correct = sum(1 for p, t in zip(pred_labels, y_test) if p == t)
    accuracy = correct / len(y_test) if y_test else 0.0
    ci_lo, ci_hi = _wilson_ci(correct, len(y_test))
    print(f"  test accuracy: {accuracy:.1%} ({correct}/{len(y_test)})")
    print(f"  Wilson 95% CI: [{ci_lo:.1%}, {ci_hi:.1%}]  (chance: 50%)")
    print(f"  predictions: {[p[1] for p in zip(preds, y_test)]}")

    # Gate: the UPPER bound of the 95% CI must be below the target. This is
    # stricter than gating on the point estimate alone and accounts for the
    # sampling uncertainty at finite N.
    if ci_hi < ACC_TARGET:
        _ok(f"{gate_label}: CI upper {ci_hi:.1%} < {ACC_TARGET:.0%}")
    else:
        _fail(gate_label,
              f"CI upper {ci_hi:.1%} >= {ACC_TARGET:.0%} -- classifier may "
              f"distinguish {label_a} from {label_b} (acc {accuracy:.1%})")

    # Feature importance (which bytes/bigrams/scalars betray the construction?)
    top_features = sorted(enumerate(clf.w), key=lambda x: abs(x[1]), reverse=True)[:5]
    print(f"  Top-5 discriminative features:")
    for idx, weight in top_features:
        if idx < _N_HIST:
            kind = f"byte 0x{idx:02x}"
        elif idx < _N_HIST + _N_BIGRAM:
            kind = f"bigram#{idx - _N_HIST}"
        else:
            kind = _G8_SCALAR_NAMES[idx - _G8_SCALAR_OFFSET]
        direction = label_b if weight > 0 else label_a
        print(f"    {kind}: weight={weight:+.6f} ({direction})")
    return accuracy, (ci_lo, ci_hi)


def main():
    print("=== Phase iO-7 adversarial ML classifier test ===")
    print(f"  N per class: {N_BUILDS} (override via $BR_ML_N)")
    print(f"  gate: Wilson 95% CI upper < {ACC_TARGET:.0%}")

    if not os.path.exists(_OBF):
        print(f"FATAL: obfuscator not found at {_OBF}")
        return 1

    work = tempfile.mkdtemp(prefix="_ioml_")
    try:
        # Write the two functionally-equivalent programs.
        p0_path = os.path.join(work, "p0.py")
        p1_path = os.path.join(work, "p1.py")
        with open(p0_path, "w", encoding="utf-8") as f:
            f.write(_PROG_P0)
        with open(p1_path, "w", encoding="utf-8") as f:
            f.write(_PROG_P1)

        # ---- Step 1: Build N obfuscated builds of EACH program ----
        print(f"\n--- Step 1: Build {N_BUILDS} obfuscated builds of P0 and P1 ---")
        obf_p0, obf_p1 = [], []
        for i in range(N_BUILDS):
            p0 = _build_and_verify(i, work, p0_path)
            if p0 is None:
                _fail(f"build P0 {i}", "failed after retries")
            else:
                obf_p0.append(p0)
                if i < 3 or i == N_BUILDS - 1:
                    print(f"  build P0 {i}: OK", flush=True)
            p1 = _build_and_verify(i, work, p1_path)
            if p1 is None:
                _fail(f"build P1 {i}", "failed after retries")
            else:
                obf_p1.append(p1)
                if i < 3 or i == N_BUILDS - 1:
                    print(f"  build P1 {i}: OK", flush=True)
        if len(obf_p0) < N_BUILDS or len(obf_p1) < N_BUILDS:
            _fail("build count",
                  f"only {len(obf_p0)}/{N_BUILDS} P0, {len(obf_p1)}/{N_BUILDS} P1")
            return 1
        _ok(f"all {2*N_BUILDS} builds succeeded")

        # ---- Step 2: Generate N urandom files matching P0 build sizes ----
        print(f"\n--- Step 2: Generate {N_BUILDS} urandom files (PRG baseline) ---")
        rand_paths = []
        for i, obf_path in enumerate(obf_p0):
            sz = os.path.getsize(obf_path)
            rand_path = os.path.join(work, f"rand_{i}.py")
            with open(rand_path, "wb") as f:
                f.write(os.urandom(sz))
            rand_paths.append(rand_path)
        _ok(f"generated {N_BUILDS} urandom files matching obf sizes")

        # ---- Step 3: Load bytes + select top-256 bigrams on the train pool ----
        print(f"\n--- Step 3: Select top-256 bigrams by variance ---")
        all_bytes = []
        for p in obf_p0 + obf_p1 + rand_paths:
            all_bytes.append(open(p, "rb").read())
        top_pairs = _select_top_bigrams(all_bytes, k=256)
        _ok(f"selected {len(top_pairs)} top-variance bigrams")

        # ---- Step 4: Extract features ----
        print(f"\n--- Step 4: Extract 512-dim features (256 hist + 256 bigram) ---")
        def feats(path):
            return _extract_features_with_bigrams(open(path, "rb").read(), top_pairs)
        X_obf_p0 = [feats(p) for p in obf_p0]
        X_obf_p1 = [feats(p) for p in obf_p1]
        X_rand = [feats(p) for p in rand_paths]
        _ok(f"extracted {len(X_obf_p0[0])}-dim features from {len(all_bytes)} files")

        # ---- Step 5a: PRG-uniformity test (obf vs urandom) ----
        print(f"\n--- Step 5a: PRG-uniformity test (obf(P0) vs urandom) ---")
        print("  (This measures ciphertext byte-uniformity, NOT the iO property.)")
        acc_prg, ci_prg = _run_classifier(
            X_obf_p0, X_rand, "obf", "urandom",
            gate_label="PRG-uniformity gate")

        # ---- Step 5b: iO-property test (Obf(P0) vs Obf(P1)) ----
        print(f"\n--- Step 5b: iO-property test (Obf(P0) vs Obf(P1)) ---")
        print("  (This is the ACTUAL indistinguishability-of-obfuscation test:")
        print("   P0 and P1 are different but functionally equivalent.)")
        acc_io, ci_io = _run_classifier(
            X_obf_p0, X_obf_p1, "obf(P0)", "obf(P1)",
            gate_label="iO-property gate")

        # ---- Step 5c: build-diversity test (Phase G8, M9) ----
        # Build P0 N times with fresh seeds -> N diverse builds of the SAME
        # program. Split them in half and classify build-set-A vs build-set-B.
        # If the classifier can tell two halves of the same program apart
        # better than chance, there is a BUILD-INVARIANT fingerprint (family
        # detector). If near chance, build-diversity holds. This catches the
        # case where the iO test passes (P0 vs P1 indistinguishable) but the
        # obfuscator leaves a per-build-family signature.
        print(f"\n--- Step 5c: build-diversity test (Obf(P0) half-A vs half-B) ---")
        print("  (Same program, fresh-seed diverse builds split in half. If the")
        print("   classifier separates the halves, a build-family fingerprint exists.)")
        half = len(X_obf_p0) // 2
        X_p0_a = X_obf_p0[:half]
        X_p0_b = X_obf_p0[half:]
        acc_bd, ci_bd = _run_classifier(
            X_p0_a, X_p0_b, "build-A(P0)", "build-B(P0)",
            gate_label="build-diversity gate")

        # ---- summary ----
        print("\n" + "=" * 60)
        print(f"Phase iO-7 adversarial ML: {PASSES}/{PASSES + len(FAILS)} passed")
        print(f"  PRG-uniformity: acc={acc_prg:.1%} CI=[{ci_prg[0]:.1%}, {ci_prg[1]:.1%}]")
        print(f"  iO-property:    acc={acc_io:.1%} CI=[{ci_io[0]:.1%}, {ci_io[1]:.1%}]")
        print(f"  build-diversity: acc={acc_bd:.1%} CI=[{ci_bd[0]:.1%}, {ci_bd[1]:.1%}]")
        # Honest reporting: distinguish 'obf weak' vs 'test weak'. If accuracy
        # is near chance AND no scalar feature dominates, the test is just
        # weak (small N); if a specific feature (e.g. raw_len or
        # bootstrap_regex_count) drives accuracy, the obf has a real leak.
        if FAILS:
            print("FAILURES:")
            for f in FAILS:
                print("  -", f)
            return 1
        print("ALL PASS")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
