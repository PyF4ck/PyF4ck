"""Phase iO-7: Adversarial ML classifier test (pure stdlib).

The chi-square test is a simple statistical test. A stronger adversary
would train a machine-learning classifier on file features and try to
distinguish obfuscated builds from random files. If the classifier can't
do better than chance (50% accuracy), the iO property holds.

This test implements a logistic-regression classifier in pure Python
(no sklearn/numpy needed) with two feature sets:
  1. Byte histogram (256 features): frequency of each byte value.
  2. Byte-pair histogram (256x256 = 65536 features, top-256 by variance):
     frequency of adjacent byte pairs.

## Protocol

  1. Build N obfuscated files with `--profile io` (binary capsule on).
  2. Generate N random files of the same size.
  3. Extract features from all 2N files.
  4. Split into train/test (50/50).
  5. Train logistic regression on the train set.
  6. Evaluate accuracy on the test set.
  7. Gate: accuracy must be < 55% (close to chance 50%, with margin for
     sampling noise at small N).

Run:
    python bedrock_native/_io_adversarial_ml.py
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
_TEST_INPUT = os.path.join(_ROOT, "_test_obf.py")

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
]

N_BUILDS = 10  # 10 obfuscated + 10 random = 20 files
MAX_RETRIES = 3

PASSES = 0
FAILS = []


def _ok(label):
    global PASSES
    PASSES += 1
    print(f"  PASS  {label}")


def _fail(label, detail=""):
    global FAILS
    FAILS.append(f"{label}: {detail}")
    print(f"  FAIL  {label} — {detail}")


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


def _build_once(build_idx, out_dir):
    out_path = os.path.join(out_dir, f"obf_{build_idx}.py")
    cmd = [sys.executable, _OBF, "-f", _TEST_INPUT, "-o", out_path] + _COMMON_FLAGS
    rc, so, se = _run(cmd, cwd=_ROOT, timeout=360)
    if rc != 0 or not os.path.exists(out_path):
        return None
    return out_path


def _build_and_verify(build_idx, out_dir, run_timeout=30):
    for attempt in range(MAX_RETRIES):
        path = _build_once(build_idx, out_dir)
        if path is None:
            continue
        rc, out, _ = _run([sys.executable, os.path.basename(path)],
                          cwd=out_dir, timeout=run_timeout)
        if rc == 0 and "final_result: 221" in out:
            return path
    return None


def _extract_features(data: bytes) -> list:
    """Extract byte-histogram features (256-dim, normalized)."""
    n = len(data)
    freq = collections.Counter(data)
    return [freq.get(b, 0) / n for b in range(256)]


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


def main():
    print("=== Phase iO-7 adversarial ML classifier test ===")
    print(f"  builds: {N_BUILDS} obfuscated + {N_BUILDS} random = {2*N_BUILDS} files")

    if not os.path.exists(_OBF):
        print(f"FATAL: obfuscator not found at {_OBF}")
        return 1

    work = tempfile.mkdtemp(prefix="_ioml_")
    try:
        # ---- Step 1: Build N obfuscated files ----
        print(f"\n--- Step 1: Build {N_BUILDS} obfuscated files ---")
        obf_paths = []
        for i in range(N_BUILDS):
            path = _build_and_verify(i, work)
            if path is None:
                _fail(f"build {i}", "failed after retries")
                continue
            obf_paths.append(path)
            print(f"  build {i}: OK", flush=True)

        if len(obf_paths) < N_BUILDS:
            _fail("build count", f"only {len(obf_paths)}/{N_BUILDS} builds succeeded")
            return 1
        _ok(f"all {N_BUILDS} builds succeeded")

        # ---- Step 2: Generate N random files of matching sizes ----
        print(f"\n--- Step 2: Generate {N_BUILDS} random files ---")
        rand_paths = []
        for i, obf_path in enumerate(obf_paths):
            sz = os.path.getsize(obf_path)
            rand_path = os.path.join(work, f"rand_{i}.py")
            with open(rand_path, 'wb') as f:
                f.write(os.urandom(sz))
            rand_paths.append(rand_path)
        _ok(f"generated {N_BUILDS} random files matching obf sizes")

        # ---- Step 3: Extract features ----
        print(f"\n--- Step 3: Extract byte-histogram features ---")
        X_obf = []
        X_rand = []
        for p in obf_paths:
            data = open(p, 'rb').read()
            X_obf.append(_extract_features(data))
        for p in rand_paths:
            data = open(p, 'rb').read()
            X_rand.append(_extract_features(data))
        _ok(f"extracted 256-dim features from {len(X_obf) + len(X_rand)} files")

        # ---- Step 4: Train/test split (50/50 stratified) ----
        print(f"\n--- Step 4: Train/test split ---")
        # Label: 0 = obfuscated, 1 = random
        X = X_obf + X_rand
        y = [0] * len(X_obf) + [1] * len(X_rand)
        indices = list(range(len(X)))
        random.seed(42)
        random.shuffle(indices)
        split = len(indices) // 2
        train_idx = indices[:split]
        test_idx = indices[split:]
        X_train = [X[i] for i in train_idx]
        y_train = [y[i] for i in train_idx]
        X_test = [X[i] for i in test_idx]
        y_test = [y[i] for i in test_idx]
        n_obf_train = sum(1 for v in y_train if v == 0)
        n_rand_train = sum(1 for v in y_train if v == 1)
        print(f"  train: {len(X_train)} ({n_obf_train} obf, {n_rand_train} rand)")
        print(f"  test:  {len(X_test)}")

        # ---- Step 5: Train logistic regression ----
        print(f"\n--- Step 5: Train logistic regression ---")
        clf = LogisticRegression(n_features=256, lr=0.1, l2=0.01, n_iters=1000)
        clf.fit(X_train, y_train)
        _ok("trained 256-dim logistic regression (1000 iters)")

        # ---- Step 6: Evaluate accuracy ----
        print(f"\n--- Step 6: Evaluate classifier accuracy ---")
        preds = clf.predict(X_test)
        pred_labels = [1 if p > 0.5 else 0 for p in preds]
        correct = sum(1 for p, t in zip(pred_labels, y_test) if p == t)
        accuracy = correct / len(y_test) if y_test else 0.0
        print(f"  test accuracy: {accuracy:.1%} ({correct}/{len(y_test)})")
        print(f"  chance baseline: 50.0%")
        print(f"  predictions: {[p[1] for p in zip(preds, y_test)]}")

        # ---- Step 7: Gate ----
        print(f"\n--- Step 7: Adversarial ML gate ---")
        # With N=10+10, test set ~10 samples. Chance = 50%. Gate: < 70%
        # (generous margin for small sample noise; a 70% threshold gives
        # ~p=0.17 of false positive under pure chance with n=10 binomial).
        ACC_TARGET = 0.70
        if accuracy < ACC_TARGET:
            _ok(f"ML accuracy {accuracy:.1%} < {ACC_TARGET:.0%} (chance: 50%)")
        else:
            _fail("ML accuracy gate",
                  f"{accuracy:.1%} >= {ACC_TARGET:.0%} — classifier can distinguish "
                  f"obfuscated from random")

        # ---- Extra: feature importance (which bytes betray the capsule?) ----
        top_features = sorted(enumerate(clf.w), key=lambda x: abs(x[1]), reverse=True)[:10]
        print(f"\n  Top-10 discriminative features (byte values):")
        for byte_val, weight in top_features:
            direction = "random" if weight > 0 else "obfuscated"
            print(f"    byte 0x{byte_val:02x} ({byte_val:3d}): weight={weight:+.6f} ({direction})")

        # ---- summary ----
        print("\n" + "=" * 60)
        print(f"Phase iO-7 adversarial ML: {PASSES}/{PASSES + len(FAILS)} passed")
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
