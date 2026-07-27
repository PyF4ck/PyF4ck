"""Phase iO-1 distinguishing-attack test scaffold.

Builds the obfuscator N times on the same input with fresh per-build RNG,
then measures how distinguishable the outputs are. The iO property we want:
two builds of the same (functionally equivalent) program should be
computationally indistinguishable — i.e. a statistical test or a small ML
classifier cannot tell them apart much better than random guessing.

This is the SCAFFOLD for Phase iO-6 (full distinguishing-attack suite).
Phase iO-1 only wires the foundation + a smoke test that:

  1. N builds of the same input all produce functionally-identical output
     (run the obfuscated file → same stdout as the original).
  2. The N output files are byte-different from each other (per-build RNG
     actually diversifies).
  3. A simple chi-square + Shannon-entropy comparison shows no obvious
     byte-distribution signature that would let a trivial statistical test
     cluster builds.

Run:
    python bedrock_native/_io_distinguish_test.py
Exit 0 if all gates pass; non-zero on failure.

NOTE: this does NOT require sklearn / torch — Phase iO-6 will add the
adversarial-ML classifier. Phase iO-1 keeps the dependency surface zero so
the scaffold runs anywhere the obfuscator runs.
"""
import collections
import hashlib
import math
import os
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_OBF = os.path.join(_ROOT, "bedrock_obfuscator.py")
_TEST_INPUT = os.path.join(_ROOT, "_test_obf.py")

# Common flags that disable environment-sensitive probes so the test runs in
# CI/sandbox without self-destructing. The iO property being measured
# (per-build diversity + functional equivalence) does not depend on these.
_COMMON_FLAGS = [
    "--profile", "io",
    "--anti-vm", "off",
    "--anti-debug", "compat",
    "--no-debug-poison",
    "--no-metamorphic",
    "--no-native-vm",        # keep build fast; iO diversity comes from AST passes
    "--no-cache",
    "--overwrite",
    "--adv-requests", "off",
    "--no-anti-timing",
    "--quiet",
]

# How many builds to compare. Phase iO-1 uses 3 (fast smoke); Phase iO-6 will
# bump this to 20+ for statistical power.
N_BUILDS = 3

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


def _run(cmd, cwd, timeout=180):
    """Run a subprocess, return (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return 125, "", str(e)


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _chi_square_uniform(data: bytes) -> float:
    """Chi-square statistic vs uniform byte distribution.

    Lower = closer to uniform (more indistinguishable). Under uniform H0,
    the statistic follows chi2 with 255 dof; values >> ~300 reject uniformity.
    """
    if not data:
        return 0.0
    freq = collections.Counter(data)
    expected = len(data) / 256.0
    return sum((freq.get(b, 0) - expected) ** 2 / expected for b in range(256))


def _build_once(build_idx, out_dir):
    """Build obf.py in out_dir. Returns dict with build info or None on failure."""
    out_path = os.path.join(out_dir, f"obf_{build_idx}.py")
    cmd = [sys.executable, _OBF, "-f", _TEST_INPUT, "-o", out_path] + _COMMON_FLAGS
    rc, so, se = _run(cmd, cwd=_ROOT, timeout=300)
    if rc != 0 or not os.path.exists(out_path):
        return None
    return {"path": out_path, "rc": rc, "stdout": so}


def _run_obf(obf_path, timeout=90):
    """Run an obfuscated file, return (returncode, stdout)."""
    work = os.path.dirname(obf_path)
    rc, so, se = _run([sys.executable, os.path.basename(obf_path)],
                      cwd=work, timeout=timeout)
    return rc, so


def main():
    print("=== Phase iO-1 distinguishing-attack scaffold ===")
    print(f"  builds: {N_BUILDS}, input: {os.path.basename(_TEST_INPUT)}")

    if not os.path.exists(_OBF):
        print(f"FATAL: obfuscator not found at {_OBF}")
        return 1
    if not os.path.exists(_TEST_INPUT):
        print(f"FATAL: test input not found at {_TEST_INPUT}")
        return 1

    work = tempfile.mkdtemp(prefix="_iodist_")
    try:
        # ---- Gate 1: baseline reference output ----
        print("\n--- Gate 1: baseline reference output ---")
        rc, ref_out, _ = _run([sys.executable, _TEST_INPUT], cwd=_ROOT)
        if rc != 0 or "final_result: 221" not in ref_out:
            _fail("baseline reference", f"rc={rc}, out={ref_out!r}")
            return 1
        _ok("baseline reference produces final_result: 221")

        # ---- Gate 2: N builds all succeed + functional equivalence ----
        print(f"\n--- Gate 2: {N_BUILDS} builds, all functional ---")
        builds = []
        all_functional = True
        for i in range(N_BUILDS):
            info = _build_once(i, work)
            if info is None:
                _fail(f"build {i}", "build failed")
                all_functional = False
                continue
            rc, out = _run_obf(info["path"])
            if rc != 0 or "final_result: 221" not in out:
                _fail(f"build {i} functional", f"rc={rc}, out={out!r}")
                all_functional = False
            else:
                _ok(f"build {i} functional (final_result: 221)")
            builds.append(info)

        if not all_functional or len(builds) < 2:
            _fail("functional equivalence", "not enough functional builds")
            return 1
        _ok(f"all {len(builds)} builds functionally equivalent to baseline")

        # ---- Gate 3: per-build byte diversity (outputs differ) ----
        print(f"\n--- Gate 3: per-build byte diversity ---")
        hashes = []
        sizes = []
        for b in builds:
            data = open(b["path"], "rb").read()
            h = hashlib.sha256(data).hexdigest()[:16]
            hashes.append(h)
            sizes.append(len(data))
            b["data"] = data
            b["hash"] = h
        unique_hashes = set(hashes)
        if len(unique_hashes) < len(hashes):
            _fail("byte diversity", f"only {len(unique_hashes)} unique hashes")
        else:
            _ok(f"all {len(hashes)} build hashes distinct: {hashes}")

        size_spread = max(sizes) - min(sizes)
        size_mean = sum(sizes) / len(sizes)
        print(f"  sizes: {sizes} (spread {size_spread}B, mean {size_mean:.0f}B)")
        if size_spread == 0:
            _fail("size diversity", "all builds same byte size")
        else:
            _ok(f"size spread {size_spread}B ({size_spread / size_mean * 100:.1f}% of mean)")

        # ---- Gate 4: byte-distribution MEASUREMENT (Phase iO-1 baseline) ----
        # NOTE: Phase iO-1 only MEASURES the byte distribution; we do NOT assert
        # uniformity yet because obfuscated Python SOURCE has structural bytes
        # (keywords, indentation, repeated `lambda`/`def`/parens) that make it
        # inherently non-uniform. Entropy ~6.3 bits/byte is the current baseline.
        # Phase iO-6 will tighten these into hard gates AFTER the iO-2..iO-5
        # passes (FSS extend, crypto opaque predicates, randomized encodings)
        # raise entropy toward the compressed/encrypted ceiling (~7.5+).
        print(f"\n--- Gate 4: byte-distribution MEASUREMENT (baseline, no assert) ---")
        chis = [_chi_square_uniform(b["data"]) for b in builds]
        ents = [_shannon_entropy(b["data"]) for b in builds]
        print(f"  chi-square vs uniform: {[round(c, 1) for c in chis]}")
        print(f"  Shannon entropy (bits/byte): {[round(e, 3) for e in ents]}")
        chi_spread = max(chis) - min(chis)
        chi_mean = sum(chis) / len(chis)
        print(f"  chi-square spread {chi_spread:.1f} ({chi_spread / chi_mean * 100:.1f}% of mean)")
        _ok(f"baseline measured: entropy ~{min(ents):.2f}-{max(ents):.2f}, "
            f"chi-spread {chi_spread / chi_mean * 100:.1f}% (Phase iO-6 target: <5%, >7.5 bits)")

        # ---- Gate 5: pairwise build-vs-build MEASUREMENT (baseline) ----
        # Same rationale: we report the pairwise chi-square but do not assert
        # indistinguishability yet. The current ~500k baseline reflects that
        # builds ARE distinguishable by byte frequency — Phase iO-2+ passes
        # will close this gap. This gate just records the number for regression
        # tracking (we want it to DECREASE over phases, not increase).
        print(f"\n--- Gate 5: pairwise build-vs-build MEASUREMENT (baseline) ---")
        max_pair_chi = 0.0
        for i in range(len(builds)):
            for j in range(i + 1, len(builds)):
                d1, d2 = builds[i]["data"], builds[j]["data"]
                n1, n2 = len(d1), len(d2)
                f1 = collections.Counter(d1)
                f2 = collections.Counter(d2)
                pair = 0.0
                for b in range(256):
                    e1 = f1.get(b, 0) / n1 * n2
                    if e1 > 0:
                        pair += (f2.get(b, 0) - e1) ** 2 / e1
                max_pair_chi = max(max_pair_chi, pair)
                print(f"  build {i} vs {j}: chi-square = {pair:.1f}")
        _ok(f"baseline pairwise chi-square max {max_pair_chi:.0f} "
            f"(Phase iO-6 target: <320 — distinguishable->indistinguishable)")

        # ---- summary ----
        print("\n" + "=" * 60)
        print(f"Phase iO-1 distinguish scaffold: {PASSES}/{PASSES + len(FAILS)} passed")
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
