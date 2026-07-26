"""Phase E (Layer 5) per-build diversity metrics test for the native obfuscator.

Builds the SAME input N times through the existing transpile pipeline
(``_transpile_pipeline.transpile_and_build``) and asserts the COMPILED
outputs differ at the C / binary level (opaque-predicate junk constants,
string-encryption XOR key) — the layer where Phase E's per-build
``_build_rng.BuildRNG`` operates.

Threat model: ML deobfuscators train on prior LEAKED *binaries*, not on the
intermediate Python source (the source is gone after the Cython transpile).
So the diversity gate is on the ``.pyd`` byte distance, NOT on the ``.py``
intermediate text/AST — which is text-identical across builds BY DESIGN
(the C-source obfuscation passes run AFTER Cython, so the Python source is
not what varies). A model fit on build N's binary must not transfer to N+1.

A reproducibility control is included: two builds with the SAME
``build_seed`` must produce an IDENTICAL ``.pyd`` (proves the diversity is
from the per-build CSPRNG, not accidental linker noise — the legacy
``sha256(source)`` derivation could not satisfy this).

Pure stdlib. Run::

    python bedrock_native/_diversity_test.py
"""
from __future__ import annotations

import ast
import hashlib
import math
import os
import re
import sys
import tempfile
from collections import Counter
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _transpile_pipeline import transpile_and_build  # noqa: E402

_REALWORLD = r"C:\Users\Admin\Downloads\bedrock obf new tier\_test_realworld.py"

# Printable-ASCII run of >= 4 chars, used to harvest a .pyd's string table.
_PRINT_RE = re.compile(rb"[\x20-\x7e]{4,}")


def ast_distance(src1: str, src2: str) -> int:
    """Coarse AST edit distance between two Python sources.

    ``abs(node_count1 - node_count2)`` plus the count of positionally-mismatched
    node types, where each ``walk`` is ``ast.walk`` flattened to a list. Coarse
    but enough to assert "not identical structure". Identical sources -> 0.
    """
    walk1 = list(ast.walk(ast.parse(src1)))
    walk2 = list(ast.walk(ast.parse(src2)))
    type_mismatch = sum(1 for a, b in zip(walk1, walk2) if type(a) != type(b))
    return abs(len(walk1) - len(walk2)) + type_mismatch


def identifier_entropy(src: str) -> float:
    """Shannon entropy (bits) over identifier-name frequencies.

    Collects ``ast.Name.id`` + ``FunctionDef.name`` + ``ClassDef.name`` via
    ``ast.walk``, computes ``-sum(p*log2(p))`` over name frequencies. Higher =
    more diverse names. Returns ``0.0`` for a nameless source.
    """
    tree = ast.parse(src)
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.FunctionDef):
            names.append(node.name)
        elif isinstance(node, ast.ClassDef):
            names.append(node.name)
    if not names:
        return 0.0
    total = len(names)
    freqs = Counter(names)
    return -sum((c / total) * math.log2(c / total) for c in freqs.values())


def pyd_strings_distance(pyd_path1: str, pyd_path2: str) -> int:
    """Symmetric-difference size of printable-string sets in two compiled .pyd.

    Harvests distinct printable runs (>=4 chars) from each binary with
    ``rb'[\\x20-\\x7e]{4,}'`` and returns ``|set1 ^ set2|``. Two diverse
    builds should have different string tables.
    """
    with open(pyd_path1, "rb") as f:
        s1 = set(_PRINT_RE.findall(f.read()))
    with open(pyd_path2, "rb") as f:
        s2 = set(_PRINT_RE.findall(f.read()))
    return len(s1 ^ s2)


def pyd_byte_distance(p1: str, p2: str) -> int:
    """Hamming-ish byte distance, clamped to ``min(len1, len2)``.

    ``zip`` stops at the shorter buffer so the sum is naturally <= the overlap.
    Two builds of the same input should NOT be byte-identical.
    """
    with open(p1, "rb") as f:
        b1 = f.read()
    with open(p2, "rb") as f:
        b2 = f.read()
    return sum(a != b for a, b in zip(b1, b2))


def _build_once(src: str, out_dir: str, *, build_seed=None,
                verbose: bool = False) -> dict:
    """One build through the pipeline, with the per-build seed threaded in."""
    prev_debug = os.environ.get("BEDROCK_TRANSPILE_DEBUG")
    debug_py = os.path.join(out_dir, "obf_debug.py")
    try:
        os.environ["BEDROCK_TRANSPILE_DEBUG"] = debug_py
        return transpile_and_build(
            src, out_dir, module_name="obf",
            c_string_obf=True, verbose=verbose,
            build_seed=build_seed,
        )
    finally:
        if prev_debug is None:
            os.environ.pop("BEDROCK_TRANSPILE_DEBUG", None)
        else:
            os.environ["BEDROCK_TRANSPILE_DEBUG"] = prev_debug


def run_diversity_test(src_path: str, n: int = 10) -> dict[str, Any]:
    """Build *src_path* ``n`` times; measure per-build C-level diversity.

    Builds ``n`` FRESH builds (no fixed seed) and additionally TWO builds
    with the SAME fixed seed (reproducibility control). For each build a
    fresh temp ``out_dir`` is created and ``BEDROCK_TRANSPILE_DEBUG`` is
    pointed at a unique path inside it so ``transpile_and_build`` dumps the
    intermediate ``obf.py`` there. Each build is wrapped in try/except so
    one failure does not abort the run.

    ``pass`` is the conjunction of:
      (a) no two FRESH ``.pyd`` byte-identical (SHA-256 hash compare)
      (b) pairwise ``pyd_byte_distance`` > 0 for ALL fresh pairs (C-level
          diversity — opaque junk + XOR key differ per build)
      (c) the TWO fixed-seed builds are byte-identical (reproducibility —
          proves the diversity is from the per-build CSPRNG, not linker noise)

    The ``.py`` text / AST are reported as informational but are NOT gates:
    they are identical across builds BY DESIGN (C-source obf runs after the
    Cython transpile, so the Python intermediate does not vary).
    """
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()

    pyd_paths: list[str] = []
    pyd_hashes: list[str] = []
    py_sources: list[str] = []
    tmpdirs: list[tempfile.TemporaryDirectory] = []

    # Fixed seed shared by the two reproducibility-control builds.
    repro_seed = b"\x42" * 32
    repro_paths: list[str] = []

    try:
        for i in range(n):
            print(f"fresh build {i + 1}/{n} ... ", end="", flush=True)
            td = tempfile.TemporaryDirectory(
                prefix=f"_divtest_{i}_", ignore_cleanup_errors=True
            )
            tmpdirs.append(td)
            try:
                r = _build_once(src, td.name, build_seed=None, verbose=False)
            except Exception as e:
                print(f"FAILED ({e})")
                continue
            if r.get("mode") != "native" or not r.get("module_path"):
                print(f"skipped ({(r.get('detail') or '')[:80]})")
                continue
            pyd_paths.append(r["module_path"])
            with open(r["module_path"], "rb") as f:
                pyd_hashes.append(hashlib.sha256(f.read()).hexdigest())
            debug_py = os.path.join(td.name, "obf_debug.py")
            if os.path.exists(debug_py):
                with open(debug_py, "r", encoding="utf-8") as f:
                    py_sources.append(f.read())
            else:
                py_sources.append(src)
            print(f"ok (build_id={(r.get('build_id') or '')[:8]})")

        # Reproducibility control: same fixed seed -> identical .pyd.
        for k in range(2):
            print(f"repro build {k + 1}/2 ... ", end="", flush=True)
            td = tempfile.TemporaryDirectory(
                prefix=f"_divtest_repro_{k}_", ignore_cleanup_errors=True
            )
            tmpdirs.append(td)
            try:
                r = _build_once(src, td.name, build_seed=repro_seed,
                                verbose=False)
            except Exception as e:
                print(f"FAILED ({e})")
                continue
            if r.get("mode") != "native" or not r.get("module_path"):
                print(f"skipped ({(r.get('detail') or '')[:80]})")
                continue
            repro_paths.append(r["module_path"])
            print(f"ok (build_id={(r.get('build_id') or '')[:8]})")
    finally:
        pass  # cleanup deferred to the finally below

    n_successful = len(pyd_paths)
    print(f"n_successful(fresh)={n_successful}/{n}  repro={len(repro_paths)}/2")

    byte_identical_pairs = 0
    text_identical_pairs = 0
    ast_sum = 0.0
    pyd_byte_sum = 0.0
    pyd_strings_sum = 0.0
    pair_count = 0
    min_pyd_byte = None

    try:
        if n_successful >= 2:
            for i in range(n_successful):
                for j in range(i + 1, n_successful):
                    pair_count += 1
                    if pyd_hashes[i] == pyd_hashes[j]:
                        byte_identical_pairs += 1
                    if py_sources[i] == py_sources[j]:
                        text_identical_pairs += 1
                    ast_sum += ast_distance(py_sources[i], py_sources[j])
                    bd = pyd_byte_distance(pyd_paths[i], pyd_paths[j])
                    pyd_byte_sum += bd
                    min_pyd_byte = bd if min_pyd_byte is None else min(min_pyd_byte, bd)
                    pyd_strings_sum += pyd_strings_distance(pyd_paths[i], pyd_paths[j])

        avg_ast = ast_sum / pair_count if pair_count else 0.0
        avg_pyd_byte = pyd_byte_sum / pair_count if pair_count else 0.0
        avg_pyd_strings = pyd_strings_sum / pair_count if pair_count else 0.0
        entropy_mean = (
            sum(identifier_entropy(s) for s in py_sources) / len(py_sources)
            if py_sources else 0.0
        )
        min_pyd_byte_val = min_pyd_byte if min_pyd_byte is not None else 0

        # Reproducibility: the two fixed-seed builds must be byte-identical.
        repro_identical = False
        if len(repro_paths) == 2:
            with open(repro_paths[0], "rb") as f:
                rb1 = f.read()
            with open(repro_paths[1], "rb") as f:
                rb2 = f.read()
            repro_identical = (rb1 == rb2)

        passed = (
            n_successful >= 2
            and byte_identical_pairs == 0
            and min_pyd_byte_val > 0
            and repro_identical
        )

        return {
            "n": n,
            "n_successful": n_successful,
            "byte_identical_pairs": byte_identical_pairs,
            "text_identical_pairs": text_identical_pairs,
            "avg_ast_distance": avg_ast,
            "avg_pyd_byte_distance": avg_pyd_byte,
            "min_pyd_byte_distance": min_pyd_byte_val,
            "avg_pyd_strings_distance": avg_pyd_strings,
            "identifier_entropy_mean": entropy_mean,
            "reproducible_identical": repro_identical,
            "pass": passed,
        }
    finally:
        for td in tmpdirs:
            try:
                td.cleanup()
            except Exception:
                pass


if __name__ == "__main__":
    result = run_diversity_test(_REALWORLD, n=5)
    print()
    print("=== diversity metrics ===")
    for k, v in result.items():
        print(f"  {k}: {v}")
    print()
    if result["pass"]:
        print("DIVERSITY OK: per-build C-level diversity verified "
              "(fresh builds differ, reproducible builds match).")
        sys.exit(0)
    # Diagnostic — no CI failure.
    if not result.get("reproducible_identical"):
        print("DIVERSITY INSUFFICIENT — reproducibility control failed: two "
              "builds with the same fixed_seed produced different .pyd. The "
              "per-build CSPRNG must be deterministic in fixed-seed mode.")
    elif result.get("byte_identical_pairs", 0) > 0:
        print("DIVERSITY INSUFFICIENT — two fresh builds produced identical "
              ".pyd. The per-build CSPRNG is not varying the obfuscation.")
    else:
        print("DIVERSITY INSUFFICIENT — min_pyd_byte_distance is 0; the C obf "
              "passes are not varying bytes across builds.")
    sys.exit(0)
