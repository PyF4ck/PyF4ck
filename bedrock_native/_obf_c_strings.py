"""Build-time string XOR preprocessor for _bedrock_vm.c.

Scans the C source for ``_DS("...")`` markers, XOR-encodes each string
literal with a per-build key, and emits a byte-array form::

    _DS("pickle")  ->  _DS((uint8_t[]){0xAB, 0x34, ...}, 6, 0xCD)

The companion C macro ``_DS`` (defined in _bedrock_vm.c) decrypts the
byte array on a static buffer at runtime, so no plaintext survives in
the compiled .pyd / .so strings window.

Usage (called by _build_system.py)::

    from _obf_c_strings import obfuscate_c_strings
    c_obf, key = obfuscate_c_strings(c_text)
    # write c_obf to temp file, pass key via -DBEDROCK_STR_KEY=0xCD
"""
import hashlib
import re
import sys
from typing import Tuple


def obfuscate_c_strings(c_source: str, key: int = 0) -> Tuple[str, int]:
    """XOR-encode every ``_DS("...")`` string literal in *c_source*.

    Returns ``(modified_source, key)``.  If *key* is 0 a per-build key is
    derived from the SHA-256 of the source (deterministic per source version).
    """
    if key == 0:
        key = hashlib.sha256(c_source.encode("utf-8")).digest()[0]
        if key == 0:
            key = 0x5A  # XOR with 0 is identity; pick a non-zero fallback

    # Pattern: _DS("...")  — match the inner string literal (with escapes).
    # We only transform the *one-argument* form _DS("literal").  After
    # transformation the call becomes _DS((uint8_t[]){...}, N, KEY) — the
    # three-argument form, which the C macro accepts.  We must NOT re-match
    # the three-argument form on a second pass, so the regex anchors on
    # the opening quote right after _DS(.
    pattern = re.compile(r'_DS\(\s*"((?:[^"\\]|\\.)*)"\s*\)')

    def _replace(match: re.Match) -> str:
        escaped = match.group(1)
        # Resolve C escape sequences to actual bytes.
        # unicode_escape handles \n, \t, \\, \xNN, etc.
        try:
            raw = escaped.encode("utf-8").decode("unicode_escape").encode("latin-1")
        except Exception:
            # Fallback: treat as raw UTF-8 bytes
            raw = escaped.encode("utf-8")
        # XOR each byte with the key.
        encoded = [b ^ key for b in raw]
        hex_bytes = ", ".join(f"0x{b:02x}" for b in encoded)
        return f"_DS(((uint8_t[]){{{hex_bytes}}}), {len(encoded)}, 0x{key:02x})"

    result = pattern.sub(_replace, c_source)
    return result, key


def main():
    """CLI: python _obf_c_strings.py <input.c> <output.c> [key_hex]"""
    if len(sys.argv) < 3:
        print("Usage: python _obf_c_strings.py <input.c> <output.c> [key_hex]",
              file=sys.stderr)
        sys.exit(1)
    inp, outp = sys.argv[1], sys.argv[2]
    key = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0
    with open(inp, "r", encoding="utf-8") as f:
        src = f.read()
    result, used_key = obfuscate_c_strings(src, key)
    with open(outp, "w", encoding="utf-8") as f:
        f.write(result)
    print(f"[obf_c_strings] encoded with key 0x{used_key:02x}")


if __name__ == "__main__":
    main()
