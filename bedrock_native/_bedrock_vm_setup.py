"""Build the BedrockVM C interpreter extension `_xvm` in-place.

Run from this directory:
    python _bedrock_vm_setup.py build_ext --inplace

This standalone build script also runs the string obfuscation preprocessor
(_obf_c_strings.py) to XOR-encode all _DS("...") string literals before
compilation, matching the production build path in _build_system.py.
"""
import os
import sys
import tempfile
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext as _build_ext

# Run the string obfuscation preprocessor on the C source before compilation.
_c_src = os.path.join(os.path.dirname(__file__), "_bedrock_vm.c")
_c_obf_path = _c_src + ".obf.c"

try:
    from _obf_c_strings import obfuscate_c_strings
    with open(_c_src, "r", encoding="utf-8") as _f:
        _c_text = _f.read()
    _c_obf, _str_key = obfuscate_c_strings(_c_text)
    with open(_c_obf_path, "w", encoding="utf-8") as _f:
        _f.write(_c_obf)
    print(f"[setup] C strings XOR-encoded (key=0x{_str_key:02x})")
    _build_source = _c_obf_path
except Exception as _e:
    print(f"[setup] string obf skipped ({_e}), using plaintext")
    _build_source = _c_src

# Compiler flags: optimize + strip symbols for harder RE.
if sys.platform == 'win32':
    extra_compile = ['/O2', '/GS-']
    extra_link = ['/INCREMENTAL:NO']
else:
    extra_compile = ['-O2', '-fno-asynchronous-unwind-tables',
                     '-fomit-frame-pointer']
    extra_link = ['-Wl,-s']

setup(
    name="_xvm",
    ext_modules=[Extension("_xvm", sources=[_build_source],
                           extra_compile_args=extra_compile,
                           extra_link_args=extra_link)],
    version="0.1",
)
