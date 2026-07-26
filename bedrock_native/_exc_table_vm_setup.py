"""Build the Phase H.11 exception-table VM extension `_xetvm` in-place.

Run from this directory:
    python _exc_table_vm_setup.py build_ext --inplace

On Windows the SEH exception-driven dispatch path is compiled in by
defining `BR_ENABLE_EXC_VM` in the compiler flags.  On other platforms
(or by editing the define out) the module falls back to direct
call/return dispatch -- the "flag-gate default-OFF" posture.
"""
import os
import sys
from setuptools import setup, Extension

_c_src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_exc_table_vm.c")

if sys.platform == 'win32':
    extra_compile = ['/O2', '/GS-', '/DBR_ENABLE_EXC_VM']
    extra_link = ['/INCREMENTAL:NO']
else:
    # Linux: no SEH; direct-dispatch fallback.  -fno-asynchronous-unwind-tables
    # keeps the .eh_frame small (the analog dispatch substrate is documented
    # but the SEH path is Windows-only here).
    extra_compile = ['-O2', '-fno-asynchronous-unwind-tables',
                     '-fomit-frame-pointer']
    extra_link = ['-Wl,-s']

setup(
    name="_xetvm",
    ext_modules=[Extension("_xetvm", sources=[_c_src],
                           extra_compile_args=extra_compile,
                           extra_link_args=extra_link)],
    version="0.1",
)
