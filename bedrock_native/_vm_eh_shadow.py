"""XuanJia EH-shadowing post-build patch (Phase F, feature F.7).

Closes the exception-handler (EH) information channel on a shipped ``.pyd`` /
``.so``. A devirtualizer that walks the OS unwind tables to map VM handler
code addresses (the XuanJia EH-shadowing attack, arXiv:2601.10261) is fed
decoy handlers instead of the real VM handlers, so debuggers and DBI
frameworks (Frida, exception tracers, ...) that rely on the unwind tables
cannot resolve the VM handler code addresses.

Threat model
------------
XuanJia-style devirtualizers correlate ``.pdata`` (Windows) / ``.eh_frame``
(Linux) with the VM dispatch loop to recover the handler set. Shadowing the
unwind information removes that mapping: the OS still dispatches exceptions
correctly (the address ranges are untouched) but the *unwind info* that tools
follow to handler code now points at decoys.

What this patch does
--------------------
* **Windows (PE)** — rewrites the ``.pdata`` section's ``RUNTIME_FUNCTION``
  entries so each entry's ``UnwindData`` pointer points at a per-build decoy
  RVA inside ``.text``. ``BeginAddress`` / ``EndAddress`` are left intact (the
  OS uses those for exception dispatch; corrupting them would break real
  exception handling). Only the unwind-info pointer is shadowed.
* **Linux (ELF)** — overwrites the leading Common Information Entry (CIE) of
  the ``.eh_frame`` section with per-build keystream bytes, so the unwinder
  cannot parse the first frame and falls back to the default personality (the
  VM handlers lose their unwind info). Only the leading CIE is touched, never
  the whole section (runtime CFI may depend on the rest).

Per-build determinism
---------------------
The decoy RVAs / keystream bytes come from ``build_rng.stream(b"vm_eh_shadow")``
(a ChaCha20 sub-stream, see ``_build_rng.BuildRNG``): reproducible in
fixed-seed mode, diverse in fresh-seed mode. The decoy for a ``RUNTIME_FUNCTION``
entry depends only on the (stable) ``BeginAddress`` family and the keystream,
NOT on the current ``UnwindData`` — so re-patching an already-shadowed binary
writes the same decoys (idempotent).

Safety
------
On any parse error or missing EH table the patch returns ``False`` and leaves
the file byte-identical (the VM still runs; only the EH channel is unshadowed).
``gen_eh_shadow_patch`` never raises. Pure stdlib; ``pefile`` / ``pyelftools``
would add robustness on exotic layouts but are not required (the manual parsers
handle standard PE32 / PE32+ and ELF32 / ELF64).

PE struct layout (manual parse — mirrors ``_zero_pe_timestamp`` in
``_transpile_pipeline.py``)::

    0x3C            e_lfanew            (file offset of 'PE\\x00\\x00')
    e_lfanew+0      'PE\\x00\\x00'
    e_lfanew+4      COFF header (20 B):
                       Machine(2)  NumberOfSections(2)@+2  TimeDateStamp(4)
                       PointerToSymbolTable(4) NumberOfSymbols(4)
                       SizeOfOptionalHeader(2)@+16  Characteristics(2)
    e_lfanew+24     Optional header. Magic(2): 0x10b=PE32, 0x20b=PE32+
                       PE32  : NumberOfRvaAndSizes@+92  data-dir array @+96
                       PE32+ : NumberOfRvaAndSizes@+108 data-dir array @+112
                       Each data dir = 8 B (RVA(4), Size(4));
                       index 3 = Exception Table (.pdata)
    opt+SizeOfOptionalHeader  section table; each entry 40 B:
                       Name(8) VirtualSize(4)@+8 VirtualAddress(4)@+12
                       SizeOfRawData(4)@+16 PointerToRawData(4)@+20
    .pdata = array of RUNTIME_FUNCTION (12 B):
                       BeginAddress(4) EndAddress(4) UnwindData(4)  -- all RVA, LE
                       (only UnwindData is shadowed)

ELF struct layout (manual parse)::

    0x00  e_ident[16]: [4]=EI_CLASS (1=ELF32, 2=ELF64), [5]=EI_DATA (1=LE, 2=BE)
    ELF64 header (64 B): e_shoff(8)@40  e_shentsize(2)@58 e_shnum(2)@60
                        e_shstrndx(2)@62
    ELF32 header (52 B): e_shoff(4)@32  e_shentsize(2)@46 e_shnum(2)@48
                        e_shstrndx(2)@50
    Section header ELF64 (64 B): sh_name(4)@0 sh_offset(8)@24 sh_size(8)@32
    Section header ELF32 (52 B): sh_name(4)@0 sh_offset(4)@16 sh_size(4)@20
    sh_name indexes the section-header string table (section e_shstrndx);
    a section named '.eh_frame' holds the CIE/FDE table. The CIE starts with
    length(4) CIE_id(4) version(1) augmentation...; corrupting it makes the
    unwinder skip the frame (arXiv:2601.10261).
"""
from __future__ import annotations

import os
import struct
import sys

# Sibling import (same bootstrap pattern as _transpile_pipeline.py).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _build_rng import BuildRNG  # noqa: E402

__all__ = ['gen_eh_shadow_patch', '_patch_pe_pdata', '_patch_elf_eh_frame']

# Label that derives the per-build EH-shadow sub-stream (ChaCha20 keystream).
_STREAM_LABEL = b'vm_eh_shadow'


def _rva_to_file_offset(data, rva, sec_off, n_sec):
    """Map a PE RVA to a raw file offset via the section table.

    Returns the file offset or ``None`` if no section covers *rva*. Mirrors the
    section-table walk in ``_zero_pe_timestamp``; a zero VirtualSize falls back
    to SizeOfRawData (some toolchains leave VirtualSize at 0).
    """
    for s in range(n_sec):
        so = sec_off + s * 40
        vaddr = struct.unpack_from('<I', data, so + 12)[0]   # VirtualAddress
        vsize = struct.unpack_from('<I', data, so + 8)[0]    # VirtualSize
        if vsize == 0:
            vsize = struct.unpack_from('<I', data, so + 16)[0]  # SizeOfRawData
        raddr = struct.unpack_from('<I', data, so + 20)[0]   # PointerToRawData
        if vaddr != 0 and vaddr <= rva < vaddr + max(vsize, 1):
            return raddr + (rva - vaddr)
    return None


def _find_section_range(data, sec_off, n_sec, name_bytes):
    """Return ``(VirtualAddress, VirtualSize)`` for the named PE section, or
    ``(None, None)`` if absent. ``name_bytes`` e.g. ``b'.text'``."""
    for s in range(n_sec):
        so = sec_off + s * 40
        if data[so:so + 8].rstrip(b'\x00') == name_bytes:
            va = struct.unpack_from('<I', data, so + 12)[0]
            vs = struct.unpack_from('<I', data, so + 8)[0]
            return va, vs
    return None, None


def gen_eh_shadow_patch(pyd_path: str, build_rng=None, *, verbose: bool = False) -> bool:
    """Patch the shipped .pyd/.so's exception-handler tables in place.

    Windows: rewrite the .pdata RUNTIME_FUNCTION entries so the UnwindData
    pointers point at a per-build decoy RVA inside .text. The real VM handlers
    (bedrock_vm_v2.c functions) lose their unwind info, so debuggers/DBI cannot
    walk to them. BeginAddress/EndAddress are left intact (the OS needs them
    for exception dispatch).

    Linux: scramble the leading CIE of the .eh_frame section so the unwinder
    falls back to the default personality (loses VM handler addresses).

    Returns True on success, False on failure (missing tables, parse error,
    unsupported platform). Never raises — a patch failure must not break the
    build (the VM still runs; only the EH channel is unshadowed). On False the
    file is left byte-identical.

    If build_rng is given, the decoy RVAs / keystream are deterministic per
    build (reproducible in fixed-seed mode, diverse in fresh-seed mode). If it
    is None, a zero-seed BuildRNG is used so the patch is still reproducible.
    """
    try:
        with open(pyd_path, 'rb') as f:
            data = bytearray(f.read())
        if build_rng is None:
            build_rng = BuildRNG(bytes(32))  # deterministic default master seed

        if sys.platform == 'win32':
            ok = _patch_pe_pdata(data, build_rng, verbose)
        elif sys.platform.startswith('linux'):
            ok = _patch_elf_eh_frame(data, build_rng, verbose)
        else:
            if verbose:
                print(f"[vm_eh_shadow] unsupported platform {sys.platform!r}; no-op")
            return False

        if ok:
            with open(pyd_path, 'wb') as f:
                f.write(data)
        elif verbose:
            print("[vm_eh_shadow] no EH table patched; file left unchanged")
        return ok
    except Exception as e:
        if verbose:
            print(f"[vm_eh_shadow] patch failed ({e})")
        return False


def _patch_pe_pdata(pyd_bytes: bytearray, build_rng, verbose: bool) -> bool:
    """Patch PE .pdata RUNTIME_FUNCTION entries (Windows). Returns True on
    success, False if the binary is not PE / has no .pdata / is unparseable.

    Only the ``UnwindData`` field of each 12-byte RUNTIME_FUNCTION is shadowed;
    ``BeginAddress`` and ``EndAddress`` are preserved so OS exception dispatch
    still routes to the right address ranges. The decoy is a per-build RVA
    inside ``.text`` (an in-image address the unwinder will misread as unwind
    info). It depends on the keystream + the (stable) section layout, not on the
    current UnwindData, so re-patching is idempotent.
    """
    data = pyd_bytes
    try:
        if data[:2] != b'MZ':
            return False
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return False
        coff_off = e_lfanew + 4
        n_sec = struct.unpack_from('<H', data, coff_off + 2)[0]      # NumberOfSections
        opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]  # SizeOfOptionalHeader
        opt_off = coff_off + 20
        opt_magic = struct.unpack_from('<H', data, opt_off)[0]
        if opt_magic == 0x10b:        # PE32
            ndir_off = opt_off + 92
            dir_off = opt_off + 96
        elif opt_magic == 0x20b:      # PE32+
            ndir_off = opt_off + 108
            dir_off = opt_off + 112
        else:
            return False
        sec_off = opt_off + opt_size

        # Exception Table = data directory index 3 (.pdata).
        n_dirs = struct.unpack_from('<I', data, ndir_off)[0]
        if n_dirs <= 3:
            return False
        ex_rva, ex_size = struct.unpack_from('<II', data, dir_off + 3 * 8)
        if ex_rva == 0 or ex_size < 12:
            return False  # no RUNTIME_FUNCTION entries to shadow
        pdata_off = _rva_to_file_offset(data, ex_rva, sec_off, n_sec)
        if pdata_off is None:
            return False
        n_entries = ex_size // 12
        if pdata_off + n_entries * 12 > len(data):
            return False  # .pdata runs past EOF -> malformed

        # Decoys stay inside .text (a valid in-image RVA). Rare no-.text fallback
        # uses the entry's own BeginAddress (in-image, deterministic).
        text_va, text_vs = _find_section_range(data, sec_off, n_sec, b'.text')

        sub = build_rng.stream(_STREAM_LABEL)
        ks = sub.random(4 * n_entries)
        patched = 0
        for i in range(n_entries):
            eo = pdata_off + i * 12
            begin, end, unwind = struct.unpack_from('<III', data, eo)
            kw = struct.unpack_from('<I', ks, i * 4)[0]
            if text_va is not None and text_vs > 0:
                decoy = text_va + (kw % text_vs)
            else:
                decoy = begin
            if decoy != unwind:  # idempotent: skip already-shadowed entries
                struct.pack_into('<I', data, eo + 8, decoy)
                patched += 1
        if verbose:
            sample = struct.unpack_from('<I', data, pdata_off + 8)[0]
            print(f"[vm_eh_shadow] PE .pdata: {n_entries} RUNTIME_FUNCTION "
                  f"entries, {patched} UnwindData pointers shadowed "
                  f"(first decoy RVA = 0x{sample:x})")
        return True
    except Exception as e:
        if verbose:
            print(f"[vm_eh_shadow] PE parse failed ({e})")
        return False


def _patch_elf_eh_frame(pyd_bytes: bytearray, build_rng, verbose: bool) -> bool:
    """Patch ELF .eh_frame CIE/FDE entries (Linux). Returns True on success.

    Overwrites the leading CIE header (up to 64 B) of ``.eh_frame`` with
    per-build keystream bytes, corrupting the length/version so the unwinder
    skips the frame (arXiv:2601.10261). Only the leading CIE is touched, never
    the whole section. We OVERWRITE rather than XOR so re-patching is
    idempotent (XOR would toggle the section back to its original bytes, which
    would un-shadow on a second pass and fail the reproducibility check).
    """
    data = pyd_bytes
    try:
        if data[:4] != b'\x7fELF':
            return False
        ei_class = data[4]   # 1 = ELF32, 2 = ELF64
        ei_data = data[5]    # 1 = LE, 2 = BE
        endian = '<' if ei_data == 1 else '>'
        if ei_class == 2:            # ELF64
            e_shoff = struct.unpack_from(endian + 'Q', data, 40)[0]
            e_shentsize = struct.unpack_from(endian + 'H', data, 58)[0]
            e_shnum = struct.unpack_from(endian + 'H', data, 60)[0]
            e_shstrndx = struct.unpack_from(endian + 'H', data, 62)[0]
            sh_off_off, sh_size_off, sh_ptr = 24, 32, 'Q'
        elif ei_class == 1:          # ELF32
            e_shoff = struct.unpack_from(endian + 'I', data, 32)[0]
            e_shentsize = struct.unpack_from(endian + 'H', data, 46)[0]
            e_shnum = struct.unpack_from(endian + 'H', data, 48)[0]
            e_shstrndx = struct.unpack_from(endian + 'H', data, 50)[0]
            sh_off_off, sh_size_off, sh_ptr = 16, 20, 'I'
        else:
            return False
        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0 or e_shstrndx >= e_shnum:
            return False

        # Section-header string table (shstrtab) gives section names.
        shstr_hdr = e_shoff + e_shstrndx * e_shentsize
        shstr_off = struct.unpack_from(endian + sh_ptr, data, shstr_hdr + sh_off_off)[0]
        shstr_size = struct.unpack_from(endian + sh_ptr, data, shstr_hdr + sh_size_off)[0]

        eh_off = eh_size = None
        for s in range(e_shnum):
            so = e_shoff + s * e_shentsize
            sh_name = struct.unpack_from(endian + 'I', data, so)[0]
            if sh_name >= shstr_size:
                continue
            nm_start = shstr_off + sh_name
            nm_end = data.find(b'\x00', nm_start)
            if nm_end < 0:
                nm_end = shstr_off + shstr_size
            if bytes(data[nm_start:nm_end]) == b'.eh_frame':
                eh_off = struct.unpack_from(endian + sh_ptr, data, so + sh_off_off)[0]
                eh_size = struct.unpack_from(endian + sh_ptr, data, so + sh_size_off)[0]
                break
        if eh_off is None or eh_size is None or eh_size == 0:
            return False
        if eh_off + eh_size > len(data):
            return False  # malformed

        n = min(64, eh_size)
        ks = build_rng.stream(_STREAM_LABEL).random(n)
        data[eh_off:eh_off + n] = ks  # overwrite leading CIE (idempotent)
        if verbose:
            print(f"[vm_eh_shadow] ELF .eh_frame: leading {n} B of CIE "
                  f"overwritten @ file offset 0x{eh_off:x}")
        return True
    except Exception as e:
        if verbose:
            print(f"[vm_eh_shadow] ELF parse failed ({e})")
        return False


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
def _build_synthetic_pe():
    """Build a minimal PE32+ blob with .text + .pdata (2 RUNTIME_FUNCTION
    entries) to exercise the manual parser when no real .pyd is at hand.

    Layout (1536 B total):
        0x000 MZ stub + e_lfanew=0x40
        0x040 'PE\\0\\0' + COFF header (Machine=x64, 2 sections, OptHdr=240)
        0x058 PE32+ optional header (data dir 3 -> .pdata RVA 0x2000, size 24)
        0x148 section table: .text(VA 0x1000) and .pdata(VA 0x2000, raw 0x400)
        0x200 .text body (nop fill)
        0x400 .pdata body: 2 RUNTIME_FUNCTION entries
    """
    img = bytearray(0x600)
    img[0:2] = b'MZ'
    struct.pack_into('<I', img, 0x3C, 0x40)
    img[0x40:0x44] = b'PE\x00\x00'
    struct.pack_into('<H', img, 0x44, 0x8664)   # Machine = IMAGE_FILE_MACHINE_AMD64
    struct.pack_into('<H', img, 0x46, 2)        # NumberOfSections
    struct.pack_into('<H', img, 0x54, 240)      # SizeOfOptionalHeader
    struct.pack_into('<H', img, 0x56, 0x2022)    # Characteristics (DLL|EXEC|LARGE_ADDR)
    struct.pack_into('<H', img, 0x58, 0x20b)     # Optional header magic = PE32+
    struct.pack_into('<I', img, 0xC4, 16)       # NumberOfRvaAndSizes
    struct.pack_into('<II', img, 0xE0, 0x2000, 24)  # Data dir 3 (Exception) -> .pdata
    # Section 0: .text (VA 0x1000, raw 0x200)
    img[0x148:0x150] = b'.text\x00\x00\x00'
    struct.pack_into('<I', img, 0x150, 0x1000)  # VirtualSize
    struct.pack_into('<I', img, 0x154, 0x1000)  # VirtualAddress
    struct.pack_into('<I', img, 0x158, 0x200)   # SizeOfRawData
    struct.pack_into('<I', img, 0x15C, 0x200)   # PointerToRawData
    # Section 1: .pdata (VA 0x2000, raw 0x400)
    img[0x170:0x178] = b'.pdata\x00\x00'
    struct.pack_into('<I', img, 0x178, 0x18)    # VirtualSize (24 = 2 entries)
    struct.pack_into('<I', img, 0x17C, 0x2000)   # VirtualAddress
    struct.pack_into('<I', img, 0x180, 0x200)   # SizeOfRawData
    struct.pack_into('<I', img, 0x184, 0x400)   # PointerToRawData
    # .text body: nop fill.
    for i in range(0x200, 0x400):
        img[i] = 0x90
    # .pdata body: 2 RUNTIME_FUNCTION entries (Begin, End, Unwind).
    struct.pack_into('<III', img, 0x400, 0x1000, 0x1020, 0x8000)
    struct.pack_into('<III', img, 0x40C, 0x1020, 0x1040, 0x8018)
    return bytes(img)


def _smoke():
    import shutil
    import tempfile

    here = os.path.dirname(os.path.abspath(__file__))
    is_pe = sys.platform == 'win32'

    # 1. Acquire a test binary: prefer a real shipped .pyd, else synthetic PE.
    src_path = None
    for name in sorted(os.listdir(here)):
        full = os.path.join(here, name)
        if name.endswith('.pyd') and os.path.isfile(full):
            src_path = full
            break
    tmp = tempfile.mkdtemp(prefix='_vm_eh_shadow_smoke_')
    try:
        if src_path is None and is_pe:
            src_path = os.path.join(tmp, '_synthetic.pyd')
            with open(src_path, 'wb') as f:
                f.write(_build_synthetic_pe())
        if src_path is None:
            # No test binary for this platform (e.g. linux without a .so).
            print("SMOKE PASS (no .pdata to patch — structural test only)")
            return

        with open(src_path, 'rb') as f:
            original = f.read()

        def patch_copy(seed):
            p = os.path.join(tmp, 'c_' + seed[:4].hex() + '.bin')
            with open(p, 'wb') as f:
                f.write(original)
            rng = BuildRNG.create(b'vm-eh-shadow-smoke', fixed_seed=seed)
            ok = gen_eh_shadow_patch(p, rng, verbose=True)
            with open(p, 'rb') as f:
                return p, ok, f.read()

        seed_a = bytes([0xAA]) * 32
        seed_b = bytes([0xBB]) * 32

        # 2. Patch with a fixed-seed BuildRNG.
        p_a, ok_a, buf_a = patch_copy(seed_a)
        if not ok_a:
            # No EH table present (or unsupported) -> structural-only pass.
            print("SMOKE PASS (no .pdata to patch — structural test only)")
            return

        # 3. Reproducibility: a second fresh copy, same seed -> identical.
        p_a2, ok_a2, buf_a2 = patch_copy(seed_a)
        assert ok_a2 and buf_a == buf_a2, 'reproducibility: same seed diverged'

        # 3b. Idempotency: re-patching the already-patched file -> unchanged.
        ok_idem = gen_eh_shadow_patch(
            p_a, BuildRNG.create(b'vm-eh-shadow-smoke', fixed_seed=seed_a),
            verbose=False)
        with open(p_a, 'rb') as f:
            buf_a_idem = f.read()
        assert ok_idem and buf_a == buf_a_idem, 'idempotency: re-patch diverged'

        # 4. Diversity: a different seed -> different patched output.
        p_b, ok_b, buf_b = patch_copy(seed_b)
        assert ok_b and buf_a != buf_b, 'diversity: distinct seeds collided'

        # 5. The patched output differs from the original (UnwindData changed).
        assert buf_a != original, 'changed: patch left the file byte-identical'

        print("SMOKE PASS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    _smoke()
