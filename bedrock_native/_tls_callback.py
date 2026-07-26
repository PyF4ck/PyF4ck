"""Phase H.10 (Layer 6) TLS callback injection — native PE post-build.

Adds NEW-section capacity that the existing PE patchers (``_zero_pe_timestamp``,
``_vm_eh_shadow._patch_pe_pdata``) lack: they only MODIFY existing data
directories; this module APPENDS a fresh ``.brtls`` section holding an
``IMAGE_TLS_DIRECTORY`` + callback array, then wires data-directory index 9
(TLS) at it and bumps ``SizeOfImage``.

## Why TLS callbacks?

TLS callbacks fire on every thread start/stop — critically including the
``LoadLibrary`` call that loads the ``.pyd`` on an already-running thread
(the Python import machinery's load). They run BEFORE ``PyInit_*`` is
called by CPython's import machinery, so they are a pre-``PyInit`` hook
for early integrity checks (build-time embedded hash verification, anti-
debug probes, etc.). This is earlier than any Python-level ``__init__``.

## Contract

``inject_tls_callback(pyd_path, sym, verbose=False) -> bool``

- ``pyd_path``: path to a built Windows ``.pyd`` (PE32+ or PE32).
- ``sym``: either
    * a ``str`` — an EXPORTED symbol name looked up in the export
      directory (data-dir index 0); the export's RVA becomes the
      callback address, or
    * an ``int`` — a direct RVA (when the symbol isn't exported but
      its RVA is known at build time, e.g., from the linker map).
- Returns ``True`` on success. On any failure (non-PE, symbol not
  found, no header room for a new section, existing TLS dir, non-
  Windows) returns ``False`` and leaves the file byte-identical.
  Never raises — a patch failure must not break the build.

## Safety

- New section gets ``IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE``
  (the TLS index slot is written by the loader, so the section must be
  writable; the callback array is read-only in practice but lives in
  the same section for simplicity — writable is harmless).
- ``SizeOfImage`` is bumped to the aligned end of the new section.
- The callback array is null-terminated (one entry + NULL) per the TLS
  contract; the loader walks it until a NULL pointer.
- If a TLS directory already exists (data-dir index 9 non-zero), the
  patch is skipped (extending an existing callback array in place is
  not safe without growing the owning section — out of scope for the
  first pass; a clean skip preserves correctness).

## Kerckhoffs posture

Public technique. The per-output secret is the integrity-check payload
the callback verifies (embedded by the build, not by this patcher).

Pure stdlib (``struct``, ``os``). Windows-PE-only; on Linux/other the
function returns ``False`` without touching the file. Run::

    python bedrock_native/_tls_callback.py
"""
from __future__ import annotations

import os
import struct
import sys

__all__ = ['inject_tls_callback']

# Data directory indices (zero-based).
_DIR_EXPORT = 0
_DIR_TLS = 9
_DIR_BASE_RELOC = 5

# Relocation types.
_RELOC_ABSOLUTE = 0   # padding
_RELOC_HIGHLOW = 3    # 32-bit VA fixup
_RELOC_DIR64 = 10    # 64-bit VA fixup

# Section characteristics: initialized data, readable, writable.
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_SCN_CNT_INITIALIZED_DATA = 0x00000040
_TLS_SECTION_CHARS = _SCN_CNT_INITIALIZED_DATA | _SCN_MEM_READ | _SCN_MEM_WRITE


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    rem = value % alignment
    return value + (alignment - rem) if rem else value


def _rva_to_file_offset(data, rva, sec_off, n_sec):
    """Map a PE RVA to a raw file offset via the section table."""
    for s in range(n_sec):
        so = sec_off + s * 40
        vaddr = struct.unpack_from('<I', data, so + 12)[0]
        vsize = struct.unpack_from('<I', data, so + 8)[0]
        if vsize == 0:
            vsize = struct.unpack_from('<I', data, so + 16)[0]
        raddr = struct.unpack_from('<I', data, so + 20)[0]
        if vaddr != 0 and vaddr <= rva < vaddr + max(vsize, 1):
            return raddr + (rva - vaddr)
    return None


def _find_export_rva(data, sym, opt_off, n_dirs, dir_off, sec_off, n_sec, image_base, is_pe32_plus):
    """Look up *sym* (a name) in the export directory; return its RVA, or None."""
    if n_dirs <= _DIR_EXPORT:
        return None
    exp_rva, exp_size = struct.unpack_from('<II', data, dir_off + _DIR_EXPORT * 8)
    if exp_rva == 0 or exp_size == 0:
        return None
    exp_off = _rva_to_file_offset(data, exp_rva, sec_off, n_sec)
    if exp_off is None:
        return None
    # IMAGE_EXPORT_DIRECTORY (40 B):
    #   Characteristics(4) TimeDateStamp(4) MajorVer(2) MinorVer(2)
    #   NameRVA(4) Base(4) NumberOfFunctions(4) NumberOfNames(4)
    #   AddressTableRVA(4) NamePointerRVA(4) OrdinalTableRVA(4)
    n_funcs = struct.unpack_from('<I', data, exp_off + 20)[0]
    n_names = struct.unpack_from('<I', data, exp_off + 24)[0]
    eat_rva = struct.unpack_from('<I', data, exp_off + 28)[0]
    npt_rva = struct.unpack_from('<I', data, exp_off + 32)[0]
    ot_rva = struct.unpack_from('<I', data, exp_off + 36)[0]
    if n_names == 0:
        return None
    npt_off = _rva_to_file_offset(data, npt_rva, sec_off, n_sec)
    ot_off = _rva_to_file_offset(data, ot_rva, sec_off, n_sec)
    eat_off = _rva_to_file_offset(data, eat_rva, sec_off, n_sec)
    if npt_off is None or ot_off is None or eat_off is None:
        return None
    target = sym.encode('utf-8') if isinstance(sym, str) else sym
    for i in range(n_names):
        name_rva = struct.unpack_from('<I', data, npt_off + i * 4)[0]
        name_off = _rva_to_file_offset(data, name_rva, sec_off, n_sec)
        if name_off is None:
            continue
        end = data.find(b'\x00', name_off)
        if end < 0:
            continue
        if data[name_off:end] == target:
            ordinal = struct.unpack_from('<H', data, ot_off + i * 2)[0]
            base = struct.unpack_from('<I', data, exp_off + 16)[0]
            # The PE spec says OrdinalTable entries are unbiased ordinals
            # biased by the Export Directory Base, so the EAT index is
            # ``ordinal - base``. However, MSVC's linker emits 0-based EAT
            # indices directly in the OrdinalTable (the Base is used only for
            # ordinal-by-number lookups, not name-based ones). Both
            # conventions exist in the wild; resolve by trying the raw index
            # first (MSVC's actual behavior), then the spec form. For the
            # spec case (ordinal=base+k, n_funcs=k+1) the raw index k is
            # out of range when n_funcs==k, so the fallback fires; for the
            # MSVC case (ordinal=k, n_funcs>k) the raw index k is in range
            # and correct.
            for func_index in (ordinal, ordinal - base):
                if 0 <= func_index < n_funcs:
                    return struct.unpack_from('<I', data, eat_off + func_index * 4)[0]
    return None


def _patch_relocs_for_brtls(data, new_sec_va, is_pe32_plus,
                            opt_off, n_dirs, dir_off, sec_off, n_sec,
                            verbose=False):
    """Append a BASE_RELOC block covering the .brtls section's VA fields so
    the loader fixes them up under ASLR.

    The .brtls section stores absolute VAs (AddressOfIndex,
    AddressOfCallBacks, and each callback entry). Without relocations,
    relocating the image to a different base address leaves those VAs
    pointing at the old base -> ERROR_NOACCESS at load time.

    We append a new reloc block to the existing .reloc section's raw data
    (within its SizeOfRawData padding, which MSVC typically leaves), then
    bump the BASE_RELOC data directory size and the .reloc section's
    VirtualSize. Returns True on success, False if the .reloc section
    is missing or has insufficient padding (the TLS injection still
    succeeds, but callbacks may fail under ASLR).
    """
    if n_dirs <= _DIR_BASE_RELOC:
        if verbose:
            print("[tls] no BASE_RELOC directory; skipping reloc patch")
        return False
    rel_rva, rel_size = struct.unpack_from('<II', data, dir_off + _DIR_BASE_RELOC * 8)
    if rel_rva == 0 or rel_size == 0:
        if verbose:
            print("[tls] BASE_RELOC directory empty; skipping reloc patch")
        return False
    # Find the .reloc section by matching its VA range to rel_rva.
    reloc_sec_idx = None
    for i in range(n_sec):
        s = sec_off + i * 40
        vaddr = struct.unpack_from('<I', data, s + 12)[0]
        vsize = struct.unpack_from('<I', data, s + 8)[0]
        rsize = struct.unpack_from('<I', data, s + 16)[0]
        if vaddr <= rel_rva < vaddr + max(vsize, rsize):
            reloc_sec_idx = i
            break
    if reloc_sec_idx is None:
        if verbose:
            print("[tls] .reloc section not found; skipping reloc patch")
        return False
    rs = sec_off + reloc_sec_idx * 40
    r_vaddr = struct.unpack_from('<I', data, rs + 12)[0]
    r_rsize = struct.unpack_from('<I', data, rs + 16)[0]
    r_roff = struct.unpack_from('<I', data, rs + 20)[0]
    r_vsize = struct.unpack_from('<I', data, rs + 8)[0]
    # Append point: just past the current reloc data, within the raw section.
    rel_off = r_roff + (rel_rva - r_vaddr)
    append_off = rel_off + rel_size
    # Offsets within the .brtls section that hold absolute VAs needing relocs.
    if is_pe32_plus:
        rtype = _RELOC_DIR64
        offsets = [0x10, 0x18, 0x28]   # AddressOfIndex, AddressOfCallBacks, cb[0]
    else:
        rtype = _RELOC_HIGHLOW
        offsets = [0x08, 0x0C, 0x18]
    # Build the reloc block: header (8 B) + entries (2 B each) + padding.
    n_entries = len(offsets)
    block_size = 8 + n_entries * 2
    if block_size % 4:
        block_size += 4 - (block_size % 4)    # DWORD-align
    n_pad = (block_size - 8 - n_entries * 2) // 2
    if append_off + block_size > r_roff + r_rsize:
        if verbose:
            print(f"[tls] .reloc padding insufficient ({r_rsize - rel_size} free, "
                  f"need {block_size}); skipping reloc patch")
        return False
    struct.pack_into('<I', data, append_off, new_sec_va)
    struct.pack_into('<I', data, append_off + 4, block_size)
    for i, off in enumerate(offsets):
        struct.pack_into('<H', data, append_off + 8 + i * 2, (rtype << 12) | off)
    for i in range(n_pad):
        struct.pack_into('<H', data, append_off + 8 + (n_entries + i) * 2, _RELOC_ABSOLUTE)
    # Bump the BASE_RELOC data directory size + .reloc VirtualSize.
    struct.pack_into('<II', data, dir_off + _DIR_BASE_RELOC * 8, rel_rva, rel_size + block_size)
    new_vsize = (rel_rva - r_vaddr) + rel_size + block_size
    struct.pack_into('<I', data, rs + 8, new_vsize)
    if verbose:
        print(f"[tls] reloc block appended: page=0x{new_sec_va:x} "
              f"size={block_size} ({n_entries} entries + {n_pad} pad)")
    return True


def inject_tls_callback(pyd_path, sym, verbose=False):
    """Append a ``.brtls`` section with an IMAGE_TLS_DIRECTORY + callback
    array pointing at *sym*, and wire data-dir index 9 (TLS) at it.

    See module docstring for the full contract. Returns ``True`` on
    success, ``False`` on any failure (file left byte-identical).
    """
    if sys.platform != 'win32':
        if verbose:
            print(f"[tls] skipping non-Windows platform {sys.platform!r}")
        return False
    try:
        with open(pyd_path, 'rb') as f:
            data = bytearray(f.read())
        if data[:2] != b'MZ':
            if verbose:
                print("[tls] not an MZ/PE file")
            return False
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            if verbose:
                print("[tls] missing PE\\x00\\x00 signature")
            return False
        coff_off = e_lfanew + 4
        n_sec = struct.unpack_from('<H', data, coff_off + 2)[0]
        opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
        opt_off = coff_off + 20
        opt_magic = struct.unpack_from('<H', data, opt_off)[0]
        if opt_magic == 0x10b:        # PE32
            is_pe32_plus = False
            image_base_off = opt_off + 28
            image_base = struct.unpack_from('<I', data, image_base_off)[0]
            ndir_off = opt_off + 92
            dir_off = opt_off + 96
            tls_dir_size = 24          # IMAGE_TLS_DIRECTORY (PE32: 4-byte addrs)
            ptr_size = 4
            ptr_fmt = '<I'
        elif opt_magic == 0x20b:      # PE32+
            is_pe32_plus = True
            image_base_off = opt_off + 24
            image_base = struct.unpack_from('<Q', data, image_base_off)[0]
            ndir_off = opt_off + 108
            dir_off = opt_off + 112
            tls_dir_size = 40          # IMAGE_TLS_DIRECTORY (PE32+: 8-byte addrs)
            ptr_size = 8
            ptr_fmt = '<Q'
        else:
            if verbose:
                print(f"[tls] unknown optional header magic 0x{opt_magic:x}")
            return False
        n_dirs = struct.unpack_from('<I', data, ndir_off)[0]
        sec_align = struct.unpack_from('<I', data, opt_off + 32)[0]
        file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
        size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
        size_of_headers = struct.unpack_from('<I', data, opt_off + 60)[0]
        sec_off = opt_off + opt_size

        # Reject if a TLS directory already exists (clean skip — see docstring).
        if n_dirs > _DIR_TLS:
            tls_rva, tls_size = struct.unpack_from('<II', data, dir_off + _DIR_TLS * 8)
            if tls_rva != 0 or tls_size != 0:
                if verbose:
                    print("[tls] TLS directory already present; skipping")
                return False

        # Resolve the callback target RVA.
        if isinstance(sym, int):
            cb_rva = sym
            if cb_rva == 0:
                if verbose:
                    print("[tls] symbol RVA is zero")
                return False
        elif isinstance(sym, str):
            cb_rva = _find_export_rva(
                data, sym, opt_off, n_dirs, dir_off, sec_off, n_sec,
                image_base, is_pe32_plus)
            if cb_rva is None or cb_rva == 0:
                if verbose:
                    print(f"[tls] exported symbol {sym!r} not found")
                return False
        else:
            if verbose:
                print(f"[tls] sym must be str or int, got {type(sym).__name__}")
            return False

        # Ensure there is header room for one more section header (40 B).
        new_sec_hdr_off = sec_off + n_sec * 40
        if new_sec_hdr_off + 40 > size_of_headers:
            if verbose:
                print("[tls] no header room for a new section header")
            return False

        # Compute the new section's virtual address: just past the last
        # section's aligned end.
        last_va = 0
        last_va_end = 0
        for s in range(n_sec):
            so = sec_off + s * 40
            va = struct.unpack_from('<I', data, so + 12)[0]
            vs = struct.unpack_from('<I', data, so + 8)[0]
            vs = vs if vs else struct.unpack_from('<I', data, so + 16)[0]
            end = va + vs
            if end > last_va_end:
                last_va_end = end
                last_va = va
        new_va = _align(last_va_end, sec_align)
        if new_va == 0:
            new_va = sec_align

        # Layout the .brtls payload:
        #   [TLS directory][callback array (1 ptr + NULL)][index slot(4)]
        cb_array_entries = 2              # 1 callback + NULL terminator
        payload_size = tls_dir_size + cb_array_entries * ptr_size + 4
        raw_size = _align(payload_size, file_align)

        # Append the payload at the end of the file (aligned to file_align).
        new_raw_off = _align(len(data), file_align)
        # Relative offsets within the payload.
        tls_dir_off = 0
        cb_array_off = tls_dir_size
        index_off = tls_dir_size + cb_array_entries * ptr_size

        # Absolute virtual addresses (VA = ImageBase + RVA) for the fields.
        tls_dir_va = image_base + new_va + tls_dir_off
        cb_array_va = image_base + new_va + cb_array_off
        index_va = image_base + new_va + index_off
        cb_va = image_base + cb_rva        # the callback function's VA

        payload = bytearray(raw_size)
        if is_pe32_plus:
            # IMAGE_TLS_DIRECTORY (PE32+, 40 B):
            #   StartAddressOfRawData(8) EndAddressOfRawData(8)
            #   AddressOfIndex(8) AddressOfCallBacks(8)
            #   SizeOfZeroFill(4) Characteristics(4)
            struct.pack_into('<Q', payload, 0, 0)            # StartAddressOfRawData
            struct.pack_into('<Q', payload, 8, 0)             # EndAddressOfRawData
            struct.pack_into('<Q', payload, 16, index_va)     # AddressOfIndex
            struct.pack_into('<Q', payload, 24, cb_array_va)  # AddressOfCallBacks
            struct.pack_into('<I', payload, 32, 0)            # SizeOfZeroFill
            struct.pack_into('<I', payload, 36, 0)            # Characteristics
            struct.pack_into('<Q', payload, 40, cb_va)        # callback[0]
            struct.pack_into('<Q', payload, 48, 0)           # NULL terminator
            struct.pack_into('<I', payload, 56, 0)           # index slot
        else:
            # IMAGE_TLS_DIRECTORY (PE32, 24 B): 4-byte addresses.
            struct.pack_into('<I', payload, 0, 0)
            struct.pack_into('<I', payload, 4, 0)
            struct.pack_into('<I', payload, 8, index_va & 0xFFFFFFFF)
            struct.pack_into('<I', payload, 12, cb_array_va & 0xFFFFFFFF)
            struct.pack_into('<I', payload, 16, 0)
            struct.pack_into('<I', payload, 20, 0)
            struct.pack_into('<I', payload, 24, cb_va & 0xFFFFFFFF)
            struct.pack_into('<I', payload, 28, 0)
            struct.pack_into('<I', payload, 32, 0)

        # Grow the file to the aligned offset, then write the payload.
        if len(data) < new_raw_off:
            data.extend(b'\x00' * (new_raw_off - len(data)))
        data.extend(payload)

        # Write the new section header (40 B):
        #   Name(8) VirtualSize(4) VirtualAddress(4) SizeOfRawData(4)
        #   PointerToRawData(4) PointerToRelocations(4) PointerToLinenumbers(4)
        #   NumberOfRelocations(2) NumberOfLinenumbers(2) Characteristics(4)
        name = b'.brtls\x00\x00'
        struct.pack_into('<8s', data, new_sec_hdr_off, name)
        struct.pack_into('<I', data, new_sec_hdr_off + 8, payload_size)   # VirtualSize
        struct.pack_into('<I', data, new_sec_hdr_off + 12, new_va)        # VirtualAddress
        struct.pack_into('<I', data, new_sec_hdr_off + 16, raw_size)      # SizeOfRawData
        struct.pack_into('<I', data, new_sec_hdr_off + 20, new_raw_off)  # PointerToRawData
        struct.pack_into('<I', data, new_sec_hdr_off + 24, 0)             # PointerToRelocations
        struct.pack_into('<I', data, new_sec_hdr_off + 28, 0)             # PointerToLinenumbers
        struct.pack_into('<H', data, new_sec_hdr_off + 32, 0)             # NumberOfRelocations
        struct.pack_into('<H', data, new_sec_hdr_off + 34, 0)            # NumberOfLinenumbers
        struct.pack_into('<I', data, new_sec_hdr_off + 36, _TLS_SECTION_CHARS)

        # Bump NumberOfSections in the COFF header.
        struct.pack_into('<H', data, coff_off + 2, n_sec + 1)

        # Wire data-dir index 9 (TLS) at our directory.
        # Ensure NumberOfRvaAndSizes >= 10; if not, bump it (the array has 16 slots).
        if n_dirs < 16:
            struct.pack_into('<I', data, ndir_off, max(n_dirs, _DIR_TLS + 1))
        struct.pack_into('<II', data, dir_off + _DIR_TLS * 8, new_va + tls_dir_off, tls_dir_size)

        # Bump SizeOfImage to the aligned end of the new section.
        new_size_of_image = _align(new_va + payload_size, sec_align)
        if new_size_of_image > size_of_image:
            struct.pack_into('<I', data, opt_off + 56, new_size_of_image)

        # Bump SizeOfInitializedData by the new section's raw size (informational).
        size_init = struct.unpack_from('<I', data, opt_off + 8)[0]
        struct.pack_into('<I', data, opt_off + 8, size_init + raw_size)

        # Append a BASE_RELOC block covering the .brtls VA fields so the
        # loader fixes them up under ASLR. Without this, the absolute VAs in
        # the TLS directory + callback array point at the compile-time base
        # after relocation -> ERROR_NOACCESS at load time.
        _patch_relocs_for_brtls(
            data, new_va, is_pe32_plus, opt_off, n_dirs, dir_off,
            sec_off, n_sec, verbose=verbose)

        with open(pyd_path, 'wb') as f:
            f.write(data)
        if verbose:
            print(f"[tls] injected .brtls: va=0x{new_va:x} rva_cb=0x{cb_rva:x} "
                  f"cb_array_va=0x{cb_array_va:x} size_of_image=0x{new_size_of_image:x}")
        return True
    except Exception as e:
        if verbose:
            print(f"[tls] injection failed: {e}")
        return False


# --- Smoke test -------------------------------------------------------------

def _build_minimal_pe(export_name, export_rva, is_pe32_plus=True):
    """Build a minimal PE DLL with one .text section and a tiny export
    directory exporting *export_name* -> *export_rva*. Returns the file
    bytes. Used by the smoke test.
    """
    file_align = 0x200
    sec_align = 0x1000
    image_base = 0x180000000 if is_pe32_plus else 0x10000000

    text_va = 0x1000
    text_size = 0x200
    edata_va = 0x2000
    edata_size = 0x200

    # Raw layout: headers @ 0, .text @ file_align, .edata @ 2*file_align.
    text_raw = file_align
    edata_raw = 2 * file_align
    headers_size = file_align  # 0x200

    # --- .edata content ---
    exp_name_off = 0x60
    dll_name_off = 0x50
    eat_off = 40
    npt_off = 44
    ot_off = 48
    edata = bytearray(edata_size)
    struct.pack_into('<I', edata, 0, 0)
    struct.pack_into('<I', edata, 4, 0)
    struct.pack_into('<H', edata, 8, 0)
    struct.pack_into('<H', edata, 10, 0)
    struct.pack_into('<I', edata, 12, edata_va + dll_name_off)
    struct.pack_into('<I', edata, 16, 1)             # Base
    struct.pack_into('<I', edata, 20, 1)             # NumberOfFunctions
    struct.pack_into('<I', edata, 24, 1)             # NumberOfNames
    struct.pack_into('<I', edata, 28, edata_va + eat_off)
    struct.pack_into('<I', edata, 32, edata_va + npt_off)
    struct.pack_into('<I', edata, 36, edata_va + ot_off)
    struct.pack_into('<I', edata, eat_off, export_rva)
    struct.pack_into('<I', edata, npt_off, edata_va + exp_name_off)
    struct.pack_into('<H', edata, ot_off, 1)              # ordinal 1 (Base=1 -> func index 0)
    edata[dll_name_off:dll_name_off + len(b'test.dll\x00')] = b'test.dll\x00'
    en = export_name.encode('utf-8') + b'\x00'
    edata[exp_name_off:exp_name_off + len(en)] = en

    text = bytearray(text_size)

    # --- Headers ---
    buf = bytearray(headers_size)
    buf[0:2] = b'MZ'
    pe_off = 0x80
    struct.pack_into('<I', buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b'PE\x00\x00'
    coff = pe_off + 4
    machine = 0x8664 if is_pe32_plus else 0x14c
    struct.pack_into('<H', buf, coff + 0, machine)
    struct.pack_into('<H', buf, coff + 2, 2)
    struct.pack_into('<I', buf, coff + 4, 0)
    struct.pack_into('<I', buf, coff + 8, 0)
    struct.pack_into('<I', buf, coff + 12, 0)
    opt_size = 240 if is_pe32_plus else 224
    struct.pack_into('<H', buf, coff + 16, opt_size)
    struct.pack_into('<H', buf, coff + 18, 0x2022)

    opt = coff + 20
    magic = 0x20b if is_pe32_plus else 0x10b
    struct.pack_into('<H', buf, opt + 0, magic)
    buf[opt + 2] = 14
    buf[opt + 3] = 0
    struct.pack_into('<I', buf, opt + 4, text_size)
    struct.pack_into('<I', buf, opt + 8, edata_size)
    struct.pack_into('<I', buf, opt + 12, 0)
    struct.pack_into('<I', buf, opt + 16, text_va)
    struct.pack_into('<I', buf, opt + 20, text_va)
    if is_pe32_plus:
        struct.pack_into('<Q', buf, opt + 24, image_base)
    else:
        struct.pack_into('<I', buf, opt + 24, 0)       # BaseOfData (PE32)
        struct.pack_into('<I', buf, opt + 28, image_base)
    struct.pack_into('<I', buf, opt + 32, sec_align)
    struct.pack_into('<I', buf, opt + 36, file_align)
    struct.pack_into('<H', buf, opt + 40, 6)
    struct.pack_into('<H', buf, opt + 42, 0)
    struct.pack_into('<H', buf, opt + 44, 0)
    struct.pack_into('<H', buf, opt + 46, 0)
    struct.pack_into('<H', buf, opt + 48, 6)
    struct.pack_into('<H', buf, opt + 50, 0)
    struct.pack_into('<I', buf, opt + 52, 0)
    size_of_image = _align(edata_va + edata_size, sec_align)
    struct.pack_into('<I', buf, opt + 56, size_of_image)
    struct.pack_into('<I', buf, opt + 60, headers_size)
    struct.pack_into('<I', buf, opt + 64, 0)
    struct.pack_into('<H', buf, opt + 68, 3)
    struct.pack_into('<H', buf, opt + 70, 0x8160)
    if is_pe32_plus:
        struct.pack_into('<Q', buf, opt + 72, 0x100000)
        struct.pack_into('<Q', buf, opt + 80, 0x1000)
        struct.pack_into('<Q', buf, opt + 88, 0x100000)
        struct.pack_into('<Q', buf, opt + 96, 0x1000)
        struct.pack_into('<I', buf, opt + 104, 0)
        struct.pack_into('<I', buf, opt + 108, 16)
        dir_off = opt + 112
    else:
        struct.pack_into('<I', buf, opt + 72, 0x100000)
        struct.pack_into('<I', buf, opt + 76, 0x1000)
        struct.pack_into('<I', buf, opt + 80, 0x100000)
        struct.pack_into('<I', buf, opt + 84, 0x1000)
        struct.pack_into('<I', buf, opt + 88, 0)
        struct.pack_into('<I', buf, opt + 92, 16)
        dir_off = opt + 96
    struct.pack_into('<II', buf, dir_off + 0 * 8, edata_va, 40)
    # Zero the rest (already zero).

    sec_off = opt + opt_size
    struct.pack_into('<8s', buf, sec_off + 0, b'.text\x00\x00\x00')
    struct.pack_into('<I', buf, sec_off + 8, text_size)
    struct.pack_into('<I', buf, sec_off + 12, text_va)
    struct.pack_into('<I', buf, sec_off + 16, text_size)
    struct.pack_into('<I', buf, sec_off + 20, text_raw)
    struct.pack_into('<I', buf, sec_off + 36, 0x60000020)
    s2 = sec_off + 40
    struct.pack_into('<8s', buf, s2 + 0, b'.edata\x00\x00')
    struct.pack_into('<I', buf, s2 + 8, edata_size)
    struct.pack_into('<I', buf, s2 + 12, edata_va)
    struct.pack_into('<I', buf, s2 + 16, edata_size)
    struct.pack_into('<I', buf, s2 + 20, edata_raw)
    struct.pack_into('<I', buf, s2 + 36, 0x40000040)

    assert len(buf) <= headers_size
    out = bytearray(headers_size)
    out[:len(buf)] = buf
    # Append .text then .edata at their raw offsets.
    out.extend(b'\x00' * (text_raw - len(out)))
    out.extend(text)
    out.extend(b'\x00' * (edata_raw - len(out)))
    out.extend(edata)
    return bytes(out)


def _verify_tls_dir(data, expected_cb_rva, expected_sym_va):
    """Re-parse a patched PE and verify the TLS directory + callback array."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_off = e_lfanew + 4
    n_sec = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff_off + 16)[0]
    opt_off = coff_off + 20
    opt_magic = struct.unpack_from('<H', data, opt_off)[0]
    is_pe32_plus = (opt_magic == 0x20b)
    if is_pe32_plus:
        image_base = struct.unpack_from('<Q', data, opt_off + 24)[0]
        dir_off = opt_off + 112
        ptr_fmt = '<Q'
        ptr_size = 8
        tls_dir_size = 40
    else:
        image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
        dir_off = opt_off + 96
        ptr_fmt = '<I'
        ptr_size = 4
        tls_dir_size = 24
    n_dirs = struct.unpack_from('<I', data, opt_off + 108 if is_pe32_plus else opt_off + 92)[0]
    assert n_dirs > _DIR_TLS, f"NumberOfRvaAndSizes={n_dirs} too small"
    tls_rva, tls_size = struct.unpack_from('<II', data, dir_off + _DIR_TLS * 8)
    assert tls_rva != 0 and tls_size == tls_dir_size, \
        f"TLS dir rva=0x{tls_rva:x} size={tls_size} (expected size {tls_dir_size})"

    sec_off = opt_off + opt_size
    tls_file_off = _rva_to_file_offset(data, tls_rva, sec_off, n_sec)
    assert tls_file_off is not None, "TLS RVA not in any section"
    cb_array_va = struct.unpack_from(ptr_fmt, data, tls_file_off + 3 * ptr_size)[0]
    cb_array_off = _rva_to_file_offset(data, cb_array_va - image_base, sec_off, n_sec)
    assert cb_array_off is not None, "callback array RVA not in any section"
    cb0 = struct.unpack_from(ptr_fmt, data, cb_array_off)[0]
    cb1 = struct.unpack_from(ptr_fmt, data, cb_array_off + ptr_size)[0]
    assert cb0 == expected_sym_va, \
        f"callback[0]=0x{cb0:x} expected 0x{expected_sym_va:x}"
    assert cb1 == 0, f"callback array not NULL-terminated (cb1=0x{cb1:x})"

    # Verify .brtls section exists.
    names = []
    for s in range(n_sec):
        so = sec_off + s * 40
        names.append(data[so:so + 8].rstrip(b'\x00'))
    assert b'.brtls' in names, f".brtls section not found; sections={names}"

    size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]
    # Find .brtls VA + size.
    brtls_va = None
    brtls_vs = None
    for s in range(n_sec):
        so = sec_off + s * 40
        if data[so:so + 8].rstrip(b'\x00') == b'.brtls':
            brtls_va = struct.unpack_from('<I', data, so + 12)[0]
            brtls_vs = struct.unpack_from('<I', data, so + 8)[0]
            break
    assert brtls_va is not None
    assert _align(brtls_va + brtls_vs, 0x1000) == size_of_image, \
        f"SizeOfImage=0x{size_of_image:x} != aligned end 0x{_align(brtls_va + brtls_vs, 0x1000):x}"
    return True


def _smoke() -> None:
    """Verify TLS injection on a synthetic PE: export-name lookup, direct
    RVA, PE32+ + PE32, rejection cases (non-PE, existing TLS, missing
    symbol), and re-parse correctness."""

    import tempfile

    # --- Case 1: PE32+ with export-name lookup ---
    export_name = 'bedrock_tls_callback'
    export_rva = 0x1000  # somewhere in .text
    pe = _build_minimal_pe(export_name, export_rva, is_pe32_plus=True)
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(pe)
        path1 = tf.name
    try:
        ok = inject_tls_callback(path1, export_name, verbose=True)
        assert ok, "PE32+ export-name injection should succeed"
        print("H.10 PE32+ export-name: injected  OK")
        with open(path1, 'rb') as f:
            patched = bytearray(f.read())
        image_base = 0x180000000
        _verify_tls_dir(patched, export_rva, image_base + export_rva)
        print("H.10 PE32+ verify: TLS dir + cb array + .brtls + SizeOfImage  OK")
    finally:
        os.unlink(path1)

    # --- Case 2: PE32+ with direct RVA ---
    pe = _build_minimal_pe(export_name, export_rva, is_pe32_plus=True)
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(pe)
        path2 = tf.name
    try:
        ok = inject_tls_callback(path2, export_rva + 4, verbose=False)
        assert ok, "PE32+ direct-RVA injection should succeed"
        print("H.10 PE32+ direct-RVA: injected  OK")
        with open(path2, 'rb') as f:
            patched = bytearray(f.read())
        _verify_tls_dir(patched, export_rva + 4, 0x180000000 + export_rva + 4)
        print("H.10 PE32+ direct-RVA verify:  OK")
    finally:
        os.unlink(path2)

    # --- Case 3: PE32 with export-name lookup ---
    pe = _build_minimal_pe(export_name, export_rva, is_pe32_plus=False)
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(pe)
        path3 = tf.name
    try:
        ok = inject_tls_callback(path3, export_name, verbose=False)
        assert ok, "PE32 export-name injection should succeed"
        print("H.10 PE32 export-name: injected  OK")
        with open(path3, 'rb') as f:
            patched = bytearray(f.read())
        _verify_tls_dir(patched, export_rva, 0x10000000 + export_rva)
        print("H.10 PE32 verify:  OK")
    finally:
        os.unlink(path3)

    # --- Case 4: rejection — missing symbol ---
    pe = _build_minimal_pe(export_name, export_rva, is_pe32_plus=True)
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(pe)
        before = bytes(pe)
        path4 = tf.name
    try:
        ok = inject_tls_callback(path4, 'nonexistent_sym', verbose=False)
        assert not ok, "missing-symbol should reject"
        with open(path4, 'rb') as f:
            after = f.read()
        assert after == before, "file should be byte-identical on rejection"
        print("H.10 missing symbol: rejected, file unchanged  OK")
    finally:
        os.unlink(path4)

    # --- Case 5: rejection — non-PE file ---
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(b'not a PE file at all')
        path5 = tf.name
    try:
        ok = inject_tls_callback(path5, export_name, verbose=False)
        assert not ok, "non-PE should reject"
        print("H.10 non-PE: rejected  OK")
    finally:
        os.unlink(path5)

    # --- Case 6: idempotence — second injection on already-patched PE skips ---
    pe = _build_minimal_pe(export_name, export_rva, is_pe32_plus=True)
    with tempfile.NamedTemporaryFile(suffix='.pyd', delete=False) as tf:
        tf.write(pe)
        path6 = tf.name
    try:
        assert inject_tls_callback(path6, export_name, verbose=False)
        with open(path6, 'rb') as f:
            once = f.read()
        # Second call must skip (TLS dir already present).
        ok2 = inject_tls_callback(path6, export_name, verbose=False)
        assert not ok2, "second injection should skip (TLS already present)"
        with open(path6, 'rb') as f:
            twice = f.read()
        assert twice == once, "second injection should not modify the file"
        print("H.10 idempotent: second injection skipped, file stable  OK")
    finally:
        os.unlink(path6)

    print("H.10 SMOKE: PASS")


if __name__ == "__main__":
    _smoke()
