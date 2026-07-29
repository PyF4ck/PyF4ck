# Bedrock Challenge — Tìm Secret License Key

Một challenge deobfuscation cho cộng đồng reverse engineering. File duy nhất bạn
nhận là một binary Python đã bị obfuscate với **Bedrock Obfuscator** ở profile
`io` (đầy đủ Phase G deobf-hardening G1-G9 + G1+ + Phase H esoteric + encrypted-
source capsule).

## Mục tiêu

Tìm **secret license key** (một số nguyên) ẩn trong file obfuscated.

File obfuscated khi chạy đúng sẽ in:

```
license: VALID
compute: 237
final_result: 56896
```

Secret license key là một giá trị số được hardcode trong source gốc, đã bị
obfuscate đi. Mục tiêu của bạn là khôi phục nó.

## Files (release)

| File | Nội dung |
|------|----------|
| `challenge_io.py` | File obfuscated (~9.7 MB). Đây là thứ bạn phân tích. |
| `challenge_io.py.key` | Capsule key (64 hex chars = 32 bytes). Cần thiết để CHẠY file. |
| `_xvm.cp311-win_amd64.pyd` | Native VM C extension (BedrockVM interpreter). Cần thiết để chạy. |
| `_bedrock_vm_ref.py` | Reference VM interpreter (Python fallback). Cần thiết để chạy. |
| `_zyitvzq_vm_ref.py` | Aliased reference VM interpreter. Cần thiết để chạy. |

**Không** phát hành: source gốc, secret key, lời giải. Tự bạn tìm.

> **Platform note**: file `.pyd` được build cho **Windows x64 + Python 3.11**.
> Challenge chạy tốt trên môi trường đó. Trên Linux/macOS hoặc Python khác,
> `_xvm*.pyd` không load → fallback sang reference interpreter
> (`_bedrock_vm_ref.py`) — vẫn chạy được nhưng chậm hơn (73x).

## Độ khó

**Medium** — có capsule key + encrypted blob, analyst có thể decrypt source gốc,
nhưng secret vẫn bị che bởi các lớp obfuscation (num_obf 4-form, opaque predicates,
anti-meta). Secret không xuất hiện dưới dạng plaintext trong source gốc obfuscated
— nó được biến đổi qua nhiều lớp.

## Cách chạy

```bash
# Yêu cầu Python 3.10+ (build trên 3.11, native VM .pyd kèm theo)
BR_CAPSULE_KEY=$(cat challenge_io.py.key) python challenge_io.py
# In ra:
#   license: VALID
#   compute: 237
#   final_result: 56896
```

Không có `BR_CAPSULE_KEY`, file từ chối chạy (source stays encrypted on disk).

## Các lớp bảo vệ đã áp dụng (đầy đủ profile io + Phase G)

| Lớp | Bảo vệ | Trạng thái |
|-----|--------|------------|
| 1 | Identifier renaming (varsobf) | ✅ |
| 2 | String/const encryption + num_obf 4 AST forms | ✅ |
| 3 | Control-flow flattening (CFF) + dec traps | ✅ |
| 4 | Capsule runtime (per-code-object encrypt) | ✅ |
| 5 | Native VM (BedrockVM bytecode trong C extension) | ✅ (`_xvm*.pyd` kèm theo) |
| 6 | Phase H esoteric (11 passes) | ✅ |
| 7 | Encrypted-source capsule (binary capsule) | ✅ |
| **G1** | Blob hex/base85 + per-build bootstrap randomization + padding | ✅ |
| **G1+** | Bootstrap structural tells randomized (zlib aliased, 4/3/2 shape forms) | ✅ |
| **G2** | anti_meta default + sentinel randomization | ✅ |
| **G3** | num_obf 4-form diversify | ✅ |
| **G4** | Capsule key delivery (sidecar) | ✅ |
| **G6** | Opaque predicates structural mix (branch on `v & 1`) | ✅ |
| **G8** | ML adversarial test features | ✅ (kiểm tra tool, không phải challenge) |

## Gợi ý (progressive — đọc khi bí)

1. File có ~14 dòng bootstrap + 1 dòng blob (hex hoặc base85). Bootstrap decrypt
   blob bằng SHA-256 CTR XOR stream cipher, rồi `zlib.decompress` + `exec`.

2. Bạn có capsule key trong `.key` file. Decrypt blob → bạn có source gốc
   obfuscated (Phase 1-6). Đây không phải là secret — đây chỉ là lớp ngoài.

3. Secret license key bị che bởi `num_obf` (4 AST forms: lambda Call,
   `int.from_bytes`, bytearray-subscript, double-XOR). Mỗi byte literal bị
   biến đổi khác shape. Một AST-fold rule đơn không collapse được hết.

4. Secret cũng đi qua point-function obfuscation nếu nó xuất hiện ở vị trí
   FSS-auto-detect. Trong challenge này, num_obf biến đổi nó trước khi FSS
   trigger — nên DPF không được kích hoạt cho input này.

5. Lời giải thật sự: trace runtime. Set capsule key, chạy file, dump decrypted
   source trong memory, rồi trace từng biến. Secret được so sánh bằng
   `check_license(code)` — tìm giá trị mà hàm trả về True.

## Lời giải (spoiler — KHÔNG đọc nếu muốn tự giải)

<details>
<summary>Click để mở lời giải</summary>

Secret license key là **`0xDEAD`** (57005 trong decimal).

Source gốc (đã ẩn, không phát hành):

```python
SECRET_LICENSE = 0xDEAD  # 57005

def check_license(code):
    return code == SECRET_LICENSE

def compute(data):
    acc = 0
    for i, d in enumerate(data):
        acc = (acc + d * (i + 1)) % 1000003
    return acc

def main():
    if not check_license(0xDEAD):
        print("LICENSE INVALID")
        return
    result = compute([3, 1, 4, 1, 5, 9, 2, 6, 5, 3])
    final = result ^ SECRET_LICENSE
    print(f"license: VALID")
    print(f"compute: {result}")
    print(f"final_result: {final}")

if __name__ == "__main__":
    main()
```

`check_license(0xDEAD)` → True vì `0xDEAD == SECRET_LICENSE` (cả hai đều 0xDEAD).
`compute([3,1,4,1,5,9,2,6,5,3])` = 237. `final = 237 ^ 57005 = 56896`.

Verify: `python -c "print(237 ^ 0xDEAD)"` → `56896`. ✓

</details>

## Honest security note

Challenge này dùng **tất cả** Phase G hardening. Tuy nhiên:

- **CFF dispatch-table structure (L3)** chưa randomize — vẫn detect được bằng
  structural signature.
- **M4** (Vietnamese-identifier debrand) bị defer do `Compile.ll` constraint —
  không ảnh hưởng challenge này (không dùng VN identifiers).
- Capsule cipher là SHA-256 CTR XOR (không phải AEAD) — confidentiality phụ thuộc
  hoàn toàn vào việc giữ capsule key ngoài file. Bạn **có** key, nên decrypt
  được. Đây là by-design: challenge Medium cho phép decrypt để tập trung vào
  việc tìm secret bị obfuscate, không phải crack cipher.

Đây là challenge giáo dục, không phải production threat model. Để hiểu full
threat model, xem `bedrock_native/IO_SPEC.md` và `PRODUCTION_READINESS.md` ở
repo chính.

## Repo

Bedrock Obfuscator: https://github.com/PyF4ck/PyF4ck
Branch hardening: `fix/phase-g-hardening`
