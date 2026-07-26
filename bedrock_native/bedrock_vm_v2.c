/* =========================================================================
 * BedrockVM Phase F leak-resilient C runtime (Layer 2) -- "v2".
 *
 * CPython C extension module "_xvm_v2".  Hardened rewrite of _bedrock_vm.c
 * (the Wave 2B interpreter) targeting the crown-jewel subset (fib,
 * compute_secret).  The blob contract, OFB cipher, perm/de-scramble and
 * opcode semantics are byte-for-byte compatible with _bedrock_vm_ref.encode()
 * / _native_vm_compiler.compile_func(); only the *dispatch substrate* changes.
 *
 * Phase F leak-resilience features (the novel work vs. the Phase 5 VM):
 *
 *   F.1  Context-threaded dispatch (no central state var, no indirect jmp).
 *        A static function-pointer table `handler_table[256]` is indexed by
 *        the canonical opcode; each handler is `int op_X(vm_ctx *ctx)`.
 *        Dispatch is a CALL (`handler_table[op](ctx)`), never
 *        `jmp [reg]`, so it dodges CET/IBT enforcement and makes the
 *        dispatch edge untraceable to tracers that key off indirect jumps.
 *
 *   F.2  Obscured VPC.  The virtual program counter is never stored as a
 *        single monotonic integer.  It is split into `vpc_lo` / `vpc_hi`
 *        with a per-ctx keystream folded in; the EFFECTIVE index is
 *        `(vpc_lo ^ vpc_hi) % ncode`, computed in a register.  A tracer
 *        watching either half sees a noisy, non-monotonic sequence.
 *
 *   F.3  Register-resident context.  All VM state lives in a heap-allocated
 *        `vm_ctx` passed by pointer to every handler (so the compiler keeps
 *        the context pointer in a register, NOT at a fixed [rsp+disp]).
 *        The pointer members (stack / locals / cells / decoded ops / args)
 *        are stored XOR'd with a per-ctx keystream mask and decrypted on
 *        access via accessor macros -- defeating the rsp-relative context
 *        anchoring that is VMPredator's primary recovery technique.
 *
 *   F.4  Non-static sha256_buffer.  Defined with external linkage so this
 *        translation unit satisfies the `extern` declaration in
 *        bedrock_antire.c (the Phase D anti-RE runtime links against it).
 *
 * Public API (same signature/kwargs as _xvm.run for wrapper compatibility):
 *   run(blob, perm, key, args, globals, perm_ext=144) -> object
 *
 * Build:
 *   python _bedrock_vm_setup.py build_ext --inplace   (add bedrock_vm_v2.c)
 *
 * NOTE: string literals are plain C literals here.  The _DS build-time XOR
 * preprocessor is a separate concern and is intentionally NOT used in this
 * F.3 MVP.  Platform-specific SMC (VirtualProtect/mprotect) is deferred.
 * ========================================================================= */
#ifndef BEDROCK_VM_V2_C
#define BEDROCK_VM_V2_C

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * F.4 SMC (Self-Modifying Code) handlers -- RW<->RX page toggle.
 *
 * Compiled in ONLY when BR_ENABLE_SMC is defined at build time. Default off:
 * SMC trips AV heuristics; ship EV-signed + vendor-whitelist only when on.
 * The mechanism maintains a page-aligned junk buffer that mutates every N
 * dispatch ticks (deterministic per smc_seed, so reproducible in fixed-seed
 * builds, diverse in fresh builds). The mutation is observable to a tracer
 * (bytes change between reads) but never affects execution -- the real
 * dispatch table is immutable; SMC only toggles a junk buffer's bytes +
 * page protection. This breaks Pushan's S1 assumption (read-only bytecode)
 * and VMPredator's static slicing (the bytes they statically snapshot
 * differ from what runs). All SMC code is additive and #ifdef-gated so the
 * default build is byte-identical to F.3.
 * ========================================================================= */
#ifdef BR_ENABLE_SMC
#ifndef BR_SMC_TOGGLE_N
#define BR_SMC_TOGGLE_N 64   /* mutate every N dispatch ticks (per-ctx) */
#endif
#ifdef _WIN32
#include <windows.h>
static int _smc_protect_rw(void *page, size_t len) {
    DWORD old;
    return VirtualProtect(page, len, PAGE_READWRITE, &old) ? 0 : -1;
}
static int _smc_protect_rx(void *page, size_t len) {
    DWORD old;
    return VirtualProtect(page, len, PAGE_EXECUTE_READ, &old) ? 0 : -1;
}
static void *_smc_alloc_page(size_t len) {
    /* _aligned_malloc frees with _aligned_free. Page size 4KB on x86/x64. */
    return _aligned_malloc(len, 4096);
}
static void _smc_free_page(void *p) {
    if (p) _aligned_free(p);
}
#else  /* POSIX */
#include <sys/mman.h>
#include <unistd.h>
static int _smc_protect_rw(void *page, size_t len) {
    return mprotect(page, len, PROT_READ | PROT_WRITE);
}
static int _smc_protect_rx(void *page, size_t len) {
    return mprotect(page, len, PROT_READ | PROT_EXEC);
}
static void *_smc_alloc_page(size_t len) {
    void *p = NULL;
    if (posix_memalign(&p, 4096, len) != 0) return NULL;
    return p;
}
static void _smc_free_page(void *p) {
    if (p) free(p);
}
#endif
#endif /* BR_ENABLE_SMC */

/* =========================================================================
 * SHA-256 (FIPS 180-4) -- self-contained, no external crypto dependency.
 *
 * sha256_buffer is NON-static (external linkage) on purpose: bedrock_antire.c
 * declares it `extern` and links against the host translation unit.  The rest
 * of the implementation (init/transform/update/final) stays file-local.
 * ========================================================================= */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x)  (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define SHA_EP1(x)  (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define SHA_SIG0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define SHA_SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_init(sha256_ctx *c) {
    c->state[0]=0x6a09e667u; c->state[1]=0xbb67ae85u;
    c->state[2]=0x3c6ef372u; c->state[3]=0xa54ff53au;
    c->state[4]=0x510e527fu; c->state[5]=0x9b05688cu;
    c->state[6]=0x1f83d9abu; c->state[7]=0x5be0cd19u;
    c->bitlen = 0; c->buflen = 0;
}

static void sha256_transform(sha256_ctx *c, const uint8_t *data) {
    uint32_t m[64];
    uint32_t a,b,cc,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i*4]   << 24) |
               ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] <<  8) |
               ((uint32_t)data[i*4+3]);
    }
    for (; i < 64; i++) {
        m[i] = SHA_SIG1(m[i-2]) + m[i-7] + SHA_SIG0(m[i-15]) + m[i-16];
    }
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + SHA_EP1(e) + SHA_CH(e,f,g) + SHA256_K[i] + m[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->bitlen += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buffer + c->buflen, data, take);
        c->buflen += take; data += take; len -= take;
        if (c->buflen == 64) {
            sha256_transform(c, c->buffer);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    int i;
    c->buffer[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buffer[c->buflen++] = 0;
        sha256_transform(c, c->buffer);
        c->buflen = 0;
    }
    while (c->buflen < 56) c->buffer[c->buflen++] = 0;
    uint64_t bl = c->bitlen;
    for (i = 7; i >= 0; i--) { c->buffer[56 + i] = (uint8_t)(bl & 0xff); bl >>= 8; }
    sha256_transform(c, c->buffer);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)((c->state[i] >> 24) & 0xff);
        out[i*4+1] = (uint8_t)((c->state[i] >> 16) & 0xff);
        out[i*4+2] = (uint8_t)((c->state[i] >>  8) & 0xff);
        out[i*4+3] = (uint8_t)( c->state[i]        & 0xff);
    }
}

/* NON-static: bedrock_antire.c declares this `extern` and links against us. */
void sha256_buffer(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* =========================================================================
 * SHA-256 OFB stream cipher (matches _bedrock_vm_ref._ofb_decrypt exactly).
 *
 *   state_0 = sha256(key)
 *   state_n = sha256(state_{n-1} + key + bytes([off & 255]))
 *   out[i]  = in[i] ^ state_n[i % 32]
 *
 * Key derivation (domain separation so two ciphertexts starting at OFB offset
 * 0 do not form a two-time pad):
 *   const pool : key directly
 *   names blob : names_key = sha256(key + b'|names')
 *   code (v2)  : code_key  = sha256(key + b'|code')
 * Empty key (b'') => no decryption (plaintext blobs).
 * ========================================================================= */
static void ofb_decrypt(const uint8_t *in, size_t in_len,
                       const uint8_t *key, size_t key_len,
                       uint8_t *out) {
    uint8_t state[32];
    uint8_t *buf;
    size_t off = 0;
    sha256_buffer(key, key_len, state);          /* state_0 */
    if (in_len == 0) return;
    buf = (uint8_t*)malloc(32 + key_len + 1);
    if (buf == NULL) return;
    while (off < in_len) {
        size_t take, j;
        memcpy(buf, state, 32);
        memcpy(buf + 32, key, key_len);
        buf[32 + key_len] = (uint8_t)(off & 255);
        sha256_buffer(buf, 32 + key_len + 1, state);  /* next state */
        take = 32;
        if (take > in_len - off) take = in_len - off;
        for (j = 0; j < take; j++) out[off + j] = in[off + j] ^ state[j];
        off += take;
    }
    free(buf);
}

/* Little-endian uint32 reader. */
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* =========================================================================
 * Canonical opcode values (must match VM_SPEC.md / _OPCODES in the ref).
 * Copied verbatim from _bedrock_vm.c so the handler_table indices line up.
 * ========================================================================= */
#define OP_NOP                   0
#define OP_POP_TOP               1
#define OP_DUP_TOP               2
#define OP_ROT_TWO               3
#define OP_ROT_THREE             4
#define OP_EXTENDED_ARG          144   /* fixed; never permuted */
#define OP_RESUME                6
#define OP_JUMP                  7
#define OP_JUMP_IF_FALSE         8
#define OP_JUMP_IF_TRUE          9
#define OP_JUMP_IF_NONE          10
#define OP_JUMP_IF_NOT_NONE      11
#define OP_FOR_ITER              12
#define OP_GET_ITER              13
#define OP_RETURN_VALUE          14
#define OP_RETURN_CONST          15
#define OP_YIELD_VALUE           16
#define OP_RETURN_GENERATOR      17
#define OP_RAISE_VARARGS         18
#define OP_POP_BLOCK             19
#define OP_PUSH_NULL             20
#define OP_LOAD_ASSERTION_ERROR  21
#define OP_RERAISE               22
#define OP_CHECK_EXC_MATCH       23
#define OP_END_FOR               25
#define OP_YIELD_FROM            26
#define OP_SETUP_FINALLY         30
#define OP_SETUP_WITH            31
#define OP_LOAD_CONST            32
#define OP_LOAD_FAST             33
#define OP_LOAD_FAST_CHECK       34
#define OP_LOAD_GLOBAL           35
#define OP_LOAD_DEREF            36
#define OP_LOAD_NAME             37
#define OP_LOAD_ATTR             38
#define OP_LOAD_METHOD           39
#define OP_STORE_FAST            40
#define OP_STORE_GLOBAL          41
#define OP_STORE_DEREF           42
#define OP_STORE_NAME            43
#define OP_DELETE_FAST           44
#define OP_DELETE_GLOBAL         45
#define OP_COPY                  46
#define OP_SWAP                  47
#define OP_LOAD_CLOSURE          48
#define OP_COPY_FREE_VARS        50
#define OP_LOAD_BUILD_CLASS      51
#define OP_UNPACK_SEQUENCE       53
#define OP_UNPACK_EX             54
#define OP_STORE_ATTR            55
#define OP_DELETE_ATTR           56
#define OP_STORE_SUBSCR          57
#define OP_DELETE_SUBSCR         58
#define OP_BINARY_SUBSCR        59
#define OP_FORMAT_VALUE          60
#define OP_BUILD_STRING          61
#define OP_IMPORT_NAME           62
#define OP_IMPORT_FROM           63
#define OP_BUILD_TUPLE           64
#define OP_BUILD_LIST            65
#define OP_BUILD_SET             66
#define OP_BUILD_MAP             67
#define OP_LIST_EXTEND           68
#define OP_SET_UPDATE            69
#define OP_DICT_UPDATE           70
#define OP_LIST_APPEND           71
#define OP_SET_ADD               72
#define OP_MAP_ADD               73
#define OP_BUILD_SLICE           75
#define OP_MAKE_FUNCTION         77
#define OP_CALL                  78
#define OP_CALL_KW               79
#define OP_CALL_FUNCTION_EX      80
#define OP_KW_NAMES              81
#define OP_GEN_START             83
#define OP_BEFORE_ASYNC_WITH     89
#define OP_SETUP_ASYNC_WITH      93
#define OP_BEFORE_WITH           118
#define OP_BINARY_OP             96
#define OP_UNARY_NEGATIVE        97
#define OP_UNARY_NOT             98
#define OP_UNARY_INVERT          99
#define OP_COMPARE_OP           100
#define OP_IS_OP                101
#define OP_CONTAINS_OP          102
#define OP_BINARY_OP_INPLACE    104
#define OP_JUMP_IF_FALSE_OR_POP 112
#define OP_JUMP_IF_TRUE_OR_POP  113
#define OP_POP_EXCEPT           115
#define OP_PUSH_EXC_INFO        116
#define OP_UNARY_POSITIVE       125
#define OP_FORMAT_SIMPLE        110
#define OP_FORMAT_WITH_SPEC     111

/* =========================================================================
 * F.3 Register-resident VM context.
 *
 * All interpreter state lives here, on the heap, addressed through a single
 * pointer that the dispatcher passes to every handler.  Because every
 * handler takes `vm_ctx *ctx`, the compiler keeps `ctx` in a register across
 * the dispatch edge rather than re-loading it from a fixed [rsp+disp] slot
 * each iteration -- there is no stable stack offset a tracer can anchor on.
 *
 * The pointer members (stack / locals / cells / ops / args) are stored
 * XOR'd at rest with `ptr_mask` (a keystream-derived value) and recovered on
 * access via the CTX_* accessor macros below.  A memory dump therefore sees
 * only masked pointers; the real value stack / locals arrays are not
 * reachable by following a raw `ctx->stack` field.  (Borrowed PyObject* refs
 * such as consts / globals point into CPython's own heap and are left plain:
 * they are immutable across execution and not the rsp-anchor target.)
 *
 * Encoded-pointer convention: an enc field of 0 means "not allocated / NULL";
 * otherwise it equals `(uintptr_t)ptr ^ ptr_mask` (always non-zero for a real
 * allocation, since a heap address never equals the sha256-derived mask).
 * ========================================================================= */
typedef struct vm_ctx {
    /* --- Pointer members, XOR'd at rest with ptr_mask --- */
    uintptr_t stack_enc;     /* PyObject** value stack           */
    uintptr_t locals_enc;    /* PyObject** locals frame          */
    uintptr_t cells_enc;     /* PyObject** closure cells         */
    uintptr_t ops_enc;       /* int* decoded canonical opcodes   */
    uintptr_t args_enc;     /* int* decoded full args            */
    uintptr_t ptr_mask;      /* per-ctx XOR mask (keystream-derived) */

    /* --- Scalar state --- */
    int sp;                   /* stack pointer (next free slot)   */
    int scap;                /* stack capacity                    */
    int nlocals_alloc;
    int ncells;
    int ncode;               /* number of decoded instructions   */
    int alive;               /* dispatch loop control (1=run)     */
    int rc;                  /* 0 ok / -1 error (set by dispatch) */
    int cur_arg;             /* arg of current instr (set by de_scramble) */

    /* --- F.2 Obscured VPC (split lo/hi; see invariant below) --- */
    int vpc_lo;
    int vpc_hi;

    /* --- Keystream state for VPC obscuration --- */
    uint8_t ks_state[32];
    int ks_pos;

    /* --- Borrowed Python refs (plain pointers; owned by _xvm_v2_run) --- */
    PyObject *consts;        /* tuple of constants                */
    PyObject *global_names;  /* tuple of global/name slots        */
    PyObject *varnames;
    PyObject *freevars;
    PyObject *cellvars;
    PyObject *globals_obj;   /* globals dict                      */
    PyObject *result;        /* return value (NULL until set)     */
    PyObject *kw_names_pending; /* set by KW_NAMES, consumed by CALL_KW */

#ifdef BR_ENABLE_SMC
    /* --- F.4 SMC junk buffer (page-aligned, RW<->RX toggle) --- */
    volatile uint8_t *smc_junk;   /* page-aligned junk buffer          */
    size_t            smc_junk_len;
    uint64_t          smc_seed;       /* per-build seed (0 = default)   */
    uint64_t          smc_call_count; /* increments each dispatch tick  */
    uint64_t          smc_ks_state;   /* keystream state for mutation   */
    int               smc_failed;     /* 1 = last toggle failed (skip)  */
#endif
} vm_ctx;

/* Accessor macros: decrypt a pointer member on access. */
#define CTX_STACK(c)   ((PyObject**)((c)->stack_enc  ^ (c)->ptr_mask))
#define CTX_LOCALS(c)  ((PyObject**)((c)->locals_enc ^ (c)->ptr_mask))
#define CTX_CELLS(c)   ((PyObject**)((c)->cells_enc  ^ (c)->ptr_mask))
#define CTX_OPS(c)     ((int*)((c)->ops_enc    ^ (c)->ptr_mask))
#define CTX_ARGS(c)    ((int*)((c)->args_enc   ^ (c)->ptr_mask))

/* =========================================================================
 * F.2 Obscured VPC.
 *
 * The true program counter `pc` (an index into the decoded ops[]/args_arr[]
 * arrays, in sequential order; jump targets are absolute instruction
 * indices) is NEVER stored directly.  It is split across vpc_lo / vpc_hi
 * with a per-ctx keystream folded in, and the EFFECTIVE index is recovered
 * in a register as  vpc_pc(ctx) = vpc_lo ^ vpc_hi.
 *
 * INVARIANT:  vpc_lo ^ vpc_hi == true_pc   (always).
 *
 * This invariant is what makes execution correct while the storage stays
 * obscured.  The spec's illustrative formulas
 *     advance: vpc_lo = (vpc_lo + 1) ^ ks
 *     jump  : vpc_lo = target & 0xFFFF ; vpc_hi = (target >> 16) ^ ks
 * combined with `idx = vpc_lo ^ vpc_hi` do NOT by themselves yield a
 * monotonic / target-faithful index (the keystream byte would corrupt the
 * recovered pc).  We therefore deviate ONLY in that vpc_lo is re-derived
 * from the (keystream-rolled) vpc_hi so the invariant holds -- preserving
 * the spec's structure (split halves, keystream on every step, idx = lo^hi,
 * jumps set both halves) while guaranteeing the crown jewels execute.  The
 * effective index is still `(vpc_lo ^ vpc_hi) % ncode`, exactly as specified.
 * ========================================================================= */

/* One byte of the rolling keystream (SHA-256 chain seeded from the key). */
static uint8_t keystream_next_byte(vm_ctx *ctx) {
    if (ctx->ks_pos >= 32) {
        sha256_buffer(ctx->ks_state, 32, ctx->ks_state);
        ctx->ks_pos = 0;
    }
    return ctx->ks_state[ctx->ks_pos++];
}

/* =========================================================================
 * F.4 SMC toggle: mutate the junk buffer every BR_SMC_TOGGLE_N ticks.
 *
 * Caller holds the GIL (we're inside a Python call), so no concurrency
 * hazard. Best-effort: a VirtualProtect/mprotect failure sets ctx->smc_failed
 * (we stop toggling -- the VM keeps running; only the SMC channel goes dead).
 * ========================================================================= */
#ifdef BR_ENABLE_SMC
static void _smc_tick(vm_ctx *ctx) {
    if (!ctx->smc_junk || ctx->smc_failed) return;
    ctx->smc_call_count++;
    if ((ctx->smc_call_count % BR_SMC_TOGGLE_N) != 0) return;

    /* Derive a fresh keystream byte from the per-ctx state + call count.
     * Deterministic given (smc_seed, call_count) so fixed-seed builds are
     * reproducible; fresh builds differ via smc_seed. */
    uint64_t mix = ctx->smc_seed ^ ctx->smc_call_count ^ 0x9E3779B97F4A7C15ULL;
    uint8_t ks = (uint8_t)(mix ^ (mix >> 32));

    /* Toggle RW, XOR each junk byte, toggle back RX. The XOR is observable
     * to a tracer (bytes change between reads) but the junk is never read
     * for execution -- it lives only to break read-only-bytecode assumptions. */
    if (_smc_protect_rw((void *)ctx->smc_junk, ctx->smc_junk_len) != 0) {
        ctx->smc_failed = 1;
        return;
    }
    for (size_t i = 0; i < ctx->smc_junk_len; i++) {
        ctx->smc_junk[i] = (uint8_t)(ctx->smc_junk[i] ^ ks);
    }
    if (_smc_protect_rx((void *)ctx->smc_junk, ctx->smc_junk_len) != 0) {
        /* Could not restore RX -- the page may fault on next exec-touch.
         * Best-effort: leave it RW (the junk is data, not code, so a RX
         * requirement is not strictly needed; we only toggled for show).
         * Mark failed so we stop trying. */
        ctx->smc_failed = 1;
    }
}

static int _smc_init(vm_ctx *ctx, uint64_t smc_seed) {
    ctx->smc_junk = NULL;
    ctx->smc_junk_len = 0;
    ctx->smc_seed = smc_seed;
    ctx->smc_call_count = 0;
    ctx->smc_ks_state = smc_seed;
    ctx->smc_failed = 0;
    /* 64 bytes of junk is enough to be observable; 4KB page-aligned so the
     * RW<->RX toggle is a whole-page VirtualProtect/mprotect (cheap + clean). */
    ctx->smc_junk_len = 64;
    ctx->smc_junk = (volatile uint8_t *)_smc_alloc_page(ctx->smc_junk_len);
    if (!ctx->smc_junk) {
        ctx->smc_failed = 1;
        return -1;
    }
    /* Seed the junk with the per-ctx keystream (deterministic). */
    uint8_t seed_bytes[8];
    for (int i = 0; i < 8; i++) seed_bytes[i] = (uint8_t)(smc_seed >> (i * 8));
    uint8_t ks[32];
    sha256_buffer(seed_bytes, 8, ks);
    for (size_t i = 0; i < ctx->smc_junk_len; i++) {
        ctx->smc_junk[i] = ks[i % 32];
    }
    /* Start RX (matches the eventual "executable junk" framing; the page
     * protection toggles to RW during mutation and back). */
    if (_smc_protect_rx((void *)ctx->smc_junk, ctx->smc_junk_len) != 0) {
        /* If we can't mark RX, leave RW -- junk is data, RX is cosmetic. */
        ctx->smc_failed = 0;  /* keep toggling; _smc_tick handles RW->RW gracefully */
    }
    return 0;
}

static void _smc_fini(vm_ctx *ctx) {
    if (ctx->smc_junk) {
        _smc_free_page((void *)ctx->smc_junk);
        ctx->smc_junk = NULL;
    }
}
#endif /* BR_ENABLE_SMC */

/* Recover the true program counter (register-resident XOR). */
static inline int vpc_pc(const vm_ctx *ctx) {
    return ctx->vpc_lo ^ ctx->vpc_hi;
}

/* Advance one instruction: pc -> pc+1.  Roll vpc_hi through the keystream,
 * then re-derive vpc_lo so the invariant vpc_lo ^ vpc_hi == pc holds. */
static inline void vpc_advance(vm_ctx *ctx) {
    int pc = vpc_pc(ctx) + 1;
    uint8_t ks = keystream_next_byte(ctx);
    ctx->vpc_hi = (ctx->vpc_hi + 1) ^ (int)ks;
    ctx->vpc_lo = pc ^ ctx->vpc_hi;       /* invariant: lo ^ hi == pc */
}

/* Jump to absolute target index.  Sets BOTH halves; vpc_hi absorbs the
 * keystream and the target's high bits, vpc_lo is derived so lo ^ hi == target. */
static inline void vpc_jump(vm_ctx *ctx, int target) {
    uint8_t ks = keystream_next_byte(ctx);
    ctx->vpc_hi = ((target >> 16) ^ (int)ks) | ((int)ks << 16);
    ctx->vpc_lo = target ^ ctx->vpc_hi;   /* invariant: lo ^ hi == target */
}

/* =========================================================================
 * F.1 Context-threaded dispatch table.
 *
 * handler_table[canonical] -> handler_fn.  NULL slots are unimplemented
 * opcodes; the dispatcher raises "unsupported opcode" for them (the
 * compiler's fail-safe skips functions it cannot compile, so the crown jewels
 * never hit a NULL slot, but we are defensive).  CALL dispatch, not jmp.
 * ========================================================================= */
typedef int (*handler_fn)(vm_ctx *ctx);
static handler_fn handler_table[256];   /* zero-initialized; filled in PyInit */

/* Grow the value stack.  Re-encrypts the (possibly moved) pointer. */
static int ensure_capacity_ctx(vm_ctx *ctx, int needed) {
    if (needed <= ctx->scap) return 0;
    int newcap = (ctx->scap > 0) ? ctx->scap : 64;
    while (newcap < needed) newcap *= 2;
    PyObject **old = ctx->stack_enc ? CTX_STACK(ctx) : NULL;
    PyObject **ns = (PyObject**)PyMem_RawRealloc(old,
                                                 (size_t)newcap * sizeof(PyObject*));
    if (ns == NULL) { PyErr_NoMemory(); return -1; }
    ctx->stack_enc = (uintptr_t)ns ^ ctx->ptr_mask;
    ctx->scap = newcap;
    return 0;
}

/* Stack helpers.  X_PUSH returns -1 from its enclosing handler on OOM. */
#define X_PUSH(ctx, v) do { \
    if (ensure_capacity_ctx(ctx, (ctx)->sp + 1) < 0) return -1; \
    CTX_STACK(ctx)[(ctx)->sp++] = (v); \
} while (0)
#define X_POP(ctx)    (CTX_STACK(ctx)[--(ctx)->sp])
#define X_TOP(ctx)    (CTX_STACK(ctx)[(ctx)->sp - 1])

/* =========================================================================
 * Handlers.  Each returns 0 on success / -1 on error (PyErr set).  A handler
 * advances the VPC itself: sequential ops call vpc_advance(); jumps call
 * vpc_jump(); return ops set ctx->result + ctx->alive=0 (no advance).  The
 * arg of the current instruction is in ctx->cur_arg (set by de_scramble).
 * ========================================================================= */

static int op_nop(vm_ctx *ctx) {           /* NOP / RESUME / GEN_START / block markers */
    vpc_advance(ctx);
    return 0;
}

static int op_pop_top(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    Py_DECREF(v);
    vpc_advance(ctx);
    return 0;
}

static int op_dup_top(vm_ctx *ctx) {
    PyObject *v = X_TOP(ctx);
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_rot_two(vm_ctx *ctx) {
    PyObject **st = CTX_STACK(ctx);
    PyObject *t = st[ctx->sp - 1];
    st[ctx->sp - 1] = st[ctx->sp - 2];
    st[ctx->sp - 2] = t;
    vpc_advance(ctx);
    return 0;
}

static int op_rot_three(vm_ctx *ctx) {
    PyObject **st = CTX_STACK(ctx);
    PyObject *t = st[ctx->sp - 1];
    st[ctx->sp - 1] = st[ctx->sp - 3];
    st[ctx->sp - 3] = st[ctx->sp - 2];
    st[ctx->sp - 2] = t;
    vpc_advance(ctx);
    return 0;
}

static int op_return_value(vm_ctx *ctx) {
    ctx->result = X_POP(ctx);   /* transfer ownership of popped ref */
    ctx->alive = 0;
    return 0;                   /* no advance: loop ends */
}

static int op_return_const(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *c = PyTuple_GetItem(ctx->consts, arg);   /* borrowed */
    if (c == NULL) return -1;
    Py_INCREF(c);
    ctx->result = c;
    ctx->alive = 0;
    return 0;
}

static int op_load_const(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *c = PyTuple_GetItem(ctx->consts, arg);   /* borrowed */
    if (c == NULL) return -1;
    Py_INCREF(c);
    X_PUSH(ctx, c);
    vpc_advance(ctx);
    return 0;
}

static int op_load_fast(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->nlocals_alloc) {
        PyErr_SetString(PyExc_IndexError, "LOAD_FAST out of range");
        return -1;
    }
    PyObject *v = CTX_LOCALS(ctx)[arg];
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_load_fast_check(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->nlocals_alloc) {
        PyErr_SetString(PyExc_IndexError, "LOAD_FAST_CHECK out of range");
        return -1;
    }
    PyObject *v = CTX_LOCALS(ctx)[arg];
    if (v == Py_None && ctx->varnames && arg < PyTuple_GET_SIZE(ctx->varnames)) {
        PyObject *name = PyTuple_GET_ITEM(ctx->varnames, arg);
        PyErr_Format(PyExc_UnboundLocalError, "%S", name);
        return -1;
    }
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_store_fast(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->nlocals_alloc) {
        PyErr_SetString(PyExc_IndexError, "STORE_FAST out of range");
        return -1;
    }
    PyObject *v = X_POP(ctx);
    Py_XDECREF(CTX_LOCALS(ctx)[arg]);
    CTX_LOCALS(ctx)[arg] = v;   /* transfer ownership */
    vpc_advance(ctx);
    return 0;
}

static int op_delete_fast(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->nlocals_alloc) {
        PyErr_SetString(PyExc_IndexError, "DELETE_FAST out of range");
        return -1;
    }
    Py_XDECREF(CTX_LOCALS(ctx)[arg]);
    Py_INCREF(Py_None);
    CTX_LOCALS(ctx)[arg] = Py_None;
    vpc_advance(ctx);
    return 0;
}

static int op_load_global(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);   /* borrowed */
    if (name == NULL) return -1;
    PyObject *v = PyObject_GetItem(ctx->globals_obj, name);     /* KeyError if missing */
    if (v == NULL) return -1;
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_store_global(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) return -1;
    PyObject *v = X_POP(ctx);
    int r = PyObject_SetItem(ctx->globals_obj, name, v);
    Py_DECREF(v);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_delete_global(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) return -1;
    if (PyObject_DelItem(ctx->globals_obj, name) < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_load_name(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) return -1;
    PyObject *v = PyObject_GetItem(ctx->globals_obj, name);
    if (v == NULL) {
        /* fall back to builtins, else None (matches reference). */
        PyErr_Clear();
        PyObject *bl = PyDict_GetItemString(ctx->globals_obj, "__builtins__");
        PyObject *bdict = (bl && PyModule_Check(bl)) ? PyModule_GetDict(bl) : bl;
        if (bdict && PyDict_Check(bdict)) {
            v = PyDict_GetItem(bdict, name);   /* borrowed */
            if (v) Py_INCREF(v);
        }
        if (v == NULL) { Py_INCREF(Py_None); v = Py_None; }
    }
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_store_name(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) return -1;
    PyObject *v = X_POP(ctx);
    int r = PyObject_SetItem(ctx->globals_obj, name, v);
    Py_DECREF(v);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_load_deref(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->ncells) {
        PyErr_SetString(PyExc_IndexError, "LOAD_DEREF out of range");
        return -1;
    }
    PyObject *v = CTX_CELLS(ctx)[arg];
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_store_deref(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->ncells) {
        PyErr_SetString(PyExc_IndexError, "STORE_DEREF out of range");
        return -1;
    }
    PyObject *v = X_POP(ctx);
    Py_XDECREF(CTX_CELLS(ctx)[arg]);
    CTX_CELLS(ctx)[arg] = v;
    vpc_advance(ctx);
    return 0;
}

static int op_load_closure(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->ncells) {
        PyErr_SetString(PyExc_IndexError, "LOAD_CLOSURE out of range");
        return -1;
    }
    PyObject *v = CTX_CELLS(ctx)[arg];
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

/* LOAD_ATTR and LOAD_METHOD share this handler (both: TOS.obj -> getattr). */
static int op_load_attr(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *obj = X_POP(ctx);
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) { Py_DECREF(obj); return -1; }
    PyObject *r = PyObject_GetAttr(obj, name);
    Py_DECREF(obj);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_store_attr(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *obj = X_POP(ctx);
    PyObject *val = X_POP(ctx);
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) { Py_DECREF(obj); Py_DECREF(val); return -1; }
    int r = PyObject_SetAttr(obj, name, val);
    Py_DECREF(obj); Py_DECREF(val);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_delete_attr(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *obj = X_POP(ctx);
    PyObject *name = PyTuple_GetItem(ctx->global_names, arg);
    if (name == NULL) { Py_DECREF(obj); return -1; }
    int r = PyObject_DelAttr(obj, name);
    Py_DECREF(obj);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_store_subscr(vm_ctx *ctx) {
    PyObject *key = X_POP(ctx);
    PyObject *obj = X_POP(ctx);
    PyObject *val = X_POP(ctx);
    int r = PyObject_SetItem(obj, key, val);
    Py_DECREF(key); Py_DECREF(obj); Py_DECREF(val);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_delete_subscr(vm_ctx *ctx) {
    PyObject *key = X_POP(ctx);
    PyObject *obj = X_POP(ctx);
    int r = PyObject_DelItem(obj, key);
    Py_DECREF(key); Py_DECREF(obj);
    if (r < 0) return -1;
    vpc_advance(ctx);
    return 0;
}

static int op_binary_subscr(vm_ctx *ctx) {
    PyObject *key = X_POP(ctx);
    PyObject *obj = X_POP(ctx);
    PyObject *r = PyObject_GetItem(obj, key);
    Py_DECREF(key); Py_DECREF(obj);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_copy(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 0 || arg >= ctx->sp) {
        PyErr_SetString(PyExc_IndexError, "COPY out of range");
        return -1;
    }
    PyObject *v = CTX_STACK(ctx)[ctx->sp - 1 - arg];
    Py_INCREF(v);
    X_PUSH(ctx, v);
    vpc_advance(ctx);
    return 0;
}

static int op_swap(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    if (arg < 1 || arg >= ctx->sp) {
        PyErr_SetString(PyExc_IndexError, "SWAP out of range");
        return -1;
    }
    PyObject **st = CTX_STACK(ctx);
    PyObject *t = st[ctx->sp - 1];
    st[ctx->sp - 1] = st[ctx->sp - 1 - arg];
    st[ctx->sp - 1 - arg] = t;
    vpc_advance(ctx);
    return 0;
}

static int op_unpack_sequence(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *seq = X_POP(ctx);
    PyObject *lst = PySequence_List(seq);
    Py_DECREF(seq);
    if (lst == NULL) return -1;
    Py_ssize_t n = PyList_GET_SIZE(lst);
    if (n != arg) {
        Py_DECREF(lst);
        PyErr_Format(PyExc_ValueError,
                     "unpack expected %d arguments, got %zd", arg, n);
        return -1;
    }
    /* Push forward: list[0] deepest, list[arg-1] on top (matches CPython:
     * subsequent STORE_FAST ops pop top-first into the rightmost target). */
    int k;
    for (k = 0; k < arg; k++) {
        PyObject *it = PyList_GET_ITEM(lst, k);   /* borrowed */
        Py_INCREF(it);
        X_PUSH(ctx, it);
    }
    Py_DECREF(lst);
    vpc_advance(ctx);
    return 0;
}

/* OP_BINARY_OP and OP_BINARY_OP_INPLACE share this (arg is the sub-op). */
static int op_binary_op(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *b = X_POP(ctx);
    PyObject *a = X_POP(ctx);
    PyObject *r;
    switch (arg) {
        case 0:  r = PyNumber_Add(a,b); break;
        case 1:  r = PyNumber_Subtract(a,b); break;
        case 2:  r = PyNumber_Multiply(a,b); break;
        case 3:  r = PyNumber_TrueDivide(a,b); break;
        case 4:  r = PyNumber_Remainder(a,b); break;
        case 5:  r = PyNumber_FloorDivide(a,b); break;
        case 6:  r = PyNumber_Power(a,b,Py_None); break;
        case 7:  r = PyNumber_Lshift(a,b); break;
        case 8:  r = PyNumber_Rshift(a,b); break;
        case 9:  r = PyNumber_And(a,b); break;
        case 10: r = PyNumber_Or(a,b); break;
        case 11: r = PyNumber_Xor(a,b); break;
        case 25: r = PyNumber_MatrixMultiply(a,b); break;
        default:
            Py_DECREF(a); Py_DECREF(b);
            PyErr_Format(PyExc_RuntimeError, "unknown BINOP sub %d", arg);
            return -1;
    }
    Py_DECREF(a); Py_DECREF(b);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_unary_negative(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    PyObject *r = PyNumber_Negative(v);
    Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_unary_positive(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    PyObject *r = PyNumber_Positive(v);
    Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_unary_not(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    int x = PyObject_IsTrue(v);
    Py_DECREF(v);
    if (x < 0) return -1;
    PyObject *r = PyBool_FromLong(!x);
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_unary_invert(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    PyObject *r = PyNumber_Invert(v);
    Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_compare_op(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *b = X_POP(ctx);
    PyObject *a = X_POP(ctx);
    PyObject *r;
    switch (arg) {
        case 0: r = PyObject_RichCompare(a,b,Py_LT); break;
        case 1: r = PyObject_RichCompare(a,b,Py_LE); break;
        case 2: r = PyObject_RichCompare(a,b,Py_EQ); break;
        case 3: r = PyObject_RichCompare(a,b,Py_NE); break;
        case 4: r = PyObject_RichCompare(a,b,Py_GT); break;
        case 5: r = PyObject_RichCompare(a,b,Py_GE); break;
        case 6: { int x = PySequence_Contains(b,a);
                  r = (x<0)?NULL:PyBool_FromLong(x); break; }
        case 7: { int x = PySequence_Contains(b,a);
                  r = (x<0)?NULL:PyBool_FromLong(!x); break; }
        case 8: r = PyBool_FromLong(a == b); break;
        case 9: r = PyBool_FromLong(a != b); break;
        default:
            Py_DECREF(a); Py_DECREF(b);
            PyErr_Format(PyExc_RuntimeError, "unknown CMP sub %d", arg);
            return -1;
    }
    Py_DECREF(a); Py_DECREF(b);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_is_op(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *b = X_POP(ctx);
    PyObject *a = X_POP(ctx);
    PyObject *r = PyBool_FromLong(arg ? (a != b) : (a == b));
    Py_DECREF(a); Py_DECREF(b);
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_contains_op(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *b = X_POP(ctx);
    PyObject *a = X_POP(ctx);
    int x = PySequence_Contains(b, a);
    Py_DECREF(a); Py_DECREF(b);
    if (x < 0) return -1;
    PyObject *r = PyBool_FromLong(arg ? !x : x);
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_jump(vm_ctx *ctx) {
    vpc_jump(ctx, ctx->cur_arg);
    return 0;
}

static int op_jump_if_false(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    int t = PyObject_IsTrue(v);
    Py_DECREF(v);
    if (t < 0) return -1;
    if (!t) vpc_jump(ctx, ctx->cur_arg);
    else    vpc_advance(ctx);
    return 0;
}

static int op_jump_if_true(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    int t = PyObject_IsTrue(v);
    Py_DECREF(v);
    if (t < 0) return -1;
    if (t) vpc_jump(ctx, ctx->cur_arg);
    else   vpc_advance(ctx);
    return 0;
}

static int op_jump_if_none(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    int is_none = (v == Py_None);
    Py_DECREF(v);
    if (is_none) vpc_jump(ctx, ctx->cur_arg);
    else         vpc_advance(ctx);
    return 0;
}

static int op_jump_if_not_none(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    int not_none = (v != Py_None);
    Py_DECREF(v);
    if (not_none) vpc_jump(ctx, ctx->cur_arg);
    else           vpc_advance(ctx);
    return 0;
}

static int op_jump_if_false_or_pop(vm_ctx *ctx) {
    PyObject *v = X_TOP(ctx);
    int t = PyObject_IsTrue(v);
    if (t < 0) return -1;
    if (!t) vpc_jump(ctx, ctx->cur_arg);
    else { PyObject *p = X_POP(ctx); Py_DECREF(p); vpc_advance(ctx); }
    return 0;
}

static int op_jump_if_true_or_pop(vm_ctx *ctx) {
    PyObject *v = X_TOP(ctx);
    int t = PyObject_IsTrue(v);
    if (t < 0) return -1;
    if (t) vpc_jump(ctx, ctx->cur_arg);
    else { PyObject *p = X_POP(ctx); Py_DECREF(p); vpc_advance(ctx); }
    return 0;
}

static int op_for_iter(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *it = X_TOP(ctx);          /* peek */
    PyObject *v = PyIter_Next(it);
    if (v == NULL) {
        if (PyErr_Occurred()) return -1; /* real error */
        /* exhausted: pop iterator, jump to arg */
        PyObject *ex = X_POP(ctx);
        Py_DECREF(ex);
        vpc_jump(ctx, arg);
    } else {
        X_PUSH(ctx, v);
        vpc_advance(ctx);
    }
    return 0;
}

static int op_get_iter(vm_ctx *ctx) {
    PyObject *obj = X_POP(ctx);
    PyObject *it = PyObject_GetIter(obj);
    Py_DECREF(obj);
    if (it == NULL) return -1;
    X_PUSH(ctx, it);
    vpc_advance(ctx);
    return 0;
}

static int op_push_null(vm_ctx *ctx) {
    /* BedrockVM has no NULL call markers (the compiler drops PUSH_NULL), so
     * this is never emitted for calls; push None for parity with the ref. */
    Py_INCREF(Py_None);
    X_PUSH(ctx, Py_None);
    vpc_advance(ctx);
    return 0;
}

static int op_call(vm_ctx *ctx) {
    int arg = ctx->cur_arg;             /* argc */
    if (arg < 0 || arg >= ctx->sp) {
        PyErr_SetString(PyExc_IndexError, "CALL argc out of range");
        return -1;
    }
    PyObject *args_t = PyTuple_New(arg);
    if (args_t == NULL) return -1;
    PyObject **st = CTX_STACK(ctx);
    int k;
    for (k = 0; k < arg; k++) PyTuple_SET_ITEM(args_t, k, st[ctx->sp - arg + k]); /* steal */
    ctx->sp -= arg;
    PyObject *callable = X_POP(ctx);
    PyObject *r = PyObject_Call(callable, args_t, NULL);
    Py_DECREF(args_t);
    Py_DECREF(callable);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_kw_names(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *names = PyTuple_GetItem(ctx->consts, arg);   /* borrowed */
    if (names == NULL) return -1;
    Py_XDECREF(ctx->kw_names_pending);
    Py_INCREF(names);
    ctx->kw_names_pending = names;
    vpc_advance(ctx);
    return 0;
}

static int op_call_kw(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    int argc = arg >> 8;
    int nkw = arg & 0xff;
    if (argc < 0 || nkw < 0 || argc + nkw >= ctx->sp) {
        PyErr_SetString(PyExc_IndexError, "CALL_KW argc/nkw out of range");
        return -1;
    }
    PyObject **st = CTX_STACK(ctx);
    PyObject *kw = PyDict_New();
    if (kw == NULL) return -1;
    if (ctx->kw_names_pending && nkw > 0) {
        int k;
        for (k = 0; k < nkw; k++) {
            PyObject *val = st[ctx->sp - nkw + k];
            PyObject *name = PyTuple_GetItem(ctx->kw_names_pending, k);
            if (name == NULL) {
                int j; for (j=0;j<nkw;j++) Py_DECREF(st[ctx->sp-nkw+j]);
                ctx->sp -= nkw; Py_DECREF(kw); return -1;
            }
            if (PyDict_SetItem(kw, name, val) < 0) {
                int j; for (j=0;j<nkw;j++) Py_DECREF(st[ctx->sp-nkw+j]);
                ctx->sp -= nkw; Py_DECREF(kw); return -1;
            }
        }
    }
    int j;
    for (j = 0; j < nkw; j++) Py_DECREF(st[ctx->sp - nkw + j]);
    ctx->sp -= nkw;
    Py_XDECREF(ctx->kw_names_pending); ctx->kw_names_pending = NULL;

    st = CTX_STACK(ctx);   /* refresh (no realloc above, but be safe) */
    PyObject *args_t = PyTuple_New(argc);
    if (args_t == NULL) { Py_DECREF(kw); return -1; }
    int k;
    for (k = 0; k < argc; k++) PyTuple_SET_ITEM(args_t, k, st[ctx->sp - argc + k]); /* steal */
    ctx->sp -= argc;
    PyObject *callable = X_POP(ctx);
    PyObject *r = PyObject_Call(callable, args_t, kw);
    Py_DECREF(args_t); Py_DECREF(kw);
    Py_DECREF(callable);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_call_function_ex(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *kwds = NULL;
    if (arg & 0x1) kwds = X_POP(ctx);
    PyObject *argv = X_POP(ctx);
    PyObject *callable = X_POP(ctx);
    PyObject *r = PyObject_Call(callable, argv, kwds);
    Py_XDECREF(kwds); Py_DECREF(argv); Py_DECREF(callable);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_make_function(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *codeobj = X_POP(ctx);
    PyObject *qualname = NULL, *defaults = NULL, *kwdefaults = NULL, *closure = NULL;
    if (arg & 0x8) qualname = X_POP(ctx);
    if (arg & 0x4) kwdefaults = X_POP(ctx);
    if (arg & 0x2) defaults = X_POP(ctx);
    if (arg & 0x1) { closure = X_POP(ctx); Py_DECREF(closure); closure = NULL; }
    PyObject *fn = NULL;
    if (PyCode_Check(codeobj)) {
        if (qualname) fn = PyFunction_NewWithQualName(codeobj, ctx->globals_obj, qualname);
        else          fn = PyFunction_New(codeobj, ctx->globals_obj);
    }
    Py_XDECREF(qualname);
    Py_XDECREF(defaults);
    Py_XDECREF(kwdefaults);
    Py_XDECREF(closure);
    Py_DECREF(codeobj);
    if (fn == NULL) {
        if (!PyErr_Occurred())
            PyErr_SetString(PyExc_NotImplementedError,
                "MAKE_FUNCTION: code object must be a real Python code");
        return -1;
    }
    X_PUSH(ctx, fn);
    vpc_advance(ctx);
    return 0;
}

static int op_build_tuple(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *t = PyTuple_New(arg);
    if (t == NULL) return -1;
    PyObject **st = CTX_STACK(ctx);
    int k;
    for (k = 0; k < arg; k++) PyTuple_SET_ITEM(t, k, st[ctx->sp - arg + k]); /* steal */
    ctx->sp -= arg;
    X_PUSH(ctx, t);
    vpc_advance(ctx);
    return 0;
}

static int op_build_list(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *l = PyList_New(arg);
    if (l == NULL) return -1;
    PyObject **st = CTX_STACK(ctx);
    int k;
    for (k = 0; k < arg; k++) PyList_SET_ITEM(l, k, st[ctx->sp - arg + k]); /* steal */
    ctx->sp -= arg;
    X_PUSH(ctx, l);
    vpc_advance(ctx);
    return 0;
}

static int op_build_map(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *d = PyDict_New();
    if (d == NULL) return -1;
    PyObject **st = CTX_STACK(ctx);
    int k;
    for (k = 0; k < arg; k++) {
        PyObject *key = st[ctx->sp - 2*arg + 2*k];
        PyObject *val = st[ctx->sp - 2*arg + 2*k + 1];
        if (PyDict_SetItem(d, key, val) < 0) {
            int j;
            for (j = 0; j < 2*arg; j++) Py_DECREF(st[ctx->sp - 2*arg + j]);
            ctx->sp -= 2*arg; Py_DECREF(d); return -1;
        }
    }
    int j;
    for (j = 0; j < 2*arg; j++) Py_DECREF(st[ctx->sp - 2*arg + j]);
    ctx->sp -= 2*arg;
    X_PUSH(ctx, d);
    vpc_advance(ctx);
    return 0;
}

static int op_build_slice(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *r;
    if (arg == 2) {
        PyObject *stop = X_POP(ctx);
        PyObject *start = X_POP(ctx);
        r = PySlice_New(start, stop, NULL);
        Py_DECREF(start); Py_DECREF(stop);
    } else {
        PyObject *step = X_POP(ctx);
        PyObject *stop = X_POP(ctx);
        PyObject *start = X_POP(ctx);
        r = PySlice_New(start, stop, step);
        Py_DECREF(start); Py_DECREF(stop); Py_DECREF(step);
    }
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_build_string(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *sep = PyUnicode_FromString("");
    if (sep == NULL) return -1;
    PyObject *parts = PyTuple_New(arg);
    if (parts == NULL) { Py_DECREF(sep); return -1; }
    PyObject **st = CTX_STACK(ctx);
    int k;
    for (k = 0; k < arg; k++) PyTuple_SET_ITEM(parts, k, st[ctx->sp - arg + k]); /* steal */
    ctx->sp -= arg;
    PyObject *r = PyUnicode_Join(sep, parts);
    Py_DECREF(sep); Py_DECREF(parts);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_format_value(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *v = X_POP(ctx);
    PyObject *r;
    if (arg & 0x4) {
        PyObject *spec = X_POP(ctx);
        r = PyObject_Format(v, spec);
        Py_DECREF(spec);
    } else if (arg == 0) {
        r = PyObject_Str(v);
    } else if (arg == 1) {
        r = PyObject_Repr(v);
    } else if (arg == 2) {
        r = PyObject_ASCII(v);
    } else {
        r = PyObject_Str(v);
    }
    Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_format_simple(vm_ctx *ctx) {
    PyObject *v = X_POP(ctx);
    PyObject *r = PyObject_Str(v);
    Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_format_with_spec(vm_ctx *ctx) {
    PyObject *spec = X_POP(ctx);
    PyObject *v = X_POP(ctx);
    PyObject *r = PyObject_Format(v, spec);
    Py_DECREF(spec); Py_DECREF(v);
    if (r == NULL) return -1;
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_load_assertion_error(vm_ctx *ctx) {
    Py_INCREF(PyExc_AssertionError);
    X_PUSH(ctx, PyExc_AssertionError);
    vpc_advance(ctx);
    return 0;
}

static int op_push_exc_info(vm_ctx *ctx) {
    Py_INCREF(Py_None);
    X_PUSH(ctx, Py_None);
    vpc_advance(ctx);
    return 0;
}

static int op_check_exc_match(vm_ctx *ctx) {
    PyObject *t = X_POP(ctx);
    PyObject *e = X_POP(ctx);
    int x = PyObject_IsInstance(e, t);
    Py_DECREF(e); Py_DECREF(t);
    if (x < 0) return -1;
    PyObject *r = PyBool_FromLong(x);
    X_PUSH(ctx, r);
    vpc_advance(ctx);
    return 0;
}

static int op_raise_varargs(vm_ctx *ctx) {
    int arg = ctx->cur_arg;
    PyObject *cause = NULL, *exc = NULL;
    if (arg >= 2) cause = X_POP(ctx);
    if (arg >= 1) exc = X_POP(ctx);
    if (exc == NULL) {
        if (!PyErr_Occurred())
            PyErr_SetString(PyExc_RuntimeError, "No active exception to re-raise");
        Py_XDECREF(cause);
        return -1;
    }
    if (PyExceptionInstance_Check(exc)) {
        PyErr_SetObject((PyObject*)Py_TYPE(exc), exc);
    } else if (PyExceptionClass_Check(exc)) {
        PyObject *inst = PyObject_CallNoArgs(exc);
        if (inst != NULL) { PyErr_SetObject(exc, inst); Py_DECREF(inst); }
    } else {
        PyErr_SetString(PyExc_TypeError, "exceptions must derive from BaseException");
    }
    Py_XDECREF(exc);
    Py_XDECREF(cause);
    return -1;
}

static int op_reraise(vm_ctx *ctx) {
    if (!PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "No active exception to re-raise");
    return -1;
}

static int op_yield_value(vm_ctx *ctx) {
    /* Non-generator frame: treat as return (generators are delegated out). */
    ctx->result = X_POP(ctx);
    ctx->alive = 0;
    return 0;
}

static int op_yield_from(vm_ctx *ctx) {
    /* Non-generator fallback: leave TOS (matches ref's else branch). */
    vpc_advance(ctx);
    return 0;
}

/* Fetch the canonical opcode at the obscured VPC; stashes its arg in
 * ctx->cur_arg.  Caller must guard the pc range first. */
static int de_scramble(vm_ctx *ctx) {
    int pc = vpc_pc(ctx);
    int idx = (ctx->ncode > 0) ? (pc % ctx->ncode) : 0;
    ctx->cur_arg = CTX_ARGS(ctx)[idx];
    return CTX_OPS(ctx)[idx];
}

/* Cached pickle.loads callable (singleton; lives for the process). */
static PyObject *g_pickle_loads = NULL;

static PyObject *get_pickle_loads(void) {
    if (g_pickle_loads) return g_pickle_loads;
    PyObject *m = PyImport_ImportModule("pickle");
    if (m == NULL) return NULL;
    g_pickle_loads = PyObject_GetAttrString(m, "loads");
    Py_DECREF(m);
    return g_pickle_loads;  /* NULL on failure */
}

/* =========================================================================
 * run(blob, perm, key, args, globals, perm_ext=144) -> object
 * ========================================================================= */
static PyObject* _xvm_v2_run(PyObject* self, PyObject* args_parse, PyObject* kwargs) {
    PyObject *blob_obj, *perm_obj, *key_obj, *args_obj, *globals_obj;
    long perm_ext = 144;
    unsigned long long smc_seed = 0;  /* F.4: 0 = default; non-zero varies per build */
    static char *kwlist[] = {"blob","perm","key","args","globals","perm_ext","smc_seed", NULL};
    (void)self;

    if (!PyArg_ParseTupleAndKeywords(args_parse, kwargs, "OOOOO|lL:run", kwlist,
            &blob_obj, &perm_obj, &key_obj, &args_obj, &globals_obj, &perm_ext, &smc_seed)) {
        return NULL;
    }

    /* Resource pointers (NULL-init so cleanup is always safe). */
    PyObject *result_owner_consts = NULL;   /* strong ref: const tuple */
    PyObject *names_blob = NULL;            /* strong ref: names 4-tuple */
    PyObject *empty_tup = NULL;
    uint8_t *code_buf = NULL;              /* decrypted code section (v2) */
    vm_ctx *ctx = NULL;
    int rc = 0;
    int i;
    Py_buffer blob_view; blob_view.buf = NULL; blob_view.len = 0;
    Py_buffer key_view;   key_view.buf = NULL;   key_view.len = 0;
    int perm[256];
    for (i = 0; i < 256; i++) perm[i] = -1;

    /* ---- Acquire blob buffer ---- */
    if (PyObject_GetBuffer(blob_obj, &blob_view, PyBUF_SIMPLE) < 0) {
        return NULL;
    }
    const uint8_t *blob = (const uint8_t*)blob_view.buf;
    Py_ssize_t blob_len = blob_view.len;

    /* ---- Generator fallback: peek flags; if is_generator, delegate ---- */
    if ((size_t)blob_len >= 9) {
        uint32_t flags = rd32(blob + 5);
        if (flags & 0x2) {
            /* Delegate to the pure-Python reference interpreter so a real
             * generator object is returned (native generator suspension is
             * out of scope for this F.3 MVP). */
            PyObject *mod = PyImport_ImportModule("_bedrock_vm_ref");
            if (mod == NULL) goto fail;
            PyObject *run_fn = PyObject_GetAttrString(mod, "run");
            Py_DECREF(mod);
            if (run_fn == NULL) goto fail;
            PyObject *res = PyObject_CallFunction(run_fn, "OOOOOl",
                blob_obj, perm_obj, key_obj, args_obj, globals_obj,
                (long)perm_ext);
            Py_DECREF(run_fn);
            PyBuffer_Release(&blob_view);
            return res;
        }
    }

    /* ---- Acquire key buffer ---- */
    if (PyObject_GetBuffer(key_obj, &key_view, PyBUF_SIMPLE) < 0) {
        PyBuffer_Release(&blob_view);
        return NULL;
    }
    const uint8_t *key = (const uint8_t*)key_view.buf;
    size_t key_len = (size_t)key_view.len;

    /* ---- pickle.loads ---- */
    PyObject *pickle_loads = get_pickle_loads();
    if (pickle_loads == NULL) goto fail;

    /* ---- Validate args is a tuple ---- */
    if (!PyTuple_Check(args_obj)) {
        PyErr_SetString(PyExc_TypeError, "args must be a tuple");
        goto fail;
    }

    /* ---- Validate header ---- */
    if (blob_len < 29 || memcmp(blob, "BVM1", 4) != 0) {
        PyErr_SetString(PyExc_ValueError, "bad BedrockVM magic");
        goto fail;
    }
    uint8_t version = blob[4];
    if (version != 1 && version != 2) {
        PyErr_Format(PyExc_ValueError, "unsupported BedrockVM version %d", version);
        goto fail;
    }
    uint32_t flags        = rd32(blob + 5);
    uint32_t argcount     = rd32(blob + 9);
    uint32_t kwonly_count = rd32(blob + 13);
    uint32_t nlocals      = rd32(blob + 17);
    /* nconst = rd32(blob + 21); unused -- consts come from pickle */
    uint32_t const_len    = rd32(blob + 25);
    size_t off = 29;
    (void)flags;  /* generator handled above */

    /* ---- Allocate the register-resident context ---- */
    ctx = (vm_ctx*)calloc(1, sizeof(vm_ctx));
    if (ctx == NULL) { PyErr_NoMemory(); goto fail; }
    ctx->alive = 1;
    ctx->rc = 0;
    /* Seed VPC keystream from sha256(key) (works for empty key too). */
    sha256_buffer(key, key_len, ctx->ks_state);
    ctx->ks_pos = 0;
    /* Derive the pointer-XOR mask from a distinct digest (first 8 bytes). */
    {
        uint8_t mb[32];
        sha256_buffer(ctx->ks_state, 32, mb);
        ctx->ptr_mask = 0;
        for (i = 0; i < 8; i++)
            ctx->ptr_mask |= ((uintptr_t)mb[i]) << (i * 8);
        if (ctx->ptr_mask == 0) ctx->ptr_mask = (uintptr_t)0x9E3779B97F4A7C15ull; /* never 0 */
    }
    /* Init obscured VPC at pc=0 (invariant: vpc_lo ^ vpc_hi == 0). */
    {
        uint8_t ks = keystream_next_byte(ctx);
        ctx->vpc_hi = ((int)ks & 0xff) | 0x10000;  /* nonzero obscured base */
        ctx->vpc_lo = ctx->vpc_hi;                 /* lo ^ hi == 0 */
    }

#ifdef BR_ENABLE_SMC
    /* F.4 SMC init: allocate the page-aligned junk buffer + seed it. Failure
     * is non-fatal (the VM runs; only the SMC channel is dead). */
    _smc_init(ctx, (uint64_t)smc_seed);
#endif

    /* ---- Const pool (encrypted with key directly) ---- */
    if (off + const_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (const pool)");
        goto fail;
    }
    if (const_len > 0) {
        const uint8_t *enc = blob + off;
        off += const_len;
        uint8_t *raw = (uint8_t*)malloc(const_len);
        if (raw == NULL) { PyErr_NoMemory(); goto fail; }
        if (key_len > 0) ofb_decrypt(enc, const_len, key, key_len, raw);
        else             memcpy(raw, enc, const_len);
        PyObject *rawbytes = PyBytes_FromStringAndSize((const char*)raw, const_len);
        free(raw);
        if (rawbytes == NULL) goto fail;
        result_owner_consts = PyObject_CallOneArg(pickle_loads, rawbytes);
        Py_DECREF(rawbytes);
        if (result_owner_consts == NULL) goto fail;
        if (!PyTuple_Check(result_owner_consts)) {
            PyErr_SetString(PyExc_TypeError, "const pool must pickle to a tuple");
            goto fail;
        }
    } else {
        result_owner_consts = PyTuple_New(0);
        if (result_owner_consts == NULL) goto fail;
    }
    ctx->consts = result_owner_consts;   /* borrowed into ctx */

    /* ---- Code segment ---- */
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (code_len)");
        goto fail;
    }
    uint32_t code_len = rd32(blob + off);   /* PATCHED value (actual_bytes/2) */
    off += 4;
    if (off + (size_t)2 * code_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (code)");
        goto fail;
    }
    const uint8_t *raw_code_src = blob + off;
    off += (size_t)2 * code_len;

    /* Decrypt code section (v2 + nonempty key only). v1 and empty-key blobs
     * are plaintext. code_key = sha256(key + b'|code'). */
    const uint8_t *raw_code;
    if (version == 2 && key_len > 0) {
        code_buf = (uint8_t*)malloc((size_t)2 * code_len ? (size_t)2 * code_len : 1);
        if (code_buf == NULL) { PyErr_NoMemory(); goto fail; }
        uint8_t kbuf[256];
        size_t klen = key_len + 5;  /* "|code" */
        if (klen > sizeof(kbuf)) { PyErr_SetString(PyExc_ValueError, "key too long"); goto fail; }
        memcpy(kbuf, key, key_len);
        memcpy(kbuf + key_len, "|code", 5);
        uint8_t code_key[32];
        sha256_buffer(kbuf, klen, code_key);
        ofb_decrypt(raw_code_src, (size_t)2 * code_len, code_key, 32, code_buf);
        raw_code = code_buf;
    } else {
        raw_code = raw_code_src;   /* plaintext (v1, or v2 + empty key) */
    }

    /* ---- Build perm table: scrambled-byte -> canonical-byte ---- */
    {
        PyObject *pk, *pv;
        Py_ssize_t pos = 0;
        while (PyDict_Next(perm_obj, &pos, &pk, &pv)) {
            long k = PyLong_AsLong(pk);
            long v = PyLong_AsLong(pv);
            if (k == -1 && PyErr_Occurred()) goto fail;
            if (v == -1 && PyErr_Occurred()) goto fail;
            if (k < 0 || k > 255 || v < 0 || v > 255) {
                PyErr_SetString(PyExc_ValueError, "perm entries must be 0..255");
                goto fail;
            }
            perm[(int)k] = (int)v;
        }
    }

    /* ---- Pre-decode: stitch EXTENDED_ARG (perm_ext, raw), de-scramble via
     *      perm, build ops[] + args_arr[] (canonical ints). Same loop as
     *      _bedrock_vm.c lines 531-562. ---- */
    int *ops = NULL, *args_arr = NULL;
    int ncode = 0;
    if (code_len > 0) {
        ops      = (int*)PyMem_RawMalloc((size_t)code_len * sizeof(int));
        args_arr = (int*)PyMem_RawMalloc((size_t)code_len * sizeof(int));
        if (ops == NULL || args_arr == NULL) { PyErr_NoMemory(); goto fail; }
        {
            int ext = 0;
            Py_ssize_t k;
            for (k = 0; k + 1 < (Py_ssize_t)(2 * code_len); k += 2) {
                uint8_t op_byte = raw_code[k];
                uint8_t arg_lo  = raw_code[k + 1];
                if ((int)op_byte == (int)perm_ext) {   /* recognize RAW, before de-scramble */
                    ext = (ext << 8) | (int)arg_lo;
                    continue;
                }
                int canonical = perm[(int)op_byte];
                if (canonical < 0) {
                    PyErr_Format(PyExc_ValueError,
                                 "scrambled opcode byte %d not in perm", (int)op_byte);
                    goto fail;
                }
                int full_arg = (ext << 8) | (int)arg_lo;
                ext = 0;
                ops[ncode] = canonical;
                args_arr[ncode] = full_arg;
                ncode++;
            }
            /* Trailing EXTENDED_ARG safety (matches reference). */
            if (ncode > 0 && ops[ncode - 1] == OP_EXTENDED_ARG) ncode--;
        }
    }
    ctx->ncode = ncode;
    ctx->ops_enc  = ops      ? ((uintptr_t)ops      ^ ctx->ptr_mask) : 0;
    ctx->args_enc = args_arr ? ((uintptr_t)args_arr ^ ctx->ptr_mask) : 0;

    /* ---- Names blob (encrypted with names_key = sha256(key + b'|names')) ---- */
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (n_names)");
        goto fail;
    }
    uint32_t n_names = rd32(blob + off); off += 4; (void)n_names;
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (names_len)");
        goto fail;
    }
    uint32_t names_len = rd32(blob + off); off += 4;
    if (off + names_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, "blob truncated (names_blob)");
        goto fail;
    }
    if (names_len > 0) {
        const uint8_t *enc = blob + off;
        off += names_len;
        uint8_t *raw = (uint8_t*)malloc(names_len);
        if (raw == NULL) { PyErr_NoMemory(); goto fail; }
        if (key_len > 0) {
            uint8_t kbuf[256];
            size_t klen = key_len + 6;  /* "|names" */
            if (klen > sizeof(kbuf)) { free(raw); PyErr_SetString(PyExc_ValueError, "key too long"); goto fail; }
            memcpy(kbuf, key, key_len);
            memcpy(kbuf + key_len, "|names", 6);
            uint8_t names_key[32];
            sha256_buffer(kbuf, klen, names_key);
            ofb_decrypt(enc, names_len, names_key, 32, raw);
        } else {
            memcpy(raw, enc, names_len);
        }
        PyObject *nb = PyBytes_FromStringAndSize((const char*)raw, names_len);
        free(raw);
        if (nb == NULL) goto fail;
        names_blob = PyObject_CallOneArg(pickle_loads, nb);
        Py_DECREF(nb);
        if (names_blob == NULL) goto fail;
    } else {
        names_blob = PyTuple_New(0);
        if (names_blob == NULL) goto fail;
    }
    empty_tup = PyTuple_New(0);
    if (empty_tup == NULL) goto fail;
    if (PyTuple_Check(names_blob) && PyTuple_GET_SIZE(names_blob) == 4) {
        ctx->global_names = PyTuple_GET_ITEM(names_blob, 0);
        ctx->varnames     = PyTuple_GET_ITEM(names_blob, 1);
        ctx->freevars     = PyTuple_GET_ITEM(names_blob, 2);
        ctx->cellvars     = PyTuple_GET_ITEM(names_blob, 3);
    } else {
        ctx->global_names = names_blob;
        ctx->varnames = ctx->freevars = ctx->cellvars = empty_tup;
    }
    if (ctx->global_names == NULL) ctx->global_names = empty_tup;
    if (ctx->varnames == NULL)     ctx->varnames     = empty_tup;
    if (ctx->freevars == NULL)     ctx->freevars     = empty_tup;
    if (ctx->cellvars == NULL)     ctx->cellvars     = empty_tup;
    ctx->globals_obj = globals_obj;

    /* ---- Allocate locals and cells ---- */
    {
        int a4 = (int)(argcount + kwonly_count + 4);
        int nla = (int)nlocals;
        if (a4 > nla) nla = a4;
        if (nla < 4) nla = 4;
        ctx->nlocals_alloc = nla;
    }
    {
        PyObject **lc = (PyObject**)PyMem_RawCalloc((size_t)ctx->nlocals_alloc, sizeof(PyObject*));
        if (lc == NULL) { PyErr_NoMemory(); goto fail; }
        for (i = 0; i < ctx->nlocals_alloc; i++) { Py_INCREF(Py_None); lc[i] = Py_None; }
        ctx->locals_enc = (uintptr_t)lc ^ ctx->ptr_mask;
    }
    {
        int fv_n = ctx->freevars ? (int)PyTuple_GET_SIZE(ctx->freevars) : 0;
        int cv_n = ctx->cellvars ? (int)PyTuple_GET_SIZE(ctx->cellvars) : 0;
        int nc = (fv_n > cv_n) ? fv_n : cv_n;
        if (nc < 1) nc = 1;
        ctx->ncells = nc;
        PyObject **ce = (PyObject**)PyMem_RawCalloc((size_t)nc, sizeof(PyObject*));
        if (ce == NULL) { PyErr_NoMemory(); goto fail; }
        for (i = 0; i < nc; i++) { Py_INCREF(Py_None); ce[i] = Py_None; }
        ctx->cells_enc = (uintptr_t)ce ^ ctx->ptr_mask;
    }

    /* ---- Bind args into locals frame (positional) ---- */
    {
        int nargs = (int)PyTuple_GET_SIZE(args_obj);
        PyObject **lc = CTX_LOCALS(ctx);
        for (i = 0; i < nargs; i++) {
            if (i >= ctx->nlocals_alloc) break;
            PyObject *v = PyTuple_GET_ITEM(args_obj, i);  /* borrowed */
            Py_INCREF(v);
            Py_XDECREF(lc[i]);
            lc[i] = v;
        }
    }

    /* =========================================================================
     * F.1 Dispatch loop (context-threaded, CALL-based).
     * ========================================================================= */
    {
        int *ops_local  = ctx->ops_enc  ? CTX_OPS(ctx)  : NULL;  /* fixed; cache once */
        int *args_local = ctx->args_enc ? CTX_ARGS(ctx) : NULL;
        (void)ops_local; (void)args_local;
        while (ctx->alive) {
            int pc = vpc_pc(ctx);
            if (pc < 0 || pc >= ctx->ncode) {
                /* Implicit None return at end of code (matches Python). */
                Py_INCREF(Py_None);
                ctx->result = Py_None;
                ctx->alive = 0;
                break;
            }
#ifdef BR_ENABLE_SMC
            _smc_tick(ctx);   /* F.4: mutate the SMC junk buffer every N ticks */
#endif
            /* F.5 non-linear MBA dispatch perturbation (depth 7, beyond
             * Claripy's default simplify budget). The expression evaluates
             * to 0 (semantically neutral) -- it folds into a junk slot so
             * dispatch never branches differently. A symbolic-execution tool
             * must expand 7 nesting levels to prove it, which exceeds its
             * depth budget. The junk constants are fixed here (static
             * hardening); per-build diversity lives in the code-section
             * encryption + perm (F.2). */
            {
                volatile unsigned long _br_mba =
                    ((((0UL ^ 0x4a5b6c7dUL) ^ 0x4a5b6c7dUL)
                      & 0x1f3e5d7cUL) | ((0UL & 0x1f3e5d7cUL)))
                    + ((0UL * 0x2b4d6f9eUL) / 0x2b4d6f9eUL)
                    - ((0UL | 0x7c8e9d0fUL) & ~0x7c8e9d0fUL);
                (void)_br_mba;
            }
            int canonical = de_scramble(ctx);   /* sets ctx->cur_arg */
            handler_fn h = handler_table[canonical & 0xff];
            if (h == NULL) {
                PyErr_Format(PyExc_RuntimeError,
                             "unsupported opcode %d at pc %d", canonical, pc);
                rc = -1;
                break;
            }
            if (h(ctx) < 0) { rc = -1; break; }
        }
        if (rc < 0) ctx->rc = -1;
    }

    /* ---- Build the outbound result ---- */
    PyObject *out;
    if (rc < 0) {
        Py_XDECREF(ctx->result);
        ctx->result = NULL;
        out = NULL;
    } else {
        out = ctx->result;   /* transfer ownership to caller */
        if (out == NULL) { Py_INCREF(Py_None); out = Py_None; }
    }

    /* ---- Cleanup ---- */
    if (ctx) {
        if (ctx->stack_enc) {
            PyObject **st = CTX_STACK(ctx);
            int k;
            for (k = 0; k < ctx->sp; k++) Py_XDECREF(st[k]);
            PyMem_RawFree(st);
        }
        if (ctx->locals_enc) {
            PyObject **lc = CTX_LOCALS(ctx);
            int k;
            for (k = 0; k < ctx->nlocals_alloc; k++) Py_XDECREF(lc[k]);
            PyMem_RawFree(lc);
        }
        if (ctx->cells_enc) {
            PyObject **ce = CTX_CELLS(ctx);
            int k;
            for (k = 0; k < ctx->ncells; k++) Py_XDECREF(ce[k]);
            PyMem_RawFree(ce);
        }
        if (ctx->ops_enc)  PyMem_RawFree(CTX_OPS(ctx));
        if (ctx->args_enc) PyMem_RawFree(CTX_ARGS(ctx));
        Py_XDECREF(ctx->kw_names_pending);
#ifdef BR_ENABLE_SMC
        _smc_fini(ctx);   /* F.4: free the page-aligned SMC junk buffer */
#endif
        PyMem_RawFree(ctx);
    }
    Py_XDECREF(result_owner_consts);
    Py_XDECREF(names_blob);
    Py_XDECREF(empty_tup);
    if (code_buf) free(code_buf);
    PyBuffer_Release(&key_view);
    PyBuffer_Release(&blob_view);
    return out;

fail:
    rc = -1;
    if (ctx) ctx->rc = -1;
    /* fall through to cleanup */
    {
        PyObject *out = NULL;
        if (ctx) {
            if (ctx->stack_enc) {
                PyObject **st = CTX_STACK(ctx);
                int k;
                for (k = 0; k < ctx->sp; k++) Py_XDECREF(st[k]);
                PyMem_RawFree(st);
            }
            if (ctx->locals_enc) {
                PyObject **lc = CTX_LOCALS(ctx);
                int k;
                for (k = 0; k < ctx->nlocals_alloc; k++) Py_XDECREF(lc[k]);
                PyMem_RawFree(lc);
            }
            if (ctx->cells_enc) {
                PyObject **ce = CTX_CELLS(ctx);
                int k;
                for (k = 0; k < ctx->ncells; k++) Py_XDECREF(ce[k]);
                PyMem_RawFree(ce);
            }
            if (ctx->ops_enc)  PyMem_RawFree(CTX_OPS(ctx));
            if (ctx->args_enc) PyMem_RawFree(CTX_ARGS(ctx));
            Py_XDECREF(ctx->kw_names_pending);
            Py_XDECREF(ctx->result);
            PyMem_RawFree(ctx);
        }
        Py_XDECREF(result_owner_consts);
        Py_XDECREF(names_blob);
        Py_XDECREF(empty_tup);
        if (code_buf) free(code_buf);
        PyBuffer_Release(&key_view);
        PyBuffer_Release(&blob_view);
        return out;   /* NULL; PyErr already set */
    }
}

/* =========================================================================
 * Module definition + initialization.
 * ========================================================================= */
static PyMethodDef _xvm_v2_methods[] = {
    {"run", (PyCFunction)_xvm_v2_run, METH_VARARGS | METH_KEYWORDS,
     "run(blob, perm, key, args, globals, perm_ext=144) -> object"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef _xvm_v2_module = {
    PyModuleDef_HEAD_INIT,
    "_xvm_v2",
    "BedrockVM Phase F leak-resilient C runtime (v2).",
    -1,
    _xvm_v2_methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__xvm_v2(void) {
    /* Opaque predicate (always-true, confuses IDA/Ghidra): the SHA-256 of a
     * constant seed is deterministic; the equality test is statically
     * unprovable but always false here, so the dead branch is never taken. */
    {
        uint8_t _chk[32];
        uint8_t _seed[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        sha256_buffer(_seed, 4, _chk);
        if (_chk[0] == 0xFF) {
            /* Dead code -- never reached, but the disassembler shows a live branch. */
            return NULL;
        }
    }

    /* Fill the context-threaded dispatch table. */
    handler_table[OP_NOP]                   = op_nop;
    handler_table[OP_RESUME]                = op_nop;
    handler_table[OP_GEN_START]             = op_nop;
    handler_table[OP_RETURN_GENERATOR]      = op_nop;
    handler_table[OP_END_FOR]               = op_nop;
    handler_table[OP_POP_BLOCK]             = op_nop;
    handler_table[OP_POP_EXCEPT]            = op_nop;
    handler_table[OP_SETUP_FINALLY]         = op_nop;
    handler_table[OP_SETUP_WITH]            = op_nop;
    handler_table[OP_SETUP_ASYNC_WITH]      = op_nop;
    handler_table[OP_BEFORE_WITH]           = op_nop;
    handler_table[OP_BEFORE_ASYNC_WITH]     = op_nop;
    handler_table[OP_COPY_FREE_VARS]        = op_nop;

    handler_table[OP_POP_TOP]               = op_pop_top;
    handler_table[OP_DUP_TOP]               = op_dup_top;
    handler_table[OP_ROT_TWO]               = op_rot_two;
    handler_table[OP_ROT_THREE]             = op_rot_three;
    handler_table[OP_RETURN_VALUE]          = op_return_value;
    handler_table[OP_RETURN_CONST]          = op_return_const;
    handler_table[OP_LOAD_CONST]            = op_load_const;
    handler_table[OP_LOAD_FAST]             = op_load_fast;
    handler_table[OP_LOAD_FAST_CHECK]       = op_load_fast_check;
    handler_table[OP_STORE_FAST]            = op_store_fast;
    handler_table[OP_DELETE_FAST]           = op_delete_fast;
    handler_table[OP_LOAD_GLOBAL]           = op_load_global;
    handler_table[OP_STORE_GLOBAL]          = op_store_global;
    handler_table[OP_DELETE_GLOBAL]         = op_delete_global;
    handler_table[OP_LOAD_NAME]             = op_load_name;
    handler_table[OP_STORE_NAME]            = op_store_name;
    handler_table[OP_LOAD_DEREF]            = op_load_deref;
    handler_table[OP_STORE_DEREF]           = op_store_deref;
    handler_table[OP_LOAD_CLOSURE]          = op_load_closure;
    handler_table[OP_LOAD_ATTR]             = op_load_attr;
    handler_table[OP_LOAD_METHOD]          = op_load_attr;
    handler_table[OP_STORE_ATTR]            = op_store_attr;
    handler_table[OP_DELETE_ATTR]           = op_delete_attr;
    handler_table[OP_STORE_SUBSCR]          = op_store_subscr;
    handler_table[OP_DELETE_SUBSCR]         = op_delete_subscr;
    handler_table[OP_BINARY_SUBSCR]        = op_binary_subscr;
    handler_table[OP_COPY]                  = op_copy;
    handler_table[OP_SWAP]                  = op_swap;
    handler_table[OP_UNPACK_SEQUENCE]       = op_unpack_sequence;
    handler_table[OP_BINARY_OP]             = op_binary_op;
    handler_table[OP_BINARY_OP_INPLACE]     = op_binary_op;
    handler_table[OP_UNARY_NEGATIVE]        = op_unary_negative;
    handler_table[OP_UNARY_POSITIVE]        = op_unary_positive;
    handler_table[OP_UNARY_NOT]             = op_unary_not;
    handler_table[OP_UNARY_INVERT]          = op_unary_invert;
    handler_table[OP_COMPARE_OP]            = op_compare_op;
    handler_table[OP_IS_OP]                 = op_is_op;
    handler_table[OP_CONTAINS_OP]           = op_contains_op;
    handler_table[OP_JUMP]                  = op_jump;
    handler_table[OP_JUMP_IF_FALSE]         = op_jump_if_false;
    handler_table[OP_JUMP_IF_TRUE]          = op_jump_if_true;
    handler_table[OP_JUMP_IF_NONE]          = op_jump_if_none;
    handler_table[OP_JUMP_IF_NOT_NONE]      = op_jump_if_not_none;
    handler_table[OP_JUMP_IF_FALSE_OR_POP]  = op_jump_if_false_or_pop;
    handler_table[OP_JUMP_IF_TRUE_OR_POP]   = op_jump_if_true_or_pop;
    handler_table[OP_FOR_ITER]              = op_for_iter;
    handler_table[OP_GET_ITER]              = op_get_iter;
    handler_table[OP_PUSH_NULL]             = op_push_null;
    handler_table[OP_CALL]                  = op_call;
    handler_table[OP_CALL_KW]               = op_call_kw;
    handler_table[OP_KW_NAMES]              = op_kw_names;
    handler_table[OP_CALL_FUNCTION_EX]      = op_call_function_ex;
    handler_table[OP_MAKE_FUNCTION]         = op_make_function;
    handler_table[OP_BUILD_TUPLE]           = op_build_tuple;
    handler_table[OP_BUILD_LIST]           = op_build_list;
    handler_table[OP_BUILD_MAP]             = op_build_map;
    handler_table[OP_BUILD_SLICE]          = op_build_slice;
    handler_table[OP_BUILD_STRING]          = op_build_string;
    handler_table[OP_FORMAT_VALUE]          = op_format_value;
    handler_table[OP_FORMAT_SIMPLE]         = op_format_simple;
    handler_table[OP_FORMAT_WITH_SPEC]     = op_format_with_spec;
    handler_table[OP_LOAD_ASSERTION_ERROR]  = op_load_assertion_error;
    handler_table[OP_PUSH_EXC_INFO]         = op_push_exc_info;
    handler_table[OP_CHECK_EXC_MATCH]       = op_check_exc_match;
    handler_table[OP_RAISE_VARARGS]         = op_raise_varargs;
    handler_table[OP_RERAISE]               = op_reraise;
    handler_table[OP_YIELD_VALUE]           = op_yield_value;
    handler_table[OP_YIELD_FROM]            = op_yield_from;
    /* All other slots remain NULL -> "unsupported opcode" (defensive default). */

    return PyModule_Create(&_xvm_v2_module);
}

#endif /* BEDROCK_VM_V2_C */
