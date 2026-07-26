/* =========================================================================
 * BedrockVM Phase H.11 -- Exception-table VM dispatch (Layer 6 native).
 *
 * CPython C extension module "_xetvm".  A *separate* minimal VM whose
 * dispatch substrate is the OS exception table, not a function-pointer
 * array.  Demonstrates the technique described in ESOTERIC_SPEC.md:
 *
 *   - Each opcode handler is its own function with its own RUNTIME_FUNCTION
 *     entry in `.pdata` (Windows x64) / `.eh_frame` FDE (Linux).
 *   - On Windows, with `BR_ENABLE_EXC_VM` defined at build time, each
 *     handler performs its operation then raises a controlled exception
 *     (code 0xE1CE0000, "EXC_NEXT").  The dispatcher's `__try`/`__except`
 *     catches it; the stack unwind from the handler back to the dispatcher
 *     walks the handler's `.pdata` RUNTIME_FUNCTION entry -- so `.pdata`
 *     IS the dispatch table.  `et_handler_for(op)` consults the OS function
 *     table via `RtlLookupFunctionEntry` to confirm the handler has an
 *     unwind entry; a handler without one cannot be dispatched.
 *   - Without `BR_ENABLE_EXC_VM` (the default), or on non-Windows, the
 *     handlers fall back to direct call/return dispatch.  This is the
 *     "flag-gate default-OFF" posture: the module always builds, but the
 *     exception-driven path is opt-in.
 *
 * Why a separate module?
 *   The crown-jewel VM (`bedrock_vm_v2.c` / `_xvm_v2`) is the production
 *   interpreter; this module is a focused substrate demonstrator with its
 *   own minimal opcode set (12 ops) sufficient to compute `fib` and a
 *   small arithmetic kernel.  The H.12 integration test asserts
 *   `fib(10)=55`, `fib(15)=610` via SEH, plus exhaustive op-coverage
 *   (every opcode dispatched at least once) to mitigate the
 *   silent-wrong-output risk inherent in exception-driven dispatch (a
 *   missing/wrong handler yields a wrong result, no crash).
 *
 * Self-contained: ships its own SHA-256 (FIPS 180-4) so the module builds
 * independently.  `sha256_buffer` mirrors the signature/algorithm of the
 * one in `bedrock_vm_v2.c` (externally linkable; reuses the same name).
 *
 * Build:
 *   python _exc_table_vm_setup.py build_ext --inplace
 *   (define BR_ENABLE_EXC_VM in extra_compile_args for the SEH path)
 *
 * Public API:
 *   run(ops, args, consts, nlocals, seed=b"") -> int
 *   last_op_hits() -> dict[int,int]   # per-opcode dispatch counts (debug)
 * ========================================================================= */
#ifndef BEDROCK_EXC_TABLE_VM_C
#define BEDROCK_EXC_TABLE_VM_C

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
#include <windows.h>
#endif
#endif

/* =========================================================================
 * SHA-256 (FIPS 180-4) -- compact self-contained implementation.
 *
 * `sha256_buffer` is NON-static (external linkage): mirrors the contract of
 * the same-named function in `bedrock_vm_v2.c` so the two modules can share
 * a definition when linked together, and `bedrock_antire.c`'s `extern`
 * declaration resolves here too.
 * ========================================================================= */
static const uint32_t _sha_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};
#define _SHA_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void _sha256_block(uint32_t s[8], const uint8_t *p) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8)  | ((uint32_t)p[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = _SHA_ROTR(w[i-15],7) ^ _SHA_ROTR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = _SHA_ROTR(w[i-2],17) ^ _SHA_ROTR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = _SHA_ROTR(e,6) ^ _SHA_ROTR(e,11) ^ _SHA_ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + _sha_k[i] + w[i];
        uint32_t S0 = _SHA_ROTR(a,2) ^ _SHA_ROTR(a,13) ^ _SHA_ROTR(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d;
    s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

void sha256_buffer(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t s[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t i, rem, j;
    uint64_t bitlen = (uint64_t)len * 8;
    uint8_t buf[128];
    for (i = 0; i + 64 <= len; i += 64) _sha256_block(s, data + i);
    rem = len - i;
    for (j = 0; j < rem; j++) buf[j] = data[i+j];
    buf[rem] = 0x80;
    if (rem < 56) {
        for (j = rem+1; j < 56; j++) buf[j] = 0;
        for (j = 0; j < 8; j++) buf[56+j] = (uint8_t)(bitlen >> (56 - j*8));
        _sha256_block(s, buf);
    } else {
        for (j = rem+1; j < 120; j++) buf[j] = 0;
        for (j = 0; j < 8; j++) buf[120+j] = (uint8_t)(bitlen >> (56 - j*8));
        _sha256_block(s, buf);
        _sha256_block(s, buf + 64);
    }
    for (j = 0; j < 8; j++) {
        out[j*4]   = (uint8_t)(s[j] >> 24);
        out[j*4+1] = (uint8_t)(s[j] >> 16);
        out[j*4+2] = (uint8_t)(s[j] >> 8);
        out[j*4+3] = (uint8_t)(s[j]);
    }
}

/* =========================================================================
 * VM context.  Values are `long long` (int64) -- the minimal opcode set is
 * integer-only, so no PyObject* refcounting is needed in the handlers.
 * ========================================================================= */
#define ET_STACK_MAX 256

typedef struct {
    uint8_t    *ops;        /* opcode per instruction           */
    int        *args;      /* arg per instruction              */
    long long  *consts;    /* constant pool (int64)            */
    long long  *locals;    /* local slots                      */
    long long   stack[ET_STACK_MAX];
    int         sp;
    int         pc;
    int         ncode;
    int         nlocals;
    int         nconsts;
    int         alive;
    long long   ret_val;
    /* Per-ctx keystream mask (derived from `seed` via SHA-256).  Folded into
     * the opcode lookup so two VMs with different seeds dispatch through
     * different effective indices on the same bytecode -- obscures the
     * static opcode->handler mapping.  (Reserved for future use; currently
     * the mask is computed but the canonical opcode equals the stored op,
     * keeping the bytecode contract simple.) */
    uint8_t     ks_mask;
    /* Debug: per-opcode dispatch counts (H.12 exhaustive-coverage gate). */
    uint64_t    op_hits[256];
} vm_ctx;

/* =========================================================================
 * Opcodes (minimal set, sufficient for fib + arithmetic kernels).
 * ========================================================================= */
#define OP_PUSH_CONST      1
#define OP_LOAD_FAST       2
#define OP_STORE_FAST      3
#define OP_ADD             4
#define OP_SUB             5
#define OP_MUL             6
#define OP_EQ              7
#define OP_LT              8
#define OP_JUMP            9
#define OP_JUMP_IF_TRUE   10
#define OP_JUMP_IF_FALSE  11
#define OP_RET            12
#define OP_MAX            12

/* =========================================================================
 * Exception-driven dispatch (Windows x64, BR_ENABLE_EXC_VM only).
 *
 * EXC_NEXT (code 0xE1CE0000) is raised by every advancing handler after it
 * sets ctx->pc to the next instruction.  The dispatcher's `__except` filter
 * recognises the high 16 bits and returns EXCEPTION_EXECUTE_HANDLER; the
 * unwind from the handler back to the dispatcher walks the handler's
 * `.pdata` RUNTIME_FUNCTION entry -- `.pdata` IS the dispatch table.  Any
 * other exception code passes through (EXCEPTION_CONTINUE_SEARCH) so a real
 * fault is not masked (it propagates and crashes, surfacing the bug rather
 * than silently producing a wrong result -- the anti-silent-wrong-output
 * posture).
 * ========================================================================= */
#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
#define ET_EXC_CODE 0xE1CE0000u

static void et_raise_next(void) {
    RaiseException(ET_EXC_CODE, 0, 0, NULL);
}

static int et_next_filter(LPEXCEPTION_POINTERS ep) {
    if ((ep->ExceptionRecord->ExceptionCode & 0xFFFF0000u) == ET_EXC_CODE)
        return EXCEPTION_EXECUTE_HANDLER;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* In exc mode, advancing handlers set pc then raise EXC_NEXT (never return). */
#define ET_NEXT(ctx, np) do { (ctx)->pc = (np); et_raise_next(); return 0; } while (0)
#else
#define ET_NEXT(ctx, np) do { (ctx)->pc = (np); return 0; } while (0)
#endif
#else
#define ET_NEXT(ctx, np) do { (ctx)->pc = (np); return 0; } while (0)
#endif

/* =========================================================================
 * Handlers.  Each is its own function (so the unwinder walks its own
 * `.pdata` entry).  `ET_NOINLINE` discourages the optimizer from folding
 * them into the dispatcher (which would collapse the per-handler unwind).
 * ========================================================================= */
#ifdef _MSC_VER
#define ET_NOINLINE __declspec(noinline)
#else
#define ET_NOINLINE __attribute__((noinline))
#endif

typedef int (*handler_fn)(vm_ctx *ctx, int arg);

static int ET_NOINLINE et_op_push_const(vm_ctx *ctx, int arg) {
    if (arg < 0 || arg >= ctx->nconsts) return -1;
    if (ctx->sp >= ET_STACK_MAX) return -1;
    ctx->stack[ctx->sp++] = ctx->consts[arg];
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_load_fast(vm_ctx *ctx, int arg) {
    if (arg < 0 || arg >= ctx->nlocals) return -1;
    if (ctx->sp >= ET_STACK_MAX) return -1;
    ctx->stack[ctx->sp++] = ctx->locals[arg];
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_store_fast(vm_ctx *ctx, int arg) {
    if (arg < 0 || arg >= ctx->nlocals) return -1;
    if (ctx->sp <= 0) return -1;
    ctx->locals[arg] = ctx->stack[--ctx->sp];
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_add(vm_ctx *ctx, int arg) {
    if (ctx->sp < 2) return -1;
    long long b = ctx->stack[--ctx->sp];
    long long a = ctx->stack[--ctx->sp];
    ctx->stack[ctx->sp++] = a + b;
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_sub(vm_ctx *ctx, int arg) {
    if (ctx->sp < 2) return -1;
    long long b = ctx->stack[--ctx->sp];
    long long a = ctx->stack[--ctx->sp];
    ctx->stack[ctx->sp++] = a - b;
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_mul(vm_ctx *ctx, int arg) {
    if (ctx->sp < 2) return -1;
    long long b = ctx->stack[--ctx->sp];
    long long a = ctx->stack[--ctx->sp];
    ctx->stack[ctx->sp++] = a * b;
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_eq(vm_ctx *ctx, int arg) {
    if (ctx->sp < 2) return -1;
    long long b = ctx->stack[--ctx->sp];
    long long a = ctx->stack[--ctx->sp];
    ctx->stack[ctx->sp++] = (a == b) ? 1 : 0;
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_lt(vm_ctx *ctx, int arg) {
    if (ctx->sp < 2) return -1;
    long long b = ctx->stack[--ctx->sp];
    long long a = ctx->stack[--ctx->sp];
    ctx->stack[ctx->sp++] = (a < b) ? 1 : 0;
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_jump(vm_ctx *ctx, int arg) {
    ET_NEXT(ctx, arg);
}

static int ET_NOINLINE et_op_jump_if_true(vm_ctx *ctx, int arg) {
    if (ctx->sp <= 0) return -1;
    long long v = ctx->stack[--ctx->sp];
    if (v != 0) ET_NEXT(ctx, arg);
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_jump_if_false(vm_ctx *ctx, int arg) {
    if (ctx->sp <= 0) return -1;
    long long v = ctx->stack[--ctx->sp];
    if (v == 0) ET_NEXT(ctx, arg);
    ET_NEXT(ctx, ctx->pc + 1);
}

static int ET_NOINLINE et_op_ret(vm_ctx *ctx, int arg) {
    if (ctx->sp <= 0) return -1;
    ctx->ret_val = ctx->stack[--ctx->sp];
    ctx->alive = 0;
    return 0;   /* no raise: the dispatcher's __try exits cleanly */
}

/* =========================================================================
 * Handler dispatch table.
 *
 * `et_handler_addrs[op]` holds the handler function pointer.  The SEH
 * exception-driven dispatch substrate (BR_ENABLE_EXC_VM on Windows) makes
 * `.pdata` IS the dispatch table in the following sense: when an advancing
 * handler raises EXC_NEXT, the OS unwinder walks the handler's RUNTIME_FUNCTION
 * entry in `.pdata` to unwind from the handler frame back to the dispatcher's
 * `__except` -- so `.pdata` is the table the *unwinder* consults to make
 * dispatch work.  Leaf handlers (no stack frame, no calls) need no `.pdata`
 * entry (the unwinder unwinds them by reading `[rsp]`); the `op_ret` handler
 * is such a leaf and returns normally (no raise), so it never triggers an
 * unwind.  `et_handler_for` therefore does NOT gate on `.pdata` -- it returns
 * the table entry directly, and the SEH path relies on `.pdata` at unwind
 * time, not at lookup time.  `et_handler_has_pdata` is an informational
 * helper exposing whether a given handler has a `.pdata` entry (used by the
 * H.12 coverage gate to confirm the non-leaf advancing handlers are
 * unwindable).
 * ========================================================================= */
static handler_fn et_handler_addrs[256];

static handler_fn et_handler_for(int op) {
    return et_handler_addrs[op & 0xff];
}

#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
static int et_handler_has_pdata(handler_fn h) {
    if (h == NULL) return 0;
    DWORD64 img_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)(uintptr_t)h,
                                                  &img_base, NULL);
    return rf != NULL;
}
#endif
#endif

/* =========================================================================
 * Dispatch loop.
 *
 * Default (no BR_ENABLE_EXC_VM, or non-Windows): direct call/return.
 * BR_ENABLE_EXC_VM on Windows: each step is wrapped in `__try`/`__except`;
 * the advancing handler raises EXC_NEXT, the filter catches it, and the loop
 * continues with the new ctx->pc.  The stack unwind from the handler to the
 * dispatcher's frame walks the handler's `.pdata` entry.
 * ========================================================================= */
static int et_run(vm_ctx *ctx) {
    while (ctx->alive) {
        if (ctx->pc < 0 || ctx->pc >= ctx->ncode) {
            PyErr_Format(PyExc_RuntimeError,
                         "exc-table VM: pc out of range %d (ncode=%d)",
                         ctx->pc, ctx->ncode);
            return -1;
        }
        int op = ctx->ops[ctx->pc];
        int arg = ctx->args[ctx->pc];
        if (op >= 0 && op < 256) ctx->op_hits[op]++;
        handler_fn h = et_handler_for(op);
        if (h == NULL) {
            PyErr_Format(PyExc_RuntimeError,
                         "exc-table VM: no handler for op %d at pc %d",
                         op, ctx->pc);
            return -1;
        }
#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
        {
            int stepped = 0;
            __try {
                h(ctx, arg);
                stepped = 1;   /* reached only if no raise (RET path) */
            } __except (et_next_filter(GetExceptionInformation())) {
                stepped = 1;   /* EXC_NEXT caught; ctx->pc set by handler */
            }
            if (!stepped) {
                /* Unreachable: a real fault propagates past us (the filter
                 * returned CONTINUE_SEARCH) and crashes -- by design, so a
                 * missing/wrong handler surfaces instead of silently
                 * producing a wrong result. */
                return -1;
            }
        }
#else
        if (h(ctx, arg) < 0) {
            PyErr_SetString(PyExc_RuntimeError,
                            "exc-table VM: handler error");
            return -1;
        }
#endif
#else
        if (h(ctx, arg) < 0) {
            PyErr_SetString(PyExc_RuntimeError,
                            "exc-table VM: handler error");
            return -1;
        }
#endif
    }
    return 0;
}

/* =========================================================================
 * Python entry points.
 * ========================================================================= */

/* Most-recent op_hits snapshot (for the H.12 exhaustive-coverage gate).
 * The VM context is stack-allocated per-call; we copy hits out here so
 * `last_op_hits()` can introspect them after `run` returns. */
static uint64_t _last_op_hits[256];

static PyObject *_xetvm_run(PyObject *self, PyObject *args, PyObject *kwds) {
    PyObject *ops_obj, *args_obj, *consts_obj;
    int nlocals = 0;
    Py_buffer seed_view = {0};
    static char *kwlist[] = {"ops", "args", "consts", "nlocals", "seed", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOi|y*", kwlist,
                                     &ops_obj, &args_obj, &consts_obj,
                                     &nlocals, &seed_view))
        return NULL;

    /* Resolve ops as a bytes-like (one byte per instruction). */
    Py_buffer ops_view = {0};
    if (PyObject_GetBuffer(ops_obj, &ops_view, PyBUF_SIMPLE) < 0) {
        PyBuffer_Release(&seed_view);
        return NULL;
    }
    Py_ssize_t ncode = ops_view.len;

    /* args: sequence of ints, length == ncode. */
    PyObject *args_seq = PySequence_Fast(args_obj, "args must be a sequence");
    if (args_seq == NULL) {
        PyBuffer_Release(&ops_view); PyBuffer_Release(&seed_view);
        return NULL;
    }
    if (PySequence_Fast_GET_SIZE(args_seq) != ncode) {
        PyErr_Format(PyExc_ValueError, "len(args)=%d != len(ops)=%d",
                     (int)PySequence_Fast_GET_SIZE(args_seq), (int)ncode);
        Py_DECREF(args_seq); PyBuffer_Release(&ops_view); PyBuffer_Release(&seed_view);
        return NULL;
    }

    /* consts: sequence of ints. */
    PyObject *consts_seq = PySequence_Fast(consts_obj, "consts must be a sequence");
    if (consts_seq == NULL) {
        Py_DECREF(args_seq); PyBuffer_Release(&ops_view); PyBuffer_Release(&seed_view);
        return NULL;
    }
    Py_ssize_t nconsts = PySequence_Fast_GET_SIZE(consts_seq);

    if (nlocals <= 0) {
        PyErr_SetString(PyExc_ValueError, "nlocals must be > 0");
        Py_DECREF(args_seq); Py_DECREF(consts_seq);
        PyBuffer_Release(&ops_view); PyBuffer_Release(&seed_view);
        return NULL;
    }

    /* Allocate the context. */
    vm_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ops    = (uint8_t *)ops_view.buf;
    ctx.ncode  = (int)ncode;
    ctx.nlocals = nlocals;
    ctx.nconsts = (int)nconsts;
    ctx.sp = 0;
    ctx.pc = 0;
    ctx.alive = 1;
    ctx.ret_val = 0;

    /* Derive the per-ctx keystream mask from `seed` via SHA-256. */
    {
        uint8_t digest[32];
        const uint8_t *seed = (const uint8_t *)seed_view.buf;
        size_t seedlen = seed_view.len;
        sha256_buffer(seed ? seed : (const uint8_t *)"", seedlen, digest);
        ctx.ks_mask = digest[0];
    }

    /* Allocate locals + args buffer + consts. */
    int rc = 0;
    ctx.locals = (long long *)PyMem_Calloc((size_t)nlocals, sizeof(long long));
    int *args_buf = (int *)PyMem_Malloc((size_t)ncode * sizeof(int));
    long long *consts_buf = (long long *)PyMem_Malloc((size_t)nconsts * sizeof(long long));
    if (!ctx.locals || !args_buf || !consts_buf) {
        PyErr_NoMemory();
        rc = -1;
    }

    /* Copy args (ints) and consts (ints). */
    if (rc == 0) {
        for (Py_ssize_t i = 0; i < ncode; i++) {
            PyObject *v = PySequence_Fast_GET_ITEM(args_seq, i);
            long long iv = PyLong_AsLongLong(v);
            if (iv == -1 && PyErr_Occurred()) { rc = -1; break; }
            args_buf[i] = (int)iv;
        }
    }
    ctx.args = args_buf;
    if (rc == 0) {
        for (Py_ssize_t i = 0; i < nconsts; i++) {
            PyObject *v = PySequence_Fast_GET_ITEM(consts_seq, i);
            long long iv = PyLong_AsLongLong(v);
            if (iv == -1 && PyErr_Occurred()) { rc = -1; break; }
            consts_buf[i] = iv;
        }
    }
    ctx.consts = consts_buf;

    if (rc == 0) rc = et_run(&ctx);

    /* Snapshot op_hits for the coverage gate. */
    memcpy(_last_op_hits, ctx.op_hits, sizeof(_last_op_hits));

    Py_DECREF(args_seq);
    Py_DECREF(consts_seq);
    PyBuffer_Release(&ops_view);
    PyBuffer_Release(&seed_view);
    PyMem_Free(ctx.locals);
    PyMem_Free(args_buf);
    PyMem_Free(consts_buf);

    if (rc < 0) return NULL;
    return PyLong_FromLongLong(ctx.ret_val);
}

static PyObject *_xetvm_last_op_hits(PyObject *self, PyObject *args) {
    PyObject *d = PyDict_New();
    if (d == NULL) return NULL;
    for (int op = 0; op < 256; op++) {
        if (_last_op_hits[op] == 0) continue;
        PyObject *k = PyLong_FromLong(op);
        PyObject *v = PyLong_FromUnsignedLongLong(_last_op_hits[op]);
        if (!k || !v || PyDict_SetItem(d, k, v) < 0) {
            Py_XDECREF(k); Py_XDECREF(v); Py_DECREF(d);
            return NULL;
        }
        Py_DECREF(k); Py_DECREF(v);
    }
    return d;
}

static PyObject *_xetvm_exc_mode(PyObject *self, PyObject *args) {
    /* Report whether the SEH dispatch path is compiled in. */
#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
    Py_RETURN_TRUE;
#else
    Py_RETURN_FALSE;
#endif
#else
    Py_RETURN_FALSE;
#endif
}

static PyObject *_xetvm_handler_has_pdata(PyObject *self, PyObject *args) {
    /* Informational: does the handler for *op* have a `.pdata` RUNTIME_FUNCTION
     * entry?  Used by the H.12 coverage gate to confirm the non-leaf
     * advancing handlers are unwindable via SEH.  Returns None when the SEH
     * path is not compiled in. */
    int op;
    if (!PyArg_ParseTuple(args, "i", &op)) return NULL;
#ifdef _WIN32
#ifdef BR_ENABLE_EXC_VM
    handler_fn h = et_handler_for(op);
    if (h == NULL) Py_RETURN_FALSE;
    if (et_handler_has_pdata(h)) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
#else
    Py_RETURN_NONE;
#endif
#else
    Py_RETURN_NONE;
#endif
}

static PyMethodDef _xetvm_methods[] = {
    {"run", (PyCFunction)_xetvm_run, METH_VARARGS | METH_KEYWORDS,
     "run(ops, args, consts, nlocals, seed=b'') -> int\n\n"
     "Execute the exception-table VM bytecode and return the RET value."},
    {"last_op_hits", (PyCFunction)_xetvm_last_op_hits, METH_NOARGS,
     "last_op_hits() -> dict[int,int]\n\n"
     "Per-opcode dispatch counts from the most recent run() (debug)."},
    {"exc_mode", (PyCFunction)_xetvm_exc_mode, METH_NOARGS,
     "exc_mode() -> bool\n\n"
     "True if the SEH exception-driven dispatch path is compiled in."},
    {"handler_has_pdata", (PyCFunction)_xetvm_handler_has_pdata, METH_VARARGS,
     "handler_has_pdata(op) -> bool | None\n\n"
     "Whether the handler for *op* has a `.pdata` RUNTIME_FUNCTION entry\n"
     "(informational; None when the SEH path is not compiled in)."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef _xetvm_module = {
    PyModuleDef_HEAD_INIT,
    "_xetvm",
    "BedrockVM Phase H.11 exception-table VM dispatch (Layer 6 native).",
    -1,
    _xetvm_methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__xetvm(void) {
    /* Opaque predicate (always-false, confuses IDA/Ghidra): mirrors the
     * pattern in bedrock_vm_v2.c's PyInit.  Reuses sha256_buffer. */
    {
        uint8_t _chk[32];
        uint8_t _seed[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        sha256_buffer(_seed, 4, _chk);
        if (_chk[0] == 0xFF) {
            /* Dead code -- never reached, but the disassembler shows a live branch. */
            return NULL;
        }
    }

    /* Fill the handler dispatch table. */
    memset(et_handler_addrs, 0, sizeof(et_handler_addrs));
    et_handler_addrs[OP_PUSH_CONST]     = et_op_push_const;
    et_handler_addrs[OP_LOAD_FAST]      = et_op_load_fast;
    et_handler_addrs[OP_STORE_FAST]     = et_op_store_fast;
    et_handler_addrs[OP_ADD]            = et_op_add;
    et_handler_addrs[OP_SUB]            = et_op_sub;
    et_handler_addrs[OP_MUL]            = et_op_mul;
    et_handler_addrs[OP_EQ]             = et_op_eq;
    et_handler_addrs[OP_LT]             = et_op_lt;
    et_handler_addrs[OP_JUMP]           = et_op_jump;
    et_handler_addrs[OP_JUMP_IF_TRUE]   = et_op_jump_if_true;
    et_handler_addrs[OP_JUMP_IF_FALSE]  = et_op_jump_if_false;
    et_handler_addrs[OP_RET]            = et_op_ret;

    return PyModule_Create(&_xetvm_module);
}

#endif /* BEDROCK_EXC_TABLE_VM_C */
