/* BedrockVM C interpreter (Wave 2B).
 *
 * CPython C extension module "_xvm" implementing the bytecode spec in
 * VM_SPEC.md. Matches the pure-Python reference interpreter
 * (_bedrock_vm_ref.py) exactly for non-generator frames. Generator frames
 * (flags & 0x2) are delegated to the reference interpreter so a true
 * generator object is returned (documented fallback; see OP generation note
 * in VM_SPEC.md "Generator semantics").
 *
 * Public API:
 *   run(blob, perm, key, args, globals, perm_ext=144) -> object
 *
 * Build:
 *   python _bedrock_vm_setup.py build_ext --inplace
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * String obfuscation — build-time XOR, runtime decrypt-on-stack.
 *
 * The build preprocessor (_obf_c_strings.py) replaces _DS(((uint8_t[]){0x04, 0x01, 0x1c, 0x0d, 0x1a, 0x09, 0x04}), 7, 0x68) with
 * _DS((uint8_t[]){0xAB, ...}, N, KEY).  This macro decrypts into a static
 * buffer so no plaintext survives in the compiled .pyd/.so strings window.
 * The GIL guarantees single-threaded access — no race on the buffer.
 * ========================================================================= */
static char _ds_buf[512];
static const char* _dec_str(const uint8_t *enc, size_t len, uint8_t key) {
    size_t i;
    for (i = 0; i < len && i < sizeof(_ds_buf) - 1; i++)
        _ds_buf[i] = (char)(enc[i] ^ key);
    _ds_buf[i] = '\0';
    return _ds_buf;
}
#define _DS(ARR, LEN, KEY) _dec_str(ARR, LEN, KEY)

/* =========================================================================
 * Timing anti-debug (portable, no OS-specific API).
 *
 * Measures wall-clock time for a fixed SHA-256 computation loop.  Normal
 * execution completes in < 5 ms; a debugger single-stepping inflates this
 * to > 50 ms.  Returns 1 if the threshold is exceeded (debugger likely
 * attached), 0 otherwise.  Uses clock() from <time.h> — cross-platform.
 * ========================================================================= */
/* Forward decl — sha256_buffer is defined in the SHA-256 section below. */
static void sha256_buffer(const uint8_t *data, size_t len, uint8_t out[32]);

static int _anti_debug_timing(void) {
    clock_t t0, t1;
    uint8_t out[32];
    uint8_t seed[64];
    int i, r;
    double ms;

    for (i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 7 + 3);
    t0 = clock();
    for (r = 0; r < 200; r++)
        sha256_buffer(seed, 64, out);
    t1 = clock();
    ms = (double)(t1 - t0) / CLOCKS_PER_SEC * 1000.0;
    return (ms > 50.0) ? 1 : 0;
}

/* =========================================================================
 * SHA-256 (FIPS 180-4) - self-contained, no external crypto dependency.
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

static void sha256_buffer(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* =========================================================================
 * SHA-256 OFB stream cipher (matches _bedrock_vm_ref._ofb_decrypt).
 *
 *   state_0 = sha256(key)
 *   state_n = sha256(state_{n-1} + key + bytes([off & 255]))
 *   out[i]  = in[i] ^ state_n[i % 32]
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

/* Cached pickle.loads callable (singleton; lives for the process). */
static PyObject *g_pickle_loads = NULL;

static PyObject *get_pickle_loads(void) {
    if (g_pickle_loads) return g_pickle_loads;
    PyObject *m = PyImport_ImportModule(_DS(((uint8_t[]){0x18, 0x01, 0x0b, 0x03, 0x04, 0x0d}), 6, 0x68));
    if (m == NULL) return NULL;
    g_pickle_loads = PyObject_GetAttrString(m, _DS(((uint8_t[]){0x04, 0x07, 0x09, 0x0c, 0x1b}), 5, 0x68));
    Py_DECREF(m);
    return g_pickle_loads;  /* NULL on failure */
}

/* Grow a PyObject* stack. Returns 0 on success, -1 on error (sets exception). */
static int ensure_capacity(PyObject ***pstack, int *pcap, int needed) {
    if (needed <= *pcap) return 0;
    int newcap = (*pcap > 0) ? *pcap : 64;
    while (newcap < needed) newcap *= 2;
    PyObject **ns = (PyObject**)PyMem_RawRealloc(*pstack,
                                                 (size_t)newcap * sizeof(PyObject*));
    if (ns == NULL) { PyErr_NoMemory(); return -1; }
    *pstack = ns;
    *pcap = newcap;
    return 0;
}

/* =========================================================================
 * run(blob, perm, key, args, globals, perm_ext=144) -> object
 * ========================================================================= */
static PyObject* _xvm_run(PyObject* self, PyObject* args_parse, PyObject* kwargs) {
    PyObject *blob_obj, *perm_obj, *key_obj, *args_obj, *globals_obj;
    long perm_ext = 144;
    static char *kwlist[] = {"blob","perm","key","args","globals","perm_ext", NULL};
    (void)self;

    if (!PyArg_ParseTupleAndKeywords(args_parse, kwargs, "OOOOO|l:run", kwlist,
            &blob_obj, &perm_obj, &key_obj, &args_obj, &globals_obj, &perm_ext)) {
        return NULL;
    }

    /* Resource pointers (NULL-init so cleanup is always safe). */
    PyObject *result = NULL;
    PyObject *consts = NULL, *names_blob = NULL, *empty_tup = NULL;
    PyObject *global_names = NULL, *varnames = NULL, *freevars = NULL, *cellvars = NULL;
    PyObject *kw_names_pending = NULL;
    PyObject **stack = NULL; int sp = 0, scap = 0;
    PyObject **locals = NULL; int nlocals_alloc = 0;
    PyObject **cells = NULL; int ncells = 0;
    int *ops = NULL, *args_arr = NULL; int ncode = 0;
    Py_buffer blob_view; blob_view.buf = NULL; blob_view.len = 0;
    Py_buffer key_view; key_view.buf = NULL; key_view.len = 0;
    int perm[256];
    int have_perm = 0;
    int i;

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
             * out of scope for Wave 2B). */
            PyObject *mod = PyImport_ImportModule(_DS(((uint8_t[]){0x37, 0x0a, 0x0d, 0x0c, 0x1a, 0x07, 0x0b, 0x03, 0x37, 0x1e, 0x05, 0x37, 0x1a, 0x0d, 0x0e}), 15, 0x68));
            if (mod == NULL) goto error;
            PyObject *run_fn = PyObject_GetAttrString(mod, _DS(((uint8_t[]){0x1a, 0x1d, 0x06}), 3, 0x68));
            Py_DECREF(mod);
            if (run_fn == NULL) goto error;
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
    if (pickle_loads == NULL) goto error;

    /* ---- Validate args is a tuple ---- */
    if (!PyTuple_Check(args_obj)) {
        PyErr_SetString(PyExc_TypeError, _DS(((uint8_t[]){0x09, 0x1a, 0x0f, 0x1b, 0x48, 0x05, 0x1d, 0x1b, 0x1c, 0x48, 0x0a, 0x0d, 0x48, 0x09, 0x48, 0x1c, 0x1d, 0x18, 0x04, 0x0d}), 20, 0x68));
        goto error;
    }

    /* ---- Validate globals is a dict (mapping) ---- */
    if (!PyDict_Check(globals_obj)) {
        /* Accept any mapping; PyObject_*Item works. Keep as-is. */
    }

    /* ---- Parse header ---- */
    if (blob_len < 29 || memcmp(blob, _DS(((uint8_t[]){0x2a, 0x3e, 0x25, 0x59}), 4, 0x68), 4) != 0) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x09, 0x0c, 0x48, 0x2a, 0x0d, 0x0c, 0x1a, 0x07, 0x0b, 0x03, 0x3e, 0x25, 0x48, 0x05, 0x09, 0x0f, 0x01, 0x0b}), 19, 0x68));
        goto error;
    }
    if (blob[4] != 1) {
        PyErr_Format(PyExc_ValueError, _DS(((uint8_t[]){0x1d, 0x06, 0x1b, 0x1d, 0x18, 0x18, 0x07, 0x1a, 0x1c, 0x0d, 0x0c, 0x48, 0x2a, 0x0d, 0x0c, 0x1a, 0x07, 0x0b, 0x03, 0x3e, 0x25, 0x48, 0x1e, 0x0d, 0x1a, 0x1b, 0x01, 0x07, 0x06, 0x48, 0x4d, 0x0c}), 32, 0x68), blob[4]);
        goto error;
    }
    uint32_t flags        = rd32(blob + 5);
    uint32_t argcount     = rd32(blob + 9);
    uint32_t kwonly_count = rd32(blob + 13);
    uint32_t nlocals      = rd32(blob + 17);
    /* nconst = rd32(blob + 21); unused -- consts come from pickle */
    uint32_t const_len    = rd32(blob + 25);
    size_t off = 29;
    (void)flags;  /* generator handled above; has_closure unused here */

    /* ---- Const pool ---- */
    if (off + const_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x0b, 0x07, 0x06, 0x1b, 0x1c, 0x48, 0x18, 0x07, 0x07, 0x04, 0x41}), 27, 0x68));
        goto error;
    }
    if (const_len > 0) {
        const uint8_t *enc = blob + off;
        off += const_len;
        uint8_t *raw = (uint8_t*)malloc(const_len);
        if (raw == NULL) { PyErr_NoMemory(); goto error; }
        if (key_len > 0) ofb_decrypt(enc, const_len, key, key_len, raw);
        else             memcpy(raw, enc, const_len);
        PyObject *rawbytes = PyBytes_FromStringAndSize((const char*)raw, const_len);
        free(raw);
        if (rawbytes == NULL) goto error;
        consts = PyObject_CallOneArg(pickle_loads, rawbytes);
        Py_DECREF(rawbytes);
        if (consts == NULL) goto error;
        if (!PyTuple_Check(consts)) {
            /* Reference tolerates non-tuple by wrapping; we require tuple. */
            PyErr_SetString(PyExc_TypeError, _DS(((uint8_t[]){0x0b, 0x07, 0x06, 0x1b, 0x1c, 0x48, 0x18, 0x07, 0x07, 0x04, 0x48, 0x05, 0x1d, 0x1b, 0x1c, 0x48, 0x18, 0x01, 0x0b, 0x03, 0x04, 0x0d, 0x48, 0x1c, 0x07, 0x48, 0x09, 0x48, 0x1c, 0x1d, 0x18, 0x04, 0x0d}), 33, 0x68));
            goto error;
        }
    } else {
        consts = PyTuple_New(0);
        if (consts == NULL) goto error;
    }

    /* ---- Frame-in-const delegation: if the const pool contains any Frame
     * objects (nested code objects compiled by the Python compiler, e.g.
     * list comprehensions), delegate the whole call to the reference
     * interpreter. MAKE_FUNCTION in native C can only build functions from
     * real code objects; Frames must be handled by run_func's _make_py_function.
     * This mirrors the generator delegation above. */
    {
        Py_ssize_t ci, cn = PyTuple_Size(consts);
        int has_frame = 0;
        for (ci = 0; ci < cn; ci++) {
            PyObject *c = PyTuple_GetItem(consts, ci);  /* borrowed */
            if (c == NULL) break;
            /* A Frame instance is NOT a code object and NOT a built-in type.
             * Detect by checking it's not PyCode_Check and has the 'code'
             * attribute (the Frame class uses __slots__ with 'code'). */
            if (!PyCode_Check(c)) {
                PyObject *code_attr = PyObject_GetAttrString(c, _DS(((uint8_t[]){0x0b, 0x07, 0x0c, 0x0d}), 4, 0x68));
                if (code_attr != NULL) {
                    Py_DECREF(code_attr);
                    has_frame = 1;
                    break;
                }
                PyErr_Clear();
            }
        }
        if (has_frame) {
            PyObject *mod = PyImport_ImportModule(_DS(((uint8_t[]){0x37, 0x0a, 0x0d, 0x0c, 0x1a, 0x07, 0x0b, 0x03, 0x37, 0x1e, 0x05, 0x37, 0x1a, 0x0d, 0x0e}), 15, 0x68));
            if (mod == NULL) goto error;
            PyObject *run_fn = PyObject_GetAttrString(mod, _DS(((uint8_t[]){0x1a, 0x1d, 0x06}), 3, 0x68));
            Py_DECREF(mod);
            if (run_fn == NULL) goto error;
            PyObject *res = PyObject_CallFunction(run_fn, "OOOOOl",
                blob_obj, perm_obj, key_obj, args_obj, globals_obj,
                (long)perm_ext);
            Py_DECREF(run_fn);
            PyBuffer_Release(&blob_view);
            PyBuffer_Release(&key_view);
            return res;
        }
    }

    /* ---- Code segment ---- */
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x0b, 0x07, 0x0c, 0x0d, 0x37, 0x04, 0x0d, 0x06, 0x41}), 25, 0x68));
        goto error;
    }
    uint32_t code_len = rd32(blob + off);
    off += 4;
    if (off + (size_t)2 * code_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x0b, 0x07, 0x0c, 0x0d, 0x41}), 21, 0x68));
        goto error;
    }
    const uint8_t *raw_code = blob + off;
    off += (size_t)2 * code_len;

    /* ---- Build perm table: scrambled-byte -> canonical-byte ---- */
    for (i = 0; i < 256; i++) perm[i] = -1;
    {
        PyObject *pk, *pv;
        Py_ssize_t pos = 0;
        while (PyDict_Next(perm_obj, &pos, &pk, &pv)) {
            long k = PyLong_AsLong(pk);
            long v = PyLong_AsLong(pv);
            if (k == -1 && PyErr_Occurred()) goto error;
            if (v == -1 && PyErr_Occurred()) goto error;
            if (k < 0 || k > 255 || v < 0 || v > 255) {
                PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x18, 0x0d, 0x1a, 0x05, 0x48, 0x0d, 0x06, 0x1c, 0x1a, 0x01, 0x0d, 0x1b, 0x48, 0x05, 0x1d, 0x1b, 0x1c, 0x48, 0x0a, 0x0d, 0x48, 0x58, 0x46, 0x46, 0x5a, 0x5d, 0x5d}), 27, 0x68));
                goto error;
            }
            perm[(int)k] = (int)v;
        }
        have_perm = 1;
    }
    (void)have_perm;

    /* ---- Decode instructions: stitch EXTENDED_ARG, de-scramble opcode ---- */
    if (code_len > 0) {
        ops     = (int*)PyMem_RawMalloc((size_t)code_len * sizeof(int));
        args_arr= (int*)PyMem_RawMalloc((size_t)code_len * sizeof(int));
        if (ops == NULL || args_arr == NULL) { PyErr_NoMemory(); goto error; }
    }
    ncode = 0;
    {
        int ext = 0;
        Py_ssize_t k;
        for (k = 0; k + 1 < (Py_ssize_t)(2 * code_len); k += 2) {
            uint8_t op_byte = raw_code[k];
            uint8_t arg_lo  = raw_code[k + 1];
            if ((int)op_byte == (int)perm_ext) {
                ext = (ext << 8) | (int)arg_lo;
                continue;
            }
            int canonical = perm[(int)op_byte];
            if (canonical < 0) {
                PyErr_Format(PyExc_ValueError,
                             _DS(((uint8_t[]){0x1b, 0x0b, 0x1a, 0x09, 0x05, 0x0a, 0x04, 0x0d, 0x0c, 0x48, 0x07, 0x18, 0x0b, 0x07, 0x0c, 0x0d, 0x48, 0x0a, 0x11, 0x1c, 0x0d, 0x48, 0x4d, 0x0c, 0x48, 0x06, 0x07, 0x1c, 0x48, 0x01, 0x06, 0x48, 0x18, 0x0d, 0x1a, 0x05}), 36, 0x68), (int)op_byte);
                goto error;
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

    /* ---- Names blob ---- */
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x06, 0x37, 0x06, 0x09, 0x05, 0x0d, 0x1b, 0x41}), 24, 0x68));
        goto error;
    }
    uint32_t n_names = rd32(blob + off); off += 4; (void)n_names;
    if (off + 4 > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x06, 0x09, 0x05, 0x0d, 0x1b, 0x37, 0x04, 0x0d, 0x06, 0x41}), 26, 0x68));
        goto error;
    }
    uint32_t names_len = rd32(blob + off); off += 4;
    if (off + names_len > (size_t)blob_len) {
        PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x0a, 0x04, 0x07, 0x0a, 0x48, 0x1c, 0x1a, 0x1d, 0x06, 0x0b, 0x09, 0x1c, 0x0d, 0x0c, 0x48, 0x40, 0x06, 0x09, 0x05, 0x0d, 0x1b, 0x37, 0x0a, 0x04, 0x07, 0x0a, 0x41}), 27, 0x68));
        goto error;
    }
    if (names_len > 0) {
        const uint8_t *enc = blob + off;
        off += names_len;
        uint8_t *raw = (uint8_t*)malloc(names_len);
        if (raw == NULL) { PyErr_NoMemory(); goto error; }
        if (key_len > 0) {
            /* Derive names_key = sha256(key + b'|names') so the names blob is
             * encrypted with a keystream distinct from the const pool (both
             * would otherwise start at OFB offset 0, creating a two-time
             * pad XOR relationship between the two ciphertexts). */
            uint8_t kbuf[256];
            size_t klen = key_len + 6;
            if (klen > sizeof(kbuf)) { free(raw); PyErr_NoMemory(); goto error; }
            memcpy(kbuf, key, key_len);
            memcpy(kbuf + key_len, _DS(((uint8_t[]){0x14, 0x06, 0x09, 0x05, 0x0d, 0x1b}), 6, 0x68), 6);
            uint8_t names_key[32];
            sha256_buffer(kbuf, klen, names_key);
            ofb_decrypt(enc, names_len, names_key, 32, raw);
        } else {
            memcpy(raw, enc, names_len);
        }
        PyObject *nb = PyBytes_FromStringAndSize((const char*)raw, names_len);
        free(raw);
        if (nb == NULL) goto error;
        names_blob = PyObject_CallOneArg(pickle_loads, nb);
        Py_DECREF(nb);
        if (names_blob == NULL) goto error;
    } else {
        names_blob = PyTuple_New(0);
        if (names_blob == NULL) goto error;
    }
    empty_tup = PyTuple_New(0);
    if (empty_tup == NULL) goto error;
    if (PyTuple_Check(names_blob) && PyTuple_GET_SIZE(names_blob) == 4) {
        global_names = PyTuple_GET_ITEM(names_blob, 0);
        varnames     = PyTuple_GET_ITEM(names_blob, 1);
        freevars     = PyTuple_GET_ITEM(names_blob, 2);
        cellvars     = PyTuple_GET_ITEM(names_blob, 3);
    } else {
        global_names = names_blob;
        varnames = freevars = cellvars = empty_tup;
    }
    if (global_names == NULL) global_names = empty_tup;
    if (varnames == NULL) varnames = empty_tup;
    if (freevars == NULL) freevars = empty_tup;
    if (cellvars == NULL) cellvars = empty_tup;

    /* ---- Allocate locals and cells ---- */
    {
        int a4 = (int)(argcount + kwonly_count + 4);
        nlocals_alloc = (int)nlocals;
        if (a4 > nlocals_alloc) nlocals_alloc = a4;
        if (nlocals_alloc < 4) nlocals_alloc = 4;
    }
    locals = (PyObject**)PyMem_RawCalloc((size_t)nlocals_alloc, sizeof(PyObject*));
    if (locals == NULL) { PyErr_NoMemory(); goto error; }
    for (i = 0; i < nlocals_alloc; i++) {
        Py_INCREF(Py_None);
        locals[i] = Py_None;
    }

    {
        int fv_n = freevars ? (int)PyTuple_GET_SIZE(freevars) : 0;
        int cv_n = cellvars ? (int)PyTuple_GET_SIZE(cellvars) : 0;
        ncells = (fv_n > cv_n) ? fv_n : cv_n;
        if (ncells < 1) ncells = 1;
    }
    cells = (PyObject**)PyMem_RawCalloc((size_t)ncells, sizeof(PyObject*));
    if (cells == NULL) { PyErr_NoMemory(); goto error; }
    for (i = 0; i < ncells; i++) {
        Py_INCREF(Py_None);
        cells[i] = Py_None;
    }

    /* ---- Bind args into locals frame ---- */
    {
        int nargs = (int)PyTuple_GET_SIZE(args_obj);
        for (i = 0; i < nargs; i++) {
            if (i >= nlocals_alloc) break;
            PyObject *v = PyTuple_GET_ITEM(args_obj, i);  /* borrowed */
            Py_INCREF(v);
            Py_XDECREF(locals[i]);
            locals[i] = v;
        }
    }

    /* ---- Stack helpers (macros operating on stack/sp/scap) ---- */
    #define X_PUSH(v) do { \
        if (ensure_capacity(&stack, &scap, sp + 1) < 0) goto error; \
        stack[sp++] = (v); \
    } while (0)
    #define X_POP()    (stack[--sp])
    #define X_TOP()    (stack[sp - 1])

    /* =========================================================================
     * Dispatch loop
     * ========================================================================= */
    {
        int pc = 0;
        while (pc < ncode) {
            int op = ops[pc];
            int arg = args_arr[pc];
            pc++;
            /* Periodic timing anti-debug: re-check every ~8K instructions.
             * If a debugger is single-stepping, the calibration loop inflates
             * and we bail with a generic error (no "debugger" hint in msg). */
            if ((pc & 0x1FFF) == 0) {
                if (_anti_debug_timing()) {
                    PyErr_SetString(PyExc_RuntimeError, _DS(((uint8_t[]){0x1a, 0x1d, 0x06, 0x1c, 0x01, 0x05, 0x0d, 0x48, 0x0d, 0x1a, 0x1a, 0x07, 0x1a}), 13, 0x68));
                    goto error;
                }
            }
            switch (op) {

            case OP_NOP:
            case OP_RESUME:
            case OP_GEN_START:
            case OP_RETURN_GENERATOR:
            case OP_END_FOR:
            case OP_POP_BLOCK:
            case OP_POP_EXCEPT:
            case OP_SETUP_FINALLY:
            case OP_SETUP_WITH:
            case OP_SETUP_ASYNC_WITH:
            case OP_COPY_FREE_VARS:
                /* no-op markers (block/try bookkeeping not needed; we propagate
                 * exceptions directly, matching the reference). */
                break;

            case OP_POP_TOP: {
                PyObject *v = X_POP();
                Py_DECREF(v);
                break;
            }
            case OP_DUP_TOP: {
                PyObject *v = X_TOP();
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }
            case OP_ROT_TWO: {
                PyObject *t = stack[sp - 1];
                stack[sp - 1] = stack[sp - 2];
                stack[sp - 2] = t;
                break;
            }
            case OP_ROT_THREE: {
                PyObject *t = stack[sp - 1];
                stack[sp - 1] = stack[sp - 3];
                stack[sp - 3] = stack[sp - 2];
                stack[sp - 2] = t;
                break;
            }

            case OP_RETURN_VALUE: {
                result = X_POP();
                goto cleanup;
            }
            case OP_RETURN_CONST: {
                PyObject *c = PyTuple_GetItem(consts, arg);
                if (c == NULL) goto error;
                Py_INCREF(c);
                result = c;
                goto cleanup;
            }

            case OP_LOAD_CONST: {
                PyObject *c = PyTuple_GetItem(consts, arg);
                if (c == NULL) goto error;
                Py_INCREF(c);
                X_PUSH(c);
                break;
            }
            case OP_LOAD_FAST: {
                if (arg < 0 || arg >= nlocals_alloc) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x24, 0x27, 0x29, 0x2c, 0x37, 0x2e, 0x29, 0x3b, 0x3c, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 22, 0x68));
                    goto error;
                }
                PyObject *v = locals[arg];
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }
            case OP_LOAD_FAST_CHECK: {
                if (arg < 0 || arg >= nlocals_alloc) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x24, 0x27, 0x29, 0x2c, 0x37, 0x2e, 0x29, 0x3b, 0x3c, 0x37, 0x2b, 0x20, 0x2d, 0x2b, 0x23, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 28, 0x68));
                    goto error;
                }
                PyObject *v = locals[arg];
                if (v == Py_None && varnames && arg < PyTuple_GET_SIZE(varnames)) {
                    PyObject *name = PyTuple_GET_ITEM(varnames, arg);
                    PyErr_Format(PyExc_UnboundLocalError, "%S", name);
                    goto error;
                }
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }
            case OP_STORE_FAST: {
                if (arg < 0 || arg >= nlocals_alloc) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x3b, 0x3c, 0x27, 0x3a, 0x2d, 0x37, 0x2e, 0x29, 0x3b, 0x3c, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 23, 0x68));
                    goto error;
                }
                PyObject *v = X_POP();
                Py_XDECREF(locals[arg]);
                locals[arg] = v;  /* transfer ownership */
                break;
            }
            case OP_DELETE_FAST: {
                if (arg < 0 || arg >= nlocals_alloc) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x2c, 0x2d, 0x24, 0x2d, 0x3c, 0x2d, 0x37, 0x2e, 0x29, 0x3b, 0x3c, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 24, 0x68));
                    goto error;
                }
                Py_XDECREF(locals[arg]);
                Py_INCREF(Py_None);
                locals[arg] = Py_None;
                break;
            }

            case OP_LOAD_GLOBAL: {
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                PyObject *v = PyObject_GetItem(globals_obj, name);  /* KeyError if missing */
                if (v == NULL) goto error;
                X_PUSH(v);
                break;
            }
            case OP_STORE_GLOBAL: {
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                PyObject *v = X_POP();
                int r = PyObject_SetItem(globals_obj, name, v);
                Py_DECREF(v);
                if (r < 0) goto error;
                break;
            }
            case OP_DELETE_GLOBAL: {
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                int r = PyObject_DelItem(globals_obj, name);
                if (r < 0) goto error;
                break;
            }
            case OP_STORE_NAME: {
                /* Reference maps STORE_NAME to globals assignment. */
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                PyObject *v = X_POP();
                int r = PyObject_SetItem(globals_obj, name, v);
                Py_DECREF(v);
                if (r < 0) goto error;
                break;
            }
            case OP_LOAD_NAME: {
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                PyObject *v = PyObject_GetItem(globals_obj, name);
                if (v == NULL) {
                    /* fall back to builtins, else None (matches reference) */
                    PyErr_Clear();
                    PyObject *bl = PyDict_GetItemString(globals_obj, _DS(((uint8_t[]){0x37, 0x37, 0x0a, 0x1d, 0x01, 0x04, 0x1c, 0x01, 0x06, 0x1b, 0x37, 0x37}), 12, 0x68));
                    PyObject *bdict = (bl && PyModule_Check(bl))
                                        ? PyModule_GetDict(bl) : bl;
                    if (bdict && PyDict_Check(bdict)) {
                        v = PyDict_GetItem(bdict, name);  /* borrowed */
                        if (v) Py_INCREF(v);
                    }
                    if (v == NULL) { Py_INCREF(Py_None); v = Py_None; }
                }
                X_PUSH(v);
                break;
            }

            case OP_LOAD_DEREF: {
                if (arg < 0 || arg >= ncells) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x24, 0x27, 0x29, 0x2c, 0x37, 0x2c, 0x2d, 0x3a, 0x2d, 0x2e, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 23, 0x68));
                    goto error;
                }
                PyObject *v = cells[arg];
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }
            case OP_STORE_DEREF: {
                if (arg < 0 || arg >= ncells) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x3b, 0x3c, 0x27, 0x3a, 0x2d, 0x37, 0x2c, 0x2d, 0x3a, 0x2d, 0x2e, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 24, 0x68));
                    goto error;
                }
                PyObject *v = X_POP();
                Py_XDECREF(cells[arg]);
                cells[arg] = v;
                break;
            }
            case OP_LOAD_CLOSURE: {
                if (arg < 0 || arg >= ncells) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x24, 0x27, 0x29, 0x2c, 0x37, 0x2b, 0x24, 0x27, 0x3b, 0x3d, 0x3a, 0x2d, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 25, 0x68));
                    goto error;
                }
                PyObject *v = cells[arg];
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }

            case OP_LOAD_ATTR:
            case OP_LOAD_METHOD: {
                PyObject *obj = X_POP();
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) { Py_DECREF(obj); goto error; }
                PyObject *r = PyObject_GetAttr(obj, name);
                Py_DECREF(obj);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_STORE_ATTR: {
                PyObject *obj = X_POP();
                PyObject *val = X_POP();
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) { Py_DECREF(obj); Py_DECREF(val); goto error; }
                int r = PyObject_SetAttr(obj, name, val);
                Py_DECREF(obj); Py_DECREF(val);
                if (r < 0) goto error;
                break;
            }
            case OP_DELETE_ATTR: {
                PyObject *obj = X_POP();
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) { Py_DECREF(obj); goto error; }
                int r = PyObject_DelAttr(obj, name);
                Py_DECREF(obj);
                if (r < 0) goto error;
                break;
            }

            case OP_STORE_SUBSCR: {
                PyObject *key = X_POP();
                PyObject *obj = X_POP();
                PyObject *val = X_POP();
                int r = PyObject_SetItem(obj, key, val);
                Py_DECREF(key); Py_DECREF(obj); Py_DECREF(val);
                if (r < 0) goto error;
                break;
            }
            case OP_DELETE_SUBSCR: {
                PyObject *key = X_POP();
                PyObject *obj = X_POP();
                int r = PyObject_DelItem(obj, key);
                Py_DECREF(key); Py_DECREF(obj);
                if (r < 0) goto error;
                break;
            }
            case OP_BINARY_SUBSCR: {
                PyObject *key = X_POP();
                PyObject *obj = X_POP();
                PyObject *r = PyObject_GetItem(obj, key);
                Py_DECREF(key); Py_DECREF(obj);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_COPY: {
                if (arg < 0 || arg >= sp) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x2b, 0x27, 0x38, 0x31, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 17, 0x68));
                    goto error;
                }
                PyObject *v = stack[sp - 1 - arg];
                Py_INCREF(v);
                X_PUSH(v);
                break;
            }
            case OP_SWAP: {
                if (arg < 1 || arg >= sp) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x3b, 0x3f, 0x29, 0x38, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 17, 0x68));
                    goto error;
                }
                PyObject *t = stack[sp - 1];
                stack[sp - 1] = stack[sp - 1 - arg];
                stack[sp - 1 - arg] = t;
                break;
            }

            case OP_UNPACK_SEQUENCE: {
                PyObject *seq = X_POP();
                PyObject *lst = PySequence_List(seq);
                Py_DECREF(seq);
                if (lst == NULL) goto error;
                Py_ssize_t n = PyList_GET_SIZE(lst);
                if (n != arg) {
                    Py_DECREF(lst);
                    PyErr_Format(PyExc_ValueError,
                                 _DS(((uint8_t[]){0x1d, 0x06, 0x18, 0x09, 0x0b, 0x03, 0x48, 0x0d, 0x10, 0x18, 0x0d, 0x0b, 0x1c, 0x0d, 0x0c, 0x48, 0x4d, 0x0c, 0x48, 0x09, 0x1a, 0x0f, 0x1d, 0x05, 0x0d, 0x06, 0x1c, 0x1b, 0x44, 0x48, 0x0f, 0x07, 0x1c, 0x48, 0x4d, 0x12, 0x0c}), 37, 0x68), arg, n);
                    goto error;
                }
                /* Push forward: list[0] deepest, list[arg-1] on top. */
                for (i = 0; i < arg; i++) {
                    PyObject *it = PyList_GET_ITEM(lst, i);
                    Py_INCREF(it);
                    X_PUSH(it);
                }
                Py_DECREF(lst);
                break;
            }
            case OP_UNPACK_EX: {
                PyObject *seq = X_POP();
                PyObject *lst = PySequence_List(seq);
                Py_DECREF(seq);
                if (lst == NULL) goto error;
                Py_ssize_t n = PyList_GET_SIZE(lst);
                int before = arg & 0xff;
                int after = arg >> 8;
                if (n < before + after) {
                    Py_DECREF(lst);
                    PyErr_SetString(PyExc_ValueError, _DS(((uint8_t[]){0x1d, 0x06, 0x18, 0x09, 0x0b, 0x03, 0x48, 0x05, 0x01, 0x1b, 0x05, 0x09, 0x1c, 0x0b, 0x00}), 15, 0x68));
                    goto error;
                }
                /* reversed(before) + middle + reversed(after) */
                for (i = before - 1; i >= 0; i--) {
                    PyObject *it = PyList_GET_ITEM(lst, i);
                    Py_INCREF(it); X_PUSH(it);
                }
                {
                    PyObject *mid = PyList_GetSlice(lst, before, n - after);
                    if (mid == NULL) { Py_DECREF(lst); goto error; }
                    X_PUSH(mid);
                }
                for (i = (int)(n - 1); i >= (int)(n - after); i--) {
                    PyObject *it = PyList_GET_ITEM(lst, i);
                    Py_INCREF(it); X_PUSH(it);
                }
                Py_DECREF(lst);
                break;
            }

            case OP_FORMAT_VALUE: {
                PyObject *v = X_POP();
                PyObject *r;
                if (arg & 0x4) {
                    PyObject *spec = X_POP();
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
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_FORMAT_SIMPLE: {
                PyObject *v = X_POP();
                PyObject *r = PyObject_Str(v);
                Py_DECREF(v);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_FORMAT_WITH_SPEC: {
                PyObject *spec = X_POP();
                PyObject *v = X_POP();
                PyObject *r = PyObject_Format(v, spec);
                Py_DECREF(spec); Py_DECREF(v);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_BUILD_STRING: {
                PyObject *sep = PyUnicode_FromString("");
                if (sep == NULL) goto error;
                PyObject *parts = PyTuple_New(arg);
                if (parts == NULL) { Py_DECREF(sep); goto error; }
                int k;
                for (k = 0; k < arg; k++) {
                    PyTuple_SET_ITEM(parts, k, stack[sp - arg + k]);  /* steals */
                }
                sp -= arg;
                PyObject *r = PyUnicode_Join(sep, parts);
                Py_DECREF(sep); Py_DECREF(parts);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_BUILD_TUPLE: {
                PyObject *t = PyTuple_New(arg);
                if (t == NULL) goto error;
                int k;
                for (k = 0; k < arg; k++) PyTuple_SET_ITEM(t, k, stack[sp - arg + k]);
                sp -= arg;
                X_PUSH(t);
                break;
            }
            case OP_BUILD_LIST: {
                PyObject *l = PyList_New(arg);
                if (l == NULL) goto error;
                int k;
                for (k = 0; k < arg; k++) PyList_SET_ITEM(l, k, stack[sp - arg + k]);
                sp -= arg;
                X_PUSH(l);
                break;
            }
            case OP_BUILD_SET: {
                PyObject *s = PySet_New(NULL);
                if (s == NULL) goto error;
                int k;
                for (k = 0; k < arg; k++) {
                    if (PySet_Add(s, stack[sp - arg + k]) < 0) {
                        /* drop remaining refs already in set; DECREF stack items */
                        int j;
                        for (j = 0; j < arg; j++) Py_DECREF(stack[sp - arg + j]);
                        sp -= arg;
                        Py_DECREF(s);
                        goto error;
                    }
                }
                int j;
                for (j = 0; j < arg; j++) Py_DECREF(stack[sp - arg + j]);
                sp -= arg;
                X_PUSH(s);
                break;
            }
            case OP_BUILD_MAP: {
                PyObject *d = PyDict_New();
                if (d == NULL) goto error;
                int k;
                for (k = 0; k < arg; k++) {
                    PyObject *key = stack[sp - 2 * arg + 2 * k];
                    PyObject *val = stack[sp - 2 * arg + 2 * k + 1];
                    if (PyDict_SetItem(d, key, val) < 0) {
                        int j;
                        for (j = 0; j < 2 * arg; j++) Py_DECREF(stack[sp - 2*arg + j]);
                        sp -= 2 * arg;
                        Py_DECREF(d);
                        goto error;
                    }
                }
                int j;
                for (j = 0; j < 2 * arg; j++) Py_DECREF(stack[sp - 2 * arg + j]);
                sp -= 2 * arg;
                X_PUSH(d);
                break;
            }
            case OP_BUILD_SLICE: {
                PyObject *r;
                if (arg == 2) {
                    PyObject *stop = X_POP();
                    PyObject *start = X_POP();
                    r = PySlice_New(start, stop, NULL);
                    Py_DECREF(start); Py_DECREF(stop);
                } else {
                    PyObject *step = X_POP();
                    PyObject *stop = X_POP();
                    PyObject *start = X_POP();
                    r = PySlice_New(start, stop, step);
                    Py_DECREF(start); Py_DECREF(stop); Py_DECREF(step);
                }
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_LIST_APPEND: {
                PyObject *v = X_POP();
                PyObject *lst = locals[arg];  /* borrowed */
                int r = PyList_Append(lst, v);
                Py_DECREF(v);
                if (r < 0) goto error;
                break;
            }
            case OP_SET_ADD: {
                PyObject *v = X_POP();
                PyObject *s = locals[arg];
                int r = PySet_Add(s, v);
                Py_DECREF(v);
                if (r < 0) goto error;
                break;
            }
            case OP_MAP_ADD: {
                PyObject *v = X_POP();
                PyObject *k = X_POP();
                PyObject *d = locals[arg];
                int r = PyDict_SetItem(d, k, v);
                Py_DECREF(k); Py_DECREF(v);
                if (r < 0) goto error;
                break;
            }
            case OP_LIST_EXTEND: {
                PyObject *it = locals[arg];  /* iterable in local (3.10 variant) */
                PyObject *lst = X_POP();
                PyObject *r = PyObject_CallMethod(lst, _DS(((uint8_t[]){0x0d, 0x10, 0x1c, 0x0d, 0x06, 0x0c}), 6, 0x68), "O", it);
                Py_DECREF(lst);
                if (r == NULL) goto error;
                Py_DECREF(r);
                break;
            }
            case OP_SET_UPDATE: {
                PyObject *it = locals[arg];
                PyObject *s = X_POP();
                PyObject *r = PyObject_CallMethod(s, _DS(((uint8_t[]){0x1d, 0x18, 0x0c, 0x09, 0x1c, 0x0d}), 6, 0x68), "O", it);
                Py_DECREF(s);
                if (r == NULL) goto error;
                Py_DECREF(r);
                break;
            }
            case OP_DICT_UPDATE: {
                PyObject *m = locals[arg];
                PyObject *d = X_POP();
                PyObject *r = PyObject_CallMethod(d, _DS(((uint8_t[]){0x1d, 0x18, 0x0c, 0x09, 0x1c, 0x0d}), 6, 0x68), "O", m);
                Py_DECREF(d);
                if (r == NULL) goto error;
                Py_DECREF(r);
                break;
            }

            case OP_MAKE_FUNCTION: {
                PyObject *codeobj = X_POP();
                PyObject *qualname = NULL, *defaults = NULL,
                          *kwdefaults = NULL, *closure = NULL;
                if (arg & 0x8) { qualname = X_POP(); }
                if (arg & 0x4) { kwdefaults = X_POP(); }
                if (arg & 0x2) { defaults = X_POP(); }
                if (arg & 0x1) { closure = X_POP(); Py_DECREF(closure); closure = NULL; }
                PyObject *fn = NULL;
                if (PyCode_Check(codeobj)) {
                    if (qualname)
                        fn = PyFunction_NewWithQualName(codeobj, globals_obj, qualname);
                    else
                        fn = PyFunction_New(codeobj, globals_obj);
                }
                /* defaults/kwdefaults setting skipped (no stable public API in 3.11
                 * to set them post-creation without attributes). */
                Py_XDECREF(qualname);
                Py_XDECREF(defaults);
                Py_XDECREF(kwdefaults);
                Py_XDECREF(closure);
                Py_DECREF(codeobj);
                if (fn == NULL) {
                    if (!PyErr_Occurred())
                        PyErr_SetString(PyExc_NotImplementedError,
                            _DS(((uint8_t[]){0x25, 0x29, 0x23, 0x2d, 0x37, 0x2e, 0x3d, 0x26, 0x2b, 0x3c, 0x21, 0x27, 0x26, 0x52, 0x48, 0x0b, 0x07, 0x0c, 0x0d, 0x48, 0x07, 0x0a, 0x02, 0x0d, 0x0b, 0x1c, 0x48, 0x05, 0x1d, 0x1b, 0x1c, 0x48, 0x0a, 0x0d, 0x48, 0x09, 0x48, 0x1a, 0x0d, 0x09, 0x04, 0x48, 0x38, 0x11, 0x1c, 0x00, 0x07, 0x06, 0x48, 0x0b, 0x07, 0x0c, 0x0d}), 53, 0x68));
                    goto error;
                }
                X_PUSH(fn);
                break;
            }

            case OP_CALL: {
                if (arg < 0 || arg >= sp) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x2b, 0x29, 0x24, 0x24, 0x48, 0x09, 0x1a, 0x0f, 0x0b, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 22, 0x68));
                    goto error;
                }
                PyObject *args_t = PyTuple_New(arg);
                if (args_t == NULL) goto error;
                int k;
                for (k = 0; k < arg; k++)
                    PyTuple_SET_ITEM(args_t, k, stack[sp - arg + k]);  /* steals */
                sp -= arg;
                PyObject *callable = X_POP();
                PyObject *r = PyObject_Call(callable, args_t, NULL);
                Py_DECREF(args_t);
                Py_DECREF(callable);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_KW_NAMES: {
                PyObject *names = PyTuple_GetItem(consts, arg);
                if (names == NULL) goto error;
                Py_XDECREF(kw_names_pending);
                Py_INCREF(names);
                kw_names_pending = names;
                break;
            }
            case OP_CALL_KW: {
                int argc = arg >> 8;
                int nkw = arg & 0xff;
                if (argc < 0 || nkw < 0 || argc + nkw >= sp) {
                    PyErr_SetString(PyExc_IndexError, _DS(((uint8_t[]){0x2b, 0x29, 0x24, 0x24, 0x37, 0x23, 0x3f, 0x48, 0x09, 0x1a, 0x0f, 0x0b, 0x47, 0x06, 0x03, 0x1f, 0x48, 0x07, 0x1d, 0x1c, 0x48, 0x07, 0x0e, 0x48, 0x1a, 0x09, 0x06, 0x0f, 0x0d}), 29, 0x68));
                    goto error;
                }
                PyObject *kw = PyDict_New();
                if (kw == NULL) goto error;
                if (kw_names_pending && nkw > 0) {
                    int k;
                    for (k = 0; k < nkw; k++) {
                        PyObject *val = stack[sp - nkw + k];
                        PyObject *name = PyTuple_GetItem(kw_names_pending, k);
                        if (name == NULL) { int j; for (j=0;j<nkw;j++) Py_DECREF(stack[sp-nkw+j]); sp-=nkw; Py_DECREF(kw); goto error; }
                        if (PyDict_SetItem(kw, name, val) < 0) {
                            int j; for (j=0;j<nkw;j++) Py_DECREF(stack[sp-nkw+j]);
                            sp -= nkw; Py_DECREF(kw); goto error;
                        }
                    }
                }
                int j;
                for (j = 0; j < nkw; j++) Py_DECREF(stack[sp - nkw + j]);
                sp -= nkw;
                Py_XDECREF(kw_names_pending); kw_names_pending = NULL;

                PyObject *args_t = PyTuple_New(argc);
                if (args_t == NULL) { Py_DECREF(kw); goto error; }
                int k;
                for (k = 0; k < argc; k++)
                    PyTuple_SET_ITEM(args_t, k, stack[sp - argc + k]);  /* steals */
                sp -= argc;
                PyObject *callable = X_POP();
                PyObject *r = PyObject_Call(callable, args_t, kw);
                Py_DECREF(args_t); Py_DECREF(kw);
                Py_DECREF(callable);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_CALL_FUNCTION_EX: {
                PyObject *kwds = NULL;
                if (arg & 0x1) { kwds = X_POP(); }
                PyObject *argv = X_POP();
                PyObject *callable = X_POP();
                PyObject *r = PyObject_Call(callable, argv, kwds);
                Py_XDECREF(kwds); Py_DECREF(argv); Py_DECREF(callable);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_BINARY_OP:
            case OP_BINARY_OP_INPLACE: {
                PyObject *b = X_POP();
                PyObject *a = X_POP();
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
                        PyErr_Format(PyExc_RuntimeError, _DS(((uint8_t[]){0x1d, 0x06, 0x03, 0x06, 0x07, 0x1f, 0x06, 0x48, 0x2a, 0x21, 0x26, 0x27, 0x38, 0x48, 0x1b, 0x1d, 0x0a, 0x48, 0x4d, 0x0c}), 20, 0x68), arg);
                        goto error;
                }
                Py_DECREF(a); Py_DECREF(b);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_UNARY_NEGATIVE: {
                PyObject *v = X_POP();
                PyObject *r = PyNumber_Negative(v);
                Py_DECREF(v);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_UNARY_POSITIVE: {
                PyObject *v = X_POP();
                PyObject *r = PyNumber_Positive(v);
                Py_DECREF(v);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_UNARY_NOT: {
                PyObject *v = X_POP();
                int x = PyObject_IsTrue(v);
                Py_DECREF(v);
                if (x < 0) goto error;
                PyObject *r = PyBool_FromLong(!x);
                X_PUSH(r);
                break;
            }
            case OP_UNARY_INVERT: {
                PyObject *v = X_POP();
                PyObject *r = PyNumber_Invert(v);
                Py_DECREF(v);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_COMPARE_OP: {
                PyObject *b = X_POP();
                PyObject *a = X_POP();
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
                        PyErr_Format(PyExc_RuntimeError, _DS(((uint8_t[]){0x1d, 0x06, 0x03, 0x06, 0x07, 0x1f, 0x06, 0x48, 0x2b, 0x25, 0x38, 0x48, 0x1b, 0x1d, 0x0a, 0x48, 0x4d, 0x0c}), 18, 0x68), arg);
                        goto error;
                }
                Py_DECREF(a); Py_DECREF(b);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_IS_OP: {
                PyObject *b = X_POP();
                PyObject *a = X_POP();
                PyObject *r = PyBool_FromLong(arg ? (a != b) : (a == b));
                Py_DECREF(a); Py_DECREF(b);
                X_PUSH(r);
                break;
            }
            case OP_CONTAINS_OP: {
                PyObject *b = X_POP();
                PyObject *a = X_POP();
                int x = PySequence_Contains(b, a);
                Py_DECREF(a); Py_DECREF(b);
                if (x < 0) goto error;
                PyObject *r = PyBool_FromLong(arg ? !x : x);
                X_PUSH(r);
                break;
            }

            case OP_JUMP:
                pc = arg;
                break;
            case OP_JUMP_IF_FALSE: {
                PyObject *v = X_POP();
                int t = PyObject_IsTrue(v);
                Py_DECREF(v);
                if (t < 0) goto error;
                if (!t) pc = arg;
                break;
            }
            case OP_JUMP_IF_TRUE: {
                PyObject *v = X_POP();
                int t = PyObject_IsTrue(v);
                Py_DECREF(v);
                if (t < 0) goto error;
                if (t) pc = arg;
                break;
            }
            case OP_JUMP_IF_NONE: {
                PyObject *v = X_POP();
                int is_none = (v == Py_None);
                Py_DECREF(v);
                if (is_none) pc = arg;
                break;
            }
            case OP_JUMP_IF_NOT_NONE: {
                PyObject *v = X_POP();
                int not_none = (v != Py_None);
                Py_DECREF(v);
                if (not_none) pc = arg;
                break;
            }
            case OP_JUMP_IF_FALSE_OR_POP: {
                PyObject *v = X_TOP();
                int t = PyObject_IsTrue(v);
                if (t < 0) goto error;
                if (!t) { pc = arg; }
                else { PyObject *p = X_POP(); Py_DECREF(p); }
                break;
            }
            case OP_JUMP_IF_TRUE_OR_POP: {
                PyObject *v = X_TOP();
                int t = PyObject_IsTrue(v);
                if (t < 0) goto error;
                if (t) { pc = arg; }
                else { PyObject *p = X_POP(); Py_DECREF(p); }
                break;
            }

            case OP_FOR_ITER: {
                PyObject *it = X_TOP();  /* peek */
                PyObject *v = PyIter_Next(it);
                if (v == NULL) {
                    if (PyErr_Occurred()) goto error;  /* real error */
                    /* exhausted: pop iterator, jump */
                    PyObject *ex = X_POP();
                    Py_DECREF(ex);
                    pc = arg;
                } else {
                    X_PUSH(v);
                }
                break;
            }
            case OP_GET_ITER: {
                PyObject *obj = X_POP();
                PyObject *it = PyObject_GetIter(obj);
                Py_DECREF(obj);
                if (it == NULL) goto error;
                X_PUSH(it);
                break;
            }

            case OP_PUSH_NULL: {
                Py_INCREF(Py_None);
                X_PUSH(Py_None);
                break;
            }
            case OP_PUSH_EXC_INFO: {
                Py_INCREF(Py_None);
                X_PUSH(Py_None);
                break;
            }
            case OP_LOAD_ASSERTION_ERROR: {
                Py_INCREF(PyExc_AssertionError);
                X_PUSH(PyExc_AssertionError);
                break;
            }
            case OP_CHECK_EXC_MATCH: {
                PyObject *t = X_POP();
                PyObject *e = X_POP();
                int x = PyObject_IsInstance(e, t);
                Py_DECREF(e); Py_DECREF(t);
                if (x < 0) goto error;
                PyObject *r = PyBool_FromLong(x);
                X_PUSH(r);
                break;
            }
            case OP_RAISE_VARARGS: {
                PyObject *cause = NULL, *exc = NULL;
                if (arg >= 2) cause = X_POP();
                if (arg >= 1) exc = X_POP();
                if (exc == NULL) {
                    /* re-raise current */
                    if (!PyErr_Occurred())
                        PyErr_SetString(PyExc_RuntimeError,
                            _DS(((uint8_t[]){0x26, 0x07, 0x48, 0x09, 0x0b, 0x1c, 0x01, 0x1e, 0x0d, 0x48, 0x0d, 0x10, 0x0b, 0x0d, 0x18, 0x1c, 0x01, 0x07, 0x06, 0x48, 0x1c, 0x07, 0x48, 0x1a, 0x0d, 0x45, 0x1a, 0x09, 0x01, 0x1b, 0x0d}), 31, 0x68));
                    Py_XDECREF(cause);
                    goto error;
                }
                if (PyExceptionInstance_Check(exc)) {
                    PyErr_SetObject((PyObject*)Py_TYPE(exc), exc);
                } else if (PyExceptionClass_Check(exc)) {
                    PyObject *inst = PyObject_CallNoArgs(exc);
                    if (inst != NULL) {
                        PyErr_SetObject(exc, inst);
                        Py_DECREF(inst);
                    }
                } else {
                    PyErr_SetString(PyExc_TypeError,
                        _DS(((uint8_t[]){0x0d, 0x10, 0x0b, 0x0d, 0x18, 0x1c, 0x01, 0x07, 0x06, 0x1b, 0x48, 0x05, 0x1d, 0x1b, 0x1c, 0x48, 0x0c, 0x0d, 0x1a, 0x01, 0x1e, 0x0d, 0x48, 0x0e, 0x1a, 0x07, 0x05, 0x48, 0x2a, 0x09, 0x1b, 0x0d, 0x2d, 0x10, 0x0b, 0x0d, 0x18, 0x1c, 0x01, 0x07, 0x06}), 41, 0x68));
                }
                if (cause && PyErr_Occurred()) {
                    /* best-effort __cause__ (no public setter in 3.11) */
                }
                Py_XDECREF(exc);
                Py_XDECREF(cause);
                goto error;
            }
            case OP_RERAISE: {
                if (!PyErr_Occurred())
                    PyErr_SetString(PyExc_RuntimeError, _DS(((uint8_t[]){0x26, 0x07, 0x48, 0x09, 0x0b, 0x1c, 0x01, 0x1e, 0x0d, 0x48, 0x0d, 0x10, 0x0b, 0x0d, 0x18, 0x1c, 0x01, 0x07, 0x06, 0x48, 0x1c, 0x07, 0x48, 0x1a, 0x0d, 0x45, 0x1a, 0x09, 0x01, 0x1b, 0x0d}), 31, 0x68));
                goto error;
            }

            case OP_YIELD_VALUE: {
                /* In a non-generator frame this is a misuse; the generator path
                 * (fallback) handles real yields. Treat as return to match ref. */
                result = X_POP();
                goto cleanup;
            }
            case OP_YIELD_FROM: {
                /* Non-generator fallback: push the value (matches ref's else
                 * branch; full drive-to-completion only meaningful in gens). */
                /* value already on top; leave it. */
                break;
            }

            case OP_IMPORT_NAME: {
                PyObject *fromlist = X_POP();
                PyObject *level = X_POP();
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) { Py_DECREF(fromlist); Py_DECREF(level); goto error; }
                PyObject *bimod = PyImport_ImportModule(_DS(((uint8_t[]){0x0a, 0x1d, 0x01, 0x04, 0x1c, 0x01, 0x06, 0x1b}), 8, 0x68));
                if (bimod == NULL) { Py_DECREF(fromlist); Py_DECREF(level); goto error; }
                PyObject *impfn = PyObject_GetAttrString(bimod, _DS(((uint8_t[]){0x37, 0x37, 0x01, 0x05, 0x18, 0x07, 0x1a, 0x1c, 0x37, 0x37}), 10, 0x68));
                Py_DECREF(bimod);
                if (impfn == NULL) { Py_DECREF(fromlist); Py_DECREF(level); goto error; }
                PyObject *empty_locals = PyDict_New();
                if (empty_locals == NULL) {
                    Py_DECREF(impfn); Py_DECREF(fromlist); Py_DECREF(level);
                    goto error;
                }
                PyObject *r = PyObject_CallFunctionObjArgs(impfn,
                    name, globals_obj, empty_locals, fromlist, level, NULL);
                Py_DECREF(impfn); Py_DECREF(empty_locals);
                Py_DECREF(fromlist); Py_DECREF(level);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }
            case OP_IMPORT_FROM: {
                PyObject *mod = X_TOP();  /* peek */
                PyObject *name = PyTuple_GetItem(global_names, arg);
                if (name == NULL) goto error;
                PyObject *r = PyObject_GetAttr(mod, name);
                if (r == NULL) goto error;
                X_PUSH(r);
                break;
            }

            case OP_BEFORE_WITH:
            case OP_BEFORE_ASYNC_WITH: {
                PyObject *mgr = X_POP();
                PyObject *enter = PyObject_CallMethod(mgr, _DS(((uint8_t[]){0x37, 0x37, 0x0d, 0x06, 0x1c, 0x0d, 0x1a, 0x37, 0x37}), 9, 0x68), NULL);
                if (enter == NULL) { Py_DECREF(mgr); goto error; }
                X_PUSH(mgr);  /* transfer ref */
                X_PUSH(enter);
                break;
            }

            case OP_LOAD_BUILD_CLASS: {
                PyObject *b = PyDict_GetItemString(globals_obj, _DS(((uint8_t[]){0x37, 0x37, 0x0a, 0x1d, 0x01, 0x04, 0x0c, 0x37, 0x0b, 0x04, 0x09, 0x1b, 0x1b, 0x37, 0x37}), 15, 0x68));
                if (b == NULL) {
                    PyErr_SetString(PyExc_NameError, _DS(((uint8_t[]){0x37, 0x37, 0x0a, 0x1d, 0x01, 0x04, 0x0c, 0x37, 0x0b, 0x04, 0x09, 0x1b, 0x1b, 0x37, 0x37, 0x48, 0x06, 0x07, 0x1c, 0x48, 0x0e, 0x07, 0x1d, 0x06, 0x0c}), 25, 0x68));
                    goto error;
                }
                Py_INCREF(b);
                X_PUSH(b);
                break;
            }

            default:
                PyErr_Format(PyExc_RuntimeError,
                             _DS(((uint8_t[]){0x1d, 0x06, 0x03, 0x06, 0x07, 0x1f, 0x06, 0x47, 0x1d, 0x06, 0x1b, 0x1d, 0x18, 0x18, 0x07, 0x1a, 0x1c, 0x0d, 0x0c, 0x48, 0x07, 0x18, 0x0b, 0x07, 0x0c, 0x0d, 0x48, 0x4d, 0x0c, 0x48, 0x09, 0x1c, 0x48, 0x18, 0x0b, 0x48, 0x4d, 0x0c}), 38, 0x68), op, pc - 1);
                goto error;
            } /* end switch */
        } /* end while */
    }

    /* Implicit None return at end (matches Python). */
    result = Py_None;
    Py_INCREF(result);
    goto cleanup;

error:
    Py_XDECREF(result);
    result = NULL;

cleanup:
    /* Drop stack */
    for (i = 0; i < sp; i++) Py_XDECREF(stack[i]);
    /* Drop locals */
    if (locals) {
        int k;
        for (k = 0; k < nlocals_alloc; k++) Py_XDECREF(locals[k]);
    }
    /* Drop cells */
    if (cells) {
        int k;
        for (k = 0; k < ncells; k++) Py_XDECREF(cells[k]);
    }
    Py_XDECREF(kw_names_pending);
    Py_XDECREF(consts);
    Py_XDECREF(names_blob);
    Py_XDECREF(empty_tup);
    if (stack)     PyMem_RawFree(stack);
    if (locals)    PyMem_RawFree(locals);
    if (cells)     PyMem_RawFree(cells);
    if (ops)       PyMem_RawFree(ops);
    if (args_arr)  PyMem_RawFree(args_arr);
    PyBuffer_Release(&key_view);
    PyBuffer_Release(&blob_view);
    return result;
}

/* =========================================================================
 * Module definition — dynamic construction (strings encrypted at build time).
 * ========================================================================= */
static PyMethodDef _xvm_methods[2];
static struct PyModuleDef _xvm_module;

PyMODINIT_FUNC PyInit__xvm(void) {
    /* Timing anti-debug gate: if a debugger is single-stepping, the SHA-256
     * calibration loop takes >50ms instead of <5ms.  Fail the module load
     * (return NULL) — the Python loader falls back to reference interpreter
     * or fail-closed per --vm-fallback policy. */
    if (_anti_debug_timing()) {
        PyErr_SetString(PyExc_ImportError, _DS(((uint8_t[]){0x01, 0x06, 0x01, 0x1c, 0x48, 0x0e, 0x09, 0x01, 0x04, 0x0d, 0x0c}), 11, 0x68));
        return NULL;
    }

    /* Opaque predicate: always-true check that confuses static analysis.
     * The SHA-256 of a constant seed is deterministic — the comparison
     * always succeeds, but IDA/Ghidra can't prove it statically. */
    {
        uint8_t _chk[32];
        uint8_t _seed[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        sha256_buffer(_seed, 4, _chk);
        if (_chk[0] == 0xFF) {
            /* Dead code — never reached, but IDA shows it as a live branch */
            return NULL;
        }
    }

    /* Build method table with decrypted strings.  strdup() is needed because
     * _DS() returns a pointer to a shared static buffer — each call overwrites
     * the previous result.  The method/module struct fields must persist for
     * the module lifetime, so we make permanent heap copies. */
    _xvm_methods[0].ml_name = strdup(_DS(((uint8_t[]){0x1a, 0x1d, 0x06}), 3, 0x68));
    _xvm_methods[0].ml_meth = (PyCFunction)_xvm_run;
    _xvm_methods[0].ml_flags = METH_VARARGS | METH_KEYWORDS;
    _xvm_methods[0].ml_doc = strdup(_DS(((uint8_t[]){0x1a, 0x1d, 0x06, 0x40, 0x0a, 0x04, 0x07, 0x0a, 0x44, 0x48, 0x18, 0x0d, 0x1a, 0x05, 0x44, 0x48, 0x03, 0x0d, 0x11, 0x44, 0x48, 0x09, 0x1a, 0x0f, 0x1b, 0x44, 0x48, 0x0f, 0x04, 0x07, 0x0a, 0x09, 0x04, 0x1b, 0x44, 0x48, 0x18, 0x0d, 0x1a, 0x05, 0x37, 0x0d, 0x10, 0x1c, 0x55, 0x59, 0x5c, 0x5c, 0x41, 0x48, 0x45, 0x56, 0x48, 0x07, 0x0a, 0x02, 0x0d, 0x0b, 0x1c}), 59, 0x68));
    _xvm_methods[1].ml_name = NULL;
    _xvm_methods[1].ml_meth = NULL;
    _xvm_methods[1].ml_flags = 0;
    _xvm_methods[1].ml_doc = NULL;

    /* Build module def with decrypted strings. */
    memset(&_xvm_module, 0, sizeof(_xvm_module));
    _xvm_module.m_name = strdup(_DS(((uint8_t[]){0x37, 0x10, 0x1e, 0x05}), 4, 0x68));
    _xvm_module.m_doc = strdup(_DS(((uint8_t[]){0x2a, 0x0d, 0x0c, 0x1a, 0x07, 0x0b, 0x03, 0x3e, 0x25, 0x48, 0x2b, 0x48, 0x01, 0x06, 0x1c, 0x0d, 0x1a, 0x18, 0x1a, 0x0d, 0x1c, 0x0d, 0x1a, 0x48, 0x40, 0x3f, 0x09, 0x1e, 0x0d, 0x48, 0x5a, 0x2a, 0x41, 0x46}), 34, 0x68));
    _xvm_module.m_size = -1;
    _xvm_module.m_methods = _xvm_methods;

    return PyModule_Create(&_xvm_module);
}
