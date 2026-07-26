/* Phase H.10 TLS callback shim.
 *
 * Provides a single exported, PyInit-safe callback function the PE TLS
 * directory points at. The callback fires at thread-attach / process-start
 * time, BEFORE CPython calls PyInit_<module> -- so it MUST NOT touch the
 * Python C API (the interpreter is not fully initialized). It is a benign
 * no-op: its mere presence (a wired TLS data directory + a real callback
 * address) is the obfuscation signal -- static analyzers that skip TLS
 * callbacks miss this execution vector, and debuggers that break on TLS
 * callbacks reveal themselves pre-PyInit.
 *
 * Compiled into the obfuscated extension only when --h-tls-callback is on
 * (see _transpile_pipeline.py). Exported via __declspec(dllexport) so the
 * post-build _tls_callback.inject_tls_callback() patcher can look it up by
 * name in the export directory and wire the IMAGE_TLS_DIRECTORY at it.
 *
 * License: Apache-2.0 (project-licensed; no GPL).
 */
#ifdef _WIN32

#define BR_TLS_EXPORT __declspec(dllexport)

/* The callback signature mandated by PIMAGE_TLS_CALLBACK:
 *     void(PVOID DllHandle, DWORD Reason, PVOID Reserved)
 * We use the Win32 SDK types via <windows.h> for correctness. */
#include <windows.h>

/* Benign no-op callback. Returning void (no LONG/Break) lets the loader
 * proceed normally. Reason codes:
 *   DLL_PROCESS_ATTACH=1, DLL_THREAD_ATTACH=2,
 *   DLL_THREAD_DETACH=3, DLL_PROCESS_DETACH=0.
 * We act only on process-attach (the anti-debug signal vector); for all
 * other reasons we return immediately. No Python API calls, no heap, no
 * exceptions -- safe to run with the loader lock held. */
BR_TLS_EXPORT void _br_tls_cb(void *hmod, unsigned long reason, void *reserved)
{
    (void)hmod;
    (void)reserved;
    if (reason != (unsigned long)1) {  /* DLL_PROCESS_ATTACH only */
        return;
    }
    /* Intentionally empty: the TLS directory's existence is the signal.
     * A future hardening pass can add a non-Python anti-debug probe here
     * (e.g. a timing check via QueryPerformanceCounter), but it must NOT
     * call into the CPython runtime. */
    return;
}

#else  /* non-Windows: nothing to export; the TLS pass is Windows-PE-only. */

/* Define a stub so the translation unit is non-empty on non-Windows builds
 * (avoids empty-translation-unit warnings). Never called. */
void _br_tls_cb_unused(void) { }

#endif
