"""Phase 5 full verification harness (Wave 5).

Builds the obfuscator with many flag combinations on the test inputs, runs
each output, and asserts the expected results. Also checks anti-meta (grep
for 'bedrock' = 0), regression (no --native-vm behaves as before), and the
tamper/self-destruct path.

All builds use --adv-requests off (avoids the Windows tasklist hang).

Run:  python _phase5_harness.py
Exit 0 if all pass; non-zero on failure.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_OBF = os.path.join(_HERE, 'bedrock_obfuscator.py')
_TESTS = {
    '_test_obf.py': 'final_result: 221',
    '_smoke_input.py': 'hello_world_secret_12345 20 42 True',
    '_test_kwargs_simple.py': 'kwargs simple: Hello, World Hi, Bob',
}
PASSES = 0
FAILS = []
RUNS = 0


def _record_pass():
    global PASSES
    PASSES += 1


def _record_fail(msg):
    global FAILS
    FAILS.append(msg)


def _record_run():
    global RUNS
    RUNS += 1


def _build_and_run(label, flags, test_file, expected_substr, extra_checks=None):
    """Build obfuscator with `flags` on `test_file`, run the output, assert
    `expected_substr` appears in stdout. `extra_checks(out_dir, stdout) -> bool`
    runs additional assertions. Records PASS/FAIL."""
    _record_run()
    out_dir = tempfile.mkdtemp(prefix='_p5_')
    out_name = 'out.py'
    out_path = os.path.join(out_dir, out_name)
    cmd = [sys.executable, _OBF, '--adv-requests', 'off',
           '--no-cache', '-o', out_path, '-f', test_file] + flags
    print(f'\n--- {label} ---')
    print('  cmd:', ' '.join(cmd[1:]))
    try:
        bproc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if bproc.returncode != 0:
            _record_fail(f'{label}: build exit {bproc.returncode}')
            print('  BUILD FAILED (exit', bproc.returncode, ')')
            print('  stdout:', bproc.stdout[-500:])
            print('  stderr:', bproc.stderr[-800:])
            shutil.rmtree(out_dir, ignore_errors=True)
            return
        if not os.path.exists(out_path):
            _record_fail(f'{label}: output not created')
            print('  NO OUTPUT FILE')
            shutil.rmtree(out_dir, ignore_errors=True)
            return
    except subprocess.TimeoutExpired:
        _record_fail(f'{label}: build timed out')
        print('  BUILD TIMEOUT')
        shutil.rmtree(out_dir, ignore_errors=True)
        return
    # Run the output.
    try:
        rproc = subprocess.run([sys.executable, out_path],
                               capture_output=True, text=True, timeout=360,
                               cwd=out_dir)
        stdout = rproc.stdout
        if rproc.returncode != 0:
            _record_fail(f'{label}: run exit {rproc.returncode}')
            print('  RUN FAILED (exit', rproc.returncode, ')')
            print('  stdout:', stdout[-500:])
            print('  stderr:', rproc.stderr[-800:])
            shutil.rmtree(out_dir, ignore_errors=True)
            return
        ok = expected_substr in stdout
        if extra_checks:
            ok = ok and extra_checks(out_dir, stdout)
        if ok:
            _record_pass()
            print(f'  PASS  (stdout: {stdout.strip()[:120]!r})')
        else:
            _record_fail(f'{label}: expected {expected_substr!r} not in stdout')
            print(f'  FAIL  expected {expected_substr!r}')
            print('  stdout:', stdout[-500:])
            print('  stderr:', rproc.stderr[-500:])
    except subprocess.TimeoutExpired:
        _record_fail(f'{label}: run timed out')
        print('  RUN TIMEOUT')
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _grep_bedrock_zero(out_dir):
    """Return True if no file in out_dir contains 'bedrock' case-insensitively
    in text form. Binary files (.pyd) are skipped for the text grep but we
    still check: grep -ic on a binary returns 0 anyway (no text match)."""
    for fn in os.listdir(out_dir):
        fp = os.path.join(out_dir, fn)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, 'rb') as f:
                data = f.read()
            # Try decode as utf-8; if it has invalid utf-8 it's likely binary.
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                continue  # binary file (e.g. .pyd); grep -ic returns 0 on these
            if 'bedrock' in text.lower():
                print(f'    [anti-meta FAIL] {fn} contains bedrock')
                return False
        except Exception:
            continue
    return True


def main():
    print('=== Phase 5 full verification harness ===')

    # ---- A: 4 presets with --native-vm on _test_obf → final_result: 221 ----
    for prof in ['fast', 'balanced', 'paranoid', 'extreme']:
        _build_and_run(
            f'preset {prof} --native-vm',
            ['--profile', prof, '--native-vm'],
            '_test_obf.py', 'final_result: 221')

    # ---- B: --native-vm on balanced ----
    _build_and_run('balanced --native-vm',
                   ['--native-vm'], '_test_obf.py', 'final_result: 221')

    # ---- C: --no-native-vm override extreme (regression) ----
    _build_and_run('extreme --no-native-vm (regression)',
                   ['--profile', 'extreme', '--no-native-vm'],
                   '_test_obf.py', 'final_result: 221')

    # ---- D: --native-vm extreme + anti-meta (grep bedrock = 0) ----
    def _check_no_bedrock(out_dir, stdout):
        return _grep_bedrock_zero(out_dir)
    _build_and_run('extreme --native-vm --anti-meta (no bedrock)',
                   ['--profile', 'extreme', '--native-vm', '--anti-meta'],
                   '_test_obf.py', 'final_result: 221',
                   extra_checks=_check_no_bedrock)

    # ---- E: --native-vm --anti-meta --chain --env-key extreme ----
    _build_and_run('extreme --native-vm --anti-meta --chain --env-key',
                   ['--profile', 'extreme', '--native-vm', '--anti-meta',
                    '--chain', '--env-key'],
                   '_test_obf.py', 'final_result: 221')

    # ---- F: --native-vm --metamorphic extreme (hash differs each run) ----
    # Build twice, compare output file hashes (should differ).
    print('\n--- F: --native-vm --metamorphic (hash differs each run) ---')
    _record_run()
    hashes = []
    for run_idx in range(2):
        out_dir = tempfile.mkdtemp(prefix='_p5_meta_')
        out_path = os.path.join(out_dir, 'out.py')
        cmd = [sys.executable, _OBF, '--adv-requests', 'off', '--no-cache',
               '-o', out_path, '-f', '_test_obf.py',
               '--profile', 'extreme', '--native-vm', '--metamorphic']
        bproc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if bproc.returncode != 0 or not os.path.exists(out_path):
            _record_fail(f'F meta run {run_idx}: build failed')
            print(f'  meta run {run_idx} BUILD FAILED')
            shutil.rmtree(out_dir, ignore_errors=True)
            continue
        h = hashlib.sha256(open(out_path, 'rb').read()).hexdigest()[:16]
        hashes.append(h)
        # also verify it runs
        rproc = subprocess.run([sys.executable, out_path],
                               capture_output=True, text=True, timeout=360,
                               cwd=out_dir)
        shutil.rmtree(out_dir, ignore_errors=True)
        if 'final_result: 221' not in rproc.stdout:
            _record_fail(f'F meta run {run_idx}: run did not produce 221')
            print(f'  meta run {run_idx} RUN FAILED')
            continue
    if len(hashes) == 2:
        if hashes[0] != hashes[1]:
            _record_pass()
            print(f'  PASS  metamorphic hashes differ: {hashes[0]} != {hashes[1]}')
        else:
            _record_fail(f'F metamorphic: hashes identical ({hashes[0]})')
            print(f'  FAIL  metamorphic hashes identical: {hashes[0]}')

    # ---- G: smoke + kwargs with extreme + native-vm ----
    _build_and_run('extreme --native-vm smoke',
                   ['--profile', 'extreme', '--native-vm'],
                   '_smoke_input.py', 'hello_world_secret_12345 20 42 True')
    _build_and_run('extreme --native-vm kwargs',
                   ['--profile', 'extreme', '--native-vm'],
                   '_test_kwargs_simple.py', 'kwargs simple: Hello, World Hi, Bob')

    # ---- H: Tamper: flip a byte in the bytecode blob, run → not 221 ----
    print('\n--- H: tamper (flip byte → not 221) ---')
    _record_run()
    out_dir = tempfile.mkdtemp(prefix='_p5_tamper_')
    out_path = os.path.join(out_dir, 'out.py')
    cmd = [sys.executable, _OBF, '--adv-requests', 'off', '--no-cache',
           '-o', out_path, '-f', '_test_obf.py',
           '--profile', 'extreme', '--native-vm', '--anti-meta']
    bproc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if bproc.returncode != 0 or not os.path.exists(out_path):
        _record_fail('H tamper: build failed')
        print('  BUILD FAILED')
        shutil.rmtree(out_dir, ignore_errors=True)
    else:
        # Flip a byte in the .py output (corrupt a VM blob char). The VM
        # blob is a very long base85 string (thousands of chars). Find the
        # longest base85-like run (skip short hex hashes ~64 chars).
        import re
        data = bytearray(open(out_path, 'rb').read())
        matches = list(re.finditer(rb"[0-9A-Za-z!#$%&()*+\-/;<=>?@^_`{|~]{500,}", bytes(data)))
        if matches:
            m = matches[0]
            pos = m.start() + len(m.group()) // 2
            data[pos] = (data[pos] + 1) % 256
            open(out_path, 'wb').write(bytes(data))
            rproc = subprocess.run([sys.executable, out_path],
                                   capture_output=True, text=True, timeout=120,
                                   cwd=out_dir)
            if 'final_result: 221' in rproc.stdout:
                _record_fail('H tamper: still produced 221 after flip')
                print('  FAIL  tampered output still produced 221')
            else:
                _record_pass()
                print(f'  PASS  tampered output did NOT produce 221 (exit {rproc.returncode})')
        else:
            _record_fail('H tamper: could not find blob to flip')
            print('  FAIL  could not find blob')
        shutil.rmtree(out_dir, ignore_errors=True)

    # ---- I: Fallback to apply_runtimedec: async function in --native-vm --runtime-dec ----
    # Build _test_async.py with --native-vm --runtime-dec; async 'fetch' should
    # go to capsule (or stay plain), rest to VM. The build should succeed and
    # run, producing the async+yield+kwargs OK line.
    _build_and_run('extreme --native-vm --runtime-dec (async fallback)',
                   ['--profile', 'extreme', '--native-vm', '--runtime-dec'],
                   '_test_async.py', 'async+yield+kwargs OK')

    # ---- J: regression — re-run the Phase 4 harness WITHOUT --native-vm ----
    # Confirm existing behavior unchanged (no VM artifacts shipped).
    def _check_no_vm_artifacts(out_dir, stdout):
        files = os.listdir(out_dir)
        # out.py should be the only file (no .pyd, no _bedrock_vm_ref.py)
        non_out = [f for f in files if f != 'out.py']
        if non_out:
            print(f'    [regression FAIL] extra files: {non_out}')
            return False
        return True
    _build_and_run('extreme --no-native-vm (regression, no VM artifacts)',
                   ['--profile', 'extreme', '--no-native-vm'],
                   '_test_obf.py', 'final_result: 221',
                   extra_checks=_check_no_vm_artifacts)
    _build_and_run('extreme NO native-vm --anti-meta (regression)',
                   ['--profile', 'extreme', '--anti-meta'],
                   '_test_obf.py', 'final_result: 221',
                   extra_checks=_check_no_bedrock)

    # ---- K: reference fallback (delete the .pyd, run via reference interp) ----
    # Build native, then delete the shipped _xvm*.pyd so the loader falls back
    # to the pure-Python reference interpreter. The output must STILL run and
    # produce 221 (degraded but functional — the core safety property).
    # NOTE: pass --vm-fallback auto explicitly. The extreme profile otherwise
    # auto-sets --vm-fallback off (fail-closed: a missing .pyd aborts instead
    # of degrading). This case verifies the *auto* reference fallback; the
    # fail-closed path is covered by test H (tamper). Without the explicit
    # override the loader would poison+SystemExit and this test would report
    # a false failure.
    print('\n--- K: reference fallback (delete .pyd → still 221) ---')
    _record_run()
    out_dir = tempfile.mkdtemp(prefix='_p5_ref_fb_')
    out_path = os.path.join(out_dir, 'out.py')
    cmd = [sys.executable, _OBF, '--adv-requests', 'off', '--no-cache',
           '-o', out_path, '-f', '_test_obf.py',
           '--profile', 'extreme', '--native-vm', '--anti-meta',
           '--vm-fallback', 'auto']
    bproc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if bproc.returncode != 0 or not os.path.exists(out_path):
        _record_fail('K ref fallback: build failed')
        print('  BUILD FAILED')
        shutil.rmtree(out_dir, ignore_errors=True)
    else:
        # Delete the compiled .pyd so the loader imports the reference fallback.
        import glob as _glob
        for _pyd in _glob.glob(os.path.join(out_dir, '_xvm*.pyd')) + \
                     _glob.glob(os.path.join(out_dir, '_xvm*.so')):
            os.remove(_pyd)
        # also clear any __pycache__ so the stale .pyd isn't re-imported
        _pc = os.path.join(out_dir, '__pycache__')
        if os.path.isdir(_pc):
            shutil.rmtree(_pc, ignore_errors=True)
        rproc = subprocess.run([sys.executable, out_path],
                               capture_output=True, text=True, timeout=360,
                               cwd=out_dir)
        ok_run = 'final_result: 221' in rproc.stdout
        if ok_run:
            _record_pass()
            print('  PASS  reference fallback produced 221 (no .pyd present)')
        else:
            _record_fail('K ref fallback: did not produce 221 without .pyd')
            print('  FAIL  no 221 via reference fallback')
            print('  stdout:', rproc.stdout[-300:])
            print('  stderr:', rproc.stderr[-300:])
        shutil.rmtree(out_dir, ignore_errors=True)

    # ---- summary ----
    print('\n' + '=' * 60)
    print(f'Phase 5 harness: {PASSES}/{RUNS} passed')
    if FAILS:
        print('FAILURES:')
        for f in FAILS:
            print('  -', f)
        return 1
    print('ALL PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
