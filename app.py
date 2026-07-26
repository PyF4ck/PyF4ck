"""Bedrock Obfuscator — SaaS Preview Playground.

FastAPI web app cho cộng đồng test RE (reverse engineering) trước khi lên
production. User paste code → chọn profile → nhận obfuscated output + download
bundle. Kiểm soát: rate limit, ephemeral storage, auto-purge.

Run:
    pip install python-multipart
    uvicorn app:app --reload --port 8000
    → http://localhost:8000
"""
import asyncio
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

# ─── Config ──────────────────────────────────────────────────────────────────

OBFUSCATOR = Path(__file__).parent / "bedrock_obfuscator.py"
WORK_DIR = Path(tempfile.gettempdir()) / "bedrock_saas"
WORK_DIR.mkdir(parents=True, exist_ok=True)

MAX_SOURCE_BYTES = 50_000      # 50 KB
MAX_SOURCE_LINES = 2000
SUBPROCESS_TIMEOUT = 120       # seconds
RATE_LIMIT_MAX = 5             # requests per window
RATE_LIMIT_WINDOW = 60         # seconds
RETENTION_SECONDS = 3600       # 1h auto-purge

VALID_PROFILES = ("fast", "balanced", "paranoid", "extreme")

# ─── State ────────────────────────────────────────────────────────────────────

app = FastAPI(title="Bedrock Playground", version="0.1.0-preview")

# download_id → { dir: Path, zip: bytes, created: float, meta: dict }
_store: Dict[str, dict] = {}

# IP → [timestamps]
_rate: Dict[str, list] = defaultdict(list)

# ─── Models ───────────────────────────────────────────────────────────────────

class ObfuscateRequest(BaseModel):
    source: str
    profile: str = "balanced"
    native_vm: bool = True
    anti_meta: bool = True


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _rate_check(ip: str) -> bool:
    """Return True if request allowed, False if rate-limited."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    _rate[ip] = [t for t in _rate[ip] if t > cutoff]
    if len(_rate[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate[ip].append(now)
    return True


def _purge_old():
    """Delete stored bundles older than RETENTION_SECONDS."""
    now = time.time()
    expired = [k for k, v in _store.items() if now - v["created"] > RETENTION_SECONDS]
    for k in expired:
        try:
            shutil.rmtree(_store[k]["dir"], ignore_errors=True)
        except Exception:
            pass
        _store.pop(k, None)


def _collect_outputs(out_dir: Path) -> List[Path]:
    """Collect obfuscated output files from the output directory."""
    files = []
    if not out_dir.is_dir():
        return files
    for f in sorted(out_dir.iterdir()):
        if f.is_file() and f.suffix in (".py", ".pyd", ".so", ".json"):
            # Skip __pycache__, input file, and report.json (added separately)
            if "__pycache__" in f.name:
                continue
            if f.name == "input.py":
                continue
            if f.name == "report.json":
                continue
            files.append(f)
    return files


def _build_zip(out_dir: Path, report_path: Optional[Path]) -> bytes:
    """Bundle output files + report + README into a ZIP."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Output files
        for f in _collect_outputs(out_dir):
            zf.write(f, f.name)
        # Report
        if report_path and report_path.exists():
            zf.write(report_path, "report.json")
        # README
        readme = (
            "Bedrock Obfuscated Output\n"
            "=========================\n\n"
            "Files in this bundle:\n"
            "  obf.py              — obfuscated Python (main file)\n"
            "  _xvm.*.pyd / .so    — native VM extension (Windows/Linux)\n"
            "  *_vm_ref.py         — pure-Python reference interpreter (fallback)\n"
            "  report.json         — build metrics\n\n"
            "Usage:\n"
            "  python obf.py\n\n"
            "Note: Native VM (.pyd/.so) chỉ hoạt động trên cùng platform+Python\n"
            "với build server (Windows Python 3.11). Các platform khác tự động\n"
            "fallback sang pure-Python reference interpreter.\n"
        )
        zf.writestr("README.txt", readme)
    return buf.getvalue()


def _parse_report(report_path: Path) -> dict:
    """Parse the --report JSON file for metrics."""
    if not report_path.exists():
        return {}
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _run_obfuscator(source: str, profile: str, native_vm: bool, anti_meta: bool) -> dict:
    """Invoke the obfuscator as a subprocess. Returns result dict."""
    work = Path(tempfile.mkdtemp(prefix="obf_", dir=WORK_DIR))
    input_path = work / "input.py"
    output_path = work / "obf.py"
    report_path = work / "report.json"

    # Write input
    input_path.write_text(source, encoding="utf-8")

    # Build CLI args
    cmd = [
        sys.executable, str(OBFUSCATOR),
        "-f", str(input_path),
        "-o", str(output_path),
        "--profile", profile,
        "--json",
        "--report", str(report_path),
        "--no-cache",
        "--overwrite",
        "--adv-requests", "off",
        "--no-debug-poison",
        "--no-anti-timing",
    ]
    if native_vm:
        cmd.append("--native-vm")
    if anti_meta:
        cmd.append("--anti-meta")

    # Spawn
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            cwd=str(work),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(work, ignore_errors=True)
        return {"ok": False, "error": "Build timed out (120s limit)"}
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return {"ok": False, "error": f"Subprocess failed: {e}"}

    # Parse report
    report = _parse_report(report_path)

    if proc.returncode != 0:
        # Extract error from NDJSON stderr/stdout
        err_lines = []
        for line in (proc.stdout or "").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("kind") in ("error", "warning"):
                    err_lines.append(obj.get("message", ""))
            except json.JSONDecodeError:
                pass
        err_msg = "; ".join(err_lines) if err_lines else f"Exit code {proc.returncode}"
        shutil.rmtree(work, ignore_errors=True)
        return {"ok": False, "error": err_msg, "report": report}

    # Collect output
    out_dir = output_path.parent
    zip_bytes = _build_zip(out_dir, report_path if report_path.exists() else None)

    # Read preview (first 200 lines of obf.py)
    preview = ""
    if output_path.exists():
        try:
            lines = output_path.read_text(encoding="utf-8", errors="replace").split("\n")
            preview = "\n".join(lines[:200])
            if len(lines) > 200:
                preview += f"\n\n... ({len(lines) - 200} more lines, download to see full)"
        except Exception:
            preview = "(unable to read preview)"

    # Build download ID
    dl_id = hashlib.sha256(f"{time.time()}{work}".encode()).hexdigest()[:16]
    _store[dl_id] = {
        "dir": work,
        "zip": zip_bytes,
        "created": time.time(),
        "meta": {"profile": profile, "native_vm": native_vm, "anti_meta": anti_meta},
    }

    # Extract metrics
    metrics = {
        "output_size": report.get("output_size", 0),
        "entropy_input": report.get("entropy_input", 0),
        "entropy_output": report.get("entropy_output", 0),
        "n_idents_renamed": report.get("n_idents_renamed", 0),
        "n_strings_encoded": report.get("n_strings_encoded", 0),
        "n_consts_encrypted": report.get("n_consts_encrypted", 0),
        "duration_ms": report.get("duration_ms", 0),
        "profile_used": report.get("profile_used", profile),
    }

    # Check native VM status from NDJSON
    native_status = "unknown"
    for line in (proc.stdout or "").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            msg = obj.get("message", "")
            if "shipped native" in msg:
                native_status = "native"
            elif "shipped reference" in msg:
                native_status = "reference"
        except json.JSONDecodeError:
            pass

    warnings = []
    if native_vm and native_status == "reference":
        warnings.append(
            "Native VM build fell back to pure-Python reference interpreter. "
            "The .pyd extension is not included."
        )
    if native_vm and native_status == "native":
        warnings.append(
            "Native VM (.pyd) built for this server's platform (Windows Python 3.11). "
            "It will only load on the same platform+Python."
        )

    return {
        "ok": True,
        "download_id": dl_id,
        "preview": preview,
        "metrics": metrics,
        "native_status": native_status,
        "warnings": warnings,
        "report": report,
    }


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/obfuscate")
async def obfuscate(req: ObfuscateRequest, request: Request):
    ip = request.client.host if request.client else "unknown"

    # Rate limit
    if not _rate_check(ip):
        raise HTTPException(429, "Rate limit exceeded (5 requests/minute)")

    # Purge old bundles
    _purge_old()

    # Validate profile
    if req.profile not in VALID_PROFILES:
        raise HTTPException(400, f"Invalid profile. Choose: {', '.join(VALID_PROFILES)}")

    # Validate source size
    source_bytes = req.source.encode("utf-8")
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise HTTPException(400, f"Source too large (max {MAX_SOURCE_BYTES} bytes)")
    source_lines = req.source.count("\n") + 1
    if source_lines > MAX_SOURCE_LINES:
        raise HTTPException(400, f"Source too long (max {MAX_SOURCE_LINES} lines)")

    # Run obfuscator — offload the blocking subprocess call to a worker
    # thread so a slow build (up to SUBPROCESS_TIMEOUT) cannot freeze the
    # asyncio event loop and stall concurrent requests.
    result = await asyncio.to_thread(_run_obfuscator, req.source, req.profile,
                                     req.native_vm, req.anti_meta)

    if not result.get("ok"):
        return JSONResponse(
            {"ok": False, "error": result.get("error", "Unknown error")},
            status_code=200,  # return 200 with error body for frontend handling
        )

    return JSONResponse(result)


@app.get("/api/download/{dl_id}")
async def download(dl_id: str):
    if dl_id not in _store:
        raise HTTPException(404, "Download expired or not found")

    entry = _store[dl_id]
    if time.time() - entry["created"] > RETENTION_SECONDS:
        shutil.rmtree(entry["dir"], ignore_errors=True)
        _store.pop(dl_id, None)
        raise HTTPException(404, "Download expired")

    zip_bytes = entry["zip"]
    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=bedrock_obf_{dl_id[:8]}.zip"},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "obfuscator": str(OBFUSCATOR), "store_count": len(_store)}


# ─── Frontend ─────────────────────────────────────────────────────────────────

FRONTEND_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bedrock Playground — Obfuscator Preview</title>
<style>
:root {
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #21262d;
  --fg: #c9d1d9;
  --fg-dim: #8b949e;
  --accent: #58a6ff;
  --accent2: #3fb950;
  --danger: #f85149;
  --warn: #d29922;
  --border: #30363d;
  --mono: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg); color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  line-height: 1.6; padding: 20px; max-width: 1100px; margin: 0 auto;
}
h1 { font-size: 1.6em; margin-bottom: 4px; }
h1 .shield { color: var(--accent); }
.subtitle { color: var(--fg-dim); font-size: 0.85em; margin-bottom: 20px; }
.panel {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; margin-bottom: 16px;
}
label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 0.9em; }
textarea {
  width: 100%; min-height: 200px; background: var(--bg);
  border: 1px solid var(--border); border-radius: 6px;
  color: var(--fg); font-family: var(--mono); font-size: 0.85em;
  padding: 10px; resize: vertical; line-height: 1.5;
}
textarea:focus { border-color: var(--accent); outline: none; }
.profile-row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.profile-btn {
  padding: 8px 16px; border: 1px solid var(--border);
  background: var(--bg3); color: var(--fg); border-radius: 6px;
  cursor: pointer; font-size: 0.85em; transition: all 0.15s;
}
.profile-btn:hover { border-color: var(--accent); }
.profile-btn.active {
  border-color: var(--accent); background: rgba(88,166,255,0.1);
  color: var(--accent); font-weight: 600;
}
.profile-desc { font-size: 0.8em; color: var(--fg-dim); margin-top: 4px; }
.opts { display: flex; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
.opt { display: flex; align-items: center; gap: 6px; font-size: 0.85em; }
.opt input { cursor: pointer; }
.caveat { font-size: 0.75em; color: var(--warn); margin-top: 6px; }
button.submit {
  padding: 10px 24px; background: var(--accent); color: #000;
  border: none; border-radius: 6px; cursor: pointer;
  font-size: 0.9em; font-weight: 600; transition: opacity 0.15s;
}
button.submit:hover { opacity: 0.85; }
button.submit:disabled { opacity: 0.5; cursor: not-allowed; }
.spinner {
  display: inline-block; width: 14px; height: 14px;
  border: 2px solid var(--border); border-top-color: var(--accent);
  border-radius: 50%; animation: spin 0.8s linear infinite;
  vertical-align: middle; margin-right: 8px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.result { margin-top: 16px; }
.error-msg {
  background: rgba(248,81,73,0.1); border: 1px solid var(--danger);
  color: var(--danger); padding: 10px 14px; border-radius: 6px;
  margin-bottom: 12px; font-size: 0.85em;
}
.warning-msg {
  background: rgba(210,153,34,0.1); border: 1px solid var(--warn);
  color: var(--warn); padding: 8px 14px; border-radius: 6px;
  margin-bottom: 8px; font-size: 0.82em;
}
.metrics {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 8px; margin-bottom: 12px;
}
.metric {
  background: var(--bg3); padding: 8px 12px; border-radius: 6px;
  text-align: center;
}
.metric .val { font-size: 1.3em; font-weight: 700; color: var(--accent2); }
.metric .lbl { font-size: 0.72em; color: var(--fg-dim); text-transform: uppercase; }
.preview-box {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 10px; max-height: 400px; overflow: auto;
  font-family: var(--mono); font-size: 0.78em; white-space: pre;
  line-height: 1.4; color: var(--fg);
}
.dl-btn {
  display: inline-block; padding: 8px 20px; background: var(--accent2);
  color: #000; border-radius: 6px; text-decoration: none;
  font-weight: 600; font-size: 0.85em; margin-top: 8px;
}
.dl-btn:hover { opacity: 0.85; }
.hidden { display: none; }
footer {
  margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border);
  font-size: 0.78em; color: var(--fg-dim); text-align: center;
}
</style>
</head>
<body>
<h1><span class="shield">🛡️</span> Bedrock Playground</h1>
<p class="subtitle">Obfuscator preview — paste Python code, pick a profile, get obfuscated output. For RE testing only.</p>

<div class="panel">
  <label for="source">Python Source Code</label>
  <textarea id="source" placeholder="# Paste your Python code here...&#10;def hello():&#10;    print('hello world')&#10;&#10;hello()"></textarea>
</div>

<div class="panel">
  <label>Profile</label>
  <div class="profile-row">
    <button class="profile-btn" data-profile="fast">Fast</button>
    <button class="profile-btn active" data-profile="balanced">Balanced</button>
    <button class="profile-btn" data-profile="paranoid">Paranoid</button>
    <button class="profile-btn" data-profile="extreme">Extreme</button>
  </div>
  <div class="profile-desc" id="profile-desc">Balanced — rename + string obf + builtin indirection. Good default.</div>

  <div class="opts" style="margin-top:12px;">
    <label class="opt"><input type="checkbox" id="native-vm" checked> Native VM (.pyd)</label>
    <label class="opt"><input type="checkbox" id="anti-meta" checked> Anti-meta (debrand)</label>
  </div>
  <div class="caveat">⚠ Native VM (.pyd) chỉ hoạt động trên Windows Python 3.11 (cùng platform với server). Platform khác tự fallback sang pure-Python reference.</div>
</div>

<button class="submit" id="submit" onclick="doObfuscate()">Obfuscate</button>

<div class="result" id="result"></div>

<footer>
  Bedrock Obfuscator Playground — Preview build. Source ≤50KB, ≤2000 lines. Rate limit 5/min.
  Tmp files auto-purge after 1h. No source is stored permanently.
</footer>

<script>
const PROFILES = {
  fast:      "Fast — identifier renaming only. Fastest, weakest.",
  balanced:  "Balanced — rename + string obf + builtin indirection. Good default.",
  paranoid:  "Paranoid — + CFF, anti-VM, anti-timing, decompiler traps, str-cipher.",
  extreme:   "Extreme — + native VM, chain, capsule, poison, metamorphic, all phases.",
};
let selectedProfile = "balanced";

document.querySelectorAll(".profile-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".profile-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    selectedProfile = btn.dataset.profile;
    document.getElementById("profile-desc").textContent = PROFILES[selectedProfile];
  });
});

async function doObfuscate() {
  const source = document.getElementById("source").value;
  const nativeVm = document.getElementById("native-vm").checked;
  const antiMeta = document.getElementById("anti-meta").checked;
  const btn = document.getElementById("submit");
  const resultDiv = document.getElementById("result");

  if (!source.trim()) {
    resultDiv.innerHTML = '<div class="error-msg">Please paste some Python code first.</div>';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Obfuscating...';
  resultDiv.innerHTML = '<span class="spinner"></span>Building (this can take 5-30s depending on profile)...';

  try {
    const resp = await fetch("/api/obfuscate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, profile: selectedProfile, native_vm: nativeVm, anti_meta: antiMeta }),
    });
    const data = await resp.json();

    if (!data.ok) {
      resultDiv.innerHTML = `<div class="error-msg">❌ ${escapeHtml(data.error)}</div>`;
      return;
    }

    let html = "";

    // Warnings
    if (data.warnings && data.warnings.length) {
      html += data.warnings.map(w => `<div class="warning-msg">⚠ ${escapeHtml(w)}</div>`).join("");
    }

    // Metrics
    const m = data.metrics || {};
    html += `<div class="metrics">
      <div class="metric"><div class="val">${fmt(m.output_size)}</div><div class="lbl">Output (bytes)</div></div>
      <div class="metric"><div class="val">${fmt(m.n_idents_renamed)}</div><div class="lbl">Renames</div></div>
      <div class="metric"><div class="val">${fmt(m.n_strings_encoded)}</div><div class="lbl">Strings</div></div>
      <div class="metric"><div class="val">${fmt(m.n_consts_encrypted)}</div><div class="lbl">Consts</div></div>
      <div class="metric"><div class="val">${(m.entropy_output||0).toFixed(2)}</div><div class="lbl">Entropy</div></div>
      <div class="metric"><div class="val">${(m.duration_ms||0)}</div><div class="lbl">ms</div></div>
    </div>`;

    // Download
    html += `<a class="dl-btn" href="/api/download/${data.download_id}" download>⬇ Download ZIP (obf.py + .pyd + ref.py + report.json)</a>`;

    // Preview
    html += `<div style="margin-top:12px;"><label>Preview (first 200 lines):</label><div class="preview-box">${escapeHtml(data.preview || "")}</div></div>`;

    resultDiv.innerHTML = html;
  } catch (err) {
    resultDiv.innerHTML = `<div class="error-msg">Network error: ${escapeHtml(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = "Obfuscate";
  }
}

function fmt(n) { return (n || 0).toLocaleString(); }
function escapeHtml(s) {
  return String(s).replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>').replace(/"/g,'"');
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return FRONTEND_HTML


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
