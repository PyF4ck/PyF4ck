"""Bedrock Obfuscator — TUI cho người ít chuyên về code.

Giao diện dòng lệnh tương tác (TUI) giúp người không rành code vẫn dùng
được Bedrock Obfuscator: chọn file → chọn mức bảo vệ → build → xem kết quả.

Run:
    python tui.py
    pip install rich prompt_toolkit   # nếu chưa có
"""
from __future__ import annotations

import os
import sys
import subprocess
import tempfile
import time
from pathlib import Path

from prompt_toolkit.shortcuts import radiolist_dialog, checkboxlist_dialog, input_dialog, yes_no_dialog, message_dialog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.align import Align
from rich.text import Text

console = Console()

OBFUSCATOR = Path(__file__).parent / "bedrock_obfuscator.py"

# --- Profile descriptions (plain Vietnamese for non-coders) ----------------

PROFILES = [
    ("fast", "⚡ Nhanh",
     "Đổi tên biến + mã hóa chuỗi. Nhẹ nhất, build <1 giây. "
     "Chống người mới học RE."),
    ("balanced", "⚖️ Cân bằng",
     "Mặc định. Đổi tên + mã hóa + builtin indirection. "
     "Tốt cho đa số trường hợp, build ~3 giây."),
    ("paranoid", "🛡️ Kỹ lưỡng",
     "Thêm chống decompile, CFF, chống VM, bẫy timing. "
     "Cho người có tool RE chuyên nghiệp, build ~8 giây."),
    ("extreme", "🔥 Tối đa",
     "Đầy đủ bảo vệ: native VM + capsule + chain + poison + "
     "metamorphic + anti-AI. Mạnh nhất, build ~15-100 giây."),
    ("io", "🔐 iO (chuyên nghiệp)",
     "Mã hóa toàn bộ source (byte distribution ≈ random) + "
     "Phase G + Phase H + anti-AI. Build ~25-180 giây. "
     "Cần capsule key để chạy (file .key đi kèm)."),
]

OPTIONS = [
    ("anti_ai", "🤖 Chống AI phân tích (anti-AI)",
     "Thêm decoy functions, prompt-injection comments, homoglyph twins, "
     "zero-width chars. Khiến GPT/Claude từ chối hoặc hiểu sai code. "
     "KHÔNG dùng output này với LLM tooling của bạn."),
    ("anti_meta", "🏷️ Xóa dấu hiệu Bedrock (anti-meta)",
     "Xóa mọi chữ 'bedrock', 'baobg' trong output. "
     "Đề phòng người khác nhận ra tool bạn dùng."),
]


def _banner():
    """Hiển thị banner chào mừng."""
    console.print()
    console.print(Align.center(Text("🛡️  BEDROCK OBFUSCATOR", style="bold cyan", size=60)))
    console.print(Align.center(Text("Công cụ bảo vệ code Python", style="dim")))
    console.print(Align.center(Text("— TUI cho người ít chuyên về code —", style="dim italic")))
    console.print()


def _choose_source() -> str | None:
    """Bước 1: chọn nguồn code (paste hoặc file path)."""
    choice = radiolist_dialog(
        title="Bước 1: Chọn nguồn code",
        text="Bạn muốn obfuscate code từ đâu?",
        values=[
            ("paste", "✍️  Dán code trực tiếp"),
            ("file", "📂 Chọn file .py có sẵn"),
        ],
    ).run()

    if choice is None:
        return None

    if choice == "file":
        path = input_dialog(
            title="Nhập đường dẫn file",
            text="Đường dẫn đến file .py cần obfuscate:",
        ).run()
        if not path:
            return None
        path = path.strip().strip('"').strip("'")
        if not os.path.isfile(path):
            console.print(f"[red]❌ Không tìm thấy file: {path}[/red]")
            return None
        try:
            return open(path, "r", encoding="utf-8").read()
        except Exception as e:
            console.print(f"[red]❌ Không đọc được file: {e}[/red]")
            return None

    # paste mode — open a simple multi-line editor
    console.print()
    console.print(Panel(
        "[yellow]Dán code Python của bạn vào đây.[/yellow]\n"
        "[dim]Nhấn Enter để xuống dòng, Ctrl+D (hoặc Esc hai lần) để kết thúc.[/dim]",
        title="Dán code",
        border_style="yellow",
    ))
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    source = "\n".join(lines)
    if not source.strip():
        console.print("[red]❌ Không có code nào được dán.[/red]")
        return None
    return source


def _choose_profile() -> str | None:
    """Bước 2: chọn mức bảo vệ."""
    values = [(p[0], f"{p[1]}\n    {p[2]}") for p in PROFILES]
    return radiolist_dialog(
        title="Bước 2: Chọn mức bảo vệ",
        text="Chọn mức độ obfuscation (dùng ↑↓ để chọn, Enter để xác nhận):",
        values=values,
    ).run()


def _choose_options() -> dict:
    """Bước 3: chọn tùy chọn."""
    values = [(o[0], f"{o[1]}\n    {o[2]}") for o in OPTIONS]
    chosen = checkboxlist_dialog(
        title="Bước 3: Tùy chọn bổ sung",
        text="Chọn các tùy chọn (Space để tick, Enter để xác nhận):",
        values=values,
    ).run()
    if chosen is None:
        chosen = []
    return {opt: (opt in chosen) for opt, _, _ in OPTIONS}


def _build(source: str, profile: str, options: dict) -> dict:
    """Chạy bedrock_obfuscator.py và trả về kết quả."""
    work = Path(tempfile.mkdtemp(prefix="bedrock_tui_"))
    input_path = work / "input.py"
    output_path = work / "obf.py"
    report_path = work / "report.json"
    input_path.write_text(source, encoding="utf-8")

    cmd = [
        sys.executable, str(OBFUSCATOR),
        "-f", str(input_path),
        "-o", str(output_path),
        "--profile", profile,
        "--no-cache", "--overwrite",
        "--adv-requests", "off",
        "--no-anti-timing",
        # Sandbox-safe defaults
        "--anti-vm", "off",
        "--anti-debug", "off",
        "--no-debug-poison",
        "--no-native-vm",
    ]
    if options.get("anti_meta"):
        cmd.append("--anti-meta")
    if options.get("anti_ai"):
        cmd.append("--h-anti-ai")
    else:
        cmd.append("--no-h-anti-ai")

    # embed-key for io (so output runs without env var in this demo TUI)
    if profile == "io":
        cmd.extend(["--no-metamorphic", "--embed-key"])

    # io/extreme + anti-AI + anti-meta can take several minutes (io is the
    # heaviest profile — encrypted capsule + all passes + 200 decoys). 600s
    # gives headroom so heavy builds don't time out on slow machines.
    t0 = time.time()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600,
        cwd=str(work), encoding="utf-8", errors="replace",
    )
    elapsed = time.time() - t0

    result = {
        "ok": proc.returncode == 0,
        "output_path": str(output_path),
        "elapsed": elapsed,
        "report_path": str(report_path),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "key_path": str(output_path) + ".key",
    }
    return result


def _show_result(result: dict, profile: str, options: dict):
    """Hiển thị kết quả build."""
    if not result["ok"]:
        console.print()
        console.print(Panel(
            f"[red]❌ Build thất bại![/red]\n\n"
            f"[dim]Lỗi:[/dim]\n{result['stderr'][-500:]}",
            title="Kết quả",
            border_style="red",
        ))
        return

    out_path = result["output_path"]
    file_size = os.path.getsize(out_path) if os.path.exists(out_path) else 0

    console.print()
    console.print(Panel(
        f"[green]✅ Build thành công![/green]  "
        f"[dim]({result['elapsed']:.1f}s)[/dim]",
        title="Kết quả",
        border_style="green",
    ))

    # Metrics table
    table = Table(title="Thông tin output", show_header=True, header_style="bold cyan")
    table.add_column("Thuộc tính", style="dim", width=20)
    table.add_column("Giá trị")
    table.add_row("File output", out_path)
    table.add_row("Kích thước", f"{file_size:,} bytes ({file_size/1024:.1f} KB)")
    table.add_row("Profile", profile)
    if options.get("anti_ai"):
        table.add_row("Anti-AI", "[green]✅ Bật[/green]")
    if options.get("anti_meta"):
        table.add_row("Anti-meta", "[green]✅ Bật[/green]")
    if os.path.exists(result["key_path"]):
        table.add_row("Capsule key", result["key_path"])
    console.print(table)

    # How to run
    console.print()
    run_lines = [f"python {out_path}"]
    if os.path.exists(result["key_path"]):
        run_lines.insert(0, f"# Cần capsule key để chạy:")
        run_lines.append(f"# hoặc: BR_CAPSULE_KEY=$(cat {result['key_path']}) python {out_path}")
    console.print(Panel(
        "\n".join(run_lines),
        title="🚀 Cách chạy file đã obfuscate",
        border_style="cyan",
    ))

    # Preview (first 30 lines)
    if os.path.exists(out_path):
        try:
            raw = open(out_path, "rb").read()
            # io profile produces latin-1; others are utf-8
            enc = "latin-1" if profile == "io" else "utf-8"
            text = raw.decode(enc, errors="replace")
            lines = text.split("\n")
            preview = "\n".join(lines[:30])
            if len(lines) > 30:
                preview += f"\n\n... ({len(lines) - 30} dòng nữa — mở file để xem hết)"
            console.print()
            console.print(Panel(
                Syntax(preview, "python", theme="monokai", line_numbers=False),
                title="📄 Xem trước (30 dòng đầu)",
                border_style="blue",
            ))
        except Exception as e:
            console.print(f"[dim](Không hiển thị preview: {e})[/dim]")


def main():
    """Vòng lặp chính: chọn → build → xem → hỏi lại."""
    _banner()

    while True:
        # Bước 1: source
        source = _choose_source()
        if source is None:
            console.print("[dim]Hủy. Tạm biệt![/dim]")
            break

        # Bước 2: profile
        profile = _choose_profile()
        if profile is None:
            console.print("[dim]Hủy.[/dim]")
            break

        # Bước 3: options
        options = _choose_options()

        # Xác nhận
        console.print()
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column(style="bold cyan", width=15)
        summary.add_column()
        summary.add_row("Nguồn:", f"{len(source)} chars")
        summary.add_row("Profile:", profile)
        summary.add_row("Anti-AI:", "✅" if options.get("anti_ai") else "❌")
        summary.add_row("Anti-meta:", "✅" if options.get("anti_meta") else "❌")
        console.print(Panel(summary, title="📋 Tóm tắt", border_style="cyan"))

        # Build với progress spinner
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Đang build...[/bold cyan]"),
            BarColumn(),
            TextColumn("[dim]{task.elapsed:.1f}s[/dim]"),
            console=console,
        ) as progress:
            progress.add_task("build", total=None)
            try:
                result = _build(source, profile, options)
            except subprocess.TimeoutExpired:
                console.print("\n[red]❌ Build hết giờ (300s). Thử profile nhẹ hơn.[/red]")
                continue
            except Exception as e:
                console.print(f"\n[red]❌ Lỗi: {e}[/red]")
                continue

        _show_result(result, profile, options)

        # Hỏi tiếp
        console.print()
        again = yes_no_dialog(
            title="Tiếp tục?",
            text="Bạn muốn obfuscate file khác không?",
        ).run()
        if not again:
            console.print()
            console.print(Align.center(Text("👋 Cảm ơn đã dùng Bedrock Obfuscator!", style="bold cyan")))
            console.print()
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Đã hủy. Tạm biệt![/dim]")
