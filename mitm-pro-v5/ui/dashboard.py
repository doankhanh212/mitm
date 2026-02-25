#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Rich Realtime Dashboard
Bảng điều khiển live: session info, ARP status, loot, PCAP stats.
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from utils.config import Config, State

console = Console()


def make_dashboard(
    cfg: Config,
    state: State,
    lan_hosts: Optional[List[Dict]] = None,
    events: Optional[List[Dict]] = None,
) -> Layout:
    """Tạo layout dashboard đầy đủ (gọi mỗi ~1.5s)."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=6),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=14),
    )

    # ─── Header: thông tin phiên ──────────────────────────────────
    uptime = _format_uptime(state.start_time)

    hdr = Table.grid(expand=True)
    hdr.add_column(ratio=1)
    hdr.add_column(ratio=1)
    hdr.add_row(
        f"[bold cyan]MITM-PRO[/] v{cfg.version}",
        f"Uptime: [green]{uptime}[/] │ Mode: [red]{state.mode.upper()}[/]",
    )
    hdr.add_row(
        f"Interface: [cyan]{state.iface}[/]  │  Gateway: [yellow]{state.gw}[/]",
        f"Targets: [yellow]{len(state.targets)}[/]  │  Bettercap: {_status_badge(state.bettercap_running)}",
    )
    layout["header"].update(Panel(hdr, title="🔒 SESSION", border_style="green"))

    # ─── Body: bảng target + trạng thái ARP ──────────────────────
    layout["body"].split_row(
        Layout(name="targets", ratio=3),
        Layout(name="events", ratio=2),
    )

    # Targets table
    tbl = Table(title="🧬 ARP POISON STATUS", box=box.ROUNDED, expand=True)
    tbl.add_column("Target IP", style="cyan", min_width=15)
    tbl.add_column("Hostname", style="white")
    tbl.add_column("MAC", style="magenta")
    tbl.add_column("Vendor", style="dim")
    tbl.add_column("Status", justify="center")

    # Tạo map host theo IP để tra nhanh
    host_map: Dict[str, Dict] = {}
    if lan_hosts:
        for h in lan_hosts:
            ip = h.get("ipv4", "")
            if ip:
                host_map[ip] = h

    for target in state.targets[:20]:  # giới hạn hiển thị 20 dòng
        info = host_map.get(target, {})
        mac = info.get("mac", "—")
        hostname = info.get("hostname", "—") or "—"
        vendor = info.get("vendor", "—") or "—"
        if mac and mac != "—":
            status = Text("✅ POISONED", style="bold green")
        else:
            status = Text("⏳ Resolving", style="yellow")
        tbl.add_row(target, hostname[:20], mac, vendor[:18], status)

    layout["targets"].update(Panel(tbl))

    # Events panel (lọc event thú vị từ bettercap)
    evt_lines = _format_events(events)
    layout["events"].update(
        Panel(evt_lines, title="📡 BETTERCAP EVENTS", border_style="blue")
    )

    # ─── Footer: loot + PCAP stats ───────────────────────────────
    loot_text = _build_loot_footer(cfg)
    layout["footer"].update(Panel(loot_text, title="🐸 REAL-TIME LOOT", border_style="red"))

    return layout


# ─── Helpers ──────────────────────────────────────────────────────────

def _format_uptime(start: float) -> str:
    if start <= 0:
        return "00:00:00"
    secs = int(time.time() - start)
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _status_badge(running: bool) -> str:
    return "[bold green]● RUNNING[/]" if running else "[bold red]● STOPPED[/]"


def _format_events(events: Optional[List[Dict]], limit: int = 12) -> str:
    """Chuyển events từ bettercap API thành text hiển thị."""
    if not events:
        return "[dim]Chờ events...[/]"

    # Lọc event quan trọng
    interesting_tags = {
        "sys.log", "net.sniff", "arp.spoof", "http.proxy",
        "https.proxy", "dns.spoof", "endpoint.new", "endpoint.lost",
    }
    lines = []
    for evt in events[-limit * 3:]:
        tag = evt.get("tag", "")
        if not any(t in tag for t in interesting_tags):
            continue
        ts = evt.get("time", "")
        if isinstance(ts, str) and "T" in ts:
            ts = ts.split("T")[1][:8]
        data_str = str(evt.get("data", ""))[:80]
        lines.append(f"[dim]{ts}[/] [cyan]{tag}[/] {data_str}")
        if len(lines) >= limit:
            break

    return "\n".join(lines) if lines else "[dim]Chưa có event đáng chú ý[/]"


def _build_loot_footer(cfg: Config) -> str:
    """Xây text footer: hash count, PCAP size, recent loot."""
    hashes = 0
    recent: List[str] = []

    if cfg.res_log and cfg.res_log.exists():
        try:
            text = cfg.res_log.read_text(encoding="utf-8", errors="ignore")
            all_lines = text.splitlines()
            recent = [
                l.strip() for l in all_lines[-15:]
                if any(k in l for k in ("NTLM", "SMB", "HTTP", "NTLMv", "Hash"))
            ]
            hashes = sum(1 for l in all_lines if "NTLM" in l)
        except Exception:
            pass

    pcap_mb = 0.0
    if cfg.pcap_file and cfg.pcap_file.exists():
        try:
            pcap_mb = os.path.getsize(cfg.pcap_file) / (1024 * 1024)
        except Exception:
            pass

    header = f"🔥 Hashes: [red]{hashes}[/]  │  PCAP: [cyan]{pcap_mb:.1f} MB[/]"
    body = "\n".join(recent[:8]) if recent else "[dim]Chưa bắt được loot nào...[/]"
    return f"{header}\n\n{body}"


def show_banner(version: str):
    """Hiển thị banner 1 lần khi khởi động."""
    console.print(Panel(
        f"[bold red]MITM-PRO v{version}[/]\n"
        "[cyan]Bettercap Core Edition — Enterprise Red Team[/]\n"
        "[green]Author: Đoàn Khánh[/]\n"
        "[yellow]AUTHORIZED INTERNAL EXERCISE ONLY[/yellow]",
        title="⚠️  LEGAL DISCLAIMER — DO NOT USE WITHOUT WRITTEN PERMISSION",
        style="bold red",
    ))
