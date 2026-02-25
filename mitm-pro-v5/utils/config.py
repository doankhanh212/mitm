#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Config Manager
Quản lý toàn bộ cấu hình phiên làm việc: đường dẫn, hằng số, YAML config.
"""

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


# ─── Hằng số mặc định ────────────────────────────────────────────────
VERSION = "5.0-BETTERCAP"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


@dataclass
class Config:
    """Cấu hình tĩnh — load 1 lần từ YAML + CLI override."""

    version: str = VERSION
    interface: str = "eth0"
    gateway: str = ""
    targets: List[str] = field(default_factory=list)
    cidr: str = ""
    mode: str = "safe"                       # safe | normal | aggressive
    max_targets: int = 25
    dry_run: bool = False
    enable_report: bool = True

    # Bettercap REST API
    api_host: str = "127.0.0.1"
    api_port: int = 8083
    api_user: str = "mitmpro"
    api_pass: str = "mitmpro"

    # Module flags
    arp_spoof: bool = True
    https_proxy: bool = True
    sslstrip: bool = True
    dns_spoof: bool = False
    dns_domains: str = ""                    # vd: "*.example.com"
    dns_address: str = ""                    # vd: IP attacker
    responder: bool = True
    pcap: bool = True

    # Đường dẫn output
    output_dir: Path = Path("mitm_pro_loot")
    log_file: Path = Path("mitm_pro.log")

    # Tính toán sau khi init
    res_log: Optional[Path] = None
    pcap_file: Optional[Path] = None

    # ARP interval theo mode
    ARP_INTERVAL = {"safe": 2.8, "normal": 1.6, "aggressive": 0.9}

    def setup_paths(self):
        """Tạo thư mục output và thiết lập đường dẫn file."""
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.res_log = self.output_dir / "responder.log"
        # capture.pcap = file bettercap net.sniff ghi vào (xem _setup_pcap)
        # tcpdump_capture.pcap = backup riêng từ tcpdump
        self.pcap_file = self.output_dir / "capture.pcap"

    @property
    def arp_interval(self) -> float:
        return self.ARP_INTERVAL.get(self.mode, 1.6)

    # ─── Load từ YAML ────────────────────────────────────────────────
    @classmethod
    def from_yaml(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        """Đọc cấu hình từ file YAML, trả về Config mới."""
        if not path.exists():
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        # Flatten: yaml có thể có section lồng nhau
        flat = {}
        for key, val in raw.items():
            if isinstance(val, dict):
                flat.update(val)
            else:
                flat[key] = val

        # Chỉ lấy key hợp lệ
        valid = {k: v for k, v in flat.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass
class State:
    """Trạng thái runtime — thay đổi trong suốt phiên."""

    iface: str = ""
    gw: str = ""
    gw_mac: str = ""
    targets: List[str] = field(default_factory=list)
    mode: str = "safe"
    start_time: float = 0.0
    orig_ip_forward: str = "0"
    bettercap_running: bool = False
    responder_pid: Optional[int] = None


def check_dependencies():
    """Kiểm tra các binary bắt buộc trước khi chạy."""
    required = ["bettercap", "tcpdump"]
    missing = [cmd for cmd in required if shutil.which(cmd) is None]
    if missing:
        print(f"❌ Thiếu các công cụ: {', '.join(missing)}")
        print("   Cài bằng: sudo apt install -y " + " ".join(missing))
        sys.exit(1)

    # Responder là tuỳ chọn
    if shutil.which("responder") is None:
        print("⚠️  Không tìm thấy responder — tính năng bắt NTLM sẽ bị tắt.")
