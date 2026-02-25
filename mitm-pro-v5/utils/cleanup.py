#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Cleanup
Dọn dẹp an toàn: stop bettercap, restore ARP, restore ip_forward, sinh report.
"""

import logging
import subprocess
import time
from typing import Optional

from utils.config import Config, State
from utils.report import generate_report


def _safe_kill(proc: Optional[subprocess.Popen], name: str, timeout: int = 5):
    """Dừng tiến trình an toàn: SIGTERM → chờ → SIGKILL."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        logging.info(f"🛑 {name} đã dừng (terminate)")
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
        logging.warning(f"⚠️ {name} phải kill cứng")
    except Exception as e:
        logging.warning(f"⚠️ Lỗi khi dừng {name}: {e}")


def restore_ip_forward(state: State):
    """Trả net.ipv4.ip_forward về giá trị ban đầu."""
    try:
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.ip_forward={state.orig_ip_forward}"],
            capture_output=True, check=True,
        )
        logging.info(f"🔁 Đã restore ip_forward={state.orig_ip_forward}")
    except Exception as e:
        logging.warning(f"⚠️ Không restore được ip_forward: {e}")


def full_cleanup(
    cfg: Config,
    state: State,
    bettercap_proc: Optional[subprocess.Popen] = None,
    responder_proc: Optional[subprocess.Popen] = None,
    tcpdump_proc: Optional[subprocess.Popen] = None,
):
    """
    Dọn dẹp toàn bộ phiên làm việc — gọi khi thoát (Ctrl+C hoặc kết thúc).
    1. Stop bettercap
    2. Stop responder
    3. Stop tcpdump
    4. Restore ip_forward
    5. Sinh report
    """
    logging.info("🧹 Bắt đầu cleanup...")

    _safe_kill(bettercap_proc, "bettercap")
    _safe_kill(responder_proc, "responder")
    _safe_kill(tcpdump_proc, "tcpdump")

    restore_ip_forward(state)

    # Tính thời lượng phiên bằng số học đơn giản (tránh nhầm lẫn timestamp vs duration)
    duration = "N/A"
    if state.start_time > 0:
        secs = int(time.time() - state.start_time)
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        duration = f"{h:02d}:{m:02d}:{s:02d}"

    if cfg.enable_report:
        generate_report(
            output_dir=cfg.output_dir,
            iface=state.iface,
            gateway=state.gw,
            mode=state.mode,
            duration_str=duration,
            targets=state.targets,
            pcap_file=cfg.pcap_file,
            res_log=cfg.res_log,
        )

    logging.info("✅ MITM-PRO v5.0 — PHIÊN LÀM VIỆC ĐÃ DỌN DẸP XONG")
