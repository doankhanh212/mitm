#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Logger
Cấu hình logging thống nhất: console + file, format chuyên nghiệp.
"""

import logging
import sys
from pathlib import Path

_CONFIGURED = False


def setup_logging(log_file: Path = Path("mitm_pro.log"), level: int = logging.INFO):
    """Thiết lập logger root — gọi 1 lần duy nhất."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ]
    logging.basicConfig(level=level, format=fmt, handlers=handlers)
    # Tắt noise từ urllib3 / requests
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
