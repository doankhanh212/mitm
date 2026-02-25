#!/usr/bin/env python3
"""
MITM-PRO v5.0 — Auto HTML Report
Sinh báo cáo pentest cuối phiên dạng HTML.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>MITM-PRO v5.0 — Pentest Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
  h2 {{ color: #f0883e; }}
  table {{ border-collapse: collapse; width: 100%%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #30363d; padding: .5rem .8rem; text-align: left; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .85rem; }}
  .ok {{ background: #238636; color: #fff; }}
  .warn {{ background: #d29922; color: #000; }}
  .footer {{ margin-top: 2rem; font-size: .8rem; color: #8b949e; }}
</style>
</head>
<body>
<h1>🔒 MITM-PRO v5.0 — Pentest Report</h1>
<table>
  <tr><th>Thời gian</th><td>{timestamp}</td></tr>
  <tr><th>Interface</th><td>{iface}</td></tr>
  <tr><th>Gateway</th><td>{gateway}</td></tr>
  <tr><th>Mode</th><td>{mode}</td></tr>
  <tr><th>Thời lượng phiên</th><td>{duration_str}</td></tr>
</table>

<h2>Mục tiêu ({target_count})</h2>
<table>
  <tr><th>#</th><th>IP</th></tr>
  {target_rows}
</table>

<h2>Kết quả thu thập</h2>
<table>
  <tr><th>NTLM Hashes</th><td>{ntlm_count}</td></tr>
  <tr><th>PCAP file</th><td>{pcap_path} ({pcap_mb:.1f} MB)</td></tr>
  <tr><th>Responder log</th><td>{res_log}</td></tr>
</table>

{loot_section}

<div class="footer">Báo cáo tạo tự động bởi MITM-PRO v5.0 — Chỉ dùng cho bài kiểm thử nội bộ có ủy quyền.</div>
</body>
</html>
"""


def _count_ntlm(res_log: Optional[Path]) -> int:
    """Đếm số dòng chứa 'NTLM' trong responder log."""
    if res_log is None or not res_log.exists():
        return 0
    try:
        return sum(1 for line in res_log.open(errors="ignore") if "NTLM" in line)
    except Exception:
        return 0


def _recent_loot(res_log: Optional[Path], limit: int = 20) -> str:
    """Trích xuất các dòng loot gần nhất."""
    if res_log is None or not res_log.exists():
        return ""
    try:
        lines = res_log.read_text(encoding="utf-8", errors="ignore").splitlines()
        interesting = [l.strip() for l in lines if any(k in l for k in ("NTLM", "SMB", "HTTP", "NTLMv", "Hash"))]
        if not interesting:
            return ""
        rows = "\n".join(f"  <tr><td>{l}</td></tr>" for l in interesting[-limit:])
        return f"<h2>Recent Loot (last {limit})</h2>\n<table>\n  <tr><th>Entry</th></tr>\n{rows}\n</table>"
    except Exception:
        return ""


def generate_report(
    *,
    output_dir: Path,
    iface: str,
    gateway: str,
    mode: str,
    duration_str: str,
    targets: List[str],
    pcap_file: Optional[Path],
    res_log: Optional[Path],
) -> Optional[Path]:
    """Sinh báo cáo HTML — trả về đường dẫn file hoặc None nếu lỗi."""
    try:
        ntlm_count = _count_ntlm(res_log)
        pcap_mb = 0.0
        if pcap_file and pcap_file.exists():
            pcap_mb = pcap_file.stat().st_size / (1024 * 1024)

        target_rows = "\n  ".join(
            f"<tr><td>{i+1}</td><td>{t}</td></tr>" for i, t in enumerate(targets)
        )

        html = _HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            iface=iface,
            gateway=gateway,
            mode=mode,
            duration_str=duration_str,
            target_count=len(targets),
            target_rows=target_rows,
            ntlm_count=ntlm_count,
            pcap_path=pcap_file or "—",
            pcap_mb=pcap_mb,
            res_log=res_log or "—",
            loot_section=_recent_loot(res_log),
        )

        report_path = output_dir / f"PENTEST_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path.write_text(html, encoding="utf-8")
        logging.info(f"📄 Report saved: {report_path}")
        return report_path
    except Exception as e:
        logging.error(f"❌ Tạo report thất bại: {e}")
        return None
