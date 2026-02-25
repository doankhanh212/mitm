# MITM-PRO v5.0 — Bettercap Core Edition

> ⚠️ **Chỉ dùng trong môi trường lab nội bộ có ủy quyền bằng văn bản. Sử dụng trái phép là vi phạm pháp luật.**

---

## Giới thiệu

MITM-PRO v5.0 là bản nâng cấp hoàn chỉnh từ v4.1, thay thế Scapy bằng **Bettercap** làm engine chính. Chương trình tự động chặn lưu lượng mạng giữa máy mục tiêu và router, ghi lại thông tin xác thực và lưu lượng rồi xuất báo cáo HTML sau mỗi phiên.

### Có gì mới so với v4.1

| | v4.1 (Scapy) | v5.0 (Bettercap) |
|---|---|---|
| Engine | Scapy tự gửi ARP | Bettercap (REST API) |
| HTTPS | Không có | SSLStrip + HSTS bypass |
| DNS Spoof | Không có | Có (tuỳ chọn) |
| Kiến trúc | 1 file duy nhất | Modular (core/ui/utils) |
| Config | Hardcode | YAML + CLI override |
| Validate input | Không | IP/CIDR kiểm tra trước khi chạy |
| Dừng process | terminate() | terminate → wait → kill |

---

## Cài đặt

### Yêu cầu

- **Linux** (Ubuntu / Kali / Debian)
- **Python 3.11+**
- **Quyền root** (`sudo`)

### Cài dependencies

```bash
# Thư viện Python
pip3 install -r requirements.txt

# Bettercap (bắt buộc)
sudo apt install -y bettercap

# tcpdump (bắt buộc)
sudo apt install -y tcpdump

# Responder (tuỳ chọn — bắt NTLM)
sudo apt install -y responder

# nmap (tuỳ chọn — quét host)
sudo apt install -y nmap
```

---

## Cấu trúc thư mục

```
mitm-pro-v5/
├── mitm_pro.py              ← Entry point chính
├── core/
│   └── bettercap_engine.py  ← Giao tiếp Bettercap qua REST API
├── ui/
│   └── dashboard.py         ← Dashboard Rich realtime
├── utils/
│   ├── config.py            ← Config + State + check dependency
│   ├── logger.py            ← Logging (console + file)
│   ├── cleanup.py           ← Dọn dẹp khi thoát
│   └── report.py            ← Sinh HTML report tự động
├── config/
│   └── default.yaml         ← Cấu hình mặc định
├── requirements.txt
└── README.md
```

---

## Cách dùng

### Chạy thử (không tấn công)

```bash
sudo python3 mitm_pro.py --dry-run
```

### Chạy hỏi đáp (Interactive Wizard)

```bash
sudo python3 mitm_pro.py
```

Chương trình hỏi lần lượt: interface, gateway IP, cách chọn target, mode.

### Chạy nhanh bằng CLI

```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --mode normal
```

### Ví dụ nâng cao

```bash
# DNS spoof + không dùng Responder + output tuỳ chỉnh
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -T 192.168.1.50,192.168.1.51 \
  --mode aggressive \
  --dns-spoof --dns-domains "*.corp.local" --dns-address 10.0.0.5 \
  --no-responder \
  -o /tmp/pentest_lab
```

---

## Tham số CLI đầy đủ

| Tham số | Ý nghĩa |
|---|---|
| `-i` | Tên card mạng |
| `-g` | IP gateway |
| `-R` | Dải CIDR để quét host |
| `-T` | Danh sách IP (phẩy phân cách) |
| `-o` | Thư mục output |
| `--mode` | `safe` / `normal` / `aggressive` |
| `--max-targets` | Giới hạn số target |
| `--dry-run` | Chạy thử |
| `--no-report` | Tắt tạo report |
| `--no-responder` | Không chạy Responder |
| `--no-sslstrip` | Tắt SSLStrip |
| `--dns-spoof` | Bật DNS spoofing |
| `--dns-domains` | Domain spoof |
| `--dns-address` | IP trả về cho DNS |
| `--api-port` | Port REST API bettercap |
| `--config` | Đường dẫn file YAML config riêng |

---

## Tuỳ chỉnh cấu hình

Sửa file `config/default.yaml` hoặc tạo file riêng rồi truyền `--config myconfig.yaml`.

---

## Kết quả sau phiên làm việc

Tất cả nằm trong thư mục `mitm_pro_loot/`:

| File | Nội dung |
|---|---|
| `mitm_pro.log` | Nhật ký chương trình |
| `responder.log` | Thông tin xác thực bắt được |
| `capture.pcap` | PCAP từ bettercap net.sniff |
| `tcpdump_capture.pcap` | PCAP backup từ tcpdump |
| `bettercap_stdout.log` | Log stdout bettercap |
| `PENTEST_REPORT_*.html` | Báo cáo HTML tự động |

---

## Mở rộng sau này

Kiến trúc modular giúp dễ thêm:
- `ntlmrelayx` integration
- `Evilginx` phishing proxy
- `Wireshark` auto-analysis
- Plugin system cho custom caplet

---

## Ghi chú kỹ thuật

### Bettercap REST API
Chương trình giao tiếp với bettercap qua REST API (`http://127.0.0.1:8083`).
Bettercap phải được khởi động với flag `-api-rest-*` — entry point xử lý việc này tự động.

### PCAP
- `capture.pcap` — ghi bởi bettercap `net.sniff` (chứa lưu lượng đi qua proxy)
- `tcpdump_capture.pcap` — backup ghi bởi tcpdump (raw traffic toàn interface)

### Module bật/tắt
Tất cả module (ARP, proxy, DNS, responder) có thể tắt riêng lẻ bằng flags CLI hoặc sửa `config/default.yaml`.

### Bug đã fix trong v5 (so với v4.1)
| Bug | Mô tả | Trạng thái |
|---|---|---|
| `--max-targets` không áp dụng | Giờ gán đúng vào config | ✅ Fixed |
| `--report` không có tác dụng | Dùng `--no-report` hoạt động thật | ✅ Fixed |
| Thiếu check binary | `check_dependencies()` kiểm tra trước khi chạy | ✅ Fixed |
| `terminate()` không `wait()` | `_safe_kill()`: terminate → wait → kill | ✅ Fixed |
| Thiếu validate IP/CIDR | `_validate_ip()` / `_validate_cidr()` | ✅ Fixed |
| Import wildcard scapy | Không còn dùng scapy | ✅ Fixed |
| Template key `{duration}` lỗi | Sửa thành `{duration_str}` khớp format() | ✅ Fixed |
| `get_events()` trả dict thay list | Unpack `data.get("events", [])` | ✅ Fixed |
| File handle `log_fd` bị leak | Lưu `self._log_fd`, đóng trong `stop()` | ✅ Fixed |
| Duration tính sai bằng `datetime.fromtimestamp` | Dùng số học nguyên h/m/s | ✅ Fixed |

---

## Lưu ý pháp lý

Sử dụng trên hệ thống không được phép là vi phạm pháp luật. Chỉ dùng trong lab có ủy quyền bằng văn bản.
