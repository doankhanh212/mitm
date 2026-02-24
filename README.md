# MITM-PRO (Phân tích mã nguồn)

> ⚠️ **Chỉ dùng cho lab nội bộ có ủy quyền bằng văn bản.**
> Repository này chứa công cụ can thiệp lưu lượng mạng (ARP spoofing / MITM). Không sử dụng trên hệ thống không thuộc quyền kiểm thử hợp pháp.

## 1) Tổng quan

`mitm_pro.py` là script Python chạy trên Linux, kết hợp:
- `scapy` để ARP scan và ARP poisoning.
- `responder` để bắt các xác thực kiểu NTLM/SMB/HTTP.
- `tcpdump` để ghi PCAP.
- `rich` để hiển thị dashboard realtime.

Mục tiêu kỹ thuật của script: dựng phiên MITM trên LAN giữa gateway và một hoặc nhiều target, đồng thời ghi log/pcap và tạo báo cáo HTML cuối phiên.

---

## 2) Kiến trúc chính trong source

### `Config`
- Quản lý hằng số phiên chạy: version, log file, output dir.
- `set_output_dir()` tạo thư mục output và thiết lập:
  - `responder.log`
  - `capture.pcap`

### `State`
- Lưu trạng thái runtime dạng global:
  - interface, gateway, gateway MAC
  - danh sách target + lock thread
  - process của responder/tcpdump
  - thread poisoning
  - mode và trạng thái `ip_forward` ban đầu

### `get_mac(ip)`
- Dò MAC qua ARP request (`srp`) và cache vào `mac_cache`.
- Trả `None` nếu không resolve được.

### `scan_live_hosts(cidr)`
- Quét ARP theo CIDR, bỏ qua gateway.
- Có giới hạn số host theo `Config.MAX_TARGETS`.

### `ArpPoisoner(Thread)`
- `run()`:
  - Resolve MAC gateway.
  - Pre-cache MAC target.
  - Lặp gửi 2 gói ARP giả:
	 - target nhận “gateway = attacker”
	 - gateway nhận “target = attacker”
- `stop()`:
  - Gửi ARP restore 2 chiều để phục hồi bảng ARP.

### `start_services()`
- Chạy `responder` và `tcpdump` bằng `subprocess.Popen`.
- Khởi tạo thread `ArpPoisoner`.

### `make_dashboard()`
- Vẽ giao diện realtime bằng `rich.Live`:
  - Header: version, uptime, mode, interface, số target
  - Main: bảng trạng thái target + MAC
  - Footer: số dòng NTLM gần đây + dung lượng PCAP

### `generate_report()`
- Sinh HTML report với thời gian, số target, số dòng chứa `NTLM`, đường dẫn log/pcap.

### `cleanup()`
- Dừng thread/process, restore `net.ipv4.ip_forward`, sinh report cuối phiên.

### `main()`
- Check Linux + quyền root.
- Parse CLI args hoặc vào chế độ interactive.
- Bật `ip_forward=1`, start service, chạy dashboard loop.
- Nhận `Ctrl+C` để thoát và cleanup.

---

## 3) Tham số CLI hiện có

- `-i, --interface`: network interface.
- `-g, --gateway`: IP gateway.
- `-R, --range`: CIDR scan targets.
- `-T, --targets`: danh sách IP phân tách dấu phẩy.
- `-o, --outdir`: thư mục output (mặc định `mitm_pro_loot`).
- `--mode`: `safe | normal | aggressive` (điều chỉnh chu kỳ ARP).
- `--max-targets`: giới hạn target (xem lưu ý bug bên dưới).
- `--report`: cờ report (hiện tại chưa tác dụng thực tế).
- `--dry-run`: chỉ kiểm tra luồng, không thực thi tấn công.

---

## 4) File output sau một phiên

- `mitm_pro.log`: log runtime của script.
- `<outdir>/responder.log`: log từ responder.
- `<outdir>/capture.pcap`: lưu lượng mạng bắt bởi tcpdump.
- `<outdir>/PENTEST_REPORT_YYYYMMDD_HHMM.html`: báo cáo tổng kết.

---

## 5) Các điểm quan trọng / rủi ro trong code

1. **`--max-targets` chưa được áp vào `Config.MAX_TARGETS`**
	- Parser nhận tham số nhưng không gán lại config, nên scan vẫn dùng giá trị mặc định 25.

2. **`--report` đang không có tác dụng**
	- `cleanup()` luôn gọi `generate_report()` bất kể cờ `--report`.

3. **Thiếu kiểm tra dependency runtime**
	- Script chỉ check import Python (`scapy`, `rich`) nhưng không check binary `responder`, `tcpdump` trước khi chạy.

4. **Xử lý lỗi còn rộng (`except:`/`except Exception`)**
	- Một số chỗ nuốt lỗi khiến khó truy vết sự cố thực tế.

5. **Thiếu validate input mạng**
	- Chưa kiểm tra format IP/CIDR/interface trước khi dùng.

6. **Quản lý process dừng chưa “cứng”**
	- `terminate()` không `wait()` hoặc fallback `kill()` khi process treo.

7. **Import wildcard `from scapy.all import *`**
	- Khó kiểm soát namespace, khó maintain lâu dài.

---

## 6) Đề xuất cải tiến kỹ thuật

- Gán `Config.MAX_TARGETS = args.max_targets` ngay sau parse args.
- Thêm cờ cấu hình thực cho report (ví dụ `state.enable_report = args.report`).
- Kiểm tra binary bằng `shutil.which("responder")` / `shutil.which("tcpdump")`.
- Validate IP/CIDR bằng `ipaddress`.
- Thay `except:` bằng exception cụ thể + log rõ nguyên nhân.
- Dừng process an toàn: `terminate() -> wait(timeout) -> kill()`.
- Tách wildcard import scapy thành import tường minh để code rõ hơn.

---

## 7) Cách kiểm tra an toàn (không tấn công)

Chỉ dùng chế độ dry-run để kiểm tra parser và luồng khởi tạo:

```bash
sudo python3 mitm_pro.py --dry-run
```

Nếu cần kiểm thử đầy đủ, chỉ thực hiện trong môi trường lab cô lập và có phê duyệt chính thức.

---

## 8) Phụ thuộc

- Python 3.10+
- Package Python: `scapy`, `rich`
- Công cụ hệ thống: `responder`, `tcpdump`, `sysctl`
- Linux + quyền `root`

---

## 9) Lưu ý pháp lý

Tác giả đã ghi rõ “Authorized Internal Exercise ONLY”. Việc sử dụng trên hệ thống trái phép có thể vi phạm pháp luật và chính sách an toàn thông tin.