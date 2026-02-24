# MITM-PRO

> ⚠️ **Công cụ này chỉ được phép chạy trong môi trường lab nội bộ, có giấy phép bằng văn bản từ người có thẩm quyền. Tuyệt đối không dùng trên hệ thống của người khác nếu chưa được cho phép.**

---

## Giới thiệu

MITM-PRO là công cụ kiểm thử bảo mật mạng nội bộ dành cho các bài lab pentest có kiểm soát. Tên đầy đủ là **Man-In-The-Middle Professional** — nghĩa là chương trình đặt máy của người kiểm thử vào vị trí trung gian giữa hai thiết bị trên cùng mạng LAN, thường là giữa một máy tính nào đó và cổng mạng (router). Từ vị trí đó, toàn bộ dữ liệu đi lại giữa hai đầu đều chạy qua máy bạn trước khi đến đích thật.

Công cụ này giúp đội bảo mật kiểm tra xem: liệu kẻ xấu có thể ngồi lặng lẽ trong mạng rồi chặn bắt mật khẩu, phiên đăng nhập hay dữ liệu nhạy cảm không — từ đó tìm ra lỗ hổng và vá trước khi bị khai thác thật.

---

## Cách hoạt động

Khi bạn khởi động, chương trình thực hiện 4 việc cùng lúc:

1. **Quét mạng** — Tìm xem có những máy nào đang bật trong dải mạng bạn chỉ định.
2. **Chặn giữa đường** — Liên tục gửi thông điệp giả đến các máy mục tiêu và router, khiến cả hai tưởng rằng máy bạn chính là đầu kia của kết nối. Nhờ đó toàn bộ lưu lượng sẽ đi qua máy bạn.
3. **Bắt thông tin đăng nhập** — Ghi lại các lần đăng nhập Windows, chia sẻ file nội bộ (SMB), trình duyệt web (HTTP) đang truyền trên mạng.
4. **Ghi lại lưu lượng** — Lưu toàn bộ gói tin ra file để đội bảo mật đem về phân tích sau.

Khi bạn nhấn `Ctrl+C` để dừng, chương trình tự dọn dẹp: trả bảng mạng về trạng thái cũ rồi tạo báo cáo tổng kết dạng HTML.

---

## Cài đặt

### Yêu cầu máy

- Hệ điều hành **Linux** (Ubuntu, Kali, Debian đều được).
- Có **quyền root** (chạy bằng `sudo`).
- Đã cài **Python 3.10** trở lên.

### Cài các thứ cần thiết

```bash
# Cài thư viện Python
pip3 install scapy rich

# Cài công cụ hệ thống
sudo apt update
sudo apt install -y tcpdump responder
```

### Tải về

```bash
git clone https://github.com/doankhanh212/mitm.git
cd mitm
```

---

## Cách dùng

### Chạy thử — không làm gì thật

Dùng khi bạn muốn kiểm tra chương trình có lỗi không mà chưa muốn tác động gì vào mạng:

```bash
sudo python3 mitm_pro.py --dry-run
```

### Chạy theo kiểu hỏi đáp

Nếu không truyền tham số, chương trình sẽ tự hỏi từng bước:

```bash
sudo python3 mitm_pro.py
```

Lần lượt nhập theo hướng dẫn trên màn hình:
- Tên card mạng đang dùng (ví dụ `eth0`).
- Địa chỉ IP của router (ví dụ `192.168.1.1`).
- Nhập thẳng danh sách máy cần kiểm thử, hoặc để chương trình tự quét cả dải mạng.

### Chạy nhanh bằng lệnh đầy đủ

```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --mode safe
```

### Giải thích các tham số

| Tham số | Ý nghĩa |
|---|---|
| `-i` | Tên card mạng (ví dụ `eth0`, `wlan0`) |
| `-g` | Địa chỉ IP của router/gateway |
| `-R` | Tự động quét toàn bộ dải mạng (ví dụ `192.168.1.0/24`) |
| `-T` | Nhập thẳng danh sách IP, cách nhau bằng dấu phẩy |
| `-o` | Thư mục lưu kết quả (mặc định là `mitm_pro_loot`) |
| `--mode` | Tốc độ gửi gói tin: `safe` (chậm, ít bị phát hiện) / `normal` / `aggressive` |
| `--dry-run` | Chạy thử, không thực sự can thiệp mạng |

---

## Màn hình khi đang chạy

Trong lúc chạy bạn sẽ thấy một bảng điều khiển tự cập nhật gồm 3 khu vực:

- **Trên cùng** — Thời gian đã chạy, chế độ đang dùng, tên card mạng, số máy đang bị can thiệp.
- **Giữa** — Danh sách từng máy mục tiêu cùng trạng thái (đã chặn được chưa).
- **Dưới cùng** — Số lần bắt được thông tin đăng nhập và dung lượng file ghi tính đến lúc đó.

Nhấn **`Ctrl+C`** bất cứ lúc nào để dừng. Chương trình tự phục hồi mạng rồi lưu báo cáo.

---

## Kết quả sau một phiên làm việc

Tất cả nằm trong thư mục `mitm_pro_loot/` (hoặc thư mục bạn chỉ định bằng `-o`):

| File | Nội dung |
|---|---|
| `mitm_pro.log` | Nhật ký hoạt động của chương trình |
| `responder.log` | Danh sách thông tin đăng nhập bắt được trong phiên |
| `capture.pcap` | Toàn bộ gói tin đã đi qua máy, mở bằng Wireshark để xem |
| `PENTEST_REPORT_*.html` | Báo cáo tổng kết, mở bằng trình duyệt web bất kỳ |

---

## Lưu ý quan trọng

Sử dụng công cụ này trên mạng không được phép là **vi phạm pháp luật**. Chỉ dùng trong:
- Môi trường lab riêng của bạn.
- Bài kiểm thử nội bộ có hợp đồng hoặc giấy phép rõ ràng bằng văn bản.
