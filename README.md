# MITM-PRO

> ⚠️ **Chỉ dùng trong môi trường lab nội bộ có ủy quyền bằng văn bản. Sử dụng trái phép là vi phạm pháp luật.**

---

## Giới thiệu

MITM-PRO là công cụ kiểm thử bảo mật mạng nội bộ dành cho các bài pentest có kiểm soát. Chương trình đặt máy kiểm thử vào vị trí trung gian giữa thiết bị mục tiêu và router trên cùng mạng LAN, thu thập thông tin xác thực, lưu lượng mạng rồi xuất báo cáo HTML tự động.

Phiên bản hiện tại: **v5.0 — Bettercap Core Edition** (nằm trong thư mục `mitm-pro-v5/`).

---

## Cấu trúc repository

```
mitm/
├── mitm-pro-v5/        ← Phiên bản hiện tại (Bettercap Engine)
│   ├── mitm_pro.py
│   ├── core/
│   ├── ui/
│   ├── utils/
│   ├── config/
│   ├── requirements.txt
│   └── README.md       ← Hướng dẫn chi tiết ở đây
└── README.md           ← File này
```

---

## Bắt đầu nhanh

```bash
cd mitm-pro-v5
pip3 install -r requirements.txt
sudo apt install -y bettercap tcpdump nmap
sudo python3 mitm_pro.py --help
```

Xem hướng dẫn đầy đủ tại [mitm-pro-v5/README.md](mitm-pro-v5/README.md).

---

## Lưu ý pháp lý

Tác giả: **Đoàn Khánh** — Authorized Internal Exercise ONLY. Không sử dụng trên hệ thống không có sự cho phép rõ ràng bằng văn bản.
