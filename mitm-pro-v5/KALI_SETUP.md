# MITM-PRO v5.0 — Bettercap Core Edition

![Version](https://img.shields.io/badge/version-5.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)

**Enterprise Red Team / Pentest Tool — Chỉ dùng cho bài kiểm thử nội bộ có ủy quyền**

---

## 📋 Tổng quan

MITM-PRO v5.0 là công cụ Man-in-the-Middle tự động sử dụng Bettercap làm engine chính, được thiết kế cho Red Team và Penetration Testing.

### ✨ Tính năng

- 🎯 **ARP Spoofing** - Bidirectional poisoning với bettercap
- 🔐 **SSL Strip** - Downgrade HTTPS → HTTP để bắt traffic cleartext  
- 🌐 **DNS Spoofing** - Redirect traffic đến attacker server
- 🐸 **Responder Integration** - Bắt NTLM/SMB hashes tự động
- 📡 **Packet Capture** - Ghi PCAP qua bettercap net.sniff và tcpdump backup
- 📊 **Live Dashboard** - Real-time monitoring với Rich UI
- 📝 **Auto Report** - Tạo báo cáo HTML chi tiết sau khi kết thúc

### 🎮 Chế độ tấn công

- **Safe** - Chậm, ít đáng ngờ (khuyên dùng)
- **Normal** - Cân bằng tốc độ/stealth
- **Aggressive** - Nhanh, dễ bị phát hiện

---

## 🛠️ Cài đặt trên Kali Linux

### 1. Yêu cầu hệ thống

- Kali Linux 2022.1+ (hoặc Debian-based distro)
- Python 3.10+
- Quyền root/sudo

### 2. Cài đặt dependencies

```bash
# Clone repository
git clone https://github.com/doankhanh212/mitm.git
cd mitm/mitm-pro-v5

# Cài đặt tất cả dependencies (bettercap, nmap, responder, v.v.)
sudo ./install_dependencies.sh
```

Script sẽ tự động cài:
- ✅ Bettercap v2.41.5
- ✅ nmap (network scanner)
- ✅ tcpdump (packet capture)
- ✅ Responder (credential harvesting)
- ✅ arp-scan (ARP discovery)
- ✅ Python packages (rich, requests, pyyaml)

### 3. Cài đặt thủ công (nếu script lỗi)

```bash
# Bettercap
wget https://github.com/bettercap/bettercap/releases/download/v2.41.5/bettercap_linux_amd64_v2.41.5.zip
unzip bettercap_linux_amd64_v2.41.5.zip
sudo mv bettercap /usr/local/bin/
sudo chmod +x /usr/local/bin/bettercap

# Network tools
sudo apt update
sudo apt install -y nmap tcpdump arp-scan dsniff

# Responder
cd /opt
sudo git clone https://github.com/lgandx/Responder.git
sudo ln -s /opt/Responder/Responder.py /usr/local/bin/responder

# Python packages
pip3 install -r requirements.txt
```

### 4. Kiểm tra cài đặt

```bash
bettercap --version      # v2.41.5
nmap --version           # Nmap 7.x
responder --version      # Responder 3.x
tcpdump --version        # tcpdump 4.x
```

---

## 🚀 Sử dụng

### Mode 1: Interactive Wizard (Khuyên dùng cho người mới)

```bash
sudo python3 mitm_pro.py
```

Tool sẽ hỏi từng bước:
1. Interface mạng (vd: `eth0`, `wlan0`)
2. Gateway IP (vd: `192.168.1.1`)
3. Cách chọn target: nhập IP hoặc quét CIDR
4. Chế độ tấn công: safe/normal/aggressive

### Mode 2: CLI Mode (Nhanh cho người có kinh nghiệm)

#### Quét mạng và tấn công:
```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --mode normal
```

#### Tấn công các IP cụ thể:
```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -T 192.168.1.100,192.168.1.101 \
  --mode safe
```

#### Với DNS Spoofing:
```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --dns-spoof \
  --dns-domains "*.corp.local" \
  --dns-address 192.168.1.50
```

### Options đầy đủ

```
Options:
  -i, --interface       Network interface (mặc định: eth0)
  -g, --gateway         Gateway IP
  -R, --range           CIDR range để quét (vd: 192.168.1.0/24)
  -T, --targets         Danh sách IP target (vd: 10.0.0.5,10.0.0.6)
  -o, --outdir          Thư mục output (mặc định: mitm_pro_loot)
  --mode                Chế độ: safe/normal/aggressive
  --max-targets         Giới hạn số target (mặc định: 25)
  --no-report           Không tạo report HTML
  --no-responder        Không chạy Responder
  --no-sslstrip         Không dùng SSLStrip
  --dns-spoof           Bật DNS spoofing
  --dns-domains         Domain cần spoof (vd: *.example.com)
  --dns-address         IP trả về cho DNS query
  --api-port            Port Bettercap API (mặc định: 8083)
  --config              File YAML config tùy chỉnh
  --dry-run             Chạy thử không tấn công
```

---

## 📊 Dashboard

Khi chạy, tool hiển thị dashboard real-time:

```
╔══════════════════════════════════════════════════════════╗
║          MITM-PRO v5.0 — Live Dashboard                  ║
╠══════════════════════════════════════════════════════════╣
║ Interface: eth0                                           ║
║ Gateway:   192.168.1.1                                    ║
║ Targets:   3 hosts                                        ║
║ Mode:      NORMAL                                         ║
║ Runtime:   00:05:23                                       ║
╠══════════════════════════════════════════════════════════╣
║ 📊 LAN Hosts Discovered: 12                              ║
║                                                           ║
║ IP              MAC                Vendor                 ║
║ 192.168.1.100   AA:BB:CC:DD:EE:FF  Apple Inc             ║
║ 192.168.1.101   11:22:33:44:55:66  Samsung Electronics   ║
║                                                           ║
╠══════════════════════════════════════════════════════════╣
║ 📡 Recent Events                                          ║
║ [18:40:46] ✅ IP forwarding = 1                          ║
║ [18:40:46] 🚀 Khởi động bettercap trên eth0...           ║
║ [18:40:48] ✅ Bettercap API đã sẵn sàng                   ║
║ [18:41:15] 🔴 ARP Spoof → 192.168.1.100                  ║
╚══════════════════════════════════════════════════════════╝

Press Ctrl+C để dừng an toàn...
```

---

## 📁 Output

Tất cả kết quả được lưu trong `mitm_pro_loot/`:

```
mitm_pro_loot/
├── mitm_pro.log                 # Log chi tiết
├── bettercap_stdout.log         # Bettercap process log
├── responder.log                # Responder output
├── capture.pcap                 # Network capture (bettercap)
├── tcpdump_capture.pcap         # Backup capture (tcpdump)
└── PENTEST_REPORT_20260306_184111.html   # Báo cáo HTML
```

### Báo cáo HTML

Mở file `PENTEST_REPORT_*.html` trong browser để xem:
- Thông tin session
- Danh sách hosts đã phát hiện
- Timeline các sự kiện
- Thống kê tấn công

---

## 🔍 Troubleshooting

### 1. "Bettercap không khởi động được"

**Nguyên nhân:** Interface sai, port xung đột, hoặc không có quyền root

**Giải pháp:**
```bash
# Kiểm tra interfaces
ip addr show

# Kiểm tra port 8083 có bị chiếm không
sudo netstat -tlnp | grep 8083

# Đảm bảo chạy với sudo
sudo python3 mitm_pro.py

# Xem log chi tiết
cat mitm_pro_loot/bettercap_stdout.log
```

### 2. "Không tìm thấy bettercap trong PATH"

```bash
# Cài lại bettercap
sudo ./install_dependencies.sh

# Hoặc kiểm tra PATH
which bettercap
echo $PATH
```

### 3. "Không có target nào được tìm thấy"

```bash
# Thử quét thủ công trước
sudo nmap -sn 192.168.1.0/24

# Hoặc dùng arp-scan
sudo arp-scan -I eth0 192.168.1.0/24
```

### 4. ARP Spoofing không hoạt động

```bash
# Đảm bảo IP forwarding đã bật
sudo sysctl -w net.ipv4.ip_forward=1

# Kiểm tra firewall không chặn
sudo iptables -L -n -v

# Thử mode aggressive
sudo python3 mitm_pro.py --mode aggressive
```

---

## ⚠️ Cảnh báo pháp lý

**QUAN TRỌNG:**

- ⛔ Chỉ sử dụng trên mạng BẠN SỞ HỮU hoặc có **ủy quyền bằng văn bản**
- ⛔ Việc tấn công mạng không được phép là **BẤT HỢP PHÁP**
- ⛔ Người phát triển KHÔNG chịu trách nhiệm cho việc lạm dụng công cụ

**Use Cases hợp pháp:**
- ✅ Pentest có hợp đồng
- ✅ Red Team exercise nội bộ
- ✅ Lab học tập/nghiên cứu
- ✅ Bug bounty programs

---

## 🧪 Testing

### Dry-run (không tấn công thật)

```bash
sudo python3 mitm_pro.py \
  -i eth0 \
  -g 192.168.1.1 \
  -R 192.168.1.0/24 \
  --dry-run
```

### Lab Setup với VirtualBox/VMware

1. Tạo mạng nội bộ Host-Only hoặc NAT Network
2. Cài Kali VM (attacker) + Windows/Ubuntu VM (victims)
3. Cấu hình cùng subnet (vd: 192.168.56.0/24)
4. Test trên môi trường isolated

---

## 🔧 Tùy chỉnh nâng cao

### Custom Config YAML

Tạo file `my_config.yaml`:

```yaml
interface: wlan0
gateway: ""
mode: safe
max_targets: 50

api_host: "127.0.0.1"
api_port: 8083
api_user: "myuser"
api_pass: "mypass"

arp_spoof: true
https_proxy: true
sslstrip: true
dns_spoof: false
responder: true
pcap: true

output_dir: "custom_loot"
```

Chạy với config:
```bash
sudo python3 mitm_pro.py --config my_config.yaml
```

### Tích hợp với tools khác

```bash
# Xem PCAP với Wireshark
wireshark mitm_pro_loot/capture.pcap

# Parse credentials từ Responder logs
grep "NTLMv2-SSP Hash" mitm_pro_loot/responder.log

# Crack hashes với John
john --format=netntlmv2 hashes.txt
```

---

## 📚 Tài liệu tham khảo

- [Bettercap Documentation](https://www.bettercap.org/)
- [Responder Documentation](https://github.com/lgandx/Responder)
- [MITM Attack Fundamentals](https://attack.mitre.org/techniques/T1557/)

---

## 👤 Tác giả

Đoàn Khánh - [@doankhanh212](https://github.com/doankhanh212)

---

## 📝 License

Chỉ dùng cho mục đích giáo dục và pentesting có ủy quyền. 
Sử dụng không đúng mục đích là trách nhiệm của người dùng.

---

**Happy (Ethical) Hacking! 🎯**
