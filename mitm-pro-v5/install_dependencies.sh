#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# MITM-PRO v5.0 — Dependency Installer
# Cài đặt tất cả công cụ cần thiết cho MITM-PRO
# ═══════════════════════════════════════════════════════════════

set -e

echo "════════════════════════════════════════════════════════"
echo "  MITM-PRO v5.0 — Cài đặt Dependencies"
echo "════════════════════════════════════════════════════════"
echo ""

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Vui lòng chạy với sudo!"
    exit 1
fi

echo "📦 Cập nhật package list..."
apt-get update -qq || true

echo ""
echo "🔧 Cài đặt build tools và dependencies..."
apt-get install -y -qq \
    build-essential \
    libpcap-dev \
    libusb-1.0-0-dev \
    libnetfilter-queue-dev \
    git \
    wget \
    curl

echo ""
echo "🌐 Cài đặt network tools..."
apt-get install -y -qq \
    nmap \
    tcpdump \
    dsniff \
    arp-scan \
    net-tools \
    iproute2 \
    iptables

echo ""
echo "🐍 Cài đặt Python dependencies..."
pip3 install -q -r requirements.txt

echo ""
echo "🚀 Cài đặt Bettercap..."
# Kiểm tra xem đã có bettercap chưa
if command -v bettercap &> /dev/null; then
    echo "   ✅ Bettercap đã được cài đặt: $(bettercap --version 2>&1 | head -n1)"
else
    # Cài bettercap từ GitHub releases
    echo "   📥 Tải Bettercap từ GitHub..."
    BETTERCAP_VERSION="v2.41.5"
    ARCH="linux_amd64"
    
    cd /tmp
    wget -q "https://github.com/bettercap/bettercap/releases/download/${BETTERCAP_VERSION}/bettercap_${ARCH}_${BETTERCAP_VERSION}.zip" -O bettercap.zip
    
    echo "   📦 Giải nén..."
    unzip -q bettercap.zip
    
    echo "   🔧 Cài đặt binary..."
    chmod +x bettercap
    mv bettercap /usr/local/bin/
    
    # Tạo symlink caplets folder
    mkdir -p /usr/local/share/bettercap/caplets
    
    echo "   ✅ Bettercap đã được cài đặt: $(bettercap --version 2>&1 | head -n1)"
    
    # Cleanup
    rm -f bettercap.zip
fi

echo ""
echo "🐸 Cài đặt Responder..."
if command -v responder &> /dev/null; then
    echo "   ✅ Responder đã được cài đặt"
else
    cd /opt
    if [ ! -d "Responder" ]; then
        git clone -q https://github.com/lgandx/Responder.git
    fi
    cd Responder
    git pull -q
    chmod +x Responder.py
    
    # Tạo symlink để dùng lệnh 'responder'
    ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
    
    echo "   ✅ Responder đã được cài đặt"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "✅ HOÀN TẤT! Các công cụ đã sẵn sàng:"
echo ""
echo "   • Bettercap: $(bettercap --version 2>&1 | head -n1 || echo 'ERROR')"
echo "   • nmap: $(nmap --version | head -n1 || echo 'ERROR')"
echo "   • tcpdump: $(tcpdump --version 2>&1 | head -n1 || echo 'ERROR')"
echo "   • Responder: $([ -f /opt/Responder/Responder.py ] && echo 'OK' || echo 'ERROR')"
echo ""
echo "🚀 Bây giờ bạn có thể chạy MITM-PRO:"
echo "   sudo python3 mitm_pro.py"
echo ""
echo "════════════════════════════════════════════════════════"
