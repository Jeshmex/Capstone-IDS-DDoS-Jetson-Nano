#!/bin/bash
# =============================================================
# install.sh
# Automated setup script for Jetson Orin Nano
# AI-Based DDoS IDS - Jeshua Vargas Valenzuela CSC 520
#
# Run this ONCE after copying files to Jetson:
#   chmod +x install.sh
#   sudo ./install.sh
# =============================================================

set -e  # stop on any error

echo ""
echo "=================================================="
echo "  AI DDoS IDS - Jetson Setup Script"
echo "=================================================="
echo ""

# ── 1. Check running as root ───────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run with sudo"
    echo "       sudo ./install.sh"
    exit 1
fi

INSTALL_DIR="/home/jetson/ids"
echo "[1/7] Install directory: $INSTALL_DIR"
mkdir -p $INSTALL_DIR
echo "      OK"

# ── 2. System packages ────────────────────────────────────
echo ""
echo "[2/7] Updating system packages..."
apt update -qq
apt install -y python3-pip python3-dev libpcap-dev net-tools
echo "      OK"

# ── 3. Python packages ────────────────────────────────────
echo ""
echo "[3/7] Installing Python packages..."
pip3 install \
    flask \
    scikit-learn \
    numpy \
    pandas \
    scapy \
    joblib \
    requests
echo "      OK"

# ── 4. Verify installs ────────────────────────────────────
echo ""
echo "[4/7] Verifying Python imports..."
python3 -c "
import flask, sklearn, numpy, scapy, joblib, requests
print('      flask:      ', flask.__version__)
print('      sklearn:    ', sklearn.__version__)
print('      numpy:      ', numpy.__version__)
print('      All imports OK')
"

# ── 5. Check model files ──────────────────────────────────
echo ""
echo "[5/7] Checking model files..."
FILES=(
    "best_model.pkl"
    "scaler.pkl"
    "imputer.pkl"
    "label_encoder.pkl"
    "feature_columns.pkl"
    "ids_engine.py"
    "app.py"
)

ALL_OK=true
for f in "${FILES[@]}"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        SIZE=$(du -h "$INSTALL_DIR/$f" | cut -f1)
        echo "      FOUND    $f  ($SIZE)"
    else
        echo "      MISSING  $f  <-- copy this file to $INSTALL_DIR/"
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo ""
    echo "ERROR: Some files are missing."
    echo "       Copy all .pkl files, app.py, and ids_engine.py"
    echo "       to $INSTALL_DIR/ then run this script again."
    exit 1
fi

# ── 6. Detect network interface ───────────────────────────
echo ""
echo "[6/7] Detecting network interface..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi
echo "      Detected interface: $IFACE"
echo "      Updating ids_engine.py..."
sed -i "s/INTERFACE     = 'eth0'/INTERFACE     = '$IFACE'/" \
    $INSTALL_DIR/ids_engine.py
echo "      OK - interface set to $IFACE"
echo ""
echo "      Available interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print "        " $2}'

# ── 7. Create systemd services ────────────────────────────
echo ""
echo "[7/7] Creating systemd services..."

# Dashboard service
cat > /etc/systemd/system/ids-dashboard.service << EOF
[Unit]
Description=AI DDoS IDS Dashboard
After=network.target

[Service]
User=jetson
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Engine service
cat > /etc/systemd/system/ids-engine.service << EOF
[Unit]
Description=AI DDoS IDS Engine
After=network.target ids-dashboard.service
Wants=ids-dashboard.service

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ids_engine.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ids-dashboard
systemctl enable ids-engine
echo "      Services created and enabled"

# ── Done ──────────────────────────────────────────────────
JETSON_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=================================================="
echo "  SETUP COMPLETE"
echo "=================================================="
echo ""
echo "  To START the IDS:"
echo "    sudo systemctl start ids-dashboard"
echo "    sudo systemctl start ids-engine"
echo ""
echo "  To CHECK status:"
echo "    sudo systemctl status ids-dashboard"
echo "    sudo systemctl status ids-engine"
echo ""
echo "  To VIEW live logs:"
echo "    sudo journalctl -u ids-engine -f"
echo "    sudo journalctl -u ids-dashboard -f"
echo ""
echo "  Dashboard URL (from any device on network):"
echo "    http://$JETSON_IP:5000"
echo ""
echo "  Interface set to: $IFACE"
echo "  If wrong, edit INTERFACE in ids_engine.py"
echo "  Then restart: sudo systemctl restart ids-engine"
echo ""
echo "=================================================="
