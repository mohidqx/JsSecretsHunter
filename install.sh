#!/usr/bin/env bash
# JSSecretHunter install script — Linux / WSL / Kali
set -e

echo "╔══════════════════════════════════════╗"
echo "║   JSSecretHunter — Install Script   ║"
echo "╚══════════════════════════════════════╝"

# Install tkinter
if command -v apt-get &>/dev/null; then
    echo "[*] Installing python3-tk..."
    sudo apt-get install -y python3-tk
elif command -v dnf &>/dev/null; then
    sudo dnf install -y python3-tkinter
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm tk
fi

# Optional pip packages
echo "[*] Installing optional packages..."
pip3 install --break-system-packages Pillow PySocks brotli 2>/dev/null || \
pip3 install Pillow PySocks brotli 2>/dev/null || true

# WSL2 DISPLAY setup
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo ""
    echo "[WSL2 Detected]"
    DISP_LINE='export DISPLAY=$(ip route show default 2>/dev/null | awk '"'"'{print $3}'"'"' | head -1):0.0'
    if ! grep -q "ip route show default" ~/.bashrc 2>/dev/null; then
        echo "$DISP_LINE" >> ~/.bashrc
        echo "[*] DISPLAY auto-detect added to ~/.bashrc"
        echo "[!] Run: source ~/.bashrc"
    fi
    echo "[!] Ensure VcXsrv or X410 is running on Windows (Display=0, Disable access control)"
fi

echo ""
echo "[✓] Installation complete!"
echo "    Run: python3 jssecrethunter_gui.py"
