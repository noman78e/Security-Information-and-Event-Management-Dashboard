#!/bin/sh
# Installs HomeSIEM as a service that starts at boot.
# Run it with sudo, from the folder that contains homesiem.service:
#   sudo ./install-linux.sh ./homesiem-linux
# (use ./homesiem-pi-arm64 on a 64-bit Raspberry Pi, and so on)
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Please run this with sudo."; exit 1
fi
BIN="${1:-./homesiem-linux}"
if [ ! -f "$BIN" ]; then
  echo "Cannot find the program file: $BIN"
  echo "Usage: sudo ./install-linux.sh ./homesiem-linux"; exit 1
fi
HERE="$(cd "$(dirname "$0")" && pwd)"

id homesiem >/dev/null 2>&1 || useradd --system --home-dir /var/lib/homesiem --shell /usr/sbin/nologin homesiem
install -d -o homesiem -g homesiem -m 750 /var/lib/homesiem
install -m 755 "$BIN" /usr/local/bin/homesiem
install -m 644 "$HERE/homesiem.service" /etc/systemd/system/homesiem.service

# Blocking devices needs the nft program; install it if apt is available.
if ! command -v nft >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
  apt-get install -y nftables || echo "Could not install nftables: blocking will stay in dry-run mode."
fi

systemctl daemon-reload
systemctl enable --now homesiem
sleep 2

echo
echo "HomeSIEM is installed and running."
echo
echo "  1. Find your first-start setup code:"
echo "       sudo cat /var/lib/homesiem/setup-code.txt"
echo "  2. Open  https://THIS-COMPUTER:8080  in a browser."
echo "     The browser warns about the certificate the first time (it is self-signed)."
echo "     Compare the fingerprint with:  sudo journalctl -u homesiem | grep fingerprint"
echo "  3. Enter the setup code and choose your password."
echo
echo "Useful commands:"
echo "  sudo systemctl status homesiem        is it running?"
echo "  sudo journalctl -u homesiem -f        live log"
echo "  sudo systemctl restart homesiem       restart"
echo "  sudo -u homesiem homesiem passwd -db /var/lib/homesiem/homesiem.db   set a new dashboard password"
echo "  sudo homesiem unblock -db /var/lib/homesiem/homesiem.db              remove every block (emergency)"
