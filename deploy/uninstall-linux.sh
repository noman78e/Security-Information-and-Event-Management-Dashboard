#!/bin/sh
# Removes the HomeSIEM service. Your data in /var/lib/homesiem is kept unless you add --purge.
#   sudo ./uninstall-linux.sh
#   sudo ./uninstall-linux.sh --purge
set -e
if [ "$(id -u)" != "0" ]; then
  echo "Please run this with sudo."; exit 1
fi
systemctl disable --now homesiem 2>/dev/null || true
rm -f /etc/systemd/system/homesiem.service /usr/local/bin/homesiem
systemctl daemon-reload
# remove the firewall rules HomeSIEM may have added, so nobody stays blocked
command -v nft >/dev/null 2>&1 && nft delete table inet homesiem 2>/dev/null || true
if [ "$1" = "--purge" ]; then
  rm -rf /var/lib/homesiem
  userdel homesiem 2>/dev/null || true
  echo "HomeSIEM and all its data were removed."
else
  echo "HomeSIEM was removed. Your data is still in /var/lib/homesiem (add --purge to delete it)."
fi
