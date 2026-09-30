#!/bin/bash
# AUTO-GENERATED STIA HARDENING SCRIPT
# Target: sat-03.smart.com

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "[+] Updating packages and installing persistence tools..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --only-upgrade squid bind9 openssh-server
apt-get install -y iptables-persistent netfilter-persistent

echo "[+] Securing SSH..."
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config

echo "[+] Applying firewall rules on port 2000..."
iptables -F
iptables -A INPUT -p tcp --dport 2000 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 2000 -m state --state NEW -m recent --update --seconds 1 --hitcount 10 -j DROP

echo "[+] Persisting firewall rules..."
netfilter-persistent save
iptables-save > /etc/iptables/rules.v4

echo "[+] Restarting services..."
systemctl restart sshd squid bind9
systemctl enable sshd squid bind9

echo "[+] Deployment complete. Hotfixes are now permanently applied."