#!/usr/bin/env bash

set -e

DAEMON_USER="pornblock"
DAEMON_PORT="8443"

echo "[+] Creating daemon user..."

if ! id "$DAEMON_USER" &>/dev/null; then
    sudo useradd -r -s /usr/sbin/nologin "$DAEMON_USER"
fi

echo "[+] Building Rust daemon..."
cargo build --release

echo "[+] Installing daemon binary..."
sudo install -o root -g root -m 755 "$(pwd)/target/release/cblocker" /usr/local/bin/cblocker

echo "[+] Cleaning old nftables table if exists..."
sudo nft delete table inet pornblock 2>/dev/null || true

echo "[+] Creating nftables table..."
sudo nft add table inet pornblock

echo "[+] Creating output chain..."
sudo nft 'add chain inet pornblock output { type nat hook output priority 0; }'

echo "[+] Excluding daemon user from redirect..."
sudo nft add rule inet pornblock output \
    meta skuid "$DAEMON_USER" return

echo "[+] Blocking QUIC / HTTP3 (UDP 443)..."
sudo nft add rule inet pornblock output \
    udp dport 443 drop

echo "[+] Redirecting HTTPS traffic to daemon..."
sudo nft add rule inet pornblock output \
    tcp dport 443 redirect to :"$DAEMON_PORT"

echo "[+] Current nftables rules:"
sudo nft list ruleset

echo
echo "[+] Starting daemon..."
echo

sudo runuser -u "$DAEMON_USER" -- /usr/local/bin/cblocker