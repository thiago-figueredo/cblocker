#!/usr/bin/env bash

set -e

DAEMON_USER="pornblock"
DAEMON_PORT="8443"
BINARY_DST="/usr/local/bin/cblocker"
NFT_DST="/usr/local/bin/cblocker-nft"
NFT_SRC="$(cd "$(dirname "$0")" && pwd)/setup-nftables.sh"
SERVICE_DST="/etc/systemd/system/cblocker.service"
SERVICE_SRC="$(cd "$(dirname "$0")/.." && pwd)/cblocker.service"

# ── 0. Clear nftables so cargo can reach crates.io ───────────────────────────
# Any rules from a previous install would redirect port 443 and break the build.
echo "[+] Clearing existing nftables rules..."
sudo nft delete table inet pornblock 2>/dev/null || true

# ── 1. Build ──────────────────────────────────────────────────────────────────
echo "[+] Building release binary..."
cargo build --release --manifest-path "$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"

# ── 2. Daemon user ────────────────────────────────────────────────────────────
echo "[+] Creating daemon user '$DAEMON_USER'..."
if ! id "$DAEMON_USER" &>/dev/null; then
    sudo useradd -r -s /usr/sbin/nologin "$DAEMON_USER"
fi

# ── 3. Install binary ─────────────────────────────────────────────────────────
echo "[+] Installing binary to $BINARY_DST..."
# Remove immutable flag if set (needed for update)
sudo chattr -i "$BINARY_DST" 2>/dev/null || true
sudo install -o root -g root -m 755 \
    "$(cd "$(dirname "$0")/.." && pwd)/target/release/cblocker" \
    "$BINARY_DST"
echo "[+] Locking binary (immutable)..."
sudo chattr +i "$BINARY_DST"

# ── 4. Install nftables setup script ─────────────────────────────────────────
echo "[+] Installing nftables setup script to $NFT_DST..."
sudo chattr -i "$NFT_DST" 2>/dev/null || true
sudo install -o root -g root -m 755 "$NFT_SRC" "$NFT_DST"
echo "[+] Locking nftables script (immutable)..."
sudo chattr +i "$NFT_DST"

# ── 5. Install systemd service ────────────────────────────────────────────────
echo "[+] Installing systemd service..."
sudo chattr -i "$SERVICE_DST" 2>/dev/null || true
sudo cp "$SERVICE_SRC" "$SERVICE_DST"
sudo chmod 644 "$SERVICE_DST"
echo "[+] Locking service file (immutable)..."
sudo chattr +i "$SERVICE_DST"

sudo systemctl daemon-reload
sudo systemctl enable cblocker

# ── 6. Start service ──────────────────────────────────────────────────────────
# systemd will call cblocker-nft (ExecStartPre) which sets up nftables first.
echo "[+] Starting cblocker service..."
sudo systemctl restart cblocker

sleep 1
sudo systemctl status cblocker --no-pager

echo
echo "[+] Done. cblocker is running as a protected daemon."
echo "    Binary and service file are immutable (chattr +i)."
echo "    Logs: journalctl -u cblocker -f"
