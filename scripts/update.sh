#!/usr/bin/env bash

# Update the binary without touching nftables or the service file.
# Use this after changing blocklist.rs or any Rust source.

set -e

BINARY_DST="/usr/local/bin/cblocker"

echo "[+] Building release binary..."
cargo build --release --manifest-path "$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"

echo "[+] Unlocking binary..."
sudo chattr -i "$BINARY_DST"

echo "[+] Installing new binary..."
sudo install -o root -g root -m 755 \
    "$(cd "$(dirname "$0")/.." && pwd)/target/release/cblocker" \
    "$BINARY_DST"

echo "[+] Re-locking binary..."
sudo chattr +i "$BINARY_DST"

echo "[+] Restarting service..."
sudo systemctl restart cblocker

sleep 1
sudo systemctl status cblocker --no-pager
