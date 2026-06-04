#!/usr/bin/env bash
# Called by systemd ExecStartPre on every service start/restart.
set -e

nft delete table inet pornblock 2>/dev/null || true
nft add table inet pornblock
nft 'add chain inet pornblock output { type nat hook output priority 0; }'
# Exclude the daemon's own traffic to prevent a redirect loop
nft add rule inet pornblock output meta skuid pornblock return
# Block QUIC/HTTP3 so browsers can't bypass the proxy via UDP
nft add rule inet pornblock output udp dport 443 drop
# Redirect all outbound HTTPS to the proxy
nft add rule inet pornblock output tcp dport 443 redirect to :8443
