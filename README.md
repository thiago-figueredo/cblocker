# cblocker

A transparent TLS proxy that blocks HTTPS connections to a configurable blocklist, running as a hardened system daemon.

## How it works

```
Browser → nftables (port 443 → 8443) → cblocker → destination server
```

1. **nftables** redirects all outbound TCP port 443 traffic to port 8443 locally.
2. **cblocker** receives the connection and checks the original destination IP via `SO_ORIGINAL_DST` — this catches sites using **ECH (Encrypted Client Hello)** where the real hostname is encrypted.
3. If not IP-blocked, cblocker reads the TLS `ClientHello` and extracts the **SNI** (Server Name Indication).
4. The SNI is checked against domains, wildcards (`*xvideos*`), and subdomain rules.
5. Blocked connections are dropped immediately. Allowed ones are relayed transparently to the real destination.

### Why IP blocking matters

Sites behind Cloudflare with ECH enabled encrypt the real SNI. The outer `ClientHello` shows `cloudflare-ech.com` instead of the actual hostname, making SNI-based blocking ineffective. Checking the destination IP before reading any TLS data bypasses this.

## Blocklist

The blocklist lives in `src/blocklist.rs` as compiled-in static arrays — no config file is read at runtime.

```
src/blocklist.rs
├── DOMAINS   — exact hostnames (subdomain matching included)
├── IPS       — IPv4/IPv6 addresses (for ECH-protected sites)
└── WILDCARDS — glob patterns like *xvideos*, *porn*
```

To add a new site:

1. Add the domain to `DOMAINS` in `src/blocklist.rs`.
2. If the site uses ECH (Cloudflare), resolve its IPs and add them to `IPS`:
   ```bash
   host example.com
   ```
3. Run `sudo bash scripts/update.sh` to rebuild and hot-swap the binary.

## Installation

Requires: Rust toolchain, `nftables`, Linux (uses `SO_ORIGINAL_DST`).

```bash
sudo bash scripts/install.sh
```

This will:

- Build the release binary
- Create a `pornblock` system user (no shell, no login)
- Install the binary to `/usr/local/bin/cblocker` and lock it with `chattr +i`
- Install and enable the systemd service, also locked with `chattr +i`
- Set up and persist nftables rules
- Start the daemon

## Updating the blocklist

After editing `src/blocklist.rs`:

```bash
sudo bash scripts/update.sh
```

This rebuilds and hot-swaps the binary without touching nftables or the service file.

## Service management

```bash
# View live logs
journalctl -u cblocker -f

# Status
systemctl status cblocker

# Manual restart (e.g. after update.sh)
sudo systemctl restart cblocker
```

## Tamper resistance

| Protection | Mechanism |
|---|---|
| Auto-restart on crash or kill | `Restart=always`, `RestartSec=1` in systemd |
| Binary cannot be deleted or overwritten | `chattr +i /usr/local/bin/cblocker` |
| Service file cannot be modified | `chattr +i /etc/systemd/system/cblocker.service` |
| nftables rules survive reboot | `/etc/nftables.conf` + `systemctl enable nftables` |
| QUIC/HTTP3 blocked | `nft drop udp dport 443` (forces browsers to use TCP) |
| Daemon excluded from redirect | `meta skuid pornblock return` (prevents loop) |

> Root can always undo `chattr -i` — there is no protection against a determined root user. The goal is resistance against non-root bypass.

## Architecture

```
src/
├── main.rs       — TCP listener, connection handler, SNI parser, relay
└── blocklist.rs  — Blocklist struct, domain/IP/wildcard matching, glob engine

scripts/
├── install.sh    — First-time setup (build, install, harden, start)
└── update.sh     — Rebuild and hot-swap binary after source changes

cblocker.service  — systemd unit file
```

## Dependencies

- [`tokio`](https://tokio.rs) — async runtime
- [`libc`](https://crates.io/crates/libc) — `getsockopt` for `SO_ORIGINAL_DST`
