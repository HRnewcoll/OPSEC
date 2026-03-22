# 01 · Proxy / VPN Tools

Manage WireGuard VPN configs, proxy chains, and Tor routing — all from the command line or the included web UI.

## Tools

| File | Description |
|------|-------------|
| `wireguard_gen.py` | Generate WireGuard server + client configs with X25519 key pairs |
| `proxy_chain.py` | Add, test, and export SOCKS5/HTTP proxy chains |
| `tor_setup.py` | Generate torrc, test Tor connectivity, renew circuits |
| `index.html` | Browser-based UI for all three tools (no backend needed) |

## Quick Start

```bash
pip install -r requirements.txt

# Generate WireGuard configs (1 server + 3 clients)
python wireguard_gen.py generate --clients 3 --endpoint vpn.example.com --psk

# Manage proxies
python proxy_chain.py add --host 127.0.0.1 --port 9050 --type socks5 --label "Tor"
python proxy_chain.py add --host proxy.example.com --port 8080 --type http
python proxy_chain.py test
python proxy_chain.py list
python proxy_chain.py export --format proxychains --output /etc/proxychains4.conf

# Tor setup
python tor_setup.py generate --control-password "StrongPass123" --output /etc/tor/torrc
sudo tor -f /etc/tor/torrc
python tor_setup.py test
python tor_setup.py newcircuit --password "StrongPass123"

# Open the web UI
open index.html
```

## WireGuard Setup (Server)

```bash
# Install WireGuard
sudo apt install wireguard

# Generate configs
python wireguard_gen.py generate --clients 5 --endpoint your.server.ip --port 51820 --psk --output ./configs

# Copy server config
sudo cp ./configs/wg0-server.conf /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Start WireGuard
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

## Proxy Chain Types

- **strict_chain** — proxies used in order; fails if any proxy is down
- **dynamic_chain** — skips dead proxies automatically
- **random_chain** — randomises order for better anonymity

## Security Notes

- Pre-shared keys (PSK) add a post-quantum-resistant layer to WireGuard
- Always use `AllowedIPs = 0.0.0.0/0` to route all traffic through VPN
- Combine Tor + WireGuard for layered anonymity
- Never reuse WireGuard private keys
