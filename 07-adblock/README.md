# 07 · Adblock & DNS Sinkhole

Aggregate blocklists from multiple sources and generate `/etc/hosts`, Pi-hole, dnsmasq, and unbound configurations.

## Quick Start

```bash
# Download all enabled blocklists (~2M+ domains)
python adblock.py update

# Build /etc/hosts file
python adblock.py build --format hosts --output /tmp/hosts_blocked
sudo cp /tmp/hosts_blocked /etc/hosts

# Flush DNS cache
sudo resolvectl flush-caches    # Linux systemd-resolved
sudo dscacheutil -flushcache    # macOS
ipconfig /flushdns              # Windows

# Build Pi-hole gravity list
python adblock.py build --format pihole --output pihole_list.txt

# Build dnsmasq config
python adblock.py build --format dnsmasq --output /etc/dnsmasq.d/blocked.conf

# Build unbound config
python adblock.py build --format unbound --output /etc/unbound/blocked.conf

# View stats
python adblock.py stats

# Whitelist management
python adblock.py whitelist --add google.com
python adblock.py whitelist --remove google.com
python adblock.py whitelist --list

# Check if a domain is blocked
python adblock.py check --domain ads.doubleclick.net
```

## Built-in Sources

| Source | Category |
|--------|----------|
| StevenBlack Unified | Ads + Trackers |
| AdAway | Ads |
| OISD Basic | Ads + Trackers |
| URLHaus Malware | Malware |
| Windows Telemetry Blocker | Telemetry |
| Phishing Army | Phishing |

## Pi-hole Setup

```bash
# Install Pi-hole
curl -sSL https://install.pi-hole.net | bash

# Add custom blocklist
python adblock.py build --format pihole --output /etc/pihole/custom_list.domains
pihole -g  # reload gravity

# Or add URL as AdList in Pi-hole admin
```

## dnsmasq (Router / OpenWrt)

```bash
python adblock.py build --format dnsmasq --output /etc/dnsmasq.d/opsec_blocked.conf
service dnsmasq restart
```

## Unbound (Self-hosted resolver)

```bash
python adblock.py build --format unbound --output /etc/unbound/conf.d/blocked.conf
unbound-control reload
```

## Additional Resources

- https://github.com/StevenBlack/hosts — Curated unified hosts
- https://oisd.nl — OISD blocklist
- https://firebog.net — Blocklist collection
- https://pi-hole.net — Network-level ad blocking
