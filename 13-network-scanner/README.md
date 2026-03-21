# 13 — Network Scanner

Port scanner, service fingerprinter, OS detection, and network topology mapper.

## Features
- **TCP connect scan** — reliable across all platforms (no raw sockets needed)
- **Top-100 port list** — most common vulnerable ports pre-loaded
- **Service name mapping** — 80+ known port-to-service mappings
- **Banner grabbing** — reads service banners for version detection
- **HTTP fingerprinting** — grabs `Server` and `X-Powered-By` headers
- **Vulnerability hints** — flags known CVEs based on banner strings
- **Ping sweep** — ICMP host discovery across /24 or larger subnets
- **OS hints** — TTL-based OS detection (Linux ≤64, Windows ≤128, Cisco ≤255)
- **Concurrent scanning** — configurable thread pool (default 100 threads)
- **Export** — JSON or CSV output for all results
- **No external dependencies** — pure stdlib Python

## Usage

```bash
# Scan top 100 ports on a single host
python network_scanner.py scan --target 192.168.1.1

# Scan a CIDR range
python network_scanner.py scan --target 192.168.1.0/24 --ports top100

# Scan specific ports
python network_scanner.py scan --target 10.0.0.1 --ports 22,80,443,8080,3306

# Scan port range
python network_scanner.py scan --target 10.0.0.1 --ports 1-1024

# Ping sweep (host discovery)
python network_scanner.py ping --network 192.168.1.0/24

# Banner grab a single service
python network_scanner.py banner --target 192.168.1.1 --port 22

# Full scan: ping sweep + port scan + export
python network_scanner.py full --target 192.168.1.0/24 --out scan.json

# Export as CSV
python network_scanner.py scan --target 192.168.1.0/24 --out results.csv --format csv
```

## Port Specs
| Spec | Ports |
|------|-------|
| `top100` | 100 most common ports (default) |
| `common` | 1–1024 |
| `all` | 1–65535 |
| `22,80,443` | Specific ports |
| `1-8080` | Range |

## Vulnerability Hints
The scanner flags banners matching known vulnerable versions:
- Apache 2.4.49/50 (path traversal)
- vsftpd 2.3.4 (backdoor)
- OpenSSH user enumeration
- Redis/Memcached with no auth
- MongoDB/Elasticsearch with no auth
- Docker daemon exposure
- WebLogic, Jenkins, Tomcat CVEs
