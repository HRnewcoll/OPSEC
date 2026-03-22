# 09 · OSINT Tools

Passive and active intelligence gathering: email recon, username enumeration across 25+ platforms, IP geolocation, DNS enumeration, WHOIS, subdomain discovery.

## Quick Start

```bash
# Email OSINT (MX records, Gravatar, breach-check links)
python osint.py email --address target@example.com

# Username search across 25+ platforms
python osint.py username --name johndoe
python osint.py username --name johndoe --output results.json

# IP geolocation + ASN + Shodan internetdb
python osint.py ip --address 8.8.8.8
python osint.py ip --address 203.0.113.50

# WHOIS domain lookup
python osint.py whois --domain example.com

# DNS records
python osint.py dns --domain example.com --type ALL
python osint.py dns --domain example.com --type SUBDOMAINS
python osint.py dns --domain example.com --type MX

# Full OSINT report (DNS + WHOIS + subdomains)
python osint.py report --target example.com --out report.json
```

## Platforms Checked (Username)

GitHub, GitLab, Twitter/X, Instagram, Reddit, LinkedIn, TikTok, YouTube, Pinterest, Twitch, Steam, Keybase, Mastodon, Telegram, Pastebin, HackerNews, Medium, Dev.to, StackOverflow, Gravatar, DockerHub, NPM, PyPI, Replit, Codepen

## Data Sources

| Module | Source |
|--------|--------|
| IP Geo | ip-api.com (free, no key) |
| IP Info | Shodan internetdb (free, no key) |
| DNS | `dig` / `socket.getaddrinfo` |
| WHOIS | `whois` CLI / RDAP (rdap.org) |
| Email Breaches | Links to HIBP, BreachDirectory, LeakCheck |

## OPSEC Warning

- Username searches **make real HTTP requests** to each platform
- Platforms may log your IP searching for a username
- Run through Tor or a VPN when doing sensitive research: `python tor_setup.py test`
- Use `--output` to save results without repeated searches

## Recommended External Tools

| Tool | Use Case |
|------|----------|
| `theHarvester` | Email, domain, host OSINT |
| `Maltego` | Visual link analysis |
| `Sherlock` | Username OSINT |
| `Recon-ng` | Full-featured OSINT framework |
| `SpiderFoot` | Automated threat intelligence |
| `OSINT Framework` | https://osintframework.com |
| `Google Dorks` | Advanced search operators |

## Example Google Dorks

```
site:example.com filetype:pdf
site:linkedin.com/in/ "example.com"
inurl:admin site:example.com
"@example.com" filetype:xls
intitle:"index of" site:example.com
```
