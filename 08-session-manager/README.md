# 08 · Session Manager

Create and manage isolated browser profiles to prevent cross-site tracking, session linking, and cookie sharing.

## Quick Start

```bash
# List all managed sessions
python session_manager.py list

# Create isolated sessions for different identities
python session_manager.py create --name personal --browser firefox
python session_manager.py create --name work --browser chromium
python session_manager.py create --name shopping --browser brave
python session_manager.py create --name research --browser firefox

# Launch a session
python session_manager.py launch --name research
python session_manager.py launch --name work --url https://example.com

# Export session (backup with all cookies/history)
python session_manager.py export --name research --out research_backup.zip

# Import session on another machine
python session_manager.py import --name research --file research_backup.zip

# Delete session and wipe all data
python session_manager.py delete --name research

# Cookie management
python session_manager.py cookies --browser firefox --action list
python session_manager.py cookies --browser firefox --action clear
python session_manager.py cookies --browser chrome --action clear

# Nuclear option — wipe ALL session data
python session_manager.py nuke
```

## Session Isolation Strategy

Each identity should have:
- Separate browser profile (this tool)
- Different browser if possible (Firefox, Chromium, Brave)
- Different VPN/proxy (see `01-proxy-vpn`)
- Unique MAC address per identity (see `05-mac-spoofer`)

| Identity | Browser | VPN | MAC |
|----------|---------|-----|-----|
| Personal | Firefox | None | Real |
| Work | Chromium | Corporate VPN | Real |
| Research | Firefox | Tor | Spoofed |
| Shopping | Brave | VPN A | Spoofed |

## Hardened Firefox Profile Settings

After launching a fresh session, go to `about:config`:

```
privacy.resistFingerprinting = true
privacy.firstparty.isolate = true
network.cookie.cookieBehavior = 2  (block third-party)
geo.enabled = false
media.peerconnection.enabled = false
dom.battery.enabled = false
browser.send_pings = false
network.http.sendRefererHeader = 0
```

## Recommended Approach with Tor

```bash
# Create a "tor" session
python session_manager.py create --name tor-research --browser firefox

# Start Tor
sudo systemctl start tor

# Launch Firefox pointing to Tor SOCKS5
BROWSER_CMD="firefox --profile ~/.opsec/sessions/firefox_tor-research --proxy-server socks5://127.0.0.1:9050"
```

Or just use the **Tor Browser Bundle** which comes pre-configured.
