# 06 · Fingerprint Blocker

Analyse browser fingerprinting vectors and deploy countermeasures: canvas noise injection, WebGL spoofing, WebRTC blocking, and more.

## Tools

| File | Description |
|------|-------------|
| `fingerprint.py` | Analyze fingerprinting risks, generate spoofed profiles, export browser extension |

## Quick Start

```bash
# Analyse fingerprinting vectors
python fingerprint.py analyze

# Generate a spoofed User-Agent
python fingerprint.py generate-ua --os windows --browser firefox
python fingerprint.py generate-ua --os macos --browser safari

# List available fingerprint profiles
python fingerprint.py list-profiles

# Generate a complete spoofed profile (JSON)
python fingerprint.py generate-profile --preset tor-browser-like
python fingerprint.py generate-profile --preset average-windows-user

# Export ready-to-load browser extension (Chrome/Firefox)
python fingerprint.py export-extension --out ./fp-blocker-extension
```

## Browser Extension

The exported extension (`export-extension`) can be loaded directly into Chrome or Firefox:

**Chrome/Chromium/Brave:**
1. Go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `fp-blocker-extension` folder

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` inside the folder

The extension blocks/spoofs:
- 🎨 Canvas fingerprinting (pixel noise injection)
- 🖥 WebGL vendor/renderer strings
- 📐 Screen resolution (reports 1920×1080)
- 📡 WebRTC IP leaks (disables ICE candidates)
- 🔋 Battery API (always full/charging)
- 🔊 AudioContext fingerprinting (noise injection)
- 💻 Hardware concurrency (reports 4 cores)
- 🔌 Plugins list (standardised)

## Firefox `about:config` Privacy Settings

```
privacy.resistFingerprinting = true
privacy.firstparty.isolate = true
geo.enabled = false
media.peerconnection.enabled = false   ← WebRTC disable
dom.battery.enabled = false
canvas.poisondata = true
```

## Recommended Extensions

| Extension | Function |
|-----------|----------|
| uBlock Origin | Ad + tracker blocking |
| Canvas Blocker | Canvas fingerprint noise |
| Privacy Badger | Tracker learning |
| ClearURLs | Strip tracking params from URLs |
| LocalCDN | Serve CDN libraries locally |
| Decentraleyes | Same as LocalCDN (legacy) |

## Online Fingerprint Test Sites

- https://browserleaks.com
- https://coveryourtracks.eff.org
- https://fingerprint.com/demo
- https://amiunique.org
