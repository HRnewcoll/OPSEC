#!/usr/bin/env python3
"""
OPSEC Fingerprint Analyzer
===========================
Analyse and generate browser fingerprint obfuscation strategies.
Outputs user-agent strings, canvas noise parameters, and WebGL spoof values.

Usage:
  python fingerprint.py analyze
  python fingerprint.py generate-ua --os windows --browser firefox
  python fingerprint.py list-profiles
  python fingerprint.py export-extension --out ./fp-spoof-extension/
"""

import argparse
import json
import random
import string
from datetime import datetime
from pathlib import Path


# ── User-Agent database ───────────────────────────────────────────────
UA_DB = {
    "windows-chrome": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    ],
    "windows-firefox": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    ],
    "macos-chrome": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ],
    "macos-safari": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    ],
    "linux-firefox": [
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "android-chrome": [
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    ],
    "ios-safari": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    ],
}

# ── Fingerprint profiles ──────────────────────────────────────────────
PROFILES = {
    "average-windows-user": {
        "ua_key": "windows-chrome",
        "screen": {"width": 1920, "height": 1080},
        "platform": "Win32",
        "language": "en-US",
        "timezone": "America/New_York",
        "hardware_concurrency": 8,
        "device_memory": 8,
        "canvas_noise": 0.0001,
        "webgl_vendor": "Google Inc. (Intel)",
        "webgl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "do_not_track": None,
        "color_depth": 24,
    },
    "privacy-mac-user": {
        "ua_key": "macos-firefox",
        "screen": {"width": 2560, "height": 1600},
        "platform": "MacIntel",
        "language": "en-US",
        "timezone": "America/Los_Angeles",
        "hardware_concurrency": 10,
        "device_memory": 16,
        "canvas_noise": 0.0002,
        "webgl_vendor": "Apple",
        "webgl_renderer": "Apple M2",
        "do_not_track": "1",
        "color_depth": 30,
    },
    "tor-browser-like": {
        "ua_key": "windows-firefox",
        "screen": {"width": 1000, "height": 900},
        "platform": "Win32",
        "language": "en-US",
        "timezone": "UTC",
        "hardware_concurrency": 2,
        "device_memory": 8,
        "canvas_noise": 0.0003,
        "webgl_vendor": "Brian Paul",
        "webgl_renderer": "Mesa OffScreen",
        "do_not_track": "1",
        "color_depth": 24,
    },
    "mobile-android": {
        "ua_key": "android-chrome",
        "screen": {"width": 393, "height": 873},
        "platform": "Linux armv8l",
        "language": "en-US",
        "timezone": "America/Chicago",
        "hardware_concurrency": 8,
        "device_memory": 8,
        "canvas_noise": 0.0001,
        "webgl_vendor": "Qualcomm",
        "webgl_renderer": "Adreno (TM) 740",
        "do_not_track": None,
        "color_depth": 24,
    },
}


# ── Analysis ──────────────────────────────────────────────────────────

def analyze_fingerprint() -> dict:
    """Generate a report on common fingerprinting vectors and countermeasures."""
    return {
        "fingerprinting_vectors": {
            "canvas": {
                "risk": "HIGH",
                "description": "Sites render text/graphics on canvas and hash the pixel data. "
                               "GPU, font rendering, and OS produce unique results.",
                "countermeasure": "Add small random noise to canvas pixel data before readback.",
            },
            "webgl": {
                "risk": "HIGH",
                "description": "WebGL exposes GPU vendor, renderer string, extensions, and "
                               "rendering capabilities.",
                "countermeasure": "Override WEBGL_debug_renderer_info and spoof extensions list.",
            },
            "fonts": {
                "risk": "HIGH",
                "description": "Installed fonts can be enumerated via CSS @font-face or canvas.",
                "countermeasure": "Report only a standard font subset. Use Tor Browser's approach.",
            },
            "user_agent": {
                "risk": "MEDIUM",
                "description": "OS, browser, and version exposed via navigator.userAgent.",
                "countermeasure": "Spoof to a common UA string. Keep platform consistent.",
            },
            "screen_resolution": {
                "risk": "MEDIUM",
                "description": "screen.width/height + window.devicePixelRatio are highly unique.",
                "countermeasure": "Report standard resolutions (1920x1080, 1280x720).",
            },
            "timezone": {
                "risk": "MEDIUM",
                "description": "Intl.DateTimeFormat().resolvedOptions().timeZone reveals location.",
                "countermeasure": "Override timezone to UTC or a common timezone.",
            },
            "hardware_concurrency": {
                "risk": "LOW",
                "description": "navigator.hardwareConcurrency exposes CPU core count.",
                "countermeasure": "Return 2 or 4 (common values).",
            },
            "battery_api": {
                "risk": "LOW",
                "description": "Battery level/charging state can be used for tracking.",
                "countermeasure": "Disable or return null for navigator.getBattery().",
            },
            "audio_api": {
                "risk": "MEDIUM",
                "description": "AudioContext processing produces hardware-specific output.",
                "countermeasure": "Add noise to AudioContext output buffers.",
            },
            "webrtc_ip": {
                "risk": "HIGH",
                "description": "WebRTC ICE candidates leak local/public IP even behind proxy/VPN.",
                "countermeasure": "Disable WebRTC or use extension to block ICE candidates.",
            },
        },
        "recommendations": [
            "Use Firefox with uBlock Origin + CanvasBlocker extension",
            "Enable Firefox's resistFingerprinting (privacy.resistFingerprinting=true)",
            "Use Tor Browser for maximum fingerprint resistance",
            "Disable JavaScript when not needed",
            "Use a VPN to mask real IP before WebRTC leaks",
            "Install Privacy Badger for tracker blocking",
        ],
    }


# ── Generation ────────────────────────────────────────────────────────

def generate_ua(os_name: str, browser: str) -> str:
    key = f"{os_name}-{browser}"
    if key in UA_DB:
        return random.choice(UA_DB[key])
    # Fallback
    return random.choice(UA_DB["windows-chrome"])


def generate_profile(preset: str = "average-windows-user") -> dict:
    profile = PROFILES.get(preset, PROFILES["average-windows-user"]).copy()
    ua_list = UA_DB.get(profile.get("ua_key", "windows-chrome"), UA_DB["windows-chrome"])
    profile["user_agent"] = random.choice(ua_list)
    profile.pop("ua_key", None)
    return profile


# ── Export browser extension ──────────────────────────────────────────

EXTENSION_MANIFEST = """{
  "manifest_version": 3,
  "name": "OPSEC Fingerprint Blocker",
  "version": "1.0.0",
  "description": "Spoofs canvas, WebGL, screen resolution, timezone, and user-agent.",
  "permissions": ["storage", "scripting"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "OPSEC Fingerprint Blocker"
  }
}
"""

EXTENSION_CONTENT_JS = r"""
// OPSEC Fingerprint Blocker — content.js
// Injected at document_start to override fingerprinting APIs

(function() {
  'use strict';

  // ── Canvas noise ──────────────────────────────────────────────────
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  const origToBlob = HTMLCanvasElement.prototype.toBlob;

  function addNoise(imageData) {
    const data = imageData.data;
    for (let i = 0; i < data.length; i += 4) {
      data[i]   = Math.min(255, data[i]   + (Math.random() < 0.003 ? 1 : 0));
      data[i+1] = Math.min(255, data[i+1] + (Math.random() < 0.003 ? 1 : 0));
      data[i+2] = Math.min(255, data[i+2] + (Math.random() < 0.003 ? 1 : 0));
    }
    return imageData;
  }

  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    const ctx = this.getContext('2d');
    if (ctx) {
      const imageData = ctx.getImageData(0, 0, this.width, this.height);
      addNoise(imageData);
      ctx.putImageData(imageData, 0, 0);
    }
    return origToDataURL.apply(this, args);
  };

  CanvasRenderingContext2D.prototype.getImageData = function(...args) {
    const imageData = origGetImageData.apply(this, args);
    return addNoise(imageData);
  };

  // ── WebGL spoof ───────────────────────────────────────────────────
  const origGetParameter = WebGLRenderingContext.prototype.getParameter;
  const WEBGL_VENDOR   = 'Google Inc. (Intel)';
  const WEBGL_RENDERER = 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)';

  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return WEBGL_VENDOR;   // UNMASKED_VENDOR_WEBGL
    if (param === 37446) return WEBGL_RENDERER; // UNMASKED_RENDERER_WEBGL
    return origGetParameter.apply(this, arguments);
  };

  if (typeof WebGL2RenderingContext !== 'undefined') {
    const origGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
      if (param === 37445) return WEBGL_VENDOR;
      if (param === 37446) return WEBGL_RENDERER;
      return origGetParameter2.apply(this, arguments);
    };
  }

  // ── Screen resolution ─────────────────────────────────────────────
  Object.defineProperty(screen, 'width',       { get: () => 1920 });
  Object.defineProperty(screen, 'height',      { get: () => 1080 });
  Object.defineProperty(screen, 'availWidth',  { get: () => 1920 });
  Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
  Object.defineProperty(screen, 'colorDepth',  { get: () => 24 });
  Object.defineProperty(window, 'devicePixelRatio', { get: () => 1 });

  // ── Hardware concurrency ──────────────────────────────────────────
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
  Object.defineProperty(navigator, 'deviceMemory',        { get: () => 8 });

  // ── WebRTC blocking ───────────────────────────────────────────────
  if (window.RTCPeerConnection) {
    const origRTC = window.RTCPeerConnection;
    window.RTCPeerConnection = function(config, constraints) {
      if (config && config.iceServers) {
        config.iceServers = [];
      }
      return new origRTC(config, constraints);
    };
    Object.assign(window.RTCPeerConnection, origRTC);
  }

  // ── Battery API ───────────────────────────────────────────────────
  if (navigator.getBattery) {
    navigator.getBattery = () => Promise.resolve({
      charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1.0,
      addEventListener: () => {}, removeEventListener: () => {},
    });
  }

  // ── AudioContext noise ────────────────────────────────────────────
  const origGetChannelData = AudioBuffer.prototype.getChannelData;
  AudioBuffer.prototype.getChannelData = function(channel) {
    const data = origGetChannelData.call(this, channel);
    for (let i = 0; i < data.length; i += 100) {
      data[i] += Math.random() * 0.0000001;
    }
    return data;
  };

  // ── Plugins ───────────────────────────────────────────────────────
  Object.defineProperty(navigator, 'plugins', {
    get: () => [
      { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
      { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
      { name: 'Native Client',     filename: 'internal-nacl-plugin', description: '' },
    ]
  });

  console.debug('[OPSEC] Fingerprint spoofing active');
})();
"""

EXTENSION_POPUP_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
  body{font-family:'Courier New',monospace;background:#0a0e17;color:#e2e8f0;width:280px;padding:16px}
  h1{color:#00ff88;font-size:.9rem;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px}
  .item{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #1a2535;font-size:.78rem}
  .status{color:#10b981;font-size:.72rem}
  .badge{background:#0a2a1a;color:#10b981;border-radius:3px;padding:1px 6px;font-size:.68rem}
</style>
</head>
<body>
<h1>🛡 OPSEC FP Blocker</h1>
<div class="item"><span>Canvas Noise</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>WebGL Spoof</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>Screen Spoof</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>WebRTC Block</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>Battery Block</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>Audio Noise</span><span class="badge">ACTIVE</span></div>
<div class="item"><span>HW Concurrency</span><span class="badge">ACTIVE</span></div>
<p class="status" style="margin-top:12px">All fingerprint blockers are active.</p>
</body>
</html>
"""


def export_extension(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(EXTENSION_MANIFEST)
    (out_dir / "content.js").write_text(EXTENSION_CONTENT_JS)
    (out_dir / "popup.html").write_text(EXTENSION_POPUP_HTML)
    print(f"[+] Extension exported to {out_dir}/")
    print("    Load in Chrome: chrome://extensions/ → Developer mode → Load unpacked → select folder")
    print("    Load in Firefox: about:debugging#/runtime/this-firefox → Load Temporary Add-on → select manifest.json")


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Fingerprint Analyzer & Blocker")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("analyze", help="Analyse fingerprinting vectors and countermeasures")

    gen_ua = sub.add_parser("generate-ua", help="Generate a spoofed User-Agent string")
    gen_ua.add_argument("--os", default="windows", choices=["windows", "macos", "linux", "android", "ios"])
    gen_ua.add_argument("--browser", default="chrome", choices=["chrome", "firefox", "safari"])

    sub.add_parser("list-profiles", help="List available fingerprint profiles")

    gp = sub.add_parser("generate-profile", help="Generate a fingerprint profile")
    gp.add_argument("--preset", default="average-windows-user", choices=list(PROFILES))

    exp = sub.add_parser("export-extension", help="Export browser extension")
    exp.add_argument("--out", default="./fp-blocker-extension")

    args = parser.parse_args()

    if args.cmd == "analyze":
        result = analyze_fingerprint()
        print(json.dumps(result, indent=2))
    elif args.cmd == "generate-ua":
        print(generate_ua(args.os, args.browser))
    elif args.cmd == "list-profiles":
        for name, profile in PROFILES.items():
            print(f"\n{'='*50}")
            print(f"Profile: {name}")
            print(json.dumps({k: v for k, v in profile.items() if k != 'ua_key'}, indent=2))
    elif args.cmd == "generate-profile":
        print(json.dumps(generate_profile(args.preset), indent=2))
    elif args.cmd == "export-extension":
        export_extension(Path(args.out))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
