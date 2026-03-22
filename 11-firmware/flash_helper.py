#!/usr/bin/env python3
"""
OPSEC Firmware Flash Helper
============================
Automates downloading and flashing firmware for:
  - ESP32 / M5StickC+ (Bruce firmware, Marauder)
  - Flipper Zero (Unleashed, RogueMaster, RM firmware)
  - Generic esptool.py wrapper

Usage:
  python flash_helper.py list-firmware
  python flash_helper.py download --firmware bruce --version latest
  python flash_helper.py flash --firmware bruce --port /dev/ttyUSB0
  python flash_helper.py flash --firmware marauder --port /dev/ttyUSB0 --board m5stickc
  python flash_helper.py flipper --action update --channel unleashed
  python flash_helper.py verify --port /dev/ttyUSB0
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import urllib.request
from pathlib import Path
from datetime import datetime

FIRMWARE_DIR = Path("~/.opsec/firmware").expanduser()

# ── Firmware catalog ─────────────────────────────────────────────────
FIRMWARE_CATALOG = {
    "bruce": {
        "name": "Bruce Firmware",
        "description": "Offensive security firmware for ESP32-based devices (M5StickC+, CARDPUTER, etc.)",
        "homepage": "https://github.com/pr3y/Bruce",
        "targets": ["M5StickC Plus", "M5StickC Plus2", "CARDPUTER", "T-Embed", "Generic ESP32"],
        "features": [
            "Wi-Fi attacks (deauth, evil twin, packet monitor)",
            "BLE scanning and spoofing",
            "IR blaster (remote cloning)",
            "RFID/NFC reading",
            "Flipper-like interface",
            "WebUI for remote control",
            "TV-B-Gone",
            "Sub-GHz (CC1101 module required)",
            "Bad USB / HID injection",
        ],
        "flash_cmd": "esptool.py --chip esp32 --port {port} --baud 921600 write_flash -z 0x0 {firmware}",
        "download_url": "https://github.com/pr3y/Bruce/releases/latest",
        "releases_api": "https://api.github.com/repos/pr3y/Bruce/releases/latest",
    },
    "marauder": {
        "name": "ESP32 Marauder",
        "description": "Suite of Wi-Fi/BLE offensive and defensive tools for ESP32",
        "homepage": "https://github.com/justcallmekoko/ESP32Marauder",
        "targets": ["M5StickC Plus", "M5Stack", "NodeMCU ESP32", "Generic ESP32"],
        "features": [
            "Wi-Fi scanning",
            "Deauthentication attacks",
            "WPA2 PMKID capture",
            "Probe sniffing",
            "BLE sniffing and wardriving",
            "Evil portal / captive portal",
            "Packet monitor",
            "GPS wardriving with SD card",
        ],
        "flash_cmd": "esptool.py --chip esp32 --port {port} --baud 115200 --before default_reset --after hard_reset write_flash -z 0x1000 {firmware}",
        "download_url": "https://github.com/justcallmekoko/ESP32Marauder/releases/latest",
        "releases_api": "https://api.github.com/repos/justcallmekoko/ESP32Marauder/releases/latest",
    },
    "flipper-unleashed": {
        "name": "Flipper Zero — Unleashed Firmware",
        "description": "Unleashed removes region locks and adds extra protocols",
        "homepage": "https://github.com/DarkFlippers/unleashed-firmware",
        "targets": ["Flipper Zero"],
        "features": [
            "Removed region restrictions",
            "More Sub-GHz frequencies",
            "Extra protocols (RAW recordings)",
            "Bad USB scripts",
            "GPIO improvements",
            "RGB LED control",
            "Extra apps via UL app store",
        ],
        "flash_cmd": "qFlipper or flipper update via web updater",
        "download_url": "https://github.com/DarkFlippers/unleashed-firmware/releases/latest",
        "releases_api": "https://api.github.com/repos/DarkFlippers/unleashed-firmware/releases/latest",
        "update_url": "https://unleashedflip.com/fw/",
        "web_updater": "https://lab.flipper.net/?url=https://unleashedflip.com/fw/",
    },
    "flipper-roguemaster": {
        "name": "Flipper Zero — RogueMaster Firmware",
        "description": "Comprehensive Flipper firmware with many plugins and tweaks",
        "homepage": "https://github.com/RogueMaster/flipperzero-firmware-wPlugins",
        "targets": ["Flipper Zero"],
        "features": [
            "Huge plugin collection",
            "Games",
            "Advanced Sub-GHz tools",
            "Enhanced BadUSB",
            "NFC extras",
            "Animated backgrounds",
            "Casino games easter egg",
        ],
        "releases_api": "https://api.github.com/repos/RogueMaster/flipperzero-firmware-wPlugins/releases/latest",
    },
    "flipper-momentum": {
        "name": "Flipper Zero — Momentum Firmware",
        "description": "Feature-rich Flipper firmware, successor to Xtreme",
        "homepage": "https://github.com/Next-Flip/Momentum-Firmware",
        "targets": ["Flipper Zero"],
        "features": [
            "Asset packs (themes, animations)",
            "Apps catalog",
            "Sub-GHz enhancements",
            "Enhanced Bluetooth",
            "Level/XP system",
            "Desktop customisation",
        ],
        "releases_api": "https://api.github.com/repos/Next-Flip/Momentum-Firmware/releases/latest",
    },
}


# ── esptool helpers ───────────────────────────────────────────────────

def check_esptool() -> bool:
    try:
        subprocess.run(["esptool.py", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def list_serial_ports() -> list[str]:
    system = platform.system()
    if system == "Linux":
        return [str(p) for p in Path("/dev").glob("ttyUSB*")] + \
               [str(p) for p in Path("/dev").glob("ttyACM*")]
    elif system == "Darwin":
        return [str(p) for p in Path("/dev").glob("cu.usbserial*")] + \
               [str(p) for p in Path("/dev").glob("cu.usbmodem*")]
    elif system == "Windows":
        result = subprocess.run(["powershell", "Get-PnpDevice -Class Ports | Select-Object FriendlyName"],
                                capture_output=True, text=True)
        return [l.strip() for l in result.stdout.splitlines() if "COM" in l]
    return []


def get_latest_release_info(api_url: str) -> dict | None:
    try:
        req = urllib.request.Request(api_url,
                                     headers={"User-Agent": "OPSEC-FlashHelper/1.0",
                                              "Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [!] API error: {e}")
        return None


def download_firmware(fw_key: str, asset_filter: str | None = None) -> Path | None:
    fw = FIRMWARE_CATALOG.get(fw_key)
    if not fw:
        print(f"[!] Unknown firmware: {fw_key}"); return None

    api_url = fw.get("releases_api")
    if not api_url:
        print(f"[!] No release API for {fw_key}"); return None

    print(f"[*] Fetching latest release for {fw['name']} …")
    release = get_latest_release_info(api_url)
    if not release:
        return None

    version = release.get("tag_name", "unknown")
    assets  = release.get("assets", [])
    print(f"    Version: {version}")
    print(f"    Assets : {len(assets)}")

    if not assets:
        print(f"[!] No assets. Download manually from: {fw.get('download_url')}")
        return None

    # Pick the right asset
    target_asset = None
    for asset in assets:
        name = asset["name"].lower()
        if asset_filter and asset_filter.lower() not in name:
            continue
        if name.endswith(".bin") or name.endswith(".zip"):
            target_asset = asset
            break

    if not target_asset:
        target_asset = assets[0]
        print(f"    Using first asset: {target_asset['name']}")

    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIRMWARE_DIR / f"{fw_key}_{version}_{target_asset['name']}"

    if out_path.exists():
        print(f"[*] Already downloaded: {out_path}")
        return out_path

    print(f"    Downloading: {target_asset['name']} ({target_asset['size']:,} bytes) …")
    try:
        req = urllib.request.Request(target_asset["browser_download_url"],
                                     headers={"User-Agent": "OPSEC-FlashHelper/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(out_path, "wb") as f:
            downloaded = 0
            while chunk := resp.read(65536):
                f.write(chunk)
                downloaded += len(chunk)
                pct = downloaded * 100 // target_asset["size"]
                print(f"    {pct:3d}% [{downloaded:,}/{target_asset['size']:,}]", end="\r")
        print(f"\n[+] Downloaded → {out_path}")
        return out_path
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return None


def flash_firmware(fw_key: str, port: str, firmware_path: Path):
    fw = FIRMWARE_CATALOG.get(fw_key)
    if not fw:
        print(f"[!] Unknown firmware: {fw_key}"); return

    if not check_esptool():
        print("[!] esptool.py not found. Install: pip install esptool")
        return

    cmd_template = fw.get("flash_cmd", "")
    if not cmd_template or "esptool" not in cmd_template:
        print(f"[!] Cannot auto-flash {fw['name']}. Manual steps:")
        print(f"    {cmd_template}")
        return

    cmd = cmd_template.format(port=port, firmware=str(firmware_path)).split()
    print(f"[*] Flashing {fw['name']} to {port} …")
    print(f"    Command: {' '.join(cmd)}")
    print("    ⚠️  Hold BOOT button on the device if it doesn't connect!")
    subprocess.run(cmd)


# ── CLI commands ───────────────────────────────────────────────────────

def cmd_list(args):
    for key, fw in FIRMWARE_CATALOG.items():
        print(f"\n{'='*60}")
        print(f"Key      : {key}")
        print(f"Name     : {fw['name']}")
        print(f"Targets  : {', '.join(fw['targets'])}")
        print(f"Homepage : {fw.get('homepage','N/A')}")
        print(f"Features :")
        for f in fw['features']:
            print(f"  • {f}")


def cmd_download(args):
    path = download_firmware(args.firmware, args.filter)
    if path:
        print(f"\n[+] Ready to flash: {path}")
        fw = FIRMWARE_CATALOG.get(args.firmware, {})
        if fw.get("flash_cmd"):
            print(f"\nFlash with:")
            print(f"  python flash_helper.py flash --firmware {args.firmware} --port /dev/ttyUSB0 --file {path}")


def cmd_flash(args):
    fw_path = Path(args.file) if args.file else None
    if not fw_path:
        # Try to find latest in cache
        files = list(FIRMWARE_DIR.glob(f"{args.firmware}_*.bin"))
        if files:
            fw_path = sorted(files)[-1]
            print(f"[*] Using cached: {fw_path}")
        else:
            print("[!] No firmware file. Run 'download' first or use --file.")
            sys.exit(1)
    flash_firmware(args.firmware, args.port, fw_path)


def cmd_ports(args):
    ports = list_serial_ports()
    if ports:
        print("Available serial ports:")
        for p in ports:
            print(f"  {p}")
    else:
        print("No serial ports found. Check USB connection and drivers.")
        print("Linux: ls /dev/ttyUSB* /dev/ttyACM*")
        print("macOS: ls /dev/cu.*")


def cmd_guide(args):
    guides = {
        "bruce": """
BRUCE FIRMWARE SETUP GUIDE
============================
Hardware: M5StickC Plus / M5StickC Plus2 / CARDPUTER

1. Install esptool:
   pip install esptool

2. Find your serial port:
   python flash_helper.py ports

3. Download Bruce firmware:
   python flash_helper.py download --firmware bruce

4. Put device in flash mode:
   - Hold side button, press reset, release side button
   - OR: Hold boot button while connecting USB

5. Flash (replace port):
   python flash_helper.py flash --firmware bruce --port /dev/ttyUSB0

6. After flashing, press reset button
7. Bruce menu will appear on screen

Features:
  - Wi-Fi: Scan, Deauth, Evil Twin, PMKID
  - BLE: Scan, Spam, Sour Apple
  - IR: Blaster, Capture
  - Sub-GHz: Requires CC1101 module
  - Bad USB: HID injection scripts
  - RF Cloner

Web UI: Connect to Bruce's Wi-Fi and go to http://192.168.4.1
""",
        "marauder": """
ESP32 MARAUDER SETUP GUIDE
============================
Hardware: M5StickC Plus / M5Stack / NodeMCU ESP32

1. Install esptool:
   pip install esptool

2. Download Marauder:
   python flash_helper.py download --firmware marauder

3. Flash:
   python flash_helper.py flash --firmware marauder --port /dev/ttyUSB0

4. Serial interface: 115200 baud
   - Use Arduino Serial Monitor or screen /dev/ttyUSB0 115200

Key commands (serial):
  scanap          - Scan access points
  scansta         - Scan stations
  deauth -t 10    - Deauth all APs for 10s
  probemon        - Monitor probe requests
  sniffpmkid      - Capture PMKID
  stopmon         - Stop monitoring
""",
        "flipper": """
FLIPPER ZERO FIRMWARE GUIDE
============================

== Unleashed ==
1. Download from: https://unleashedflip.com/fw/
2. Flash via qFlipper OR web updater:
   https://lab.flipper.net/?url=https://unleashedflip.com/fw/
3. Or: Settings → Firmware → Update → Custom URL

== RogueMaster ==
Download: https://github.com/RogueMaster/flipperzero-firmware-wPlugins/releases

== Momentum ==
Download: https://github.com/Next-Flip/Momentum-Firmware/releases
Web update: https://momentum-fw.dev/update/

== Manual Update ==
1. Download .tgz file
2. Copy to Flipper SD card via USB
3. In Flipper: Settings → Firmware → Update → From SD card

== Recovery ==
If bricked:
1. Download official firmware from flipperzero.one/update
2. Use qFlipper recovery mode

== Recommended Setup ==
1. Flash Unleashed or Momentum firmware
2. Install Flipper App on phone
3. Set up Sub-GHz region unlocking
4. Install plugins: NFC tools, IR library, Bad USB scripts
5. Load RF captures from GitHub repositories
""",
    }
    guide = guides.get(args.firmware)
    if guide:
        print(guide)
    else:
        print(f"Available guides: {', '.join(guides)}")


def main():
    parser = argparse.ArgumentParser(description="OPSEC Firmware Flash Helper")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list-firmware", help="List all supported firmware")

    dl = sub.add_parser("download", help="Download latest firmware")
    dl.add_argument("--firmware", required=True, choices=list(FIRMWARE_CATALOG))
    dl.add_argument("--filter", help="Filter asset by keyword (e.g. 'm5stickc')")

    fl = sub.add_parser("flash", help="Flash firmware to device")
    fl.add_argument("--firmware", required=True, choices=[k for k in FIRMWARE_CATALOG if "flipper" not in k])
    fl.add_argument("--port", required=True, help="Serial port (e.g. /dev/ttyUSB0)")
    fl.add_argument("--file", help="Path to .bin file (auto-detected if omitted)")

    sub.add_parser("ports", help="List available serial ports")

    gd = sub.add_parser("guide", help="Print setup guide for firmware")
    gd.add_argument("--firmware", required=True, choices=["bruce", "marauder", "flipper"])

    args = parser.parse_args()
    dispatch = {
        "list-firmware": cmd_list,
        "download": cmd_download,
        "flash": cmd_flash,
        "ports": cmd_ports,
        "guide": cmd_guide,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
