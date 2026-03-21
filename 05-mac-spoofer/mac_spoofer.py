#!/usr/bin/env python3
"""
OPSEC MAC Address Spoofer
=========================
Randomise or set MAC addresses on network interfaces.
Supports vendor-specific MAC generation, scheduled rotation,
and restoration of original MAC.

Requires root / administrator privileges.

Usage:
  sudo python mac_spoofer.py list
  sudo python mac_spoofer.py spoof --interface eth0
  sudo python mac_spoofer.py spoof --interface eth0 --vendor Apple
  sudo python mac_spoofer.py spoof --interface wlan0 --mac AA:BB:CC:DD:EE:FF
  sudo python mac_spoofer.py restore --interface eth0
  sudo python mac_spoofer.py rotate --interface wlan0 --interval 300
  sudo python mac_spoofer.py lookup --mac 00:0c:29:xx:xx:xx
"""

import argparse
import json
import os
import platform
import random
import re
import subprocess
import sys
import time
from pathlib import Path

BACKUP_FILE = Path("/tmp/.opsec_mac_backup.json")

# Common vendor OUIs (first 3 octets)
VENDOR_OUIS = {
    "Apple":      ["00:03:93", "00:0a:27", "00:0a:95", "00:14:51", "28:6a:ba", "3c:07:54", "a4:c3:61"],
    "Samsung":    ["00:26:37", "08:08:c2", "2c:54:cf", "50:01:bb", "78:25:ad"],
    "Dell":       ["00:14:22", "18:03:73", "bc:30:5b", "f8:b1:56"],
    "Intel":      ["00:02:b3", "00:21:6a", "8c:8d:28", "a4:34:d9"],
    "Cisco":      ["00:00:0c", "00:01:42", "00:1b:d4", "00:50:56"],
    "Lenovo":     ["00:21:cc", "28:d2:44", "8c:8d:28", "f8:16:54"],
    "HP":         ["00:14:38", "18:a9:05", "3c:d9:2b", "94:18:82"],
    "Microsoft":  ["00:50:f2", "28:18:78", "7c:1e:52"],
    "Google":     ["3c:5a:b4", "f4:f5:e8", "54:60:09"],
    "Raspberry":  ["b8:27:eb", "dc:a6:32", "e4:5f:01"],
    "Random":     [],
}


# ─────────────────────────── detection ──────────────────────────────

def is_root() -> bool:
    return os.geteuid() == 0 if platform.system() != "Windows" else True


def get_interfaces() -> list[dict]:
    """List network interfaces with their current MAC addresses."""
    interfaces = []
    system = platform.system()
    if system == "Linux":
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^\d+: (\S+):.*", line)
            if m:
                iface = m.group(1).rstrip(":")
                mac = None
                for j in range(i, min(i + 3, len(lines))):
                    mm = re.search(r"link/\S+\s+([0-9a-f:]{17})", lines[j])
                    if mm:
                        mac = mm.group(1).upper()
                        break
                if iface != "lo":
                    interfaces.append({"name": iface, "mac": mac})
    elif system == "Darwin":
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        current = None
        for line in result.stdout.splitlines():
            m = re.match(r"^(\S+):", line)
            if m:
                current = m.group(1)
            elif current and "ether" in line:
                mac = re.search(r"([0-9a-f:]{17})", line)
                if mac:
                    interfaces.append({"name": current, "mac": mac.group(1).upper()})
    return interfaces


def get_mac(interface: str) -> str | None:
    """Get the current MAC address of an interface."""
    for iface in get_interfaces():
        if iface["name"] == interface:
            return iface["mac"]
    return None


# ─────────────────────────── spoofing ───────────────────────────────

def generate_mac(vendor: str | None = None) -> str:
    """Generate a random MAC address, optionally with a specific vendor OUI."""
    if vendor and vendor in VENDOR_OUIS and VENDOR_OUIS[vendor]:
        oui = random.choice(VENDOR_OUIS[vendor])
        oui_parts = oui.split(":")
    else:
        # Locally administered, unicast
        first_byte = random.randint(0, 255) & 0xFE | 0x02  # LAA, unicast
        oui_parts = [f"{first_byte:02X}", f"{random.randint(0,255):02X}", f"{random.randint(0,255):02X}"]

    nic = [f"{random.randint(0, 255):02X}" for _ in range(3)]
    return ":".join(oui_parts + nic)


def backup_mac(interface: str, current_mac: str):
    backup = {}
    if BACKUP_FILE.exists():
        try:
            backup = json.loads(BACKUP_FILE.read_text())
        except Exception:
            pass
    if interface not in backup:
        backup[interface] = current_mac
        BACKUP_FILE.write_text(json.dumps(backup))


def set_mac_linux(interface: str, mac: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["ip", "link", "set", interface, "address", mac], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e}"); return False


def set_mac_macos(interface: str, mac: str) -> bool:
    try:
        subprocess.run(["ifconfig", interface, "ether", mac], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e}"); return False


def set_mac(interface: str, mac: str) -> bool:
    system = platform.system()
    if system == "Linux":
        return set_mac_linux(interface, mac)
    elif system == "Darwin":
        return set_mac_macos(interface, mac)
    else:
        print(f"[!] Unsupported OS: {system}"); return False


# ─────────────────────────── vendor lookup ──────────────────────────

def lookup_vendor(mac: str) -> str:
    oui = mac[:8].upper().replace("-", ":")
    for vendor, ouis in VENDOR_OUIS.items():
        if any(o.upper() == oui for o in ouis):
            return vendor
    return "Unknown"


# ─────────────────────────── CLI commands ───────────────────────────

def cmd_list(args):
    interfaces = get_interfaces()
    print(f"{'Interface':<20} {'MAC Address':<20} {'Vendor'}")
    print("-" * 60)
    for iface in interfaces:
        vendor = lookup_vendor(iface["mac"] or "") if iface["mac"] else ""
        print(f"{iface['name']:<20} {iface['mac'] or 'N/A':<20} {vendor}")


def cmd_spoof(args):
    if not is_root():
        print("[!] Root/administrator privileges required."); sys.exit(1)

    interface = args.interface
    current = get_mac(interface)
    if not current:
        print(f"[!] Interface '{interface}' not found."); sys.exit(1)

    backup_mac(interface, current)
    new_mac = args.mac or generate_mac(args.vendor)

    print(f"[*] Interface : {interface}")
    print(f"    Original  : {current}")
    print(f"    New MAC   : {new_mac}")
    if args.vendor:
        print(f"    Vendor    : {args.vendor}")

    ok = set_mac(interface, new_mac)
    if ok:
        actual = get_mac(interface)
        print(f"[+] MAC changed → {actual}")
    else:
        print("[!] MAC change failed.")


def cmd_restore(args):
    if not is_root():
        print("[!] Root required."); sys.exit(1)
    if not BACKUP_FILE.exists():
        print("[!] No backup found."); sys.exit(1)
    backup = json.loads(BACKUP_FILE.read_text())
    interface = args.interface
    if interface not in backup:
        print(f"[!] No backup for {interface}"); sys.exit(1)
    original = backup[interface]
    ok = set_mac(interface, original)
    if ok:
        print(f"[+] Restored {interface} → {original}")
        del backup[interface]
        BACKUP_FILE.write_text(json.dumps(backup))
    else:
        print("[!] Restore failed.")


def cmd_rotate(args):
    if not is_root():
        print("[!] Root required."); sys.exit(1)
    interface = args.interface
    interval  = args.interval
    current = get_mac(interface)
    if not current:
        print(f"[!] Interface '{interface}' not found."); sys.exit(1)
    backup_mac(interface, current)
    print(f"[*] MAC rotation started on {interface} every {interval}s")
    print("    Press Ctrl+C to stop and restore original MAC.")
    try:
        count = 0
        while True:
            new_mac = generate_mac(args.vendor)
            ok = set_mac(interface, new_mac)
            count += 1
            actual = get_mac(interface)
            print(f"    [{count}] → {actual or new_mac}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Stopping rotation…")
        backup = json.loads(BACKUP_FILE.read_text()) if BACKUP_FILE.exists() else {}
        if interface in backup:
            set_mac(interface, backup[interface])
            print(f"[+] Restored original MAC: {backup[interface]}")


def cmd_lookup(args):
    vendor = lookup_vendor(args.mac)
    oui = args.mac[:8].upper()
    print(f"MAC: {args.mac.upper()}")
    print(f"OUI: {oui}")
    print(f"Vendor: {vendor}")


def cmd_generate(args):
    for _ in range(args.count):
        print(generate_mac(args.vendor))


def main():
    parser = argparse.ArgumentParser(
        description="OPSEC MAC Address Spoofer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python mac_spoofer.py list
  sudo python mac_spoofer.py spoof --interface wlan0
  sudo python mac_spoofer.py spoof --interface wlan0 --vendor Apple
  sudo python mac_spoofer.py spoof --interface eth0 --mac 00:11:22:33:44:55
  sudo python mac_spoofer.py restore --interface wlan0
  sudo python mac_spoofer.py rotate --interface wlan0 --interval 300 --vendor Samsung
  python mac_spoofer.py generate --count 10 --vendor Intel
  python mac_spoofer.py lookup --mac 00:0c:29:12:34:56
        """,
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List all interfaces and MACs")

    sp = sub.add_parser("spoof", help="Spoof MAC address")
    sp.add_argument("--interface", "-i", required=True)
    sp.add_argument("--mac", help="Specific MAC to set")
    sp.add_argument("--vendor", "-v", choices=list(VENDOR_OUIS), help="Vendor OUI to use")

    rs = sub.add_parser("restore", help="Restore original MAC")
    rs.add_argument("--interface", "-i", required=True)

    rot = sub.add_parser("rotate", help="Periodically rotate MAC")
    rot.add_argument("--interface", "-i", required=True)
    rot.add_argument("--interval", type=int, default=300, help="Rotation interval in seconds")
    rot.add_argument("--vendor", "-v", choices=list(VENDOR_OUIS))

    gen = sub.add_parser("generate", help="Generate random MAC addresses")
    gen.add_argument("--count", type=int, default=1)
    gen.add_argument("--vendor", "-v", choices=list(VENDOR_OUIS))

    lk = sub.add_parser("lookup", help="Lookup vendor for a MAC")
    lk.add_argument("--mac", required=True)

    args = parser.parse_args()
    dispatch = {
        "list": cmd_list, "spoof": cmd_spoof, "restore": cmd_restore,
        "rotate": cmd_rotate, "generate": cmd_generate, "lookup": cmd_lookup,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
