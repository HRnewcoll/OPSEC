# 05 · MAC Spoofer

Randomise, spoof, and rotate MAC addresses on network interfaces to reduce tracking and fingerprinting.

## Quick Start

```bash
# List all interfaces and their MACs
sudo python mac_spoofer.py list

# Spoof to a random MAC (locally administered)
sudo python mac_spoofer.py spoof --interface wlan0

# Spoof with a specific vendor OUI (blend in)
sudo python mac_spoofer.py spoof --interface wlan0 --vendor Apple

# Set a specific MAC
sudo python mac_spoofer.py spoof --interface eth0 --mac 00:11:22:33:44:55

# Restore original MAC
sudo python mac_spoofer.py restore --interface wlan0

# Rotate MAC every 5 minutes (Ctrl+C to stop and restore)
sudo python mac_spoofer.py rotate --interface wlan0 --interval 300 --vendor Samsung

# Generate random MACs
python mac_spoofer.py generate --count 10 --vendor Intel

# Vendor lookup
python mac_spoofer.py lookup --mac 00:0c:29:12:34:56
```

## Supported Vendors

Apple, Samsung, Dell, Intel, Cisco, Lenovo, HP, Microsoft, Google, Raspberry Pi, Random (LAA)

## Persistent MAC Spoofing (Linux — systemd)

```bash
# /etc/systemd/network/10-wlan0.network
[Match]
Name=wlan0

[Link]
MACAddress=random
# OR:
# MACAddressPolicy=random

# Reload
sudo systemctl restart systemd-networkd
```

## NetworkManager (Linux)

```bash
nmcli connection modify "WiFi Name" 802-11-wireless.cloned-mac-address random
nmcli connection modify "WiFi Name" 802-11-wireless.mac-address-randomization always
```

## macOS

```bash
# Randomise on every scan (macOS 14+)
# System Preferences → Network → WiFi → Details → Private Wi-Fi Address → Rotating
```

## Security Notes

- Locally administered MACs (LAA) set the second-least-significant bit of the first byte to 1
- Vendor-spoofed MACs blend into normal traffic better than LAA MACs
- MAC spoofing is layer-2 only; your IP address is still visible to routers and beyond
- Some enterprise networks use 802.1X authentication with MAC as a factor — spoofing may trigger alerts
- macOS and iOS do MAC randomisation by default for Wi-Fi scanning
