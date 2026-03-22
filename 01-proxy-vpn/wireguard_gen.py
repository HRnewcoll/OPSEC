#!/usr/bin/env python3
"""
WireGuard Configuration Generator
Generates server + client WireGuard configs with key pairs.
Uses cryptography library for X25519 key generation when wg binary is absent.
"""

import argparse
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ─────────────────────────── key helpers ────────────────────────────

def _wg_available() -> bool:
    try:
        subprocess.run(["wg", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64)."""
    if _wg_available():
        priv = subprocess.check_output(["wg", "genkey"]).decode().strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode()).decode().strip()
        return priv, pub
    if CRYPTO_AVAILABLE:
        priv_obj = X25519PrivateKey.generate()
        priv_bytes = priv_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        priv_b64 = base64.b64encode(priv_bytes).decode()
        pub_b64 = base64.b64encode(pub_bytes).decode()
        return priv_b64, pub_b64
    raise RuntimeError("Neither 'wg' binary nor 'cryptography' package is available. "
                       "Install with: pip install cryptography  OR  apt install wireguard-tools")


def generate_psk() -> str:
    """Generate a 32-byte pre-shared key encoded as base64."""
    if _wg_available():
        return subprocess.check_output(["wg", "genpsk"]).decode().strip()
    return base64.b64encode(os.urandom(32)).decode()


# ─────────────────────────── config builders ────────────────────────

def build_server_config(
    server_priv: str,
    server_port: int,
    server_vpn_ip: str,
    clients: list[dict],
    dns: str = "1.1.1.1",
    allowed_ips: str = "0.0.0.0/0, ::/0",
) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {server_priv}",
        f"Address = {server_vpn_ip}/24",
        f"ListenPort = {server_port}",
        f"DNS = {dns}",
        "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        "",
    ]
    for client in clients:
        lines += [
            f"# Peer: {client['name']}",
            "[Peer]",
            f"PublicKey = {client['pub']}",
        ]
        if client.get("psk"):
            lines.append(f"PresharedKey = {client['psk']}")
        lines += [
            f"AllowedIPs = {client['vpn_ip']}/32",
            "",
        ]
    return "\n".join(lines)


def build_client_config(
    client_priv: str,
    client_vpn_ip: str,
    server_pub: str,
    server_endpoint: str,
    server_port: int,
    psk: str | None = None,
    dns: str = "1.1.1.1",
    allowed_ips: str = "0.0.0.0/0, ::/0",
) -> str:
    lines = [
        "[Interface]",
        f"PrivateKey = {client_priv}",
        f"Address = {client_vpn_ip}/24",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub}",
    ]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines += [
        f"Endpoint = {server_endpoint}:{server_port}",
        f"AllowedIPs = {allowed_ips}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines)


# ─────────────────────────── CLI ────────────────────────────────────

def cmd_generate(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    print("[*] Generating server key pair …")
    server_priv, server_pub = generate_keypair()

    clients = []
    base_net = ipaddress.IPv4Network(f"10.0.0.0/24")
    hosts = list(base_net.hosts())
    server_vpn_ip = str(hosts[0])  # 10.0.0.1

    for i in range(args.clients):
        name = f"client{i+1}"
        print(f"[*] Generating key pair for {name} …")
        cpriv, cpub = generate_keypair()
        psk = generate_psk() if args.psk else None
        client_vpn_ip = str(hosts[i + 1])
        clients.append({
            "name": name,
            "priv": cpriv,
            "pub": cpub,
            "vpn_ip": client_vpn_ip,
            "psk": psk,
        })

    # Write server config
    server_cfg = build_server_config(
        server_priv=server_priv,
        server_port=args.port,
        server_vpn_ip=server_vpn_ip,
        clients=clients,
        dns=args.dns,
    )
    server_file = out / "wg0-server.conf"
    server_file.write_text(server_cfg)
    server_file.chmod(0o600)
    print(f"[+] Server config  → {server_file}")

    # Write client configs
    for client in clients:
        cfg = build_client_config(
            client_priv=client["priv"],
            client_vpn_ip=client["vpn_ip"],
            server_pub=server_pub,
            server_endpoint=args.endpoint,
            server_port=args.port,
            psk=client.get("psk"),
            dns=args.dns,
        )
        cfile = out / f"wg0-{client['name']}.conf"
        cfile.write_text(cfg)
        cfile.chmod(0o600)
        print(f"[+] Client config  → {cfile}")

    # Write key summary
    summary = out / "keys.txt"
    lines = [f"Server private key: {server_priv}", f"Server public key:  {server_pub}", ""]
    for c in clients:
        lines += [
            f"{c['name']} private key: {c['priv']}",
            f"{c['name']} public key:  {c['pub']}",
        ]
        if c.get("psk"):
            lines.append(f"{c['name']} PSK:         {c['psk']}")
        lines.append("")
    summary.write_text("\n".join(lines))
    summary.chmod(0o600)
    print(f"[+] Key summary    → {summary}")


def main():
    parser = argparse.ArgumentParser(
        description="WireGuard Configuration Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wireguard_gen.py generate --clients 3 --endpoint vpn.example.com
  python wireguard_gen.py generate --clients 1 --endpoint 203.0.113.1 --port 51820 --psk
        """,
    )
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("generate", help="Generate WireGuard server+client configs")
    gen.add_argument("--clients", type=int, default=1, help="Number of client configs (default: 1)")
    gen.add_argument("--endpoint", default="YOUR_SERVER_IP", help="Server public IP/hostname")
    gen.add_argument("--port", type=int, default=51820, help="Server listen port (default: 51820)")
    gen.add_argument("--dns", default="1.1.1.1", help="DNS server for clients (default: 1.1.1.1)")
    gen.add_argument("--psk", action="store_true", help="Add pre-shared keys (extra layer)")
    gen.add_argument("--output", default="./wireguard-configs", help="Output directory")

    args = parser.parse_args()
    if args.command == "generate":
        cmd_generate(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
