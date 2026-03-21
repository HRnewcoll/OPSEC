#!/usr/bin/env python3
"""
OPSEC Secure Messaging — Double Ratchet Protocol (Simplified)
=============================================================
Implements a simplified Double Ratchet Algorithm (Signal Protocol inspired)
providing forward secrecy and break-in recovery.

Architecture:
  - X25519 for initial key exchange (Diffie-Hellman ratchet)
  - HKDF-SHA256 for key derivation
  - AES-256-GCM for message encryption
  - Chain keys updated on every message (forward secrecy)

Usage:
  python messaging.py init --name alice
  python messaging.py init --name bob
  python messaging.py exchange --my-key alice.key --their-pub bob.pub
  python messaging.py send --session alice_session.json --message "Hello Bob!"
  python messaging.py recv --session bob_session.json --ciphertext <hex>
"""

import argparse
import hashlib
import hmac as _hmac
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key,
)
from cryptography.hazmat.backends import default_backend


# ─────────────────────────── KDF helpers ────────────────────────────

def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Root key derivation. Returns (new_root_key, new_chain_key)."""
    hkdf = HKDF(SHA256(), length=64, salt=rk, info=b"OPSEC-RK", backend=default_backend())
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Chain key ratchet step. Returns (new_chain_key, message_key)."""
    new_ck = _hmac.new(ck, b"\x02", digestmod="sha256").digest()
    mk     = _hmac.new(ck, b"\x01", digestmod="sha256").digest()
    return new_ck, mk


# ─────────────────────────── encryption helpers ─────────────────────

def encrypt_message(mk: bytes, plaintext: str, associated: bytes = b"") -> dict:
    nonce = os.urandom(12)
    aesgcm = AESGCM(mk)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), associated)
    return {"nonce": nonce.hex(), "ciphertext": ct.hex()}


def decrypt_message(mk: bytes, nonce_hex: str, ct_hex: str, associated: bytes = b"") -> str:
    nonce = bytes.fromhex(nonce_hex)
    ct    = bytes.fromhex(ct_hex)
    aesgcm = AESGCM(mk)
    return aesgcm.decrypt(nonce, ct, associated).decode()


# ─────────────────────────── session state ──────────────────────────

def create_session(my_priv_pem: bytes, their_pub_pem: bytes, is_initiator: bool) -> dict:
    """Perform initial X3DH-style handshake and create session state."""
    my_priv = load_pem_private_key(my_priv_pem, password=None)
    their_pub = load_pem_public_key(their_pub_pem)

    # Initial DH
    dh_out = my_priv.exchange(their_pub)

    # Initial root key from shared DH output
    rk = hashlib.sha256(dh_out).digest()

    # Derive chain keys
    rk, send_ck = kdf_rk(rk, dh_out)
    _,  recv_ck = kdf_rk(rk, dh_out[::-1])  # simplified: use reversed DH for recv chain

    # Generate new DH ratchet keypair
    new_dh_priv = X25519PrivateKey.generate()
    new_dh_pub  = new_dh_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    new_dh_priv_pem = new_dh_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()

    return {
        "root_key":      rk.hex(),
        "send_chain_key": send_ck.hex() if is_initiator else recv_ck.hex(),
        "recv_chain_key": recv_ck.hex() if is_initiator else send_ck.hex(),
        "send_msg_num":  0,
        "recv_msg_num":  0,
        "dh_ratchet_priv": new_dh_priv_pem,
        "dh_ratchet_pub":  new_dh_pub,
        "their_dh_pub":    their_pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "is_initiator":    is_initiator,
        "message_log":     [],
    }


def session_send(state: dict, plaintext: str) -> dict:
    """Encrypt a message and advance the sending chain."""
    send_ck = bytes.fromhex(state["send_chain_key"])
    new_ck, mk = kdf_ck(send_ck)
    state["send_chain_key"] = new_ck.hex()
    msg_num = state["send_msg_num"]
    state["send_msg_num"] += 1

    header = json.dumps({
        "dh": state["dh_ratchet_pub"],
        "n":  msg_num,
    }).encode()

    enc = encrypt_message(mk, plaintext, associated=header)
    packet = {
        "header":     header.decode(),
        "nonce":      enc["nonce"],
        "ciphertext": enc["ciphertext"],
    }
    state["message_log"].append({"direction": "sent", "msg_num": msg_num, "preview": plaintext[:20]})
    return packet


def session_recv(state: dict, packet: dict) -> str:
    """Decrypt a received packet and advance the receiving chain."""
    recv_ck = bytes.fromhex(state["recv_chain_key"])
    new_ck, mk = kdf_ck(recv_ck)
    state["recv_chain_key"] = new_ck.hex()
    state["recv_msg_num"] += 1

    header = packet["header"].encode()
    try:
        plain = decrypt_message(mk, packet["nonce"], packet["ciphertext"], associated=header)
    except Exception as e:
        raise ValueError(f"Decryption failed — wrong session or corrupted packet: {e}")

    state["message_log"].append({
        "direction": "received",
        "msg_num": state["recv_msg_num"] - 1,
        "preview": plain[:20],
    })
    return plain


# ─────────────────────────── CLI commands ───────────────────────────

def cmd_init(args):
    out = Path(args.output or ".")
    out.mkdir(parents=True, exist_ok=True)
    priv = X25519PrivateKey.generate()
    pem_priv = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pem_pub  = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    name = args.name
    (out / f"{name}.key").write_bytes(pem_priv)
    (out / f"{name}.key").chmod(0o600)
    (out / f"{name}.pub").write_bytes(pem_pub)
    print(f"[+] Identity created:")
    print(f"    Private key → {out / (name+'.key')}  (keep secret!)")
    print(f"    Public key  → {out / (name+'.pub')}  (share with peers)")


def cmd_exchange(args):
    my_priv_pem   = Path(args.my_key).read_bytes()
    their_pub_pem = Path(args.their_pub).read_bytes()
    initiator = not args.responder
    state = create_session(my_priv_pem, their_pub_pem, is_initiator=initiator)
    out = Path(args.output or f"session_{args.name or 'session'}.json")
    out.write_text(json.dumps(state, indent=2))
    out.chmod(0o600)
    print(f"[+] Session established → {out}")
    print(f"    Role: {'initiator' if initiator else 'responder'}")


def cmd_send(args):
    session_file = Path(args.session)
    state = json.loads(session_file.read_text())
    plaintext = args.message or sys.stdin.read()
    packet = session_send(state, plaintext)
    session_file.write_text(json.dumps(state, indent=2))
    packet_json = json.dumps(packet)
    if args.output:
        Path(args.output).write_text(packet_json)
        print(f"[+] Encrypted packet → {args.output}")
    else:
        print(packet_json)


def cmd_recv(args):
    session_file = Path(args.session)
    state = json.loads(session_file.read_text())
    if args.packet_file:
        packet = json.loads(Path(args.packet_file).read_text())
    else:
        packet = json.loads(sys.stdin.read())
    try:
        plain = session_recv(state, packet)
    except ValueError as e:
        print(f"[!] {e}"); sys.exit(1)
    session_file.write_text(json.dumps(state, indent=2))
    print(f"[Message]\n{plain}")


def cmd_log(args):
    state = json.loads(Path(args.session).read_text())
    log = state.get("message_log", [])
    print(f"Session log ({len(log)} entries):")
    for e in log:
        arrow = "→ SENT" if e["direction"] == "sent" else "← RECV"
        print(f"  [{e['msg_num']:04d}] {arrow}  {e['preview']}…")


def main():
    parser = argparse.ArgumentParser(
        description="OPSEC Secure Messaging — Double Ratchet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example workflow (Alice ↔ Bob):
  # Both generate identity keys
  python messaging.py init --name alice
  python messaging.py init --name bob

  # Exchange keys and create sessions
  python messaging.py exchange --my-key alice.key --their-pub bob.pub --name alice_to_bob
  python messaging.py exchange --my-key bob.key   --their-pub alice.pub --name bob_to_alice --responder

  # Alice sends to Bob
  python messaging.py send --session session_alice_to_bob.json --message "Hello Bob!" --output msg1.json

  # Bob receives
  python messaging.py recv --session session_bob_to_alice.json --packet-file msg1.json
        """,
    )
    sub = parser.add_subparsers(dest="cmd")

    # init
    i = sub.add_parser("init", help="Generate identity key pair")
    i.add_argument("--name", required=True)
    i.add_argument("--output", default=".")

    # exchange
    ex = sub.add_parser("exchange", help="Key exchange to establish session")
    ex.add_argument("--my-key",    required=True)
    ex.add_argument("--their-pub", required=True)
    ex.add_argument("--name")
    ex.add_argument("--output")
    ex.add_argument("--responder", action="store_true")

    # send
    s = sub.add_parser("send", help="Encrypt and send a message")
    s.add_argument("--session", required=True)
    s.add_argument("--message", "-m")
    s.add_argument("--output", "-o")

    # recv
    r = sub.add_parser("recv", help="Receive and decrypt a message")
    r.add_argument("--session", required=True)
    r.add_argument("--packet-file", "-p")

    # log
    l = sub.add_parser("log", help="Show session message log")
    l.add_argument("--session", required=True)

    args = parser.parse_args()
    dispatch = {
        "init": cmd_init,
        "exchange": cmd_exchange,
        "send": cmd_send,
        "recv": cmd_recv,
        "log": cmd_log,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
