#!/usr/bin/env python3
"""
OPSEC Encryption Tool
Hybrid encryption: AES-256-GCM (symmetric) + X25519 ECDH (key exchange)
Key derivation: Argon2id

Usage examples:
  python encrypt.py keygen --out keys/
  python encrypt.py encrypt --pub keys/recipient.pub --in secret.txt --out secret.enc
  python encrypt.py decrypt --priv keys/my.key --in secret.enc --out secret.txt
  python encrypt.py encrypt-sym --in secret.txt --out secret.enc    (password-based)
  python encrypt.py decrypt-sym --in secret.enc --out secret.txt
"""

import argparse
import json
import os
import struct
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

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

import hashlib
import getpass


MAGIC = b"OPSEC01"   # file format magic bytes
VERSION = 1


# ─────────────────────────── key derivation ─────────────────────────

def derive_key_argon2(password: str, salt: bytes, key_len: int = 32) -> bytes:
    if ARGON2_AVAILABLE:
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            hash_len=key_len,
            type=Type.ID,
        )
    # Fallback: PBKDF2-HMAC-SHA256 (weaker, but always available)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=key_len)


def derive_key_hkdf(shared_secret: bytes, salt: bytes | None = None, info: bytes = b"opsec-enc") -> bytes:
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=info, backend=default_backend())
    return hkdf.derive(shared_secret)


# ─────────────────────────── key pair ───────────────────────────────

def generate_keypair() -> tuple[X25519PrivateKey, bytes, bytes]:
    """Return (priv_key_obj, pem_priv, pem_pub)."""
    priv = X25519PrivateKey.generate()
    pem_priv = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pem_pub = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv, pem_priv, pem_pub


# ─────────────────────────── symmetric (password) ───────────────────

def encrypt_symmetric(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = derive_key_argon2(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Format: MAGIC | VERSION(1) | MODE(1) | salt(32) | nonce(12) | ciphertext
    return MAGIC + bytes([VERSION, 0x01]) + salt + nonce + ciphertext


def decrypt_symmetric(data: bytes, password: str) -> bytes:
    if not data.startswith(MAGIC):
        raise ValueError("Invalid file format (missing magic bytes)")
    offset = len(MAGIC) + 2
    mode = data[len(MAGIC) + 1]
    if mode != 0x01:
        raise ValueError("Not a symmetric-encrypted file")
    salt = data[offset:offset + 32]
    nonce = data[offset + 32:offset + 44]
    ciphertext = data[offset + 44:]
    key = derive_key_argon2(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─────────────────────────── asymmetric (X25519) ────────────────────

def encrypt_asymmetric(plaintext: bytes, recipient_pub_pem: bytes) -> bytes:
    """Encrypt for a recipient given their X25519 public key PEM."""
    recipient_pub = load_pem_public_key(recipient_pub_pem)
    # Ephemeral keypair
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # ECDH shared secret
    shared = eph_priv.exchange(recipient_pub)
    # Derive AES key
    salt = os.urandom(32)
    key = derive_key_hkdf(shared, salt=salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Format: MAGIC | VERSION(1) | MODE(1) | eph_pub(32) | salt(32) | nonce(12) | ciphertext
    return MAGIC + bytes([VERSION, 0x02]) + eph_pub_bytes + salt + nonce + ciphertext


def decrypt_asymmetric(data: bytes, recipient_priv_pem: bytes) -> bytes:
    if not data.startswith(MAGIC):
        raise ValueError("Invalid file format")
    mode = data[len(MAGIC) + 1]
    if mode != 0x02:
        raise ValueError("Not an asymmetric-encrypted file")
    offset = len(MAGIC) + 2
    eph_pub_bytes = data[offset:offset + 32]
    salt = data[offset + 32:offset + 64]
    nonce = data[offset + 64:offset + 76]
    ciphertext = data[offset + 76:]

    priv = load_pem_private_key(recipient_priv_pem, password=None)
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared = priv.exchange(eph_pub)
    key = derive_key_hkdf(shared, salt=salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─────────────────────────── CLI ────────────────────────────────────

def cmd_keygen(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    _, pem_priv, pem_pub = generate_keypair()
    priv_file = out / f"{args.name}.key"
    pub_file  = out / f"{args.name}.pub"
    priv_file.write_bytes(pem_priv)
    priv_file.chmod(0o600)
    pub_file.write_bytes(pem_pub)
    print(f"[+] Private key → {priv_file}  (keep secret!)")
    print(f"[+] Public key  → {pub_file}   (share freely)")


def cmd_encrypt(args):
    indata = Path(args.input).read_bytes()
    pub_pem = Path(args.pub).read_bytes()
    enc = encrypt_asymmetric(indata, pub_pem)
    Path(args.output).write_bytes(enc)
    print(f"[+] Encrypted → {args.output}  ({len(enc)} bytes)")


def cmd_decrypt(args):
    indata = Path(args.input).read_bytes()
    priv_pem = Path(args.priv).read_bytes()
    plain = decrypt_asymmetric(indata, priv_pem)
    Path(args.output).write_bytes(plain)
    print(f"[+] Decrypted → {args.output}  ({len(plain)} bytes)")


def cmd_encrypt_sym(args):
    password = getpass.getpass("Password: ")
    confirm  = getpass.getpass("Confirm : ")
    if password != confirm:
        print("[!] Passwords do not match."); sys.exit(1)
    indata = Path(args.input).read_bytes()
    enc = encrypt_symmetric(indata, password)
    Path(args.output).write_bytes(enc)
    print(f"[+] Encrypted → {args.output}  ({len(enc)} bytes)")


def cmd_decrypt_sym(args):
    password = getpass.getpass("Password: ")
    indata = Path(args.input).read_bytes()
    try:
        plain = decrypt_symmetric(indata, password)
    except Exception as e:
        print(f"[!] Decryption failed: {e}"); sys.exit(1)
    Path(args.output).write_bytes(plain)
    print(f"[+] Decrypted → {args.output}  ({len(plain)} bytes)")


def main():
    parser = argparse.ArgumentParser(
        description="OPSEC Hybrid Encryption (AES-256-GCM + X25519)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  keygen        Generate X25519 key pair
  encrypt       Encrypt with recipient public key (asymmetric)
  decrypt       Decrypt with private key
  encrypt-sym   Encrypt with password (Argon2id + AES-256-GCM)
  decrypt-sym   Decrypt password-encrypted file
        """,
    )
    sub = parser.add_subparsers(dest="cmd")

    kg = sub.add_parser("keygen")
    kg.add_argument("--out", default="./keys")
    kg.add_argument("--name", default="my_key")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--pub", required=True, help="Recipient public key PEM")
    enc.add_argument("--in", dest="input", required=True)
    enc.add_argument("--out", dest="output", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--priv", required=True, help="Your private key PEM")
    dec.add_argument("--in", dest="input", required=True)
    dec.add_argument("--out", dest="output", required=True)

    encs = sub.add_parser("encrypt-sym")
    encs.add_argument("--in", dest="input", required=True)
    encs.add_argument("--out", dest="output", required=True)

    decs = sub.add_parser("decrypt-sym")
    decs.add_argument("--in", dest="input", required=True)
    decs.add_argument("--out", dest="output", required=True)

    args = parser.parse_args()
    dispatch = {
        "keygen": cmd_keygen,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "encrypt-sym": cmd_encrypt_sym,
        "decrypt-sym": cmd_decrypt_sym,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
