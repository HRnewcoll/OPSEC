#!/usr/bin/env python3
"""
OPSEC Secure File Sharing
=========================
Encrypt files into chunks with AES-256-GCM + BLAKE2b integrity,
then reassemble and decrypt. Suitable for splitting across multiple
channels for plausible deniability.

Features:
  - AES-256-GCM per-chunk encryption
  - BLAKE2b file integrity
  - Argon2id / PBKDF2 key derivation
  - Chunk manifest with HMAC
  - Optional compression (zlib)
  - CLI interface

Usage:
  python file_share.py split   --in secret.pdf --out chunks/ --password "strong pass" --chunks 5
  python file_share.py join    --chunks chunks/ --out recovered.pdf --password "strong pass"
  python file_share.py encrypt --in file.pdf --out file.enc --password "pass"
  python file_share.py decrypt --in file.enc --out file.pdf --password "pass"
  python file_share.py verify  --in file.pdf --hash-file file.sha3
"""

import argparse
import hashlib
import hmac as _hmac
import json
import math
import os
import sys
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2 = True
except ImportError:
    ARGON2 = False

MAGIC_FILE = b"OPSECFS1"
MAGIC_CHUNK = b"OPSCHUNK"


# ─────────────────────────── key derivation ─────────────────────────

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    if ARGON2:
        return hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536,
                               parallelism=2, hash_len=length, type=Type.ID)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000, dklen=length)


# ─────────────────────────── encrypt/decrypt single file ────────────

def encrypt_file(in_path: Path, out_path: Path, password: str, compress: bool = True):
    data = in_path.read_bytes()
    original_size = len(data)
    original_hash = hashlib.blake2b(data).hexdigest()

    if compress:
        data = zlib.compress(data, level=6)

    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, None)

    meta = json.dumps({
        "original_name": in_path.name,
        "original_size": original_size,
        "original_hash": original_hash,
        "compressed": compress,
        "algo": "AES-256-GCM",
        "kdf": "argon2id" if ARGON2 else "pbkdf2-sha256",
    }).encode()
    meta_len = len(meta).to_bytes(4, "big")

    out_path.write_bytes(MAGIC_FILE + meta_len + meta + salt + nonce + ct)
    print(f"[+] Encrypted: {in_path.name} → {out_path.name}")
    print(f"    Original size : {original_size:,} bytes")
    print(f"    Encrypted size: {out_path.stat().st_size:,} bytes")
    print(f"    BLAKE2b hash  : {original_hash[:32]}…")


def decrypt_file(in_path: Path, out_path: Path, password: str):
    raw = in_path.read_bytes()
    if not raw.startswith(MAGIC_FILE):
        raise ValueError("Not a valid OPSEC encrypted file (missing magic bytes)")

    offset = len(MAGIC_FILE)
    meta_len = int.from_bytes(raw[offset:offset + 4], "big")
    offset += 4
    meta = json.loads(raw[offset:offset + meta_len])
    offset += meta_len
    salt  = raw[offset:offset + 32]
    nonce = raw[offset + 32:offset + 44]
    ct    = raw[offset + 44:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        data = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or corrupted file")

    if meta.get("compressed"):
        data = zlib.decompress(data)

    actual_hash = hashlib.blake2b(data).hexdigest()
    if actual_hash != meta.get("original_hash"):
        raise ValueError(f"Integrity check FAILED!\nExpected: {meta['original_hash']}\nGot:      {actual_hash}")

    out_path.write_bytes(data)
    print(f"[+] Decrypted: {in_path.name} → {out_path.name}")
    print(f"    Size          : {len(data):,} bytes")
    print(f"    Integrity      : ✓ BLAKE2b match")
    print(f"    Original name  : {meta.get('original_name','unknown')}")


# ─────────────────────────── chunk split / join ─────────────────────

def split_file(in_path: Path, out_dir: Path, password: str, n_chunks: int = 5, compress: bool = True):
    out_dir.mkdir(parents=True, exist_ok=True)
    data = in_path.read_bytes()
    original_size = len(data)
    original_hash = hashlib.blake2b(data).hexdigest()

    if compress:
        data = zlib.compress(data, level=6)

    chunk_size = math.ceil(len(data) / n_chunks)
    chunks_data = [data[i * chunk_size:(i + 1) * chunk_size] for i in range(n_chunks)]
    actual_chunks = [c for c in chunks_data if c]

    master_salt = os.urandom(32)
    master_key  = derive_key(password, master_salt, length=64)
    enc_key   = master_key[:32]
    hmac_key  = master_key[32:]

    manifest = {
        "original_name": in_path.name,
        "original_size": original_size,
        "original_hash": original_hash,
        "compressed": compress,
        "n_chunks": len(actual_chunks),
        "chunks": [],
        "master_salt": master_salt.hex(),
        "kdf": "argon2id" if ARGON2 else "pbkdf2-sha256",
    }

    for i, chunk in enumerate(actual_chunks):
        chunk_salt  = os.urandom(32)
        chunk_nonce = os.urandom(12)
        chunk_key   = derive_key(password, chunk_salt + i.to_bytes(4, "big"))
        aesgcm = AESGCM(chunk_key)
        enc_chunk = aesgcm.encrypt(chunk_nonce, chunk, i.to_bytes(4, "big"))

        chunk_hash = hashlib.blake2b(chunk).hexdigest()
        chunk_file = out_dir / f"chunk_{i:04d}.bin"
        chunk_file.write_bytes(MAGIC_CHUNK + chunk_salt + chunk_nonce + enc_chunk)

        manifest["chunks"].append({
            "index": i,
            "file": chunk_file.name,
            "hash": chunk_hash,
            "size": len(chunk),
        })
        print(f"    Chunk {i:02d}: {chunk_file.name}  ({len(enc_chunk):,} bytes)")

    # HMAC over manifest
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode()
    mac = _hmac.new(hmac_key, manifest_json, digestmod="sha256").hexdigest()
    manifest["hmac"] = mac

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    manifest_path.chmod(0o600)

    print(f"[+] Split {in_path.name} into {len(actual_chunks)} chunks → {out_dir}")
    print(f"    Manifest: {manifest_path}")
    print(f"    BLAKE2b : {original_hash[:32]}…")


def join_file(chunks_dir: Path, out_path: Path, password: str):
    manifest_path = chunks_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found in {chunks_dir}")

    manifest = json.loads(manifest_path.read_text())
    master_salt = bytes.fromhex(manifest["master_salt"])
    master_key  = derive_key(password, master_salt, length=64)
    hmac_key    = master_key[32:]

    # Verify manifest HMAC
    stored_hmac = manifest.pop("hmac", None)
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode()
    computed_mac  = _hmac.new(hmac_key, manifest_json, digestmod="sha256").hexdigest()
    if stored_hmac and not _hmac.compare_digest(stored_hmac, computed_mac):
        raise ValueError("Manifest HMAC verification FAILED — manifest may have been tampered!")
    manifest["hmac"] = stored_hmac

    chunks_data = []
    for ch in sorted(manifest["chunks"], key=lambda x: x["index"]):
        chunk_path = chunks_dir / ch["file"]
        raw = chunk_path.read_bytes()
        if not raw.startswith(MAGIC_CHUNK):
            raise ValueError(f"Invalid chunk file: {chunk_path}")
        i = ch["index"]
        chunk_salt  = raw[len(MAGIC_CHUNK):len(MAGIC_CHUNK) + 32]
        chunk_nonce = raw[len(MAGIC_CHUNK) + 32:len(MAGIC_CHUNK) + 44]
        enc_chunk   = raw[len(MAGIC_CHUNK) + 44:]
        chunk_key = derive_key(password, chunk_salt + i.to_bytes(4, "big"))
        aesgcm = AESGCM(chunk_key)
        try:
            chunk = aesgcm.decrypt(chunk_nonce, enc_chunk, i.to_bytes(4, "big"))
        except Exception:
            raise ValueError(f"Chunk {i} decryption failed — wrong password or corrupted")

        actual_hash = hashlib.blake2b(chunk).hexdigest()
        if actual_hash != ch["hash"]:
            raise ValueError(f"Chunk {i} integrity FAILED")
        chunks_data.append(chunk)
        print(f"    Chunk {i:02d}: ✓")

    data = b"".join(chunks_data)
    if manifest.get("compressed"):
        data = zlib.decompress(data)

    actual_hash = hashlib.blake2b(data).hexdigest()
    if actual_hash != manifest["original_hash"]:
        raise ValueError("Final file integrity check FAILED")

    out_path.write_bytes(data)
    print(f"[+] Reassembled → {out_path}")
    print(f"    Size     : {len(data):,} bytes")
    print(f"    Integrity: ✓ BLAKE2b match")


def verify_file(in_path: Path, hash_file: Path | None = None):
    data = in_path.read_bytes()
    b2 = hashlib.blake2b(data).hexdigest()
    s256 = hashlib.sha256(data).hexdigest()
    s3 = hashlib.sha3_256(data).hexdigest()
    print(f"File: {in_path}")
    print(f"  BLAKE2b-512 : {b2}")
    print(f"  SHA-256     : {s256}")
    print(f"  SHA3-256    : {s3}")
    print(f"  Size        : {len(data):,} bytes")
    if hash_file:
        expected = hash_file.read_text().strip().split()[0]
        match = expected in (b2, s256, s3)
        print(f"  Hash check  : {'✓ MATCH' if match else '✗ MISMATCH'}")


# ─────────────────────────── CLI ────────────────────────────────────

def main():
    import getpass
    parser = argparse.ArgumentParser(description="OPSEC Secure File Sharing")
    sub = parser.add_subparsers(dest="cmd")

    enc = sub.add_parser("encrypt", help="Encrypt a single file")
    enc.add_argument("--in", dest="input", required=True)
    enc.add_argument("--out", dest="output", required=True)
    enc.add_argument("--password")
    enc.add_argument("--no-compress", action="store_true")

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--in", dest="input", required=True)
    dec.add_argument("--out", dest="output", required=True)
    dec.add_argument("--password")

    sp = sub.add_parser("split", help="Split & encrypt file into chunks")
    sp.add_argument("--in", dest="input", required=True)
    sp.add_argument("--out", dest="output", default="./chunks")
    sp.add_argument("--chunks", type=int, default=5)
    sp.add_argument("--password")
    sp.add_argument("--no-compress", action="store_true")

    jn = sub.add_parser("join", help="Reassemble & decrypt chunks")
    jn.add_argument("--chunks", required=True, help="Directory containing chunks + manifest")
    jn.add_argument("--out", dest="output", required=True)
    jn.add_argument("--password")

    vf = sub.add_parser("verify", help="Verify file hashes")
    vf.add_argument("--in", dest="input", required=True)
    vf.add_argument("--hash-file")

    args = parser.parse_args()

    def get_password(a):
        return a.password or getpass.getpass("Password: ")

    try:
        if args.cmd == "encrypt":
            encrypt_file(Path(args.input), Path(args.output), get_password(args), not args.no_compress)
        elif args.cmd == "decrypt":
            decrypt_file(Path(args.input), Path(args.output), get_password(args))
        elif args.cmd == "split":
            split_file(Path(args.input), Path(args.output), get_password(args), args.chunks, not args.no_compress)
        elif args.cmd == "join":
            join_file(Path(args.chunks), Path(args.output), get_password(args))
        elif args.cmd == "verify":
            verify_file(Path(args.input), Path(args.hash_file) if args.hash_file else None)
        else:
            parser.print_help()
    except (ValueError, FileNotFoundError) as e:
        print(f"[!] {e}"); sys.exit(1)


if __name__ == "__main__":
    main()
