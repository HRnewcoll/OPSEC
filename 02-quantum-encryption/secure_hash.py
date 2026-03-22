#!/usr/bin/env python3
"""
Secure Hash Utilities
Supports: SHA-3 family, BLAKE2b/BLAKE2s, HMAC, Argon2id password hashing,
file integrity verification, and multi-file comparison.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ─────────────────────────── hashing ────────────────────────────────

ALGORITHMS = {
    "sha3-256":  lambda: hashlib.sha3_256(),
    "sha3-512":  lambda: hashlib.sha3_512(),
    "sha3-384":  lambda: hashlib.sha3_384(),
    "shake256":  lambda: hashlib.shake_256(),
    "blake2b":   lambda: hashlib.blake2b(digest_size=64),
    "blake2b-32":lambda: hashlib.blake2b(digest_size=32),
    "blake2s":   lambda: hashlib.blake2s(digest_size=32),
    "sha256":    lambda: hashlib.sha256(),
    "sha512":    lambda: hashlib.sha512(),
    "md5":       lambda: hashlib.md5(),   # legacy/insecure — included for compat
}


def hash_data(data: bytes, algorithm: str = "sha3-256") -> str:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}. Choose from: {list(ALGORITHMS)}")
    h = ALGORITHMS[algorithm]()
    h.update(data)
    if algorithm == "shake256":
        return h.hexdigest(64)
    return h.hexdigest()


def hash_file(path: str | Path, algorithm: str = "sha3-256", chunk_size: int = 65536) -> str:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    h = ALGORITHMS[algorithm]()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    if algorithm == "shake256":
        return h.hexdigest(64)
    return h.hexdigest()


def compute_hmac(data: bytes, key: bytes, algorithm: str = "sha3-256") -> str:
    # HMAC with SHA2 family (SHA3 not natively in hmac module on all platforms)
    alg = "sha256" if algorithm.startswith("sha3") else algorithm.replace("-", "")
    return hmac.new(key, data, digestmod=alg).hexdigest()


# ─────────────────────────── password hashing ───────────────────────

def hash_password(password: str) -> str:
    """Hash a password with Argon2id (or PBKDF2 fallback)."""
    if ARGON2_AVAILABLE:
        ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
        return ph.hash(password)
    # PBKDF2 fallback
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2$sha256$600000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if ARGON2_AVAILABLE and stored_hash.startswith("$argon2"):
        ph = PasswordHasher()
        try:
            return ph.verify(stored_hash, password)
        except Exception:
            return False
    if stored_hash.startswith("pbkdf2$"):
        _, alg, iters, salt_hex, dk_hex = stored_hash.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        actual = hashlib.pbkdf2_hmac(alg.replace("sha", "sha"), password.encode(), salt, int(iters))
        return hmac.compare_digest(actual, expected)
    return False


# ─────────────────────────── integrity DB ───────────────────────────

def build_integrity_db(paths: list[str], algorithm: str = "sha3-256") -> dict:
    db = {}
    for p in paths:
        path = Path(p)
        if path.is_file():
            db[str(path)] = {"hash": hash_file(path, algorithm), "algo": algorithm, "size": path.stat().st_size}
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file():
                    db[str(f)] = {"hash": hash_file(f, algorithm), "algo": algorithm, "size": f.stat().st_size}
    return db


def verify_integrity_db(db: dict) -> list[dict]:
    results = []
    for filepath, info in db.items():
        path = Path(filepath)
        if not path.exists():
            results.append({"file": filepath, "status": "MISSING"})
            continue
        current = hash_file(path, info["algo"])
        if current == info["hash"]:
            results.append({"file": filepath, "status": "OK"})
        else:
            results.append({"file": filepath, "status": "MODIFIED", "expected": info["hash"], "got": current})
    return results


# ─────────────────────────── CLI ────────────────────────────────────

def cmd_hash(args):
    alg = args.algorithm
    if args.text:
        h = hash_data(args.text.encode(), alg)
        print(f"{alg}: {h}")
    elif args.file:
        h = hash_file(args.file, alg)
        print(f"{alg}:{args.file}: {h}")
    elif args.stdin:
        data = sys.stdin.buffer.read()
        h = hash_data(data, alg)
        print(f"{alg}: {h}")
    else:
        print("[!] Provide --text, --file, or --stdin")


def cmd_hash_all(args):
    """Hash a file/text with all supported algorithms."""
    if args.file:
        data = None
        src = args.file
        for alg in sorted(ALGORITHMS):
            try:
                if data is None:
                    h = hash_file(src, alg)
                else:
                    h = hash_data(data, alg)
                print(f"{alg:<14} {h}")
            except Exception as e:
                print(f"{alg:<14} ERROR: {e}")
    elif args.text:
        data = args.text.encode()
        for alg in sorted(ALGORITHMS):
            try:
                print(f"{alg:<14} {hash_data(data, alg)}")
            except Exception as e:
                print(f"{alg:<14} ERROR: {e}")


def cmd_password(args):
    import getpass
    pw = args.password or getpass.getpass("Password: ")
    if args.verify:
        stored = args.verify
        ok = verify_password(pw, stored)
        print(f"[{'✓' if ok else '✗'}] Password {'matches' if ok else 'does NOT match'}")
    else:
        h = hash_password(pw)
        print(f"Hash: {h}")
        if ARGON2_AVAILABLE:
            print("(Argon2id — safe to store)")
        else:
            print("(PBKDF2-SHA256 — argon2-cffi not installed, consider: pip install argon2-cffi)")


def cmd_integrity(args):
    db_path = Path(args.db)
    if args.action == "create":
        db = build_integrity_db(args.paths, algorithm=args.algorithm)
        db_path.write_text(json.dumps(db, indent=2))
        print(f"[+] Integrity DB written: {db_path}  ({len(db)} files)")
    elif args.action == "verify":
        if not db_path.exists():
            print(f"[!] DB not found: {db_path}"); sys.exit(1)
        db = json.loads(db_path.read_text())
        results = verify_integrity_db(db)
        ok = modified = missing = 0
        for r in results:
            status = r["status"]
            colour = {"OK": "\033[32m", "MODIFIED": "\033[31m", "MISSING": "\033[33m"}
            reset = "\033[0m"
            print(f"{colour.get(status,'')}{status:<10}{reset} {r['file']}")
            if status == "OK": ok += 1
            elif status == "MODIFIED": modified += 1
            else: missing += 1
        print(f"\nSummary: {ok} OK, {modified} MODIFIED, {missing} MISSING")
        if modified or missing:
            sys.exit(1)


def cmd_hmac(args):
    key = args.key.encode()
    data = args.text.encode() if args.text else Path(args.file).read_bytes()
    result = compute_hmac(data, key, args.algorithm)
    print(f"HMAC-{args.algorithm}: {result}")


def main():
    parser = argparse.ArgumentParser(description="OPSEC Secure Hash Utilities")
    sub = parser.add_subparsers(dest="cmd")

    # hash
    h = sub.add_parser("hash", help="Hash text or file")
    h.add_argument("--algorithm", "-a", default="sha3-256", choices=list(ALGORITHMS))
    h.add_argument("--text", "-t")
    h.add_argument("--file", "-f")
    h.add_argument("--stdin", action="store_true")

    # hash-all
    ha = sub.add_parser("hash-all", help="Hash with all algorithms")
    ha.add_argument("--text", "-t")
    ha.add_argument("--file", "-f")

    # password
    pw = sub.add_parser("password", help="Hash or verify passwords with Argon2id")
    pw.add_argument("--password", "-p")
    pw.add_argument("--verify", "-v", help="Stored hash to verify against")

    # integrity
    ig = sub.add_parser("integrity", help="File integrity database")
    ig.add_argument("action", choices=["create", "verify"])
    ig.add_argument("--paths", nargs="*", default=["."])
    ig.add_argument("--db", default="integrity.json")
    ig.add_argument("--algorithm", "-a", default="sha3-256", choices=list(ALGORITHMS))

    # hmac
    hm = sub.add_parser("hmac", help="Compute HMAC")
    hm.add_argument("--key", required=True)
    hm.add_argument("--text")
    hm.add_argument("--file")
    hm.add_argument("--algorithm", "-a", default="sha256", choices=["sha256", "sha512", "blake2b"])

    args = parser.parse_args()
    dispatch = {
        "hash": cmd_hash,
        "hash-all": cmd_hash_all,
        "password": cmd_password,
        "integrity": cmd_integrity,
        "hmac": cmd_hmac,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
