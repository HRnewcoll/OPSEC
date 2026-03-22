#!/usr/bin/env python3
"""
OPSEC Hash Tools
=================
Multi-algorithm file and text hashing, hash comparison,
breach/malware hash lookup, and hash cracking utilities.

Usage:
  python hash_tools.py hash --file document.pdf
  python hash_tools.py hash --text "hello world" --algorithm sha3-256
  python hash_tools.py compare --hash1 <h1> --hash2 <h2>
  python hash_tools.py crack --hash <md5_hash> --wordlist rockyou.txt
  python hash_tools.py identify --hash <unknown_hash>
  python hash_tools.py malware-check --hash <sha256>
  python hash_tools.py batch --dir /path/to/files --output hashes.csv
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


ALGORITHMS = {
    "md5":        lambda: hashlib.md5(),
    "sha1":       lambda: hashlib.sha1(),
    "sha224":     lambda: hashlib.sha224(),
    "sha256":     lambda: hashlib.sha256(),
    "sha384":     lambda: hashlib.sha384(),
    "sha512":     lambda: hashlib.sha512(),
    "sha3-224":   lambda: hashlib.sha3_224(),
    "sha3-256":   lambda: hashlib.sha3_256(),
    "sha3-384":   lambda: hashlib.sha3_384(),
    "sha3-512":   lambda: hashlib.sha3_512(),
    "blake2b":    lambda: hashlib.blake2b(digest_size=64),
    "blake2s":    lambda: hashlib.blake2s(digest_size=32),
    "shake-256":  None,  # special case
}

# Hash length → likely algorithms (for identification)
HASH_LENGTHS = {
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224"],
    64:  ["sha256", "blake2s"],
    96:  ["sha384"],
    128: ["sha512", "sha3-512", "blake2b"],
    56:  ["sha3-224"],
    64:  ["sha3-256"],
    96:  ["sha3-384"],
}


# ─────────────────────────── core hashing ───────────────────────────

def hash_data(data: bytes, algorithm: str) -> str:
    if algorithm == "shake-256":
        h = hashlib.shake_256()
        h.update(data)
        return h.hexdigest(64)
    h = ALGORITHMS[algorithm]()
    h.update(data)
    return h.hexdigest()


def hash_file(path: Path, algorithm: str, chunk_size: int = 65536) -> str:
    if algorithm == "shake-256":
        h = hashlib.shake_256()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest(64)
    h = ALGORITHMS[algorithm]()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_all_algorithms(data: bytes) -> dict[str, str]:
    results = {}
    for alg in ALGORITHMS:
        try:
            results[alg] = hash_data(data, alg)
        except Exception as e:
            results[alg] = f"ERROR: {e}"
    return results


# ─────────────────────────── identification ─────────────────────────

def identify_hash(hash_str: str) -> list[str]:
    """Identify likely algorithm(s) for a hash string."""
    h = hash_str.strip().lower()
    length = len(h)
    # Check hex validity
    if not all(c in "0123456789abcdef" for c in h):
        return ["Invalid hex string — may be bcrypt, argon2, or base64-encoded"]
    candidates = HASH_LENGTHS.get(length, [])
    # Special patterns
    if h.startswith("$2") and "$" in h[3:]:
        return ["bcrypt"]
    if h.startswith("$argon2"):
        return ["argon2id/argon2i/argon2d"]
    if h.startswith("$pbkdf2"):
        return ["PBKDF2"]
    if length == 32:
        return ["MD5 (insecure — avoid for integrity, NEVER for passwords)"]
    if length == 40:
        return ["SHA-1 (deprecated — avoid for new designs)"]
    if length == 64:
        return ["SHA-256 or SHA3-256 or BLAKE2s-256"]
    if length == 128:
        return ["SHA-512 or SHA3-512 or BLAKE2b-512"]
    return candidates or [f"Unknown ({length} hex chars)"]


# ─────────────────────────── comparison ─────────────────────────────

def compare_hashes(h1: str, h2: str) -> bool:
    return hmac.compare_digest(h1.strip().lower(), h2.strip().lower())


# ─────────────────────────── dictionary crack ────────────────────────

def crack_hash(target_hash: str, algorithm: str, wordlist_path: Path,
               rules: bool = False) -> str | None:
    """Attempt to crack a hash by trying words from a wordlist."""
    target = target_hash.strip().lower()
    count = 0
    start = time.time()
    try:
        with open(wordlist_path, "rb") as f:
            for line in f:
                word = line.rstrip(b"\n\r")
                count += 1
                candidate = hash_data(word, algorithm)
                if hmac.compare_digest(candidate, target):
                    elapsed = time.time() - start
                    print(f"[+] CRACKED after {count:,} attempts ({elapsed:.2f}s)")
                    return word.decode("utf-8", errors="replace")
                if rules:
                    # Common rules: uppercase, reverse, append digits
                    variants = [
                        word.upper(), word.lower(), word.capitalize(),
                        word + b"1", word + b"123", word + b"!",
                        word[::-1],
                    ]
                    for v in variants:
                        if hmac.compare_digest(hash_data(v, algorithm), target):
                            elapsed = time.time() - start
                            print(f"[+] CRACKED (rule) after {count:,} attempts ({elapsed:.2f}s)")
                            return v.decode("utf-8", errors="replace")
                if count % 100000 == 0:
                    elapsed = time.time() - start
                    rate = count / elapsed if elapsed > 0 else 0
                    print(f"    … {count:,} tried ({rate:,.0f}/s)", end="\r")
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted after {count:,} attempts")
    elapsed = time.time() - start
    print(f"\n[-] Not found ({count:,} tried in {elapsed:.2f}s)")
    return None


# ─────────────────────────── malware hash check ─────────────────────

def check_malware_hash(sha256_hash: str) -> dict:
    """Check hash against MalwareBazaar (free, no API key)."""
    result = {"hash": sha256_hash, "malware": None, "error": None}
    url = "https://mb-api.abuse.ch/api/v1/"
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha256_hash}).encode()
    try:
        req = urllib.request.Request(url, data=data,
                                     headers={"User-Agent": "OPSEC-HashTools/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_data = json.loads(resp.read())
            if resp_data.get("query_status") == "ok":
                result["malware"] = True
                result["details"] = resp_data.get("data", [{}])[0]
            else:
                result["malware"] = False
                result["status"] = resp_data.get("query_status")
    except Exception as e:
        result["error"] = str(e)
    return result


def check_virustotal_link(sha256_hash: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha256_hash}"


# ─────────────────────────── batch hashing ──────────────────────────

def batch_hash_dir(directory: Path, algorithm: str = "sha256") -> list[dict]:
    results = []
    files = [f for f in directory.rglob("*") if f.is_file()]
    print(f"[*] Hashing {len(files)} files with {algorithm} …")
    for f in files:
        try:
            h = hash_file(f, algorithm)
            size = f.stat().st_size
            results.append({
                "file": str(f),
                "hash": h,
                "algorithm": algorithm,
                "size": size,
            })
        except Exception as e:
            results.append({"file": str(f), "hash": None, "error": str(e)})
    return results


# ─────────────────────────── CLI ────────────────────────────────────

def cmd_hash(args):
    alg = args.algorithm
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[!] File not found: {path}"); sys.exit(1)
        if args.all:
            data = path.read_bytes()
            for a, h in hash_all_algorithms(data).items():
                print(f"{a:<14} {h}")
        else:
            h = hash_file(path, alg)
            print(f"{alg}: {h}")
            print(f"File: {path}  ({path.stat().st_size:,} bytes)")
    elif args.text:
        data = args.text.encode()
        if args.all:
            for a, h in hash_all_algorithms(data).items():
                print(f"{a:<14} {h}")
        else:
            print(f"{alg}: {hash_data(data, alg)}")
    else:
        data = sys.stdin.buffer.read()
        print(f"{alg}: {hash_data(data, alg)}")


def cmd_compare(args):
    match = compare_hashes(args.hash1, args.hash2)
    print(f"{'✓ MATCH' if match else '✗ DO NOT MATCH'}")
    print(f"  h1: {args.hash1[:32]}…")
    print(f"  h2: {args.hash2[:32]}…")
    sys.exit(0 if match else 1)


def cmd_identify(args):
    candidates = identify_hash(args.hash)
    print(f"Hash : {args.hash[:32]}…  (length: {len(args.hash.strip())} chars)")
    print(f"Likely: {', '.join(candidates)}")


def cmd_crack(args):
    target = args.hash.strip().lower()
    wl = Path(args.wordlist)
    if not wl.exists():
        print(f"[!] Wordlist not found: {wl}"); sys.exit(1)
    print(f"[*] Cracking {args.algorithm} hash: {target[:20]}…")
    print(f"    Wordlist: {wl}  ({wl.stat().st_size:,} bytes)")
    result = crack_hash(target, args.algorithm, wl, rules=args.rules)
    if result:
        print(f"\n[+] PASSWORD FOUND: {result}")
    else:
        print("\n[-] Hash not cracked.")


def cmd_malware(args):
    h = args.hash.strip().lower()
    print(f"[*] Checking MalwareBazaar: {h[:20]}…")
    result = check_malware_hash(h)
    print(json.dumps(result, indent=2))
    print(f"\nVirusTotal: {check_virustotal_link(h)}")


def cmd_batch(args):
    directory = Path(args.dir)
    if not directory.exists():
        print(f"[!] Directory not found: {directory}"); sys.exit(1)
    results = batch_hash_dir(directory, algorithm=args.algorithm)
    out = Path(args.output)
    if out.suffix.lower() == ".json":
        out.write_text(json.dumps(results, indent=2))
    else:
        with open(out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["file", "hash", "algorithm", "size"])
            writer.writeheader()
            writer.writerows(r for r in results if "error" not in r)
    print(f"[+] {len(results)} hashes → {out}")


def main():
    parser = argparse.ArgumentParser(description="OPSEC Hash Tools")
    sub = parser.add_subparsers(dest="cmd")

    # hash
    h = sub.add_parser("hash", help="Hash files or text")
    h.add_argument("--file", "-f")
    h.add_argument("--text", "-t")
    h.add_argument("--algorithm", "-a", default="sha256", choices=list(ALGORITHMS))
    h.add_argument("--all", action="store_true", help="Hash with ALL algorithms")

    # compare
    c = sub.add_parser("compare", help="Compare two hashes (constant-time)")
    c.add_argument("--hash1", required=True)
    c.add_argument("--hash2", required=True)

    # identify
    i = sub.add_parser("identify", help="Identify likely hash algorithm")
    i.add_argument("--hash", required=True)

    # crack
    cr = sub.add_parser("crack", help="Dictionary attack against a hash")
    cr.add_argument("--hash", required=True)
    cr.add_argument("--wordlist", required=True)
    cr.add_argument("--algorithm", "-a", default="md5", choices=list(ALGORITHMS))
    cr.add_argument("--rules", action="store_true", help="Apply common mutation rules")

    # malware check
    m = sub.add_parser("malware-check", help="Check SHA256 against MalwareBazaar")
    m.add_argument("--hash", required=True)

    # batch
    b = sub.add_parser("batch", help="Hash all files in a directory")
    b.add_argument("--dir", required=True)
    b.add_argument("--output", default="hashes.csv")
    b.add_argument("--algorithm", "-a", default="sha256", choices=list(ALGORITHMS))

    args = parser.parse_args()
    dispatch = {
        "hash": cmd_hash, "compare": cmd_compare, "identify": cmd_identify,
        "crack": cmd_crack, "malware-check": cmd_malware, "batch": cmd_batch,
    }
    if args.cmd in dispatch:
        dispatch[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
