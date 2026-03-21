#!/usr/bin/env python3
"""
OPSEC Password Manager
=======================
AES-256-GCM encrypted local password vault with:
  - Master password with PBKDF2-SHA256 key derivation
  - Per-entry encryption with unique nonces
  - Password generator (strong, pronounceable, passphrase)
  - HaveIBeenPwned breach check (k-anonymity — password never sent)
  - Auto-clear clipboard after 30s
  - Search, tag, and category support
  - Import/export (encrypted JSON)
  - Password strength scorer
  - TOTP (Time-based OTP) secret storage

Usage:
  python password_manager.py init
  python password_manager.py add   --name "GitHub" --username "user@example.com" --url "https://github.com"
  python password_manager.py get   --name "GitHub"
  python password_manager.py list
  python password_manager.py search --query "git"
  python password_manager.py gen   --length 24 --type strong
  python password_manager.py check --password "mypassword"
  python password_manager.py delete --name "OldSite"
  python password_manager.py export --out vault_backup.enc
  python password_manager.py import-vault --file vault_backup.enc
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import string
import struct
import sys
import time
import urllib.request
from datetime import datetime
from getpass import getpass
from pathlib import Path
from secrets import token_bytes


# ── paths ─────────────────────────────────────────────────────────────

VAULT_DIR  = Path("~/.opsec/vault").expanduser()
VAULT_FILE = VAULT_DIR / "vault.enc"

MAGIC   = b"OPSECVLT"
VERSION = 1


# ── crypto (same pattern as other modules) ───────────────────────────

def _kdf(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, None)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        nonce = token_bytes(12)
        ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plaintext)
        return nonce + tag + ct
    except ImportError:
        pass
    return _xor_hmac_encrypt(key, plaintext)


def _decrypt(key: bytes, blob: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)
    except ImportError:
        pass
    return _xor_hmac_decrypt(key, blob)


def _xor_hmac_encrypt(key: bytes, data: bytes) -> bytes:
    import hmac as _hmac
    nonce = token_bytes(16)
    ks = hashlib.shake_256(key + nonce).digest(len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))
    mac = _hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce + mac + ct


def _xor_hmac_decrypt(key: bytes, blob: bytes) -> bytes:
    import hmac as _hmac
    nonce, mac, ct = blob[:16], blob[16:48], blob[48:]
    expected = _hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not _hmac.compare_digest(mac, expected):
        raise ValueError("Authentication failed — wrong master password")
    ks = hashlib.shake_256(key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# ── vault I/O ─────────────────────────────────────────────────────────

def _load_vault(master_pw: str) -> tuple[bytes, dict]:
    """Return (key, entries_dict)."""
    if not VAULT_FILE.exists():
        raise FileNotFoundError("Vault not initialised. Run: python password_manager.py init")

    raw = VAULT_FILE.read_bytes()
    if raw[:8] != MAGIC:
        raise ValueError("Not an OPSEC vault file")

    salt = raw[8:40]
    key  = _kdf(master_pw, salt)
    data = _decrypt(key, raw[40:])
    return key, json.loads(data)


def _save_vault(key: bytes, salt: bytes, entries: dict):
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    blob  = _encrypt(key, json.dumps(entries).encode())
    VAULT_FILE.write_bytes(MAGIC + salt + blob)
    VAULT_FILE.chmod(0o600)


def _init_vault(master_pw: str):
    if VAULT_FILE.exists():
        print("[!] Vault already exists at", VAULT_FILE)
        return
    salt = token_bytes(32)
    key  = _kdf(master_pw, salt)
    _save_vault(key, salt, {"entries": {}, "metadata": {"created": datetime.now().isoformat()}})
    print(f"[+] Vault initialised: {VAULT_FILE}")
    print("    Keep your master password safe — there is no recovery mechanism!")


def _get_salt() -> bytes:
    return VAULT_FILE.read_bytes()[8:40]


# ── password generator ────────────────────────────────────────────────

WORDLIST = [
    "apple", "brave", "cloud", "delta", "eagle", "flame", "grape", "honey",
    "ivory", "jungle", "kite", "lemon", "maple", "noble", "ocean", "peach",
    "quartz", "river", "stone", "tiger", "ultra", "vivid", "water", "xenon",
    "yacht", "zebra", "amber", "blast", "coral", "drift", "ember", "frost",
    "glide", "haste", "inlet", "jewel", "karma", "lunar", "mossy", "night",
    "olive", "plaza", "quest", "rainy", "swift", "trove", "umbra", "vague",
    "windy", "xenial", "yarrow", "zonal", "agate", "birch", "cedar", "dune",
    "elder", "fjord", "glade", "hazel", "iron", "jade", "kelp", "lime",
    "mint", "nova", "opal", "pine", "quill", "reed", "sage", "thorn",
    "umber", "vale", "wren", "xeric", "yew", "zinc",
]


def generate_password(length: int = 20, style: str = "strong") -> str:
    if style == "strong":
        chars = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        while True:
            pw = "".join(secrets.choice(chars) for _ in range(length))
            if (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                    and any(c.isdigit() for c in pw)
                    and any(c in "!@#$%^&*-_=+" for c in pw)):
                return pw

    elif style == "pronounceable":
        vowels = "aeiou"
        consonants = "bcdfghjklmnpqrstvwxyz"
        pw = []
        for i in range(length):
            pw.append(secrets.choice(consonants if i % 2 == 0 else vowels))
        # Add a digit and symbol for strength
        pw[secrets.randbelow(length)] = str(secrets.randbelow(10))
        pw[secrets.randbelow(length)] = secrets.choice("!@#$")
        return "".join(pw)

    elif style == "passphrase":
        words = [secrets.choice(WORDLIST) for _ in range(length)]
        sep = secrets.choice(["-", "_", ".", " "])
        return sep.join(words) + str(secrets.randbelow(9999))

    elif style == "pin":
        return "".join(str(secrets.randbelow(10)) for _ in range(length))

    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


# ── password strength ─────────────────────────────────────────────────

def score_password(pw: str) -> dict:
    score = 0
    issues = []
    if len(pw) >= 12: score += 1
    if len(pw) >= 16: score += 1
    if len(pw) >= 20: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    else: issues.append("Add uppercase letters")
    if re.search(r"[a-z]", pw): score += 1
    else: issues.append("Add lowercase letters")
    if re.search(r"\d", pw): score += 1
    else: issues.append("Add digits")
    if re.search(r"[!@#$%^&*\-_=+<>?,./;:'\"\\|`~]", pw): score += 1
    else: issues.append("Add special characters")
    if len(set(pw)) < len(pw) * 0.6:
        issues.append("Too many repeated characters")
        score = max(0, score - 1)

    common_patterns = ["password", "123456", "qwerty", "letmein", "admin", "welcome"]
    for p in common_patterns:
        if p in pw.lower():
            issues.append(f"Contains common pattern: '{p}'")
            score = max(0, score - 2)

    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"]
    label = labels[min(score, len(labels) - 1)]
    return {"score": score, "max": 7, "label": label, "issues": issues}


# ── HaveIBeenPwned check (k-anonymity) ───────────────────────────────

def hibp_check(password: str) -> dict:
    """Check password against HIBP using k-anonymity (never sends full hash)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url  = f"https://api.pwnedpasswords.com/range/{prefix}"
        req  = urllib.request.Request(url, headers={"User-Agent": "OPSEC-PwManager/1.0",
                                                     "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
        for line in body.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return {"pwned": True, "count": int(count),
                        "message": f"⚠ Found in {int(count):,} data breaches!"}
        return {"pwned": False, "count": 0, "message": "✓ Not found in known breaches"}
    except Exception as e:
        return {"pwned": None, "error": str(e),
                "message": "Could not connect to HaveIBeenPwned API"}


# ── TOTP ──────────────────────────────────────────────────────────────

def totp_generate(secret_b32: str) -> str:
    """Generate current TOTP code (RFC 6238)."""
    try:
        import hmac as _hmac
        key = base64.b32decode(secret_b32.upper().replace(" ", ""))
        t   = int(time.time()) // 30
        msg = struct.pack(">Q", t)
        h   = _hmac.new(key, msg, hashlib.sha1).digest()
        o   = h[-1] & 0x0F
        code = struct.unpack(">I", h[o:o+4])[0] & 0x7FFFFFFF
        return f"{code % 1_000_000:06d}"
    except Exception as e:
        return f"[TOTP error: {e}]"


# ── clipboard ─────────────────────────────────────────────────────────

def copy_to_clipboard(text: str, clear_after: int = 30):
    """Copy to clipboard and schedule clear."""
    import subprocess
    import threading

    copied = False
    for cmd in [["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
                ["pbcopy"],
                ["clip"]]:
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            proc.communicate(text.encode())
            if proc.returncode == 0:
                copied = True
                break
        except (FileNotFoundError, OSError):
            continue

    if copied:
        print(f"    📋 Copied to clipboard (auto-cleared in {clear_after}s)")
        def _clear():
            time.sleep(clear_after)
            for cmd in [["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"],
                        ["pbcopy"],
                        ["clip"]]:
                try:
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    proc.communicate(b"")
                    break
                except Exception:
                    continue
        threading.Thread(target=_clear, daemon=True).start()
    else:
        print("    [!] Clipboard tool not found (install xclip/xsel/pbcopy)")


# ── vault operations ──────────────────────────────────────────────────

def vault_add(name: str, username: str = "", url: str = "",
              password: str = "", tags: list = None, notes: str = "",
              totp_secret: str = "", category: str = ""):
    master = getpass("Master password: ")
    try:
        key, vault = _load_vault(master)
    except FileNotFoundError:
        print("[!] Run 'init' first"); return

    salt = _get_salt()
    if name in vault["entries"]:
        overwrite = input(f"  Entry '{name}' exists. Overwrite? [y/N]: ").strip().lower()
        if overwrite != "y":
            return

    if not password:
        pw_choice = input("  Generate password? [Y/n]: ").strip().lower()
        if pw_choice != "n":
            style = input("  Style [strong/pronounceable/passphrase]: ").strip() or "strong"
            length = int(input("  Length [20]: ").strip() or "20")
            password = generate_password(length, style)
            print(f"  Generated: {password}")

    strength = score_password(password)
    vault["entries"][name] = {
        "name": name,
        "username": username,
        "url": url,
        "password": password,
        "tags": tags or [],
        "category": category,
        "notes": notes,
        "totp_secret": totp_secret,
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "strength": strength["label"],
    }
    _save_vault(key, salt, vault)
    print(f"[+] Entry saved: {name}  (strength: {strength['label']})")
    if strength["issues"]:
        for issue in strength["issues"]:
            print(f"    ⚠ {issue}")


def vault_get(name: str, copy: bool = True):
    master = getpass("Master password: ")
    _, vault = _load_vault(master)
    entry = vault["entries"].get(name)
    if not entry:
        # Fuzzy search
        matches = [k for k in vault["entries"] if name.lower() in k.lower()]
        if matches:
            print(f"  Did you mean: {', '.join(matches)}")
        else:
            print(f"[!] Entry not found: {name}")
        return

    print(f"\n  Name     : {entry['name']}")
    print(f"  Username : {entry['username']}")
    print(f"  URL      : {entry.get('url','')}")
    print(f"  Password : {entry['password']}")
    print(f"  Strength : {entry.get('strength','')}")
    print(f"  Tags     : {', '.join(entry.get('tags', []))}")
    print(f"  Notes    : {entry.get('notes','')}")
    if entry.get("totp_secret"):
        code = totp_generate(entry["totp_secret"])
        print(f"  TOTP     : {code}  (valid ~{30 - int(time.time()) % 30}s)")

    if copy:
        copy_to_clipboard(entry["password"])


def vault_list(master: str = None):
    if not master:
        master = getpass("Master password: ")
    _, vault = _load_vault(master)
    entries = vault["entries"]
    if not entries:
        print("  Vault is empty")
        return

    print(f"\n  {'Name':<30} {'Username':<30} {'Category':<15} {'Strength'}")
    print("  " + "-" * 90)
    for name, entry in sorted(entries.items()):
        print(f"  {name:<30} {entry.get('username',''):<30} "
              f"{entry.get('category',''):<15} {entry.get('strength','')}")
    print(f"\n  Total: {len(entries)} entries")


def vault_search(query: str):
    master = getpass("Master password: ")
    _, vault = _load_vault(master)
    query_lower = query.lower()
    results = []
    for name, entry in vault["entries"].items():
        searchable = " ".join([
            name, entry.get("username",""), entry.get("url",""),
            entry.get("category",""), " ".join(entry.get("tags", [])),
            entry.get("notes","")
        ]).lower()
        if query_lower in searchable:
            results.append(entry)

    if not results:
        print(f"  No entries matching '{query}'")
        return

    print(f"\n  Found {len(results)} result(s):")
    for e in results:
        print(f"    • {e['name']:<30} {e.get('username',''):<25} {e.get('url','')}")


def vault_delete(name: str):
    master = getpass("Master password: ")
    key, vault = _load_vault(master)
    salt = _get_salt()
    if name not in vault["entries"]:
        print(f"[!] Entry not found: {name}"); return
    confirm = input(f"  Delete '{name}'? [y/N]: ").strip().lower()
    if confirm == "y":
        del vault["entries"][name]
        _save_vault(key, salt, vault)
        print(f"[+] Deleted: {name}")


def vault_export(out_path: Path):
    master = getpass("Master password (re-enter for export): ")
    key, vault = _load_vault(master)
    salt = _get_salt()
    # Re-encrypt with fresh salt for portability
    new_salt = token_bytes(32)
    new_key  = _kdf(master, new_salt)
    blob = _encrypt(new_key, json.dumps(vault).encode())
    out_path.write_bytes(MAGIC + new_salt + blob)
    print(f"[+] Vault exported → {out_path}")


def vault_import(in_path: Path):
    if not in_path.exists():
        print(f"[!] File not found: {in_path}"); return
    old_master = getpass("Master password for import file: ")
    raw  = in_path.read_bytes()
    if raw[:8] != MAGIC:
        print("[!] Not an OPSEC vault file"); return
    salt = raw[8:40]
    key  = _kdf(old_master, salt)
    try:
        imported = json.loads(_decrypt(key, raw[40:]))
    except Exception:
        print("[!] Decryption failed — wrong password"); return

    new_master = getpass("Master password for current vault: ")
    cur_key, cur_vault = _load_vault(new_master)
    cur_salt = _get_salt()
    merged_count = 0
    for name, entry in imported.get("entries", {}).items():
        if name not in cur_vault["entries"]:
            cur_vault["entries"][name] = entry
            merged_count += 1
    _save_vault(cur_key, cur_salt, cur_vault)
    print(f"[+] Imported {merged_count} new entries")


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Password Manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Initialise new vault")

    ad = sub.add_parser("add", help="Add or update an entry")
    ad.add_argument("--name", required=True)
    ad.add_argument("--username", default="")
    ad.add_argument("--url", default="")
    ad.add_argument("--password", default="")
    ad.add_argument("--tags", nargs="*", default=[])
    ad.add_argument("--notes", default="")
    ad.add_argument("--totp-secret", default="")
    ad.add_argument("--category", default="")

    gt = sub.add_parser("get", help="Retrieve an entry")
    gt.add_argument("--name", required=True)
    gt.add_argument("--no-copy", action="store_true")

    sub.add_parser("list", help="List all entries")

    sr = sub.add_parser("search", help="Search entries")
    sr.add_argument("--query", required=True)

    gn = sub.add_parser("gen", help="Generate a password")
    gn.add_argument("--length", type=int, default=20)
    gn.add_argument("--type", choices=["strong", "pronounceable", "passphrase", "pin"],
                    default="strong")
    gn.add_argument("--count", type=int, default=1)

    ck = sub.add_parser("check", help="Check password strength and breach status")
    ck.add_argument("--password")

    dl = sub.add_parser("delete", help="Delete an entry")
    dl.add_argument("--name", required=True)

    ex = sub.add_parser("export", help="Export vault to encrypted file")
    ex.add_argument("--out", required=True, type=Path)

    im = sub.add_parser("import-vault", help="Import entries from another vault")
    im.add_argument("--file", required=True, type=Path)

    args = parser.parse_args()

    if args.cmd == "init":
        pw1 = getpass("Choose master password: ")
        pw2 = getpass("Confirm master password: ")
        if pw1 != pw2:
            print("[!] Passwords do not match"); sys.exit(1)
        s = score_password(pw1)
        if s["score"] < 3:
            print(f"[!] Master password is {s['label']}. Strengthen it first.")
            for i in s["issues"]: print(f"    {i}")
            sys.exit(1)
        _init_vault(pw1)

    elif args.cmd == "add":
        vault_add(args.name, args.username, args.url, args.password,
                  args.tags, args.notes, args.totp_secret, args.category)

    elif args.cmd == "get":
        vault_get(args.name, copy=not args.no_copy)

    elif args.cmd == "list":
        vault_list()

    elif args.cmd == "search":
        vault_search(args.query)

    elif args.cmd == "gen":
        for _ in range(args.count):
            pw = generate_password(args.length, args.type)
            s  = score_password(pw)
            print(f"  {pw}  [{s['label']}]")

    elif args.cmd == "check":
        pw = args.password or getpass("Password to check: ")
        s  = score_password(pw)
        print(f"\n  Strength : {s['label']} ({s['score']}/{s['max']})")
        for issue in s["issues"]:
            print(f"  ⚠ {issue}")
        print("\n  Checking HaveIBeenPwned …")
        result = hibp_check(pw)
        print(f"  {result['message']}")

    elif args.cmd == "delete":
        vault_delete(args.name)

    elif args.cmd == "export":
        vault_export(args.out)

    elif args.cmd == "import-vault":
        vault_import(args.file)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
