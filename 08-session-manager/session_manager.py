#!/usr/bin/env python3
"""
OPSEC Session Manager
======================
Manage isolated browser profiles, cookies, and sessions.
Create, export, import, and nuke browser sessions.

Supports: Firefox, Chromium/Chrome, Brave

Usage:
  python session_manager.py list
  python session_manager.py create --name work --browser firefox
  python session_manager.py launch --name work
  python session_manager.py export --name work --out work_session.zip
  python session_manager.py import --name work --file work_session.zip
  python session_manager.py delete --name work
  python session_manager.py nuke                    # wipe all session data
  python session_manager.py cookies --browser firefox --action list
  python session_manager.py cookies --browser firefox --action clear
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

CONFIG_DIR = Path("~/.opsec/sessions").expanduser()
REGISTRY = CONFIG_DIR / "registry.json"


# ─────────────────────────── browser paths ──────────────────────────

def get_browser_profile_base(browser: str) -> Path | None:
    system = platform.system()
    home = Path.home()
    paths = {
        "firefox": {
            "Linux":  home / ".mozilla/firefox",
            "Darwin": home / "Library/Application Support/Firefox",
            "Windows": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox",
        },
        "chrome": {
            "Linux":   home / ".config/google-chrome",
            "Darwin":  home / "Library/Application Support/Google/Chrome",
            "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data",
        },
        "chromium": {
            "Linux":   home / ".config/chromium",
            "Darwin":  home / "Library/Application Support/Chromium",
            "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "Chromium/Application/User Data",
        },
        "brave": {
            "Linux":   home / ".config/BraveSoftware/Brave-Browser",
            "Darwin":  home / "Library/Application Support/BraveSoftware/Brave-Browser",
            "Windows": Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/User Data",
        },
    }
    return paths.get(browser, {}).get(system)


def find_browser_binary(browser: str) -> str | None:
    system = platform.system()
    candidates = {
        "firefox":  ["firefox", "firefox-esr", "/Applications/Firefox.app/Contents/MacOS/firefox"],
        "chrome":   ["google-chrome", "google-chrome-stable", "chrome",
                     "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
        "chromium": ["chromium", "chromium-browser",
                     "/Applications/Chromium.app/Contents/MacOS/Chromium"],
        "brave":    ["brave", "brave-browser",
                     "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"],
    }
    for name in candidates.get(browser, []):
        path = shutil.which(name)
        if path:
            return path
        if os.path.exists(name):
            return name
    return None


# ─────────────────────────── registry ───────────────────────────────

def load_registry() -> dict:
    if REGISTRY.exists():
        return json.loads(REGISTRY.read_text())
    return {}


def save_registry(reg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(reg, indent=2))


# ─────────────────────────── session ops ────────────────────────────

def create_session(name: str, browser: str) -> Path:
    profile_dir = CONFIG_DIR / f"{browser}_{name}"
    profile_dir.mkdir(parents=True, exist_ok=True)

    reg = load_registry()
    reg[name] = {
        "browser": browser,
        "profile_dir": str(profile_dir),
        "created": datetime.now().isoformat(),
        "last_used": None,
        "notes": "",
    }
    save_registry(reg)
    print(f"[+] Session created: {name}  ({browser})  → {profile_dir}")
    return profile_dir


def launch_session(name: str, url: str | None = None):
    reg = load_registry()
    if name not in reg:
        print(f"[!] Session '{name}' not found."); sys.exit(1)

    entry = reg[name]
    browser = entry["browser"]
    profile_dir = Path(entry["profile_dir"])
    binary = find_browser_binary(browser)

    if not binary:
        print(f"[!] Browser '{browser}' not found. Is it installed?"); sys.exit(1)

    args_map = {
        "firefox":  [binary, "--profile", str(profile_dir), "--no-remote"],
        "chrome":   [binary, f"--user-data-dir={profile_dir}", "--no-first-run"],
        "chromium": [binary, f"--user-data-dir={profile_dir}", "--no-first-run"],
        "brave":    [binary, f"--user-data-dir={profile_dir}", "--no-first-run"],
    }
    cmd = args_map.get(browser, [binary, f"--user-data-dir={profile_dir}"])
    if url:
        cmd.append(url)

    reg[name]["last_used"] = datetime.now().isoformat()
    save_registry(reg)

    print(f"[*] Launching {browser} with isolated profile: {name}")
    print(f"    Profile: {profile_dir}")
    subprocess.Popen(cmd)


def export_session(name: str, out_path: Path):
    reg = load_registry()
    if name not in reg:
        print(f"[!] Session '{name}' not found."); sys.exit(1)

    profile_dir = Path(reg[name]["profile_dir"])
    if not profile_dir.exists():
        print(f"[!] Profile directory not found: {profile_dir}"); sys.exit(1)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in profile_dir.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(profile_dir.parent))
        # Write metadata
        zf.writestr("opsec_session_meta.json", json.dumps(reg[name], indent=2))

    print(f"[+] Session exported: {out_path}  ({out_path.stat().st_size:,} bytes)")


def import_session(name: str, file_path: Path):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(file_path) as zf:
        meta_str = zf.read("opsec_session_meta.json").decode()
        meta = json.loads(meta_str)
        # Extract profile
        for member in zf.namelist():
            if member == "opsec_session_meta.json":
                continue
            zf.extract(member, CONFIG_DIR)

    reg = load_registry()
    meta["imported"] = datetime.now().isoformat()
    reg[name] = meta
    save_registry(reg)
    print(f"[+] Session imported: {name}")


def delete_session(name: str, wipe_data: bool = True):
    reg = load_registry()
    if name not in reg:
        print(f"[!] Session '{name}' not found."); sys.exit(1)
    profile_dir = Path(reg[name]["profile_dir"])
    if wipe_data and profile_dir.exists():
        shutil.rmtree(profile_dir)
        print(f"[-] Wiped profile data: {profile_dir}")
    del reg[name]
    save_registry(reg)
    print(f"[-] Session deleted: {name}")


def nuke_all():
    if input("⚠️  This will DELETE all OPSEC session data. Type YES to confirm: ") != "YES":
        print("Aborted."); return
    if CONFIG_DIR.exists():
        shutil.rmtree(CONFIG_DIR)
    print("[+] All session data wiped.")


# ─────────────────────────── cookie ops ─────────────────────────────

def find_cookies_db(browser: str) -> list[Path]:
    base = get_browser_profile_base(browser)
    if not base or not base.exists():
        return []
    # Firefox: profiles.ini → profile dirs → cookies.sqlite
    # Chrome/Brave: User Data/*/Cookies
    found = []
    if browser == "firefox":
        found.extend(base.rglob("cookies.sqlite"))
    else:
        found.extend(base.rglob("Cookies"))
    return found


def cmd_cookies(args):
    browser = args.browser
    action  = args.action
    cookie_files = find_cookies_db(browser)

    if not cookie_files:
        print(f"[!] No cookie databases found for {browser}")
        print(f"    Expected location: {get_browser_profile_base(browser)}")
        return

    if action == "list":
        for f in cookie_files:
            size = f.stat().st_size if f.exists() else 0
            print(f"  {f}  ({size:,} bytes)")
            # Try to read Firefox sqlite
            if browser == "firefox" and f.suffix == ".sqlite":
                try:
                    import sqlite3
                    conn = sqlite3.connect(str(f))
                    count = conn.execute("SELECT COUNT(*) FROM moz_cookies").fetchone()[0]
                    domains = conn.execute(
                        "SELECT DISTINCT host FROM moz_cookies LIMIT 20"
                    ).fetchall()
                    conn.close()
                    print(f"    Entries: {count:,}")
                    print(f"    Sample domains: {', '.join(d[0] for d in domains)}")
                except Exception as e:
                    print(f"    (sqlite read error: {e})")
    elif action == "clear":
        for f in cookie_files:
            if f.suffix == ".sqlite":
                try:
                    import sqlite3
                    conn = sqlite3.connect(str(f))
                    count_before = conn.execute("SELECT COUNT(*) FROM moz_cookies").fetchone()[0]
                    conn.execute("DELETE FROM moz_cookies")
                    conn.commit()
                    conn.close()
                    print(f"[+] Cleared {count_before:,} cookies from {f.name}")
                except Exception as e:
                    print(f"[!] Could not clear {f}: {e}")
            else:
                # Chrome — just remove the file (must be done when browser is closed)
                try:
                    f.unlink()
                    print(f"[+] Deleted cookie file: {f}")
                except Exception as e:
                    print(f"[!] Could not delete {f}: {e} (Is browser running?)")


# ─────────────────────────── CLI ────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OPSEC Session Manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List all managed sessions")

    cr = sub.add_parser("create", help="Create a new isolated browser session")
    cr.add_argument("--name", required=True)
    cr.add_argument("--browser", default="firefox",
                    choices=["firefox", "chrome", "chromium", "brave"])

    la = sub.add_parser("launch", help="Launch browser with isolated session")
    la.add_argument("--name", required=True)
    la.add_argument("--url")

    ex = sub.add_parser("export", help="Export session to ZIP")
    ex.add_argument("--name", required=True)
    ex.add_argument("--out", required=True)

    im = sub.add_parser("import", help="Import session from ZIP")
    im.add_argument("--name", required=True)
    im.add_argument("--file", required=True)

    dl = sub.add_parser("delete", help="Delete a session")
    dl.add_argument("--name", required=True)
    dl.add_argument("--keep-data", action="store_true", help="Keep profile data")

    sub.add_parser("nuke", help="Wipe ALL session data (irreversible)")

    ck = sub.add_parser("cookies", help="List or clear browser cookies")
    ck.add_argument("--browser", default="firefox",
                    choices=["firefox", "chrome", "chromium", "brave"])
    ck.add_argument("--action", choices=["list", "clear"], default="list")

    args = parser.parse_args()

    if args.cmd == "list":
        reg = load_registry()
        if not reg:
            print("No sessions. Use 'create' to add one.")
            return
        print(f"{'Name':<20} {'Browser':<12} {'Created':<22} {'Last Used'}")
        print("-" * 75)
        for name, entry in reg.items():
            lu = entry.get("last_used") or "never"
            print(f"{name:<20} {entry['browser']:<12} {entry['created'][:19]:<22} {lu[:19] if lu != 'never' else lu}")
    elif args.cmd == "create":
        create_session(args.name, args.browser)
    elif args.cmd == "launch":
        launch_session(args.name, args.url)
    elif args.cmd == "export":
        export_session(args.name, Path(args.out))
    elif args.cmd == "import":
        import_session(args.name, Path(args.file))
    elif args.cmd == "delete":
        delete_session(args.name, wipe_data=not args.keep_data)
    elif args.cmd == "nuke":
        nuke_all()
    elif args.cmd == "cookies":
        cmd_cookies(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
