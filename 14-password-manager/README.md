# 14 — Password Manager

AES-256-GCM encrypted local password vault with breach checking, TOTP, and a strong password generator.

## Features
- **AES-256-GCM vault** — authenticated encryption, tamper detection
- **PBKDF2-SHA256** with 260 000 iterations — slow brute-force
- **Zero-knowledge design** — master password never stored
- **Password generator** — strong, pronounceable, passphrase, or PIN styles
- **Strength scorer** — detects weak patterns, flags improvements
- **HaveIBeenPwned** — k-anonymity breach check (only first 5 chars of SHA-1 hash sent)
- **TOTP** — stores and generates time-based OTP codes (Google Authenticator compatible)
- **Clipboard auto-clear** — password cleared from clipboard after 30s
- **Search & tags** — find entries by name, URL, tag, or notes
- **Import / export** — encrypted portable vault files
- **No external dependencies** — works with stdlib (or `cryptography` for real AES-GCM)

## Quick Start

```bash
# Initialise vault (first time)
python password_manager.py init

# Add an entry (prompts for password or generates one)
python password_manager.py add --name "GitHub" --username "user@example.com" --url "https://github.com"

# Add with custom password and tags
python password_manager.py add --name "Bank" --username "user123" \
    --category "Finance" --tags banking important

# Retrieve entry (copies password to clipboard for 30s)
python password_manager.py get --name "GitHub"

# List all entries
python password_manager.py list

# Search
python password_manager.py search --query "finance"

# Generate a password (without saving)
python password_manager.py gen --length 24 --type strong
python password_manager.py gen --length 6 --type passphrase --count 5

# Check a password against HaveIBeenPwned
python password_manager.py check --password "hunter2"

# Delete an entry
python password_manager.py delete --name "OldSite"

# Export vault for backup
python password_manager.py export --out vault_backup.enc

# Import entries from another vault
python password_manager.py import-vault --file vault_backup.enc
```

## Password Styles
| Style | Example |
|-------|---------|
| `strong` | `K#8mP@wQ2!xN7vR$` |
| `pronounceable` | `bo4ku!zetawi` |
| `passphrase` | `maple-ocean-tiger-frost-2847` |
| `pin` | `748291` |

## Vault Location
`~/.opsec/vault/vault.enc`

## Security Notes
- The vault file is AES-256-GCM encrypted — unreadable without master password
- Master password is never stored; derived key lives only in memory
- For best security install `pip install cryptography` for real hardware-accelerated AES-GCM
- Keep regular encrypted exports on separate storage (see module 12)
