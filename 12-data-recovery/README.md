# 12 — Encrypted Data Recovery & Backup

AES-256-GCM encrypted backup tool with integrity verification, compression,
incremental support, and scheduled rotation.

## Features
- **AES-256-GCM encryption** — authenticated encryption, tamper-proof
- **PBKDF2-SHA256 key derivation** from password (200 000 iterations)
- **Key-file mode** — no password needed, uses random 64-byte key file
- **BLAKE2b integrity verification** — per-file hash in encrypted manifest
- **zlib compression** before encryption — smaller backup files
- **Incremental backups** — only changed files re-encrypted
- **Point-in-time restore** — full restore with hash verification
- **Backup listing** — see all backups with size and date
- **Scheduled backup** — prints cron / PowerShell Task Scheduler entry
- **Zero external dependencies** — works with stdlib only (or `cryptography`/`PyCryptodome` for real AES-GCM)

## Quick Start

```bash
# Create a backup (password-based)
python data_recovery.py backup --source ~/documents --dest ~/backups --password "my-secret"

# Create a backup (key-file based)
python data_recovery.py keygen --out backup.key
python data_recovery.py backup --source ~/documents --dest ~/backups --keyfile backup.key

# List backups
python data_recovery.py list --backup-dir ~/backups

# Restore
python data_recovery.py restore --backup ~/backups/backup_20240101_020000.enc \
    --dest ~/restored --password "my-secret"

# Verify backup integrity without restoring
python data_recovery.py verify --backup ~/backups/backup_20240101_020000.enc \
    --password "my-secret"

# Incremental backup (only changed files)
python data_recovery.py backup --source ~/documents --dest ~/backups \
    --keyfile backup.key --incremental ~/backups/backup_20240101_020000.enc

# Schedule daily backups (prints cron line)
python data_recovery.py schedule --source ~/documents --dest ~/backups \
    --keyfile backup.key --cron "0 2 * * *"
```

## Backup File Format

```
[8  bytes]  magic "OPSECBAK"
[4  bytes]  version (uint32 LE)
[32 bytes]  PBKDF2 salt
[4  bytes]  manifest length
[N  bytes]  AES-256-GCM encrypted JSON manifest
[4  bytes]  file count
For each file:
  [4 bytes]  file ID
  [8 bytes]  encrypted blob length
  [N bytes]  AES-256-GCM encrypted (compressed) file data
```

## Security Notes
- The manifest is encrypted — an attacker cannot see file names or metadata
- Each encryption operation uses a unique random nonce
- Key file should be stored on a separate physical medium (e.g. hardware token)
- For maximum security install `cryptography` pip package for real AES-GCM:
  `pip install cryptography`
