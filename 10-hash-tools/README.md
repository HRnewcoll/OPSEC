# 10 · Hash Tools

Multi-algorithm file and text hashing, constant-time comparison, hash identification, dictionary cracking, and malware hash lookup.

## Quick Start

```bash
# Hash a file with SHA-256
python hash_tools.py hash --file document.pdf

# Hash with ALL algorithms at once
python hash_tools.py hash --file malware.exe --all

# Hash text
python hash_tools.py hash --text "hello world" --algorithm sha3-256

# Compare two hashes (constant-time, safe against timing attacks)
python hash_tools.py compare --hash1 abc123 --hash2 abc123

# Identify unknown hash algorithm
python hash_tools.py identify --hash 5d41402abc4b2a76b9719d911017c592

# Dictionary attack (cracking)
python hash_tools.py crack --hash 5d41402abc4b2a76b9719d911017c592 --wordlist /usr/share/wordlists/rockyou.txt
python hash_tools.py crack --hash <sha256> --wordlist wordlist.txt --algorithm sha256 --rules

# Check SHA256 against MalwareBazaar
python hash_tools.py malware-check --hash <sha256_of_file>

# Batch hash all files in a directory
python hash_tools.py batch --dir /path/to/files --output hashes.csv
python hash_tools.py batch --dir /etc --output system_hashes.json --algorithm sha3-256
```

## Supported Algorithms

| Algorithm | Output | Security |
|-----------|--------|----------|
| md5 | 32 hex | ⚠️ Broken — legacy only |
| sha1 | 40 hex | ⚠️ Deprecated |
| sha256 | 64 hex | ✅ Good |
| sha512 | 128 hex | ✅ Good |
| sha3-256 | 64 hex | ✅ Best (NIST standard) |
| sha3-512 | 128 hex | ✅ Best |
| blake2b | 128 hex | ✅ Very fast |
| blake2s | 64 hex | ✅ Very fast |
| shake-256 | 128 hex | ✅ Variable-length |

## Get Wordlists

```bash
# rockyou.txt (classic)
sudo apt install wordlists  # Kali Linux
# or: https://github.com/danielmiessler/SecLists

# SecLists (huge collection)
git clone https://github.com/danielmiessler/SecLists.git

# Online wordlist sources
# https://weakpass.com
# https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm
```

## Integration with hashcat (GPU-accelerated)

```bash
# MD5
hashcat -m 0 hash.txt wordlist.txt

# SHA-256
hashcat -m 1400 hash.txt wordlist.txt

# SHA3-256
hashcat -m 17300 hash.txt wordlist.txt

# With rules
hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```
