# 04 · Secure File Sharing

Encrypted file transfer with chunking, integrity verification, and zlib compression.

## Features

- **AES-256-GCM** per-file and per-chunk encryption
- **BLAKE2b** integrity verification (before encryption, after decryption)
- **Argon2id** key derivation (PBKDF2 fallback)
- **Chunked splitting** — split files across multiple channels for plausible deniability
- **HMAC-signed manifest** — chunk manifest cannot be tampered
- **zlib compression** — optional, applied before encryption

## Quick Start

```bash
pip install -r requirements.txt

# Encrypt a single file
python file_share.py encrypt --in secret.pdf --out secret.enc --password "StrongPass123"

# Decrypt
python file_share.py decrypt --in secret.enc --out recovered.pdf --password "StrongPass123"

# Split into 5 chunks (send each chunk via a different channel)
python file_share.py split --in secret.pdf --out ./chunks --chunks 5 --password "pass"

# Reassemble
python file_share.py join --chunks ./chunks --out recovered.pdf --password "pass"

# Verify file integrity
python file_share.py verify --in document.pdf
```

## Format Specification

**Single encrypted file:**
```
MAGIC(8) | meta_len(4) | meta_json(N) | salt(32) | nonce(12) | ciphertext+GCM_tag
```

**Chunk file:**
```
MAGIC(8) | chunk_salt(32) | nonce(12) | enc_chunk+GCM_tag
```

**Manifest (manifest.json):**
```json
{
  "original_name": "secret.pdf",
  "original_hash": "<blake2b>",
  "compressed": true,
  "n_chunks": 5,
  "chunks": [{"index": 0, "file": "chunk_0000.bin", "hash": "…"}],
  "master_salt": "<hex>",
  "hmac": "<hmac-sha256 of manifest>"
}
```

## Security Notes

- Each chunk is encrypted with a separate key derived from `password + chunk_salt + chunk_index`
- Even if one chunk is compromised, others remain secure
- The manifest HMAC prevents chunk reordering or substitution attacks
- Always verify BLAKE2b hashes after reassembly
