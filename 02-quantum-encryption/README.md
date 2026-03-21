# 02 · Quantum-Resistant Encryption

Hybrid encryption suite combining classical AES-256-GCM with X25519 ECDH key exchange, Argon2id key derivation, and SHA-3 hashing. Includes an educational CRYSTALS-Kyber simulation.

## Tools

| File | Description |
|------|-------------|
| `encrypt.py` | Hybrid file/text encryption (AES-256-GCM + X25519 or Argon2id) |
| `secure_hash.py` | Multi-algorithm hashing, HMAC, Argon2id password hashing, integrity DB |
| `kyber_sim.py` | CRYSTALS-Kyber KEM educational simulation (NOT for production) |
| `index.html` | Browser-based encryption/hash suite (Web Crypto API) |

## Quick Start

```bash
pip install -r requirements.txt

# ── Key-based encryption ──────────────────────────────────────
# Generate key pair
python encrypt.py keygen --out ./keys --name alice

# Encrypt for a recipient
python encrypt.py encrypt --pub keys/alice.pub --in secret.txt --out secret.enc

# Decrypt
python encrypt.py decrypt --priv keys/alice.key --in secret.enc --out secret.txt

# ── Password-based encryption ─────────────────────────────────
python encrypt.py encrypt-sym --in secret.txt --out secret.enc
python encrypt.py decrypt-sym --in secret.enc --out secret.txt

# ── Hashing ───────────────────────────────────────────────────
python secure_hash.py hash --algorithm sha3-256 --text "hello world"
python secure_hash.py hash --algorithm sha3-512 --file myfile.pdf
python secure_hash.py hash-all --text "hello world"
python secure_hash.py hash-all --file document.pdf

# ── Password hashing ──────────────────────────────────────────
python secure_hash.py password                   # prompts for password
python secure_hash.py password --verify '$argon2...'

# ── HMAC ─────────────────────────────────────────────────────
python secure_hash.py hmac --key "secret" --text "message" --algorithm sha256

# ── File integrity database ───────────────────────────────────
python secure_hash.py integrity create --paths /etc/nginx --db nginx_integrity.json
python secure_hash.py integrity verify --db nginx_integrity.json

# ── Kyber KEM demo ────────────────────────────────────────────
python kyber_sim.py --demo

# Open web UI
open index.html
```

## Encryption Format

Files encrypted with `encrypt.py` use a custom binary format:

**Asymmetric (X25519):**
```
MAGIC(7) | VERSION(1) | MODE=0x02(1) | eph_pub(32) | salt(32) | nonce(12) | ciphertext+tag
```

**Symmetric (Argon2id):**
```
MAGIC(7) | VERSION(1) | MODE=0x01(1) | salt(32) | nonce(12) | ciphertext+tag
```

## Post-Quantum Status

| Component | PQ-Safe? | Algorithm |
|-----------|----------|-----------|
| Symmetric encryption | ✅ Yes (key size ≥ 256-bit) | AES-256-GCM |
| Key derivation | ✅ Yes | Argon2id (memory-hard) |
| Key exchange | ⚠️ Classically secure | X25519 (broken by quantum) |
| Hashing | ✅ Yes | SHA-3, BLAKE2 |
| PQ key exchange (demo) | 🧪 Educational | Kyber-512 simulation |

**For true post-quantum encryption:** combine this tool with `liboqs-python` (CRYSTALS-Kyber + CRYSTALS-Dilithium) to replace the X25519 exchange.

```bash
pip install liboqs-python
python -c "import oqs; kem = oqs.KeyEncapsulation('Kyber512'); print('Kyber available!')"
```

## Security Notes

- Never reuse nonces with the same key
- Use asymmetric encryption for communicating with others; symmetric for personal storage
- The Kyber simulation is for learning only — do not use in production
