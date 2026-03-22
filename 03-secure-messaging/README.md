# 03 · Secure Messaging

End-to-end encrypted messaging with forward secrecy using a simplified Double Ratchet protocol.

## Tools

| File | Description |
|------|-------------|
| `messaging.py` | CLI secure messenger with Double Ratchet (X25519 + AES-256-GCM) |
| `index.html` | Browser-based E2E encrypted chat (ECDH P-256 + AES-256-GCM) |

## Quick Start

```bash
pip install -r requirements.txt

# Alice and Bob generate identity keys
python messaging.py init --name alice
python messaging.py init --name bob

# Exchange public keys out-of-band (copy alice.pub → Bob's machine, bob.pub → Alice's)

# Create sessions
python messaging.py exchange --my-key alice.key --their-pub bob.pub --name alice_to_bob
python messaging.py exchange --my-key bob.key   --their-pub alice.pub --name bob_to_alice --responder

# Alice sends encrypted message (outputs JSON packet to stdout or file)
python messaging.py send --session session_alice_to_bob.json -m "Hello Bob!" -o msg1.json

# (Send msg1.json to Bob via any channel — it is fully encrypted)

# Bob decrypts
python messaging.py recv --session session_bob_to_alice.json --packet-file msg1.json

# View session log
python messaging.py log --session session_alice_to_bob.json

# Web UI — open in browser (no backend needed)
open index.html
```

## Security Properties

| Property | Status |
|----------|--------|
| Forward secrecy | ✅ Each message uses a unique derived key |
| Break-in recovery | ✅ Chain keys rotate on every message |
| Authentication | ✅ ECDH bound to identity keys |
| Confidentiality | ✅ AES-256-GCM |
| Integrity | ✅ GCM authentication tag |
| Replay protection | ✅ Message counter in header |

## Comparison to Signal Protocol

This is a simplified implementation. The full Signal Protocol (Double Ratchet + X3DH) adds:
- One-time prekeys (X3DH)
- Out-of-order message handling
- Skipped message key caching
- Session resumption

For production use, consider: **Signal**, **Matrix/Element**, **Briar**, or implement with **libsignal**.

## Recommended Tools for Production E2E Messaging

- **Signal App**: https://signal.org — gold standard
- **Matrix/Element**: Self-hostable, federated
- **Briar**: P2P, works over Tor/Bluetooth
- **Session**: Decentralised, no phone number required
