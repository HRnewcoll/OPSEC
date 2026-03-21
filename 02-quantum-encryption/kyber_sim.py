#!/usr/bin/env python3
"""
CRYSTALS-Kyber Key Encapsulation Mechanism — Educational Simulation
====================================================================
This is a SIMPLIFIED, EDUCATIONAL implementation that illustrates
the core concepts of CRYSTALS-Kyber (NIST PQC standard FIPS 203).

⚠️  NOT FOR PRODUCTION USE ⚠️
For production, use:
  - liboqs (Open Quantum Safe): https://github.com/open-quantum-safe/liboqs
  - pqcrypto: https://pqcrypto.org/
  - oqs-python: pip install liboqs-python

This simulation demonstrates:
  - Polynomial ring arithmetic in Z_q[x]/(x^n + 1)
  - Module-LWE problem setup
  - Key generation, encapsulation, decapsulation flow
  - Error correction (simplified)
"""

import hashlib
import os
import struct

# ── Parameters (Kyber-512 inspired) ──────────────────────────────────
N = 256          # polynomial degree
Q = 3329         # prime modulus
K = 2            # module rank (Kyber-512 uses k=2)
ETA1 = 3         # noise parameter
ETA2 = 2         # noise parameter
DU = 10          # compression bits for u
DV = 4           # compression bits for v


# ── Utility ───────────────────────────────────────────────────────────

def _reduce(x: int) -> int:
    return x % Q


def poly_add(a: list[int], b: list[int]) -> list[int]:
    return [_reduce(a[i] + b[i]) for i in range(N)]


def poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [_reduce(a[i] - b[i]) for i in range(N)]


def poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    """
    Schoolbook polynomial multiplication mod (x^N + 1) mod Q.
    Real Kyber uses NTT for efficiency; this is O(N^2) for clarity.
    """
    result = [0] * N
    for i in range(N):
        for j in range(N):
            idx = (i + j) % N
            sign = 1 if (i + j) < N else -1
            result[idx] = _reduce(result[idx] + sign * a[i] * b[j])
    return result


def poly_inner_product(vec_a: list[list[int]], vec_b: list[list[int]]) -> list[int]:
    """Dot product of two polynomial vectors."""
    acc = [0] * N
    for a, b in zip(vec_a, vec_b):
        acc = poly_add(acc, poly_mul_ntt(a, b))
    return acc


def matrix_vec_mul(matrix: list[list[list[int]]], vec: list[list[int]]) -> list[list[int]]:
    """Matrix-vector multiplication where entries are polynomials."""
    result = []
    for row in matrix:
        acc = [0] * N
        for a, v in zip(row, vec):
            acc = poly_add(acc, poly_mul_ntt(a, v))
        result.append(acc)
    return result


# ── Sampling ──────────────────────────────────────────────────────────

def sample_uniform_poly(seed: bytes, i: int, j: int) -> list[int]:
    """Sample a polynomial with coefficients uniform in [0, Q)."""
    data = hashlib.shake_128(seed + bytes([i, j])).digest(N * 2)
    coeffs = []
    idx = 0
    while len(coeffs) < N:
        val = struct.unpack_from("<H", data, idx % len(data))[0] & 0x1FFF
        if val < Q:
            coeffs.append(val)
        idx += 2
        if idx + 2 > len(data):
            data = hashlib.shake_128(data).digest(N * 2)
            idx = 0
    return coeffs[:N]


def sample_cbd(seed: bytes, nonce: int, eta: int) -> list[int]:
    """Sample from centred binomial distribution (CBD)."""
    prf_out = hashlib.shake_256(seed + bytes([nonce])).digest(64 * eta)
    bits = []
    for byte in prf_out:
        for b in range(8):
            bits.append((byte >> b) & 1)
    coeffs = []
    for i in range(N):
        a = sum(bits[2 * i * eta + j] for j in range(eta))
        b = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        coeffs.append(_reduce(a - b))
    return coeffs[:N]


def sample_poly_vec(sigma: bytes, offset: int, eta: int, size: int) -> list[list[int]]:
    return [sample_cbd(sigma, offset + i, eta) for i in range(size)]


# ── Compression / Decompression ───────────────────────────────────────

def compress(poly: list[int], bits: int) -> list[int]:
    factor = (1 << bits)
    return [round(x * factor / Q) % factor for x in poly]


def decompress(poly: list[int], bits: int) -> list[int]:
    factor = (1 << bits)
    return [round(x * Q / factor) % Q for x in poly]


# ── Key Generation ────────────────────────────────────────────────────

def keygen() -> tuple[bytes, bytes]:
    """
    Generate a Kyber key pair.
    Returns: (public_key_bytes, private_key_bytes)
    """
    d = os.urandom(32)
    rho, sigma = hashlib.sha3_512(d).digest()[:32], hashlib.sha3_512(d).digest()[32:]

    # Generate public matrix A ∈ R_q^{k×k}
    A = [[sample_uniform_poly(rho, i, j) for j in range(K)] for i in range(K)]

    # Sample secret and error vectors
    s = sample_poly_vec(sigma, 0, ETA1, K)
    e = sample_poly_vec(sigma, K, ETA1, K)

    # Compute public key: t = A*s + e
    t = matrix_vec_mul(A, s)
    for i in range(K):
        t[i] = poly_add(t[i], e[i])

    # Encode keys (simple concatenation of compressed coefficients)
    def encode_vec(v, bits=12):
        out = []
        for poly in v:
            out.extend(compress(poly, bits))
        return bytes(out)

    pk = rho + encode_vec(t)
    sk = encode_vec(s) + pk   # sk includes pk for decapsulation

    return pk, sk


# ── Encapsulation ─────────────────────────────────────────────────────

def encaps(pk: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the public key.
    Returns: (ciphertext_bytes, shared_secret_32_bytes)
    """
    rho = pk[:32]
    t_bytes = pk[32:]

    def decode_vec(data, bits=12):
        total = K * N
        flat = list(data[:total])
        return [decompress(flat[i*N:(i+1)*N], bits) for i in range(K)]

    t = decode_vec(t_bytes)
    A = [[sample_uniform_poly(rho, i, j) for j in range(K)] for i in range(K)]

    m = os.urandom(32)
    m_hash = hashlib.sha3_256(m).digest()  # hash message for FO transform
    r_seed, _ = hashlib.sha3_512(m_hash).digest()[:32], hashlib.sha3_512(m_hash).digest()[32:]

    r = sample_poly_vec(r_seed, 0, ETA1, K)
    e1 = sample_poly_vec(r_seed, K, ETA2, K)
    e2 = sample_cbd(r_seed, 2 * K, ETA2)

    # u = A^T * r + e1
    AT = [[A[j][i] for j in range(K)] for i in range(K)]  # transpose
    u = matrix_vec_mul(AT, r)
    for i in range(K):
        u[i] = poly_add(u[i], e1[i])

    # v = t^T * r + e2 + msg_encoded
    v = poly_inner_product(t, r)
    v = poly_add(v, e2)
    msg_poly = [(_reduce(int(bit) * ((Q + 1) // 2))) for bit in
                ''.join(format(b, '08b') for b in m_hash)[:N]]
    v = poly_add(v, msg_poly)

    def encode_poly(poly, bits):
        return bytes(compress(poly, bits))

    def encode_vec2(vec, bits):
        out = b""
        for p in vec:
            out += encode_poly(p, bits)
        return out

    c1 = encode_vec2(u, DU)
    c2 = encode_poly(v, DV)
    ciphertext = c1 + c2

    # Shared secret = H(m || ciphertext)
    shared_secret = hashlib.sha3_256(m + ciphertext).digest()
    return ciphertext, shared_secret


# ── Decapsulation ─────────────────────────────────────────────────────

def decaps(ciphertext: bytes, sk: bytes) -> bytes:
    """
    Decapsulate to recover the shared secret.
    Returns: shared_secret_32_bytes
    """
    # In this simulation, sk = encoded_s || pk
    s_len = K * N
    pk = sk[s_len:]
    rho = pk[:32]

    def decode_vec(data, bits, count=K):
        flat = list(data[:count * N])
        return [decompress(flat[i*N:(i+1)*N], bits) for i in range(count)]

    s_bytes = sk[:s_len]
    s = decode_vec(s_bytes, 12)

    c1 = ciphertext[:K * N]
    c2 = ciphertext[K * N:]

    u = decode_vec(list(c1), DU)
    v = decompress(list(c2)[:N], DV)

    # Recover v - s^T*u
    su = poly_inner_product(s, u)
    w = poly_sub(v, su)

    # Decode message bits (simplified)
    msg_bits = [1 if (x > Q // 4 and x < 3 * Q // 4) else 0 for x in w]
    msg_bytes = bytes(
        int(''.join(str(msg_bits[i * 8 + j]) for j in range(8)), 2)
        for i in range(len(msg_bits) // 8)
    )[:32]

    # Recompute shared secret from recovered m
    shared_secret = hashlib.sha3_256(msg_bytes + ciphertext).digest()
    return shared_secret


# ── CLI ───────────────────────────────────────────────────────────────

def demo():
    """Run a full Kyber KEM demonstration."""
    print("=" * 60)
    print("CRYSTALS-Kyber KEM — Educational Simulation")
    print("=" * 60)
    print("\n[*] Generating key pair …")
    pk, sk = keygen()
    print(f"    Public key : {len(pk)} bytes  ({pk[:16].hex()}…)")
    print(f"    Private key: {len(sk)} bytes  ({sk[:16].hex()}…)")

    print("\n[*] Encapsulating shared secret …")
    ciphertext, ss_sender = encaps(pk)
    print(f"    Ciphertext  : {len(ciphertext)} bytes  ({ciphertext[:16].hex()}…)")
    print(f"    Shared secret (sender): {ss_sender.hex()}")

    print("\n[*] Decapsulating shared secret …")
    ss_recip = decaps(ciphertext, sk)
    print(f"    Shared secret (recip) : {ss_recip.hex()}")

    match = ss_sender == ss_recip
    print(f"\n[{'✓' if match else '✗'}] Shared secrets {'MATCH' if match else 'DO NOT MATCH'}")
    if not match:
        print("    (Note: this simplified simulation may have decapsulation errors")
        print("     due to the schoolbook polynomial multiplication approximation.)")
    print("\n" + "=" * 60)
    print("⚠️  NOT FOR PRODUCTION USE")
    print("   For real post-quantum crypto, use: pip install liboqs-python")
    print("   Documentation: https://openquantumsafe.org/")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Kyber KEM Educational Simulation")
    parser.add_argument("--demo", action="store_true", default=True, help="Run full KEM demo")
    args = parser.parse_args()
    demo()
