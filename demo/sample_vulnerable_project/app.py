"""
Sample vulnerable application — for pqc-scanner demo.
This file intentionally uses quantum-vulnerable cryptography.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib
import os

# === RSA Key Exchange (CRITICAL: Shor-vulnerable) ===
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

message = b"Sensitive financial transaction data"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                  algorithm=hashes.SHA256(), label=None)
)

# === ECDSA Signatures (CRITICAL: Shor-vulnerable) ===
ec_key = ec.generate_private_key(ec.SECP256R1())
signature = ec_key.sign(b"document to sign", ec.ECDSA(hashes.SHA256()))

# === AES-128 (MEDIUM: Grover halves to 64-bit) ===
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
aes_key = os.urandom(16)  # AES-128 — only 64-bit post-quantum security!
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)))

# === SHA-1 (MEDIUM: collision-broken since 2017) ===
legacy_hash = hashlib.sha1(b"legacy data fingerprint")

# === MD5 (HIGH: completely broken) ===
old_checksum = hashlib.md5(b"file integrity check")

# === Good practice: AES-256 and SHA-256 are quantum-safe ===
strong_key = os.urandom(32)  # AES-256 — 128-bit post-quantum security
strong_hash = hashlib.sha256(b"modern hash").hexdigest()
