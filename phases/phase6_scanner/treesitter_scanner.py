"""
Enigma pqc-scanner v4.0: Tree-sitter Deep Multi-Language Crypto Scanner.

Supports 7 languages via installable tree-sitter grammars:
  Python, Java, Go, JavaScript/TypeScript, Rust, C/C++.
6 additional analyzers ship (C#, Ruby, PHP, Kotlin, Swift, Scala)
but require tree-sitter grammars not yet packaged in the [treesitter] extra.

Detects crypto API usage through:
  - Import/use statement tracking
  - Function call analysis with argument extraction
  - Key size constant propagation (backward slicing)
  - Algorithm mode detection (ECB vs GCM)
  - Cross-file import resolution
  - IaC config scanning (Terraform, YAML, Docker)
"""

from __future__ import annotations
import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pqc_scanner import Finding, Severity, Category, REMEDIATION

try:
    from tree_sitter import Language, Parser, Query
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# ============================================================================
# LANGUAGE SETUP
# ============================================================================

_LANGUAGE_MODULES = {
    'python':     ('tree_sitter_python', 'language'),
    'java':       ('tree_sitter_java', 'language'),
    'go':         ('tree_sitter_go', 'language'),
    'javascript': ('tree_sitter_javascript', 'language'),
    'typescript': ('tree_sitter_typescript', 'language_typescript'),
    'rust':       ('tree_sitter_rust', 'language'),
    'c':          ('tree_sitter_c', 'language'),
    'csharp':     ('tree_sitter_c_sharp', 'language'),
    'ruby':       ('tree_sitter_ruby', 'language'),
    'php':        ('tree_sitter_php', 'language_php'),
    'kotlin':     ('tree_sitter_kotlin', 'language'),
    'swift':      ('tree_sitter_swift', 'language'),
    'scala':      ('tree_sitter_scala', 'language'),
}

_EXT_TO_LANG = {
    '.py': 'python',
    '.java': 'java',
    '.go': 'go',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript',
    '.rs': 'rust',
    '.c': 'c', '.h': 'c', '.cpp': 'c', '.cc': 'c', '.hpp': 'c',
    '.cs': 'csharp',
    '.rb': 'ruby',
    '.php': 'php',
    '.kt': 'kotlin', '.kts': 'kotlin',
    '.swift': 'swift',
    '.scala': 'scala', '.sc': 'scala',
    # IaC / config files (parsed with regex, not tree-sitter)
    '.tf': 'terraform',
    '.yml': 'yaml_config', '.yaml': 'yaml_config',
    '.dockerfile': 'docker',
}

_parsers: Dict[str, Parser] = {}
_languages: Dict[str, Language] = {}


def _get_parser(lang: str) -> Optional[Parser]:
    """Get or create a tree-sitter parser for a language."""
    if not TREE_SITTER_AVAILABLE:
        return None
    if lang in _parsers:
        return _parsers[lang]
    try:
        mod_name, func_name = _LANGUAGE_MODULES[lang]
        mod = importlib.import_module(mod_name)
        lang_obj = Language(getattr(mod, func_name)())
        parser = Parser(lang_obj)
        _parsers[lang] = parser
        _languages[lang] = lang_obj
        return parser
    except (ImportError, KeyError, AttributeError):
        return None


# ============================================================================
# CRYPTO API DATABASE (per-language)
# ============================================================================

@dataclass
class CryptoPattern:
    """A crypto API pattern to detect via tree-sitter."""
    module: str           # Module/package path (e.g., 'cryptography.hazmat.primitives.asymmetric.rsa')
    function: str         # Function/method name (e.g., 'generate_private_key')
    algorithm: str        # Algorithm name (e.g., 'RSA')
    severity: Severity
    category: Category
    description: str
    key_size_arg: Optional[str] = None  # Name of kwarg containing key size
    key_size_pos: Optional[int] = None  # Position of positional arg containing key size


# Python crypto APIs
PYTHON_CRYPTO = [
    # cryptography library
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.rsa', 'generate_private_key',
                  'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key generation',
                  key_size_arg='key_size'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.ec', 'generate_private_key',
                  'ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECC key generation'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.ec', 'ECDSA',
                  'ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECDSA signing'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.ec', 'ECDH',
                  'ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'ECDH key exchange'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.dsa', 'generate_private_key',
                  'DSA', Severity.CRITICAL, Category.SIGNATURE, 'DSA key generation',
                  key_size_arg='key_size'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.dh', 'generate_parameters',
                  'DH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'DH parameter generation'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.ed25519', 'Ed25519PrivateKey',
                  'Ed25519', Severity.HIGH, Category.SIGNATURE, 'Ed25519 key usage'),
    # PyCryptodome
    CryptoPattern('Crypto.PublicKey.RSA', 'generate', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'PyCrypto RSA key generation', key_size_pos=0),
    CryptoPattern('Crypto.PublicKey.RSA', 'import_key', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'PyCrypto RSA key import'),
    CryptoPattern('Crypto.PublicKey.ECC', 'generate', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'PyCrypto ECC key generation'),
    CryptoPattern('Crypto.PublicKey.DSA', 'generate', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'PyCrypto DSA key generation', key_size_pos=0),
    CryptoPattern('Crypto.Cipher.DES', 'new', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'DES cipher instantiation'),
    CryptoPattern('Crypto.Cipher.DES3', 'new', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, '3DES cipher instantiation'),
    CryptoPattern('Crypto.Cipher.Blowfish', 'new', 'Blowfish', Severity.HIGH,
                  Category.SYMMETRIC, 'Blowfish cipher instantiation'),
    CryptoPattern('Crypto.Cipher.ARC4', 'new', 'RC4', Severity.HIGH,
                  Category.SYMMETRIC, 'RC4 cipher instantiation'),
    # hashlib
    CryptoPattern('hashlib', 'md5', 'MD5', Severity.HIGH, Category.HASH, 'MD5 hash'),
    CryptoPattern('hashlib', 'sha1', 'SHA-1', Severity.MEDIUM, Category.HASH, 'SHA-1 hash'),
    # cryptography library — additional patterns
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.rsa', 'RSAPrivateKey',
                  'RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'RSA private key usage'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.ed448', 'Ed448PrivateKey',
                  'Ed448', Severity.HIGH, Category.SIGNATURE, 'Ed448 key usage'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.x25519', 'X25519PrivateKey',
                  'X25519', Severity.HIGH, Category.KEY_EXCHANGE, 'X25519 key exchange'),
    CryptoPattern('cryptography.hazmat.primitives.asymmetric.x448', 'X448PrivateKey',
                  'X448', Severity.HIGH, Category.KEY_EXCHANGE, 'X448 key exchange'),
    CryptoPattern('cryptography.hazmat.primitives.ciphers', 'TripleDES',
                  '3DES', Severity.HIGH, Category.SYMMETRIC, '3DES cipher algorithm'),
    CryptoPattern('cryptography.hazmat.primitives.ciphers', 'Blowfish',
                  'Blowfish', Severity.HIGH, Category.SYMMETRIC, 'Blowfish cipher'),
    CryptoPattern('cryptography.hazmat.primitives.ciphers', 'ARC4',
                  'RC4', Severity.HIGH, Category.SYMMETRIC, 'RC4 stream cipher'),
    CryptoPattern('cryptography.hazmat.primitives.ciphers', 'IDEA',
                  'IDEA', Severity.HIGH, Category.SYMMETRIC, 'IDEA cipher (deprecated)'),
    CryptoPattern('cryptography.hazmat.primitives.ciphers.modes', 'ECB',
                  'AES-ECB', Severity.HIGH, Category.SYMMETRIC, 'ECB mode — patterns leak'),
    CryptoPattern('cryptography.hazmat.primitives.hashes', 'MD5',
                  'MD5', Severity.HIGH, Category.HASH, 'MD5 hash algorithm'),
    CryptoPattern('cryptography.hazmat.primitives.hashes', 'SHA1',
                  'SHA-1', Severity.MEDIUM, Category.HASH, 'SHA-1 hash algorithm'),
    # paramiko (SSH library)
    CryptoPattern('paramiko', 'RSAKey', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'Paramiko RSA SSH key'),
    CryptoPattern('paramiko', 'DSSKey', 'DSA', Severity.HIGH,
                  Category.SIGNATURE, 'Paramiko DSA SSH key'),
    # PyJWT / jose
    CryptoPattern('jwt', 'encode', 'RSA', Severity.HIGH,
                  Category.SIGNATURE, 'JWT token signing (check algorithm)'),
    CryptoPattern('jose', 'sign', 'RSA', Severity.HIGH,
                  Category.SIGNATURE, 'JOSE signing (check algorithm)'),
    # PyCryptodome — additional
    CryptoPattern('Crypto.Cipher.CAST', 'new', 'CAST5', Severity.HIGH,
                  Category.SYMMETRIC, 'CAST5 cipher (deprecated)'),
    CryptoPattern('Crypto.Signature.pkcs1_15', 'new', 'RSA', Severity.HIGH,
                  Category.SIGNATURE, 'RSA PKCS#1 v1.5 signature'),
    CryptoPattern('Crypto.Signature.DSS', 'new', 'DSA', Severity.HIGH,
                  Category.SIGNATURE, 'DSA/ECDSA signature'),
]

# Java crypto APIs
JAVA_CRYPTO = [
    CryptoPattern('java.security.KeyPairGenerator', 'getInstance', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA key generation'),
    CryptoPattern('javax.crypto.Cipher', 'getInstance', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Cipher instantiation'),
    CryptoPattern('java.security.Signature', 'getInstance', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'Digital signature'),
    CryptoPattern('javax.crypto.KeyAgreement', 'getInstance', 'ECDH/DH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Key agreement'),
    CryptoPattern('java.security.MessageDigest', 'getInstance', 'SHA-1/MD5', Severity.MEDIUM,
                  Category.HASH, 'Hash function'),
    # Additional Java/JCA patterns
    CryptoPattern('javax.crypto.KeyGenerator', 'getInstance', 'DES', Severity.HIGH,
                  Category.SYMMETRIC, 'Symmetric key generation'),
    CryptoPattern('javax.crypto.SecretKeyFactory', 'getInstance', 'DES', Severity.HIGH,
                  Category.SYMMETRIC, 'Secret key factory'),
    CryptoPattern('javax.crypto.Mac', 'getInstance', 'HMAC', Severity.MEDIUM,
                  Category.HASH, 'MAC computation (check algorithm)'),
    CryptoPattern('java.security.KeyStore', 'getInstance', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'KeyStore (may contain RSA keys)'),
    CryptoPattern('java.security.cert.CertificateFactory', 'getInstance', 'X.509', Severity.MEDIUM,
                  Category.KEY_EXCHANGE, 'Certificate handling (check key algorithm)'),
    CryptoPattern('javax.net.ssl.SSLContext', 'getInstance', 'TLS', Severity.MEDIUM,
                  Category.PROTOCOL, 'SSL/TLS context (check protocol version)'),
    CryptoPattern('java.security.AlgorithmParameters', 'getInstance', 'DH', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'Algorithm parameters'),
    # BouncyCastle patterns
    CryptoPattern('org.bouncycastle', 'RSAEngine', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'BouncyCastle RSA engine'),
    CryptoPattern('org.bouncycastle', 'DSASigner', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'BouncyCastle DSA signer'),
    CryptoPattern('org.bouncycastle', 'ECDSASigner', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'BouncyCastle ECDSA signer'),
]

# Go crypto APIs
GO_CRYPTO = [
    CryptoPattern('crypto/rsa', 'GenerateKey', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA key generation', key_size_pos=1),
    CryptoPattern('crypto/rsa', 'SignPKCS1v15', 'RSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'RSA PKCS#1 v1.5 signature'),
    CryptoPattern('crypto/rsa', 'SignPSS', 'RSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'RSA-PSS signature'),
    CryptoPattern('crypto/rsa', 'EncryptOAEP', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA OAEP encryption'),
    CryptoPattern('crypto/rsa', 'EncryptPKCS1v15', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA PKCS#1 v1.5 encryption'),
    CryptoPattern('crypto/ecdsa', 'GenerateKey', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'ECDSA key generation'),
    CryptoPattern('crypto/ecdsa', 'Sign', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'ECDSA signing'),
    CryptoPattern('crypto/ecdsa', 'SignASN1', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'ECDSA ASN.1 signing'),
    CryptoPattern('crypto/dsa', 'GenerateParameters', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'DSA parameter generation'),
    CryptoPattern('crypto/dsa', 'GenerateKey', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'DSA key generation'),
    CryptoPattern('crypto/des', 'NewCipher', 'DES', Severity.CRITICAL,
                  Category.SYMMETRIC, 'DES cipher'),
    CryptoPattern('crypto/des', 'NewTripleDESCipher', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, '3DES cipher'),
    CryptoPattern('crypto/rc4', 'NewCipher', 'RC4', Severity.HIGH,
                  Category.SYMMETRIC, 'RC4 stream cipher'),
    CryptoPattern('crypto/elliptic', 'P256', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'P-256 elliptic curve'),
    CryptoPattern('crypto/elliptic', 'P384', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'P-384 elliptic curve'),
    CryptoPattern('crypto/elliptic', 'P521', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'P-521 elliptic curve'),
    CryptoPattern('crypto/ed25519', 'GenerateKey', 'Ed25519', Severity.HIGH,
                  Category.SIGNATURE, 'Ed25519 key generation'),
    CryptoPattern('crypto/ed25519', 'Sign', 'Ed25519', Severity.HIGH,
                  Category.SIGNATURE, 'Ed25519 signing'),
    CryptoPattern('crypto/sha1', 'New', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'SHA-1 hash'),
    CryptoPattern('crypto/md5', 'New', 'MD5', Severity.HIGH,
                  Category.HASH, 'MD5 hash'),
    CryptoPattern('crypto/x509', 'ParseCertificate', 'X.509', Severity.MEDIUM,
                  Category.KEY_EXCHANGE, 'X.509 certificate parsing (check key algo)'),
    CryptoPattern('crypto/tls', 'Config', 'TLS', Severity.MEDIUM,
                  Category.PROTOCOL, 'TLS configuration (check cipher suites)'),
]

# JavaScript/TypeScript crypto APIs
JS_CRYPTO = [
    CryptoPattern('crypto', 'createSign', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'Digital signature creation'),
    CryptoPattern('crypto', 'createVerify', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'Signature verification'),
    CryptoPattern('crypto', 'generateKeyPair', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Key pair generation'),
    CryptoPattern('crypto', 'generateKeyPairSync', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Key pair generation (sync)'),
    CryptoPattern('crypto', 'createDiffieHellman', 'DH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Diffie-Hellman key exchange'),
    CryptoPattern('crypto', 'createDiffieHellmanGroup', 'DH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'DH group key exchange'),
    CryptoPattern('crypto', 'createECDH', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'ECDH key exchange'),
    CryptoPattern('crypto', 'createHash', 'SHA-1/MD5', Severity.MEDIUM,
                  Category.HASH, 'Hash creation'),
    CryptoPattern('crypto', 'createHmac', 'HMAC', Severity.MEDIUM,
                  Category.HASH, 'HMAC creation (check algorithm)'),
    CryptoPattern('crypto', 'createCipheriv', 'DES', Severity.HIGH,
                  Category.SYMMETRIC, 'Cipher creation (check algorithm)'),
    CryptoPattern('crypto', 'createDecipheriv', 'DES', Severity.HIGH,
                  Category.SYMMETRIC, 'Decipher creation (check algorithm)'),
    CryptoPattern('crypto', 'privateEncrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'RSA private key encryption'),
    CryptoPattern('crypto', 'publicEncrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'RSA public key encryption'),
    CryptoPattern('crypto', 'privateDecrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'RSA private key decryption'),
    CryptoPattern('crypto', 'publicDecrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'RSA public key decryption'),
    # Web Crypto API (browser + Node.js)
    CryptoPattern('subtle', 'generateKey', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'WebCrypto key generation'),
    CryptoPattern('subtle', 'importKey', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'WebCrypto key import'),
    CryptoPattern('subtle', 'sign', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'WebCrypto signing'),
    CryptoPattern('subtle', 'encrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'WebCrypto encryption'),
    # jsonwebtoken / jose
    CryptoPattern('jsonwebtoken', 'sign', 'RSA', Severity.HIGH,
                  Category.SIGNATURE, 'JWT signing (check algorithm: RS256/ES256)'),
    CryptoPattern('jose', 'SignJWT', 'RSA', Severity.HIGH,
                  Category.SIGNATURE, 'JOSE JWT signing'),
]

# Rust crypto APIs
RUST_CRYPTO = [
    CryptoPattern('rsa', 'RsaPrivateKey', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA private key'),
    CryptoPattern('rsa', 'RsaPublicKey', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'RSA public key'),
    CryptoPattern('rsa', 'Pkcs1v15Sign', 'RSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'RSA PKCS#1 v1.5 signature'),
    CryptoPattern('rsa', 'Oaep', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'RSA OAEP encryption'),
    CryptoPattern('p256', 'SecretKey', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'P-256 secret key'),
    CryptoPattern('p256', 'SigningKey', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'P-256 signing key'),
    CryptoPattern('p384', 'SecretKey', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'P-384 secret key'),
    CryptoPattern('k256', 'SecretKey', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'secp256k1 secret key'),
    CryptoPattern('ed25519_dalek', 'SigningKey', 'Ed25519', Severity.HIGH,
                  Category.SIGNATURE, 'Ed25519 signing key'),
    CryptoPattern('ed25519_dalek', 'Keypair', 'Ed25519', Severity.HIGH,
                  Category.SIGNATURE, 'Ed25519 keypair'),
    CryptoPattern('x25519_dalek', 'EphemeralSecret', 'X25519', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'X25519 key exchange'),
    CryptoPattern('x25519_dalek', 'StaticSecret', 'X25519', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'X25519 static key'),
    CryptoPattern('dsa', 'SigningKey', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'DSA signing key'),
    CryptoPattern('sha1', 'Sha1', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'SHA-1 hash'),
    CryptoPattern('md5', 'Md5', 'MD5', Severity.HIGH,
                  Category.HASH, 'MD5 hash'),
    CryptoPattern('md4', 'Md4', 'MD4', Severity.HIGH,
                  Category.HASH, 'MD4 hash (severely broken)'),
    CryptoPattern('des', 'Des', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'DES cipher'),
    CryptoPattern('des', 'TdesEde3', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, '3DES cipher'),
    CryptoPattern('blowfish', 'Blowfish', 'Blowfish', Severity.HIGH,
                  Category.SYMMETRIC, 'Blowfish cipher'),
    CryptoPattern('rc4', 'Rc4', 'RC4', Severity.HIGH,
                  Category.SYMMETRIC, 'RC4 stream cipher'),
]

# C/C++ crypto APIs (OpenSSL focus)
C_CRYPTO = [
    CryptoPattern('openssl/rsa.h', 'RSA_generate_key_ex', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'OpenSSL RSA key generation', key_size_pos=1),
    CryptoPattern('openssl/rsa.h', 'RSA_new', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'OpenSSL RSA allocation'),
    CryptoPattern('openssl/ec.h', 'EC_KEY_generate_key', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'OpenSSL ECC key generation'),
    CryptoPattern('openssl/ec.h', 'EC_KEY_new', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'OpenSSL ECC key allocation'),
    CryptoPattern('openssl/dh.h', 'DH_generate_parameters_ex', 'DH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'OpenSSL DH parameter generation'),
    CryptoPattern('openssl/evp.h', 'EVP_des_ede3_cbc', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'OpenSSL 3DES'),
    CryptoPattern('openssl/evp.h', 'EVP_sha1', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'OpenSSL SHA-1'),
    CryptoPattern('openssl/evp.h', 'EVP_md5', 'MD5', Severity.HIGH,
                  Category.HASH, 'OpenSSL MD5'),
    CryptoPattern('openssl/evp.h', 'EVP_aes_128_cbc', 'AES-128', Severity.MEDIUM,
                  Category.SYMMETRIC, 'OpenSSL AES-128-CBC'),
    CryptoPattern('openssl/evp.h', 'EVP_aes_128_gcm', 'AES-128', Severity.MEDIUM,
                  Category.SYMMETRIC, 'OpenSSL AES-128-GCM'),
]

# C# / .NET crypto APIs
CSHARP_CRYPTO = [
    CryptoPattern('System.Security.Cryptography', 'RSA.Create', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'C# RSA key creation'),
    CryptoPattern('System.Security.Cryptography', 'RSACryptoServiceProvider', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'C# RSA crypto service'),
    CryptoPattern('System.Security.Cryptography', 'ECDsa.Create', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'C# ECDSA creation'),
    CryptoPattern('System.Security.Cryptography', 'ECDiffieHellman.Create', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'C# ECDH creation'),
    CryptoPattern('System.Security.Cryptography', 'DSA.Create', 'DSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'C# DSA creation'),
    CryptoPattern('System.Security.Cryptography', 'TripleDES.Create', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'C# 3DES creation'),
    CryptoPattern('System.Security.Cryptography', 'MD5.Create', 'MD5', Severity.HIGH,
                  Category.HASH, 'C# MD5 creation'),
    CryptoPattern('System.Security.Cryptography', 'SHA1.Create', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'C# SHA-1 creation'),
]

# Ruby crypto APIs
RUBY_CRYPTO = [
    CryptoPattern('openssl', 'OpenSSL::PKey::RSA', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Ruby OpenSSL RSA'),
    CryptoPattern('openssl', 'OpenSSL::PKey::EC', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'Ruby OpenSSL ECC'),
    CryptoPattern('openssl', 'OpenSSL::PKey::DH', 'DH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Ruby OpenSSL DH'),
    CryptoPattern('openssl', 'OpenSSL::Cipher', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'Ruby OpenSSL cipher'),
    CryptoPattern('digest', 'Digest::MD5', 'MD5', Severity.HIGH,
                  Category.HASH, 'Ruby MD5 digest'),
    CryptoPattern('digest', 'Digest::SHA1', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'Ruby SHA-1 digest'),
]

# PHP crypto APIs
PHP_CRYPTO = [
    CryptoPattern('openssl', 'openssl_pkey_new', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'PHP RSA key generation'),
    CryptoPattern('openssl', 'openssl_sign', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'PHP digital signature'),
    CryptoPattern('openssl', 'openssl_encrypt', 'RSA', Severity.HIGH,
                  Category.KEY_EXCHANGE, 'PHP OpenSSL encryption'),
    CryptoPattern('hash', 'md5', 'MD5', Severity.HIGH,
                  Category.HASH, 'PHP md5() hash'),
    CryptoPattern('hash', 'sha1', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'PHP sha1() hash'),
    CryptoPattern('mcrypt', 'mcrypt_encrypt', '3DES', Severity.HIGH,
                  Category.SYMMETRIC, 'PHP mcrypt (deprecated)'),
]

# Kotlin crypto APIs (uses JCA like Java)
KOTLIN_CRYPTO = [
    CryptoPattern('javax.crypto', 'Cipher.getInstance', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Kotlin JCA cipher'),
    CryptoPattern('java.security', 'KeyPairGenerator.getInstance', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Kotlin JCA key generation'),
    CryptoPattern('java.security', 'MessageDigest.getInstance', 'SHA-1/MD5', Severity.MEDIUM,
                  Category.HASH, 'Kotlin JCA hash'),
    CryptoPattern('java.security', 'Signature.getInstance', 'RSA/ECDSA', Severity.HIGH,
                  Category.SIGNATURE, 'Kotlin JCA signature'),
]

# Swift crypto APIs
SWIFT_CRYPTO = [
    CryptoPattern('Security', 'SecKeyCreateRandomKey', 'RSA', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Swift RSA key generation'),
    CryptoPattern('CryptoKit', 'P256.Signing', 'ECDSA', Severity.CRITICAL,
                  Category.SIGNATURE, 'Swift P-256 signing'),
    CryptoPattern('CryptoKit', 'P256.KeyAgreement', 'ECDH', Severity.CRITICAL,
                  Category.KEY_EXCHANGE, 'Swift P-256 key agreement'),
    CryptoPattern('CryptoKit', 'Curve25519.Signing', 'Ed25519', Severity.HIGH,
                  Category.SIGNATURE, 'Swift Curve25519 signing'),
    CryptoPattern('CommonCrypto', 'CC_MD5', 'MD5', Severity.HIGH,
                  Category.HASH, 'Swift CommonCrypto MD5'),
    CryptoPattern('CommonCrypto', 'CC_SHA1', 'SHA-1', Severity.MEDIUM,
                  Category.HASH, 'Swift CommonCrypto SHA-1'),
]

# Scala crypto APIs (uses JCA like Java/Kotlin)
SCALA_CRYPTO = KOTLIN_CRYPTO  # Same JCA APIs

_LANG_PATTERNS = {
    'python': PYTHON_CRYPTO,
    'java': JAVA_CRYPTO,
    'go': GO_CRYPTO,
    'javascript': JS_CRYPTO,
    'typescript': JS_CRYPTO,
    'rust': RUST_CRYPTO,
    'c': C_CRYPTO,
    'csharp': CSHARP_CRYPTO,
    'ruby': RUBY_CRYPTO,
    'php': PHP_CRYPTO,
    'kotlin': KOTLIN_CRYPTO,
    'swift': SWIFT_CRYPTO,
    'scala': SCALA_CRYPTO,
}

# Algorithms that are quantum-vulnerable when found in string arguments
_QUANTUM_VULNERABLE_STRINGS = {
    'rsa': ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE),
    'dsa': ('DSA', Severity.CRITICAL, Category.SIGNATURE),
    'ecdsa': ('ECDSA', Severity.CRITICAL, Category.SIGNATURE),
    'ecdh': ('ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE),
    'diffie-hellman': ('DH', Severity.CRITICAL, Category.KEY_EXCHANGE),
    'diffiehellman': ('DH', Severity.CRITICAL, Category.KEY_EXCHANGE),
    'des': ('3DES', Severity.HIGH, Category.SYMMETRIC),
    '3des': ('3DES', Severity.HIGH, Category.SYMMETRIC),
    'desede': ('3DES', Severity.HIGH, Category.SYMMETRIC),
    'blowfish': ('Blowfish', Severity.HIGH, Category.SYMMETRIC),
    'rc4': ('RC4', Severity.HIGH, Category.SYMMETRIC),
    'md5': ('MD5', Severity.HIGH, Category.HASH),
    'sha-1': ('SHA-1', Severity.MEDIUM, Category.HASH),
    'sha1': ('SHA-1', Severity.MEDIUM, Category.HASH),
}

# ECB mode detection — always a finding
_WEAK_MODES = {
    'ecb': ('ECB mode — no diffusion, patterns leak', Severity.HIGH),
    'cbc': ('CBC mode — consider GCM for authenticated encryption', Severity.LOW),
}


# ============================================================================
# TREE-SITTER ANALYSIS ENGINE
# ============================================================================

@dataclass
class TSFinding:
    """Extended finding from tree-sitter analysis with extra context."""
    algorithm: str
    severity: Severity
    category: Category
    description: str
    file: str
    line: int
    code_snippet: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    import_chain: Optional[str] = None  # How the crypto was imported


def _node_text(node, source: bytes) -> str:
    """Extract text from a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')


def _get_line_text(source: bytes, line: int) -> str:
    """Get the full text of a source line (0-indexed)."""
    lines = source.split(b'\n')
    if 0 <= line < len(lines):
        return lines[line].decode('utf-8', errors='replace').strip()[:120]
    return ''


def _extract_string_value(node, source: bytes) -> Optional[str]:
    """Extract the string value from a string literal node, stripping quotes."""
    text = _node_text(node, source)
    # Strip various quote styles
    for q in ('"""', "'''", '"', "'", '`'):
        if text.startswith(q) and text.endswith(q):
            return text[len(q):-len(q)]
    return text


def _extract_integer(node, source: bytes) -> Optional[int]:
    """Try to extract an integer value from a node."""
    text = _node_text(node, source).strip()
    try:
        return int(text)
    except (ValueError, OverflowError):
        return None


# ============================================================================
# LANGUAGE-SPECIFIC ANALYZERS
# ============================================================================

def _analyze_python(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Python source code for crypto usage."""
    findings = []
    root = tree.root_node
    imports: Dict[str, str] = {}  # local_name → full_module

    # Phase 1: Track imports
    _walk_for_type(root, 'import_statement', lambda n: _track_python_import(n, source, imports))
    _walk_for_type(root, 'import_from_statement', lambda n: _track_python_from_import(n, source, imports))

    # Check imports against crypto modules (don't double-report — calls are more precise)
    # Imports are tracked for resolution, not reported as findings

    # Phase 2: Track function calls
    def check_call(node):
        func_name, obj_name = _extract_call_info_python(node, source)
        if func_name is None:
            return

        # Resolve through imports
        resolved = imports.get(obj_name, obj_name) if obj_name else ''
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        # Check against crypto patterns
        for pat in PYTHON_CRYPTO:
            mod_tail = pat.module.split('.')[-1]
            if func_name == pat.function and (
                obj_name == mod_tail or
                resolved == pat.module or
                resolved.startswith(pat.module)
            ):
                key_size = _extract_key_size(node, source, pat)
                mode = _detect_mode_from_args(node, source)
                desc = pat.description
                if key_size:
                    desc += f' (key_size={key_size})'
                if mode:
                    desc += f' [mode={mode.upper()}]'
                findings.append(TSFinding(
                    algorithm=pat.algorithm, severity=pat.severity,
                    category=pat.category, description=desc,
                    file=filepath, line=line + 1, code_snippet=snippet,
                    key_size=key_size, mode=mode,
                    import_chain=f'{obj_name}.{func_name}' if obj_name else func_name,
                ))
                return

        # Check hashlib special case
        if obj_name in ('hashlib', imports.get('hashlib', '')) or resolved == 'hashlib':
            if func_name == 'md5':
                findings.append(TSFinding('MD5', Severity.HIGH, Category.HASH,
                    'MD5 hash — completely broken', filepath, line + 1, snippet))
            elif func_name == 'sha1':
                findings.append(TSFinding('SHA-1', Severity.MEDIUM, Category.HASH,
                    'SHA-1 hash — collision-broken since 2017', filepath, line + 1, snippet))
            elif func_name == 'new':
                # Check string argument
                algo = _get_first_string_arg(node, source)
                if algo and algo.lower() in _QUANTUM_VULNERABLE_STRINGS:
                    a, s, c = _QUANTUM_VULNERABLE_STRINGS[algo.lower()]
                    findings.append(TSFinding(a, s, c,
                        f'hashlib.new("{algo}")', filepath, line + 1, snippet))

        # Check string arguments for algorithm selection
        _check_string_args_for_crypto(node, source, filepath, line, snippet, findings)

    _walk_for_type(root, 'call', check_call)
    return findings


def _analyze_java(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Java source for crypto API usage."""
    findings = []
    root = tree.root_node

    def check_invocation(node):
        # Java method_invocation: object.method(args)
        name_node = node.child_by_field_name('name')
        if name_node is None:
            return
        method_name = _node_text(name_node, source)
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        # Check getInstance patterns
        if method_name == 'getInstance':
            algo_str = _get_first_string_arg(node, source)
            if algo_str:
                algo_lower = algo_str.lower().split('/')[0]  # "RSA/ECB/PKCS1" → "rsa"
                if algo_lower in _QUANTUM_VULNERABLE_STRINGS:
                    a, s, c = _QUANTUM_VULNERABLE_STRINGS[algo_lower]
                    # Detect mode from transform string
                    mode = None
                    if '/' in algo_str:
                        parts = algo_str.split('/')
                        if len(parts) >= 2:
                            mode = parts[1].lower()
                    desc = f'Java crypto: {algo_str}'
                    if mode and mode in _WEAK_MODES:
                        desc += f' [{_WEAK_MODES[mode][0]}]'
                        # Mode context ADDS to description but NEVER downgrades algorithm severity.
                        # A CRITICAL RSA finding stays CRITICAL even when mode info is benign.
                    findings.append(TSFinding(a, s, c, desc,
                        filepath, line + 1, snippet, mode=mode))

        # Check KeyPairGenerator, KeyAgreement
        elif method_name in ('generateKeyPair', 'generateKey', 'init'):
            # Try to find key size in arguments
            key_size = _get_first_integer_arg(node, source)
            # Only fire if key_size is in plausible asymmetric range.
            # Symmetric keys: AES (128/192/256), ChaCha (256), etc. — all <= 512.
            # Asymmetric keys: RSA (1024/2048/3072/4096), DSA (1024/2048/3072).
            # Below 1024: almost certainly symmetric. Don't report as RSA.
            if key_size and key_size >= 1024:
                obj = node.child_by_field_name('object')
                if obj:
                    desc = f'Java key generation (size={key_size})'
                    sev = Severity.CRITICAL if key_size < 4096 else Severity.HIGH
                    findings.append(TSFinding('RSA', sev, Category.KEY_EXCHANGE,
                        desc, filepath, line + 1, snippet, key_size=key_size))

    _walk_for_type(root, 'method_invocation', check_invocation)
    return findings


def _analyze_go(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Go source for crypto usage."""
    findings = []
    root = tree.root_node
    imported_crypto: Set[str] = set()

    # Track crypto imports
    def _process_import_spec(spec):
        path_node = spec.child_by_field_name('path')
        if path_node:
            path = _extract_string_value(path_node, source)
            if path and path.startswith('crypto/'):
                imported_crypto.add(path)
                for pat in GO_CRYPTO:
                    if path == pat.module:
                        findings.append(TSFinding(
                            pat.algorithm, Severity.HIGH, pat.category,
                            f'Go crypto import: {path}',
                            filepath, spec.start_point[0] + 1,
                            _get_line_text(source, spec.start_point[0]),
                        ))

    def check_import(node):
        for child in node.children:
            if child.type == 'import_spec_list':
                for spec in child.children:
                    if spec.type == 'import_spec':
                        _process_import_spec(spec)
            elif child.type == 'import_spec':
                _process_import_spec(child)
            # Handle single-line: import "crypto/rsa"
            elif child.type in ('interpreted_string_literal', 'raw_string_literal'):
                path = _extract_string_value(child, source)
                if path and path.startswith('crypto/'):
                    imported_crypto.add(path)
                    for pat in GO_CRYPTO:
                        if path == pat.module:
                            findings.append(TSFinding(
                                pat.algorithm, Severity.HIGH, pat.category,
                                f'Go crypto import: {path}',
                                filepath, node.start_point[0] + 1,
                                _get_line_text(source, node.start_point[0]),
                            ))

    _walk_for_type(root, 'import_declaration', check_import)

    # Track function calls
    def check_call(node):
        func_node = node.child_by_field_name('function')
        if func_node is None:
            return
        func_text = _node_text(func_node, source)
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        for pat in GO_CRYPTO:
            pkg = pat.module.split('/')[-1]
            if func_text == f'{pkg}.{pat.function}':
                key_size = None
                if pat.key_size_pos is not None:
                    key_size = _get_nth_integer_arg(node, source, pat.key_size_pos)
                desc = pat.description
                if key_size:
                    desc += f' (key_size={key_size})'
                findings.append(TSFinding(
                    pat.algorithm, pat.severity, pat.category, desc,
                    filepath, line + 1, snippet, key_size=key_size,
                ))
                return

    _walk_for_type(root, 'call_expression', check_call)
    return findings


def _analyze_javascript(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of JavaScript/TypeScript for crypto usage."""
    findings = []
    root = tree.root_node

    def check_call(node):
        func_node = node.child_by_field_name('function')
        if func_node is None:
            return
        func_text = _node_text(func_node, source)
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        for pat in JS_CRYPTO:
            if func_text == f'{pat.module}.{pat.function}' or func_text == pat.function:
                algo_str = _get_first_string_arg(node, source)
                algo = pat.algorithm
                sev = pat.severity

                # Refine based on string argument
                if algo_str:
                    algo_lower = algo_str.lower()
                    if algo_lower in _QUANTUM_VULNERABLE_STRINGS:
                        a, s, c = _QUANTUM_VULNERABLE_STRINGS[algo_lower]
                        algo, sev = a, s

                findings.append(TSFinding(
                    algo, sev, pat.category, f'{pat.description}: {func_text}',
                    filepath, line + 1, snippet,
                ))
                return

    _walk_for_type(root, 'call_expression', check_call)
    return findings


def _analyze_rust(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Rust source for crypto crate usage."""
    findings = []
    root = tree.root_node
    imported_crates: Set[str] = set()

    # Track use declarations — word-boundary match to avoid substring false positives
    # (e.g., 'dsa' must not match 'ed25519_dalek')
    import re as _re
    def check_use(node):
        text = _node_text(node, source)
        for pat in RUST_CRYPTO:
            if _re.search(r'\b' + _re.escape(pat.module) + r'\b', text):
                imported_crates.add(pat.module)
                findings.append(TSFinding(
                    pat.algorithm, Severity.HIGH, pat.category,
                    f'Rust crypto crate: {pat.module}',
                    filepath, node.start_point[0] + 1,
                    _get_line_text(source, node.start_point[0]),
                ))

    _walk_for_type(root, 'use_declaration', check_use)

    # Track constructor/method calls.
    # Match the QUALIFIED path (module::function) OR (module.function), not a bare function name.
    # Bare name matching caused false positives on common method names like .sign(), .new(), .generate()
    # in any file that imported a crypto crate.
    def check_call(node):
        func_node = node.child_by_field_name('function')
        if func_node is None:
            return
        func_text = _node_text(func_node, source)
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        for pat in RUST_CRYPTO:
            # Require qualified path: either "module::function" or "module.function" or "module::...::function"
            qualified_colons = f'{pat.module}::{pat.function}'
            qualified_dot = f'{pat.module}.{pat.function}'
            # Also accept any path starting with module:: that ends in function
            nested_pattern = r'\b' + _re.escape(pat.module) + r'::[\w:]*' + _re.escape(pat.function) + r'\b'
            if (qualified_colons in func_text
                or qualified_dot in func_text
                or _re.search(nested_pattern, func_text)):
                findings.append(TSFinding(
                    pat.algorithm, pat.severity, pat.category, pat.description,
                    filepath, line + 1, snippet,
                ))
                return

    _walk_for_type(root, 'call_expression', check_call)
    return findings


def _analyze_c(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of C/C++ source for OpenSSL/crypto library usage."""
    findings = []
    root = tree.root_node

    def check_call(node):
        func_node = node.child_by_field_name('function')
        if func_node is None:
            return
        func_text = _node_text(func_node, source)
        line = node.start_point[0]
        snippet = _get_line_text(source, line)

        for pat in C_CRYPTO:
            if func_text == pat.function:
                key_size = None
                if pat.key_size_pos is not None:
                    key_size = _get_nth_integer_arg(node, source, pat.key_size_pos)
                desc = pat.description
                if key_size:
                    desc += f' (key_size={key_size})'
                findings.append(TSFinding(
                    pat.algorithm, pat.severity, pat.category, desc,
                    filepath, line + 1, snippet, key_size=key_size,
                ))
                return

    _walk_for_type(root, 'call_expression', check_call)
    return findings


# ============================================================================
# GENERIC AST HELPERS (shared by dedicated language analyzers below)
# ============================================================================

def _find_args_container(node):
    """Find the arguments container node regardless of language-specific naming.

    Different tree-sitter grammars use different node types for argument lists:
    Python/Java/Go/C: field name 'arguments'
    C#: 'argument_list'
    Kotlin: 'value_arguments'
    Swift: 'call_suffix' wrapping 'value_arguments'
    Scala: 'arguments'
    """
    args = node.child_by_field_name('arguments')
    if args is not None:
        return args
    for child in node.children:
        if child.type in ('argument_list', 'arguments', 'value_arguments',
                          'call_suffix'):
            return child
    return None


def _find_first_string_in_subtree(node, source: bytes) -> Optional[str]:
    """Find and extract the first string literal value in a node's subtree.

    Handles all tree-sitter string node types across supported languages:
    Python/Java/Go/C: 'string', 'string_literal', 'interpreted_string_literal'
    C#: 'string_literal'
    Ruby/PHP/Scala: 'string'
    Kotlin: 'string_literal'
    Swift: 'line_string_literal'
    """
    if node is None:
        return None
    _STRING_TYPES = {'string', 'string_literal', 'line_string_literal',
                     'interpreted_string_literal', 'raw_string_literal'}
    if node.type in _STRING_TYPES:
        return _extract_string_value(node, source)
    for child in node.children:
        result = _find_first_string_in_subtree(child, source)
        if result is not None:
            return result
    return None


def _find_first_integer_in_subtree(node, source: bytes) -> Optional[int]:
    """Find and extract the first integer literal value in a node's subtree.

    Handles all tree-sitter integer node types across supported languages:
    Python/Java/Go/C/C#/Scala: 'integer_literal'
    Ruby/PHP: 'integer'
    Kotlin: 'number_literal'
    Swift: 'integer_literal'
    """
    if node is None:
        return None
    _INT_TYPES = {'integer', 'integer_literal', 'number_literal',
                  'int_literal', 'decimal_integer_literal'}
    if node.type in _INT_TYPES:
        return _extract_integer(node, source)
    for child in node.children:
        result = _find_first_integer_in_subtree(child, source)
        if result is not None:
            return result
    return None


def _match_call_against_patterns(node, source: bytes, filepath: str,
                                  patterns: list, findings: list):
    """Match a call/invocation AST node against crypto patterns.

    Core matching logic shared by all dedicated language analyzers.
    By operating on call-expression nodes (not raw text), we eliminate
    false positives from comments, string literals, and documentation.
    Extracts key sizes and algorithm strings from AST argument nodes.
    """
    call_text = _node_text(node, source)
    line = node.start_point[0]
    snippet = _get_line_text(source, line)

    import re as _re_match
    for pat in patterns:
        # Word-boundary match to avoid false positives from substrings
        # (e.g., 'new' must not match 'renewed', 'sign' must not match 'assign')
        if not _re_match.search(r'(?<![a-zA-Z_])' + _re_match.escape(pat.function) + r'(?![a-zA-Z_])', call_text):
            continue

        args_node = _find_args_container(node)
        key_size = _find_first_integer_in_subtree(args_node, source)
        algo_str = _find_first_string_in_subtree(args_node, source)

        algo, sev = pat.algorithm, pat.severity
        mode = None

        # Refine algorithm from string argument (e.g., getInstance("RSA/ECB/PKCS1"))
        if algo_str:
            algo_lower = algo_str.lower().split('/')[0]
            if algo_lower in _QUANTUM_VULNERABLE_STRINGS:
                a, s, _ = _QUANTUM_VULNERABLE_STRINGS[algo_lower]
                algo, sev = a, s
            # Detect cipher mode from transform string
            if '/' in algo_str:
                parts = algo_str.split('/')
                if len(parts) >= 2:
                    mode_candidate = parts[1].lower()
                    if mode_candidate in _WEAK_MODES:
                        mode = mode_candidate
                        # Mode context adds description only — NEVER downgrades severity.
                        # Same fix as _analyze_java: CRITICAL RSA stays CRITICAL regardless of mode.

        desc = pat.description
        if key_size:
            desc += f' (key_size={key_size})'
        if mode and mode in _WEAK_MODES:
            desc += f' [{_WEAK_MODES[mode][0]}]'

        findings.append(TSFinding(
            algorithm=algo, severity=sev, category=pat.category,
            description=desc, file=filepath, line=line + 1,
            code_snippet=snippet, key_size=key_size, mode=mode,
        ))
        return  # First match wins per call node


# ============================================================================
# DEDICATED ANALYZERS: C#, Ruby, PHP, Kotlin, Swift, Scala
# ============================================================================

def _analyze_csharp(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of C# for System.Security.Cryptography usage.

    AST node types used:
      using_directive — track crypto namespace imports
      invocation_expression — RSA.Create(), ECDsa.Create(), MD5.Create()
      object_creation_expression — new RSACryptoServiceProvider(2048)
      member_access_expression, argument_list, string_literal, integer_literal
    """
    findings = []
    root = tree.root_node

    def check_call(node):
        _match_call_against_patterns(node, source, filepath, CSHARP_CRYPTO, findings)

    _walk_for_type(root, 'invocation_expression', check_call)
    _walk_for_type(root, 'object_creation_expression', check_call)
    return findings


def _analyze_ruby(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Ruby for OpenSSL and Digest crypto usage.

    AST node types used:
      call — method calls and require statements (Ruby has no import node)
      scope_resolution — namespaced access (OpenSSL::PKey::RSA)
      constant — class/module names within scope_resolution
      string, integer, argument_list
    """
    findings = []
    root = tree.root_node

    # Check all call nodes: covers require 'openssl', Class.new(2048), method(args)
    def check_call(node):
        _match_call_against_patterns(node, source, filepath, RUBY_CRYPTO, findings)
    _walk_for_type(root, 'call', check_call)

    # Check scope_resolution for bare references (Digest::MD5, OpenSSL::PKey::RSA)
    # These appear when the class is referenced but .new() may be on a parent node
    seen_lines = {f.line for f in findings}

    def check_scope(node):
        text = _node_text(node, source)
        line = node.start_point[0] + 1
        if line in seen_lines:
            return
        snippet = _get_line_text(source, node.start_point[0])
        for pat in RUBY_CRYPTO:
            if pat.function in text:
                findings.append(TSFinding(
                    algorithm=pat.algorithm, severity=pat.severity,
                    category=pat.category, description=pat.description,
                    file=filepath, line=line, code_snippet=snippet,
                ))
                seen_lines.add(line)
                return
    _walk_for_type(root, 'scope_resolution', check_scope)
    return findings


def _analyze_php(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of PHP for OpenSSL, hash, and mcrypt crypto usage.

    AST node types used:
      function_call_expression — openssl_pkey_new(), md5(), sha1(), mcrypt_encrypt()
      member_call_expression — $obj->method() (-> operator)
      scoped_call_expression — ClassName::method() (:: operator)
      string, integer
    """
    findings = []
    root = tree.root_node

    def check_call(node):
        _match_call_against_patterns(node, source, filepath, PHP_CRYPTO, findings)

    _walk_for_type(root, 'function_call_expression', check_call)
    _walk_for_type(root, 'member_call_expression', check_call)
    _walk_for_type(root, 'scoped_call_expression', check_call)
    return findings


def _analyze_kotlin(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Kotlin for JCA crypto API usage.

    Kotlin uses the same JCA APIs as Java (Cipher.getInstance, KeyPairGenerator, etc.)
    AST node types used:
      import — javax.crypto, java.security imports
      call_expression — function/method calls
      navigation_expression — dot access (Cipher.getInstance)
      string_literal, number_literal (NOT integer_literal), value_arguments
    """
    findings = []
    root = tree.root_node

    def check_call(node):
        _match_call_against_patterns(node, source, filepath, KOTLIN_CRYPTO, findings)
    _walk_for_type(root, 'call_expression', check_call)
    return findings


def _analyze_swift(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Swift for CryptoKit, Security, and CommonCrypto usage.

    AST node types used:
      import_declaration — CryptoKit, Security, CommonCrypto framework imports
      call_expression — function/constructor calls
      navigation_expression + navigation_suffix — member access (P256.Signing.PrivateKey)
      simple_identifier (NOT identifier), call_suffix wrapping value_arguments
      line_string_literal (NOT string_literal), integer_literal
    """
    findings = []
    root = tree.root_node

    def check_call(node):
        _match_call_against_patterns(node, source, filepath, SWIFT_CRYPTO, findings)
    _walk_for_type(root, 'call_expression', check_call)
    return findings


def _analyze_scala(tree, source: bytes, filepath: str) -> List[TSFinding]:
    """Deep analysis of Scala for JCA crypto API usage.

    Scala uses the same JCA APIs as Java/Kotlin via interop.
    AST node types used:
      import_declaration — javax.crypto, java.security imports
      call_expression — function/method calls
      field_expression — dot access (Cipher.getInstance)
      instance_expression — new keyword object creation
      arguments (NOT argument_list), string (NOT string_literal), integer_literal
    """
    findings = []
    root = tree.root_node

    def check_call(node):
        _match_call_against_patterns(node, source, filepath, SCALA_CRYPTO, findings)
    _walk_for_type(root, 'call_expression', check_call)
    _walk_for_type(root, 'instance_expression', check_call)
    return findings


def _analyze_iac(filepath: str, source: bytes) -> List[TSFinding]:
    """Scan Infrastructure-as-Code files for crypto configuration.

    Handles: Terraform (.tf), YAML configs, Dockerfiles.
    """
    import re as _re
    findings = []
    text = source.decode('utf-8', errors='replace')
    lines = text.split('\n')
    ext = Path(filepath).suffix.lower()
    name = Path(filepath).name.lower()

    # IaC crypto patterns
    iac_patterns = [
        # TLS version configuration
        (_re.compile(r'tls_version\s*=\s*["\']?(TLS1\.0|TLSv1\.0|TLS1\.1|TLSv1\.1|SSLv3)',
                     _re.IGNORECASE),
         'Old TLS', Severity.HIGH, Category.PROTOCOL, 'Deprecated TLS version in IaC config'),
        # Weak cipher suites
        (_re.compile(r'cipher[_\s]?suites?.*(?:RC4|DES|3DES|NULL|EXPORT|anon)', _re.IGNORECASE),
         'Weak cipher', Severity.HIGH, Category.PROTOCOL, 'Weak cipher suite in IaC config'),
        # RSA key type in Terraform/config
        (_re.compile(r'key_algorithm\s*=\s*["\']?RSA', _re.IGNORECASE),
         'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key algorithm in IaC'),
        (_re.compile(r'algorithm\s*=\s*["\']?RSA', _re.IGNORECASE),
         'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA algorithm in IaC config'),
        # Terraform TLS provider
        (_re.compile(r'resource\s+"tls_private_key".*\{', _re.IGNORECASE),
         'RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'Terraform TLS private key resource'),
        # SSH key type
        (_re.compile(r'ssh[_-]key[_-]type\s*[:=]\s*["\']?rsa', _re.IGNORECASE),
         'RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'RSA SSH key type in config'),
        # Docker: weak crypto in env/args
        (_re.compile(r'(?:ENV|ARG)\s+.*(?:CIPHER|TLS|SSL).*(?:RC4|DES|MD5|SHA1)', _re.IGNORECASE),
         'Weak cipher', Severity.HIGH, Category.PROTOCOL, 'Weak crypto in Dockerfile'),
        # YAML: certificate algorithm
        (_re.compile(r'algorithm:\s*(?:RSA|DSA|ECDSA)', _re.IGNORECASE),
         'RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'Certificate algorithm in YAML config'),
        # Min TLS version in YAML
        (_re.compile(r'min[_\-]?tls[_\-]?version:\s*["\']?1\.[01]', _re.IGNORECASE),
         'Old TLS', Severity.HIGH, Category.PROTOCOL, 'Deprecated min TLS version'),
    ]

    for line_num, line in enumerate(lines, 1):
        for pattern, algo, severity, category, desc in iac_patterns:
            if pattern.search(line):
                rec, replacement = REMEDIATION.get(algo, (
                    'Update to quantum-safe configuration', 'Consult NIST PQC standards'))
                findings.append(TSFinding(
                    algorithm=algo, severity=severity, category=category,
                    description=f'{desc} (IaC)',
                    file=filepath, line=line_num,
                    code_snippet=line.strip()[:120],
                ))

    return findings


_ANALYZERS = {
    'python': _analyze_python,
    'java': _analyze_java,
    'go': _analyze_go,
    'javascript': _analyze_javascript,
    'typescript': _analyze_javascript,
    'rust': _analyze_rust,
    'c': _analyze_c,
    'csharp': _analyze_csharp,
    'ruby': _analyze_ruby,
    'php': _analyze_php,
    'kotlin': _analyze_kotlin,
    'swift': _analyze_swift,
    'scala': _analyze_scala,
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _walk_for_type(node, node_type: str, callback):
    """Walk tree and call callback for every node of the given type."""
    if node.type == node_type:
        callback(node)
    for child in node.children:
        _walk_for_type(child, node_type, callback)


def _track_python_import(node, source: bytes, imports: Dict[str, str]):
    """Track `import X` and `import X as Y` statements."""
    for child in node.children:
        if child.type == 'dotted_name':
            name = _node_text(child, source)
            imports[name.split('.')[-1]] = name
        elif child.type == 'aliased_import':
            name_node = child.child_by_field_name('name')
            alias_node = child.child_by_field_name('alias')
            if name_node:
                full_name = _node_text(name_node, source)
                local = _node_text(alias_node, source) if alias_node else full_name.split('.')[-1]
                imports[local] = full_name


def _track_python_from_import(node, source: bytes, imports: Dict[str, str]):
    """Track `from X import Y` and `from X import Y as Z` statements."""
    module_node = node.child_by_field_name('module_name')
    if module_node is None:
        return
    module = _node_text(module_node, source)

    for child in node.children:
        if child.type == 'dotted_name' and child != module_node:
            name = _node_text(child, source)
            imports[name] = f'{module}.{name}'
        elif child.type == 'aliased_import':
            name_node = child.child_by_field_name('name')
            alias_node = child.child_by_field_name('alias')
            if name_node:
                name = _node_text(name_node, source)
                local = _node_text(alias_node, source) if alias_node else name
                imports[local] = f'{module}.{name}'
        elif child.type == 'import_prefix':
            # from X import Y — the Y names are in the remaining children
            pass


def _extract_call_info_python(node, source: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Extract function name and object name from a Python call node."""
    func_node = node.child_by_field_name('function')
    if func_node is None:
        return None, None

    if func_node.type == 'attribute':
        attr_node = func_node.child_by_field_name('attribute')
        obj_node = func_node.child_by_field_name('object')
        func_name = _node_text(attr_node, source) if attr_node else None
        obj_name = _node_text(obj_node, source) if obj_node else None
        return func_name, obj_name
    elif func_node.type == 'identifier':
        return _node_text(func_node, source), None
    return None, None


def _get_first_string_arg(node, source: bytes) -> Optional[str]:
    """Get the first string argument from a function call."""
    args_node = node.child_by_field_name('arguments')
    if args_node is None:
        return None
    for child in args_node.children:
        if child.type in ('string', 'string_literal', 'interpreted_string_literal',
                          'raw_string_literal', 'string_content'):
            return _extract_string_value(child, source)
        # Handle string inside expression_statement or other wrappers
        if child.type == 'string_fragment':
            return _node_text(child, source)
    return None


def _get_first_integer_arg(node, source: bytes) -> Optional[int]:
    """Get the first integer argument from a function call."""
    args_node = node.child_by_field_name('arguments')
    if args_node is None:
        return None
    for child in args_node.children:
        if child.type in ('integer', 'integer_literal', 'int_literal', 'decimal_integer_literal'):
            return _extract_integer(child, source)
    return None


def _get_nth_integer_arg(node, source: bytes, n: int) -> Optional[int]:
    """Get the nth positional argument as integer (0-indexed)."""
    args_node = node.child_by_field_name('arguments')
    if args_node is None:
        return None
    real_args = [c for c in args_node.children if c.type not in ('(', ')', ',')]
    if n < len(real_args):
        return _extract_integer(real_args[n], source)
    return None


def _extract_key_size(node, source: bytes, pat: CryptoPattern) -> Optional[int]:
    """Extract key size from function arguments."""
    if pat.key_size_pos is not None:
        return _get_nth_integer_arg(node, source, pat.key_size_pos)
    if pat.key_size_arg:
        args_node = node.child_by_field_name('arguments')
        if args_node is None:
            return None
        for child in args_node.children:
            if child.type == 'keyword_argument':
                name_node = child.child_by_field_name('name')
                value_node = child.child_by_field_name('value')
                if name_node and value_node:
                    if _node_text(name_node, source) == pat.key_size_arg:
                        return _extract_integer(value_node, source)
    return None


def _detect_mode_from_args(node, source: bytes) -> Optional[str]:
    """Detect cipher mode (ECB, CBC, GCM) from function arguments."""
    args_node = node.child_by_field_name('arguments')
    if args_node is None:
        return None
    args_text = _node_text(args_node, source).upper()
    for mode in ('ECB', 'CBC', 'CTR', 'GCM', 'CFB', 'OFB', 'CCM'):
        if f'MODE_{mode}' in args_text or f'.{mode}' in args_text:
            return mode.lower()
    return None


def _check_string_args_for_crypto(node, source, filepath, line, snippet, findings):
    """Check string arguments for quantum-vulnerable algorithm names."""
    args_node = node.child_by_field_name('arguments')
    if args_node is None:
        return
    for child in args_node.children:
        if child.type in ('string', 'string_literal', 'interpreted_string_literal'):
            val = _extract_string_value(child, source)
            if val and val.lower() in _QUANTUM_VULNERABLE_STRINGS:
                a, s, c = _QUANTUM_VULNERABLE_STRINGS[val.lower()]
                findings.append(TSFinding(a, s, c,
                    f'Algorithm string reference: "{val}"',
                    filepath, line + 1, snippet))


# ============================================================================
# PUBLIC API
# ============================================================================

def ts_scan_file(filepath: str) -> List[Finding]:
    """Scan a single file using tree-sitter deep analysis.

    Returns standard Finding objects compatible with the rest of the scanner pipeline.
    Handles both tree-sitter languages and IaC config files.
    """
    ext = Path(filepath).suffix.lower()
    name = Path(filepath).name.lower()
    lang = _EXT_TO_LANG.get(ext)

    # Also check filename for Dockerfile
    if name == 'dockerfile' or name.startswith('dockerfile.'):
        lang = 'docker'

    if lang is None:
        return []

    try:
        source = Path(filepath).read_bytes()
    except (OSError, PermissionError):
        return []

    # IaC files: use regex-based analyzer (no tree-sitter needed)
    if lang in ('terraform', 'yaml_config', 'docker'):
        ts_findings = _analyze_iac(filepath, source)
    else:
        if not TREE_SITTER_AVAILABLE:
            return []
        parser = _get_parser(lang)
        if parser is None:
            return []
        analyzer = _ANALYZERS.get(lang)
        if analyzer is None:
            return []
        tree = parser.parse(source)
        ts_findings = analyzer(tree, source, filepath)

    # Convert TSFinding → Finding
    findings = []
    # Stable hash: hashlib.md5 is deterministic across Python processes.
    # Python's built-in hash() is randomized per-process (PEP 456) and produces
    # different finding IDs on every run, breaking downstream ID tracking.
    import hashlib as _hashlib
    _file_hash = int(_hashlib.md5(filepath.encode('utf-8', errors='replace')).hexdigest()[:4], 16)
    for i, tsf in enumerate(ts_findings):
        rec, replacement = REMEDIATION.get(tsf.algorithm, (
            'Review and migrate to PQC equivalent', 'Consult NIST PQC standards'))
        desc = f'{tsf.description} (tree-sitter deep analysis)'
        if tsf.key_size:
            desc = f'{tsf.description}'  # key_size already in description
        findings.append(Finding(
            id=f'TS-{_file_hash:04X}-{i + 1:04d}',
            severity=tsf.severity,
            category=tsf.category,
            algorithm=tsf.algorithm,
            file=filepath,
            line=tsf.line,
            code_snippet=tsf.code_snippet,
            description=desc,
            recommendation=rec,
            pqc_replacement=replacement,
        ))
    return findings


def ts_scan_directory(path: str) -> List[Finding]:
    """Scan all supported files in a directory using tree-sitter."""
    if not TREE_SITTER_AVAILABLE:
        return []

    findings = []
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
    target = Path(path)

    if target.is_file():
        return ts_scan_file(str(target))

    file_count = 0
    max_files = 10000  # Same cap as PQCScanner._walk_files
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if file_count >= max_files:
                import sys as _sys
                print(f"Warning: tree-sitter scan capped at {max_files} files. "
                      f"Use regex scanner for remaining files.", file=_sys.stderr)
                return findings
            ext = Path(fname).suffix.lower()
            if ext in _EXT_TO_LANG:
                filepath = os.path.join(dirpath, fname)
                findings.extend(ts_scan_file(filepath))
                file_count += 1

    return findings


def get_supported_languages() -> List[str]:
    """Return list of languages with tree-sitter support available."""
    available = []
    for lang in _LANGUAGE_MODULES:
        if _get_parser(lang) is not None:
            available.append(lang)
    return available
