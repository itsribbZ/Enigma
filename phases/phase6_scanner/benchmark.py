"""
Enigma pqc-scanner v4.0: Precision/Recall Benchmark Suite.

Tests the scanner against known crypto patterns (true positives)
and non-crypto code (true negatives) to measure accuracy.

Metrics:
  Precision = TP / (TP + FP)  — "of what we flagged, how much was real?"
  Recall    = TP / (TP + FN)  — "of what exists, how much did we find?"
  F1 Score  = 2 * (P * R) / (P + R)
"""

from __future__ import annotations
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from pqc_scanner import PQCScanner, Finding
from treesitter_scanner import ts_scan_file, TREE_SITTER_AVAILABLE


# ============================================================================
# BENCHMARK DATA — Known True Positives (code that SHOULD be detected)
# ============================================================================

TRUE_POSITIVES = {
    # (filename, code, expected_algorithms)
    'python_rsa.py': (
        'from cryptography.hazmat.primitives.asymmetric import rsa\n'
        'key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n',
        {'RSA'},
    ),
    'python_ecdsa.py': (
        'from cryptography.hazmat.primitives.asymmetric import ec\n'
        'key = ec.generate_private_key(ec.SECP256R1())\n'
        'sig = key.sign(data, ec.ECDSA(hashes.SHA256()))\n',
        {'ECDSA'},
    ),
    'python_md5.py': (
        'import hashlib\n'
        'h = hashlib.md5(data)\n',
        {'MD5'},
    ),
    'python_sha1.py': (
        'import hashlib\n'
        'h = hashlib.sha1(data)\n',
        {'SHA-1'},
    ),
    'python_des.py': (
        'from Crypto.Cipher import DES3\n'
        'cipher = DES3.new(key, DES3.MODE_CBC)\n',
        {'3DES'},
    ),
    'python_dh.py': (
        'from cryptography.hazmat.primitives.asymmetric import dh\n'
        'params = dh.generate_parameters(generator=2, key_size=2048)\n',
        {'DH'},
    ),
    'python_hashlib_new.py': (
        'import hashlib\n'
        'h = hashlib.new("sha1", data)\n',
        {'SHA-1'},
    ),
    'java_rsa.java': (
        'import java.security.KeyPairGenerator;\n'
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
        'kpg.initialize(2048);\n',
        {'RSA'},
    ),
    'java_cipher_des.java': (
        'import javax.crypto.Cipher;\n'
        'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");\n',
        {'3DES'},
    ),
    'java_md5.java': (
        'import java.security.MessageDigest;\n'
        'MessageDigest md = MessageDigest.getInstance("MD5");\n',
        {'MD5'},
    ),
    'java_sha1.java': (
        'import java.security.MessageDigest;\n'
        'MessageDigest md = MessageDigest.getInstance("SHA-1");\n',
        {'SHA-1'},
    ),
    'go_rsa.go': (
        'package main\n\nimport "crypto/rsa"\nimport "crypto/rand"\n\n'
        'func main() {\n    key, _ := rsa.GenerateKey(rand.Reader, 2048)\n}\n',
        {'RSA'},
    ),
    'go_ecdsa.go': (
        'package main\n\nimport "crypto/ecdsa"\nimport "crypto/elliptic"\n\n'
        'func main() {\n    key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n}\n',
        {'ECDSA', 'ECDH'},
    ),
    'go_des.go': (
        'package main\n\nimport "crypto/des"\n\n'
        'func main() {\n    block, _ := des.NewCipher(key)\n}\n',
        {'3DES'},
    ),
    'js_rsa.js': (
        "const crypto = require('crypto');\n"
        "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, callback);\n",
        {'RSA'},
    ),
    'js_dh.js': (
        "const crypto = require('crypto');\n"
        "const dh = crypto.createDiffieHellman(2048);\n",
        {'DH'},
    ),
    'rust_rsa.rs': (
        'use rsa::{RsaPrivateKey, RsaPublicKey};\n\n'
        'fn main() {\n    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();\n}\n',
        {'RSA'},
    ),
    'c_openssl_rsa.c': (
        '#include <openssl/rsa.h>\n\n'
        'int main() {\n    RSA *rsa = RSA_new();\n    return 0;\n}\n',
        {'RSA'},
    ),
    'c_openssl_md5.c': (
        '#include <openssl/evp.h>\n\nvoid hash() {\n    const EVP_MD *md = EVP_md5();\n}\n',
        {'MD5'},
    ),
    'cs_rsa.cs': (
        'using System.Security.Cryptography;\nvar rsa = RSA.Create(2048);\n',
        {'RSA'},
    ),
    'config_tls.conf': (
        'ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n'
        'ssl_ciphers RC4-SHA:DES-CBC3-SHA;\n',
        {'Old TLS', 'RC4', 'Weak cipher'},
    ),
    'terraform_rsa.tf': (
        'resource "tls_private_key" "example" {\n'
        '  algorithm = "RSA"\n  rsa_bits  = 2048\n}\n',
        {'RSA'},
    ),
}

# ============================================================================
# BENCHMARK DATA — Known True Negatives (code that should NOT be detected)
# ============================================================================

TRUE_NEGATIVES = {
    'clean_python.py': (
        'import os\nimport sys\nimport json\n\n'
        'def hello(name):\n    print(f"Hello, {name}")\n\n'
        'data = json.loads(\'{"key": "value"}\')\n'
        'path = os.path.join("/tmp", "file.txt")\n',
    ),
    'clean_java.java': (
        'import java.util.List;\nimport java.util.ArrayList;\n\n'
        'public class Main {\n'
        '    public static void main(String[] args) {\n'
        '        List<String> items = new ArrayList<>();\n'
        '        items.add("hello");\n'
        '        System.out.println(items.size());\n'
        '    }\n}\n',
    ),
    'clean_go.go': (
        'package main\n\nimport "fmt"\nimport "strings"\n\n'
        'func main() {\n    s := strings.ToUpper("hello")\n    fmt.Println(s)\n}\n',
    ),
    'clean_js.js': (
        'const fs = require("fs");\n'
        'const data = fs.readFileSync("file.txt", "utf8");\n'
        'console.log(data.length);\n',
    ),
    'clean_rust.rs': (
        'fn main() {\n    let x = 42;\n    println!("Value: {}", x);\n}\n',
    ),
    'clean_c.c': (
        '#include <stdio.h>\n#include <string.h>\n\n'
        'int main() {\n    char buf[256];\n    strcpy(buf, "hello");\n'
        '    printf("%s\\n", buf);\n    return 0;\n}\n',
    ),
    'comment_only.py': (
        '# This file discusses RSA encryption\n'
        '# We should migrate from SHA-1 to SHA-256\n'
        '# DES is deprecated, use AES instead\n'
        'print("no actual crypto here")\n',
    ),
    'string_only.py': (
        'msg = "Please migrate from RSA to ML-KEM"\n'
        'log = "SHA-1 hash detected in legacy system"\n'
        'note = "3DES is no longer secure"\n',
    ),
}


# ============================================================================
# BENCHMARK RUNNER
# ============================================================================

@dataclass
class BenchmarkResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    scan_time: float
    details: List[str]


def run_benchmark() -> BenchmarkResult:
    """Run the full precision/recall benchmark."""
    details = []
    tp = 0  # True positives: correctly detected crypto
    fp = 0  # False positives: flagged non-crypto as crypto
    fn = 0  # False negatives: missed real crypto
    tn = 0  # True negatives: correctly ignored non-crypto

    scanner = PQCScanner()
    start = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        # ── Test True Positives ──
        details.append("=== TRUE POSITIVES ===")
        for filename, (code, expected_algos) in TRUE_POSITIVES.items():
            filepath = os.path.join(tmpdir, filename)
            Path(filepath).write_text(code, encoding='utf-8')

            # Run both regex and tree-sitter
            result = scanner.scan(filepath)
            ts_findings = ts_scan_file(filepath) if TREE_SITTER_AVAILABLE else []

            # Combine and deduplicate
            all_algos = set()
            for f in result.findings:
                all_algos.add(f.algorithm)
            for f in ts_findings:
                all_algos.add(f.algorithm)

            # Check if expected algorithms were found
            found = expected_algos & all_algos
            missed = expected_algos - all_algos

            if found:
                tp += len(found)
                details.append(f"  [TP] {filename}: found {found}")
            if missed:
                fn += len(missed)
                details.append(f"  [FN] {filename}: MISSED {missed} (found {all_algos})")
            if not found and not missed:
                fn += 1
                details.append(f"  [FN] {filename}: NOTHING found (expected {expected_algos})")

            # Check for unexpected algorithms (not a FP for this test, but notable)
            extra = all_algos - expected_algos
            if extra:
                # Compound algorithms like RSA/ECDSA are acceptable matches
                real_extra = set()
                for e in extra:
                    if not any(exp in e or e in exp for exp in expected_algos):
                        real_extra.add(e)
                if real_extra:
                    details.append(f"  [!]  {filename}: extra detections {real_extra}")

        # ── Test True Negatives ──
        details.append("\n=== TRUE NEGATIVES ===")
        for filename, code_tuple in TRUE_NEGATIVES.items():
            code = code_tuple[0] if isinstance(code_tuple, tuple) else code_tuple
            filepath = os.path.join(tmpdir, filename)
            Path(filepath).write_text(code, encoding='utf-8')

            result = scanner.scan(filepath)
            ts_findings = ts_scan_file(filepath) if TREE_SITTER_AVAILABLE else []
            total_findings = len(result.findings) + len(ts_findings)

            if total_findings == 0:
                tn += 1
                details.append(f"  [TN] {filename}: correctly clean")
            else:
                fp += total_findings
                algos = set(f.algorithm for f in result.findings)
                algos.update(f.algorithm for f in ts_findings)
                details.append(f"  [FP] {filename}: FALSE POSITIVE — {algos}")

    elapsed = time.time() - start

    # Calculate metrics
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)

    return BenchmarkResult(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        scan_time=round(elapsed, 3),
        details=details,
    )


def format_benchmark_report(result: BenchmarkResult) -> str:
    """Format benchmark results as text report."""
    lines = [
        "=" * 70,
        "  PQC-SCANNER BENCHMARK — Precision / Recall Measurement",
        "=" * 70,
        "",
        f"  TRUE POSITIVES:  {result.true_positives:>4}  (correctly detected crypto)",
        f"  FALSE POSITIVES: {result.false_positives:>4}  (flagged non-crypto as crypto)",
        f"  FALSE NEGATIVES: {result.false_negatives:>4}  (missed real crypto)",
        f"  TRUE NEGATIVES:  {result.true_negatives:>4}  (correctly ignored non-crypto)",
        "",
        f"  PRECISION:  {result.precision:.1%}  (of what we flag, how much is real)",
        f"  RECALL:     {result.recall:.1%}  (of what exists, how much we find)",
        f"  F1 SCORE:   {result.f1_score:.1%}  (harmonic mean of P and R)",
        "",
        f"  Scan time:  {result.scan_time:.3f}s",
        "",
    ]

    for line in result.details:
        lines.append(f"  {line}")

    lines.extend(["", "=" * 70])
    return "\n".join(lines)


if __name__ == '__main__':
    result = run_benchmark()
    print(format_benchmark_report(result))
