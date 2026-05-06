// Sample Go code with quantum-vulnerable crypto
package main

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/des"
)

func main() {
    // RSA — quantum vulnerable
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
    _ = key

    // ECDSA — quantum vulnerable
    ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = ecKey

    // DES — deprecated AND quantum vulnerable
    block, _ := des.NewCipher([]byte("8byteky"))
    _ = block
}
