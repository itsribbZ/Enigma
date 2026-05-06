// Sample Node.js API with quantum-vulnerable crypto
const crypto = require('crypto');

// RSA key generation — quantum vulnerable
crypto.generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
}, (err, publicKey, privateKey) => {
    console.log('Keys generated');
});

// DH key exchange — quantum vulnerable
const dh = crypto.createDiffieHellman(2048);
dh.generateKeys();

// Digital signatures
const sign = crypto.createSign('SHA256');
sign.update('data to sign');

// ECDH — quantum vulnerable
const ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();
