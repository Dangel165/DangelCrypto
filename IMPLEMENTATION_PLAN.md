# Implementation Plan

This project implements cryptographic primitives directly in Nim.

The public API exists first, but a primitive is only opened for real use after
its internal implementation has:

- deterministic tests,
- official or independently generated vectors,
- negative tests for invalid input,
- constant-time review for secret-dependent operations.

## Kyber

Current:

- modular arithmetic over `q = 3329`,
- polynomial type with 256 coefficients,
- polynomial add/sub,
- coefficient compression/decompression,
- polynomial encode/decode,
- slow reference negacyclic multiplication.
- Montgomery and Barrett reduction,
- NTT and inverse NTT,
- NTT-domain base multiplication,
- SHAKE128/SHAKE256,
- XOF uniform rejection sampler,
- Kyber 12-bit polynomial serialization,
- Kyber 4-bit and 5-bit polynomial compression,
- message-to-polynomial and polynomial-to-message conversion,
- polyvec serialization and compression,
- matrix expansion,
- PRF-based noise vector sampling,
- deterministic CPA-PKE key generation foundation,
- deterministic CPA-PKE encryption/decryption foundation,
- CPA-PKE public key, secret key, and ciphertext packing,
- SHA3-256 and SHA3-512,
- CCA-KEM keypair, encapsulation, and decapsulation foundation.

Next:

- NTT-optimized CPA PKE,
- KAT vector tests.

## Curve25519 / Ed25519

Current:

- field element representation for `2^255 - 19`,
- field add/sub/mul/square,
- encode/decode foundation,
- field inversion,
- X25519 Montgomery ladder,
- X25519 public key generation and shared-secret API,
- Edwards25519 point addition/doubling/scalar multiplication,
- Ed25519 seed-to-public-key generation.

Next:

- Ed25519 signing and verification vectors.

## ECDSA

Current:

- finite-field backend for selected curves,
- secp256k1 point addition/scalar multiplication foundation,
- compressed public key generation,
- compressed public key decoding,
- deterministic explicit-nonce ECDSA signing foundation,
- HMAC-SHA512,
- RFC6979 deterministic nonce foundation,
- deterministic ECDSA signing helper.

Next:

- compressed public key decoding fix,
- ECDSA verification optimization,
- DER/raw signature encode/decode,
- verification vectors.

## KCDSA / EC-KCDSA

Current:

- KCDSA / EC-KCDSA typed foundation,
- hash/domain separation foundation,
- signature component encoding.

Next:

- exact parameter profile selection,
- key generation,
- sign/verify,
- vector tests.
