import std/unittest

import dangelcrypto/bytes
import dangelcrypto/ecdsa
import dangelcrypto/errors
import dangelcrypto/types
import dangelcrypto/internal/secp256k1

suite "secp256k1 foundation":
  test "generator compressed encoding":
    check encodePublicKeyCompressed(generator()).toHex ==
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "private key one gives generator":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    check publicKeyFromPrivate(privateKey).toHex ==
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "compressed public key decode roundtrip":
    let encoded = encodePublicKeyCompressed(generator())
    let decoded = decodePublicKeyCompressed(encoded)
    check isOnCurve(decoded)
    check encodePublicKeyCompressed(decoded) == encoded

  test "point inverse gives infinity":
    let g = generator()
    check pointAdd(g, pointNeg(g)).infinity

  test "field multiplication sanity":
    check mulMod(fromUint64(7), fromUint64(6), P) == fromUint64(42)
    let nearP = subMod(P, fromUint64(1), P)
    check mulMod(nearP, nearP, P) == fromUint64(1)

  test "scalar multiplication by two matches point doubling":
    var two = zero256()
    two[0] = 2
    let doubled = pointAdd(generator(), generator())
    let multiplied = scalarMult(two, generator())
    check encodePublicKeyCompressed(doubled) == encodePublicKeyCompressed(multiplied)

  test "public ECDSA helper private key one":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    check secp256k1PublicKeyFromPrivate(privateKey).raw.toHex ==
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

  test "RFC6979 nonce is deterministic":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    var digest = newSeq[byte](32)
    digest[31] = 42
    check nonceRfc6979Sha512(privateKey, digest) == nonceRfc6979Sha512(privateKey, digest)
    digest[31] = 43
    check nonceRfc6979Sha512(privateKey, digest) != nonceRfc6979Sha512(privateKey, fromHex("000000000000000000000000000000000000000000000000000000000000002a"))

  test "deterministic ECDSA signing helper is reproducible":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    var digest = newSeq[byte](32)
    digest[31] = 42
    let a = ecdsaSignDeterministic(privateKey, digest)
    let b = ecdsaSignDeterministic(privateKey, digest)
    check a.r == b.r
    check a.s == b.s
    digest[31] = 43
    let c = ecdsaSignDeterministic(privateKey, digest)
    check a.r != c.r or a.s != c.s

  test "public ECDSA signing is deterministic DER":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    let key = PrivateKey(algorithm: "ECDSA", curve: Secp256k1, raw: privateKey)
    let sigA = signEcdsa(key, [byte 1, 2, 3])
    let sigB = signEcdsa(key, [byte 1, 2, 3])
    check sigA.scheme == ECDSA
    check sigA.raw == sigB.raw
    check sigA.raw.len > 8
    check sigA.raw[0] == byte 0x30

  test "public ECDSA verify accepts valid signature and rejects tampering":
    var privateKey = newSeq[byte](32)
    privateKey[31] = 1
    let publicKey = secp256k1PublicKeyFromPrivate(privateKey)
    let privateKeyObj = PrivateKey(algorithm: "ECDSA", curve: Secp256k1, raw: privateKey)
    let message = [byte 1, 2, 3, 4]
    let signature = signEcdsa(privateKeyObj, message)
    let parts = decodeDerEcdsaSignature(signature.raw)
    check ecdsaVerifyPoint(pointFromPrivate(privateKey), ecdsaMessageDigest(message), parts.r, parts.s)
    check verifyEcdsa(publicKey, message, signature)
    check not verifyEcdsa(publicKey, [byte 1, 2, 3, 5], signature)

    var tampered = signature
    tampered.raw[tampered.raw.len - 1] = tampered.raw[tampered.raw.len - 1] xor 1
    check not verifyEcdsa(publicKey, message, tampered)

  test "public ECDSA message digest uses SHA-256":
    check ecdsaMessageDigest([byte 0x61, 0x62, 0x63]).toHex ==
      "ba7816bf8f01cfea414140de5dae2223" &
      "b00361a396177a9cb410ff61f20015ad"

  test "public ECDSA rejects invalid key and signature shapes":
    expect InvalidKeyError:
      discard signEcdsa(PrivateKey(algorithm: "ECDSA", curve: Secp256k1, raw: @[]), [])
    let publicKey = PublicKey(algorithm: "ECDSA", curve: Secp256k1, raw: publicKeyFromPrivate(fromHex("0000000000000000000000000000000000000000000000000000000000000001")))
    check not verifyEcdsa(publicKey, [byte 1], Signature(scheme: EdDSA, raw: @[]))
    check not verifyEcdsa(publicKey, [byte 1], Signature(scheme: ECDSA, raw: @[byte 0x30, 0x00]))
