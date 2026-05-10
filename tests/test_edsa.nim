import std/unittest

import dangelcrypto/bytes
import dangelcrypto/edsa
import dangelcrypto/errors
import dangelcrypto/types

suite "EDSA facade":
  test "Ed25519 dispatch signs and verifies":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    let privateKey = PrivateKey(algorithm: "Ed25519", curve: Ed25519, raw: seed)
    let publicKey = edsaPublicKeyFromPrivate(privateKey)
    let signature = signEdsa(privateKey, [byte 0x72])
    check signature.scheme == EdDSA
    check verifyEdsa(publicKey, [byte 0x72], signature)
    check not verifyEdsa(publicKey, [byte 0x73], signature)

  test "secp256k1 dispatch signs and verifies":
    var privateRaw = newSeq[byte](32)
    privateRaw[31] = 1
    let privateKey = PrivateKey(algorithm: "ECDSA", curve: Secp256k1, raw: privateRaw)
    let publicKey = edsaPublicKeyFromPrivate(privateKey)
    let signature = signEdsa(privateKey, [byte 1, 2, 3])
    check signature.scheme == ECDSA
    check verifyEdsa(publicKey, [byte 1, 2, 3], signature)
    check not verifyEdsa(publicKey, [byte 1, 2, 4], signature)

  test "unsupported curve remains gated":
    expect CryptoUnavailableError:
      discard generateEdsaKeyPair(Secp256r1)
