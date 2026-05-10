import std/unittest

import dangelcrypto/bytes
import dangelcrypto/errors
import dangelcrypto/types
import dangelcrypto/kcdsa
import dangelcrypto/ecc_kcdsa
import dangelcrypto/internal/kcdsa_common

suite "kcdsa common foundation":
  test "domain separated hashes differ":
    let msg = [byte 1, 2, 3]
    check kcdsaDigest(msg).len == 32
    check ecKcdsaDigest(msg).len == 32
    check kcdsaDigest(msg) != ecKcdsaDigest(msg)

  test "digest is deterministic":
    let msg = [byte 9, 8, 7]
    check kcdsaDigest(msg) == kcdsaDigest(msg)
    check ecKcdsaDigest(msg) == ecKcdsaDigest(msg)

  test "signature parts encode roundtrip":
    let parts = KcdsaSignatureParts(
      r: fromHex("010203"),
      s: fromHex("aabbccdd")
    )
    let decoded = decodeSignatureParts(encodeSignatureParts(parts))
    check decoded.r == parts.r
    check decoded.s == parts.s

  test "EC-KCDSA secp256k1 key generation foundation":
    let kp = generateEcKcdsaKeyPair(Secp256k1)
    check kp.privateKey.algorithm == "EC-KCDSA"
    check kp.privateKey.curve == Secp256k1
    check kp.privateKey.raw.len == 32
    check kp.publicKey.algorithm == "EC-KCDSA"
    check kp.publicKey.curve == Secp256k1
    check kp.publicKey.raw.len == 33
    check kp.publicKey.raw[0] in [byte 0x02, 0x03]
    check ecKcdsaPublicKeyFromPrivate(kp.privateKey.raw).raw == kp.publicKey.raw

  test "classic KCDSA and EC-KCDSA signing remain gated":
    expect CryptoUnavailableError:
      discard generateKcdsaKeyPair()
    expect CryptoUnavailableError:
      discard generateEcKcdsaKeyPair(Secp256r1)
    expect CryptoUnavailableError:
      discard signKcdsa(PrivateKey(), [])
    expect CryptoUnavailableError:
      discard signEcKcdsa(PrivateKey(), [])
