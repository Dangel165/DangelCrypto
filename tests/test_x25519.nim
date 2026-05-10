import std/unittest

import dangelcrypto/bytes
import dangelcrypto/errors
import dangelcrypto/types
import dangelcrypto/curve25519
import dangelcrypto/internal/x25519_impl

suite "x25519":
  test "RFC 7748 vector 1":
    let scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    let u = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    check x25519Raw(scalar, u).toHex == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

  test "RFC 7748 vector 2":
    let scalar = fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    let u = fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    check x25519Raw(scalar, u).toHex == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

  test "public API shared secret agreement":
    let alice = generateX25519KeyPair()
    let bob = generateX25519KeyPair()
    let a = x25519(alice.privateKey, bob.publicKey)
    let b = x25519(bob.privateKey, alice.publicKey)
    check a.raw == b.raw
    check a.raw.len == 32

  test "public API accepts explicit keys":
    let privateKey = PrivateKey(
      algorithm: "X25519",
      curve: Curve25519,
      raw: fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    )
    let publicKey = PublicKey(
      algorithm: "X25519",
      curve: Curve25519,
      raw: fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    )
    check x25519(privateKey, publicKey).raw.toHex == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

  test "public API rejects invalid curve and all-zero shared secret":
    let privateKey = PrivateKey(
      algorithm: "X25519",
      curve: Curve25519,
      raw: fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    )
    expect InvalidKeyError:
      discard x25519(PrivateKey(algorithm: "X25519", curve: Ed25519, raw: privateKey.raw), PublicKey())
    expect InvalidKeyError:
      discard x25519(
        privateKey,
        PublicKey(algorithm: "X25519", curve: Curve25519, raw: newSeq[byte](32))
      )
