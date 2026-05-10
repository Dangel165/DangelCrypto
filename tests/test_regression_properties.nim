import std/unittest

import dangelcrypto/bytes
import dangelcrypto/curve25519
import dangelcrypto/ecdsa
import dangelcrypto/eddsa
import dangelcrypto/types

suite "regression properties":
  test "hex encoding roundtrips representative byte patterns":
    let patterns = [
      @[],
      @[byte 0],
      @[byte 0xff],
      @[byte 0, 1, 2, 3, 0xfe, 0xff],
      @[byte 0x10, 0x20, 0x30, 0x40, 0x50]
    ]
    for pattern in patterns:
      check fromHex(pattern.toHex) == pattern

  test "raw and DER ECDSA encodings preserve fixed-width components":
    for marker in [byte 1, 2, 0x7f, 0x80, 0xff]:
      var r = newSeq[byte](32)
      var s = newSeq[byte](32)
      r[0] = marker
      r[31] = marker xor 0x5a
      s[0] = marker xor 0xa5
      s[31] = marker

      let rawParts = decodeRawEcdsaSignature(encodeRawEcdsaSignature(r, s))
      check rawParts.r == r
      check rawParts.s == s

      let derParts = decodeDerEcdsaSignature(encodeDerEcdsaSignature(r, s))
      check derParts.r == r
      check derParts.s == s

  test "Ed25519 signatures are deterministic and message-bound":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    let privateKey = PrivateKey(algorithm: "Ed25519", curve: Ed25519, raw: seed)
    let publicKey = ed25519PublicKeyFromPrivateSeed(seed)
    let a = signEddsa(privateKey, [byte 1, 2, 3])
    let b = signEddsa(privateKey, [byte 1, 2, 3])
    check a.raw == b.raw
    check verifyEddsa(publicKey, [byte 1, 2, 3], a)
    check not verifyEddsa(publicKey, [byte 1, 2, 4], a)

  test "X25519 agreement is symmetric across several generated keypairs":
    for _ in 0 ..< 3:
      let alice = generateX25519KeyPair()
      let bob = generateX25519KeyPair()
      check x25519(alice.privateKey, bob.publicKey).raw ==
        x25519(bob.privateKey, alice.publicKey).raw
