import std/unittest

import dangelcrypto

suite "DangelCrypto core":
  test "hex roundtrip":
    let data: ByteSeq = @[byte 0, 1, 2, 15, 16, 255]
    check data.toHex == "0001020f10ff"
    check fromHex(data.toHex) == data

  test "constant time equality":
    check constantTimeEqual(@[byte 1, 2, 3], @[byte 1, 2, 3])
    check not constantTimeEqual(@[byte 1, 2, 3], @[byte 1, 2, 4])
    check not constantTimeEqual(@[byte 1, 2], @[byte 1, 2, 0])

  test "random byte length":
    check randomBytes(32).len == 32

  test "kyber parameter sizes":
    check publicKeySize(Kyber512) == 800
    check ciphertextSize(Kyber768) == 1088
    check sharedSecretSize(Kyber1024) == 32

  test "public kyber experimental polynomial API":
    let poly = experimentalKyberPolyFromSeed([byte 1, 2, 3, 4])
    check decodeKyberPoly(encodeKyberPoly(poly)) == poly

  test "public kyber kem roundtrip":
    let kp = generateKyberKeyPair(Kyber512)
    let enc = encapsulate(kp.publicKey)
    let ss = decapsulate(kp.privateKey, enc.ciphertext)
    check enc.sharedSecret.raw == ss.raw
    check kp.publicKey.raw.len == publicKeySize(Kyber512)
    check kp.privateKey.raw.len == privateKeySize(Kyber512)
    check enc.ciphertext.raw.len == ciphertextSize(Kyber512)

  test "public kyber validation helpers":
    let kp = generateKyberKeyPair(Kyber512)
    let enc = encapsulate(kp.publicKey)
    check isValidKyberPublicKey(kp.publicKey)
    check isValidKyberPrivateKey(kp.privateKey)
    check isValidKyberCiphertext(Kyber512, enc.ciphertext)
    check not isValidKyberPublicKey(KyberPublicKey(level: Kyber512, raw: @[]))
    check not isValidKyberPrivateKey(KyberPrivateKey(level: Kyber512, raw: @[]))
    check not isValidKyberCiphertext(Kyber512, Ciphertext(raw: @[]))

  test "public kyber kem roundtrip for all levels":
    for level in [Kyber512, Kyber768, Kyber1024]:
      let kp = generateKyberKeyPair(level)
      let enc = encapsulate(kp.publicKey)
      let ss = decapsulate(kp.privateKey, enc.ciphertext)
      check enc.sharedSecret.raw == ss.raw
      check kp.publicKey.raw.len == publicKeySize(level)
      check kp.privateKey.raw.len == privateKeySize(level)
      check enc.ciphertext.raw.len == ciphertextSize(level)

  test "public kyber rejects malformed inputs":
    expect InvalidKeyError:
      discard encapsulate(KyberPublicKey(level: Kyber512, raw: @[]))
    let kp = generateKyberKeyPair(Kyber512)
    expect InvalidKeyError:
      discard decapsulate(KyberPrivateKey(level: Kyber512, raw: @[]), Ciphertext(raw: @[]))
    expect InvalidCiphertextError:
      discard decapsulate(kp.privateKey, Ciphertext(raw: @[]))
