import std/unittest

import dangelcrypto/types
import dangelcrypto/internal/kyber_indcpa

suite "kyber indcpa":
  test "indcpa byte sizes":
    check indCpaPublicKeyBytes(Kyber512) == 800
    check indCpaPublicKeyBytes(Kyber768) == 1184
    check indCpaSecretKeyBytes(Kyber1024) == 1536
    check indCpaCiphertextBytes(Kyber512) == 768
    check indCpaCiphertextBytes(Kyber768) == 1088
    check indCpaCiphertextBytes(Kyber1024) == 1568

  test "keypair is deterministic from seed":
    let seed = [byte 0, 1, 2, 3, 4, 5, 6, 7]
    let a = indCpaKeyPairFromSeed(Kyber768, seed)
    let b = indCpaKeyPairFromSeed(Kyber768, seed)
    check packPublicKey(a.publicKey) == packPublicKey(b.publicKey)
    check packSecretKey(a.secretKey) == packSecretKey(b.secretKey)

  test "pack public and secret keys roundtrip":
    let kp = indCpaKeyPairFromSeed(Kyber512, [byte 9, 8, 7, 6])
    let pk = unpackPublicKey(Kyber512, packPublicKey(kp.publicKey))
    let sk = unpackSecretKey(Kyber512, packSecretKey(kp.secretKey))
    check packPublicKey(pk) == packPublicKey(kp.publicKey)
    check packSecretKey(sk) == packSecretKey(kp.secretKey)

  test "encrypt is deterministic for fixed coins":
    let kp = indCpaKeyPairFromSeed(Kyber512, [byte 1, 3, 5, 7])
    var msg: array[32, byte]
    for i in 0 ..< msg.len:
      msg[i] = byte(i)
    let coins = [byte 2, 4, 6, 8]
    let a = indCpaEncrypt(kp.publicKey, msg, coins)
    let b = indCpaEncrypt(kp.publicKey, msg, coins)
    check packCiphertext(a) == packCiphertext(b)

  test "pack ciphertext roundtrip":
    let kp = indCpaKeyPairFromSeed(Kyber768, [byte 1, 1, 2, 3, 5, 8])
    var msg: array[32, byte]
    msg[0] = 0xff
    let ct = indCpaEncrypt(kp.publicKey, msg, [byte 13, 21, 34, 55])
    let unpacked = unpackCiphertext(Kyber768, packCiphertext(ct))
    check packCiphertext(unpacked) == packCiphertext(ct)

  test "decrypt uncompressed ciphertext roundtrip":
    let kp = indCpaKeyPairFromSeed(Kyber512, [byte 7, 7, 7, 7])
    var msg: array[32, byte]
    for i in 0 ..< msg.len:
      msg[i] = byte((i * 11) and 0xff)
    let ct = indCpaEncrypt(kp.publicKey, msg, [byte 1, 2, 3, 4])
    check indCpaDecrypt(kp.secretKey, ct) == @msg
