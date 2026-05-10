import std/unittest

import dangelcrypto/types
import dangelcrypto/internal/kyber_kem

suite "kyber kem foundation":
  test "kem byte sizes":
    check kemPublicKeyBytes(Kyber512) == 800
    check kemSecretKeyBytes(Kyber512) == 1632
    check kemCiphertextBytes(Kyber768) == 1088
    check kemSharedSecretBytes() == 32

  test "keypair is deterministic from seed":
    let a = kemKeyPairFromSeed(Kyber512, [byte 1, 2, 3, 4])
    let b = kemKeyPairFromSeed(Kyber512, [byte 1, 2, 3, 4])
    check a.publicKey.packed == b.publicKey.packed
    check a.secretKey.indCpaSecret == b.secretKey.indCpaSecret
    check a.secretKey.z == b.secretKey.z

  test "encapsulation is deterministic for fixed message":
    let kp = kemKeyPairFromSeed(Kyber512, [byte 9, 8, 7, 6])
    var msg: array[32, byte]
    for i in 0 ..< msg.len:
      msg[i] = byte(i * 3)
    let a = kemEncapsulateWithMessage(kp.publicKey, msg)
    let b = kemEncapsulateWithMessage(kp.publicKey, msg)
    check a.ciphertext == b.ciphertext
    check a.sharedSecret == b.sharedSecret

  test "decapsulation matches encapsulation":
    let kp = kemKeyPairFromSeed(Kyber512, [byte 5, 5, 5, 5])
    var msg: array[32, byte]
    for i in 0 ..< msg.len:
      msg[i] = byte(i xor 0x55)
    let enc = kemEncapsulateWithMessage(kp.publicKey, msg)
    check kemDecapsulate(kp.secretKey, enc.ciphertext) == enc.sharedSecret

  test "tampered ciphertext derives fallback secret":
    let kp = kemKeyPairFromSeed(Kyber512, [byte 4, 3, 2, 1])
    var msg: array[32, byte]
    msg[0] = 1
    let enc = kemEncapsulateWithMessage(kp.publicKey, msg)
    var tampered = enc.ciphertext
    tampered[0] = tampered[0] xor 1
    check kemDecapsulate(kp.secretKey, tampered) != enc.sharedSecret
