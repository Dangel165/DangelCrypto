import std/unittest

import dangelcrypto/bytes
import dangelcrypto/types
import dangelcrypto/eddsa
import dangelcrypto/internal/ed25519_impl

suite "ed25519 foundation":
  test "RFC 8032 public key vector 1":
    let seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    check ed25519PublicKeyFromSeed(seed).toHex ==
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

  test "RFC 8032 public key vector 2":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    check ed25519PublicKeyFromSeed(seed).toHex ==
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"

  test "public API key generation shape":
    let kp = generateEddsaKeyPair(Ed25519)
    check kp.publicKey.raw.len == 32
    check kp.privateKey.raw.len == 32

  test "public key helper":
    let seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    check ed25519PublicKeyFromPrivateSeed(seed).raw.toHex ==
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

  test "point decode encode roundtrip":
    let pk = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    let r = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
    check encodePoint(decodePoint(pk)).toHex == pk.toHex
    check encodePoint(decodePoint(r)).toHex == r.toHex

  test "RFC 8032 sign vector 1":
    let seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    let sig = ed25519Sign(seed, [])
    check sig.toHex ==
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" &
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    check ed25519Verify(ed25519PublicKeyFromSeed(seed), [], sig)

  test "RFC 8032 sign vector 2":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    let msg = fromHex("72")
    let sig = ed25519Sign(seed, msg)
    check sig.toHex ==
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" &
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    check ed25519Verify(ed25519PublicKeyFromSeed(seed), msg, sig)

  test "RFC 8032 sign vector 3":
    let seed = fromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    let msg = fromHex("af82")
    let sig = ed25519Sign(seed, msg)
    check sig.toHex ==
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" &
      "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    check ed25519Verify(ed25519PublicKeyFromSeed(seed), msg, sig)

  test "public API sign verify":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    let pk = ed25519PublicKeyFromPrivateSeed(seed)
    let sk = PrivateKey(algorithm: "Ed25519", curve: Ed25519, raw: seed)
    let sig = signEddsa(sk, [byte 0x72])
    check sig.raw.toHex ==
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" &
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    check verifyEddsa(pk, [byte 0x72], sig)

  test "public API rejects tampered ed25519 signatures":
    let seed = fromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    let pk = ed25519PublicKeyFromPrivateSeed(seed)
    let sk = PrivateKey(algorithm: "Ed25519", curve: Ed25519, raw: seed)
    var sig = signEddsa(sk, [byte 0x72])
    check not verifyEddsa(pk, [byte 0x73], sig)
    sig.raw[0] = sig.raw[0] xor 1
    check not verifyEddsa(pk, [byte 0x72], sig)
