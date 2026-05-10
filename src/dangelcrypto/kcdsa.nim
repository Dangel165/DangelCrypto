import ./[errors, types]
import ./internal/kcdsa_common

type
  KcdsaKeyPair* = KeyPair

proc kcdsaDigest*(message: openArray[byte]): ByteSeq =
  kcdsaHash(KcdsaClassic, message).raw

proc generateKcdsaKeyPair*(): KcdsaKeyPair =
  raise unavailable("KCDSA")

proc signKcdsa*(privateKey: PrivateKey; message: openArray[byte]): Signature =
  discard privateKey
  discard message
  raise unavailable("KCDSA signing")

proc verifyKcdsa*(publicKey: PublicKey; message: openArray[byte]; signature: Signature): bool =
  discard publicKey
  discard message
  discard signature
  raise unavailable("KCDSA verification")
