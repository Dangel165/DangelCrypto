import ./[errors, random, types]
import ./internal/kcdsa_common
import ./internal/secp256k1

type
  EcKcdsaKeyPair* = KeyPair

proc ecKcdsaDigest*(message: openArray[byte]): ByteSeq =
  kcdsaHash(EcKcdsaSecp256k1, message).raw

proc ecKcdsaPublicKeyFromPrivate*(privateKey: openArray[byte]): PublicKey =
  PublicKey(
    algorithm: "EC-KCDSA",
    curve: Secp256k1,
    raw: publicKeyFromPrivate(privateKey)
  )

proc generateEcKcdsaKeyPair*(curve = Secp256k1): EcKcdsaKeyPair =
  if curve != Secp256k1:
    raise unavailable("EC-KCDSA for non-secp256k1 curves")
  var privateRaw = randomBytes(32)
  while not decode32be(privateRaw).isValidScalar:
    privateRaw = randomBytes(32)
  let publicRaw = publicKeyFromPrivate(privateRaw)
  KeyPair(
    publicKey: PublicKey(algorithm: "EC-KCDSA", curve: Secp256k1, raw: publicRaw),
    privateKey: PrivateKey(algorithm: "EC-KCDSA", curve: Secp256k1, raw: privateRaw)
  )

proc signEcKcdsa*(privateKey: PrivateKey; message: openArray[byte]): Signature =
  discard privateKey
  discard message
  raise unavailable("EC-KCDSA signing")

proc verifyEcKcdsa*(publicKey: PublicKey; message: openArray[byte]; signature: Signature): bool =
  discard publicKey
  discard message
  discard signature
  raise unavailable("EC-KCDSA verification")
