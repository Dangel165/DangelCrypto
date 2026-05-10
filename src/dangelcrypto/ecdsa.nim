import ./[errors, random, types]
import ./internal/ecdsa_encoding
import ./internal/secp256k1
import ./internal/sha2

export ecdsa_encoding

type
  EcdsaKeyPair* = KeyPair

proc generateEcdsaKeyPair*(curve = Secp256r1): EcdsaKeyPair =
  if curve != Secp256k1:
    raise unavailable("ECDSA for non-secp256k1 curves")
  var privateRaw = randomBytes(32)
  while not decode32be(privateRaw).isValidScalar:
    privateRaw = randomBytes(32)
  let publicRaw = publicKeyFromPrivate(privateRaw)
  KeyPair(
    publicKey: PublicKey(algorithm: "ECDSA", curve: Secp256k1, raw: publicRaw),
    privateKey: PrivateKey(algorithm: "ECDSA", curve: Secp256k1, raw: privateRaw)
  )

proc secp256k1PublicKeyFromPrivate*(privateKey: openArray[byte]): PublicKey =
  PublicKey(algorithm: "ECDSA", curve: Secp256k1, raw: publicKeyFromPrivate(privateKey))

proc ecdsaMessageDigest*(message: openArray[byte]): ByteSeq =
  sha256(message)

proc signEcdsa*(privateKey: PrivateKey; message: openArray[byte]): Signature =
  if privateKey.curve != Secp256k1 or privateKey.raw.len != 32:
    raise newException(InvalidKeyError, "ECDSA secp256k1 private key must be 32 bytes")
  if not decode32be(privateKey.raw).isValidScalar:
    raise newException(InvalidKeyError, "ECDSA secp256k1 private scalar is out of range")
  let digest = ecdsaMessageDigest(message)
  let parts = ecdsaSignDeterministic(privateKey.raw, digest)
  Signature(scheme: ECDSA, raw: encodeDerEcdsaSignature(parts.r, parts.s))

proc verifyEcdsa*(publicKey: PublicKey; message: openArray[byte]; signature: Signature): bool =
  if publicKey.curve != Secp256k1 or publicKey.raw.len != 33:
    raise newException(InvalidKeyError, "ECDSA secp256k1 compressed public key must be 33 bytes")
  if signature.scheme != ECDSA:
    return false
  try:
    let parts =
      if signature.raw.len == 64:
        decodeRawEcdsaSignature(signature.raw)
      else:
        decodeDerEcdsaSignature(signature.raw)
    ecdsaVerifyRaw(publicKey.raw, ecdsaMessageDigest(message), parts.r, parts.s)
  except ValueError:
    false
