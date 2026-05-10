import ./[errors, random, types]
import ./internal/ed25519_impl

type
  EddsaKeyPair* = KeyPair

proc generateEddsaKeyPair*(curve = Ed25519): EddsaKeyPair =
  if curve != Ed25519:
    raise unavailable("EdDSA for non-Ed25519 curves")
  let seed = randomBytes(32)
  let publicRaw = ed25519PublicKeyFromSeed(seed)
  KeyPair(
    publicKey: PublicKey(algorithm: "Ed25519", curve: Ed25519, raw: publicRaw),
    privateKey: PrivateKey(algorithm: "Ed25519", curve: Ed25519, raw: seed)
  )

proc ed25519PublicKeyFromPrivateSeed*(seed: openArray[byte]): PublicKey =
  PublicKey(algorithm: "Ed25519", curve: Ed25519, raw: ed25519PublicKeyFromSeed(seed))

proc signEddsa*(privateKey: PrivateKey; message: openArray[byte]): Signature =
  if privateKey.curve != Ed25519 or privateKey.raw.len != 32:
    raise newException(InvalidKeyError, "Ed25519 private seed must be 32 bytes")
  Signature(scheme: EdDSA, raw: ed25519Sign(privateKey.raw, message))

proc verifyEddsa*(publicKey: PublicKey; message: openArray[byte]; signature: Signature): bool =
  if publicKey.curve != Ed25519 or publicKey.raw.len != 32:
    raise newException(InvalidKeyError, "Ed25519 public key must be 32 bytes")
  if signature.scheme != EdDSA or signature.raw.len != 64:
    return false
  ed25519Verify(publicKey.raw, message, signature.raw)
