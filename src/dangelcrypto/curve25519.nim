import ./[errors, random, types]
import ./internal/x25519_impl

type
  X25519KeyPair* = KeyPair

proc generateX25519KeyPair*(): X25519KeyPair =
  let privateRaw = randomBytes(32)
  let publicRaw = x25519Base(privateRaw)
  KeyPair(
    publicKey: PublicKey(algorithm: "X25519", curve: Curve25519, raw: publicRaw),
    privateKey: PrivateKey(algorithm: "X25519", curve: Curve25519, raw: privateRaw)
  )

proc isAllZero(data: openArray[byte]): bool =
  var acc: byte = 0
  for value in data:
    acc = acc or value
  acc == 0

proc x25519*(privateKey: PrivateKey; publicKey: PublicKey): SharedSecret =
  if privateKey.curve != Curve25519:
    raise newException(InvalidKeyError, "X25519 private key must use Curve25519")
  if publicKey.curve != Curve25519:
    raise newException(InvalidKeyError, "X25519 public key must use Curve25519")
  if privateKey.raw.len != 32:
    raise newException(InvalidKeyError, "X25519 private key must be 32 bytes")
  if publicKey.raw.len != 32:
    raise newException(InvalidKeyError, "X25519 public key must be 32 bytes")
  let secret = x25519Raw(privateKey.raw, publicKey.raw)
  if isAllZero(secret):
    raise newException(InvalidKeyError, "X25519 shared secret is all zero")
  SharedSecret(raw: secret)
