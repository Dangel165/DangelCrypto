import ./[errors, random, types]
import ./internal/kyber_math
import ./internal/kyber_kem

export KyberN, KyberQ, KyberCoeff, KyberPoly

type
  KyberPublicKey* = object
    level*: KyberLevel
    raw*: ByteSeq

  KyberPrivateKey* = object
    level*: KyberLevel
    raw*: ByteSeq

  KyberKeyPair* = object
    publicKey*: KyberPublicKey
    privateKey*: KyberPrivateKey

proc publicKeySize*(level: KyberLevel): int =
  kemPublicKeyBytes(level)

proc privateKeySize*(level: KyberLevel): int =
  kemSecretKeyBytes(level)

proc ciphertextSize*(level: KyberLevel): int =
  kemCiphertextBytes(level)

proc sharedSecretSize*(level: KyberLevel): int =
  discard level
  kemSharedSecretBytes()

proc isValidKyberPublicKey*(publicKey: KyberPublicKey): bool =
  publicKey.raw.len == publicKeySize(publicKey.level)

proc isValidKyberPrivateKey*(privateKey: KyberPrivateKey): bool =
  privateKey.raw.len == privateKeySize(privateKey.level)

proc isValidKyberCiphertext*(level: KyberLevel; ciphertext: Ciphertext): bool =
  ciphertext.raw.len == ciphertextSize(level)

proc generateKyberSeed*(size = 32): ByteSeq =
  randomBytes(size)

proc experimentalKyberPolyFromSeed*(seed: openArray[byte]): KyberPoly =
  ## Builds a deterministic Kyber polynomial using this project's pure Nim
  ## arithmetic foundation.
  ##
  ## This is not the final Kyber XOF sampler yet.
  uniformPoly(seed)

proc encodeKyberPoly*(poly: KyberPoly): ByteSeq =
  toBytes(poly)

proc decodeKyberPoly*(data: openArray[byte]): KyberPoly =
  polyFromBytes(data)

proc generateKyberKeyPair*(level: KyberLevel): KyberKeyPair =
  let kp = kemGenerateKeyPair(level)
  result.publicKey = KyberPublicKey(level: level, raw: kp.publicKey.packed)
  result.privateKey = KyberPrivateKey(level: level, raw: packKemSecretKey(kp.secretKey))

proc encapsulate*(publicKey: KyberPublicKey): tuple[ciphertext: Ciphertext, sharedSecret: SharedSecret] =
  if not isValidKyberPublicKey(publicKey):
    raise newException(InvalidKeyError, "invalid Kyber public key length")
  let enc = kemEncapsulate(KyberKemPublicKey(level: publicKey.level, packed: publicKey.raw))
  (Ciphertext(raw: enc.ciphertext), SharedSecret(raw: enc.sharedSecret))

proc decapsulate*(privateKey: KyberPrivateKey; ciphertext: Ciphertext): SharedSecret =
  if not isValidKyberPrivateKey(privateKey):
    raise newException(InvalidKeyError, "invalid Kyber private key length")
  if not isValidKyberCiphertext(privateKey.level, ciphertext):
    raise newException(InvalidCiphertextError, "invalid Kyber ciphertext length")
  let sk = unpackKemSecretKey(privateKey.level, privateKey.raw)
  SharedSecret(raw: kemDecapsulate(sk, ciphertext.raw))
