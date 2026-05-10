type
  ByteSeq* = seq[byte]

  CurveKind* = enum
    Secp256k1,
    Secp256r1,
    Secp384r1,
    Ed25519,
    Ed448,
    Curve25519

  KyberLevel* = enum
    Kyber512,
    Kyber768,
    Kyber1024

  SignatureScheme* = enum
    EDSA,
    ECDSA,
    EdDSA,
    KCDSA,
    ECKCDSA

  PublicKey* = object
    algorithm*: string
    curve*: CurveKind
    raw*: ByteSeq

  PrivateKey* = object
    algorithm*: string
    curve*: CurveKind
    raw*: ByteSeq

  KeyPair* = object
    publicKey*: PublicKey
    privateKey*: PrivateKey

  Signature* = object
    scheme*: SignatureScheme
    raw*: ByteSeq

  SharedSecret* = object
    raw*: ByteSeq

  Ciphertext* = object
    raw*: ByteSeq
