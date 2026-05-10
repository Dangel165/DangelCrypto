import ./types

proc name*(curve: CurveKind): string =
  case curve
  of Secp256k1: "secp256k1"
  of Secp256r1: "secp256r1"
  of Secp384r1: "secp384r1"
  of Ed25519: "ed25519"
  of Ed448: "ed448"
  of Curve25519: "curve25519"

proc privateKeySize*(curve: CurveKind): int =
  case curve
  of Secp256k1, Secp256r1, Ed25519, Curve25519: 32
  of Secp384r1: 48
  of Ed448: 57

proc publicKeySize*(curve: CurveKind): int =
  case curve
  of Secp256k1, Secp256r1: 33
  of Secp384r1: 49
  of Ed25519, Curve25519: 32
  of Ed448: 57

proc signatureSize*(scheme: SignatureScheme; curve: CurveKind): int =
  case scheme
  of EdDSA:
    case curve
    of Ed25519: 64
    of Ed448: 114
    else: 64
  of ECDSA, EDSA, KCDSA, ECKCDSA:
    case curve
    of Secp384r1: 96
    else: 64
