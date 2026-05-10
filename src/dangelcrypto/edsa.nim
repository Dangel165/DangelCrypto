## EDSA facade.
##
## In many projects "EDSA" is used loosely for elliptic-curve digital
## signature algorithms. This module exposes that generic name while keeping
## concrete ECDSA and EdDSA entry points separate.

import ./[ecdsa, eddsa, errors, types]

export ecdsa, eddsa

type
  EdsaKeyPair* = KeyPair

proc generateEdsaKeyPair*(curve = Ed25519): EdsaKeyPair =
  case curve
  of Ed25519:
    generateEddsaKeyPair(curve)
  of Secp256k1:
    generateEcdsaKeyPair(curve)
  else:
    raise unavailable("EDSA for unsupported curve")

proc edsaPublicKeyFromPrivate*(privateKey: PrivateKey): PublicKey =
  case privateKey.curve
  of Ed25519:
    ed25519PublicKeyFromPrivateSeed(privateKey.raw)
  of Secp256k1:
    secp256k1PublicKeyFromPrivate(privateKey.raw)
  else:
    raise unavailable("EDSA public key derivation for unsupported curve")

proc signEdsa*(privateKey: PrivateKey; message: openArray[byte]): Signature =
  case privateKey.curve
  of Ed25519:
    signEddsa(privateKey, message)
  of Secp256k1:
    signEcdsa(privateKey, message)
  else:
    raise unavailable("EDSA signing for unsupported curve")

proc verifyEdsa*(publicKey: PublicKey; message: openArray[byte]; signature: Signature): bool =
  case publicKey.curve
  of Ed25519:
    verifyEddsa(publicKey, message, signature)
  of Secp256k1:
    verifyEcdsa(publicKey, message, signature)
  else:
    raise unavailable("EDSA verification for unsupported curve")
