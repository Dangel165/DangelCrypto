## Kyber CCA-KEM foundation built on the deterministic IND-CPA layer.
##
## This module follows the Kyber CCA transform shape: hash public key, derive
## coins from message plus public-key hash, encrypt, then derive the shared
## secret from key material and ciphertext hash. It remains internal until KAT
## vectors and the optimized IND-CPA path are complete.

import ../[bytes, random, types]
import ./[keccak, kyber_indcpa, kyber_math]

type
  KyberKemPublicKey* = object
    level*: KyberLevel
    packed*: ByteSeq

  KyberKemSecretKey* = object
    level*: KyberLevel
    indCpaSecret*: ByteSeq
    publicKey*: ByteSeq
    publicKeyHash*: ByteSeq
    z*: ByteSeq

  KyberKemKeyPair* = object
    publicKey*: KyberKemPublicKey
    secretKey*: KyberKemSecretKey

  KyberKemEncapsulation* = object
    ciphertext*: ByteSeq
    sharedSecret*: ByteSeq

proc kdf(input: openArray[byte]): ByteSeq =
  shake256(input, KyberSymBytes)

proc concat(a, b: openArray[byte]): ByteSeq =
  result = newSeq[byte](a.len + b.len)
  for i, value in a:
    result[i] = value
  for i, value in b:
    result[a.len + i] = value

proc split64(input: openArray[byte]): tuple[left, right: ByteSeq] =
  if input.len != 64:
    raise newException(ValueError, "expected 64 bytes")
  (@input[0 ..< 32], @input[32 ..< 64])

proc constantTimeSelect(a, b: openArray[byte]; useB: bool): ByteSeq =
  if a.len != b.len:
    raise newException(ValueError, "constant-time select inputs must have equal length")
  result = newSeq[byte](a.len)
  let mask = if useB: byte 0xff else: byte 0
  for i in 0 ..< a.len:
    result[i] = (a[i] and not mask) or (b[i] and mask)

proc kemPublicKeyBytes*(level: KyberLevel): int =
  indCpaPublicKeyBytes(level)

proc kemSecretKeyBytes*(level: KyberLevel): int =
  indCpaSecretKeyBytes(level) + indCpaPublicKeyBytes(level) + 2 * KyberSymBytes

proc kemCiphertextBytes*(level: KyberLevel): int =
  indCpaCiphertextBytes(level)

proc kemSharedSecretBytes*(): int =
  KyberSymBytes

proc packKemSecretKey*(sk: KyberKemSecretKey): ByteSeq =
  result = newSeq[byte](kemSecretKeyBytes(sk.level))
  var offset = 0
  for value in sk.indCpaSecret:
    result[offset] = value
    inc offset
  for value in sk.publicKey:
    result[offset] = value
    inc offset
  for value in sk.publicKeyHash:
    result[offset] = value
    inc offset
  for value in sk.z:
    result[offset] = value
    inc offset

proc unpackKemSecretKey*(level: KyberLevel; data: openArray[byte]): KyberKemSecretKey =
  if data.len != kemSecretKeyBytes(level):
    raise newException(ValueError, "invalid Kyber KEM secret key length")
  let skLen = indCpaSecretKeyBytes(level)
  let pkLen = indCpaPublicKeyBytes(level)
  result.level = level
  result.indCpaSecret = @data[0 ..< skLen]
  result.publicKey = @data[skLen ..< skLen + pkLen]
  result.publicKeyHash = @data[skLen + pkLen ..< skLen + pkLen + KyberSymBytes]
  result.z = @data[skLen + pkLen + KyberSymBytes ..< data.len]

proc kemKeyPairFromSeed*(level: KyberLevel; seed: openArray[byte]): KyberKemKeyPair =
  let material = shake256(seed, KyberSymBytes * 2)
  let indSeed = material[0 ..< KyberSymBytes]
  let z = @material[KyberSymBytes ..< KyberSymBytes * 2]
  let ind = indCpaKeyPairFromSeed(level, indSeed)
  let packedPk = packPublicKey(ind.publicKey)
  let packedSk = packSecretKey(ind.secretKey)

  result.publicKey = KyberKemPublicKey(level: level, packed: packedPk)
  result.secretKey = KyberKemSecretKey(
    level: level,
    indCpaSecret: packedSk,
    publicKey: packedPk,
    publicKeyHash: sha3_256(packedPk),
    z: z
  )

proc kemGenerateKeyPair*(level: KyberLevel): KyberKemKeyPair =
  kemKeyPairFromSeed(level, randomBytes(KyberSymBytes))

proc kemEncapsulateWithMessage*(pk: KyberKemPublicKey; message: openArray[byte]): KyberKemEncapsulation =
  if message.len != KyberSymBytes:
    raise newException(ValueError, "Kyber KEM message must be 32 bytes")

  let publicKey = unpackPublicKey(pk.level, pk.packed)
  let publicKeyHash = sha3_256(pk.packed)
  let kr = split64(sha3_512(concat(message, publicKeyHash)))
  let ct = packCiphertext(indCpaEncrypt(publicKey, message, kr.right))
  result.ciphertext = ct
  result.sharedSecret = kdf(concat(kr.left, sha3_256(ct)))

proc kemEncapsulate*(pk: KyberKemPublicKey): KyberKemEncapsulation =
  kemEncapsulateWithMessage(pk, randomBytes(KyberSymBytes))

proc kemDecapsulate*(sk: KyberKemSecretKey; ciphertext: openArray[byte]): ByteSeq =
  let indSk = unpackSecretKey(sk.level, sk.indCpaSecret)
  let indPk = unpackPublicKey(sk.level, sk.publicKey)
  let ct = unpackCiphertext(sk.level, ciphertext)
  let message = indCpaDecrypt(indSk, ct)
  let kr = split64(sha3_512(concat(message, sk.publicKeyHash)))
  let recomputed = packCiphertext(indCpaEncrypt(indPk, message, kr.right))
  let fail = not constantTimeEqual(recomputed, ciphertext)
  let keyMaterial = constantTimeSelect(kr.left, sk.z, fail)
  kdf(concat(keyMaterial, sha3_256(ciphertext)))
