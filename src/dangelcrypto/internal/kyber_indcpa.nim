## Deterministic Kyber CPA-PKE foundation.
##
## This module intentionally favors clarity and testability over speed. It uses
## the reference negacyclic multiplication path while the optimized NTT-domain
## CPA implementation is built out.

import ../types
import ./[keccak, kyber_math, kyber_polyvec]

type
  IndCpaPublicKey* = object
    level*: KyberLevel
    t*: KyberPolyVec
    rho*: ByteSeq

  IndCpaSecretKey* = object
    level*: KyberLevel
    s*: KyberPolyVec

  IndCpaCiphertext* = object
    level*: KyberLevel
    u*: KyberPolyVec
    v*: KyberPoly

  IndCpaKeyPair* = object
    publicKey*: IndCpaPublicKey
    secretKey*: IndCpaSecretKey

proc takeBytes(input: openArray[byte]; offset, count: int): ByteSeq =
  result = newSeq[byte](count)
  for i in 0 ..< count:
    if offset + i < input.len:
      result[i] = input[offset + i]

proc deriveKeypairSeeds(seed: openArray[byte]): tuple[rho, sigma: ByteSeq] =
  let material = shake256(seed, KyberSymBytes * 2)
  (takeBytes(material, 0, KyberSymBytes), takeBytes(material, KyberSymBytes, KyberSymBytes))

proc indCpaPublicKeyBytes*(level: KyberLevel): int =
  polyVecBytes(kyberK(level)) + KyberSymBytes

proc indCpaSecretKeyBytes*(level: KyberLevel): int =
  polyVecBytes(kyberK(level))

proc indCpaCiphertextBytes*(level: KyberLevel): int =
  polyVecCompressedBytes(level) +
    (if level == Kyber1024: KyberPolyCompressedBytes5 else: KyberPolyCompressedBytes4)

proc packPublicKey*(pk: IndCpaPublicKey): ByteSeq =
  result = encodePolyVec12(pk.t)
  result.add pk.rho

proc unpackPublicKey*(level: KyberLevel; data: openArray[byte]): IndCpaPublicKey =
  if data.len != indCpaPublicKeyBytes(level):
    raise newException(ValueError, "invalid Kyber IND-CPA public key length")
  let k = kyberK(level)
  result.level = level
  result.t = decodePolyVec12(data[0 ..< polyVecBytes(k)], k)
  result.rho = @data[polyVecBytes(k) ..< data.len]

proc packSecretKey*(sk: IndCpaSecretKey): ByteSeq =
  encodePolyVec12(sk.s)

proc unpackSecretKey*(level: KyberLevel; data: openArray[byte]): IndCpaSecretKey =
  if data.len != indCpaSecretKeyBytes(level):
    raise newException(ValueError, "invalid Kyber IND-CPA secret key length")
  result.level = level
  result.s = decodePolyVec12(data, kyberK(level))

proc packCiphertext*(ct: IndCpaCiphertext): ByteSeq =
  result = compressPolyVecForLevel(ct.u, ct.level)
  case ct.level
  of Kyber1024:
    result.add compressPoly5(ct.v)
  of Kyber512, Kyber768:
    result.add compressPoly4(ct.v)

proc unpackCiphertext*(level: KyberLevel; data: openArray[byte]): IndCpaCiphertext =
  if data.len != indCpaCiphertextBytes(level):
    raise newException(ValueError, "invalid Kyber IND-CPA ciphertext length")
  let vecLen = polyVecCompressedBytes(level)
  result.level = level
  result.u = decompressPolyVecForLevel(data[0 ..< vecLen], level)
  case level
  of Kyber1024:
    result.v = decompressPoly5(data[vecLen ..< data.len])
  of Kyber512, Kyber768:
    result.v = decompressPoly4(data[vecLen ..< data.len])

proc indCpaKeyPairFromSeed*(level: KyberLevel; seed: openArray[byte]): IndCpaKeyPair =
  let seeds = deriveKeypairSeeds(seed)
  let matrix = expandMatrix(seeds.rho, level)
  let s = sampleNoiseVec(seeds.sigma, level, 0)
  let e = sampleNoiseVec(seeds.sigma, level, byte(kyberK(level)))
  let t = matrixVectorMul(matrix, s) + e

  result.publicKey = IndCpaPublicKey(level: level, t: t, rho: seeds.rho)
  result.secretKey = IndCpaSecretKey(level: level, s: s)

proc indCpaEncrypt*(pk: IndCpaPublicKey; message: openArray[byte]; coins: openArray[byte]): IndCpaCiphertext =
  if message.len != KyberSymBytes:
    raise newException(ValueError, "Kyber IND-CPA message must be 32 bytes")

  let at = expandMatrix(pk.rho, pk.level, transposed = true)
  let r = sampleNoiseVec(coins, pk.level, 0)
  let e1 = sampleNoiseVecEta2(coins, pk.level, byte(kyberK(pk.level)))
  let e2 = sampleNoiseEta2(coins, byte(2 * kyberK(pk.level)))
  let u = matrixVectorMul(at, r) + e1
  let v = dotNegacyclic(pk.t, r) + e2 + polyFromMsg(message)
  result = IndCpaCiphertext(level: pk.level, u: u, v: v)

proc indCpaDecrypt*(sk: IndCpaSecretKey; ct: IndCpaCiphertext): ByteSeq =
  if sk.level != ct.level:
    raise newException(ValueError, "Kyber IND-CPA key/ciphertext level mismatch")
  let messagePoly = ct.v - dotNegacyclic(ct.u, sk.s)
  polyToMsg(messagePoly)
