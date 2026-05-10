## Kyber polynomial-vector layer.

import ../types
import ./kyber_math

type
  KyberPolyVec* = object
    k*: int
    polys*: seq[KyberPoly]

proc kyberK*(level: KyberLevel): int =
  case level
  of Kyber512: 2
  of Kyber768: 3
  of Kyber1024: 4

proc kyberEta1*(level: KyberLevel): int =
  case level
  of Kyber512: 3
  of Kyber768, Kyber1024: 2

proc polyVecBytes*(k: int): int =
  k * KyberPolyBytes

proc polyVecCompressedBytes*(level: KyberLevel): int =
  case level
  of Kyber512, Kyber768: kyberK(level) * 320
  of Kyber1024: kyberK(level) * 352

proc newPolyVec*(k: int): KyberPolyVec =
  if k notin 2 .. 4:
    raise newException(ValueError, "Kyber polyvec k must be 2, 3, or 4")
  result.k = k
  result.polys = newSeq[KyberPoly](k)

proc ensureSameK(a, b: KyberPolyVec) =
  if a.k != b.k or a.polys.len != b.polys.len:
    raise newException(ValueError, "Kyber polyvec dimensions do not match")

proc encodePolyVec12*(vec: KyberPolyVec): ByteSeq =
  result = newSeq[byte](polyVecBytes(vec.k))
  for i, poly in vec.polys:
    let encoded = encodePoly12(poly)
    for j, value in encoded:
      result[i * KyberPolyBytes + j] = value

proc decodePolyVec12*(data: openArray[byte]; k: int): KyberPolyVec =
  if data.len != polyVecBytes(k):
    raise newException(ValueError, "Kyber polyvec encoding has invalid length")
  result = newPolyVec(k)
  for i in 0 ..< k:
    result.polys[i] = decodePoly12(data[i * KyberPolyBytes ..< (i + 1) * KyberPolyBytes])

proc appendBits(output: var ByteSeq; bitPos: var int; value: uint16; bits: int) =
  for bit in 0 ..< bits:
    if bitPos div 8 >= output.len:
      output.add 0
    if ((value shr bit) and 1) != 0:
      output[bitPos div 8] = output[bitPos div 8] or byte(1 shl (bitPos mod 8))
    inc bitPos

proc readBits(input: openArray[byte]; bitPos: var int; bits: int): uint16 =
  for bit in 0 ..< bits:
    let byteIndex = bitPos div 8
    if byteIndex >= input.len:
      raise newException(ValueError, "not enough bytes while reading Kyber bit stream")
    let current = (input[byteIndex] shr (bitPos mod 8)) and 1
    result = result or (uint16(current) shl bit)
    inc bitPos

proc compressPolyVec*(vec: KyberPolyVec; bits: range[10 .. 11]): ByteSeq =
  let outputLen = vec.k * KyberN * int(bits) div 8
  result = newSeq[byte](outputLen)
  var bitPos = 0
  for poly in vec.polys:
    for coeff in poly:
      appendBits(result, bitPos, compressCoeff(modQ(int(coeff)), bits), bits)

proc decompressPolyVec*(data: openArray[byte]; k: int; bits: range[10 .. 11]): KyberPolyVec =
  let expectedLen = k * KyberN * int(bits) div 8
  if data.len != expectedLen:
    raise newException(ValueError, "Kyber compressed polyvec has invalid length")
  result = newPolyVec(k)
  var bitPos = 0
  for i in 0 ..< k:
    for j in 0 ..< KyberN:
      result.polys[i][j] = decompressCoeff(readBits(data, bitPos, bits), bits)

proc compressPolyVecForLevel*(vec: KyberPolyVec; level: KyberLevel): ByteSeq =
  if vec.k != kyberK(level):
    raise newException(ValueError, "Kyber polyvec level does not match vector dimension")
  case level
  of Kyber512, Kyber768: compressPolyVec(vec, 10)
  of Kyber1024: compressPolyVec(vec, 11)

proc decompressPolyVecForLevel*(data: openArray[byte]; level: KyberLevel): KyberPolyVec =
  case level
  of Kyber512, Kyber768: decompressPolyVec(data, kyberK(level), 10)
  of Kyber1024: decompressPolyVec(data, kyberK(level), 11)

proc `+`*(a, b: KyberPolyVec): KyberPolyVec =
  ensureSameK(a, b)
  result = newPolyVec(a.k)
  for i in 0 ..< a.k:
    result.polys[i] = a.polys[i] + b.polys[i]

proc `-`*(a, b: KyberPolyVec): KyberPolyVec =
  ensureSameK(a, b)
  result = newPolyVec(a.k)
  for i in 0 ..< a.k:
    result.polys[i] = a.polys[i] - b.polys[i]

proc ntt*(vec: KyberPolyVec): KyberPolyVec =
  result = newPolyVec(vec.k)
  for i in 0 ..< vec.k:
    result.polys[i] = ntt(vec.polys[i])

proc inverseNtt*(vec: KyberPolyVec): KyberPolyVec =
  result = newPolyVec(vec.k)
  for i in 0 ..< vec.k:
    result.polys[i] = inverseNtt(vec.polys[i])

proc reduce*(vec: KyberPolyVec): KyberPolyVec =
  result = newPolyVec(vec.k)
  for i in 0 ..< vec.k:
    for j in 0 ..< KyberN:
      result.polys[i][j] = barrettReduce(int(vec.polys[i][j]))

proc dotNegacyclic*(a, b: KyberPolyVec): KyberPoly =
  ensureSameK(a, b)
  for i in 0 ..< a.k:
    result = result + negacyclicMul(a.polys[i], b.polys[i])

proc matrixVectorMul*(matrix: seq[KyberPolyVec]; vector: KyberPolyVec): KyberPolyVec =
  if matrix.len != vector.k:
    raise newException(ValueError, "Kyber matrix/vector dimensions do not match")
  result = newPolyVec(vector.k)
  for i in 0 ..< vector.k:
    result.polys[i] = dotNegacyclic(matrix[i], vector)

proc expandMatrix*(seed: openArray[byte]; level: KyberLevel; transposed = false): seq[KyberPolyVec] =
  let k = kyberK(level)
  result = newSeq[KyberPolyVec](k)
  for i in 0 ..< k:
    result[i] = newPolyVec(k)
    for j in 0 ..< k:
      let x = if transposed: byte(i) else: byte(j)
      let y = if transposed: byte(j) else: byte(i)
      result[i].polys[j] = sampleUniformXof(seed, x, y)

proc sampleNoiseVec*(seed: openArray[byte]; level: KyberLevel; startNonce: byte): KyberPolyVec =
  let k = kyberK(level)
  result = newPolyVec(k)
  for i in 0 ..< k:
    let nonce = byte(int(startNonce) + i)
    result.polys[i] =
      if kyberEta1(level) == 3: sampleNoiseEta3(seed, nonce)
      else: sampleNoiseEta2(seed, nonce)

proc sampleNoiseVecEta2*(seed: openArray[byte]; level: KyberLevel; startNonce: byte): KyberPolyVec =
  let k = kyberK(level)
  result = newPolyVec(k)
  for i in 0 ..< k:
    result.polys[i] = sampleNoiseEta2(seed, byte(int(startNonce) + i))
