## Experimental pure Nim Kyber arithmetic foundation.
##
## This module contains the low-level ring arithmetic used by Kyber:
## polynomials with 256 coefficients modulo q = 3329. It is intentionally
## internal while the full KEM is being built and checked against official
## test vectors.

import ../types
import ./keccak

const
  KyberN* = 256
  KyberQ* = 3329
  KyberSymBytes* = 32
  KyberPolyBytes* = 384
  KyberPolyCompressedBytes4* = 128
  KyberPolyCompressedBytes5* = 160
  KyberRootOfUnity* = 17
  KyberMont* = -1044
  KyberQInv* = -3327

type
  KyberCoeff* = int16
  KyberPoly* = array[KyberN, KyberCoeff]

proc modQ*(value: int): KyberCoeff =
  var reduced = value mod KyberQ
  if reduced < 0:
    reduced += KyberQ
  KyberCoeff(reduced)

proc addQ*(a, b: KyberCoeff): KyberCoeff =
  modQ(int(a) + int(b))

proc subQ*(a, b: KyberCoeff): KyberCoeff =
  modQ(int(a) - int(b))

proc mulQ*(a, b: KyberCoeff): KyberCoeff =
  modQ(int(a) * int(b))

proc centeredQ*(value: int): KyberCoeff =
  var reduced = int(modQ(value))
  if reduced > KyberQ div 2:
    reduced -= KyberQ
  KyberCoeff(reduced)

proc barrettReduce*(value: int): KyberCoeff =
  const v = ((1 shl 26) + KyberQ div 2) div KyberQ
  let t = ((v * value) + (1 shl 25)) shr 26
  centeredQ(value - t * KyberQ)

proc int16Wrap(value: int): int =
  var wrapped = value and 0xffff
  if wrapped >= 0x8000:
    wrapped -= 0x10000
  wrapped

proc montgomeryReduce*(value: int): KyberCoeff =
  let t = int16Wrap(value) * KyberQInv
  centeredQ((value - t * KyberQ) shr 16)

proc fqmul*(a, b: KyberCoeff): KyberCoeff =
  montgomeryReduce(int(a) * int(b))

proc bitReverse(value, bits: int): int =
  for i in 0 ..< bits:
    result = (result shl 1) or ((value shr i) and 1)

proc zetaAt(index: range[0 .. 127]): KyberCoeff =
  var tmp: array[128, KyberCoeff]
  tmp[0] = KyberCoeff(KyberMont)
  let root = KyberCoeff((KyberMont * KyberRootOfUnity) mod KyberQ)
  for i in 1 ..< 128:
    tmp[i] = fqmul(tmp[i - 1], root)
  result = centeredQ(int(tmp[bitReverse(index, 7)]))

proc zeroPoly*(): KyberPoly =
  discard

proc uniformPoly*(seed: openArray[byte]): KyberPoly =
  ## Deterministically expands bytes into coefficients modulo q.
  ##
  ## This is a development helper, not Kyber's final XOF sampler.
  if seed.len == 0:
    return zeroPoly()

  for i in 0 ..< KyberN:
    let lo = int(seed[(i * 2) mod seed.len])
    let hi = int(seed[(i * 2 + 1) mod seed.len])
    result[i] = modQ(lo or (hi shl 8))

proc `+`*(a, b: KyberPoly): KyberPoly =
  for i in 0 ..< KyberN:
    result[i] = addQ(a[i], b[i])

proc `-`*(a, b: KyberPoly): KyberPoly =
  for i in 0 ..< KyberN:
    result[i] = subQ(a[i], b[i])

proc pointwiseMul*(a, b: KyberPoly): KyberPoly =
  for i in 0 ..< KyberN:
    result[i] = mulQ(a[i], b[i])

proc negacyclicMul*(a, b: KyberPoly): KyberPoly =
  ## Slow reference multiplication in Z_q[x] / (x^256 + 1).
  ##
  ## This is useful for correctness tests while the NTT implementation is being
  ## developed. It is not the fast production multiplication path.
  var accum: array[KyberN, int]
  for i in 0 ..< KyberN:
    for j in 0 ..< KyberN:
      let product = int(a[i]) * int(b[j])
      let degree = i + j
      if degree < KyberN:
        accum[degree] += product
      else:
        accum[degree - KyberN] -= product

  for i in 0 ..< KyberN:
    result[i] = modQ(accum[i])

proc scalarMul*(poly: KyberPoly; scalar: KyberCoeff): KyberPoly =
  for i in 0 ..< KyberN:
    result[i] = mulQ(poly[i], scalar)

proc monomial*(degree: range[0 .. KyberN - 1]; coeff: KyberCoeff): KyberPoly =
  result[degree] = modQ(int(coeff))

proc centeredBinomialEta2*(data: openArray[byte]): KyberPoly =
  ## Kyber eta=2 centered binomial sampler foundation.
  ##
  ## Consumes 128 bytes for 256 coefficients. Missing input is treated as zero
  ## so tests can exercise the function with short deterministic buffers.
  for i in 0 ..< KyberN:
    let byteIndex = i div 2
    let value = if byteIndex < data.len: data[byteIndex] else: byte 0
    let nibble = if i mod 2 == 0: value and 0x0f else: value shr 4
    let a = int(nibble and 0x01) + int((nibble shr 1) and 0x01)
    let b = int((nibble shr 2) and 0x01) + int((nibble shr 3) and 0x01)
    result[i] = modQ(a - b)

proc centeredBinomialEta3*(data: openArray[byte]): KyberPoly =
  ## Kyber eta=3 centered binomial sampler foundation.
  for i in 0 ..< KyberN:
    let bitOffset = i * 6
    var value = 0
    for bit in 0 ..< 6:
      let absolute = bitOffset + bit
      let byteIndex = absolute div 8
      if byteIndex < data.len:
        value = value or (int((data[byteIndex] shr (absolute mod 8)) and 1) shl bit)
    let a = int(value and 0x01) + int((value shr 1) and 0x01) + int((value shr 2) and 0x01)
    let b = int((value shr 3) and 0x01) + int((value shr 4) and 0x01) + int((value shr 5) and 0x01)
    result[i] = modQ(a - b)

proc kyberPrf*(seed: openArray[byte]; nonce: byte; outputLen: Natural): ByteSeq =
  var input = newSeq[byte](seed.len + 1)
  for i, value in seed:
    input[i] = value
  input[seed.len] = nonce
  shake256(input, outputLen)

proc sampleNoiseEta2*(seed: openArray[byte]; nonce: byte): KyberPoly =
  centeredBinomialEta2(kyberPrf(seed, nonce, 128))

proc sampleNoiseEta3*(seed: openArray[byte]; nonce: byte): KyberPoly =
  centeredBinomialEta3(kyberPrf(seed, nonce, 192))

proc sampleUniformFromBytes*(data: openArray[byte]): KyberPoly =
  ## Rejection-samples Kyber coefficients from a byte stream.
  var coeffIndex = 0
  var offset = 0
  while coeffIndex < KyberN and offset + 2 < data.len:
    let d1 = int(data[offset]) or ((int(data[offset + 1]) and 0x0f) shl 8)
    let d2 = (int(data[offset + 1]) shr 4) or (int(data[offset + 2]) shl 4)
    offset += 3

    if d1 < KyberQ:
      result[coeffIndex] = KyberCoeff(d1)
      inc coeffIndex

    if coeffIndex < KyberN and d2 < KyberQ:
      result[coeffIndex] = KyberCoeff(d2)
      inc coeffIndex

  if coeffIndex != KyberN:
    raise newException(ValueError, "not enough bytes to sample a Kyber polynomial")

proc sampleUniformXof*(seed: openArray[byte]; x, y: byte): KyberPoly =
  ## Kyber matrix-expansion sampler using SHAKE128(seed || x || y).
  ##
  ## 672 bytes is enough with overwhelming margin for one Kyber polynomial.
  var input = newSeq[byte](seed.len + 2)
  for i, value in seed:
    input[i] = value
  input[seed.len] = x
  input[seed.len + 1] = y
  sampleUniformFromBytes(shake128(input, 672))

proc ntt*(poly: KyberPoly): KyberPoly =
  ## In-place style Kyber NTT, returned as a new polynomial.
  ##
  ## Input is standard order; output is bit-reversed order.
  result = poly
  var k = 1
  var len = 128
  while len >= 2:
    var start = 0
    while start < KyberN:
      let zeta = zetaAt(k)
      inc k
      for j in start ..< start + len:
        let t = fqmul(zeta, result[j + len])
        result[j + len] = KyberCoeff(int(result[j]) - int(t))
        result[j] = KyberCoeff(int(result[j]) + int(t))
      start += len * 2
    len = len shr 1

proc inverseNttToMont*(poly: KyberPoly): KyberPoly =
  ## Inverse Kyber NTT matching the Kyber reference `invntt_tomont` behavior.
  ## Input is bit-reversed order; output is standard order multiplied by R.
  result = poly
  const f = KyberCoeff(1441)
  var k = 127
  var len = 2
  while len <= 128:
    var start = 0
    while start < KyberN:
      let zeta = zetaAt(k)
      dec k
      for j in start ..< start + len:
        let t = result[j]
        result[j] = barrettReduce(int(t) + int(result[j + len]))
        result[j + len] = KyberCoeff(int(result[j + len]) - int(t))
        result[j + len] = fqmul(zeta, result[j + len])
      start += len * 2
    len = len shl 1

  for j in 0 ..< KyberN:
    result[j] = modQ(int(fqmul(result[j], f)))

proc fromMont*(value: KyberCoeff): KyberCoeff =
  modQ(int(fqmul(value, KyberCoeff(1))))

proc inverseNtt*(poly: KyberPoly): KyberPoly =
  ## Convenience inverse NTT returning ordinary Z_q coefficients.
  result = inverseNttToMont(poly)
  for j in 0 ..< KyberN:
    result[j] = fromMont(result[j])

proc basemul*(a0, a1, b0, b1, zeta: KyberCoeff): tuple[c0, c1: KyberCoeff] =
  var c0 = fqmul(a1, b1)
  c0 = fqmul(c0, zeta)
  c0 = KyberCoeff(int(c0) + int(fqmul(a0, b0)))
  let c1 = KyberCoeff(int(fqmul(a0, b1)) + int(fqmul(a1, b0)))
  (barrettReduce(int(c0)), barrettReduce(int(c1)))

proc compressCoeff*(value: KyberCoeff; bits: range[1 .. 11]): uint16 =
  let scale = 1 shl bits
  uint16(((int(value) * scale) + KyberQ div 2) div KyberQ and (scale - 1))

proc decompressCoeff*(value: uint16; bits: range[1 .. 11]): KyberCoeff =
  let scale = 1 shl bits
  modQ((int(value) * KyberQ + scale div 2) div scale)

proc toBytes*(poly: KyberPoly): ByteSeq =
  ## Serializes coefficients as little-endian uint16 values.
  result = newSeq[byte](KyberN * 2)
  for i, coeff in poly:
    let value = uint16(coeff)
    result[i * 2] = byte(value and 0xff)
    result[i * 2 + 1] = byte(value shr 8)

proc polyFromBytes*(data: openArray[byte]): KyberPoly =
  if data.len != KyberN * 2:
    raise newException(ValueError, "Kyber polynomial encoding must be 512 bytes")

  for i in 0 ..< KyberN:
    let value = int(data[i * 2]) or (int(data[i * 2 + 1]) shl 8)
    result[i] = modQ(value)

proc encodePoly12*(poly: KyberPoly): ByteSeq =
  ## Kyber 12-bit polynomial serialization. Output length: 384 bytes.
  result = newSeq[byte](KyberPolyBytes)
  for i in 0 ..< KyberN div 2:
    let t0 = uint16(modQ(int(poly[2 * i])))
    let t1 = uint16(modQ(int(poly[2 * i + 1])))
    result[3 * i] = byte(t0 and 0xff)
    result[3 * i + 1] = byte((t0 shr 8) or ((t1 and 0x0f) shl 4))
    result[3 * i + 2] = byte(t1 shr 4)

proc decodePoly12*(data: openArray[byte]): KyberPoly =
  if data.len != KyberPolyBytes:
    raise newException(ValueError, "Kyber 12-bit polynomial encoding must be 384 bytes")

  for i in 0 ..< KyberN div 2:
    result[2 * i] = KyberCoeff((int(data[3 * i]) or (int(data[3 * i + 1]) shl 8)) and 0x0fff)
    result[2 * i + 1] = KyberCoeff(((int(data[3 * i + 1]) shr 4) or (int(data[3 * i + 2]) shl 4)) and 0x0fff)

proc compressPoly4*(poly: KyberPoly): ByteSeq =
  ## Compresses a polynomial to 4 bits per coefficient. Output length: 128 bytes.
  result = newSeq[byte](KyberPolyCompressedBytes4)
  for i in 0 ..< KyberN div 2:
    let t0 = compressCoeff(modQ(int(poly[2 * i])), 4)
    let t1 = compressCoeff(modQ(int(poly[2 * i + 1])), 4)
    result[i] = byte(t0 or (t1 shl 4))

proc decompressPoly4*(data: openArray[byte]): KyberPoly =
  if data.len != KyberPolyCompressedBytes4:
    raise newException(ValueError, "Kyber 4-bit compressed polynomial must be 128 bytes")

  for i in 0 ..< KyberN div 2:
    result[2 * i] = decompressCoeff(uint16(data[i] and 0x0f), 4)
    result[2 * i + 1] = decompressCoeff(uint16(data[i] shr 4), 4)

proc compressPoly5*(poly: KyberPoly): ByteSeq =
  ## Compresses a polynomial to 5 bits per coefficient. Output length: 160 bytes.
  result = newSeq[byte](KyberPolyCompressedBytes5)
  for i in 0 ..< KyberN div 8:
    var t: array[8, uint16]
    for j in 0 ..< 8:
      t[j] = compressCoeff(modQ(int(poly[8 * i + j])), 5)
    let offset = 5 * i
    result[offset] = byte((t[0] shr 0) or (t[1] shl 5))
    result[offset + 1] = byte((t[1] shr 3) or (t[2] shl 2) or (t[3] shl 7))
    result[offset + 2] = byte((t[3] shr 1) or (t[4] shl 4))
    result[offset + 3] = byte((t[4] shr 4) or (t[5] shl 1) or (t[6] shl 6))
    result[offset + 4] = byte((t[6] shr 2) or (t[7] shl 3))

proc decompressPoly5*(data: openArray[byte]): KyberPoly =
  if data.len != KyberPolyCompressedBytes5:
    raise newException(ValueError, "Kyber 5-bit compressed polynomial must be 160 bytes")

  for i in 0 ..< KyberN div 8:
    let offset = 5 * i
    let a0 = uint16(data[offset])
    let a1 = uint16(data[offset + 1])
    let a2 = uint16(data[offset + 2])
    let a3 = uint16(data[offset + 3])
    let a4 = uint16(data[offset + 4])
    let t = [
      (a0 shr 0) and 0x1f,
      ((a0 shr 5) or (a1 shl 3)) and 0x1f,
      (a1 shr 2) and 0x1f,
      ((a1 shr 7) or (a2 shl 1)) and 0x1f,
      ((a2 shr 4) or (a3 shl 4)) and 0x1f,
      (a3 shr 1) and 0x1f,
      ((a3 shr 6) or (a4 shl 2)) and 0x1f,
      (a4 shr 3) and 0x1f
    ]
    for j in 0 ..< 8:
      result[8 * i + j] = decompressCoeff(t[j], 5)

proc polyFromMsg*(message: openArray[byte]): KyberPoly =
  if message.len != KyberSymBytes:
    raise newException(ValueError, "Kyber message polynomial input must be 32 bytes")

  for i in 0 ..< KyberSymBytes:
    for j in 0 ..< 8:
      let mask = -int((message[i] shr j) and 1)
      result[8 * i + j] = KyberCoeff(mask and ((KyberQ + 1) div 2))

proc polyToMsg*(poly: KyberPoly): ByteSeq =
  result = newSeq[byte](KyberSymBytes)
  for i in 0 ..< KyberSymBytes:
    for j in 0 ..< 8:
      var t = int(modQ(int(poly[8 * i + j])))
      t = (((t shl 1) + KyberQ div 2) div KyberQ) and 1
      result[i] = result[i] or byte(t shl j)
