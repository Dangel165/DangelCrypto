## Pure Nim secp256k1 arithmetic foundation.
##
## This is a clarity-first implementation for ECDSA work. It uses fixed
## 256-bit little-endian limbs and simple modular arithmetic.

import ../types
import ./hmac

type
  UInt256* = array[4, uint64]

  SecpPoint* = object
    x*, y*: UInt256
    infinity*: bool

const
  P*: UInt256 = [
    0xfffffffefffffc2f'u64,
    0xffffffffffffffff'u64,
    0xffffffffffffffff'u64,
    0xffffffffffffffff'u64
  ]
  N*: UInt256 = [
    0xbfd25e8cd0364141'u64,
    0xbaaedce6af48a03b'u64,
    0xfffffffffffffffe'u64,
    0xffffffffffffffff'u64
  ]
  Gx*: UInt256 = [
    0x59f2815b16f81798'u64,
    0x029bfcdb2dce28d9'u64,
    0x55a06295ce870b07'u64,
    0x79be667ef9dcbbac'u64
  ]
  Gy*: UInt256 = [
    0x9c47d08ffb10d4b8'u64,
    0xfd17b448a6855419'u64,
    0x5da4fbfc0e1108a8'u64,
    0x483ada7726a3c465'u64
  ]

proc zero256*(): UInt256 =
  discard

proc one256*(): UInt256 =
  result[0] = 1

proc fromUint64*(value: uint64): UInt256 =
  result[0] = value

proc cmp(a, b: UInt256): int =
  for i in countdown(3, 0):
    if a[i] < b[i]: return -1
    if a[i] > b[i]: return 1
  0

proc isZero*(a: UInt256): bool =
  (a[0] or a[1] or a[2] or a[3]) == 0

proc isValidScalar*(a: UInt256): bool =
  not a.isZero and cmp(a, N) < 0

proc addRaw(a, b: UInt256): tuple[value: UInt256, carry: uint64] =
  var carry: uint64 = 0
  for i in 0 ..< 4:
    let old = a[i]
    result.value[i] = a[i] + b[i] + carry
    carry = (if result.value[i] < old or (carry == 1 and result.value[i] == old): 1'u64 else: 0'u64)
  result.carry = carry

proc subRaw(a, b: UInt256): tuple[value: UInt256, borrow: uint64] =
  var borrow: uint64 = 0
  for i in 0 ..< 4:
    let subtrahend = b[i] + borrow
    result.value[i] = a[i] - subtrahend
    borrow = (if a[i] < subtrahend or (borrow == 1 and subtrahend == 0): 1'u64 else: 0'u64)
  result.borrow = borrow

proc modP*(a: UInt256): UInt256 =
  result = a
  while cmp(result, P) >= 0:
    result = subRaw(result, P).value

proc modN*(a: UInt256): UInt256 =
  result = a
  while cmp(result, N) >= 0:
    result = subRaw(result, N).value

proc addMod*(a, b, modulus: UInt256): UInt256 =
  let sum = addRaw(a, b)
  result = sum.value
  if sum.carry != 0 or cmp(result, modulus) >= 0:
    result = subRaw(result, modulus).value

proc subMod*(a, b, modulus: UInt256): UInt256 =
  let diff = subRaw(a, b)
  result = diff.value
  if diff.borrow != 0:
    result = addRaw(result, modulus).value

proc bitAt(a: UInt256; index: int): int =
  int((a[index div 64] shr (index mod 64)) and 1)

proc shl1Mod(value: var UInt256; modulus: UInt256) =
  var carry = 0'u64
  for i in 0 ..< 4:
    let nextCarry = value[i] shr 63
    value[i] = (value[i] shl 1) or carry
    carry = nextCarry
  if carry != 0 or cmp(value, modulus) >= 0:
    value = subRaw(value, modulus).value

proc mulMod*(a, b, modulus: UInt256): UInt256 =
  var acc = zero256()
  var base = a
  for i in 0 ..< 256:
    if bitAt(b, i) == 1:
      acc = addMod(acc, base, modulus)
    shl1Mod(base, modulus)
  acc

proc squareMod*(a, modulus: UInt256): UInt256 =
  mulMod(a, a, modulus)

proc powMod*(base, exponent, modulus: UInt256): UInt256 =
  result = one256()
  var b = base
  for i in 0 ..< 256:
    if bitAt(exponent, i) == 1:
      result = mulMod(result, b, modulus)
    b = squareMod(b, modulus)

proc invMod*(a, modulus: UInt256): UInt256 =
  var exponent = subRaw(modulus, fromUint64(2)).value
  powMod(a, exponent, modulus)

proc sqrtModP*(a: UInt256): UInt256 =
  let exponent = [
    0xffffffffbfffff0c'u64,
    0xffffffffffffffff'u64,
    0xffffffffffffffff'u64,
    0x3fffffffffffffff'u64
  ]
  powMod(a, exponent, P)

proc generator*(): SecpPoint =
  SecpPoint(x: Gx, y: Gy, infinity: false)

proc pointNeg*(p: SecpPoint): SecpPoint =
  if p.infinity:
    return p
  SecpPoint(x: p.x, y: subMod(zero256(), p.y, P), infinity: false)

proc pointAdd*(p, q: SecpPoint): SecpPoint =
  if p.infinity: return q
  if q.infinity: return p

  if cmp(p.x, q.x) == 0:
    if cmp(p.y, q.y) != 0:
      return SecpPoint(infinity: true)
    if isZero(p.y):
      return SecpPoint(infinity: true)
    let numerator = mulMod(fromUint64(3), squareMod(p.x, P), P)
    let denominator = invMod(mulMod(fromUint64(2), p.y, P), P)
    let lambda = mulMod(numerator, denominator, P)
    let xr = subMod(subMod(squareMod(lambda, P), p.x, P), q.x, P)
    let yr = subMod(mulMod(lambda, subMod(p.x, xr, P), P), p.y, P)
    return SecpPoint(x: xr, y: yr, infinity: false)

  let numerator = subMod(q.y, p.y, P)
  let denominator = invMod(subMod(q.x, p.x, P), P)
  let lambda = mulMod(numerator, denominator, P)
  let xr = subMod(subMod(squareMod(lambda, P), p.x, P), q.x, P)
  let yr = subMod(mulMod(lambda, subMod(p.x, xr, P), P), p.y, P)
  SecpPoint(x: xr, y: yr, infinity: false)

proc scalarMult*(scalar: UInt256; point: SecpPoint): SecpPoint =
  result = SecpPoint(infinity: true)
  var base = point
  for i in 0 ..< 256:
    if bitAt(scalar, i) == 1:
      result = pointAdd(result, base)
    base = pointAdd(base, base)

proc encode32be*(value: UInt256): ByteSeq =
  result = newSeq[byte](32)
  for limb in 0 ..< 4:
    for j in 0 ..< 8:
      result[31 - (limb * 8 + j)] = byte((value[limb] shr (8 * j)) and 0xff)

proc decode32be*(data: openArray[byte]): UInt256 =
  if data.len != 32:
    raise newException(ValueError, "secp256k1 integer must be 32 bytes")
  for i in 0 ..< 32:
    let limb = (31 - i) div 8
    let shift = ((31 - i) mod 8) * 8
    result[limb] = result[limb] or (uint64(data[i]) shl shift)

proc encodePublicKeyCompressed*(point: SecpPoint): ByteSeq =
  if point.infinity:
    raise newException(ValueError, "cannot encode point at infinity")
  result = newSeq[byte](33)
  result[0] = if (point.y[0] and 1) == 0: byte 0x02 else: byte 0x03
  let xBytes = encode32be(point.x)
  for i, value in xBytes:
    result[i + 1] = value

proc publicKeyFromPrivate*(privateKey: openArray[byte]): ByteSeq =
  let scalar = decode32be(privateKey)
  encodePublicKeyCompressed(scalarMult(scalar, generator()))

proc bits2octets(hash: openArray[byte]): ByteSeq =
  var z = decode32be(hash)
  while cmp(z, N) >= 0:
    z = subRaw(z, N).value
  encode32be(z)

proc nonceRfc6979Sha512*(privateKey, messageHash: openArray[byte]): ByteSeq =
  if privateKey.len != 32 or messageHash.len != 32:
    raise newException(ValueError, "RFC6979 secp256k1 inputs must be 32 bytes")
  let x = encode32be(decode32be(privateKey))
  let h1 = bits2octets(messageHash)
  var v = newSeq[byte](64)
  var k = newSeq[byte](64)
  for i in 0 ..< v.len:
    v[i] = 0x01

  k = hmacSha512(k, v & @[byte 0x00] & x & h1)
  v = hmacSha512(k, v)
  k = hmacSha512(k, v & @[byte 0x01] & x & h1)
  v = hmacSha512(k, v)

  while true:
    var t: ByteSeq = @[]
    while t.len < 32:
      v = hmacSha512(k, v)
      t.add v
    result = t[0 ..< 32]
    let candidate = decode32be(result)
    if not candidate.isZero and cmp(candidate, N) < 0:
      return
    k = hmacSha512(k, v & @[byte 0x00])
    v = hmacSha512(k, v)

proc pointFromPrivate*(privateKey: openArray[byte]): SecpPoint =
  scalarMult(decode32be(privateKey), generator())

proc decodePublicKeyCompressed*(data: openArray[byte]): SecpPoint =
  if data.len != 33 or data[0] notin [byte 0x02, 0x03]:
    raise newException(ValueError, "compressed secp256k1 public key must be 33 bytes")
  let x = decode32be(data[1 ..< 33])
  let rhs = addMod(mulMod(squareMod(x, P), x, P), fromUint64(7), P)
  var y = sqrtModP(rhs)
  if byte(y[0] and 1) != (data[0] and 1):
    y = subMod(zero256(), y, P)
  SecpPoint(x: x, y: y, infinity: false)

proc isOnCurve*(point: SecpPoint): bool =
  if point.infinity:
    return true
  let lhs = squareMod(point.y, P)
  let rhs = addMod(mulMod(squareMod(point.x, P), point.x, P), fromUint64(7), P)
  cmp(lhs, rhs) == 0

proc ecdsaSignWithNonce*(privateKey, messageHash, nonce: openArray[byte]): tuple[r, s: ByteSeq] =
  let d = decode32be(privateKey)
  let z = modN(decode32be(messageHash))
  let k = decode32be(nonce)
  if isZero(d) or isZero(k):
    raise newException(ValueError, "ECDSA private key and nonce must be non-zero")
  let rPoint = scalarMult(k, generator())
  let rInt = modN(rPoint.x)
  if isZero(rInt):
    raise newException(ValueError, "ECDSA nonce produced zero r")
  let kinv = invMod(k, N)
  let rd = mulMod(rInt, d, N)
  let sum = addMod(z, rd, N)
  let sInt = mulMod(kinv, sum, N)
  if isZero(sInt):
    raise newException(ValueError, "ECDSA nonce produced zero s")
  (encode32be(rInt), encode32be(sInt))

proc ecdsaSignDeterministic*(privateKey, messageHash: openArray[byte]): tuple[r, s: ByteSeq] =
  let nonce = nonceRfc6979Sha512(privateKey, messageHash)
  ecdsaSignWithNonce(privateKey, messageHash, nonce)

proc ecdsaVerifyRaw*(publicKey, messageHash, rBytes, sBytes: openArray[byte]): bool =
  try:
    let q = decodePublicKeyCompressed(publicKey)
    if not isOnCurve(q):
      return false
    let r = decode32be(rBytes)
    let s = decode32be(sBytes)
    if isZero(r) or isZero(s) or cmp(r, N) >= 0 or cmp(s, N) >= 0:
      return false
    let z = modN(decode32be(messageHash))
    let w = invMod(s, N)
    let u1 = mulMod(z, w, N)
    let u2 = mulMod(r, w, N)
    let p = pointAdd(scalarMult(u1, generator()), scalarMult(u2, q))
    if p.infinity:
      return false
    cmp(modN(p.x), r) == 0
  except ValueError:
    false

proc ecdsaVerifyPoint*(publicPoint: SecpPoint; messageHash, rBytes, sBytes: openArray[byte]): bool =
  try:
    if not isOnCurve(publicPoint):
      return false
    let r = decode32be(rBytes)
    let s = decode32be(sBytes)
    if isZero(r) or isZero(s) or cmp(r, N) >= 0 or cmp(s, N) >= 0:
      return false
    let z = modN(decode32be(messageHash))
    let w = invMod(s, N)
    let u1 = mulMod(z, w, N)
    let u2 = mulMod(r, w, N)
    let p = pointAdd(scalarMult(u1, generator()), scalarMult(u2, publicPoint))
    if p.infinity:
      return false
    cmp(modN(p.x), r) == 0
  except ValueError:
    false
