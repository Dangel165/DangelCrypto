## Pure Nim Ed25519 public-key foundation.
##
## Implements Edwards25519 point arithmetic and seed -> public key generation.

import ./[field25519, sha2]

type
  EdwardsPoint* = object
    x*, y*, z*, t*: Fe25519

const Ed25519Bytes* = 32

proc feFromDecimalString(value: string): Fe25519 =
  result = zeroFe()
  for ch in value:
    result = result * feFromInt(10)
    result = result + feFromInt(uint64(ord(ch) - ord('0')))

proc edwardsD(): Fe25519 =
  feFromDecimalString("37095705934669439343138083508754565189542113879843219016388785533085940283555")

proc edwardsBaseY(): Fe25519 =
  feFromDecimalString("46316835694926478169428394003475163141307993866256225615783033603165251855960")

proc edwardsBaseX(): Fe25519 =
  feFromDecimalString("15112221349535400772501151409588531511454012693041857206046113283949847762202")

proc identityPoint*(): EdwardsPoint =
  EdwardsPoint(x: zeroFe(), y: oneFe(), z: oneFe(), t: zeroFe())

proc basePoint*(): EdwardsPoint =
  let x = edwardsBaseX()
  let y = edwardsBaseY()
  EdwardsPoint(x: x, y: y, z: oneFe(), t: x * y)

proc add*(p, q: EdwardsPoint): EdwardsPoint =
  let d = edwardsD()
  let twoD = d + d
  let a = (p.y - p.x) * (q.y - q.x)
  let b = (p.y + p.x) * (q.y + q.x)
  let c = twoD * p.t * q.t
  let dd = feFromInt(2) * p.z * q.z
  let e = b - a
  let f = dd - c
  let g = dd + c
  let h = b + a
  EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)

proc negate*(p: EdwardsPoint): EdwardsPoint =
  EdwardsPoint(x: zeroFe() - p.x, y: p.y, z: p.z, t: zeroFe() - p.t)

proc double*(p: EdwardsPoint): EdwardsPoint =
  let a = square(p.x)
  let b = square(p.y)
  let c = feFromInt(2) * square(p.z)
  let h = a + b
  let e = h - square(p.x + p.y)
  let g = a - b
  let f = c + g
  EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)

proc scalarMult*(scalar: openArray[byte]; point: EdwardsPoint): EdwardsPoint =
  result = identityPoint()
  var base = point
  for byteValue in scalar:
    var current = byteValue
    for _ in 0 ..< 8:
      if (current and 1) != 0:
        result = add(result, base)
      base = add(base, base)
      current = current shr 1

proc toAffine(p: EdwardsPoint): tuple[x, y: Fe25519] =
  let zInv = inv(p.z)
  (p.x * zInv, p.y * zInv)

proc encodePoint*(p: EdwardsPoint): seq[byte] =
  let affine = toAffine(p)
  result = encode(affine.y)
  if (encode(affine.x)[0] and 1) != 0:
    result[31] = result[31] or 0x80

proc decodePoint*(encoded: openArray[byte]): EdwardsPoint =
  if encoded.len != Ed25519Bytes:
    raise newException(ValueError, "Ed25519 point encoding must be 32 bytes")
  var yBytes = @encoded
  let sign = (yBytes[31] shr 7) and 1
  yBytes[31] = yBytes[31] and 0x7f
  let y = decodeFe25519(yBytes)
  let yy = square(y)
  let u = yy - oneFe()
  let v = edwardsD() * yy + oneFe()
  let root = sqrtRatioM1(u, v)
  if not root.wasSquare:
    raise newException(ValueError, "invalid Ed25519 point encoding")
  var x = root.result
  if (encode(x)[0] and 1) != sign:
    x = zeroFe() - x
  result = EdwardsPoint(x: x, y: y, z: oneFe(), t: x * y)

proc clampEd25519Scalar*(digest: openArray[byte]): seq[byte] =
  if digest.len < 32:
    raise newException(ValueError, "Ed25519 digest must contain at least 32 bytes")
  result = newSeq[byte](32)
  for i in 0 ..< 32:
    result[i] = digest[i]
  result[0] = result[0] and 248
  result[31] = result[31] and 63
  result[31] = result[31] or 64

proc ed25519PublicKeyFromSeed*(seed: openArray[byte]): seq[byte] =
  if seed.len != Ed25519Bytes:
    raise newException(ValueError, "Ed25519 seed must be 32 bytes")
  let digest = sha512(seed)
  let scalar = clampEd25519Scalar(digest)
  encodePoint(scalarMult(scalar, basePoint()))

const
  Ed25519Order: array[32, byte] = [
    byte 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  ]

proc cmpLe(a, b: openArray[byte]): int =
  let top = max(a.len, b.len) - 1
  for i in countdown(top, 0):
    let av = if i < a.len: a[i] else: byte 0
    let bv = if i < b.len: b[i] else: byte 0
    if av < bv: return -1
    if av > bv: return 1
  0

proc subLe(a: var seq[byte]; b: openArray[byte]) =
  var borrow = 0
  for i in 0 ..< a.len:
    var value = int(a[i]) - int(b[i]) - borrow
    if value < 0:
      value += 256
      borrow = 1
    else:
      borrow = 0
    a[i] = byte(value)

proc shl1Le(a: var seq[byte]) =
  var carry = 0
  for i in 0 ..< a.len:
    let value = int(a[i]) * 2 + carry
    a[i] = byte(value and 0xff)
    carry = value shr 8
  if carry != 0:
    a.add byte(carry)

proc bitAtLe(input: openArray[byte]; bitIndex: int): int =
  let byteIndex = bitIndex div 8
  if byteIndex >= input.len:
    0
  else:
    int((input[byteIndex] shr (bitIndex mod 8)) and 1)

proc reduceScalar*(input: openArray[byte]): seq[byte] =
  ## Reduces a little-endian integer modulo the Ed25519 group order.
  var rem = newSeq[byte](32)
  for bit in countdown(input.len * 8 - 1, 0):
    shl1Le(rem)
    rem[0] = rem[0] or byte(bitAtLe(input, bit))
    while rem.len > 32 and rem[^1] == 0:
      rem.setLen(rem.len - 1)
    if cmpLe(rem, Ed25519Order) >= 0:
      subLe(rem, Ed25519Order)
  rem.setLen(32)
  rem

proc scalarMulAddMod(h, a, r: openArray[byte]): seq[byte] =
  var wide = newSeq[byte](64)
  for i in 0 ..< 32:
    var carry = 0
    for j in 0 ..< 32:
      let index = i + j
      let value = int(wide[index]) + int(h[i]) * int(a[j]) + carry
      wide[index] = byte(value and 0xff)
      carry = value shr 8
    var index = i + 32
    while carry > 0:
      let value = int(wide[index]) + carry
      wide[index] = byte(value and 0xff)
      carry = value shr 8
      inc index

  var carry = 0
  for i in 0 ..< 32:
    let value = int(wide[i]) + int(r[i]) + carry
    wide[i] = byte(value and 0xff)
    carry = value shr 8
  var index = 32
  while carry > 0 and index < wide.len:
    let value = int(wide[index]) + carry
    wide[index] = byte(value and 0xff)
    carry = value shr 8
    inc index

  reduceScalar(wide)

proc concat(a, b: openArray[byte]): seq[byte] =
  result = newSeq[byte](a.len + b.len)
  for i, value in a:
    result[i] = value
  for i, value in b:
    result[a.len + i] = value

proc concat3(a, b, c: openArray[byte]): seq[byte] =
  concat(concat(a, b), c)

proc ed25519Sign*(seed, message: openArray[byte]): seq[byte] =
  if seed.len != Ed25519Bytes:
    raise newException(ValueError, "Ed25519 seed must be 32 bytes")
  let digest = sha512(seed)
  let a = clampEd25519Scalar(digest)
  let prefix = digest[32 ..< 64]
  let publicKey = encodePoint(scalarMult(a, basePoint()))
  let r = reduceScalar(sha512(concat(prefix, message)))
  let rPoint = encodePoint(scalarMult(r, basePoint()))
  let h = reduceScalar(sha512(concat3(rPoint, publicKey, message)))
  let s = scalarMulAddMod(h, a, r)

  result = newSeq[byte](64)
  for i in 0 ..< 32:
    result[i] = rPoint[i]
    result[32 + i] = s[i]

proc ed25519Verify*(publicKey, message, signature: openArray[byte]): bool =
  if publicKey.len != Ed25519Bytes or signature.len != 64:
    return false
  let rBytes = signature[0 ..< 32]
  let sBytes = signature[32 ..< 64]
  if cmpLe(sBytes, Ed25519Order) >= 0:
    return false
  try:
    let aPoint = decodePoint(publicKey)
    let rPoint = decodePoint(rBytes)
    let h = reduceScalar(sha512(concat3(rBytes, publicKey, message)))
    var left = add(scalarMult(sBytes, basePoint()), negate(scalarMult(h, aPoint)))
    var right = rPoint
    for _ in 0 ..< 3:
      left = add(left, left)
      right = add(right, right)
    encodePoint(left) == encodePoint(right)
  except ValueError:
    false
