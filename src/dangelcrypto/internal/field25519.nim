## Experimental field arithmetic for p = 2^255 - 19.
##
## Representation: 16 little-endian limbs in base 2^16.
## This is a clear reference implementation foundation. Constant-time cleanup
## is required before public key operations are exposed as production-ready.

import ../types

const
  LimbBits = 16
  LimbBase = 1'u64 shl LimbBits
  LimbMask = LimbBase - 1
  FeLimbs* = 16
  P25519*: array[FeLimbs, uint32] = [
    65517'u32,
    65535'u32, 65535'u32, 65535'u32, 65535'u32,
    65535'u32, 65535'u32, 65535'u32, 65535'u32,
    65535'u32, 65535'u32, 65535'u32, 65535'u32,
    65535'u32, 65535'u32,
    32767'u32
  ]

type
  Fe25519* = array[FeLimbs, uint32]

proc zeroFe*(): Fe25519 =
  discard

proc oneFe*(): Fe25519 =
  result[0] = 1

proc geqP(a: Fe25519): bool =
  for i in countdown(FeLimbs - 1, 0):
    if a[i] > P25519[i]:
      return true
    if a[i] < P25519[i]:
      return false
  true

proc subP(a: var Fe25519) =
  var borrow: int64 = 0
  for i in 0 ..< FeLimbs:
    var value = int64(a[i]) - int64(P25519[i]) - borrow
    if value < 0:
      value += int64(LimbBase)
      borrow = 1
    else:
      borrow = 0
    a[i] = uint32(value)

proc normalizeWide(limbs: var array[32, uint64]): Fe25519 =
  for i in FeLimbs ..< 32:
    limbs[i - FeLimbs] += limbs[i] * 38'u64
    limbs[i] = 0

  for pass in 0 ..< 3:
    discard pass
    var carry = 0'u64
    for i in 0 ..< FeLimbs:
      let value = limbs[i] + carry
      limbs[i] = value and LimbMask
      carry = value shr LimbBits
    limbs[0] += carry * 38'u64

  for i in 0 ..< FeLimbs:
    result[i] = uint32(limbs[i] and LimbMask)

  while geqP(result):
    subP(result)

proc normalize*(a: Fe25519): Fe25519 =
  var wide: array[32, uint64]
  for i in 0 ..< FeLimbs:
    wide[i] = uint64(a[i])
  normalizeWide(wide)

proc feFromInt*(value: uint64): Fe25519 =
  var wide: array[32, uint64]
  wide[0] = value and LimbMask
  wide[1] = (value shr 16) and LimbMask
  wide[2] = (value shr 32) and LimbMask
  wide[3] = (value shr 48) and LimbMask
  normalizeWide(wide)

proc `+`*(a, b: Fe25519): Fe25519 =
  var wide: array[32, uint64]
  for i in 0 ..< FeLimbs:
    wide[i] = uint64(a[i]) + uint64(b[i])
  normalizeWide(wide)

proc `-`*(a, b: Fe25519): Fe25519 =
  var wide: array[32, uint64]
  var borrow: int64 = 0
  for i in 0 ..< FeLimbs:
    var value = int64(a[i]) + int64(P25519[i]) - int64(b[i]) - borrow
    if value < 0:
      value += int64(LimbBase)
      borrow = 1
    else:
      borrow = 0
    wide[i] = uint64(value)

  normalizeWide(wide)

proc `*`*(a, b: Fe25519): Fe25519 =
  var wide: array[32, uint64]
  for i in 0 ..< FeLimbs:
    for j in 0 ..< FeLimbs:
      wide[i + j] += uint64(a[i]) * uint64(b[j])
  normalizeWide(wide)

proc square*(a: Fe25519): Fe25519 =
  a * a

proc pow*(a: Fe25519; exponent: openArray[byte]): Fe25519 =
  ## Raises a field element to a little-endian exponent.
  result = oneFe()
  var base = a
  for byteValue in exponent:
    var current = byteValue
    for _ in 0 ..< 8:
      if (current and 1) != 0:
        result = result * base
      base = square(base)
      current = current shr 1

proc equal*(a, b: Fe25519): bool

proc inv*(a: Fe25519): Fe25519 =
  ## Multiplicative inverse: a^(p - 2), p = 2^255 - 19.
  var exponent: array[32, byte]
  for i in 0 ..< 31:
    exponent[i] = 0xff
  exponent[31] = 0x7f

  var borrow = 20
  var i = 0
  while borrow > 0:
    let value = int(exponent[i]) - (borrow and 0xff)
    if value < 0:
      exponent[i] = byte(value + 256)
      borrow = 1
    else:
      exponent[i] = byte(value)
      borrow = 0
    inc i

  pow(a, exponent)

proc sqrtRatioM1*(u, v: Fe25519): tuple[wasSquare: bool, result: Fe25519] =
  ## Computes sqrt(u / v) for p = 5 mod 8.
  let pMinus5Div8: array[32, byte] = [
    byte 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
  ]
  let pMinus1Div4: array[32, byte] = [
    byte 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f
  ]
  let sqrtM1 = feFromInt(2).pow(pMinus1Div4)
  let v3 = square(v) * v
  let v7 = square(v3) * v
  var r = u * v3 * pow(u * v7, pMinus5Div8)
  let check = v * square(r)
  if equal(check, u):
    return (true, r)
  if equal(check, zeroFe() - u):
    r = r * sqrtM1
    return (true, r)
  (false, r)

proc encode*(a: Fe25519): ByteSeq =
  let normalized = normalize(a)
  result = newSeq[byte](32)
  for i, limb in normalized:
    result[i * 2] = byte(limb and 0xff)
    result[i * 2 + 1] = byte((limb shr 8) and 0xff)
  result[31] = result[31] and 0x7f

proc decodeFe25519*(data: openArray[byte]): Fe25519 =
  if data.len != 32:
    raise newException(ValueError, "field25519 encoding must be 32 bytes")

  var wide: array[32, uint64]
  for i in 0 ..< FeLimbs:
    wide[i] = uint64(data[i * 2]) or (uint64(data[i * 2 + 1]) shl 8)
  wide[15] = wide[15] and 0x7fff'u64
  normalizeWide(wide)

proc equal*(a, b: Fe25519): bool =
  let aa = normalize(a)
  let bb = normalize(b)
  var diff: uint32 = 0
  for i in 0 ..< FeLimbs:
    diff = diff or (aa[i] xor bb[i])
  diff == 0
