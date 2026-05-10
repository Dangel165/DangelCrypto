## Pure Nim X25519 foundation following RFC 7748.

import ../types
import ./field25519

const X25519Bytes* = 32

proc clampScalar*(scalar: openArray[byte]): ByteSeq =
  if scalar.len != X25519Bytes:
    raise newException(ValueError, "X25519 scalar must be 32 bytes")
  result = @scalar
  result[0] = result[0] and 248
  result[31] = result[31] and 127
  result[31] = result[31] or 64

proc cswap(swap: byte; x2, x3: var Fe25519) =
  let mask = uint32(0) - uint32(swap)
  for i in 0 ..< FeLimbs:
    let t = mask and (x2[i] xor x3[i])
    x2[i] = x2[i] xor t
    x3[i] = x3[i] xor t

proc x25519Raw*(scalar, uCoordinate: openArray[byte]): ByteSeq =
  if uCoordinate.len != X25519Bytes:
    raise newException(ValueError, "X25519 u-coordinate must be 32 bytes")

  let k = clampScalar(scalar)
  var u = @uCoordinate
  u[31] = u[31] and 0x7f

  let x1 = decodeFe25519(u)
  var x2 = oneFe()
  var z2 = zeroFe()
  var x3 = x1
  var z3 = oneFe()
  var swap: byte = 0
  let a24 = feFromInt(121665)

  for t in countdown(254, 0):
    let kt = byte((k[t div 8] shr (t mod 8)) and 1)
    swap = swap xor kt
    cswap(swap, x2, x3)
    cswap(swap, z2, z3)
    swap = kt

    let a = x2 + z2
    let aa = square(a)
    let b = x2 - z2
    let bb = square(b)
    let e = aa - bb
    let c = x3 + z3
    let d = x3 - z3
    let da = d * a
    let cb = c * b
    x3 = square(da + cb)
    z3 = x1 * square(da - cb)
    x2 = aa * bb
    z2 = e * (aa + (a24 * e))

  cswap(swap, x2, x3)
  cswap(swap, z2, z3)
  encode(x2 * inv(z2))

proc x25519Base*(scalar: openArray[byte]): ByteSeq =
  var base = newSeq[byte](X25519Bytes)
  base[0] = 9
  x25519Raw(scalar, base)
