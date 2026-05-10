import std/unittest

import dangelcrypto/internal/kyber_math

suite "kyber internal math":
  test "mod q normalization":
    check modQ(0) == 0
    check modQ(KyberQ) == 0
    check modQ(-1) == KyberQ - 1
    check modQ(KyberQ + 5) == 5

  test "coefficient arithmetic":
    check addQ(KyberCoeff(3328), KyberCoeff(2)) == 1
    check subQ(KyberCoeff(1), KyberCoeff(2)) == KyberQ - 1
    check mulQ(KyberCoeff(100), KyberCoeff(100)) == modQ(10_000)

  test "polynomial add subtract":
    var a = zeroPoly()
    var b = zeroPoly()
    a[0] = KyberCoeff(3328)
    b[0] = KyberCoeff(2)

    let sum = a + b
    let diff = sum - b
    check sum[0] == 1
    check diff[0] == a[0]

  test "polynomial bytes roundtrip":
    let poly = uniformPoly([byte 1, 2, 3, 4, 5, 6, 7, 8])
    check polyFromBytes(poly.toBytes) == poly

  test "kyber 12-bit polynomial encoding roundtrip":
    let poly = uniformPoly([byte 1, 2, 3, 4, 5, 6, 7, 8])
    check encodePoly12(poly).len == KyberPolyBytes
    check decodePoly12(encodePoly12(poly)) == poly

  test "kyber compressed polynomial lengths":
    let poly = uniformPoly([byte 8, 7, 6, 5, 4, 3, 2, 1])
    check compressPoly4(poly).len == KyberPolyCompressedBytes4
    check compressPoly5(poly).len == KyberPolyCompressedBytes5

  test "message polynomial roundtrip":
    var msg: array[KyberSymBytes, byte]
    for i in 0 ..< KyberSymBytes:
      msg[i] = byte((i * 7) and 0xff)
    check polyToMsg(polyFromMsg(msg)) == @msg

  test "compressed polynomial preserves message bits":
    let poly = polyFromMsg([
      byte 0xff, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0
    ])
    check polyToMsg(decompressPoly4(compressPoly4(poly)))[0] == 0xff
    check polyToMsg(decompressPoly5(compressPoly5(poly)))[0] == 0xff

  test "negacyclic multiplication identity":
    let one = monomial(0, KyberCoeff(1))
    let x = monomial(1, KyberCoeff(1))
    let sample = uniformPoly([byte 9, 8, 7, 6])
    check negacyclicMul(sample, one) == sample
    check negacyclicMul(one, sample) == sample
    check negacyclicMul(x, monomial(KyberN - 1, KyberCoeff(1)))[0] == KyberQ - 1

  test "centered binomial eta2 maps into q":
    let poly = centeredBinomialEta2([byte 0b0001_1110])
    check poly[0] == modQ(-1)
    check poly[1] == modQ(1)

  test "uniform rejection sampler from bytes":
    var data = newSeq[byte](KyberN * 3 div 2)
    for i in 0 ..< KyberN:
      let value = i mod KyberQ
      let pair = i div 2
      let offset = pair * 3
      if i mod 2 == 0:
        data[offset] = byte(value and 0xff)
        data[offset + 1] = byte((int(data[offset + 1]) and 0xf0) or ((value shr 8) and 0x0f))
      else:
        data[offset + 1] = byte((int(data[offset + 1]) and 0x0f) or ((value and 0x0f) shl 4))
        data[offset + 2] = byte((value shr 4) and 0xff)
    let poly = sampleUniformFromBytes(data)
    check poly[0] == 0
    check poly[1] == 1
    check poly[255] == 255

  test "uniform xof sampler is deterministic":
    let seed = [byte 0, 1, 2, 3, 4, 5, 6, 7]
    let a = sampleUniformXof(seed, 1, 2)
    let b = sampleUniformXof(seed, 1, 2)
    let c = sampleUniformXof(seed, 2, 1)
    check a == b
    check a != c

  test "montgomery and barrett reduction":
    check modQ(int(montgomeryReduce(0))) == 0
    check modQ(int(barrettReduce(KyberQ + 9))) == 9
    check modQ(int(fqmul(KyberCoeff(2), KyberCoeff(3)))) == modQ(2 * 3 * 169)

  test "ntt inverse roundtrip":
    let poly = uniformPoly([byte 9, 8, 7, 6, 5, 4, 3, 2])
    check inverseNtt(ntt(poly)) == poly
    for i, coeff in inverseNttToMont(ntt(poly)):
      check modQ(int(coeff)) == mulQ(poly[i], KyberCoeff(2285))

  test "basemul smoke test":
    let product = basemul(KyberCoeff(1), KyberCoeff(2), KyberCoeff(3), KyberCoeff(4), KyberCoeff(5))
    var expected0 = fqmul(KyberCoeff(2), KyberCoeff(4))
    expected0 = fqmul(expected0, KyberCoeff(5))
    expected0 = barrettReduce(int(expected0) + int(fqmul(KyberCoeff(1), KyberCoeff(3))))
    let expected1 = barrettReduce(
      int(fqmul(KyberCoeff(1), KyberCoeff(4))) +
      int(fqmul(KyberCoeff(2), KyberCoeff(3)))
    )
    check product.c0 == expected0
    check product.c1 == expected1

  test "compression stays in requested bit width":
    for coeff in [KyberCoeff(0), KyberCoeff(1), KyberCoeff(1664), KyberCoeff(3328)]:
      let compressed = compressCoeff(coeff, 10)
      check compressed < (1'u16 shl 10)
