import std/unittest

import dangelcrypto/types
import dangelcrypto/internal/kyber_math
import dangelcrypto/internal/kyber_polyvec

suite "kyber polyvec":
  test "level parameters":
    check kyberK(Kyber512) == 2
    check kyberK(Kyber768) == 3
    check kyberK(Kyber1024) == 4
    check kyberEta1(Kyber512) == 3
    check kyberEta1(Kyber768) == 2

  test "polyvec 12-bit roundtrip":
    var vec = newPolyVec(3)
    for i in 0 ..< vec.k:
      vec.polys[i] = uniformPoly([byte i, 1, 2, 3])
    check decodePolyVec12(encodePolyVec12(vec), 3).polys == vec.polys

  test "polyvec compression lengths":
    var vec768 = newPolyVec(3)
    var vec1024 = newPolyVec(4)
    check compressPolyVecForLevel(vec768, Kyber768).len == polyVecCompressedBytes(Kyber768)
    check compressPolyVecForLevel(vec1024, Kyber1024).len == polyVecCompressedBytes(Kyber1024)

  test "matrix expansion is deterministic":
    let seed = [byte 0, 1, 2, 3, 4, 5, 6, 7]
    let a = expandMatrix(seed, Kyber768)
    let b = expandMatrix(seed, Kyber768)
    let at = expandMatrix(seed, Kyber768, transposed = true)
    check a[0].polys[0] == b[0].polys[0]
    check a[0].polys[1] == at[1].polys[0]

  test "noise vectors are deterministic":
    let seed = [byte 9, 8, 7, 6, 5, 4, 3, 2]
    let a = sampleNoiseVec(seed, Kyber512, 0)
    let b = sampleNoiseVec(seed, Kyber512, 0)
    let c = sampleNoiseVec(seed, Kyber512, 1)
    check a.polys == b.polys
    check a.polys != c.polys

  test "dot product identity":
    var a = newPolyVec(2)
    var b = newPolyVec(2)
    a.polys[0] = uniformPoly([byte 1, 2, 3, 4])
    b.polys[0] = monomial(0, KyberCoeff(1))
    check dotNegacyclic(a, b) == a.polys[0]
