import std/unittest

import dangelcrypto/internal/field25519

suite "field25519 internal arithmetic":
  test "zero and one":
    check equal(zeroFe(), feFromInt(0))
    check equal(oneFe(), feFromInt(1))

  test "addition and subtraction":
    let a = feFromInt(1234)
    let b = feFromInt(9876)
    check equal((a + b) - b, a)

  test "multiplication and square":
    let a = feFromInt(12)
    let b = feFromInt(13)
    check equal(a * b, feFromInt(156))
    check equal(square(a), feFromInt(144))

  test "inversion":
    let a = feFromInt(12)
    check equal(a * inv(a), oneFe())

  test "encoding roundtrip":
    let value = feFromInt(0x1234_5678_9abc_def0'u64)
    check equal(decodeFe25519(encode(value)), value)

  test "prime wraps to zero":
    let p = decodeFe25519([
      byte 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ])
    check equal(p, zeroFe())
