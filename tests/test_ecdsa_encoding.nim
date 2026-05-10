import std/unittest

import dangelcrypto/bytes
import dangelcrypto/ecdsa

suite "ECDSA signature encoding":
  test "raw signature roundtrip":
    let r = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let s = fromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
    let raw = encodeRawEcdsaSignature(r, s)
    check raw.len == 64
    let decoded = decodeRawEcdsaSignature(raw)
    check decoded.r == r
    check decoded.s == s

  test "DER signature roundtrip":
    let r = fromHex("0000000000000000000000000000000000000000000000000000000000000001")
    let s = fromHex("000000000000000000000000000000000000000000000000000000000000002a")
    let der = encodeDerEcdsaSignature(r, s)
    check der.toHex == "300602010102012a"
    let decoded = decodeDerEcdsaSignature(der)
    check decoded.r == r
    check decoded.s == s

  test "DER integer adds sign guard when high bit is set":
    var r = newSeq[byte](32)
    var s = newSeq[byte](32)
    r[0] = 0x80
    s[31] = 1
    let der = encodeDerEcdsaSignature(r, s)
    check der.toHex[0 ..< 12] == "302602210080"
    let decoded = decodeDerEcdsaSignature(der)
    check decoded.r == r
    check decoded.s == s

  test "invalid DER is rejected":
    expect ValueError:
      discard decodeDerEcdsaSignature(fromHex("300602010102012a00"))
    expect ValueError:
      discard decodeDerEcdsaSignature(fromHex("30070202000102012a"))
    expect ValueError:
      discard decodeDerEcdsaSignature(fromHex("300602018002012a"))
