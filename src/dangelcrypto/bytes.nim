import std/strutils

import ./types

const HexAlphabet = "0123456789abcdef"

proc toHex*(data: openArray[byte]): string =
  result = newString(data.len * 2)
  for i, value in data:
    result[i * 2] = HexAlphabet[int(value shr 4)]
    result[i * 2 + 1] = HexAlphabet[int(value and 0x0f)]

proc fromHex*(hex: string): ByteSeq =
  let clean = hex.strip
  if clean.len mod 2 != 0:
    raise newException(ValueError, "hex string must contain an even number of characters")

  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    let part = clean[i * 2 .. i * 2 + 1]
    try:
      result[i] = byte(parseHexInt(part))
    except ValueError:
      raise newException(ValueError, "invalid hex byte at offset " & $(i * 2))

proc constantTimeEqual*(a, b: openArray[byte]): bool =
  if a.len != b.len:
    return false

  var diff: byte = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  result = diff == 0

proc wipe*(data: var openArray[byte]) =
  for i in 0 ..< data.len:
    data[i] = 0
