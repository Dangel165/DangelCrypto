## ECDSA signature encoding helpers.
##
## These helpers intentionally only handle the byte representation of ECDSA
## `(r, s)` components. Curve validation and signature verification stay in the
## secp256k1 arithmetic layer.

import ../types

type
  EcdsaSignatureParts* = object
    r*, s*: ByteSeq

proc require32(name: string; value: openArray[byte]) =
  if value.len != 32:
    raise newException(ValueError, name & " must be 32 bytes")

proc encodeRawEcdsaSignature*(r, s: openArray[byte]): ByteSeq =
  require32("ECDSA r", r)
  require32("ECDSA s", s)
  result = newSeq[byte](64)
  for i in 0 ..< 32:
    result[i] = r[i]
    result[i + 32] = s[i]

proc decodeRawEcdsaSignature*(signature: openArray[byte]): EcdsaSignatureParts =
  if signature.len != 64:
    raise newException(ValueError, "raw ECDSA signature must be 64 bytes")
  result.r = newSeq[byte](32)
  result.s = newSeq[byte](32)
  for i in 0 ..< 32:
    result.r[i] = signature[i]
    result.s[i] = signature[i + 32]

proc trimUnsigned(value: openArray[byte]): ByteSeq =
  require32("ECDSA integer", value)
  var first = 0
  while first < 31 and value[first] == 0:
    inc first
  result = @[]
  if (value[first] and 0x80'u8) != 0:
    result.add byte 0
  for i in first ..< value.len:
    result.add value[i]

proc encodeDerInteger(value: openArray[byte]): ByteSeq =
  let body = trimUnsigned(value)
  result = @[byte 0x02, byte body.len]
  result.add body

proc encodeDerEcdsaSignature*(r, s: openArray[byte]): ByteSeq =
  let rInt = encodeDerInteger(r)
  let sInt = encodeDerInteger(s)
  let bodyLen = rInt.len + sInt.len
  if bodyLen > 127:
    raise newException(ValueError, "ECDSA DER signature body is too long")
  result = @[byte 0x30, byte bodyLen]
  result.add rInt
  result.add sInt

proc decodeDerInteger(data: openArray[byte]; offset: var int): ByteSeq =
  if offset + 2 > data.len or data[offset] != 0x02'u8:
    raise newException(ValueError, "invalid ECDSA DER integer")
  let length = int(data[offset + 1])
  offset += 2
  if length < 1 or length > 33 or offset + length > data.len:
    raise newException(ValueError, "invalid ECDSA DER integer length")

  let first = data[offset]
  if (first and 0x80'u8) != 0:
    raise newException(ValueError, "negative ECDSA DER integer")
  if length > 1 and first == 0 and (data[offset + 1] and 0x80'u8) == 0:
    raise newException(ValueError, "non-minimal ECDSA DER integer")

  var start = offset
  var size = length
  if data[start] == 0:
    inc start
    dec size
  if size > 32:
    raise newException(ValueError, "ECDSA DER integer is too large")

  result = newSeq[byte](32)
  let pad = 32 - size
  for i in 0 ..< size:
    result[pad + i] = data[start + i]
  offset += length

proc decodeDerEcdsaSignature*(signature: openArray[byte]): EcdsaSignatureParts =
  if signature.len < 8 or signature[0] != 0x30'u8:
    raise newException(ValueError, "invalid ECDSA DER sequence")
  let bodyLen = int(signature[1])
  if bodyLen != signature.len - 2:
    raise newException(ValueError, "invalid ECDSA DER sequence length")
  var offset = 2
  result.r = decodeDerInteger(signature, offset)
  result.s = decodeDerInteger(signature, offset)
  if offset != signature.len:
    raise newException(ValueError, "trailing bytes in ECDSA DER signature")
