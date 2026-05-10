## Pure Nim HMAC helpers.

import ../types
import ./sha2

const Sha512BlockBytes = 128

proc hmacSha512*(key, message: openArray[byte]): ByteSeq =
  var keyBlock = newSeq[byte](Sha512BlockBytes)
  if key.len > Sha512BlockBytes:
    let hashed = sha512(key)
    for i, value in hashed:
      keyBlock[i] = value
  else:
    for i, value in key:
      keyBlock[i] = value

  var inner = newSeq[byte](Sha512BlockBytes + message.len)
  var outer = newSeq[byte](Sha512BlockBytes + Sha512DigestBytes)
  for i in 0 ..< Sha512BlockBytes:
    inner[i] = keyBlock[i] xor 0x36
    outer[i] = keyBlock[i] xor 0x5c
  for i, value in message:
    inner[Sha512BlockBytes + i] = value

  let innerHash = sha512(inner)
  for i, value in innerHash:
    outer[Sha512BlockBytes + i] = value
  sha512(outer)
