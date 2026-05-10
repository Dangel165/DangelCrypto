## KCDSA / EC-KCDSA foundation.
##
## The exact parameter sets and hash/domain-separation rules differ by profile.
## This module defines the common typed surface used by public modules while the
## concrete algorithms are implemented and vector-tested.

import ../types
import ./sha2

type
  KcdsaDomain* = enum
    KcdsaClassic,
    EcKcdsaSecp256k1

  KcdsaDigest* = object
    domain*: KcdsaDomain
    raw*: ByteSeq

  KcdsaSignatureParts* = object
    r*: ByteSeq
    s*: ByteSeq

proc domainLabel(domain: KcdsaDomain): string =
  case domain
  of KcdsaClassic: "KCDSA"
  of EcKcdsaSecp256k1: "EC-KCDSA-secp256k1"

proc kcdsaHash*(domain: KcdsaDomain; message: openArray[byte]): KcdsaDigest =
  let label = domainLabel(domain)
  var input = newSeq[byte](label.len + 1 + message.len)
  for i, ch in label:
    input[i] = byte(ord(ch))
  input[label.len] = 0
  for i, value in message:
    input[label.len + 1 + i] = value
  KcdsaDigest(domain: domain, raw: sha512(input)[0 ..< 32])

proc encodeSignatureParts*(parts: KcdsaSignatureParts): ByteSeq =
  if parts.r.len > 255 or parts.s.len > 255:
    raise newException(ValueError, "KCDSA signature component too long")
  result = newSeq[byte](2 + parts.r.len + parts.s.len)
  result[0] = byte(parts.r.len)
  for i, value in parts.r:
    result[1 + i] = value
  result[1 + parts.r.len] = byte(parts.s.len)
  for i, value in parts.s:
    result[2 + parts.r.len + i] = value

proc decodeSignatureParts*(data: openArray[byte]): KcdsaSignatureParts =
  if data.len < 2:
    raise newException(ValueError, "KCDSA signature encoding too short")
  let rLen = int(data[0])
  if data.len < 1 + rLen + 1:
    raise newException(ValueError, "KCDSA signature encoding missing s length")
  let sLen = int(data[1 + rLen])
  if data.len != 2 + rLen + sLen:
    raise newException(ValueError, "KCDSA signature encoding length mismatch")
  result.r = @data[1 ..< 1 + rLen]
  result.s = @data[2 + rLen ..< data.len]
