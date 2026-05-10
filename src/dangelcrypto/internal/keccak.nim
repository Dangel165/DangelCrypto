## Pure Nim Keccak-f[1600] and SHAKE XOF foundation.
##
## SHAKE128 and SHAKE256 are specified by NIST FIPS 202.

import ../types

type
  KeccakState = array[25, uint64]

const
  KeccakRounds = 24
  ShakeDomain = byte 0x1f
  Sha3Domain = byte 0x06
  RoundConstants: array[KeccakRounds, uint64] = [
    0x0000000000000001'u64, 0x0000000000008082'u64,
    0x800000000000808a'u64, 0x8000000080008000'u64,
    0x000000000000808b'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64,
    0x000000000000008a'u64, 0x0000000000000088'u64,
    0x0000000080008009'u64, 0x000000008000000a'u64,
    0x000000008000808b'u64, 0x800000000000008b'u64,
    0x8000000000008089'u64, 0x8000000000008003'u64,
    0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800a'u64, 0x800000008000000a'u64,
    0x8000000080008081'u64, 0x8000000000008080'u64,
    0x0000000080000001'u64, 0x8000000080008008'u64
  ]
  RhoOffsets: array[25, int] = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
  ]

proc rotl64(value: uint64; amount: int): uint64 =
  if amount == 0:
    value
  else:
    (value shl amount) or (value shr (64 - amount))

proc load64(input: openArray[byte]; offset: int): uint64 =
  for i in 0 ..< 8:
    result = result or (uint64(input[offset + i]) shl (8 * i))

proc store64(output: var openArray[byte]; offset: int; value: uint64) =
  for i in 0 ..< 8:
    output[offset + i] = byte((value shr (8 * i)) and 0xff)

proc keccakF1600*(state: var KeccakState) =
  for round in 0 ..< KeccakRounds:
    var c: array[5, uint64]
    var d: array[5, uint64]
    var b: KeccakState

    for x in 0 ..< 5:
      c[x] = state[x] xor state[x + 5] xor state[x + 10] xor state[x + 15] xor state[x + 20]

    for x in 0 ..< 5:
      d[x] = c[(x + 4) mod 5] xor rotl64(c[(x + 1) mod 5], 1)

    for y in 0 ..< 5:
      for x in 0 ..< 5:
        state[x + 5 * y] = state[x + 5 * y] xor d[x]

    for y in 0 ..< 5:
      for x in 0 ..< 5:
        let index = x + 5 * y
        let newX = y
        let newY = (2 * x + 3 * y) mod 5
        b[newX + 5 * newY] = rotl64(state[index], RhoOffsets[index])

    for y in 0 ..< 5:
      for x in 0 ..< 5:
        state[x + 5 * y] =
          b[x + 5 * y] xor ((not b[((x + 1) mod 5) + 5 * y]) and b[((x + 2) mod 5) + 5 * y])

    state[0] = state[0] xor RoundConstants[round]

proc xorByte(state: var KeccakState; offset: int; value: byte) =
  let lane = offset div 8
  let shift = (offset mod 8) * 8
  state[lane] = state[lane] xor (uint64(value) shl shift)

proc keccakSponge(input: openArray[byte]; outputLen, rate: int; domain: byte): ByteSeq =
  var state: KeccakState
  var offset = 0

  while input.len - offset >= rate:
    for i in 0 ..< (rate div 8):
      state[i] = state[i] xor load64(input, offset + i * 8)
    keccakF1600(state)
    offset += rate

  var blockPos = 0
  while offset < input.len:
    xorByte(state, blockPos, input[offset])
    inc offset
    inc blockPos

  xorByte(state, blockPos, domain)
  xorByte(state, rate - 1, 0x80)
  keccakF1600(state)

  result = newSeq[byte](outputLen)
  var outPos = 0
  while outPos < outputLen:
    let chunk = min(rate, outputLen - outPos)
    var lane = 0
    while lane * 8 < chunk:
      var temp: array[8, byte]
      store64(temp, 0, state[lane])
      let copyLen = min(8, chunk - lane * 8)
      for i in 0 ..< copyLen:
        result[outPos + lane * 8 + i] = temp[i]
      inc lane

    outPos += chunk
    if outPos < outputLen:
      keccakF1600(state)

proc shake128*(input: openArray[byte]; outputLen: Natural): ByteSeq =
  keccakSponge(input, int(outputLen), 168, ShakeDomain)

proc shake256*(input: openArray[byte]; outputLen: Natural): ByteSeq =
  keccakSponge(input, int(outputLen), 136, ShakeDomain)

proc sha3_256*(input: openArray[byte]): ByteSeq =
  keccakSponge(input, 32, 136, Sha3Domain)

proc sha3_512*(input: openArray[byte]): ByteSeq =
  keccakSponge(input, 64, 72, Sha3Domain)
