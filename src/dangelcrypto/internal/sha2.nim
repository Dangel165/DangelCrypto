## Pure Nim SHA-2 foundation.

import ../types

const
  Sha256BlockBytes = 64
  Sha256DigestBytes* = 32
  Sha512BlockBytes = 128
  Sha512DigestBytes* = 64
  K256: array[64, uint32] = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]
  K512: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64,
    0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64,
    0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64,
    0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64,
    0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64,
    0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64,
    0x9bdc06a725c71235'u64, 0xc19bf174cf692694'u64,
    0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64,
    0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
    0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64,
    0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64,
    0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64,
    0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
    0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64,
    0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64,
    0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64,
    0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
    0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64,
    0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64,
    0xd192e819d6ef5218'u64, 0xd69906245565a910'u64,
    0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64,
    0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64,
    0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64,
    0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64,
    0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64,
    0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64,
    0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64,
    0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64,
    0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64,
    0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64,
    0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64,
    0x3c9ebe0a15c9bebc'u64, 0x431d67c49c100d4c'u64,
    0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64,
    0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

proc rotr(x: uint32; n: int): uint32 =
  (x shr n) or (x shl (32 - n))

proc rotr(x: uint64; n: int): uint64 =
  (x shr n) or (x shl (64 - n))

proc load32be(input: openArray[byte]; offset: int): uint32 =
  for i in 0 ..< 4:
    result = (result shl 8) or uint32(input[offset + i])

proc load64be(input: openArray[byte]; offset: int): uint64 =
  for i in 0 ..< 8:
    result = (result shl 8) or uint64(input[offset + i])

proc store32be(output: var openArray[byte]; offset: int; value: uint32) =
  for i in 0 ..< 4:
    output[offset + i] = byte((value shr (24 - 8 * i)) and 0xff)

proc store64be(output: var openArray[byte]; offset: int; value: uint64) =
  for i in 0 ..< 8:
    output[offset + i] = byte((value shr (56 - 8 * i)) and 0xff)

proc compress256(state: var array[8, uint32]; chunk: openArray[byte]) =
  var w: array[64, uint32]
  for i in 0 ..< 16:
    w[i] = load32be(chunk, i * 4)
  for i in 16 ..< 64:
    let s0 = rotr(w[i - 15], 7) xor rotr(w[i - 15], 18) xor (w[i - 15] shr 3)
    let s1 = rotr(w[i - 2], 17) xor rotr(w[i - 2], 19) xor (w[i - 2] shr 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  var a = state[0]
  var b = state[1]
  var c = state[2]
  var d = state[3]
  var e = state[4]
  var f = state[5]
  var g = state[6]
  var h = state[7]

  for i in 0 ..< 64:
    let s1 = rotr(e, 6) xor rotr(e, 11) xor rotr(e, 25)
    let ch = (e and f) xor ((not e) and g)
    let temp1 = h + s1 + ch + K256[i] + w[i]
    let s0 = rotr(a, 2) xor rotr(a, 13) xor rotr(a, 22)
    let maj = (a and b) xor (a and c) xor (b and c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e
  state[5] += f
  state[6] += g
  state[7] += h

proc compress512(state: var array[8, uint64]; chunk: openArray[byte]) =
  var w: array[80, uint64]
  for i in 0 ..< 16:
    w[i] = load64be(chunk, i * 8)
  for i in 16 ..< 80:
    let s0 = rotr(w[i - 15], 1) xor rotr(w[i - 15], 8) xor (w[i - 15] shr 7)
    let s1 = rotr(w[i - 2], 19) xor rotr(w[i - 2], 61) xor (w[i - 2] shr 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  var a = state[0]
  var b = state[1]
  var c = state[2]
  var d = state[3]
  var e = state[4]
  var f = state[5]
  var g = state[6]
  var h = state[7]

  for i in 0 ..< 80:
    let s1 = rotr(e, 14) xor rotr(e, 18) xor rotr(e, 41)
    let ch = (e and f) xor ((not e) and g)
    let temp1 = h + s1 + ch + K512[i] + w[i]
    let s0 = rotr(a, 28) xor rotr(a, 34) xor rotr(a, 39)
    let maj = (a and b) xor (a and c) xor (b and c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e
  state[5] += f
  state[6] += g
  state[7] += h

proc sha256*(input: openArray[byte]): ByteSeq =
  var state = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  var offset = 0
  while input.len - offset >= Sha256BlockBytes:
    compress256(state, input[offset ..< offset + Sha256BlockBytes])
    offset += Sha256BlockBytes

  let remaining = input.len - offset
  let paddingLen =
    if remaining + 9 <= Sha256BlockBytes: Sha256BlockBytes
    else: Sha256BlockBytes * 2
  var finalBlock = newSeq[byte](paddingLen)
  for i in 0 ..< remaining:
    finalBlock[i] = input[offset + i]
  finalBlock[remaining] = 0x80

  let bitLenLow = uint64(input.len) * 8'u64
  store64be(finalBlock, paddingLen - 8, bitLenLow)

  compress256(state, finalBlock[0 ..< Sha256BlockBytes])
  if paddingLen == Sha256BlockBytes * 2:
    compress256(state, finalBlock[Sha256BlockBytes ..< paddingLen])

  result = newSeq[byte](Sha256DigestBytes)
  for i in 0 ..< 8:
    store32be(result, i * 4, state[i])

proc sha512*(input: openArray[byte]): ByteSeq =
  var state = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
    0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
    0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64
  ]

  var offset = 0
  while input.len - offset >= Sha512BlockBytes:
    compress512(state, input[offset ..< offset + Sha512BlockBytes])
    offset += Sha512BlockBytes

  let remaining = input.len - offset
  let paddingLen =
    if remaining + 17 <= Sha512BlockBytes: Sha512BlockBytes
    else: Sha512BlockBytes * 2
  var finalBlock = newSeq[byte](paddingLen)
  for i in 0 ..< remaining:
    finalBlock[i] = input[offset + i]
  finalBlock[remaining] = 0x80

  let bitLenLow = uint64(input.len) * 8'u64
  store64be(finalBlock, paddingLen - 8, bitLenLow)

  compress512(state, finalBlock[0 ..< Sha512BlockBytes])
  if paddingLen == Sha512BlockBytes * 2:
    compress512(state, finalBlock[Sha512BlockBytes ..< paddingLen])

  result = newSeq[byte](Sha512DigestBytes)
  for i in 0 ..< 8:
    store64be(result, i * 8, state[i])
