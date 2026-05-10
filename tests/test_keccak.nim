import std/unittest

import dangelcrypto/bytes
import dangelcrypto/internal/keccak

suite "keccak and shake":
  test "sha3-256 empty string vector":
    check sha3_256([]).toHex ==
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

  test "sha3-512 empty string vector":
    check sha3_512([]).toHex ==
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" &
      "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"

  test "shake128 empty string vector":
    check shake128([], 32).toHex ==
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"

  test "shake256 empty string vector":
    check shake256([], 64).toHex ==
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" &
      "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"

  test "shake output can be extended":
    let short = shake128([byte 1, 2, 3], 16)
    let long = shake128([byte 1, 2, 3], 32)
    check long[0 ..< 16] == short

  test "shake128 and shake256 differ":
    check shake128([byte 1, 2, 3], 32) != shake256([byte 1, 2, 3], 32)
