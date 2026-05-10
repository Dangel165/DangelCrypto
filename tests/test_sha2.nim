import std/unittest

import dangelcrypto/bytes
import dangelcrypto/internal/sha2

suite "sha2":
  test "sha256 empty string vector":
    check sha256([]).toHex ==
      "e3b0c44298fc1c149afbf4c8996fb924" &
      "27ae41e4649b934ca495991b7852b855"

  test "sha256 abc vector":
    check sha256([byte 0x61, 0x62, 0x63]).toHex ==
      "ba7816bf8f01cfea414140de5dae2223" &
      "b00361a396177a9cb410ff61f20015ad"

  test "sha512 empty string vector":
    check sha512([]).toHex ==
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" &
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

  test "sha512 abc vector":
    check sha512([byte 0x61, 0x62, 0x63]).toHex ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
