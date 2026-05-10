import std/unittest

import dangelcrypto/bytes
import dangelcrypto/internal/hmac

suite "hmac":
  test "RFC 4231 HMAC-SHA512 test case 1":
    var key = newSeq[byte](20)
    for i in 0 ..< key.len:
      key[i] = 0x0b
    let msg = @[byte 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65]
    check hmacSha512(key, msg).toHex ==
      "87aa7cdea5ef619d4ff0b4241a1d6cb0" &
      "2379f4e2ce4ec2787ad0b30545e17cde" &
      "daa833b7d6b8a702038b274eaea3f4e4" &
      "be9d914eeb61f1702e696c203a126854"
