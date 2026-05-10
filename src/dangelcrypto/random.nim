import std/sysrand

import ./types

proc randomBytes*(size: Natural): ByteSeq =
  ## Returns operating-system random bytes.
  sysrand.urandom(size)

proc randomBytes*(dest: var openArray[byte]): bool =
  ## Fills `dest` with operating-system random bytes.
  sysrand.urandom(dest)
