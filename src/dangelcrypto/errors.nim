type
  CryptoError* = object of CatchableError
  CryptoUnavailableError* = object of CryptoError
  InvalidKeyError* = object of CryptoError
  InvalidSignatureError* = object of CryptoError
  InvalidCiphertextError* = object of CryptoError

proc unavailable*(algorithm: string): ref CryptoUnavailableError =
  newException(
    CryptoUnavailableError,
    algorithm & " backend is not connected. Wire an audited implementation before production use."
  )
