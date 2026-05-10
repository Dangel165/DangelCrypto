import dangelcrypto

let entropy = randomBytes(32)
echo "random: ", entropy.toHex
echo "kyber768 public key bytes: ", publicKeySize(Kyber768)
echo "kyber q: ", KyberQ

let poly = experimentalKyberPolyFromSeed(entropy)
echo "experimental polynomial bytes: ", encodeKyberPoly(poly).len

try:
  discard generateKyberKeyPair(Kyber768)
except CryptoUnavailableError as err:
  echo err.msg
