# DangelCrypto

`DangelCrypto`는 포스트 양자 암호와 타원곡선 암호 API를 순수 Nim으로
새로 구현하기 위한 암호 라이브러리 프로젝트입니다.

제작자: Dangel

## 주의

DangelCrypto는 아직 보안 감사를 받지 않은 실험용 암호 라이브러리입니다.
Dangel 또는 Dangel에게 사전 허가를 받은 사람은 학습, 연구, 테스트, 실험
목적으로 사용할 수 있습니다.

실제 서비스, 지갑, 인증 시스템, 개인정보 보호, 금융, 상용 제품에는 사용하지
마십시오.

- Kyber KEM
- EDSA / ECDSA
- EdDSA
- KCDSA
- EC-KCDSA
- Curve25519 / X25519 style curve operations

이 프로젝트는 기존 Nimble 암호 패키지를 감싸는 래퍼가 아니라,
알고리즘을 이 저장소 안에서 직접 만들어 가는 구조입니다.

아직 완성되지 않은 암호화, 서명, 키 생성 함수는
`CryptoUnavailableError`를 발생시킵니다. 미완성 암호 기능이 안전한 것처럼
사용되는 일을 막기 위한 의도적인 설계입니다.

## 로컬 실행

```powershell
cd DangelCrypto
nimble test
```

제한된 작업 환경에서는 Nimble이 사용자 프로필 폴더에 메타데이터를 쓰려고
하면서 권한 문제가 생길 수 있습니다. 그럴 때는 테스트를 직접 실행할 수
있습니다.

```powershell
nim c -r --path:src --nimcache:build\nimcache_core tests\test_core.nim
nim c -r --path:src --nimcache:build\nimcache_kyber_math tests\test_kyber_math.nim
nim c -r --path:src --nimcache:build\nimcache_field25519 tests\test_field25519.nim
nim c -r --path:src --nimcache:build\nimcache_keccak tests\test_keccak.nim
```

## 예제

```nim
import dangelcrypto

let bytes = randomBytes(32)
echo bytes.toHex

let poly = experimentalKyberPolyFromSeed(bytes)
echo encodeKyberPoly(poly).len

let kp = generateKyberKeyPair(Kyber512)
let enc = encapsulate(kp.publicKey)
let ss = decapsulate(kp.privateKey, enc.ciphertext)
echo enc.sharedSecret.raw == ss.raw
```

## 현재 구현 상태

현재 구현된 Kyber 내부 기반:

- `modQ`, `addQ`, `subQ`, `mulQ`
- `KyberPoly`
- 다항식 덧셈과 뺄셈
- coefficient 압축과 복원
- 일반 512-byte 다항식 encode/decode
- Kyber 12-bit polynomial encoding
- Kyber 4-bit / 5-bit polynomial compression
- message polynomial 변환
- Kyber polyvec serialization
- Kyber polyvec compression
- Kyber matrix expansion
- Kyber PRF noise vector sampling
- deterministic CPA-PKE key generation foundation
- deterministic CPA-PKE encryption/decryption foundation
- CPA-PKE public key, secret key, ciphertext packing
- reference negacyclic 다항식 곱셈
- eta=2 centered binomial sampler 기반
- Montgomery reduction
- Barrett reduction
- Kyber NTT
- Kyber inverse NTT
- NTT domain base multiplication
- SHAKE128 / SHAKE256
- SHA3-256 / SHA3-512
- SHA-512
- HMAC-SHA512
- Kyber XOF uniform rejection sampler
- Kyber CCA-KEM keypair foundation
- Kyber CCA-KEM encapsulation foundation
- Kyber CCA-KEM decapsulation foundation
- public Kyber keypair / encapsulate / decapsulate API

현재 구현된 Curve25519 / Ed25519 내부 기반:

- `Fe25519`
- `zeroFe`
- `oneFe`
- field add/sub/mul/square
- field inversion
- field encode/decode
- `p = 2^255 - 19` 정규화
- X25519 Montgomery ladder
- X25519 public key generation
- X25519 shared secret API
- RFC 7748 X25519 테스트 벡터 검증
- Edwards25519 point arithmetic
- Ed25519 seed-to-public-key generation
- Ed25519 signing
- Ed25519 verification
- RFC 8032 Ed25519 public key 테스트 벡터 1, 2 검증
- RFC 8032 Ed25519 signature 테스트 벡터 1, 2, 3 검증
- Ed25519 tampered message/signature rejection

현재 구현된 ECDSA / secp256k1 내부 기반:

- secp256k1 field/scalar modular arithmetic foundation
- secp256k1 point addition
- secp256k1 scalar multiplication
- compressed public key encoding
- ECDSA secp256k1 keypair generation foundation
- explicit-nonce ECDSA signing foundation
- RFC6979 deterministic nonce foundation
- deterministic ECDSA signing helper

현재 구현된 KCDSA / EC-KCDSA 내부 기반:

- KCDSA / EC-KCDSA typed foundation
- hash/domain separation foundation
- signature component encoding
- public KCDSA / EC-KCDSA APIs are still gated pending profile-specific vectors

Kyber NTT와 polynomial encoding 구조는 CRYSTALS-Kyber 공식 reference
구현을 기준으로 작성했습니다. SHAKE는 NIST FIPS 202의 Keccak/SHAKE
구조를 기준으로 작성했습니다.

## 주의

DangelCrypto는 학습, 연구, 실험을 위한 순수 Nim 암호 라이브러리입니다.

이 프로젝트는 아직 보안 감사를 받지 않았고, side-channel 안전성 및 constant-time 동작이 전체적으로 검증되지 않았습니다. Kyber, KCDSA, EC-KCDSA 일부 기능은 아직 표준 벡터와 완전한 호환 검증이 끝나지 않았습니다.

따라서 이 라이브러리는 실제 서비스, 지갑, 인증 시스템, 개인정보 보호, 금융, 상용 제품에 사용하면 안 됩니다.
