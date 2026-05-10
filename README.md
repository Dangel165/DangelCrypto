# DangelCrypto

`DangelCrypto`는 포스트 양자 암호와 타원곡선 암호 API를 순수 Nim으로
새로 구현하기 위한 암호 라이브러리 프로젝트입니다.

제작자: Dangel

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

## 구현 전략

구현 순서는 다음과 같습니다.

1. Kyber 수학 기반: 모듈러 연산, 다항식 연산, 압축, NTT.
2. Kyber CPA-PKE: 키 생성, 암호화, 복호화.
3. Kyber KEM: encapsulation, decapsulation, KAT 테스트 벡터.
4. Curve25519 / Ed25519: 필드 연산과 스칼라 곱셈.
5. ECDSA / EdDSA: 결정론적 nonce 규칙과 테스트 벡터.
6. KCDSA / EC-KCDSA: 곡선 백엔드가 안정된 뒤 구현.

다음 주요 작업은 Kyber CPA-PKE를 NTT-domain 고속 경로로 맞추고,
공식 KAT 벡터와 비교하는 것입니다.

Kyber NTT와 polynomial encoding 구조는 CRYSTALS-Kyber 공식 reference
구현을 기준으로 작성했습니다. SHAKE는 NIST FIPS 202의 Keccak/SHAKE
구조를 기준으로 작성했습니다.
