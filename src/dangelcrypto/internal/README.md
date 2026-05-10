# Internal Implementation Notes

This folder is for pure Nim implementations written in this project.

Current status:

- `kyber_math.nim`: Kyber ring arithmetic foundation over `Z_q`, q = 3329.
- `field25519.nim`: Curve25519 / Ed25519 field arithmetic foundation over
  `2^255 - 19`.

Rules for this folder:

- Keep code deterministic and covered by tests.
- Add official test vectors before exposing a primitive as production API.
- Avoid wiring placeholder cryptography into public encrypt/sign functions.
