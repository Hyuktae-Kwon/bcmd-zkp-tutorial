# bcmd-zkp-tutorial

## rust-prover

Rust Arkwroks 라이브러리를 사용하여 영지식증명을 생성하는 코드

### `test` 모듈

"SHA256에 대한 preimage를 알고 있다"는 사실을 증명하는 서킷

- `main.rs`의 `TestCircuitWitnessOnly` 서킷: message, hash 모두 witness
- `main.rs`의 `TestCircuitPublicInput` 서킷: message: witness / hash: public input

### `main` 함수

#### Entities

Issuer

- credential을 발급하는 party
- Holder들의 credential을 해시하여 공개

Holder

- credential을 소유하는 party

Verifier

- Holder의 credential을 검증하려는 party
- Holder가 소유한 credential이 Issuer가 공개한 credential 리스트에 포함되어 있음을 검증

Relation

- "Issuer가 공개한 hashed credential list에 포함되어 있으면서 19세 이상인 credential `cred`가 존재한다."
