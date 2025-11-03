# bcmd-zkp-tutorial

## rust-prover

Rust Arkwroks 라이브러리를 사용하여 영지식증명을 생성하는 코드 (`rust-prover/README.md` 참고)

### Circuits

SHA256 Preimage Circuit

- 증명하고자 하는 것 (relation)

  - "SHA256에 대한 preimage를 알고 있다"

- `main.rs`의 `TestCircuitWitnessOnly` 서킷
  - public input: 없음
  - witness: message, hash
- `main.rs`의 `TestCircuitPublicInput` 서킷
  - public input: hash
  - witness: message

DID circuit

- 증명하고자 하는 것 (relation)
  - Issuer가 publish한 hashed credential list의 원소 중 credential의 preimage(비밀 r값 포함)를 알고 있다.
  - 해당 credential의 생년은 성인 기준 년도 이하이다.
- `circuit.rs`의 `AgeCircuit` 서킷
  - public input: 성인 기준 년도 및 hashed credential list
  - witness: Holder의 credential

### `main` 함수

- Arkworks에서 만든 Groth16 proof를 Hardhat 테스트 네트워크에서 검증

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

## solidity-verifier

solidity 를 사용하여 스트컨트랙트에서 영지식증명을 검증하는 코드 (`solidity-veirifer/README.md` 참고)

### `Pairing.sol`

`Groth16` 에서 사용하는 `pairing` 과 관련된 solidity 코드.

### `Groth16VerifyBn254.sol`

`solidity` 에서 Groth16 을 검증하는 코드.
