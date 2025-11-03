# Rust ZKP Tutorial: Age Verification

이 프로젝트는 Rust와 `arkworks` 라이브러리를 사용하여 간단한 영지식 증명(ZKP) 시스템을 구현한 예제입니다. 사용자의 정확한 생년월일을 노출하지 않고 특정 연령 이상임을 증명하는 시나리오를 다룹니다.

## 주요 기능

- **Entities**: `Issuer`(발급자), `Holder`(소유자), `Verifier`(검증자).
- **영지식 증명**: `ark-groth16`을 사용하여 Groth16 증명 시스템을 구현합니다.
- **해시 함수**: `SHA256`을 사용하여 자격증명을 해시하고 데이터 무결성을 보장합니다.
- **나이 증명 회로**: 사용자가 기준 연도 이전에 태어났음을 증명하는 R1CS 회로를 구현합니다.

## 프로젝트 구조

```
/
├── Cargo.toml       # 프로젝트 의존성 및 메타데이터
├── run_test.sh      # 테스트 실행 스크립트
└── src/
    ├── main.rs      # 메인 애플리케이션 로직 및 테스트
    ├── data_structures/ # 회로, 자격증명 등 핵심 데이터 구조
    │   ├── circuit.rs
    │   └── credential.rs
    ├── entities/      # Issuer, Holder, Verifier 역할 정의
    │   ├── issuer.rs
    │   ├── holder.rs
    │   └── verifier.rs
    └── utils/         # 유틸리티 함수
        └── utils.rs
        └── solidity
```

## 워크플로우

1.  **credential 발급**:
    - `Issuer`가 `Holder`에게 이름, 생년월일 등이 포함된 `Credential`(자격증명)을 발급합니다.
    - `Issuer`는 발급한 모든 자격증명의 SHA256 해시를 계산하여 공개적으로 게시합니다. Verifier는 이를 통해 Holder가 제시한 자격증명이 `Issuer`가 발급한 것임을 검증합니다.
2.  **설정**: `Verifier`가 `setup` 함수를 호출하여 증명 생성 및 검증에 필요한 키(Proving Key, Verifying Key)를 생성합니다.
3.  **증명 생성**:
    - `Holder`는 자신의 나이를 증명하기 위해 `AgeCircuit`을 사용하여 영지식 증명을 생성합니다.
    - 이 회로는 다음 두 가지를 증명합니다.
      1.  자신이 소유한 `Credential`이 `Issuer`가 공개한 해시 목록에 포함되어 있다.
      2.  자신의 생년이 `Verifier`가 제시한 기준 연도(`CUTOFF_YEAR`)보다 이전이다.
4.  **증명 검증**:
    - `Holder`가 생성한 증명을 `Verifier`에게 제출합니다.
    - `Verifier`는 검증 키(Verifying Key)를 사용하여 증명이 유효한지 검증합니다. 이 과정에서 `Holder`의 실제 생년월일은 노출되지 않습니다.

## main 함수 실행 방법

1. solidity-verifier 폴더에서 hardhat을 실행합니다. (`solidity-verifier/README.md` 참고)
2. rust-prover 폴더에서 .env 의 변수를 설정합니다. (hardhat의 주소, private key 등)
3. deploy_verifier.js 를 이용하여 contract 를 배포합니다.
4. main 함수의 contract_address 변수에 배포된 contract 주소를 입력합니다.
5. cargo run --release -- --nocapture 명령어로 main 함수를 실행합니다.
