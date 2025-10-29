# ZKP Verification Tutorial

solidity 를 사용하여 rust-prover 에서 생성한 영지식증명을 스트컨트랙트에서 검증합니다.

## Verifier.sol

`rust-prover`에서 생성된 증명을 검증하는 스마트 컨트랙트입니다.

`ark-groth16` 라이브러리에서 제공하는 `Verifier.sol` 컨트랙트를 상속하여, `Groth16` 증명을 검증하는 로직을 구현합니다.

## 🛠️ 사용 방법

### 사전 요구 사항

- VSCode 에 [solidity](https://marketplace.visualstudio.com/items?itemName=JuanBlanco.solidity) 익스텐션을 설치합니다.
- npm, nodejs 가 필요합니다(hardhat 을 위해).

### 실행 코드

```
npm i
npx hardhat node
npx hardhat run scripts/deploy_verifier.js --network localhost
npx hardhat run scripts/verify_proof.js --network localhost
```

만약 hardhat node 를 실행하는 데에 오류가 발생한다면, 다음의 코드를 실행합니다.

```
brew install nvm
nvm install 22.10.0
nvm use 22.10.0
```
