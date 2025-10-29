import hre from "hardhat";

async function main() {
  console.log("--- Groth16 검증 컨트랙트 배포 시작 ---");

  // 1. 배포자 계정 가져오기
  const [deployer] = await hre.ethers.getSigners();
  console.log(`배포 계정: ${await deployer.getAddress()}`);

  // 2. 컨트랙트 팩토리 가져오기
  const Groth16VerifyBn254 = await hre.ethers.getContractFactory(
    "Groth16VerifyBn254"
  );

  // 3. 컨트랙트 배포
  const groth = await Groth16VerifyBn254.deploy();
  await groth.waitForDeployment(); // 배포가 완료될 때까지 대기

  const grothAddress = await groth.getAddress();
  console.log(`✅ Groth verification deployed to: ${grothAddress}`);

  console.log(
    `\n다음 단계: 'verify_proof.js' 스크립트에서 이 주소를 사용하여 검증을 실행합니다.`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
