use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use std::str::FromStr;
use std::sync::Arc;
use crate::{
    data_structures::{circuit::AgeCircuit, credential::Credential},
    entities::{holder::Holder, issuer::Issuer, verifier::Verifier},
};
use crate::utils::solidity::ToSolidity;
use ethers::prelude::*;
use std::time::Duration;

pub mod data_structures;
pub mod entities;
pub mod utils;

type F = ark_bn254::Fr;
type Sha256Digest = Vec<u8>;
type Groth16Proof = <Groth16<Bn254> as SNARK<F>>::Proof;
type Groth16ProvingKey = <Groth16<Bn254> as SNARK<F>>::ProvingKey;
type Groth16VerifyingKey = <Groth16<Bn254> as SNARK<F>>::VerifyingKey;

const MAX_CREDENTIALS: usize = 3;
const CUTOFF_YEAR: &'static str = "2006"; // 성인 연령 기준 연도

abigen!(Groth16Verifier, "./abi.json");

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::utils::*;
    use ark_crypto_primitives::{
        crh::sha256::{
            Sha256,
            constraints::{DigestVar, Sha256Gadget},
            digest::Digest,
        },
        snark::CircuitSpecificSetupSNARK,
    };
    use ark_ff::{One, Zero};
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
    use ark_relations::r1cs::ConstraintSynthesizer;

    #[derive(Clone)]
    // SHA256 해시의 preimage를 증명하는 회로
    struct TestCircuitWitnessOnly {
        // witness
        pub expected_hash: [u8; 32],
        pub input: [u8; 32],
    }

    #[derive(Clone)]
    // SHA256 해시의 preimage를 증명하는 회로
    struct TestCircuitPublicInput {
        // public input
        pub expected_hash: [u8; 32],

        // witness
        pub input: [u8; 32],
    }

    impl ConstraintSynthesizer<F> for TestCircuitWitnessOnly {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        ) -> ark_relations::r1cs::Result<()> {
            let input_var = to_byte_vars(cs.clone(), &self.input);
            // witness로 할당
            let expected_hash_var =
                DigestVar::<F>::new_witness(cs.clone(), || Ok(self.expected_hash.to_vec()))?;

            let mut sha256_var = Sha256Gadget::default();
            sha256_var.update(&input_var)?;
            let sha256_var = sha256_var.finalize()?;

            sha256_var.enforce_equal(&expected_hash_var)?;

            Ok(())
        }
    }

    impl ConstraintSynthesizer<F> for TestCircuitPublicInput {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        ) -> ark_relations::r1cs::Result<()> {
            let input_var = to_byte_vars(cs.clone(), &self.input);
            // public input으로 할당
            let expected_hash_var =
                DigestVar::<F>::new_input(cs.clone(), || Ok(self.expected_hash.to_vec()))?;

            let mut sha256_var = Sha256Gadget::default();
            sha256_var.update(&input_var)?;
            let sha256_var = sha256_var.finalize()?;

            sha256_var.enforce_equal(&expected_hash_var)?;

            Ok(())
        }
    }

    #[test]
    // hash 값도 public input이 아닌 witness로 할당한 경우
    fn test_sha256_preimage_witness_only() {
        let input: [u8; 32] = [1u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let expected_hash = hasher.finalize();
        let circuit = TestCircuitWitnessOnly {
            input,
            expected_hash: expected_hash.to_vec().try_into().unwrap(),
        };

        // 1. constraint 생성 / 만족 여부 검사 / constraint 개수 출력
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables(), 1);
        println!("Number of constraints: {}", cs.num_constraints());

        // 2. Groth16 setup / prove / verify
        let (pk, vk) =
            Groth16::<Bn254>::setup(circuit.clone(), &mut ark_std::rand::thread_rng()).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut ark_std::rand::thread_rng())
            .unwrap();

        // 모두 witness -> public input 없음
        let result = Groth16::<Bn254>::verify(&vk, &[], &proof).unwrap();
        assert!(result);
    }

    #[test]
    // hash 값이 public input으로 할당된 경우
    // 해시값의 각 비트를 field 원소로 변환하여 public input으로 제공해야 함
    fn test_sha256_preimage_public_input() {
        let input: [u8; 32] = [1u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let expected_hash = hasher.finalize();
        let circuit = TestCircuitPublicInput {
            input,
            expected_hash: expected_hash.to_vec().try_into().unwrap(),
        };

        // 1. constraint 생성 / 만족 여부 검사 / constraint 개수 출력
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables(), 257);
        println!("Number of constraints: {}", cs.num_constraints());

        // 2. Groth16 setup / prove / verify
        let (pk, vk) =
            Groth16::<Bn254>::setup(circuit.clone(), &mut ark_std::rand::thread_rng()).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut ark_std::rand::thread_rng())
            .unwrap();

        let mut public_inputs = Vec::with_capacity(256);
        let expected_hash_bytes: &[u8] = &expected_hash.to_vec();
        for byte in expected_hash_bytes.iter() {
            for i in 0..8 {
                // Little-endian
                if (byte >> i) & 1 == 1 {
                    public_inputs.push(F::one());
                } else {
                    public_inputs.push(F::zero());
                }
            }
        }

        // public input으로 해시값 제공
        let result = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
        assert!(result);
    }

    #[test]
    fn test_did_scenario() {
        let mut issuer = Issuer::new("1");

        let mut credentials = Vec::new();
        for i in 0..MAX_CREDENTIALS {
            let cred = Credential {
                issuer_id: issuer.id.clone(),
                holder_name: format!("{}", 2005 + i as u32),
                holder_dob_year: format!("{}", 2005 + i as u32), // 2005, 2006, 2007, ...
                randomness: rand::random::<u128>().to_string(),
            };
            credentials.push(cred);
        }

        // Issuer의 credential 발급. credentials를 해시하여 publish
        for cred in &credentials {
            issuer.issue_credential(cred).unwrap();
        }

        // Issuer가 publish한 해시된 credentials
        let hashed_creds: [Sha256Digest; MAX_CREDENTIALS] = issuer
            .hashed_credentials()
            .unwrap()
            .try_into()
            .expect("Wrong length");

        let holder_2005 = Holder::new("2005", credentials[0].clone());
        let holder_2007 = Holder::new("2007", credentials[2].clone());

        // public input으로 사용
        let cutoff_year = <<Bn254 as Pairing>::ScalarField>::from_str(CUTOFF_YEAR).unwrap();

        let verifier = Verifier::new("2");
        let (proving_key, verifying_key) = verifier.setup().unwrap();

        let is_valid_2005 = {
            // holder가 2005년생인 circuit
            let age_circuit_2005 = AgeCircuit {
                dob_cutoff_year: CUTOFF_YEAR.to_string(),
                hashed_credentials: hashed_creds.clone(),
                credential: holder_2005.credentials.clone(),
            };

            // prove
            let proof_2005 = Holder::prove(proving_key.clone(), age_circuit_2005).unwrap();

            // verify
            Groth16::<Bn254>::verify(&verifying_key, &[cutoff_year], &proof_2005).unwrap()
        };

        // 2007년생인 holder는 만 18세 미만이므로 검증 실패해야 함
        let is_valid_2007 = {
            // holder가 2007년생인 circuit
            let age_circuit_2007 = AgeCircuit {
                dob_cutoff_year: CUTOFF_YEAR.to_string(),
                hashed_credentials: hashed_creds.clone(),
                credential: holder_2007.credentials.clone(),
            };

            // prove
            let proof_2007 = Holder::prove(proving_key.clone(), age_circuit_2007).unwrap();

            // verify
            Groth16::<Bn254>::verify(&verifying_key, &[cutoff_year], &proof_2007).unwrap()
        };

        // constraint 개수 출력
        {
            let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
            let circuit = AgeCircuit {
                dob_cutoff_year: CUTOFF_YEAR.to_string(),
                hashed_credentials: hashed_creds,
                credential: holder_2005.credentials.clone(),
            };
            circuit.clone().generate_constraints(cs.clone()).unwrap();
            println!("Number of constraints: {}", cs.num_constraints());
        }

        // 2005년생은 검증에 성공하고 2007년생은 실패해야 함
        assert!(is_valid_2005 && !is_valid_2007);
    }
}

async fn send_tx(
    proof: Vec<String>,
    public_inputs: Vec<String>,
    vk: Vec<String>,
    contract_address: Address,
) -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
    let private_key = std::env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

    let provider = Provider::<Http>::try_from(rpc_url)?
        .interval(Duration::from_millis(10u64));
    let chain_id = provider.get_chainid().await?;

    let wallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id.as_u64());
    let client = SignerMiddleware::new(provider, wallet.clone());
    let client = Arc::new(client);

    let contract = Groth16Verifier::new(contract_address, client.clone());

    let mut proof_uints: [U256; 8] = [U256::zero(); 8];
    for i in 0..8 {
        proof_uints[i] = U256::from_str_radix(&proof[i], 10)?;
    }

    let mut inputs: [U256; 1] = [U256::zero(); 1];
    inputs[0] = U256::from_str_radix(&public_inputs[0], 10)?;

    let vk_alpha1 = G1Point {
        x: U256::from_str_radix(&vk[0], 10)?,
        y: U256::from_str_radix(&vk[1], 10)?,
    };
    let vk_beta2 = G2Point {
        x: [U256::from_str_radix(&vk[2], 10)?, U256::from_str_radix(&vk[3], 10)?],
        y: [U256::from_str_radix(&vk[4], 10)?, U256::from_str_radix(&vk[5], 10)?],
    };
    let vk_gamma2 = G2Point {
        x: [U256::from_str_radix(&vk[6], 10)?, U256::from_str_radix(&vk[7], 10)?],
        y: [U256::from_str_radix(&vk[8], 10)?, U256::from_str_radix(&vk[9], 10)?],
    };
    let vk_delta2 = G2Point {
        x: [U256::from_str_radix(&vk[10], 10)?, U256::from_str_radix(&vk[11], 10)?],
        y: [U256::from_str_radix(&vk[12], 10)?, U256::from_str_radix(&vk[13], 10)?],
    };

    let mut vk_public_input_unconverted = vec![];
    for i in (14..vk.len()).step_by(2) {
        vk_public_input_unconverted.push([
            U256::from_str_radix(&vk[i], 10)?,
            U256::from_str_radix(&vk[i+1], 10)?,
        ]);
    }
    let vk_public_input: [G1Point; 2] = [
        G1Point {
            x: vk_public_input_unconverted[0][0],
            y: vk_public_input_unconverted[0][1],
        },
        G1Point {
            x: vk_public_input_unconverted[1][0],
            y: vk_public_input_unconverted[1][1],
        },
    ];

    let verifying_key = VerifyingKey {
        alpha_1: vk_alpha1,
        beta_2: vk_beta2,
        gamma_2: vk_gamma2,
        delta_2: vk_delta2,
        public_input: vk_public_input,
    };

    let tx = contract.verify_proof(proof_uints, inputs, verifying_key);
    let pending_tx = tx.send().await?;
    let receipt = pending_tx.await?.unwrap();

    println!("Transaction receipt: {:?}", receipt);

    let tx = contract.get_pairing_result();
    let pairing_result: bool = tx.call().await?;
    println!("Pairing result from contract: {}", pairing_result);

    Ok(())
}

#[tokio::main]
async fn main() {
    let mut issuer = Issuer::new("1");

    let mut credentials = Vec::new();
    for i in 0..MAX_CREDENTIALS {
        let cred = Credential {
            issuer_id: issuer.id.clone(),
            holder_name: format!("{}", 2005 + i as u32),
            holder_dob_year: format!("{}", 2005 + i as u32), // 2005, 2006, 2007, ...
            randomness: rand::random::<u128>().to_string(),
        };
        credentials.push(cred);
    }

    // Issuer의 credential 발급. credentials를 해시하여 publish
    for cred in &credentials {
        issuer.issue_credential(cred).unwrap();
    }

    // Issuer가 publish한 해시된 credentials
    let hashed_creds: [Sha256Digest; MAX_CREDENTIALS] = issuer
        .hashed_credentials()
        .unwrap()
        .try_into()
        .expect("Wrong length");

    let holder_2005 = Holder::new("2005", credentials[0].clone());

    // public input으로 사용
    let cutoff_year = <<Bn254 as Pairing>::ScalarField>::from_str(CUTOFF_YEAR).unwrap();

    let verifier = Verifier::new("2");
    let (proving_key, verifying_key) = verifier.setup().unwrap();

    let age_circuit_2005 = AgeCircuit {
        dob_cutoff_year: CUTOFF_YEAR.to_string(),
        hashed_credentials: hashed_creds.clone(),
        credential: holder_2005.credentials.clone(),
    };

    // 증명 생성 후 local 에서 검증
    let proof_2005 = Holder::prove(proving_key.clone(), age_circuit_2005).unwrap();
    let is_valid_2005 = Groth16::<Bn254>::verify(&verifying_key, &[cutoff_year], &proof_2005).unwrap();
    assert!(is_valid_2005);

    // for solidity verifier contract
    let vk_solidity = verifying_key.to_solidity();
    println!("Verifying Key for Solidity: {:?}", vk_solidity);

    let proof_solidity = proof_2005.to_solidity();
    println!("Proof for Solidity: {:?}", proof_solidity);

    let public_inputs_solidity: Vec<String> = vec![cutoff_year].to_solidity();
    println!("Public Inputs for Solidity: {:?}", public_inputs_solidity);

    let contract_address = "0x5FbDB2315678afecb367f032d93F642f64180aa3".parse::<Address>().unwrap();

    send_tx(proof_solidity, public_inputs_solidity, vk_solidity, contract_address).await.unwrap();

}