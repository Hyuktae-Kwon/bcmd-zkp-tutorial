use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use std::str::FromStr;

use crate::{
    data_structures::{circuit::AgeCircuit, credential::Credential},
    entities::{holder::Holder, issuer::Issuer, verifier::Verifier},
};

pub mod data_structures;
pub mod entities;
pub mod utils;

type F = ark_bn254::Fr;
type Sha256Digest = Vec<u8>;
type Groth16Proof = <Groth16<Bn254> as SNARK<ark_bn254::Fr>>::Proof;
type Groth16ProvingKey = <Groth16<Bn254> as SNARK<ark_bn254::Fr>>::ProvingKey;
type Groth16VerifyingKey = <Groth16<Bn254> as SNARK<ark_bn254::Fr>>::VerifyingKey;

const MAX_CREDENTIALS: usize = 5;
const CUTOFF_YEAR: &'static str = "2006"; // 성인 연령 기준 연도

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

    impl ConstraintSynthesizer<ark_bn254::Fr> for TestCircuitWitnessOnly {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<ark_bn254::Fr>,
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

    impl ConstraintSynthesizer<ark_bn254::Fr> for TestCircuitPublicInput {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<ark_bn254::Fr>,
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
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
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
        let cs = ark_relations::r1cs::ConstraintSystem::<ark_bn254::Fr>::new_ref();
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
}

fn main() {
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

    let is_valid_2007 = {
        // holder가 2007년생인 circuit
        let age_circuit_2007 = AgeCircuit {
            dob_cutoff_year: CUTOFF_YEAR.to_string(),
            hashed_credentials: hashed_creds,
            credential: holder_2007.credentials.clone(),
        };

        // prove
        let proof_2005 = Holder::prove(proving_key.clone(), age_circuit_2007).unwrap();

        // verify
        Groth16::<Bn254>::verify(&verifying_key, &[cutoff_year], &proof_2005).unwrap()
    };

    assert!(is_valid_2005 && !is_valid_2007);
}
