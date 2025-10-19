use ark_bn254::Bn254;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use ark_std::test_rng;
use rand::{RngCore, SeedableRng};

use crate::{
    Groth16ProvingKey, Groth16VerifyingKey,
    data_structures::{circuit::AgeCircuit, credential::Credential},
    utils::utils::string_to_bytes,
};

pub struct Verifier {
    pub id: [u8; 32],
}

impl Verifier {
    pub fn new(id: &str) -> Self {
        Verifier {
            id: string_to_bytes(id),
        }
    }
    pub fn setup(&self) -> Result<(Groth16ProvingKey, Groth16VerifyingKey), VerifierError> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let mock_circuit = AgeCircuit {
            dob_cutoff_year: "0".to_string(),
            hashed_credentials: vec![vec![0u8; 32]; crate::MAX_CREDENTIALS]
                .try_into()
                .expect("Wrong length"),
            credential: Credential::new(
                [0u8; 32],
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
            ),
        };

        let (pk, vk) = Groth16::<Bn254>::setup(mock_circuit, &mut rng)
            .map_err(|_| VerifierError::SetupFailed)?;
        Ok((pk, vk))
    }
}

#[derive(Debug, Clone)]
pub enum VerifierError {
    SetupFailed,
}
