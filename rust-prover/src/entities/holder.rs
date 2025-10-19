use crate::{
    Groth16Proof, Groth16ProvingKey,
    data_structures::{circuit::AgeCircuit, credential::Credential},
    utils::utils::string_to_bytes,
};

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

pub struct Holder {
    pub id: [u8; 32],
    pub credentials: Credential,
}

impl Holder {
    pub fn new(id: &str, cred: Credential) -> Self {
        Holder {
            id: string_to_bytes(id),
            credentials: cred,
        }
    }

    pub fn prove(
        proving_key: Groth16ProvingKey,
        age_circuit: AgeCircuit,
    ) -> Result<Groth16Proof, HolderError> {
        Groth16::<Bn254>::prove(&proving_key, age_circuit, &mut ark_std::rand::thread_rng())
            .map_err(|_| HolderError::ProveFailed)
    }
}

#[derive(Debug, Clone)]
pub enum HolderError {
    ProveFailed,
}
