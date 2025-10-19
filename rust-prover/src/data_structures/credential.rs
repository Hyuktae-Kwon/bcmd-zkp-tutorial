use ark_crypto_primitives::crh::sha256::{Sha256, digest::Digest};

use crate::{Sha256Digest, utils::utils::string_to_bytes};

#[derive(Clone)]
pub struct Credential {
    pub issuer_id: [u8; 32],
    pub holder_name: String,
    pub holder_dob_year: String,
    pub randomness: String,
}

impl Credential {
    pub fn new(
        issuer_id: [u8; 32],
        holder_name: String,
        holder_dob_year: String,
        randomness: String,
    ) -> Self {
        Credential {
            issuer_id,
            holder_name,
            holder_dob_year,
            randomness,
        }
    }

    // Credential의 SHA256 해시 계산
    pub fn to_sha256(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(&self.issuer_id);
        hasher.update(&string_to_bytes(&self.holder_name));
        hasher.update(&string_to_bytes(&self.holder_dob_year));
        hasher.update(&string_to_bytes(&self.randomness));
        hasher.finalize().to_vec()
    }
}
