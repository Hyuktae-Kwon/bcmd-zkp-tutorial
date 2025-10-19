use crate::{
    F, MAX_CREDENTIALS, Sha256Digest, data_structures::credential::Credential, utils::utils::*,
};

use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::ConstraintSynthesizer;
use std::str::FromStr;

#[derive(Clone)]
pub struct AgeCircuit {
    // public input
    pub dob_cutoff_year: String,

    // witness
    // 간단히 하기 위해 hased_credentials를 witness로 사용
    pub hashed_credentials: [Sha256Digest; MAX_CREDENTIALS],
    pub credential: Credential,
}

impl ConstraintSynthesizer<F> for AgeCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    ) -> ark_relations::r1cs::Result<()> {
        // -------------------- public input 할당 --------------------
        // circuit 안에서 사용하는 값은 변수명에 _var 접미사를 붙임
        let dob_year_var = FpVar::new_input(cs.clone(), || {
            Ok(F::from_str(&self.dob_cutoff_year).unwrap())
        })?;

        // -------------------- witness 할당 --------------------
        let credential_hash_var_1 =
            DigestVar::<F>::new_witness(cs.clone(), || Ok(self.hashed_credentials[0].clone()))?;

        let credential_hash_var_2 =
            DigestVar::<F>::new_witness(cs.clone(), || Ok(self.hashed_credentials[1].clone()))?;

        let credential_hash_var_3 =
            DigestVar::<F>::new_witness(cs.clone(), || Ok(self.hashed_credentials[2].clone()))?;

        let holder_dob_year_var = FpVar::new_witness(cs.clone(), || {
            Ok(F::from_str(&self.credential.holder_dob_year).unwrap())
        })?;

        // -------------------- constraints --------------------
        // hash 계산
        let mut sha256_var = Sha256Gadget::default();

        sha256_var
            .update(&to_byte_vars(cs.clone(), &self.credential.issuer_id))
            .unwrap();
        sha256_var
            .update(&to_byte_vars(
                cs.clone(),
                &string_to_bytes(&self.credential.holder_name),
            ))
            .unwrap();
        sha256_var
            .update(&to_byte_vars(
                cs.clone(),
                &string_to_bytes(&self.credential.holder_dob_year),
            ))
            .unwrap();
        sha256_var
            .update(&to_byte_vars(
                cs.clone(),
                &string_to_bytes(&self.credential.randomness),
            ))
            .unwrap();

        let sha256_var = sha256_var.finalize().unwrap();

        // 1. Issuer가 발급한 credential이 맞는지 확인
        let is_eq1 = sha256_var.is_eq(&credential_hash_var_1)?;
        let is_eq2 = sha256_var.is_eq(&credential_hash_var_2)?;
        let is_eq3 = sha256_var.is_eq(&credential_hash_var_3)?;

        let is_valid_credential = Boolean::kary_or(&[is_eq1, is_eq2, is_eq3]).unwrap();
        is_valid_credential.enforce_equal(&Boolean::TRUE)?;

        // 2. 성인 여부 확인
        holder_dob_year_var.enforce_cmp(&dob_year_var, std::cmp::Ordering::Less, true)?;

        Ok(())
    }
}
