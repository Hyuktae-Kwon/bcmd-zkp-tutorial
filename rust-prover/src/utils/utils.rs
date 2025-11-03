use ark_bn254::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::{ToBytesGadget, uint8::UInt8};
use ark_relations::r1cs::Namespace;
use std::str::FromStr;

use crate::F;

/// &[u8]을 Uint8 witness vector로 변환
pub fn to_byte_vars(cs: impl Into<Namespace<F>>, data: &[u8]) -> Vec<UInt8<F>> {
    let cs = cs.into().cs();
    UInt8::new_witness_vec(cs, data).unwrap()
}

/// string을 [u8; 32]로 변환
pub fn string_to_bytes(s: &str) -> [u8; 32] {
    let f = Fr::from_str(s).unwrap();
    let f_bigint = f.into_bigint();
    let f_bytes_vec = f_bigint.to_bytes_le();
    let f_bytes_arr: [u8; 32] = f_bytes_vec
        .try_into()
        .expect("Failed to convert field element bytes to array");
    f_bytes_arr
}
