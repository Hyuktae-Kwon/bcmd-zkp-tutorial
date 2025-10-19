use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{R1CSVar, uint8::UInt8};
use ark_relations::r1cs::Namespace;

/// &[u8]을 Uint8 witness vector로 변환
pub fn to_byte_vars(
    cs: impl Into<Namespace<ark_bn254::Fr>>,
    data: &[u8],
) -> Vec<UInt8<ark_bn254::Fr>> {
    let cs = cs.into().cs();
    UInt8::new_witness_vec(cs, data).unwrap()
}

/// SHA256 Gadget의 최종 해시 값을 Vec<u8>로 변환
pub fn finalize_var(sha256_var: Sha256Gadget<ark_bn254::Fr>) -> Vec<u8> {
    let tmp = sha256_var.finalize().unwrap();
    let tmp = tmp.value();
    tmp.unwrap().to_vec()
}

/// string을 [u8; 32]로 변환
pub fn string_to_bytes(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let s_bytes = s.as_bytes();
    let len = s_bytes.len().min(32);
    bytes[..len].copy_from_slice(&s_bytes[..len]);
    bytes
}
