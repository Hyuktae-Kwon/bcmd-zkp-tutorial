use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::Namespace;

use crate::F;

/// &[u8]을 Uint8 witness vector로 변환
pub fn to_byte_vars(cs: impl Into<Namespace<F>>, data: &[u8]) -> Vec<UInt8<F>> {
    let cs = cs.into().cs();
    UInt8::new_witness_vec(cs, data).unwrap()
}

/// string을 [u8; 32]로 변환
pub fn string_to_bytes(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let s_bytes = s.as_bytes();
    let len = s_bytes.len().min(32);
    bytes[..len].copy_from_slice(&s_bytes[..len]);
    bytes
}
