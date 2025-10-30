use ark_ec::pairing::Pairing;
use ark_ff::{Fp, Fp2, Fp2Config, FpConfig, Zero};
use ark_groth16::{Proof, VerifyingKey};
use std::fmt::Display;

pub mod sw;
pub mod te;

pub trait ToSolidity {
    fn to_solidity(&self) -> Vec<String>;
}

fn to_solidity<T: Display + Zero>(x: T) -> String {
    if x.is_zero() {
        "0".to_string()
    } else {
        x.to_string()
    }
}

impl<P: FpConfig<N>, const N: usize> ToSolidity for Fp<P, N> {
    fn to_solidity(&self) -> Vec<String> {
        vec![to_solidity(*self)]
    }
}

impl<P: Fp2Config> ToSolidity for Fp2<P> {
    fn to_solidity(&self) -> Vec<String> {
        vec![to_solidity(self.c1), to_solidity(self.c0)]
    }
}

impl<T: ToSolidity> ToSolidity for Vec<T> {
    fn to_solidity(&self) -> Vec<String> {
        self.iter().map(|x| x.to_solidity()).flatten().collect()
    }
}

impl<E: Pairing> ToSolidity for Proof<E>
where
    E::G1Affine: ToSolidity,
    E::G2Affine: ToSolidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.a.to_solidity(),
            self.b.to_solidity(),
            self.c.to_solidity(),
        ]
        .concat()
    }
}

impl<E: Pairing> ToSolidity for VerifyingKey<E>
where
    E::G1Affine: ToSolidity,
    E::G2Affine: ToSolidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.alpha_g1.to_solidity(),
            self.beta_g2.to_solidity(),
            self.gamma_g2.to_solidity(),
            self.delta_g2.to_solidity(),
            self.gamma_abc_g1.to_solidity(),
        ]
        .concat()
    }
}

impl<F: ToSolidity, const N: usize> ToSolidity for [F; N] {
    fn to_solidity(&self) -> Vec<String> {
        self.iter()
            .flat_map(|element| element.to_solidity())
            .collect()
    }
}
