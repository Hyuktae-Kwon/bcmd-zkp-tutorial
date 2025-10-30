use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    AffineRepr,
};

use super::ToSolidity;

impl<P: SWCurveConfig> ToSolidity for Affine<P>
where
    P::BaseField: ToSolidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.x().unwrap().to_solidity(),
            self.y().unwrap().to_solidity(),
        ]
        .concat()
    }
}

impl<P: SWCurveConfig> ToSolidity for Projective<P>
where
    P::BaseField: ToSolidity,
{
    fn to_solidity(&self) -> Vec<String> {
        [
            self.x.to_solidity(),
            self.y.to_solidity(),
            self.z.to_solidity(),
        ]
        .concat()
    }
}
