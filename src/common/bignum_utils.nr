use bignum::BN254_Fq;
use std::embedded_curve_ops::EmbeddedCurveScalar;

/// Convert a BN254_Fq element (from bignum library) into an EmbeddedCurveScalar (used as input into multiscalar muls)
pub(crate) fn convert_bn254_to_embedded_scalar(bignum: BN254_Fq) -> EmbeddedCurveScalar {
    let bit_limbs = bignum.limbs;
    let low_120 = bit_limbs[0] as Field;
    let mid_120 = bit_limbs[1] as Field;
    let mid_bytes = (mid_120 as Field).to_le_bytes::<15>();
    let low_128 = low_120 + (mid_bytes[0] as Field) * 0x1000000000000000000000000000000;

    let remainder_mid_112 = (mid_120 - (mid_bytes[0] as Field)) / 0x100;

    let high_16 = bit_limbs[2] as Field;

    let high_128 = remainder_mid_112 + high_16 * 0x10000000000000000000000000000;

    EmbeddedCurveScalar::new(low_128, high_128)
}
