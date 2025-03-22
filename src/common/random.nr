use crate::common::crypto::expand_secret;

/// Given a uniformly randomly distribted field element `input_randomness`, return a set of uniformly randomly distributed indices `r`
/// such that `r[i]` is uniformly randomly distributed such that `0 <= r[i] <= i`
/// Note: we use this algorithm to compute inputs into the Fisher-Yates shuffle algorithm
pub(crate) fn convert_scalar_into_random_u16s<let N: u32>(input_randomness: Field) -> [u16; N] {
    let mut r: [u16; N] = [0; N];
    // note: std::field::modulus_num_bits() is not known at compile time so I am uncertain how to implement this algo generically
    assert(
        std::field::modulus_num_bits() > 240,
        "library does not currently work for fields smaller than 250 bits",
    );

    // To compute randomly distributed indices in the range `[0,..,k] ,
    // we generate a uniformly randomly distributed integer in the range [0,..,65535] and reduce the result modulo k+1
    // Note: the maximum array the MPC library can shuffle is of size 512. Reducing a random intger in the range [0,..,65535] modulo an integer k close to 512
    // will not produce a *perfectly* uniformly randomly distributed integer in the range [0,..,k], but the error should not be statistically significant
    // TODO: prove this! (logic is similar to how ZCash generates random ~256-bit field elements by reducing a 512-bit integer modulo the field modulus)

    // We need 2 bytes (16 bits) of entropy per element,and we can extract 30 bytes of randomness from a uniformly randomly distributed field element (for a ~256 bit field element)
    // (note: prove this?!)
    // Therefore the number of field elements we need = N / 15
    let num_full_limbs = (N) / 15;
    // sanity check num_full_limbs is constant as we're using it to define iteration bounds
    assert_constant(num_full_limbs);
    // Expand our secret into the required number of field elements of entropy
    let entropy: [Field; (15 + N) / 15] = expand_secret(input_randomness);
    for i in 0..num_full_limbs {
        // NOTE: I don't know how to make to_be_bytes field agnostic. I need the length parameter `32` to equal the smallest number of bytes that fits into a std::field
        let bits: [u8; 32] = entropy[i].to_be_bytes();
        for j in 0..15 {
            let digit: u16 = bits[j * 2 + 1] as u16 + (bits[j * 2]) as u16 * 0x100;
            let modulus = (i * 15 + j + 1) as u16;
            // sanity check - this costs way too many constraints if modulus is not constant!
            assert_constant(modulus);
            let value = digit % modulus;
            r[i * 15 + j] = value;
        }
    }
    let num_remaining_bits = (N - (num_full_limbs * 15));
    assert_constant(num_remaining_bits);
    let last_entropy = entropy[N / 15];
    let last_bits: [u8; 32] = last_entropy.to_be_bytes();
    // let ff: [u8; 8] = entropy[num_full_limbs].to_be_bytes::<8>();
    for j in 0..num_remaining_bits {
        let digit: u16 = last_bits[j * 2 + 1] as u16 + (last_bits[j * 2]) as u16 * 0x100;
        let value = digit % (num_full_limbs * 15 + j + 1) as u16;
        r[num_full_limbs * 15 + j] = value;
    }
    r
}
