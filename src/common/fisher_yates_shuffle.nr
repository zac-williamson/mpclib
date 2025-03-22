use crate::common::random::convert_scalar_into_random_u16s;

/// Execute the Fisher Yates shuffle algorithm, to compute a uniformly randomly distributed permutation of the list of integers [0,..,N]
/// See https://en.wikipedia.org/wiki/Fisher-Yates_shuffle for more information
/// # Algorithm summary:
/// We start with N uniformly randomly distributed values `random_indices`, where `0 <= random_indices[i] <= i`
/// NOTE this algorithm DOES NOT validate the input `random_indices` are well-formed - we assume this already has been done
/// We then take an array `indices` where `indices[i] = i`
/// Next: `for i from n-1 down to 1 do`
///         swap indices[i] and indices[random_indices[i]]
pub(crate) fn fisher_yates_shuffle<let N: u32>(random_indices: [u16; N]) -> [Field; N] {
    let mut indices: [Field; N] = [0; N];
    for i in 0..N {
        indices[i] = i as Field;
    }
    for i in 0..N - 1 {
        let idx = N - 1 - i;
        let temp = indices[idx];
        indices[idx] = indices[random_indices[idx]];
        indices[random_indices[idx]] = temp;
    }
    indices
}

/// Equivalent to `fisher_yates_shuffle`, except instead of starting with uniformly random indices,
/// we start with a random Field element that is expanded into the required randomly distributed indices
pub(crate) fn fisher_yates_shuffle_from_secret<let N: u32>(secret: Field) -> [Field; N] {
    let x = convert_scalar_into_random_u16s::<N>(secret);
    fisher_yates_shuffle::<N>(x)
}

#[test]
fn test_fisher_yates_shuffle() {
    let permutation_bits: [u16; 8] = [0, 0, 2, 2, 0, 5, 1, 5];
    let r = fisher_yates_shuffle(permutation_bits);
    assert_eq(r, [6, 4, 3, 2, 0, 7, 1, 5]);
}
