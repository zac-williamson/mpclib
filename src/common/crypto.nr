/// Given an initial secret Field element, expand it into `N` uniformly randomly distributed field elements
pub(crate) fn expand_secret<let N: u32>(secret: Field) -> [Field; N] {
    let mut rolling_secret: [Field; 2] = [0, secret];
    let mut r: [Field; N] = [0; N];
    for i in 0..N {
        r[i] = std::hash::poseidon2::Poseidon2::hash(rolling_secret, 2);
        rolling_secret[1] += 1;
    }
    r
}

pub(crate) fn symmetric_encrypt<let N: u32>(plaintext: [Field; N], secret: Field) -> [Field; N] {
    let mut ciphertext: [Field; N] = [0; N];

    let secrets: [Field; N] = expand_secret(secret);
    for i in 0..N {
        ciphertext[i] = secrets[i] + plaintext[i];
    }
    ciphertext
}

pub(crate) fn symmetric_decrypt(
    ciphertext: [Field; 2],
    secret: Field,
) -> std::option::Option<Field> {
    let mut r: std::option::Option<Field> = std::option::Option::default();
    let mut decrypted_text: [Field; 2] = [0; 2];

    let secrets: [Field; 2] = expand_secret(secret);
    for i in 0..2 {
        decrypted_text[i] = ciphertext[i] - secrets[i];
    }

    let is_real = decrypted_text[0] == 0;

    if is_real {
        r = std::option::Option::some(decrypted_text[1]);
    } else {
        r = std::option::Option::none();
    }
    r
}

use std::embedded_curve_ops::EmbeddedCurvePoint as Point;

pub struct Ciphertext<let N: u32> {
    data: [Field; N * 2],
}

impl<let N: u32> std::default::Default for Ciphertext<N> {
    fn default() -> Self {
        Ciphertext { data: [0; 2 * N] }
    }
}

pub(crate) fn trial_decrypt<let N: u32>(
    possible_encryption_keys: [Point; N],
    ciphertext: Ciphertext<N>,
) -> [Option<Field>; N] {
    let mut possible_plaintext: [Option<Field>; N] = [Option::default(); N];
    for i in 0..N {
        possible_plaintext[i] = symmetric_decrypt(
            [ciphertext.data[2 * i], ciphertext.data[2 * i + 1]],
            possible_encryption_keys[i].x,
        );
    }
    possible_plaintext
}
