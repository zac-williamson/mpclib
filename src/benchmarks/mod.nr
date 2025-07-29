use crate::common::crypto::{Ciphertext, expand_secret, trial_decrypt};
use crate::selective_disclosure::selective_disclosure::{
    commit, commit_mask, execute_round, H, reveal_mask, RoundState, update_mask, UserOutputState,
};
use bignum::{BN254_Fq};
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

use std::embedded_curve_ops::EmbeddedCurvePoint as Point;

// 10 = 11206
// 11 = 12048
// 842 ouch what

// fixed base
// 10 = 9317
// 11 = 9970
// 653 strange its smaller

// using G
// 10 = 4161
// 11 = 4301
// 140 gates hmm is expected

// ok so where are the costs coming in?

// when computing the mask, that's not native because of the conditional assign
// updating the mask is...not

// alice commits x.[G] + [B]

// am I losing my marbles here?

// m.[G] + [H]
// xm.[G] + x.[H]

#[export]
fn execute_round_bench(
    user_plaintext: [Field; 64],
    reveal_vector: [Field; 64],
    encrypt_secret: Field,
    masking_secret: Field,
    previous_round_state: RoundState<64, 2>,
    previous_round_hash: Field,
) -> (UserOutputState<64, 2>, [[Option<Field>; 64]; 2 - 1]) {
    execute_round(
        user_plaintext,
        reveal_vector,
        encrypt_secret,
        masking_secret,
        previous_round_state,
        previous_round_hash,
        1,
    )
}
// 64 = 18,442
// 65 = 18,687
// delta = 245 which is not ideal
// 105 gates for all the extra stuff which is a bit rubbish
#[export]
fn test_mask(reveal_vector: [Field; 65], alice_masking_secret: Field) -> [Point; 65] {
    commit_mask(reveal_vector, alice_masking_secret)
}

global K: u32 = 11;
#[export]
fn curve_mul(points: [Point; K], scalars: [Field; K]) -> [Point; K] {
    let mut r: [Point; K] = [Point::point_at_infinity(); K];

    for i in 0..K {
        r[i] = multi_scalar_mul([points[i]], [EmbeddedCurveScalar::from_field(scalars[i])]);
    }
    r
}

// when I move I create a new mask vector and send to Bob
// I also update Bob's mask vector and use to see his state
#[export]
fn round_1_commit(
    board_state: [Field; 64],
    bob_masking_update: [Point; 64],
    alice_reveal_vector: [Field; 64],
    bobs_masking_commitments_that_he_wants_updated_and_returned: [Point; 64],
    alice_masking_secret: Field,
    alice_encrypt_secret: Field,
    board_update_index: Field,
    board_update_value: Field,
    bob_ciphertext: Ciphertext<64>,
) -> ([Point; 64], [Point; 64], Ciphertext<64>) {
    let mut mask_commits_to_bob: [Point; 64] = [Point::point_at_infinity(); 64];

    mask_commits_to_bob = commit_mask(alice_reveal_vector, alice_masking_secret);

    // let mut masking_secrets: [Field; 64] = expand_secret(alice_masking_secret);
    //   println(f"final masking secrets {inverse_masking_secrets}");
    // let mut inverse_masking_secrets: [BN254_Fq; 64] = [BN254_Fq::new(); 64];

    // // oh arse we need to invert in the bn254 field
    // for i in 0..64 {
    //     let secret_bn = BN254_Fq::from(masking_secrets[i]);
    //     let inverse = BN254_Fq::one() / secret_bn;
    //     inverse_masking_secrets[i] = inverse;
    // }

    // println(f"{inverse_masking_secrets}");

    // let mut possible_encryption_keys: [Point; 64] = [Point::point_at_infinity(); 64];
    // for i in 0..64 {
    //     let bit_limbs = inverse_masking_secrets[i].limbs;
    //     println(f"{bit_limbs}");
    //     // 120, 120, 120
    //     let low_120: Field = bit_limbs[0] as Field;
    //     println(f"{low_120}");
    //     let mid_120 = bit_limbs[1] as Field;
    //     let mid_bytes = (mid_120 as Field).to_be_bytes::<15>();
    //     println(f"{mid_bytes}");
    //     let low_128 = low_120 + (mid_bytes[0] as Field) * 0x1000000000000000000000000000000;

    //     let remainder_mid_112 = (mid_120 - (mid_bytes[0] as Field)) / 0x100;

    //     let high_16 = bit_limbs[2] as Field;

    //     let high_128 = remainder_mid_112 + high_16 * 0x10000000000000000000000000000;
    //     println(f"{low_128} {high_128}");
    //     possible_encryption_keys[i] = multi_scalar_mul(
    //         [bob_masking_update[i]],
    //         [EmbeddedCurveScalar::new(low_128, high_128)],
    //     );
    // }
    // println(f"{possible_encryption_keys}");

    // without reveal and trial decrypt it's 41,236 gates
    // 128,148 after reveal_mask
    // 80k?

    // with only the inverse BN stuff it's 49,522 so that's ok

    // with the bit limb stuff it becomes 76,098
    // which is 26k or 400 gates wtf

    // ok after changing byte len from 32 bytes to 15 bytes (wat) it becomes 51,042 gates. 500 gates so about 10 per . ok.

    // but the scalar mul move to 103,092 gates

    // about 52,000 gates or 812.5 what the fuck

    // xs + b

    // g.(xs + b) - b = g.xs
    // [A].xs + [B].s
    let partial_decrypt_keys = reveal_mask(bob_masking_update, alice_masking_secret);
    println(f"{partial_decrypt_keys}");

    // moving from decryption to plaintext = 113,332 gates or about 10k.
    // odd
    // ok for each iteration we expand the secret = 2 hashes ~200 gates
    // 200 * 60 = 12k
    // so we could save about 5k from only using 1 hash
    // and the initial encryption would save about 5k
    // so this becomes 103,332 gates
    // still ick
    //
    // have we done everything?
    // Alice gives Bob ciphertext for turn i
    // Alice gives Bob her masking vector for turn i
    // Alice has Bob's original masking vector for turn i-1 that she need to update?

    // updated = 165,300 ouch this sucks!

    // generate Alice's mask = 64 fixed
    // update Bob's mask = 64 variable
    // reveal Bob's previous mask = 64 variable
    // generate ciphertext = 64 fixed
    // about 128k
    // then we have unneccessary 64 poseidon2 ~5k (2 expand secrets)
    // and an extra 5k for expand alice secret
    // and an extra 5k for expand alice mask
    // and 20k for ciphertext secrets
    // about 35k
    // for ~160k so close enough
    // ok let's stop worrying about this 250k is smol, we can keep going with building the library.

    // How to make a decent interface?

    // 1: "execute turn" . We have:
    // Alice plaintext state
    // Alice reveal vector
    // Bob ciphertext state
    // Alice encrypt secret
    // Alice mask secret
    // Bob's mask to update
    // Alice's updated mask

    // output is:
    // Bob partial ciphertext state
    // Alice mask commits
    // Bob's updated mask
    // Alice ciphertext state

    // Perhaps we could generalize to:
    // Execute turn for *Player i*
    // We need to generate mask updates for all other players
    // We need to generate our own mask
    // We need to generate our own ciphertext
    // We need to receive all other player's updated masks and trial decrypt

    // so... input = plaintext, reveal vector and some kind of mpc state struct

    // We have MPCPlayerInputState and MPCPlayerOutputState
    // and a fn that takes in N MPCPlayerOutputState to form N MPCPlayerInputState
    // ^^ let's do this!

    // probably about 160K + 100K * (N-2) . so 6 players 560k. painful but not impossible
    let updated_mask_for_bob = update_mask(
        bobs_masking_commitments_that_he_wants_updated_and_returned,
        alice_encrypt_secret,
    );
    let partial_plaintext = trial_decrypt(partial_decrypt_keys, bob_ciphertext);

    for i in 0..64 {
        let mut result = partial_plaintext[i].unwrap_or(0);
        assert_eq(result, 1234);
    }
    let mut new_board_state = board_state;
    // TODO: conversion to u32 is expensive. fix interface
    new_board_state[board_update_index as u32] = board_update_value;
    let alice_ciphertext = commit(board_state, alice_encrypt_secret);
    (mask_commits_to_bob, updated_mask_for_bob, alice_ciphertext)
}
