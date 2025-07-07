use std::embedded_curve_ops::{
    embedded_curve_add_unsafe, EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul,
};
use std::hash::poseidon2::Poseidon2::hash as poseidon2;

use crate::common::crypto::{Ciphertext, expand_secret, symmetric_encrypt, trial_decrypt};

use bignum::{BigNumTrait, BN254_Fq};

type Point = EmbeddedCurvePoint;

pub global G: Point = Point {
    x: 0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a,
    y: 0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d,
    is_infinite: false,
};

global H: Point = Point {
    x: 0x054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402,
    y: 0x209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126,
    is_infinite: false,
};

pub struct RoundState<let NumEntries: u32, let NumParticipants: u32> {
    pub round_number: u32,
    pub user_encrypt_secret_hashes: [Field; NumParticipants],
    pub user_mask_secret_hashes: [Field; NumParticipants],
    pub previous_output_states: [UserOutputState<NumEntries, NumParticipants>; NumParticipants],
}

pub struct UserOutputState<let NumEntries: u32, let NumParticipants: u32> {
    ciphertext: Ciphertext<NumEntries>,
    mask_commitments: [Point; NumEntries],
    user_updated_mask_commitments: [[Point; NumEntries]; NumParticipants],
}

impl<let NumEntries: u32, let NumParticipants: u32> std::default::Default for UserOutputState<NumEntries, NumParticipants> {
    fn default() -> Self {
        UserOutputState {
            ciphertext: Ciphertext::default(),
            mask_commitments: [Point::point_at_infinity(); NumEntries],
            user_updated_mask_commitments: [
                [Point::point_at_infinity(); NumEntries]; NumParticipants
            ],
        }
    }
}

impl<let NumEntries: u32, let NumParticipants: u32> UserOutputState<NumEntries, NumParticipants> {

    pub fn flatten(self: Self) -> [Field; NumEntries * (NumParticipants + 2) * 2] {
        let mut flattened_data: [Field; NumEntries * (NumParticipants + 2) * 2] =
            [0; NumEntries * (NumParticipants + 2) * 2];

        for i in 0..NumEntries {
            flattened_data[i * 2] = self.ciphertext.data[2 * i];
            flattened_data[i * 2 + 1] = self.ciphertext.data[2 * i + 1];

            flattened_data[NumEntries * 2 + i * 2] = self.mask_commitments[i].x;
            flattened_data[NumEntries * 2 + i * 2 + 1] = self.mask_commitments[i].y;
        }

        let offset: u32 = NumEntries * 4;
        for i in 0..NumParticipants {
            for j in 0..NumEntries {
                flattened_data[offset + (i * NumEntries * 2) + j * 2] =
                    self.user_updated_mask_commitments[i][j].x;
                flattened_data[offset + (i * NumEntries * 2) + j * 2 + 1] =
                    self.user_updated_mask_commitments[i][j].y;
                // TODO I think its ok to not include point at infinity here in the hash?
            }
        }
        flattened_data
    }
    pub fn hash(self: Self) -> Field {
        std::hash::poseidon2::Poseidon2::hash(
            self.flatten(),
            NumEntries * (NumParticipants + 2) * 2,
        )
    }
}

pub fn commit<let N: u32>(plaintext: [Field; N], secret: Field) -> Ciphertext<N> {
    let secrets: [Field; N] = expand_secret(secret);

    let mut encryption_keys: [Point; N] = [Point::point_at_infinity(); N];
    let mut ciphertext: Ciphertext<N> = Ciphertext::default();
    for i in 0..N {
        encryption_keys[i] = multi_scalar_mul([G], [EmbeddedCurveScalar::from_field(secrets[i])]);
        let encrypted = symmetric_encrypt([0, plaintext[i]], encryption_keys[i].x);
        ciphertext.data[2 * i] = encrypted[0];
        ciphertext.data[2 * i + 1] = encrypted[1];
    }
    ciphertext
}

pub fn commit_mask<let N: u32>(reveal_vector: [Field; N], masking_secret: Field) -> [Point; N] {
    // if reveal_vector[i] = true, use G1, else use G2
    let secrets: [Field; N] = expand_secret(masking_secret);
    // let mut base_points: [Point; N] = [Point::point_at_infinity(); N];
    // for i in 0..N {
    //     base_points[i] = G.conditional_assign(H, reveal_vector[i]);
    // }
    let mut masking_keys: [Point; N] = [Point::point_at_infinity(); N];

    // embedded_curve_add_unsafe
    for i in 0..N {
        masking_keys[i] = multi_scalar_mul([G], [EmbeddedCurveScalar::from_field(secrets[i])]);

        // we can use an unsafe add op here because masking_keys[i] is a function of [G], and colliding with [H] would require solving the dlog problem
        let alternative_masking_key = embedded_curve_add_unsafe(masking_keys[i], H);

        masking_keys[i].x = (masking_keys[i].x - alternative_masking_key.x) * reveal_vector[i]
            + alternative_masking_key.x;
        masking_keys[i].y = (masking_keys[i].y - alternative_masking_key.y) * reveal_vector[i]
            + alternative_masking_key.y;
    }

    masking_keys
}

pub fn update_mask<let N: u32>(masking_keys: [Point; N], encrypt_secret: Field) -> [Point; N] {
    let secrets: [Field; N] = expand_secret(encrypt_secret);
    let mut updated_masking_keys: [Point; N] = [Point::point_at_infinity(); N];
    for i in 0..N {
        updated_masking_keys[i] = multi_scalar_mul(
            [masking_keys[i]],
            [EmbeddedCurveScalar::from_field(secrets[i])],
        );
    }
    updated_masking_keys
}

pub fn reveal_mask<let N: u32>(
    updated_masking_keys: [Point; N],
    masking_secret: Field,
) -> [Point; N] {
    let mut masking_secrets: [Field; N] = expand_secret(masking_secret);
    //   println(f"final masking secrets {inverse_masking_secrets}");
    let mut inverse_masking_secrets: [BN254_Fq; N] = [BN254_Fq::new(); N];

    // oh arse we need to invert in the bn254 field
    for i in 0..N {
        let secret_bn = BN254_Fq::from(masking_secrets[i]);
        let inverse = BN254_Fq::one() / secret_bn;
        inverse_masking_secrets[i] = inverse;
    }

    let mut possible_encryption_keys: [Point; N] = [Point::point_at_infinity(); N];
    for i in 0..N {
        let bit_limbs = inverse_masking_secrets[i].limbs;
        // 120, 120, 120
        let low_120 = bit_limbs[0] as Field;
        let mid_120 = bit_limbs[1] as Field;
        let mid_bytes = (mid_120 as Field).to_le_bytes::<15>();
        let low_128 = low_120 + (mid_bytes[0] as Field) * 0x1000000000000000000000000000000;

        let remainder_mid_112 = (mid_120 - (mid_bytes[0] as Field)) / 0x100;

        let high_16 = bit_limbs[2] as Field;

        let high_128 = remainder_mid_112 + high_16 * 0x10000000000000000000000000000;
        possible_encryption_keys[i] = multi_scalar_mul(
            [updated_masking_keys[i]],
            [EmbeddedCurveScalar::new(low_128, high_128)],
        );
    }
    possible_encryption_keys
}


/// Alternative to `create_round_commitments` to bypass aztec-nargo compiler errors
pub fn create_round_commitments_const<let NumEntries: u32, let NumParticipants: u32, let UserIndex: u32>(
    user_plaintext: [Field; NumEntries],
    reveal_vector: [Field; NumEntries],
    encrypt_secret: Field,
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
) -> UserOutputState<NumEntries, NumParticipants> {
    let mut r: UserOutputState<NumEntries, NumParticipants> = UserOutputState::default();
    for i in 0..NumParticipants {
        if (i != UserIndex) {
            r.user_updated_mask_commitments[i] = update_mask(
                round_state.previous_output_states[i].mask_commitments,
                encrypt_secret,
            );
        }
    }
    r.ciphertext = commit(user_plaintext, encrypt_secret);
    r.mask_commitments = commit_mask(reveal_vector, masking_secret);
    r
}


pub fn create_round_commitments<let NumEntries: u32, let NumParticipants: u32>(
    user_plaintext: [Field; NumEntries],
    reveal_vector: [Field; NumEntries],
    encrypt_secret: Field,
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
    user_index: u32,
) -> UserOutputState<NumEntries, NumParticipants> {
    let mut r: UserOutputState<NumEntries, NumParticipants> = UserOutputState::default();
    for i in 0..NumParticipants {
        if (i != user_index) {
            r.user_updated_mask_commitments[i] = update_mask(
                round_state.previous_output_states[i].mask_commitments,
                encrypt_secret,
            );
        }
    }
    r.ciphertext = commit(user_plaintext, encrypt_secret);
    r.mask_commitments = commit_mask(reveal_vector, masking_secret);
    r
}

/// Alternative to `consume_round_commitments` to bypass aztec-nargo compiler errors
pub fn consume_round_commitments_const<let NumEntries: u32, let NumParticipants: u32, let UserIndex: u32>(
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
) -> [[Option<Field>; NumEntries]; NumParticipants - 1] {
    let mut count: Field = 0;

    let mut target_plaintexts: [[Option<Field>; NumEntries]; NumParticipants - 1] =
        [[Option::default(); NumEntries]; NumParticipants - 1];
    for i in 0..NumParticipants {
        if (i != UserIndex) {
            let decryption_keys = reveal_mask(
                round_state.previous_output_states[i].user_updated_mask_commitments[UserIndex],
                masking_secret,
            );
            let plaintexts = trial_decrypt(
                decryption_keys,
                round_state.previous_output_states[i].ciphertext,
            );
            target_plaintexts[count] = plaintexts;
            count += 1;
        }
    }
    target_plaintexts
}


pub fn consume_round_commitments<let NumEntries: u32, let NumParticipants: u32>(
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
    user_index: u32,
) -> [[Option<Field>; NumEntries]; NumParticipants - 1] {
    let mut count: Field = 0;

    let mut target_plaintexts: [[Option<Field>; NumEntries]; NumParticipants - 1] =
        [[Option::default(); NumEntries]; NumParticipants - 1];
    for i in 0..NumParticipants {
        if (i != user_index) {
            let decryption_keys = reveal_mask(
                round_state.previous_output_states[i].user_updated_mask_commitments[user_index],
                masking_secret,
            );
            let plaintexts = trial_decrypt(
                decryption_keys,
                round_state.previous_output_states[i].ciphertext,
            );
            target_plaintexts[count] = plaintexts;
            count += 1;
        }
    }
    target_plaintexts
}

impl<let NumEntries: u32, let NumParticipants: u32> std::default::Default for RoundState<NumEntries, NumParticipants> {
    fn default() -> Self {
        RoundState {
            round_number: 0,
            user_encrypt_secret_hashes: [0; NumParticipants],
            user_mask_secret_hashes: [0; NumParticipants],
            previous_output_states: [UserOutputState::default(); NumParticipants],
        }
    }
}
impl<let NumEntries: u32, let NumParticipants: u32> RoundState<NumEntries, NumParticipants> {

    pub fn hash(self) -> Field {
        let mut flattened_data: [Field; NumParticipants * 3 + 1] = [0; NumParticipants * 3 + 1];

        for i in 0..NumParticipants {
            flattened_data[3 * i] = self.user_encrypt_secret_hashes[i];
            flattened_data[3 * i + 1] = self.user_mask_secret_hashes[i];
            flattened_data[3 * i + 2] = self.previous_output_states[i].hash();
        }
        flattened_data[NumParticipants * 3] = self.round_number as Field - 1;

        std::hash::poseidon2::Poseidon2::hash(flattened_data, NumParticipants * 3 + 1)
    }

    pub fn update2(
        self,
        new_output_state: UserOutputState<NumEntries, NumParticipants>,
        user_index: u32,
    ) -> Self {
        let mut updated = self;

        updated.round_number += 1;
        updated.previous_output_states[user_index] = new_output_state;
        updated
    }
    pub fn update(
        self,
        new_output_states: [UserOutputState<NumEntries, NumParticipants>; NumParticipants],
    ) -> Self {
        let mut updated = self;

        updated.round_number += 1;
        updated.previous_output_states = new_output_states;
        updated
    }
}

/// Alternative to `execute_round` to bypass aztec-nargo compiler errors
pub fn execute_round_const<let NumEntries: u32, let NumParticipants: u32, let UserIndex: u32> (
        user_plaintext: [Field; NumEntries],
    reveal_vector: [Field; NumEntries],
    encrypt_secret: Field,
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
    previous_round_hash: Field,
)->
(UserOutputState<NumEntries, NumParticipants>, [[Option<Field>; NumEntries]; NumParticipants - 1])
{
    // when used inside a Noir program, previous_round_hash should be sourced from a pub variable
    assert_eq(previous_round_hash, round_state.hash());

    assert_eq(
        std::hash::poseidon2::Poseidon2::hash([encrypt_secret, -1], 2),
        round_state.user_encrypt_secret_hashes[UserIndex],
    );
    assert_eq(
        std::hash::poseidon2::Poseidon2::hash([masking_secret, -1], 2),
        round_state.user_mask_secret_hashes[UserIndex],
    );
    let state = create_round_commitments_const::<NumEntries, NumParticipants, UserIndex>(
        user_plaintext,
        reveal_vector,
        encrypt_secret,
        masking_secret,
        round_state,
    );

    let plaintexts = consume_round_commitments_const::<NumEntries, NumParticipants, UserIndex>(masking_secret, round_state);

    (state, plaintexts)
}

pub fn execute_round<let NumEntries: u32, let NumParticipants: u32>(
    user_plaintext: [Field; NumEntries],
    reveal_vector: [Field; NumEntries],
    encrypt_secret: Field,
    masking_secret: Field,
    round_state: RoundState<NumEntries, NumParticipants>,
    previous_round_hash: Field,
    user_index: u32,
    ) -> (UserOutputState<NumEntries, NumParticipants>, [[Option<Field>; NumEntries]; NumParticipants - 1]) {
    std::assert_constant(user_index);

    // when used inside a Noir program, previous_round_hash should be sourced from a pub variable
    assert_eq(previous_round_hash, round_state.hash());

    assert_eq(
        std::hash::poseidon2::Poseidon2::hash([encrypt_secret, -1], 2),
        round_state.user_encrypt_secret_hashes[user_index],
    );
    assert_eq(
        std::hash::poseidon2::Poseidon2::hash([masking_secret, -1], 2),
        round_state.user_mask_secret_hashes[user_index],
    );
    let state = create_round_commitments(
        user_plaintext,
        reveal_vector,
        encrypt_secret,
        masking_secret,
        round_state,
        user_index,
    );

    let plaintexts = consume_round_commitments(masking_secret, round_state, user_index);

    (state, plaintexts)
}


#[test]
fn test_execute_round() {
    let alice_secret = std::hash::poseidon2::Poseidon2::hash([0], 1);
    let alice_mask = std::hash::poseidon2::Poseidon2::hash([1], 1);
    let bob_secret = std::hash::poseidon2::Poseidon2::hash([2], 1);
    let bob_mask = std::hash::poseidon2::Poseidon2::hash([3], 1);

    let round_state: RoundState<4, 2> = RoundState {
        round_number: 1,
        user_encrypt_secret_hashes: [
            poseidon2([alice_secret, -1], 2),
            poseidon2([bob_secret, -1], 2),
        ],
        user_mask_secret_hashes: [poseidon2([alice_mask, -1], 2), poseidon2([bob_mask, -1], 2)],
        previous_output_states: [UserOutputState::default(); 2],
    };

    let previous_round_hash = round_state.hash();
    let alice_state = [0, 1, 2, 3];
    let alice_reveal = [0, 1, 0, 1];
    let bob_state = [-1, -2, -3, -4];
    let bob_reveal = [1, 0, 1, 0];

    // after executing. we have ciphertexts and mask commitments, but no mask reveal commitments
    let alice_output = execute_round(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
        0
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
        1
    );

    let round_state = round_state.update([round_state.previous_output_states[0], bob_output.0]);
    let previous_round_hash = round_state.hash();

    let alice_output = execute_round(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
        0
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
        1
    );

    let alice_decrypted = alice_output.1[0];
    let bob_decrypted = bob_output.1[0];

    assert_eq(alice_decrypted[0].is_some(), false);
    assert_eq(alice_decrypted[1].is_some(), true);
    assert_eq(alice_decrypted[2].is_some(), false);
    assert_eq(alice_decrypted[3].is_some(), true);

    assert_eq(alice_decrypted[1].unwrap_unchecked(), -2);
    assert_eq(alice_decrypted[3].unwrap_unchecked(), -4);

    assert_eq(bob_decrypted[0].is_some(), true);
    assert_eq(bob_decrypted[1].is_some(), false);
    assert_eq(bob_decrypted[2].is_some(), true);
    assert_eq(bob_decrypted[3].is_some(), false);

    assert_eq(bob_decrypted[0].unwrap_unchecked(), 0);
    assert_eq(bob_decrypted[2].unwrap_unchecked(), 2);
}


#[test]
fn test_execute_round_const() {
    let alice_secret = std::hash::poseidon2::Poseidon2::hash([0], 1);
    let alice_mask = std::hash::poseidon2::Poseidon2::hash([1], 1);
    let bob_secret = std::hash::poseidon2::Poseidon2::hash([2], 1);
    let bob_mask = std::hash::poseidon2::Poseidon2::hash([3], 1);

    let round_state: RoundState<4, 2> = RoundState {
        round_number: 1,
        user_encrypt_secret_hashes: [
            poseidon2([alice_secret, -1], 2),
            poseidon2([bob_secret, -1], 2),
        ],
        user_mask_secret_hashes: [poseidon2([alice_mask, -1], 2), poseidon2([bob_mask, -1], 2)],
        previous_output_states: [UserOutputState::default(); 2],
    };

    let previous_round_hash = round_state.hash();
    let alice_state = [0, 1, 2, 3];
    let alice_reveal = [0, 1, 0, 1];
    let bob_state = [-1, -2, -3, -4];
    let bob_reveal = [1, 0, 1, 0];

    // after executing. we have ciphertexts and mask commitments, but no mask reveal commitments
    let alice_output = execute_round_const::<_,_,0>(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round_const::<_,_,1>(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
    );

    let round_state = round_state.update([round_state.previous_output_states[0], bob_output.0]);
    let previous_round_hash = round_state.hash();

    let alice_output = execute_round_const::<_,_,0>(
        alice_state,
        alice_reveal,
        alice_secret,
        alice_mask,
        round_state,
        previous_round_hash,
    );

    let round_state = round_state.update([alice_output.0, round_state.previous_output_states[1]]);
    let previous_round_hash = round_state.hash();

    let bob_output = execute_round_const::<_,_,1>(
        bob_state,
        bob_reveal,
        bob_secret,
        bob_mask,
        round_state,
        previous_round_hash,
    );

    let alice_decrypted = alice_output.1[0];
    let bob_decrypted = bob_output.1[0];

    assert_eq(alice_decrypted[0].is_some(), false);
    assert_eq(alice_decrypted[1].is_some(), true);
    assert_eq(alice_decrypted[2].is_some(), false);
    assert_eq(alice_decrypted[3].is_some(), true);

    assert_eq(alice_decrypted[1].unwrap_unchecked(), -2);
    assert_eq(alice_decrypted[3].unwrap_unchecked(), -4);

    assert_eq(bob_decrypted[0].is_some(), true);
    assert_eq(bob_decrypted[1].is_some(), false);
    assert_eq(bob_decrypted[2].is_some(), true);
    assert_eq(bob_decrypted[3].is_some(), false);

    assert_eq(bob_decrypted[0].unwrap_unchecked(), 0);
    assert_eq(bob_decrypted[2].unwrap_unchecked(), 2);
}

/// This doesn't really do anything by ensures that there is a test for CI to run.
#[test]
fn smoke_test() {
    let plaintext: [Field; 3] = [0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, 123, -1];
    let bob_reveal_vector: [Field; 3] = [0, 1, 1];

    let alice_encrypt_secret: Field = std::hash::poseidon2::Poseidon2::hash([0], 1);

    let bob_masking_secret: Field = std::hash::poseidon2::Poseidon2::hash([2], 1);

    // Round 1a: Alice generates the ciphertext that describes her hidden state, sends to Bob
    let ciphertext = commit(plaintext, alice_encrypt_secret);

    // Round 1b: Bob generates commitment mask that describes which parts of the state he is entitled to see, sends to Alice
    let bob_masking_keys = commit_mask(bob_reveal_vector, bob_masking_secret);

    // Round 2: Alice uses Bob's commitment mask to create a hidden version of her encryption keys, sends to Bob
    let alice_masking_update = update_mask(bob_masking_keys, alice_encrypt_secret);

    // Round 3: Bob removes his masking component from Alice's updated mask to produce partial decryption keys
    let partial_decrypt_keys = reveal_mask(alice_masking_update, bob_masking_secret);

    // (still round 3): Bob uses the partial decryption keys to decrypt the part of Alice's state he is entitled to see
    let partial_plaintext = trial_decrypt(partial_decrypt_keys, ciphertext);

    assert_eq(partial_plaintext[0].is_some(), false);
    assert_eq(partial_plaintext[1].is_some(), true);
    assert_eq(partial_plaintext[2].is_some(), true);

    assert_eq(partial_plaintext[1].unwrap_unchecked(), 123);
    assert_eq(partial_plaintext[2].unwrap_unchecked(), -1);
}
