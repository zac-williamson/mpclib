use crate::common::bignum_utils::convert_bn254_to_embedded_scalar;
use crate::common::fisher_yates_shuffle::fisher_yates_shuffle_from_secret;
use crate::shuffle::generators::INDEX_GENERATORS;

use bignum::{BigNumTrait, BN254_Fq};
use std::embedded_curve_ops::{EmbeddedCurvePoint as Point, EmbeddedCurveScalar, multi_scalar_mul};

/// ShuffleData contains the data and metadata we need to track the Shuffle MPC protocol
/// # Parameters
/// `index_commitments`: elliptic curve points that represent indices of an array we want to shuffle, randomized as part of the MPC protocol
/// `user_key_hashes`: contains the hash of the secret each user is using to shuffle the array and randomize `index_commitments`.
///                    note: the users need to commit to their secrets before the shuffle protocol starts so they cannot bias the outcome
/// `round`: how many rounds of the shuffle algorithm have occured?
/// `shuffle_receipts`: tracks whether a given user has participated in the shuffle protocol
struct ShuffleData<let N: u32, let NumParticipants: u32> {
    index_commitments: [Point; N],
    user_key_hashes: [Field; NumParticipants],
    round: Field,
    num_unblinded_items: u32,
    shuffle_receipts: [bool; NumParticipants],
}

impl<let N: u32, let NumParticipants: u32> ShuffleData<N, NumParticipants> {
    /// ShuffleData constructor . `user_key_hashes` needs to be known ahead of time before the shuffle protocol begins
    fn new(user_key_hashes: [Field; NumParticipants]) -> Self {
        ShuffleData {
            index_commitments: [Point::point_at_infinity(); N],
            user_key_hashes,
            round: 0,
            num_unblinded_items: 0,
            shuffle_receipts: [false; NumParticipants],
        }
    }

    /// Execute one user's part of the shuffle protocol
    /// # Params
    /// `user_secret`: the secret the user is using to shuffle and randomize (its hash needs to match the value in `user_key_hashes`)
    /// `user_index`: which participant is taking part?
    fn shuffle(self, user_secret: Field, user_index: u32) -> Self {
        let mut input_points = self.index_commitments;
        if (self.round == 0) {
            for i in 0..N {
                input_points[i] = INDEX_GENERATORS[i];
            }
        }

        // https://eprint.iacr.org/2009/439.pdf

        let shuffled_indices: [Field; N] = fisher_yates_shuffle_from_secret(user_secret);

        let mut shuffled_commitments: [Point; N] = [Point::point_at_infinity(); N];
        for i in 0..N {
            shuffled_commitments[i] = multi_scalar_mul(
                [input_points[shuffled_indices[i]]],
                [EmbeddedCurveScalar::from_field(user_secret)],
            );
        }

        assert_eq(self.shuffle_receipts[user_index], false, "user has already shuffled!");
        assert_eq(
            self.user_key_hashes[user_index],
            std::hash::poseidon2::Poseidon2::hash([user_secret], 1),
            "user secret does not match committed hash",
        );
        let mut output_data = self;
        output_data.index_commitments = shuffled_commitments;
        output_data.shuffle_receipts[user_index] = true;
        output_data.round += 1;
        output_data
    }
}

struct UnblindContainer<let NumUnblinded: u32, let NumParticipants: u32> {
    user_index_of_owner: Field,
    index_commitments: [Point; NumUnblinded],
    unblind_receipts: [bool; NumParticipants],
    count: Field,
}

impl<let NumUnblinded: u32, let NumParticipants: u32> UnblindContainer<NumUnblinded, NumParticipants> {
    fn new(user_index_of_owner: Field) -> Self {
        UnblindContainer {
            user_index_of_owner,
            index_commitments: [Point::point_at_infinity(); NumUnblinded],
            unblind_receipts: [false; NumParticipants],
            count: 0,
        }
    }
}

// ok mostly working...kind of
fn deal_and_unblind<let N: u32, let NumItems: u32, let NumParticipants: u32>(
    user_secret: Field,
    _data: ShuffleData<N, NumParticipants>,
    _unblind_data: UnblindContainer<NumItems, NumParticipants>,
    user_index: u32,
) -> (ShuffleData<N, NumParticipants>, UnblindContainer<NumItems, NumParticipants>) {
    let mut data = _data;
    let mut unblind_data = _unblind_data;
    // TODO optimize out branch
    if (unblind_data.count == 0) {
        assert(
            data.num_unblinded_items + NumItems <= N,
            "attempting to blind more items than were committed to!",
        );
    } else {
        assert(
            data.num_unblinded_items <= N,
            "attempting to blind more items than were committed to!",
        );
    }
    let mut all_shuffled: bool = true;
    for i in 0..NumParticipants {
        all_shuffled = all_shuffled & data.shuffle_receipts[i];
    }
    assert_eq(all_shuffled, true, "cannot unblind commitments if shuffle is not complete");
    let mut commitments: [Point; NumItems] = unblind_data.index_commitments;
    if (unblind_data.count == 0) {
        for i in 0..NumItems {
            commitments[i] = data.index_commitments[data.num_unblinded_items + i];
        }
        data.num_unblinded_items += NumItems;
    }
    let secret_bn = BN254_Fq::from(user_secret);
    let inverse = BN254_Fq::one() / secret_bn;
    let scalar = convert_bn254_to_embedded_scalar(inverse);

    let mut unblinded_commitments: [Point; NumItems] = [Point::point_at_infinity(); NumItems];
    for i in 0..NumItems {
        let to_unblind = commitments[i];
        unblinded_commitments[i] = multi_scalar_mul([to_unblind], [scalar]);
    }

    assert(
        unblind_data.user_index_of_owner != user_index as Field,
        "user cannot unblind their own commitments!",
    );
    unblind_data.count = unblind_data.count + 1;
    assert(unblind_data.unblind_receipts[user_index] == false);
    unblind_data.unblind_receipts[user_index] = true;
    unblind_data.index_commitments = unblinded_commitments;

    (data, unblind_data)
}

unconstrained fn __determine_index<let N: u32>(unblinded_commitment: Point) -> u32 {
    let mut idx: u32 = 0;
    let mut found = false;
    for i in 0..N {
        if (INDEX_GENERATORS[i] == unblinded_commitment) {
            idx = i;
            found = true;
        }
    }
    assert(found, "could not map unblinded commitment to an index");
    idx
}

fn unblind_and_determine_index<let N: u32, let NumItems: u32, let NumParticipants: u32>(
    user_secret: Field,
    data: ShuffleData<N, NumParticipants>,
    unblind_data: UnblindContainer<NumItems, NumParticipants>,
    user_index: u32,
) -> [u32; NumItems] {
    assert_eq(
        data.user_key_hashes[user_index],
        std::hash::poseidon2::Poseidon2::hash([user_secret], 1),
        "user secret does not match committed hash",
    );

    let mut is_unblinded: bool = true;
    for i in 0..NumParticipants {
        let receipt = unblind_data.unblind_receipts[i];
        let receipt_result = receipt | (i == user_index);
        is_unblinded = is_unblinded & receipt_result;
    }
    assert_eq(
        is_unblinded,
        true,
        "unblinded commitments have not be unblinded by all participants!",
    );

    let secret_bn = BN254_Fq::from(user_secret);
    let inverse = BN254_Fq::one() / secret_bn;
    let scalar = convert_bn254_to_embedded_scalar(inverse);

    let mut index_results: [u32; NumItems] = [0; NumItems];
    for i in 0..NumItems {
        let raw_commitment = multi_scalar_mul([unblind_data.index_commitments[i]], [scalar]);
        let index = determine_index::<N>(raw_commitment);
        index_results[i] = index;
    }

    index_results
}

fn determine_index<let N: u32>(unblinded_commitment: Point) -> u32 {
    //Safety: determine which generator point we have via an unconstrained fn, then constrain the returned idx is correct
    let idx = unsafe { __determine_index::<N>(unblinded_commitment) };

    assert_eq(unblinded_commitment, INDEX_GENERATORS[idx]);
    idx
}

#[test]
fn test_shuffle_2pc() {
    let alice_secret = std::hash::poseidon2::Poseidon2::hash([0], 1);
    let bob_secret = std::hash::poseidon2::Poseidon2::hash([2], 1);
    let secret_hashes: [Field; 2] = [
        std::hash::poseidon2::Poseidon2::hash([alice_secret], 1),
        std::hash::poseidon2::Poseidon2::hash([bob_secret], 1),
    ];
    let mut shuffle_data: ShuffleData<8, 2> = ShuffleData::new(secret_hashes);

    shuffle_data = shuffle_data.shuffle(alice_secret, 0);
    shuffle_data = shuffle_data.shuffle(bob_secret, 1);

    let mut alice_unblind_data: UnblindContainer<4, 2> = UnblindContainer::new(0);
    let mut bob_unblind_data: UnblindContainer<4, 2> = UnblindContainer::new(1);

    let (_s, _a) = deal_and_unblind::<8, 4, 2>(bob_secret, shuffle_data, alice_unblind_data, 1);
    shuffle_data = _s;
    alice_unblind_data = _a;
    let (_s, _b) = deal_and_unblind::<8, 4, 2>(alice_secret, shuffle_data, bob_unblind_data, 0);
    shuffle_data = _s;
    bob_unblind_data = _b;
    let alice_indices =
        unblind_and_determine_index(alice_secret, shuffle_data, alice_unblind_data, 0);
    let bob_indices = unblind_and_determine_index(bob_secret, shuffle_data, bob_unblind_data, 1);
    let mut all_indices_used: [bool; 8] = [false; 8];
    for i in 0..4 {
        assert(alice_indices[i] < 8);
        assert(bob_indices[i] < 8);
        all_indices_used[alice_indices[i]] = true;
        all_indices_used[bob_indices[i]] = true;
    }
    assert_eq(all_indices_used, [true; 8]);
}

#[test]
fn test_poker_5players() {
    let player_secrets: [Field; 5] = [
        std::hash::poseidon2::Poseidon2::hash([8], 1),
        std::hash::poseidon2::Poseidon2::hash([1], 1),
        std::hash::poseidon2::Poseidon2::hash([2], 1),
        std::hash::poseidon2::Poseidon2::hash([3], 1),
        std::hash::poseidon2::Poseidon2::hash([4], 1),
    ];

    let secret_hashes: [Field; 5] = [
        std::hash::poseidon2::Poseidon2::hash([player_secrets[0]], 1),
        std::hash::poseidon2::Poseidon2::hash([player_secrets[1]], 1),
        std::hash::poseidon2::Poseidon2::hash([player_secrets[2]], 1),
        std::hash::poseidon2::Poseidon2::hash([player_secrets[3]], 1),
        std::hash::poseidon2::Poseidon2::hash([player_secrets[4]], 1),
    ];

    let mut shuffle_data: ShuffleData<52, _> = ShuffleData::new(secret_hashes);

    // STEP 1: SHUFFLE CARDS (5 proofs)
    // In MPC setting this would require 5 proofs - one per player secret
    for i in 0..5 {
        shuffle_data = shuffle_data.shuffle(player_secrets[i], i);
    }

    let mut player_card_data: [UnblindContainer<2, 5>; 5] = [
        UnblindContainer::new(0),
        UnblindContainer::new(1),
        UnblindContainer::new(2),
        UnblindContainer::new(3),
        UnblindContainer::new(4),
    ];

    // THE PRE-FLOP
    // PRE-FLOP 1: DEAL CARDS (5 proofs)
    // the outer loop here would, in a real world setting, take place in 5 separate circuits
    for player_index in 0..5 {
        for j in 0..5 {
            if (j != player_index) {
                let (s, b) = deal_and_unblind::<_, _, _>(
                    player_secrets[player_index],
                    shuffle_data,
                    player_card_data[j],
                    player_index,
                );
                shuffle_data = s;
                player_card_data[j] = b;
            }
        }
    }

    // PRE-FLOP 2: UNBLIND CARDS FOR EACH PLAYER (5 proofs)
    let player_indices: [[u32; 2]; 5] = [
        unblind_and_determine_index(player_secrets[0], shuffle_data, player_card_data[0], 0),
        unblind_and_determine_index(player_secrets[1], shuffle_data, player_card_data[1], 1),
        unblind_and_determine_index(player_secrets[2], shuffle_data, player_card_data[2], 2),
        unblind_and_determine_index(player_secrets[3], shuffle_data, player_card_data[3], 3),
        unblind_and_determine_index(player_secrets[4], shuffle_data, player_card_data[4], 4),
    ];
    println(f"player_indices {player_indices}");

    let dealer_idx: u32 = 2; // let's say player 2 is the dealer

    // THE FLOP
    let mut flop_public_card_data: UnblindContainer<3, 5> =
        UnblindContainer::new(dealer_idx as Field);

    // turn 1: players unblind the flop (4 proofs)
    for player_index in 0..5 {
        if (player_index != dealer_idx) {
            let (s, b) = deal_and_unblind::<_, _, _>(
                player_secrets[player_index],
                shuffle_data,
                flop_public_card_data,
                player_index,
            );
            shuffle_data = s;
            flop_public_card_data = b;
        }
    }

    // FLOP 2: DEALER REVEALS FLOP (1 proof)
    let flop_indices: [u32; 3] = unblind_and_determine_index(
        player_secrets[dealer_idx],
        shuffle_data,
        flop_public_card_data,
        dealer_idx,
    );
    println(f"flop_indices {flop_indices}");

    // THE TURN
    let mut turn_public_card_data: UnblindContainer<1, 5> =
        UnblindContainer::new(dealer_idx as Field);
    // turn 1: PLAYERS UNBLIND THE TURN CARD (4 proofs)
    for player_index in 0..5 {
        if (player_index != dealer_idx) {
            let (s, b) = deal_and_unblind::<_, _, _>(
                player_secrets[player_index],
                shuffle_data,
                turn_public_card_data,
                player_index,
            );
            shuffle_data = s;
            turn_public_card_data = b;
        }
    }
    // turn 2: DEALER REVEALS turn (1 proof)
    let turn_indices: [u32; 1] = unblind_and_determine_index(
        player_secrets[dealer_idx],
        shuffle_data,
        turn_public_card_data,
        dealer_idx,
    );
    println(f"turn_indices {turn_indices}");

    // THE RIVER
    let mut turn_public_card_data: UnblindContainer<1, 5> =
        UnblindContainer::new(dealer_idx as Field);
    // turn 1: PLAYERS UNBLIND THE RIVER CARD (4 proofs)
    for player_index in 0..5 {
        if (player_index != dealer_idx) {
            let (s, b) = deal_and_unblind::<_, _, _>(
                player_secrets[player_index],
                shuffle_data,
                turn_public_card_data,
                player_index,
            );
            shuffle_data = s;
            turn_public_card_data = b;
        }
    }
    // turn 2: DEALER REVEALS RIVER (1 proof)
    let river_indices: [u32; 1] = unblind_and_determine_index(
        player_secrets[dealer_idx],
        shuffle_data,
        turn_public_card_data,
        dealer_idx,
    );
    println(f"river_indices {river_indices}");

    let mut uniqueness_check: [bool; 52] = [false; 52];
    for i in 0..5 {
        for j in 0..2 {
            assert_eq(uniqueness_check[player_indices[i][j]], false);
            uniqueness_check[player_indices[i][j]] = true;
        }
    }
    for i in 0..3 {
        assert_eq(uniqueness_check[flop_indices[i]], false);
        uniqueness_check[flop_indices[i]] = true;
    }
    assert_eq(uniqueness_check[turn_indices[0]], false);
    uniqueness_check[turn_indices[0]] = true;
    assert_eq(uniqueness_check[river_indices[0]], false);
    uniqueness_check[river_indices[0]] = true;
}
