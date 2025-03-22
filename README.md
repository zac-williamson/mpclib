# noir-library-starter

**PLEASE NOTE THIS LIBRARY IS NOT AUDITED. USE AT YOUR OWN RISK**

This repository is a template used by the noir-lang org when creating internally maintained libraries.

This provides out of the box:

- A simple CI setup to test and format the library
- A canary flagging up compilation failures on nightly releases.
- A [release-please](https://github.com/googleapis/release-please) setup to ease creating releases for the library.
- Contributing guidelines specified in [CONTRIBUTING.md](CONTRIBUTING.md)

Feel free to use this template as a starting point to create your own Noir libraries.

---

# mpclib

A library that implements useful and simple multiparty computation protocols in Noir


## Noir version compatibility

This library is tested to work as of Noir version 1.0.0-beta.3

## Benchmarks

Benchmarks are ignored by `git` and checked on pull-request. As such, benchmarks may be generated
with the following command.

```bash
# execute the following
./scripts/build-gates-report.sh
```

The benchmark will be generated at `./gates_report.json`.

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
LIBRARY = { tag = "v0.1.0", git = "https://github.com/noir-lang/LIBRARY_NAME" }
```

## `library`

Library currently implements two protocols: a selective disclosure protocol and a random shuffle protocol.

Each round of an MPC protocol is intended to be represented via a separate circuit + proof. Recursion is required to wrap multiple MPC rounds into an atomic proof.

### `selective_disclosure` usage

K participants. Each participant has a size-N array of field elements that are encrypted.

The following pseudocode is what the protocol *enables*, but imagine `alice_data, bob_data, alice_mask, bob_mask` are encrypted. Bob cannot view alice's data + mask and Alice cannot view bob's data + mask.

```
// example where K=2
let alice_data: [Field; N];
let bob_data: [Field; N];

let alice_mask: [bool; N];
let bob_mask: [bool; N];

let alice_data_to_bob: [Field];
let bob_data_to_alice; [Field];

for i in 0..N {
    if (bob_mask[i] == true)
    {
        alice_data_to_bob.push(alice_data[i]);
    }
    if (alice_mask[i] == true)
    {
        bob_data_to_alice.push(bob_data[i]);
    }
}

return (alice_data_to_bob, bob_data_to_alice)
```

An example of `selective_disclosure` being used in practise:

```noir
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
        0,
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
        1,
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
        0,
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
        1,
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

```

### `shuffle` usage

```
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
```