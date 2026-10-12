//! Independent bounded-decoder tests: honest streams use upstream Encoders;
//! two tiny contract cases isolate exact-zero and mapping-incidence checks.

use riblt::{Encoder, HashKey, RandomMapping, Symbol};

use crate::riblt_cache::{Cell, KeySymbol};
use crate::riblt_decode::{DecodeError, Limits, ResidualDecoder};

fn symbol(number: u64) -> KeySymbol {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&number.to_be_bytes());
    KeySymbol(bytes)
}

fn encoder(key: HashKey, symbols: impl IntoIterator<Item = KeySymbol>) -> Encoder<KeySymbol> {
    let mut encoder = Encoder::with_key(key);
    for symbol in symbols {
        encoder.add_symbol(symbol);
    }
    encoder
}

fn residual(local: &mut Encoder<KeySymbol>, remote: &mut Encoder<KeySymbol>) -> Cell {
    let local = local.produce_next_coded_symbol();
    let remote = remote.produce_next_coded_symbol();
    Cell {
        symbol: remote.symbol.xor(&local.symbol),
        hash: remote.hash ^ local.hash,
        count: remote.count.checked_sub(local.count).unwrap(),
    }
}

fn recovered(decoder: &ResidualDecoder, local: bool) -> Vec<[u8; 32]> {
    let mut keys: Vec<_> = if local {
        decoder.local()
    } else {
        decoder.remote()
    }
    .iter()
    .map(|item| item.symbol.0)
    .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn riblt_decode_honest_mixed_sign_cascade_matches_upstream_encoders() {
    let key = [7; 16];
    let mut local = encoder(key, (0..24).map(symbol));
    let mut remote = encoder(key, (12..36).map(symbol));
    let mut decoder = ResidualDecoder::with_key(key);
    assert!(!decoder.decoded(), "no initially-decoded empty shortcut");
    let mut cascade = false;
    for _ in 0..4096 {
        let before = decoder.local().len() + decoder.remote().len();
        decoder.add(residual(&mut local, &mut remote)).unwrap();
        cascade |= decoder.local().len() + decoder.remote().len() > before + 1;
        if decoder.decoded() {
            break;
        }
    }
    assert!(decoder.decoded());
    assert!(
        cascade,
        "this fixture exercises more than one peel in an add call"
    );
    assert_eq!(
        recovered(&decoder, true),
        (0..12).map(|n| symbol(n).0).collect::<Vec<_>>()
    );
    assert_eq!(
        recovered(&decoder, false),
        (24..36).map(|n| symbol(n).0).collect::<Vec<_>>()
    );
}

#[test]
fn riblt_decode_honest_cascade_has_a_cumulative_work_budget() {
    let key = [7; 16];
    let mut saw_partial_recovery_limit = false;
    // These are small injected work allowances, not timing-based deadlines.
    // At least one must stop ordinary peeling after making partial progress.
    for work in [8, 16, 32, 64, 128, 256, 512] {
        let mut local = encoder(key, (0..24).map(symbol));
        let mut remote = encoder(key, (12..36).map(symbol));
        let mut decoder = ResidualDecoder::with_limits(
            key,
            Limits {
                cells: 4096,
                support: 64,
                work,
            },
        );
        let mut stopped = false;
        for _ in 0..4096 {
            match decoder.add(residual(&mut local, &mut remote)) {
                Ok(()) if decoder.decoded() => {
                    stopped = true;
                    break;
                }
                Ok(()) => {}
                Err(error) => {
                    assert_eq!(error, DecodeError::Limit);
                    saw_partial_recovery_limit |=
                        !decoder.local().is_empty() || !decoder.remote().is_empty();
                    stopped = true;
                    break;
                }
            }
        }
        assert!(stopped);
    }
    assert!(
        saw_partial_recovery_limit,
        "work is bounded during recovery, not only before it"
    );
}

#[test]
fn riblt_decode_recovered_support_is_bounded_even_when_each_residual_count_fits() {
    let key = [17; 16];
    let mut locals = Vec::new();
    let (mut first_remote, mut second_remote) = (None, None);
    // Choose ordinary source keys by their upstream mapping: the local pair
    // skips rows1,2; the remote pair occupies row1 and row2 separately.
    for number in 0..4096 {
        let candidate = symbol(number);
        let mut mapping = RandomMapping::new(candidate.keyed_mapping_seed(&key));
        let first = mapping.next_index();
        let second = mapping.next_index();
        if first >= 3 && locals.len() < 2 {
            locals.push(candidate);
        }
        if first == 1 && second >= 3 {
            first_remote.get_or_insert(candidate);
        }
        if first == 2 {
            second_remote.get_or_insert(candidate);
        }
        if locals.len() == 2 && first_remote.is_some() && second_remote.is_some() {
            break;
        }
    }
    assert_eq!(locals.len(), 2);
    let remotes = [first_remote.unwrap(), second_remote.unwrap()];
    let mut local = encoder(key, locals);
    let mut remote = encoder(key, remotes);
    let mut decoder = ResidualDecoder::with_limits(
        key,
        Limits {
            cells: 16,
            support: 1,
            work: 1024,
        },
    );
    for index in 0..3 {
        let row = residual(&mut local, &mut remote);
        assert!(row.count.unsigned_abs() <= 1);
        let result = decoder.add(row);
        if index < 2 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(DecodeError::Limit));
        }
    }
    assert_eq!(decoder.remote().len(), 1);
    assert!(decoder.local().is_empty());
    assert!(!decoder.decoded());
}

#[test]
fn riblt_decode_cell_and_residual_limits_are_independent_of_zero_completion() {
    let key = [23; 16];
    let limits = Limits {
        cells: 1,
        support: 1,
        work: 128,
    };
    let mut decoder = ResidualDecoder::with_limits(key, limits);
    assert!(!decoder.decoded());
    assert_eq!(decoder.add(Cell::default()), Ok(()));
    assert!(decoder.decoded());
    assert_eq!(decoder.add(Cell::default()), Err(DecodeError::Limit));
    for count in [-2, 2] {
        let mut decoder = ResidualDecoder::with_limits(key, limits);
        assert_eq!(
            decoder.add(Cell {
                count,
                ..Cell::default()
            }),
            Err(DecodeError::Limit)
        );
        assert!(!decoder.decoded());
    }
}

#[test]
fn riblt_decode_exact_zero_includes_symbol_bytes() {
    let key = [29; 16];
    let mut exact = ResidualDecoder::with_key(key);
    assert_eq!(exact.add(Cell::default()), Ok(()));
    assert!(exact.decoded());

    let mut nonzero = ResidualDecoder::with_key(key);
    assert_eq!(
        nonzero.add(Cell {
            symbol: symbol(1),
            ..Cell::default()
        }),
        Ok(())
    );
    assert!(!nonzero.decoded());
    assert!(nonzero.local().is_empty() && nonzero.remote().is_empty());
}

#[test]
fn riblt_decode_checksum_purity_does_not_replace_mapping_incidence() {
    let key = [31; 16];
    let candidate = (0..4096)
        .map(symbol)
        .find(|candidate| RandomMapping::new(candidate.keyed_mapping_seed(&key)).next_index() > 1)
        .expect("bounded fixture search finds a key absent from row1");
    let cell = Cell {
        symbol: candidate,
        hash: candidate.keyed_hash(&key),
        count: 1,
    };
    assert!(cell.is_pure_with_key(Some(&key)));
    let mut mapping = RandomMapping::new(candidate.keyed_mapping_seed(&key));
    assert_eq!(mapping.last_index(), 0);
    assert!(
        mapping.next_index() > 1,
        "row1 is not in this key's mapping"
    );

    let mut decoder = ResidualDecoder::with_key(key);
    assert_eq!(decoder.add(Cell::default()), Ok(()));
    assert_eq!(decoder.add(cell), Err(DecodeError::Invalid));
    assert!(!decoder.decoded());
    assert!(decoder.local().is_empty() && decoder.remote().is_empty());
}
