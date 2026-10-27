//! Independent decoder tests: honest streams use upstream Encoders; tiny
//! contract cases isolate exact-zero, budget-free and mapping-incidence checks.

use riblt::{Encoder, HashKey, RandomMapping, Symbol};

use crate::riblt_cache::{Cell, KeySymbol};
use crate::riblt_decode::{DecodeError, ResidualDecoder};
use crate::riblt_store::CHUNK;

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
fn riblt_decode_recovers_across_file_backed_chunk_boundaries() {
    // More residual rows and more remote-only keys than one storage chunk
    // holds, so rows, windows and frontiers all cross chunk boundaries.
    let key = [11; 16];
    let remote_only = CHUNK as u64 + 4_000;
    let mut local = encoder(key, (0..6_000).map(symbol));
    let mut remote = encoder(key, (3_000..6_000 + remote_only).map(symbol));
    let mut decoder = ResidualDecoder::with_key(key);
    let mut rows = 0;
    while !decoder.decoded() {
        decoder.add(residual(&mut local, &mut remote)).unwrap();
        rows += 1;
    }
    assert!(rows > CHUNK, "{rows} rows stay within one chunk");
    assert_eq!(
        recovered(&decoder, true),
        (0..3_000).map(|n| symbol(n).0).collect::<Vec<_>>()
    );
    assert_eq!(
        recovered(&decoder, false),
        (6_000..6_000 + remote_only)
            .map(|n| symbol(n).0)
            .collect::<Vec<_>>()
    );
}

#[test]
fn riblt_decode_has_no_cell_or_support_budget() {
    // The exchange bounds residual counts by the peer's root count and cell
    // indices by the u32 wire domain; the decoder itself refuses neither.
    let key = [23; 16];
    let mut decoder = ResidualDecoder::with_key(key);
    for _ in 0..3 {
        assert_eq!(decoder.add(Cell::default()), Ok(()));
        assert!(decoder.decoded());
    }
    for count in [-2, 2, -(1 << 21), 1 << 21] {
        let mut decoder = ResidualDecoder::with_key(key);
        assert_eq!(
            decoder.add(Cell {
                count,
                ..Cell::default()
            }),
            Ok(())
        );
        assert!(!decoder.decoded());
        assert!(decoder.local().is_empty() && decoder.remote().is_empty());
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
