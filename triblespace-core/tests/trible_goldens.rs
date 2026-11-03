//! Byte-level golden tests for `Trible`.
//!
//! These pin what the 64-byte trible representation produces TODAY
//! (triblespace main e77f8e67), so that a change to how `Trible` is laid out
//! in memory cannot silently alter any byte that leaves the process:
//!
//! 1. intrinsic entity ids, which BLAKE3-hash the canonical row bytes;
//! 2. the encoded `SimpleArchive` blob, which is the canonical row bytes;
//! 3. `Trible`'s `Ord`, which must agree with byte-lexicographic order of the
//!    64 bytes, and the strictly increasing row order of sets and archives.
//!
//! The golden literals were obtained by running these tests against e77f8e67
//! and copying the printed values. They record that behaviour; they are not
//! an independent specification. Where an independent oracle is cheap (the
//! intrinsic-id rule, the archive layout) it is checked alongside the golden.
//!
//! Every byte view below is assembled from the public accessors `e()`, `a()`
//! and `v()` rather than from the `data` field, so the tests keep compiling
//! across a change of field layout.

use triblespace_core::id::{Id, ID_LEN};
use triblespace_core::prelude::blobencodings::{SimpleArchive, UTF8String};
use triblespace_core::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace_core::prelude::*;

mod ns {
    use triblespace_core::prelude::*;

    // Fixture ids minted with `trible genid` on 2026-11-03. Literal-pinned
    // (`unsafe as`) so the attribute ids are exactly these bytes and do not
    // depend on encoding metadata.
    attributes! {
        "8949D4202DE4A164FEAC264478D411E7" unsafe as pub count: inlineencodings::U256BE;
        "07B5DE7D05C41D9301D562F45C2BD30F" unsafe as pub link: inlineencodings::GenId;
        "D51B6AC3896E2A8C2150D62065AB0DCF" unsafe as pub label: inlineencodings::Handle<blobencodings::UTF8String>;
        "F4987A1FB24FDEA3F099CB0CAF7C6060" unsafe as pub tag: inlineencodings::U256BE;
    }
}

// Further fixture ids minted with `trible genid` on 2026-11-03.
const ENTITY_ONE: &str = "9E8A61897BC9E70576E6634DCE637A73";
const ENTITY_TWO: &str = "22FF76BE1F4F274D51C226E0A0BB91A9";
const TARGET: &str = "6C3397AA84280EF176363B6FF8F52111";
const OTHER_TARGET: &str = "9403348320524DD71401F5246F006FD2";

fn id(hex: &str) -> Id {
    Id::from_hex(hex).expect("fixture id is valid non-nil hex")
}

/// The 64 bytes of a trible, assembled from its public accessors.
fn raw(trible: &Trible) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..16].copy_from_slice(&trible.e()[..]);
    out[16..32].copy_from_slice(&trible.a()[..]);
    out[32..64].copy_from_slice(&trible.v::<UnknownInline>().raw);
    out
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Independent oracle for the current intrinsic-id rule: rows of
/// `NIL || attribute || value`, sorted and deduplicated as 64-byte strings,
/// concatenated, BLAKE3-hashed, last 16 digest bytes.
fn oracle_intrinsic_id(pairs: &[(Id, [u8; 32])]) -> Id {
    let mut rows: Vec<[u8; 64]> = pairs
        .iter()
        .map(|(attribute, value)| {
            let mut row = [0u8; 64];
            row[16..32].copy_from_slice(&attribute[..]);
            row[32..64].copy_from_slice(value);
            row
        })
        .collect();
    rows.sort_unstable();
    rows.dedup();
    let mut hasher = blake3::Hasher::new();
    for row in &rows {
        hasher.update(row);
    }
    let digest = hasher.finalize();
    let digest = digest.as_bytes();
    let mut id = [0u8; ID_LEN];
    id.copy_from_slice(&digest[digest.len() - ID_LEN..]);
    Id::new(id).expect("BLAKE3 digest tail is non-nil")
}

fn n(value: u64) -> Inline<U256BE> {
    value.to_inline()
}

fn g(target: Id) -> Inline<GenId> {
    target.to_inline()
}

fn u256be(value: u64) -> [u8; 32] {
    let inline: Inline<U256BE> = value.to_inline();
    inline.raw
}

fn genid_value(target: Id) -> [u8; 32] {
    let inline: Inline<GenId> = target.to_inline();
    inline.raw
}

fn text(value: &str) -> [u8; 32] {
    let inline: Inline<Handle<UTF8String>> = value.to_inline();
    inline.raw
}

/// Checks a fragment's root against the golden and the oracle, and checks
/// every fact carries that root as its entity.
fn check_intrinsic(name: &str, fragment: &Fragment, pairs: &[(Id, [u8; 32])], golden: &str) {
    let root = fragment.root().expect("intrinsic entity exports one root");
    println!("GOLDEN {name} root = {root:X}");
    assert_eq!(root, oracle_intrinsic_id(pairs), "{name}: oracle disagrees");
    assert_eq!(format!("{root:X}"), golden, "{name}: golden root changed");
    for trible in fragment.facts().iter() {
        assert_eq!(*trible.e(), root, "{name}: fact not filled with the root");
    }
}

#[test]
fn golden_intrinsic_id_fields_declared_out_of_sorted_order() {
    // Declared tag (F4..), count (89..), link (07..): the reverse of the
    // byte order of the attribute ids.
    let fragment = entity! {
        ns::tag: 3u64,
        ns::count: 42u64,
        ns::link: id(TARGET),
    };
    let pairs = [
        (ns::tag.id(), u256be(3)),
        (ns::count.id(), u256be(42)),
        (ns::link.id(), genid_value(id(TARGET))),
    ];
    assert_eq!(fragment.facts().len(), 3);
    check_intrinsic(
        "out_of_order",
        &fragment,
        &pairs,
        "0BE4F64EABC549AD8D7719EAB20C5B57",
    );
}

#[test]
fn golden_intrinsic_id_repeated_attribute() {
    // Repeated values in non-sorted order with one duplicate; the duplicate
    // collapses, so the entity has four facts.
    let fragment = entity! {
        ns::count*: [9u64, 1, 5, 1],
        ns::link: id(OTHER_TARGET),
    };
    let pairs = [
        (ns::count.id(), u256be(9)),
        (ns::count.id(), u256be(1)),
        (ns::count.id(), u256be(5)),
        (ns::count.id(), u256be(1)),
        (ns::link.id(), genid_value(id(OTHER_TARGET))),
    ];
    assert_eq!(fragment.facts().len(), 4);
    check_intrinsic(
        "repeated",
        &fragment,
        &pairs,
        "FD9F6481CDFC7A44EA2E1027DC2E2117",
    );
}

#[test]
fn golden_intrinsic_id_text_handles() {
    // Content-handle values (BLAKE3 of the text) on three attributes,
    // declared label, tag, count.
    let fragment = entity! {
        ns::label: "golden trible",
        ns::tag: 7u64,
        ns::count: 0u64,
    };
    let pairs = [
        (ns::label.id(), text("golden trible")),
        (ns::tag.id(), u256be(7)),
        (ns::count.id(), u256be(0)),
    ];
    assert_eq!(fragment.facts().len(), 3);
    check_intrinsic(
        "text_handles",
        &fragment,
        &pairs,
        "D952A4332619FA46B9CAF86A34B50274",
    );
}

#[test]
fn golden_intrinsic_id_empty_entity() {
    let fragment = entity! {};
    check_intrinsic("empty", &fragment, &[], "9BCB25C9ADC112B7CC9A93CAE41F3262");
}

/// A fixed set exercising every tie position: two entities, a shared
/// attribute on both, and two values under one (entity, attribute).
fn fixed_set() -> TribleSet {
    let e1 = id(ENTITY_ONE);
    let e2 = id(ENTITY_TWO);
    let tribles = [
        Trible::force(&e1, &ns::tag.id(), &n(3)),
        Trible::force(&e1, &ns::count.id(), &n(42)),
        Trible::force(&e2, &ns::count.id(), &n(7)),
        Trible::force(&e1, &ns::count.id(), &n(41)),
        Trible::force(&e1, &ns::link.id(), &g(id(TARGET))),
        Trible::force(&e2, &ns::link.id(), &g(e1)),
        // Duplicate insert: must not appear twice.
        Trible::force(&e1, &ns::count.id(), &n(42)),
    ];
    let mut set = TribleSet::new();
    for trible in &tribles {
        set.insert(trible);
    }
    set
}

#[test]
fn golden_simple_archive_bytes() {
    let set = fixed_set();
    assert_eq!(set.len(), 6);

    let blob: Blob<SimpleArchive> = (&set).to_blob();
    let bytes: &[u8] = &blob.bytes;
    let handle = hex_upper(&blob.get_handle().raw);
    println!("GOLDEN archive len = {}", bytes.len());
    println!("GOLDEN archive handle = {handle}");
    println!(
        "GOLDEN archive blake3 = {}",
        blake3::hash(bytes).to_hex().to_ascii_uppercase()
    );
    for (index, row) in bytes.chunks(64).enumerate() {
        println!("GOLDEN archive row {index} = {}", hex_upper(row));
    }

    // Independent layout oracle: rows are the 64 accessor bytes in sorted
    // order, concatenated with no header or padding.
    let mut expected_rows: Vec<[u8; 64]> = set.iter().map(raw).collect();
    expected_rows.sort_unstable();
    expected_rows.dedup();
    let expected: Vec<u8> = expected_rows.concat();
    assert_eq!(
        bytes,
        &expected[..],
        "archive is not the sorted accessor rows"
    );

    const GOLDEN_ROWS: [&str; 6] = [
        "22FF76BE1F4F274D51C226E0A0BB91A907B5DE7D05C41D9301D562F45C2BD30F000000000000000000000000000000009E8A61897BC9E70576E6634DCE637A73",
        "22FF76BE1F4F274D51C226E0A0BB91A98949D4202DE4A164FEAC264478D411E70000000000000000000000000000000000000000000000000000000000000007",
        "9E8A61897BC9E70576E6634DCE637A7307B5DE7D05C41D9301D562F45C2BD30F000000000000000000000000000000006C3397AA84280EF176363B6FF8F52111",
        "9E8A61897BC9E70576E6634DCE637A738949D4202DE4A164FEAC264478D411E70000000000000000000000000000000000000000000000000000000000000029",
        "9E8A61897BC9E70576E6634DCE637A738949D4202DE4A164FEAC264478D411E7000000000000000000000000000000000000000000000000000000000000002A",
        "9E8A61897BC9E70576E6634DCE637A73F4987A1FB24FDEA3F099CB0CAF7C60600000000000000000000000000000000000000000000000000000000000000003",
    ];
    assert_eq!(bytes.len(), 6 * 64);
    for (index, row) in bytes.chunks(64).enumerate() {
        assert_eq!(
            hex_upper(row),
            GOLDEN_ROWS[index],
            "archive row {index} changed"
        );
    }
    assert_eq!(
        handle, "BC409A7F81AA58DF31DE3BE073D9BE9033DCA9B7C8158033C5971E44C66FB6B1",
        "archive handle changed"
    );

    // The archive decodes back to the same set.
    let decoded: TribleSet = blob.try_from_blob().expect("canonical archive decodes");
    assert_eq!(decoded, set);
}

#[test]
fn golden_simple_archive_of_intrinsic_fragment() {
    let fragment = entity! {
        ns::tag: 3u64,
        ns::count: 42u64,
        ns::link: id(TARGET),
    };
    let blob: Blob<SimpleArchive> = fragment.facts().to_blob();
    let handle = hex_upper(&blob.get_handle().raw);
    println!("GOLDEN fragment archive len = {}", blob.bytes.len());
    println!("GOLDEN fragment archive handle = {handle}");
    assert_eq!(blob.bytes.len(), 3 * 64);
    assert_eq!(
        handle, "F76A263AB4608A56C3C70DE5069FFF4740D2EA50766B3AE865445A3DCC47EA40",
        "fragment archive handle changed"
    );
}

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A byte from a tiny alphabet, so that random rows share long prefixes
    /// and comparisons are decided deep inside the 64 bytes.
    fn narrow_byte(&mut self) -> u8 {
        [0x00, 0x01, 0x7F, 0x80, 0xFF][(self.next() % 5) as usize]
    }

    fn row(&mut self) -> [u8; 64] {
        let mut row = [0u8; 64];
        // Mostly-narrow bytes, with an occasional fully random byte.
        for byte in row.iter_mut() {
            *byte = if self.next() % 8 == 0 {
                self.next() as u8
            } else {
                self.narrow_byte()
            };
        }
        row
    }
}

fn sweep_tribles(count: usize, seed: u64) -> Vec<Trible> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let row = rng.row();
        // force_raw refuses nil entities or attributes; those are not tribles.
        if let Some(trible) = Trible::force_raw(row) {
            assert_eq!(
                raw(&trible),
                row,
                "accessor bytes differ from the input row"
            );
            out.push(trible);
        }
    }
    out
}

#[test]
fn trible_ord_agrees_with_byte_lexicographic_order() {
    let tribles = sweep_tribles(20_000, 0x9E37_79B9_7F4A_7C15);
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);

    // Neighbours, random pairs, and every trible against itself.
    for window in tribles.windows(2) {
        let (a, b) = (&window[0], &window[1]);
        assert_eq!(a.cmp(b), raw(a).cmp(&raw(b)));
        assert_eq!(a == b, raw(a) == raw(b));
    }
    for _ in 0..20_000 {
        let a = &tribles[(rng.next() % tribles.len() as u64) as usize];
        let b = &tribles[(rng.next() % tribles.len() as u64) as usize];
        assert_eq!(a.cmp(b), raw(a).cmp(&raw(b)));
        assert_eq!(a.partial_cmp(b), raw(a).partial_cmp(&raw(b)));
    }
    for t in &tribles {
        assert_eq!(t.cmp(t), std::cmp::Ordering::Equal);
    }

    // Pairs differing in exactly one byte, at every position, in both
    // directions: the first differing byte decides, whatever field it is in.
    let base = tribles[0];
    for position in 0..64 {
        let mut low = raw(&base);
        let mut high = raw(&base);
        low[position] = 0x10;
        high[position] = 0x11;
        let (Some(low), Some(high)) = (Trible::force_raw(low), Trible::force_raw(high)) else {
            panic!("single-byte edits of a non-nil row stay non-nil");
        };
        assert!(low < high, "byte {position} does not decide the order");
        assert!(high > low);
    }

    // Sorting by Ord is sorting by bytes.
    let mut by_ord = tribles.clone();
    by_ord.sort();
    let mut by_bytes: Vec<[u8; 64]> = tribles.iter().map(raw).collect();
    by_bytes.sort();
    let by_ord_bytes: Vec<[u8; 64]> = by_ord.iter().map(raw).collect();
    assert_eq!(by_ord_bytes, by_bytes);
}

#[test]
fn tribleset_and_archive_rows_are_strictly_increasing_bytes() {
    let tribles = sweep_tribles(20_000, 0x0123_4567_89AB_CDEF);
    let mut set = TribleSet::new();
    for trible in &tribles {
        set.insert(trible);
    }
    // Re-insert a slice to make sure duplicates do not surface.
    for trible in &tribles[..1_000] {
        set.insert(trible);
    }

    let mut distinct: Vec<[u8; 64]> = tribles.iter().map(raw).collect();
    distinct.sort();
    distinct.dedup();
    assert_eq!(set.len(), distinct.len());

    let ordered: Vec<[u8; 64]> = set.iter_ordered().map(raw).collect();
    assert_eq!(ordered.len(), distinct.len());
    for window in ordered.windows(2) {
        assert!(
            window[0] < window[1],
            "iter_ordered is not strictly increasing"
        );
    }
    assert_eq!(ordered, distinct);

    let blob: Blob<SimpleArchive> = (&set).to_blob();
    let bytes: &[u8] = &blob.bytes;
    assert_eq!(bytes.len(), distinct.len() * 64);
    let rows: Vec<&[u8]> = bytes.chunks(64).collect();
    for window in rows.windows(2) {
        assert!(
            window[0] < window[1],
            "archive rows are not strictly increasing"
        );
    }
    for (row, expected) in rows.iter().zip(&distinct) {
        assert_eq!(*row, &expected[..]);
    }

    // The native iterator yields the same set of rows, whatever its order.
    let mut native: Vec<[u8; 64]> = set.iter().map(raw).collect();
    native.sort();
    assert_eq!(native, distinct);

    let decoded: TribleSet = blob.try_from_blob().expect("canonical archive decodes");
    assert_eq!(decoded, set);
}
