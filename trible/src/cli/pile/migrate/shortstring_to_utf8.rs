//! `trible-migrate <PILE> shortstring-to-utf8`: give old short-text facts their
//! blob-text twins.
//!
//! Text attributes used to be declared with the 32-byte inline `ShortString`
//! encoding and are now declared as `Handle<UTF8String>`. The encoding takes
//! part in an attribute's identity, so the same declaration now names a
//! different attribute id, and facts written under the old id are invisible to
//! code reading the new one. Nothing is wrong with those facts and nothing here
//! touches them. This command appends, for every old fact `(e, old, text)` in a
//! collection's current view, the twin `(e, new, handle(text))` with the text
//! stored as a `UTF8String` blob, in one commit signed by the given key.
//!
//! How the two ids are found, per declaration hex:
//!
//! * `--pinned HEX` was declared `"HEX" unsafe as name: ShortString`, so the
//!   old id is HEX itself;
//! * `--anchored HEX` was declared `"HEX" as name: ShortString`, so the old id
//!   is derived from HEX and the ShortString encoding.
//!
//! Either way the new declaration is `"HEX" as name: Handle<UTF8String>`, and
//! the new id is derived from HEX and that encoding. The ShortString encoding
//! id is kept here as a constant so the backfill keeps working once the type
//! itself is gone.
//!
//! Re-running is a no-op: a twin already in the view is not written again, and
//! a run with nothing to write publishes nothing. A value that is not a valid
//! ShortString (invalid UTF-8, or bytes after its NUL terminator) gets no twin;
//! it is counted and listed, never dropped quietly.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::collection::records::CollectionCommit;
use triblespace_core::collection::{Collection, CollectionStoreExt};
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::id_hex;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::macros::{entity, find};
use triblespace_core::metadata;
use triblespace_core::prelude::TriblePattern;
use triblespace_core::query::Variable;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::{Fragment, Trible, TribleSet};
use triblespace_core::{and, temp};

use super::super::collection::{handle_hex, open_resolved};
use super::super::open_refreshed;

/// The retired `ShortString` inline encoding's id, as its `MetaDescribe`
/// declared it. Kept as a constant so old ids stay derivable after the type is
/// deleted.
pub const SHORT_STRING_ENCODING: Id = id_hex!("2D848DB0AF112DB226A6BF1A3640D019");

/// Append the `Handle<UTF8String>` twin of every old `ShortString` fact.
///
/// Name each retired declaration by its hex, `--pinned` when it was declared
/// `"HEX" unsafe as ..: ShortString` and `--anchored` when it was declared
/// `"HEX" as ..: ShortString`. The old and new ids are printed first. Every
/// old fact in the collection's current view whose twin is not already there
/// gets one, in a single commit signed by the key. Nothing is deleted or
/// rewritten, and a second run writes nothing. Values that do not decode as a
/// ShortString are counted and listed, and get no twin.
#[derive(clap::Args, Debug)]
pub struct ShortstringToUtf8Args {
    /// Collection holding the old facts: name, or descriptor handle (`name:`
    /// / `blake3:` to disambiguate).
    pub collection: String,
    /// Hex of a declaration that was literal-pinned
    /// (`"HEX" unsafe as ..: ShortString`): the old id is HEX itself.
    /// Repeat for several.
    #[arg(long = "pinned", value_name = "HEX")]
    pub pinned: Vec<String>,
    /// Hex of a declaration that was anchored (`"HEX" as ..: ShortString`):
    /// the old id is derived from HEX and the ShortString encoding. Repeat
    /// for several.
    #[arg(long = "anchored", value_name = "HEX")]
    pub anchored: Vec<String>,
    /// Signing key for the commit; the collection's WRITE policy must admit
    /// it. Defaults to TRIBLESPACE_KEY or self.key beside the pile.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Report what would be written without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// How a retired declaration named its old id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Declared {
    /// `"HEX" unsafe as ..: ShortString`.
    Pinned,
    /// `"HEX" as ..: ShortString`.
    Anchored,
}

/// One retired declaration and the two attribute ids it spans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pair {
    pub declared: Declared,
    pub anchor: Id,
    pub old: Id,
    pub new: Id,
}

impl Pair {
    pub(crate) fn new(declared: Declared, anchor: Id) -> Self {
        let old = match declared {
            Declared::Pinned => anchor,
            Declared::Anchored => anchored_id(anchor, SHORT_STRING_ENCODING),
        };
        let new =
            triblespace_core::attribute::Attribute::<Handle<UTF8String>>::anchored(anchor).id();
        Self {
            declared,
            anchor,
            old,
            new,
        }
    }

    fn label(&self) -> String {
        let kind = match self.declared {
            Declared::Pinned => "pinned",
            Declared::Anchored => "anchored",
        };
        format!("{kind} {:X}", self.anchor)
    }
}

/// The id `Attribute::<S>::anchored(anchor)` derives when `S`'s encoding id is
/// `encoding`: the intrinsic id of the same identity core, spelled without the
/// type so a deleted encoding stays derivable.
pub(crate) fn anchored_id(anchor: Id, encoding: Id) -> Id {
    entity! {
        metadata::anchor: GenId::inline_from(anchor),
        metadata::value_encoding: encoding,
        metadata::tag: metadata::KIND_ATTRIBUTE,
    }
    .root()
    .expect("an entity! without an explicit id exports its intrinsic root")
}

/// Decode the retired ShortString layout from its raw 32 bytes: UTF-8, NUL
/// terminated and zero padded, or all 32 bytes when there is no NUL. Mirrors
/// the encoding's own validation (and the legacy branch-name reader in
/// `trible-migrate`).
pub(crate) fn decode_short_string(raw: &[u8; 32]) -> Result<&str, String> {
    let len = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    if raw[len..].iter().any(|&byte| byte != 0) {
        return Err("bytes after its NUL terminator".to_owned());
    }
    std::str::from_utf8(&raw[..len]).map_err(|error| format!("invalid UTF-8: {error}"))
}

/// One old fact that gets no twin, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Undecodable {
    pub entity: Id,
    pub raw: [u8; 32],
    pub reason: String,
}

/// What one declaration found in the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttributeReport {
    pub pair: Pair,
    /// Old facts under the old id.
    pub seen: usize,
    /// Old facts whose twin is already in the view.
    pub present: usize,
    /// Twins this run writes (or would write, on a dry run).
    pub written: usize,
    /// Old facts whose value does not decode, so get no twin.
    pub undecodable: Vec<Undecodable>,
}

/// The whole run: per-declaration counts, and the fragment carrying the twins
/// and their text blobs.
pub(crate) struct Plan {
    pub reports: Vec<AttributeReport>,
    pub fragment: Fragment,
}

impl Plan {
    pub(crate) fn twins(&self) -> usize {
        self.fragment.facts().len()
    }
}

/// Find every old fact in `view` and build the twins it does not yet hold.
pub(crate) fn plan(view: &TribleSet, pairs: &[Pair]) -> Plan {
    let mut fragment = Fragment::empty();
    let mut reports = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let old = GenId::inline_from(pair.old);
        let mut report = AttributeReport {
            pair: *pair,
            seen: 0,
            present: 0,
            written: 0,
            undecodable: Vec::new(),
        };
        let facts: Vec<(Id, Inline<UnknownInline>)> = find!(
            (entity: Id, value: Inline<UnknownInline>),
            temp!(
                (attribute),
                and!(
                    attribute.is(old),
                    view.pattern(entity, attribute, value as Variable<UnknownInline>)
                )
            )
        )
        .collect();
        for (entity, value) in facts {
            report.seen += 1;
            let text = match decode_short_string(&value.raw) {
                Ok(text) => text,
                Err(reason) => {
                    report.undecodable.push(Undecodable {
                        entity,
                        raw: value.raw,
                        reason,
                    });
                    continue;
                }
            };
            let blob: Blob<UTF8String> = text.to_blob();
            let handle = blob.get_handle();
            let twin = Trible::new(ExclusiveId::force_ref(&entity), &pair.new, &handle);
            // Two declarations naming one anchor map to one new id; such a
            // twin is written once, under the first, and present for the rest.
            if view.contains(&twin) || fragment.facts().contains(&twin) {
                report.present += 1;
            } else {
                fragment.facts_mut().insert(&twin);
                fragment.blobs_mut().insert(blob);
                report.written += 1;
            }
        }
        reports.push(report);
    }
    Plan { reports, fragment }
}

/// What a run did: the plan's counts, and the commit if one was made.
pub(crate) struct Outcome {
    pub reports: Vec<AttributeReport>,
    pub twins: usize,
    pub commit: Option<CollectionCommit>,
}

/// Plan against the collection's current view and, unless `dry_run`, commit
/// the twins signed by `signer`.
///
/// The collection's WRITE policy must admit the signer: local storage would
/// take the commit regardless, and every twin would then read as absent.
pub(crate) fn backfill(
    pile: &mut Pile,
    collection: Collection<SimpleArchive>,
    pairs: &[Pair],
    signer: Option<&SigningKey>,
    dry_run: bool,
) -> Result<Outcome> {
    let snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
    let view: TribleSet = collection
        .read(&snapshot)
        .map_err(|error| anyhow!("read collection view: {error}"))?;
    let plan = plan(&view, pairs);
    let twins = plan.twins();
    if dry_run || twins == 0 {
        return Ok(Outcome {
            reports: plan.reports,
            twins,
            commit: None,
        });
    }
    let Some(signer) = signer else {
        bail!("a signing key is needed to write {twins} twins");
    };
    let admitted = collection
        .writer_is_admitted(&snapshot, signer.verifying_key())
        .map_err(|error| anyhow!("check WRITE admission: {error}"))?;
    if !admitted {
        bail!(
            "key {} is not admitted by the collection's WRITE policy; the twins would land and read as absent",
            hex::encode_upper(signer.verifying_key().to_bytes())
        );
    }
    drop(snapshot);
    let commit = pile
        .commit(collection, signer, plan.fragment)
        .map_err(|error| anyhow!("commit twins: {error}"))?;
    Ok(Outcome {
        reports: plan.reports,
        twins,
        commit: Some(commit),
    })
}

fn parse_pairs(pinned: &[String], anchored: &[String]) -> Result<Vec<Pair>> {
    let parse = |flag: &str, text: &str| {
        Id::from_hex(text.trim())
            .ok_or_else(|| anyhow!("--{flag}: {text:?} is not a 32-hex-digit id"))
    };
    let mut pairs = Vec::new();
    for text in pinned {
        pairs.push(Pair::new(Declared::Pinned, parse("pinned", text)?));
    }
    for text in anchored {
        pairs.push(Pair::new(Declared::Anchored, parse("anchored", text)?));
    }
    if pairs.is_empty() {
        bail!("name at least one retired declaration with --pinned HEX or --anchored HEX");
    }
    Ok(pairs)
}

pub fn run(pile_path: PathBuf, args: ShortstringToUtf8Args) -> Result<()> {
    let pairs = parse_pairs(&args.pinned, &args.anchored)?;
    let key_path =
        triblespace_core::signing_key_file::resolve_path(args.key.as_deref(), &pile_path);
    let signer = match triblespace_core::signing_key_file::load_existing(&key_path) {
        Ok(key) => Some(key),
        Err(_) if args.dry_run => None,
        Err(error) => bail!("load signing key {}: {error}", key_path.display()),
    };

    let mut pile = open_refreshed(&pile_path)?;
    let res = (|| -> Result<()> {
        let collection = open_resolved::<SimpleArchive>(&mut pile, &args.collection)?;
        println!("collection: blake3:{}", handle_hex(collection.handle()));
        for pair in &pairs {
            println!("{}: {:X} -> {:X}", pair.label(), pair.old, pair.new);
        }
        let outcome = backfill(&mut pile, collection, &pairs, signer.as_ref(), args.dry_run)?;
        print_outcome(&outcome, args.dry_run);
        Ok(())
    })();
    let close = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close)
}

fn print_outcome(outcome: &Outcome, dry_run: bool) {
    let verb = if dry_run { "would write" } else { "written" };
    for report in &outcome.reports {
        println!(
            "{}: seen {}, already present {}, {verb} {}, undecodable {}",
            report.pair.label(),
            report.seen,
            report.present,
            report.written,
            report.undecodable.len()
        );
        for bad in &report.undecodable {
            println!(
                "  undecodable: entity {:X} value {} ({})",
                bad.entity,
                hex::encode_upper(bad.raw),
                bad.reason
            );
        }
    }
    match &outcome.commit {
        Some(commit) => println!(
            "committed {} twins: data blake3:{}",
            outcome.twins,
            hex::encode(commit.data().raw)
        ),
        None if dry_run => println!("dry run: {} twins, nothing written", outcome.twins),
        None => println!("nothing to write"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

    fn direct(key: &SigningKey) -> CollectionPolicy {
        let root = key.verifying_key();
        CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
    }

    fn short(text: &[u8]) -> Inline<UnknownInline> {
        let mut raw = [0u8; 32];
        raw[..text.len()].copy_from_slice(text);
        Inline::new(raw)
    }

    fn old_fact(entity: Id, attribute: Id, value: Inline<UnknownInline>) -> Trible {
        Trible::new(ExclusiveId::force_ref(&entity), &attribute, &value)
    }

    fn entity(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    #[test]
    #[allow(deprecated)]
    fn the_derivation_matches_the_library_for_both_encodings() {
        use triblespace_core::attribute::Attribute;
        use triblespace_core::inline::encodings::shortstring::ShortString;
        use triblespace_core::metadata::MetaDescribe;

        assert_eq!(<ShortString as MetaDescribe>::id(), SHORT_STRING_ENCODING);
        let anchor = id_hex!("097951EF7FC4C64A4AE9ADBD9ED89482");
        assert_eq!(
            anchored_id(anchor, SHORT_STRING_ENCODING),
            Attribute::<ShortString>::anchored(anchor).id()
        );
        assert_eq!(
            anchored_id(anchor, <Handle<UTF8String> as MetaDescribe>::id()),
            Attribute::<Handle<UTF8String>>::anchored(anchor).id()
        );
    }

    /// The pairs recorded when the attributes moved: one anchored, one pinned.
    #[test]
    fn pairs_reproduce_the_recorded_moves() {
        let field_name = Pair::new(
            Declared::Anchored,
            id_hex!("097951EF7FC4C64A4AE9ADBD9ED89482"),
        );
        assert_eq!(field_name.old, id_hex!("5549CA93F5AF696728172789F1EEBFD0"));
        assert_eq!(field_name.new, id_hex!("1DEC73A8171524D4668AED337F8625FA"));
        let rdf_lang = Pair::new(
            Declared::Pinned,
            id_hex!("904DCA1F8C0BF087B02C0581F69EDF4D"),
        );
        assert_eq!(rdf_lang.old, id_hex!("904DCA1F8C0BF087B02C0581F69EDF4D"));
        assert_eq!(rdf_lang.new, id_hex!("8AFACC1C2E28546AC73EFE57B47A302A"));
    }

    #[test]
    fn the_short_string_layout_decodes_like_the_encoding() {
        assert_eq!(decode_short_string(&[0; 32]), Ok(""));
        let full = [b'x'; 32];
        assert_eq!(decode_short_string(&full), Ok("x".repeat(32).as_str()));
        assert!(decode_short_string(&short(&[0xFF, 0xFE]).raw).is_err());
        let mut trailing = [0u8; 32];
        trailing[0] = b'a';
        trailing[5] = b'b';
        assert!(decode_short_string(&trailing).is_err());
    }

    /// Old pinned and anchored facts get their twins; the 32-byte and empty
    /// values round-trip; an invalid one is reported, not twinned; a second
    /// run writes nothing.
    #[test]
    fn backfill_writes_twins_once_and_reports_what_it_cannot_decode() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("text.pile");
        std::fs::File::create(&path)?;
        let key_path = directory.path().join("self.key");
        let key = triblespace_core::signing_key_file::init(&key_path)?;
        let mut pile = Pile::open(&path)?;
        let collection = pile.collection("legacy-text", direct(&key))?;

        let pinned = Pair::new(
            Declared::Pinned,
            id_hex!("8A4BE2C4D0E90D2B9EE0E1A07ECA2CFA"),
        );
        let anchored = Pair::new(
            Declared::Anchored,
            id_hex!("097951EF7FC4C64A4AE9ADBD9ED89482"),
        );
        let thirty_two = "abcdefghijklmnopqrstuvwxyz012345";
        assert_eq!(thirty_two.len(), 32);

        let mut old = TribleSet::new();
        old.insert(&old_fact(entity(1), pinned.old, short(b"hello")));
        old.insert(&old_fact(
            entity(2),
            pinned.old,
            short(thirty_two.as_bytes()),
        ));
        old.insert(&old_fact(entity(3), anchored.old, short(b"")));
        old.insert(&old_fact(entity(4), anchored.old, short(&[0xC3, 0x28])));
        old.insert(&old_fact(
            entity(5),
            anchored.old,
            short("grüße".as_bytes()),
        ));
        pile.commit(collection, &key, Fragment::from(old.clone()))?;
        pile.flush()?;
        let before = std::fs::metadata(&path)?.len();

        // The dry run writes nothing and says what it would.
        let dry = backfill(&mut pile, collection, &[pinned, anchored], Some(&key), true)?;
        assert!(dry.commit.is_none());
        assert_eq!(dry.twins, 4);
        pile.flush()?;
        assert_eq!(std::fs::metadata(&path)?.len(), before);

        let first = backfill(
            &mut pile,
            collection,
            &[pinned, anchored],
            Some(&key),
            false,
        )?;
        assert!(first.commit.is_some());
        assert_eq!(first.twins, 4);
        let [p, a] = &first.reports[..] else {
            panic!("two reports")
        };
        assert_eq!(
            (p.seen, p.present, p.written, p.undecodable.len()),
            (2, 0, 2, 0)
        );
        assert_eq!(
            (a.seen, a.present, a.written, a.undecodable.len()),
            (3, 0, 2, 1)
        );
        assert_eq!(a.undecodable[0].entity, entity(4));
        assert!(
            a.undecodable[0].reason.contains("UTF-8"),
            "{}",
            a.undecodable[0].reason
        );

        // Every twin reads back through the view, text through its blob.
        let snapshot = pile.snapshot()?;
        let view: TribleSet = collection.read(&snapshot).map_err(|e| anyhow!("{e}"))?;
        assert!(
            old.iter().all(|fact| view.contains(fact)),
            "old facts are untouched"
        );
        for (entity_id, pair, text) in [
            (entity(1), pinned, "hello"),
            (entity(2), pinned, thirty_two),
            (entity(3), anchored, ""),
            (entity(5), anchored, "grüße"),
        ] {
            let handle: Inline<Handle<UTF8String>> =
                IntoBlob::<UTF8String>::to_blob(text).get_handle();
            let twin = Trible::new(ExclusiveId::force_ref(&entity_id), &pair.new, &handle);
            assert!(view.contains(&twin), "twin of {text:?}");
            let stored: Blob<UTF8String> =
                triblespace_core::repo::BlobStoreGet::get(&snapshot, handle)?;
            assert_eq!(&stored.bytes[..], text.as_bytes());
        }
        assert_eq!(view.len(), old.len() + 4);
        drop(snapshot);

        // A second run finds every twin present and commits nothing.
        pile.flush()?;
        let after_first = std::fs::metadata(&path)?.len();
        let second = backfill(
            &mut pile,
            collection,
            &[pinned, anchored],
            Some(&key),
            false,
        )?;
        assert!(second.commit.is_none());
        assert_eq!(second.twins, 0);
        let [p, a] = &second.reports[..] else {
            panic!("two reports")
        };
        assert_eq!((p.seen, p.present, p.written), (2, 2, 0));
        assert_eq!(
            (a.seen, a.present, a.written, a.undecodable.len()),
            (3, 2, 0, 1)
        );
        pile.flush()?;
        assert_eq!(std::fs::metadata(&path)?.len(), after_first);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn a_key_the_collection_does_not_admit_is_refused_before_writing() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("text.pile");
        std::fs::File::create(&path)?;
        let owner = SigningKey::from_bytes(&[3; 32]);
        let stranger = SigningKey::from_bytes(&[4; 32]);
        let mut pile = Pile::open(&path)?;
        let collection = pile.collection("legacy-text", direct(&owner))?;
        let pair = Pair::new(
            Declared::Pinned,
            id_hex!("8A4BE2C4D0E90D2B9EE0E1A07ECA2CFA"),
        );
        let mut old = TribleSet::new();
        old.insert(&old_fact(entity(1), pair.old, short(b"x")));
        pile.commit(collection, &owner, Fragment::from(old))?;
        pile.flush()?;
        let before = std::fs::metadata(&path)?.len();
        let error = backfill(&mut pile, collection, &[pair], Some(&stranger), false)
            .err()
            .expect("an unadmitted signer is refused");
        assert!(error.to_string().contains("not admitted"), "{error}");
        pile.flush()?;
        assert_eq!(std::fs::metadata(&path)?.len(), before);
        pile.close()?;
        Ok(())
    }

    /// The command line end to end: resolve by name, key beside the pile.
    #[test]
    fn the_command_resolves_the_collection_by_name_and_signs_with_the_pile_key() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("text.pile");
        std::fs::File::create(&path)?;
        let key = triblespace_core::signing_key_file::init(&directory.path().join("self.key"))?;
        let pair = Pair::new(
            Declared::Anchored,
            id_hex!("5E3F4C5973047A386688FCFB5C29B03E"),
        );
        {
            let mut pile = Pile::open(&path)?;
            let collection = pile.collection("telemetry", direct(&key))?;
            let mut old = TribleSet::new();
            old.insert(&old_fact(entity(9), pair.old, short(b"worker-one")));
            pile.commit(collection, &key, Fragment::from(old))?;
            pile.close()?;
        }
        let args = |dry_run| ShortstringToUtf8Args {
            collection: "telemetry".to_owned(),
            pinned: Vec::new(),
            anchored: vec!["5E3F4C5973047A386688FCFB5C29B03E".to_owned()],
            key: Some(directory.path().join("self.key")),
            dry_run,
        };
        run(path.clone(), args(true))?;
        run(path.clone(), args(false))?;
        run(path.clone(), args(false))?;

        let mut pile = Pile::open(&path)?;
        pile.refresh()?;
        let collection = open_resolved::<SimpleArchive>(&mut pile, "telemetry")?;
        let snapshot = pile.snapshot()?;
        let view: TribleSet = collection.read(&snapshot).map_err(|e| anyhow!("{e}"))?;
        let handle: Inline<Handle<UTF8String>> =
            IntoBlob::<UTF8String>::to_blob("worker-one").get_handle();
        assert!(view.contains(&Trible::new(
            ExclusiveId::force_ref(&entity(9)),
            &pair.new,
            &handle
        )));
        assert_eq!(view.len(), 2);
        drop(snapshot);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn the_subcommand_parses_as_documented() {
        use clap::Parser;
        let parsed = super::super::Command::try_parse_from([
            "migrate",
            "shortstring-to-utf8",
            "telemetry",
            "--pinned",
            "8A4BE2C4D0E90D2B9EE0E1A07ECA2CFA",
            "--anchored",
            "097951EF7FC4C64A4AE9ADBD9ED89482",
            "--anchored",
            "5E3F4C5973047A386688FCFB5C29B03E",
            "--dry-run",
        ])
        .expect("parses");
        let super::super::Command::ShortstringToUtf8(args) = parsed else {
            panic!("shortstring-to-utf8 parses to its own variant");
        };
        assert_eq!(args.collection, "telemetry");
        assert_eq!(args.pinned.len(), 1);
        assert_eq!(args.anchored.len(), 2);
        assert!(args.dry_run);
        assert!(args.key.is_none());
    }

    #[test]
    fn no_declaration_is_refused() {
        assert!(parse_pairs(&[], &[]).is_err());
        assert!(parse_pairs(&["not-hex".to_owned()], &[]).is_err());
    }
}
