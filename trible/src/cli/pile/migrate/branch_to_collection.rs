//! Direct legacy branch-to-native-collection migration.
//!
//! Validation and publication are separate phases. The first phase freezes the
//! selected pin head, opens one later append-only blob snapshot which contains
//! everything that head can name, validates every reachable commit, and
//! prepares every authored native commit entirely in memory. Only after that
//! succeeds may the second phase append dependencies and final `COMMIT`
//! records to the same pile.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::attribute::Attribute;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionCommit, CollectionPolicy, CollectionRecord,
    CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::shortstring::ShortString;
use triblespace_core::inline::{Inline, InlineEncoding, TryFromInline};
use triblespace_core::metadata;
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::{self, BlobStoreGet, CommitHandle, PinSnapshotSource, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use super::super::signing::load_signing_key;

type ArchiveHandle = Inline<Handle<SimpleArchive>>;
type NameHandle = Inline<Handle<UTF8String>>;

fn private_policy(root: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MigrationReport {
    branch: Id,
    head: Option<CommitHandle>,
    reachable: usize,
    authored: usize,
    contentless_merges: usize,
    unique_targets: usize,
}

pub(super) fn run(
    pile_path: PathBuf,
    branch: String,
    collection_name: String,
    authority: Option<String>,
    signing_key: PathBuf,
) -> Result<()> {
    let signer = load_signing_key(&Some(signing_key))?;
    let authority = authority
        .as_deref()
        .map(|value| parse_public_key(value, "authority"))
        .transpose()?
        .unwrap_or_else(|| signer.verifying_key());

    let mut pile = super::super::open_refreshed(&pile_path)?;
    let result = migrate(&mut pile, &branch, &collection_name, authority, &signer);
    let close = pile.close().map_err(|error| anyhow!("close pile: {error}"));
    let (report, mappings, collection) = result?;
    close?;
    print_report(
        &pile_path,
        &collection_name,
        collection,
        authority,
        signer.verifying_key(),
        report,
        &mappings,
    );
    Ok(())
}

fn parse_public_key(text: &str, label: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(text).map_err(|error| anyhow!("decode {label} hex: {error}"))?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&raw).map_err(|error| anyhow!("invalid {label}: {error}"))
}

fn migrate(
    pile: &mut Pile,
    branch_reference: &str,
    name: &str,
    authority: VerifyingKey,
    signer: &SigningKey,
) -> Result<(
    MigrationReport,
    Vec<(CommitHandle, CollectionCommit)>,
    Collection<SimpleArchive>,
)> {
    // Freeze the mutable names first, then take one append-only blob view.
    // A concurrent append may enter the later reader, but cannot change the
    // selected head; every handle reachable from that frozen head predates it.
    // Native appends later remap `pile`, while this reader keeps the validated
    // legacy bytes alive.
    let pins = pile
        .snapshot_pin_heads()
        .context("snapshot active legacy branch pins")?;
    let snapshot = pile.snapshot().context("snapshot legacy pile")?;
    let (branch, branch_meta) = resolve_branch(&snapshot, &pins, branch_reference)?;
    let head = validate_branch_head(&snapshot, branch, &branch_meta)?;
    let (reachable, contentless_merges, prepared) = match head {
        Some(head) => prepare_reachable(&snapshot, head)?,
        None => (0, 0, Vec::new()),
    };
    let authored = prepared.len();

    // Preparation above performs no I/O. Register the target only after every
    // reachable legacy node has passed validation. The legacy branch had no
    // READ/WRITE split, so the selected trust root controls both actions.
    let collection = pile
        .collection(name, private_policy(authority))
        .map_err(|error| anyhow!("register target collection: {error}"))?;
    let mut mappings = Vec::with_capacity(authored);
    for (source, fragment) in prepared {
        let commit = pile
            .commit(collection, signer, fragment)
            .map_err(|error| anyhow!("publish native collection commit: {error}"))?;
        mappings.push((source, commit));
    }
    mappings.sort_unstable_by_key(|(source, _)| source.raw);

    let unique_targets = mappings
        .iter()
        .map(|(_, target)| *target)
        .collect::<BTreeSet<_>>()
        .len();
    let report = MigrationReport {
        branch,
        head,
        reachable,
        authored,
        contentless_merges,
        unique_targets,
    };
    Ok((report, mappings, collection))
}

fn resolve_branch(
    snapshot: &PileSnapshot,
    pins: &repo::PinSnapshot,
    reference: &str,
) -> Result<(Id, TribleSet)> {
    if let Ok(id) = parse_branch_id(reference) {
        let raw: [u8; 16] = id.into();
        if let Some(handle) = pins.get(&raw).copied() {
            let facts = read_archive(snapshot, handle, "legacy branch metadata")?.1;
            repo::branch::branch_entity(&facts, id)
                .map_err(|_| anyhow!("pin {id:X} does not contain one branch metadata subject"))?;
            return Ok((id, facts));
        }
    }

    let wanted: NameHandle = reference.to_owned().to_blob().get_handle();
    let mut matches = Vec::new();
    for raw in pins.iter_ordered() {
        let id = Id::new(*raw).expect("pin snapshot contains a nil id");
        let handle = *pins.get(raw).expect("iterated pin has a value");
        let (_, facts) = read_archive(snapshot, handle, "legacy branch metadata")?;

        let Ok(subject) = repo::branch::branch_entity(&facts, id) else {
            continue;
        };
        let matches_name = {
            let mut current_names = facts
                .iter()
                .filter(|fact| fact.e() == &subject && fact.a() == &metadata::name.id())
                .map(|fact| *fact.v::<Handle<UTF8String>>());
            let current = current_names.next();
            if current_names.next().is_some() {
                continue;
            }
            match current {
                Some(name) => name == wanted,
                None => legacy_branch_name(&facts, id)?.as_deref() == Some(reference),
            }
        };
        if matches_name {
            matches.push((id, facts));
        }
    }
    match matches.len() {
        0 => bail!("no active legacy branch named {reference:?}"),
        1 => Ok(matches.pop().expect("one branch match")),
        count => bail!("{count} active legacy branches are named {reference:?}; use an id"),
    }
}

/// Read the pre-UTF8-blob branch name used by old repository versions.
///
/// This is intentionally local to the one-way migration. Keeping the decoder
/// here avoids preserving a public legacy branch-construction API merely to
/// resolve old names.
fn legacy_branch_name(facts: &TribleSet, branch: Id) -> Result<Option<String>> {
    let Ok(subject) = repo::branch::branch_entity(facts, branch) else {
        return Ok(None);
    };
    let attribute = triblespace_core::id_hex!("2E26F8BA886495A8DF04ACF0ED3ACBD4");
    let mut names = facts
        .iter()
        .filter(|fact| fact.e() == &subject && fact.a() == &attribute)
        .map(|fact| {
            let value = ShortString::validate(*fact.v::<ShortString>())
                .map_err(|error| anyhow!("invalid legacy branch name: {error:?}"))?;
            String::try_from_inline(&value)
                .map_err(|error| anyhow!("invalid UTF-8 in legacy branch name: {error}"))
        });
    let Some(name) = names.next().transpose()? else {
        return Ok(None);
    };
    if names.next().transpose()?.is_some() {
        return Ok(None);
    }
    Ok(Some(name))
}

fn parse_branch_id(text: &str) -> Result<Id> {
    let bytes = hex::decode(text.trim()).context("not a branch id")?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| anyhow!("not a branch id"))?;
    Id::new(bytes).ok_or_else(|| anyhow!("branch id cannot be nil"))
}

fn validate_branch_head(
    snapshot: &PileSnapshot,
    branch: Id,
    facts: &TribleSet,
) -> Result<Option<CommitHandle>> {
    let subject = repo::branch::branch_entity(facts, branch)
        .map_err(|_| anyhow!("legacy branch {branch:X} has no unique metadata subject"))?;
    let head = one_value(facts, subject, &repo::head, "branch head")?;
    if let Some(head) = head {
        let (blob, _) = read_archive(snapshot, head, "legacy branch head commit")?;
        repo::branch::verify(branch, blob, facts.clone())
            .map_err(|_| anyhow!("legacy branch {branch:X} head signature is invalid"))?;
    }
    Ok(head)
}

fn prepare_reachable(
    snapshot: &PileSnapshot,
    head: CommitHandle,
) -> Result<(usize, usize, Vec<(CommitHandle, Fragment)>)> {
    let empty_metadata: Blob<SimpleArchive> = TribleSet::new().to_blob();
    // Pile reads verify each content address. A reference cycle would require
    // a BLAKE3 fixed point or collision, so set reachability needs no separate
    // active-path cycle state.
    let mut seen = HashSet::new();
    let mut stack = vec![head];
    let mut contentless_merges = 0;
    let mut prepared = Vec::new();

    while let Some(handle) = stack.pop() {
        if !seen.insert(handle) {
            continue;
        }

        let (_, facts) = read_archive(snapshot, handle, "legacy commit wrapper")?;
        let Some(first) = facts.iter().next() else {
            bail!("legacy commit {} has an empty wrapper", handle_hex(handle));
        };
        let subject = *first.e();
        if facts.iter().any(|fact| fact.e() != &subject) {
            bail!(
                "legacy commit {} must contain exactly one wrapper subject",
                handle_hex(handle)
            );
        }

        let content = one_value(&facts, subject, &repo::content, "content")?;
        let metadata = one_value(&facts, subject, &metadata::archive, "metadata archive")?;
        let parents: Vec<CommitHandle> = facts
            .iter()
            .filter(|fact| fact.a() == &repo::parent.id())
            .map(|fact| *fact.v::<Handle<SimpleArchive>>())
            .collect();
        stack.extend(parents.iter().copied());

        if let Some(content) = content {
            let data = read_blob(snapshot, content, "legacy commit content")?;
            repo::commit::verify(data.clone(), facts).map_err(|_| {
                anyhow!(
                    "legacy authored commit {} has an invalid content signature",
                    handle_hex(handle)
                )
            })?;
            let metadata = match metadata {
                Some(handle) => read_blob(snapshot, handle, "legacy commit metadata archive")?,
                None => empty_metadata.clone(),
            };
            let facts = data
                .clone()
                .try_from_blob()
                .with_context(|| format!("decode legacy commit content {}", handle_hex(handle)))?;
            let metafacts = metadata
                .clone()
                .try_from_blob()
                .with_context(|| format!("decode legacy commit metadata {}", handle_hex(handle)))?;
            // Re-wrapping canonical fact sets does not mint or substitute any
            // entity id. `commit` serializes these exact sets back to the same
            // data and metadata handles while signing the native record.
            prepared.push((
                handle,
                Fragment::from_parts(facts, metafacts, Default::default()),
            ));
        } else {
            validate_contentless_merge(&facts, subject, handle, &parents)?;
            contentless_merges += 1;
        }
    }

    Ok((seen.len(), contentless_merges, prepared))
}

fn validate_contentless_merge(
    facts: &TribleSet,
    subject: Id,
    handle: CommitHandle,
    parents: &[CommitHandle],
) -> Result<()> {
    let only_parents = facts
        .iter()
        .all(|fact| fact.e() == &subject && fact.a() == &repo::parent.id());
    let current =
        triblespace_core::macros::entity! { repo::parent*: parents.iter().copied() }.root();
    let historical = triblespace_core::trible::intrinsic_entity_id_v1(
        parents
            .iter()
            .map(|parent| (repo::parent.id(), parent.raw))
            .collect(),
    );
    if parents.len() < 2 || !only_parents || (current != Some(subject) && historical != subject) {
        bail!(
            "contentless legacy commit {} is not a canonical merge",
            handle_hex(handle)
        );
    }
    Ok(())
}

fn read_archive(
    snapshot: &PileSnapshot,
    handle: ArchiveHandle,
    what: &str,
) -> Result<(Blob<SimpleArchive>, TribleSet)> {
    let blob: Blob<SimpleArchive> = snapshot
        .get(handle)
        .with_context(|| format!("read {what} {}", handle_hex(handle)))?;
    let facts = blob
        .clone()
        .try_from_blob()
        .with_context(|| format!("decode canonical {what} {}", handle_hex(handle)))?;
    Ok((blob, facts))
}

fn read_blob(
    snapshot: &PileSnapshot,
    handle: ArchiveHandle,
    what: &str,
) -> Result<Blob<SimpleArchive>> {
    snapshot
        .get(handle)
        .with_context(|| format!("read {what} {}", handle_hex(handle)))
}

fn one_value<V: InlineEncoding>(
    facts: &TribleSet,
    subject: Id,
    attribute: &Attribute<V>,
    field: &str,
) -> Result<Option<Inline<V>>> {
    let mut values = facts
        .iter()
        .filter(|fact| fact.e() == &subject && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>());
    let first = values.next();
    if values.next().is_some() {
        bail!("legacy wrapper subject {subject:X} has repeated {field}");
    }
    Ok(first)
}

fn handle_hex(handle: ArchiveHandle) -> String {
    hex::encode_upper(handle.raw)
}

fn print_report(
    pile_path: &PathBuf,
    name: &str,
    collection: Collection<SimpleArchive>,
    authority: VerifyingKey,
    signer: VerifyingKey,
    report: MigrationReport,
    mappings: &[(CommitHandle, CollectionCommit)],
) {
    println!("same-pile migration: {}", pile_path.display());
    println!("source branch: {:X}", report.branch);
    println!(
        "source head: {}",
        report
            .head
            .map(handle_hex)
            .unwrap_or_else(|| "<none>".to_owned())
    );
    println!("collection name: {name}");
    println!("authority: {}", hex::encode_upper(authority.to_bytes()));
    println!(
        "collection: blake3:{}",
        hex::encode(collection.handle().raw)
    );
    println!("target signer: {}", hex::encode_upper(signer.to_bytes()));
    println!("SOURCE COMMIT                                                     TARGET RECORD FINGERPRINT");
    for (source, target) in mappings {
        println!(
            "{}  {:X}",
            handle_hex(*source),
            CollectionRecord::Commit(*target).fingerprint()
        );
    }
    println!(
        "validated {} reachable node(s): {} authored, {} canonical contentless merge(s) skipped",
        report.reachable, report.authored, report.contentless_merges
    );
    println!(
        "{} source authored node(s) -> {} unique native COMMIT(s) ({} many-to-one collapse(s)); replay is idempotent",
        report.authored,
        report.unique_targets,
        report.authored.saturating_sub(report.unique_targets),
    );
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ed25519_dalek::Signer;
    use tempfile::NamedTempFile;
    use triblespace_core::collection::{CollectionRead, CollectionRecord};
    use triblespace_core::id::ExclusiveId;
    use triblespace_core::patch::Entry;
    use triblespace_core::repo::BlobStorePut;

    use super::*;

    const LEGACY_FIXTURE: &[u8] =
        include_bytes!("../../../../tests/fixtures/legacy_v0464_branch.pile");
    const LEGACY_FIXTURE_HASH: &str =
        "a32cfb8c7bc338c26f62ca28f95cec4873076beed36004134f1f7e571b6b15dc";

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn fact(byte: u8) -> TribleSet {
        let id = Id::new([byte; 16]).unwrap();
        triblespace_core::macros::entity! {
            ExclusiveId::force_ref(&id) @
                metadata::tag: metadata::KIND_MULTI,
        }
        .into_facts()
    }

    fn frozen_fixture() -> Result<(NamedTempFile, Id)> {
        assert_eq!(
            blake3::hash(LEGACY_FIXTURE).to_hex().as_str(),
            LEGACY_FIXTURE_HASH
        );
        let file = NamedTempFile::new()?;
        fs::write(file.path(), LEGACY_FIXTURE)?;
        Ok((file, Id::new([0x42; 16]).unwrap()))
    }

    fn archive_handle(text: &str) -> ArchiveHandle {
        let raw: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
        Inline::new(raw)
    }

    fn authored_wrapper(
        author: &SigningKey,
        parents: impl IntoIterator<Item = CommitHandle>,
        content: &Blob<SimpleArchive>,
        metadata_archive: Option<ArchiveHandle>,
    ) -> TribleSet {
        let content_handle = content.get_handle();
        let signature = author.sign(&content.bytes);
        let parents = parents.into_iter().collect::<Vec<_>>();
        triblespace_core::macros::entity! {
            repo::content: content_handle,
            repo::parent*: parents,
            metadata::archive?: metadata_archive,
            triblespace_core::attestation::signed_by: author.verifying_key(),
            triblespace_core::attestation::signature_r: signature,
            triblespace_core::attestation::signature_s: signature,
        }
        .into_facts()
    }

    #[test]
    fn migration_replays_idempotently_and_preserves_many_to_one_collapse() -> Result<()> {
        let (file, branch) = frozen_fixture()?;
        let path = file.path().to_path_buf();
        let name = "events";
        let signer = key(3);
        let authority = signer.verifying_key();

        let mut pile = super::super::super::open_refreshed(&path)?;
        let (first, first_map, collection) =
            migrate(&mut pile, "legacy", name, authority, &signer)?;
        assert_eq!(first.branch, branch);
        assert_eq!(first.reachable, 5);
        assert_eq!(first.authored, 4);
        assert_eq!(first.contentless_merges, 1);
        assert_eq!(first.unique_targets, 3);
        assert_eq!(first_map.len(), 4);

        let c1 = archive_handle("FCFB841A8429723FEB019ABEABB64DDC36CA7D0413DD88451AFFD3E809B63EF7");
        let c2 = archive_handle("30955980A1F6196A5CCB4E4B40E1799CEADFD09808797FE7265407BDDE47A5F1");
        let c1_target = first_map
            .iter()
            .find(|(source, _)| *source == c1)
            .map(|(_, target)| *target)
            .expect("C1 mapping");
        let c2_target = first_map
            .iter()
            .find(|(source, _)| *source == c2)
            .map(|(_, target)| *target)
            .expect("C2 mapping");
        assert_eq!(c1_target, c2_target);

        let expected_metadata = fact(9).to_blob().get_handle();
        assert!(first_map
            .iter()
            .all(|(_, target)| target.metadata() == expected_metadata));

        let mut expected_union = fact(1);
        expected_union += fact(2);
        expected_union += fact(3);
        let snapshot = pile.snapshot()?;
        let materialized: TribleSet = collection
            .read(&snapshot)
            .map_err(|error| anyhow!("materialize migrated collection: {error}"))?;
        assert_eq!(materialized, expected_union);

        pile.flush()?;
        let first_len = fs::metadata(&path)?.len();
        let (second, second_map, second_collection) =
            migrate(&mut pile, &format!("{branch:X}"), name, authority, &signer)?;
        pile.flush()?;
        assert_eq!(second, first);
        assert_eq!(second_collection, collection);
        assert_eq!(
            first_map
                .iter()
                .map(|(source, target)| (source.raw, *target))
                .collect::<Vec<_>>(),
            second_map
                .iter()
                .map(|(source, target)| (source.raw, *target))
                .collect::<Vec<_>>()
        );
        assert_eq!(fs::metadata(&path)?.len(), first_len);
        let target = collection.handle();
        let snapshot = pile.snapshot()?;
        assert_eq!(
            snapshot
                .records()?
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|record| {
                    matches!(record, triblespace_core::collection::CollectionRecord::Commit(commit) if commit.collection() == target)
                })
                .count(),
            3
        );
        pile.close()?;
        Ok(())
    }

    #[test]
    fn distinct_authority_does_not_block_publication_but_needs_delegation_to_read() -> Result<()> {
        let (file, _) = frozen_fixture()?;
        let path = file.path().to_path_buf();
        let signer = key(12);
        let authority = key(13).verifying_key();
        let mut pile = super::super::super::open_refreshed(&path)?;

        let (_, mappings, collection) =
            migrate(&mut pile, "legacy", "delegated-events", authority, &signer)?;

        assert!(!mappings.is_empty(), "migration still publishes locally");
        let snapshot = pile.snapshot()?;
        assert!(collection
            .admitted(&snapshot)
            .map_err(|error| anyhow!("read unauthorized cover: {error}"))?
            .is_empty());
        assert!(snapshot
            .records()?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|record| {
                matches!(record, CollectionRecord::Commit(commit) if commit.collection() == collection.handle())
            }));
        pile.close()?;
        Ok(())
    }

    #[test]
    fn authored_empty_and_absent_metadata_survive_while_merge_is_skipped() -> Result<()> {
        let file = NamedTempFile::new()?;
        let mut pile = Pile::open(file.path())?;
        let author = key(8);

        let empty: Blob<SimpleArchive> = TribleSet::new().to_blob();
        pile.put::<SimpleArchive, _>(empty.clone())?;
        let empty_wrapper = authored_wrapper(&author, [], &empty, None);
        let empty_commit = pile.put::<SimpleArchive, _>(empty_wrapper)?;

        let data: Blob<SimpleArchive> = fact(9).to_blob();
        pile.put::<SimpleArchive, _>(data.clone())?;
        let data_wrapper = authored_wrapper(&author, [], &data, None);
        let data_commit = pile.put::<SimpleArchive, _>(data_wrapper)?;

        let merge_wrapper = triblespace_core::macros::entity! {
            repo::parent*: [empty_commit, data_commit],
        }
        .into_facts();
        let merge_commit = pile.put::<SimpleArchive, _>(merge_wrapper)?;

        let collection_name = "empty-preserved";
        let signer = key(11);
        let snapshot = pile.snapshot()?;
        let (reachable, contentless_merges, prepared) = prepare_reachable(&snapshot, merge_commit)?;

        assert_eq!(reachable, 3);
        assert_eq!(contentless_merges, 1);
        assert_eq!(prepared.len(), 2);
        let collection =
            pile.collection(collection_name, private_policy(signer.verifying_key()))?;
        let mut mappings = Vec::new();
        for (source, fragment) in prepared {
            let target = pile
                .commit(collection, &signer, fragment)
                .map_err(|error| anyhow!("publish test migration: {error}"))?;
            mappings.push((source, target));
        }

        let empty_metadata = TribleSet::new().to_blob().get_handle();
        let empty_target = mappings
            .iter()
            .find(|(source, _)| *source == empty_commit)
            .map(|(_, target)| *target)
            .expect("authored empty commit has a mapping");
        assert_eq!(empty_target.data().raw, empty.get_handle().raw);
        assert_eq!(empty_target.metadata(), empty_metadata);
        let data_target = mappings
            .iter()
            .find(|(source, _)| *source == data_commit)
            .map(|(_, target)| *target)
            .expect("authored data commit has a mapping");
        assert_eq!(data_target.data().raw, data.get_handle().raw);
        assert_eq!(data_target.metadata(), empty_metadata);

        let snapshot = pile.snapshot()?;
        let materialized: TribleSet = collection
            .read(&snapshot)
            .map_err(|error| anyhow!("materialize authored-empty fixture: {error}"))?;
        assert_eq!(materialized, fact(9));
        pile.close()?;
        Ok(())
    }

    #[test]
    fn hex_shaped_legacy_name_falls_back_from_absent_id() -> Result<()> {
        mod legacy {
            use triblespace_core::macros::attributes;
            use triblespace_core::prelude::inlineencodings;

            attributes! {
                "2E26F8BA886495A8DF04ACF0ED3ACBD4" unsafe as name: inlineencodings::ShortString;
            }
        }

        let file = NamedTempFile::new()?;
        let mut pile = Pile::open(file.path())?;
        let branch = Id::new([0xE9; 16]).unwrap();
        let hex_name = "ABABABABABABABABABABABABABABABAB";
        let legacy_meta = triblespace_core::macros::entity! {
            repo::branch: branch,
            legacy::name: hex_name,
        }
        .into_facts();
        let legacy_meta = pile.put::<SimpleArchive, _>(legacy_meta)?;

        let mut pins = repo::PinSnapshot::new();
        let raw: [u8; 16] = branch.into();
        pins.insert(&Entry::with_value(&raw, legacy_meta));
        let snapshot = pile.snapshot()?;
        let (resolved, _) = resolve_branch(&snapshot, &pins, hex_name)?;
        assert_eq!(resolved, branch);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn authored_random_wrapper_subject_remains_valid_legacy_input() -> Result<()> {
        let file = NamedTempFile::new()?;
        let mut pile = Pile::open(file.path())?;
        let author = key(4);
        let content: Blob<SimpleArchive> = fact(4).to_blob();
        let content_handle = pile.put::<SimpleArchive, _>(content.clone())?;
        let signature = author.sign(&content.bytes);
        let subject = Id::new([0xA5; 16]).unwrap();
        let wrapper = triblespace_core::macros::entity! {
            ExclusiveId::force_ref(&subject) @
                repo::content: content_handle,
                triblespace_core::attestation::signed_by: author.verifying_key(),
                triblespace_core::attestation::signature_r: signature,
                triblespace_core::attestation::signature_s: signature,
        }
        .into_facts();
        let handle = pile.put::<SimpleArchive, _>(wrapper)?;
        let snapshot = pile.snapshot()?;

        let (_, wrapper) = read_archive(&snapshot, handle, "random-subject wrapper")?;
        assert_eq!(
            one_value(&wrapper, subject, &repo::content, "content")?,
            Some(content_handle)
        );
        let (reachable, merges, prepared) = prepare_reachable(&snapshot, handle)?;
        assert_eq!((reachable, merges, prepared.len()), (1, 0, 1));
        pile.close()?;
        Ok(())
    }

    #[test]
    fn invalid_reachable_signature_writes_no_collection_record() -> Result<()> {
        let file = NamedTempFile::new()?;
        let mut pile = Pile::open(file.path())?;
        let author = key(5);

        let valid_content: Blob<SimpleArchive> = fact(4).to_blob();
        pile.put::<SimpleArchive, _>(valid_content.clone())?;
        let valid_wrapper = authored_wrapper(&author, [], &valid_content, None);
        let valid_parent = pile.put::<SimpleArchive, _>(valid_wrapper)?;

        let content: Blob<SimpleArchive> = fact(5).to_blob();
        let content_handle = pile.put::<SimpleArchive, _>(content.clone())?;
        let wrong_signature = author.sign(b"not the content archive");
        let subject = Id::new([0xB6; 16]).unwrap();
        let wrapper = triblespace_core::macros::entity! {
            ExclusiveId::force_ref(&subject) @
                repo::content: content_handle,
                repo::parent: valid_parent,
                triblespace_core::attestation::signed_by: author.verifying_key(),
                triblespace_core::attestation::signature_r: wrong_signature,
                triblespace_core::attestation::signature_s: wrong_signature,
        }
        .into_facts();
        let wrapper = pile.put::<SimpleArchive, _>(wrapper)?;

        let snapshot = pile.snapshot()?;
        let error = prepare_reachable(&snapshot, wrapper)
            .expect_err("bad authored signature must reject the whole migration");
        assert!(error.to_string().contains("invalid content signature"));
        assert!(snapshot
            .records()?
            .collect::<Result<Vec<_>, _>>()?
            .is_empty());
        pile.close()?;
        Ok(())
    }
}
