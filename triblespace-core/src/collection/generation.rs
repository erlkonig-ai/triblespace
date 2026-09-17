//! Same-named collection generations, and the records they strand.
//!
//! A collection's identity is the handle of its descriptor blob, so *any*
//! change to what a descriptor says — including the encoding of its admission
//! policy — mints a different collection under the same name. Nothing about
//! that is visible at the call site: a caller registers the name it has always
//! used, receives the current generation's handle, finds it empty, and carries
//! on. The previous generation's records are still resident and still signed;
//! they are simply no longer referenced by anything that asks for the name.
//!
//! That silence is the whole problem. Four such cutovers landed in nine days in
//! one pile, each re-minting every named root at once, and none announced
//! itself. They were noticed three weeks later because somebody thought the
//! collection *count* looked wrong, which is not a detection mechanism.
//!
//! This module answers the question that would have caught it on the day:
//! *does another collection in this store carry the same name, and does it hold
//! commits this one does not?* The trigger is the **existence of a same-named
//! sibling**, never emptiness on its own — a genuinely new collection on a
//! fresh pile has no siblings and reports nothing at all.
//!
//! Two outcomes are worth telling apart, and [`GenerationReport`] does:
//!
//! - **Stranded.** A sibling holds commits the selected generation lacks. Those
//!   records are unreachable through the name and need a migration.
//! - **Superseded.** Siblings exist but everything they hold is also in the
//!   selected generation. The leftovers are inert, and saying so is how a
//!   completed migration proves it completed.
//!
//! Comparison is by `(data, metadata)` pair rather than by record identity,
//! because that pair is exactly what re-signing a commit into another
//! collection reproduces. Two commits of the same payload under different
//! authors are the same *content*, and counting them as different rows would
//! report a migration as incomplete forever.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::{Blob, TryFromBlob};
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::repo::BlobStoreGet;
use crate::trible::{Fragment, TribleSet};

use super::discovery::CollectionDiscoveryError;
use super::{descriptor, CollectionData, CollectionHandle, CollectionRead, CollectionRecord};

/// The content one collection holds: the `(data, metadata)` pair of each commit.
type CommitContent = BTreeSet<(CollectionData, Inline<Handle<SimpleArchive>>)>;

/// One collection sharing a name with another, and what it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationRecords {
    handle: CollectionHandle,
    commits: usize,
    stranded: usize,
}

impl GenerationRecords {
    /// The descriptor handle that identifies this generation.
    pub fn handle(&self) -> CollectionHandle {
        self.handle
    }

    /// Distinct `(data, metadata)` pairs committed to this generation.
    pub fn commits(&self) -> usize {
        self.commits
    }

    /// Pairs held here that the selected generation does not hold.
    ///
    /// Always zero for the selected generation itself.
    pub fn stranded(&self) -> usize {
        self.stranded
    }
}

/// Every collection in one store that shares a name with a selected one.
///
/// Produced by [`named_generations`]. A report exists only when at least one
/// same-named sibling was found, so holding one is already the finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationReport {
    name: String,
    selected: GenerationRecords,
    siblings: Vec<GenerationRecords>,
}

impl GenerationReport {
    /// The name all of these collections claim.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The generation the caller resolved.
    pub fn selected(&self) -> &GenerationRecords {
        &self.selected
    }

    /// Other collections claiming the same name, most stranded first.
    pub fn siblings(&self) -> &[GenerationRecords] {
        &self.siblings
    }

    /// Total pairs held by siblings and not by the selected generation.
    pub fn stranded_records(&self) -> usize {
        self.siblings.iter().map(GenerationRecords::stranded).sum()
    }

    /// Whether any sibling holds content the selected generation cannot reach.
    ///
    /// `false` means the siblings are inert leftovers of a migration that did
    /// complete; `true` means records are unreachable through this name.
    pub fn strands_records(&self) -> bool {
        self.stranded_records() > 0
    }
}

impl fmt::Display for GenerationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stranded = self.stranded_records();
        if stranded > 0 {
            writeln!(
                f,
                "collection {:?} has {} other generation(s) in this store holding {stranded} \
                 record(s) it cannot reach",
                self.name,
                self.siblings.len(),
            )?;
        } else {
            writeln!(
                f,
                "collection {:?} has {} superseded generation(s) in this store; every record \
                 they hold is also here",
                self.name,
                self.siblings.len(),
            )?;
        }
        writeln!(
            f,
            "  selected  {}  {} record(s)",
            hex::encode(self.selected.handle.raw),
            self.selected.commits,
        )?;
        for sibling in &self.siblings {
            writeln!(
                f,
                "  other     {}  {} record(s), {} not reachable from the selected one",
                hex::encode(sibling.handle.raw),
                sibling.commits,
                sibling.stranded,
            )?;
        }
        if stranded > 0 {
            write!(
                f,
                "a descriptor change re-mints a collection under the same name; the fix is to \
                 migrate the records forward, not to adopt the older handle as the live one"
            )?;
        } else {
            write!(f, "nothing is unreachable; no migration is outstanding")?;
        }
        Ok(())
    }
}

/// Read one collection's name from its descriptor, if it has a readable one.
///
/// Open world: a descriptor that is absent, undecodable, or carries no name is
/// simply not a candidate for sharing a name. It is never an error here.
fn readable_name<S>(snapshot: &S, collection: CollectionHandle) -> Option<String>
where
    S: BlobStoreGet,
{
    let blob: Blob<SimpleArchive> = snapshot.get(collection).ok()?;
    let facts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob).ok()?;
    let handle = descriptor::name(&facts).ok()??;
    let name: Blob<UTF8String> = snapshot.get(handle).ok()?;
    std::str::from_utf8(&name.bytes).ok().map(str::to_owned)
}

/// Every collection's committed content, from one walk of the record stream.
fn commit_content<S>(
    snapshot: &S,
) -> Result<BTreeMap<CollectionHandle, CommitContent>, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead,
{
    let mut content: BTreeMap<CollectionHandle, CommitContent> = BTreeMap::new();
    let records = snapshot
        .records()
        .map_err(CollectionDiscoveryError::Records)?;
    for record in records {
        let record = record.map_err(CollectionDiscoveryError::Records)?;
        if let CollectionRecord::Commit(commit) = record {
            content
                .entry(commit.collection())
                .or_default()
                .insert((commit.data(), commit.metadata()));
        }
    }
    Ok(content)
}

/// Find every collection in `snapshot` that claims the same name as `selected`.
///
/// Returns `None` when there is nothing to say: the selected descriptor carries
/// no readable name (it is derived, or from a generation this build cannot
/// read), or no other collection claims that name. A fresh collection on a
/// fresh pile therefore reports nothing, which is the point — emptiness alone
/// is not the signal, a same-named sibling holding records is.
///
/// This walks the store's records once and reads one descriptor per collection
/// that holds commits. It is a diagnostic, not something to put in a hot path.
pub fn named_generations<S>(
    snapshot: &S,
    selected: CollectionHandle,
) -> Result<Option<GenerationReport>, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead + BlobStoreGet,
{
    let Some(name) = readable_name(snapshot, selected) else {
        return Ok(None);
    };

    let content = commit_content(snapshot)?;

    let here = content.get(&selected).cloned().unwrap_or_default();
    let mut siblings: Vec<GenerationRecords> = content
        .iter()
        .filter(|(handle, _)| **handle != selected)
        .filter(|(handle, _)| readable_name(snapshot, **handle).as_deref() == Some(name.as_str()))
        .map(|(handle, theirs)| GenerationRecords {
            handle: *handle,
            commits: theirs.len(),
            stranded: theirs.difference(&here).count(),
        })
        .collect();

    if siblings.is_empty() {
        return Ok(None);
    }

    siblings.sort_by(|a, b| {
        b.stranded
            .cmp(&a.stranded)
            .then(b.commits.cmp(&a.commits))
            .then(a.handle.raw.cmp(&b.handle.raw))
    });

    Ok(Some(GenerationReport {
        name,
        selected: GenerationRecords {
            handle: selected,
            commits: here.len(),
            stranded: 0,
        },
        siblings,
    }))
}

/// Every name in this store claimed by more than one collection.
///
/// The sweep form, for asking the question of a whole pile rather than of one
/// handle a caller already resolved. Because nothing here knows which
/// generation a given build would resolve, the member holding the most records
/// is used as the basis for comparison and the rest are reported against it.
/// That is a heuristic and is labelled as one: to ask the exact question, pass
/// the handle your build actually resolves to [`named_generations`].
///
/// Walks the record stream once and reads each collection's descriptor once.
/// Groups are ordered most-stranded first, so the pile's worst problem is the
/// first thing printed.
pub fn all_named_generations<S>(
    snapshot: &S,
) -> Result<Vec<GenerationReport>, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead + BlobStoreGet,
{
    let content = commit_content(snapshot)?;
    let mut by_name: BTreeMap<String, Vec<(CollectionHandle, &CommitContent)>> = BTreeMap::new();
    for (handle, held) in &content {
        if let Some(name) = readable_name(snapshot, *handle) {
            by_name.entry(name).or_default().push((*handle, held));
        }
    }

    let mut reports = Vec::new();
    for (name, mut members) in by_name {
        if members.len() < 2 {
            continue;
        }
        // Largest first: the presumptive current generation.
        members.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.raw.cmp(&b.0.raw)));
        let (basis, here) = members[0];
        let mut siblings: Vec<GenerationRecords> = members[1..]
            .iter()
            .map(|(handle, theirs)| GenerationRecords {
                handle: *handle,
                commits: theirs.len(),
                stranded: theirs.difference(here).count(),
            })
            .collect();
        siblings.sort_by(|a, b| {
            b.stranded
                .cmp(&a.stranded)
                .then(b.commits.cmp(&a.commits))
                .then(a.handle.raw.cmp(&b.handle.raw))
        });
        reports.push(GenerationReport {
            name,
            selected: GenerationRecords {
                handle: basis,
                commits: here.len(),
                stranded: 0,
            },
            siblings,
        });
    }
    reports.sort_by(|a, b| {
        b.stranded_records()
            .cmp(&a.stranded_records())
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(reports)
}

/// Compare two exact collections, whichever names they carry.
///
/// [`named_generations`] answers "is something hiding behind this name?".
/// This answers the narrower question a migration needs: *after adopting
/// `source` into `target`, is anything left behind?* It is the completeness
/// assertion that adopting on its own does not provide — a re-signing pass
/// reports how many records it processed, not how many the target was missing,
/// so a partial migration looks exactly like a complete one.
///
/// Counts distinct `(data, metadata)` pairs, so a target that already holds a
/// payload under a different author counts as holding it.
pub fn unreached_records<S>(
    snapshot: &S,
    source: CollectionHandle,
    target: CollectionHandle,
) -> Result<usize, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead,
{
    let mut from = CommitContent::new();
    let mut into = CommitContent::new();
    let records = snapshot
        .records()
        .map_err(CollectionDiscoveryError::Records)?;
    for record in records {
        let record = record.map_err(CollectionDiscoveryError::Records)?;
        if let CollectionRecord::Commit(commit) = record {
            let collection = commit.collection();
            if collection == source {
                from.insert((commit.data(), commit.metadata()));
            } else if collection == target {
                into.insert((commit.data(), commit.metadata()));
            }
        }
    }
    Ok(from.difference(&into).count())
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;

    use crate::collection::policy::{AdmissionPolicy, CollectionPolicy};
    use crate::collection::CollectionStoreExt;
    use crate::metadata;
    use crate::prelude::entity;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::SnapshotSource;

    fn signer(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn private(key: &SigningKey) -> CollectionPolicy {
        CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        )
    }

    fn row(tag: u8) -> Fragment {
        entity! { metadata::tag: crate::id::Id::new([tag; 16]).unwrap() }
    }

    /// The case that must stay silent: a genuinely new collection.
    ///
    /// Emptiness is not the signal. A fresh faculty against a fresh pile has no
    /// records and no siblings, and warning there would train everyone to
    /// ignore the warning that matters.
    #[test]
    fn a_collection_with_no_same_named_sibling_reports_nothing() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let fresh = store.collection("wiki", private(&key)).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(named_generations(&snapshot, fresh.handle())
            .unwrap()
            .is_none());

        // Still nothing once it holds records of its own.
        let mut store = store;
        store.commit(fresh, &key, row(0x11)).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(named_generations(&snapshot, fresh.handle())
            .unwrap()
            .is_none());
    }

    /// The case that must be loud: a same-named sibling holding unreachable rows.
    #[test]
    fn a_same_named_sibling_with_unreachable_rows_is_reported() {
        let old_key = signer(1);
        let new_key = signer(2);
        let mut store = MemoryRepo::default();
        let old = store.collection("wiki", private(&old_key)).unwrap();
        let new = store.collection("wiki", private(&new_key)).unwrap();
        // Same name, different descriptors: this is the re-mint.
        assert_ne!(old.handle(), new.handle());

        store.commit(old, &old_key, row(0x11)).unwrap();
        store.commit(old, &old_key, row(0x22)).unwrap();
        store.commit(new, &new_key, row(0x11)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let report = named_generations(&snapshot, new.handle())
            .unwrap()
            .expect("a same-named sibling exists");
        assert_eq!(report.name(), "wiki");
        assert_eq!(report.selected().handle(), new.handle());
        assert_eq!(report.selected().commits(), 1);
        assert_eq!(report.siblings().len(), 1);
        assert_eq!(report.siblings()[0].handle(), old.handle());
        assert_eq!(report.siblings()[0].commits(), 2);
        assert_eq!(report.siblings()[0].stranded(), 1);
        assert!(report.strands_records());
        assert_eq!(report.stranded_records(), 1);

        let rendered = report.to_string();
        assert!(rendered.contains("cannot reach"));
        assert!(rendered.contains(&hex::encode(old.handle().raw)));
        assert!(rendered.contains(&hex::encode(new.handle().raw)));
    }

    /// A completed migration proves it completed: siblings, but nothing stranded.
    #[test]
    fn a_fully_superseded_sibling_reports_no_stranded_records() {
        let old_key = signer(1);
        let new_key = signer(2);
        let mut store = MemoryRepo::default();
        let old = store.collection("compass", private(&old_key)).unwrap();
        let new = store.collection("compass", private(&new_key)).unwrap();

        store.commit(old, &old_key, row(0x11)).unwrap();
        // The same payload re-signed into the new generation under a different
        // author is the same content, and must not count as stranded.
        store.commit(new, &new_key, row(0x11)).unwrap();
        store.commit(new, &new_key, row(0x22)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let report = named_generations(&snapshot, new.handle())
            .unwrap()
            .expect("a same-named sibling exists");
        assert_eq!(report.stranded_records(), 0);
        assert!(!report.strands_records());
        assert!(report.to_string().contains("no migration is outstanding"));
    }

    /// A different name is a different collection, not a generation.
    #[test]
    fn collections_with_different_names_are_not_generations_of_each_other() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let wiki = store.collection("wiki", private(&key)).unwrap();
        let compass = store.collection("compass", private(&key)).unwrap();
        store.commit(wiki, &key, row(0x11)).unwrap();
        store.commit(compass, &key, row(0x22)).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(named_generations(&snapshot, wiki.handle())
            .unwrap()
            .is_none());
    }

    /// The completeness assertion an adopt does not give you.
    #[test]
    fn unreached_records_counts_what_a_migration_would_leave_behind() {
        let old_key = signer(1);
        let new_key = signer(2);
        let mut store = MemoryRepo::default();
        let old = store.collection("message", private(&old_key)).unwrap();
        let new = store.collection("message", private(&new_key)).unwrap();
        store.commit(old, &old_key, row(0x11)).unwrap();
        store.commit(old, &old_key, row(0x22)).unwrap();
        store.commit(new, &new_key, row(0x11)).unwrap();

        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            unreached_records(&snapshot, old.handle(), new.handle()).unwrap(),
            1
        );
        // The other direction is already complete.
        assert_eq!(
            unreached_records(&snapshot, new.handle(), old.handle()).unwrap(),
            0
        );
    }
}
