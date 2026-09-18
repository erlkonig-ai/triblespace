//! Exact record ancestry endorsed by a signed collection equation.
//!
//! This walk establishes closure, not a second authorization decision. The
//! caller admits the selected producer; that producer attests the validity of
//! these exact input records. No ancestor payload, metadata, capability proof,
//! or signature is read or checked here. Missing records remain unknown, never
//! an empty support and never an instruction to disclose another collection.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;

use super::api::AdmissionEvidence;
use super::{
    Collection, CollectionData, CollectionHandle, CollectionRead, CollectionRecord,
    CollectionRecordFingerprint, Support,
};
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::repo::StoreRead;

/// Operation-local memoization of immutable record references. Not persisted.
///
/// A closed record's support is a property of that record's own immutable
/// witness DAG and of the descriptor lineage naming each `DERIVE`'s source.
/// Records are content addressed and storage is grow-only, so one operation
/// establishes it once and every later resolution over the same lineage reads
/// the same answer. Both inputs are remembered here: a different lineage names
/// different sources and starts a new memo rather than answering from the old
/// one.
///
/// Only closed results are retained. That a record is not *yet* closed is an
/// absence in one snapshot rather than a fact about the record, and the same
/// operation may close it by publishing the witness it was missing.
#[derive(Default)]
pub(super) struct WitnessMemo {
    lineage: Option<(
        Collection<SimpleArchive>,
        BTreeMap<CollectionHandle, CollectionHandle>,
    )>,
    records: BTreeMap<CollectionRecordFingerprint, CollectionRecord>,
    /// Support of one LOGICAL VALUE, not of one record that asserts it.
    ///
    /// `Support` is documented as "denotational support shared by every
    /// representation of one logical value", so it is a property of
    /// `(collection, payload)` and never of the particular record that
    /// happened to publish it. Keying it that way also shrinks the memo from
    /// one entry per assertion to one per value.
    support: BTreeMap<(CollectionHandle, CollectionData), Support>,
}

impl WitnessMemo {
    /// Open one resolution over `foundation` and `source_by_target`, reusing
    /// whatever an earlier resolution over that same lineage established.
    pub(super) fn closure<'a>(
        &'a mut self,
        foundation: Collection<SimpleArchive>,
        source_by_target: &'a BTreeMap<CollectionHandle, CollectionHandle>,
        writers: &'a BTreeMap<CollectionHandle, AdmissionEvidence>,
    ) -> WitnessClosure<'a> {
        let bound = self
            .lineage
            .as_ref()
            .is_some_and(|(known, sources)| *known == foundation && sources == source_by_target);
        if !bound {
            self.records.clear();
            self.support.clear();
            self.lineage = Some((foundation, source_by_target.clone()));
        }
        WitnessClosure {
            memo: self,
            foundation,
            source_by_target,
            writers,
            unresolved: BTreeSet::new(),
            groups: None,
            grounded: BTreeSet::new(),
        }
    }
}

pub(super) fn output(record: CollectionRecord) -> CollectionData {
    super::coverage::Attestation::of(&record).result()
}

/// One resolution's walk over a [`WitnessMemo`].
pub(super) struct WitnessClosure<'a> {
    memo: &'a mut WitnessMemo,
    foundation: Collection<SimpleArchive>,
    source_by_target: &'a BTreeMap<CollectionHandle, CollectionHandle>,
    /// Who may WRITE each collection, so an attestation can be believed or
    /// discarded ONCE, while the edge index is built.
    writers: &'a BTreeMap<CollectionHandle, AdmissionEvidence>,
    unresolved: BTreeSet<(CollectionHandle, CollectionData)>,
    /// Believed payload-to-payload relations in THIS snapshot, and the values
    /// grounded directly by a foundation commit.
    ///
    /// Records do not appear here. A record is an attestation ABOUT a
    /// relationship between payloads; once we have decided to believe it the
    /// relationship is the fact and the record has done its job. Indexing
    /// records instead reifies the evidence and makes every later walk
    /// re-examine what it already accepted.
    ///
    /// Both are `(collection, to, from)` and prefix-walkable on
    /// `(collection, to)`; their natural home is a PATCH keyed the same way.
    /// Three fields rather than four, because a derived collection's
    /// descriptor names its source and hashes into its id -- so the collection
    /// an input lives in follows from knowing whether the edge is a JOIN or a
    /// MAPPING, and that is carried by which relation holds it rather than by
    /// a repeated field.
    ///
    /// Grouped by producing record, not flattened. The union over a group is
    /// what a value CORRESPONDS TO, and correspondence is all-or-nothing: a
    /// join of `a` and `d` corresponds to `{a, d}`, and if `d` cannot be
    /// resolved its set is UNKNOWN, not `{a}`. Reporting the resolvable part
    /// would silently narrow it, and a narrower set passes a subset test it
    /// should fail -- which is how an artifact built over `{a, d}` would come
    /// to be used for a view over `{a}` and quietly answer with `d` in it.
    ///
    /// Across groups it is a union: two producers of one value are two ways it
    /// could have been built, and either resolving is enough.
    ///
    /// Belief is decided once, while these are built, so walking is pure.
    /// Scoped to the closure rather than the memo: a record not yet present is
    /// an absence in one snapshot, never a fact about the record, and the same
    /// operation may publish the input that closes it.
    groups: Option<BTreeMap<(CollectionHandle, CollectionData), Vec<Vec<(CollectionHandle, CollectionData)>>>>,
    grounded: BTreeSet<(CollectionHandle, CollectionData)>,
}

impl WitnessClosure<'_> {
    /// Ground one record's output in the foundation, iteratively so an
    /// arbitrarily deep retained history does not consume the call stack.
    ///
    /// The walk is over VALUES, not over cited records. An equation states
    /// that payloads combine; which record asserted an input is not part of
    /// that statement, and binding it made support narrower than the facts
    /// warrant -- a reader holding a different but equally admitted assertion
    /// of the same payload had the support and was told it did not.
    pub(super) fn support<R: StoreRead>(
        &mut self,
        snapshot: &R,
        root: CollectionRecord,
    ) -> Result<Option<Support>, R::RecordsError> {
        self.index_edges(snapshot)?;
        let root_key = (root.collection(), output(root));
        self.close(root_key);
        Ok(self.memo.support.get(&root_key).cloned())
    }

    /// Decide once which attestations to believe, and keep only the payload
    /// relationships they assert.
    ///
    /// An attestation is believed when its author may WRITE the collection it
    /// speaks about. That is the same check the caller already makes for the
    /// record it starts from; making it here applies it to every edge instead
    /// of only the first, which is what a cited witness was standing in for.
    /// Trust is transitive: a believed MERGE says its inputs join to its
    /// result, and we do not recompute that -- whoever signed it checked its
    /// inputs were themselves attested, and stopped there for the same reason.
    ///
    /// Done once per snapshot, so a value reached by many paths costs one
    /// decision rather than one per path.
    fn index_edges<R: StoreRead>(&mut self, snapshot: &R) -> Result<(), R::RecordsError> {
        if self.groups.is_some() {
            return Ok(());
        }
        let mut groups: BTreeMap<
            (CollectionHandle, CollectionData),
            Vec<Vec<(CollectionHandle, CollectionData)>>,
        > = BTreeMap::new();
        for record in snapshot.records()? {
            let record = record?;
            let collection = record.collection();
            // Retained regardless of belief: `records_for` answers which
            // records to keep and transfer, and that question is about what
            // exists, not about what this walk was willing to traverse.
            self.memo.records.insert(record.fingerprint(), record);
            // An attestation is believed when its AUTHOR may WRITE the
            // collection it speaks about. Nothing here concerns who is
            // reading: a reader with no write authority of its own still
            // resolves everything an admitted author published.
            let believed = VerifyingKey::from_bytes(&record.public_key().raw)
                .ok()
                .is_some_and(|subject| {
                    self.writers
                        .get(&collection)
                        .is_some_and(|writers| writers.authorizes(snapshot, subject))
                });
            if !believed {
                continue;
            }
            match record {
                CollectionRecord::Commit(commit) => {
                    // A commit into the foundation grounds its own payload.
                    // Nothing above it needs walking.
                    if collection == self.foundation.handle() {
                        self.grounded.insert((collection, commit.data()));
                    }
                }
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    let result = merge.result();
                    groups
                        .entry((collection, result))
                        .or_default()
                        .push(vec![(collection, low), (collection, high)]);
                }
                CollectionRecord::Derive(derive) => {
                    if let Some(source) = self.source_by_target.get(&collection) {
                        groups
                            .entry((collection, derive.output()))
                            .or_default()
                            .push(vec![(*source, derive.input())]);
                    }
                }
            }
        }
        self.groups = Some(groups);
        Ok(())
    }

    /// What one value CORRESPONDS TO: the foundation commits below it.
    ///
    /// Downward through the lattice, iteratively so a deep history does not
    /// consume the call stack. A group is one way the value could have been
    /// built and resolves all-or-nothing; across groups the sets union,
    /// because either way of building it is a way it could have been built.
    fn close(&mut self, root: (CollectionHandle, CollectionData)) {
        let mut pending = vec![(root, false)];
        let mut visiting = BTreeSet::new();
        while let Some((key, settle)) = pending.pop() {
            if self.memo.support.contains_key(&key) || self.unresolved.contains(&key) {
                continue;
            }
            if self.grounded.contains(&key) {
                let (_, data) = key;
                self.memo
                    .support
                    .insert(key, Support::from_data(self.foundation, [data]));
                continue;
            }
            let groups = self.groups(key);
            if groups.is_empty() {
                self.unresolved.insert(key);
                continue;
            }
            if settle {
                visiting.remove(&key);
                let mut known: Option<Support> = None;
                for group in &groups {
                    let mut set = Support::from_data(self.foundation, []);
                    let mut whole = true;
                    for input in group {
                        match self.memo.support.get(input) {
                            Some(part) => set = set.union(part).expect("one foundation"),
                            None => {
                                // One unresolved input makes the whole group
                                // unknown, never a smaller set.
                                whole = false;
                                break;
                            }
                        }
                    }
                    if whole {
                        known = Some(match known {
                            Some(seen) => seen.union(&set).expect("one foundation"),
                            None => set,
                        });
                    }
                }
                match known {
                    Some(set) => {
                        self.memo.support.insert(key, set);
                    }
                    None => {
                        self.unresolved.insert(key);
                    }
                }
                continue;
            }
            if !visiting.insert(key) {
                self.unresolved.insert(key);
                continue;
            }
            pending.push((key, true));
            for group in groups {
                pending.extend(group.into_iter().map(|input| (input, false)));
            }
        }
    }

    /// The ways this value could have been built, one entry per producer.
    fn groups(
        &self,
        key: (CollectionHandle, CollectionData),
    ) -> Vec<Vec<(CollectionHandle, CollectionData)>> {
        self.groups
            .as_ref()
            .and_then(|groups| groups.get(&key))
            .cloned()
            .unwrap_or_default()
    }

    /// Retain the exact closed witness DAG reachable from accepted producers.
    /// Unrelated equations sharing a payload hash never enter this set.
    pub(super) fn records_for(
        &self,
        roots: impl IntoIterator<Item = CollectionRecordFingerprint>,
    ) -> Vec<CollectionRecord> {
        let mut selected = BTreeSet::new();
        let mut pending: Vec<_> = roots.into_iter().collect();
        while let Some(id) = pending.pop() {
            if !selected.insert(id) {
                continue;
            }
            let record = self.memo.records[&id];
            pending.extend(record.record_references());
        }
        selected
            .into_iter()
            .map(|id| self.memo.records[&id])
            .collect()
    }
}
