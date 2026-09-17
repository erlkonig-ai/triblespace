//! Moving content between collections, and proving it arrived.
//!
//! A collection is the handle of its descriptor blob, so any change to what a
//! descriptor says — a policy value, an encoding, a word of prose caught inside
//! the identity — mints a *different* collection under the same name. The
//! records of the previous one stay resident and stay signed; nothing points at
//! them any more. [`super::generation`] is the detector for that. This module
//! is the repair: it carries the previous generation's content forward, and it
//! answers, by content, whether the carry is finished.
//!
//! Three properties decide everything here.
//!
//! **Carrying is re-signing, never a pointer.** A record naming the old
//! collection is admitted under the *old* policy. Unioning it into the new
//! collection at read time would let anyone holding the retired key write into
//! the stronger generation. So each carried assertion is signed afresh, by a
//! key the target admits, and the old record stays exactly where it is.
//!
//! **Re-signing is byte-deterministic, which is what makes this idempotent.** A
//! COMMIT is `(collection, data, metadata, author)` plus an Ed25519 signature
//! over exactly those, and Ed25519 signing is deterministic. Signing the same
//! tuple under the same key therefore reproduces the same bytes, the same
//! fingerprint, and the grow-only record set absorbs it without appending
//! anything. Running a migration twice is free — *if the key is the same one*.
//! Under a different author every record is new, so the key choice, not the
//! content, decides how much gets written. That is why [`MigrationSurvey`]
//! reports net-new against `(target, data, metadata, signer)` and not against
//! the source count: the source count is identical on the first run, the second
//! run, and with the wrong key, and so tells an operator nothing.
//!
//! **What the source's own policy never admitted must not be promoted in
//! silence.** Local storage is a claim ledger: `commit` performs no capability
//! check, so any process with pile-write access can append a COMMIT naming any
//! collection, and admission filters it out at read time. A carry that walks
//! raw records re-signs those claims under an admitted key and *launders* them
//! into the new generation. The survey therefore splits each source's content
//! by whether the source's own WRITE policy admits an author who asserted it,
//! and [`Scope`] makes the caller say which of the two it means. Neither answer
//! is silent: dropping content is the failure this module exists to prevent,
//! and promoting unadmitted content is a privilege escalation.
//!
//! Comparison is by the `(data, metadata)` pair, matching
//! [`super::generation::unreached_records`]. That pair is exactly what
//! re-signing reproduces, so the same payload under two different authors is
//! one piece of content, not two.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::repo::{BlobStoreGet, BlobStoreMeta, CapabilityProofRead, StoreSnapshot};

use super::discovery::CollectionDiscoveryError;
use super::records::CollectionCommit;
use super::{
    Collection, CollectionData, CollectionHandle, CollectionRead, CollectionRecord, CollectionStore,
};

/// The content one COMMIT asserts: its data archive and its metadata archive.
///
/// Identity for every comparison in this module. Two commits carrying this same
/// pair under different authors assert the same content.
pub type CommitPair = (CollectionData, Inline<Handle<SimpleArchive>>);

/// Which of a source's content a caller means.
///
/// The distinction is not a refinement; it is the difference between a
/// migration and a privilege escalation, so there is no default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Only content asserted by an author the source's own WRITE policy
    /// admits. This is what a reader of the source could ever see, and
    /// carrying it forward changes no authority.
    Admitted,
    /// Every content pair committed to the source, including assertions its
    /// own policy never admitted. Re-signing these promotes them into the
    /// target; that is a deliberate act and belongs to whoever runs it.
    All,
}

/// One source collection, and what it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSurvey {
    handle: CollectionHandle,
    admitted: BTreeSet<CommitPair>,
    unadmitted: BTreeSet<CommitPair>,
    policy_readable: bool,
    authors: usize,
    admitted_authors: usize,
    invalid: usize,
    other_records: usize,
}

impl SourceSurvey {
    /// The descriptor handle of this source.
    pub fn handle(&self) -> CollectionHandle {
        self.handle
    }

    /// Content pairs asserted by an author this source's WRITE policy admits.
    pub fn admitted(&self) -> &BTreeSet<CommitPair> {
        &self.admitted
    }

    /// Content pairs whose every asserting author this source excludes.
    ///
    /// These read as absent from the source itself. Carrying them forward
    /// makes them admitted content of the target, signed by the target's key.
    pub fn unadmitted(&self) -> &BTreeSet<CommitPair> {
        &self.unadmitted
    }

    /// Whether this build could read the source descriptor's WRITE policy.
    ///
    /// Open world: a descriptor that is absent, of an encoding this build does
    /// not model, or carrying a policy shape it cannot decode is not an error.
    /// Nothing it holds can be shown to be admitted, so all of it lands in
    /// [`Self::unadmitted`] and the caller is told the policy was unreadable
    /// rather than told the content was excluded.
    pub fn policy_readable(&self) -> bool {
        self.policy_readable
    }

    /// Distinct authors who committed to this source.
    pub fn authors(&self) -> usize {
        self.authors
    }

    /// How many of those authors the source's WRITE policy admits.
    pub fn admitted_authors(&self) -> usize {
        self.admitted_authors
    }

    /// Commits whose embedded signature does not verify, and were ignored.
    pub fn invalid_signatures(&self) -> usize {
        self.invalid
    }

    /// Records of this source that are not COMMITs.
    ///
    /// MERGE and DERIVE records are equations *about* a collection's own
    /// members, not exogenous content, so they are not carried: the target's
    /// maintenance re-derives its own. Counted rather than ignored, because an
    /// operator should never have to guess what a tool passed over.
    pub fn other_records(&self) -> usize {
        self.other_records
    }

    /// Distinct content pairs committed to this source, admitted or not.
    pub fn pairs(&self) -> usize {
        self.admitted.len() + self.unadmitted.len()
    }

    /// The content this source offers under `scope`.
    pub fn content(&self, scope: Scope) -> impl Iterator<Item = &CommitPair> {
        let unadmitted = match scope {
            Scope::Admitted => None,
            Scope::All => Some(self.unadmitted.iter()),
        };
        self.admitted.iter().chain(unadmitted.into_iter().flatten())
    }
}

/// What one carry would move, and what it would append.
///
/// Produced by [`survey`] from a single frozen snapshot, so every figure in it
/// describes one consistent view of the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationSurvey {
    target: CollectionHandle,
    signer: Option<VerifyingKey>,
    sources: Vec<SourceSurvey>,
    target_content: BTreeSet<CommitPair>,
    target_by_signer: BTreeSet<CommitPair>,
    target_other_records: usize,
    target_invalid: usize,
}

impl MigrationSurvey {
    /// The collection content is being carried into.
    pub fn target(&self) -> CollectionHandle {
        self.target
    }

    /// The key whose re-signing was priced, if one was supplied.
    pub fn signer(&self) -> Option<VerifyingKey> {
        self.signer
    }

    /// The surveyed sources, in the order they were requested.
    pub fn sources(&self) -> &[SourceSurvey] {
        &self.sources
    }

    /// Whether the target already holds this content, under any author.
    pub fn holds(&self, pair: &CommitPair) -> bool {
        self.target_content.contains(pair)
    }

    /// Distinct content pairs the target already holds, under any author.
    pub fn target_pairs(&self) -> usize {
        self.target_content.len()
    }

    /// Distinct content pairs the target already holds under the survey's key.
    ///
    /// These are precisely the records re-signing would reproduce byte for
    /// byte, and therefore the reason a repeated migration appends nothing.
    pub fn target_pairs_by_signer(&self) -> usize {
        self.target_by_signer.len()
    }

    /// Non-COMMIT records already in the target.
    pub fn target_other_records(&self) -> usize {
        self.target_other_records
    }

    /// Commits of the target whose signature does not verify.
    ///
    /// They assert nothing, so the content they name still counts as missing
    /// and a carry writes the record its key genuinely signs.
    pub fn target_invalid_signatures(&self) -> usize {
        self.target_invalid
    }

    /// Everything the sources offer under `scope`, deduplicated across them.
    pub fn carried(&self, scope: Scope) -> BTreeSet<CommitPair> {
        self.sources
            .iter()
            .flat_map(|source| source.content(scope))
            .copied()
            .collect()
    }

    /// Content the sources hold and the target does not, under any author.
    ///
    /// This is what the target *gains*. It is independent of the key, and it is
    /// the number that answers "is the migration finished?".
    pub fn missing(&self, scope: Scope) -> BTreeSet<CommitPair> {
        self.carried(scope)
            .into_iter()
            .filter(|pair| !self.target_content.contains(pair))
            .collect()
    }

    /// Records a carry under this survey's key would actually append.
    ///
    /// The comparison is against `(target, data, metadata, signer)` — the exact
    /// tuple a re-signing produces — so a second run of an applied migration
    /// reports zero, and a run under a key that did not author the target's
    /// existing records reports all of them.
    ///
    /// Empty when no key was supplied: without one there is nothing to price.
    pub fn net_new(&self, scope: Scope) -> BTreeSet<CommitPair> {
        if self.signer.is_none() {
            return BTreeSet::new();
        }
        self.carried(scope)
            .into_iter()
            .filter(|pair| !self.target_by_signer.contains(pair))
            .collect()
    }

    /// Records that would be appended while adding no content the target lacks.
    ///
    /// Re-authoring content the target already holds under someone else. Large
    /// here means the wrong key: the write is redundant, it collapses
    /// authorship, and it is exactly how tens of thousands of surplus records
    /// get written by a tool that only counted its source.
    pub fn redundant(&self, scope: Scope) -> BTreeSet<CommitPair> {
        self.net_new(scope)
            .into_iter()
            .filter(|pair| self.target_content.contains(pair))
            .collect()
    }

    /// Content the target holds that none of these sources does.
    ///
    /// The other direction, and the one a pairwise comparison cannot ask: with
    /// every source of a migration in one survey, whatever is left in the
    /// target came from somewhere else. While a new generation is not yet live
    /// that should be empty, and anything in it is content the carrying key
    /// introduced rather than moved. Once the generation is live its own
    /// writers fill it legitimately, so this is a window, not an invariant —
    /// which is why it is reported and never gated on.
    pub fn unsourced(&self) -> BTreeSet<CommitPair> {
        let carried = self.carried(Scope::All);
        self.target_content
            .iter()
            .filter(|pair| !carried.contains(pair))
            .copied()
            .collect()
    }

    /// Content pairs held only by authors their own source excludes.
    pub fn unadmitted(&self) -> BTreeSet<CommitPair> {
        self.sources
            .iter()
            .flat_map(|source| source.unadmitted().iter())
            .copied()
            .collect()
    }
}

/// Failure of [`survey`]: only the record walk can fail.
///
/// Everything else this module reads — a descriptor, a policy, a proof — is
/// open world. Unreadable means "nothing can be shown about it", never "stop".
pub type SurveyError<E> = CollectionDiscoveryError<E>;

/// Survey what carrying `sources` into `target` would move and append.
///
/// One walk of the record stream, then one WRITE admission decision per
/// distinct `(source, author)` pair. `signer` prices the re-signing; pass
/// `None` to ask the content question alone, as a completeness check does.
///
/// A source equal to the target contributes nothing and is skipped: carrying a
/// collection into itself is a no-op, not an error.
pub fn survey<S>(
    snapshot: &S,
    sources: &[CollectionHandle],
    target: CollectionHandle,
    signer: Option<VerifyingKey>,
) -> Result<MigrationSurvey, SurveyError<S::RecordsError>>
where
    S: CollectionRead + StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    let wanted: BTreeSet<CollectionHandle> = sources
        .iter()
        .copied()
        .filter(|source| *source != target)
        .collect();

    // Per source: which authors asserted each content pair, so an admission
    // decision per author can split the content afterwards.
    let mut held: BTreeMap<CollectionHandle, BTreeMap<CommitPair, BTreeSet<[u8; 32]>>> =
        BTreeMap::new();
    let mut invalid: BTreeMap<CollectionHandle, usize> = BTreeMap::new();
    let mut other: BTreeMap<CollectionHandle, usize> = BTreeMap::new();
    let mut target_content = BTreeSet::new();
    let mut target_by_signer = BTreeSet::new();
    let mut target_other = 0usize;
    let mut target_invalid = 0usize;

    let signer_bytes = signer.map(|key| key.to_bytes());

    let records = snapshot
        .records()
        .map_err(CollectionDiscoveryError::Records)?;
    for record in records {
        let record = record.map_err(CollectionDiscoveryError::Records)?;
        let collection = record.collection();
        let is_target = collection == target;
        let is_source = wanted.contains(&collection);
        if !is_target && !is_source {
            continue;
        }
        let CollectionRecord::Commit(commit) = &record else {
            // A record kind this carry does not model is passed over and
            // counted. It is never fatal: refusing the whole migration because
            // one equation is not a membership assertion would strand every
            // record behind it.
            if is_target {
                target_other += 1;
            } else {
                *other.entry(collection).or_default() += 1;
            }
            continue;
        };
        if commit.verify_strict().is_err() {
            // An unverifiable signature is not an assertion. On a source it
            // carries no author claim, and the author claim is what the
            // admission split is about; on the target it does not make the
            // target hold anything, so the content is still missing and the
            // carry replaces it with the record its key genuinely signs.
            *invalid.entry(collection).or_default() += 1;
            if is_target {
                target_invalid += 1;
            }
            continue;
        }
        let pair = (commit.data(), commit.metadata());
        if is_target {
            target_content.insert(pair);
            if Some(commit.public_key().raw) == signer_bytes {
                target_by_signer.insert(pair);
            }
            continue;
        }
        held.entry(collection)
            .or_default()
            .entry(pair)
            .or_default()
            .insert(commit.public_key().raw);
    }

    let mut surveyed = Vec::new();
    for source in sources.iter().copied() {
        if source == target {
            continue;
        }
        let content = held.remove(&source).unwrap_or_default();
        let opened = Collection::<SimpleArchive>::open(snapshot, source).ok();
        let policy_readable = opened.is_some();

        // Decide the whole author set up front rather than as each pair asks.
        // A collection has a handful of writers, so the cost is the same; what
        // changes is that the reported author counts describe the source
        // rather than describing whichever authors a short-circuit happened to
        // reach first.
        let authors: BTreeSet<[u8; 32]> = content.values().flatten().copied().collect();
        let mut admitted_authors: BTreeSet<[u8; 32]> = BTreeSet::new();
        if let Some(collection) = opened {
            for raw in &authors {
                let admitted = VerifyingKey::from_bytes(raw)
                    .ok()
                    .and_then(|key| collection.writer_is_admitted(snapshot, key).ok())
                    .unwrap_or(false);
                if admitted {
                    admitted_authors.insert(*raw);
                }
            }
        }

        let mut admitted = BTreeSet::new();
        let mut unadmitted = BTreeSet::new();
        for (pair, asserted_by) in content {
            // One admitted author is enough: the content is readable from this
            // source, so carrying it forward changes nothing about authority.
            if asserted_by.iter().any(|raw| admitted_authors.contains(raw)) {
                admitted.insert(pair);
            } else {
                unadmitted.insert(pair);
            }
        }
        surveyed.push(SourceSurvey {
            handle: source,
            admitted,
            unadmitted,
            policy_readable,
            authors: authors.len(),
            admitted_authors: admitted_authors.len(),
            invalid: invalid.remove(&source).unwrap_or_default(),
            other_records: other.remove(&source).unwrap_or_default(),
        });
    }

    Ok(MigrationSurvey {
        target,
        signer,
        sources: surveyed,
        target_content,
        target_by_signer,
        target_other_records: target_other,
        target_invalid,
    })
}

/// Carry content into `target` by signing each pair afresh.
///
/// Nothing is decoded and nothing is minted: the data and metadata handles a
/// source commit already names are signed again as a COMMIT of `target`. That
/// keeps the carry open world — a payload this build cannot parse, or one whose
/// blob is not even resident, moves as the claim it is — and it removes the
/// only way re-encoding could silently relocate content by producing a
/// different handle.
///
/// Pass [`MigrationSurvey::net_new`] to write only what is not already there;
/// passing more is safe but pointless, because a record the store already holds
/// is absorbed without appending a byte. Returns how many records were signed.
pub fn carry<S>(
    store: &mut S,
    target: CollectionHandle,
    signer: &SigningKey,
    pairs: &BTreeSet<CommitPair>,
) -> Result<usize, S::InsertError>
where
    S: CollectionStore,
{
    for (data, metadata) in pairs {
        let commit = CollectionCommit::sign(signer, target, *data, *metadata);
        store.insert(CollectionRecord::Commit(commit))?;
    }
    Ok(pairs.len())
}

/// Which of these content pairs name blobs this store does not hold.
///
/// A commit is a claim about content, and the claim is what moves; the payload
/// may be somewhere else entirely. Carrying such a record forward is correct —
/// dropping it would lose the only reference to the content — but an operator
/// should be told, because a migration that moves claims does not move bytes.
pub fn unresident<S>(snapshot: &S, pairs: &BTreeSet<CommitPair>) -> Result<usize, S::MetaError>
where
    S: BlobStoreMeta,
{
    let mut missing = 0;
    for (data, metadata) in pairs {
        let data: Inline<Handle<SimpleArchive>> = Inline::new(data.raw);
        if snapshot.metadata(data)?.is_none() || snapshot.metadata(*metadata)?.is_none() {
            missing += 1;
        }
    }
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::collection::policy::{AdmissionPolicy, CollectionPolicy};
    use crate::collection::records::{CollectionCommit, CollectionMerge};
    use crate::collection::{grant_collection_write, CollectionStoreExt};
    use crate::id::Id;
    use crate::metadata;
    use crate::prelude::entity;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::SnapshotSource;
    use crate::trible::Fragment;

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
        entity! { metadata::tag: Id::new([tag; 16]).unwrap() }
    }

    /// Every record in the store, so a test can say "this appended nothing".
    fn record_count(store: &mut MemoryRepo) -> usize {
        store
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .filter_map(Result::ok)
            .count()
    }

    /// A retired generation, its current generation, and the key each uses.
    struct Cutover {
        store: MemoryRepo,
        old: Collection<SimpleArchive>,
        new: Collection<SimpleArchive>,
        old_key: SigningKey,
        new_key: SigningKey,
    }

    fn cutover(rows: &[u8]) -> Cutover {
        let old_key = signer(1);
        let new_key = signer(2);
        let mut store = MemoryRepo::default();
        let old = store.collection("wiki", private(&old_key)).unwrap();
        let new = store.collection("wiki", private(&new_key)).unwrap();
        assert_ne!(old.handle(), new.handle(), "the re-mint under one name");
        for tag in rows {
            store.commit(old, &old_key, row(*tag)).unwrap();
        }
        Cutover {
            store,
            old,
            new,
            old_key,
            new_key,
        }
    }

    /// The whole operation: carry, and prove nothing was left behind.
    #[test]
    fn a_carry_moves_content_and_then_reconciles_complete() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11, 0x22, 0x33]);

        let snapshot = store.snapshot().unwrap();
        let before = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(before.sources()[0].admitted().len(), 3);
        assert_eq!(before.missing(Scope::Admitted).len(), 3);
        assert_eq!(before.net_new(Scope::Admitted).len(), 3);
        assert_eq!(before.redundant(Scope::Admitted).len(), 0);

        let appended = carry(
            &mut store,
            new.handle(),
            &new_key,
            &before.net_new(Scope::Admitted),
        )
        .unwrap();
        assert_eq!(appended, 3);

        let snapshot = store.snapshot().unwrap();
        let after = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(
            after.missing(Scope::Admitted).len(),
            0,
            "nothing left behind"
        );
        assert_eq!(after.target_pairs(), 3);
        // And the detector built for the same question agrees.
        assert_eq!(
            super::super::generation::unreached_records(&snapshot, old.handle(), new.handle())
                .unwrap(),
            0
        );
    }

    /// The dry run's promise: the number it prints is the number written.
    ///
    /// The old adopt printed its *source* count, which is the same figure on a
    /// first run, a second run, and under a key that reproduces nothing. This
    /// asserts the figure against what the store actually grows by.
    #[test]
    fn the_net_new_figure_is_exactly_what_a_carry_appends() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11, 0x22, 0x33, 0x44]);
        // The target already holds one of them, under its own key.
        store.commit(new, &new_key, row(0x11)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let predicted = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap()
        .net_new(Scope::Admitted);
        assert_eq!(predicted.len(), 3, "four pairs, one already committed here");

        let before = record_count(&mut store);
        carry(&mut store, new.handle(), &new_key, &predicted).unwrap();
        assert_eq!(record_count(&mut store) - before, predicted.len());
    }

    /// Re-signing is deterministic, so the second run is free.
    #[test]
    fn a_second_migration_appends_nothing() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11, 0x22, 0x33]);

        let snapshot = store.snapshot().unwrap();
        let first = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        carry(
            &mut store,
            new.handle(),
            &new_key,
            &first.net_new(Scope::Admitted),
        )
        .unwrap();
        let settled = record_count(&mut store);

        let snapshot = store.snapshot().unwrap();
        let second = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(
            second.net_new(Scope::Admitted).len(),
            0,
            "a repeated migration has nothing to do"
        );
        // Carrying everything anyway is still a no-op in the store.
        carry(
            &mut store,
            new.handle(),
            &new_key,
            &second.carried(Scope::Admitted),
        )
        .unwrap();
        assert_eq!(record_count(&mut store), settled);
    }

    /// The regression test for a migration that quietly under-delivered.
    ///
    /// A previous cutover left 428 archives behind and neither the carry nor
    /// its dry run said so. Here the shortfall is constructed deliberately: a
    /// carry that moves three of five pairs must be *reported* as incomplete,
    /// by content, and the two that are missing must be nameable.
    #[test]
    fn a_deliberately_incomplete_migration_is_detected_and_named() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11, 0x22, 0x33, 0x44, 0x55]);

        let snapshot = store.snapshot().unwrap();
        let full = survey(&snapshot, &[old.handle()], new.handle(), None).unwrap();
        let everything = full.carried(Scope::Admitted);
        assert_eq!(everything.len(), 5);
        let partial: BTreeSet<CommitPair> = everything.iter().take(3).copied().collect();
        let withheld: BTreeSet<CommitPair> = everything.difference(&partial).copied().collect();
        carry(&mut store, new.handle(), &new_key, &partial).unwrap();

        // Standalone: no key, no migration in flight, just the question.
        let snapshot = store.snapshot().unwrap();
        let check = survey(&snapshot, &[old.handle()], new.handle(), None).unwrap();
        let missing = check.missing(Scope::Admitted);
        assert_eq!(missing.len(), 2, "the shortfall is counted");
        assert_eq!(missing, withheld, "and it names exactly what is absent");
        assert_eq!(check.sources()[0].admitted().len(), 5);
        assert_eq!(check.target_pairs(), 3);
    }

    /// The key decides the size of the write, and the survey says so.
    ///
    /// Adopting under the target's own writer reproduces its existing records
    /// byte for byte and appends only what is new. Under any other author every
    /// record is new, and the surplus adds no content at all. A tool that
    /// cannot tell these apart is how tens of thousands of redundant records
    /// get written.
    #[test]
    fn the_wrong_key_appends_everything_and_gains_nothing_extra() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11, 0x22, 0x33, 0x44]);
        // Three of the four are already here, authored by the target's writer.
        for tag in [0x11, 0x22, 0x33] {
            store.commit(new, &new_key, row(tag)).unwrap();
        }
        let stranger = signer(9);

        let snapshot = store.snapshot().unwrap();
        let right = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        let wrong = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(stranger.verifying_key()),
        )
        .unwrap();

        assert_eq!(right.net_new(Scope::Admitted).len(), 1);
        assert_eq!(right.redundant(Scope::Admitted).len(), 0);
        assert_eq!(wrong.net_new(Scope::Admitted).len(), 4);
        assert_eq!(
            wrong.redundant(Scope::Admitted).len(),
            3,
            "three writes that add no content the target lacks"
        );
        // Both gain the same content: the key changes the cost, not the result.
        assert_eq!(
            right.missing(Scope::Admitted),
            wrong.missing(Scope::Admitted)
        );

        // And it is true in the store, not just in the arithmetic.
        let before = record_count(&mut store);
        carry(
            &mut store,
            new.handle(),
            &stranger,
            &wrong.net_new(Scope::Admitted),
        )
        .unwrap();
        assert_eq!(record_count(&mut store) - before, 4);
    }

    /// Content the source's own policy never admitted is kept separate.
    ///
    /// Local storage is a claim ledger: `commit` performs no capability check,
    /// so anything with write access can append a COMMIT naming any collection
    /// and the source's policy filters it out at read time. Re-signing it under
    /// the target's key promotes it. The survey must not blur the two.
    #[test]
    fn content_the_source_never_admitted_is_separated_from_content_it_did() {
        let Cutover {
            mut store,
            old,
            new,
            old_key,
            new_key,
        } = cutover(&[0x11, 0x22]);
        let intruder = signer(7);
        // Admitted nowhere, and yet the record lands: that is the ledger.
        store.commit(old, &intruder, row(0x99)).unwrap();
        assert!(!old
            .writer_is_admitted(&store.snapshot().unwrap(), intruder.verifying_key())
            .unwrap());

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        let source = &view.sources()[0];
        assert_eq!(source.admitted().len(), 2);
        assert_eq!(source.unadmitted().len(), 1);
        assert_eq!(source.authors(), 2);
        assert_eq!(source.admitted_authors(), 1);
        assert!(source.policy_readable());
        assert_eq!(view.net_new(Scope::Admitted).len(), 2, "the move");
        assert_eq!(view.net_new(Scope::All).len(), 3, "the promotion");

        // A later grant makes the intruder admitted, and the same survey then
        // carries its content as an ordinary move. Nothing here is cardinality
        // or validation; it is one admission decision, read at the time.
        grant_collection_write(&mut store, old.handle(), &old_key, intruder.verifying_key())
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let view = survey(&snapshot, &[old.handle()], new.handle(), None).unwrap();
        assert_eq!(view.sources()[0].admitted().len(), 3);
        assert_eq!(view.sources()[0].unadmitted().len(), 0);
    }

    /// Author counts describe the source, not the order pairs were classified.
    ///
    /// A pair asserted by both an admitted and an unadmitted author is admitted
    /// content; deciding only until the first admitted author would leave the
    /// other one uncounted, and the counts are what an operator reads to decide
    /// whether a promotion is happening.
    #[test]
    fn every_author_is_decided_not_only_the_first_admitted_one() {
        let Cutover {
            mut store,
            old,
            new,
            old_key,
            new_key,
        } = cutover(&[0x11]);
        let intruder = signer(7);
        // The same payload, asserted a second time by a key the source excludes.
        store.commit(old, &intruder, row(0x11)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        let source = &view.sources()[0];
        assert_eq!(source.pairs(), 1, "one payload, two assertions");
        assert_eq!(source.admitted().len(), 1, "an admitted author asserted it");
        assert_eq!(source.authors(), 2, "and the excluded one is still counted");
        assert_eq!(source.admitted_authors(), 1);
        let _ = old_key;
    }

    /// A source this build cannot read admits nothing, and is never an error.
    ///
    /// Open world. A descriptor that is absent, of an encoding this build does
    /// not model, or carrying a policy shape it cannot decode is a thing about
    /// which nothing can be shown — not a reason to refuse the migration of
    /// every other source beside it.
    #[test]
    fn a_source_whose_policy_cannot_be_read_is_reported_not_refused() {
        let Cutover {
            mut store,
            old,
            new,
            old_key,
            new_key,
        } = cutover(&[0x11]);
        // A handle whose descriptor blob is not in this store at all.
        let phantom: CollectionHandle = Inline::new([0x5A; 32]);
        let orphan = CollectionCommit::sign(
            &old_key,
            phantom,
            crate::inline::Inline::new([0x11; 32]),
            crate::inline::Inline::new([0x00; 32]),
        );
        store.insert(CollectionRecord::Commit(orphan)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle(), phantom],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        let unreadable = &view.sources()[1];
        assert!(!unreadable.policy_readable());
        assert_eq!(unreadable.admitted().len(), 0);
        assert_eq!(unreadable.unadmitted().len(), 1);
        // The readable source is unaffected.
        assert_eq!(view.sources()[0].admitted().len(), 1);
        assert_eq!(view.net_new(Scope::Admitted).len(), 1);
    }

    /// A record kind this carry does not model is counted, never fatal.
    ///
    /// MERGE and DERIVE are equations about a collection's own members, not
    /// exogenous content; the target re-derives its own. Refusing the whole
    /// migration because one record is not a membership assertion would strand
    /// every record behind it — the failure mode this tooling exists to end.
    #[test]
    fn a_record_kind_the_carry_does_not_model_is_skipped_and_counted() {
        let Cutover {
            mut store,
            old,
            new,
            old_key,
            new_key,
        } = cutover(&[0x11, 0x22]);

        let commits: Vec<CollectionCommit> = store
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) if commit.collection() == old.handle() => {
                    Some(commit)
                }
                _ => None,
            })
            .collect();
        assert_eq!(commits.len(), 2);
        let merge = CollectionMerge::sign(
            &old_key,
            old.handle(),
            (commits[0].data(), commits[0].fingerprint()),
            (commits[1].data(), commits[1].fingerprint()),
            crate::inline::Inline::new([0xEE; 32]),
        );
        store.insert(CollectionRecord::Merge(merge)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(view.sources()[0].other_records(), 1, "seen and set aside");
        assert_eq!(view.sources()[0].pairs(), 2, "and not counted as content");
        assert_eq!(view.net_new(Scope::Admitted).len(), 2);
    }

    /// A commit whose signature does not verify carries no author claim.
    #[test]
    fn an_unverifiable_commit_is_skipped_rather_than_carried() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11]);
        let genuine = CollectionCommit::sign(
            &signer(3),
            old.handle(),
            Inline::new([0xAB; 32]),
            Inline::new([0x00; 32]),
        );
        let (r, s) = genuine.signature();
        // Same statement, one bit of the signature turned over.
        let mut broken = s.raw;
        broken[0] ^= 0x01;
        let forged = CollectionCommit::from_parts(
            genuine.collection(),
            genuine.data(),
            genuine.metadata(),
            genuine.public_key(),
            r,
            Inline::new(broken),
        );
        store.insert(CollectionRecord::Commit(forged)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(view.sources()[0].invalid_signatures(), 1);
        assert_eq!(view.sources()[0].pairs(), 1, "only the genuine row");
        assert_eq!(view.net_new(Scope::Admitted).len(), 1);
    }

    /// An unverifiable commit in the *target* does not make it hold anything.
    ///
    /// The target side decides what is missing, so counting an assertion that
    /// is not one would report content as arrived when no valid record names
    /// it. The carry then writes the record its key genuinely signs.
    #[test]
    fn an_unverifiable_commit_in_the_target_leaves_its_content_missing() {
        let Cutover {
            mut store,
            old,
            new,
            new_key,
            ..
        } = cutover(&[0x11]);
        let pair = {
            let snapshot = store.snapshot().unwrap();
            survey(&snapshot, &[old.handle()], new.handle(), None)
                .unwrap()
                .carried(Scope::Admitted)
                .into_iter()
                .next()
                .unwrap()
        };
        let genuine = CollectionCommit::sign(&new_key, new.handle(), pair.0, pair.1);
        let (r, s) = genuine.signature();
        let mut broken = s.raw;
        broken[0] ^= 0x01;
        store
            .insert(CollectionRecord::Commit(CollectionCommit::from_parts(
                genuine.collection(),
                genuine.data(),
                genuine.metadata(),
                genuine.public_key(),
                r,
                Inline::new(broken),
            )))
            .unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(view.target_invalid_signatures(), 1);
        assert_eq!(view.target_pairs(), 0, "an invalid record asserts nothing");
        assert_eq!(view.missing(Scope::Admitted).len(), 1);
        assert_eq!(view.net_new(Scope::Admitted).len(), 1);
    }

    /// Several sources into one target, deduplicated across them.
    #[test]
    fn many_sources_collapse_into_one_target() {
        let a_key = signer(1);
        let b_key = signer(2);
        let live_key = signer(3);
        let mut store = MemoryRepo::default();
        let a = store.collection("wiki", private(&a_key)).unwrap();
        let b = store.collection("wiki", private(&b_key)).unwrap();
        let live = store.collection("wiki", private(&live_key)).unwrap();
        store.commit(a, &a_key, row(0x11)).unwrap();
        store.commit(a, &a_key, row(0x22)).unwrap();
        // Overlapping content: the same payload in two generations is one pair.
        store.commit(b, &b_key, row(0x22)).unwrap();
        store.commit(b, &b_key, row(0x33)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[a.handle(), b.handle()],
            live.handle(),
            Some(live_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(view.sources().len(), 2);
        assert_eq!(view.carried(Scope::Admitted).len(), 3);
        assert_eq!(view.net_new(Scope::Admitted).len(), 3);

        carry(
            &mut store,
            live.handle(),
            &live_key,
            &view.net_new(Scope::Admitted),
        )
        .unwrap();
        let snapshot = store.snapshot().unwrap();
        let after = survey(
            &snapshot,
            &[a.handle(), b.handle()],
            live.handle(),
            Some(live_key.verifying_key()),
        )
        .unwrap();
        assert_eq!(after.missing(Scope::Admitted).len(), 0);
        for source in [a.handle(), b.handle()] {
            assert_eq!(
                super::super::generation::unreached_records(&snapshot, source, live.handle())
                    .unwrap(),
                0
            );
        }
    }

    /// The other direction: what the target holds that no source does.
    ///
    /// A pairwise check cannot ask this — with two sources, content from one is
    /// "unsourced" with respect to the other. Holding every source of a
    /// migration in one survey is what makes the question answerable.
    #[test]
    fn content_no_source_holds_is_reported_in_the_other_direction() {
        let a_key = signer(1);
        let b_key = signer(2);
        let live_key = signer(3);
        let mut store = MemoryRepo::default();
        let a = store.collection("wiki", private(&a_key)).unwrap();
        let b = store.collection("wiki", private(&b_key)).unwrap();
        let live = store.collection("wiki", private(&live_key)).unwrap();
        store.commit(a, &a_key, row(0x11)).unwrap();
        store.commit(b, &b_key, row(0x22)).unwrap();
        // Both carried, plus one the carrying key introduced from nowhere.
        for tag in [0x11, 0x22, 0x33] {
            store.commit(live, &live_key, row(tag)).unwrap();
        }

        let snapshot = store.snapshot().unwrap();
        let both = survey(&snapshot, &[a.handle(), b.handle()], live.handle(), None).unwrap();
        assert_eq!(both.unsourced().len(), 1, "only the introduced row");
        // Against one source alone the other source's content looks introduced,
        // which is exactly why the pairwise form cannot answer this.
        let alone = survey(&snapshot, &[a.handle()], live.handle(), None).unwrap();
        assert_eq!(alone.unsourced().len(), 2);
    }

    /// Carrying a collection into itself is a no-op, not a refusal.
    #[test]
    fn a_source_equal_to_the_target_contributes_nothing() {
        let Cutover {
            mut store,
            new,
            new_key,
            ..
        } = cutover(&[0x11]);
        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[new.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        assert!(view.sources().is_empty());
        assert_eq!(view.net_new(Scope::All).len(), 0);
    }

    /// A claim about content this store does not hold still moves.
    ///
    /// The record is the claim; the payload may be somewhere else entirely.
    /// Dropping it would lose the only reference to that content — and the old
    /// carry did worse, aborting every record because one blob was absent.
    #[test]
    fn a_commit_naming_absent_content_is_carried_and_counted() {
        let Cutover {
            mut store,
            old,
            new,
            old_key,
            new_key,
        } = cutover(&[0x11]);
        let absent = CollectionCommit::sign(
            &old_key,
            old.handle(),
            Inline::new([0xC0; 32]),
            Inline::new([0xC1; 32]),
        );
        store.insert(CollectionRecord::Commit(absent)).unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = survey(
            &snapshot,
            &[old.handle()],
            new.handle(),
            Some(new_key.verifying_key()),
        )
        .unwrap();
        let pairs = view.net_new(Scope::Admitted);
        assert_eq!(pairs.len(), 2);
        assert_eq!(
            unresident(&snapshot, &pairs).unwrap(),
            1,
            "one of them names content this store does not hold"
        );

        carry(&mut store, new.handle(), &new_key, &pairs).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            survey(&snapshot, &[old.handle()], new.handle(), None)
                .unwrap()
                .missing(Scope::Admitted)
                .len(),
            0
        );
    }
}
