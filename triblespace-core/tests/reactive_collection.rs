use std::convert::Infallible;
use std::io;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::{BlobEncoding, IntoBlob};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionMerge, CollectionPolicy, CollectionRecord,
    CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
};
use triblespace_core::metadata;
use triblespace_core::prelude::blobencodings::SimpleArchive;
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;
use triblespace_core::query::register::Resolution;
use triblespace_core::reactive::collection::{
    schema as c, AdvanceError, CollectionEnvironment, ObserveError, PublishError,
};
use triblespace_core::reactive::{schema as r, Progress};
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{BlobStorePut, SnapshotSource, StorageFlush};
use triblespace_core::trible::Trible;

fn id() -> Id {
    *genid()
}
fn edge(facts: &mut TribleSet, e: Id, a: Id, v: Id) {
    let value: Inline<GenId> = v.to_inline();
    facts.insert(&Trible::force(&e, &a, &value));
}
fn clause(f: &mut TribleSet, rule: Id, relation: Id, s: Id, a: Id, o: Id) {
    let clause = id();
    edge(f, rule, relation, clause);
    edge(f, clause, r::subject.id(), s);
    edge(f, clause, r::predicate.id(), a);
    edge(f, clause, r::object.id(), o);
}
fn copy_rule(f: &mut TribleSet, rule: Id, input: Id, output: Id) {
    let (s, o) = (id(), id());
    edge(f, rule, r::operation.id(), r::POSITIVE);
    clause(f, rule, r::matches.id(), s, input, o);
    clause(f, rule, r::emits.id(), s, output, o);
}
fn reading(anchor: Id, rules: &[Id], prior: &[Id]) -> (Id, Fragment) {
    let reading = genid();
    let f = entity! { &reading @
        c::reading_of: anchor,
        c::selects*: rules.iter().copied(),
        metadata::supersedes*: prior.iter().copied(),
    };
    (*reading, f)
}
fn has(f: &TribleSet, e: Id, a: Id, v: Id) -> bool {
    exists!(f.pattern::<GenId>(e.to_inline(), a.to_inline(), v.to_inline()))
}
fn policy(key: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    )
}
fn setup() -> (MemoryRepo, SigningKey, Collection<SimpleArchive>, Id) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = MemoryRepo::for_host(key.verifying_key());
    let root = store.collection("reactive test", policy(&key)).unwrap();
    (store, key, root, id())
}

#[test]
fn cross_commit_join_publishes_then_restart_recomputes_without_new_facts() {
    let (mut store, key, root, anchor) = setup();
    let (a, b, out, x, y, rule, s, o) = (id(), id(), id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    edge(&mut facts, rule, r::operation.id(), r::POSITIVE);
    clause(&mut facts, rule, r::matches.id(), s, a, o);
    clause(&mut facts, rule, r::matches.id(), o, b, o);
    clause(&mut facts, rule, r::emits.id(), s, out, o);
    edge(&mut facts, x, a, y);
    let (read, control) = reading(anchor, &[rule], &[]);
    store
        .commit(root, &key, Fragment::from(facts) + control)
        .unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    let snapshot = store.snapshot().unwrap();
    assert_eq!(env.observe(&snapshot).unwrap(), Resolution::Sole(read));
    assert_eq!(
        env.advance(10, &snapshot).unwrap().progress,
        Progress::Quiescent
    );
    assert!(env.publish(&mut store, &key).unwrap().is_none());
    let mut second = TribleSet::new();
    edge(&mut second, y, b, y);
    store.commit(root, &key, second.into()).unwrap();
    let snapshot = store.snapshot().unwrap();
    env.observe(&snapshot).unwrap();
    assert_eq!(
        env.advance(1, &snapshot).unwrap().progress,
        Progress::Pending
    );
    assert!(has(env.facts(), x, out, y));
    env.publish(&mut store, &key).unwrap().unwrap();
    let snapshot = store.snapshot().unwrap();
    let durable: TribleSet = root.read(&snapshot).unwrap();
    assert!(has(&durable, x, out, y));
    let mut reopened = CollectionEnvironment::new(root, anchor);
    reopened.observe(&snapshot).unwrap();
    assert_eq!(reopened.advance(10, &snapshot).unwrap().firings.len(), 1);
    assert!(reopened.publish(&mut store, &key).unwrap().is_none());
    assert_eq!(reopened.facts(), &durable);
}

#[test]
fn forks_empty_retirement_and_reselection_are_explicit() {
    let (mut store, key, root, anchor) = setup();
    let (a, b, out, x, y, z, old, new) = (id(), id(), id(), id(), id(), id(), id(), id());
    let mut f = TribleSet::new();
    copy_rule(&mut f, old, a, b);
    copy_rule(&mut f, new, b, out);
    edge(&mut f, new, metadata::supersedes.id(), old);
    edge(&mut f, x, a, y);
    store.commit(root, &key, f.into()).unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    let snapshot = store.snapshot().unwrap();
    assert_eq!(env.observe(&snapshot).unwrap(), Resolution::Empty);
    assert!(matches!(
        env.advance(10, &snapshot),
        Err(AdvanceError::UnresolvedReading(Resolution::Empty))
    ));
    let (one, f) = reading(anchor, &[old], &[]);
    store.commit(root, &key, f).unwrap();
    let snapshot = store.snapshot().unwrap();
    env.observe(&snapshot).unwrap();
    env.advance(10, &snapshot).unwrap();
    assert!(has(env.facts(), x, b, y)); // Explicit old revision, despite a newer head.
    assert!(!has(env.facts(), x, out, y));
    env.publish(&mut store, &key).unwrap();
    let (left, f) = reading(anchor, &[old], &[one]);
    store.commit(root, &key, f).unwrap();
    let (right, f) = reading(anchor, &[new], &[one]);
    store.commit(root, &key, f).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        env.observe(&snapshot).unwrap(),
        Resolution::Fork([left, right].into())
    );
    assert!(matches!(
        env.advance(10, &snapshot),
        Err(AdvanceError::UnresolvedReading(Resolution::Fork(_)))
    ));
    let (retired, f) = reading(anchor, &[], &[left, right]);
    store.commit(root, &key, f).unwrap();
    let mut more = TribleSet::new();
    edge(&mut more, x, a, z);
    store.commit(root, &key, more.into()).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(env.observe(&snapshot).unwrap(), Resolution::Sole(retired));
    assert!(env.advance(10, &snapshot).unwrap().firings.is_empty());
    assert!(!has(env.facts(), x, b, z));
    let (next, f) = reading(anchor, &[new], &[retired]);
    store.commit(root, &key, f).unwrap();
    let snapshot = store.snapshot().unwrap();
    env.observe(&snapshot).unwrap();
    env.advance(10, &snapshot).unwrap();
    assert!(has(env.facts(), x, out, y)); // Historical consequence is an input.
    env.publish(&mut store, &key).unwrap();
    let (_, f) = reading(anchor, &[old], &[next]);
    store.commit(root, &key, f).unwrap();
    let snapshot = store.snapshot().unwrap();
    env.observe(&snapshot).unwrap();
    assert_eq!(env.advance(10, &snapshot).unwrap().firings.len(), 1);
    assert!(has(env.facts(), x, b, z));
}

#[test]
fn partial_success_on_error_is_published_and_blocks_control_changes() {
    let (mut store, key, root, anchor) = setup();
    let mut rules = [id(), id()];
    rules.sort();
    let [good, bad] = rules;
    let (a, out, x, y) = (id(), id(), id(), id());
    let mut f = TribleSet::new();
    copy_rule(&mut f, good, a, out);
    edge(&mut f, bad, r::operation.id(), id());
    edge(&mut f, x, a, y);
    let (initial, control) = reading(anchor, &rules, &[]);
    store
        .commit(root, &key, Fragment::from(f) + control)
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&snapshot).unwrap();
    assert!(matches!(
        env.advance(10, &snapshot),
        Err(AdvanceError::Evaluation(_))
    ));
    assert!(has(env.unpublished().facts(), x, out, y));
    let (retired, f) = reading(anchor, &[], &[initial]);
    store.commit(root, &key, f).unwrap();
    let later = store.snapshot().unwrap();
    assert!(matches!(
        env.observe(&later),
        Err(ObserveError::PublicationPending)
    ));
    assert_eq!(env.reading(), Some(&Resolution::Sole(initial)));
    assert!(matches!(
        env.advance(10, &later),
        Err(AdvanceError::PublicationPending)
    ));
    env.publish(&mut store, &key).unwrap().unwrap();
    assert_eq!(
        env.observe(&store.snapshot().unwrap()).unwrap(),
        Resolution::Sole(retired)
    );
    assert!(has(env.facts(), x, out, y));
}

struct FaultStore {
    inner: MemoryRepo,
    commit_failure: bool,
    flush_failure: bool,
    attempts: Vec<CollectionRecord>,
}
impl SnapshotSource for FaultStore {
    type Snapshot = MemoryRepoSnapshot;
    type SnapshotError = Infallible;
    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.inner.snapshot()
    }
}
impl BlobStorePut for FaultStore {
    type PutError = Infallible;
    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.inner.put(item)
    }
}
impl CollectionStore for FaultStore {
    type InsertError = io::Error;
    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.attempts.push(record);
        self.inner.insert(record).unwrap(); // Uncertain insertion: visible before the error.
        if self.commit_failure {
            Err(io::Error::other("injected insertion failure"))
        } else {
            Ok(())
        }
    }
}
impl StorageFlush for FaultStore {
    type Error = io::Error;
    fn flush(&mut self) -> Result<(), Self::Error> {
        if self.flush_failure {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn uncertain_commit_and_flush_retry_identical_batch_and_signer() {
    let (mut inner, key, root, anchor) = setup();
    let (rule, a, out, x, y) = (id(), id(), id(), id(), id());
    let mut f = TribleSet::new();
    copy_rule(&mut f, rule, a, out);
    edge(&mut f, x, a, y);
    let (_, control) = reading(anchor, &[rule], &[]);
    inner
        .commit(root, &key, Fragment::from(f) + control)
        .unwrap();
    let mut store = FaultStore {
        inner,
        commit_failure: true,
        flush_failure: false,
        attempts: Vec::new(),
    };
    let snapshot = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&snapshot).unwrap();
    env.advance(10, &snapshot).unwrap();
    let pending = env.unpublished().clone();
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    assert!(matches!(
        env.publish(&mut store, &other),
        Err(PublishError::Unadmitted)
    ));
    assert!(store.attempts.is_empty());
    assert!(matches!(
        env.publish(&mut store, &key),
        Err(PublishError::Commit(_))
    ));
    assert_eq!(env.unpublished(), &pending);
    assert!(matches!(
        env.publish(&mut store, &other),
        Err(PublishError::DifferentSigner)
    ));
    store.commit_failure = false;
    store.flush_failure = true;
    assert!(matches!(
        env.publish(&mut store, &key),
        Err(PublishError::Flush(_))
    ));
    assert_eq!(env.unpublished(), &pending);
    assert!(has(
        &root
            .read::<TribleSet, _>(&store.snapshot().unwrap())
            .unwrap(),
        x,
        out,
        y
    ));
    assert!(matches!(
        env.observe(&store.snapshot().unwrap()),
        Err(ObserveError::PublicationPending)
    ));
    store.flush_failure = false;
    env.publish(&mut store, &key).unwrap().unwrap();
    assert!(env.unpublished().is_empty());
    assert_eq!(store.attempts.len(), 3);
    assert!(store.attempts.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn incomplete_view_and_shrinking_support_never_erase_held_facts() {
    let (mut store, key, root, anchor) = setup();
    let (_, f) = reading(anchor, &[], &[]);
    store.commit(root, &key, f).unwrap();
    let old = store.snapshot().unwrap();
    let e = genid();
    let commit = store
        .commit(root, &key, entity! { &e @ metadata::tag: anchor })
        .unwrap();
    let new = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&new).unwrap();
    let held = env.facts().clone();
    let support = env.support().cloned();
    assert!(matches!(
        env.observe(&old),
        Err(ObserveError::ResetRequired(_))
    ));
    assert_eq!(env.facts(), &held);
    assert_eq!(env.support(), support.as_ref());
    assert!(matches!(
        env.advance(10, &old),
        Err(AdvanceError::ObservationRequired)
    ));
    let keep: Vec<_> = store
        .blobs
        .snapshot()
        .unwrap()
        .iter()
        .map(|(h, _)| h)
        .filter(|h| h.raw != commit.data().raw)
        .collect();
    store.blobs.keep(keep);
    let unavailable = store.snapshot().unwrap();
    assert!(matches!(
        env.observe(&unavailable),
        Err(ObserveError::View(_))
    ));
    assert_eq!(env.facts(), &held);
    assert_eq!(env.support(), support.as_ref());
}

#[test]
fn merged_cover_reads_complete_facts_without_original_payloads() {
    let (mut store, key, root, anchor) = setup();
    let mut inputs = Vec::new();
    let mut facts = TribleSet::new();
    for _ in 0..8 {
        let (_, f) = reading(anchor, &[], &[]);
        facts += f.facts().clone();
        inputs.push(store.commit(root, &key, f).unwrap().data());
    }
    let before = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&before).unwrap();
    let support = env.support().cloned();
    let result = store.put::<SimpleArchive, _>(facts.clone()).unwrap();
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &key,
                root.handle(),
                inputs.iter().copied(),
                Handle::<SimpleArchive>::to_hash(result),
            )
            .unwrap(),
        ))
        .unwrap();
    let keep: Vec<_> = store
        .blobs
        .snapshot()
        .unwrap()
        .iter()
        .map(|(h, _)| h)
        .filter(|h| !inputs.iter().any(|i| i.raw == h.raw))
        .collect();
    store.blobs.keep(keep);
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.collection(root).unwrap().cover().len(), 1);
    env.observe(&snapshot).unwrap();
    assert_eq!(env.support(), support.as_ref());
    assert_eq!(env.facts(), &facts);
}

#[test]
fn temporary_pile_reopens_durable_consequences() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reactive.pile");
    std::fs::File::create(&path).unwrap();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let (anchor, rule, a, out, x, y) = (id(), id(), id(), id(), id(), id());
    let root;
    {
        let mut store = triblespace_core::repo::pile::Pile::open(&path).unwrap();
        root = store.collection("reopen", policy(&key)).unwrap();
        let mut f = TribleSet::new();
        copy_rule(&mut f, rule, a, out);
        edge(&mut f, x, a, y);
        let (_, control) = reading(anchor, &[rule], &[]);
        store
            .commit(root, &key, Fragment::from(f) + control)
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let mut env = CollectionEnvironment::new(root, anchor);
        env.observe(&snapshot).unwrap();
        env.advance(10, &snapshot).unwrap();
        env.publish(&mut store, &key).unwrap().unwrap();
    }
    let mut store = triblespace_core::repo::pile::Pile::open(&path).unwrap();
    let snapshot = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&snapshot).unwrap();
    assert!(has(env.facts(), x, out, y));
    env.advance(10, &snapshot).unwrap();
    assert!(env.publish(&mut store, &key).unwrap().is_none());
}

#[test]
fn content_arrival_retries_with_unchanged_fact_support_and_resumes_budget() {
    use triblespace_core::prelude::blobencodings::UTF8String;
    let (mut store, key, root, anchor) = setup();
    let (rule, attr, out, item, s, text, needle, constraint) =
        (id(), id(), id(), id(), id(), id(), id(), id());
    let wanted = store.put::<UTF8String, _>("ready").unwrap();
    let missing: Inline<Handle<UTF8String>> = "already ready".to_inline();
    let mut facts = TribleSet::new();
    edge(&mut facts, rule, r::operation.id(), r::POSITIVE);
    clause(&mut facts, rule, r::matches.id(), s, attr, text);
    clause(&mut facts, rule, r::emits.id(), s, out, text);
    edge(&mut facts, rule, r::constraints.id(), constraint);
    edge(
        &mut facts,
        constraint,
        r::operation.id(),
        r::STRING_CONTAINS,
    );
    edge(&mut facts, constraint, r::container.id(), text);
    edge(&mut facts, constraint, r::needle.id(), needle);
    facts.insert(&Trible::force(&needle, &r::literal.id(), &wanted));
    facts.insert(&Trible::force(&item, &attr, &missing));
    let (_, control) = reading(anchor, &[rule], &[]);
    store
        .commit(root, &key, Fragment::from(facts) + control)
        .unwrap();
    let before = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&before).unwrap();
    assert!(matches!(
        env.advance(1, &before),
        Err(AdvanceError::Evaluation(_))
    ));
    assert!(env.unpublished().is_empty());
    let support = env.support().cloned();
    assert_eq!(
        store.put::<UTF8String, _>("already ready").unwrap(),
        missing
    );
    let later = store.snapshot().unwrap();
    assert_eq!(root.admitted(&later).unwrap(), support.clone().unwrap());
    assert_eq!(env.advance(1, &later).unwrap().progress, Progress::Pending);
    env.publish(&mut store, &key).unwrap().unwrap();
    assert_eq!(
        env.advance(1, &later).unwrap().progress,
        Progress::Quiescent
    );
    assert_eq!(env.support(), support.as_ref());
    assert!(exists!(env.facts().pattern::<Handle<UTF8String>>(
        item.to_inline(),
        out.to_inline(),
        missing
    )));
}

#[test]
fn emitted_reading_takes_effect_only_after_publication_and_observation() {
    let (mut store, key, root, anchor) = setup();
    let (rule, future, ts, ta, tp, trigger, x, y, s, o) =
        (id(), id(), id(), id(), id(), id(), id(), id(), id(), id());
    let (initial, control) = reading(anchor, &[rule], &[]);
    let mut facts = TribleSet::new();
    edge(&mut facts, rule, r::operation.id(), r::POSITIVE);
    clause(&mut facts, rule, r::matches.id(), s, trigger, o);
    clause(&mut facts, rule, r::emits.id(), ts, c::reading_of.id(), ta);
    clause(
        &mut facts,
        rule,
        r::emits.id(),
        ts,
        metadata::supersedes.id(),
        tp,
    );
    edge(&mut facts, ts, r::literal.id(), future);
    edge(&mut facts, ta, r::literal.id(), anchor);
    edge(&mut facts, tp, r::literal.id(), initial);
    edge(&mut facts, x, trigger, y);
    store
        .commit(root, &key, Fragment::from(facts) + control)
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let mut env = CollectionEnvironment::new(root, anchor);
    env.observe(&snapshot).unwrap();
    env.advance(10, &snapshot).unwrap();
    assert_eq!(env.reading(), Some(&Resolution::Sole(initial)));
    assert!(has(
        env.unpublished().facts(),
        future,
        c::reading_of.id(),
        anchor
    ));
    env.publish(&mut store, &key).unwrap();
    assert_eq!(env.reading(), Some(&Resolution::Sole(initial)));
    assert_eq!(
        env.observe(&store.snapshot().unwrap()).unwrap(),
        Resolution::Sole(future)
    );
    assert!(env.selected().is_empty());
}
