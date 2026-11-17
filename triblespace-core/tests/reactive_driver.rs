use std::time::Duration;

use ed25519_dalek::SigningKey;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::prelude::blobencodings::{SimpleArchive, UTF8String};
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;
use triblespace_core::query::register::Resolution;
use triblespace_core::reactive::collection::schema as c;
use triblespace_core::reactive::driver::{Bound, Bounds, CollectionDriver, Outcome};
use triblespace_core::reactive::schema as r;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
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
/// `?s input ?o` concludes the entity whose whole core is `about: ?s`.
fn conclude_rule(f: &mut TribleSet, rule: Id, input: Id, about: Id) -> Id {
    let (s, o, conclusion) = (id(), id(), id());
    edge(f, rule, r::operation.id(), r::POSITIVE);
    clause(f, rule, r::matches.id(), s, input, o);
    clause(f, rule, r::core.id(), conclusion, about, s);
    o
}
fn reading(anchor: Id, rules: &[Id]) -> Fragment {
    entity! { &genid() @ c::reading_of: anchor, c::selects*: rules.iter().copied() }
}
fn setup() -> (MemoryRepo, SigningKey, Collection<SimpleArchive>, Id) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = MemoryRepo::for_host(key.verifying_key());
    let policy = AdmissionPolicy::direct(key.verifying_key());
    let root = store
        .collection(
            "reactive driver",
            CollectionPolicy::new(policy.clone(), policy),
        )
        .unwrap();
    (store, key, root, id())
}
fn driver(
    root: Collection<SimpleArchive>,
    anchor: Id,
    key: &SigningKey,
) -> CollectionDriver<MemoryRepoSnapshot> {
    CollectionDriver::new(root, anchor, key.clone(), Bounds::default())
}
/// Durable conclusion entities about `subject`, read from the store, not the driver.
fn conclusions(store: &mut MemoryRepo, root: Collection<SimpleArchive>, about: Id, s: Id) -> usize {
    let facts: TribleSet = root.read(&store.snapshot().unwrap()).unwrap();
    find!(e: Id, facts.pattern::<GenId>(e, about.to_inline(), s.to_inline())).count()
}

#[test]
fn reacts_to_a_new_reading_and_a_new_fact_then_settles() {
    let (mut store, key, root, anchor) = setup();
    let (rule, input, about, x, y) = (id(), id(), id(), id(), id());
    let mut program = TribleSet::new();
    conclude_rule(&mut program, rule, input, about);
    store.commit(root, &key, program.into()).unwrap();
    let mut d = driver(root, anchor, &key);
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(
        step.outcome,
        Outcome::Unresolved(Resolution::Empty)
    ));
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Unchanged
    ));

    store.commit(root, &key, reading(anchor, &[rule])).unwrap();
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (0, 0));
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Unchanged
    ));

    let mut fact = TribleSet::new();
    edge(&mut fact, x, input, y);
    store.commit(root, &key, fact.into()).unwrap();
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (1, 1));
    assert_eq!(conclusions(&mut store, root, about, x), 1);
    // The driver's own commit changed the records it read: one quiet re-step.
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (0, 0));
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Unchanged
    ));
}

#[test]
fn late_blob_wakes_the_driver_without_a_new_fact() {
    let (mut store, key, root, anchor) = setup();
    let (rule, attr, about, item, constraint, needle) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let text = conclude_rule(&mut facts, rule, attr, about);
    edge(&mut facts, rule, r::constraints.id(), constraint);
    edge(
        &mut facts,
        constraint,
        r::operation.id(),
        r::STRING_CONTAINS,
    );
    edge(&mut facts, constraint, r::container.id(), text);
    edge(&mut facts, constraint, r::needle.id(), needle);
    let wanted = store.put::<UTF8String, _>("red").unwrap();
    facts.insert(&Trible::force(&needle, &r::literal.id(), &wanted));
    let late: Inline<Handle<UTF8String>> = "red lantern".to_inline();
    facts.insert(&Trible::force(&item, &attr, &late));
    store
        .commit(root, &key, Fragment::from(facts) + reading(anchor, &[rule]))
        .unwrap();
    let mut d = driver(root, anchor, &key);
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Blocked(_)
    ));
    // The miss itself is part of the read-set the next poll compares.
    let read = d.read_set().expect("a blocked step settles");
    assert!(read.blobs.contains(&Handle::<UTF8String>::to_hash(late)));
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Unchanged
    ));
    assert_eq!(conclusions(&mut store, root, about, item), 0);

    assert_eq!(store.put::<UTF8String, _>("red lantern").unwrap(), late);
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (1, 1));
    assert_eq!(conclusions(&mut store, root, about, item), 1);
}

#[test]
fn restart_repeats_firings_without_duplicate_conclusions() {
    let (mut store, key, root, anchor) = setup();
    let (rule, input, about, x, y) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    conclude_rule(&mut facts, rule, input, about);
    edge(&mut facts, x, input, y);
    store
        .commit(root, &key, Fragment::from(facts) + reading(anchor, &[rule]))
        .unwrap();
    let step = driver(root, anchor, &key).poll(&mut store).unwrap();
    assert_eq!((step.firings, step.commits.len()), (1, 1));
    let before: TribleSet = root.read(&store.snapshot().unwrap()).unwrap();

    // A restart is a new driver: memo gone, the binding fires again.
    let mut restarted = driver(root, anchor, &key);
    let step = restarted.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (1, 0));
    let after: TribleSet = root.read(&store.snapshot().unwrap()).unwrap();
    assert_eq!(before, after);
    assert_eq!(conclusions(&mut store, root, about, x), 1);
}

#[test]
fn explicit_bounds_stop_a_step_and_the_next_poll_continues() {
    let (mut store, key, root, anchor) = setup();
    let (rule, input, about) = (id(), id(), id());
    let mut facts = TribleSet::new();
    conclude_rule(&mut facts, rule, input, about);
    let subjects = [id(), id(), id()];
    for s in subjects {
        edge(&mut facts, s, input, id());
    }
    store
        .commit(root, &key, Fragment::from(facts) + reading(anchor, &[rule]))
        .unwrap();

    let mut timed = CollectionDriver::<MemoryRepoSnapshot>::new(
        root,
        anchor,
        key.clone(),
        Bounds {
            firings: 10,
            chunk: 10,
            time: Duration::ZERO,
        },
    );
    let step = timed.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Bounded(Bound::Time)));
    assert_eq!(step.firings, 0);

    let mut d = CollectionDriver::<MemoryRepoSnapshot>::new(
        root,
        anchor,
        key.clone(),
        Bounds {
            firings: 1,
            chunk: 8,
            time: Duration::from_secs(60),
        },
    );
    let mut firings = 0;
    for _ in 0..3 {
        let step = d.poll(&mut store).unwrap();
        assert!(matches!(step.outcome, Outcome::Bounded(Bound::Firings)));
        assert_eq!((step.firings, step.commits.len()), (1, 1));
        firings += step.firings;
    }
    assert_eq!(firings, 3);
    // Not Unchanged: a bounded step never settles, so this poll steps and proves quiescence.
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!(step.firings, 0);
    for s in subjects {
        assert_eq!(conclusions(&mut store, root, about, s), 1);
    }
}

#[test]
fn restart_over_a_temporary_pile_publishes_nothing_new() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver.pile");
    std::fs::File::create(&path).unwrap();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let (anchor, rule, input, about, x, y) = (id(), id(), id(), id(), id(), id());
    let root;
    let before: TribleSet;
    {
        let mut store = triblespace_core::repo::pile::Pile::open(&path).unwrap();
        let policy = AdmissionPolicy::direct(key.verifying_key());
        root = store
            .collection(
                "driver restart",
                CollectionPolicy::new(policy.clone(), policy),
            )
            .unwrap();
        let mut facts = TribleSet::new();
        conclude_rule(&mut facts, rule, input, about);
        edge(&mut facts, x, input, y);
        store
            .commit(root, &key, Fragment::from(facts) + reading(anchor, &[rule]))
            .unwrap();
        let mut d = CollectionDriver::new(root, anchor, key.clone(), Bounds::default());
        let step = d.poll(&mut store).unwrap();
        assert_eq!((step.firings, step.commits.len()), (1, 1));
        before = root.read(&store.snapshot().unwrap()).unwrap();
    }
    let mut store = triblespace_core::repo::pile::Pile::open(&path).unwrap();
    let mut d = CollectionDriver::new(root, anchor, key.clone(), Bounds::default());
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (1, 0));
    let after: TribleSet = root.read(&store.snapshot().unwrap()).unwrap();
    assert_eq!(before, after);
    let found = find!(e: Id, after.pattern::<GenId>(e, about.to_inline(), x.to_inline())).count();
    assert_eq!(found, 1);
}

#[test]
fn on_a_pile_only_the_missing_blob_wakes_a_blocked_driver() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver.pile");
    std::fs::File::create(&path).unwrap();
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut store = triblespace_core::repo::pile::Pile::open(&path).unwrap();
    let policy = AdmissionPolicy::direct(key.verifying_key());
    let root = store
        .collection(
            "driver precision",
            CollectionPolicy::new(policy.clone(), policy),
        )
        .unwrap();
    let (anchor, rule, attr, about, item, constraint, needle) =
        (id(), id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let text = conclude_rule(&mut facts, rule, attr, about);
    edge(&mut facts, rule, r::constraints.id(), constraint);
    edge(
        &mut facts,
        constraint,
        r::operation.id(),
        r::STRING_CONTAINS,
    );
    edge(&mut facts, constraint, r::container.id(), text);
    edge(&mut facts, constraint, r::needle.id(), needle);
    let wanted = store.put::<UTF8String, _>("red").unwrap();
    facts.insert(&Trible::force(&needle, &r::literal.id(), &wanted));
    let late: Inline<Handle<UTF8String>> = "red lantern".to_inline();
    facts.insert(&Trible::force(&item, &attr, &late));
    store
        .commit(root, &key, Fragment::from(facts) + reading(anchor, &[rule]))
        .unwrap();
    let mut d = CollectionDriver::new(root, anchor, key.clone(), Bounds::default());
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Blocked(_)
    ));
    store.put::<UTF8String, _>("an unrelated blob").unwrap();
    assert!(matches!(
        d.poll(&mut store).unwrap().outcome,
        Outcome::Unchanged
    ));
    store.put::<UTF8String, _>("red lantern").unwrap();
    let step = d.poll(&mut store).unwrap();
    assert!(matches!(step.outcome, Outcome::Quiescent));
    assert_eq!((step.firings, step.commits.len()), (1, 1));
}
