//! Exercise retained per-hop gates using the real pass and indexed Pile reads.
//! Counts stop at storage/publication boundaries; they are not timings or
//! signature/mapping invocation counts. The original fresh-pass controls stay.

use super::*;
use triblespace_core::repo::memoryrepo::MemoryRepo;

type State = MaintenanceState<Counted<PileSnapshot>>;

fn hop(state: &State, handle: CollectionHandle) -> &MaintenanceHop<Counted<PileSnapshot>> {
    state
        .hops
        .get(&handle.raw)
        .expect("the exercised maintenance hop is retained")
}

fn hops(state: &State) -> impl Iterator<Item = &MaintenanceHop<Counted<PileSnapshot>>> {
    state
        .hops
        .iter_ordered()
        .map(|key| state.hops.get(key).expect("retained hop key has a value"))
}

fn pass(
    fixture: &mut Fixture,
    references: &[String],
    dependencies: bool,
    state: &mut State,
    selection_hook: Option<Arc<SelectionHook>>,
) -> (usize, Counts) {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let mut counted = Counted {
        inner: &mut fixture.pile,
        counts: Arc::clone(&counts),
        selection_hook,
        fail_snapshot_at: None,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let failures = runtime
        .block_on(maintenance_pass(
            &mut counted,
            references,
            &fixture.signer,
            dependencies,
            SuccinctBackend::Cpu,
            state,
        ))
        .unwrap();
    let result = counts.lock().unwrap().clone();
    (failures, result)
}

fn references(fixture: &Fixture) -> Vec<String> {
    fixture
        .targets
        .iter()
        .map(|target| handle_hex(target.handle()))
        .collect()
}

fn warm(fixture: &mut Fixture, state: &mut State) -> Vec<String> {
    fixture.warm();
    let references = references(fixture);
    let (failures, counts) = pass(fixture, &references, true, state, None);
    assert_eq!(failures, 0);
    assert_eq!(counts.blob_puts, 0);
    assert!(counts.insertions.is_empty());
    references
}

fn assert_skipped(counts: &Counts, fixture: &Fixture, chain: usize) {
    for handle in [
        fixture.sources[chain].handle(),
        fixture.targets[chain].handle(),
    ] {
        assert_eq!(counts.selected_calls.get(&handle), None);
        assert_eq!(counts.selected_rows.get(&handle), None);
        assert_eq!(counts.insertions.get(&handle), None);
    }
}

#[test]
fn changed_chain_skips_other_chain_without_losing_its_wake_interest() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let references = warm(&mut fixture, &mut state);
    let settled = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .put::<UTF8String, _>("unrelated arrival")
        .unwrap();
    fixture
        .writer
        .commit(
            fixture.other,
            &fixture.signer,
            receipt(fixture.first_value, "unselected source arrival"),
        )
        .unwrap();
    let current = fixture.pile.snapshot().unwrap();
    assert!(!maintenance_changed(&settled, &current, &state.interests()));
    let (_, idle) = pass(&mut fixture, &references, true, &mut state, None);
    assert!(idle.selected_calls.is_empty());
    assert_eq!(idle.proof_enumerations, 0);
    assert_eq!(idle.blob_puts, 0);
    for hop in hops(&state) {
        assert!(
            hop.before.inner.changes_since(&current).is_empty(),
            "proven-unchanged entries release their older observation"
        );
    }

    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(Id::new([2; 16]).unwrap(), "hot new event"),
        )
        .unwrap();
    let (failures, hot) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert_skipped(&hot, &fixture, 1);
    assert!(hot.selected_calls[&fixture.targets[0].handle()] >= 2);
    assert!(hot.insertions[&fixture.targets[0].handle()][2] > 0);
    let (_, catch_up) = pass(&mut fixture, &references, true, &mut state, None);
    assert_skipped(&catch_up, &fixture, 1);
    assert_eq!(catch_up.blob_puts, 0);
    assert!(catch_up.insertions.is_empty());
    let before_quiet_change = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .commit(
            fixture.sources[1],
            &fixture.signer,
            receipt(Id::new([3; 16]).unwrap(), "formerly quiet new event"),
        )
        .unwrap();
    assert!(
        maintenance_changed(
            &before_quiet_change,
            &fixture.pile.snapshot().unwrap(),
            &state.interests()
        ),
        "skipping B must not erase B from the outer wake set"
    );
    let (failures, formerly_quiet) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert_skipped(&formerly_quiet, &fixture, 0);
    assert!(formerly_quiet.insertions[&fixture.targets[1].handle()][2] > 0);
    let snapshot = fixture.pile.snapshot().unwrap();
    let observed = snapshot.collection(fixture.targets[1]).unwrap();
    assert_eq!(
        observed
            .view::<EntityIdSet>()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [fixture.first_value, Id::new([3; 16]).unwrap()]
    );
    assert_eq!(
        observed.support().unwrap(),
        &fixture.sources[1].admitted(&snapshot).unwrap()
    );
    fixture.close();
}

#[test]
fn scoped_proof_changes_remain_component_wide() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let references = warm(&mut fixture, &mut state);
    grant_collection_read(
        &mut fixture.writer,
        fixture.other.handle(),
        &fixture.signer,
        SigningKey::from_bytes(&[73; 32]).verifying_key(),
    )
    .unwrap();
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    for target in fixture.targets {
        assert!(counts.selected_calls[&target.handle()] >= 2);
    }
    assert!(counts.proof_enumerations > 0);
    assert_eq!(counts.blob_puts, 0);
    assert!(counts.insertions.is_empty());
    fixture.close();
}

#[test]
fn failed_hop_keeps_its_retry_opportunity_when_another_chain_wakes() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let mut references = warm(&mut fixture, &mut state);
    let inaccessible = fixture
        .pile
        .derive::<EntityIdSetBlob>(
            fixture.sources[0],
            metadata::tag.id(),
            CollectionPolicy::new(
                AdmissionPolicy::direct(fixture.signer.verifying_key()),
                AdmissionPolicy::direct(SigningKey::from_bytes(&[74; 32]).verifying_key()),
            ),
        )
        .unwrap();
    references.push(handle_hex(inaccessible.handle()));
    let (failures, _) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 1);
    assert!(hop(&state, inaccessible.handle()).retry_on_pass);
    let failed = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .commit(
            fixture.sources[1],
            &fixture.signer,
            receipt(Id::new([5; 16]).unwrap(), "independent wake after failure"),
        )
        .unwrap();
    let arrived = fixture.pile.snapshot().unwrap();
    assert!(
        !maintenance_changed(
            &failed,
            &arrived,
            &hop(&state, inaccessible.handle()).interests
        ),
        "the failed hop's own stored inputs did not change"
    );
    assert!(maintenance_changed(&failed, &arrived, &state.interests()));
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 1);
    assert!(
        counts.selected_calls[&inaccessible.handle()] > 0,
        "a failed attempt is retried on the old whole-worker wake opportunity"
    );
    assert_eq!(counts.insertions.get(&inaccessible.handle()), None);
    fixture.close();
}

#[test]
fn pre_hop_snapshot_failure_retries_old_success_on_another_chain_wake() {
    let mut fixture = Fixture::new();
    fixture.warm();
    let mut state = State::default();
    let references = references(&fixture);
    assert_eq!(
        pass(&mut fixture, &references, false, &mut state, None).0,
        0
    );
    // Pin which hop is first under the real key-biased order. Without dependency
    // traversal, snapshot 1 resolves the selection, 2 plans that first target,
    // and 3 is precisely its pre-hop observation, before any census or upkeep.
    let author = fixture.signer.verifying_key();
    let b = (0..2)
        .min_by_key(|&index| {
            let target = fixture.targets[index].handle();
            let mut hash = blake3::Hasher::new();
            hash.update(b"trible/maintenance-target-order");
            hash.update(author.as_bytes());
            hash.update(&target.raw);
            (*hash.finalize().as_bytes(), target.raw)
        })
        .unwrap();
    let a = 1 - b;
    let failed_target = fixture.targets[b].handle();
    assert!(!hop(&state, failed_target).retry_on_pass);
    let counts = Arc::new(Mutex::new(Counts::default()));
    let mut counted = Counted {
        inner: &mut fixture.pile,
        counts: Arc::clone(&counts),
        selection_hook: None,
        fail_snapshot_at: Some(3),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let failures = runtime
        .block_on(maintenance_pass(
            &mut counted,
            &references,
            &fixture.signer,
            false,
            SuccinctBackend::Cpu,
            &mut state,
        ))
        .unwrap();
    drop(counted);
    assert_eq!(failures, 1);
    assert_eq!(counts.lock().unwrap().snapshots, 5);
    assert!(counts.lock().unwrap().selected_calls.is_empty());
    assert!(
        hop(&state, failed_target).retry_on_pass,
        "the pre-hop Err must invalidate its old successful attempt"
    );
    let failed = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .commit(
            fixture.sources[a],
            &fixture.signer,
            receipt(
                Id::new([6; 16]).unwrap(),
                "other chain wakes after snapshot failure",
            ),
        )
        .unwrap();
    let arrived = fixture.pile.snapshot().unwrap();
    assert!(!maintenance_changed(
        &failed,
        &arrived,
        &hop(&state, failed_target).interests
    ));
    assert!(maintenance_changed(&failed, &arrived, &state.interests()));
    let (failures, retry) = pass(&mut fixture, &references, false, &mut state, None);
    assert_eq!(failures, 0);
    assert!(
        retry.selected_calls[&failed_target] >= 2,
        "the one-shot failed B is really retried even though only A changed"
    );
    assert!(!hop(&state, failed_target).retry_on_pass);
    fixture.close();
}

#[test]
fn scoped_same_value_keeps_new_support_and_skips_other_chain() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let references = warm(&mut fixture, &mut state);
    let before = fixture.pile.snapshot().unwrap();
    let target = fixture.targets[0].handle();
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(
                fixture.first_value,
                "same event, independent receipt annotation",
            ),
        )
        .unwrap();
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert_skipped(&counts, &fixture, 1);
    let after = fixture.pile.snapshot().unwrap();
    assert_eq!(
        output_handles(&before, target),
        output_handles(&after, target)
    );
    assert!(selected_records(&after, target).len() > selected_records(&before, target).len());
    fixture.assert_value_and_support(&[fixture.first_value], 2);
    let (_, catch_up) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(catch_up.blob_puts, 0);
    assert!(catch_up.insertions.is_empty());
    let (_, idle) = pass(&mut fixture, &references, true, &mut state, None);
    assert!(idle.selected_calls.is_empty());
    fixture.close();
}

#[test]
fn implicit_root_retries_when_explicitly_selected() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let mut references = warm(&mut fixture, &mut state);
    let root = fixture.sources[0].handle();
    assert!(hop(&state, root).dependency_only);
    references.push(handle_hex(root));
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert!(!hop(&state, root).dependency_only);
    assert!(counts.selected_calls[&root] >= 2);
    assert_eq!(
        counts.selected_calls.get(&fixture.targets[0].handle()),
        None
    );
    assert_skipped(&counts, &fixture, 1);
    fixture.close();
}

#[test]
fn upstream_publication_rechecks_downstream_in_the_same_pass() {
    let mut fixture = Fixture::new();
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(Id::new([2; 16]).unwrap(), "second root member"),
        )
        .unwrap();
    let mut state = State::default();
    let mut references = warm(&mut fixture, &mut state);
    let source = fixture.sources[0].handle();
    let target = fixture.targets[0].handle();
    let before = fixture.pile.snapshot().unwrap();
    assert!(selected_records(&before, source)
        .iter()
        .all(|record| matches!(record, CollectionRecord::Commit(_))));
    assert!(!maintenance_changed(
        &hop(&state, target).before.inner,
        &before,
        &hop(&state, target).interests
    ));
    // Explicitly maintaining the previously ensure-only root publishes a
    // coarsening. Target eligibility must be checked after that publication,
    // even when target ordering puts its chain first. Repeated references do
    // not change the selected set or upstream-first walk.
    references.extend([handle_hex(source), handle_hex(target)]);
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert!(counts.insertions[&source][1] > 0);
    assert!(counts.selected_calls[&target] >= 2);
    assert_skipped(&counts, &fixture, 1);
    let snapshot = fixture.pile.snapshot().unwrap();
    let observed = snapshot.collection(fixture.targets[0]).unwrap();
    assert_eq!(
        observed
            .view::<EntityIdSet>()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [fixture.first_value, Id::new([2; 16]).unwrap()]
    );
    assert_eq!(
        observed.support().unwrap(),
        &fixture.sources[0].admitted(&snapshot).unwrap()
    );
    fixture.close();
}

#[test]
fn broad_name_planning_does_not_make_each_hop_broad() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let mut references = warm(&mut fixture, &mut state);
    references.push("name:hot receipt source".to_owned());
    assert_eq!(pass(&mut fixture, &references, true, &mut state, None).0, 0);
    assert!(state.planning.all_records);
    assert!(hops(&state).all(|hop| !hop.interests.all_records));
    let before = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .commit(
            fixture.other,
            &fixture.signer,
            receipt(fixture.first_value, "unselected record wakes name planning"),
        )
        .unwrap();
    assert!(maintenance_changed(
        &before,
        &fixture.pile.snapshot().unwrap(),
        &state.interests()
    ));
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert!(counts.record_enumerations > 0);
    assert!(counts.selected_calls.is_empty());
    assert_eq!(counts.proof_enumerations, 0);
    fixture.close();
}

#[test]
fn missing_planning_descriptor_survives_an_unrelated_pass() {
    let mut fixture = Fixture::new();
    let mut state = State::default();
    let mut references = warm(&mut fixture, &mut state);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(fixture.signer.verifying_key()),
        AdmissionPolicy::direct(fixture.signer.verifying_key()),
    );
    let mut elsewhere = MemoryRepo::default();
    let late = elsewhere
        .collection("late private maintenance root", policy)
        .unwrap();
    let late_blob: Blob<SimpleArchive> = elsewhere.snapshot().unwrap().get(late.handle()).unwrap();
    references.push(handle_hex(late.handle()));
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 1);
    assert!(counts.selected_calls.is_empty());
    assert!(state
        .interests()
        .blobs
        .contains(&Handle::<SimpleArchive>::to_hash(late.handle())));
    let failed = fixture.pile.snapshot().unwrap();
    fixture
        .writer
        .put::<UTF8String, _>("unrelated to missing descriptor")
        .unwrap();
    let unrelated = fixture.pile.snapshot().unwrap();
    assert!(!maintenance_changed(
        &failed,
        &unrelated,
        &state.interests()
    ));
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(
                Id::new([7; 16]).unwrap(),
                "A wakes while the descriptor stays missing",
            ),
        )
        .unwrap();
    assert!(maintenance_changed(
        &unrelated,
        &fixture.pile.snapshot().unwrap(),
        &state.interests()
    ));
    let (failures, intervening) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 1);
    assert!(intervening.selected_calls[&fixture.targets[0].handle()] >= 2);
    assert_skipped(&intervening, &fixture, 1);
    // Settle A's own-write catch-up while the planning miss remains present.
    assert_eq!(pass(&mut fixture, &references, true, &mut state, None).0, 1);
    let unrelated = fixture.pile.snapshot().unwrap();
    fixture.writer.put::<SimpleArchive, _>(late_blob).unwrap();
    assert!(maintenance_changed(
        &unrelated,
        &fixture.pile.snapshot().unwrap(),
        &state.interests()
    ));
    let (failures, counts) = pass(&mut fixture, &references, true, &mut state, None);
    assert_eq!(failures, 0);
    assert_skipped(&counts, &fixture, 0);
    assert_skipped(&counts, &fixture, 1);
    assert!(counts.selected_calls[&late.handle()] >= 2);
    fixture.close();
}

#[test]
fn append_during_frozen_hop_is_not_absorbed_by_end_baseline() {
    let mut fixture = Fixture::new();
    fixture.warm();
    let mut state = State::default();
    let references = vec![handle_hex(fixture.targets[0].handle())];
    let path = fixture._directory.path().join("counted-maintenance.pile");
    let mut arriving_writer = Pile::open(&path).unwrap();
    let source = fixture.sources[0];
    let signer = fixture.signer.clone();
    let new_value = Id::new([4; 16]).unwrap();
    let hook = Arc::new(SelectionHook {
        collection: source.handle(),
        action: Mutex::new(Some(Box::new(move || {
            arriving_writer
                .commit(
                    source,
                    &signer,
                    receipt(new_value, "arrived during frozen work"),
                )
                .unwrap();
            arriving_writer.close().unwrap();
        }))),
    });
    // No dependency pass: the hook fires in target upkeep's source selection,
    // after Core has frozen its control frontier, not in an upstream census.
    let (failures, _) = pass(
        &mut fixture,
        &references,
        false,
        &mut state,
        Some(Arc::clone(&hook)),
    );
    assert_eq!(failures, 0);
    assert!(
        hook.action.lock().unwrap().is_none(),
        "actual source selection reached the injection"
    );
    let after = fixture.pile.snapshot().unwrap();
    assert_eq!(
        after
            .collection(fixture.targets[0])
            .unwrap()
            .support()
            .unwrap()
            .len(),
        1
    );
    assert!(maintenance_changed(
        &hop(&state, fixture.targets[0].handle()).before.inner,
        &after,
        &state.interests()
    ));
    let (failures, counts) = pass(&mut fixture, &references, false, &mut state, None);
    assert_eq!(failures, 0);
    assert!(counts.insertions[&fixture.targets[0].handle()][2] > 0);
    fixture.assert_value_and_support(&[fixture.first_value, new_value], 2);
    fixture.close();
}
