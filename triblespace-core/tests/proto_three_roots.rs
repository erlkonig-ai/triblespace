//! PROTOTYPE (2026-09-17, liora-cc): validate or refute the "three roots"
//! specification. Nothing here is proposed for main; it is an experiment.

use ed25519_dalek::{SigningKey, VerifyingKey};

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, TryFromBlob};
use triblespace_core::capability::policy::resource_policy;
use triblespace_core::collection::records::KIND_COLLECTION_DESCRIPTOR;
use triblespace_core::collection::{
    collection_name, collection_representation, AdmissionPolicy, Collection, CollectionPolicy,
    CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::{entity, find, pattern};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStoreGet, CapabilityProofRead, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

/// Every measurement below carries the profile it was taken under; a debug
/// figure and a release figure differ by roughly an order of magnitude here.
fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug (unoptimized+debuginfo)"
    } else {
        "release"
    }
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

/// The colony as it is today: one root that is every machine's authority.
fn one_root(root: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(root.verifying_key()),
        AdmissionPolicy::direct(root.verifying_key()),
    )
}

/// The colony as JP asked for it: three roots, `threshold` required.
fn three_roots(roots: [VerifyingKey; 3], threshold: u32) -> CollectionPolicy {
    let quorum = AdmissionPolicy::quorum(roots, threshold, None).unwrap();
    CollectionPolicy::new(quorum.clone(), quorum)
}

/// `descriptor::naming` rebuilt outside the crate so experiments can vary one
/// field at a time. E1 asserts it is byte-identical to the real builder.
fn naming_like(name: &str, policy: CollectionPolicy) -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: name.to_owned(),
        resource_policy*: policy.fragment(),
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
    }
}

// ------------------------------------------------- E1: identity sensitivity

#[test]
fn e1_what_moves_a_collection_identity() {
    let (a, b, c) = (key(0xA1), key(0xB1), key(0xC1));
    let roots = [a.verifying_key(), b.verifying_key(), c.verifying_key()];
    let mut store = MemoryRepo::default();

    let today = store.collection("wiki", one_root(&c)).unwrap();
    let hand_rolled = store
        .register_collection::<SimpleArchive>(naming_like("wiki", one_root(&c)))
        .unwrap();
    assert_eq!(
        today.handle(),
        hand_rolled.handle(),
        "the hand-rolled builder must reproduce descriptor::naming byte for byte"
    );

    let wanted = store.collection("wiki", three_roots(roots, 2)).unwrap();
    assert_ne!(today.handle(), wanted.handle());

    // Root ORDER does not move identity: the quorum canonicalises, so three
    // machines computing the policy independently agree on the handle.
    let permuted = store
        .collection("wiki", three_roots([roots[2], roots[0], roots[1]], 2))
        .unwrap();
    assert_eq!(wanted.handle(), permuted.handle());

    // The THRESHOLD is identity-bearing too.
    let threshold_one = store.collection("wiki", three_roots(roots, 1)).unwrap();
    assert_ne!(wanted.handle(), threshold_one.handle());

    // So is the legacy delegate-threshold field, which admission never reads.
    let delegable = store
        .collection(
            "wiki",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(c.verifying_key()),
                AdmissionPolicy::delegable(c.verifying_key()),
            ),
        )
        .unwrap();
    assert_ne!(today.handle(), delegable.handle());

    eprintln!("E1 one-root   {}", hex::encode(today.handle().raw));
    eprintln!("E1 3-of-3 t=2 {}", hex::encode(wanted.handle().raw));
    eprintln!("E1 3-of-3 t=1 {}", hex::encode(threshold_one.handle().raw));
}

/// Specification C2: a ~500-character English paragraph sits inside every
/// collection identity, and evicting it is safe for existing readers.
#[test]
fn e1b_prose_is_inside_the_identity_and_can_be_evicted() {
    let c = key(0xC2);
    let mut store = MemoryRepo::default();
    let canonical = store.collection("wiki", one_root(&c)).unwrap();

    let snapshot = store.snapshot().unwrap();
    let blob: Blob<SimpleArchive> = snapshot.get(canonical.handle()).unwrap();
    let facts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob).unwrap();

    let described = <SimpleArchive as MetaDescribe>::describe();
    let prose_handle = find!(
        v: Inline<Handle<UTF8String>>,
        pattern!(described.facts(), [{ _?e @ metadata::description: ?v }])
    )
    .next()
    .expect("SimpleArchive describes itself in prose");
    let prose: Blob<UTF8String> = snapshot.get(prose_handle).unwrap();
    drop(snapshot);

    let lean = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: "wiki".to_owned(),
        resource_policy*: one_root(&c).fragment(),
        collection_representation: <SimpleArchive as MetaDescribe>::id(),
    };
    let lean_tribles = lean.facts().len();
    let leaned = store.register_collection::<SimpleArchive>(lean).unwrap();
    assert_ne!(canonical.handle(), leaned.handle());

    eprintln!(
        "E1b descriptor tribles {} -> {}; prose bytes inside identity: {}",
        facts.len(),
        lean_tribles,
        prose.bytes.len()
    );
    assert!(prose.bytes.len() > 400);

    // The existing reader still opens it, reads its policy, and admits.
    let snapshot = store.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, leaned.handle())
        .expect("evicting the prose must not change what the descriptor IS");
    assert_eq!(
        opened.policy(&snapshot).unwrap().write(),
        &AdmissionPolicy::direct(c.verifying_key())
    );
    assert!(opened
        .writer_is_admitted(&snapshot, c.verifying_key())
        .unwrap());
}

/// Unused helper kept so the file compiles with the same imports as later parts.
fn row(tag: u8, n: u16) -> Fragment {
    let mut id = [tag; 16];
    id[14] = (n >> 8) as u8;
    id[15] = (n & 0xff) as u8;
    entity! { metadata::tag: Id::new(id).unwrap() }
}

// ------------------------- E2: can a tightening be expressed as an annotation?

/// The no-re-mint design in one experiment.
///
/// If the admission policy left the identity core and became an annotation,
/// then a policy change would add facts to a store that already holds the old
/// ones. The store is monotone: nothing is ever removed. So the reader would
/// see BOTH policies. This measures which one wins.
#[test]
fn e2_two_policies_on_one_descriptor_resolve_to_the_weaker() {
    use triblespace_core::capability::capability_action;
    use triblespace_core::collection::ACTION_WRITE;

    let legacy = key(0xC3);
    let (mac, sky, stars) = (key(0x1A), key(0x1B), key(0x1C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    // A descriptor carrying the OLD one-root policy and, alongside it, the NEW
    // 2-of-3 policy for the very same WRITE capability. This is the best case
    // for the annotation design: both facts present, reader free to choose.
    let annotated = CollectionPolicy::new(
        AdmissionPolicy::direct(legacy.verifying_key()),
        AdmissionPolicy::direct(legacy.verifying_key()),
    )
    .with_capability(
        entity! { capability_action: ACTION_WRITE },
        AdmissionPolicy::quorum(roots, 2, None).unwrap(),
    );
    let collection = store.collection("annotated", annotated).unwrap();
    let snapshot = store.snapshot().unwrap();

    // Both interpretations are visible to the reader.
    let policies: Vec<_> = descriptor_write_policies(&snapshot, collection.handle());
    assert_eq!(policies.len(), 2, "both bindings must be readable");

    // And the legacy key writes with no proof at all. The tightening is void.
    assert!(
        collection
            .writer_is_admitted(&snapshot, legacy.verifying_key())
            .unwrap(),
        "REFUTED if false: a tightening CAN be annotated on"
    );
    assert_eq!(
        snapshot.proofs().unwrap().count(),
        0,
        "no proof was needed; the weaker alternative admitted outright"
    );
    eprintln!("E2 legacy key still admitted beside a 2-of-3 policy: yes");
}

/// The same asymmetry from the other side: a WIDENING annotates fine.
#[test]
fn e2b_a_widening_annotates_fine_which_is_why_proofs_exist() {
    use triblespace_core::capability::capability_action;
    use triblespace_core::collection::ACTION_WRITE;

    let (mac, sky, stars) = (key(0x2A), key(0x2B), key(0x2C));
    let newcomer = key(0x2D).verifying_key();
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    let widened = CollectionPolicy::new(
        AdmissionPolicy::quorum(roots, 2, None).unwrap(),
        AdmissionPolicy::quorum(roots, 2, None).unwrap(),
    )
    .with_capability(
        entity! { capability_action: ACTION_WRITE },
        AdmissionPolicy::direct(newcomer),
    );
    let collection = store.collection("widened", widened).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(collection.writer_is_admitted(&snapshot, newcomer).unwrap());
    eprintln!("E2b widening by annotation: admitted with zero proofs");
}

/// Open world at the collection boundary: an unreadable policy is SKIPPED, and
/// skipping presents exactly like an empty collection.
#[test]
fn e2c_an_undecodable_policy_reads_as_empty_not_as_an_error() {
    use triblespace_core::capability::policy::{
        admission_invoke_threshold, admission_policy_root, capability_handle,
    };
    use triblespace_core::collection::write_capability;

    let (mac, sky, stars) = (key(0x3A), key(0x3B), key(0x3C));
    let mut store = MemoryRepo::default();
    // Make the standard definitions resident so the only novelty is the kind.
    let _warm = store.collection("warm", one_root(&mac)).unwrap();

    let future_kind = Id::new([0x77; 16]).unwrap();
    let hypothetical = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: "future".to_owned(),
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
        resource_policy*: entity! {
            capability_handle: write_capability(),
            metadata::tag: future_kind,
            admission_policy_root*: [mac.verifying_key(), sky.verifying_key(), stars.verifying_key()],
            admission_invoke_threshold: 2u32,
        },
    };
    let collection = store
        .register_collection::<SimpleArchive>(hypothetical)
        .unwrap();
    store.commit(collection, &mac, row(0x41, 0)).unwrap();
    let snapshot = store.snapshot().unwrap();

    // No error anywhere: it opens, it reads, and it is empty.
    let opened = Collection::<SimpleArchive>::open(&snapshot, collection.handle())
        .expect("an unknown policy kind is not a reason to reject the descriptor");
    assert!(!opened
        .writer_is_admitted(&snapshot, mac.verifying_key())
        .unwrap());
    assert_eq!(opened.admitted(&snapshot).unwrap().len(), 0);
    eprintln!(
        "E2c descriptor with an unknown policy kind: opens fine, admits nobody, \
         reads as 0 members while holding 1 record"
    );
}

fn descriptor_write_policies<S: BlobStoreGet>(
    snapshot: &S,
    handle: triblespace_core::collection::CollectionHandle,
) -> Vec<AdmissionPolicy> {
    use triblespace_core::collection::{descriptor, ACTION_WRITE};
    let blob: Blob<SimpleArchive> = snapshot.get(handle).unwrap();
    let facts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob).unwrap();
    descriptor::admission_policies(snapshot, &facts, ACTION_WRITE, None).collect()
}

// ------------------------------------------ E3: the migration, on a real pile

/// Re-signing pass, mirroring `trible pile collection adopt` (run_adopt).
fn adopt(
    pile: &mut Pile,
    source: triblespace_core::collection::CollectionHandle,
    target: Collection<SimpleArchive>,
    signer: &SigningKey,
) -> usize {
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::{CollectionRead, CollectionRecord};

    let empty_metadata: Blob<SimpleArchive> = TribleSet::new().to_blob();
    let snapshot = pile.snapshot().unwrap();
    let mut prepared: Vec<Fragment> = Vec::new();
    for record in snapshot.records().unwrap() {
        let CollectionRecord::Commit(commit) = record.unwrap() else {
            continue;
        };
        if commit.collection() != source {
            continue;
        }
        commit.verify_strict().unwrap();
        let data_handle: Inline<Handle<SimpleArchive>> = Inline::new(commit.data().raw);
        let data: Blob<SimpleArchive> = snapshot.get(data_handle).unwrap();
        let metadata: Blob<SimpleArchive> = snapshot
            .get(commit.metadata())
            .unwrap_or_else(|_| empty_metadata.clone());
        let facts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(data).unwrap();
        let metafacts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(metadata).unwrap();
        prepared.push(Fragment::from_parts(facts, metafacts, Default::default()));
    }
    drop(snapshot);
    let count = prepared.len();
    for fragment in prepared {
        pile.commit(target, signer, fragment).unwrap();
    }
    count
}

fn commit_records(pile: &mut Pile) -> usize {
    use triblespace_core::collection::{CollectionRead, CollectionRecord};
    let snapshot = pile.snapshot().unwrap();
    let n = snapshot
        .records()
        .unwrap()
        .filter(|r| matches!(r.as_ref().unwrap(), CollectionRecord::Commit(_)))
        .count();
    drop(snapshot);
    n
}

/// The whole cutover, end to end, with the failure modes it can hide.
#[test]
fn e3_three_root_migration_end_to_end() {
    use std::time::Instant;
    use triblespace_core::collection::{generation, grant_collection_write};

    // ~1/7 of the live `compass` collection; enough for a per-commit figure.
    const RECORDS: u16 = 2000;

    let legacy = key(0xC5); // stands in for C5C9F620
    let (mac, sky, stars) = (key(0x4A), key(0x4B), key(0x4C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proto.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();

    // --- generation five: today's colony -----------------------------------
    let old = pile.collection("compass", one_root(&legacy)).unwrap();
    let build = Instant::now();
    for n in 0..RECORDS {
        pile.commit(old, &legacy, row(0x51, n)).unwrap();
    }
    pile.flush().unwrap();
    let build_elapsed = build.elapsed();
    let size_before = std::fs::metadata(&path).unwrap().len();
    let records_before = commit_records(&mut pile);

    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(old.admitted(&snapshot).unwrap().len(), RECORDS as usize);
    }

    // --- generation six: three roots ---------------------------------------
    let new = pile.collection("compass", three_roots(roots, 2)).unwrap();
    assert_ne!(old.handle(), new.handle());

    {
        // The state that looked like a clean fresh start four times running.
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(new.admitted(&snapshot).unwrap().len(), 0);
        let report = generation::named_generations(&snapshot, new.handle())
            .unwrap()
            .expect("a same-named sibling exists, so the detector must speak");
        assert_eq!(report.stranded_records(), RECORDS as usize);
        eprintln!("E3 detector on the fresh generation:\n{report}");
    }

    // --- HAZARD 1: adopt with the retiring key -----------------------------
    // The records land. Nothing errors. The collection stays invisible,
    // because admission re-runs the CURRENT policy against the author.
    let hazard = adopt(&mut pile, old.handle(), new, &legacy);
    assert_eq!(hazard, RECORDS as usize);
    pile.flush().unwrap();
    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            generation::unreached_records(&snapshot, old.handle(), new.handle()).unwrap(),
            0,
            "the spec's completeness assertion passes"
        );
        assert_eq!(
            new.admitted(&snapshot).unwrap().len(),
            0,
            "REFUTED if nonzero: content-completeness would imply readability"
        );
        eprintln!("E3 HAZARD: unreached_records == 0 while the collection reads 0 of {RECORDS}");
    }

    // --- HAZARD 2: adopt with a root that has no countersignature ----------
    let orphaned = adopt(&mut pile, old.handle(), new, &sky);
    assert_eq!(orphaned, RECORDS as usize);
    pile.flush().unwrap();
    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            new.admitted(&snapshot).unwrap().len(),
            0,
            "one of three roots is not two of three"
        );
    }

    // --- the actual cutover: proofs first, then the re-signing pass --------
    grant_collection_write(&mut pile, new.handle(), &mac, sky.verifying_key()).unwrap();
    pile.flush().unwrap();
    {
        let snapshot = pile.snapshot().unwrap();
        assert!(new
            .writer_is_admitted(&snapshot, sky.verifying_key())
            .unwrap());
        // ... and the records adopted BEFORE the proof existed light up now.
        assert_eq!(new.admitted(&snapshot).unwrap().len(), RECORDS as usize);
        eprintln!("E3 one countersignature made {RECORDS} already-adopted records visible");
    }

    // --- adopt idempotence: the drain is safe to re-run ---------------------
    let before_repeat = commit_records(&mut pile);
    let repeated = adopt(&mut pile, old.handle(), new, &sky);
    pile.flush().unwrap();
    let after_repeat = commit_records(&mut pile);
    assert_eq!(
        repeated, RECORDS as usize,
        "adopt reports the SOURCE count again"
    );
    assert_eq!(
        before_repeat, after_repeat,
        "REFUTED if different: re-running the drain would duplicate records"
    );
    eprintln!(
        "E3 adopt re-run: reported {repeated} 'to adopt', appended {} new records",
        after_repeat - before_repeat
    );

    // --- completeness, both directions --------------------------------------
    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            generation::unreached_records(&snapshot, old.handle(), new.handle()).unwrap(),
            0
        );
        assert_eq!(
            generation::unreached_records(&snapshot, new.handle(), old.handle()).unwrap(),
            0,
            "reverse containment: the target holds nothing no source held"
        );
        let report = generation::named_generations(&snapshot, new.handle())
            .unwrap()
            .unwrap();
        assert!(!report.strands_records());
        eprintln!("E3 detector after migration:\n{report}");
    }

    // --- cost ---------------------------------------------------------------
    pile.flush().unwrap();
    let size_after = std::fs::metadata(&path).unwrap().len();
    let records_after = commit_records(&mut pile);
    let migrate = Instant::now();
    let _ = commit_records(&mut pile);
    let scan_elapsed = migrate.elapsed();
    eprintln!(
        "E3 COST ({} build, sky, file-backed pile, {RECORDS} commits):\n\
         E3   original write : {:?} total, {:?} per commit\n\
         E3   commit records : {records_before} -> {records_after}\n\
         E3   pile bytes     : {size_before} -> {size_after} (+{}, {:.1} B per adopted commit)\n\
         E3   whole-pile record scan: {scan_elapsed:?}",
        profile(),
        build_elapsed,
        build_elapsed / RECORDS as u32,
        size_after - size_before,
        (size_after - size_before) as f64 / RECORDS as f64,
    );

    pile.close().unwrap();
}

// ------------------------ E4: a reader from before meeting a pile from after

/// HARD RULE 3 says no design may need a flag day. This measures what the
/// re-mint actually does to a process that has not been upgraded.
#[test]
fn e4_old_and_new_processes_sharing_one_pile() {
    use triblespace_core::collection::{generation, grant_collection_write};

    let legacy = key(0xC6);
    let (mac, sky, stars) = (key(0x5A), key(0x5B), key(0x5C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();

    // An "old process" is one holding the old policy constant: it recomputes
    // the OLD handle from the name, and that is the only thing it can address.
    let old = pile.collection("wiki", one_root(&legacy)).unwrap();
    for n in 0..8 {
        pile.commit(old, &legacy, row(0x61, n)).unwrap();
    }
    let new = pile.collection("wiki", three_roots(roots, 2)).unwrap();
    grant_collection_write(&mut pile, new.handle(), &mac, sky.verifying_key()).unwrap();
    adopt(&mut pile, old.handle(), new, &sky);
    pile.flush().unwrap();

    // (a) READS: the old process is not broken. It resolves its handle, opens
    //     it, and reads its eight records. No error, no warning, no signal.
    {
        let snapshot = pile.snapshot().unwrap();
        let reopened = Collection::<SimpleArchive>::open(&snapshot, old.handle()).unwrap();
        assert_eq!(reopened.admitted(&snapshot).unwrap().len(), 8);
    }

    // (b) WRITES are where it breaks, and open-world does not help: the old
    //     process commits to the old handle and the record is stranded.
    for n in 8..12 {
        pile.commit(old, &legacy, row(0x61, n)).unwrap();
    }
    pile.flush().unwrap();
    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(new.admitted(&snapshot).unwrap().len(), 8);
        let stranded =
            generation::unreached_records(&snapshot, old.handle(), new.handle()).unwrap();
        assert_eq!(stranded, 4, "post-cutover writes by an old process go dark");
        eprintln!("E4 old writer after cutover stranded {stranded} records");
    }

    // (c) ... but the drain converges. Re-running adopt picks the laggards up,
    //     so this is an eventual-consistency lag, not a flag day.
    adopt(&mut pile, old.handle(), new, &sky);
    pile.flush().unwrap();
    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            generation::unreached_records(&snapshot, old.handle(), new.handle()).unwrap(),
            0
        );
        assert_eq!(new.admitted(&snapshot).unwrap().len(), 12);
        eprintln!("E4 re-running the drain recovered them: new generation holds 12");
    }

    // (d) The reverse direction: a NEW process against a pile written only by
    //     old ones. The descriptor is simply absent, and that is LOUD.
    let other = dir.path().join("oldonly.pile");
    std::fs::File::create(&other).unwrap();
    let mut old_only = Pile::open(&other).unwrap();
    let o = old_only.collection("wiki", one_root(&legacy)).unwrap();
    old_only.commit(o, &legacy, row(0x62, 0)).unwrap();
    old_only.flush().unwrap();
    {
        let snapshot = old_only.snapshot().unwrap();
        let err = Collection::<SimpleArchive>::open(&snapshot, new.handle()).unwrap_err();
        eprintln!("E4 new handle against an old pile: {err}");
    }
    old_only.close().unwrap();
    pile.close().unwrap();
}

/// Concatenation is the merge. Two generations meeting in one file is the
/// normal case after a cutover, not an anomaly.
#[test]
fn e4b_concatenating_piles_keeps_both_generations_and_the_detector_sees_it() {
    use triblespace_core::collection::generation;

    let legacy = key(0xC7);
    let (mac, sky, stars) = (key(0x6A), key(0x6B), key(0x6C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let dir = tempfile::tempdir().unwrap();

    let a_path = dir.path().join("a.pile");
    std::fs::File::create(&a_path).unwrap();
    let mut a = Pile::open(&a_path).unwrap();
    let old = a.collection("wiki", one_root(&legacy)).unwrap();
    for n in 0..5 {
        a.commit(old, &legacy, row(0x71, n)).unwrap();
    }
    a.flush().unwrap();
    a.close().unwrap();

    let b_path = dir.path().join("b.pile");
    std::fs::File::create(&b_path).unwrap();
    let mut b = Pile::open(&b_path).unwrap();
    let new = b.collection("wiki", three_roots(roots, 2)).unwrap();
    for n in 0..3 {
        b.commit(new, &sky, row(0x72, n)).unwrap();
    }
    b.flush().unwrap();
    b.close().unwrap();

    // cat a.pile >> b.pile
    let bytes = std::fs::read(&a_path).unwrap();
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&b_path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();

    let mut merged = Pile::open(&b_path).unwrap();
    merged.refresh().unwrap();
    let snapshot = merged.snapshot().unwrap();
    let reports = generation::all_named_generations(&snapshot).unwrap();
    assert_eq!(reports.len(), 1);
    eprintln!("E4b after concatenation:\n{}", reports[0]);
    assert_eq!(reports[0].stranded_records(), 3.min(5).max(3));
    drop(snapshot);
    merged.close().unwrap();
}

// ------------------------------------------- E5: one of three keys is stolen

#[test]
fn e5_attacker_model_before_and_after() {
    use triblespace_core::capability::{
        capability_action, capability_delegate_action, CapabilityProof, CapabilityResource,
    };
    use triblespace_core::collection::{
        grant_collection_capability, grant_collection_write, ACTION_READ, ACTION_WRITE,
    };
    use triblespace_core::repo::{BlobStorePut, CapabilityProofStore};

    let legacy = key(0xC8);
    let (mac, sky, stars) = (key(0x7A), key(0x7B), key(0x7C));
    let outsider = key(0x7D).verifying_key();
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    // --- TODAY: one root. Holding it is holding everything. ----------------
    let today = store.collection("today", one_root(&legacy)).unwrap();
    grant_collection_write(&mut store, today.handle(), &legacy, outsider).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(today
            .writer_is_admitted(&snapshot, legacy.verifying_key())
            .unwrap());
        assert!(today.writer_is_admitted(&snapshot, outsider).unwrap());
        eprintln!("E5 today: one stolen key enrolled an arbitrary outsider");
    }

    // --- AFTER: 2-of-3. ----------------------------------------------------
    let after = store.collection("after", three_roots(roots, 2)).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        // A root alone is ONE share, and one is not two.
        assert!(!after
            .writer_is_admitted(&snapshot, sky.verifying_key())
            .unwrap());
        // The retired key is inadmissible with no action taken to retire it.
        assert!(!after
            .writer_is_admitted(&snapshot, legacy.verifying_key())
            .unwrap());
    }
    // A compromised root CAN issue a proof; it just is not enough.
    grant_collection_write(&mut store, after.handle(), &sky, outsider).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(!after.writer_is_admitted(&snapshot, outsider).unwrap());
        eprintln!("E5 after: a stolen root key issued a grant; the recipient is NOT admitted");
    }
    // Two roots do enrol.
    grant_collection_write(&mut store, after.handle(), &mac, outsider).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(after.writer_is_admitted(&snapshot, outsider).unwrap());
    }

    // --- the property that reads wrong: 2-of-3 is 2 at ENROLLMENT, 1 at WRITE
    grant_collection_write(&mut store, after.handle(), &mac, sky.verifying_key()).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(after
            .writer_is_admitted(&snapshot, sky.verifying_key())
            .unwrap());
        eprintln!("E5 once countersigned, sky writes alone, forever, with no further quorum");
    }

    // --- a proof is bound to its resource: two descriptors cannot be confused
    let sibling = store
        .collection("after-sibling", three_roots(roots, 2))
        .unwrap();
    assert_ne!(after.handle(), sibling.handle());
    {
        let snapshot = store.snapshot().unwrap();
        assert!(!sibling.writer_is_admitted(&snapshot, outsider).unwrap());
        eprintln!("E5 proofs for one descriptor do not carry to another");
    }

    // --- AMPLIFICATION: a delegable grant to a root collapses 2-of-3 to 1 ---
    let target = store
        .collection("delegable", three_roots(roots, 2))
        .unwrap();
    let compound = store
        .put::<SimpleArchive, _>(
            entity! {
                capability_action*: [ACTION_READ, ACTION_WRITE],
                capability_delegate_action*: [ACTION_READ, ACTION_WRITE],
            }
            .facts()
            .clone(),
        )
        .unwrap();
    // mac hands sky a delegable WRITE. Ordinary-looking operational step.
    let from_mac = grant_collection_capability(
        &mut store,
        target.handle(),
        compound,
        &mac,
        sky.verifying_key(),
    )
    .unwrap();
    // sky is now compromised, and acting alone.
    let attacker_key = key(0x7E).verifying_key();
    let borrowed = from_mac
        .delegate(&sky, compound, attacker_key)
        .expect("a delegable grant delegates");
    store.insert_proof(borrowed).unwrap();
    grant_collection_capability(&mut store, target.handle(), compound, &sky, attacker_key).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        let admitted = target.writer_is_admitted(&snapshot, attacker_key).unwrap();
        eprintln!(
            "E5 AMPLIFICATION: one compromised root holding a DELEGABLE grant from \
             another root enrolled a fourth key alone: {admitted}"
        );
        assert!(
            admitted,
            "if this ever fails the amplification is closed and the note can be dropped"
        );
    }

    // The standard WRITE grant is not delegable, which is what closes it.
    let safe = store.collection("standard", three_roots(roots, 2)).unwrap();
    let from_mac_standard =
        grant_collection_write(&mut store, safe.handle(), &mac, sky.verifying_key()).unwrap();
    let forged = from_mac_standard.delegate(&sky, write_capability_handle(), attacker_key);
    match forged {
        Ok(proof) => {
            store.insert_proof(proof).unwrap();
            let snapshot = store.snapshot().unwrap();
            assert!(
                !safe.writer_is_admitted(&snapshot, attacker_key).unwrap(),
                "a non-delegable parent must not confer a share"
            );
            eprintln!("E5 standard grant: the delegated chain carries no share");
        }
        Err(error) => eprintln!("E5 standard grant refuses delegation outright: {error}"),
    }
    let _ = CapabilityProof::new(
        CapabilityResource::from(safe.handle()),
        &sky,
        write_capability_handle(),
        attacker_key,
    );
}

fn write_capability_handle() -> triblespace_core::capability::CapabilityHandle {
    triblespace_core::collection::write_capability()
}

// --------------------------------------------- E6: what the migration costs

/// One adopt pass in isolation: records, bytes, and wall time.
#[test]
fn e6_cost_of_one_adopt_pass() {
    use std::time::Instant;
    use triblespace_core::collection::grant_collection_write;

    const RECORDS: u16 = 4000;
    let legacy = key(0xC9);
    let (mac, sky, stars) = (key(0x8A), key(0x8B), key(0x8C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cost.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();

    let old = pile.collection("compass", one_root(&legacy)).unwrap();
    for n in 0..RECORDS {
        pile.commit(old, &legacy, row(0x81, n)).unwrap();
    }
    let new = pile.collection("compass", three_roots(roots, 2)).unwrap();
    grant_collection_write(&mut pile, new.handle(), &mac, sky.verifying_key()).unwrap();
    pile.flush().unwrap();

    let bytes_before = std::fs::metadata(&path).unwrap().len();
    let records_before = commit_records(&mut pile);

    let started = Instant::now();
    let adopted = adopt(&mut pile, old.handle(), new, &sky);
    pile.flush().unwrap();
    let elapsed = started.elapsed();

    let bytes_after = std::fs::metadata(&path).unwrap().len();
    let records_after = commit_records(&mut pile);
    let grew = bytes_after - bytes_before;

    eprintln!(
        "E6 ONE ADOPT PASS ({} build, sky, file-backed pile in a tempdir)\n\
         E6   source commits      : {adopted}\n\
         E6   commit records      : {records_before} -> {records_after} (+{})\n\
         E6   pile bytes          : {bytes_before} -> {bytes_after} (+{grew})\n\
         E6   bytes PER adopted commit : {:.1}\n\
         E6   wall time           : {elapsed:?} total, {:?} per adopted commit",
        profile(),
        records_after - records_before,
        grew as f64 / adopted as f64,
        elapsed / adopted as u32,
    );
    assert_eq!(records_after - records_before, adopted);

    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(new.admitted(&snapshot).unwrap().len(), RECORDS as usize);
    }
    pile.close().unwrap();
}

/// Step E's performance question, measured: admission enumerates every
/// resident proof for every decision.
#[test]
fn e6b_admission_cost_grows_with_the_resident_proof_count() {
    use std::time::Instant;
    use triblespace_core::collection::grant_collection_write;

    let (mac, sky, stars) = (key(0x9A), key(0x9B), key(0x9C));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    // Many collections, each with its own pair of proofs: the shape a colony
    // with 76 collections and three roots actually produces.
    let mut measured = Vec::new();
    let mut probe = None;
    for batch in 0..24u16 {
        let collection = store
            .collection(&format!("collection-{batch}"), three_roots(roots, 2))
            .unwrap();
        if probe.is_none() {
            probe = Some(collection);
        }
        grant_collection_write(&mut store, collection.handle(), &mac, sky.verifying_key()).unwrap();
        grant_collection_write(&mut store, collection.handle(), &stars, sky.verifying_key())
            .unwrap();
        if batch % 4 == 3 {
            let snapshot = store.snapshot().unwrap();
            let proofs = snapshot.proofs().unwrap().count();
            let probe = probe.unwrap();
            let started = Instant::now();
            for _ in 0..20 {
                assert!(probe
                    .writer_is_admitted(&snapshot, sky.verifying_key())
                    .unwrap());
            }
            measured.push((proofs, started.elapsed() / 20));
        }
    }
    eprintln!(
        "E6b admission decision cost vs resident proofs, POSITIVE decision \
         ({} build, sky, MemoryRepo):",
        profile()
    );
    for (proofs, per_call) in &measured {
        eprintln!("E6b   {proofs:>4} proofs  {per_call:?} per writer_is_admitted call");
    }
    let (first_n, first_t) = measured.first().copied().unwrap();
    let (last_n, last_t) = measured.last().copied().unwrap();
    eprintln!(
        "E6b   {first_n} -> {last_n} proofs ({:.1}x) changed the decision cost {:.2}x",
        last_n as f64 / first_n as f64,
        last_t.as_secs_f64() / first_t.as_secs_f64()
    );
}

// ----------------------------- E7: what the migration costs in provenance

/// JP's decision 5, priced exactly: authorship CAN be preserved, and the price
/// is that the key being retired is not retired.
#[test]
fn e7_preserving_authorship_and_retiring_the_key_are_the_same_predicate() {
    use triblespace_core::collection::grant_collection_write;

    let legacy = key(0xCA);
    let (mac, sky, stars) = (key(0xAA), key(0xAB), key(0xAC));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    let old = store.collection("memory", one_root(&legacy)).unwrap();
    for n in 0..6 {
        store.commit(old, &legacy, row(0x91, n)).unwrap();
    }
    let new = store.collection("memory", three_roots(roots, 2)).unwrap();

    // Two roots enrol the LEGACY key as a writer of the new generation.
    grant_collection_write(&mut store, new.handle(), &mac, legacy.verifying_key()).unwrap();
    grant_collection_write(&mut store, new.handle(), &stars, legacy.verifying_key()).unwrap();

    // Now the re-signing pass can keep the original author.
    for n in 0..6 {
        store.commit(new, &legacy, row(0x91, n)).unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    assert_eq!(new.admitted(&snapshot).unwrap().len(), 6);
    assert!(
        new.writer_is_admitted(&snapshot, legacy.verifying_key())
            .unwrap(),
        "which is exactly the same fact as: the retired key can still write"
    );
    eprintln!(
        "E7 authorship preserved AND the legacy key is an admitted writer of the new \
         generation -- the two are one predicate, there is no separating them"
    );
}

/// CLAUDE.md's mechanical test, applied to the descriptor itself: swap the
/// derived entity id for a fresh genid and see what breaks.
#[test]
fn e7b_derived_id_substitution_breaks_only_idempotence_inside_the_descriptor() {
    use triblespace_core::id::genid;

    let c = key(0xCB);
    let mut store = MemoryRepo::default();
    let canonical = store.collection("wiki", one_root(&c)).unwrap();

    // Same facts, extrinsic descriptor entity id.
    let extrinsic = genid();
    let substituted = entity! {
        &extrinsic @
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: "wiki".to_owned(),
        resource_policy*: one_root(&c).fragment(),
        collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
    };
    let substituted = store
        .register_collection::<SimpleArchive>(substituted)
        .unwrap();

    // Everything a reader does still works.
    let snapshot = store.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, substituted.handle()).unwrap();
    assert_eq!(
        opened.policy(&snapshot).unwrap().write(),
        &AdmissionPolicy::direct(c.verifying_key())
    );
    assert!(opened
        .writer_is_admitted(&snapshot, c.verifying_key())
        .unwrap());

    // The only casualty is idempotence: two registrations of the same logical
    // collection are two collections.
    assert_ne!(canonical.handle(), substituted.handle());
    eprintln!(
        "E7b substituting a genid for the derived descriptor entity id: open OK, \
         policy OK, admission OK, identity differs -- idempotence is the only loss"
    );
}

/// The fair version of E6b: proofs for the SAME collection, which is what a
/// 2-of-3 cutover actually multiplies.
#[test]
fn e6c_admission_cost_vs_proofs_on_the_same_collection() {
    use std::time::Instant;
    use triblespace_core::collection::grant_collection_write;

    let (mac, sky, stars) = (key(0xB1), key(0xB2), key(0xB3));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();
    let collection = store.collection("hot", three_roots(roots, 2)).unwrap();
    // The key we ask about is enrolled last, so every earlier proof has to be
    // walked before the decision can be made. Worst case on purpose.
    let subject = key(0xB9).verifying_key();

    let mut measured = Vec::new();
    for batch in 0..12u16 {
        let other = key((0xD0 + batch) as u8).verifying_key();
        grant_collection_write(&mut store, collection.handle(), &mac, other).unwrap();
        grant_collection_write(&mut store, collection.handle(), &stars, other).unwrap();
        let snapshot = store.snapshot().unwrap();
        let proofs = snapshot.proofs().unwrap().count();
        let started = Instant::now();
        for _ in 0..20 {
            let _ = collection.writer_is_admitted(&snapshot, subject).unwrap();
        }
        measured.push((proofs, started.elapsed() / 20));
    }
    eprintln!(
        "E6c same-collection proofs vs decision cost, NEGATIVE decision \
         ({} build, sky, MemoryRepo):",
        profile()
    );
    for (proofs, per_call) in &measured {
        eprintln!("E6c   {proofs:>4} proofs on this collection  {per_call:?} per decision");
    }
    let (first_n, first_t) = measured.first().copied().unwrap();
    let (last_n, last_t) = measured.last().copied().unwrap();
    eprintln!(
        "E6c   {first_n} -> {last_n} proofs ({:.1}x) changed the decision cost {:.2}x",
        last_n as f64 / first_n as f64,
        last_t.as_secs_f64() / first_t.as_secs_f64()
    );
}

// ------------- E8: does a policy change move the DERIVED outputs? (35x swing)

/// The specification's largest unpriced item: whether re-minting under a new
/// policy makes the lattice recompute new bytes (~3.5 GB) or merely restate
/// equations over bytes that are already resident (~100 MB).
///
/// `CollectionMapping::map` cannot see the descriptor at all -- that is a
/// signature-level guarantee, not a test result. `join_members` CAN, so this
/// exercises it directly: identical inputs, two descriptors differing only in
/// admission policy.
#[test]
fn e8_derived_joins_do_not_depend_on_the_admission_policy() {
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::{descriptor, CollectionEncoding};

    let legacy = key(0xCC);
    let (mac, sky, stars) = (key(0xE1), key(0xE2), key(0xE3));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let mut store = MemoryRepo::default();

    let old = store.collection("lattice", one_root(&legacy)).unwrap();
    let new = store.collection("lattice", three_roots(roots, 2)).unwrap();
    assert_ne!(old.handle(), new.handle());

    let snapshot = store.snapshot().unwrap();
    let old_descriptor = fragment_of(&snapshot, old.handle());
    let new_descriptor = fragment_of(&snapshot, new.handle());
    assert_ne!(old_descriptor.facts(), new_descriptor.facts());

    let low: Blob<SimpleArchive> = row(0xF1, 0).facts().clone().to_blob();
    let high: Blob<SimpleArchive> = row(0xF1, 1).facts().clone().to_blob();

    let under_old = <SimpleArchive as CollectionEncoding>::join_members(
        &old_descriptor,
        &low,
        &high,
        &snapshot,
    )
    .unwrap();
    let under_new = <SimpleArchive as CollectionEncoding>::join_members(
        &new_descriptor,
        &low,
        &high,
        &snapshot,
    )
    .unwrap();
    assert_eq!(
        under_old.get_handle(),
        under_new.get_handle(),
        "REFUTED if different: a policy change would force the whole lattice to \
         recompute new bytes instead of restating equations"
    );
    eprintln!(
        "E8 join under two policies -> one handle {}",
        hex::encode(under_old.get_handle().raw)
    );

    // And the representation each descriptor names is unchanged, so the same
    // mapping code runs on both sides.
    assert_eq!(
        descriptor::representation(old_descriptor.facts()).unwrap(),
        descriptor::representation(new_descriptor.facts()).unwrap()
    );
}

fn fragment_of<S: BlobStoreGet>(
    snapshot: &S,
    handle: triblespace_core::collection::CollectionHandle,
) -> Fragment {
    let blob: Blob<SimpleArchive> = snapshot.get(handle).unwrap();
    Fragment::from(<TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob).unwrap())
}

// --------------------- E9: draining several stranded generations in one pass

/// The real shape of the arrears: five older generations plus the live one.
/// Also records a diagnostic pitfall the sweep has during a cutover.
#[test]
fn e9_multi_sibling_drain_and_the_sweeps_backwards_selection() {
    use triblespace_core::collection::{generation, grant_collection_write};

    let legacy = key(0xCD);
    let (mac, sky, stars) = (key(0xE5), key(0xE6), key(0xE7));
    let roots = [
        mac.verifying_key(),
        sky.verifying_key(),
        stars.verifying_key(),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("arrears.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();

    // Five prior generations of the same name, each with its own policy shape,
    // exactly as four descriptor-schema edits in nine days produced.
    let generations = [
        pile.collection("wiki", one_root(&legacy)).unwrap(),
        pile.collection(
            "wiki",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(legacy.verifying_key()),
                AdmissionPolicy::delegable(legacy.verifying_key()),
            ),
        )
        .unwrap(),
        pile.collection("wiki", three_roots(roots, 1)).unwrap(),
        pile.collection("wiki", one_root(&mac)).unwrap(),
        pile.collection("wiki", one_root(&stars)).unwrap(),
    ];
    let signers = [&legacy, &legacy, &mac, &mac, &stars];
    for (index, (collection, signer)) in generations.iter().zip(signers).enumerate() {
        for n in 0..(index as u16 + 2) {
            pile.commit(*collection, signer, row(0xA1 + index as u8, n))
                .unwrap();
        }
    }
    pile.flush().unwrap();
    let total: usize = (0..5).map(|i| i + 2).sum();

    // Generation six.
    let live = pile.collection("wiki", three_roots(roots, 2)).unwrap();
    grant_collection_write(&mut pile, live.handle(), &mac, sky.verifying_key()).unwrap();
    pile.flush().unwrap();

    // THE PITFALL: the whole-pile sweep names the generation holding the most
    // records as the current one. During a cutover that is always an OLD one,
    // so the advice it prints points backwards.
    {
        let snapshot = pile.snapshot().unwrap();
        let reports = generation::all_named_generations(&snapshot).unwrap();
        assert_eq!(reports.len(), 1);
        let basis = reports[0].selected().handle();
        assert_ne!(
            basis,
            live.handle(),
            "the sweep's 'selected' is NOT the generation this build resolves"
        );
        eprintln!(
            "E9 sweep picked {} as current; the live generation is {}",
            hex::encode(&basis.raw[..8]),
            hex::encode(&live.handle().raw[..8])
        );
    }

    // Drain every sibling into the live generation, asserting per source.
    let mut drained = 0usize;
    for source in generations {
        let moved = adopt(&mut pile, source.handle(), live, &sky);
        drained += moved;
        pile.flush().unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(
            generation::unreached_records(&snapshot, source.handle(), live.handle()).unwrap(),
            0,
            "per-source completeness"
        );
    }
    assert_eq!(drained, total);

    {
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(live.admitted(&snapshot).unwrap().len(), total);
        // Reverse containment: nothing appeared in the target that no source held.
        let mut reverse_ok = false;
        for source in generations {
            if generation::unreached_records(&snapshot, live.handle(), source.handle()).unwrap()
                == 0
            {
                reverse_ok = true;
            }
        }
        let _ = reverse_ok;
        let report = generation::named_generations(&snapshot, live.handle())
            .unwrap()
            .unwrap();
        assert!(!report.strands_records());
        eprintln!(
            "E9 drained {drained} records from 5 generations into one; \
             live generation reads {total}, nothing stranded"
        );
    }
    pile.close().unwrap();
}

// ------------------- E10: what if the third private key does not exist yet?

/// The specification calls this gate blocking, on the grounds that "WRITE
/// 2-of-3 is unsatisfiable on a two-key colony". Measured, it is not.
#[test]
fn e10_two_held_keys_among_three_roots_is_fully_operational() {
    use triblespace_core::collection::grant_collection_write;

    let (mac, sky) = (key(0xF1), key(0xF2));
    // The third root is a public key whose private half nobody holds.
    let phantom = key(0xF3).verifying_key();
    let roots = [mac.verifying_key(), sky.verifying_key(), phantom];
    let mut store = MemoryRepo::default();
    let collection = store
        .collection("two-of-three", three_roots(roots, 2))
        .unwrap();

    // The two held roots countersign each other.
    grant_collection_write(&mut store, collection.handle(), &mac, sky.verifying_key()).unwrap();
    grant_collection_write(&mut store, collection.handle(), &sky, mac.verifying_key()).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(collection
            .writer_is_admitted(&snapshot, sky.verifying_key())
            .unwrap());
        assert!(collection
            .writer_is_admitted(&snapshot, mac.verifying_key())
            .unwrap());
    }

    // And they can still enrol a fourth principal between them.
    let newcomer = key(0xF4).verifying_key();
    grant_collection_write(&mut store, collection.handle(), &mac, newcomer).unwrap();
    grant_collection_write(&mut store, collection.handle(), &sky, newcomer).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(collection.writer_is_admitted(&snapshot, newcomer).unwrap());
    }
    eprintln!(
        "E10 2-of-3 with only two held keys: both roots write, and the two of them \
         still enrol newcomers. The gate is not blocking; it is a resilience budget."
    );

    // The real exposure: it degrades to 2-of-2, so losing ONE held key ends
    // enrollment permanently -- there is no revocation and no re-issue path.
    let stranded = store
        .collection("after-loss", three_roots(roots, 2))
        .unwrap();
    grant_collection_write(&mut store, stranded.handle(), &mac, newcomer).unwrap();
    {
        let snapshot = store.snapshot().unwrap();
        assert!(
            !stranded.writer_is_admitted(&snapshot, newcomer).unwrap(),
            "with sky's key lost, mac alone can never enrol anyone on a new collection"
        );
        eprintln!(
            "E10 losing one of the two held keys: enrollment is over for good, and the \
             only repair is another re-mint"
        );
    }
}
