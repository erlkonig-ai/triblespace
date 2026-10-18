//! Manual differential gate against the actual /32 writer/reader baseline.
//! LEGACY32_ADMISSION_FIXTURE names the directory containing admission.pile and
//! admission-baseline.json, produced by the preserved isolated3ca example.
//! This is synthetic source-publication parity, not a vault or live-pile test.
use super::tests::{args, exports, hash, ids, key};
use super::*;
use ed25519_dalek::VerifyingKey;
use triblespace_core::blob::encodings::{
    simplearchive::SimpleArchive, succinctarchive::SuccinctArchiveBlob,
};
use triblespace_core::collection::{Collection, CollectionHandle, CollectionSnapshotExt};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata;
use triblespace_core::prelude::{exists, pattern};
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::BlobStoreGet;
use triblespace_core::trible::TribleSet;

fn raw(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn sorted(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by_key(Value::to_string);
    rows
}
fn facts(set: &TribleSet) -> Vec<String> {
    let mut rows: Vec<_> = set.iter().map(|t| hex::encode(t.data)).collect();
    rows.sort();
    rows
}
fn has_receipt(facts: &TribleSet, label: &str, ready: &str) -> bool {
    exists!(pattern!(facts, [{ _?receipt @ metadata::name: label, metadata::description: ready }]))
}
fn published_receipt(
    snapshot: &PileSnapshot,
    source: Collection<SimpleArchive>,
    expected: CollectionHandle,
    signer: VerifyingKey,
    label: &str,
    ready: &str,
) -> bool {
    if source.handle() != expected
        || !source
            .writer_is_admitted_acquiring(snapshot, signer)
            .unwrap()
    {
        return false;
    }
    let observed = snapshot.collection(source).unwrap();
    for member in observed.support().unwrap().members() {
        // One-call selector scratch; no application catalogue or union predicate.
        let claims = snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::CommitMember(
                source.handle(),
                Handle::to_hash(member),
            )]))
            .unwrap();
        let own = claims.into_iter().any(|record| match record {
            CollectionRecord::Commit(c) => {
                c.collection() == expected
                    && c.data() == Handle::to_hash(member)
                    && c.public_key().raw == signer.to_bytes()
                    && c.verify_strict().is_ok()
            }
            _ => false,
        });
        if own {
            let facts = snapshot.get::<TribleSet, SimpleArchive>(member).unwrap();
            if has_receipt(&facts, label, ready) {
                return true;
            }
        }
    }
    false
}
fn tuple(c: triblespace_core::collection::CollectionCommit) -> Value {
    json!({"collection":hex::encode(c.collection().raw),"data":hex::encode(c.data().raw),
        "metadata":hex::encode(c.metadata().raw),"author":hex::encode(c.public_key().raw)})
}

#[test]
#[ignore = "manual: requires actual /32 admission producer pile and baseline"]
fn actual_old_admission_member_provenance_and_individual_publication_survive_rewrite() {
    let base = PathBuf::from(
        std::env::var_os("LEGACY32_ADMISSION_FIXTURE").expect("set actual /32 fixture directory"),
    );
    let source = base.join("admission.pile");
    let baseline: Value =
        serde_json::from_slice(&std::fs::read(base.join("admission-baseline.json")).unwrap())
            .unwrap();
    assert_eq!(
        baseline["runtime_revision"],
        "3ca5c1cb5504d8ff60730edfe5bf641b01f44913"
    );
    let before = hash(&source);
    assert_eq!(baseline["source_blake3"], before);
    let dir = tempfile::tempdir().unwrap();
    let refreshes = exports(&source, dir.path());
    let signer = key(dir.path(), 7);
    // C is currently unadmitted, but that is not authority to discard C's
    // distinct signature-valid source foundations or substitute A for C.
    let mut missing = args(&source, dir.path(), "missing-c.pile", &signer);
    missing.refreshes = vec![refreshes[0].clone()];
    missing.retain_unconverted_caches = true;
    let missing_output = missing.into.clone();
    assert!(run(source.clone(), missing).is_err());
    assert!(!missing_output.exists());
    let mut a = args(&source, dir.path(), "admitted.pile", &signer);
    a.refreshes = refreshes.clone();
    let output = a.into.clone();
    run(source.clone(), a).unwrap();
    assert_eq!(ids(&output).records.len(), 13);
    let mut file = Pile::new(PileFile::open_read_only(&output).unwrap());
    let snapshot = file.snapshot().unwrap();
    let root =
        Collection::<SimpleArchive>::open(&snapshot, Inline::new(raw(&baseline["root"]))).unwrap();
    let derived =
        Collection::<SuccinctArchiveBlob>::open(&snapshot, Inline::new(raw(&baseline["derived"])))
            .unwrap();
    let mut admission = Vec::new();
    for name in ["a", "b", "c"] {
        let signer = VerifyingKey::from_bytes(&raw(&baseline["keys"][name])).unwrap();
        for (collection, write, read) in [
            (
                root.handle(),
                root.writer_is_admitted_acquiring(&snapshot, signer)
                    .unwrap(),
                root.reader_is_admitted_acquiring(&snapshot, signer)
                    .unwrap(),
            ),
            (
                derived.handle(),
                derived
                    .writer_is_admitted_acquiring(&snapshot, signer)
                    .unwrap(),
                derived
                    .reader_is_admitted_acquiring(&snapshot, signer)
                    .unwrap(),
            ),
        ] {
            admission.push(json!({"collection":hex::encode(collection.raw),"signer":hex::encode(signer.to_bytes()),"name":name,"write":write,"read":read}));
        }
    }
    assert_eq!(json!(sorted(admission)), baseline["admission"]);
    let observed = snapshot.collection(root).unwrap();
    let derived_observed = snapshot.collection(derived).unwrap();
    let mut root_support: Vec<_> = observed
        .support()
        .unwrap()
        .members()
        .map(|h| hex::encode(h.raw))
        .collect();
    root_support.sort();
    let mut derived_support: Vec<_> = derived_observed
        .support()
        .unwrap()
        .members()
        .map(|h| hex::encode(h.raw))
        .collect();
    derived_support.sort();
    assert_eq!(json!(root_support), baseline["root_support"]);
    assert_eq!(json!(derived_support), baseline["derived_support"]);
    let mut support = Vec::new();
    for member in observed.support().unwrap().members() {
        let claims = snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::CommitMember(
                root.handle(),
                Handle::to_hash(member),
            )]))
            .unwrap();
        let tuples = claims
            .into_iter()
            .map(|record| {
                record.verify_strict().unwrap();
                let CollectionRecord::Commit(c) = record else {
                    panic!("not a COMMIT")
                };
                tuple(c)
            })
            .collect();
        support.push(json!({"data":hex::encode(member.raw),"claims":sorted(tuples)}));
    }
    assert_eq!(json!(sorted(support)), baseline["support_members"]);
    let mut commits = Vec::new();
    let mut derives = Vec::new();
    for record in snapshot
        .select_records(&BTreeSet::from([
            CollectionRecordSelector::Collection(root.handle()),
            CollectionRecordSelector::Collection(derived.handle()),
        ]))
        .unwrap()
    {
        record.verify_strict().unwrap();
        match record {
            CollectionRecord::Commit(c) => {
                let mut row = tuple(c);
                row["facts"] = json!(facts(&snapshot.get::<TribleSet, SimpleArchive>(Handle::from_hash(c.data())).unwrap()));
                row["metafacts"] = json!(facts(&snapshot.get::<TribleSet, SimpleArchive>(c.metadata()).unwrap()));
                commits.push(row);
            }
            CollectionRecord::Derive(d) => derives.push(json!({"target":hex::encode(d.target().raw),"author":hex::encode(d.public_key().raw),"locator":hex::encode(d.input().raw()),"output":hex::encode(d.output().raw)})),
            _ => panic!("unexpected cache"),
        }
    }
    for (name, current) in [("commits", commits), ("derives", derives)] {
        let old = baseline[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let mut row = row.clone();
                let object = row.as_object_mut().unwrap();
                object.remove("old_id");
                object.remove("signed_bytes");
                row
            })
            .collect();
        assert_eq!(sorted(current), sorted(old));
    }
    let b = VerifyingKey::from_bytes(&raw(&baseline["keys"]["b"])).unwrap();
    let c = VerifyingKey::from_bytes(&raw(&baseline["keys"]["c"])).unwrap();
    let label = |name: &str| baseline["receipts"][name].as_str().unwrap();
    let ready = label("ready");
    let union = observed.view::<TribleSet>().unwrap();
    let checks = json!({
        "b_shared":published_receipt(&snapshot, root, root.handle(), b, label("shared"), ready),
        "b_positive":published_receipt(&snapshot, root, root.handle(), b, label("b_positive"), ready),
        "c_shared_denied":published_receipt(&snapshot, root, root.handle(), c, label("shared"), ready),
        "c_only_denied":published_receipt(&snapshot, root, root.handle(), c, label("c_only"), ready),
        "b_missing_publication":published_receipt(&snapshot, root, root.handle(), b, label("a_only"), ready),
        "b_split_publication":published_receipt(&snapshot, root, root.handle(), b, label("split"), ready),
        "wrong_source":published_receipt(&snapshot, root, derived.handle(), b, label("b_positive"), ready),
        "union_a_only":has_receipt(&union, label("a_only"), ready),
        "union_split":has_receipt(&union, label("split"), ready),
        "union_c_only":has_receipt(&union, label("c_only"), ready),
    });
    assert_eq!(checks, baseline["receipt_checks"]);
    drop(derived_observed);
    drop(observed);
    drop(snapshot);
    file.into_inner().close().unwrap();
    let output_ids = ids(&output);
    for id in baseline["blob_ids"].as_array().unwrap() {
        assert!(output_ids.blobs.get(&raw(id)).is_some());
    }
    assert_eq!(
        output_ids.proofs.len(),
        baseline["proof_ids"].as_array().unwrap().len() as u64
    );
    for id in baseline["proof_ids"].as_array().unwrap() {
        assert!(output_ids.proofs.get(&raw(id)).is_some());
    }
    for (n, stop) in [Stop::AfterCopy, Stop::AfterAssertion, Stop::BeforePublish]
        .into_iter()
        .enumerate()
    {
        let mut a = args(
            &source,
            dir.path(),
            &format!("interrupted-{n}.pile"),
            &signer,
        );
        a.refreshes = refreshes.clone();
        let into = a.into.clone();
        assert!(execute(source.clone(), a, Mode::Rewrite, stop).is_err());
        assert!(!into.exists() && partial_path(&into).exists());
    }
    let mut retry = args(&source, dir.path(), "fresh-retry.pile", &signer);
    retry.refreshes = refreshes;
    let retry_path = retry.into.clone();
    run(source.clone(), retry).unwrap();
    assert_eq!(ids(&retry_path), output_ids);
    assert_eq!(hash(&source), before);
}
