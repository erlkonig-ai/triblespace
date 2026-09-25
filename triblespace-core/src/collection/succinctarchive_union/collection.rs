//! Logical views for canonical SuccinctArchive collection encodings.
//!
//! The public view is an ordinary two-stage collection derivation:
//!
//! ```text
//! SimpleArchive --DERIVE--> SuccinctArchiveBlob
//!                --DERIVE--> Rank9AcceleratedSuccinctArchiveBlob
//! ```
//!
//! Both encodings are full lattices with canonical `MERGE` operations. The
//! accelerated encoding is an ordinary blob whose header names its portable
//! raw source. [`TryFromCover`] attaches those roots directly through the
//! immutable store snapshot; collection admission, derivation, and maintenance
//! use the generic store APIs rather than a domain lifecycle facade.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive, SuccinctArchiveBlob,
    SuccinctArchiveError, UnionArchive,
};
use crate::blob::{Blob, TryFromBlob};
use crate::collection::{CollectionData, Cover, TryFromCover, TryFromCoverError};
use crate::inline::encodings::hash::Handle;
use crate::repo::BlobStoreGet;
use crate::trible::Fragment;

impl TryFromCover<SuccinctArchiveBlob> for UnionArchive<OrderedUniverse> {
    type Error = SuccinctArchiveError;

    fn try_from_cover<R>(
        cover: &Cover<SuccinctArchiveBlob>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut segments = Vec::with_capacity(cover.len());
        for handle in cover.members() {
            let member = Handle::<SuccinctArchiveBlob>::to_hash(handle);
            let root = snapshot
                .get::<Blob<SuccinctArchiveBlob>, SuccinctArchiveBlob>(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            segments.push(SuccinctArchive::try_from_blob(root).map_err(TryFromCoverError::View)?);
        }
        if segments.is_empty() {
            segments.push(
                super::empty()
                    .try_from_blob()
                    .map_err(TryFromCoverError::View)?,
            );
        }
        Ok(UnionArchive::new(segments))
    }
}

/// Failure to attach one Rank9 root to the raw archive named in its header.
#[derive(Debug)]
pub enum Rank9AcceleratedViewError {
    /// The accelerated root header or exact raw/index pair is invalid.
    Invalid(SuccinctArchiveError),
    /// The exact raw child named by an accelerated root is not resident.
    MissingRaw {
        /// Accelerated root whose child could not be loaded.
        member: CollectionData,
        /// Backend diagnostic.
        reason: String,
    },
}

impl fmt::Display for Rank9AcceleratedViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(source) => source.fmt(formatter),
            Self::MissingRaw { member, reason } => write!(
                formatter,
                "accelerated SuccinctArchive member {} is missing its raw child: {reason}",
                hex::encode_upper(member.raw),
            ),
        }
    }
}

impl Error for Rank9AcceleratedViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(source) => Some(source),
            Self::MissingRaw { .. } => None,
        }
    }
}

impl TryFromCover<Rank9AcceleratedSuccinctArchiveBlob> for UnionArchive<OrderedUniverse> {
    type Error = Rank9AcceleratedViewError;

    fn try_from_cover<R>(
        cover: &Cover<Rank9AcceleratedSuccinctArchiveBlob>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut segments = Vec::with_capacity(cover.len());
        for handle in cover.members() {
            let member = Handle::<Rank9AcceleratedSuccinctArchiveBlob>::to_hash(handle);
            let root = snapshot
                .get::<Blob<Rank9AcceleratedSuccinctArchiveBlob>, _>(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let source = Rank9AcceleratedSuccinctArchiveBlob::source_handle(&root)
                .map_err(Rank9AcceleratedViewError::Invalid)
                .map_err(TryFromCoverError::View)?;
            let raw = snapshot
                .get::<crate::blob::Blob<SuccinctArchiveBlob>, SuccinctArchiveBlob>(source)
                .map_err(|source| {
                    TryFromCoverError::View(Rank9AcceleratedViewError::MissingRaw {
                        member,
                        reason: source.to_string(),
                    })
                })?;
            segments.push(
                SuccinctArchive::from_accelerated_parts(raw, root)
                    .map_err(Rank9AcceleratedViewError::Invalid)
                    .map_err(TryFromCoverError::View)?,
            );
        }
        if segments.is_empty() {
            segments.push(
                super::empty()
                    .try_from_blob()
                    .map_err(Rank9AcceleratedViewError::Invalid)
                    .map_err(TryFromCoverError::View)?,
            );
        }
        Ok(UnionArchive::new(segments))
    }
}

#[cfg(test)]
mod tests {
    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;
    use futures::executor::block_on;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use crate::blob::{Blob, IntoBlob};
    use crate::collection::descriptor;
    use crate::collection::{
        Collection, CollectionCommit, CollectionData, CollectionDerivation, CollectionDerive,
        CollectionEncoding, CollectionHandle, CollectionMerge, CollectionOperationError,
        CollectionPolicy, CollectionRead, CollectionRecord, CollectionSnapshotExt, CollectionStore,
        CollectionStoreExt, Support,
    };
    use crate::inline::encodings::hash::Handle;
    use crate::metadata::MetaDescribe;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{BlobStorePut, SnapshotSource};
    use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

    use super::*;

    fn authority() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[7; 32]).verifying_key()
    }

    fn direct_policy() -> CollectionPolicy {
        CollectionPolicy::new(
            crate::collection::AdmissionPolicy::direct(authority()),
            crate::collection::AdmissionPolicy::direct(authority()),
        )
    }

    fn input_record(collection: CollectionHandle, data: CollectionData) -> CollectionRecord {
        CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            collection,
            data,
            crate::collection::empty_metadata_handle(),
        ))
    }

    fn collections(
        store: &mut MemoryRepo,
    ) -> (
        Collection<SimpleArchive>,
        Collection<SuccinctArchiveBlob>,
        Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    ) {
        let source = store.collection("facts", direct_policy()).unwrap();
        let raw = store
            .derive::<SuccinctArchiveBlob>(source, (), direct_policy())
            .unwrap();
        let accelerated = store
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), direct_policy())
            .unwrap();
        (source, raw, accelerated)
    }

    fn row(entity: u8, attribute: u8, value: u8) -> Trible {
        let mut row = [value; TRIBLE_LEN];
        row[..16].fill(entity);
        row[16..32].fill(attribute);
        Trible::force_raw(row).unwrap()
    }

    fn raw(rows: impl IntoIterator<Item = Trible>) -> Blob<SuccinctArchiveBlob> {
        let mut set = TribleSet::new();
        for row in rows {
            set.insert(&row);
        }
        let simple: Blob<SimpleArchive> = set.to_blob();
        super::super::derive_element(&simple).unwrap()
    }

    fn simple(rows: impl IntoIterator<Item = Trible>) -> Blob<SimpleArchive> {
        rows.into_iter().collect::<TribleSet>().to_blob()
    }

    fn accelerated(raw: &Blob<SuccinctArchiveBlob>) -> Blob<Rank9AcceleratedSuccinctArchiveBlob> {
        let mut store = MemoryRepo::default();
        let snapshot = store.snapshot().unwrap();
        Rank9AcceleratedSuccinctArchiveBlob::map(&(), raw, &snapshot).unwrap()
    }

    #[test]
    fn descriptors_form_a_two_stage_ordinary_derivation() {
        let mut store = MemoryRepo::default();
        let (source, raw, accelerated) = collections(&mut store);
        let snapshot = store.snapshot().unwrap();
        let raw_descriptor =
            crate::collection::api::load_collection_descriptor(&snapshot, raw.handle())
                .unwrap()
                .fragment;
        let accelerated_descriptor =
            crate::collection::api::load_collection_descriptor(&snapshot, accelerated.handle())
                .unwrap()
                .fragment;
        assert_eq!(
            descriptor::source(raw_descriptor.facts()).unwrap(),
            Some(source.handle())
        );
        assert_eq!(
            descriptor::source(accelerated_descriptor.facts()).unwrap(),
            Some(raw.handle())
        );
        assert_eq!(
            descriptor::representation(raw_descriptor.facts()).unwrap(),
            SuccinctArchiveBlob::id()
        );
        assert_eq!(
            descriptor::representation(accelerated_descriptor.facts()).unwrap(),
            Rank9AcceleratedSuccinctArchiveBlob::id()
        );
    }

    #[test]
    fn rank9_join_reports_a_missing_input_raw_child() {
        let a = raw([row(1, 2, 3)]);
        let b = raw([row(4, 5, 6)]);
        let fa = accelerated(&a);
        let fb = accelerated(&b);
        let a_data = Handle::<SuccinctArchiveBlob>::to_hash(a.get_handle());
        let b_data = Handle::<SuccinctArchiveBlob>::to_hash(b.get_handle());

        for (resident, missing, expected) in [
            (b.clone(), a_data, (fa.clone(), fb.clone())),
            (a.clone(), b_data, (fa.clone(), fb.clone())),
        ] {
            let mut store = MemoryRepo::default();
            store.put::<SuccinctArchiveBlob, _>(resident).unwrap();
            for member in [&expected.0, &expected.1] {
                store
                    .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(member.clone())
                    .unwrap();
            }
            let snapshot = store.snapshot().unwrap();
            assert_eq!(
                Rank9AcceleratedSuccinctArchiveBlob::join_members(
                    &Fragment::empty(),
                    &expected.0,
                    &expected.1,
                    &snapshot,
                ),
                Err(CollectionOperationError::MissingDependency(missing)),
            );
        }
    }

    #[test]
    fn rank9_join_requires_the_exact_raw_union_then_succeeds() {
        let a = raw([row(1, 2, 3)]);
        let b = raw([row(4, 5, 6)]);
        let c = super::super::join(&a, &b).unwrap();
        let fa = accelerated(&a);
        let fb = accelerated(&b);
        let expected = accelerated(&c);
        let c_data = Handle::<SuccinctArchiveBlob>::to_hash(c.get_handle());

        let mut store = MemoryRepo::default();
        for member in [a, b] {
            store.put::<SuccinctArchiveBlob, _>(member).unwrap();
        }
        for member in [&fa, &fb] {
            store
                .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(member.clone())
                .unwrap();
        }
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            Rank9AcceleratedSuccinctArchiveBlob::join_members(
                &Fragment::empty(),
                &fa,
                &fb,
                &snapshot,
            ),
            Err(CollectionOperationError::MissingDependency(c_data)),
        );
        drop(snapshot);

        let c_handle = c.get_handle();
        store.put::<SuccinctArchiveBlob, _>(c).unwrap();
        let snapshot = store.snapshot().unwrap();
        let joined = Rank9AcceleratedSuccinctArchiveBlob::join_members(
            &Fragment::empty(),
            &fa,
            &fb,
            &snapshot,
        )
        .unwrap();
        assert_eq!(joined.get_handle(), expected.get_handle());
        assert_eq!(
            Rank9AcceleratedSuccinctArchiveBlob::source_handle(&joined).unwrap(),
            c_handle,
        );
    }

    #[test]
    fn rank9_member_join_is_associative_commutative_and_idempotent() {
        let a = raw([row(1, 2, 3)]);
        let b = raw([row(4, 5, 6)]);
        let c = raw([row(7, 8, 9)]);
        let ab = super::super::join(&a, &b).unwrap();
        let bc = super::super::join(&b, &c).unwrap();
        let abc = super::super::join(&ab, &c).unwrap();
        assert_eq!(
            abc.get_handle(),
            super::super::join(&a, &bc).unwrap().get_handle()
        );

        let fa = accelerated(&a);
        let fb = accelerated(&b);
        let fc = accelerated(&c);
        let fab = accelerated(&ab);
        let fbc = accelerated(&bc);
        let fabc = accelerated(&abc);
        let expected_source = abc.get_handle();
        let mut store = MemoryRepo::default();
        for raw in [a, b, c, ab, bc, abc] {
            store.put::<SuccinctArchiveBlob, _>(raw).unwrap();
        }
        let snapshot = store.snapshot().unwrap();
        let join = |low: &Blob<Rank9AcceleratedSuccinctArchiveBlob>,
                    high: &Blob<Rank9AcceleratedSuccinctArchiveBlob>| {
            Rank9AcceleratedSuccinctArchiveBlob::join_members(
                &Fragment::empty(),
                low,
                high,
                &snapshot,
            )
            .unwrap()
        };

        let left = join(&join(&fa, &fb), &fc);
        let right = join(&fa, &join(&fb, &fc));
        assert_eq!(left.get_handle(), fabc.get_handle());
        assert_eq!(right.get_handle(), fabc.get_handle());
        assert_eq!(join(&fa, &fb).get_handle(), fab.get_handle());
        assert_eq!(join(&fb, &fa).get_handle(), fab.get_handle());
        assert_eq!(join(&fb, &fc).get_handle(), fbc.get_handle());
        assert_eq!(join(&fa, &fa).get_handle(), fa.get_handle());
        assert_eq!(
            Rank9AcceleratedSuccinctArchiveBlob::source_handle(&left).unwrap(),
            expected_source,
        );
        assert_eq!(
            Rank9AcceleratedSuccinctArchiveBlob::source_handle(&right).unwrap(),
            expected_source,
        );
    }

    #[test]
    fn ensure_uses_ordinary_derives_for_both_stages() {
        let mut store = MemoryRepo::default();
        let (source_collection, raw_collection, accelerated_collection) = collections(&mut store);
        let source: Blob<SimpleArchive> = [row(1, 2, 3), row(4, 5, 6)]
            .into_iter()
            .collect::<TribleSet>()
            .to_blob();
        store.put::<SimpleArchive, _>(source.clone()).unwrap();
        store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        store
            .insert(input_record(
                source_collection.handle(),
                Handle::<SimpleArchive>::to_hash(source.get_handle()),
            ))
            .unwrap();

        block_on(store.ensure(raw_collection, &SigningKey::from_bytes(&[7; 32]))).unwrap();
        let snapshot =
            block_on(store.ensure(accelerated_collection, &SigningKey::from_bytes(&[7; 32])))
                .unwrap();
        let attached = snapshot.collection(accelerated_collection).unwrap();
        let view: UnionArchive<OrderedUniverse> = attached.view().unwrap();
        assert_eq!(view.iter().count(), 2);

        let snapshot = store.snapshot().unwrap();
        let records = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let raw = records
            .iter()
            .find_map(|record| match record {
                CollectionRecord::Derive(derive)
                    if derive.collection() == raw_collection.handle() =>
                {
                    Some(derive.output())
                }
                _ => None,
            })
            .expect("raw DERIVE was published");
        let accelerated = records
            .iter()
            .find_map(|record| match record {
                CollectionRecord::Derive(derive)
                    if derive.collection() == accelerated_collection.handle() =>
                {
                    assert_eq!(
                        derive.input(),
                        crate::collection::SourceLocator::of(raw.raw)
                    );
                    Some(derive.output())
                }
                _ => None,
            })
            .expect("accelerated DERIVE was published");
        assert_ne!(raw, accelerated);
    }

    #[test]
    fn ordinary_observation_contains_only_support_realized_at_its_snapshot() {
        let mut store = MemoryRepo::default();
        let (source_collection, raw_collection, accelerated_collection) = collections(&mut store);
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let first = store
            .commit(
                source_collection,
                &signing_key,
                Fragment::from([row(1, 2, 3)].into_iter().collect::<TribleSet>()),
            )
            .unwrap();
        let first_support = Support::from_data(source_collection, [first.data()]);

        block_on(store.ensure(raw_collection, &SigningKey::from_bytes(&[7; 32]))).unwrap();
        let snapshot =
            block_on(store.ensure(accelerated_collection, &SigningKey::from_bytes(&[7; 32])))
                .unwrap();
        // The source grows after the target was realized: the attachment
        // reports what the target stands on in its snapshot, not what the
        // source admits now.
        let second = store
            .commit(
                source_collection,
                &signing_key,
                Fragment::from([row(4, 5, 6)].into_iter().collect::<TribleSet>()),
            )
            .unwrap();
        let full_support = Support::from_data(source_collection, [first.data(), second.data()]);
        let observed = snapshot.collection(accelerated_collection).unwrap();
        assert_eq!(
            crate::collection::test_support::stood_for(&observed),
            first_support
        );

        block_on(store.ensure(raw_collection, &SigningKey::from_bytes(&[7; 32]))).unwrap();
        let snapshot =
            block_on(store.ensure(accelerated_collection, &SigningKey::from_bytes(&[7; 32])))
                .unwrap();
        let observed = snapshot.collection(accelerated_collection).unwrap();
        assert_eq!(
            crate::collection::test_support::stood_for(&observed),
            full_support
        );
        let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
        assert_eq!(view.iter().count(), 2);
    }

    #[test]
    fn downstream_ensure_never_constructs_an_upstream_member() {
        let mut store = MemoryRepo::default();
        let (source_collection, raw_collection, accelerated_collection) = collections(&mut store);
        let source = simple([row(1, 2, 3)]);
        let source_data = Handle::<SimpleArchive>::to_hash(source.get_handle());
        store.put::<SimpleArchive, _>(source).unwrap();
        store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        store
            .insert(input_record(source_collection.handle(), source_data))
            .unwrap();

        // The accelerated target stands for what the raw frontier stands on;
        // with no raw member realized that is nothing, and nothing is built.
        let before_raw =
            block_on(store.ensure(accelerated_collection, &SigningKey::from_bytes(&[7; 32])))
                .unwrap();
        assert!(before_raw
            .collection(accelerated_collection)
            .unwrap()
            .cover()
            .is_empty());
        assert!(!before_raw
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .iter()
            .any(|record| matches!(
                record,
                CollectionRecord::Derive(derive)
                    if derive.collection() == raw_collection.handle()
            )));

        block_on(store.ensure(raw_collection, &SigningKey::from_bytes(&[7; 32]))).unwrap();
        let snapshot =
            block_on(store.ensure(accelerated_collection, &SigningKey::from_bytes(&[7; 32])))
                .unwrap();
        let attached = snapshot.collection(accelerated_collection).unwrap();
        let view: UnionArchive<OrderedUniverse> = attached.view().unwrap();
        assert_eq!(view.iter().count(), 1);
    }

    #[test]
    fn exact_observation_accepts_a_multihop_support_equivalent_union_image() {
        let mut store = MemoryRepo::default();
        let (source_collection, raw_collection, accelerated_collection) = collections(&mut store);
        let source_a = simple([row(1, 2, 3)]);
        let source_b = simple([row(4, 5, 6)]);
        let source_a_data = Handle::<SimpleArchive>::to_hash(source_a.get_handle());
        let source_b_data = Handle::<SimpleArchive>::to_hash(source_b.get_handle());
        let a = super::super::derive_element(&source_a).unwrap();
        let b = super::super::derive_element(&source_b).unwrap();
        let c = super::super::join(&a, &b).unwrap();
        let a_data = Handle::<SuccinctArchiveBlob>::to_hash(a.get_handle());
        let b_data = Handle::<SuccinctArchiveBlob>::to_hash(b.get_handle());
        let c_data = Handle::<SuccinctArchiveBlob>::to_hash(c.get_handle());
        let fc = accelerated(&c);
        let fc_data = Handle::<Rank9AcceleratedSuccinctArchiveBlob>::to_hash(fc.get_handle());

        for member in [source_a, source_b] {
            store.put::<SimpleArchive, _>(member).unwrap();
        }
        store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        let source_records = [source_a_data, source_b_data]
            .map(|data| input_record(source_collection.handle(), data));
        for record in source_records {
            store.insert(record).unwrap();
        }
        for member in [a, b, c] {
            store.put::<SuccinctArchiveBlob, _>(member).unwrap();
        }
        store
            .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(fc)
            .unwrap();
        let raw_records = [(source_a_data, a_data), (source_b_data, b_data)]
            .into_iter()
            .zip(source_records)
            .map(|((input, output), _source)| {
                CollectionRecord::Derive(CollectionDerive::sign(
                    &SigningKey::from_bytes(&[7; 32]),
                    raw_collection.handle(),
                    crate::collection::SourceLocator::of(input.raw),
                    output,
                ))
            })
            .collect::<Vec<_>>();
        for record in &raw_records {
            store.insert(*record).unwrap();
        }
        let merged = CollectionRecord::Merge(
            CollectionMerge::sign(
                &SigningKey::from_bytes(&[7; 32]),
                raw_collection.handle(),
                [a_data, b_data],
                c_data,
            )
            .unwrap(),
        );
        store.insert(merged).unwrap();
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &SigningKey::from_bytes(&[7; 32]),
                accelerated_collection.handle(),
                crate::collection::SourceLocator::of(c_data.raw),
                fc_data,
            )))
            .unwrap();

        let support = Support::from_data(source_collection, [source_a_data, source_b_data]);
        let snapshot = store.snapshot().unwrap();
        let attached = snapshot.collection(accelerated_collection).unwrap();

        assert_eq!(
            crate::collection::test_support::stood_for(&attached),
            support
        );
        assert_eq!(
            attached.cover().data_members().collect::<Vec<_>>(),
            vec![fc_data],
        );
        let view: UnionArchive<OrderedUniverse> = attached.view().unwrap();
        assert_eq!(view.iter().count(), 2);
    }

    #[test]
    fn accelerated_member_validation_reports_a_missing_raw_child() {
        let raw = raw([row(1, 2, 3)]);
        let root = accelerated(&raw);
        let raw_data = Handle::<SuccinctArchiveBlob>::to_hash(raw.get_handle());
        let mut store = MemoryRepo::default();
        store
            .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(root.clone())
            .unwrap();
        let snapshot = store.snapshot().unwrap();

        assert!(matches!(
            Rank9AcceleratedSuccinctArchiveBlob::validate_member(
                &Fragment::empty(), &root, &snapshot,
            ),
            Err(CollectionOperationError::MissingDependency(member))
                if member == raw_data
        ));
    }

    #[test]
    fn accelerated_member_validation_rejects_a_corrupt_index() {
        let raw = raw([row(1, 2, 3)]);
        let root = accelerated(&raw);
        let mut bytes = root.bytes.as_ref().to_vec();
        let last = bytes.last_mut().expect("Rank9 root is not empty");
        *last ^= 1;
        let corrupted = Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(Bytes::from_source(bytes));
        let mut store = MemoryRepo::default();
        store.put::<SuccinctArchiveBlob, _>(raw).unwrap();
        let snapshot = store.snapshot().unwrap();

        assert!(matches!(
            Rank9AcceleratedSuccinctArchiveBlob::validate_member(
                &Fragment::empty(),
                &corrupted,
                &snapshot,
            ),
            Err(CollectionOperationError::Fatal(_))
        ));
    }
}
