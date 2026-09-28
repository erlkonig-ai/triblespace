//! Logical views for canonical SuccinctArchive collection encodings.
//!
//! Both are attached to a `SimpleArchive` root:
//!
//! ```text
//! SimpleArchive node --MAP--> SuccinctArchiveBlob
//!                   --MAP--> Rank9AcceleratedSuccinctArchiveBlob
//! ```
//!
//! the accelerator mapped from the same node's Succinct attachment. The
//! accelerated encoding is an ordinary blob whose header names its portable
//! raw source. [`TryFromCover`] attaches a cover of either directly through
//! the immutable store snapshot; attachment and maintenance use the generic
//! store APIs rather than a domain lifecycle facade.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive, SuccinctArchiveBlob,
    SuccinctArchiveError, UnionArchive,
};
use crate::blob::{Blob, TryFromBlob};
use crate::collection::{
    AttachedRead, AttachedSnapshot, CollectionData, CollectionEncoding, Cover, Support,
    TryFromCover, TryFromCoverError,
};
use crate::inline::encodings::hash::Handle;
use crate::repo::{BlobStoreGet, StoreRead};
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

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use crate::blob::{Blob, IntoBlob};
    use crate::collection::{CollectionEncoding, CollectionOperationError};
    use crate::inline::encodings::hash::Handle;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{BlobStorePut, SnapshotSource};
    use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

    use super::*;

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

    fn accelerated(raw: &Blob<SuccinctArchiveBlob>) -> Blob<Rank9AcceleratedSuccinctArchiveBlob> {
        SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw.clone()).unwrap()
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

/// Failure to read an attached Succinct or Rank9 collection with its
/// residual ([`read_attached`]).
#[derive(Debug)]
pub enum ReadAttachedError {
    /// The attached cover could not be read.
    Cover(String),
    /// The store could not read a residual foundation whose bytes are here.
    Residual {
        /// The parent foundation.
        member: CollectionData,
        /// What went wrong.
        reason: String,
    },
}

impl fmt::Display for ReadAttachedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cover(reason) => write!(formatter, "read the attached cover: {reason}"),
            Self::Residual { member, reason } => write!(
                formatter,
                "read residual foundation {}: {reason}",
                hex::encode_upper(member.raw),
            ),
        }
    }
}

impl Error for ReadAttachedError {}

/// Read an attached Succinct or Rank9 collection as one union: the segments
/// of its cover, and one more segment for every residual foundation whose
/// bytes the read's snapshot holds, built from those bytes.
///
/// This is the raw read of what no usable attachment reaches -- a commit
/// written since the last maintenance pass, or written by another key and
/// not attached here yet -- so a reader sees it without waiting for
/// maintenance. What it cannot read is named in [`AttachedRead::unread`],
/// never dropped silently: a residual foundation whose bytes are not here
/// (their arrival turns [`AttachedSnapshot::is_current`] false), and one
/// whose bytes cannot form one archive -- malformed, or too wide for one
/// segment. Only a store that cannot read resident bytes fails the read.
pub fn read_attached<R, E>(
    attached: &AttachedSnapshot<R, E>,
) -> Result<AttachedRead<UnionArchive<OrderedUniverse>>, ReadAttachedError>
where
    R: StoreRead,
    E: CollectionEncoding,
    UnionArchive<OrderedUniverse>: TryFromCover<E>,
    <UnionArchive<OrderedUniverse> as TryFromCover<E>>::Error: fmt::Display,
{
    let snapshot = attached.snapshot();
    let mut residual = Vec::new();
    let mut unread = Vec::new();
    for foundation in attached.residual().members() {
        let member = Handle::<SimpleArchive>::to_hash(foundation);
        let failed = |reason: String| ReadAttachedError::Residual { member, reason };
        if snapshot
            .metadata(foundation)
            .map_err(|error| failed(error.to_string()))?
            .is_none()
        {
            unread.push(member);
            continue;
        }
        let bytes: Blob<SimpleArchive> = snapshot
            .get(foundation)
            .map_err(|error| failed(error.to_string()))?;
        let archive = super::derive_element(&bytes)
            .ok()
            .and_then(|image| SuccinctArchive::try_from_blob(image).ok());
        match archive {
            Some(archive) => residual.push(archive),
            None => unread.push(member),
        }
    }
    let cover: UnionArchive<OrderedUniverse> = attached
        .view()
        .map_err(|error| ReadAttachedError::Cover(error.to_string()))?;
    let union = if residual.is_empty() {
        cover
    } else {
        cover.with_segments(residual)
    };
    Ok(AttachedRead::new(
        union,
        Support::from_data(attached.support().collection(), unread),
    ))
}
