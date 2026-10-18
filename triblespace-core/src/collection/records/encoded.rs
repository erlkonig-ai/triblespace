//! Canonical fixed record layouts for structural byte views.
//!
//! These types describe bytes, not verified assertions. Every correctly sized
//! byte sequence can be viewed safely: 224 bytes for COMMIT/DERIVE/MAP, or 448
//! for MERGE. Structural views accept arbitrary kinds, authors and signatures.
//! Public conversion to a semantic record always uses its strict decoder;
//! only explicitly trusted crate-internal replay may skip verification.

use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use super::{
    collection_record_fingerprint, CollectionCommit, CollectionData, CollectionDerive,
    CollectionHandle, CollectionMap, CollectionRecordFingerprint, RecordDecodeError, SourceLocator,
    COLLECTION_COMMIT_BYTES_LEN, COLLECTION_DERIVE_BYTES_LEN, COLLECTION_MAP_BYTES_LEN,
    KIND_COLLECTION_COMMIT, KIND_COLLECTION_DERIVE, KIND_COLLECTION_MAP,
};
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::inline::encodings::ed25519::{ED25519PublicKey, ED25519RComponent, ED25519SComponent};
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;

/// Canonical COMMIT: `kind | collection | data | metadata | author | R | S`.
///
/// An [`anybytes::View<EncodedCommit>`] checks only this structural layout.
/// Neither construction nor field access verifies kind, authorship or admission.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct EncodedCommit {
    kind: [u8; 32],
    collection: [u8; 32],
    data: [u8; 32],
    metadata: [u8; 32],
    author: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

impl From<CollectionCommit> for EncodedCommit {
    fn from(record: CollectionCommit) -> Self {
        let (r, s) = record.signature();
        Self {
            kind: KIND_COLLECTION_COMMIT,
            collection: record.collection().raw,
            data: record.data().raw,
            metadata: record.metadata().raw,
            author: record.public_key().raw,
            r: r.raw,
            s: s.raw,
        }
    }
}

impl EncodedCommit {
    /// Complete canonical bytes, including kind, without copying or verification.
    pub fn body_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    /// Collection receiving the asserted member.
    pub fn collection(&self) -> CollectionHandle {
        Inline::new(self.collection)
    }

    /// Asserted member's content hash.
    pub fn data(&self) -> CollectionData {
        Inline::new(self.data)
    }

    /// Mandatory metadata archive handle.
    pub fn metadata(&self) -> Inline<Handle<SimpleArchive>> {
        Inline::new(self.metadata)
    }

    /// Unverified author public-key bytes.
    pub fn author(&self) -> Inline<ED25519PublicKey> {
        Inline::new(self.author)
    }

    /// Unverified signature R component.
    pub fn r(&self) -> Inline<ED25519RComponent> {
        Inline::new(self.r)
    }

    /// Unverified signature S component.
    pub fn s(&self) -> Inline<ED25519SComponent> {
        Inline::new(self.s)
    }

    /// BLAKE3 of the complete canonical bytes, including kind and signature.
    /// This is not a proof of signature validity or authorization.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        #[cfg(test)]
        super::FINGERPRINT_CALLS.set(super::FINGERPRINT_CALLS.get() + 1);
        collection_record_fingerprint(self.as_bytes())
    }

    /// Decode these bytes and strictly verify the embedded signature.
    /// Authorization remains the caller's policy.
    pub fn to_record(&self) -> Result<CollectionCommit, RecordDecodeError> {
        CollectionCommit::from_bytes(self.as_bytes().try_into().expect("fixed COMMIT layout"))
    }

    /// Decode bytes already trusted by native replay without re-verifying.
    pub(crate) fn to_record_trusted(&self) -> CollectionCommit {
        CollectionCommit::from_bytes_trusted(
            self.as_bytes().try_into().expect("fixed COMMIT layout"),
        )
        .expect("trusted canonical COMMIT kind")
    }
}

/// Canonical DERIVE: `kind | target | output | locator | author | R | S`.
///
/// An [`anybytes::View<EncodedDerive>`] checks only this structural layout.
/// Neither construction nor field access verifies kind, authorship or admission.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct EncodedDerive {
    kind: [u8; 32],
    target: [u8; 32],
    output: [u8; 32],
    locator: [u8; 32],
    author: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

impl From<CollectionDerive> for EncodedDerive {
    fn from(record: CollectionDerive) -> Self {
        let (r, s) = record.signature();
        Self {
            kind: KIND_COLLECTION_DERIVE,
            target: record.target().raw,
            locator: record.input().raw(),
            output: record.output().raw,
            author: record.public_key().raw,
            r: r.raw,
            s: s.raw,
        }
    }
}

impl EncodedDerive {
    /// Complete canonical bytes, including kind, without copying or verification.
    pub fn body_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    /// The target collection, which holds the output.
    pub fn collection(&self) -> CollectionHandle {
        self.target()
    }

    /// The target collection, which holds the output.
    pub fn target(&self) -> CollectionHandle {
        Inline::new(self.target)
    }

    /// Locator of the source foundation. This is not a blob handle.
    pub fn locator(&self) -> SourceLocator {
        SourceLocator::from_raw(self.locator)
    }

    /// Target member produced by the asserted equation.
    pub fn output(&self) -> CollectionData {
        Inline::new(self.output)
    }

    /// Unverified author public-key bytes.
    pub fn author(&self) -> Inline<ED25519PublicKey> {
        Inline::new(self.author)
    }

    /// Unverified signature R component.
    pub fn r(&self) -> Inline<ED25519RComponent> {
        Inline::new(self.r)
    }

    /// Unverified signature S component.
    pub fn s(&self) -> Inline<ED25519SComponent> {
        Inline::new(self.s)
    }

    /// BLAKE3 of the complete canonical bytes, including kind and signature.
    /// This is not a proof of signature validity or authorization.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        #[cfg(test)]
        super::FINGERPRINT_CALLS.set(super::FINGERPRINT_CALLS.get() + 1);
        collection_record_fingerprint(self.as_bytes())
    }

    /// Decode these bytes and strictly verify the embedded signature.
    /// Authorization remains the caller's policy.
    pub fn to_record(&self) -> Result<CollectionDerive, RecordDecodeError> {
        CollectionDerive::from_bytes(self.as_bytes().try_into().expect("fixed DERIVE layout"))
    }

    /// Decode bytes already trusted by native replay without re-verifying.
    pub(crate) fn to_record_trusted(&self) -> CollectionDerive {
        CollectionDerive::from_bytes_trusted(
            self.as_bytes().try_into().expect("fixed DERIVE layout"),
        )
        .expect("trusted canonical DERIVE kind")
    }
}

/// Canonical MAP: `kind | attached | attachment | node | author | R | S`.
///
/// An [`anybytes::View<EncodedMap>`] checks only this structural layout.
/// Neither construction nor field access verifies kind, authorship or admission.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct EncodedMap {
    kind: [u8; 32],
    attached: [u8; 32],
    attachment: [u8; 32],
    node: [u8; 32],
    author: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

impl From<CollectionMap> for EncodedMap {
    fn from(record: CollectionMap) -> Self {
        let (r, s) = record.signature();
        Self {
            kind: KIND_COLLECTION_MAP,
            attached: record.attached().raw,
            node: record.node().raw,
            attachment: record.attachment().raw,
            author: record.public_key().raw,
            r: r.raw,
            s: s.raw,
        }
    }
}

impl EncodedMap {
    /// Complete canonical bytes, including kind, without copying or verification.
    pub fn body_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    /// The attached collection, which holds the attachment.
    pub fn collection(&self) -> CollectionHandle {
        self.attached()
    }

    /// The attached collection, which holds the attachment.
    pub fn attached(&self) -> CollectionHandle {
        Inline::new(self.attached)
    }

    /// Parent lattice node indexed by the asserted mapping.
    pub fn node(&self) -> CollectionData {
        Inline::new(self.node)
    }

    /// Attachment the asserted mapping gives the node.
    pub fn attachment(&self) -> CollectionData {
        Inline::new(self.attachment)
    }

    /// Unverified author public-key bytes.
    pub fn author(&self) -> Inline<ED25519PublicKey> {
        Inline::new(self.author)
    }

    /// Unverified signature R component.
    pub fn r(&self) -> Inline<ED25519RComponent> {
        Inline::new(self.r)
    }

    /// Unverified signature S component.
    pub fn s(&self) -> Inline<ED25519SComponent> {
        Inline::new(self.s)
    }

    /// BLAKE3 of the complete canonical bytes, including kind and signature.
    /// This is not a proof of signature validity or authorization.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        #[cfg(test)]
        super::FINGERPRINT_CALLS.set(super::FINGERPRINT_CALLS.get() + 1);
        collection_record_fingerprint(self.as_bytes())
    }

    /// Decode these bytes and strictly verify the embedded signature.
    /// Authorization remains the caller's policy.
    pub fn to_record(&self) -> Result<CollectionMap, RecordDecodeError> {
        CollectionMap::from_bytes(self.as_bytes().try_into().expect("fixed MAP layout"))
    }

    /// Decode bytes already trusted by native replay without re-verifying.
    pub(crate) fn to_record_trusted(&self) -> CollectionMap {
        CollectionMap::from_bytes_trusted(self.as_bytes().try_into().expect("fixed MAP layout"))
            .expect("trusted canonical MAP kind")
    }
}

const _: [(); COLLECTION_COMMIT_BYTES_LEN] = [(); std::mem::size_of::<EncodedCommit>()];
const _: [(); COLLECTION_DERIVE_BYTES_LEN] = [(); std::mem::size_of::<EncodedDerive>()];
const _: [(); COLLECTION_MAP_BYTES_LEN] = [(); std::mem::size_of::<EncodedMap>()];

/// Structural view of one complete eight-input canonical MERGE.
/// Layout: `kind | collection | result | author | inputs[8] | R | S`.
/// Construction alone verifies neither the kind, input ordering nor signature.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct EncodedMerge {
    kind: [u8; 32],
    collection: [u8; 32],
    result: [u8; 32],
    author: [u8; 32],
    inputs: [[u8; 32]; super::MERGE_INPUTS],
    r: [u8; 32],
    s: [u8; 32],
}

impl From<super::CollectionMerge> for EncodedMerge {
    fn from(record: super::CollectionMerge) -> Self {
        let (r, s) = record.signature();
        Self {
            kind: super::KIND_COLLECTION_MERGE,
            collection: record.collection().raw,
            result: record.result().raw,
            author: record.public_key().raw,
            inputs: std::array::from_fn(|i| record.inputs()[i].raw),
            r: r.raw,
            s: s.raw,
        }
    }
}

impl EncodedMerge {
    /// Exact complete canonical assertion, including kind and signature.
    pub fn body_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    /// Collection containing the inputs and result.
    pub fn collection(&self) -> CollectionHandle {
        Inline::new(self.collection)
    }
    /// Asserted union result's content hash.
    pub fn result(&self) -> CollectionData {
        Inline::new(self.result)
    }
    /// Unverified author public-key bytes.
    pub fn author(&self) -> Inline<ED25519PublicKey> {
        Inline::new(self.author)
    }
    /// Raw input hashes; structural access does not check their canonical order.
    pub fn inputs(&self) -> &[[u8; 32]; super::MERGE_INPUTS] {
        &self.inputs
    }
    /// BLAKE3 of every canonical byte, including kind and signature.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        collection_record_fingerprint(self.as_bytes())
    }
    /// Check the kind, distinct sorted inputs and strict signature.
    /// Authorization remains the caller's policy.
    pub fn to_record(&self) -> Result<super::CollectionMerge, RecordDecodeError> {
        super::CollectionMerge::from_bytes(self.as_bytes())
    }
    /// Decode bytes already trusted by native replay without re-verifying.
    pub(crate) fn to_record_trusted(&self) -> super::CollectionMerge {
        super::CollectionMerge::from_bytes_trusted(self.as_bytes())
            .expect("trusted canonical MERGE")
    }
}

const _: [(); super::COLLECTION_MERGE_BYTES_LEN] = [(); std::mem::size_of::<EncodedMerge>()];

#[cfg(test)]
mod tests {
    use std::mem::{align_of, offset_of, size_of};

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::collection::records::{
        CollectionMerge, RecordVerificationError, KIND_COLLECTION_MERGE,
    };

    #[test]
    fn layouts_match_complete_canonical_assertions() {
        assert_eq!(size_of::<EncodedCommit>(), 224);
        assert_eq!(align_of::<EncodedCommit>(), 1);
        assert_eq!(offset_of!(EncodedCommit, kind), 0);
        assert_eq!(offset_of!(EncodedCommit, collection), 32);
        assert_eq!(offset_of!(EncodedCommit, data), 64);
        assert_eq!(offset_of!(EncodedCommit, metadata), 96);
        assert_eq!(offset_of!(EncodedCommit, author), 128);
        assert_eq!(offset_of!(EncodedCommit, r), 160);
        assert_eq!(offset_of!(EncodedCommit, s), 192);

        assert_eq!(size_of::<EncodedDerive>(), 224);
        assert_eq!(align_of::<EncodedDerive>(), 1);
        assert_eq!(offset_of!(EncodedDerive, kind), 0);
        assert_eq!(offset_of!(EncodedDerive, target), 32);
        assert_eq!(offset_of!(EncodedDerive, output), 64);
        assert_eq!(offset_of!(EncodedDerive, locator), 96);
        assert_eq!(offset_of!(EncodedDerive, author), 128);
        assert_eq!(offset_of!(EncodedDerive, r), 160);
        assert_eq!(offset_of!(EncodedDerive, s), 192);

        assert_eq!(size_of::<EncodedMap>(), 224);
        assert_eq!(align_of::<EncodedMap>(), 1);
        assert_eq!(offset_of!(EncodedMap, kind), 0);
        assert_eq!(offset_of!(EncodedMap, attached), 32);
        assert_eq!(offset_of!(EncodedMap, attachment), 64);
        assert_eq!(offset_of!(EncodedMap, node), 96);
        assert_eq!(offset_of!(EncodedMap, author), 128);
        assert_eq!(offset_of!(EncodedMap, r), 160);
        assert_eq!(offset_of!(EncodedMap, s), 192);

        assert_eq!(size_of::<EncodedMerge>(), 448);
        assert_eq!(align_of::<EncodedMerge>(), 1);
        assert_eq!(offset_of!(EncodedMerge, kind), 0);
        assert_eq!(offset_of!(EncodedMerge, collection), 32);
        assert_eq!(offset_of!(EncodedMerge, result), 64);
        assert_eq!(offset_of!(EncodedMerge, author), 96);
        assert_eq!(offset_of!(EncodedMerge, inputs), 128);
        assert_eq!(offset_of!(EncodedMerge, r), 384);
        assert_eq!(offset_of!(EncodedMerge, s), 416);
    }

    #[test]
    fn commit_matches_existing_codec_and_fingerprint() {
        let record = CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        );
        let encoded = EncodedCommit::from(record);
        assert_eq!(encoded.as_bytes(), &record.to_bytes());
        assert_eq!(encoded.as_bytes()[..32], KIND_COLLECTION_COMMIT);
        assert_eq!(record.signing_transcript(), encoded.as_bytes()[..160]);
        let view = Bytes::from_source(record.to_bytes().to_vec())
            .view::<EncodedCommit>()
            .unwrap();
        assert_eq!(*view, encoded);
        assert_eq!(view.collection(), record.collection());
        assert_eq!(view.data(), record.data());
        assert_eq!(view.metadata(), record.metadata());
        assert_eq!(view.author(), record.public_key());
        assert_eq!((view.r(), view.s()), record.signature());
        assert_eq!(view.fingerprint(), record.fingerprint());
        assert_eq!(
            view.fingerprint().as_bytes(),
            blake3::hash(view.as_bytes()).as_bytes()
        );
        assert_eq!(view.to_record().unwrap(), record);
        assert_eq!(view.to_record_trusted(), record);
    }

    #[test]
    fn derive_matches_existing_codec_and_fingerprint() {
        let record = CollectionDerive::sign(
            &SigningKey::from_bytes(&[8; 32]),
            Inline::new([4; 32]),
            SourceLocator::of([5; 32]),
            Inline::new([6; 32]),
        );
        let encoded = EncodedDerive::from(record);
        assert_eq!(encoded.as_bytes(), &record.to_bytes());
        assert_eq!(encoded.as_bytes()[..32], KIND_COLLECTION_DERIVE);
        assert_eq!(record.signing_transcript(), encoded.as_bytes()[..160]);
        let view = Bytes::from_source(record.to_bytes().to_vec())
            .view::<EncodedDerive>()
            .unwrap();
        assert_eq!(*view, encoded);
        assert_eq!(view.collection(), record.collection());
        assert_eq!(view.target(), record.target());
        assert_eq!(view.locator(), record.input());
        assert_eq!(view.output(), record.output());
        assert_eq!(view.author(), record.public_key());
        assert_eq!((view.r(), view.s()), record.signature());
        assert_eq!(view.fingerprint(), record.fingerprint());
        assert_eq!(
            view.fingerprint().as_bytes(),
            blake3::hash(view.as_bytes()).as_bytes()
        );
        assert_eq!(view.to_record().unwrap(), record);
        assert_eq!(view.to_record_trusted(), record);
    }

    #[test]
    fn map_matches_existing_codec_and_fingerprint() {
        let record = CollectionMap::sign(
            &SigningKey::from_bytes(&[9; 32]),
            Inline::new([7; 32]),
            Inline::new([8; 32]),
            Inline::new([9; 32]),
        );
        let encoded = EncodedMap::from(record);
        assert_eq!(encoded.as_bytes(), &record.to_bytes());
        assert_eq!(encoded.as_bytes()[..32], KIND_COLLECTION_MAP);
        assert_eq!(record.signing_transcript(), encoded.as_bytes()[..160]);
        let view = Bytes::from_source(record.to_bytes().to_vec())
            .view::<EncodedMap>()
            .unwrap();
        assert_eq!(*view, encoded);
        assert_eq!(view.collection(), record.collection());
        assert_eq!(view.attached(), record.attached());
        assert_eq!(view.node(), record.node());
        assert_eq!(view.attachment(), record.attachment());
        assert_eq!(view.author(), record.public_key());
        assert_eq!((view.r(), view.s()), record.signature());
        assert_eq!(view.fingerprint(), record.fingerprint());
        assert_eq!(
            view.fingerprint().as_bytes(),
            blake3::hash(view.as_bytes()).as_bytes()
        );
        assert_eq!(view.to_record().unwrap(), record);
        assert_eq!(view.to_record_trusted(), record);
    }

    #[test]
    fn merge_matches_canonical_codec_and_checks_inputs_and_signature() {
        let record = CollectionMerge::sign(
            &SigningKey::from_bytes(&[11; 32]),
            Inline::new([12; 32]),
            (1..=8).rev().map(|n| Inline::new([n; 32])),
            Inline::new([13; 32]),
        )
        .unwrap();
        let encoded = EncodedMerge::from(record);
        let canonical = record.to_bytes();
        assert_eq!(encoded.as_bytes(), &canonical);
        assert_eq!(canonical[..32], KIND_COLLECTION_MERGE);
        assert_eq!(record.signing_transcript(), canonical[..384]);
        let mut unaligned = vec![0];
        unaligned.extend_from_slice(&canonical);
        let bytes = Bytes::from_source(unaligned).slice(1..449);
        let view = bytes.clone().view::<EncodedMerge>().unwrap();
        assert_eq!(view.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(*view, encoded);
        assert_eq!(view.collection(), record.collection());
        assert_eq!(view.result(), record.result());
        assert_eq!(view.author(), record.public_key());
        for (index, input) in record.inputs().iter().enumerate() {
            assert_eq!(view.inputs()[index], input.raw);
            assert_eq!(canonical[128 + index * 32..160 + index * 32], input.raw);
        }
        let (r, s) = record.signature();
        assert_eq!(canonical[384..416], r.raw);
        assert_eq!(canonical[416..448], s.raw);
        assert_eq!(view.fingerprint(), record.fingerprint());
        assert_eq!(
            view.fingerprint().as_bytes(),
            blake3::hash(view.as_bytes()).as_bytes()
        );
        assert_eq!(view.to_record().unwrap(), record);
        assert_eq!(view.to_record_trusted(), record);

        let mut duplicate = canonical;
        duplicate[160..192].copy_from_slice(&canonical[128..160]);
        let mut reversed = canonical;
        reversed[128..160].copy_from_slice(&canonical[160..192]);
        reversed[160..192].copy_from_slice(&canonical[128..160]);
        for invalid in [duplicate, reversed] {
            let view = Bytes::from_source(invalid.to_vec())
                .view::<EncodedMerge>()
                .unwrap();
            assert_eq!(
                view.to_record(),
                Err(RecordDecodeError::NonCanonicalMergeInputs)
            );
        }
        let mut invalid_signature = canonical;
        invalid_signature[416..448].fill(0xff);
        let view = Bytes::from_source(invalid_signature.to_vec())
            .view::<EncodedMerge>()
            .unwrap();
        assert_eq!(
            view.to_record(),
            Err(RecordDecodeError::Verification(
                RecordVerificationError::InvalidSignature
            ))
        );
        assert_eq!(view.to_record_trusted().to_bytes(), invalid_signature);
    }

    #[test]
    fn structural_views_accept_arbitrary_kinds_but_typed_decoders_check_all_kind_bytes() {
        macro_rules! check {
            ($encoded:ty, $kind:expr, $other:expr, $len:expr) => {{
                let mut changed_last_byte = $kind;
                changed_last_byte[31] ^= 1;
                for kind in [changed_last_byte, $other] {
                    let mut raw = vec![0xff; $len];
                    raw[..32].copy_from_slice(&kind);
                    let bytes = Bytes::from_source(raw);
                    let view = bytes.clone().view::<$encoded>().unwrap();
                    assert_eq!(view.as_bytes().as_ptr(), bytes.as_ptr());
                    assert_eq!(view.to_record(), Err(RecordDecodeError::InvalidKind(kind)));
                }
            }};
        }
        check!(
            EncodedCommit,
            KIND_COLLECTION_COMMIT,
            KIND_COLLECTION_MAP,
            224
        );
        check!(
            EncodedDerive,
            KIND_COLLECTION_DERIVE,
            KIND_COLLECTION_COMMIT,
            224
        );
        check!(EncodedMap, KIND_COLLECTION_MAP, KIND_COLLECTION_DERIVE, 224);
        check!(
            EncodedMerge,
            KIND_COLLECTION_MERGE,
            KIND_COLLECTION_COMMIT,
            448
        );
    }

    #[test]
    fn structural_views_do_not_bypass_strict_signature_verification() {
        // A valid public key and noncanonical S guarantee a signature error,
        // independently of how the other fields happen to be interpreted.
        let author = SigningKey::from_bytes(&[10; 32]).verifying_key();
        let body = |kind: [u8; 32]| {
            let mut body = [0xff; 224];
            body[..32].copy_from_slice(&kind);
            body[128..160].copy_from_slice(&author.to_bytes());
            body
        };
        let commit_body = body(KIND_COLLECTION_COMMIT);
        let derive_body = body(KIND_COLLECTION_DERIVE);
        let map_body = body(KIND_COLLECTION_MAP);
        let commit = Bytes::from_source(commit_body.to_vec())
            .view::<EncodedCommit>()
            .unwrap();
        let derive = Bytes::from_source(derive_body.to_vec())
            .view::<EncodedDerive>()
            .unwrap();
        let map = Bytes::from_source(map_body.to_vec())
            .view::<EncodedMap>()
            .unwrap();
        let expected = RecordDecodeError::Verification(RecordVerificationError::InvalidSignature);
        assert_eq!(commit.to_record(), Err(expected.clone()));
        assert_eq!(derive.to_record(), Err(expected.clone()));
        assert_eq!(map.to_record(), Err(expected));

        // Trusted replay's existing structural contract retains all bytes.
        assert_eq!(commit.to_record_trusted().to_bytes(), commit_body);
        assert_eq!(derive.to_record_trusted().to_bytes(), derive_body);
        assert_eq!(map.to_record_trusted().to_bytes(), map_body);
    }

    #[test]
    fn structural_views_accept_byte_alignment_and_reject_wrong_lengths() {
        let bytes = Bytes::from_source(vec![0u8; 450]);
        let body = bytes.slice(1..225);
        let commit = body.clone().view::<EncodedCommit>().unwrap();
        let derive = body.clone().view::<EncodedDerive>().unwrap();
        let map = body.clone().view::<EncodedMap>().unwrap();
        assert_eq!(commit.as_bytes().as_ptr(), body.as_ptr());
        assert_eq!(derive.as_bytes().as_ptr(), body.as_ptr());
        assert_eq!(map.as_bytes().as_ptr(), body.as_ptr());
        for length in [0, 191, 192, 223, 225] {
            assert!(bytes.slice(..length).view::<EncodedCommit>().is_err());
            assert!(bytes.slice(..length).view::<EncodedDerive>().is_err());
            assert!(bytes.slice(..length).view::<EncodedMap>().is_err());
        }
        let body = bytes.slice(1..449);
        let merge = body.clone().view::<EncodedMerge>().unwrap();
        assert_eq!(merge.as_bytes().as_ptr(), body.as_ptr());
        for length in [0, 224, 447, 449] {
            assert!(bytes.slice(..length).view::<EncodedMerge>().is_err());
        }
    }
}
