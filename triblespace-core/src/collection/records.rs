//! Dense typed records for the top-level collection calculus.
//!
//! [`CollectionCommit`], [`CollectionMerge`], and [`CollectionDerive`] are
//! native algebra records, not graph data. Their canonical representations are
//! the fixed-width byte layouts exposed by their `to_bytes`/`from_bytes`
//! methods. A collection *descriptor* is not a record at all: it is an
//! ordinary [`TribleSet`] stored as a self-describing [`SimpleArchive`], and
//! that blob's handle is the collection identity. See
//! [`descriptor`](crate::collection::descriptor) for reading one.
//!
//! Public byte decoding verifies the embedded signature before admitting
//! foreign evidence. Trusted native replay uses crate-private structural
//! decoding instead: local persisted records are not cryptographically checked
//! again on every read. Signatures prove authorship; WRITE authorization is a
//! separate observation-time policy.

use std::error::Error;
use std::fmt;

#[cfg(test)]
thread_local! {
    pub(crate) static FINGERPRINT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

use ed25519::signature::Signer;
use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};

#[cfg(test)]
use crate::attribute::Attribute;
use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::id::Id;
use crate::id_hex;
use crate::inline::encodings::ed25519::{ED25519PublicKey, ED25519RComponent, ED25519SComponent};
use crate::inline::encodings::genid::GenId;
#[cfg(test)]
use crate::inline::encodings::genid::IdParseError;
use crate::inline::encodings::hash::{Blake3, Handle, Hash};
use crate::inline::Inline;
#[cfg(test)]
use crate::inline::InlineEncoding;
use crate::prelude::attributes;
use crate::trible::TribleSet;

pub use crate::capability::policy::{
    admission_delegate_threshold, admission_invoke_threshold, admission_policy_root,
};

/// Tag identifying a canonical collection descriptor.
///
/// Minted with `trible genid` on 2026-08-07.
pub const KIND_COLLECTION_DESCRIPTOR: Id = id_hex!("C5E238729BB95FA4A55E3939B11B3C29");
/// Tag identifying a concrete collection mapping instance.
///
/// Minted with `trible genid` on 2026-08-29.
pub const KIND_COLLECTION_MAPPING: Id = id_hex!("8725AF624FE719B70289A67B21174FEA");
/// Stable semantic kind of a signed `COMMIT(descriptor, data, metadata)` assertion.
///
/// Minted with `trible genid` on 2026-08-11.
pub const KIND_COLLECTION_COMMIT: Id = id_hex!("B34817308188C4515A3C51967A91A603");
/// Stable semantic kind of a signed, witness-bound commutative `MERGE` equation.
/// Minted with `trible genid` on 2026-09-14.
pub const KIND_COLLECTION_MERGE: Id = id_hex!("96AB9DE7389DD621D44C55E593898A69");
/// Stable semantic kind of a signed, witness-bound `DERIVE` equation.
/// Minted with `trible genid` on 2026-09-14.
pub const KIND_COLLECTION_DERIVE: Id = id_hex!("529D8F57A20FCA0BC921121313DC619B");
/// Retired signed MERGE kind without input-record witnesses.
/// Minted with `trible genid` on 2026-09-13, retired 2026-09-14.
pub const KIND_COLLECTION_MERGE_SIGNED_V2: Id = id_hex!("1E5277B23D177FD692B074FBF0EF28F1");
/// Retired signed DERIVE kind without an input-record witness.
/// Minted with `trible genid` on 2026-09-13, retired 2026-09-14.
pub const KIND_COLLECTION_DERIVE_SIGNED_V2: Id = id_hex!("CE6A838612D0AA0812C05A50CCD11DC1");
/// Retired unsigned MERGE kind; never interpreted as a signed equation.
/// Minted with `trible genid` on 2026-08-11, retired 2026-09-13.
pub const KIND_COLLECTION_MERGE_UNSIGNED: Id = id_hex!("5F20FFC64313969B7E046A7677874D39");
/// Retired unsigned DERIVE kind; never interpreted as a signed equation.
/// Minted with `trible genid` on 2026-08-11, retired 2026-09-13.
pub const KIND_COLLECTION_DERIVE_UNSIGNED: Id = id_hex!("46C621338B6DD5B71C8E1E6DD74B087C");

/// The three-field derive's predecessor, which also named its source.
///
/// A derive's source is what the target's descriptor says it is, so naming it
/// again in the record only created a way for the two to disagree. Records
/// under this kind are not read: a derivation is a computation with a
/// checkable artifact, so the cheapest correct thing to do with a stale one is
/// recompute it. Kept here so the id is not minted twice.
///
/// Minted with `trible genid` on 2026-08-07, retired 2026-08-20.
pub const KIND_COLLECTION_DERIVE_V1: Id = id_hex!("6DB0214CB4F3BD8259F0117CDC127331");

/// Retired semantic kind of a signed collection-gossip grant.
///
/// A grant was an author-signed, irrevocable permission to redistribute that
/// author's commits in one collection. It is gone because discovery and
/// dissemination are now governed by the descriptor's READ policy and exact
/// capability evidence, independently of any one COMMIT author.
///
/// No pile has ever held one -- 21.2 GB across six piles were scanned for the
/// record marker before the kind was removed, and the same scan found commit
/// records, so the absence was the grant's and not the scan's. Nothing in
/// production minted them: `sign` appeared only in tests, which is exactly the
/// silent failure the move to the descriptor removes.
///
/// Minted with `trible genid` on 2026-08-12, retired 2026-08-21. Kept here so
/// the id is not minted twice.
pub const KIND_COLLECTION_GOSSIP_V1: Id = id_hex!("9BB5B1F4D6FD8FB850B494C2CF51B5CA");

/// Byte length of a dense signed commit.
pub const COLLECTION_COMMIT_BYTES_LEN: usize = 6 * 32;
/// Byte length of a dense merge equation.
pub const COLLECTION_MERGE_BYTES_LEN: usize = 7 * 32;
/// Byte length of a dense derive equation.
pub const COLLECTION_DERIVE_BYTES_LEN: usize = 6 * 32;

/// Dense byte length of a witness-free `MERGE`: collection, two inputs, the
/// result, the author key and its signature. One 32-byte field shorter per
/// input than the witness-bearing form it replaces.
pub const COLLECTION_MERGE_V4_BYTES_LEN: usize = 7 * 32;

/// Dense byte length of a witness-free `DERIVE`. Structurally identical to a
/// COMMIT -- a collection, the payloads, the key and the signature -- which is
/// the tell that all three records are now one kind of statement.
pub const COLLECTION_DERIVE_V4_BYTES_LEN: usize = 6 * 32;
/// Byte length of a retired signed merge without input-record witnesses.
pub const COLLECTION_MERGE_SIGNED_V2_BYTES_LEN: usize = 7 * 32;
/// Byte length of a retired signed derive without an input-record witness.
pub const COLLECTION_DERIVE_SIGNED_V2_BYTES_LEN: usize = 6 * 32;

attributes! {
    /// The human-readable name of a root collection.
    ///
    /// The UTF-8 bytes live in an attachment so the identity has no arbitrary
    /// 32-byte ceiling. Independent READ and WRITE policy fragments provide
    /// the authorization context; the name remains descriptive rather than an
    /// ambient namespace.
    ///
    /// Anchor minted with `trible genid` on 2026-08-28:
    /// `A2EEF06D4E1AA4B17B745AA2E8C37867`.
    "A2EEF06D4E1AA4B17B745AA2E8C37867" as pub collection_name: Handle<UTF8String>;
    /// The collection this one derives from, by descriptor handle.
    ///
    /// This says *what* a derived collection is computed from; which state of
    /// that source a given commit reflects belongs on the commit, not here.
    /// A handle rather than a shared label means a descriptor cannot claim a
    /// lineage it does not have: it names one exact source descriptor.
    ///
    /// Minted with `trible genid` on 2026-08-19.
    "8D93B2A626CD32182C0A026BC8D5A014" unsafe as pub collection_source: Handle<SimpleArchive>;
    /// Blob representation carried by the elements of this collection.
    /// Minted with `trible genid` on 2026-08-07.
    "620FA4F2B456357DCD1882E583B85CC3" unsafe as pub collection_representation: GenId;
    /// Concrete mapping instance carried by a derived collection.
    ///
    /// The linked entity names one mapping algorithm and carries its concrete
    /// parameters. Root collections omit this field; derived collections carry
    /// it together with [`collection_source`].
    /// Anchor minted with `trible genid` on 2026-08-29:
    /// `D63BCA62411CA97CCF5DB2132EE57CDF`.
    "D63BCA62411CA97CCF5DB2132EE57CDF" as pub collection_mapping: GenId;
    /// Algorithm used by one concrete collection mapping instance.
    ///
    /// The algorithm entity is embedded through Fragment spread, keeping the
    /// descriptor self-describing. Canonical builders derive the mapping id
    /// from its concrete parameters, while readers validate these facts
    /// directly so equivalent extrinsic ids remain valid.
    /// Anchor minted with `trible genid` on 2026-08-29:
    /// `AF43D02D710977411CA7DA164BDA5CD9`.
    "AF43D02D710977411CA7DA164BDA5CD9" as pub mapping_algorithm: GenId;
}

/// Type-erased content identity of one collection element.
///
/// The concrete blob encoding is named by the collection's
/// [`collection_representation`] field. Keeping the element itself as a bare
/// Blake3 digest avoids falsely claiming that it has the `UnknownBlob`
/// encoding; after validating the collection descriptor, callers can transmute
/// this digest into the representation's typed [`Handle`].
pub type CollectionData = Inline<Hash<Blake3>>;

/// Content identity of one canonical collection descriptor.
///
/// The descriptor is an ordinary [`SimpleArchive`] blob. Claims carry this
/// handle directly so their collection semantics can be recovered through
/// ordinary blob resolution without a separate definition-record namespace.
pub type CollectionHandle = Inline<Handle<SimpleArchive>>;

/// Full-width content fingerprint of one canonical persisted collection record.
///
/// A fingerprint is an implementation key for indexes, deduplication,
/// transport deltas, diagnostics, and exact input-record witnesses. It is not
/// an entity id or a member of denotational support. The fingerprint is the
/// full BLAKE3 digest of the record's stable semantic kind followed by its
/// canonical dense payload, and is recomputed from those bytes rather than
/// stored as a self-address in the record value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionRecordFingerprint([u8; 32]);

impl CollectionRecordFingerprint {
    /// Construct a fingerprint from its raw digest bytes.
    pub const fn from_raw(raw: [u8; 32]) -> Self {
        Self(raw)
    }

    /// Return the raw full-width digest.
    pub const fn raw(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw full-width digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CollectionRecordFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for CollectionRecordFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Version of the signed collection-commit transcript.
pub const COMMIT_TRANSCRIPT_VERSION: u32 = 2;

/// Domain prefix of the signed collection-commit transcript.
pub const COMMIT_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.commit.transcript";

/// Number of bytes in a version-2 commit transcript.
pub const COMMIT_TRANSCRIPT_LEN: usize = COMMIT_TRANSCRIPT_DOMAIN.len()
    + 16 // kind id
    + 4 // version
    + 32 // public key
    + 32 // collection descriptor handle
    + 32 // data hash
    + 32; // metadata handle

/// Signature domain for witness-bound MERGE endorsements.
pub const MERGE_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.merge.endorsement";
/// Signature domain for witness-bound DERIVE endorsements.
pub const DERIVE_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.derive.endorsement";
/// Retired signature domain for MERGE equations without input witnesses.
pub const MERGE_SIGNED_V2_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.merge.transcript";
/// Retired signature domain for DERIVE equations without an input witness.
pub const DERIVE_SIGNED_V2_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.derive.transcript";

/// Witness-free equation transcripts.
///
/// An equation is a statement about PAYLOADS: these inputs combine to this
/// output in this collection. Which record happened to assert an input is not
/// part of that statement. Binding one made support narrower than the facts
/// warranted -- a reader holding a different but equally admitted assertion of
/// the same payload had the support and was told it did not, because the cited
/// record was missing. An annotation may only widen; a witness narrowed.
pub const MERGE_V4_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.merge.equation";
/// See [`MERGE_V4_TRANSCRIPT_DOMAIN`].
pub const DERIVE_V4_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.derive.equation";

/// Return the canonical handle of an empty metadata archive.
///
/// Metadata is mandatory in a [`CollectionCommit`]. Callers with no metadata
/// use this handle rather than omitting the field, so record arity and signed
/// transcript shape never vary.
pub fn empty_metadata_handle() -> Inline<Handle<SimpleArchive>> {
    encode_archive(TribleSet::new()).get_handle()
}

/// Canonical decoding or foreign-signature verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordDecodeError {
    /// The bytes were not a canonical `SimpleArchive`.
    Archive(UnarchiveError),
    /// A required field was absent.
    MissingField(&'static str),
    /// A single-valued field occurred more than once.
    RepeatedField(&'static str),
    /// A typed descriptor field had a noncanonical inline representation.
    InvalidId(&'static str),
    /// A dense record had no kind byte or the wrong payload length.
    InvalidLength { expected: usize, actual: usize },
    /// A tagged dense record used an unknown variant byte.
    UnknownKind(u8),
    /// A merge did not carry its (payload digest, witness) pairs in ascending order.
    NonCanonicalMergeInputs,
    /// Public ingress rejected the embedded key or signature.
    Verification(RecordVerificationError),
}

impl fmt::Display for RecordDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Archive(error) => write!(f, "invalid SimpleArchive record: {error}"),
            Self::MissingField(field) => write!(f, "collection record is missing {field}"),
            Self::RepeatedField(field) => {
                write!(f, "collection record contains repeated {field}")
            }
            Self::InvalidId(field) => write!(f, "collection record contains invalid {field}"),
            Self::InvalidLength { expected, actual } => write!(
                f,
                "collection record has {actual} bytes; expected exactly {expected}"
            ),
            Self::UnknownKind(kind) => {
                write!(f, "collection record has unknown dense kind {kind}")
            }
            Self::NonCanonicalMergeInputs => {
                write!(f, "collection merge inputs are not canonically ordered")
            }
            Self::Verification(error) => error.fmt(f),
        }
    }
}

impl Error for RecordDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Archive(error) => Some(error),
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}

impl From<UnarchiveError> for RecordDecodeError {
    fn from(error: UnarchiveError) -> Self {
        Self::Archive(error)
    }
}

/// Signature verification failure for any signed collection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordVerificationError {
    /// The public-key bytes do not encode a canonical non-weak Ed25519 key.
    InvalidPublicKey,
    /// Strict Ed25519 verification rejected the transcript/signature pair.
    InvalidSignature,
}

impl fmt::Display for RecordVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "collection record has an invalid public key"),
            Self::InvalidSignature => write!(f, "collection record signature is invalid"),
        }
    }
}

impl Error for RecordVerificationError {}

impl From<RecordVerificationError> for RecordDecodeError {
    fn from(error: RecordVerificationError) -> Self {
        Self::Verification(error)
    }
}

/// Signed exogenous membership assertion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CollectionCommit {
    collection: CollectionHandle,
    data: CollectionData,
    metadata: Inline<Handle<SimpleArchive>>,
    public_key: Inline<ED25519PublicKey>,
    signature_r: Inline<ED25519RComponent>,
    signature_s: Inline<ED25519SComponent>,
}

impl CollectionCommit {
    /// Canonical persisted record identity, distinct from its content handle.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        CollectionRecord::Commit(*self).fingerprint()
    }

    /// Sign a canonical `COMMIT(descriptor, data, metadata)` statement.
    pub fn sign(
        signing_key: &SigningKey,
        collection: CollectionHandle,
        data_hash: CollectionData,
        metadata: Inline<Handle<SimpleArchive>>,
    ) -> Self {
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let transcript = commit_transcript(public_key, collection, data_hash, metadata);
        let signature: Signature = signing_key.sign(&transcript);
        Self::from_parts(
            collection,
            data_hash,
            metadata,
            public_key,
            Inline::new(*signature.r_bytes()),
            Inline::new(*signature.s_bytes()),
        )
    }

    pub(crate) fn from_parts(
        collection: CollectionHandle,
        data_hash: CollectionData,
        metadata: Inline<Handle<SimpleArchive>>,
        public_key: Inline<ED25519PublicKey>,
        r_component: Inline<ED25519RComponent>,
        s_component: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            collection,
            data: data_hash,
            metadata,
            public_key,
            signature_r: r_component,
            signature_s: s_component,
        }
    }

    /// Decode foreign dense bytes and strictly verify their signature.
    pub fn from_bytes(bytes: [u8; COLLECTION_COMMIT_BYTES_LEN]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes);
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(bytes: [u8; COLLECTION_COMMIT_BYTES_LEN]) -> Self {
        Self::from_parts(
            Inline::new(field(&bytes, 0)),
            Inline::new(field(&bytes, 1)),
            Inline::new(field(&bytes, 2)),
            Inline::new(field(&bytes, 3)),
            Inline::new(field(&bytes, 4)),
            Inline::new(field(&bytes, 5)),
        )
    }

    /// Strictly verify the Ed25519 signature over the canonical transcript.
    ///
    /// This proves only that the embedded public key signed the record. Key
    /// authorization is a separate caller policy.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        let transcript =
            commit_transcript(self.public_key, self.collection, self.data, self.metadata);
        verify_record_signature(self.public_key, self.signature(), &transcript)
    }

    /// Exact bytes attested by this commit's signature.
    pub fn signing_transcript(&self) -> Vec<u8> {
        commit_transcript(self.public_key, self.collection, self.data, self.metadata).to_vec()
    }

    /// Collection receiving the asserted member.
    pub fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Asserted member's content hash.
    pub fn data(&self) -> CollectionData {
        self.data
    }

    /// Mandatory metadata archive handle.
    pub fn metadata(&self) -> Inline<Handle<SimpleArchive>> {
        self.metadata
    }

    /// Raw public-key field. It becomes trusted only after strict verification.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        self.public_key
    }

    /// Raw signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        (self.signature_r, self.signature_s)
    }

    /// Blob handles named directly by this record.
    ///
    /// This is structural ownership information, not a validity or admission
    /// decision. A retained commit owns every one of these handles when it is
    /// resident, even when the commit's signature is invalid or another
    /// referenced handle is absent.
    pub fn blob_references(&self) -> [Inline<Handle<UnknownBlob>>; 3] {
        [
            self.collection.transmute(),
            Handle::<UnknownBlob>::from_hash(self.data),
            self.metadata.transmute(),
        ]
    }

    /// Encode this record into its exact dense 192-byte layout.
    pub fn to_bytes(&self) -> [u8; COLLECTION_COMMIT_BYTES_LEN] {
        commit_bytes(
            self.collection,
            self.data,
            self.metadata,
            self.public_key,
            self.signature_r,
            self.signature_s,
        )
    }
}

/// Signed exact join equation endorsing two specific input records.
///
/// The input payloads describe the computation. Their record fingerprints
/// bind the producer's validation endorsement to one support route, rather
/// than to every other record that happens to produce the same payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CollectionMerge {
    collection: CollectionHandle,
    low: CollectionData,
    high: CollectionData,
    result: CollectionData,
    public_key: Inline<ED25519PublicKey>,
    signature_r: Inline<ED25519RComponent>,
    signature_s: Inline<ED25519SComponent>,
}

impl CollectionMerge {
    /// Canonical persisted record identity.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        CollectionRecord::Merge(*self).fingerprint()
    }

    /// Sign a join of two payloads, in canonical order.
    ///
    /// The statement is about PAYLOADS: these two join to this result. Which
    /// records happen to produce the inputs is not part of it -- a reader
    /// finds those by content, and naming one here only chose a route nobody
    /// needed and made the same join publishable several times over.
    pub fn sign(
        signing_key: &SigningKey,
        collection: CollectionHandle,
        mut low: CollectionData,
        mut high: CollectionData,
        result: CollectionData,
    ) -> Self {
        if high < low {
            std::mem::swap(&mut low, &mut high);
        }
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let transcript = equation_transcript(
            MERGE_SIGNED_V2_TRANSCRIPT_DOMAIN,
            KIND_COLLECTION_MERGE_SIGNED_V2,
            public_key,
            [collection.raw, low.raw, high.raw, result.raw],
        );
        let signature: Signature = signing_key.sign(&transcript);
        Self::from_parts(
            collection,
            low,
            high,
            result,
            public_key,
            Inline::new(*signature.r_bytes()),
            Inline::new(*signature.s_bytes()),
        )
    }

    pub(crate) fn from_parts(
        collection: CollectionHandle,
        low: CollectionData,
        high: CollectionData,
        result: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            collection,
            low,
            high,
            result,
            public_key,
            signature_r,
            signature_s,
        }
    }

    /// Decode foreign dense bytes, requiring canonical order and a strict signature.
    pub fn from_bytes(bytes: [u8; COLLECTION_MERGE_BYTES_LEN]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(
        bytes: [u8; COLLECTION_MERGE_BYTES_LEN],
    ) -> Result<Self, RecordDecodeError> {
        let low = Inline::new(field(&bytes, 1));
        let high = Inline::new(field(&bytes, 2));
        if high < low {
            return Err(RecordDecodeError::NonCanonicalMergeInputs);
        }
        Ok(Self::from_parts(
            Inline::new(field(&bytes, 0)),
            low,
            high,
            Inline::new(field(&bytes, 3)),
            Inline::new(field(&bytes, 4)),
            Inline::new(field(&bytes, 5)),
            Inline::new(field(&bytes, 6)),
        ))
    }

    /// Prove authorship only; WRITE admission remains a separate policy query.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        verify_record_signature(
            self.public_key,
            self.signature(),
            &self.signing_transcript(),
        )
    }

    /// Exact domain-separated bytes signed by the author.
    pub fn signing_transcript(&self) -> Vec<u8> {
        equation_transcript(
            MERGE_SIGNED_V2_TRANSCRIPT_DOMAIN,
            KIND_COLLECTION_MERGE_SIGNED_V2,
            self.public_key,
            [
                self.collection.raw,
                self.low.raw,
                self.high.raw,
                self.result.raw,
            ],
        )
    }

    /// Author's public key.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        self.public_key
    }

    /// Exact signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        (self.signature_r, self.signature_s)
    }

    /// Collection whose join law is asserted.
    pub fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Canonically ordered merge inputs.
    pub fn inputs(&self) -> (CollectionData, CollectionData) {
        (self.low, self.high)
    }

    /// Asserted exact join result.
    pub fn result(&self) -> CollectionData {
        self.result
    }

    /// Blob handles named directly by this record.
    ///
    /// A retained equation owns its descriptor, both inputs, and result when
    /// those blobs are resident. Residency of each handle is independent.
    pub fn blob_references(&self) -> [Inline<Handle<UnknownBlob>>; 4] {
        [
            self.collection.transmute(),
            Handle::<UnknownBlob>::from_hash(self.low),
            Handle::<UnknownBlob>::from_hash(self.high),
            Handle::<UnknownBlob>::from_hash(self.result),
        ]
    }

    /// Encode this endorsement into its exact dense 288-byte layout.
    pub fn to_bytes(&self) -> [u8; COLLECTION_MERGE_BYTES_LEN] {
        concat_fields([
            self.collection.raw,
            self.low.raw,
            self.high.raw,
            self.result.raw,
            self.public_key.raw,
            self.signature_r.raw,
            self.signature_s.raw,
        ])
    }
}

/// One signed exact mapping equation endorsing a specific source record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CollectionDerive {
    collection: CollectionHandle,
    input: CollectionData,
    output: CollectionData,
    public_key: Inline<ED25519PublicKey>,
    signature_r: Inline<ED25519RComponent>,
    signature_s: Inline<ED25519SComponent>,
}

impl CollectionDerive {
    /// Canonical persisted record identity.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        CollectionRecord::Derive(*self).fingerprint()
    }

    /// Sign a canonical input-record-bound `DERIVE` endorsement.
    ///
    /// The output collection is named by descriptor handle, exactly as a commit names its
    /// collection, and that descriptor already says which collection is the
    /// source and embeds the exact mapping facts. A derive therefore
    /// says *which input/output equation* was computed, never restates the
    /// mapping definition. The input witness additionally names the exact
    /// source record the producer validated; another equation for the same
    /// payload cannot silently change the endorsed route.
    pub fn sign(
        signing_key: &SigningKey,
        collection: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
    ) -> Self {
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let transcript = equation_transcript(
            DERIVE_SIGNED_V2_TRANSCRIPT_DOMAIN,
            KIND_COLLECTION_DERIVE_SIGNED_V2,
            public_key,
            [collection.raw, input.raw, output.raw],
        );
        let signature: Signature = signing_key.sign(&transcript);
        Self::from_parts(
            collection,
            input,
            output,
            public_key,
            Inline::new(*signature.r_bytes()),
            Inline::new(*signature.s_bytes()),
        )
    }

    pub(crate) fn from_parts(
        collection: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            collection,
            input,
            output,
            public_key,
            signature_r,
            signature_s,
        }
    }

    /// Decode foreign dense bytes and strictly verify their signature.
    pub fn from_bytes(bytes: [u8; COLLECTION_DERIVE_BYTES_LEN]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes);
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(bytes: [u8; COLLECTION_DERIVE_BYTES_LEN]) -> Self {
        Self::from_parts(
            Inline::new(field(&bytes, 0)),
            Inline::new(field(&bytes, 1)),
            Inline::new(field(&bytes, 2)),
            Inline::new(field(&bytes, 3)),
            Inline::new(field(&bytes, 4)),
            Inline::new(field(&bytes, 5)),
        )
    }

    /// Prove authorship only; WRITE admission remains a separate policy query.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        verify_record_signature(
            self.public_key,
            self.signature(),
            &self.signing_transcript(),
        )
    }

    /// Exact domain-separated bytes signed by the author.
    pub fn signing_transcript(&self) -> Vec<u8> {
        equation_transcript(
            DERIVE_SIGNED_V2_TRANSCRIPT_DOMAIN,
            KIND_COLLECTION_DERIVE_SIGNED_V2,
            self.public_key,
            [
                self.collection.raw,
                self.input.raw,
                self.output.raw,
            ],
        )
    }

    /// Author's public key.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        self.public_key
    }

    /// Exact signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        (self.signature_r, self.signature_s)
    }

    /// Collection containing the output member.
    pub fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Source member mapped by this equation.
    pub fn input(&self) -> CollectionData {
        self.input
    }

    /// Target member produced by this equation.
    pub fn output(&self) -> CollectionData {
        self.output
    }

    /// Blob handles named directly by this record.
    ///
    /// A retained equation owns its target descriptor, input, and output when
    /// those blobs are resident. Residency of each handle is independent.
    pub fn blob_references(&self) -> [Inline<Handle<UnknownBlob>>; 3] {
        [
            self.collection.transmute(),
            Handle::<UnknownBlob>::from_hash(self.input),
            Handle::<UnknownBlob>::from_hash(self.output),
        ]
    }

    /// Encode this endorsement into its exact dense 224-byte layout.
    pub fn to_bytes(&self) -> [u8; COLLECTION_DERIVE_BYTES_LEN] {
        concat_fields([
            self.collection.raw,
            self.input.raw,
            self.output.raw,
            self.public_key.raw,
            self.signature_r.raw,
            self.signature_s.raw,
        ])
    }
}

/// Historical unsigned computation evidence, never a current collection record.
///
/// Only an explicitly authorized writer may endorse this evidence by signing a
/// new equation. Decoding or receiving it never manufactures an endorsement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LegacyUnsignedCollectionEquation {
    Merge {
        collection: CollectionHandle,
        low: CollectionData,
        high: CollectionData,
        result: CollectionData,
    },
    Derive {
        collection: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
    },
}

impl LegacyUnsignedCollectionEquation {
    /// Structurally decode an exact retired dense value for explicit migration.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let Some((&kind, payload)) = bytes.split_first() else {
            return Err(RecordDecodeError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match kind {
            COLLECTION_RECORD_KIND_MERGE_V1 => {
                let bytes = exact_array::<128>(payload)?;
                let low = Inline::new(field(&bytes, 1));
                let high = Inline::new(field(&bytes, 2));
                if high < low {
                    return Err(RecordDecodeError::NonCanonicalMergeInputs);
                }
                Ok(Self::Merge {
                    collection: Inline::new(field(&bytes, 0)),
                    low,
                    high,
                    result: Inline::new(field(&bytes, 3)),
                })
            }
            COLLECTION_RECORD_KIND_DERIVE_V1 => {
                let bytes = exact_array::<96>(payload)?;
                Ok(Self::Derive {
                    collection: Inline::new(field(&bytes, 0)),
                    input: Inline::new(field(&bytes, 1)),
                    output: Inline::new(field(&bytes, 2)),
                })
            }
            unknown => Err(RecordDecodeError::UnknownKind(unknown)),
        }
    }

    /// The exact collection (target for DERIVE) requiring writer endorsement.
    pub fn collection(&self) -> CollectionHandle {
        match self {
            Self::Merge { collection, .. } | Self::Derive { collection, .. } => *collection,
        }
    }

    /// Historical content key, used only to check persisted dense evidence.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        match self {
            Self::Merge {
                collection,
                low,
                high,
                result,
            } => collection_record_fingerprint(
                KIND_COLLECTION_MERGE_UNSIGNED,
                &concat_fields::<4, 128>([collection.raw, low.raw, high.raw, result.raw]),
            ),
            Self::Derive {
                collection,
                input,
                output,
            } => collection_record_fingerprint(
                KIND_COLLECTION_DERIVE_UNSIGNED,
                &concat_fields::<3, 96>([collection.raw, input.raw, output.raw]),
            ),
        }
    }

    /// Every direct dependency remains a physical retention root when resident.
    pub fn blob_references(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, 4>::new();
        references.push(self.collection().transmute());
        match self {
            Self::Merge {
                low, high, result, ..
            } => {
                references.extend([*low, *high, *result].map(Handle::<UnknownBlob>::from_hash));
            }
            Self::Derive { input, output, .. } => {
                references.extend([*input, *output].map(Handle::<UnknownBlob>::from_hash));
            }
        }
        references.into_iter()
    }
}

/// A canonical signed native collection record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CollectionRecord {
    /// Signed membership assertion whose embedded signature can be verified.
    Commit(CollectionCommit),
    /// Signed exact join equation.
    Merge(CollectionMerge),
    /// Signed exact mapping equation.
    Derive(CollectionDerive),
}

impl CollectionRecord {
    /// The exact collection named by this record (the target for a DERIVE).
    pub fn collection(&self) -> CollectionHandle {
        match self {
            Self::Commit(record) => record.collection(),
            Self::Merge(record) => record.collection(),
            Self::Derive(record) => record.collection(),
        }
    }

    /// The principal whose signed assertion this record carries.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        match self {
            Self::Commit(record) => record.public_key(),
            Self::Merge(record) => record.public_key(),
            Self::Derive(record) => record.public_key(),
        }
    }

    /// Verify foreign evidence or explicitly audit trusted persisted bytes.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        match self {
            Self::Commit(record) => record.verify_strict(),
            Self::Merge(record) => record.verify_strict(),
            Self::Derive(record) => record.verify_strict(),
        }
    }

    /// Blob handles named directly by this native record.
    ///
    /// The returned handles express physical ownership only. Callers must not
    /// filter them through signature validity, collection admission, or
    /// algebraic usefulness before applying retention.
    pub fn blob_references(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, 4>::new();
        match self {
            Self::Commit(record) => references.extend(record.blob_references()),
            Self::Merge(record) => references.extend(record.blob_references()),
            Self::Derive(record) => references.extend(record.blob_references()),
        }
        references.into_iter()
    }

    /// Actual input records whose support route this endorsement binds.
    ///
    /// These are record fingerprints, not blob handles or support members.
    /// Retention follows them even when the referenced payload is absent;
    /// authority and network disclosure remain separate decisions.


    /// Decode the self-tagged dense form and strictly verify its signature.
    ///
    /// The first byte identifies the variant; the remainder is that variant's
    /// exact untagged payload. Typed protocols should use the concrete record
    /// codecs directly and avoid this extra byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Decode explicitly trusted persisted values without repeating crypto.
    /// This is not an ingress boundary for external imports or repair.
    pub(crate) fn from_bytes_trusted(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let Some((&kind, payload)) = bytes.split_first() else {
            return Err(RecordDecodeError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match kind {
            COLLECTION_RECORD_KIND_COMMIT_V1 => {
                let bytes = exact_array::<COLLECTION_COMMIT_BYTES_LEN>(payload)?;
                Ok(Self::Commit(CollectionCommit::from_bytes_trusted(bytes)))
            }
            COLLECTION_RECORD_KIND_MERGE_V2 => {
                let bytes = exact_array::<COLLECTION_MERGE_BYTES_LEN>(payload)?;
                Ok(Self::Merge(CollectionMerge::from_bytes_trusted(bytes)?))
            }
            COLLECTION_RECORD_KIND_DERIVE_V2 => {
                let bytes = exact_array::<COLLECTION_DERIVE_BYTES_LEN>(payload)?;
                Ok(Self::Derive(CollectionDerive::from_bytes_trusted(bytes)))
            }
            unknown => Err(RecordDecodeError::UnknownKind(unknown)),
        }
    }

    /// Recompute the exact content fingerprint of this canonical record.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        #[cfg(test)]
        FINGERPRINT_CALLS.set(FINGERPRINT_CALLS.get() + 1);
        match self {
            Self::Commit(record) => {
                collection_record_fingerprint(KIND_COLLECTION_COMMIT, &record.to_bytes())
            }
            Self::Merge(record) => {
                collection_record_fingerprint(KIND_COLLECTION_MERGE_SIGNED_V2, &record.to_bytes())
            }
            Self::Derive(record) => {
                collection_record_fingerprint(KIND_COLLECTION_DERIVE_SIGNED_V2, &record.to_bytes())
            }
        }
    }

    /// Encode the self-tagged dense form used by generic record stores.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Commit(record) => {
                tagged_bytes(COLLECTION_RECORD_KIND_COMMIT_V1, &record.to_bytes())
            }
            Self::Merge(record) => {
                tagged_bytes(COLLECTION_RECORD_KIND_MERGE_V2, &record.to_bytes())
            }
            Self::Derive(record) => {
                tagged_bytes(COLLECTION_RECORD_KIND_DERIVE_V2, &record.to_bytes())
            }
        }
    }
}

/// Dense generic-store tag for the version-1 [`CollectionRecord::Commit`] layout.
///
/// A future payload layout allocates a new tag rather than reinterpreting this
/// one, so stored bytes remain self-versioning without a second prefix byte.
pub const COLLECTION_RECORD_KIND_COMMIT_V1: u8 = 1;
/// Retired dense tag for the unsigned MERGE layout. Never reused.
pub const COLLECTION_RECORD_KIND_MERGE_V1: u8 = 2;
/// Retired dense tag for the unsigned DERIVE layout. Never reused.
pub const COLLECTION_RECORD_KIND_DERIVE_V1: u8 = 3;
/// Dense generic-store tag for signed MERGE. An equation names the payloads it
/// relates, never the particular records that happened to assert them.
pub const COLLECTION_RECORD_KIND_MERGE_V2: u8 = 4;
/// Dense generic-store tag for signed DERIVE. See the MERGE tag above.
pub const COLLECTION_RECORD_KIND_DERIVE_V2: u8 = 5;
/// Retired dense tag for the witness-bound MERGE layout. Never reused: those
/// bytes carried a second copy of a relation content addressing already holds.
pub const COLLECTION_RECORD_KIND_MERGE_V3: u8 = 6;
/// Retired dense tag for the witness-bound DERIVE layout. Never reused.
pub const COLLECTION_RECORD_KIND_DERIVE_V3: u8 = 7;

fn commit_bytes(
    collection: CollectionHandle,
    data_hash: CollectionData,
    metadata_handle: Inline<Handle<SimpleArchive>>,
    public_key: Inline<ED25519PublicKey>,
    r: Inline<ED25519RComponent>,
    s: Inline<ED25519SComponent>,
) -> [u8; COLLECTION_COMMIT_BYTES_LEN] {
    concat_fields([
        collection.raw,
        data_hash.raw,
        metadata_handle.raw,
        public_key.raw,
        r.raw,
        s.raw,
    ])
}

fn verify_record_signature(
    public_key: Inline<ED25519PublicKey>,
    (r, s): (Inline<ED25519RComponent>, Inline<ED25519SComponent>),
    transcript: &[u8],
) -> Result<(), RecordVerificationError> {
    let key = VerifyingKey::from_bytes(&public_key.raw)
        .map_err(|_| RecordVerificationError::InvalidPublicKey)?;
    if !crate::capability::is_valid_capability_principal(&key) {
        return Err(RecordVerificationError::InvalidPublicKey);
    }
    key.verify_strict(transcript, &Signature::from_components(r.raw, s.raw))
        .map_err(|_| RecordVerificationError::InvalidSignature)
}

fn equation_transcript<const N: usize>(
    domain: &[u8],
    kind: Id,
    public_key: Inline<ED25519PublicKey>,
    fields: [[u8; 32]; N],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(domain.len() + 16 + 32 + N * 32);
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&kind.raw());
    transcript.extend_from_slice(&public_key.raw);
    for field in fields {
        transcript.extend_from_slice(&field);
    }
    transcript
}

fn collection_record_fingerprint(kind: Id, payload: &[u8]) -> CollectionRecordFingerprint {
    let mut hasher = Blake3::new();
    hasher.update(&kind.raw());
    hasher.update(payload);
    CollectionRecordFingerprint::from_raw(hasher.finalize())
}

fn concat_fields<const N: usize, const OUT: usize>(fields: [[u8; 32]; N]) -> [u8; OUT] {
    debug_assert_eq!(OUT, N * 32);
    let mut bytes = [0u8; OUT];
    for (index, value) in fields.into_iter().enumerate() {
        bytes[index * 32..(index + 1) * 32].copy_from_slice(&value);
    }
    bytes
}

fn field<const N: usize>(bytes: &[u8; N], index: usize) -> [u8; 32] {
    bytes[index * 32..(index + 1) * 32]
        .try_into()
        .expect("fixed dense record field")
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RecordDecodeError> {
    bytes
        .try_into()
        .map_err(|_| RecordDecodeError::InvalidLength {
            expected: N,
            actual: bytes.len(),
        })
}

fn tagged_bytes(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + payload.len());
    bytes.push(kind);
    bytes.extend_from_slice(payload);
    bytes
}

fn commit_transcript(
    public_key: Inline<ED25519PublicKey>,
    collection: CollectionHandle,
    data_hash: CollectionData,
    metadata: Inline<Handle<SimpleArchive>>,
) -> [u8; COMMIT_TRANSCRIPT_LEN] {
    let mut transcript = [0; COMMIT_TRANSCRIPT_LEN];
    let mut offset = 0;
    let mut append = |bytes: &[u8]| {
        let end = offset + bytes.len();
        transcript[offset..end].copy_from_slice(bytes);
        offset = end;
    };
    append(COMMIT_TRANSCRIPT_DOMAIN);
    append(&KIND_COLLECTION_COMMIT.raw());
    append(&COMMIT_TRANSCRIPT_VERSION.to_be_bytes());
    append(&public_key.raw);
    append(&collection.raw);
    append(&data_hash.raw);
    append(&metadata.raw);
    debug_assert_eq!(offset, COMMIT_TRANSCRIPT_LEN);
    transcript
}

fn encode_archive(facts: TribleSet) -> Blob<SimpleArchive> {
    <TribleSet as crate::blob::IntoBlob<SimpleArchive>>::to_blob(facts)
}

#[cfg(test)]
pub(crate) fn one_id_for_test(facts: &TribleSet, attribute: &Attribute<GenId>) -> Id {
    one_id(facts, attribute, "test").expect("present")
}

#[cfg(test)]
fn one_id(
    facts: &TribleSet,
    attribute: &Attribute<GenId>,
    field: &'static str,
) -> Result<Id, RecordDecodeError> {
    let value: Inline<GenId> = one_inline(facts, attribute, field)?;
    value
        .try_from_inline::<Id>()
        .map_err(|_: IdParseError| RecordDecodeError::InvalidId(field))
}

#[cfg(test)]
fn one_inline<S: InlineEncoding>(
    facts: &TribleSet,
    attribute: &Attribute<S>,
    field: &'static str,
) -> Result<Inline<S>, RecordDecodeError> {
    let mut values = facts
        .iter()
        .filter(|fact| fact.a() == &attribute.id())
        .map(|fact| *fact.v::<S>());
    let Some(value) = values.next() else {
        return Err(RecordDecodeError::MissingField(field));
    };
    if values.next().is_some() {
        return Err(RecordDecodeError::RepeatedField(field));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    use crate::blob::TryFromBlob;

    fn hash(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    /// An equation names its input PAYLOAD; this used to pair it with a
    /// fingerprint citing a record that produced it.
    fn input(byte: u8) -> CollectionData {
        hash(byte)
    }

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    fn fixture_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn malformed_archive_is_a_structural_error() {
        let malformed: Blob<SimpleArchive> = Blob::new(vec![0].into());
        assert_eq!(
            <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(malformed)
                .map_err(RecordDecodeError::from),
            Err(RecordDecodeError::Archive(UnarchiveError::BadArchive))
        );
    }

    #[test]
    fn empty_metadata_is_the_canonical_empty_archive() {
        let empty = encode_archive(TribleSet::new());
        assert_eq!(empty_metadata_handle(), empty.get_handle());
        assert!(empty.bytes.is_empty());
    }

    #[test]
    fn signed_commit_checks_foreign_bytes_and_retries_identically() {
        let key = fixture_key();
        let first = CollectionCommit::sign(&key, collection(1), hash(2), empty_metadata_handle());
        let retry = CollectionCommit::sign(&key, collection(1), hash(2), empty_metadata_handle());
        assert_eq!(first, retry);
        assert_eq!(first.to_bytes(), retry.to_bytes());
        assert_eq!(
            CollectionCommit::from_bytes(first.to_bytes()).unwrap(),
            first
        );
        first.verify_strict().unwrap();

        let mut bad_s = first.signature_s;
        bad_s.raw[0] ^= 1;
        let bad = CollectionCommit::from_parts(
            first.collection,
            first.data,
            first.metadata,
            first.public_key,
            first.signature_r,
            bad_s,
        );
        let decoded = CollectionCommit::from_bytes_trusted(bad.to_bytes());
        assert_eq!(
            decoded.verify_strict(),
            Err(RecordVerificationError::InvalidSignature)
        );
        assert_eq!(
            CollectionCommit::from_bytes(bad.to_bytes()),
            Err(RecordDecodeError::Verification(
                RecordVerificationError::InvalidSignature
            ))
        );

        let mut bad_r = first.signature_r;
        bad_r.raw[0] ^= 1;
        let bad = CollectionCommit::from_parts(
            first.collection,
            first.data,
            first.metadata,
            first.public_key,
            bad_r,
            first.signature_s,
        );
        assert_eq!(
            bad.verify_strict(),
            Err(RecordVerificationError::InvalidSignature)
        );

        let mut invalid_key = [0; 32];
        invalid_key[0] = 2;
        let invalid_key = CollectionCommit::from_parts(
            first.collection,
            first.data,
            first.metadata,
            Inline::new(invalid_key),
            first.signature_r,
            first.signature_s,
        );
        let decoded = CollectionCommit::from_bytes_trusted(invalid_key.to_bytes());
        assert_eq!(
            decoded.verify_strict(),
            Err(RecordVerificationError::InvalidPublicKey)
        );
        assert_eq!(
            CollectionCommit::from_bytes(invalid_key.to_bytes()),
            Err(RecordDecodeError::Verification(
                RecordVerificationError::InvalidPublicKey
            ))
        );
    }

    #[test]
    fn every_signed_field_is_bound_by_the_transcript() {
        let valid =
            CollectionCommit::sign(&fixture_key(), collection(1), hash(2), Inline::new([3; 32]));
        valid.verify_strict().unwrap();

        let mut alterations = Vec::new();
        alterations.push(CollectionCommit::from_parts(
            collection(9),
            valid.data,
            valid.metadata,
            valid.public_key,
            valid.signature_r,
            valid.signature_s,
        ));
        alterations.push(CollectionCommit::from_parts(
            valid.collection,
            hash(9),
            valid.metadata,
            valid.public_key,
            valid.signature_r,
            valid.signature_s,
        ));
        alterations.push(CollectionCommit::from_parts(
            valid.collection,
            valid.data,
            Inline::new([9; 32]),
            valid.public_key,
            valid.signature_r,
            valid.signature_s,
        ));
        let mut public_key = valid.public_key;
        public_key.raw[0] ^= 1;
        alterations.push(CollectionCommit::from_parts(
            valid.collection,
            valid.data,
            valid.metadata,
            public_key,
            valid.signature_r,
            valid.signature_s,
        ));

        assert!(alterations
            .iter()
            .all(|altered| altered.verify_strict().is_err()));
    }

    #[test]
    fn merge_is_commutative_in_dense_encoding() {
        let forward =
            CollectionMerge::sign(&fixture_key(), collection(1), input(2), input(3), hash(4));
        let reverse =
            CollectionMerge::sign(&fixture_key(), collection(1), input(3), input(2), hash(4));
        assert_eq!(forward, reverse);
        assert_eq!(forward.to_bytes(), reverse.to_bytes());
        assert_eq!(
            CollectionMerge::from_bytes(forward.to_bytes()).unwrap(),
            forward
        );
    }

    // Two tests lived here that existed only to pin witness behaviour --
    // that equal payloads sorted by their citation, and that changing a
    // citation changed record identity. A merge names no record now, so
    // neither statement is expressible, let alone true.

    #[test]
    fn derive_roundtrips() {
        let record = CollectionDerive::sign(&fixture_key(), collection(2), input(3), hash(4));
        assert_eq!(
            CollectionDerive::from_bytes(record.to_bytes()).unwrap(),
            record
        );
    }

    #[test]
    fn generic_codec_tags_each_variant() {
        let commit = CollectionCommit::sign(
            &fixture_key(),
            collection(1),
            hash(2),
            empty_metadata_handle(),
        );
        let merge =
            CollectionMerge::sign(&fixture_key(), collection(1), input(2), input(3), hash(4));
        let derive = CollectionDerive::sign(&fixture_key(), collection(2), input(3), hash(4));
        for record in [
            CollectionRecord::Commit(commit),
            CollectionRecord::Merge(merge),
            CollectionRecord::Derive(derive),
        ] {
            assert_eq!(
                CollectionRecord::from_bytes(&record.to_bytes()).unwrap(),
                record
            );
        }
        assert_eq!(
            CollectionRecord::from_bytes(&[99]),
            Err(RecordDecodeError::UnknownKind(99))
        );
    }

    #[test]
    fn native_records_enumerate_every_direct_blob_reference() {
        let metadata = Inline::<Handle<SimpleArchive>>::new([3; 32]);
        let commit = CollectionCommit::sign(&fixture_key(), collection(1), hash(2), metadata);
        let merge =
            CollectionMerge::sign(&fixture_key(), collection(4), input(5), input(6), hash(7));
        let derive = CollectionDerive::sign(&fixture_key(), collection(8), input(9), hash(10));

        assert_eq!(
            CollectionRecord::Commit(commit)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32], [3; 32]],
        );
        assert_eq!(
            CollectionRecord::Merge(merge)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[4; 32], [5; 32], [6; 32], [7; 32]],
        );
        assert_eq!(
            CollectionRecord::Derive(derive)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[8; 32], [9; 32], [10; 32]],
        );
    }

    #[test]
    fn endorsements_reference_actual_records_separately_from_blobs() {
        let _first = CollectionRecord::Commit(CollectionCommit::sign(
            &fixture_key(),
            collection(1),
            hash(2),
            empty_metadata_handle(),
        ));
        let _second = CollectionRecord::Commit(CollectionCommit::sign(
            &fixture_key(),
            collection(1),
            hash(3),
            empty_metadata_handle(),
        ));
        let merged = CollectionRecord::Merge(CollectionMerge::sign(
            &fixture_key(),
            collection(1),
            hash(2),
            hash(3),
            hash(4),
        ));
        let derived = CollectionRecord::Derive(CollectionDerive::sign(
            &fixture_key(),
            collection(5),
            hash(4),
            hash(6),
        ));
        // Record references were the citation graph. A record names payloads
        // now, and a reader relates it to its inputs by content.
        assert_eq!(merged.blob_references().len(), 4);
        assert_eq!(derived.blob_references().len(), 3);
    }

    #[test]
    fn generic_codec_rejects_wrong_lengths() {
        assert_eq!(
            CollectionRecord::from_bytes(&[COLLECTION_RECORD_KIND_COMMIT_V1]),
            Err(RecordDecodeError::InvalidLength {
                expected: COLLECTION_COMMIT_BYTES_LEN,
                actual: 0,
            })
        );
    }

    #[test]
    fn merge_decoder_rejects_noncanonical_input_order() {
        let record =
            CollectionMerge::sign(&fixture_key(), collection(1), input(2), input(3), hash(4));
        let mut bytes = record.to_bytes();
        bytes[32..64].fill(9);
        bytes[64..96].fill(1);
        assert_eq!(
            CollectionMerge::from_bytes(bytes),
            Err(RecordDecodeError::NonCanonicalMergeInputs)
        );
    }

    #[test]
    fn equations_bind_every_field_and_reject_weak_authors_at_ingress() {
        let records = [
            CollectionRecord::Merge(CollectionMerge::sign(
                &fixture_key(),
                collection(1),
                input(2),
                input(3),
                hash(4),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &fixture_key(),
                collection(2),
                input(3),
                hash(4),
            )),
        ];
        for record in records {
            let encoded = record.to_bytes();
            for field_start in (1..encoded.len()).step_by(32) {
                let mut altered = encoded.clone();
                altered[field_start] ^= 1;
                assert!(CollectionRecord::from_bytes(&altered).is_err());
                // Structural native/audit replay must retain the evidence.
                let retained = CollectionRecord::from_bytes_trusted(&altered).unwrap();
                assert!(retained.verify_strict().is_err());
            }
            let key_start = match record {
                CollectionRecord::Merge(_) => 1 + 4 * 32,
                CollectionRecord::Derive(_) => 1 + 3 * 32,
                CollectionRecord::Commit(_) => unreachable!(),
            };
            let mut weak = encoded;
            weak[key_start..key_start + 32].fill(0);
            weak[key_start] = 1; // Canonical Edwards identity: a weak principal.
            assert_eq!(
                CollectionRecord::from_bytes(&weak),
                Err(RecordDecodeError::Verification(
                    RecordVerificationError::InvalidPublicKey
                ))
            );
        }
    }

    #[test]
    fn distinct_writers_endorse_distinct_equation_records() {
        let first =
            CollectionMerge::sign(&fixture_key(), collection(1), input(2), input(3), hash(4));
        let second = CollectionMerge::sign(
            &SigningKey::from_bytes(&[8; 32]),
            collection(1),
            input(2),
            input(3),
            hash(4),
        );
        assert_ne!(first, second);
        assert_ne!(
            CollectionRecord::Merge(first).fingerprint(),
            CollectionRecord::Merge(second).fingerprint()
        );
        first.verify_strict().unwrap();
        second.verify_strict().unwrap();
    }

    #[test]
    fn retired_dense_equations_are_inert_exact_evidence() {
        let merge = tagged_bytes(
            COLLECTION_RECORD_KIND_MERGE_V1,
            &concat_fields::<4, 128>([collection(1).raw, hash(2).raw, hash(3).raw, hash(4).raw]),
        );
        let derive = tagged_bytes(
            COLLECTION_RECORD_KIND_DERIVE_V1,
            &concat_fields::<3, 96>([collection(2).raw, hash(3).raw, hash(4).raw]),
        );
        for (bytes, fingerprint, references) in [
            (
                merge,
                hex!("92A19C12DAF4046397A43C607051ECCB1DD1EFB74D8B977B8A19AE7846521170"),
                vec![[1; 32], [2; 32], [3; 32], [4; 32]],
            ),
            (
                derive,
                hex!("2CF7BBFA3A8567AECED029BC0A0A74925501AC0E60D51CC5AAA32E5225F54B4B"),
                vec![[2; 32], [3; 32], [4; 32]],
            ),
        ] {
            let legacy = LegacyUnsignedCollectionEquation::from_bytes(&bytes).unwrap();
            assert_eq!(legacy.fingerprint().raw(), fingerprint);
            assert_eq!(
                legacy
                    .blob_references()
                    .map(|handle| handle.raw)
                    .collect::<Vec<_>>(),
                references
            );
            assert_eq!(
                CollectionRecord::from_bytes(&bytes),
                Err(RecordDecodeError::UnknownKind(bytes[0]))
            );
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(LegacyUnsignedCollectionEquation::from_bytes(&trailing).is_err());
        }
        assert!(LegacyUnsignedCollectionEquation::from_bytes(
            &CollectionRecord::Merge(CollectionMerge::sign(
                &fixture_key(),
                collection(1),
                input(2),
                input(3),
                hash(4)
            ),)
            .to_bytes()
        )
        .is_err());
    }

    #[test]
    fn transcript_and_record_fingerprints_are_golden() {
        let collection_name_anchor = id_hex!("A2EEF06D4E1AA4B17B745AA2E8C37867");
        assert_eq!(
            collection_name.raw(),
            Attribute::<Handle<UTF8String>>::anchored(collection_name_anchor).raw(),
            "the UTF-8 name attribute is derived from the minted anchor and encoding"
        );
        assert_ne!(
            collection_name.id(),
            collection_name_anchor,
            "the anchored form must not pin the anchor as the attribute id"
        );
        let commit =
            CollectionCommit::sign(&fixture_key(), collection(1), hash(2), Inline::new([3; 32]));
        let merge =
            CollectionMerge::sign(&fixture_key(), collection(1), input(2), input(3), hash(4));
        let derive = CollectionDerive::sign(&fixture_key(), collection(2), input(3), hash(4));

        assert_eq!(commit.to_bytes().len(), COLLECTION_COMMIT_BYTES_LEN);
        assert_eq!(merge.to_bytes().len(), COLLECTION_MERGE_BYTES_LEN);
        assert_eq!(derive.to_bytes().len(), COLLECTION_DERIVE_BYTES_LEN);
        assert_eq!(merge.signing_transcript().len(), 215);
        assert_eq!(derive.signing_transcript().len(), 184);
        assert_eq!(
            concat_fields::<2, 64>([merge.signature().0.raw, merge.signature().1.raw]),
            hex!("39D1BE8DC91EE25298CD4B03D4CDD9D1D021994A0B5999EFCD86F1BB4D87EE08A64EE5C40BBBAA21F01C6963BCF2F259CD76D93CBBB4D4351879CB7167ADB00B")
        );
        assert_eq!(
            concat_fields::<2, 64>([derive.signature().0.raw, derive.signature().1.raw]),
            hex!("10325E15C286E263AFE7D7219F4F637F852F1EB61ECA68916DA4793C6BE9BAB5287380B741FF9D1AE6AD5FA36329785AAA36C6FAABFEB759A7E5387F1F2D140B")
        );

        assert_eq!(commit.signing_transcript().len(), COMMIT_TRANSCRIPT_LEN);
        assert_eq!(
            CollectionRecord::Commit(commit).fingerprint().raw(),
            hex!("B1740DE9C272B4552B97EDDF77C796D72688A2B9325D815C302236882657E608")
        );
        assert_eq!(
            commit.signature_r.raw,
            hex!("F89FCF5C72BC7EC3E376C6AB6BDEFC6ECEA3ADBBCA7A36DBF1729413A7820564")
        );
        assert_eq!(
            commit.signature_s.raw,
            hex!("F684108AF3E8E3898904D20EA458DCAE68F0F97F4E5C06DAFA0FAE0691F68D0B")
        );
        assert_eq!(
            CollectionRecord::Merge(merge).fingerprint().raw(),
            hex!("BF31C64514D9721278866D2AD87819D0C4282D5AC59A7AEBC37729D078038BDC")
        );
        assert_eq!(
            CollectionRecord::Derive(derive).fingerprint().raw(),
            hex!("2CEC0E4B0A78362E7EC93F5951B4FE6B1BB8233A1A6377C51ECF455A5B945672")
        );
        assert_eq!(
            commit.signing_transcript(),
            hex!(
                "747269626C6573706163652E636F6C6C656374696F6E2E636F6D6D69742E7472616E736372697074
                 B34817308188C4515A3C51967A91A603
                 00000002
                 EA4A6C63E29C520ABEF5507B132EC5F9954776AEBEBE7B92421EEA691446D22C
                 0101010101010101010101010101010101010101010101010101010101010101
                 0202020202020202020202020202020202020202020202020202020202020202
                 0303030303030303030303030303030303030303030303030303030303030303"
            )
            .to_vec()
        );
        commit.verify_strict().unwrap();
    }
}

#[cfg(test)]
mod mapping_algorithm_description_tests {
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::IntoBlob;
    use crate::collection::latest::LatestStatesMappingV1;
    use crate::collection::lww_register::RegisterCoordinatesMappingV1;
    use crate::collection::succinctarchive_union::{
        RawToRank9AcceleratedMappingV1, SimpleToSuccinctMappingV1,
    };
    use crate::inline::encodings::hash::Handle;
    use crate::inline::Inline;
    use crate::metadata::{self, MetaDescribe};

    /// Every mapping algorithm describes itself under its minted identity.
    /// Concrete, parameterized mapping entities embed these descriptions
    /// without conflating the algorithm with one particular mapping.
    #[test]
    fn every_mapping_algorithm_describes_itself_under_its_own_id() {
        fn check<L: MetaDescribe>(expected: crate::id::Id, name: &str) {
            let fragment = <L as MetaDescribe>::describe();
            assert_eq!(
                <L as MetaDescribe>::id(),
                expected,
                "{name} describes itself under a different id than it was minted with"
            );
            let facts = fragment.facts();
            let kind = crate::collection::records::one_id_for_test(&facts, &metadata::tag);
            assert_eq!(
                kind,
                metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
                "{name} is not tagged as a collection mapping algorithm"
            );
            let actual_name = super::one_inline(facts, &metadata::name, "name")
                .expect("mapping algorithm has one name");
            let expected_name: Inline<Handle<UTF8String>> = name.to_owned().to_blob().get_handle();
            assert_eq!(
                actual_name, expected_name,
                "mapping algorithm description retained a stale name"
            );
        }
        check::<SimpleToSuccinctMappingV1>(
            crate::collection::succinctarchive_union::SIMPLE_TO_SUCCINCT_MAPPING_V1,
            "simple-to-succinct-v1",
        );
        check::<LatestStatesMappingV1>(
            crate::collection::latest::LATEST_STATES_MAPPING_V1,
            "latest-states-mapping-v1",
        );
        check::<RegisterCoordinatesMappingV1>(
            crate::collection::lww_register::REGISTER_COORDINATES_MAPPING_V1,
            "register-coordinates-v1",
        );
        check::<RawToRank9AcceleratedMappingV1>(
            crate::collection::succinctarchive_union::current_rank9_accelerated_mapping_algorithm(),
            "raw-to-rank9-accelerated-succinctarchive-v1",
        );
    }
}
