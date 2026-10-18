//! Dense typed records for the top-level collection calculus.
//!
//! [`CollectionCommit`], [`CollectionMerge`], [`CollectionDerive`] and
//! [`CollectionMap`] are native algebra records, not graph data. Their
//! canonical representations are the 32-byte-aligned dense byte layouts
//! exposed by their `to_bytes`/`from_bytes` methods. MERGE has exactly eight
//! inputs. COMMIT and DERIVE add foundations and replicate; MERGE and
//! MAP are a host's own choices over what it holds and stay local. A
//! collection *descriptor* is not a record at all: it is an ordinary
//! [`TribleSet`] stored as a self-describing [`SimpleArchive`], and
//! that blob's handle is the collection identity. See
//! [`descriptor`](crate::collection::descriptor) for reading one.
//!
//! Public byte decoding verifies the embedded signature before admitting
//! foreign evidence. Trusted native replay uses crate-private structural
//! decoding instead: local persisted records are not cryptographically checked
//! again on every read. Signatures prove authorship; WRITE authorization is a
//! separate observation-time policy.
//!
//! Every assertion is kind32 | fields | signature over the literal preceding
//! bytes. Storage, typed views and wire share those bytes. Carrier recovery
//! metadata and padding are not part of the assertion. Historical formats
//! require an explicit offline migration; native retention is not admission.

use std::error::Error;
use std::fmt;

mod body_view;
pub use body_view::CollectionRecordView;
mod encoded;
pub use encoded::{EncodedCommit, EncodedDerive, EncodedMap, EncodedMerge};

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
/// Canonical COMMIT kind: the handle of its exact grammar description.
/// Anchor minted with `trible genid` on 2026-10-17: FDB671F61026890184000D275E0AB0F7.
pub const KIND_COLLECTION_COMMIT: [u8; 32] =
    hex_literal::hex!("630454328DD62B0254179781E3413DC58397255ACC22152778ABFC9679211A3D");
/// Canonical MERGE kind: the handle of its exact grammar description.
/// Anchor minted with `trible genid` on 2026-10-17: 75B76CA9E028127AC06C550A156B469D.
pub const KIND_COLLECTION_MERGE: [u8; 32] =
    hex_literal::hex!("9F13367C022BD21D2EE7554A2635EF4F8F431E1D96362729EC0369EE1E647ADC");
/// Canonical DERIVE kind: the handle of its exact grammar description.
/// Anchor minted with `trible genid` on 2026-10-17: 5D09D99A2B549A60BEA9942E7E5752FD.
pub const KIND_COLLECTION_DERIVE: [u8; 32] =
    hex_literal::hex!("B71A1803BA4905C1ACBD3E8C8A544EA0A918233409A66EA42E2FA245AC6B77DC");
/// Canonical MAP kind: the handle of its exact grammar description.
/// Anchor minted with `trible genid` on 2026-10-17: 3D52F26EC0A2852BF2ED998A3A8A56F5.
pub const KIND_COLLECTION_MAP: [u8; 32] =
    hex_literal::hex!("4C8850C0D6E70FB67AA6DB87122824E068D8F1526F663870463ABD5290DFF3D9");
/// RETIRED tombstone: the witness-bound MERGE (pile kind v6, dense tag 6).
///
/// Minted with `trible genid` on 2026-09-14 and retired without ever being
/// the live merge kind. Nothing signs or fingerprints under it; it is kept so
/// the id is never minted twice. Formerly named `KIND_COLLECTION_MERGE`.
pub const KIND_COLLECTION_MERGE_WITNESSED_RETIRED: Id = id_hex!("96AB9DE7389DD621D44C55E593898A69");
/// RETIRED tombstone: the witness-bound DERIVE (pile kind v7, dense tag 7).
///
/// Minted with `trible genid` on 2026-09-14; see
/// [`KIND_COLLECTION_MERGE_WITNESSED_RETIRED`]. Formerly named
/// `KIND_COLLECTION_DERIVE`.
pub const KIND_COLLECTION_DERIVE_WITNESSED_RETIRED: Id =
    id_hex!("529D8F57A20FCA0BC921121313DC619B");
/// RETIRED: semantic kind of the signed binary MERGE.
///
/// Minted with `trible genid` on 2026-09-13 for the first witness-free
/// signed merge, then signed and fingerprinted under again by pile kind v8
/// and dense tag 4 until lattice v2 (2026-09-25), under the misleading name
/// `KIND_COLLECTION_MERGE_SIGNED_V2`. Only
/// [`RetiredCollectionEquation`] still reads it, to verify and fingerprint
/// the retired records exactly as they were written.
pub const KIND_COLLECTION_MERGE_BINARY_RETIRED: Id = id_hex!("1E5277B23D177FD692B074FBF0EF28F1");
/// RETIRED: semantic kind of the signed handle DERIVE.
///
/// Minted with `trible genid` on 2026-09-13 for the first witness-free
/// signed derive, then used again by pile kind v9 and dense tag 5 until
/// lattice v2 (2026-09-25), under the misleading name
/// `KIND_COLLECTION_DERIVE_SIGNED_V2`. See
/// [`KIND_COLLECTION_MERGE_BINARY_RETIRED`].
pub const KIND_COLLECTION_DERIVE_HANDLE_RETIRED: Id = id_hex!("CE6A838612D0AA0812C05A50CCD11DC1");
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

/// Complete canonical fixed-record sizes, including kind and signature.
pub const COLLECTION_COMMIT_BYTES_LEN: usize = 7 * 32;
pub const COLLECTION_DERIVE_BYTES_LEN: usize = 7 * 32;
pub const COLLECTION_MAP_BYTES_LEN: usize = 7 * 32;
/// Every MERGE has exactly eight distinct, ordered payload inputs.
pub const MERGE_INPUTS: usize = 8;
/// Complete canonical MERGE size, including kind and signature.
pub const COLLECTION_MERGE_BYTES_LEN: usize = 14 * 32;
/// Byte length of a dense retired binary MERGE (dense tag 4): collection,
/// low, high, result, author, R, S.
pub const RETIRED_MERGE_BINARY_BYTES_LEN: usize = 7 * 32;
/// Byte length of a dense retired handle DERIVE (dense tag 5): target, input,
/// output, author, R, S.
pub const RETIRED_DERIVE_HANDLE_BYTES_LEN: usize = 6 * 32;

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
    /// The collection whose lattice nodes an attached collection indexes, by
    /// descriptor handle.
    ///
    /// An attached collection carries this and its mapping and nothing else:
    /// no policy and no source. Its records are MAPs, one per indexed node
    /// of the parent, believed only on the host's own key. It is kept apart
    /// from [`collection_source`] because a source makes a collection
    /// derived, with foundations and a lattice of its own; a parent does not.
    ///
    /// Anchor minted with `trible genid` on 2026-09-28:
    /// `9B20AA2BE739DB1B4911186620368262`.
    "9B20AA2BE739DB1B4911186620368262" as pub collection_parent: Handle<SimpleArchive>;
    /// An attached collection of the same parent whose attachment of a node
    /// a mapping reads instead of the node itself, by descriptor handle.
    ///
    /// A parameter of one concrete mapping instance, carried on the mapping
    /// entity. It names the sibling explicitly, so nothing recomputes a
    /// sibling's handle from its parent and mapping.
    ///
    /// Anchor minted with `trible genid` on 2026-09-28:
    /// `7A852B1D4097983EA823D04C8CD1A53A`.
    "7A852B1D4097983EA823D04C8CD1A53A" as pub mapping_reads_attached: Handle<SimpleArchive>;
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

/// RETIRED signature domain of the witness-bound MERGE. Reserved: never reuse.
pub const MERGE_WITNESSED_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.merge.endorsement";
/// RETIRED signature domain of the witness-bound DERIVE. Reserved: never reuse.
pub const DERIVE_WITNESSED_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.derive.endorsement";
/// RETIRED signature domain of the binary MERGE (dense tag 4, pile kind v8).
/// [`RetiredCollectionEquation`] still verifies under it.
pub const MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.merge.transcript";
/// RETIRED signature domain of the handle DERIVE (dense tag 5, pile kind v9).
/// [`RetiredCollectionEquation`] still verifies under it.
pub const DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.derive.transcript";
/// RETIRED, never used by a written record. Reserved: never reuse.
pub const MERGE_EQUATION_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.merge.equation";
/// RETIRED, never used by a written record. Reserved: never reuse.
pub const DERIVE_EQUATION_TRANSCRIPT_DOMAIN_RETIRED: &[u8] =
    b"triblespace.collection.derive.equation";

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
    /// A record did not have the exact length required by its grammar.
    InvalidLength { expected: usize, actual: usize },
    /// A tagged dense record used an unknown variant byte.
    UnknownKind(u8),
    /// The complete canonical kind is unknown or does not match the typed decoder.
    InvalidKind([u8; 32]),
    /// A merge's inputs were not strictly increasing by raw bytes.
    NonCanonicalMergeInputs,
    /// A merge named fewer than [`MERGE_INPUTS`] or more than
    /// [`MERGE_INPUTS`] inputs.
    InvalidMergeArity(u32),
    /// Bytes a canonical record leaves zero were not zero.
    NonCanonicalPadding,
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
            Self::InvalidKind(kind) => write!(
                f,
                "collection record has unexpected canonical kind {kind:02X?}"
            ),
            Self::NonCanonicalMergeInputs => {
                write!(f, "collection merge inputs are not strictly increasing")
            }
            Self::InvalidMergeArity(count) => write!(
                f,
                "collection merge names {count} inputs; expected exactly {MERGE_INPUTS}"
            ),
            Self::NonCanonicalPadding => {
                write!(f, "collection record has nonzero padding")
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

/// A MERGE was asked to join fewer than [`MERGE_INPUTS`] or more than
/// [`MERGE_INPUTS`] distinct inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergeArityError {
    /// Number of distinct inputs after sorting and removing duplicates.
    pub distinct_inputs: usize,
}

impl fmt::Display for MergeArityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a MERGE joins exactly {MERGE_INPUTS} distinct inputs; got {}",
            self.distinct_inputs
        )
    }
}

impl Error for MergeArityError {}

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
        let mut record = Self::from_parts(
            collection,
            data_hash,
            metadata,
            public_key,
            Inline::new([0; 32]),
            Inline::new([0; 32]),
        );
        let signature: Signature = signing_key.sign(&record.signing_transcript());
        record.signature_r = Inline::new(*signature.r_bytes());
        record.signature_s = Inline::new(*signature.s_bytes());
        record
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
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(
        bytes: [u8; COLLECTION_COMMIT_BYTES_LEN],
    ) -> Result<Self, RecordDecodeError> {
        require_kind(&bytes, KIND_COLLECTION_COMMIT)?;
        Ok(Self::from_parts(
            Inline::new(field(&bytes, 1)),
            Inline::new(field(&bytes, 2)),
            Inline::new(field(&bytes, 3)),
            Inline::new(field(&bytes, 4)),
            Inline::new(field(&bytes, 5)),
            Inline::new(field(&bytes, 6)),
        ))
    }

    /// Strictly verify the Ed25519 signature over the canonical transcript.
    ///
    /// This proves only that the embedded public key signed the record. Key
    /// authorization is a separate caller policy.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        verify_record_signature(
            self.public_key,
            self.signature(),
            &self.signing_transcript(),
        )
    }

    /// Exact bytes attested by this commit's signature.
    pub fn signing_transcript(&self) -> Vec<u8> {
        self.to_bytes()[..COLLECTION_COMMIT_BYTES_LEN - 64].to_vec()
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

    /// Encode this record into its exact canonical 224-byte layout.
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

/// The distinct inputs of one MERGE, strictly increasing by raw bytes.
///
/// A fixed array of exactly eight actual inputs; there are no unused slots.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MergeInputs {
    inputs: [CollectionData; MERGE_INPUTS],
}

impl MergeInputs {
    /// Sort and deduplicate `inputs`; fewer than [`MERGE_INPUTS`] or more
    /// than [`MERGE_INPUTS`] distinct inputs is refused.
    pub fn new(inputs: impl IntoIterator<Item = CollectionData>) -> Result<Self, MergeArityError> {
        let mut distinct: Vec<CollectionData> = inputs.into_iter().collect();
        distinct.sort_unstable_by(|left, right| left.raw.cmp(&right.raw));
        distinct.dedup_by(|left, right| left.raw == right.raw);
        Self::from_sorted(&distinct).map_err(|_| MergeArityError {
            distinct_inputs: distinct.len(),
        })
    }

    /// Accept exactly eight inputs that are already canonical: strictly
    /// increasing. This is the decoder's check; it never reorders.
    pub(crate) fn from_canonical(inputs: &[CollectionData]) -> Result<Self, RecordDecodeError> {
        if inputs.len() != MERGE_INPUTS {
            return Err(RecordDecodeError::InvalidMergeArity(inputs.len() as u32));
        }
        if inputs.windows(2).any(|pair| pair[0].raw >= pair[1].raw) {
            return Err(RecordDecodeError::NonCanonicalMergeInputs);
        }
        Self::from_sorted(inputs)
    }

    fn from_sorted(inputs: &[CollectionData]) -> Result<Self, RecordDecodeError> {
        if inputs.len() != MERGE_INPUTS {
            return Err(RecordDecodeError::InvalidMergeArity(inputs.len() as u32));
        }
        Ok(Self {
            inputs: inputs.try_into().expect("checked exact eight inputs"),
        })
    }

    /// The inputs, strictly increasing.
    pub fn as_slice(&self) -> &[CollectionData] {
        &self.inputs
    }

    /// Number of distinct inputs, always eight.
    pub fn len(&self) -> usize {
        MERGE_INPUTS
    }

    /// Never true for a valid merge; present for API symmetry.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Iterate the inputs in ascending order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = CollectionData> + '_ {
        self.as_slice().iter().copied()
    }

    /// Whether `node` is one of the inputs.
    pub fn contains(&self, node: CollectionData) -> bool {
        self.as_slice()
            .binary_search_by(|input| input.raw.cmp(&node.raw))
            .is_ok()
    }
}

/// The locator of one source foundation: `L(H) = BLAKE3(LOCATOR_CONTEXT || H)`.
///
/// This is what a [`CollectionDerive`] names instead of the source payload's
/// handle. It is a one-way image of the handle, so it names the source
/// foundation without being able to fetch it: never confuse it with a handle,
/// and never treat it as a blob reference. See
/// [`blob_locator`](crate::blob::locator::blob_locator).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceLocator([u8; 32]);

impl SourceLocator {
    /// The locator of the source payload whose handle is `handle_raw`.
    pub fn of(handle_raw: [u8; 32]) -> Self {
        Self(crate::blob::locator::blob_locator(handle_raw))
    }

    /// Reinterpret raw locator bytes read from a record or an index. This
    /// does not hash: the bytes must already be a locator.
    ///
    /// Crate-private on purpose. Outside the decoders a locator is only ever
    /// built from a handle with [`Self::of`]; wrapping a raw handle here would
    /// publish a leaf no freshness query can find.
    pub(crate) const fn from_raw(raw: [u8; 32]) -> Self {
        Self(raw)
    }

    /// The raw locator bytes.
    pub const fn raw(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the raw locator bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SourceLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Signed exact-eight join: these distinct payloads of one collection join to this
/// result.
///
/// The statement is about PAYLOADS. Which records produce the inputs is not
/// part of it; a reader finds those by content. The result may equal one of
/// the eight inputs; there is no binary absorption record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionMerge {
    collection: CollectionHandle,
    result: CollectionData,
    inputs: MergeInputs,
    public_key: Inline<ED25519PublicKey>,
    signature_r: Inline<ED25519RComponent>,
    signature_s: Inline<ED25519SComponent>,
}

impl CollectionMerge {
    /// Canonical persisted record identity.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        CollectionRecord::Merge(*self).fingerprint()
    }

    /// Sign a join of `inputs` to `result` in `collection`.
    ///
    /// The inputs are sorted by raw bytes and deduplicated before signing, so
    /// the same join signs identically however it is listed. Exactly
    /// [`MERGE_INPUTS`] distinct inputs are required.
    pub fn sign(
        signing_key: &SigningKey,
        collection: CollectionHandle,
        inputs: impl IntoIterator<Item = CollectionData>,
        result: CollectionData,
    ) -> Result<Self, MergeArityError> {
        let inputs = MergeInputs::new(inputs)?;
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let mut record = Self::from_parts(
            collection,
            result,
            inputs,
            public_key,
            Inline::new([0; 32]),
            Inline::new([0; 32]),
        );
        let signature: Signature = signing_key.sign(&record.signing_transcript());
        record.signature_r = Inline::new(*signature.r_bytes());
        record.signature_s = Inline::new(*signature.s_bytes());
        Ok(record)
    }

    pub(crate) fn from_parts(
        collection: CollectionHandle,
        result: CollectionData,
        inputs: MergeInputs,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            collection,
            result,
            inputs,
            public_key,
            signature_r,
            signature_s,
        }
    }

    /// Decode foreign dense bytes, requiring canonical form and a strict
    /// signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    ///
    /// Requires the exact kind, 448-byte length and eight strictly ordered inputs.
    pub(crate) fn from_bytes_trusted(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        if bytes.len() != COLLECTION_MERGE_BYTES_LEN {
            return Err(RecordDecodeError::InvalidLength {
                expected: COLLECTION_MERGE_BYTES_LEN,
                actual: bytes.len(),
            });
        }
        require_kind(bytes, KIND_COLLECTION_MERGE)?;
        let inputs: [CollectionData; MERGE_INPUTS] =
            std::array::from_fn(|index| Inline::new(slice_field(bytes, 4 + index)));
        let inputs = MergeInputs::from_canonical(&inputs)?;
        Ok(Self::from_parts(
            Inline::new(slice_field(bytes, 1)),
            Inline::new(slice_field(bytes, 2)),
            inputs,
            Inline::new(slice_field(bytes, 3)),
            Inline::new(slice_field(bytes, 12)),
            Inline::new(slice_field(bytes, 13)),
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

    /// Exact literal canonical prefix signed by the author.
    pub fn signing_transcript(&self) -> Vec<u8> {
        self.to_bytes()[..COLLECTION_MERGE_BYTES_LEN - 64].to_vec()
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

    /// The distinct inputs, strictly increasing by raw bytes.
    pub fn inputs(&self) -> &[CollectionData] {
        self.inputs.as_slice()
    }

    /// The inputs as the fixed-capacity value the record holds.
    pub fn merge_inputs(&self) -> MergeInputs {
        self.inputs
    }

    /// Asserted exact join result.
    pub fn result(&self) -> CollectionData {
        self.result
    }

    /// Blob handles named directly by this record: the collection descriptor,
    /// the result, then every input. Residency of each handle is independent.
    ///
    /// The descriptor is owned like a COMMIT owns its descriptor. A derived
    /// collection holds only MERGEs and DERIVEs, so if these did not name it,
    /// nothing would keep a derived collection's descriptor through
    /// record-rooted garbage collection, and without it none of the
    /// collection's records can be decided.
    pub fn blob_references(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, { MERGE_INPUTS + 2 }>::new();
        references.push(self.collection.transmute());
        references.push(Handle::<UnknownBlob>::from_hash(self.result));
        references.extend(self.inputs.iter().map(Handle::<UnknownBlob>::from_hash));
        references.into_iter()
    }

    /// Exact canonical byte length, including kind and signature.
    pub fn dense_len(&self) -> usize {
        COLLECTION_MERGE_BYTES_LEN
    }

    /// Encode kind, collection, result, author, eight inputs, then signature.
    pub fn to_bytes(&self) -> [u8; COLLECTION_MERGE_BYTES_LEN] {
        let mut fields = [[0; 32]; 14];
        fields[0] = KIND_COLLECTION_MERGE;
        fields[1] = self.collection.raw;
        fields[2] = self.result.raw;
        fields[3] = self.public_key.raw;
        for (slot, input) in fields[4..12].iter_mut().zip(self.inputs.iter()) {
            *slot = input.raw;
        }
        fields[12] = self.signature_r.raw;
        fields[13] = self.signature_s.raw;
        concat_fields(fields)
    }
}

/// Signed leaf of a derived collection: the target's mapping takes the
/// source foundation whose locator is `input` to `output`.
///
/// The record names the source foundation by its [`SourceLocator`], never by
/// its handle: a DERIVE is a foundation of the TARGET collection, and the
/// locator is the only link between a derived collection and its source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionDerive {
    target: CollectionHandle,
    input: SourceLocator,
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

    /// Sign `DERIVE(target, input -> output)`.
    ///
    /// The target is named by descriptor handle, and that descriptor already
    /// names the source and the mapping, so the record only says which source
    /// foundation (by locator) maps to which output.
    pub fn sign(
        signing_key: &SigningKey,
        target: CollectionHandle,
        input: SourceLocator,
        output: CollectionData,
    ) -> Self {
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let mut record = Self::from_parts(
            target,
            input,
            output,
            public_key,
            Inline::new([0; 32]),
            Inline::new([0; 32]),
        );
        let signature: Signature = signing_key.sign(&record.signing_transcript());
        record.signature_r = Inline::new(*signature.r_bytes());
        record.signature_s = Inline::new(*signature.s_bytes());
        record
    }

    pub(crate) fn from_parts(
        target: CollectionHandle,
        input: SourceLocator,
        output: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            target,
            input,
            output,
            public_key,
            signature_r,
            signature_s,
        }
    }

    /// Decode foreign dense bytes and strictly verify their signature.
    pub fn from_bytes(bytes: [u8; COLLECTION_DERIVE_BYTES_LEN]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(
        bytes: [u8; COLLECTION_DERIVE_BYTES_LEN],
    ) -> Result<Self, RecordDecodeError> {
        require_kind(&bytes, KIND_COLLECTION_DERIVE)?;
        Ok(Self::from_parts(
            Inline::new(field(&bytes, 1)),
            SourceLocator::from_raw(field(&bytes, 3)),
            Inline::new(field(&bytes, 2)),
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

    /// Exact literal canonical prefix signed by the author.
    pub fn signing_transcript(&self) -> Vec<u8> {
        self.to_bytes()[..COLLECTION_DERIVE_BYTES_LEN - 64].to_vec()
    }

    /// Author's public key.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        self.public_key
    }

    /// Exact signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        (self.signature_r, self.signature_s)
    }

    /// The target collection, which holds the output.
    pub fn collection(&self) -> CollectionHandle {
        self.target
    }

    /// The target collection, which holds the output. Same as
    /// [`Self::collection`].
    pub fn target(&self) -> CollectionHandle {
        self.target
    }

    /// Locator of the source foundation this leaf maps. Not a blob handle.
    pub fn input(&self) -> SourceLocator {
        self.input
    }

    /// Target member produced by this equation.
    pub fn output(&self) -> CollectionData {
        self.output
    }

    /// Blob handles named directly by this record: the target descriptor and
    /// the output. Never the locator, which is not fetchable.
    ///
    /// The target descriptor is owned for the reason a MERGE owns its
    /// collection's: a derived collection holds no COMMIT to keep it.
    pub fn blob_references(&self) -> [Inline<Handle<UnknownBlob>>; 2] {
        [
            self.target.transmute(),
            Handle::<UnknownBlob>::from_hash(self.output),
        ]
    }

    /// Encode into the exact canonical 224-byte layout: `kind | target | output |
    /// locator | author | R | S`.
    pub fn to_bytes(&self) -> [u8; COLLECTION_DERIVE_BYTES_LEN] {
        concat_fields([
            KIND_COLLECTION_DERIVE,
            self.target.raw,
            self.output.raw,
            self.input.raw(),
            self.public_key.raw,
            self.signature_r.raw,
            self.signature_s.raw,
        ])
    }
}

/// Signed attachment: the attached collection's mapping takes this node of
/// its parent collection's lattice to `attachment`.
///
/// A MAP is a host's own index of one of its own nodes. It adds no
/// foundation and means nothing to another store: a reader believes it only
/// when the store's host signed it, and only for a node the reader reaches in the
/// parent's lattice. The node is named by its handle directly: an attached
/// collection indexes nodes, not source foundations, so there is no locator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionMap {
    attached: CollectionHandle,
    node: CollectionData,
    attachment: CollectionData,
    public_key: Inline<ED25519PublicKey>,
    signature_r: Inline<ED25519RComponent>,
    signature_s: Inline<ED25519SComponent>,
}

impl CollectionMap {
    /// Canonical persisted record identity.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        CollectionRecord::Map(*self).fingerprint()
    }

    /// Sign `MAP(attached; node -> attachment)`.
    ///
    /// The attached collection's descriptor names its parent and its
    /// mapping, so the record only says which parent node maps to which
    /// attachment.
    pub fn sign(
        signing_key: &SigningKey,
        attached: CollectionHandle,
        node: CollectionData,
        attachment: CollectionData,
    ) -> Self {
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let mut record = Self::from_parts(
            attached,
            node,
            attachment,
            public_key,
            Inline::new([0; 32]),
            Inline::new([0; 32]),
        );
        let signature: Signature = signing_key.sign(&record.signing_transcript());
        record.signature_r = Inline::new(*signature.r_bytes());
        record.signature_s = Inline::new(*signature.s_bytes());
        record
    }

    pub(crate) fn from_parts(
        attached: CollectionHandle,
        node: CollectionData,
        attachment: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Self {
        Self {
            attached,
            node,
            attachment,
            public_key,
            signature_r,
            signature_s,
        }
    }

    /// Decode foreign dense bytes and strictly verify their signature.
    pub fn from_bytes(bytes: [u8; COLLECTION_MAP_BYTES_LEN]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for explicitly trusted persisted bytes and audits.
    pub(crate) fn from_bytes_trusted(
        bytes: [u8; COLLECTION_MAP_BYTES_LEN],
    ) -> Result<Self, RecordDecodeError> {
        require_kind(&bytes, KIND_COLLECTION_MAP)?;
        Ok(Self::from_parts(
            Inline::new(field(&bytes, 1)),
            Inline::new(field(&bytes, 3)),
            Inline::new(field(&bytes, 2)),
            Inline::new(field(&bytes, 4)),
            Inline::new(field(&bytes, 5)),
            Inline::new(field(&bytes, 6)),
        ))
    }

    /// Prove authorship only. Belief is the store's host key, not WRITE.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        verify_record_signature(
            self.public_key,
            self.signature(),
            &self.signing_transcript(),
        )
    }

    /// Exact literal canonical prefix signed by the author.
    pub fn signing_transcript(&self) -> Vec<u8> {
        self.to_bytes()[..COLLECTION_MAP_BYTES_LEN - 64].to_vec()
    }

    /// Author's public key.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        self.public_key
    }

    /// Exact signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        (self.signature_r, self.signature_s)
    }

    /// The attached collection, which holds the attachment.
    pub fn collection(&self) -> CollectionHandle {
        self.attached
    }

    /// The attached collection. Same as [`Self::collection`].
    pub fn attached(&self) -> CollectionHandle {
        self.attached
    }

    /// The node of the parent collection's lattice this attachment indexes.
    pub fn node(&self) -> CollectionData {
        self.node
    }

    /// The attachment the mapping gives the node.
    pub fn attachment(&self) -> CollectionData {
        self.attachment
    }

    /// Blob handles named directly by this record: the attached descriptor
    /// and the attachment. Never the node: a MAP must not keep a consumed
    /// interior node of the parent resident, and the parent's own records
    /// name its nodes.
    pub fn blob_references(&self) -> [Inline<Handle<UnknownBlob>>; 2] {
        [
            self.attached.transmute(),
            Handle::<UnknownBlob>::from_hash(self.attachment),
        ]
    }

    /// Encode into the exact canonical 224-byte layout: `kind | attached | attachment |
    /// node | author | R | S`.
    pub fn to_bytes(&self) -> [u8; COLLECTION_MAP_BYTES_LEN] {
        concat_fields([
            KIND_COLLECTION_MAP,
            self.attached.raw,
            self.attachment.raw,
            self.node.raw,
            self.public_key.raw,
            self.signature_r.raw,
            self.signature_s.raw,
        ])
    }
}

/// A signed equation under one of the two kinds lattice v2 retired.
///
/// Until 2026-09-25 these were the live MERGE and DERIVE: the binary MERGE
/// (pile kind v8, dense tag 4) and the handle DERIVE (pile kind v9, dense tag
/// 5). They decode into this separate inert type with every field kept, so
/// the clean-pile migration can read them and rewrites can carry them byte
/// for byte, but they are never folded, never served as current records, and
/// never counted as opaque.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RetiredCollectionEquation {
    /// `MERGE(collection, low, high) -> result`, `low <= high`.
    MergeV8 {
        collection: CollectionHandle,
        low: CollectionData,
        high: CollectionData,
        result: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    },
    /// `DERIVE(target, input handle) -> output`.
    DeriveV9 {
        target: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    },
}

impl RetiredCollectionEquation {
    /// Structurally decode the retired self-tagged dense form (tag 4 or 5).
    /// Nothing is verified: this is evidence for an explicit migration.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let Some((&kind, payload)) = bytes.split_first() else {
            return Err(RecordDecodeError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match kind {
            COLLECTION_RECORD_KIND_MERGE_V2 => {
                let bytes = exact_array::<RETIRED_MERGE_BINARY_BYTES_LEN>(payload)?;
                let low = Inline::new(field(&bytes, 1));
                let high = Inline::new(field(&bytes, 2));
                Self::merge_v8(
                    Inline::new(field(&bytes, 0)),
                    low,
                    high,
                    Inline::new(field(&bytes, 3)),
                    Inline::new(field(&bytes, 4)),
                    Inline::new(field(&bytes, 5)),
                    Inline::new(field(&bytes, 6)),
                )
            }
            COLLECTION_RECORD_KIND_DERIVE_V2 => {
                let bytes = exact_array::<RETIRED_DERIVE_HANDLE_BYTES_LEN>(payload)?;
                Ok(Self::DeriveV9 {
                    target: Inline::new(field(&bytes, 0)),
                    input: Inline::new(field(&bytes, 1)),
                    output: Inline::new(field(&bytes, 2)),
                    public_key: Inline::new(field(&bytes, 3)),
                    signature_r: Inline::new(field(&bytes, 4)),
                    signature_s: Inline::new(field(&bytes, 5)),
                })
            }
            unknown => Err(RecordDecodeError::UnknownKind(unknown)),
        }
    }

    /// A retired binary merge from its fields, refusing `high < low` exactly
    /// as the retired decoders did.
    pub(crate) fn merge_v8(
        collection: CollectionHandle,
        low: CollectionData,
        high: CollectionData,
        result: CollectionData,
        public_key: Inline<ED25519PublicKey>,
        signature_r: Inline<ED25519RComponent>,
        signature_s: Inline<ED25519SComponent>,
    ) -> Result<Self, RecordDecodeError> {
        if high.raw < low.raw {
            return Err(RecordDecodeError::NonCanonicalMergeInputs);
        }
        Ok(Self::MergeV8 {
            collection,
            low,
            high,
            result,
            public_key,
            signature_r,
            signature_s,
        })
    }

    /// Sign a retired binary merge. Test fixtures only: nothing writes this
    /// kind any more.
    #[cfg(test)]
    pub(crate) fn sign_merge_v8(
        signing_key: &SigningKey,
        collection: CollectionHandle,
        mut low: CollectionData,
        mut high: CollectionData,
        result: CollectionData,
    ) -> Self {
        if high.raw < low.raw {
            std::mem::swap(&mut low, &mut high);
        }
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let transcript = equation_transcript(
            MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
            KIND_COLLECTION_MERGE_BINARY_RETIRED,
            public_key,
            [collection.raw, low.raw, high.raw, result.raw],
        );
        let signature: Signature = signing_key.sign(&transcript);
        Self::MergeV8 {
            collection,
            low,
            high,
            result,
            public_key,
            signature_r: Inline::new(*signature.r_bytes()),
            signature_s: Inline::new(*signature.s_bytes()),
        }
    }

    /// Sign a retired handle derive. Test fixtures only.
    #[cfg(test)]
    pub(crate) fn sign_derive_v9(
        signing_key: &SigningKey,
        target: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
    ) -> Self {
        let public_key = Inline::new(signing_key.verifying_key().to_bytes());
        let transcript = equation_transcript(
            DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED,
            KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
            public_key,
            [target.raw, input.raw, output.raw],
        );
        let signature: Signature = signing_key.sign(&transcript);
        Self::DeriveV9 {
            target,
            input,
            output,
            public_key,
            signature_r: Inline::new(*signature.r_bytes()),
            signature_s: Inline::new(*signature.s_bytes()),
        }
    }

    /// The collection the equation names (the target for a DERIVE).
    pub fn collection(&self) -> CollectionHandle {
        match self {
            Self::MergeV8 { collection, .. } => *collection,
            Self::DeriveV9 { target, .. } => *target,
        }
    }

    /// The member the equation produced: the merge result or derive output.
    pub fn produced(&self) -> CollectionData {
        match self {
            Self::MergeV8 { result, .. } => *result,
            Self::DeriveV9 { output, .. } => *output,
        }
    }

    /// The author's public key.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        match self {
            Self::MergeV8 { public_key, .. } | Self::DeriveV9 { public_key, .. } => *public_key,
        }
    }

    /// The exact signature components.
    pub fn signature(&self) -> (Inline<ED25519RComponent>, Inline<ED25519SComponent>) {
        match self {
            Self::MergeV8 {
                signature_r,
                signature_s,
                ..
            }
            | Self::DeriveV9 {
                signature_r,
                signature_s,
                ..
            } => (*signature_r, *signature_s),
        }
    }

    /// The exact bytes the author signed, under the retired domain and kind.
    pub fn signing_transcript(&self) -> Vec<u8> {
        match *self {
            Self::MergeV8 {
                collection,
                low,
                high,
                result,
                public_key,
                ..
            } => equation_transcript(
                MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
                KIND_COLLECTION_MERGE_BINARY_RETIRED,
                public_key,
                [collection.raw, low.raw, high.raw, result.raw],
            ),
            Self::DeriveV9 {
                target,
                input,
                output,
                public_key,
                ..
            } => equation_transcript(
                DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED,
                KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
                public_key,
                [target.raw, input.raw, output.raw],
            ),
        }
    }

    /// Strictly verify the retired signature. Authorship only.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        verify_record_signature(
            self.public_key(),
            self.signature(),
            &self.signing_transcript(),
        )
    }

    /// The untagged dense bytes, exactly as the retired codec wrote them.
    pub fn dense_bytes(&self) -> Vec<u8> {
        match *self {
            Self::MergeV8 {
                collection,
                low,
                high,
                result,
                public_key,
                signature_r,
                signature_s,
            } => concat_fields::<7, RETIRED_MERGE_BINARY_BYTES_LEN>([
                collection.raw,
                low.raw,
                high.raw,
                result.raw,
                public_key.raw,
                signature_r.raw,
                signature_s.raw,
            ])
            .to_vec(),
            Self::DeriveV9 {
                target,
                input,
                output,
                public_key,
                signature_r,
                signature_s,
            } => concat_fields::<6, RETIRED_DERIVE_HANDLE_BYTES_LEN>([
                target.raw,
                input.raw,
                output.raw,
                public_key.raw,
                signature_r.raw,
                signature_s.raw,
            ])
            .to_vec(),
        }
    }

    /// The retired self-tagged dense form (tag 4 or 5).
    pub fn to_bytes(&self) -> Vec<u8> {
        let tag = match self {
            Self::MergeV8 { .. } => COLLECTION_RECORD_KIND_MERGE_V2,
            Self::DeriveV9 { .. } => COLLECTION_RECORD_KIND_DERIVE_V2,
        };
        tagged_bytes(tag, &self.dense_bytes())
    }

    /// The fingerprint the record had while it was live: BLAKE3 of the
    /// retired semantic kind followed by the dense bytes. Object stores keyed
    /// such records by it.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        let kind = match self {
            Self::MergeV8 { .. } => KIND_COLLECTION_MERGE_BINARY_RETIRED,
            Self::DeriveV9 { .. } => KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
        };
        retired_collection_record_fingerprint(kind, &self.dense_bytes())
    }

    /// Every blob the retired record named, as it named them: the collection
    /// and every payload, the input handle of a DERIVE included. Resident
    /// ones stay owned until the clean migration has read them.
    pub fn blob_references(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, 4>::new();
        references.push(self.collection().transmute());
        match *self {
            Self::MergeV8 {
                low, high, result, ..
            } => {
                references.extend([low, high, result].map(Handle::<UnknownBlob>::from_hash));
            }
            Self::DeriveV9 { input, output, .. } => {
                references.extend([input, output].map(Handle::<UnknownBlob>::from_hash));
            }
        }
        references.into_iter()
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
            } => retired_collection_record_fingerprint(
                KIND_COLLECTION_MERGE_UNSIGNED,
                &concat_fields::<4, 128>([collection.raw, low.raw, high.raw, result.raw]),
            ),
            Self::Derive {
                collection,
                input,
                output,
            } => retired_collection_record_fingerprint(
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CollectionRecord {
    /// Signed membership assertion: a foundation of a root collection.
    Commit(CollectionCommit),
    /// Signed exact-eight join inside one collection.
    Merge(CollectionMerge),
    /// Signed locator leaf: a foundation of a derived collection.
    Derive(CollectionDerive),
    /// Signed attachment of one parent node: a host's own index, never a
    /// foundation.
    Map(CollectionMap),
}

impl CollectionRecord {
    /// The exact collection named by this record (the target for a DERIVE,
    /// the attached collection for a MAP).
    pub fn collection(&self) -> CollectionHandle {
        match self {
            Self::Commit(record) => record.collection(),
            Self::Merge(record) => record.collection(),
            Self::Derive(record) => record.collection(),
            Self::Map(record) => record.collection(),
        }
    }

    /// The principal whose signed assertion this record carries.
    pub fn public_key(&self) -> Inline<ED25519PublicKey> {
        match self {
            Self::Commit(record) => record.public_key(),
            Self::Merge(record) => record.public_key(),
            Self::Derive(record) => record.public_key(),
            Self::Map(record) => record.public_key(),
        }
    }

    /// Verify foreign evidence or explicitly audit trusted persisted bytes.
    pub fn verify_strict(&self) -> Result<(), RecordVerificationError> {
        match self {
            Self::Commit(record) => record.verify_strict(),
            Self::Merge(record) => record.verify_strict(),
            Self::Derive(record) => record.verify_strict(),
            Self::Map(record) => record.verify_strict(),
        }
    }

    /// Blob handles named directly by this native record.
    ///
    /// Every record names its collection's descriptor. Beyond that, a commit
    /// names its data and metadata; a merge its result and every input; a
    /// derive its output only, because its input is a locator, not a
    /// fetchable handle; a map its attachment only, never the node it
    /// indexes. The returned handles express physical ownership
    /// only. Callers must not filter them through signature validity,
    /// collection admission, or algebraic usefulness before applying
    /// retention.
    pub fn blob_references(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, { MERGE_INPUTS + 2 }>::new();
        match self {
            Self::Commit(record) => references.extend(record.blob_references()),
            Self::Merge(record) => references.extend(record.blob_references()),
            Self::Derive(record) => references.extend(record.blob_references()),
            Self::Map(record) => references.extend(record.blob_references()),
        }
        references.into_iter()
    }

    /// Exact byte length of this complete canonical assertion.
    pub fn dense_len(&self) -> usize {
        match self {
            Self::Commit(_) => COLLECTION_COMMIT_BYTES_LEN,
            Self::Merge(record) => record.dense_len(),
            Self::Derive(_) => COLLECTION_DERIVE_BYTES_LEN,
            Self::Map(_) => COLLECTION_MAP_BYTES_LEN,
        }
    }

    /// Decode one complete canonical assertion and verify its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let record = Self::from_bytes_trusted(bytes)?;
        record.verify_strict()?;
        Ok(record)
    }

    /// Structural decoding for an explicitly trusted store. Kind, length and
    /// canonical inputs are still checked; no old tagged grammar is accepted.
    pub(crate) fn from_bytes_trusted(bytes: &[u8]) -> Result<Self, RecordDecodeError> {
        let kind = canonical_kind(bytes)?;
        match kind {
            KIND_COLLECTION_COMMIT => Ok(Self::Commit(CollectionCommit::from_bytes_trusted(
                exact_array(bytes)?,
            )?)),
            KIND_COLLECTION_MERGE => Ok(Self::Merge(CollectionMerge::from_bytes_trusted(bytes)?)),
            KIND_COLLECTION_DERIVE => Ok(Self::Derive(CollectionDerive::from_bytes_trusted(
                exact_array(bytes)?,
            )?)),
            KIND_COLLECTION_MAP => Ok(Self::Map(CollectionMap::from_bytes_trusted(exact_array(
                bytes,
            )?)?)),
            other => Err(RecordDecodeError::InvalidKind(other)),
        }
    }

    /// BLAKE3 of every canonical byte, including the kind and signature.
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        #[cfg(test)]
        FINGERPRINT_CALLS.set(FINGERPRINT_CALLS.get() + 1);
        match self {
            Self::Commit(record) => collection_record_fingerprint(&record.to_bytes()),
            Self::Merge(record) => collection_record_fingerprint(&record.to_bytes()),
            Self::Derive(record) => collection_record_fingerprint(&record.to_bytes()),
            Self::Map(record) => collection_record_fingerprint(&record.to_bytes()),
        }
    }

    /// The same complete canonical bytes used by typed codecs, stores and wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Commit(record) => record.to_bytes().to_vec(),
            Self::Merge(record) => record.to_bytes().to_vec(),
            Self::Derive(record) => record.to_bytes().to_vec(),
            Self::Map(record) => record.to_bytes().to_vec(),
        }
    }
}

/// Retired dense tag for the unsigned MERGE layout. Never reused.
pub const COLLECTION_RECORD_KIND_MERGE_V1: u8 = 2;
/// Retired dense tag for the unsigned DERIVE layout. Never reused.
pub const COLLECTION_RECORD_KIND_DERIVE_V1: u8 = 3;
/// RETIRED dense tag of the signed binary MERGE, live until lattice v2.
/// Never reused. Only [`RetiredCollectionEquation`] reads it explicitly.
pub const COLLECTION_RECORD_KIND_MERGE_V2: u8 = 4;
/// RETIRED dense tag of the signed handle DERIVE, live until lattice v2.
/// Never reused. See [`COLLECTION_RECORD_KIND_MERGE_V2`].
pub const COLLECTION_RECORD_KIND_DERIVE_V2: u8 = 5;

fn commit_bytes(
    collection: CollectionHandle,
    data_hash: CollectionData,
    metadata_handle: Inline<Handle<SimpleArchive>>,
    public_key: Inline<ED25519PublicKey>,
    r: Inline<ED25519RComponent>,
    s: Inline<ED25519SComponent>,
) -> [u8; COLLECTION_COMMIT_BYTES_LEN] {
    concat_fields([
        KIND_COLLECTION_COMMIT,
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

fn collection_record_fingerprint(bytes: &[u8]) -> CollectionRecordFingerprint {
    CollectionRecordFingerprint::from_raw(Blake3::digest(bytes))
}

/// Historical identity helper; never used for current canonical assertions.
fn retired_collection_record_fingerprint(kind: Id, payload: &[u8]) -> CollectionRecordFingerprint {
    let mut hasher = Blake3::new();
    hasher.update(&kind.raw());
    hasher.update(payload);
    CollectionRecordFingerprint::from_raw(hasher.finalize())
}

fn canonical_kind(bytes: &[u8]) -> Result<[u8; 32], RecordDecodeError> {
    bytes
        .get(..32)
        .and_then(|kind| kind.try_into().ok())
        .ok_or(RecordDecodeError::InvalidLength {
            expected: 32,
            actual: bytes.len(),
        })
}

fn require_kind(bytes: &[u8], expected: [u8; 32]) -> Result<(), RecordDecodeError> {
    let actual = canonical_kind(bytes)?;
    if actual == expected {
        Ok(())
    } else {
        Err(RecordDecodeError::InvalidKind(actual))
    }
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

fn slice_field(bytes: &[u8], index: usize) -> [u8; 32] {
    bytes[index * 32..(index + 1) * 32]
        .try_into()
        .expect("dense record field lies inside the checked length")
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

    fn locator(byte: u8) -> SourceLocator {
        SourceLocator::of([byte; 32])
    }

    fn fixture_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn merge(inputs: &[u8], result: u8) -> CollectionMerge {
        CollectionMerge::sign(
            &fixture_key(),
            collection(1),
            inputs.iter().map(|byte| input(*byte)),
            hash(result),
        )
        .expect("fixture merges join exactly eight distinct inputs")
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
        let decoded = CollectionCommit::from_bytes_trusted(bad.to_bytes()).unwrap();
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
        let decoded = CollectionCommit::from_bytes_trusted(invalid_key.to_bytes()).unwrap();
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
    fn merge_sorts_and_deduplicates_its_inputs() {
        let forward = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        let reverse = merge(&[10, 9, 8, 7, 6, 5, 3, 2, 3], 4);
        assert_eq!(forward, reverse);
        assert_eq!(forward.inputs(), &[2, 3, 5, 6, 7, 8, 9, 10].map(input));
        assert_eq!(
            CollectionMerge::from_bytes(&forward.to_bytes()).unwrap(),
            forward
        );
    }

    #[test]
    fn merge_requires_exactly_eight_distinct_inputs() {
        for count in [0, 1, 2, 7, 9, 16, 17] {
            assert_eq!(
                CollectionMerge::sign(
                    &fixture_key(),
                    collection(1),
                    (0..count).map(input),
                    hash(99)
                ),
                Err(MergeArityError {
                    distinct_inputs: count as usize
                })
            );
        }
        let record = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        assert_eq!(record.inputs().len(), MERGE_INPUTS);
        assert_eq!(record.to_bytes().len(), COLLECTION_MERGE_BYTES_LEN);
        assert_eq!(record.blob_references().len(), MERGE_INPUTS + 2);
    }

    /// An eight-input union may already equal one of its inputs.
    #[test]
    fn merge_result_may_be_one_of_its_inputs() {
        let absorbing = merge(&[2, 3, 4, 5, 6, 7, 8, 9], 3);
        absorbing.verify_strict().unwrap();
        assert_eq!(
            CollectionMerge::from_bytes(&absorbing.to_bytes()).unwrap(),
            absorbing
        );
    }

    #[test]
    fn merge_dense_layout_is_exact() {
        let record = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 448);
        assert_eq!(&bytes[..32], &KIND_COLLECTION_MERGE);
        assert_eq!(&bytes[32..64], &collection(1).raw);
        assert_eq!(&bytes[64..96], &hash(4).raw);
        assert_eq!(&bytes[96..128], &record.public_key().raw);
        for (i, input) in record.inputs().iter().enumerate() {
            assert_eq!(&bytes[128 + i * 32..160 + i * 32], &input.raw);
        }
        assert_eq!(&bytes[384..416], &record.signature().0.raw);
        assert_eq!(&bytes[416..448], &record.signature().1.raw);
        assert_eq!(record.signing_transcript(), bytes[..384]);
    }

    #[test]
    fn merge_decoder_rejects_every_noncanonical_form() {
        let record = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        let bytes = record.to_bytes();
        let mut swapped = bytes;
        swapped[128..160].fill(3);
        swapped[160..192].fill(2);
        let mut duplicate = bytes;
        duplicate[160..192].fill(2);
        // Even a valid signature cannot make unordered or duplicate inputs canonical.
        for mut malformed in [swapped, duplicate] {
            let signature: Signature = fixture_key().sign(&malformed[..384]);
            malformed[384..].copy_from_slice(&signature.to_bytes());
            assert_eq!(
                CollectionMerge::from_bytes(&malformed),
                Err(RecordDecodeError::NonCanonicalMergeInputs)
            );
            assert_eq!(
                CollectionMerge::from_bytes_trusted(&malformed),
                Err(RecordDecodeError::NonCanonicalMergeInputs)
            );
        }
        for length in 0..bytes.len() {
            assert!(matches!(
                CollectionMerge::from_bytes(&bytes[..length]),
                Err(RecordDecodeError::InvalidLength { .. })
            ));
        }
        let mut long = bytes.to_vec();
        long.extend_from_slice(&[0; 32]);
        assert_eq!(
            CollectionMerge::from_bytes(&long),
            Err(RecordDecodeError::InvalidLength {
                expected: 448,
                actual: 480
            })
        );
    }

    #[test]
    fn derive_roundtrips_and_names_a_locator_not_a_handle() {
        let record = CollectionDerive::sign(&fixture_key(), collection(2), locator(3), hash(4));
        assert_eq!(
            CollectionDerive::from_bytes(record.to_bytes()).unwrap(),
            record
        );
        assert_eq!(
            record.input(),
            SourceLocator::from_raw(crate::blob::locator::blob_locator([3; 32]))
        );
        assert_ne!(record.input().raw(), [3; 32]);
        assert_eq!(&record.to_bytes()[64..96], &record.output().raw);
        assert_eq!(&record.to_bytes()[96..128], &record.input().raw());
    }

    #[test]
    fn map_roundtrips_and_names_its_node_by_handle() {
        let record = CollectionMap::sign(&fixture_key(), collection(2), hash(3), hash(4));
        assert_eq!(
            CollectionMap::from_bytes(record.to_bytes()).unwrap(),
            record
        );
        assert_eq!(record.attached(), collection(2));
        assert_eq!(record.node(), hash(3));
        assert_eq!(record.attachment(), hash(4));
        assert_eq!(&record.to_bytes()[64..96], &[4; 32]);
        assert_eq!(&record.to_bytes()[96..128], &[3; 32]);
        assert_eq!(record.signing_transcript(), record.to_bytes()[..160]);
        let derive = CollectionDerive::from_parts(
            collection(2),
            SourceLocator::from_raw([3; 32]),
            hash(4),
            record.public_key(),
            record.signature().0,
            record.signature().1,
        );
        assert!(derive.verify_strict().is_err());
        assert_eq!(
            record.fingerprint().raw(),
            *blake3::hash(&record.to_bytes()).as_bytes()
        );
    }

    #[test]
    fn generic_codec_preserves_each_canonical_variant() {
        let records = [
            (
                CollectionRecord::Commit(CollectionCommit::sign(
                    &fixture_key(),
                    collection(1),
                    hash(2),
                    empty_metadata_handle(),
                )),
                KIND_COLLECTION_COMMIT,
            ),
            (
                CollectionRecord::Merge(merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4)),
                KIND_COLLECTION_MERGE,
            ),
            (
                CollectionRecord::Derive(CollectionDerive::sign(
                    &fixture_key(),
                    collection(2),
                    locator(3),
                    hash(4),
                )),
                KIND_COLLECTION_DERIVE,
            ),
            (
                CollectionRecord::Map(CollectionMap::sign(
                    &fixture_key(),
                    collection(5),
                    hash(6),
                    hash(7),
                )),
                KIND_COLLECTION_MAP,
            ),
        ];
        for (record, kind) in records {
            let bytes = record.to_bytes();
            assert_eq!(&bytes[..32], &kind);
            assert_eq!(bytes.len(), record.dense_len());
            assert_eq!(CollectionRecord::from_bytes(&bytes).unwrap(), record);
            assert_eq!(CollectionRecordView::from(record).body_bytes(), bytes);
        }
        assert_eq!(
            CollectionRecord::from_bytes(&[99; 32]),
            Err(RecordDecodeError::InvalidKind([99; 32]))
        );
    }

    #[test]
    fn collection_prefix_layout_rejects_old_dense_tags_and_preserves_all_fields() {
        let derive = CollectionDerive::sign(&fixture_key(), collection(2), locator(3), hash(4));
        let map = CollectionMap::sign(&fixture_key(), collection(2), hash(3), hash(4));
        for record in [CollectionRecord::Derive(derive), CollectionRecord::Map(map)] {
            let bytes = record.to_bytes();
            assert_eq!(&bytes[32..64], &collection(2).raw);
            assert_eq!(&bytes[64..96], &hash(4).raw);
            for old_tag in [1, 8, 9, 10, 11, 12] {
                let mut old = vec![old_tag];
                old.extend_from_slice(&bytes[32..]);
                assert!(CollectionRecord::from_bytes(&old).is_err());
                assert!(CollectionRecord::from_bytes_trusted(&old).is_err());
            }
            for offset in [96, 128, 160, 192] {
                let mut altered = bytes.clone();
                altered[offset] ^= 1;
                let structural = CollectionRecord::from_bytes_trusted(&altered).unwrap();
                assert_ne!(structural.fingerprint(), record.fingerprint());
                assert!(CollectionRecord::from_bytes(&altered).is_err());
            }
        }
    }

    #[test]
    fn native_records_enumerate_every_direct_blob_reference() {
        let metadata = Inline::<Handle<SimpleArchive>>::new([3; 32]);
        let commit = CollectionCommit::sign(&fixture_key(), collection(1), hash(2), metadata);
        let merge = CollectionMerge::sign(
            &fixture_key(),
            collection(4),
            [5, 6, 8, 9, 10, 11, 12, 13].map(input),
            hash(7),
        )
        .unwrap();
        let derive = CollectionDerive::sign(&fixture_key(), collection(8), locator(9), hash(10));

        assert_eq!(
            CollectionRecord::Commit(commit)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32], [3; 32]],
        );
        // The descriptor, the result, then every input.
        assert_eq!(
            CollectionRecord::Merge(merge)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![
                [4; 32], [7; 32], [5; 32], [6; 32], [8; 32], [9; 32], [10; 32], [11; 32], [12; 32],
                [13; 32]
            ],
        );
        // The target descriptor and the output; never the locator, which is
        // not fetchable.
        assert_eq!(
            CollectionRecord::Derive(derive)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[8; 32], [10; 32]],
        );
        // The attached descriptor and the attachment; never the node, which
        // the parent's own records keep.
        let map = CollectionMap::sign(&fixture_key(), collection(11), hash(12), hash(13));
        assert_eq!(
            CollectionRecord::Map(map)
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[11; 32], [13; 32]],
        );
    }

    #[test]
    fn generic_codec_rejects_wrong_lengths() {
        for (kind, length) in [
            (KIND_COLLECTION_COMMIT, 224),
            (KIND_COLLECTION_DERIVE, 224),
            (KIND_COLLECTION_MAP, 224),
            (KIND_COLLECTION_MERGE, 448),
        ] {
            assert_eq!(
                CollectionRecord::from_bytes(&kind),
                Err(RecordDecodeError::InvalidLength {
                    expected: length,
                    actual: 32
                })
            );
            let mut oversized = vec![0; length + 1];
            oversized[..32].copy_from_slice(&kind);
            assert_eq!(
                CollectionRecord::from_bytes(&oversized),
                Err(RecordDecodeError::InvalidLength {
                    expected: length,
                    actual: length + 1
                })
            );
        }
    }

    #[test]
    fn equations_bind_every_field_and_reject_weak_authors_at_ingress() {
        let records = [
            CollectionRecord::Commit(CollectionCommit::sign(
                &fixture_key(),
                collection(1),
                hash(2),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4)),
            CollectionRecord::Derive(CollectionDerive::sign(
                &fixture_key(),
                collection(2),
                locator(3),
                hash(4),
            )),
            CollectionRecord::Map(CollectionMap::sign(
                &fixture_key(),
                collection(5),
                hash(6),
                hash(7),
            )),
        ];
        for record in records {
            let encoded = record.to_bytes();
            for offset in 0..encoded.len() {
                let mut altered = encoded.clone();
                altered[offset] ^= 1;
                assert!(
                    CollectionRecord::from_bytes(&altered).is_err(),
                    "unbound byte {offset}"
                );
                // Trusted structural decoding may reject kind/order violations;
                // it never re-attests or repairs malformed signatures.
                if let Ok(retained) = CollectionRecord::from_bytes_trusted(&altered) {
                    assert!(retained.verify_strict().is_err());
                }
            }
            let key_start = if matches!(record, CollectionRecord::Merge(_)) {
                96
            } else {
                128
            };
            let mut weak = encoded;
            weak[key_start..key_start + 32].fill(0);
            weak[key_start] = 1;
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
        let first = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        let second = CollectionMerge::sign(
            &SigningKey::from_bytes(&[8; 32]),
            collection(1),
            [2, 3, 5, 6, 7, 8, 9, 10].map(input),
            hash(4),
        )
        .unwrap();
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
        let merge_v1 = tagged_bytes(
            COLLECTION_RECORD_KIND_MERGE_V1,
            &concat_fields::<4, 128>([collection(1).raw, hash(2).raw, hash(3).raw, hash(4).raw]),
        );
        let derive_v1 = tagged_bytes(
            COLLECTION_RECORD_KIND_DERIVE_V1,
            &concat_fields::<3, 96>([collection(2).raw, hash(3).raw, hash(4).raw]),
        );
        for (bytes, fingerprint, references) in [
            (
                merge_v1,
                hex!("92A19C12DAF4046397A43C607051ECCB1DD1EFB74D8B977B8A19AE7846521170"),
                vec![[1; 32], [2; 32], [3; 32], [4; 32]],
            ),
            (
                derive_v1,
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
            assert!(CollectionRecord::from_bytes(&bytes).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(LegacyUnsignedCollectionEquation::from_bytes(&trailing).is_err());
        }
        assert!(LegacyUnsignedCollectionEquation::from_bytes(
            &CollectionRecord::Merge(merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4)).to_bytes()
        )
        .is_err());
    }

    /// The retired live kinds keep their exact bytes, signatures and
    /// fingerprints, and no current decoder serves them.
    #[test]
    fn retired_live_equations_keep_their_fields_and_golden_bytes() {
        let merge_v8 = RetiredCollectionEquation::sign_merge_v8(
            &fixture_key(),
            collection(1),
            input(3),
            input(2),
            hash(4),
        );
        let derive_v9 = RetiredCollectionEquation::sign_derive_v9(
            &fixture_key(),
            collection(2),
            input(3),
            hash(4),
        );
        // Signatures and fingerprints pinned while these were the live kinds.
        assert_eq!(
            concat_fields::<2, 64>([merge_v8.signature().0.raw, merge_v8.signature().1.raw]),
            hex!("39D1BE8DC91EE25298CD4B03D4CDD9D1D021994A0B5999EFCD86F1BB4D87EE08A64EE5C40BBBAA21F01C6963BCF2F259CD76D93CBBB4D4351879CB7167ADB00B")
        );
        assert_eq!(
            concat_fields::<2, 64>([derive_v9.signature().0.raw, derive_v9.signature().1.raw]),
            hex!("10325E15C286E263AFE7D7219F4F637F852F1EB61ECA68916DA4793C6BE9BAB5287380B741FF9D1AE6AD5FA36329785AAA36C6FAABFEB759A7E5387F1F2D140B")
        );
        assert_eq!(
            merge_v8.fingerprint().raw(),
            hex!("BF31C64514D9721278866D2AD87819D0C4282D5AC59A7AEBC37729D078038BDC")
        );
        assert_eq!(
            derive_v9.fingerprint().raw(),
            hex!("2CEC0E4B0A78362E7EC93F5951B4FE6B1BB8233A1A6377C51ECF455A5B945672")
        );
        assert_eq!(merge_v8.signing_transcript().len(), 215);
        assert_eq!(derive_v9.signing_transcript().len(), 184);
        for (retired, tag, references) in [
            (
                merge_v8,
                COLLECTION_RECORD_KIND_MERGE_V2,
                vec![[1; 32], [2; 32], [3; 32], [4; 32]],
            ),
            (
                derive_v9,
                COLLECTION_RECORD_KIND_DERIVE_V2,
                vec![[2; 32], [3; 32], [4; 32]],
            ),
        ] {
            retired.verify_strict().unwrap();
            let bytes = retired.to_bytes();
            assert_eq!(bytes[0], tag);
            assert_eq!(
                RetiredCollectionEquation::from_bytes(&bytes).unwrap(),
                retired
            );
            assert_eq!(
                retired
                    .blob_references()
                    .map(|handle| handle.raw)
                    .collect::<Vec<_>>(),
                references
            );
            assert!(CollectionRecord::from_bytes(&bytes).is_err());
        }
        assert_eq!(merge_v8.produced(), hash(4));
        assert_eq!(derive_v9.collection(), collection(2));
        // A binary merge whose inputs are out of order is not canonical.
        let mut swapped = merge_v8.to_bytes();
        swapped[33..65].fill(9);
        assert_eq!(
            RetiredCollectionEquation::from_bytes(&swapped),
            Err(RecordDecodeError::NonCanonicalMergeInputs)
        );
    }

    #[test]
    fn canonical_signature_and_fingerprint_vectors() {
        // Generated once from this grammar and fixture key [7; 32]; literal pins
        // catch encoder/transcript changes even when both implementations move.
        let fixtures = [
            (
                CollectionRecord::Commit(CollectionCommit::sign(&fixture_key(), collection(1), hash(2), Inline::new([3; 32]))),
                hex!("361010E052FB27CA975F2458997FBBC68B295028A138723E96ABF7114B8A0F92390DF5A416458C697E16A2949A12C99C9B667A5F1D81325F00F7C5F7C78E7909"),
                hex!("F9FB7095E9401BB3EC078CCFF44BEA6717D888B238661A9DF64E5204C9EE0D0B"),
            ),
            (
                CollectionRecord::Derive(CollectionDerive::sign(&fixture_key(), collection(2), locator(3), hash(4))),
                hex!("36F70C8E0FE9E4F3828499140F352C94B69230F3C666A5B1F6AE5386A1BEDCB79628DC2909512940474CD7EC3E97B2C0C6FC453D73906FF531E60A3DDD72F500"),
                hex!("400F3A2A2D050FE1826D73FD9A57D2D16CA3DF695BE6D8682A29B57C3658148E"),
            ),
            (
                CollectionRecord::Map(CollectionMap::sign(&fixture_key(), collection(2), hash(3), hash(4))),
                hex!("280820F5ABE26685A332A63F72C59770C3217BED56B4A2600EF1981614CF901369E600BCB8DDA0F8AF2B6F13EA8025A2B8FCD5772C68393AF48BF478C7E9510E"),
                hex!("D7B6D63DB1045BB83AFB79345B2298D76AD2F293A9ECA65DA84A81AA8338416D"),
            ),
            (
                CollectionRecord::Merge(merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4)),
                hex!("32108BF9CACCA072718D2E20F522AAE5558D1564964B88BFA285B27261DAF030273B1DAE32F3DE5EA8E11611ACCD51CD76691D5F6D69BB48C7C5CCF652FB620D"),
                hex!("C83AA91A27C18AD796B32C4BD9C2210DAA827A2C8027CE94286811F208150917"),
            ),
        ];
        for (record, signature, fingerprint) in fixtures {
            let bytes = record.to_bytes();
            assert_eq!(&bytes[bytes.len() - 64..], signature);
            assert_eq!(record.fingerprint().raw(), fingerprint);
            assert_eq!(CollectionRecord::from_bytes(&bytes).unwrap(), record);
        }
    }
    #[test]
    fn signatures_and_fingerprints_use_exact_canonical_bytes() {
        let anchor = id_hex!("A2EEF06D4E1AA4B17B745AA2E8C37867");
        assert_eq!(
            collection_name.raw(),
            Attribute::<Handle<UTF8String>>::anchored(anchor).raw()
        );
        assert_ne!(collection_name.id(), anchor);
        let commit =
            CollectionCommit::sign(&fixture_key(), collection(1), hash(2), Inline::new([3; 32]));
        let merge = merge(&[2, 3, 5, 6, 7, 8, 9, 10], 4);
        let derive = CollectionDerive::sign(&fixture_key(), collection(2), locator(3), hash(4));
        let map = CollectionMap::sign(&fixture_key(), collection(2), hash(3), hash(4));
        for (record, prefix) in [
            (
                CollectionRecord::Commit(commit),
                commit.signing_transcript(),
            ),
            (CollectionRecord::Merge(merge), merge.signing_transcript()),
            (
                CollectionRecord::Derive(derive),
                derive.signing_transcript(),
            ),
            (CollectionRecord::Map(map), map.signing_transcript()),
        ] {
            let bytes = record.to_bytes();
            assert_eq!(prefix, bytes[..bytes.len() - 64]);
            let signature: Signature = fixture_key().sign(&prefix);
            assert_eq!(&bytes[bytes.len() - 64..], signature.to_bytes());
            assert_eq!(record.fingerprint().raw(), *blake3::hash(&bytes).as_bytes());
            record.verify_strict().unwrap();
        }
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
