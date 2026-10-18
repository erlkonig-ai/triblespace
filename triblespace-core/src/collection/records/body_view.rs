//! Sealed trusted views of complete canonical assertions.

use super::*;
use anybytes::{Bytes, View};
use zerocopy::IntoBytes;

/// A complete canonical assertion from a trusted store or verified domain record.
/// Structural views alone cannot construct this trusted carrier:
/// ```compile_fail
/// use anybytes::Bytes;
/// use triblespace_core::collection::{CollectionRecordView, EncodedCommit};
/// let raw = Bytes::from_source(vec![0u8; 224]).view::<EncodedCommit>().unwrap();
/// let trusted = CollectionRecordView::from(raw);
/// ```
#[derive(Clone, Debug)]
pub struct CollectionRecordView(
    Body,
    Option<CollectionRecordFingerprint>,
);

// Cached metadata is not assertion identity.
impl PartialEq for CollectionRecordView {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}
impl Eq for CollectionRecordView {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Body {
    Commit(View<EncodedCommit>),
    Derive(View<EncodedDerive>),
    Map(View<EncodedMap>),
    Merge(View<EncodedMerge>),
}

#[cfg(test)]
mod fingerprint_cache_tests {
    use super::*;
    #[test]
    fn cached_fingerprint_avoids_rehash_and_fallback_stays_equal() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &signer, Inline::new([1; 32]), Inline::new([2; 32]), Inline::new([3; 32]),
        ));
        let fallback = CollectionRecordView::from(record);
        let raw = record.fingerprint().raw();
        let cached = fallback.clone().with_native_fingerprint(raw);
        FINGERPRINT_CALLS.set(0);
        assert_eq!(cached.fingerprint().raw(), raw);
        assert_eq!(cached.fingerprint().raw(), raw);
        assert_eq!(FINGERPRINT_CALLS.get(), 0);
        assert_eq!(fallback.fingerprint().raw(), raw);
        assert_eq!(FINGERPRINT_CALLS.get(), 1);
        assert_eq!(cached, fallback);
    }
}

impl From<CollectionRecord> for CollectionRecordView {
    fn from(record: CollectionRecord) -> Self {
        Self::from_native_fixed(Bytes::from_source(record.to_bytes()))
    }
}

impl CollectionRecordView {
    /// Only checked native framing or trusted semantic construction calls this.
    /// The kind lives in the borrowed bytes, never in an independent wire tag.
    pub(crate) fn from_native_fixed(bytes: Bytes) -> Self {
        let kind = canonical_kind(&bytes).expect("checked canonical kind");
        Self(match kind {
            KIND_COLLECTION_COMMIT => Body::Commit(bytes.view().expect("canonical COMMIT layout")),
            KIND_COLLECTION_DERIVE => Body::Derive(bytes.view().expect("canonical DERIVE layout")),
            KIND_COLLECTION_MAP => Body::Map(bytes.view().expect("canonical MAP layout")),
            KIND_COLLECTION_MERGE => Body::Merge(bytes.view().expect("canonical MERGE layout")),
            _ => panic!("checked native collection kind"),
        }, None)
    }

    /// Only the native fixed-record index supplies this
    /// fingerprint, which it computed from these complete bytes during replay.
    pub(crate) fn with_native_fingerprint(mut self, raw: [u8; 32]) -> Self {
        self.1 = Some(CollectionRecordFingerprint::from_raw(raw));
        self
    }

    /// Borrow the complete canonical assertion, including kind and signature.
    pub fn body_bytes(&self) -> &[u8] {
        match &self.0 {
            Body::Commit(v) => v.as_bytes(),
            Body::Derive(v) => v.as_bytes(),
            Body::Map(v) => v.as_bytes(),
            Body::Merge(v) => v.as_bytes(),
        }
    }

    /// Share the complete assertion's owner without copying bytes.
    pub fn body(&self) -> Bytes {
        match &self.0 {
            Body::Commit(v) => v.clone().bytes(),
            Body::Derive(v) => v.clone().bytes(),
            Body::Map(v) => v.clone().bytes(),
            Body::Merge(v) => v.clone().bytes(),
        }
    }

    pub fn as_commit(&self) -> Option<&View<EncodedCommit>> {
        match &self.0 {
            Body::Commit(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_derive(&self) -> Option<&View<EncodedDerive>> {
        match &self.0 {
            Body::Derive(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&View<EncodedMap>> {
        match &self.0 {
            Body::Map(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_merge(&self) -> Option<&View<EncodedMerge>> {
        match &self.0 {
            Body::Merge(v) => Some(v),
            _ => None,
        }
    }
    pub fn collection(&self) -> CollectionHandle {
        Inline::new(
            self.body_bytes()[32..64]
                .try_into()
                .expect("canonical collection"),
        )
    }
    pub fn is_foundation(&self) -> bool {
        matches!(self.0, Body::Commit(_) | Body::Derive(_))
    }
    pub fn to_record(&self) -> CollectionRecord {
        match &self.0 {
            Body::Commit(v) => CollectionRecord::Commit(v.to_record_trusted()),
            Body::Derive(v) => CollectionRecord::Derive(v.to_record_trusted()),
            Body::Map(v) => CollectionRecord::Map(v.to_record_trusted()),
            Body::Merge(v) => CollectionRecord::Merge(v.to_record_trusted()),
        }
    }
    pub fn fingerprint(&self) -> CollectionRecordFingerprint {
        if let Some(fingerprint) = self.1 {
            return fingerprint;
        }
        #[cfg(test)]
        FINGERPRINT_CALLS.set(FINGERPRINT_CALLS.get() + 1);
        collection_record_fingerprint(self.body_bytes())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.body_bytes().to_vec()
    }
}
