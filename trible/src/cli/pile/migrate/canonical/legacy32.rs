//! Private one-assertion offline migration verifier. Never runtime dispatch.
//!
//! Input is explicitly the deployed /32 self-tagged dense assertion, NOT a
//! native Pile frame. No files, key loading, admission, blob discovery, runtime
//! compatibility dispatch, batch catalogue or completion receipt lives here.
//! Historical constants are copied exactly from deployed commit 3ca5c1cb.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::records::{
    CollectionRecord, KIND_COLLECTION_COMMIT, KIND_COLLECTION_DERIVE, KIND_COLLECTION_MAP,
    KIND_COLLECTION_MERGE,
};

#[derive(Clone, Copy, Debug)]
pub enum Input<'a> {
    TaggedCollection(&'a [u8]),
    Auth(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Commit,
    Merge,
    Derive,
    Map,
}

impl Kind {
    fn semantic(self) -> [u8; 16] {
        match self {
            Self::Commit => hex_literal::hex!("B34817308188C4515A3C51967A91A603"),
            Self::Merge => hex_literal::hex!("D0D98881093C0A6F318E1E1525521F80"),
            Self::Derive => hex_literal::hex!("630BF5B294A3A1D85C0A7B185C9BC899"),
            Self::Map => hex_literal::hex!("329669AA662709605053C123671DF1D2"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Unresolved {
    SignerUnavailable {
        author: [u8; 32],
    },
    SignerMismatch {
        author: [u8; 32],
        supplied: [u8; 32],
    },
    UnsupportedHistoricalKind(u8),
    CacheDispositionRequired {
        kind: Kind,
        author: [u8; 32],
    },
    RefreshMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invalid {
    Length,
    MergeCount,
    MergePadding,
    MergeInputOrder,
    PublicKey,
    Signature,
    AuthStructure,
    AuthSignature,
    CanonicalEncoding,
}

#[derive(Debug)]
pub enum Outcome {
    Converted {
        record: CollectionRecord,
        new_fingerprint: [u8; 32],
    },
    UnchangedAuth {
        id: [u8; 32],
    },
    Unresolved(Unresolved),
    Invalid(Invalid),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Converted {
                new_fingerprint, ..
            } => write!(f, "converted {}", hex::encode(new_fingerprint)),
            Self::UnchangedAuth { id } => write!(f, "unchanged AUTH {}", hex::encode(id)),
            Self::Unresolved(reason) => write!(f, "unresolved: {reason:?}"),
            Self::Invalid(reason) => write!(f, "invalid: {reason:?}"),
        }
    }
}

#[derive(Debug)]
pub struct Conversion<'a> {
    /// Exact original bytes, preserved for every outcome, including failure.
    pub original: &'a [u8],
    /// Old semantic-kind16/dense-body fingerprint, not a hash of a wrapper.
    /// Present after recognized structural decoding, even if signature-invalid;
    /// it is an identity, not a validation or admission claim. AUTH has its own id.
    pub old_fingerprint: Option<[u8; 32]>,
    pub outcome: Outcome,
}

/// A single result says nothing about batch, native framing, blob closure,
/// authority, source refresh, durability, or completeness. Foreign records are
/// never substituted under a supplied local signer. No signer means unresolved.
pub fn convert<'a>(input: Input<'a>, signer: Option<&SigningKey>) -> Conversion<'a> {
    convert_inner(input, signer, false, None)
}

/// Explicit offline rewrite policy: owned MAP/exact-eight MERGE may be resealed.
/// A foreign foundation can only be refreshed by an independently supplied
/// current-valid assertion with the exact original author and semantic fields.
/// This verifies statements, NOT cache equations, admission or blob closure.
pub fn reseal_or_refresh<'a>(
    input: Input<'a>,
    signer: &SigningKey,
    refresh: Option<&CollectionRecord>,
) -> Conversion<'a> {
    convert_inner(input, Some(signer), true, refresh)
}

/// One verified assertion, borrowed only while processing its source frame.
/// Not a retained catalogue; the exact source remains the original evidence.
pub struct Verified<'a> {
    pub original: &'a [u8],
    pub kind: Kind,
    pub author: [u8; 32],
    pub old_fingerprint: [u8; 32],
}

pub fn verified(bytes: &[u8]) -> Result<Verified<'_>, Outcome> {
    let checked = convert(Input::TaggedCollection(bytes), None);
    match checked.outcome {
        Outcome::Unresolved(Unresolved::SignerUnavailable { author })
        | Outcome::Unresolved(Unresolved::CacheDispositionRequired { author, .. }) => {
            let kind = match bytes[0] {
                1 => Kind::Commit,
                8 => Kind::Merge,
                9 => Kind::Derive,
                10 => Kind::Map,
                _ => unreachable!("convert recognized this kind"),
            };
            Ok(Verified {
                original: checked.original,
                kind,
                author,
                old_fingerprint: checked.old_fingerprint.unwrap(),
            })
        }
        other => Err(other),
    }
}

impl Verified<'_> {
    pub fn foundation(&self) -> bool {
        matches!(self.kind, Kind::Commit | Kind::Derive)
    }
    pub fn collection(&self) -> [u8; 32] {
        self.original[1..33].try_into().unwrap()
    }
    pub fn produced(&self) -> [u8; 32] {
        let offset = if self.kind == Kind::Commit { 33 } else { 65 };
        self.original[offset..offset + 32].try_into().unwrap()
    }
    pub fn matches(&self, refresh: &CollectionRecord) -> bool {
        if !self.foundation() || refresh.verify_strict().is_err() {
            return false;
        }
        let prefix = canonical_prefix(self.kind, &self.original[1..]);
        let bytes = refresh.to_bytes();
        bytes.len() == prefix.len() + 64 && bytes[..prefix.len()] == prefix
    }
}

fn convert_inner<'a>(
    input: Input<'a>,
    signer: Option<&SigningKey>,
    allow_owned_caches: bool,
    refresh: Option<&CollectionRecord>,
) -> Conversion<'a> {
    let bytes = match input {
        Input::TaggedCollection(bytes) | Input::Auth(bytes) => bytes,
    };
    let mut result = Conversion {
        original: bytes,
        old_fingerprint: None,
        outcome: Outcome::Invalid(Invalid::Length),
    };
    if let Input::Auth(_) = input {
        result.outcome = match CapabilityProof::from_bytes(bytes) {
            Err(_) => Outcome::Invalid(Invalid::AuthStructure),
            Ok(proof) => match proof.verify_signatures() {
                Err(_) => Outcome::Invalid(Invalid::AuthSignature),
                Ok(()) => Outcome::UnchangedAuth { id: proof.id().raw },
            },
        };
        return result;
    }
    let Some((&tag, dense)) = bytes.split_first() else {
        return result;
    };
    let kind = match tag {
        1 => Kind::Commit,
        8 => Kind::Merge,
        9 => Kind::Derive,
        10 => Kind::Map,
        other => {
            result.outcome = Outcome::Unresolved(Unresolved::UnsupportedHistoricalKind(other));
            return result;
        }
    };
    let decoded = match decode(kind, dense) {
        Ok(decoded) => decoded,
        Err(error) => {
            result.outcome = Outcome::Invalid(error);
            return result;
        }
    };
    let mut hash = blake3::Hasher::new();
    hash.update(&kind.semantic());
    hash.update(dense);
    result.old_fingerprint = Some(*hash.finalize().as_bytes());
    let key = match VerifyingKey::from_bytes(&decoded.author) {
        Ok(key) if valid_old_principal(&key) => key,
        _ => {
            result.outcome = Outcome::Invalid(Invalid::PublicKey);
            return result;
        }
    };
    if key
        .verify_strict(&decoded.transcript, &decoded.signature)
        .is_err()
    {
        result.outcome = Outcome::Invalid(Invalid::Signature);
        return result;
    }
    if matches!(kind, Kind::Merge | Kind::Map)
        && (!allow_owned_caches || (kind == Kind::Merge && dense.len() != 448))
    {
        result.outcome = Outcome::Unresolved(Unresolved::CacheDispositionRequired {
            kind,
            author: decoded.author,
        });
        return result;
    }
    let mut canonical = canonical_prefix(kind, dense);
    if matches!(kind, Kind::Commit | Kind::Derive) {
        if let Some(refresh) = refresh {
            let refreshed = refresh.to_bytes();
            result.outcome = if refresh.verify_strict().is_ok()
                && refreshed.len() == canonical.len() + 64
                && refreshed[..canonical.len()] == canonical
            {
                Outcome::Converted {
                    record: *refresh,
                    new_fingerprint: refresh.fingerprint().raw(),
                }
            } else {
                Outcome::Unresolved(Unresolved::RefreshMismatch)
            };
            return result;
        }
    }
    let Some(signer) = signer else {
        result.outcome = Outcome::Unresolved(Unresolved::SignerUnavailable {
            author: decoded.author,
        });
        return result;
    };
    let supplied = signer.verifying_key().to_bytes();
    if supplied != decoded.author {
        result.outcome = Outcome::Unresolved(Unresolved::SignerMismatch {
            author: decoded.author,
            supplied,
        });
        return result;
    }

    // SourceLocator::from_raw is intentionally crate-private. Preserve the old
    // locator bytes directly; never hash them again or reverse/guess a source
    // handle. The public current strict decoder validates the newly signed bytes.
    let signature = signer.sign(&canonical);
    canonical.extend_from_slice(&signature.to_bytes());
    result.outcome = match CollectionRecord::from_bytes(&canonical) {
        Ok(record) => Outcome::Converted {
            new_fingerprint: record.fingerprint().raw(),
            record,
        },
        Err(_) => Outcome::Invalid(Invalid::CanonicalEncoding),
    };
    result
}

fn canonical_prefix(kind: Kind, dense: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(if kind == Kind::Merge { 384 } else { 160 });
    match kind {
        Kind::Commit => {
            bytes.extend_from_slice(&KIND_COLLECTION_COMMIT);
            bytes.extend_from_slice(&dense[..128]);
        }
        Kind::Derive | Kind::Map => {
            bytes.extend_from_slice(if kind == Kind::Derive {
                &KIND_COLLECTION_DERIVE
            } else {
                &KIND_COLLECTION_MAP
            });
            bytes.extend_from_slice(&dense[..32]);
            bytes.extend_from_slice(&dense[64..96]);
            bytes.extend_from_slice(&dense[32..64]);
            bytes.extend_from_slice(&dense[96..128]);
        }
        Kind::Merge => {
            bytes.extend_from_slice(&KIND_COLLECTION_MERGE);
            bytes.extend_from_slice(&dense[..96]);
            bytes.extend_from_slice(&dense[192..]);
        }
    }
    bytes
}

// Ephemeral parsing state for one call, never a retained record catalogue.
struct Decoded {
    author: [u8; 32],
    signature: Signature,
    transcript: Vec<u8>,
}

// Deployed3ca capability.rs:817 uses this same canonical-y and non-weak check.
// It is crate-private; keep this historical verifier rule offline rather than
// widening the runtime API or weakening old verification to curve parsing only.
fn valid_old_principal(key: &VerifyingKey) -> bool {
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    let mut y = key.to_bytes();
    y[31] &= 0x7f;
    y.iter().rev().cmp(modulus.iter().rev()).is_lt() && !key.is_weak()
}

fn decode(kind: Kind, dense: &[u8]) -> Result<Decoded, Invalid> {
    let author_offset = if kind == Kind::Merge { 64 } else { 96 };
    if kind == Kind::Merge {
        if dense.len() < 192 {
            return Err(Invalid::Length);
        }
        if dense[160..188].iter().any(|&byte| byte != 0) {
            return Err(Invalid::MergePadding);
        }
        let count = u32::from_be_bytes(dense[188..192].try_into().unwrap()) as usize;
        if !(2..=16).contains(&count) {
            return Err(Invalid::MergeCount);
        }
        if dense.len() != 192 + count * 32 {
            return Err(Invalid::Length);
        }
        if dense[192..]
            .chunks_exact(32)
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(Invalid::MergeInputOrder);
        }
    } else if dense.len() != 192 {
        return Err(Invalid::Length);
    }
    let author: [u8; 32] = dense[author_offset..author_offset + 32].try_into().unwrap();
    let signature = Signature::from_slice(&dense[author_offset + 32..author_offset + 96]).unwrap();
    let mut transcript = Vec::new();
    match kind {
        Kind::Commit => transcript.extend_from_slice(b"triblespace.collection.commit.transcript"),
        Kind::Merge => transcript.extend_from_slice(&hex_literal::hex!(
            "B75F4382781F565972D759D69C72703B2A2E525B9D3B13A249590235C7BE8C40"
        )),
        Kind::Derive => transcript.extend_from_slice(&hex_literal::hex!(
            "3F33151333CCDE3566D792C723DF70A74ACCF357CD0B9A7E7E1C61913020D22F"
        )),
        Kind::Map => transcript.extend_from_slice(&hex_literal::hex!(
            "4A5191C36898D0B453FEFF99ED0E38524AADD87ED8EB8620BD39623B5221B5BE"
        )),
    }
    transcript.extend_from_slice(&kind.semantic());
    if kind == Kind::Commit {
        transcript.extend_from_slice(&2u32.to_be_bytes())
    }
    transcript.extend_from_slice(&author);
    if kind == Kind::Merge {
        transcript.extend_from_slice(&dense[..32]);
        transcript.extend_from_slice(&dense[188..192]);
        transcript.extend_from_slice(&dense[192..]);
        transcript.extend_from_slice(&dense[32..64]);
    } else {
        transcript.extend_from_slice(&dense[..96]);
    }
    Ok(Decoded {
        author,
        signature,
        transcript,
    })
}
