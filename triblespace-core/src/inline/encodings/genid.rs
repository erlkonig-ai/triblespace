use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id::NilUuidError;
use crate::id::OwnedId;
use crate::id::RawId;
use crate::id_hex;
use crate::inline::Encodes;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::IntoInline;
use crate::inline::TryFromInline;
use crate::inline::TryToInline;
use crate::inline::INLINE_LEN;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

use std::convert::TryInto;

use hex::FromHex;
use hex::FromHexError;

/// A inline encoding for an abstract 128-bit identifier.
/// This identifier is generated with high entropy and is suitable for use as a unique identifier.
///
/// See the [crate::id] module documentation for a discussion on the role of this identifier.
pub struct GenId;

impl MetaDescribe for GenId {
    fn describe() -> Fragment {
        let id: Id = id_hex!("B08EE1D45EB081E8C47618178AFE0D81");
        #[allow(unused_mut)]
        let mut tribles = entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "genid",
                metadata::description: "Opaque 128-bit identifier stored in the lower 16 bytes; the upper 16 bytes are zero. The value is intended to be high-entropy and stable over time.\n\nUse for entity ids, references, or user-assigned identifiers when the bytes do not carry meaning. If you want content-derived identifiers or deduplication, use a Hash schema instead.\n\nGenId does not imply ordering or integrity. If you need deterministic ids across systems, derive them from agreed inputs (for example by wrapping the inputs in `entity!{}` and taking its `root()`, or by hashing them directly).",
                metadata::tag: metadata::KIND_INLINE_ENCODING,
        };

        #[cfg(feature = "wasm")]
        {
            tribles += entity! { ExclusiveId::force_ref(&id) @
                metadata::value_formatter: wasm_formatter::GENID_WASM,
            };
        }
        tribles
    }
}

#[cfg(feature = "wasm")]
mod wasm_formatter {
    use core::fmt::Write;

    use triblespace_core_macros::value_formatter;

    #[value_formatter]
    pub(crate) fn genid(raw: &[u8; 32], out: &mut impl Write) -> Result<(), u32> {
        const TABLE: &[u8; 16] = b"0123456789ABCDEF";

        let prefix_ok = raw[..16].iter().all(|&b| b == 0);
        let bytes = if prefix_ok { &raw[16..] } else { &raw[..] };
        for &byte in bytes {
            let hi = (byte >> 4) as usize;
            let lo = (byte & 0x0F) as usize;
            out.write_char(TABLE[hi] as char).map_err(|_| 1u32)?;
            out.write_char(TABLE[lo] as char).map_err(|_| 1u32)?;
        }
        Ok(())
    }
}
impl InlineEncoding for GenId {
    type ValidationError = ();
    type Encoding = Self;
    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        if value.raw[0..16] == [0; 16] {
            Ok(value)
        } else {
            Err(())
        }
    }
}

/// Error returned when extracting an identifier from a [`Inline<GenId>`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IdParseError {
    /// The identifier is nil (all zeros), which is reserved.
    IsNil,
    /// The upper 16 bytes are not zero, violating the GenId layout.
    BadFormat,
}

//RawId
impl<'a> TryFromInline<'a, GenId> for &'a RawId {
    type Error = IdParseError;

    fn try_from_inline(value: &'a Inline<GenId>) -> Result<Self, Self::Error> {
        if value.raw[0..16] != [0; 16] {
            return Err(IdParseError::BadFormat);
        }
        Ok(value.raw[16..32].try_into().unwrap())
    }
}

impl TryFromInline<'_, GenId> for RawId {
    type Error = IdParseError;

    fn try_from_inline(value: &Inline<GenId>) -> Result<Self, Self::Error> {
        let r: Result<&RawId, IdParseError> = value.try_from_inline();
        r.copied()
    }
}

impl Encodes<RawId> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: RawId) -> Inline<GenId> {
        let mut data = [0; INLINE_LEN];
        data[16..32].copy_from_slice(&source[..]);
        Inline::new(data)
    }
}

impl Encodes<&RawId> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: &RawId) -> Inline<GenId> {
        <GenId as Encodes<RawId>>::encode(*source)
    }
}

//Id
impl<'a> TryFromInline<'a, GenId> for &'a Id {
    type Error = IdParseError;

    fn try_from_inline(value: &'a Inline<GenId>) -> Result<Self, Self::Error> {
        if value.raw[0..16] != [0; 16] {
            return Err(IdParseError::BadFormat);
        }
        if let Some(id) = Id::as_transmute_raw(value.raw[16..32].try_into().unwrap()) {
            Ok(id)
        } else {
            Err(IdParseError::IsNil)
        }
    }
}

impl TryFromInline<'_, GenId> for Id {
    type Error = IdParseError;

    fn try_from_inline(value: &Inline<GenId>) -> Result<Self, Self::Error> {
        let r: Result<&Id, IdParseError> = value.try_from_inline();
        r.copied()
    }
}

impl Encodes<&Id> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: &Id) -> Inline<GenId> {
        let mut data = [0; INLINE_LEN];
        data[16..32].copy_from_slice(&source[..]);
        Inline::new(data)
    }
}

impl Encodes<Id> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: Id) -> Inline<GenId> {
        (&source).to_inline()
    }
}

impl TryFromInline<'_, GenId> for uuid::Uuid {
    type Error = IdParseError;

    fn try_from_inline(value: &Inline<GenId>) -> Result<Self, Self::Error> {
        if value.raw[0..16] != [0; 16] {
            return Err(IdParseError::BadFormat);
        }
        let bytes: [u8; 16] = value.raw[16..32].try_into().unwrap();
        Ok(uuid::Uuid::from_bytes(bytes))
    }
}

/// Error returned when extracting an [`ExclusiveId`] from a [`Inline<GenId>`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExclusiveIdError {
    /// The raw bytes could not be interpreted as an identifier.
    FailedParse(IdParseError),
    /// The identifier is valid but could not be exclusively acquired
    /// (another holder already owns it).
    FailedAcquire(),
}

impl From<IdParseError> for ExclusiveIdError {
    fn from(e: IdParseError) -> Self {
        ExclusiveIdError::FailedParse(e)
    }
}

impl<'a> TryFromInline<'a, GenId> for ExclusiveId {
    type Error = ExclusiveIdError;

    fn try_from_inline(value: &'a Inline<GenId>) -> Result<Self, Self::Error> {
        let id: Id = value.try_from_inline()?;
        id.acquire().ok_or(ExclusiveIdError::FailedAcquire())
    }
}

impl Encodes<ExclusiveId> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: ExclusiveId) -> Inline<GenId> {
        source.id.to_inline()
    }
}

impl Encodes<&ExclusiveId> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: &ExclusiveId) -> Inline<GenId> {
        source.id.to_inline()
    }
}

impl TryFromInline<'_, GenId> for String {
    type Error = IdParseError;

    fn try_from_inline(v: &'_ Inline<GenId>) -> Result<Self, Self::Error> {
        let id: Id = v.try_from_inline()?;
        let mut s = String::new();
        s.push_str("genid:");
        s.push_str(&hex::encode(id));
        Ok(s)
    }
}

impl Encodes<OwnedId<'_>> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: OwnedId<'_>) -> Inline<GenId> {
        source.id.to_inline()
    }
}

impl Encodes<&OwnedId<'_>> for GenId {
    type Output = Inline<GenId>;
    fn encode(source: &OwnedId<'_>) -> Inline<GenId> {
        source.id.to_inline()
    }
}

/// Error returned when packing a string into a [`Inline<GenId>`].
///
/// The expected format is `"genid:<32 hex chars>"`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PackIdError {
    /// The string does not start with `"genid:"`.
    BadProtocol,
    /// The hex portion could not be decoded.
    BadHex(FromHexError),
}

impl From<FromHexError> for PackIdError {
    fn from(value: FromHexError) -> Self {
        PackIdError::BadHex(value)
    }
}

impl TryToInline<GenId> for &str {
    type Error = PackIdError;

    fn try_to_inline(self) -> Result<Inline<GenId>, Self::Error> {
        let protocol = "genid:";
        if !self.starts_with(protocol) {
            return Err(PackIdError::BadProtocol);
        }
        let id = RawId::from_hex(&self[protocol.len()..])?;
        Ok(id.to_inline())
    }
}

impl TryToInline<GenId> for uuid::Uuid {
    type Error = NilUuidError;

    fn try_to_inline(self) -> Result<Inline<GenId>, Self::Error> {
        let mut data = [0; INLINE_LEN];
        data[16..32].copy_from_slice(self.as_bytes());
        Ok(Inline::new(data))
    }
}

impl TryToInline<GenId> for &uuid::Uuid {
    type Error = NilUuidError;

    fn try_to_inline(self) -> Result<Inline<GenId>, Self::Error> {
        (*self).try_to_inline()
    }
}

#[cfg(feature = "proptest")]
/// Proptest value tree for a random [`GenId`]. Does not shrink.
pub struct IdValueTree(RawId);

#[cfg(feature = "proptest")]
/// Proptest strategy that generates random 128-bit identifiers.
#[derive(Debug)]
pub struct RandomGenId();
#[cfg(feature = "proptest")]
impl proptest::strategy::Strategy for RandomGenId {
    type Tree = IdValueTree;
    type Value = RawId;

    fn new_tree(
        &self,
        runner: &mut proptest::prelude::prop::test_runner::TestRunner,
    ) -> proptest::prelude::prop::strategy::NewTree<Self> {
        // Drawn through proptest's own `any` strategy rather than the runner's
        // rng trait: `fill_bytes` moved from `RngCore` (proptest 1.11, rand 0.9)
        // to `Rng` (1.12, rand 0.10), and the root Cargo.lock is untracked, so
        // a fresh resolve may pick either.
        use proptest::strategy::ValueTree;
        let id = proptest::prelude::any::<RawId>().new_tree(runner)?.current();

        Ok(IdValueTree(id))
    }
}

#[cfg(feature = "proptest")]
impl proptest::strategy::ValueTree for IdValueTree {
    type Value = RawId;

    fn simplify(&mut self) -> bool {
        false
    }
    fn complicate(&mut self) -> bool {
        false
    }
    fn current(&self) -> RawId {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::GenId;
    use crate::id::rngid;
    use crate::inline::InlineEncoding;
    use crate::inline::TryFromInline;
    use crate::inline::TryToInline;

    #[test]
    fn unique() {
        assert!(rngid() != rngid());
    }

    #[test]
    fn uuid_nil_round_trip() {
        let uuid = uuid::Uuid::nil();
        let value = uuid.try_to_inline().expect("uuid packing should succeed");
        GenId::validate(value).expect("schema validation");
        let round_trip =
            uuid::Uuid::try_from_inline(&value).expect("uuid unpacking should succeed");
        assert_eq!(uuid, round_trip);
    }
}
