use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Encodes;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::TryFromInline;
use crate::inline::TryToInline;
use crate::inline::INLINE_LEN;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

use std::convert::Infallible;

/// Error raised when a value does not match the [`Boolean`] encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBoolean;

/// Inline schema that stores boolean flags as either all-zero or all-one bit patterns.
///
/// Storing `false` as `0x00` and `true` as `0xFF` in every byte makes it trivial to
/// distinguish the two cases while leaving room for future SIMD optimisations when
/// scanning large collections of flags.
pub struct Boolean;

impl Boolean {
    fn encode(flag: bool) -> Inline<Self> {
        if flag {
            Inline::new([u8::MAX; INLINE_LEN])
        } else {
            Inline::new([0u8; INLINE_LEN])
        }
    }

    fn decode(value: &Inline<Self>) -> Result<bool, InvalidBoolean> {
        if value.raw.iter().all(|&b| b == 0) {
            Ok(false)
        } else if value.raw.iter().all(|&b| b == u8::MAX) {
            Ok(true)
        } else {
            Err(InvalidBoolean)
        }
    }
}

impl MetaDescribe for Boolean {
    fn describe() -> Fragment {
        let id: Id = id_hex!("73B414A3E25B0C0F9E4D6B0694DC33C5");
        #[allow(unused_mut)]
        let mut tribles = entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "boolean",
                metadata::description: "Boolean stored as all-zero bytes for false and all-0xFF bytes for true. The encoding uses the full 32-byte value, making the two states obvious and cheap to test.\n\nUse for simple flags and binary states. Represent unknown or missing data by omitting the trible rather than inventing a third sentinel value.\n\nMixed patterns are invalid and will fail validation. If you need tri-state or richer states, model it explicitly (for example with a GenId tag or a dedicated entity).",
                metadata::tag: metadata::KIND_INLINE_ENCODING,
        };

        #[cfg(feature = "wasm")]
        {
            tribles += entity! { ExclusiveId::force_ref(&id) @
                metadata::value_formatter: wasm_formatter::BOOLEAN_WASM,
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
    pub(crate) fn boolean(raw: &[u8; 32], out: &mut impl Write) -> Result<(), u32> {
        let all_zero = raw.iter().all(|&b| b == 0);
        let all_ones = raw.iter().all(|&b| b == u8::MAX);

        let text = if all_zero {
            "false"
        } else if all_ones {
            "true"
        } else {
            return Err(2);
        };

        out.write_str(text).map_err(|_| 1u32)?;
        Ok(())
    }
}

impl InlineEncoding for Boolean {
    type ValidationError = InvalidBoolean;
    type Encoding = Self;

    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        Self::decode(&value)?;
        Ok(value)
    }
}

impl<'a> TryFromInline<'a, Boolean> for bool {
    type Error = InvalidBoolean;

    fn try_from_inline(v: &'a Inline<Boolean>) -> Result<Self, Self::Error> {
        Boolean::decode(v)
    }
}

impl TryToInline<Boolean> for bool {
    type Error = Infallible;

    fn try_to_inline(self) -> Result<Inline<Boolean>, Self::Error> {
        Ok(Boolean::encode(self))
    }
}

impl TryToInline<Boolean> for &bool {
    type Error = Infallible;

    fn try_to_inline(self) -> Result<Inline<Boolean>, Self::Error> {
        Ok(Boolean::encode(*self))
    }
}

impl Encodes<bool> for Boolean {
    type Output = Inline<Boolean>;
    fn encode(source: bool) -> Inline<Boolean> {
        Boolean::encode(source)
    }
}

impl Encodes<&bool> for Boolean {
    type Output = Inline<Boolean>;
    fn encode(source: &bool) -> Inline<Boolean> {
        Boolean::encode(*source)
    }
}

#[cfg(test)]
mod tests {
    use super::Boolean;
    use super::InvalidBoolean;
    use crate::inline::Inline;
    use crate::inline::InlineEncoding;

    #[test]
    fn encodes_false_as_zero_bytes() {
        let value = Boolean::inline_from(false);
        assert!(value.raw.iter().all(|&b| b == 0));
        assert_eq!(Boolean::validate(value), Ok(Boolean::inline_from(false)));
    }

    #[test]
    fn encodes_true_as_all_ones() {
        let value = Boolean::inline_from(true);
        assert!(value.raw.iter().all(|&b| b == u8::MAX));
        assert_eq!(Boolean::validate(value), Ok(Boolean::inline_from(true)));
    }

    #[test]
    fn rejects_mixed_bit_patterns() {
        let mut mixed = [0u8; crate::inline::INLINE_LEN];
        mixed[0] = 1;
        let value = Inline::<Boolean>::new(mixed);
        assert_eq!(Boolean::validate(value), Err(InvalidBoolean));
    }
}
