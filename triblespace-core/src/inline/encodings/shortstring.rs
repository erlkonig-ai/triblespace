// ShortString is deprecated; its own module and conversion impls still
// have to name it until the type is removed.
#![allow(deprecated)]

use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Encodes;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::TryFromInline;
use crate::inline::TryToInline;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

use indxvec::Printing;
use std::str::Utf8Error;

/// An error that occurs when converting a string to a short string.
/// This error occurs when the string is too long or contains an interior NUL byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromStrError {
    /// The string exceeds 32 bytes when encoded as UTF-8.
    TooLong,
    /// The string contains a NUL byte, which is used as the terminator.
    InteriorNul,
}

/// Errors that can occur when validating a [`ShortString`] value.
#[derive(Debug)]
pub enum ValidationError {
    /// Non-zero bytes appear after the first NUL.
    InteriorNul,
    /// The byte sequence before the terminator is not valid UTF-8.
    Utf8(Utf8Error),
}

/// A inline encoding for a short string.
/// A short string is a UTF-8 encoded string with a maximum length of 32 bytes (inclusive)
/// The string is null-terminated.
/// If the string is shorter than 32 bytes, the remaining bytes are zero.
/// If the string is exactly 32 bytes, then there is no zero terminator.
///
/// Deprecated: the 32-byte ceiling made `entity!` panic on longer input and
/// pushed every caller into silent truncation or dropping. Declare text
/// attributes as [`Handle<UTF8String>`](crate::inline::encodings::hash::Handle)
/// instead. The type stays so that downstream crates keep compiling and old
/// rows remain decodable; it will be removed once nothing writes it.
#[deprecated(
    note = "ShortString is being removed: declare text attributes as Handle<UTF8String> (blob text). Old rows stay readable under their old attribute ids."
)]
pub struct ShortString;

impl MetaDescribe for ShortString {
    fn describe() -> Fragment {
        let id: Id = id_hex!("2D848DB0AF112DB226A6BF1A3640D019");
        #[allow(unused_mut)]
        let mut tribles = entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "shortstring",
                metadata::description: "UTF-8 string stored inline in 32 bytes with NUL termination and zero padding. Keeping the bytes inside the value makes the string sortable and queryable without an extra blob lookup.\n\nUse for short labels, enum-like names, and keys that must fit in the value boundary. For longer or variable text, store a UTF8String blob and reference it with a Handle.\n\nInterior NUL bytes are invalid and the maximum length is 32 bytes. The schema stores raw bytes, so it does not account for grapheme width or display columns.",
                metadata::tag: metadata::KIND_INLINE_ENCODING,
        };

        #[cfg(feature = "wasm")]
        {
            tribles += entity! { ExclusiveId::force_ref(&id) @
                metadata::value_formatter: wasm_formatter::SHORTSTRING_WASM,
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
    pub(crate) fn shortstring(raw: &[u8; 32], out: &mut impl Write) -> Result<(), u32> {
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());

        if raw[len..].iter().any(|&b| b != 0) {
            return Err(2);
        }

        let text = core::str::from_utf8(&raw[..len]).map_err(|_| 3u32)?;
        out.write_str(text).map_err(|_| 1u32)?;
        Ok(())
    }
}

impl InlineEncoding for ShortString {
    type ValidationError = ValidationError;
    type Encoding = Self;

    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        let raw = &value.raw;
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        // ensure all bytes after first NUL are zero
        if raw[len..].iter().any(|&b| b != 0) {
            return Err(ValidationError::InteriorNul);
        }
        std::str::from_utf8(&raw[..len]).map_err(ValidationError::Utf8)?;
        Ok(value)
    }
}

impl<'a> TryFromInline<'a, ShortString> for &'a str {
    type Error = Utf8Error;

    fn try_from_inline(v: &'a Inline<ShortString>) -> Result<&'a str, Self::Error> {
        let len = v.raw.iter().position(|&b| b == 0).unwrap_or(v.raw.len());
        #[cfg(kani)]
        {
            // Kani spends significant time unwinding the UTF-8 validation loop.
            // Bounding `len` to 32 keeps the verifier from exploring unrealistic
            // larger values, reducing runtime from minutes to seconds.
            kani::assume(len <= 32);
        }
        std::str::from_utf8(&v.raw[..len])
    }
}

impl<'a> TryFromInline<'a, ShortString> for String {
    type Error = Utf8Error;

    fn try_from_inline(v: &Inline<ShortString>) -> Result<Self, Self::Error> {
        let s: &str = v.try_from_inline()?;
        Ok(s.to_string())
    }
}

impl TryToInline<ShortString> for &str {
    type Error = FromStrError;

    fn try_to_inline(self) -> Result<Inline<ShortString>, Self::Error> {
        let bytes = self.as_bytes();
        if bytes.len() > 32 {
            return Err(FromStrError::TooLong);
        }
        if bytes.contains(&0) {
            return Err(FromStrError::InteriorNul);
        }

        let mut data: [u8; 32] = [0; 32];
        data[..bytes.len()].copy_from_slice(bytes);

        Ok(Inline::new(data))
    }
}

impl TryToInline<ShortString> for String {
    type Error = FromStrError;

    fn try_to_inline(self) -> Result<Inline<ShortString>, Self::Error> {
        (&self[..]).try_to_inline()
    }
}

impl Encodes<&str> for ShortString {
    type Output = Inline<ShortString>;
    fn encode(source: &str) -> Inline<ShortString> {
        source.try_to_inline().unwrap()
    }
}

impl Encodes<String> for ShortString {
    type Output = Inline<ShortString>;
    fn encode(source: String) -> Inline<ShortString> {
        source.try_to_inline().unwrap()
    }
}

impl Encodes<&String> for ShortString {
    type Output = Inline<ShortString>;
    fn encode(source: &String) -> Inline<ShortString> {
        source.to_str().try_to_inline().unwrap()
    }
}
