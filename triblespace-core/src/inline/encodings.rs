//! This is a collection of Rust types that can be (de)serialized as [crate::prelude::Inline]s.

/// Boolean inline encoding (all-zero / all-one).
pub mod boolean;
/// Ed25519 signature component and public key encodings.
pub mod ed25519;
/// 256-bit IEEE-like floating point encodings (little-endian and big-endian).
pub mod f256;
/// IEEE-754 double-precision floating point encoding.
pub mod f64;
/// Opaque 128-bit identifier encoding.
pub mod genid;
/// Cryptographic hash and typed blob handle encodings.
pub mod hash;
/// 256-bit signed and unsigned integer encodings (little-endian and big-endian).
pub mod iu256;
/// Line/column source location encoding.
pub mod linelocation;
/// Exact monetary amounts, with the currency carried by the encoding's type.
pub mod money;
/// 256-bit rational number encodings (little-endian and big-endian).
pub mod r256;
/// Range encodings for pairs of `u128` values.
pub mod range;
/// Order-preserving exact rational encoding (bytes sort numerically).
pub mod rord256;
/// Inline UTF-8 short string encoding (up to 32 bytes).
pub mod shortstring;
/// Socket address (IP address and port) encoding.
pub mod socketaddr;
/// TAI nanosecond interval encoding.
pub mod time;

use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;
use std::convert::Infallible;

/// An inline encoding for unknown values.
///
/// Fallback when the encoding of an inline value isn't known. Not
/// recommended for everyday use — prefer a specific encoding.
///
/// Any bit pattern is a valid `Inline<UnknownInline>`.
pub struct UnknownInline {}

impl MetaDescribe for UnknownInline {
    fn describe() -> Fragment {
        let id: Id = id_hex!("4EC697E8599AC79D667C722E2C8BEBF4");
        #[allow(unused_mut)]
        let mut tribles = entity! {
            ExclusiveId::force_ref(&id) @ metadata::tag: metadata::KIND_INLINE_ENCODING
        };
        #[cfg(feature = "wasm")]
        {
            tribles += entity! { ExclusiveId::force_ref(&id) @
                metadata::value_formatter: wasm_formatter::UNKNOWN_VALUE_WASM,
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
    pub(crate) fn unknown_value(raw: &[u8; 32], out: &mut impl Write) -> Result<(), u32> {
        out.write_str("unknown:").map_err(|_| 1u32)?;
        const TABLE: &[u8; 16] = b"0123456789ABCDEF";
        for &byte in raw {
            let hi = (byte >> 4) as usize;
            let lo = (byte & 0x0F) as usize;
            out.write_char(TABLE[hi] as char).map_err(|_| 1u32)?;
            out.write_char(TABLE[lo] as char).map_err(|_| 1u32)?;
        }
        Ok(())
    }
}

impl InlineEncoding for UnknownInline {
    type ValidationError = Infallible;
    type Encoding = Self;

    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        Ok(value)
    }
}
