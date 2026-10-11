#![cfg(kani)]
// ShortString is deprecated; its proof stays until the type is removed.
#![allow(deprecated)]

use crate::inline::encodings::money::Amount;
use crate::inline::encodings::money::Currency;
use crate::inline::encodings::money::Euro;
use crate::inline::encodings::shortstring::ShortString;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::TryFromInline;
use crate::inline::TryToInline;

#[kani::proof]
#[kani::unwind(33)]
fn short_string_roundtrip() {
    let raw: [u8; 32] = kani::any();
    let value: Inline<ShortString> = Inline::new(raw);
    kani::assume(value.is_valid());

    let s: &str = value.try_from_inline().unwrap();
    let roundtrip = ShortString::inline_from(s);
    assert_eq!(value, roundtrip);
}

/// Canonical form for [`Currency`]: every raw value that validates decodes to
/// an [`Amount`] that re-encodes to exactly those bytes.
///
/// This is the property the fixed global scale exists to guarantee. Because it
/// holds for *every* valid bit pattern, no amount has a second spelling, so
/// two facts asserting the same figure always derive the same intrinsic id and
/// byte order always coincides with the decoded order.
#[kani::proof]
#[kani::unwind(33)]
fn money_canonical_roundtrip() {
    let raw: [u8; 32] = kani::any();
    let value: Inline<Currency<Euro>> = Inline::new(raw);
    kani::assume(value.is_valid());

    let amount: Amount<Euro> = value.try_from_inline().unwrap();
    let roundtrip = amount.try_to_inline().unwrap();
    assert_eq!(value, roundtrip);
}
