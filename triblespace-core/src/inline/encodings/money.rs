//! Exact monetary amounts, denominated by their type.
//!
//! [`Currency<C>`] is one encoding per currency: `Currency<Euro>` and
//! `Currency<UsDollar>` are different encodings with different ids, so an
//! attribute holding euros and an attribute holding dollars are different
//! attributes even when they share a name and an anchor. Mixing them is not a
//! runtime check that a reader might skip — it does not typecheck, and the two
//! do not meet in a query.
//!
//! The value is an exact rational in [`ROrd256`]'s encoding, so a money value
//! carries no chosen scale at all: €1.50 is `3/2`, exactly, and there is no
//! constant anywhere that a later decision could invalidate. See [`Currency`]
//! for the reasoning and the costs, and [`CurrencyUnit`] for how to declare a
//! currency of your own.

use crate::blob::encodings::utf8string::UTF8String;
use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::iu256::U256BE;
use crate::inline::encodings::rord256::OrderedRatioError;
use crate::inline::encodings::rord256::ROrd256;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::TryFromInline;
use crate::inline::TryToInline;
use crate::macros::attributes;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::trible::Fragment;

use num_rational::Ratio;
use num_traits::CheckedAdd;
use num_traits::CheckedMul;
use num_traits::CheckedSub;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

/// The namespace this encoding family derives its per-currency ids under.
///
/// Minted with `trible genid` on 2026-08-13. It participates in the derived
/// identity rather than replacing it — exactly as [`metadata::anchor`] does for
/// attributes — so a future sibling encoding for the same currency takes a
/// different anchor and cannot collide with this one.
const CURRENCY_ANCHOR: Id = id_hex!("51D01773A3AF0A26A936C56B3A95A9F0");

attributes! {
    /// The alphabetic code of the currency a [`Currency<C>`] encoding is
    /// denominated in — identity-determining, so it is what makes one
    /// currency's encoding a different encoding from another's.
    ///
    /// Anyone who declares a [`CurrencyUnit`] with the same code derives the
    /// same encoding id and therefore the same attribute ids, with no
    /// coordination: two codebases that both declare EUR interoperate without
    /// having agreed on anything.
    "CE4138C8D49DE483673E21822D63E6C4" as pub code: Handle<UTF8String>;
    /// The exponent of a currency's customary minor unit — 2 for EUR, 0 for
    /// JPY, 8 for BTC.
    ///
    /// An annotation, deliberately *not* part of identity: it is a
    /// presentation convention, and if two writers disagreed about one the
    /// pile should hold both claims about one currency rather than fork into
    /// two currencies whose amounts no longer meet.
    "3B3C14395D9BCD5DFB0E63485E073FAB" as pub minor_units: U256BE;
}

// ── currencies ───────────────────────────────────────────────────────────

/// A currency, as a type.
///
/// Implement it on a unit struct to get a [`Currency<C>`] encoding for a
/// currency this crate does not ship:
///
/// ```
/// use triblespace_core::inline::encodings::money::{Currency, CurrencyUnit};
///
/// /// The Norwegian krone.
/// pub struct NorwegianKrone;
/// impl CurrencyUnit for NorwegianKrone {
///     const CODE: &'static str = "NOK";
///     const MINOR_UNITS: u32 = 2;
/// }
///
/// type Nok = Currency<NorwegianKrone>;
/// ```
///
/// The trait carries facts about the currency and nothing else. The code and
/// the minor-unit exponent are properties of the currency itself; symbol
/// placement, digit grouping and locale are properties of a *rendering*, and
/// they do not belong in a substrate encoding.
pub trait CurrencyUnit: 'static {
    /// The ISO&nbsp;4217 alphabetic code, or a registry-free ticker for a unit
    /// the registry does not cover.
    ///
    /// This is the currency's identity here, so two declarations that agree on
    /// the code agree on everything that matters. Codes are conventionally
    /// three uppercase letters; nothing enforces that, because the enforcing
    /// table would be a copy of a registry that changes without asking this
    /// crate — and because a ticker the registry has never heard of should
    /// cost four lines rather than a release of this crate. It is stored as
    /// `UTF8String` text, so there is no length ceiling.
    const CODE: &'static str;

    /// The exponent of the currency's customary minor unit: 2 for EUR (cents),
    /// 0 for JPY, 8 for BTC (satoshi), 18 for ETH (wei).
    ///
    /// Storage never uses this — the stored value is an exact rational with no
    /// scale at all. It is what [`Display`](fmt::Display) pads *to* (never
    /// truncates to), so `1.00 EUR` and `5 JPY` both come out right, and what
    /// [`Amount::from_minor`] counts in.
    const MINOR_UNITS: u32;
}

/// Declare the currencies this crate ships. Each is just a marker type.
macro_rules! currencies {
    ($($(#[$doc:meta])* $name:ident = $code:literal / $minor:literal;)*) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name;

            impl CurrencyUnit for $name {
                const CODE: &'static str = $code;
                const MINOR_UNITS: u32 = $minor;
            }
        )*
    };
}

currencies! {
    /// The euro (EUR).
    Euro = "EUR" / 2;
    /// The United States dollar (USD).
    UsDollar = "USD" / 2;
    /// Sterling (GBP).
    PoundSterling = "GBP" / 2;
    /// The Swiss franc (CHF).
    SwissFranc = "CHF" / 2;
    /// The Japanese yen (JPY), which has no minor unit.
    Yen = "JPY" / 0;
    /// Bitcoin (BTC), whose minor unit is the satoshi.
    Bitcoin = "BTC" / 8;
    /// Ether (ETH), whose minor unit is the wei.
    Ether = "ETH" / 18;
}

// ── amount ───────────────────────────────────────────────────────────────

/// An exact amount of money in currency `C`.
///
/// The amount is a [`Ratio<i128>`], so `Amount::<Euro>::from_minor(150)` is
/// €1.50 held as `3/2` — not as a count of some chosen unit. There is no float
/// anywhere in this type or its encoding: binary floats cannot represent `0.1`,
/// and widening them only moves the discrepancy.
///
/// `Amount<Euro>` and `Amount<UsDollar>` are different types, so adding them
/// is a compile error rather than a runtime check. That is why the arithmetic
/// here needs no currency-mismatch error at all.
pub struct Amount<C> {
    ratio: Ratio<i128>,
    currency: PhantomData<fn() -> C>,
}

impl<C> Amount<C> {
    /// The zero amount.
    pub const ZERO: Self = Self {
        ratio: Ratio::new_raw(0, 1),
        currency: PhantomData,
    };

    /// Build an amount from an exact rational.
    ///
    /// Whether it can be *stored* is checked at encode time, not here: the
    /// representable subset is [`ROrd256`]'s, and the answer is a typed
    /// [`OrderedRatioError`] rather than a rounded value.
    pub fn from_ratio(ratio: Ratio<i128>) -> Self {
        Self {
            ratio,
            currency: PhantomData,
        }
    }

    /// The amount as an exact rational, always reduced with a positive
    /// denominator.
    pub fn ratio(&self) -> Ratio<i128> {
        self.ratio
    }

    /// Add two amounts.
    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.combine(other, |left, right| left.checked_add(&right))
    }

    /// Subtract one amount from another.
    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.combine(other, |left, right| left.checked_sub(&right))
    }

    /// Negate the amount.
    pub fn checked_neg(self) -> Result<Self, AmountError> {
        Ok(Self::from_ratio(
            Ratio::new_raw(0, 1)
                .checked_sub(&self.ratio)
                .ok_or(AmountError::Overflow)?,
        ))
    }

    /// Multiply by an integer quantity — a line item's count.
    pub fn checked_mul_int(self, factor: i128) -> Result<Self, AmountError> {
        self.checked_mul_ratio(Ratio::from_integer(factor))
    }

    /// Apply an exact rate: a VAT percentage, a discount, an allocation
    /// fraction.
    ///
    /// This is the operation the rational form buys. `total * Ratio::new(19,
    /// 100)` is the VAT on a net figure with no rounding anywhere, so the
    /// intermediate carries its full value and rounding happens once, when the
    /// figure is put on a document — which is the caller's decision, and the
    /// only place it belongs.
    pub fn checked_mul_ratio(self, rate: Ratio<i128>) -> Result<Self, AmountError> {
        Ok(Self::from_ratio(
            self.ratio.checked_mul(&rate).ok_or(AmountError::Overflow)?,
        ))
    }

    fn combine(
        self,
        other: Self,
        op: fn(Ratio<i128>, Ratio<i128>) -> Option<Ratio<i128>>,
    ) -> Result<Self, AmountError> {
        Ok(Self::from_ratio(
            op(self.ratio, other.ratio).ok_or(AmountError::Overflow)?,
        ))
    }
}

impl<C: CurrencyUnit> Amount<C> {
    /// Build an amount from an integer at some source scale, exactly.
    ///
    /// `from_units(150, 2)` is €1.50 and `from_units(12, 0)` is €12. This is
    /// the ingest path: databases store money as an integer plus a column
    /// scale, and `units / 10^scale` is that value exactly, with no rounding
    /// and — unlike a fixed-point encoding — no widening onto a chosen scale
    /// either. The scale is consumed here and never stored.
    pub fn from_units(units: i128, scale: u32) -> Result<Self, AmountError> {
        let divisor = 10i128.checked_pow(scale).ok_or(AmountError::Scale)?;
        Ok(Self::from_ratio(Ratio::new(units, divisor)))
    }

    /// Build an amount from a count of the currency's own minor unit: cents
    /// for EUR, whole yen for JPY, satoshi for BTC.
    pub fn from_minor(minor: i128) -> Result<Self, AmountError> {
        Self::from_units(minor, C::MINOR_UNITS)
    }

    /// Recover an integer at `scale`, exactly, or fail.
    ///
    /// Returns [`AmountError::Inexact`] when the amount is not a whole number
    /// of `10^-scale` units — which now includes the genuinely non-decimal
    /// amounts a rational can hold, such as a third of a euro.
    pub fn to_units(&self, scale: u32) -> Result<i128, AmountError> {
        let factor = 10i128.checked_pow(scale).ok_or(AmountError::Scale)?;
        let scaled = self
            .ratio
            .checked_mul(&Ratio::from_integer(factor))
            .ok_or(AmountError::Overflow)?;
        if !scaled.is_integer() {
            return Err(AmountError::Inexact);
        }
        Ok(scaled.to_integer())
    }

    /// Recover a count of the currency's own minor unit, exactly, or fail.
    pub fn to_minor(&self) -> Result<i128, AmountError> {
        self.to_units(C::MINOR_UNITS)
    }
}

// `derive` would demand `C: Clone`/`C: Ord`/… of the marker type, which is a
// phantom and never touched. These are the same impls without the bound.
impl<C> Clone for Amount<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Amount<C> {}

impl<C> PartialEq for Amount<C> {
    fn eq(&self, other: &Self) -> bool {
        self.ratio == other.ratio
    }
}

impl<C> Eq for Amount<C> {}

impl<C> PartialOrd for Amount<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<C> Ord for Amount<C> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ratio.cmp(&other.ratio)
    }
}

impl<C> std::hash::Hash for Amount<C> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ratio.hash(state);
    }
}

impl<C: CurrencyUnit> fmt::Debug for Amount<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Amount<{}>({}/{})",
            C::CODE,
            self.ratio.numer(),
            self.ratio.denom()
        )
    }
}

/// How many decimal places `denom` needs, if it needs finitely many.
///
/// A reduced fraction terminates as a decimal exactly when its denominator is
/// `2^a · 5^b`, and then it needs `max(a, b)` places.
fn decimal_places(denom: i128) -> Option<u32> {
    let mut rest = denom;
    let mut twos = 0;
    let mut fives = 0;
    while rest % 2 == 0 {
        rest /= 2;
        twos += 1;
    }
    while rest % 5 == 0 {
        rest /= 5;
        fives += 1;
    }
    (rest == 1).then(|| twos.max(fives))
}

impl<C: CurrencyUnit> fmt::Display for Amount<C> {
    /// Render exactly, never through a float and never rounded.
    ///
    /// An amount whose denominator is a product of 2s and 5s has a finite
    /// decimal expansion, and it is written that way, padded to the currency's
    /// own minor unit (`1.50 EUR`, `5 JPY`) and *extended* past it whenever the
    /// value needs more digits (`1.505 EUR`). An amount that has no finite
    /// decimal — a third of a euro, say, which this encoding can hold and a
    /// fixed-point one cannot — is written as a fraction, `1/3 EUR`, because
    /// the alternative is to lie about it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let numer = *self.ratio.numer();
        let denom = *self.ratio.denom();
        let currency_code = C::CODE;

        let decimal = decimal_places(denom).and_then(|needed| {
            let places = needed.max(C::MINOR_UNITS);
            let factor = 10i128.checked_pow(places)?.checked_div(denom)?;
            let scaled = numer.checked_mul(factor)?;
            Some((scaled, places))
        });

        let Some((scaled, places)) = decimal else {
            return write!(formatter, "{numer}/{denom} {currency_code}");
        };

        let sign = if scaled < 0 { "-" } else { "" };
        let digits = scaled.unsigned_abs().to_string();
        if places == 0 {
            return write!(formatter, "{sign}{digits} {currency_code}");
        }
        let places = places as usize;
        let padded = if digits.len() <= places {
            format!("{:0>width$}", digits, width = places + 1)
        } else {
            digits
        };
        let split = padded.len() - places;
        write!(
            formatter,
            "{sign}{}.{} {currency_code}",
            &padded[..split],
            &padded[split..]
        )
    }
}

impl<C: CurrencyUnit> FromStr for Amount<C> {
    type Err = AmountError;

    /// Parse the inverse of [`Display`](fmt::Display): a figure, a space, and
    /// the currency's code. The figure may be a decimal (`1.50 EUR`, and any
    /// number of places) or a fraction (`1/3 EUR`).
    ///
    /// A code that is not `C::CODE` is [`AmountError::Currency`]: the target
    /// type says which currency this is, and text claiming another one is
    /// wrong rather than convertible.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let (figure, parsed) = text.rsplit_once(' ').ok_or(AmountError::Syntax)?;
        if parsed.trim() != C::CODE {
            return Err(AmountError::Currency);
        }
        Ok(Self::from_ratio(parse_figure(figure.trim())?))
    }
}

fn parse_figure(figure: &str) -> Result<Ratio<i128>, AmountError> {
    if let Some((numer, denom)) = figure.split_once('/') {
        let numer: i128 = numer.trim().parse().map_err(|_| AmountError::Syntax)?;
        let denom: i128 = denom.trim().parse().map_err(|_| AmountError::Syntax)?;
        if denom == 0 {
            return Err(AmountError::Syntax);
        }
        return Ok(Ratio::new(numer, denom));
    }

    let (negative, digits) = match figure.as_bytes().first() {
        Some(b'-') => (true, &figure[1..]),
        Some(b'+') => (false, &figure[1..]),
        _ => (false, figure),
    };
    let (integral, fractional) = match digits.split_once('.') {
        Some((integral, fractional)) => (integral, fractional),
        None => (digits, ""),
    };
    if integral.is_empty() || digits.ends_with('.') {
        return Err(AmountError::Syntax);
    }

    let mut magnitude: i128 = 0;
    for byte in integral.bytes().chain(fractional.bytes()) {
        if !byte.is_ascii_digit() {
            return Err(AmountError::Syntax);
        }
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(i128::from(byte - b'0')))
            .ok_or(AmountError::Overflow)?;
    }
    let denom = 10i128
        .checked_pow(u32::try_from(fractional.len()).map_err(|_| AmountError::Scale)?)
        .ok_or(AmountError::Scale)?;
    if negative {
        magnitude = magnitude.checked_neg().ok_or(AmountError::Overflow)?;
    }
    Ok(Ratio::new(magnitude, denom))
}

// ── errors ───────────────────────────────────────────────────────────────

/// Why an [`Amount`] could not be built, converted, or parsed.
///
/// Storing an amount fails with [`OrderedRatioError`] instead — that is
/// [`ROrd256`]'s own error, deliberately not wrapped, so a caller sees exactly
/// which of the encoding's conditions it hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// The text names a different currency than the target type.
    Currency,
    /// The scale has no `i128` power of ten.
    Scale,
    /// An intermediate exceeded `i128`.
    Overflow,
    /// The amount is not a whole number of the requested unit — including the
    /// non-decimal amounts a rational can hold and a fixed-point form cannot.
    Inexact,
    /// The text is not a figure followed by a currency code.
    Syntax,
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Currency => formatter.write_str("text names a different currency"),
            Self::Scale => formatter.write_str("scale has no i128 power of ten"),
            Self::Overflow => formatter.write_str("amount exceeds i128"),
            Self::Inexact => formatter.write_str("amount is not a whole number of that unit"),
            Self::Syntax => formatter.write_str("expected a figure and a currency code"),
        }
    }
}

impl std::error::Error for AmountError {}

// ── the encoding ─────────────────────────────────────────────────────────

/// An inline encoding for an exact [`Amount`] of the currency `C`.
///
/// # Example
///
/// ```
/// use triblespace_core::inline::encodings::money::{Amount, Currency, Euro, UsDollar};
/// use triblespace_core::inline::TryToInline;
/// use triblespace_core::metadata::MetaDescribe;
/// use num_rational::Ratio;
///
/// let price = Amount::<Euro>::from_minor(150).expect("valid scale"); // €1.50
/// assert_eq!(price.to_string(), "1.50 EUR");
/// assert_eq!(price.ratio(), Ratio::new(3, 2)); // no scale, just the value
///
/// let value = price.try_to_inline().expect("in domain");
///
/// // One encoding per currency, so one anchored attribute name gives one
/// // attribute id per currency — nothing is minted per currency.
/// assert_ne!(Currency::<Euro>::id(), Currency::<UsDollar>::id());
/// ```
///
/// ```
/// use triblespace_core::attribute::Attribute;
/// use triblespace_core::id::Id;
/// use triblespace_core::id_hex;
/// use triblespace_core::inline::encodings::money::{Currency, Euro, UsDollar};
///
/// // Minted once with `trible genid`; the currency does the rest.
/// const TOTAL: Id = id_hex!("251C2B673AE7F49F7374866925D4F7D7");
/// let euros = Attribute::<Currency<Euro>>::anchored(TOTAL);
/// let dollars = Attribute::<Currency<UsDollar>>::anchored(TOTAL);
/// assert_ne!(euros.id(), dollars.id());
/// ```
///
/// # The value is a rational, so there is no scale to get wrong
///
/// The obvious encoding for money is a fixed-point integer: pick a scale, count
/// units of `10⁻ˢᶜᵃˡᵉ`. It works, and it hides a decision. Whatever scale is
/// picked is a constant that every stored value depends on, that has to be
/// right for every currency and every future use — sub-cent unit prices, an
/// eighteen-decimal crypto denomination — and that cannot be revised without
/// rewriting every amount ever written, because the same figure at a different
/// scale is a different byte string and therefore a different intrinsic id.
///
/// A rational has no such constant. €1.50 is `3/2`; €1.505 is `301/200`; a
/// third of a euro is `1/3`, which no fixed-point encoding can hold at all. The
/// question "is 18 places enough, or 4, or 36?" simply does not arise, and
/// there is no migration hiding behind a later answer to it.
///
/// Exactness is the other half. Every value is stored reduced, so one amount
/// has exactly one byte string and merge, equality and intrinsic ids all agree
/// — the same canonical-form property a fixed global scale was buying, obtained
/// here from the number itself rather than from a convention about it.
///
/// # …and it still sorts
///
/// Using [`ROrd256`] rather than [`R256`](super::r256::R256) is what makes that
/// free. `R256` stores numerator and denominator side by side, so its bytes
/// sort by numerator first and `1/1` lands below `2/3`; index ranges over such
/// a column are not value ranges. `ROrd256` stores the canonical continued
/// fraction in an order-preserving code, so plain bytewise comparison — which
/// is what the indexes do — *is* numeric comparison. "Invoices over €10,000"
/// is an index range, and the answer is exact rather than float-keyed.
///
/// Ordering was not, in the end, the reason to choose this: at the scale of a
/// working accounting database a linear filter over a hundred thousand rows is
/// milliseconds, and index acceleration only starts to matter in the millions.
/// It is simply that with `ROrd256` available there is no trade to make.
///
/// # What it costs
///
/// Encoding is a continued-fraction expansion rather than a byte copy —
/// hundreds of nanoseconds against a few, though still an order of magnitude
/// below the surrounding I/O for any real ingest. Decoding and comparison are
/// unaffected: comparison is a byte compare, which is the operation queries
/// actually perform.
///
/// The representable subset is bounded and, unlike a fixed-scale integer's,
/// *data-dependent*: cost is roughly `2·log2(max(|p|, q))` bits, so every
/// `p/q` with `max(|p|, q) ≤ 2^104` is guaranteed to fit and wider values are
/// rejected — with a typed [`OrderedRatioError::OutOfDomain`], never rounded
/// silently. For money this is a wide margin rather than a tight one, because
/// decimal money reduces to a small denominator: a two-decimal amount is
/// `p/100` at worst, and the numerator would have to reach 10³¹ before the
/// guarantee stopped applying. The check that matters is on the *source*
/// column, not on today's values — a 64-bit money column at three decimal
/// places cannot produce anything outside the guarantee, with 44 bits to spare.
/// Ingest code should still surface the error rather than unwrap it.
///
/// # The currency is in the encoding, not in the value
///
/// A trible is (entity, attribute, value), so the attribute is always present
/// when the value is: the currency does not have to be repeated in every
/// amount to be known. Putting it in the type instead buys three things.
///
/// Adding euros to dollars stops being a mistake a reader can make: they are
/// different encodings, hence different attribute ids, hence they never meet
/// in a query. The value stays a plain number with no prefix to skip, which is
/// what lets it be an `ROrd256` payload unchanged. And the per-currency
/// identity is *derived*, so one anchored attribute name gives you
/// `total: Currency<Euro>` and `total: Currency<UsDollar>` as two ids without
/// minting anything per currency.
///
/// The cost is real and worth stating: a query that spans currencies has to
/// name each one, with an `or!` across attributes. Since adding EUR to USD
/// without a conversion rate is meaningless anyway, that is a sum you should
/// have to write out — but you do have to write it out.
///
/// # A zeroed buffer cannot pass for money
///
/// The all-zero byte string is not a valid encoding: it is rejected as
/// [`OrderedRatioError::NonCanonical`], because a continued fraction's term
/// codes are self-delimiting and an all-zero bit string does not form one.
/// Zero is `0x80` followed by zeros, not all zeros. So an uninitialised or
/// accidentally zeroed value fails loudly instead of decoding as some
/// extreme amount — with no niche carved out for it, and nothing to remember.
///
/// # What this encoding is deliberately not
///
/// Not a float, at any width. Binary floats cannot represent `0.1`; extra
/// width only moves the discrepancy.
///
/// Not an interval. Money that has been through a currency conversion is
/// genuinely bounded rather than exact and deserves `[low, high]` — but an
/// ingested figure is exact, and a VAT split or an allocation is now exact too,
/// because a rational multiplied by a rate is still a rational. What is left
/// for an interval is narrow, and it belongs in an additive sibling encoding
/// under its own anchor rather than in this one.
///
/// Rounding, finally, is still the caller's. A rational can carry `19/300` of a
/// euro exactly, but the figure that is legally owed is the rounded one printed
/// on the invoice. This encoding lets the intermediate stay exact so that
/// rounding happens once, deliberately, where the document is produced —
/// rather than silently, at every step, because the storage could not hold the
/// value.
pub struct Currency<C> {
    currency: PhantomData<fn() -> C>,
}

impl<C: CurrencyUnit> MetaDescribe for Currency<C> {
    fn describe() -> Fragment {
        // Intrinsic core: no `@`, so the id is derived from these facts. The
        // anchor scopes the family and the code separates the currencies, so
        // any two declarations that agree on the code agree on the id.
        let mut core = entity! {
            metadata::anchor: CURRENCY_ANCHOR,
            code: C::CODE,
            metadata::tag: metadata::KIND_INLINE_ENCODING,
        };
        let id = core.root().expect("rooted");
        let id_ref = ExclusiveId::force_ref(&id);
        let currency_code = C::CODE;
        core += entity! { id_ref @
            metadata::name: format!("currency/{currency_code}"),
            minor_units: u64::from(C::MINOR_UNITS),
            metadata::description: format!(
                "Exact monetary amount in {currency_code}, stored as an exact rational in the ROrd256 encoding: the canonical continued fraction, whose bytes sort in numeric order under plain bytewise comparison. There is no decimal scale anywhere — 1.50 is 3/2 — so no stored value depends on a chosen constant, and a value with no finite decimal expansion is held exactly rather than rounded.\n\nUse for every {currency_code} figure — prices, totals, balances, unit prices, and the results of applying a VAT rate or an allocation fraction, which stay exact. Never encode money as a float: binary floats cannot represent 0.1 and extra width only moves the discrepancy. The currency lives in the encoding rather than in the value, so amounts in different currencies are different attributes and cannot be summed by accident.\n\nOne amount has exactly one byte string, so merge, equality and intrinsic ids all agree, and byte order is numeric order, so ordered indexes answer range queries directly. Values wider than the ROrd256 domain (roughly max(|numerator|, denominator) above 2^104) are rejected rather than rounded. The all-zero byte string is not a valid encoding, so a zeroed buffer fails loudly."
            ),
        };

        #[cfg(feature = "wasm")]
        {
            // The same formatter ROrd256 uses: the payload is byte-identical,
            // so re-deriving one would only be a second copy to keep in step.
            core += entity! { id_ref @
                metadata::value_formatter:
                    crate::inline::encodings::rord256::wasm_formatter::RORD256_WASM,
            };
        }
        core
    }
}

impl<C: CurrencyUnit> InlineEncoding for Currency<C> {
    type ValidationError = OrderedRatioError;
    type Encoding = Self;

    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        ROrd256::validate(value.transmute())?;
        Ok(value)
    }
}

impl<C: CurrencyUnit> TryToInline<Currency<C>> for Amount<C> {
    type Error = OrderedRatioError;

    fn try_to_inline(self) -> Result<Inline<Currency<C>>, Self::Error> {
        Ok(self.ratio.try_to_inline()?.transmute())
    }
}

impl<C: CurrencyUnit> TryFromInline<'_, Currency<C>> for Amount<C> {
    type Error = OrderedRatioError;

    fn try_from_inline(value: &Inline<Currency<C>>) -> Result<Self, Self::Error> {
        let inner: Inline<ROrd256> = value.transmute();
        Ok(Self::from_ratio(Ratio::try_from_inline(&inner)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline::INLINE_LEN;
    use proptest::prelude::*;

    /// A second, independent declaration of the euro — what another codebase
    /// would write without having coordinated with this one.
    struct AlsoTheEuro;
    impl CurrencyUnit for AlsoTheEuro {
        const CODE: &'static str = "EUR";
        // Deliberately disagreeing about presentation.
        const MINOR_UNITS: u32 = 4;
    }

    fn inline<C: CurrencyUnit>(amount: Amount<C>) -> Inline<Currency<C>> {
        amount.try_to_inline().expect("in domain")
    }

    fn ratio<C: CurrencyUnit>(numer: i128, denom: i128) -> Amount<C> {
        Amount::from_ratio(Ratio::new(numer, denom))
    }

    // ── identity ─────────────────────────────────────────────────────────

    /// The property the parameterisation exists for: one encoding per
    /// currency, so one attribute name gives one id per currency.
    #[test]
    fn each_currency_is_its_own_encoding() {
        assert_ne!(Currency::<Euro>::id(), Currency::<UsDollar>::id());
        assert_ne!(Currency::<Euro>::id(), Currency::<Yen>::id());
        assert_ne!(Currency::<Bitcoin>::id(), Currency::<Ether>::id());
        // …and distinct from the bare rational encoding it borrows its layout
        // from, so money and unitless rationals never share an attribute.
        assert_ne!(Currency::<Euro>::id(), ROrd256::id());
    }

    /// …and the property that makes it usable without coordination: identity
    /// is derived from the code, so an independent declaration of the same
    /// currency lands on the same id — even when it disagrees about the
    /// presentation convention, which is annotation rather than identity.
    #[test]
    fn independent_declarations_of_one_currency_agree() {
        assert_eq!(Currency::<Euro>::id(), Currency::<AlsoTheEuro>::id());
    }

    /// One anchor, one attribute name, a different id per currency — no
    /// per-currency minting and no combinatorial explosion.
    #[test]
    fn one_anchor_yields_one_attribute_per_currency() {
        use crate::attribute::Attribute;

        // Minted with `trible genid` on 2026-08-13 for this test.
        const ANCHOR: Id = id_hex!("251C2B673AE7F49F7374866925D4F7D7");
        let euros = Attribute::<Currency<Euro>>::anchored(ANCHOR);
        let dollars = Attribute::<Currency<UsDollar>>::anchored(ANCHOR);
        assert_ne!(euros.id(), dollars.id());
        assert_eq!(
            euros.id(),
            Attribute::<Currency<AlsoTheEuro>>::anchored(ANCHOR).id()
        );
    }

    // ── canonical form ───────────────────────────────────────────────────

    /// One amount, one byte string, no matter which scale it arrived at — and
    /// now with no stored scale for it to arrive *onto*.
    #[test]
    fn canonical_form_is_independent_of_source_scale() {
        let expected = inline(ratio::<Euro>(3, 2)).raw;
        for (units, scale) in [
            (150i128, 2u32),
            (1_500, 3),
            (15_000, 4),
            (1_500_000_000_000, 12),
            (1_500_000_000_000_000_000, 18),
        ] {
            let amount = Amount::<Euro>::from_units(units, scale).expect("valid scale");
            assert_eq!(amount.ratio(), Ratio::new(3, 2), "scale {scale} disagreed");
            assert_eq!(inline(amount).raw, expected, "scale {scale} disagreed");
        }
        assert_eq!(
            inline(Amount::<Euro>::from_minor(150).expect("valid scale")).raw,
            expected
        );
    }

    /// The stored value is the number, not a representation of it.
    #[test]
    fn there_is_no_scale_in_the_value() {
        // A third of a euro is exact here, and has no fixed-point spelling.
        let third = ratio::<Euro>(1, 3);
        let round_tripped = Amount::try_from_inline(&inline(third)).expect("valid");
        assert_eq!(round_tripped.ratio(), Ratio::new(1, 3));
        assert_eq!(third.to_string(), "1/3 EUR");
        assert_eq!(third.to_units(2), Err(AmountError::Inexact));
    }

    // ── round trip ───────────────────────────────────────────────────────

    #[test]
    fn extremes_round_trip() {
        for (numer, denom) in [
            (0i128, 1i128),
            (1, 1),
            (-1, 1),
            (i128::MAX, 1),
            (i128::MIN + 1, 1),
            (1, i128::MAX),
            (-1, i128::MAX),
        ] {
            let amount = ratio::<Euro>(numer, denom);
            let decoded = Amount::try_from_inline(&inline(amount)).expect("valid");
            assert_eq!(decoded, amount, "{numer}/{denom} did not round-trip");
        }
    }

    // ── ordering ─────────────────────────────────────────────────────────

    #[test]
    fn byte_order_is_numeric_order() {
        let ordered = [
            ratio::<Euro>(i128::MIN + 1, 1),
            ratio::<Euro>(-10_000, 1),
            ratio::<Euro>(-3, 2),
            ratio::<Euro>(-1, 3),
            Amount::ZERO,
            ratio::<Euro>(1, 3),
            ratio::<Euro>(2, 3),
            ratio::<Euro>(1, 1),
            ratio::<Euro>(3, 2),
            ratio::<Euro>(10_000, 1),
            ratio::<Euro>(i128::MAX, 1),
        ];
        for window in ordered.windows(2) {
            assert!(window[0] < window[1], "Amount order disagreed");
            assert!(
                inline(window[0]).raw < inline(window[1]).raw,
                "byte order disagreed with numeric order"
            );
        }
    }

    // ── malformed values ─────────────────────────────────────────────────

    /// A zeroed buffer must fail loudly rather than decode as some amount.
    /// The continued-fraction encoding gives this for free — no reserved niche.
    #[test]
    fn a_zeroed_buffer_is_rejected() {
        let value = Inline::<Currency<Euro>>::new([0u8; INLINE_LEN]);
        assert_eq!(
            Amount::<Euro>::try_from_inline(&value),
            Err(OrderedRatioError::NonCanonical)
        );
        assert!(Currency::<Euro>::validate(value).is_err());
        // Zero itself is a perfectly good amount, and is not all-zero bytes.
        assert_ne!(inline(Amount::<Euro>::ZERO).raw, [0u8; INLINE_LEN]);
        assert!(Currency::<Euro>::validate(inline(Amount::<Euro>::ZERO)).is_ok());
    }

    /// Out-of-domain is a typed error that reaches the caller, never a
    /// silently approximated value.
    #[test]
    fn out_of_domain_is_a_typed_error() {
        // A long continued fraction of small terms is the worst case: two
        // large coprime numbers close in magnitude.
        let amount = ratio::<Euro>(i128::MAX, i128::MAX - 1);
        assert_eq!(
            amount.try_to_inline().map(|_| ()),
            Err(OrderedRatioError::OutOfDomain)
        );
    }

    // ── the domain, against the real source ──────────────────────────────

    /// The safety argument for the domain cliff, made executable.
    ///
    /// Revolver — the accounting database this was built for — stores every
    /// monetary field as a PostgreSQL `bigint` at three decimal places, and
    /// its ingest rejects a value whose third decimal is non-zero (measured:
    /// across the 31 currency columns of the ingest slice, 316,375 non-zero
    /// values, none with a digit below the second decimal). So the worst case
    /// is not "the largest amount we happen to hold today" but the widest
    /// value the *column* can hold at all: `±(2⁶³−1)` at scale 3.
    ///
    /// Reduced, that is at most `922_337_203_685_477_580 / 100` — a numerator
    /// below `2⁶⁰` against a denominator dividing 100, where `ROrd256`
    /// guarantees everything up to `2¹⁰⁴`. Forty-four bits of margin, and it
    /// cannot be eroded by new data, only by a schema change.
    #[test]
    fn every_value_a_revolver_money_column_can_hold_fits() {
        let extremes = [i64::MAX as i128, i64::MIN as i128, 1, -1, 0];
        for units in extremes {
            // As stored: scale 3, third decimal zero.
            let rounded = (units / 10) * 10;
            let amount = Amount::<Euro>::from_units(rounded, 3).expect("valid scale");
            let value = amount
                .try_to_inline()
                .expect("every bigint at scale 3 is inside the ROrd256 domain");
            assert_eq!(
                Amount::try_from_inline(&value).expect("valid"),
                amount,
                "{rounded} did not round-trip"
            );
            // And even with the third-decimal check relaxed.
            let raw = Amount::<Euro>::from_units(units, 3).expect("valid scale");
            assert!(raw.try_to_inline().is_ok(), "{units} at scale 3 must fit");
        }
    }

    // ── scale conversion ─────────────────────────────────────────────────

    #[test]
    fn to_units_is_exact_or_an_error() {
        let amount = Amount::<Euro>::from_minor(150).expect("valid scale");
        assert_eq!(amount.to_minor(), Ok(150));
        assert_eq!(amount.to_units(2), Ok(150));
        assert_eq!(amount.to_units(4), Ok(15_000));
        assert_eq!(amount.to_units(1), Ok(15));
        assert_eq!(amount.to_units(0), Err(AmountError::Inexact));
    }

    #[test]
    fn minor_units_follow_the_currency() {
        assert_eq!(
            Amount::<Yen>::from_minor(5).expect("valid scale").ratio(),
            Ratio::from_integer(5)
        );
        assert_eq!(
            Amount::<Bitcoin>::from_minor(1)
                .expect("valid scale")
                .ratio(),
            Ratio::new(1, 100_000_000)
        );
        assert_eq!(
            Amount::<Ether>::from_minor(1).expect("valid scale").ratio(),
            Ratio::new(1, 10i128.pow(18))
        );
    }

    // ── arithmetic ───────────────────────────────────────────────────────

    #[test]
    fn arithmetic_is_exact() {
        let one = Amount::<Euro>::from_units(1, 0).expect("valid scale");
        let two = Amount::<Euro>::from_units(2, 0).expect("valid scale");
        assert_eq!(one.checked_add(one), Ok(two));
        assert_eq!(two.checked_sub(one), Ok(one));
        assert_eq!(one.checked_mul_int(2), Ok(two));
        assert_eq!(
            one.checked_neg().and_then(|value| value.checked_add(one)),
            Ok(Amount::ZERO)
        );
    }

    /// The capability the rational form buys: a rate applies without rounding,
    /// so the intermediate is the exact value rather than a truncation of it.
    #[test]
    fn a_vat_rate_applies_exactly() {
        let net = Amount::<Euro>::from_minor(1_999).expect("valid scale"); // €19.99
        let vat = net
            .checked_mul_ratio(Ratio::new(19, 100))
            .expect("no overflow");
        // €3.7981 exactly — not 3.79, not 3.80, and not a float.
        assert_eq!(vat.ratio(), Ratio::new(37_981, 10_000));
        assert_eq!(vat.to_string(), "3.7981 EUR");
        assert_eq!(vat.to_units(2), Err(AmountError::Inexact));
        // Summing net and VAT stays exact too.
        assert_eq!(
            net.checked_add(vat).expect("no overflow").ratio(),
            Ratio::new(237_881, 10_000)
        );
    }

    // ── text ─────────────────────────────────────────────────────────────

    #[test]
    fn display_pads_to_the_minor_unit_but_never_rounds() {
        assert_eq!(
            Amount::<Euro>::from_minor(150)
                .expect("valid scale")
                .to_string(),
            "1.50 EUR"
        );
        assert_eq!(
            Amount::<Euro>::from_units(1, 0)
                .expect("valid scale")
                .to_string(),
            "1.00 EUR"
        );
        // Finer than the minor unit: extended rather than rounded.
        assert_eq!(
            Amount::<Euro>::from_units(1505, 3)
                .expect("valid scale")
                .to_string(),
            "1.505 EUR"
        );
        assert_eq!(
            Amount::<Yen>::from_minor(5)
                .expect("valid scale")
                .to_string(),
            "5 JPY"
        );
        assert_eq!(Amount::<Euro>::ZERO.to_string(), "0.00 EUR");
        assert_eq!(ratio::<Euro>(-3, 2).to_string(), "-1.50 EUR");
        // No finite decimal: written as the fraction it is.
        assert_eq!(ratio::<Euro>(1, 3).to_string(), "1/3 EUR");
        assert_eq!(ratio::<Euro>(-22, 7).to_string(), "-22/7 EUR");
    }

    #[test]
    fn parse_examples() {
        let expected = Amount::<Euro>::from_minor(150).expect("valid scale");
        for text in [
            "1.5 EUR",
            "1.50 EUR",
            "+1.5 EUR",
            "  1.500  EUR  ",
            "3/2 EUR",
        ] {
            assert_eq!(
                text.parse::<Amount<Euro>>(),
                Ok(expected),
                "{text:?} misparsed"
            );
        }
        assert_eq!("1/3 EUR".parse::<Amount<Euro>>(), Ok(ratio::<Euro>(1, 3)));
        // The type says which currency this is; text claiming another is wrong.
        assert_eq!(
            "1.50 USD".parse::<Amount<Euro>>(),
            Err(AmountError::Currency)
        );
        for bad in [
            "1.5EUR",
            "1.5 eur",
            "EUR",
            ".5 EUR",
            "1. EUR",
            "1.5.5 EUR",
            "1,5 EUR",
            "1/0 EUR",
            "1/ EUR",
        ] {
            assert!(
                bad.parse::<Amount<Euro>>().is_err(),
                "{bad:?} should not parse"
            );
        }
    }

    // ── properties ───────────────────────────────────────────────────────

    /// Money-shaped values: a two-decimal amount over a realistic range.
    fn money_amount<C: CurrencyUnit>() -> impl Strategy<Value = Amount<C>> {
        (-1_000_000_000_000i128..1_000_000_000_000)
            .prop_map(|cents| Amount::from_units(cents, 2).expect("valid scale"))
    }

    proptest! {
        #[test]
        fn round_trips(amount in money_amount::<Euro>()) {
            let value = inline(amount);
            prop_assert_eq!(Amount::try_from_inline(&value), Ok(amount));
            prop_assert!(Currency::<Euro>::validate(value).is_ok());
        }

        #[test]
        fn ordering_agrees_with_bytes(
            left in money_amount::<Euro>(),
            right in money_amount::<Euro>(),
        ) {
            prop_assert_eq!(left.cmp(&right), inline(left).raw.cmp(&inline(right).raw));
        }

        #[test]
        fn text_round_trips(amount in money_amount::<Euro>()) {
            prop_assert_eq!(amount.to_string().parse::<Amount<Euro>>(), Ok(amount));
        }

        #[test]
        fn text_round_trips_without_a_minor_unit(amount in money_amount::<Yen>()) {
            prop_assert_eq!(amount.to_string().parse::<Amount<Yen>>(), Ok(amount));
        }

        /// Every value a Revolver money column can hold, sampled across the
        /// full `bigint` range rather than only the realistic part.
        #[test]
        fn the_whole_bigint_source_range_encodes(units in any::<i64>()) {
            let amount = Amount::<Euro>::from_units(i128::from(units), 3).expect("valid scale");
            let value = amount.try_to_inline();
            prop_assert!(value.is_ok(), "{units} at scale 3 fell outside the domain");
            prop_assert_eq!(Amount::try_from_inline(&value.unwrap()), Ok(amount));
        }

        #[test]
        fn unit_conversion_round_trips(units in any::<i64>(), scale in 0u32..=18) {
            let amount = Amount::<Euro>::from_units(i128::from(units), scale).expect("valid scale");
            prop_assert_eq!(amount.to_units(scale), Ok(i128::from(units)));
        }
    }
}
