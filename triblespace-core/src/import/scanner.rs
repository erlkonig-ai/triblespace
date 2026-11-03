//! A streaming JSON scanner over [`anybytes::Bytes`] — the *ingredients* for
//! building importers that project JSON into tribles, rather than the packaged
//! [`json`](crate::import::json) / [`json_tree`](crate::import::json_tree)
//! whole-document importers.
//!
//! # Why this exists
//!
//! Both packaged importers *consume* every value in a document and impose one
//! identity model (content-addressed hash of canonical fact rows, or a
//! lossless tree). An importer that wants to *project* — read the handful of
//! fields it cares about and ignore the rest — had no ingredient to reach for,
//! so importers outside this crate reached for `serde_json::Value` instead:
//! a full dynamic tree per record, several times the source size, allocated
//! eagerly. On a 2 GB line-delimited transcript that is the difference between
//! O(document) and O(one value) memory.
//!
//! The scanner is that missing ingredient. It walks the byte cursor and hands
//! back one value at a time — as a borrowed [`Bytes`] slice where possible, no
//! `Value` tree ever built — and lets the caller decide what to keep. Its two
//! load-bearing primitives:
//!
//! * [`parse_string`] returns the string content with a zero-copy fast path
//!   (an unescaped string is returned as a slice of the input, no allocation).
//! * [`skip_value`] advances past a value the caller does not want — a nested
//!   object, a huge base64 blob, an array — *without materializing it*. This is
//!   what makes projection cheap: read `uuid` and `role`, skip the 2 GB of
//!   content you are not projecting on this pass.
//! * [`take_value`] advances the same scanner while returning the value's exact
//!   source slice. It is the lossless counterpart to `skip_value`: still O(1),
//!   still backed by the original mmap, but suitable for source receipts.
//!
//! # Example: project two fields from a JSONL record
//!
//! ```ignore
//! use triblespace_core::import::scanner as sc;
//! // bytes is one line of JSONL positioned at the opening '{'
//! sc::expect(bytes, b'{')?;
//! loop {
//!     sc::skip_ws(bytes);
//!     let key = sc::parse_string(bytes)?;
//!     sc::skip_ws(bytes); sc::expect(bytes, b':')?; sc::skip_ws(bytes);
//!     match key.view::<str>().unwrap().as_ref() {
//!         "uuid" => { let v = sc::parse_string(bytes)?; /* keep */ }
//!         "role" => { let v = sc::parse_string(bytes)?; /* keep */ }
//!         _ => sc::skip_value(bytes)?,          // cheap: never built
//!     }
//!     sc::skip_ws(bytes);
//!     if bytes.peek_token() == Some(b',') { bytes.pop_front(); } else { break; }
//! }
//! sc::expect(bytes, b'}')?;
//! ```

use anybytes::Bytes;
use winnow::stream::Stream;

/// A scanning error. Deliberately lean — it says only *that* the bytes were not
/// valid JSON at the cursor, not what the importer wanted them to mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The bytes at the cursor are not the JSON the scanner expected.
    Syntax(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Syntax(msg) => write!(f, "json scan error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

fn syntax(msg: &str) -> ScanError {
    ScanError::Syntax(msg.to_owned())
}

/// Advance the cursor past RFC 8259 JSON whitespace.
pub fn skip_ws(bytes: &mut Bytes) {
    while matches!(bytes.peek_token(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        bytes.pop_front();
    }
}

fn is_value_boundary(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}')
}

/// Consume exactly `expected`, or error.
pub fn expect(bytes: &mut Bytes, expected: u8) -> Result<(), ScanError> {
    match bytes.pop_front() {
        Some(b) if b == expected => Ok(()),
        _ => Err(syntax("unexpected token")),
    }
}

/// Consume each byte of `literal` in order (e.g. `b"true"`), or error.
pub fn expect_literal(bytes: &mut Bytes, literal: &[u8]) -> Result<(), ScanError> {
    for expected in literal {
        expect(bytes, *expected)?;
    }
    Ok(())
}

/// Parse the four hexadecimal digits in one JSON UTF-16 code unit. The cursor
/// must be positioned just after the `u`.
pub(crate) fn parse_utf16_code_unit(bytes: &mut Bytes) -> Result<u16, ScanError> {
    use winnow::error::InputError;
    use winnow::token::take;
    use winnow::Parser;

    let mut grab = take::<_, _, InputError<Bytes>>(4usize);
    let hex = grab
        .parse_next(bytes)
        .map_err(|_| syntax("unterminated unicode escape"))?;

    let mut code: u16 = 0;
    for h in hex.as_ref() {
        code = (code << 4)
            | match h {
                b'0'..=b'9' => (h - b'0') as u16,
                b'a'..=b'f' => (h - b'a' + 10) as u16,
                b'A'..=b'F' => (h - b'A' + 10) as u16,
                _ => return Err(syntax("invalid unicode escape")),
            };
    }

    Ok(code)
}

/// Decode a JSON `\uXXXX` escape into UTF-8 bytes. The cursor must be
/// positioned just after the first `u`.
///
/// JSON spells non-BMP scalar values as a UTF-16 surrogate pair. A leading
/// surrogate therefore consumes the immediately following `\uXXXX` escape;
/// lone low surrogates and malformed pairs are rejected.
pub fn parse_unicode_escape(bytes: &mut Bytes) -> Result<Vec<u8>, ScanError> {
    let first = parse_utf16_code_unit(bytes)?;
    let code = match first {
        high @ 0xD800..=0xDBFF => {
            if bytes.pop_front() != Some(b'\\') || bytes.pop_front() != Some(b'u') {
                return Err(syntax("high surrogate must be followed by a low surrogate"));
            }
            let low = parse_utf16_code_unit(bytes)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(syntax("high surrogate must be followed by a low surrogate"));
            }
            0x1_0000 + (((high as u32) - 0xD800) << 10) + ((low as u32) - 0xDC00)
        }
        0xDC00..=0xDFFF => return Err(syntax("lone low surrogate")),
        scalar => scalar as u32,
    };

    if let Some(ch) = char::from_u32(code) {
        let mut buf = [0u8; 4];
        Ok(ch.encode_utf8(&mut buf).as_bytes().to_vec())
    } else {
        Err(syntax("invalid unicode escape"))
    }
}

/// Parse a JSON string, returning its decoded content as [`Bytes`].
///
/// Zero-copy fast path: a string with no escapes is returned as a borrowed
/// slice of the input, no allocation. Escaped strings allocate only the decoded
/// result. The cursor must be positioned at the opening `"`.
pub fn parse_string(bytes: &mut Bytes) -> Result<Bytes, ScanError> {
    expect(bytes, b'"')?;
    {
        use winnow::error::InputError;
        use winnow::token::take_while;
        use winnow::Parser;

        let mut tentative = bytes.clone();
        let mut segment = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            b >= 0x20 && b != b'"' && b != b'\\'
        });

        if let Ok(prefix) = segment.parse_next(&mut tentative) {
            if tentative.peek_token() == Some(b'"') {
                tentative.pop_front();
                *bytes = tentative;
                return Ok(prefix);
            }
        }
    }

    let mut out = Vec::new();
    loop {
        use winnow::error::InputError;
        use winnow::token::take_while;
        use winnow::Parser;

        let mut segment = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            b >= 0x20 && b != b'\\' && b != b'"'
        });
        let chunk = segment
            .parse_next(bytes)
            .map_err(|_| syntax("unterminated string"))?;
        out.extend_from_slice(chunk.as_ref());

        match bytes.peek_token() {
            Some(b'"') => {
                bytes.pop_front();
                return Ok(Bytes::from(out));
            }
            Some(b'\\') => {
                bytes.pop_front();
                let esc = bytes
                    .pop_front()
                    .ok_or_else(|| syntax("unterminated escape"))?;
                match esc {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => out.extend_from_slice(&parse_unicode_escape(bytes)?),
                    _ => return Err(syntax("invalid escape sequence")),
                }
            }
            Some(0x00..=0x1F) => return Err(syntax("unescaped control character in string")),
            None => return Err(syntax("unterminated string")),
            _ => unreachable!("peek_token only yields bytes"),
        }
    }
}

/// Parse a JSON number, returning the raw token bytes (the caller decodes to
/// `f64` / `i64` as it needs — see [`parse_f64`]).
pub fn parse_number(bytes: &mut Bytes) -> Result<Bytes, ScanError> {
    fn consume_digits(bytes: &mut Bytes) -> usize {
        let mut count = 0;
        while matches!(bytes.peek_token(), Some(b'0'..=b'9')) {
            bytes.pop_front();
            count += 1;
        }
        count
    }

    // Parse through a clone so malformed tokens leave the caller's cursor
    // untouched. Both the clone and the returned prefix retain the same
    // anybytes owner, so success is still O(1) and zero-copy.
    let start = bytes.clone();
    let mut rest = start.clone();

    if rest.peek_token() == Some(b'-') {
        rest.pop_front();
    }

    match rest.peek_token() {
        Some(b'0') => {
            rest.pop_front();
            if matches!(rest.peek_token(), Some(b'0'..=b'9')) {
                return Err(syntax("leading zero in number"));
            }
        }
        Some(b'1'..=b'9') => {
            rest.pop_front();
            consume_digits(&mut rest);
        }
        _ => return Err(syntax("expected number")),
    }

    if rest.peek_token() == Some(b'.') {
        rest.pop_front();
        if consume_digits(&mut rest) == 0 {
            return Err(syntax("fraction requires at least one digit"));
        }
    }

    if matches!(rest.peek_token(), Some(b'e' | b'E')) {
        rest.pop_front();
        if matches!(rest.peek_token(), Some(b'+' | b'-')) {
            rest.pop_front();
        }
        if consume_digits(&mut rest) == 0 {
            return Err(syntax("exponent requires at least one digit"));
        }
    }

    if matches!(rest.peek_token(), Some(byte) if !is_value_boundary(byte)) {
        return Err(syntax("invalid character after number"));
    }

    let consumed = start.len() - rest.len();
    let raw = start.slice(..consumed);
    *bytes = rest;
    Ok(raw)
}

/// Parse a JSON number and decode it to `f64`.
pub fn parse_f64(bytes: &mut Bytes) -> Result<f64, ScanError> {
    let raw = parse_number(bytes)?;
    let s = raw.view::<str>().map_err(|_| syntax("invalid number"))?;
    let n: f64 = s.as_ref().parse().map_err(|_| syntax("invalid number"))?;
    if !n.is_finite() {
        return Err(syntax("non-finite number"));
    }
    Ok(n)
}

/// Advance the cursor past one complete JSON value *without materializing it* —
/// the primitive that makes projection cheap. Handles nesting to any depth.
///
/// The cursor must be positioned at the first byte of the value (after any
/// leading whitespace).
pub fn skip_value(bytes: &mut Bytes) -> Result<(), ScanError> {
    fn literal(bytes: &mut Bytes, expected: &[u8]) -> Result<(), ScanError> {
        expect_literal(bytes, expected)?;
        if matches!(bytes.peek_token(), Some(byte) if !is_value_boundary(byte)) {
            return Err(syntax("invalid character after literal"));
        }
        Ok(())
    }

    match bytes.peek_token() {
        Some(b'"') => {
            let _ = parse_string(bytes)?;
            Ok(())
        }
        Some(b't') => literal(bytes, b"true"),
        Some(b'f') => literal(bytes, b"false"),
        Some(b'n') => literal(bytes, b"null"),
        // Reuse the fold combinators so the recursive skipper and the public
        // `object` / `array` share one implementation of the brace-matching
        // structure — dropping each member/element on the floor via `skip_value`.
        Some(b'{') => object(bytes, (), |(), _key, b| skip_value(b)),
        Some(b'[') => array(bytes, (), |(), b| skip_value(b)),
        Some(_) => {
            let _ = parse_number(bytes)?;
            Ok(())
        }
        None => Err(syntax("expected a value")),
    }
}

/// Return the exact source bytes of one complete JSON value and advance past
/// it without decoding or copying the value.
///
/// The cursor must already be positioned at the value's first byte. Leading
/// and trailing whitespace are therefore not part of the returned slice, but
/// whitespace inside an object or array is retained byte-for-byte. On error,
/// the caller's cursor is left unchanged.
pub fn take_value(bytes: &mut Bytes) -> Result<Bytes, ScanError> {
    let start = bytes.clone();
    let mut rest = start.clone();
    skip_value(&mut rest)?;

    let consumed = start.len() - rest.len();
    let value = start.slice(..consumed);
    *bytes = rest;
    Ok(value)
}

/// Parse a JSON object, folding `member` over each `"key": value` pair.
///
/// For each member the key string is parsed (via [`parse_string`]) and the `:`
/// consumed, then `member(acc, key, bytes)` is called with the cursor positioned
/// at the first byte of the value — the callback is responsible for consuming
/// exactly one value from `bytes`. Handles the surrounding `{`, whitespace, the
/// empty object `{}`, comma separators, and the closing `}`; a trailing comma is
/// rejected as invalid JSON.
///
/// The cursor must be positioned at the opening `{` (after any leading
/// whitespace).
pub fn object<A>(
    bytes: &mut Bytes,
    init: A,
    mut member: impl FnMut(A, Bytes, &mut Bytes) -> Result<A, ScanError>,
) -> Result<A, ScanError> {
    expect(bytes, b'{')?;
    skip_ws(bytes);
    if bytes.peek_token() == Some(b'}') {
        bytes.pop_front();
        return Ok(init);
    }
    let mut acc = init;
    loop {
        skip_ws(bytes);
        let key = parse_string(bytes)?;
        skip_ws(bytes);
        expect(bytes, b':')?;
        skip_ws(bytes);
        acc = member(acc, key, bytes)?;
        skip_ws(bytes);
        match bytes.pop_front() {
            Some(b',') => continue,
            Some(b'}') => return Ok(acc),
            _ => return Err(syntax("expected ',' or '}' in object")),
        }
    }
}

/// Parse a JSON array, folding `element` over each value.
///
/// For each element `element(acc, bytes)` is called with the cursor positioned
/// at the first byte of the value — the callback is responsible for consuming
/// exactly one value from `bytes`. Handles the surrounding `[`, whitespace, the
/// empty array `[]`, comma separators, and the closing `]`; a trailing comma is
/// rejected as invalid JSON.
///
/// The cursor must be positioned at the opening `[` (after any leading
/// whitespace).
pub fn array<A>(
    bytes: &mut Bytes,
    init: A,
    mut element: impl FnMut(A, &mut Bytes) -> Result<A, ScanError>,
) -> Result<A, ScanError> {
    expect(bytes, b'[')?;
    skip_ws(bytes);
    if bytes.peek_token() == Some(b']') {
        bytes.pop_front();
        return Ok(init);
    }
    let mut acc = init;
    loop {
        skip_ws(bytes);
        acc = element(acc, bytes)?;
        skip_ws(bytes);
        match bytes.pop_front() {
            Some(b',') => continue,
            Some(b']') => return Ok(acc),
            _ => return Err(syntax("expected ',' or ']' in array")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Bytes {
        Bytes::from(s.as_bytes().to_vec())
    }

    #[test]
    fn string_zero_copy_and_escaped() {
        let mut b = bytes(r#""plain" rest"#);
        let original_ptr = b.as_ptr();
        let s = parse_string(&mut b).unwrap();
        assert_eq!(s.as_ptr(), unsafe { original_ptr.add(1) });
        assert_eq!(s.view::<str>().unwrap().as_ref(), "plain");

        let mut e = bytes(r#""a\nb☺""#);
        let s = parse_string(&mut e).unwrap();
        assert_eq!(s.view::<str>().unwrap().as_ref(), "a\nb\u{263A}");
    }

    #[test]
    fn string_decodes_utf16_surrogate_pairs() {
        let mut emoji = bytes(r#""\uD83D\uDE00""#);
        let decoded = parse_string(&mut emoji).unwrap();
        assert_eq!(decoded.view::<str>().unwrap().as_ref(), "😀");
        assert_eq!(emoji.peek_token(), None);

        let mut maximum = bytes(r#""\uDBFF\uDFFF""#);
        let decoded = parse_string(&mut maximum).unwrap();
        assert_eq!(decoded.view::<str>().unwrap().as_ref(), "\u{10FFFF}");
    }

    #[test]
    fn string_rejects_lone_and_malformed_surrogates() {
        for invalid in [
            r#""\uD800""#,
            r#""\uDC00""#,
            r#""\uD800\u0041""#,
            r#""\uD800\uD800""#,
            r#""\uD800x""#,
            r#""\uD800\xDC00""#,
            r#""\uD800\uDFF""#,
        ] {
            let mut input = bytes(invalid);
            assert!(parse_string(&mut input).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn string_rejects_every_unescaped_control_byte() {
        for control in 0x00..=0x1F {
            let mut fast_path = Bytes::from_source(vec![b'"', b'a', control, b'"']);
            assert!(
                parse_string(&mut fast_path).is_err(),
                "fast path accepted control byte 0x{control:02X}"
            );

            let mut escaped_path = Bytes::from_source(vec![b'"', b'\\', b'n', control, b'"']);
            assert!(
                parse_string(&mut escaped_path).is_err(),
                "escaped path accepted control byte 0x{control:02X}"
            );
        }

        let mut escaped_controls = bytes(r#""\b\f\n\r\t\u0000""#);
        assert_eq!(
            parse_string(&mut escaped_controls).unwrap().as_ref(),
            b"\x08\x0c\n\r\t\0"
        );
    }

    #[test]
    fn skip_value_handles_arbitrary_nesting() {
        // skip a deeply nested value and confirm the cursor lands exactly after it.
        let mut b = bytes(r#"{"a":[1,{"b":"c\"d"},[true,null]],"keep":42}"#);
        expect(&mut b, b'{').unwrap();
        skip_ws(&mut b);
        let key = parse_string(&mut b).unwrap();
        assert_eq!(key.view::<str>().unwrap().as_ref(), "a");
        skip_ws(&mut b);
        expect(&mut b, b':').unwrap();
        skip_ws(&mut b);
        skip_value(&mut b).unwrap(); // skip the whole nested array
        skip_ws(&mut b);
        expect(&mut b, b',').unwrap();
        skip_ws(&mut b);
        let key2 = parse_string(&mut b).unwrap();
        assert_eq!(key2.view::<str>().unwrap().as_ref(), "keep");
    }

    #[test]
    fn project_two_fields_skipping_the_rest() {
        // the exact projecting-parse pattern the archive importers want.
        let mut b =
            bytes(r#"{"noise":{"big":[0,1,2,3]},"uuid":"u-1","more":123,"role":"assistant"}"#);
        let mut uuid = None;
        let mut role = None;
        expect(&mut b, b'{').unwrap();
        loop {
            skip_ws(&mut b);
            let key = parse_string(&mut b).unwrap();
            let key = key.view::<str>().unwrap().as_ref().to_owned();
            skip_ws(&mut b);
            expect(&mut b, b':').unwrap();
            skip_ws(&mut b);
            match key.as_str() {
                "uuid" => {
                    uuid = Some(
                        parse_string(&mut b)
                            .unwrap()
                            .view::<str>()
                            .unwrap()
                            .as_ref()
                            .to_owned(),
                    )
                }
                "role" => {
                    role = Some(
                        parse_string(&mut b)
                            .unwrap()
                            .view::<str>()
                            .unwrap()
                            .as_ref()
                            .to_owned(),
                    )
                }
                _ => skip_value(&mut b).unwrap(),
            }
            skip_ws(&mut b);
            match b.pop_front() {
                Some(b',') => continue,
                Some(b'}') => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(uuid.as_deref(), Some("u-1"));
        assert_eq!(role.as_deref(), Some("assistant"));
    }

    #[test]
    fn f64_rejects_non_finite_shaped_and_parses_plain() {
        let mut b = bytes("3.5e2,");
        assert_eq!(parse_f64(&mut b).unwrap(), 350.0);

        let mut overflow = bytes("1e999");
        assert!(parse_f64(&mut overflow).is_err());
    }

    #[test]
    fn number_accepts_exact_rfc_8259_grammar() {
        for valid in [
            "0", "-0", "1", "-1", "10", "0.25", "-0.25", "1e10", "1E+10", "1e-10", "0.0e0",
        ] {
            let source = format!("{valid},tail");
            let mut input = bytes(&source);
            let raw = parse_number(&mut input).unwrap();
            assert_eq!(raw.as_ref(), valid.as_bytes(), "failed {valid:?}");
            assert_eq!(input.as_ref(), b",tail");
        }
    }

    #[test]
    fn number_rejects_non_json_forms_without_advancing() {
        for invalid in [
            "+1", ".1", "-", "01", "-01", "1.", "1e", "1E+", "1e-", "--1", "1+2", "1e2e3", "NaN",
            "Infinity",
        ] {
            let mut input = bytes(invalid);
            let before = input.clone();
            assert!(parse_number(&mut input).is_err(), "accepted {invalid:?}");
            assert_eq!(input, before, "advanced on {invalid:?}");
        }

        for invalid in ["[01]", "[-01]", "[1.]", "[1e]", "[+1]"] {
            let mut input = bytes(invalid);
            assert!(skip_value(&mut input).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn take_value_returns_an_exact_zero_copy_slice() {
        let mut input = bytes(r#"{"a": [1, 2], "s":"x\\ny"},tail"#);
        let source_ptr = input.as_ptr();
        let value = take_value(&mut input).unwrap();
        assert_eq!(value.as_ref(), br#"{"a": [1, 2], "s":"x\\ny"}"#);
        assert_eq!(value.as_ptr(), source_ptr);
        assert_eq!(input.as_ref(), b",tail");

        let mut invalid = bytes("[01],tail");
        let before = invalid.clone();
        assert!(take_value(&mut invalid).is_err());
        assert_eq!(invalid, before);
    }

    #[test]
    fn object_folds_top_level_keys() {
        // a fold that actually accumulates: collect every top-level key.
        let mut b = bytes(r#"{"a":1,"b":"two","c":[3,3]}"#);
        let keys = object(&mut b, Vec::new(), |mut acc, key, v| {
            acc.push(key.view::<str>().unwrap().as_ref().to_owned());
            skip_value(v)?;
            Ok(acc)
        })
        .unwrap();
        assert_eq!(keys, vec!["a", "b", "c"]);
        assert_eq!(b.peek_token(), None); // cursor landed exactly past the '}'
    }

    #[test]
    fn array_sums_numbers() {
        let mut b = bytes("[1, 2, 3, 4]");
        let sum = array(&mut b, 0.0, |acc, v| Ok(acc + parse_f64(v)?)).unwrap();
        assert_eq!(sum, 10.0);
        assert_eq!(b.peek_token(), None);
    }

    #[test]
    fn empty_object_and_array() {
        let mut o = bytes("{}");
        let n = object(&mut o, 0usize, |acc, _k, v| {
            skip_value(v)?;
            Ok(acc + 1)
        })
        .unwrap();
        assert_eq!(n, 0);
        assert_eq!(o.peek_token(), None);

        let mut a = bytes("[]");
        let n = array(&mut a, 0usize, |acc, v| {
            skip_value(v)?;
            Ok(acc + 1)
        })
        .unwrap();
        assert_eq!(n, 0);
        assert_eq!(a.peek_token(), None);
    }

    #[test]
    fn whitespace_in_all_positions() {
        // whitespace before/around braces, keys, colons, commas, and values.
        let mut b = bytes("  {  \"a\" :  1 ,  \"b\"  :  2  }  ");
        skip_ws(&mut b);
        let keys = object(&mut b, Vec::new(), |mut acc, key, v| {
            acc.push(key.view::<str>().unwrap().as_ref().to_owned());
            skip_value(v)?;
            Ok(acc)
        })
        .unwrap();
        assert_eq!(keys, vec!["a", "b"]);
        skip_ws(&mut b);
        assert_eq!(b.peek_token(), None);

        for non_json_whitespace in [b'\x0b', b'\x0c'] {
            let mut invalid = Bytes::from_source(vec![b'{', non_json_whitespace, b'}']);
            assert!(object(&mut invalid, (), |(), _key, value| { skip_value(value) }).is_err());
        }
    }

    #[test]
    fn nested_object_in_array_in_object() {
        // {"outer": [ {"inner": N}, ... ], "tail": 9} — fold all three levels.
        let mut b = bytes(r#"{"outer":[{"inner":1},{"inner":2}],"tail":9}"#);
        let mut inner_sum = 0.0;
        let mut saw_tail = false;
        object(&mut b, (), |(), key, v| {
            match key.view::<str>().unwrap().as_ref() {
                "outer" => {
                    inner_sum = array(v, 0.0, |acc, e| {
                        let one = object(e, 0.0, |a, k2, v2| {
                            assert_eq!(k2.view::<str>().unwrap().as_ref(), "inner");
                            Ok(a + parse_f64(v2)?)
                        })?;
                        Ok(acc + one)
                    })?;
                }
                "tail" => {
                    saw_tail = true;
                    skip_value(v)?;
                }
                _ => skip_value(v)?,
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(inner_sum, 3.0);
        assert!(saw_tail);
        assert_eq!(b.peek_token(), None);
    }

    #[test]
    fn rejects_trailing_comma_and_missing_colon() {
        let mut obj_trailing = bytes(r#"{"a":1,}"#);
        assert!(matches!(
            object(&mut obj_trailing, (), |(), _k, v| skip_value(v)),
            Err(ScanError::Syntax(_))
        ));

        let mut arr_trailing = bytes("[1,]");
        assert!(matches!(
            array(&mut arr_trailing, (), |(), v| skip_value(v)),
            Err(ScanError::Syntax(_))
        ));

        let mut missing_colon = bytes(r#"{"a" 1}"#);
        assert!(matches!(
            object(&mut missing_colon, (), |(), _k, v| skip_value(v)),
            Err(ScanError::Syntax(_))
        ));

        for invalid in ["truex", "false0", "nullnull"] {
            let mut value = bytes(invalid);
            assert!(skip_value(&mut value).is_err(), "accepted {invalid:?}");
        }
    }
}
