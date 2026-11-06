//! Text projection of an explicitly supplied native fact set.
//!
//! Parsing produces facts directly, plus blobs explicitly authored with `utf8`.
//! It adds no exports, schema metafacts, default operation, selection or execution.
//! Aliases are document-local spellings, declared before use; every semantic id
//! is explicit. Repeated statements union facts. `@name` and `?name` use the same
//! alias namespace; the latter only helps readers recognize term entities.
//!
//! Writing preserves every input fact, using conservative rule shorthand and
//! `fact … raw32"…"` for everything else. Thus parsing the output recovers the
//! exact finite `TribleSet`, including unknown, incomplete and malformed facts.
//! This is not a Fragment/pile archive: exports, metafacts and existing blob
//! bodies are separate channels. Writing never reads blobs or guesses literal
//! encodings. Semantic editing/forking and collection selection remain explicit.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anybytes::Bytes;
use hex::FromHex;
use winnow::stream::Stream;

use super::schema as r;
use crate::import::scanner;
use crate::prelude::blobencodings::UTF8String;
use crate::prelude::inlineencodings::{GenId, Handle};
use crate::prelude::*;
use crate::trible::Trible;

/// A syntax error. Offsets and columns count bytes, starting at zero and one
/// respectively; lines start at one. No partially parsed fragment is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextError {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {}:{} (byte {})",
            self.message, self.line, self.column, self.offset
        )
    }
}

impl std::error::Error for TextError {}

/// Parse a complete document. Whitespace and `//` line comments are ignored.
/// Strings use JSON escaping. Ids must be non-nil, 32-hex-digit `id"…"`
/// literals or previously declared `@alias`/`?alias` references. Alias names
/// match `[A-Za-z_][A-Za-z_0-9]*`; conflicting rebindings are syntax errors.
///
/// Values are `raw32"64 hex digits"`, `genid(ID)`,
/// `handle<UTF8String>"64 hex digits"`, or `utf8("JSON string")`.
/// A rule block only supplies the revision subject for its statements; an
/// empty block therefore adds no facts. See the book's native text example.
pub fn parse(source: Bytes) -> Result<Fragment, TextError> {
    let mut parser = Parser {
        rest: source.clone(),
        source,
        aliases: BTreeMap::new(),
        fragment: Fragment::empty(),
    };
    parser.document()?;
    Ok(parser.fragment)
}

struct Parser {
    source: Bytes,
    rest: Bytes,
    aliases: BTreeMap<String, Id>,
    fragment: Fragment,
}

impl Parser {
    fn error(&self, message: impl Into<String>) -> TextError {
        let offset = self.source.len() - self.rest.len();
        let prefix = &self.source.as_ref()[..offset];
        TextError {
            offset,
            line: prefix.iter().filter(|&&b| b == b'\n').count() + 1,
            column: prefix
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(offset + 1, |p| offset - p),
            message: message.into(),
        }
    }

    fn ws(&mut self) {
        loop {
            scanner::skip_ws(&mut self.rest);
            if !self.rest.as_ref().starts_with(b"//") {
                break;
            }
            while self.rest.pop_front().is_some_and(|b| b != b'\n') {}
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        self.ws();
        if self.rest.peek_token() == Some(byte) {
            self.rest.pop_front();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), TextError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(self.error(format!("expected '{}'", byte as char)))
        }
    }

    fn word(&mut self) -> Result<String, TextError> {
        self.ws();
        if !matches!(
            self.rest.peek_token(),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'_')
        ) {
            return Err(self.error("expected identifier"));
        }
        let start = self.rest.clone();
        while matches!(
            self.rest.peek_token(),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9')
        ) {
            self.rest.pop_front();
        }
        let length = start.len() - self.rest.len();
        Ok(String::from_utf8(start.as_ref()[..length].to_vec()).expect("ASCII identifier"))
    }

    fn keyword(&mut self, expected: &str) -> Result<(), TextError> {
        self.ws();
        let error = self.error(format!("expected {expected}"));
        if self.word()? == expected {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn string(&mut self) -> Result<String, TextError> {
        self.ws();
        let decoded =
            scanner::parse_string(&mut self.rest).map_err(|e| self.error(e.to_string()))?;
        String::from_utf8(decoded.as_ref().to_vec()).map_err(|_| self.error("string is not UTF-8"))
    }

    fn id(&mut self) -> Result<Id, TextError> {
        self.ws();
        let error = self.error("expected non-nil 32-hex-digit id or declared alias");
        if self.take(b'@') || self.take(b'?') {
            let alias = self.word()?;
            return self
                .aliases
                .get(&alias)
                .copied()
                .ok_or_else(|| self.error(format!("unknown alias {alias}")));
        }
        self.keyword("id")?;
        Id::from_hex(&self.string()?).ok_or(error)
    }

    fn value(&mut self) -> Result<Inline<UnknownInline>, TextError> {
        self.ws();
        let error = self.error("expected raw32, genid, handle<UTF8String> or utf8 value");
        match self.word()?.as_str() {
            "raw32" => {
                let raw = <[u8; 32]>::from_hex(self.string()?)
                    .map_err(|_| self.error("expected 64 hex digits"))?;
                Ok(Inline::new(raw))
            }
            "genid" => {
                self.expect(b'(')?;
                let value: Inline<GenId> = self.id()?.to_inline();
                self.expect(b')')?;
                Ok(value.transmute())
            }
            "handle" => {
                self.expect(b'<')?;
                self.keyword("UTF8String")?;
                self.expect(b'>')?;
                let raw = <[u8; 32]>::from_hex(self.string()?)
                    .map_err(|_| self.error("expected 64 hex digits"))?;
                Ok(Inline::<Handle<UTF8String>>::new(raw).transmute())
            }
            "utf8" => {
                self.expect(b'(')?;
                let text = self.string()?;
                self.expect(b')')?;
                Ok(self
                    .fragment
                    .put::<UTF8String, _>(text.as_str())
                    .transmute())
            }
            _ => Err(error),
        }
    }

    // Fixed-schema expansions use entity!, retaining only content facts.
    // The text contract deliberately has no implicit exports or descriptions.
    fn add(&mut self, fragment: Fragment) {
        *self.fragment.facts_mut() += fragment.into_facts();
    }

    fn document(&mut self) -> Result<(), TextError> {
        loop {
            self.ws();
            if self.rest.is_empty() {
                return Ok(());
            }
            let error = self.error("expected alias, fact or rule");
            match self.word()?.as_str() {
                "alias" => {
                    let alias = self.word()?;
                    self.expect(b'=')?;
                    let id = self.id()?;
                    self.expect(b';')?;
                    if self.aliases.get(&alias).is_some_and(|&old| old != id) {
                        return Err(self.error(format!("ambiguous alias {alias}")));
                    }
                    self.aliases.insert(alias, id);
                }
                "fact" => {
                    let entity = self.id()?;
                    let attribute = self.id()?;
                    let value = self.value()?;
                    self.expect(b';')?;
                    self.fragment
                        .facts_mut()
                        .insert(&Trible::force(&entity, &attribute, &value));
                }
                "rule" => {
                    let revision = self.id()?;
                    self.expect(b'{')?;
                    while !self.take(b'}') {
                        self.statement(revision)?;
                    }
                }
                _ => return Err(error),
            }
        }
    }

    fn statement(&mut self, revision: Id) -> Result<(), TextError> {
        self.ws();
        let error = self.error("expected operation, matches, core, emits, literal or constraint");
        let rev = ExclusiveId::force_ref(&revision);
        match self.word()?.as_str() {
            "operation" => {
                self.keyword("POSITIVE")?;
                self.expect(b';')?;
                self.add(entity! { rev @ r::operation: r::POSITIVE });
            }
            relation @ ("matches" | "core" | "emits") => {
                let clause = self.id()?;
                self.expect(b'(')?;
                let subject = self.id()?;
                let predicate = self.id()?;
                let object = self.id()?;
                self.expect(b')')?;
                self.expect(b';')?;
                let c = ExclusiveId::force_ref(&clause);
                self.add(
                    entity! { c @ r::subject: subject, r::predicate: predicate, r::object: object },
                );
                self.add(match relation {
                    "matches" => entity! { rev @ r::matches: clause },
                    "core" => entity! { rev @ r::core: clause },
                    _ => entity! { rev @ r::emits: clause },
                });
            }
            "literal" => {
                let term = self.id()?;
                let value = self.value()?;
                self.expect(b';')?;
                self.add(entity! { ExclusiveId::force_ref(&term) @ r::literal: value });
            }
            "constraint" => {
                let constraint = self.id()?;
                self.keyword("STRING_CONTAINS")?;
                self.expect(b'(')?;
                let container = self.id()?;
                self.expect(b',')?;
                let needle = self.id()?;
                self.expect(b')')?;
                self.expect(b';')?;
                self.add(entity! { rev @ r::constraints: constraint });
                self.add(entity! { ExclusiveId::force_ref(&constraint) @
                    r::operation: r::STRING_CONTAINS, r::container: container, r::needle: needle
                });
            }
            _ => return Err(error),
        }
        Ok(())
    }
}

// A display preference only: ambiguous, undecodable or absent fields fall
// back to raw facts. Query raw values so malformed alternatives count too.
fn display_id(facts: &TribleSet, entity: Id, attribute: Id) -> Option<Id> {
    let mut values = find!(v: Inline<UnknownInline>,
        facts.pattern::<UnknownInline>(entity.to_inline(), attribute.to_inline(), v));
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Id::try_from_inline(&first.transmute::<GenId>()).ok()
}

/// Write a deterministic projection without a blob reader. Only witnessed
/// singleton clause/constraint fields receive shorthand; all uncovered facts
/// use raw32. Unknown operations and all literal bytes remain raw. Shared ids
/// are never copied or remapped. Any output error is returned to the caller.
pub fn write(facts: &TribleSet, out: &mut impl fmt::Write) -> fmt::Result {
    // This table controls spelling only, not graph ownership or interpretation.
    let mut ids = BTreeSet::new();
    let references = [
        r::matches.id(),
        r::core.id(),
        r::emits.id(),
        r::subject.id(),
        r::predicate.id(),
        r::object.id(),
        r::constraints.id(),
        r::operation.id(),
        r::container.id(),
        r::needle.id(),
    ];
    for fact in facts.iter_ordered() {
        ids.extend([*fact.e(), *fact.a()]);
        if references.contains(fact.a()) {
            if let Ok(id) = Id::try_from_inline(fact.v::<GenId>()) {
                ids.insert(id);
            }
        }
    }
    let aliases: BTreeMap<_, _> = ids
        .into_iter()
        .enumerate()
        .map(|(n, id)| (id, format!("n{n}")))
        .collect();
    for (id, alias) in &aliases {
        writeln!(out, "alias {alias} = id\"{id:x}\";")?;
    }
    let mut covered = TribleSet::new();
    let mut open = None;
    for fact in facts.iter_ordered() {
        let entity = *fact.e();
        let attribute = *fact.a();
        let Ok(value) = Id::try_from_inline(fact.v::<GenId>()) else {
            continue;
        };
        let mut expansion = TribleSet::new();
        let statement = if attribute == r::operation.id() && value == r::POSITIVE {
            "operation POSITIVE;".to_owned()
        } else if [r::matches.id(), r::core.id(), r::emits.id()].contains(&attribute) {
            let fields = [r::subject.id(), r::predicate.id(), r::object.id()];
            let [Some(s), Some(a), Some(o)] = fields.map(|a| display_id(facts, value, a)) else {
                continue;
            };
            for (a, v) in fields.into_iter().zip([s, a, o]) {
                let v: Inline<GenId> = v.to_inline();
                expansion.insert(&Trible::force(&value, &a, &v));
            }
            let keyword = if attribute == r::matches.id() {
                "matches"
            } else if attribute == r::core.id() {
                "core"
            } else {
                "emits"
            };
            format!(
                "{keyword} @{} (?{} @{} ?{});",
                aliases[&value], aliases[&s], aliases[&a], aliases[&o]
            )
        } else if attribute == r::constraints.id() {
            let fields = [r::operation.id(), r::container.id(), r::needle.id()];
            let [Some(op), Some(container), Some(needle)] =
                fields.map(|a| display_id(facts, value, a))
            else {
                continue;
            };
            if op != r::STRING_CONTAINS {
                continue;
            }
            for (a, v) in fields.into_iter().zip([op, container, needle]) {
                let v: Inline<GenId> = v.to_inline();
                expansion.insert(&Trible::force(&value, &a, &v));
            }
            format!(
                "constraint @{} STRING_CONTAINS(?{}, ?{});",
                aliases[&value], aliases[&container], aliases[&needle]
            )
        } else {
            continue;
        };
        if open != Some(entity) {
            if open.is_some() {
                writeln!(out, "}}")?;
            }
            writeln!(out, "rule @{} {{", aliases[&entity])?;
            open = Some(entity);
        }
        writeln!(out, "  {statement}")?;
        covered += expansion;
        covered.insert(fact);
    }
    if open.is_some() {
        writeln!(out, "}}")?;
    }
    for fact in facts.iter_ordered() {
        if !covered.contains(fact) {
            writeln!(
                out,
                "fact @{} @{} raw32\"{}\";",
                aliases[fact.e()],
                aliases[fact.a()],
                hex::encode(fact.v::<UnknownInline>().raw)
            )?;
        }
    }
    Ok(())
}
