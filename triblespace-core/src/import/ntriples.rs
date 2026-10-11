//! N-Triples → TribleSpace importer.
//!
//! Each N-Triples line maps directly to a triblespace trible. Subjects and
//! object URIs are derived deterministically into entity ids via
//! [`crate::import::rdf_uri`] — the same URI always maps to the same
//! triblespace `Id` across processes, so repeated imports converge.
//!
//! Predicate URIs become attribute ids through
//! [`Attribute::<S>::iri`](crate::attribute::Attribute::iri), which derives a
//! rooted identity from the IRI and value encoding. The inline encoding is
//! chosen from the object's XSD datatype:
//!
//! - `xsd:integer` / `xsd:long` / `xsd:int` / `xsd:short` / `xsd:byte`
//!   / `xsd:negativeInteger` / `xsd:nonPositiveInteger` → `I256BE`
//! - `xsd:nonNegativeInteger` / `xsd:positiveInteger` / `xsd:unsignedInt`
//!   / `xsd:unsignedLong` / `xsd:unsignedShort` / `xsd:unsignedByte` → `U256BE`
//! - `xsd:decimal` → `R256BE` (exact rational)
//! - `xsd:float` / `xsd:double` → `F64`
//! - `xsd:boolean` → `Boolean`
//! - `xsd:string`, untyped → `Handle<UTF8String>`
//! - URI objects (and `xsd:anyURI` literals) → `GenId`
//! - `xsd:dateTime` → `NsTAIInterval` as `[t, t]` (degenerate instant)
//! - `xsd:date` → `NsTAIInterval` (whole day, inclusive bounds)
//! - `xsd:gYear` / `xsd:gYearMonth` → `NsTAIInterval` (year / month)
//! - `xsd:duration` / `xsd:dayTimeDuration` → `NsDuration`
//!   (year/month-only durations fall through to text since their
//!   ns count depends on context)
//! - `xsd:hexBinary` / `xsd:base64Binary` → `Handle<RawBytes>`
//!
//! Language-tagged literals (`"text"@lang`) are reified into a small
//! entity carrying [`rdf_lang`](crate::import::rdf_lang) and
//! [`rdf_text`](crate::import::rdf_text). The owning predicate then
//! holds a `GenId` pointing at that entity, so language handling falls
//! out of normal joins instead of needing a `lang()` builtin.
//!
//! Blank nodes are resolved via the same content-address path the
//! `entity!` macro uses: a bnode's id is the Blake3 of its sorted and
//! deduplicated `NIL || attribute || value` rows. Two bnodes with the same
//! outgoing facts collapse to a single entity automatically — the bnode IS
//! the entity that has these facts. Orphan bnodes (referenced but never appear
//! as a subject) are instead skolemised from the immutable source-document
//! content hash and their literal label. Retrying byte-identical input
//! therefore reproduces the same ids, while different documents and labels
//! remain distinct. Cyclic blank-node graphs return
//! [`IngestError::BnodeCycle`] — there's no fixed-point id assignment
//! without symmetry-breaking, and we'd rather refuse than guess.
//!
//! ## API
//!
//! [`import_bytes`] is the core entry point — it parses a `Bytes`
//! buffer (e.g. a memory-mapped file, an over-the-wire payload, or a
//! `String::into_bytes`'d test fixture) without copying string slices.
//! [`import_blob`] is a convenience over `Blob<UTF8String>`, mirroring
//! [`crate::import::json::JsonObjectImporter::import_blob`].
//! [`ingest_ntriples`] adapts a `BufRead` by slurping it into a
//! `Bytes`. [`ingest_ntriples_file`] opens a path and forwards.
//!
//! Inside, the parser is winnow-driven over `anybytes::Bytes`. URI and
//! bnode label slices come back as `View<str>` — Arc-shared into the
//! input buffer, so storing them in the bnode-resolution buffer costs
//! nothing. Literal lexical forms come back as `Bytes`: zero-copy on
//! the no-escape fast path, freshly-allocated only when ECHAR / UCHAR
//! escapes forced decoding. ECHAR `\b`, `\f`, `\'`, `\n`, `\r`, `\t`,
//! `\"`, `\\` and UCHAR `\uXXXX` / `\UXXXXXXXX` are all supported in
//! both string literals and IRIs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{BufRead, Read};
use std::path::Path;

use anybytes::{Bytes, View};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use blake3::Hasher;
use hifitime::prelude::*;
use num_rational::Ratio;
use winnow::error::InputError;
use winnow::stream::Stream;
use winnow::token::{take, take_while};
use winnow::Parser;

use crate::blob::encodings::rawbytes::RawBytes;
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::{Blob, IntoBlob};
use crate::id::{ExclusiveId, Id, ID_LEN};
use crate::inline::encodings::boolean::Boolean;
use crate::inline::encodings::f64::F64;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::time::{i128_to_ordered_be, NsDuration, NsTAIInterval};
use crate::inline::encodings::UnknownInline;
use crate::inline::{Inline, IntoInline, RawInline};
use crate::macros::entity;
use crate::prelude::inlineencodings;
use crate::trible::{build_intrinsic_entity, Fragment, IntrinsicEntityRow, Trible, TribleSet};

const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

/// Blake3 derive-key context for document-scoped orphan blank-node ids.
///
/// This deliberately keeps skolem ids in a domain separate from both raw
/// document hashes and intrinsic entity ids. Changing it changes the identity
/// protocol.
const ORPHAN_BNODE_ID_CONTEXT: &str =
    "triblespace N-Triples document-scoped orphan blank-node id v1";

// ── Errors ──────────────────────────────────────────────────────────

/// Error returned by [`ingest_ntriples`] when the input cannot be
/// completed without compromising semantics.
#[derive(Debug, Clone)]
pub enum IngestError {
    /// A blank-node cycle was detected. Each label's intrinsic id depends
    /// on its neighbors' ids, so a cycle has no fixed-point assignment
    /// without a more elaborate symmetry-breaking scheme (see RDF-Canon's
    /// gossip-path algorithm). We refuse rather than emit something
    /// arbitrary.
    BnodeCycle {
        /// The bnode labels that participate in the unresolved cycle.
        labels: Vec<String>,
    },
    /// The underlying reader returned an I/O error.
    Io(String),
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BnodeCycle { labels } => {
                write!(f, "blank-node cycle in input: {}", labels.join(", "))
            }
            Self::Io(msg) => write!(f, "i/o error reading n-triples: {msg}"),
        }
    }
}

impl std::error::Error for IngestError {}

// ── Blank-node buffering ────────────────────────────────────────────
//
// Bnode identity in RDF is existential ("some thing with these
// properties"). We materialise that by deriving each bnode's
// triblespace `Id` from the set of its outgoing facts via the same
// content-hash the `entity!` macro uses — the bnode IS the entity that
// has these facts. Two bnodes with identical outgoing facts collapse
// to the same id automatically, which is what RDF semantics promise.
//
// For bnodes with no outgoing facts (only referenced from elsewhere),
// we retain a separate skolem protocol. Its scope is the byte-exact source
// document: `derive_key(document_content_hash || literal_label)`. Thus a
// retry of identical content converges, while distinct source documents and
// distinct labels remain distinct. This does not route factless nodes through
// the intrinsic empty-entity identity.
//
// Cycles in the bnode reference graph produce `IngestError::BnodeCycle`
// — there is no fixed point to assign without arbitrarily breaking
// symmetry, and we'd rather refuse than emit something wrong.

/// One outgoing edge from a bnode subject.
enum OutgoingFact {
    /// Fully-resolved value (URI handle, literal, lang-entity reference).
    Resolved { attr_id: Id, value_raw: RawInline },
    /// Bnode-to-bnode edge; both subject and target are deferred. The
    /// `attr_id` is already the GenId-typed predicate-attribute id.
    BnodeRef {
        attr_id: Id,
        target_label: View<str>,
    },
}

/// One triple of the form `<resolved_subject> <predicate> _:target`.
/// Emitted after `target` is resolved.
struct IncomingFact {
    subject_id: Id,
    attr_id: Id,
    target_label: View<str>,
}

/// Per-import buffer for blank-node triples. Keys are `View<str>`
/// slices into the underlying input `Bytes`, so storing a label costs
/// nothing — the slice Arc-shares the input buffer.
struct BnodeBuffer {
    /// Outgoing facts, keyed by bnode subject label.
    outgoing: HashMap<View<str>, Vec<OutgoingFact>>,
    /// Triples whose object is a bnode (subject is already resolved).
    incoming: Vec<IncomingFact>,
    /// Hash of the immutable, byte-exact source document. This scopes orphan
    /// blank-node labels without making retries produce fresh identities.
    document_hash: [u8; 32],
}

impl BnodeBuffer {
    fn new(document_hash: [u8; 32]) -> Self {
        Self {
            outgoing: HashMap::new(),
            incoming: Vec::new(),
            document_hash,
        }
    }

    fn is_empty(&self) -> bool {
        self.outgoing.is_empty() && self.incoming.is_empty()
    }

    fn push_outgoing(&mut self, label: View<str>, fact: OutgoingFact) {
        self.outgoing.entry(label).or_default().push(fact);
    }

    fn push_incoming(&mut self, fact: IncomingFact) {
        self.incoming.push(fact);
    }

    /// Resolve every buffered bnode and emit its tribles into `facts`.
    fn flush(self, facts: &mut TribleSet) -> Result<(), IngestError> {
        if self.is_empty() {
            return Ok(());
        }

        // 1. Build dependency graph: label → labels its outgoing facts reference.
        //    Also collect every label that appears anywhere (subject or target).
        let mut deps: HashMap<View<str>, HashSet<View<str>>> = HashMap::new();
        let mut all_labels: HashSet<View<str>> = HashSet::new();
        for (label, edges) in &self.outgoing {
            all_labels.insert(label.clone());
            let entry = deps.entry(label.clone()).or_default();
            for edge in edges {
                if let OutgoingFact::BnodeRef { target_label, .. } = edge {
                    entry.insert(target_label.clone());
                    all_labels.insert(target_label.clone());
                }
            }
        }
        for inc in &self.incoming {
            all_labels.insert(inc.target_label.clone());
        }

        // 2. Topo-sort. Cycle → error.
        let order = topo_sort(&all_labels, &deps).map_err(|labels| {
            let mut sorted: Vec<String> = labels.iter().map(|v| v.as_ref().to_owned()).collect();
            sorted.sort();
            IngestError::BnodeCycle { labels: sorted }
        })?;

        // 3. Resolve each bnode's id in dependency order. By the time
        //    we visit a label, all labels its outgoing facts reference
        //    are already in `resolved`. Non-orphans go through the exact
        //    canonical builder used by `entity!`; its returned facts are the
        //    complete defining rows for that intrinsic root.
        let mut resolved: HashMap<View<str>, Id> = HashMap::new();
        for label in order {
            let rows = bnode_rows(&label, &self.outgoing, &resolved);
            let (id, outgoing_facts) = if rows.is_empty() {
                (
                    resolve_orphan_bnode_id(&label, &self.document_hash),
                    TribleSet::new(),
                )
            } else {
                build_intrinsic_entity(rows)
            };
            *facts += outgoing_facts;
            resolved.insert(label, id);
        }

        // 4. Emit incoming tribles (bnode-as-object, subject already known).
        for inc in self.incoming {
            let target_id = resolved[&inc.target_label];
            let e = ExclusiveId::force_ref(&inc.subject_id);
            let g: Inline<GenId> = target_id.to_inline();
            let v: Inline<UnknownInline> = Inline::new(g.raw);
            facts.insert(&Trible::new(e, &inc.attr_id, &v));
        }

        Ok(())
    }
}

/// Project one bnode's outgoing facts into the canonical scratch rows consumed
/// by [`build_intrinsic_entity`].
fn bnode_rows(
    label: &View<str>,
    outgoing: &HashMap<View<str>, Vec<OutgoingFact>>,
    resolved: &HashMap<View<str>, Id>,
) -> Vec<IntrinsicEntityRow> {
    outgoing
        .get(label)
        .map(|edges| {
            edges
                .iter()
                .map(|edge| match edge {
                    OutgoingFact::Resolved { attr_id, value_raw } => (*attr_id, *value_raw),
                    OutgoingFact::BnodeRef {
                        attr_id,
                        target_label,
                    } => {
                        let target_id = resolved
                            .get(target_label)
                            .expect("topo order resolved this target first");
                        let v: Inline<GenId> = target_id.to_inline();
                        (*attr_id, v.raw)
                    }
                })
                .map(|(attribute, value)| IntrinsicEntityRow::new(attribute, value))
                .collect()
        })
        .unwrap_or_default()
}

/// Skolemise a blank node that is referenced but has no defining outgoing
/// facts. This intentionally remains outside the intrinsic entity identity
/// protocol. Its domain-separated scope is the byte-exact source document,
/// while the label keeps distinct orphans within that document separate.
fn resolve_orphan_bnode_id(label: &View<str>, document_hash: &[u8; 32]) -> Id {
    let mut hasher = Hasher::new_derive_key(ORPHAN_BNODE_ID_CONTEXT);
    hasher.update(document_hash);
    hasher.update(label.as_ref().as_bytes());
    let digest = hasher.finalize();
    let mut raw = [0u8; ID_LEN];
    raw.copy_from_slice(&digest.as_bytes()[digest.as_bytes().len() - ID_LEN..]);
    Id::new(raw).expect("document-scoped orphan id is non-nil")
}

/// Kahn's topological sort. Returns an ordering where every node comes
/// after the labels it depends on (its outgoing-fact targets). Returns
/// the unresolved cycle labels as `Err` if no full ordering exists.
fn topo_sort(
    nodes: &HashSet<View<str>>,
    edges: &HashMap<View<str>, HashSet<View<str>>>,
) -> Result<Vec<View<str>>, Vec<View<str>>> {
    let mut in_degree: HashMap<View<str>, usize> = nodes.iter().map(|n| (n.clone(), 0)).collect();
    for dsts in edges.values() {
        for dst in dsts {
            *in_degree.entry(dst.clone()).or_insert(0) += 1;
        }
    }
    let mut queue: VecDeque<View<str>> = in_degree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| n.clone())
        .collect();
    let mut order: Vec<View<str>> = Vec::with_capacity(nodes.len());
    while let Some(n) = queue.pop_front() {
        if let Some(dsts) = edges.get(&n) {
            for dst in dsts {
                let d = in_degree.get_mut(dst).expect("dst recorded above");
                *d -= 1;
                if *d == 0 {
                    queue.push_back(dst.clone());
                }
            }
        }
        order.push(n);
    }
    if order.len() < nodes.len() {
        let cycle: Vec<View<str>> = nodes
            .iter()
            .filter(|n| in_degree.get(*n).copied().unwrap_or(0) > 0)
            .cloned()
            .collect();
        Err(cycle)
    } else {
        // Edges point from a bnode to the bnodes its intrinsic rows depend on.
        // Kahn's walk above therefore discovers dependants first; resolution
        // needs the reverse order so every referenced id already exists.
        order.reverse();
        Ok(order)
    }
}

// ── Parsing — Bytes/winnow ──────────────────────────────────────────
//
// Each parser step takes `&mut Bytes` and returns a `View<str>` (or a
// `Bytes` for literal lexical forms whose fast/slow path differ). View
// slices Arc-share the input buffer, so storing them in `BnodeBuffer`
// across line-equivalent boundaries costs nothing — no copy or alloc.
// Mirrors `json::parse_string_common`'s shape.

/// What follows a closing `"` on an N-Triples literal:
/// `^^<datatype>`, `@language`, or nothing.
enum LiteralSuffix {
    None,
    Datatype(View<str>),
    Language(View<str>),
}

fn skip_ws_and_comments(bytes: &mut Bytes) {
    loop {
        // Eat whitespace bytes. N-Triples grammar permits HT/LF/CR/SP.
        while matches!(bytes.peek_token(), Some(b) if matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
            bytes.pop_front();
        }
        // Eat `# ... \n` comments.
        if bytes.peek_token() == Some(b'#') {
            while let Some(b) = bytes.pop_front() {
                if b == b'\n' {
                    break;
                }
            }
            continue;
        }
        break;
    }
}

fn skip_inline_ws(bytes: &mut Bytes) {
    while matches!(bytes.peek_token(), Some(b' ') | Some(b'\t')) {
        bytes.pop_front();
    }
}

/// Take an `<iri>` and return its content as a `View<str>`.
///
/// Fast path: scan for `>` with no `\` along the way → return the
/// slice directly, zero copy. Slow path (any `\u`/`\U` UCHAR escape):
/// decode into a fresh `Bytes`-backed buffer.
///
/// Per the N-Triples grammar, an IRIREF is `'<' (([^#x00-#x20<>"{}|^`\]
/// | UCHAR))* '>'` — bytes in `0x00..=0x20`, `<`, `>`, `"`, `{`, `}`,
/// `|`, `^`, `\`` and lone `\` are all rejected literal-form.
fn take_iri(bytes: &mut Bytes) -> Option<View<str>> {
    if bytes.peek_token() != Some(b'<') {
        return None;
    }
    bytes.pop_front();

    // Fast path: scan unescaped chars, rejecting any forbidden byte.
    {
        let mut tentative = bytes.clone();
        let mut take = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            // Accept: anything that isn't terminator (`>`), escape
            // (`\\`), or one of the spec-forbidden literal chars.
            b > 0x20
                && !matches!(
                    b,
                    b'<' | b'>' | b'"' | b'{' | b'}' | b'|' | b'^' | b'`' | b'\\'
                )
        });
        if let Ok(prefix) = take.parse_next(&mut tentative) {
            if tentative.peek_token() == Some(b'>') {
                tentative.pop_front();
                *bytes = tentative;
                return prefix.view::<str>().ok();
            }
        }
    }

    // Slow path: handle `\uXXXX` / `\UXXXXXXXX` escapes. We arrive
    // here only if the fast path bailed — either an escape was seen
    // or a forbidden byte was hit.
    let mut out: Vec<u8> = Vec::new();
    while let Some(b) = bytes.peek_token() {
        match b {
            b'>' => {
                bytes.pop_front();
                return Bytes::from_source(out).view::<str>().ok();
            }
            b'\\' => {
                bytes.pop_front();
                let kind = bytes.pop_front()?;
                let decoded = match kind {
                    b'u' => parse_uchar(bytes, 4)?,
                    b'U' => parse_uchar(bytes, 8)?,
                    _ => return None, // IRIs allow only UCHAR escapes
                };
                out.extend_from_slice(&decoded);
            }
            // Forbidden literal bytes — reject.
            0..=0x20 | b'<' | b'"' | b'{' | b'}' | b'|' | b'^' | b'`' => return None,
            _ => {
                out.push(b);
                bytes.pop_front();
            }
        }
    }
    None
}

/// Take a `_:label` blank-node label as a `View<str>`. Per BLANK_NODE_LABEL,
/// labels can contain dots in the middle — we terminate purely on
/// whitespace, since the triple-ending `.` is always preceded by it.
fn take_bnode(bytes: &mut Bytes) -> Option<View<str>> {
    if bytes.peek_token() != Some(b'_') {
        return None;
    }
    let mut tentative = bytes.clone();
    let mut prefix = take::<_, _, InputError<Bytes>>(2usize);
    let head = prefix.parse_next(&mut tentative).ok()?;
    if head.as_ref() != b"_:" {
        return None;
    }
    let mut take_label = take_while::<_, _, InputError<Bytes>>(1.., |b: u8| {
        !matches!(b, b' ' | b'\t' | b'\n' | b'\r')
    });
    let label = take_label.parse_next(&mut tentative).ok()?;
    *bytes = tentative;

    // Re-include the `_:` prefix so callers see the literal label form.
    // We rebuild from `out` rather than try to reconstruct a contiguous
    // slice — `View<str>` allocation cost is one Vec, comparable to a
    // `String::from`. (Future optimisation: have anybytes expose a
    // contiguous-slice constructor that re-merges adjacent Bytes.)
    let mut combined = Vec::with_capacity(2 + label.len());
    combined.extend_from_slice(b"_:");
    combined.extend_from_slice(label.as_ref());
    Bytes::from_source(combined).view::<str>().ok()
}

/// Take a `"..."` literal plus optional `^^<datatype>` / `@language`
/// suffix. Returns the lexical form as `Bytes` (use `.view::<str>()`)
/// — zero-copy on the no-escape fast path, freshly-allocated only when
/// escapes forced decoding.
fn take_literal(bytes: &mut Bytes) -> Option<(Bytes, LiteralSuffix)> {
    if bytes.peek_token() != Some(b'"') {
        return None;
    }
    bytes.pop_front();

    // Fast path: scan for the closing quote without any `\`.
    {
        let mut tentative = bytes.clone();
        let mut take = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            b != b'"' && b != b'\\' && b != b'\n' && b != b'\r'
        });
        if let Ok(prefix) = take.parse_next(&mut tentative) {
            if tentative.peek_token() == Some(b'"') {
                tentative.pop_front();
                *bytes = tentative;
                let suffix = parse_literal_suffix(bytes)?;
                return Some((prefix, suffix));
            }
        }
    }

    // Slow path: full ECHAR + UCHAR decoding.
    let mut out: Vec<u8> = Vec::new();
    loop {
        let b = bytes.peek_token()?;
        match b {
            b'"' => {
                bytes.pop_front();
                let suffix = parse_literal_suffix(bytes)?;
                return Some((Bytes::from_source(out), suffix));
            }
            b'\\' => {
                bytes.pop_front();
                let kind = bytes.pop_front()?;
                match kind {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'"' => out.push(b'"'),
                    b'\'' => out.push(b'\''),
                    b'\\' => out.push(b'\\'),
                    b'u' => {
                        let decoded = parse_uchar(bytes, 4)?;
                        out.extend_from_slice(&decoded);
                    }
                    b'U' => {
                        let decoded = parse_uchar(bytes, 8)?;
                        out.extend_from_slice(&decoded);
                    }
                    _ => return None,
                }
            }
            b'\n' | b'\r' => return None,
            _ => {
                out.push(b);
                bytes.pop_front();
            }
        }
    }
}

/// Decode `\uXXXX` (4 hex digits) or `\UXXXXXXXX` (8) into UTF-8 bytes.
/// Caller has already consumed the leading `\u` / `\U`.
fn parse_uchar(bytes: &mut Bytes, hex_digits: usize) -> Option<Vec<u8>> {
    let mut grab = take::<_, _, InputError<Bytes>>(hex_digits);
    let hex = grab.parse_next(bytes).ok()?;
    let mut code: u32 = 0;
    for h in hex.as_ref() {
        code = (code << 4)
            | match h {
                b'0'..=b'9' => (h - b'0') as u32,
                b'a'..=b'f' => (h - b'a' + 10) as u32,
                b'A'..=b'F' => (h - b'A' + 10) as u32,
                _ => return None,
            };
    }
    let ch = char::from_u32(code)?;
    let mut buf = [0u8; 4];
    Some(ch.encode_utf8(&mut buf).as_bytes().to_vec())
}

/// Match the optional `^^<datatype>` / `@language` suffix.
fn parse_literal_suffix(bytes: &mut Bytes) -> Option<LiteralSuffix> {
    match bytes.peek_token() {
        Some(b'^') => {
            // expect `^^`
            bytes.pop_front();
            if bytes.pop_front() != Some(b'^') {
                return None;
            }
            let dt = take_iri(bytes)?;
            Some(LiteralSuffix::Datatype(dt))
        }
        Some(b'@') => {
            bytes.pop_front();
            let mut take = take_while::<_, _, InputError<Bytes>>(1.., |b: u8| {
                b.is_ascii_alphanumeric() || b == b'-'
            });
            let tag = take.parse_next(bytes).ok()?;
            tag.view::<str>().ok().map(LiteralSuffix::Language)
        }
        _ => Some(LiteralSuffix::None),
    }
}

/// Parse a decimal string into a `Ratio<i128>`.
/// Handles `"3.14"` → `314/100`, `"42"` → `42/1`, `"-0.5"` → `-1/2`.
fn parse_decimal(s: &str) -> Option<Ratio<i128>> {
    if let Some(dot_pos) = s.find('.') {
        let decimals = s.len() - dot_pos - 1;
        let without_dot: String = s.chars().filter(|c| *c != '.').collect();
        let numerator: i128 = without_dot.parse().ok()?;
        let denominator: i128 = 10i128.checked_pow(decimals as u32)?;
        Some(Ratio::new(numerator, denominator))
    } else {
        let n: i128 = s.parse().ok()?;
        Some(Ratio::from_integer(n))
    }
}

// ── XSD temporal parsers ────────────────────────────────────────────
//
// xsd:dateTime / xsd:date / xsd:gYear* lexical forms are deliberately
// strict subsets of ISO 8601. We parse the components ourselves and
// hand them to hifitime's `from_gregorian_utc`, so leap-second handling
// and pre-Gregorian dates fall out of hifitime's correctness — we just
// have to be permissive about timezone notation (`Z`, `+HH:MM`,
// missing — RDF data uses all three).

/// Eat `[-]YYYY` from the front of `s`, returning the signed year and
/// the remainder. (Year-range overflow handled by hifitime's checked
/// constructor in `epoch_from_gregorian_with_offset`.)
fn parse_year(mut s: &str) -> Option<(i32, &str)> {
    let neg = if let Some(rest) = s.strip_prefix('-') {
        s = rest;
        true
    } else {
        false
    };
    let digits_end = s
        .as_bytes()
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    if digits_end < 4 {
        return None;
    }
    let year_abs: i64 = s[..digits_end].parse().ok()?;
    let year: i32 = if neg {
        i32::try_from(-year_abs).ok()?
    } else {
        i32::try_from(year_abs).ok()?
    };
    Some((year, &s[digits_end..]))
}

/// Strip an `xsd` timezone suffix (`Z` or `±HH:MM`) and return the
/// offset in seconds. Missing timezone → 0 (UTC convention for RDF).
fn parse_timezone_offset(s: &str) -> Option<i64> {
    if s.is_empty() {
        return Some(0);
    }
    if s == "Z" {
        return Some(0);
    }
    let bytes = s.as_bytes();
    let sign = match bytes.first()? {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    if bytes.len() != 6 || bytes[3] != b':' {
        return None;
    }
    let hh: i64 = std::str::from_utf8(&bytes[1..3]).ok()?.parse().ok()?;
    let mm: i64 = std::str::from_utf8(&bytes[4..6]).ok()?.parse().ok()?;
    Some(sign * (hh * 3600 + mm * 60))
}

/// Build an [`Epoch`] (UTC) from Gregorian fields and a timezone offset
/// in seconds. The offset is *subtracted* — `12:00 +05:00` is `07:00 UTC`.
fn epoch_from_gregorian_with_offset(
    year: i32,
    month: u8,
    day: u8,
    hh: u8,
    mm: u8,
    ss: u8,
    ns: u32,
    offset_secs: i64,
) -> Option<Epoch> {
    // hifitime panics on overflow when out of its representable range
    // (Wikidata has dateTime values like year 1e9 that hifitime can't
    // hold). Use the checked variant so we fall through to text
    // storage instead of crashing the importer.
    let local = Epoch::maybe_from_gregorian_utc(year, month, day, hh, mm, ss, ns).ok()?;
    Some(local - Duration::from_seconds(offset_secs as f64))
}

/// xsd:dateTime — `[-]YYYY-MM-DDThh:mm:ss[.f][Z|±HH:MM]`.
fn parse_xsd_datetime(s: &str) -> Option<i128> {
    let (year, rest) = parse_year(s)?;
    let mut chars = rest.as_bytes();
    if chars.first() != Some(&b'-') {
        return None;
    }
    let month: u8 = std::str::from_utf8(chars.get(1..3)?).ok()?.parse().ok()?;
    if chars.get(3) != Some(&b'-') {
        return None;
    }
    let day: u8 = std::str::from_utf8(chars.get(4..6)?).ok()?.parse().ok()?;
    if chars.get(6) != Some(&b'T') {
        return None;
    }
    let hh: u8 = std::str::from_utf8(chars.get(7..9)?).ok()?.parse().ok()?;
    if chars.get(9) != Some(&b':') {
        return None;
    }
    let mm: u8 = std::str::from_utf8(chars.get(10..12)?).ok()?.parse().ok()?;
    if chars.get(12) != Some(&b':') {
        return None;
    }
    let ss: u8 = std::str::from_utf8(chars.get(13..15)?).ok()?.parse().ok()?;
    chars = &chars[15..];

    let mut ns: u32 = 0;
    if chars.first() == Some(&b'.') {
        chars = &chars[1..];
        let frac_end = chars
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(chars.len());
        // Pad / truncate to 9 digits (nanosecond resolution).
        let frac_str = std::str::from_utf8(&chars[..frac_end]).ok()?;
        let mut padded = String::with_capacity(9);
        padded.push_str(frac_str);
        while padded.len() < 9 {
            padded.push('0');
        }
        ns = padded[..9].parse().ok()?;
        chars = &chars[frac_end..];
    }

    let tz = std::str::from_utf8(chars).ok()?;
    let offset = parse_timezone_offset(tz)?;
    let epoch = epoch_from_gregorian_with_offset(year, month, day, hh, mm, ss, ns, offset)?;
    Some(epoch.to_tai_duration().total_nanoseconds())
}

/// xsd:date — `[-]YYYY-MM-DD[Z|±HH:MM]`. Returned as inclusive bounds
/// `[day_start, day_end]`.
fn parse_xsd_date(s: &str) -> Option<(i128, i128)> {
    let (year, rest) = parse_year(s)?;
    let bytes = rest.as_bytes();
    if bytes.first() != Some(&b'-') {
        return None;
    }
    let month: u8 = std::str::from_utf8(bytes.get(1..3)?).ok()?.parse().ok()?;
    if bytes.get(3) != Some(&b'-') {
        return None;
    }
    let day: u8 = std::str::from_utf8(bytes.get(4..6)?).ok()?.parse().ok()?;
    let tz = std::str::from_utf8(&bytes[6..]).ok()?;
    let offset = parse_timezone_offset(tz)?;
    let lower = epoch_from_gregorian_with_offset(year, month, day, 0, 0, 0, 0, offset)?
        .to_tai_duration()
        .total_nanoseconds();
    // Day end: lower + 86_400 s - 1 ns. (Inclusive upper.)
    let upper = lower.checked_add(86_400_000_000_000i128 - 1)?;
    Some((lower, upper))
}

/// xsd:gYear — `[-]YYYY[Z|±HH:MM]`. Returned as the whole year as an
/// inclusive interval.
fn parse_xsd_gyear(s: &str) -> Option<(i128, i128)> {
    let (year, rest) = parse_year(s)?;
    let offset = parse_timezone_offset(rest)?;
    let lower = epoch_from_gregorian_with_offset(year, 1, 1, 0, 0, 0, 0, offset)?
        .to_tai_duration()
        .total_nanoseconds();
    let next_year = year.checked_add(1)?;
    let upper_excl = epoch_from_gregorian_with_offset(next_year, 1, 1, 0, 0, 0, 0, offset)?
        .to_tai_duration()
        .total_nanoseconds();
    Some((lower, upper_excl.checked_sub(1)?))
}

/// xsd:gYearMonth — `[-]YYYY-MM[Z|±HH:MM]`. Whole month, inclusive.
fn parse_xsd_gyearmonth(s: &str) -> Option<(i128, i128)> {
    let (year, rest) = parse_year(s)?;
    let bytes = rest.as_bytes();
    if bytes.first() != Some(&b'-') {
        return None;
    }
    let month: u8 = std::str::from_utf8(bytes.get(1..3)?).ok()?.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let tz = std::str::from_utf8(&bytes[3..]).ok()?;
    let offset = parse_timezone_offset(tz)?;
    let lower = epoch_from_gregorian_with_offset(year, month, 1, 0, 0, 0, 0, offset)?
        .to_tai_duration()
        .total_nanoseconds();
    let (next_year, next_month) = if month == 12 {
        (year.checked_add(1)?, 1u8)
    } else {
        (year, month + 1)
    };
    let upper_excl =
        epoch_from_gregorian_with_offset(next_year, next_month, 1, 0, 0, 0, 0, offset)?
            .to_tai_duration()
            .total_nanoseconds();
    Some((lower, upper_excl.checked_sub(1)?))
}

/// xsd:duration — `[-]P[nY][nM][nD][T[nH][nM][nS]]`. We reject mixed
/// year/month durations (their second-count depends on context); pure
/// dayTime durations (`PnDTnHnMnS`) convert to a single ns count.
fn parse_xsd_duration(s: &str) -> Option<i128> {
    let mut s = s;
    let neg = if let Some(rest) = s.strip_prefix('-') {
        s = rest;
        true
    } else {
        false
    };
    let mut s = s.strip_prefix('P')?;
    let mut total_ns: i128 = 0;

    let mut in_time = false;
    while !s.is_empty() {
        if let Some(rest) = s.strip_prefix('T') {
            in_time = true;
            s = rest;
            continue;
        }
        let num_end = s
            .as_bytes()
            .iter()
            .position(|b| !(b.is_ascii_digit() || *b == b'.'))?;
        let num_str = &s[..num_end];
        let unit = s.as_bytes().get(num_end).copied()?;
        s = &s[num_end + 1..];
        let value: f64 = num_str.parse().ok()?;
        match (in_time, unit) {
            (false, b'Y') | (false, b'M') => {
                // Years and months can't be expressed in fixed ns —
                // their second count depends on which year/month.
                return None;
            }
            (false, b'D') => total_ns = total_ns.checked_add((value * 86_400e9) as i128)?,
            (true, b'H') => total_ns = total_ns.checked_add((value * 3_600e9) as i128)?,
            (true, b'M') => total_ns = total_ns.checked_add((value * 60e9) as i128)?,
            (true, b'S') => total_ns = total_ns.checked_add((value * 1e9) as i128)?,
            _ => return None,
        }
    }
    Some(if neg { -total_ns } else { total_ns })
}

// ── URI → Id ────────────────────────────────────────────────────────

/// Map an RDF URI to a triblespace [`Id`] deterministically by routing
/// it through an `rdf_uri` fragment, without storing anything. The
/// same URI always produces the same `Id` — across processes,
/// machines, and repeated imports — so callers can derive ids for
/// query constants that match what [`import_bytes`] inserts.
pub fn uri_to_id_pure(uri: &str) -> Id {
    let handle: Inline<Handle<UTF8String>> = uri.to_owned().to_blob().get_handle();
    let fragment = entity! { crate::import::rdf_uri: handle };
    fragment.root().expect("intrinsic URI entity")
}

/// Record `uri` into the URI-map fragment — the URI-string blob plus the
/// `rdf_uri` annotation trible referencing it — and return the URI's
/// intrinsic entity id. One blob hash derives the handle, the
/// annotation entity, and the id; idempotent under content
/// addressing, so repeated mentions of the same URI cost a hash and
/// two no-op inserts.
///
/// The annotation's export is deliberately not propagated: URI annotations
/// are queryable mapping facts, not roots in the imported fragment's public
/// interface. `import_bytes` attaches the `rdf_uri` vocabulary once after all
/// annotations have been collected.
fn record_uri(uri_map: &mut Fragment, uri: impl IntoBlob<UTF8String>) -> Id {
    let handle: Inline<Handle<UTF8String>> = uri_map.put(uri);
    let annotation = entity! { crate::import::rdf_uri: handle };
    let id = annotation.root().expect("intrinsic URI entity");
    *uri_map += annotation.into_facts();
    id
}

/// Merge every channel of `part` into `whole` except its exports.
///
/// Reified language literals are implementation details of an N-Triples
/// import, so exporting each one would unnecessarily bloat the fragment's
/// interface. Their facts, descriptions, and shared blob store still have to
/// travel together.
fn merge_without_exports(whole: &mut Fragment, part: Fragment) {
    let (_, facts, metafacts, blobs) = part.into_parts();
    *whole.facts_mut() += facts;
    *whole.metafacts_mut() += metafacts;
    whole.blobs_mut().union(blobs);
}

// ── Ingestion ───────────────────────────────────────────────────────

/// An imported N-Triples document. Both fields are self-contained
/// [`Fragment`]s — facts plus the blobs those facts reference — which
/// is what lets the importer be a pure function of the input bytes:
/// no workspace is touched until the caller decides where the result
/// should live.
///
/// `facts` is the faithful translation of the source document — one
/// trible per source triple, carrying the literal blobs (string
/// values, hex/base64 payloads) its tribles reference by handle.
/// Queries over `facts` see exactly the rows a SPARQL engine over
/// the same document would.
///
/// Every attribute minted from a predicate IRI describes itself in
/// `facts`'s metafacts, including the source-IRI blob in the fragment's shared
/// blob store. Committing `facts` therefore cannot discard its vocabulary.
///
/// `uri_map` is separate because entity URI↔id annotations are optional,
/// queryable content rather than schema. A caller may merge it into `facts`,
/// attach it as additional metadata with `describe_with`, or drop it when URI
/// recovery is not required.
#[derive(Debug)]
pub struct NtImport {
    /// The imported graph — one trible per source triple, with the
    /// literal blobs those tribles reference embedded and descriptions of
    /// every predicate attribute carried in its metafacts.
    pub facts: Fragment,
    /// The URI↔id inverse mapping: one `rdf_uri` annotation per distinct
    /// entity IRI plus the URI-string blobs those annotations reference.
    pub uri_map: Fragment,
    /// Number of triples parsed.
    pub triples: usize,
}

/// Import an N-Triples document already loaded as `Bytes`. This is the
/// core entry point — every other adapter funnels here. Pure: the
/// result fragments carry their own blobs, so no workspace or blob
/// store is needed (or touched) during parsing.
pub fn import_bytes(mut bytes: Bytes) -> Result<NtImport, IngestError> {
    // Hash before parsing advances the view. `Bytes::as_ref()` is exactly the
    // caller-provided document slice, including otherwise insignificant
    // whitespace and comments: identical serialized content is one
    // content-addressed document regardless of how often it is ingested.
    let document_hash = *blake3::hash(bytes.as_ref()).as_bytes();
    let mut facts = Fragment::empty();
    let mut uri_map = Fragment::empty();
    let mut bnodes = BnodeBuffer::new(document_hash);
    let mut count = 0;
    let mut attr_cache = NTriplesAttrCache::default();

    loop {
        skip_ws_and_comments(&mut bytes);
        if bytes.peek_token().is_none() {
            break;
        }
        if parse_triple(
            &mut facts,
            &mut uri_map,
            &mut bnodes,
            &mut bytes,
            &mut attr_cache,
        ) {
            count += 1;
        } else {
            // Malformed triple — skip to next newline so a single bad
            // line doesn't abort the import. Mirrors the line-skip
            // tolerance the BufRead version had.
            while let Some(b) = bytes.pop_front() {
                if b == b'\n' {
                    break;
                }
            }
        }
    }

    bnodes.flush(facts.facts_mut())?;
    // `record_uri` drops per-annotation exports and descriptions on purpose;
    // one shared description is sufficient and keeps metafacts a cover of the
    // mapping facts actually present.
    if !uri_map.facts().is_empty() {
        uri_map.describe_with(crate::import::rdf_uri.meta().clone());
    }
    Ok(NtImport {
        facts,
        uri_map,
        triples: count,
    })
}

/// Convenience wrapper around [`import_bytes`] for a `Blob<UTF8String>`
/// — the on-disk / on-wire representation N-Triples shows up as.
pub fn import_blob(blob: Blob<UTF8String>) -> Result<NtImport, IngestError> {
    import_bytes(blob.bytes)
}

/// `BufRead` adapter — slurps the reader into a `Bytes` and forwards
/// to [`import_bytes`].
pub fn ingest_ntriples(mut reader: impl BufRead) -> Result<NtImport, IngestError> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| IngestError::Io(e.to_string()))?;
    import_bytes(Bytes::from_source(buf))
}

/// Parse one triple from the front of `bytes` and emit its facts.
/// Plain triples emit directly into `facts`; triples touching a blank
/// node go into `bnodes` for deferred resolution. Returns `true` on
/// success, `false` on malformed input (caller skips to next line).
/// Per-import cache of predicate-IRI → attribute-id, one slot per value
/// schema the parser dispatches to. Resolution computes
/// `entity!{ metadata::iri:, metadata::value_encoding: }.root()` —
/// `<S as MetaDescribe>::id()` plus a content-address per call, both
/// nontrivial — so caching by (S, IRI) avoids redoing that work for
/// every trible sharing a predicate.
///
/// First resolution per `(S, IRI)` also describes the attribute into the
/// content fragment that uses it. The describing entity
/// (`metadata::iri` + `metadata::value_encoding`) travels in metafacts while
/// its source-IRI blob lives in the same shared fragment store.
#[derive(Default)]
struct NTriplesAttrCache {
    genid: HashMap<String, Id>,
    utf8string: HashMap<String, Id>,
    rawbytes: HashMap<String, Id>,
    i256be: HashMap<String, Id>,
    u256be: HashMap<String, Id>,
    r256be: HashMap<String, Id>,
    f64: HashMap<String, Id>,
    boolean: HashMap<String, Id>,
    nsduration: HashMap<String, Id>,
    nstai: HashMap<String, Id>,
}

impl NTriplesAttrCache {
    /// Shared resolver: derive (and memoise) the attribute id for
    /// `(S, iri)`, describing it into `facts` on first encounter.
    fn resolve<S: crate::inline::InlineEncoding + crate::metadata::MetaDescribe>(
        map: &mut HashMap<String, Id>,
        facts: &mut Fragment,
        iri: &str,
    ) -> Id {
        if let Some(id) = map.get(iri) {
            return *id;
        }
        let attribute = crate::attribute::Attribute::<S>::iri(iri);
        let id = attribute.id();
        facts.describe_with(attribute.fragment().clone());
        map.insert(iri.to_string(), id);
        id
    }

    fn genid(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::GenId>(&mut self.genid, facts, iri)
    }
    fn utf8string(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<Handle<UTF8String>>(&mut self.utf8string, facts, iri)
    }
    fn rawbytes(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<Handle<RawBytes>>(&mut self.rawbytes, facts, iri)
    }
    fn i256be(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::I256BE>(&mut self.i256be, facts, iri)
    }
    fn u256be(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::U256BE>(&mut self.u256be, facts, iri)
    }
    fn r256be(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::R256BE>(&mut self.r256be, facts, iri)
    }
    fn f64(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::F64>(&mut self.f64, facts, iri)
    }
    fn boolean(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<inlineencodings::Boolean>(&mut self.boolean, facts, iri)
    }
    fn nsduration(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<NsDuration>(&mut self.nsduration, facts, iri)
    }
    fn nstai(&mut self, facts: &mut Fragment, iri: &str) -> Id {
        Self::resolve::<NsTAIInterval>(&mut self.nstai, facts, iri)
    }
}

fn parse_triple(
    facts: &mut Fragment,
    uri_map: &mut Fragment,
    bnodes: &mut BnodeBuffer,
    bytes: &mut Bytes,
    attr_cache: &mut NTriplesAttrCache,
) -> bool {
    // Subject — IRI or bnode label.
    let (subject_iri, subject_label): (Option<View<str>>, Option<View<str>>) =
        match bytes.peek_token() {
            Some(b'<') => match take_iri(bytes) {
                Some(uri) => (Some(uri), None),
                None => return false,
            },
            Some(b'_') => match take_bnode(bytes) {
                Some(label) => (None, Some(label)),
                None => return false,
            },
            _ => return false,
        };
    skip_inline_ws(bytes);

    let Some(predicate) = take_iri(bytes) else {
        return false;
    };
    skip_inline_ws(bytes);

    // Anchor the IRI subject up front so its rdf_uri annotation lands
    // before any emission. Bnode subjects resolve in `flush`.
    let iri_subject_anchor: Option<Id> = subject_iri
        .as_ref()
        .map(|uri| record_uri(uri_map, uri.clone()));

    // Object — IRI, bnode, or literal.
    let outcome = match bytes.peek_token() {
        Some(b'<') => {
            let Some(obj_uri) = take_iri(bytes) else {
                return false;
            };
            emit_object_iri(
                facts,
                uri_map,
                bnodes,
                iri_subject_anchor,
                subject_label,
                predicate.as_ref(),
                obj_uri,
                attr_cache,
            );
            true
        }
        Some(b'_') => {
            let Some(target_label) = take_bnode(bytes) else {
                return false;
            };
            let attr_id = attr_cache.genid(facts, predicate.as_ref());
            match (iri_subject_anchor, subject_label) {
                (Some(s_id), None) => {
                    bnodes.push_incoming(IncomingFact {
                        subject_id: s_id,
                        attr_id,
                        target_label,
                    });
                }
                (None, Some(s_label)) => {
                    bnodes.push_outgoing(
                        s_label,
                        OutgoingFact::BnodeRef {
                            attr_id,
                            target_label,
                        },
                    );
                }
                _ => return false,
            }
            true
        }
        Some(b'"') => {
            let Some((text_bytes, suffix)) = take_literal(bytes) else {
                return false;
            };
            let Ok(text) = text_bytes.view::<str>() else {
                return false;
            };
            match (iri_subject_anchor, subject_label) {
                (Some(s_id), None) => {
                    let e = ExclusiveId::force_ref(&s_id);
                    match suffix {
                        LiteralSuffix::None => {
                            emit_text_literal(facts, e, predicate.as_ref(), text, attr_cache)
                        }
                        LiteralSuffix::Datatype(dt) => emit_typed_literal(
                            facts,
                            uri_map,
                            e,
                            predicate.as_ref(),
                            text,
                            dt.as_ref(),
                            attr_cache,
                        ),
                        LiteralSuffix::Language(lang) => emit_lang_literal(
                            facts,
                            e,
                            predicate.as_ref(),
                            lang.as_ref(),
                            text,
                            attr_cache,
                        ),
                    }
                }
                (None, Some(s_label)) => {
                    if let Some(fact) = build_resolved_outgoing(
                        facts,
                        uri_map,
                        predicate.as_ref(),
                        text,
                        suffix,
                        attr_cache,
                    ) {
                        bnodes.push_outgoing(s_label, fact);
                    }
                }
                _ => return false,
            }
            true
        }
        _ => false,
    };

    if outcome {
        skip_inline_ws(bytes);
        // The trailing `.` terminator. Tolerant: missing-dot gets the
        // line skipped by the outer loop.
        if bytes.peek_token() != Some(b'.') {
            return false;
        }
        bytes.pop_front();
    }
    outcome
}

fn emit_object_iri(
    facts: &mut Fragment,
    uri_map: &mut Fragment,
    bnodes: &mut BnodeBuffer,
    iri_subject_anchor: Option<Id>,
    subject_label: Option<View<str>>,
    predicate: &str,
    obj_uri: View<str>,
    attr_cache: &mut NTriplesAttrCache,
) {
    match (iri_subject_anchor, subject_label) {
        (Some(s_id), None) => {
            emit_uri_object(
                facts,
                uri_map,
                &ExclusiveId::force_ref(&s_id),
                predicate,
                obj_uri.as_ref(),
                attr_cache,
            );
        }
        (None, Some(s_label)) => {
            let attr_id = attr_cache.genid(facts, predicate);
            let obj_id = record_uri(uri_map, obj_uri);
            let g: Inline<GenId> = obj_id.to_inline();
            bnodes.push_outgoing(
                s_label,
                OutgoingFact::Resolved {
                    attr_id,
                    value_raw: g.raw,
                },
            );
        }
        _ => {}
    }
}

/// Materialise a literal-valued bnode-outgoing fact: blob writes /
/// reified-language entities happen now, and we hand back the
/// (attr_id, value_raw) pair to be inserted once the bnode subject id
/// is resolved.
fn build_resolved_outgoing(
    facts: &mut Fragment,
    uri_map: &mut Fragment,
    predicate: &str,
    text: View<str>,
    suffix: LiteralSuffix,
    attr_cache: &mut NTriplesAttrCache,
) -> Option<OutgoingFact> {
    match suffix {
        LiteralSuffix::None => {
            let attr_id = attr_cache.utf8string(facts, predicate);
            let handle: Inline<Handle<UTF8String>> = facts.put(text);
            Some(OutgoingFact::Resolved {
                attr_id,
                value_raw: handle.raw,
            })
        }
        LiteralSuffix::Datatype(dt) => {
            // Build a temporary scratch fragment to reuse the existing
            // emit_typed_literal logic, then steal the (attr, value)
            // back out of it. Cheaper than re-implementing per-type.
            let mut scratch = Fragment::empty();
            let scratch_id = Id::new([0xFF; ID_LEN]).expect("non-nil scratch id");
            let scratch_e = ExclusiveId::force_ref(&scratch_id);
            // The scratch fragment only captures the (attr, value)
            // pair; rdf_uri annotations (the anyURI path) go to the
            // real `uri_map` fragment — they're valid import provenance
            // regardless of how the parent bnode resolves.
            emit_typed_literal(
                &mut scratch,
                uri_map,
                scratch_e,
                predicate,
                text,
                dt.as_ref(),
                attr_cache,
            );
            // Any blobs the typed emit produced (hex/base64 payloads) are real
            // content the stolen value handle references. The attribute
            // description is equally real: the resolver memoises `(schema,
            // IRI)`, so if this scratch path first sees a predicate, dropping
            // its metafacts would make every later cache hit undescribed.
            let (_, scratch_facts, scratch_metafacts, scratch_blobs) = scratch.into_parts();
            facts.blobs_mut().union(scratch_blobs);
            *facts.metafacts_mut() += scratch_metafacts;
            let pair = scratch_facts
                .iter()
                .next()
                .map(|t| (*t.a(), t.v::<UnknownInline>().raw));
            pair.map(|(attr_id, value_raw)| OutgoingFact::Resolved { attr_id, value_raw })
        }
        LiteralSuffix::Language(lang) => {
            // Reify into the @lang entity now; the parent bnode's
            // outgoing fact carries a GenId reference to it. Side
            // effects (the lang-entity tribles) land in `facts`
            // immediately since they don't depend on the parent id.
            let lang: &str = lang.as_ref();
            let lang_value: Inline<Handle<UTF8String>> = facts.put(lang);
            let text_handle: Inline<Handle<UTF8String>> = facts.put(text);
            let label_fragment = entity! {
                crate::import::rdf_lang: lang_value,
                crate::import::rdf_text: text_handle,
            };
            let label_id = label_fragment
                .root()
                .expect("intrinsic id from rdf_lang+rdf_text");
            merge_without_exports(facts, label_fragment);
            let attr_id = attr_cache.genid(facts, predicate);
            let g: Inline<GenId> = label_id.to_inline();
            Some(OutgoingFact::Resolved {
                attr_id,
                value_raw: g.raw,
            })
        }
    }
}

fn emit_uri_object(
    facts: &mut Fragment,
    uri_map: &mut Fragment,
    e: &ExclusiveId,
    predicate: &str,
    obj_uri: &str,
    attr_cache: &mut NTriplesAttrCache,
) {
    let attr_id = attr_cache.genid(facts, predicate);
    let obj_id = record_uri(uri_map, obj_uri.to_owned());
    let g: Inline<GenId> = obj_id.to_inline();
    facts.facts_mut().insert(&Trible::new(e, &attr_id, &g));
}

fn emit_text_literal(
    facts: &mut Fragment,
    e: &ExclusiveId,
    predicate: &str,
    text: View<str>,
    attr_cache: &mut NTriplesAttrCache,
) {
    let attr_id = attr_cache.utf8string(facts, predicate);
    let handle: Inline<Handle<UTF8String>> = facts.put(text);
    facts.facts_mut().insert(&Trible::new(e, &attr_id, &handle));
}

fn emit_typed_literal(
    facts: &mut Fragment,
    uri_map: &mut Fragment,
    e: &ExclusiveId,
    predicate: &str,
    text: View<str>,
    datatype: &str,
    attr_cache: &mut NTriplesAttrCache,
) {
    if let Some(local) = datatype.strip_prefix(XSD) {
        match local {
            "integer" | "int" | "long" | "short" | "byte" | "negativeInteger"
            | "nonPositiveInteger" => {
                if let Ok(val) = text.parse::<i128>() {
                    let attr_id = attr_cache.i256be(facts, predicate);
                    let v: Inline<inlineencodings::I256BE> = val.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
            }
            "nonNegativeInteger" | "positiveInteger" | "unsignedInt" | "unsignedLong"
            | "unsignedShort" | "unsignedByte" => {
                if let Ok(val) = text.parse::<u128>() {
                    let attr_id = attr_cache.u256be(facts, predicate);
                    let v: Inline<inlineencodings::U256BE> = val.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
            }
            "decimal" => {
                if let Some(val) = parse_decimal(text.as_ref()) {
                    let attr_id = attr_cache.r256be(facts, predicate);
                    let v: Inline<inlineencodings::R256BE> = val.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
            }
            "float" | "double" => {
                if let Ok(val) = text.parse::<f64>() {
                    let attr_id = attr_cache.f64(facts, predicate);
                    let v: Inline<F64> = val.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
            }
            "boolean" => match text.as_ref() {
                "true" | "1" => {
                    let attr_id = attr_cache.boolean(facts, predicate);
                    let v: Inline<Boolean> = true.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
                "false" | "0" => {
                    let attr_id = attr_cache.boolean(facts, predicate);
                    let v: Inline<Boolean> = false.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
                _ => {}
            },
            "dateTime" => {
                if let Some(ns) = parse_xsd_datetime(text.as_ref()) {
                    emit_interval(facts, e, predicate, ns, ns, attr_cache);
                    return;
                }
            }
            "date" => {
                if let Some((lo, hi)) = parse_xsd_date(text.as_ref()) {
                    emit_interval(facts, e, predicate, lo, hi, attr_cache);
                    return;
                }
            }
            "gYear" => {
                if let Some((lo, hi)) = parse_xsd_gyear(text.as_ref()) {
                    emit_interval(facts, e, predicate, lo, hi, attr_cache);
                    return;
                }
            }
            "gYearMonth" => {
                if let Some((lo, hi)) = parse_xsd_gyearmonth(text.as_ref()) {
                    emit_interval(facts, e, predicate, lo, hi, attr_cache);
                    return;
                }
            }
            "duration" | "dayTimeDuration" => {
                if let Some(ns) = parse_xsd_duration(text.as_ref()) {
                    let attr_id = attr_cache.nsduration(facts, predicate);
                    let v: Inline<NsDuration> = ns.to_inline();
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
                    return;
                }
            }
            "hexBinary" => {
                if let Ok(bytes) = hex::decode(text.as_ref()) {
                    let attr_id = attr_cache.rawbytes(facts, predicate);
                    let handle: Inline<Handle<RawBytes>> = facts.put(bytes);
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &handle));
                    return;
                }
            }
            "base64Binary" => {
                if let Ok(bytes) = BASE64.decode(text.as_ref()) {
                    let attr_id = attr_cache.rawbytes(facts, predicate);
                    let handle: Inline<Handle<RawBytes>> = facts.put(bytes);
                    facts.facts_mut().insert(&Trible::new(e, &attr_id, &handle));
                    return;
                }
            }
            "anyURI" => {
                // Treat the literal as an IRI reference — same path as
                // bracketed `<...>` objects, so `"http://x"^^xsd:anyURI`
                // and `<http://x>` collapse to the same entity id.
                emit_uri_object(facts, uri_map, e, predicate, text.as_ref(), attr_cache);
                return;
            }
            _ => {}
        }
    }
    // Unknown / unparseable typed literal: fall back to text storage.
    emit_text_literal(facts, e, predicate, text, attr_cache);
}

/// Helper to emit an `[lo, hi]` interval trible.
fn emit_interval(
    facts: &mut Fragment,
    e: &ExclusiveId,
    predicate: &str,
    lo: i128,
    hi: i128,
    attr_cache: &mut NTriplesAttrCache,
) {
    let attr_id = attr_cache.nstai(facts, predicate);
    let mut raw = [0u8; 32];
    raw[0..16].copy_from_slice(&i128_to_ordered_be(lo));
    raw[16..32].copy_from_slice(&i128_to_ordered_be(hi));
    let v: Inline<NsTAIInterval> = Inline::new(raw);
    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
}

fn emit_lang_literal(
    facts: &mut Fragment,
    e: &ExclusiveId,
    predicate: &str,
    lang: &str,
    text: View<str>,
    attr_cache: &mut NTriplesAttrCache,
) {
    // Reify `"text"@lang` into a small entity carrying `rdf_lang` and
    // `rdf_text`. The intrinsic id derived from those facts dedupes
    // `(lang, text)` pairs across the whole import.
    let lang_value: Inline<Handle<UTF8String>> = facts.put(lang);
    let text_handle: Inline<Handle<UTF8String>> = facts.put(text);
    let label_fragment = entity! {
        crate::import::rdf_lang: lang_value,
        crate::import::rdf_text: text_handle,
    };
    let label_id = label_fragment
        .root()
        .expect("intrinsic id from rdf_lang+rdf_text");
    merge_without_exports(facts, label_fragment);
    let attr_id = attr_cache.genid(facts, predicate);
    let v: Inline<GenId> = label_id.to_inline();
    facts.facts_mut().insert(&Trible::new(e, &attr_id, &v));
}

/// Convenience wrapper around [`import_bytes`] that opens a file at
/// `path`, slurps it into a `Bytes`, and ingests.
pub fn ingest_ntriples_file(path: &Path) -> Result<NtImport, IngestError> {
    let file = std::fs::File::open(path).map_err(|e| IngestError::Io(e.to_string()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| IngestError::Io(e.to_string()))?;
    import_bytes(Bytes::from_source(buf))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_of(s: &str) -> Bytes {
        Bytes::from_source(s.as_bytes().to_vec())
    }

    #[test]
    fn take_iri_consumes_brackets() {
        let mut input = bytes_of("<http://example.org/s> rest");
        let iri = take_iri(&mut input).unwrap();
        assert_eq!(iri.as_ref(), "http://example.org/s");
        // Remaining bytes should start with " rest".
        let remaining: Vec<u8> = (0..).scan(input.clone(), |b, _| b.pop_front()).collect();
        assert_eq!(&remaining[..5], b" rest");
    }

    #[test]
    fn take_bnode_includes_prefix() {
        let mut input = bytes_of("_:bf55954f96378f65ddb1da9836e2eb87 .");
        let label = take_bnode(&mut input).unwrap();
        assert_eq!(label.as_ref(), "_:bf55954f96378f65ddb1da9836e2eb87");
    }

    #[test]
    fn take_bnode_allows_internal_dot() {
        // BLANK_NODE_LABEL grammar permits dots in the middle of labels.
        // The trailing triple-`.` is always preceded by whitespace, so
        // whitespace-only termination handles both.
        let mut input = bytes_of("_:foo.bar .");
        let label = take_bnode(&mut input).unwrap();
        assert_eq!(label.as_ref(), "_:foo.bar");
    }

    #[test]
    fn take_literal_unescaped() {
        let mut input = bytes_of(r#""hello" ."#);
        let (text, suffix) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "hello");
        assert!(matches!(suffix, LiteralSuffix::None));
    }

    #[test]
    fn take_literal_with_datatype_suffix() {
        let mut input = bytes_of(r#""42"^^<http://www.w3.org/2001/XMLSchema#integer> ."#);
        let (text, suffix) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "42");
        assert!(matches!(
            suffix,
            LiteralSuffix::Datatype(ref dt)
                if dt.as_ref() == "http://www.w3.org/2001/XMLSchema#integer"
        ));
    }

    #[test]
    fn take_literal_with_lang_tag() {
        let mut input = bytes_of(r#""hello"@en ."#);
        let (text, suffix) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "hello");
        assert!(matches!(
            suffix,
            LiteralSuffix::Language(ref tag) if tag.as_ref() == "en"
        ));
    }

    #[test]
    fn take_literal_with_lang_region() {
        let mut input = bytes_of(r#""labor"@en-US ."#);
        let (text, suffix) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "labor");
        assert!(matches!(
            suffix,
            LiteralSuffix::Language(ref tag) if tag.as_ref() == "en-US"
        ));
    }

    #[test]
    fn take_literal_with_basic_escapes() {
        let mut input = bytes_of(r#""line\nbreak" ."#);
        let (text, _) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "line\nbreak");
    }

    #[test]
    fn take_literal_with_extended_echar() {
        // \b, \f, \' are valid N-Triples ECHAR but were previously unsupported.
        let mut input = bytes_of(r#""a\bb\fc\'d" ."#);
        let (text, _) = take_literal(&mut input).unwrap();
        assert_eq!(
            text.view::<str>().unwrap().as_ref(),
            "a\u{0008}b\u{000c}c'd"
        );
    }

    #[test]
    fn take_literal_with_unicode_escape_4() {
        let mut input = bytes_of(r#""smile ☺ here" ."#);
        let (text, _) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "smile ☺ here");
    }

    #[test]
    fn take_literal_with_unicode_escape_8() {
        // \U with 8 hex digits — N-Triples-only (JSON has no \U).
        let mut input = bytes_of(r#""grin \U0001F600 here" ."#);
        let (text, _) = take_literal(&mut input).unwrap();
        assert_eq!(text.view::<str>().unwrap().as_ref(), "grin 😀 here");
    }

    #[test]
    fn take_iri_with_unicode_escape() {
        // IRIs may carry \u escapes for non-ASCII path components.
        let mut input = bytes_of(r#"<http://ex/é> rest"#);
        let iri = take_iri(&mut input).unwrap();
        assert_eq!(iri.as_ref(), "http://ex/é");
    }

    #[test]
    fn decimal_parse_helper() {
        let r = parse_decimal("3.14").unwrap();
        assert_eq!(*r.numer(), 157);
        assert_eq!(*r.denom(), 50);

        let r = parse_decimal("42").unwrap();
        assert_eq!(*r.numer(), 42);
        assert_eq!(*r.denom(), 1);

        let r = parse_decimal("-0.5").unwrap();
        assert_eq!(*r.numer(), -1);
        assert_eq!(*r.denom(), 2);
    }

    #[test]
    fn xsd_datetime_z_and_offset() {
        // The two strings should parse to the same instant.
        let utc = parse_xsd_datetime("2020-01-01T12:00:00Z").unwrap();
        let plus5 = parse_xsd_datetime("2020-01-01T17:00:00+05:00").unwrap();
        assert_eq!(utc, plus5);
    }

    #[test]
    fn xsd_datetime_with_fractional_seconds() {
        let no_frac = parse_xsd_datetime("2020-01-01T00:00:00Z").unwrap();
        let with_frac = parse_xsd_datetime("2020-01-01T00:00:00.5Z").unwrap();
        assert_eq!(with_frac - no_frac, 500_000_000);
    }

    #[test]
    fn xsd_datetime_bce_year() {
        // Negative year → year before 1 CE in proleptic Gregorian.
        // Just check it parses (round-trip semantics is hifitime's problem).
        assert!(parse_xsd_datetime("-0500-01-01T00:00:00Z").is_some());
    }

    #[test]
    fn xsd_date_spans_one_day() {
        let (lo, hi) = parse_xsd_date("2020-01-01").unwrap();
        // 86400 seconds in nanoseconds, minus 1 for inclusive upper.
        assert_eq!(hi - lo, 86_400_000_000_000 - 1);
    }

    #[test]
    fn xsd_gyear_spans_full_year() {
        let (lo_2020, hi_2020) = parse_xsd_gyear("2020").unwrap();
        let (lo_2021, _) = parse_xsd_gyear("2021").unwrap();
        // 2020 was a leap year — 366 days.
        assert_eq!(hi_2020 - lo_2020, 366 * 86_400_000_000_000 - 1);
        // 2020 immediately precedes 2021.
        assert_eq!(hi_2020 + 1, lo_2021);
    }

    #[test]
    fn xsd_gyearmonth_spans_one_month() {
        let (lo_jan, hi_jan) = parse_xsd_gyearmonth("2020-01").unwrap();
        // January has 31 days.
        assert_eq!(hi_jan - lo_jan, 31 * 86_400_000_000_000 - 1);

        let (_, hi_feb) = parse_xsd_gyearmonth("2020-02").unwrap();
        let (lo_mar, _) = parse_xsd_gyearmonth("2020-03").unwrap();
        assert_eq!(hi_feb + 1, lo_mar);
    }

    #[test]
    fn xsd_duration_daytime_only() {
        // P1DT2H3M4.5S = 1 day + 2h + 3m + 4.5s
        let ns = parse_xsd_duration("P1DT2H3M4.5S").unwrap();
        let expected =
            86_400_000_000_000i128 + 2 * 3_600_000_000_000 + 3 * 60_000_000_000 + 4_500_000_000;
        assert_eq!(ns, expected);
    }

    #[test]
    fn xsd_duration_negative() {
        let ns = parse_xsd_duration("-PT5S").unwrap();
        assert_eq!(ns, -5_000_000_000);
    }

    #[test]
    fn xsd_duration_rejects_year_month() {
        // Year/month durations don't have a fixed ns count.
        assert!(parse_xsd_duration("P1Y").is_none());
        assert!(parse_xsd_duration("P1M").is_none());
        assert!(parse_xsd_duration("P1Y2M").is_none());
    }
}
