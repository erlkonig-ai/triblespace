//! Experimental positive rules whose programs are ordinary tribles.
//!
//! A revision states `operation: POSITIVE`, and links `matches` and `emits`
//! clauses, plus `core` clauses for content-derived output entities. Every
//! decoded `(subject, predicate, object)` clause tuple is a conjunct/template. Subject and object name opaque, revision-local terms;
//! predicate names the actual attribute. Reusing a term means equality.
//! A term's `literal` values are alternatives constraining that term, read
//! directly from the program facts. Without literals it is a variable.
//! Values remain native inline bytes; the target attribute supplies their
//! encoding. There is no host callback registry or serialized Rust program.
//!
//! Keep revisions and their semantic clause/term graph immutable: edit by publishing a new revision with
//! `metadata::supersedes` edges to the revisions observed. Unrelated annotations
//! are harmless. [`Environment::heads`] uses the existing observation register;
//! execution only uses the revisions explicitly named by [`Environment::select`].
//! Concurrent heads are never silently combined. Selecting several revisions
//! deliberately composes them. Switching selection retains previous consequences;
//! it is not support-dependent retraction or an alternative-world evaluator.
//!
//! [`Environment`] is a continuing, additive, in-memory environment, not a daemon.
//! Extend its facts with observations or rule revisions, select revisions, then
//! advance/resume. Each firing emits facts that can activate another rule.
//! Matching uses the native incremental query constraints beneath `pattern_changes!`.
//! A newly selected revision seeds from all current facts. Subsequent batches
//! match additions since that revision's exhausted snapshot, with a delta witness
//! in any input clause. Each finite batch owns its native query cursor; its
//! snapshot becomes the frontier only after exhaustion. Emitted or externally
//! added facts are included in the next batch, even across budget pauses.
//! Snapshots, constraints, complete bindings already fired and the fair rule
//! cursor are disposable execution state, never an authoritative domain catalog.
//!
//! Output-only terms are constructed from their `core` clauses using the same
//! native producer as `entity!`. Identity contains only those attribute/value
//! rows: no rule id, source, binding salt or provenance. `emits` adds annotations
//! and relations outside that core. Core subjects must be output-only terms,
//! never matched/literal ids: annotating an existing opaque id uses `emits`.
//! Nested constructions run in dependency order.
//! A term with no value or constructible core is an explicit selected-program
//! error; there is no implicit gensym. Matching never derives an id for lookup
//! or validates an id by re-derivation. Independent rules and reopened environments
//! converge on the same core; the in-memory firing memo only avoids repeated work.
//! [`Firing`] exposes complete bindings and constructed roots for inspection.
//!
//! A revision may also link `constraints` with `operation: STRING_CONTAINS`
//! and `container`/`needle` terms. Both must already be bound by matches or
//! literals to UTF-8 blob handles. Evaluation reads through the explicit
//! [`Environment::advance_with_reader`] capability and uses exact
//! case-sensitive `str::contains`, without normalization. Both strings must
//! be readable even for an empty needle. These pure predicates stream complete
//! native bindings before projection; they do not prune partial query search.
//! Missing/corrupt/undecodable bytes return an error and retain the exact row
//! and batch frontier for retry, including with a newer reader snapshot.
//!
//! Positive rules can diverge. The budget bounds *firings*, not query search,
//! memory, or wall time. Exhaustion returns [`Progress::Pending`] even if the
//! next call would prove quiescence. No global cycle/closure check is imposed.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use crate::id::Id;
use crate::inline::encodings::{genid::GenId, UnknownInline};
use crate::inline::{Inline, IntoInline, RawInline, TryFromInline};
use crate::metadata;
use crate::prelude::blobencodings::UTF8String;
use crate::prelude::inlineencodings::Handle;
use crate::prelude::*;
use crate::query::equalityconstraint::EqualityConstraint;
use crate::query::register::{resolve, ObservationOrder};
use crate::query::unionconstraint::UnionConstraint;
use crate::query::{Constraint, Query};
use crate::trible::{build_intrinsic_entity, Fragment, IntrinsicEntityRow, Trible, TribleSet};

/// Native rule vocabulary. Anchors were minted with `trible genid` on 2026-11-05.
pub mod schema {
    use super::*;
    crate::macros::attributes! {
        /// Revision's positive input clauses.
        "478B4ADB973B54FA29C9599B3487E5EA" as pub matches: GenId;
        /// Output identity-core clauses, grouped by their subject term.
        "C0562F23EE7D90EE89C11D07EA3FE2A2" as pub core: GenId;
        /// Revision's output templates.
        "A08E6BF7AA2DAD670F229A32F6218BB3" as pub emits: GenId;
        /// Clause's subject term.
        "F477470581C50922084EFFCCCC1ECB98" as pub subject: GenId;
        /// Clause's fixed attribute.
        "E30FDD85068BF48E680DAE61A0437B18" as pub predicate: GenId;
        /// Clause's value term.
        "BE38F57708506342357C8895DFD3924C" as pub object: GenId;
        /// Alternative native inline constants for a term. Encoding is supplied
        /// by each matched/emitted attribute, rather than coerced to a string.
        "39606138DDA5D4CB3F275B3A029AD6B0" as pub literal: UnknownInline;
        /// Revision's pure bound-content constraints.
        "71748F0D860D04E1935C7D04CB4491B2" as pub constraints: GenId;
        /// String-containing term, already bound by matches or literals.
        "BD2EE2B6256C34B0463AEF42A1A2D127" as pub container: GenId;
        /// String sought within the container, already bound by matches or literals.
        "C4DD00AC00156749CE1F8C23E1B4EBEC" as pub needle: GenId;
        /// Explicit evaluator operation; unknown selected operations are errors.
        "411026B46A23661F442A9469E8F4D3D2" as pub operation: GenId;
    }
    /// Exact case-sensitive UTF-8 `str::contains`, without normalization.
    pub const STRING_CONTAINS: Id = crate::id_hex!("8EF54F3AA52E28F3D9CBCAB4D3C177E9");
    /// The positive conjunction / fact-emission operation.
    pub const POSITIVE: Id = crate::id_hex!("92BE7FE5E9579770A96E8C67316434EA");
}

/// A selected program problem, not a rejection of the surrounding store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A revision has no supported, decodable operation yet.
    MissingOperation(Id),
    /// A selected revision explicitly requests an unknown operation.
    UnsupportedOperation { revision: Id, operation: Id },
    /// A linked clause has no complete typed subject/predicate/object tuple.
    IncompleteClause { revision: Id, clause: Id },
    /// A content constraint has no complete typed operation/argument tuple.
    IncompleteConstraint { revision: Id, constraint: Id },
    /// A selected content constraint names an unsupported operation.
    UnsupportedConstraint {
        revision: Id,
        constraint: Id,
        operation: Id,
    },
    /// Content arguments must be bound by positive matches or literal facts.
    UnboundContentTerm {
        revision: Id,
        constraint: Id,
        term: Id,
    },
    /// A content reading was reached without an explicit blob reader.
    MissingContentReader { revision: Id, constraint: Id },
    /// This native query engine supports at most 128 variable slots.
    VariableLimit(Id),
    /// Output terms have no ready core (missing fields or cyclic construction).
    UnresolvedTerms { revision: Id, terms: BTreeSet<Id> },
    /// A core constructor attempts to overwrite an already matched/literal term.
    BoundCore { revision: Id, term: Id },
    /// An output subject binding is not a native entity id.
    InvalidSubject { revision: Id, term: Id },
}

/// Failure while advancing with an explicit blob reader. Backend errors retain
/// their concrete type and source chain (including `repo::MissingBlob`). No
/// unavailable, corrupt or undecodable content is interpreted as predicate false.
#[derive(Debug)]
pub enum ReadAdvanceError<E> {
    Program(Error),
    Content {
        revision: Id,
        constraint: Id,
        term: Id,
        handle: Inline<Handle<UTF8String>>,
        source: E,
    },
}

impl<E> From<Error> for ReadAdvanceError<E> {
    fn from(error: Error) -> Self {
        Self::Program(error)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for ReadAdvanceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Program(error) => write!(f, "selected rule error: {error:?}"),
            Self::Content {
                revision,
                constraint,
                term,
                source,
                ..
            } => write!(
                f,
                "rule {revision:?} constraint {constraint:?} term {term:?}: {source}"
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ReadAdvanceError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Program(_) => None,
            Self::Content { source, .. } => Some(source),
        }
    }
}

/// One actual firing, including all binding alternatives separately.
#[derive(Debug)]
pub struct Firing {
    pub revision: Id,
    /// Complete input/literal binding, not merely a coverage set.
    pub binding: BTreeMap<Id, RawInline>,
    /// Roots produced from explicit content cores by this firing.
    pub constructed: BTreeMap<Id, Id>,
    /// Emitted facts; existing duplicates may already be in the environment.
    pub emitted: Fragment,
}

/// Whether another advance is needed for this observation/selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// Every selected rule was checked with no unseen complete binding.
    Quiescent,
    /// Budget exhausted; computation has not established quiescence.
    Pending,
}

#[derive(Debug)]
pub struct Advance {
    pub progress: Progress,
    pub firings: Vec<Firing>,
}

/// A continuing native fact environment. See module documentation for restart
/// and immutable revision semantics.
#[derive(Default)]
pub struct Environment {
    facts: TribleSet,
    selected: Vec<Id>,
    fired: BTreeSet<(Id, Vec<(Id, RawInline)>)>,
    cursor: usize,
    executions: BTreeMap<Id, Execution>,
    #[cfg(test)]
    enumerated: usize,
}

type Binding = Vec<(Id, RawInline)>;
type NativeQuery = Query<
    IntersectionConstraint<Box<dyn Constraint<'static>>>,
    Box<dyn Fn(&crate::query::Binding<'_>) -> Option<Binding>>,
    Binding,
>;
type StringReader<'a, E> = dyn Fn(Inline<Handle<UTF8String>>) -> Result<View<str>, E> + 'a;

struct ContentConstraint {
    id: Id,
    container: Id,
    needle: Id,
}

#[derive(Default)]
struct Execution {
    frontier: Option<TribleSet>,
    batch: Option<Batch>,
}

struct Batch {
    snapshot: TribleSet,
    query: Option<NativeQuery>,
    content: Vec<ContentConstraint>,
    pending: Option<Binding>,
    slots: BTreeMap<Id, usize>,
    bound: BTreeSet<Id>,
    cores: BTreeMap<Id, Vec<(Id, Id)>>,
    templates: Vec<(Id, Id, Id)>,
}

impl Environment {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add observations, programs, annotations or register edges. Duplicate
    /// facts are harmless; selection does not mutate the supplied programs.
    pub fn extend(&mut self, facts: &TribleSet) {
        self.facts += facts.clone();
    }

    pub fn facts(&self) -> &TribleSet {
        &self.facts
    }

    /// Explicit execution reading. Multiple IDs deliberately compose rules;
    /// no implicit latest/head choice is performed. Old consequences survive.
    /// Still-selected revisions retain their query cursors. Deselecting drops
    /// that revision's cursor/frontier; reselecting seeds again, while the
    /// environment's complete-binding memo suppresses already completed firings.
    pub fn select(&mut self, revisions: impl IntoIterator<Item = Id>) {
        self.selected = revisions
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.executions
            .retain(|revision, _| self.selected.contains(revision));
        self.cursor = 0;
    }

    /// Every incomparable revision in this frame, using the existing DAG
    /// register. Even states outside `candidates` can dominate a candidate.
    pub fn heads(&self, candidates: impl IntoIterator<Item = Id>) -> BTreeSet<Id> {
        resolve(
            &ObservationOrder::new(&self.facts, metadata::supersedes.id()),
            candidates,
        )
    }

    /// Fire at most `budget` complete bindings. Round-robin rule scheduling
    /// keeps an expanding first rule from starving a later selected rule.
    /// Errors leave earlier completed firings committed and available in facts;
    /// retry never repeats those firings within this environment.
    pub fn advance(&mut self, budget: usize) -> Result<Advance, Error> {
        match self.advance_reading::<Infallible>(budget, None) {
            Ok(result) => Ok(result),
            Err(ReadAdvanceError::Program(error)) => Err(error),
            Err(ReadAdvanceError::Content { source, .. }) => match source {},
        }
    }

    /// Advance using an explicit synchronous blob capability. The reader is
    /// borrowed only for this call; a later call may supply a newer snapshot
    /// to retry unavailable content. Successful reads must obey BlobStoreGet's
    /// content-identity contract. No ambient blob store or content cache is used.
    pub fn advance_with_reader<R: BlobStoreGet>(
        &mut self,
        budget: usize,
        reader: &R,
    ) -> Result<Advance, ReadAdvanceError<R::GetError<<View<str> as TryFromBlob<UTF8String>>::Error>>>
    {
        self.advance_reading(budget, Some(&|handle| reader.get(handle)))
    }

    fn advance_reading<E>(
        &mut self,
        budget: usize,
        reader: Option<&StringReader<'_, E>>,
    ) -> Result<Advance, ReadAdvanceError<E>> {
        let mut firings = Vec::new();
        while firings.len() < budget {
            let mut next = None;
            for _ in 0..self.selected.len() {
                let revision = self.selected[self.cursor];
                self.cursor = (self.cursor + 1) % self.selected.len();
                if let Some(firing) = self.next_firing(revision, reader)? {
                    next = Some(firing);
                    break;
                }
            }
            let Some(firing) = next else {
                return Ok(Advance {
                    progress: Progress::Quiescent,
                    firings,
                });
            };
            self.fired.insert((
                firing.revision,
                firing.binding.iter().map(|(k, v)| (*k, *v)).collect(),
            ));
            self.facts += firing.emitted.facts().clone();
            firings.push(firing);
        }
        Ok(Advance {
            progress: Progress::Pending,
            firings,
        })
    }

    fn next_firing<E>(
        &mut self,
        revision: Id,
        reader: Option<&StringReader<'_, E>>,
    ) -> Result<Option<Firing>, ReadAdvanceError<E>> {
        let execution = self.executions.entry(revision).or_default();
        loop {
            if execution.batch.is_none() {
                let changed = execution
                    .frontier
                    .as_ref()
                    .map(|previous| self.facts.difference(previous));
                if changed.as_ref().is_some_and(TribleSet::is_empty) {
                    return Ok(None);
                }
                execution.batch = Some(Batch::new(revision, self.facts.clone(), changed.as_ref())?);
            }
            let batch = execution.batch.as_mut().expect("batch prepared");
            loop {
                let binding = if let Some(binding) = batch.pending.take() {
                    Some(binding)
                } else if let Some(query) = batch.query.as_mut() {
                    query.try_next_where(|binding| -> Result<bool, ReadAdvanceError<E>> {
                        if batch.content.is_empty() {
                            return Ok(true);
                        }
                        let complete: Binding = batch
                            .bound
                            .iter()
                            .map(|term| {
                                (
                                    *term,
                                    *binding.get(batch.slots[term]).expect("bound by constraint"),
                                )
                            })
                            .collect();
                        // A completed firing does not need its content again,
                        // even if this delta rediscovers it after blob eviction.
                        if self.fired.contains(&(revision, complete)) {
                            return Ok(false);
                        }
                        for content in &batch.content {
                            let reader = reader.ok_or(Error::MissingContentReader {
                                revision,
                                constraint: content.id,
                            })?;
                            let read = |term| {
                                let handle = Inline::<Handle<UTF8String>>::new(
                                    *binding.get(batch.slots[&term]).expect("checked bound term"),
                                );
                                reader(handle).map_err(|source| ReadAdvanceError::Content {
                                    revision,
                                    constraint: content.id,
                                    term,
                                    handle,
                                    source,
                                })
                            };
                            let container = read(content.container)?;
                            let needle = read(content.needle)?;
                            if !container.contains(&*needle) {
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    })?
                } else {
                    None
                };
                #[cfg(test)]
                if binding.is_some() {
                    self.enumerated += 1;
                }
                let Some(binding) = binding else {
                    break;
                };
                if self.fired.contains(&(revision, binding.clone())) {
                    continue;
                }
                match batch.fire(revision, &binding) {
                    Ok(firing) => return Ok(Some(firing)),
                    Err(error) => {
                        // A failed output is not consumed, even though Query::next
                        // has moved. Retry reports it again without partial output.
                        batch.pending = Some(binding);
                        return Err(error.into());
                    }
                }
            }
            execution.frontier = Some(execution.batch.take().expect("exhausted batch").snapshot);
        }
    }
}

impl Batch {
    fn new(revision: Id, snapshot: TribleSet, changed: Option<&TribleSet>) -> Result<Self, Error> {
        let r: Inline<GenId> = revision.to_inline();
        let mut supported = false;
        for operation in find!(operation: Id,
            snapshot.pattern(r, schema::operation.id().to_inline(), operation))
        {
            if operation != schema::POSITIVE {
                return Err(Error::UnsupportedOperation {
                    revision,
                    operation,
                });
            }
            supported = true;
        }
        if !supported {
            return Err(Error::MissingOperation(revision));
        }

        // One selected rule's disposable executable constraints, never a
        // persistent domain catalog. Query program clauses at the point of use.
        let mut slots = BTreeMap::<Id, usize>::new();
        let mut body = Vec::new();
        let mut templates = Vec::new();
        let mut cores = BTreeMap::<Id, Vec<(Id, Id)>>::new();
        for relation in [schema::matches.id(), schema::emits.id(), schema::core.id()] {
            for clause in find!(clause: Id, snapshot.pattern(r, relation.to_inline(), clause)) {
                let c: Inline<GenId> = clause.to_inline();
                let mut decoded = false;
                for (subject, predicate, object) in find!((subject: Id, predicate: Id, object: Id),
                and!(
                    snapshot.pattern(c, schema::subject.id().to_inline(), subject),
                    snapshot.pattern(c, schema::predicate.id().to_inline(), predicate),
                    snapshot.pattern(c, schema::object.id().to_inline(), object)
                )) {
                    decoded = true;
                    for term in [subject, object] {
                        let n = slots.len();
                        slots.entry(term).or_insert(n);
                    }
                    if relation == schema::matches.id() {
                        body.push((subject, predicate, object));
                    } else if relation == schema::core.id() {
                        cores.entry(subject).or_default().push((predicate, object));
                    } else {
                        templates.push((subject, predicate, object));
                    }
                }
                if !decoded {
                    return Err(Error::IncompleteClause { revision, clause });
                }
            }
        }
        let mut content = Vec::new();
        for constraint in find!(c: Id,
            snapshot.pattern(r, schema::constraints.id().to_inline(), c))
        {
            let c: Inline<GenId> = constraint.to_inline();
            let mut decoded = false;
            for (operation, container, needle) in find!((operation: Id, container: Id, needle: Id),
            and!(
                snapshot.pattern(c, schema::operation.id().to_inline(), operation),
                snapshot.pattern(c, schema::container.id().to_inline(), container),
                snapshot.pattern(c, schema::needle.id().to_inline(), needle)
            )) {
                decoded = true;
                if operation != schema::STRING_CONTAINS {
                    return Err(Error::UnsupportedConstraint {
                        revision,
                        constraint,
                        operation,
                    });
                }
                for term in [container, needle] {
                    let n = slots.len();
                    slots.entry(term).or_insert(n);
                }
                content.push(ContentConstraint {
                    id: constraint,
                    container,
                    needle,
                });
            }
            if !decoded {
                return Err(Error::IncompleteConstraint {
                    revision,
                    constraint,
                });
            }
        }
        let mut constraints: Vec<Box<dyn Constraint<'static>>> = Vec::new();
        let mut bound = BTreeSet::new();
        let mut slot_count = slots.len();
        if slot_count > 128 {
            return Err(Error::VariableLimit(revision));
        }
        let mut inputs = Vec::new();
        for (subject, predicate, object) in body {
            let s = slots[&subject];
            let mut o = slots[&object];
            bound.extend([subject, object]);
            // Like pattern!, desugar same-term subject/value to native equality:
            // TribleSetConstraint requires distinct variables per position.
            if s == o {
                if slot_count == 128 {
                    return Err(Error::VariableLimit(revision));
                }
                o = slot_count;
                slot_count += 1;
                constraints.push(Box::new(EqualityConstraint::new(s, o)));
            }
            inputs.push((s, predicate, o));
        }
        for (&term, &slot) in &slots {
            let t: Inline<GenId> = term.to_inline();
            if exists!(temp!(
                (value),
                snapshot.pattern::<UnknownInline>(t, schema::literal.id().to_inline(), value)
            )) {
                bound.insert(term);
                constraints.push(Box::new(snapshot.pattern(
                    t,
                    schema::literal.id().to_inline(),
                    Variable::<UnknownInline>::new(slot),
                )));
            }
        }
        for constraint in &content {
            for term in [constraint.container, constraint.needle] {
                if !bound.contains(&term) {
                    return Err(Error::UnboundContentTerm {
                        revision,
                        constraint: constraint.id,
                        term,
                    });
                }
            }
        }
        // This is the dynamic-clause lowering used by pattern_changes!: one
        // native conjunction per delta position, combined by native union.
        // Equality helpers and immutable literal constraints sit outside it.
        // Union deduplicates identical complete bindings across delta branches.
        if !inputs.is_empty() {
            let positions: Vec<_> = match changed {
                Some(_) => (0..inputs.len()).map(Some).collect(),
                None => vec![None],
            };
            let variants: Vec<_> = positions
                .into_iter()
                .map(|position| {
                    let clauses: Vec<Box<dyn Constraint<'static>>> = inputs
                        .iter()
                        .enumerate()
                        .map(|(index, &(s, predicate, o))| {
                            let source = if position == Some(index) {
                                changed.expect("delta position")
                            } else {
                                &snapshot
                            };
                            Box::new(source.pattern(
                                Variable::<GenId>::new(s),
                                predicate.to_inline(),
                                Variable::<UnknownInline>::new(o),
                            )) as Box<dyn Constraint<'static>>
                        })
                        .collect();
                    IntersectionConstraint::new(clauses)
                })
                .collect();
            constraints.push(Box::new(UnionConstraint::new(variants)));
        }
        let projection: Vec<_> = bound.iter().map(|term| (*term, slots[term])).collect();
        let query: Option<NativeQuery> = if changed.is_some() && inputs.is_empty() {
            // Empty-body/literal-only rules depend solely on the immutable
            // program. There is no data delta position after the initial seed.
            None
        } else {
            Some(
                Query::new(
                    IntersectionConstraint::new(constraints),
                    Box::new(move |binding: &crate::query::Binding<'_>| {
                        Some(
                            projection
                                .iter()
                                .map(|&(term, slot)| {
                                    (term, *binding.get(slot).expect("bound by constraint"))
                                })
                                .collect::<Binding>(),
                        )
                    })
                        as Box<dyn Fn(&crate::query::Binding<'_>) -> Option<Binding>>,
                )
                .with_frontier_width(1),
            )
        };
        Ok(Self {
            snapshot,
            query,
            content,
            pending: None,
            slots,
            bound,
            cores,
            templates,
        })
    }

    fn fire(&self, revision: Id, binding: &Binding) -> Result<Firing, Error> {
        let Self {
            slots,
            bound,
            cores,
            templates,
            ..
        } = self;
        let binding: BTreeMap<_, _> = binding.iter().copied().collect();
        let mut values = binding.clone();
        let mut constructed = BTreeMap::new();
        let mut emitted = TribleSet::new();
        for term in cores.keys() {
            if bound.contains(term) {
                return Err(Error::BoundCore {
                    revision,
                    term: *term,
                });
            }
        }
        let mut remaining: BTreeSet<_> = slots
            .keys()
            .filter(|term| !bound.contains(*term))
            .copied()
            .collect();
        while !remaining.is_empty() {
            let before = remaining.len();
            for term in remaining.clone() {
                let Some(fields) = cores.get(&term) else {
                    continue;
                };
                if fields.iter().all(|(_, object)| values.contains_key(object)) {
                    let rows = fields
                        .iter()
                        .map(|(attribute, object)| {
                            IntrinsicEntityRow::new(*attribute, values[object])
                        })
                        .collect();
                    let (root, facts) = build_intrinsic_entity(rows);
                    emitted += facts;
                    let root_value: Inline<GenId> = root.to_inline();
                    values.insert(term, root_value.raw);
                    constructed.insert(term, root);
                    remaining.remove(&term);
                }
            }
            if before == remaining.len() {
                return Err(Error::UnresolvedTerms {
                    revision,
                    terms: remaining,
                });
            }
        }
        let value = |term: Id| -> RawInline { values[&term] };
        for &(subject, predicate, object) in templates {
            let raw = Inline::<GenId>::new(value(subject));
            let subject_id = Id::try_from_inline(&raw).map_err(|_| Error::InvalidSubject {
                revision,
                term: subject,
            })?;
            emitted.insert(&Trible::force(
                &subject_id,
                &predicate,
                &Inline::<UnknownInline>::new(value(object)),
            ));
        }
        Ok(Firing {
            revision,
            binding,
            constructed,
            emitted: emitted.into(),
        })
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;

    #[test]
    fn environment_enumerates_only_new_bindings_and_resumes_its_query() {
        fn edge(facts: &mut TribleSet, e: Id, a: Id, v: Id) {
            let v: Inline<GenId> = v.to_inline();
            facts.insert(&Trible::force(&e, &a, &v));
        }
        let [revision, clause, subject, object, input] = std::array::from_fn(|_| *genid());
        let mut facts = TribleSet::new();
        edge(
            &mut facts,
            revision,
            schema::operation.id(),
            schema::POSITIVE,
        );
        edge(&mut facts, revision, schema::matches.id(), clause);
        edge(&mut facts, clause, schema::subject.id(), subject);
        edge(&mut facts, clause, schema::predicate.id(), input);
        edge(&mut facts, clause, schema::object.id(), object);
        for _ in 0..100 {
            edge(&mut facts, *genid(), input, *genid());
        }
        let mut env = Environment::new();
        env.extend(&facts);
        env.select([revision]);
        assert_eq!(env.advance(101).unwrap().progress, Progress::Quiescent);
        assert_eq!(env.enumerated, 100);
        for _ in 0..3 {
            edge(&mut facts, *genid(), input, *genid());
        }
        env.extend(&facts);
        for count in 101..=103 {
            assert_eq!(env.advance(1).unwrap().firings.len(), 1);
            assert_eq!(
                env.enumerated, count,
                "no old rows and no repeated prefix on resume"
            );
            assert_eq!(
                env.executions[&revision].frontier.as_ref().unwrap().len(),
                105,
                "frontier cannot pass unconsumed bindings"
            );
        }
        assert_eq!(env.advance(1).unwrap().progress, Progress::Quiescent);
        assert_eq!(env.executions[&revision].frontier.as_ref().unwrap(), &facts);
        env.extend(&facts);
        assert_eq!(env.advance(1).unwrap().progress, Progress::Quiescent);
        assert_eq!(
            env.enumerated, 103,
            "duplicate-only extension does no query work"
        );
    }
}
