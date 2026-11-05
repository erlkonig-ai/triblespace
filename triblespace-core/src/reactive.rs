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
//! Matching uses the native query engine. Only the current rule's constraints,
//! complete bindings already fired, and a fair rule cursor are execution state.
//! No catalog replaces the authoritative fact set. This first implementation
//! re-queries selected rules instead of maintaining a semi-naive delta index.
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
//! Positive rules can diverge. The budget bounds *firings*, not query search,
//! memory, or wall time. Exhaustion returns [`Progress::Pending`] even if the
//! next call would prove quiescence. No global cycle/closure check is imposed.

use std::collections::{BTreeMap, BTreeSet};

use crate::id::Id;
use crate::inline::encodings::{genid::GenId, UnknownInline};
use crate::inline::{Inline, IntoInline, RawInline, TryFromInline};
use crate::metadata;
use crate::prelude::*;
use crate::query::equalityconstraint::EqualityConstraint;
use crate::query::register::{resolve, ObservationOrder};
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
        /// Explicit evaluator operation; unknown selected operations are errors.
        "411026B46A23661F442A9469E8F4D3D2" as pub operation: GenId;
    }
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
    /// This native query engine supports at most 128 variable slots.
    VariableLimit(Id),
    /// Output terms have no ready core (missing fields or cyclic construction).
    UnresolvedTerms { revision: Id, terms: BTreeSet<Id> },
    /// A core constructor attempts to overwrite an already matched/literal term.
    BoundCore { revision: Id, term: Id },
    /// An output subject binding is not a native entity id.
    InvalidSubject { revision: Id, term: Id },
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
    pub fn select(&mut self, revisions: impl IntoIterator<Item = Id>) {
        self.selected = revisions
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
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
        let mut firings = Vec::new();
        while firings.len() < budget {
            let mut next = None;
            for _ in 0..self.selected.len() {
                let revision = self.selected[self.cursor];
                self.cursor = (self.cursor + 1) % self.selected.len();
                if let Some(firing) = self.next_firing(revision)? {
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

    fn next_firing(&self, revision: Id) -> Result<Option<Firing>, Error> {
        let r: Inline<GenId> = revision.to_inline();
        let mut supported = false;
        for operation in find!(operation: Id,
            self.facts.pattern(r, schema::operation.id().to_inline(), operation))
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
            for clause in find!(clause: Id, self.facts.pattern(r, relation.to_inline(), clause)) {
                let c: Inline<GenId> = clause.to_inline();
                let mut decoded = false;
                for (subject, predicate, object) in find!((subject: Id, predicate: Id, object: Id),
                and!(
                    self.facts.pattern(c, schema::subject.id().to_inline(), subject),
                    self.facts.pattern(c, schema::predicate.id().to_inline(), predicate),
                    self.facts.pattern(c, schema::object.id().to_inline(), object)
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
        let mut constraints: Vec<Box<dyn Constraint<'static>>> = Vec::new();
        let mut bound = BTreeSet::new();
        let mut slot_count = slots.len();
        if slot_count > 128 {
            return Err(Error::VariableLimit(revision));
        }
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
            constraints.push(Box::new(self.facts.pattern(
                Variable::<GenId>::new(s),
                predicate.to_inline(),
                Variable::<UnknownInline>::new(o),
            )));
        }
        for (&term, &slot) in &slots {
            let t: Inline<GenId> = term.to_inline();
            if exists!(temp!(
                (value),
                self.facts
                    .pattern::<UnknownInline>(t, schema::literal.id().to_inline(), value)
            )) {
                bound.insert(term);
                constraints.push(Box::new(self.facts.pattern(
                    t,
                    schema::literal.id().to_inline(),
                    Variable::<UnknownInline>::new(slot),
                )));
            }
        }
        let constraint = IntersectionConstraint::new(constraints);
        let query = Query::new(constraint, |binding| {
            Some(
                bound
                    .iter()
                    .map(|term| {
                        (
                            *term,
                            *binding.get(slots[term]).expect("bound by constraint"),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .with_frontier_width(1);
        for binding in query {
            if self.fired.contains(&(revision, binding.clone())) {
                continue;
            }
            let binding: BTreeMap<_, _> = binding.into_iter().collect();
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
            for &(subject, predicate, object) in &templates {
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
            return Ok(Some(Firing {
                revision,
                binding,
                constructed,
                emitted: emitted.into(),
            }));
        }
        Ok(None)
    }
}
