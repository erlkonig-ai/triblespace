//! Query facilities for matching tribles by declaring patterns of constraints.
//! Build queries with the [`find!`](crate::prelude::find) macro which binds variables and
//! combines constraint expressions:
//!
//! ```
//! # use triblespace_core::prelude::*;
//! # use triblespace_core::prelude::inlineencodings::ShortString;
//! let results = find!((x: Inline<ShortString>), x.is("foo".to_inline())).collect::<Vec<_>>();
//! ```
//!
//! Variables are converted via [`TryFromInline`](crate::inline::TryFromInline). By default,
//! conversion failures silently skip the row (filter semantics). Append `?` to a variable
//! to receive `Result<T, E>` instead, letting the caller handle errors explicitly.
//!
//! For a tour of the language see the "Query Language" chapter in the book.
//! Conceptual background on schemas and join strategy appears in the
//! "Query Engine" and "Atreides Join" chapters.
/// [`ConstantConstraint`] — pins a variable to a single value.
pub mod constantconstraint;
/// [`EqualityConstraint`](equalityconstraint::EqualityConstraint) — constrains two variables to have the same value.
pub mod equalityconstraint;
/// [`latest`](frontier::latest) — the maximal states of an observation DAG.
pub mod frontier;
/// Shared finite continuation for immutable, ordered single-variable sources.
#[doc(hidden)]
/// [`KeysConstraint`](hashmapconstraint::KeysConstraint) — constrains a variable to HashMap keys.
pub mod hashmapconstraint;
/// [`SetConstraint`](hashsetconstraint::SetConstraint) — constrains a variable to HashSet members.
pub mod hashsetconstraint;
/// [`IntersectionConstraint`](intersectionconstraint::IntersectionConstraint) — logical AND.
pub mod intersectionconstraint;
/// [`ProposalBuffer`] and [`Candidates`] — candidate storage and bit-packed
/// liveness for one search level.
mod liveness;
/// Exact consecutive or explicit row selections.
mod ordinal;
/// [`PatchValueConstraint`](patchconstraint::PatchValueConstraint) and [`PatchIdConstraint`](patchconstraint::PatchIdConstraint) — constrains variables to PATCH entries.
pub mod patchconstraint;
#[doc(hidden)]
/// [`InlineRange`](rangeconstraint::InlineRange) — restricts a variable to a byte-lexicographic range.
pub mod rangeconstraint;
/// [`resolve`](register::resolve) — registers: states, an order, and the
/// reader's choice of which are current.
pub mod register;
/// [`SortedSliceConstraint`](sortedsliceconstraint::SortedSliceConstraint) — constrains a variable to values in a sorted slice (binary search confirm).
pub mod sortedsliceconstraint;
/// [`UnionConstraint`](unionconstraint::UnionConstraint) — logical OR.
pub mod unionconstraint;
mod variableset;

use std::cmp::Reverse;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arrayvec::ArrayVec;
use constantconstraint::*;
use ordinal::RowSelection;

use crate::inline::encodings::genid::GenId;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;

/// Re-export of [`VariableSet`](variableset::VariableSet).
pub use variableset::VariableSet;

/// Re-exports of the candidate/liveness pair. The module they come from is
/// private on purpose: the bit-packed representation and the region-boundary
/// invariants that keep it honest are enforced at the boundary of these two
/// types, so nothing outside `query::liveness` can reach them. Its
/// module-level comment is the reference for anyone editing it — or writing a
/// device kernel against [`LIVENESS_WORD_BITS`].
pub use liveness::{and_words, or_words, Candidates, ProposalBuffer, LIVENESS_WORD_BITS};

impl<T: InlineEncoding> Term<T> {
    /// Erases the schema type, yielding the runtime representation
    /// constraint implementations store.
    pub fn erase(self) -> RawTerm {
        match self {
            Term::Var(v) => RawTerm::Var(v.index),
            Term::Const(c) => RawTerm::Const(c.raw),
        }
    }
}

/// Types storing tribles can implement this trait to expose them to queries.
/// The trait provides a method to create a constraint for a given trible pattern.
pub trait TriblePattern {
    /// The type of the constraint created by the pattern method.
    ///
    /// `Send + Sync` is required so the resulting constraint tree can be
    /// used with the `parallel` feature's rayon iterators. Every in-tree
    /// pattern backend (TribleSet, SuccinctArchive) satisfies this; custom
    /// implementations should hold their data behind `Arc` or similar.
    type PatternConstraint<'a>: Constraint<'a> + Send + Sync
    where
        Self: 'a;

    /// Create a constraint for a given trible pattern.
    /// Each position takes a [`Term`]: either a [`Variable`] to solve for
    /// or a constant [`Inline`] value baked into the constraint (a constant
    /// position behaves exactly like a variable the engine has already
    /// bound, but never appears in the constraint's [`VariableSet`]).
    /// The schemas of the entities and attributes are always [GenId], while the value
    /// schema can be any type implementing [InlineEncoding] and is specified as a type parameter.
    ///
    /// This method is usually not called directly, but rather through typed query language
    /// macros like [pattern!][crate::macros::pattern], which pass attribute
    /// constants and literal values as constant terms.
    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a>;
}

/// Low-level identifier for a variable in a query.
pub type VariableId = usize;

/// Context for creating variables in a query.
/// The context keeps track of the next index to assign to a variable.
/// This allows for the creation of new anonymous variables in higher-level query languages.
#[derive(Debug)]
pub struct VariableContext {
    /// The index that will be assigned to the next variable.
    pub next_index: VariableId,
}

impl Default for VariableContext {
    fn default() -> Self {
        Self::new()
    }
}

impl VariableContext {
    /// Create a new variable context.
    /// The context starts with an index of 0.
    pub fn new() -> Self {
        VariableContext { next_index: 0 }
    }

    /// Create a new variable.
    /// The variable is assigned the next available index.
    ///
    /// Panics if the number of variables exceeds 128.
    ///
    /// This method is usually not called directly, but rather through typed query language
    /// macros like [find!][crate::query].
    pub fn next_variable<T: InlineEncoding>(&mut self) -> Variable<T> {
        assert!(
            self.next_index < 128,
            "currently queries support at most 128 variables"
        );
        let v = Variable::new(self.next_index);
        self.next_index += 1;
        v
    }
}

/// A placeholder for unknowns in a query.
/// Within the query engine each variable is identified by an integer,
/// which can be accessed via the `index` property.
/// Variables also have an associated type which is used to parse the [Inline]s
/// found by the query engine.
#[derive(Debug)]
pub struct Variable<T: InlineEncoding> {
    /// The integer index identifying this variable in the [`Binding`].
    pub index: VariableId,
    typed: PhantomData<T>,
}

impl<T: InlineEncoding> Copy for Variable<T> {}

impl<T: InlineEncoding> Clone for Variable<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: InlineEncoding> Variable<T> {
    /// Creates a variable with the given index.
    pub fn new(index: VariableId) -> Self {
        Variable {
            index,
            typed: PhantomData,
        }
    }

    /// Extracts the bound value for this variable from `binding`.
    ///
    /// # Panics
    ///
    /// Panics if the variable has not been bound.
    pub fn extract<'b>(self, binding: &Binding<'b>) -> &'b Inline<T> {
        let raw = binding.get(self.index).unwrap_or_else(|| {
            panic!(
                "query variable (idx {}) was never bound before projection. This usually means the variable was projected in `find!` but never appeared in any constraint. If you intended a pure existence query, use `find!((), ...)` or `exists!(constraint)`.",
                self.index
            )
        });
        Inline::as_transmute_raw(raw)
    }
}

/// One position of a triple pattern: either a [`Variable`] the engine
/// solves for, or a constant [`Inline`] value pinned at construction.
///
/// Constants are how the macro layer expresses attribute constants and
/// literal values without allocating hidden helper variables. A constant
/// position behaves exactly like a variable that is already bound — the
/// backends' bound/unbound dispatch handles it with no extra cases — but
/// it never appears in the constraint's [`VariableSet`]. This keeps the
/// visible variable set of a `pattern!` equal to the query variables the
/// user actually wrote, which is what makes
/// [`or!`](crate::or) over patterns with different attributes or literals
/// well-formed (all arms declare the same set).
#[derive(Debug)]
pub enum Term<T: InlineEncoding> {
    /// A variable to solve for.
    Var(Variable<T>),
    /// A constant value pinned at construction.
    Const(Inline<T>),
}

impl<T: InlineEncoding> Copy for Term<T> {}

impl<T: InlineEncoding> Clone for Term<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: InlineEncoding> From<Variable<T>> for Term<T> {
    fn from(v: Variable<T>) -> Self {
        Term::Var(v)
    }
}

impl<T: InlineEncoding> From<Inline<T>> for Term<T> {
    fn from(value: Inline<T>) -> Self {
        Term::Const(value)
    }
}

/// Untyped runtime form of a [`Term`]: a variable slot index or a pinned
/// 32-byte value. Constraint implementations store this and use
/// [`is_var`](RawTerm::is_var) / [`bound`](RawTerm::bound) in place of the
/// raw `VariableId` comparison and `Binding::get` lookup — a constant term
/// then flows through the existing bound-position dispatch for free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawTerm {
    /// A variable slot index.
    Var(VariableId),
    /// A pinned raw value.
    Const(RawInline),
}

impl RawTerm {
    /// Returns `true` when this term is the given variable.
    #[inline]
    pub fn is_var(&self, variable: VariableId) -> bool {
        matches!(self, RawTerm::Var(v) if *v == variable)
    }

    /// Returns the value this position holds under `binding`: the pinned
    /// value for a constant, the binding's value (if any) for a variable.
    ///
    /// This is the helper that unifies "bound variable" and "constant" —
    /// backend dispatch keyed on "is this position bound?" treats a
    /// constant as a position that is born bound, with no extra match arms.
    #[inline]
    pub fn position_value<'b>(&'b self, binding: &'b Binding) -> Option<&'b RawInline> {
        match self {
            RawTerm::Var(v) => binding.get(*v),
            RawTerm::Const(c) => Some(c),
        }
    }

    /// Adds the term's variable (if it is one) to `set`. Constants stay
    /// below the variable layer and are never added.
    #[inline]
    pub fn add_to(&self, set: &mut VariableSet) {
        if let RawTerm::Var(v) = self {
            set.set(*v);
        }
    }
}

/// Collections can implement this trait so that they can be used in queries.
/// The returned constraint will filter the values assigned to the variable
/// to only those that are contained in the collection.
pub trait ContainsConstraint<'a, T: InlineEncoding> {
    /// The concrete constraint type produced by [`has`](ContainsConstraint::has).
    type Constraint: Constraint<'a>;

    /// Create a constraint that filters the values assigned to the variable
    /// to only those that are contained in the collection.
    ///
    /// The returned constraint will usually perform a conversion between the
    /// concrete rust type stored in the collection a [Inline] of the appropriate schema
    /// type for the variable.
    fn has(self, v: Variable<T>) -> Self::Constraint;
}

impl<T: InlineEncoding> Variable<T> {
    /// Create a constraint so that only a specific value can be assigned to the variable.
    pub fn is(self, constant: Inline<T>) -> ConstantConstraint {
        ConstantConstraint::new(self, constant)
    }
}

/// The values assigned to the variables of a query — stored as **paths,
/// not copies**.
///
/// A bound variable's value always *originates* from that variable's own
/// level buffer: [`propose`](Constraint::propose) fills the buffer and
/// the engine binds by consuming one of its entries. So a binding does
/// not need to carry the 32 bytes; it carries the `u32` index of the
/// chosen entry and resolves it through the buffers on read. Two
/// properties make the index as good as the value:
///
/// * A level's buffer is cleared and refilled only when its variable is
///   (re-)pushed, and the engine only ever pushes a variable that is
///   currently unbound (deeper levels are unset by backtracking before
///   their level is re-pushed). While a variable is bound, its buffer is
///   stable, so its index stays valid for exactly the lifetime of the
///   binding. Nothing ever appends to a level while its variable is
///   bound, so the stability is unconditional (see
///   [`BindingStore::refill`]).
/// * Buffers are write-once: confirmers kill entries by clearing a
///   parallel liveness word, and nothing ever moves or rewrites a stored
///   value once the engine can see it.
///
/// `Binding` is therefore a *view* — the index row plus a borrow of the
/// buffers it indexes into — constructed for the duration of one
/// constraint call. [`BindingStore`] owns the buffers; the index rows of
/// a whole batch live in a [`Frontier`].
///
/// The payoff is size: an assignment is one `u32` per variable slot
/// instead of a 32-byte raw value each, a bind is a 4-byte write instead
/// of a 32-byte copy, cloning the search state no longer memcpies the
/// values, and a *batch* of bindings is a small integer matrix over
/// shared buffers rather than a pile of value copies.
#[derive(Clone, Copy)]
pub struct Binding<'a> {
    /// Bitset tracking which variables have been assigned a value.
    pub bound: VariableSet,
    indexes: &'a [u32],
    levels: &'a [LevelValues],
}

impl fmt::Debug for Binding<'_> {
    /// Prints the bound variables and the values they resolve to — the
    /// assignment, not the buffers it is a path through.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.bound.into_iter().map(|v| (v, self.get(v))))
            .finish()
    }
}

impl<'a> Binding<'a> {
    /// Returns the value bound to `variable`, or `None` when it is
    /// unbound — resolved through `variable`'s level buffer.
    pub fn get(&self, variable: VariableId) -> Option<&'a RawInline> {
        if self.bound.is_set(variable) {
            Some(&self.levels[variable].buffer()[self.indexes[variable] as usize])
        } else {
            None
        }
    }
}

/// Backing for the empty [`Binding`]: nothing is bound, so nothing ever
/// resolves through them, but a view needs something to point at.
static NO_LEVELS: [LevelValues; 128] = [const { LevelValues::empty() }; 128];
static NO_INDEXES: [u32; 128] = [0; 128];

impl Default for Binding<'_> {
    /// The empty binding — no variable is bound.
    fn default() -> Self {
        Binding {
            bound: VariableSet::new_empty(),
            indexes: &NO_INDEXES,
            levels: &NO_LEVELS,
        }
    }
}

/// A **batch of parent bindings** — the collection [`Constraint::propose`]
/// expands and [`Constraint::confirm`] filters against.
///
/// Because bindings are indexes rather than values, a frontier is an
/// *index matrix*, not a pile of copied assignments: one row of `stride`
/// `u32`s per parent binding, over the level buffers those indexes point
/// into. Identity selections and their offset slices remain consecutive and
/// allocation-free, while a genuine permutation borrows explicit row
/// numbers. Narrowing never copies an index row.
///
/// Every row of a frontier has the *same* [`bound`](Frontier::bound) set —
/// they are all at the same point in the search, differing only in which
/// values they took. Today's single-binding call sites are a frontier of
/// one; see [`BindingStore::frontier`].
#[derive(Clone, Copy)]
pub struct Frontier<'a> {
    bound: VariableSet,
    block: &'a [u32],
    stride: usize,
    select: RowSelection<'a>,
    levels: &'a [LevelValues],
    /// Whether this frontier is being driven by `QueryParIter`.
    ///
    /// Crate-private execution intent lets built-in CPU constraints expose
    /// work to the same Rayon pool without making ordinary `Iterator`
    /// queries parallel merely because the crate was built with the
    /// `parallel` feature.
    parallel: bool,
}

impl fmt::Debug for Frontier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.rows()).finish()
    }
}

impl Default for Frontier<'_> {
    /// A batch of exactly one empty binding — the root of every search,
    /// and the shape a caller with nothing bound hands a constraint.
    fn default() -> Self {
        Frontier {
            bound: VariableSet::new_empty(),
            block: &NO_INDEXES,
            stride: NO_INDEXES.len(),
            select: RowSelection::identity(1),
            levels: &NO_LEVELS,
            parallel: false,
        }
    }
}

impl<'a> Frontier<'a> {
    /// Number of parent bindings in this batch.
    pub fn len(&self) -> usize {
        self.select.len()
    }

    /// True when the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.select.len() == 0
    }

    /// The variables bound in *every* row of this batch.
    pub fn bound(&self) -> VariableSet {
        self.bound
    }

    /// Whether this batch belongs to a query explicitly converted with
    /// `into_par_iter`.
    #[cfg(feature = "parallel")]
    pub(crate) fn parallel(&self) -> bool {
        self.parallel
    }

    /// The binding of row `i`.
    pub fn row(&self, i: usize) -> Binding<'a> {
        Binding {
            bound: self.bound,
            indexes: self.row_indexes(i),
            levels: self.levels,
        }
    }

    /// Iterates the batch's bindings in row order.
    pub fn rows(&self) -> impl Iterator<Item = Binding<'a>> + '_ {
        (0..self.len()).map(|i| self.row(i))
    }

    fn row_indexes(&self, i: usize) -> &'a [u32] {
        let row = self.select.get(i).expect("frontier row index is in bounds") as usize;
        &self.block[row * self.stride..(row + 1) * self.stride]
    }

    /// Translates `positions` (row numbers *in this view*) into row
    /// numbers of the underlying block, appending them to `out`.
    ///
    /// The result is the `select` array of a sub-batch: pair it with
    /// [`with_select`](Frontier::with_select) to hand a subset of this
    /// frontier to a child constraint without copying any row.
    pub fn compose(&self, positions: impl IntoIterator<Item = u32>, out: &mut Vec<u32>) {
        out.extend(positions.into_iter().map(|position| {
            self.select
                .get(position as usize)
                .expect("frontier composition index is in bounds")
        }));
    }

    /// This frontier restricted to `select` — row numbers of the
    /// underlying block, as produced by [`compose`](Frontier::compose).
    pub fn with_select<'b>(&self, select: &'b [u32]) -> Frontier<'b>
    where
        'a: 'b,
    {
        Frontier {
            bound: self.bound,
            block: self.block,
            stride: self.stride,
            select: RowSelection::explicit(select),
            levels: self.levels,
            parallel: self.parallel,
        }
    }
}

/// Owns what a [`Binding`] is a view of: the per-variable level buffers,
/// plus the index row that picks one entry out of each for callers
/// outside the search.
///
/// The query engine keeps its frontiers' index matrices separately (they
/// are per search *depth*, while buffers are per *variable*) and reaches
/// the buffers through [`refill`](BindingStore::refill) and
/// [`take_chunk`](BindingStore::take_chunk). Code outside the engine
/// builds a binding over values it picked itself — see
/// [`bind`](BindingStore::bind) — and turns it into a width-1
/// [`Frontier`] with [`frontier`](BindingStore::frontier).
#[derive(Clone)]
pub struct BindingStore {
    bound: VariableSet,
    indexes: [u32; 128],
    levels: [LevelValues; 128],
}

impl fmt::Debug for BindingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.view(), f)
    }
}

impl Default for BindingStore {
    fn default() -> Self {
        BindingStore {
            bound: VariableSet::new_empty(),
            indexes: [0; 128],
            levels: std::array::from_fn(|_| LevelValues::default()),
        }
    }
}

impl BindingStore {
    /// An empty store: nothing bound, every level empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current assignment, as [`satisfied`](Constraint::satisfied)
    /// and result post-processing see it.
    pub fn view(&self) -> Binding<'_> {
        Binding {
            bound: self.bound,
            indexes: &self.indexes,
            levels: &self.levels,
        }
    }

    /// The current assignment as a **frontier of one** — the batch shape
    /// [`propose`](Constraint::propose) and [`confirm`](Constraint::confirm)
    /// take. This is the bridge for every caller that has a single
    /// binding: a collection of one behaves exactly like the old
    /// single-binding protocol.
    pub fn frontier(&self) -> Frontier<'_> {
        Frontier {
            bound: self.bound,
            block: &self.indexes,
            stride: self.indexes.len(),
            select: RowSelection::identity(1),
            levels: &self.levels,
            parallel: false,
        }
    }

    /// Binds `variable` to `value` by appending it to that variable's
    /// level buffer and pointing the index row at it.
    ///
    /// The engine never needs this — its candidates are already in the
    /// buffer, so it binds by index. This is the entry point for callers
    /// outside the search (tests, tools) that want a binding over values
    /// of their own choosing.
    pub fn bind(&mut self, variable: VariableId, value: &RawInline) {
        let level = &mut self.levels[variable];
        let buffer = Arc::make_mut(
            level
                .buffer
                .get_or_insert_with(|| Arc::new(ProposalBuffer::new())),
        );
        let index = buffer.len();
        buffer.push(*value);
        self.indexes[variable] = index as u32;
        self.bound.set(variable);
    }

    /// Unbinds `variable` — the engine's backtracking step.
    pub fn unset(&mut self, variable: VariableId) {
        self.bound.unset(variable);
    }

    /// The set of currently bound variables.
    pub fn bound(&self) -> VariableSet {
        self.bound
    }

    /// Clears `variable`'s level and refills it by proposing over the
    /// frontier `block`/`select`/`stride` describe.
    ///
    /// The level is moved *out* of the array for the duration of the
    /// call, so `propose` gets `&mut` on it while the remaining levels
    /// lend immutably through the [`Frontier`] view — the borrow split
    /// the search needs, with no `unsafe` and no second copy of the
    /// candidates. This is sound precisely because the engine only ever
    /// refills the level of a variable it is about to push, which is by
    /// construction unbound: nothing can be resolving through this level
    /// while it is away.
    ///
    /// This is now the *only* way a level's buffer is written. With the
    /// resumable-narrowing path gone, no level is ever appended to while
    /// its variable is bound, so "a bound variable's buffer is stable for
    /// the lifetime of its binding" holds unconditionally — the
    /// `debug_assert` below is that invariant.
    ///
    /// A uniquely owned buffer is cleared in place so ordinary backtracking
    /// retains its capacity. If a rayon sibling shares the published buffer,
    /// refill replaces this branch's handle with a fresh empty buffer before
    /// calling `propose`; cloning and then clearing the old contents would be
    /// both slower and semantically unnecessary.
    pub(crate) fn refill(
        &mut self,
        variable: VariableId,
        block: &[u32],
        select: RowSelection<'_>,
        stride: usize,
        parallel: bool,
        propose: impl FnOnce(&Frontier<'_>, &mut ProposalBuffer),
    ) -> usize {
        debug_assert!(
            !self.bound.is_set(variable),
            "refilling a bound variable's level would strand its binding"
        );
        let mut level = std::mem::take(&mut self.levels[variable]);
        let mut buffer = level
            .buffer
            .take()
            .unwrap_or_else(|| Arc::new(ProposalBuffer::new()));
        if Arc::get_mut(&mut buffer).is_none() {
            // A rayon sibling still resolves indexes through the published
            // buffer. Refill discards every old entry, so cloning it before
            // `clear` would be pure waste: replace our handle with a fresh
            // empty allocation and leave the sibling's snapshot untouched.
            buffer = Arc::new(ProposalBuffer::new());
        }
        level.pos = 0;
        let proposed = {
            let buffer = Arc::get_mut(&mut buffer).expect("sole owner after replacement");
            buffer.clear();
            propose(
                &Frontier {
                    bound: self.bound,
                    block,
                    stride,
                    select,
                    levels: &self.levels,
                    parallel,
                },
                buffer,
            );
            buffer.len()
        };
        level.buffer = Some(buffer);
        self.levels[variable] = level;
        proposed
    }

    /// A [`Frontier`] over the rows `block`/`select`/`stride` describe,
    /// resolving through this store's level buffers.
    pub(crate) fn batch<'s>(
        &'s self,
        block: &'s [u32],
        select: RowSelection<'s>,
        stride: usize,
        parallel: bool,
    ) -> Frontier<'s> {
        Frontier {
            bound: self.bound,
            block,
            stride,
            select,
            levels: &self.levels,
            parallel,
        }
    }

    /// How far `variable`'s level cursor has run — the count of entries the
    /// level has consumed or skipped. With `Level::proposed` this bounds the
    /// candidates still pending without scanning the liveness words.
    pub(crate) fn consumed(&self, variable: VariableId) -> usize {
        self.levels[variable].pos
    }

    /// Consumes up to `width` further live candidates from `variable`'s
    /// level and writes the child frontier's rows into `out`, recording
    /// each child row's parent row number in `parents_out`.
    ///
    /// Each consumed candidate `i` carries the parent tag its proposer
    /// wrote; the child row is that parent's index row with `variable`'s
    /// slot pointed at `i`. Returns how many rows were produced (zero
    /// means the level is spent).
    ///
    /// This is the fused path: one pass, no intermediate. A descent that
    /// might be 1:1 uses [`draw`](BindingStore::draw) instead, which defers
    /// the write until the shape of the draw is known.
    pub(crate) fn take_chunk(
        &mut self,
        variable: VariableId,
        width: usize,
        parent_block: &[u32],
        parent_select: RowSelection<'_>,
        stride: usize,
        out: &mut Vec<u32>,
        parents_out: &mut Vec<u32>,
    ) -> usize {
        out.clear();
        parents_out.clear();
        let level = &mut self.levels[variable];
        let buffer = level
            .buffer
            .as_deref()
            .expect("an active level must have a proposal buffer");
        let pos = &mut level.pos;
        let mut rows = 0;
        while rows < width {
            let Some(i) = buffer.next_live(*pos) else {
                break;
            };
            *pos = i + 1;
            let parent = parent_select
                .get(buffer.parent_of(i) as usize)
                .expect("candidate parent tag is in bounds") as usize;
            out.extend_from_slice(&parent_block[parent * stride..(parent + 1) * stride]);
            let base = out.len() - stride;
            out[base + variable] = i as u32;
            parents_out.push(parent as u32);
            rows += 1;
        }
        self.bound.set_value(variable, rows != 0);
        rows
    }

    /// Consumes up to `width` further live candidates from `variable`'s
    /// level *without* materialising any child row: each drawn entry's
    /// index lands in `drawn_out` and the frontier row it was proposed for
    /// in `parents_out`.
    ///
    /// Deferring the write is what lets the engine look at the shape of a
    /// draw before paying for it — a 1:1 draw needs no new rows at all,
    /// see [`Query::next_chunk`]. It is not free (two passes instead of
    /// one), which is exactly why the caller only takes this path when a
    /// 1:1 draw is *possible*.
    pub(crate) fn draw(
        &mut self,
        variable: VariableId,
        width: usize,
        parent_select: RowSelection<'_>,
        drawn_out: &mut Vec<u32>,
        parents_out: &mut Vec<u32>,
    ) {
        drawn_out.clear();
        parents_out.clear();
        let level = &mut self.levels[variable];
        let buffer = level
            .buffer
            .as_deref()
            .expect("an active level must have a proposal buffer");
        let pos = &mut level.pos;
        while drawn_out.len() < width {
            let Some(i) = buffer.next_live(*pos) else {
                break;
            };
            *pos = i + 1;
            drawn_out.push(i as u32);
            parents_out.push(
                parent_select
                    .get(buffer.parent_of(i) as usize)
                    .expect("candidate parent tag is in bounds"),
            );
        }
        self.bound.set_value(variable, !drawn_out.is_empty());
    }

    /// Whether `variable`'s level has no live candidate left beyond what
    /// has already been drawn.
    ///
    /// Deliberately *not* folded into [`draw`](BindingStore::draw): it is a
    /// forward scan over the liveness words, so asking after every draw
    /// would pay a second pass over a level's dead tail that the next draw
    /// pays anyway. The one caller asks only once the cheap `O(1)`
    /// conditions for an in-place descent already hold.
    pub(crate) fn spent(&self, variable: VariableId) -> bool {
        let level = &self.levels[variable];
        level.buffer().next_live(level.pos).is_none()
    }
}

/// The cooperative protocol that every query participant implements.
///
/// A constraint restricts the values that can be assigned to query variables.
/// The query engine does not plan joins in advance; instead it consults
/// constraints directly during a depth-first search over partial bindings.
/// Each constraint reports which variables it touches, estimates how many
/// candidates remain, enumerates concrete values on demand, and signals
/// whether its requirements are still satisfiable. This protocol is the
/// sole interface between the engine and the data — whether that data lives
/// in a [`TribleSet`](crate::trible::TribleSet), a [`HashMap`](std::collections::HashMap),
/// or a custom application predicate.
///
/// # The protocol
///
/// The engine drives the search by calling five methods in a fixed rhythm:
///
/// | Method | Role | Called when |
/// |--------|------|------------|
/// | [`variables`](Constraint::variables) | Declares which variables the constraint touches. | Once, at query start. |
/// | [`estimate`](Constraint::estimate) | Predicts the candidate count for a variable. | Before each binding decision. |
/// | [`propose`](Constraint::propose) | Enumerates candidate values for a variable, for a whole batch of bindings. | On the most selective constraint. |
/// | [`confirm`](Constraint::confirm) | Filters candidates proposed by another constraint. | On all remaining constraints. |
/// | [`satisfied`](Constraint::satisfied) | Checks whether fully-bound sub-constraints still hold. | Before propose/confirm in composite constraints. |
///
/// [`influence`](Constraint::influence) completes the picture by telling the
/// engine which estimates to refresh when a variable is bound or unbound.
///
/// # Batching
///
/// `propose` and `confirm` operate on a **[`Frontier`]** — a collection of
/// parent bindings — rather than on one binding. Today's single-binding
/// call sites are a frontier of one ([`BindingStore::frontier`]) and behave
/// exactly as before; the engine drives wider batches so that every level
/// of the search offers a source a *wide* region to work on, not just the
/// root. A source that has nothing to gain from width writes the loop over
/// [`Frontier::rows`] and is done; one that does (a GPU-resident index, a
/// SIMD probe) sees the whole batch in one call. Nothing in the protocol
/// requires a source to seek: iteration and point queries still suffice,
/// which is what keeps hash maps, PATCHes, succinct archives and
/// device-resident structures all admissible.
///
/// # Statelessness
///
/// Constraints are stateless: every method receives the current [`Binding`]
/// as a parameter rather than maintaining internal bookkeeping. This lets
/// the engine backtrack freely by unsetting variables in the binding
/// without notifying the constraints.
///
/// # Composability
///
/// Constraints combine via [`IntersectionConstraint`](crate::query::intersectionconstraint::IntersectionConstraint)
/// (logical AND — built by [`and!`](crate::and)) and
/// [`UnionConstraint`](crate::query::unionconstraint::UnionConstraint)
/// (logical OR — built by [`or!`](crate::or)). Because every constraint
/// speaks the same protocol, heterogeneous data sources mix freely in a
/// single query.
///
/// # Implementing a custom constraint
///
/// A new constraint only needs to implement [`variables`](Constraint::variables),
/// [`estimate`](Constraint::estimate), [`propose`](Constraint::propose), and
/// [`confirm`](Constraint::confirm). Override [`satisfied`](Constraint::satisfied)
/// when the constraint can detect unsatisfiability before the engine asks
/// about individual variables (e.g. a fully-bound triple lookup that found
/// no match). Override [`influence`](Constraint::influence) when binding one
/// variable changes the estimates for a non-obvious set of others.
pub trait Constraint<'a> {
    /// Returns the set of variables this constraint touches.
    ///
    /// Called once at query start. The engine uses this to build influence
    /// graphs and to determine which constraints participate when a
    /// particular variable is being bound.
    fn variables(&self) -> VariableSet;

    /// Estimates the number of candidate values for `variable` given the
    /// current partial `binding`.
    ///
    /// Returns `None` when `variable` is not constrained by this constraint.
    /// The estimate need not be exact — it guides variable ordering, not
    /// correctness. Tighter estimates lead to better search pruning; see the
    /// [Atreides join](crate) family for how different estimate fidelities
    /// affect performance.
    ///
    /// Whether the answer is `Some` or `None` must depend only on which
    /// variables are bound, not on the values they are bound to: every row
    /// of a [`Frontier`] shares one bound set, and composites read
    /// relevance off the batch.
    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize>;

    /// Enumerates candidate values for `variable`, for every row of
    /// `frontier`, into `proposals`.
    ///
    /// Called on the constraint with the lowest estimate for the variable
    /// being bound. Before appending the candidates of row `r`, the
    /// proposer calls [`ProposalBuffer::open`] with `r`, which tags them so
    /// confirmers and the engine can tell whose they are. A proposer may
    /// visit the rows in any order and interleave them; contiguous segments
    /// are merely the cheaper shape.
    ///
    /// Values are appended to `proposals`; entries appended by an enclosing
    /// composite's other children may precede them, and must be left
    /// untouched.
    ///
    /// Does nothing when `variable` is not constrained by this constraint.
    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    );

    /// Kills [`Candidates`] entries whose values for `variable` violate
    /// this constraint under the entry's own frontier row.
    ///
    /// Called on every constraint *except* the one that proposed, in order
    /// of increasing estimate, all killing into the same region —
    /// sequential kills compute the conjunction. Implementations may only
    /// kill entries, never revive them, and may skip entries that are
    /// already dead. Nothing is ever compacted: dead entries stay in place
    /// and the engine iterates live ones.
    ///
    /// The region spans the whole batch: entry `i` belongs to frontier row
    /// [`cands.parent(i)`](Candidates::parent). A confirmer whose verdict
    /// depends on the parent binding walks the region with
    /// [`Candidates::for_each_parent`]; one whose verdict does not simply
    /// ignores the tags.
    ///
    /// Does nothing when `variable` is not constrained by this constraint.
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>);

    /// Returns whether this constraint is consistent with the current
    /// `binding`.
    ///
    /// The default implementation returns `true`. Override this when the
    /// constraint can cheaply detect that no solution exists — for example,
    /// a `TribleSetConstraint`
    /// whose entity, attribute, and value are all bound but the triple is
    /// absent from the dataset.
    ///
    /// Composite constraints propagate this check to their children:
    /// [`IntersectionConstraint`](crate::query::intersectionconstraint::IntersectionConstraint)
    /// requires *all* children to be satisfied, while
    /// [`UnionConstraint`](crate::query::unionconstraint::UnionConstraint)
    /// requires *at least one*. The union uses this to skip dead variants
    /// in propose and confirm, preventing values from a satisfied variant
    /// from leaking through a dead one.
    fn satisfied(&self, _binding: &Binding) -> bool {
        true
    }

    /// Returns the set of variables whose estimates may change when
    /// `variable` is bound or unbound.
    ///
    /// The default includes every variable this constraint touches except
    /// `variable` itself. Returns an empty set when `variable` is not part
    /// of this constraint.
    fn influence(&self, variable: VariableId) -> VariableSet {
        let mut vars = self.variables();
        if vars.is_set(variable) {
            vars.unset(variable);
            vars
        } else {
            VariableSet::new_empty()
        }
    }
}

impl<'a, T: Constraint<'a> + ?Sized> Constraint<'a> for Box<T> {
    fn variables(&self) -> VariableSet {
        let inner: &T = self;
        inner.variables()
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        let inner: &T = self;
        inner.estimate(variable, binding)
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        let inner: &T = self;
        inner.propose(variable, frontier, proposals)
    }

    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        let inner: &T = self;
        inner.confirm(variable, frontier, cands)
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        let inner: &T = self;
        inner.satisfied(binding)
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        let inner: &T = self;
        inner.influence(variable)
    }
}

impl<'a, T: Constraint<'a> + ?Sized> Constraint<'a> for std::sync::Arc<T> {
    fn variables(&self) -> VariableSet {
        let inner: &T = self;
        inner.variables()
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        let inner: &T = self;
        inner.estimate(variable, binding)
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        let inner: &T = self;
        inner.propose(variable, frontier, proposals)
    }

    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        let inner: &T = self;
        inner.confirm(variable, frontier, cands)
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        let inner: &T = self;
        inner.satisfied(binding)
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        let inner: &T = self;
        inner.influence(variable)
    }
}

/// Per-variable candidate storage for one search level: the proposals for
/// the whole batch that produced them, plus how far the engine has consumed
/// them. Slots are indexed by [`VariableId`], so siblings — different
/// variables chosen at the same depth — never share one; what a slot is
/// reused for is the *next* binding of its own variable, whose refill keeps
/// the buffer's capacity.
#[derive(Clone, Debug)]
struct LevelValues {
    /// Once proposed and confirmed, a buffer is immutable. Rayon siblings
    /// therefore share it and keep only their consumption cursor local.
    /// `None` is the never-used state, so an empty [`BindingStore`] needs no
    /// heap allocation for its 128 variable slots.
    buffer: Option<Arc<ProposalBuffer>>,
    /// Consumption position: entries before it are consumed, live entries at
    /// or after it are pending. Dead entries are skipped, never moved.
    pos: usize,
}

impl LevelValues {
    /// An empty level, const-constructible so the empty [`Binding`] can
    /// borrow a `static` array of them.
    const fn empty() -> Self {
        LevelValues {
            buffer: None,
            pos: 0,
        }
    }

    /// The published, immutable proposals for this level.
    fn buffer(&self) -> &ProposalBuffer {
        self.buffer
            .as_deref()
            .expect("a bound or active level must have a proposal buffer")
    }
}

impl Default for LevelValues {
    fn default() -> Self {
        Self::empty()
    }
}

/// Widest frontier the engine expands at once.
///
/// The search keeps a *frontier* — all the rows sitting at one point of the
/// tree — and expands up to this many of them in a single
/// [`propose`](Constraint::propose)/[`confirm`](Constraint::confirm) pass.
/// Width is what makes a level's candidate region large: with a width-1
/// frontier only the root level ever proposes widely, and every deeper level
/// hands a source a handful of candidates for one parent — measured on real
/// data, a median region of 1–7 candidates at every scale, which is far
/// below any batch-dispatch threshold.
///
/// 16384 is chosen to equal
/// `triblespace_gpu::batch_confirm::DEFAULT_MIN_CONFIRM_BATCH`, the measured
/// crossover at which a device round trip beats the CPU probes. At that
/// width a level's region carries at least as many candidates as there are
/// rows, so the batched tier is reachable at *every* depth rather than only
/// at a wide root.
///
/// It is a *ceiling*, not the first batch: a level's first chunk is
/// [`INITIAL_FRONTIER_WIDTH`], then chunk width grows by
/// [`FRONTIER_RAMP_BASE`] until it reaches this ceiling. A conservative tail
/// merge may consume the remainder early, but never exceeds the ceiling.
///
/// The frontier matrices cost `O(width · variables · depth)`, but a level's
/// proposal buffer can be larger: proposing `fanout` candidates for every row
/// in one group materialises `O(width · fanout)` entries before that level is
/// consumed. Each entry currently has 32 bytes of value, a four-byte parent
/// tag, and one packed liveness bit — nominally 36.125 bytes, before allocator
/// capacity slack. [`FrontierStats::peak_region`] observes this high-water mark
/// in entries; [`Query::with_frontier_width`] is the direct way to reduce it
/// when a query joins against a high-fanout source.
///
/// Worst-case optimality is untouched: expanding N prefixes together is the
/// same total work as expanding them one at a time, and the AGM bound is a
/// statement about output size, not traversal order.
///
/// Tune per query with [`Query::with_frontier_width`].
pub const DEFAULT_FRONTIER_WIDTH: usize = 16384;

/// Width of the *first* chunk a level draws. Later chunks grow by
/// [`FRONTIER_RAMP_BASE`] up to [`DEFAULT_FRONTIER_WIDTH`] (or whatever
/// [`Query::with_frontier_width`] set).
///
/// Starting at one keeps time-to-first-result identical to plain
/// depth-first search. A query the caller stops after one row — `exists!`,
/// `.next()` — must not pay to materialise a full-width frontier it will
/// throw away, and with a first chunk of one it does exactly the work the
/// pre-batching engine did. Measured on a first-row-only join, a flat
/// full-width engine is **8.8x** slower than the pre-batching engine;
/// one narrow chunk closes the whole gap.
///
/// This is the same insight as the `INITIAL_CHUNK`/`WIDEN_FACTOR` pair this
/// branch deleted, and as the deleted residual engine's rule that search
/// width grows geometrically after negative work — recovered at the right
/// layer (the frontier) instead of the wrong one (per-parent chunking).
///
/// Starting at one protects `.next()` and `exists!`; the ramp then trades
/// low-demand granularity against full-drain batch width. The base controls
/// that trade. Doubling was measured and rejected because its final chunk is
/// only about half a drain, but base eight retains seven eighths
/// asymptotically while reaching the ceiling in far fewer steps. See
/// [`FRONTIER_RAMP_BASE`] for the measured rationale.
pub const INITIAL_FRONTIER_WIDTH: usize = 1;

/// Factor a level's chunk width grows by after each chunk, from
/// [`INITIAL_FRONTIER_WIDTH`] up to the query's ceiling.
///
/// # Why a base, and why not two
///
/// A ramp's cost is not its number of steps, it is the size of its LAST
/// chunk. Ramping by `b` consumes `1 + b + b^2 + … + b^k`, of which the
/// final chunk `b^k` is `(b-1)/b` of the total — so the widest frontier a
/// level can build is `N - N/b`, and the peak is what batching exists to
/// produce. At `b = 2` that is `N/2`: doubling throws away half the peak,
/// which is the whole of the measured 2048 -> 512 that got the geometric
/// ramp rejected. The failure was the base, not the ramp.
///
/// At `b = 8` the peak is `7N/8` and a level reaches a 16384 ceiling in
/// `log8(16384) ~ 4.7` chunks rather than doubling's fourteen — the
/// amortised expansion overhead stops mattering well before the peak does.
///
/// A base at or above the ceiling reproduces the one-narrow-chunk-then-
/// ceiling schedule this replaced, which is the control arm to measure
/// against. Base `1` is NOT that control — `width * 1` never grows, so it
/// pins the engine to a width-1 frontier and reproduces the pre-batching
/// engine instead. Both are useful arms; they are not the same arm.
pub const FRONTIER_RAMP_BASE: usize = 8;

/// A query is an iterator over the results of a query.
/// It takes a constraint and a post-processing function as input,
/// and returns the results of the query as a stream of values.
/// The query engine uses a depth-first search to find solutions to the query,
/// proposing values for the variables and backtracking when it reaches a dead end.
/// The query engine is designed to be simple and efficient, providing low, consistent,
/// and predictable latency, skew resistance, and no required (or possible) tuning.
/// The query engine is designed to be used in combination with the [Constraint] trait,
/// which provides a simple and flexible way to implement constraints that can be used
/// to filter the results of a query.
///
/// This struct is usually not created directly, but rather through the `find!` macro,
/// which provides a convenient way to declare variables and concrete types for them.
/// And which sets up the nessecairy context for higher-level query languages
/// like the one provided by the [`crate::macros`] module.
pub struct Query<C, P: Fn(&Binding<'_>) -> Option<R>, R> {
    constraint: C,
    postprocessing: P,
    mode: Search,
    bindings: BindingStore,
    influences: [VariableSet; 128],
    unbound: VariableSet,
    /// Index-row width: one slot per variable the query mentions.
    slots: usize,
    width: usize,
    /// Set only by `IntoParallelIterator`; carried into every frontier so a
    /// built-in leaf may join the same pool without changing ordinary
    /// iterator execution.
    parallel: bool,
    stack: ArrayVec<Level, 128>,
    /// Frontier stack. `depths[0]` is the root (one empty row); `depths[d]`
    /// holds the rows with `d` variables bound. Entries above `depth` are
    /// retired but keep their allocations for the next descent.
    depths: Vec<Depth>,
    depth: usize,
    /// Scratch for per-row preferred variables, materialized only after the
    /// first disagreement in an expansion.
    choice: Vec<u32>,
    /// Scratch: the level-buffer entry index of each freshly-drawn child row.
    drawn: Vec<u32>,
    /// Scratch: each freshly-drawn child row's parent row number.
    parents: Vec<u32>,
    stats: Arc<FrontierStats>,
}

/// One pushed search level: the variable it binds, how wide its *next*
/// chunk may be, and how many candidates its proposer produced.
///
/// The width is per level rather than per query because the schedule is a
/// statement about one level's drain: the first chunk a level hands down is
/// a single row, so a caller who stops after one result never pays for a
/// batch it will not look at. See [`INITIAL_FRONTIER_WIDTH`].
///
/// `proposed` is the `O(1)` gate on the in-place descent: a level with more
/// candidates than parent rows cannot possibly yield one child per parent,
/// so the engine never pays to check. See [`Query::next_chunk`].
#[derive(Clone, Copy, Debug)]
struct Level {
    variable: VariableId,
    width: usize,
    proposed: usize,
}

/// Empties one of a [`Depth`]'s `Arc`-shared buffers for rewriting, without
/// copying the contents it is about to discard.
///
/// `Arc::make_mut` deep-clones whenever the `Arc` is shared — which is the
/// normal state right after a rayon split, since splitting hands both halves
/// the same matrices — and every caller here clears the result on the next
/// line. That copy is pure waste, and it is proportional to the frontier:
/// `rows * slots` entries, so it grows with exactly the width the engine
/// exists to make large.
///
/// When we are the sole owner the allocation is reused. When we are not, a
/// fresh empty buffer replaces our handle and the other half keeps the old
/// one untouched, which is the same outcome `make_mut` produces minus the
/// memcpy.
fn reset_shared<T: Clone>(slot: &mut Arc<Vec<T>>, capacity: usize) -> &mut Vec<T> {
    if Arc::get_mut(slot).is_none() {
        *slot = Arc::new(Vec::with_capacity(capacity));
    }
    let buffer = Arc::get_mut(slot).expect("sole owner after replacement");
    buffer.clear();
    buffer.reserve(capacity);
    buffer
}

/// The variable choice shared by every row, or the first exact partition
/// observed when rows disagree.
///
/// `Unplanned` and `Universal` carry no allocation. A split plan owns the
/// stable variable groups and stores an order override only when stable
/// grouping genuinely permutes row ordinals.
#[derive(Clone, Debug, Default)]
enum DepthPlan {
    #[default]
    Unplanned,
    Universal(VariableId),
    Split(Arc<SplitPlan>),
}

/// Explicit metadata for a frontier whose rows choose different variables.
#[derive(Debug, Default)]
struct SplitPlan {
    /// Stable grouped row order. Empty exactly when that order is the
    /// consecutive identity `0..rows`.
    order_override: Vec<u32>,
    /// `(variable, end offset into the grouped order)`, in variable order.
    groups: Vec<(VariableId, usize)>,
}

impl DepthPlan {
    /// Row visitation order denoted by this plan.
    fn selection(&self, rows: usize) -> RowSelection<'_> {
        match self {
            Self::Split(plan) if !plan.order_override.is_empty() => {
                debug_assert_eq!(plan.order_override.len(), rows);
                RowSelection::explicit(&plan.order_override)
            }
            Self::Unplanned | Self::Universal(_) | Self::Split(_) => RowSelection::identity(rows),
        }
    }

    fn group_count(&self) -> usize {
        match self {
            Self::Unplanned => 0,
            Self::Universal(_) => 1,
            Self::Split(plan) => plan.groups.len(),
        }
    }

    fn group(&self, group: usize, rows: usize) -> (VariableId, std::ops::Range<usize>) {
        match self {
            Self::Unplanned => panic!("an unplanned frontier has no variable groups"),
            Self::Universal(variable) => {
                assert_eq!(group, 0, "universal plan has exactly one group");
                (*variable, 0..rows)
            }
            Self::Split(plan) => {
                let start = if group == 0 {
                    0
                } else {
                    plan.groups[group - 1].1
                };
                let (variable, end) = plan.groups[group];
                (variable, start..end)
            }
        }
    }
}

/// One frontier: the index matrix of the rows sitting at one point of the
/// search, their per-row estimates, and an exact generated-or-split plan.
#[derive(Clone, Debug, Default)]
struct Depth {
    /// Row-major index matrix, `rows * slots` entries.
    block: Arc<Vec<u32>>,
    rows: usize,
    /// Row-major estimate matrix, `rows * slots` entries.
    estimates: Arc<Vec<usize>>,
    plan: DepthPlan,
    /// Next group to expand.
    group: usize,
    /// Exclusive end of the group range this query owns.
    ///
    /// Normally this is `plan.group_count()`. A rayon sibling is fenced to one
    /// shared-plan group by setting `group_limit = group + 1`; the original
    /// advances `group` and retains everything after it. Keeping ownership as
    /// a cursor interval lets both halves share a fragmented [`SplitPlan`]
    /// without copying or truncating it.
    group_limit: usize,
    /// Emission cursor, used only when every variable is bound.
    emit: usize,
}

impl Depth {
    fn selection(&self) -> RowSelection<'_> {
        self.plan.selection(self.rows)
    }

    fn group(&self, group: usize) -> (VariableId, std::ops::Range<usize>) {
        self.plan.group(group, self.rows)
    }
}

/// Observational counters for the batched search — how wide the frontier
/// actually got, and how often its rows disagreed about which variable to
/// bind next.
///
/// Fragmentation is the interesting number:
/// [`mean_variable_groups`](FrontierStats::mean_variable_groups) is 1.0 when
/// every row of every frontier agreed (the batch stayed whole) and rises as
/// bindings pull rows onto different adaptive choices. It is measured
/// rather than assumed because a row is never moved onto a variable it did
/// not choose — see [`Query::plan`].
///
/// Counters use relaxed atomics and are shared with every rayon clone of
/// the query, so a snapshot taken after the iterator is exhausted covers
/// the whole (possibly parallel) run.
#[derive(Debug, Default)]
pub struct FrontierStats {
    expansions: AtomicU64,
    rows: AtomicU64,
    variable_groups: AtomicU64,
    proposals: AtomicU64,
    peak_region: AtomicU64,
    widest: AtomicU64,
    inplace_descents: AtomicU64,
    copied_descents: AtomicU64,
}

impl FrontierStats {
    /// Number of frontier expansions (one per batch of parent rows).
    pub fn expansions(&self) -> u64 {
        self.expansions.load(Ordering::Relaxed)
    }

    /// Total parent rows expanded, summed over expansions.
    pub fn rows(&self) -> u64 {
        self.rows.load(Ordering::Relaxed)
    }

    /// Total preferred-variable groups, summed over expansions. Equal to
    /// [`expansions`](Self::expansions) when no frontier ever fragmented.
    pub fn variable_groups(&self) -> u64 {
        self.variable_groups.load(Ordering::Relaxed)
    }

    /// Total candidates proposed across all levels.
    pub fn proposals(&self) -> u64 {
        self.proposals.load(Ordering::Relaxed)
    }

    /// Largest number of proposals materialised by one level at once.
    ///
    /// A refill proposes for every parent row in one preferred-variable
    /// group before the level is consumed in geometrically widening chunks.
    /// The resident proposal region can therefore be much larger than the
    /// frontier itself. Cumulative [`proposals`](Self::proposals) and row
    /// width [`widest`](Self::widest) measure different quantities; neither
    /// can be used to recover this proposal-memory high-water mark.
    pub fn peak_region(&self) -> u64 {
        self.peak_region.load(Ordering::Relaxed)
    }

    /// Rows in the widest single expansion — the widest frontier the
    /// search actually reached.
    ///
    /// [`mean_width`](Self::mean_width) says what the typical expansion
    /// looked like; this says whether the ceiling was ever approached at
    /// all. The difference matters when reading a benchmark: a query whose
    /// widest frontier is far below `DEFAULT_FRONTIER_WIDTH` cannot
    /// demonstrate anything about batch-width thresholds, however the
    /// engine behaves — the data simply never filled a batch.
    pub fn widest(&self) -> u64 {
        self.widest.load(Ordering::Relaxed)
    }

    /// Descents that reused the parent frontier's matrices in place — the
    /// 1:1 case, where the child block *is* the parent block with one more
    /// slot filled in and nothing is allocated or copied.
    pub fn inplace_descents(&self) -> u64 {
        self.inplace_descents.load(Ordering::Relaxed)
    }

    /// Descents that had to build a fresh child frontier by copying each
    /// row of the parent.
    pub fn copied_descents(&self) -> u64 {
        self.copied_descents.load(Ordering::Relaxed)
    }

    /// Mean rows per expansion — the width the search actually achieved.
    pub fn mean_width(&self) -> f64 {
        let expansions = self.expansions();
        if expansions == 0 {
            0.0
        } else {
            self.rows() as f64 / expansions as f64
        }
    }

    /// Mean preferred-variable groups per expansion; 1.0 means no frontier
    /// ever fragmented.
    pub fn mean_variable_groups(&self) -> f64 {
        let expansions = self.expansions();
        if expansions == 0 {
            0.0
        } else {
            self.variable_groups() as f64 / expansions as f64
        }
    }
}

// Manual `Clone` impl, because `#[derive(Clone)]` would require `R: Clone`
// which isn't actually needed — `R` only appears in `P`'s return type.
#[cfg(feature = "parallel")]
impl<C, P, R> Clone for Query<C, P, R>
where
    C: Clone,
    P: Fn(&Binding<'_>) -> Option<R> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            constraint: self.constraint.clone(),
            postprocessing: self.postprocessing.clone(),
            mode: self.mode,
            // Consumption cursors are branch-local; immutable published
            // proposal buffers are shared by refcount.
            bindings: self.bindings.clone(),
            influences: self.influences,
            unbound: self.unbound,
            slots: self.slots,
            width: self.width,
            parallel: self.parallel,
            stack: self.stack.clone(),
            // Only the live prefix of the frontier stack matters; the
            // retired tail is scratch. Each `Depth`'s matrices sit behind
            // `Arc`, so transferring a planned group copies refcounts, not
            // megabytes — the copy-on-write lands on whichever owner
            // rewrites a frontier first.
            depths: self.depths[..=self.depth].to_vec(),
            depth: self.depth,
            choice: Vec::new(),
            drawn: Vec::new(),
            parents: Vec::new(),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(feature = "parallel")]
impl<C, P, R> Query<C, P, R>
where
    C: Clone,
    P: Fn(&Binding<'_>) -> Option<R> + Clone,
{
    /// Whether retiring the current frontier would expose work still owned
    /// by this query.
    ///
    /// A split is useful only when the left producer has a distinct future
    /// after transferring the right producer's frontier unit. That future
    /// can be a later group in an ancestor frontier, or candidates from the
    /// ancestor's already-proposed level that its geometric cursor has not
    /// consumed yet. `proposed > consumed` is intentionally conservative:
    /// the unseen suffix may contain only dead candidates, but discovering
    /// that is precisely the left continuation's work.
    fn has_ancestor_continuation(&self) -> bool {
        (0..self.depth).any(|depth| {
            let frontier = &self.depths[depth];
            frontier.group < frontier.group_limit
                || self
                    .stack
                    .get(depth)
                    .is_some_and(|level| level.proposed > self.bindings.consumed(level.variable))
        })
    }

    /// Transfers the next *whole planned group* to a fenced sibling query.
    ///
    /// A group is all rows of one frontier that chose the same next
    /// variable under the same ordered binding history. The sibling owns
    /// that group in its entirety; `self` advances past it and retains the
    /// continuation — later groups at this depth and, once they are spent,
    /// the ancestor source that can draw the next geometric page. No
    /// proposal buffer is bisected, so a source's batch remains intact.
    ///
    /// The sibling is re-rooted at the group's frontier and fenced there:
    /// ancestor `Level`s are discarded, while their `LevelValues` remain in
    /// the cloned [`BindingStore`] because the group's rows resolve bound
    /// indexes through them. Once the owned group is exhausted, the sibling
    /// ends instead of replaying an ancestor continuation still owned by
    /// `self`.
    ///
    /// A sole group at the root cannot be transferred: neither half would
    /// retain a distinct continuation, and repeated rayon splitting would
    /// merely hand the same indivisible work back and forth. Entering it
    /// serially may create child groups/pages that *do* have a continuation
    /// and can then be transferred safely.
    fn split_pending_group(&mut self) -> Option<Self> {
        debug_assert_eq!(self.mode, Search::NextGroup);

        let depth = self.depth;
        let current = self.depths[depth].group;
        let group_limit = self.depths[depth].group_limit;
        let later_group = current + 1 < group_limit;
        if current >= group_limit || !(later_group || self.has_ancestor_continuation()) {
            return None;
        }

        let mut right = self.clone();
        self.depths[depth].group += 1;

        drop(right.stack.drain(..depth));
        drop(right.depths.drain(..depth));
        right.depth = 0;

        let root = &mut right.depths[0];
        root.group_limit = root.group + 1;
        Some(right)
    }

    /// Transfers the un-emitted remainder of a complete frontier page to a
    /// fenced sibling, leaving `self` at the parent source continuation.
    ///
    /// Terminal pages have no `NextGroup` state — planning moves them
    /// straight to [`Search::Emit`] — but they are still whole products of a
    /// planned group. Treating the page as one indivisible unit is what lets
    /// single-variable queries participate in rayon without slicing their
    /// proposal buffers or their result frontiers. The sibling preserves the
    /// current emission cursor, so the operation is correct even if a future
    /// caller exposes splitting after partial consumption.
    fn split_terminal_frontier(&mut self) -> Option<Self> {
        debug_assert_eq!(self.mode, Search::Emit);
        let depth = self.depth;
        if depth == 0
            || self.depths[depth].emit >= self.depths[depth].rows
            || !self.has_ancestor_continuation()
        {
            return None;
        }

        let mut right = self.clone();
        self.depth -= 1;
        self.mode = Search::NextChunk;

        drop(right.stack.drain(..depth));
        drop(right.depths.drain(..depth));
        right.depth = 0;
        Some(right)
    }
}

impl<'a, C: Constraint<'a>, P: Fn(&Binding<'_>) -> Option<R>, R> Query<C, P, R> {
    /// Create a new query.
    /// The query takes a constraint and a post-processing function as input,
    /// and returns the results of the query as a stream of values.
    /// The post-processing function returns `Option<R>`: returning `None`
    /// skips the current binding and continues the search.
    ///
    /// This method is usually not called directly, but rather through the [find!] macro,
    pub fn new(constraint: C, postprocessing: P) -> Self {
        let variables = constraint.variables();
        let influences = std::array::from_fn(|v| {
            if variables.is_set(v) {
                constraint.influence(v)
            } else {
                VariableSet::new_empty()
            }
        });
        let bindings = BindingStore::new();
        let slots = variables.find_last_set().map(|v| v + 1).unwrap_or(0);
        let estimates: Vec<usize> = (0..slots)
            .map(|v| {
                if variables.is_set(v) {
                    constraint
                        .estimate(v, &bindings.view())
                        .expect("unconstrained variable in query")
                } else {
                    usize::MAX
                }
            })
            .collect();

        // Constraints whose positions are all constant [`Term`]s (e.g. a
        // fully-constant `pattern!` used as an existence check) have an
        // empty variable set, so the propose/confirm search never consults
        // them. Their truth is binding-independent and `satisfied` is exact
        // for them from the start (the fully-bound exactness law: zero
        // unbound variables). One check up front settles every such
        // subtree; constraints with unbound variables answer an optimistic
        // `true` here and are validated by the search as usual.
        let mode = if constraint.satisfied(&bindings.view()) {
            Search::Plan
        } else {
            Search::Done
        };

        let root = Depth {
            block: Arc::new(vec![0u32; slots]),
            rows: 1,
            estimates: Arc::new(estimates),
            plan: DepthPlan::Unplanned,
            group: 0,
            group_limit: 0,
            emit: 0,
        };

        Query {
            constraint,
            postprocessing,
            mode,
            bindings,
            influences,
            unbound: variables,
            slots,
            width: DEFAULT_FRONTIER_WIDTH,
            parallel: false,
            stack: ArrayVec::new(),
            depths: vec![root],
            depth: 0,
            choice: Vec::new(),
            drawn: Vec::new(),
            parents: Vec::new(),
            stats: Arc::new(FrontierStats::default()),
        }
    }

    /// Sets the *widest* frontier this query expands at once. See
    /// [`DEFAULT_FRONTIER_WIDTH`] for what the number buys and
    /// [`INITIAL_FRONTIER_WIDTH`] for the ramp that leads up to it.
    ///
    /// A width of 1 reduces the engine to expanding one binding at a time —
    /// the shape the protocol had before frontiers — which is what the
    /// equivalence tests pin. The ramp is a no-op at that ceiling, so the
    /// reduction is exact.
    ///
    /// # Panics
    ///
    /// Panics if `width` is zero.
    pub fn with_frontier_width(mut self, width: usize) -> Self {
        assert!(width > 0, "frontier width must be at least one binding");
        self.width = width;
        self
    }

    /// Observational counters for this query's frontiers. The handle is
    /// shared with every rayon clone, so it stays meaningful under parallel
    /// execution.
    pub fn stats(&self) -> Arc<FrontierStats> {
        Arc::clone(&self.stats)
    }

    /// The frontier currently at the top of the stack, unrestricted.
    fn frontier(&self) -> Frontier<'_> {
        let depth = &self.depths[self.depth];
        self.bindings
            .batch(&depth.block, depth.selection(), self.slots, self.parallel)
    }

    /// Partitions the top frontier by each row's preferred variable.
    ///
    /// The preference is the same adaptive, magnitude-bucketed choice the
    /// engine has always made — smallest estimate magnitude, most
    /// influence — evaluated per row, against that row's own estimates.
    /// Rows are never moved onto a variable they did not choose:
    /// [`propose`](Constraint::propose) owns candidate support and
    /// first-seen order, and the protocol supplies no cross-variable
    /// support-equivalence law, so an estimate-compatible variable is not
    /// an interchangeable action. All the leeway lives in the magnitude
    /// bucketing, which is what makes agreement — and therefore a whole,
    /// unsplit batch — the common case.
    fn plan(&mut self) {
        if self.unbound.is_empty() {
            self.depths[self.depth].emit = 0;
            self.mode = Search::Emit;
            return;
        }

        let slots = self.slots;
        let influences = &self.influences;
        let unbound = self.unbound;
        let depth = &mut self.depths[self.depth];
        let rows = depth.rows;

        assert!(rows != 0, "the engine never plans an empty frontier");
        u32::try_from(rows - 1).expect("frontier row ordinal exceeds u32");

        let preferred = |row: usize| {
            let row_estimates = &depth.estimates[row * slots..(row + 1) * slots];
            unbound
                .into_iter()
                .max_by_key(|&v| {
                    (
                        Reverse(
                            row_estimates[v]
                                .checked_ilog2()
                                .map(|magnitude| magnitude + 1)
                                .unwrap_or(0),
                        ),
                        influences[v].count(),
                    )
                })
                .expect("non-empty unbound")
        };

        self.choice.clear();
        let first = preferred(0);
        let disagreement = (1..rows).find_map(|row| {
            let variable = preferred(row);
            (variable != first).then_some((row, variable))
        });

        if let Some((row, variable)) = disagreement {
            // Only an observed distinction earns storage. Materialise the
            // implied unanimous prefix at the first counterexample, then the
            // counterexample and remaining exact choices.
            self.choice.resize(
                row,
                u32::try_from(first).expect("query variables fit in u32"),
            );
            self.choice
                .push(u32::try_from(variable).expect("query variables fit in u32"));
            for row in row + 1..rows {
                self.choice
                    .push(u32::try_from(preferred(row)).expect("query variables fit in u32"));
            }

            let mut counts = [0usize; 128];
            for &variable in &self.choice {
                counts[variable as usize] += 1;
            }
            let mut starts = [0usize; 128];
            let mut split = SplitPlan::default();
            let mut offset = 0;
            for variable in 0..slots {
                starts[variable] = offset;
                if counts[variable] != 0 {
                    offset += counts[variable];
                    split.groups.push((variable, offset));
                }
            }
            debug_assert_eq!(offset, rows);
            debug_assert!(split.groups.len() > 1);

            // Stable counting sort is the identity exactly when the input
            // choices are already in nondecreasing variable order.
            let identity = self.choice.windows(2).all(|pair| pair[0] <= pair[1]);
            if !identity {
                split.order_override.resize(rows, 0);
                for (row, &variable) in self.choice.iter().enumerate() {
                    split.order_override[starts[variable as usize]] =
                        u32::try_from(row).expect("frontier row ordinal exceeds u32");
                    starts[variable as usize] += 1;
                }
            }
            depth.plan = DepthPlan::Split(Arc::new(split));
        } else {
            depth.plan = DepthPlan::Universal(first);
        }
        depth.group = 0;
        depth.group_limit = depth.plan.group_count();

        self.stats.expansions.fetch_add(1, Ordering::Relaxed);
        self.stats.rows.fetch_add(rows as u64, Ordering::Relaxed);
        self.stats.widest.fetch_max(rows as u64, Ordering::Relaxed);
        self.stats.variable_groups.fetch_add(
            self.depths[self.depth].group_limit as u64,
            Ordering::Relaxed,
        );
        self.mode = Search::NextGroup;
    }

    /// Expands the next group of the top frontier: pushes its variable and
    /// proposes candidates for every row of the group in one call. When the
    /// groups are exhausted the frontier itself is retired.
    fn next_group(&mut self) {
        let depth = &self.depths[self.depth];
        if depth.group >= depth.group_limit {
            if self.depth == 0 {
                self.mode = Search::Done;
            } else {
                self.depth -= 1;
                self.mode = Search::NextChunk;
            }
            return;
        }
        let group = depth.group;
        let (variable, range) = depth.group(group);
        self.depths[self.depth].group += 1;

        self.unbound.unset(variable);

        let constraint = &self.constraint;
        let depth = &self.depths[self.depth];
        let block = Arc::clone(&depth.block);
        let selection = depth.selection().slice(range);
        let proposed = self.bindings.refill(
            variable,
            &block,
            selection,
            self.slots,
            self.parallel,
            |frontier, proposals| constraint.propose(variable, frontier, proposals),
        );
        self.stack.push(Level {
            variable,
            width: INITIAL_FRONTIER_WIDTH.min(self.width),
            proposed,
        });
        self.stats
            .proposals
            .fetch_add(proposed as u64, Ordering::Relaxed);
        self.stats
            .peak_region
            .fetch_max(proposed as u64, Ordering::Relaxed);
        self.mode = Search::NextChunk;
    }

    /// Consumes the next chunk of the top level's candidates into the child
    /// frontier. When the level is spent the group is retired and the next
    /// one gets its turn.
    ///
    /// # In-place 1:1 descent
    ///
    /// The child frontier is normally built by copying each drawn
    /// candidate's parent row and filling in the newly bound variable's
    /// slot. When the draw is **1:1** — one surviving child per parent row,
    /// in order, covering the whole parent frontier, with nothing left over
    /// — no row was gained, lost or reordered, so the child block *is* the
    /// parent block with one more slot written. The engine's two standing
    /// invariants are what make that safe: confirmers may only kill
    /// candidates and never revive them (so a surviving row keeps its
    /// identity), and buffers are write-once (so `variable`'s slot in every
    /// row was previously unwritten and filling it destroys nothing). The
    /// same argument covers the estimate matrix: the rows the child would
    /// have copied are bit-identical to the parent's, and the only slots it
    /// then overwrites are the ones the influence refresh recomputes
    /// anyway.
    ///
    /// A 1:1 draw that leaves the level spent is also the last thing the
    /// parent frontier is ever asked for, so the matrices are handed *down*
    /// (swapped with the child's retired allocations) rather than shared —
    /// which is what lets a whole chain of 1:1 descents run without a
    /// single matrix copy, instead of only the first one.
    ///
    /// Ownership is not tracked separately: the frontier matrices already
    /// sit behind `Arc` so a rayon split copies refcounts, and
    /// [`Arc::get_mut`] therefore succeeds exactly when no split or steal
    /// is holding the other half. Let the `Arc` be the guard; when it says
    /// no, take the copying path.
    ///
    /// **The fast path is gated so it costs nothing when it cannot fire.**
    /// Recognising a 1:1 draw means deferring the child rows until the
    /// draw's shape is known, and that deferral is a second pass — measured
    /// at +10% on F10 and +20% on F6 when charged to every descent. So the
    /// engine asks first, from what it already knows: a level holding
    /// `proposed` candidates for `rows` parents can only yield one child
    /// per parent if `proposed == rows`. Fan-out levels fail that `O(1)`
    /// test and run the fused [`take_chunk`](BindingStore::take_chunk)
    /// exactly as before.
    fn next_chunk(&mut self) {
        let level = *self.stack.last().expect("a level to chunk");
        let variable = level.variable;
        let parent = self.depth;
        let group = self.depths[parent].group - 1;
        let (_, range) = self.depths[parent].group(group);
        let slots = self.slots;

        if self.depths.len() <= parent + 1 {
            self.depths.push(Depth::default());
        }

        // Could this draw possibly be 1:1? One child per parent needs
        // exactly as many candidates as there are parent rows, and a chunk
        // wide enough to take them all. Both are known before drawing, and
        // both are `O(1)`.
        let source_rows = range.len();
        let speculate = level.proposed == source_rows
            && level.width >= source_rows
            && self.depths[parent].group >= self.depths[parent].group_limit;

        let rows = if speculate {
            let selection = self.depths[parent].selection().slice(range.clone());
            self.bindings.draw(
                variable,
                level.width,
                selection,
                &mut self.drawn,
                &mut self.parents,
            );
            self.drawn.len()
        } else {
            let (head, tail) = self.depths.split_at_mut(parent + 1);
            let selection = head[parent].selection().slice(range);
            self.bindings.take_chunk(
                variable,
                level.width,
                &head[parent].block,
                selection,
                slots,
                Arc::make_mut(&mut tail[0].block),
                &mut self.parents,
            )
        };
        // Widen the next chunk this level hands down. The first chunk is one
        // binding, so a caller who stops after one row pays exactly what
        // depth-first paid; after that the width climbs by
        // `FRONTIER_RAMP_BASE` to the ceiling, which serves the caller who
        // wants a handful of rows without surrendering the peak (see
        // `FRONTIER_RAMP_BASE` for why the base is what decides that).
        let consumed = self.bindings.consumed(variable);
        if let Some(top) = self.stack.last_mut() {
            let next = top.width.saturating_mul(FRONTIER_RAMP_BASE).min(self.width);
            // Never leave a tail smaller than the chunk that would precede
            // it. `proposed - consumed` over-counts (it cannot see which
            // entries confirm already killed), so this merges conservatively
            // — it can decline a merge it should have made, never force one
            // it should not. Both branches are O(1): the level already knows
            // how many candidates it proposed and how far the cursor ran.
            let remaining = top.proposed.saturating_sub(consumed);
            top.width = if remaining < next.saturating_mul(2) {
                // `.min(self.width)` is load-bearing, not belt-and-braces:
                // `remaining` is bounded by the region, not by the ceiling,
                // so merging a tail without it hands down a chunk up to
                // twice the width the caller asked for. Measured before the
                // cap: 134 of 300 registry spans exceeded a 16384 ceiling,
                // worst at 1.93x — and `width` is a ceiling that the
                // `O(width · variables · depth)` frontier-memory bound is
                // stated against. At the ceiling the merge is a no-op, which
                // is right: a level already running flat has no ramp tail.
                remaining.max(next).min(self.width)
            } else {
                next
            };
        }

        if rows == 0 {
            self.stack.pop();
            self.bindings.unset(variable);
            self.unbound.set(variable);
            self.mode = Search::NextGroup;
            return;
        }

        // The speculation paid off when every parent really did produce
        // exactly one child, in order, and nothing is left pending.
        // `spent` is last because it scans the level's remaining liveness
        // words.
        let reusable = speculate
            && rows == source_rows
            && self
                .parents
                .iter()
                .enumerate()
                .all(|(row, &parent_row)| parent_row as usize == row)
            && self.bindings.spent(variable);

        let (head, tail) = self.depths.split_at_mut(parent + 1);
        let source = &mut head[parent];
        let child = &mut tail[0];

        let inplace = reusable
            && Arc::get_mut(&mut source.block).is_some()
            && Arc::get_mut(&mut source.estimates).is_some();

        if inplace {
            // Hand the matrices down and take the child's retired
            // allocations in exchange, so the next 1:1 descent finds a
            // uniquely-owned block again and the chain stays copy-free.
            std::mem::swap(&mut source.block, &mut child.block);
            std::mem::swap(&mut source.estimates, &mut child.estimates);
            let block = Arc::get_mut(&mut child.block).expect("unique across the swap");
            for (row, &entry) in self.drawn.iter().enumerate() {
                block[row * slots + variable] = entry;
            }
            self.stats.inplace_descents.fetch_add(1, Ordering::Relaxed);
        } else {
            if speculate {
                // Speculated and lost: the rows still have to be written,
                // just from the deferred draw rather than fused with it.
                let block = reset_shared(&mut child.block, rows * slots);
                for (&entry, &parent_row) in self.drawn.iter().zip(self.parents.iter()) {
                    let parent_row = parent_row as usize;
                    block.extend_from_slice(
                        &source.block[parent_row * slots..(parent_row + 1) * slots],
                    );
                    let base = block.len() - slots;
                    block[base + variable] = entry;
                }
            }
            // Inherit each child row's estimates from its parent; the
            // refresh below then updates exactly the ones binding
            // `variable` can have changed — the same influence-driven
            // refresh the single-binding engine did, now once per row of
            // the batch. Nothing else can have gone stale: a row's
            // estimates were computed against its own binding, so
            // backtracking never invalidates them.
            let estimates = reset_shared(&mut child.estimates, rows * slots);
            for &parent_row in self.parents.iter() {
                let parent_row = parent_row as usize;
                estimates.extend_from_slice(
                    &source.estimates[parent_row * slots..(parent_row + 1) * slots],
                );
            }
            self.stats.copied_descents.fetch_add(1, Ordering::Relaxed);
        }
        child.rows = rows;
        child.plan = DepthPlan::Unplanned;
        child.group = 0;
        child.group_limit = 0;
        child.emit = 0;

        let stale = self.influences[variable].intersect(self.unbound);
        if !stale.is_empty() {
            let child = &mut self.depths[parent + 1];
            let block = Arc::clone(&child.block);
            let estimates = Arc::make_mut(&mut child.estimates);
            let batch =
                self.bindings
                    .batch(&block, RowSelection::identity(rows), slots, self.parallel);
            for row in 0..rows {
                let binding = batch.row(row);
                for v in stale {
                    estimates[row * slots + v] = self
                        .constraint
                        .estimate(v, &binding)
                        .expect("unconstrained variable in query");
                }
            }
        }

        self.depth = parent + 1;
        self.mode = Search::Plan;
    }
}

/// The search mode of the query engine.
///
/// The engine is still a depth-first search; what moved is its unit of
/// work. A step no longer binds one variable to one value — it expands a
/// whole *frontier* of parent bindings at once, so every level's proposal
/// region is as wide as the batch rather than as wide as one parent's
/// candidate list.
///
/// - `Plan` — partition the top frontier by each row's preferred variable.
/// - `NextGroup` — expand the next group: push its variable and propose for
///   all its rows in one call.
/// - `NextChunk` — turn the next `width` surviving candidates into the
///   child frontier, or retire the group when they run out.
/// - `Emit` — every variable is bound; stream the frontier's rows out.
/// - `Done` — the search is finished.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Search {
    Plan,
    NextGroup,
    NextChunk,
    Emit,
    Done,
}

impl<'a, C: Constraint<'a>, P: Fn(&Binding<'_>) -> Option<R>, R> Iterator for Query<C, P, R> {
    type Item = R;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.mode {
                Search::Plan => self.plan(),
                Search::NextGroup => self.next_group(),
                Search::NextChunk => self.next_chunk(),
                Search::Emit => {
                    // One row per complete binding, in frontier order, no
                    // dedup — bag semantics are a property of the rows, not
                    // of how many at a time the engine happened to build.
                    let frontier = self.frontier();
                    let rows = frontier.len();
                    let mut emit = self.depths[self.depth].emit;
                    let mut result = None;
                    while emit < rows {
                        let binding = frontier.row(emit);
                        emit += 1;
                        if let Some(row) = (self.postprocessing)(&binding) {
                            result = Some(row);
                            break;
                        }
                    }
                    self.depths[self.depth].emit = emit;
                    if result.is_some() {
                        return result;
                    }
                    // The batch is spent; hand control back to the level
                    // that produced it for its next chunk.
                    if self.depth == 0 {
                        self.mode = Search::Done;
                    } else {
                        self.depth -= 1;
                        self.mode = Search::NextChunk;
                    }
                }
                Search::Done => return None,
            }
        }
    }
}

impl<'a, C: Constraint<'a>, P: Fn(&Binding<'_>) -> Option<R>, R> fmt::Debug for Query<C, P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("constraint", &std::any::type_name::<C>())
            .field("mode", &self.mode)
            .field("width", &self.width)
            .field("frontier", &self.frontier())
            .field("stack", &self.stack)
            .field("unbound", &self.unbound)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Parallel execution via rayon.
//
// `Query` implements `IntoParallelIterator` with `Iter = QueryParIter`.
// `QueryParIter` is a separate wrapper type implementing `ParallelIterator`
// + `UnindexedProducer`, distinct from `Query` itself to avoid method-name
// ambiguity between `Iterator` and `ParallelIterator` — methods like
// `.count()`, `.collect()`, `.map()` exist on both.
//
// Usage: `find!(...).into_par_iter().map(...).collect::<Vec<_>>()`.
//
// The producer's `split` transfers one *whole planned frontier group* to a
// sibling. A group is the rows sharing both an ordered variable-choice prefix
// and their preferred next variable. The original producer skips that group
// and retains the source continuation, so it can draw the next geometric page
// while the sibling evaluates the current one. The sibling is re-rooted and
// fenced at the group: it cannot replay later groups or ancestor work.
//
// No proposal buffer is bisected. This is the load-bearing difference from
// candidate sharding: every owned group reaches `propose`/`confirm` at its
// natural width, preserving geometric widening and accelerator-sized batches.
// A heavy sole root group is honestly serial until executing it produces a
// child group with a source continuation; the parallel path does not invent a
// destructive intra-group split merely to keep rayon busy.
//
// A built-in CPU constraint may nevertheless expose *work inside one logical
// confirm call* to the same pool. `IntoParallelIterator` marks the query's
// frontier views with crate-private execution intent; ordinary `Iterator`
// queries do not acquire that intent merely because they happen to run on a
// Rayon worker. TribleSet confirmation uses it to divide packed liveness at
// word boundaries, where each worker owns disjoint killable words. That leaves
// the frontier, proposal buffer, and any accelerator routing whole: it is data
// parallelism inside a leaf, not another search-state split.
// Every successful split advances the original owner's group/page cursor and
// fences that unit out of the sibling's future, so ownership is a strict
// progress measure. Rayon's pressure splitter needs no engine-specific split
// budget.
//
// `fold_with` is the terminal leaf: it just drives the existing sequential
// `Iterator::next()` and feeds results into the folder. No duplicated
// execution logic.
// ---------------------------------------------------------------------------

#[cfg(feature = "parallel")]
pub use parallel::QueryParIter;

#[cfg(feature = "parallel")]
mod parallel {
    use super::*;
    use rayon::iter::plumbing::{bridge_unindexed, Folder, UnindexedConsumer, UnindexedProducer};
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    /// Parallel iterator over the results of a [`Query`]. Obtained via
    /// [`IntoParallelIterator::into_par_iter`] on a `Query`.
    ///
    /// Drives rayon's work-stealing scheduler through an `UnindexedProducer`
    /// impl on the underlying query state. The sequential `Iterator::next`
    /// on `Query` is reused as the fold leaf — parallel execution is purely
    /// additional, no duplicated engine logic.
    ///
    /// The inner query is stored in a [`Box`] so rayon's work-stealing
    /// `split` (which clones the producer) doesn't memcpy the query's large
    /// fixed state on every fork — just a Box pointer copy, with the heap
    /// allocation paid only by the child.
    pub struct QueryParIter<C, P: Fn(&Binding<'_>) -> Option<R>, R> {
        inner: Box<Query<C, P, R>>,
    }

    impl<'a, C, P, R> IntoParallelIterator for Query<C, P, R>
    where
        C: Constraint<'a> + Clone + Send + 'a,
        P: Fn(&Binding<'_>) -> Option<R> + Clone + Send,
        R: Send,
    {
        type Item = R;
        type Iter = QueryParIter<C, P, R>;

        fn into_par_iter(mut self) -> Self::Iter {
            self.parallel = true;
            QueryParIter {
                inner: Box::new(self),
            }
        }
    }

    impl<'a, C, P, R> UnindexedProducer for QueryParIter<C, P, R>
    where
        C: Constraint<'a> + Clone + Send + 'a,
        P: Fn(&Binding<'_>) -> Option<R> + Clone + Send,
        R: Send,
    {
        type Item = R;

        /// Advance the Query's state machine until either a whole planned
        /// group can be transferred to a sibling or the sub-query is
        /// exhausted / has reached a batch of complete rows (return `None`,
        /// leaving `self` as a leaf that `fold_with` will fold sequentially).
        fn split(mut self) -> (Self, Option<Self>) {
            let q = &mut *self.inner;
            loop {
                match q.mode {
                    Search::Plan => q.plan(),
                    Search::NextGroup => {
                        if let Some(right) = q.split_pending_group() {
                            return (
                                self,
                                Some(QueryParIter {
                                    inner: Box::new(right),
                                }),
                            );
                        }
                        q.next_group();
                    }
                    Search::Emit => {
                        if let Some(right) = q.split_terminal_frontier() {
                            return (
                                self,
                                Some(QueryParIter {
                                    inner: Box::new(right),
                                }),
                            );
                        }
                        return (self, None);
                    }
                    Search::Done => return (self, None),
                    Search::NextChunk => {
                        // Draw the next geometric page intact. Planning its
                        // child frontier exposes one or more whole groups on
                        // the next loop iteration; those are the stealable
                        // units, not slices of this proposal buffer.
                        q.next_chunk();
                    }
                }
            }
        }

        fn fold_with<F: Folder<R>>(self, mut folder: F) -> F {
            let QueryParIter { inner: mut q } = self;
            while !folder.full() {
                match q.next() {
                    Some(item) => folder = folder.consume(item),
                    None => break,
                }
            }
            folder
        }
    }

    impl<'a, C, P, R> ParallelIterator for QueryParIter<C, P, R>
    where
        C: Constraint<'a> + Clone + Send + 'a,
        P: Fn(&Binding<'_>) -> Option<R> + Clone + Send,
        R: Send,
    {
        type Item = R;

        fn drive_unindexed<Con>(self, consumer: Con) -> Con::Result
        where
            Con: UnindexedConsumer<Self::Item>,
        {
            bridge_unindexed(self, consumer)
        }
    }
}

/// Iterate over query results, converting each variable via
/// [`TryFromInline`](crate::inline::TryFromInline).
///
/// The macro takes two arguments: a tuple of variables with optional type
/// annotations, and a constraint expression. It injects a `__local_find_context!`
/// macro that provides the variable context to nested query macros like
/// [`pattern!`](crate::macros::pattern) and [`temp!`](crate::temp).
///
/// # Variable syntax
///
/// | Syntax | Meaning |
/// |--------|---------|
/// | `name` | inferred type, filter on conversion failure |
/// | `name: Type` | explicit type, filter on conversion failure |
/// | `name?` | inferred type, yield `Result<T, E>` (no filter) |
/// | `name: Type?` | explicit type, yield `Result<T, E>` (no filter) |
///
/// Query heads have BAG semantics: one row per complete satisfying assignment.
/// Two assignments that agree on every declared head variable but differ in
/// hidden variables therefore produce two rows — hidden-variable multiplicity
/// is visible in the output, and the engine performs no deduplication. That is
/// deliberate: deduplicating would mean carrying a claim table proportional to
/// the distinct result set, sharing it across rayon shards, and deciding what a
/// panicking or filtered row does to a claimed key. Dedup is the consumer's
/// choice instead: collect into a set, or use two queries (an outer enumeration
/// over the values you want distinct, with an inner [`exists!`](crate::exists)
/// for the witness). Every projected variable must be unique; repeating a
/// variable in the head is a compile error because it would not add a column.
///
/// The unit form `find!((), constraint)` projects no variables and yields one
/// `()` per satisfying assignment — it counts witnesses rather than answering a
/// yes/no question. Use [`exists!`](crate::exists) for existence, which stops
/// at the first witness.
///
/// **Filter semantics (default):** when a variable's conversion fails the
/// entire row is silently skipped — like a constraint that doesn't match.
/// For types whose `TryFromInline::Error = Infallible` the error branch is
/// dead code, so no rows can ever be accidentally filtered.
///
/// **`?` pass-through:** appending `?` to a variable makes it yield
/// `Result<T, E>` directly. Both `Ok` and `Err` values pass through with
/// no filtering, matching Rust's `?` semantics of "bubble the error to the
/// caller."
///
/// # Examples
///
/// ```
/// # use triblespace_core::prelude::*;
/// # use triblespace_core::prelude::inlineencodings::ShortString;
/// // Filter semantics — rows where conversion fails are skipped:
/// let results = find!((x: Inline<ShortString>), x.is("foo".to_inline())).collect::<Vec<_>>();
/// ```
#[macro_export]
macro_rules! find {
    ($($tokens:tt)*) => {
        {
            #[allow(unused_mut, unused_variables)]
            let mut ctx = $crate::query::VariableContext::new();

            macro_rules! __local_find_context {
                () => { &mut ctx }
            }

            $crate::macros::__find_impl!($crate, ctx, $($tokens)*)
        }
    };
}
/// Re-export of the [`find!`] macro.
pub use find;

/// Returns `true` when a query produces at least one row.
///
/// This is equivalent to calling `find!(...).next().is_some()`, but reads more
/// directly for existence checks.
///
/// # Forms
///
/// - `exists!(constraint)` checks a pure constraint with no projected
///   variables.
/// - `exists!((vars...), constraint)` uses the same variable/conversion syntax
///   as [`find!`] before checking whether any row survives projection.
///
/// ```rust,ignore
/// exists!(pattern!(&kb, [{ ?person @ social::name: "Alice" }]))
/// ```
///
/// ```rust,ignore
/// exists!(
///     (name: Inline<_>),
///     pattern!(&kb, [{ ?person @ social::name: ?name }])
/// )
/// ```
#[macro_export]
macro_rules! exists {
    (($($vars:tt)*), $Constraint:expr) => {
        $crate::query::find!(($($vars)*), $Constraint).next().is_some()
    };
    ($Constraint:expr) => {
        $crate::query::find!((), $Constraint).next().is_some()
    };
}
/// Re-export of the [`exists!`] macro.
pub use exists;

/// Introduces one or more temporary query variables for a nested constraint.
///
/// `temp!` is only meaningful inside macros that provide a local query context,
/// such as [`find!`], [`exists!`], or macros expanded from them like
/// [`pattern!`](crate::macros::pattern). Each identifier becomes a fresh query
/// variable that is scoped to the wrapped body.
///
/// ```rust,ignore
/// find!(
///     (person: Inline<_>),
///     temp!((friend), and!(
///         pattern!(&kb, [{ ?person @ social::friend: ?friend }]),
///         pattern!(&kb, [{ ?friend @ social::name: "Bob" }])
///     ))
/// )
/// ```
#[macro_export]
macro_rules! temp {
    (($Var:ident), $body:expr) => {{
        let $Var = __local_find_context!().next_variable();
        $body
    }};
    (($Var:ident,), $body:expr) => {
        $crate::temp!(($Var), $body)
    };
    (($Var:ident, $($rest:ident),+ $(,)?), $body:expr) => {{
        $crate::temp!(
            ($Var),
            $crate::temp!(($($rest),+), $body)
        )
    }};
}
/// Re-export of the [`temp!`] macro.
pub use temp;

#[cfg(test)]
mod tests {
    use inlineencodings::ShortString;

    use crate::prelude::inlineencodings::*;
    use crate::prelude::*;

    use crate::examples::literature;

    use fake::faker::lorem::en::Sentence;
    use fake::faker::lorem::en::Words;
    use fake::faker::name::raw::*;
    use fake::locales::*;
    use fake::Fake;

    use std::collections::HashSet;

    use super::*;

    fn variable_set(indices: impl IntoIterator<Item = VariableId>) -> VariableSet {
        let mut variables = VariableSet::new_empty();
        for variable in indices {
            variables.set(variable);
        }
        variables
    }

    pub mod knights {
        use crate::prelude::*;

        attributes! {
            "8143F46E812E88C4544E7094080EC523" unsafe as loves: inlineencodings::GenId;
            "D6E0F2A6E5214E1330565B4D4138E55C" unsafe as name: inlineencodings::ShortString;
        }
    }

    mod shared_level_buffers {
        use super::*;

        fn value(byte: u8) -> RawInline {
            let mut value = [0; 32];
            value[31] = byte;
            value
        }

        fn refill(store: &mut BindingStore, values: &[RawInline]) {
            store.refill(
                0,
                &[0],
                RowSelection::identity(1),
                1,
                false,
                |frontier, proposals| {
                    assert_eq!(frontier.len(), 1);
                    proposals.open(0);
                    proposals.extend(values.iter().copied());
                },
            );
        }

        #[test]
        fn clone_shares_published_buffer_but_not_consumption_cursor() {
            let mut left = BindingStore::new();
            refill(&mut left, &[value(1), value(2), value(3)]);
            let right = left.clone();

            assert!(Arc::ptr_eq(
                left.levels[0].buffer.as_ref().unwrap(),
                right.levels[0].buffer.as_ref().unwrap(),
            ));

            let mut drawn = Vec::new();
            let mut parents = Vec::new();
            left.draw(0, 1, RowSelection::identity(1), &mut drawn, &mut parents);
            assert_eq!(left.levels[0].pos, 1);
            assert_eq!(right.levels[0].pos, 0);
            assert_eq!(right.levels[0].buffer()[0], value(1));
        }

        #[test]
        fn refill_replaces_a_shared_buffer_without_touching_its_sibling() {
            let mut left = BindingStore::new();
            refill(&mut left, &[value(1), value(2)]);
            let right = left.clone();

            refill(&mut left, &[value(9)]);

            assert!(!Arc::ptr_eq(
                left.levels[0].buffer.as_ref().unwrap(),
                right.levels[0].buffer.as_ref().unwrap(),
            ));
            assert_eq!(&right.levels[0].buffer()[..], &[value(1), value(2)]);
            assert_eq!(&left.levels[0].buffer()[..], &[value(9)]);
        }

        #[test]
        fn refill_reuses_a_uniquely_owned_buffer() {
            let mut store = BindingStore::new();
            refill(&mut store, &[value(1), value(2), value(3)]);
            let allocation = Arc::as_ptr(store.levels[0].buffer.as_ref().unwrap());

            refill(&mut store, &[value(4)]);

            assert_eq!(
                Arc::as_ptr(store.levels[0].buffer.as_ref().unwrap()),
                allocation,
                "unique refill should retain the ProposalBuffer allocation",
            );
            assert_eq!(&store.levels[0].buffer()[..], &[value(4)]);
        }
    }

    mod social {
        use crate::prelude::*;

        attributes! {
            "A19EC1D9DD534BA9896223A457A6B9C9" unsafe as name: inlineencodings::ShortString;
            "C21DE0AA5BA3446AB886C9640BA60244" unsafe as friend: inlineencodings::GenId;
        }
    }

    #[test]
    fn and_set() {
        let mut books = HashSet::<String>::new();
        let mut movies = HashSet::<Inline<ShortString>>::new();

        books.insert("LOTR".to_string());
        books.insert("Dragonrider".to_string());
        books.insert("Highlander".to_string());

        movies.insert("LOTR".to_inline());
        movies.insert("Highlander".to_inline());

        let inter: Vec<_> =
            find!((a: Inline<ShortString>), and!(books.has(a), movies.has(a))).collect();

        assert_eq!(inter.len(), 2);

        let cross: Vec<_> =
            find!((a: Inline<ShortString>, b: Inline<ShortString>), and!(books.has(a), movies.has(b))).collect();

        assert_eq!(cross.len(), 6);

        let one: Vec<_> = find!((a: Inline<ShortString>),
            and!(books.has(a), a.is(ShortString::inline_from("LOTR")))
        )
        .collect();

        assert_eq!(one.len(), 1);
    }

    #[test]
    fn pattern() {
        let mut kb = TribleSet::new();
        (0..1000).for_each(|_| {
            let author = fucid();
            let book = fucid();
            kb += entity! { &author @
               literature::firstname: FirstName(EN).fake::<String>(),
               literature::lastname: LastName(EN).fake::<String>(),
            };
            kb += entity! { &book @
               literature::author: &author,
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::quote: Sentence(5..25).fake::<String>().to_blob().get_handle()
            };
        });

        let author = fucid();
        let book = fucid();
        kb += entity! { &author @
           literature::firstname: "Frank",
           literature::lastname: "Herbert",
        };
        kb += entity! { &book @
           literature::author: &author,
           literature::title: "Dune",
           literature::quote: "I must not fear. Fear is the \
                   mind-killer. Fear is the little-death that brings total \
                   obliteration. I will face my fear. I will permit it to \
                   pass over me and through me. And when it has gone past I \
                   will turn the inner eye to see its path. Where the fear \
                   has gone there will be nothing. Only I will remain.".to_blob().get_handle()
        };

        (0..100).for_each(|_| {
            let author = fucid();
            let book = fucid();
            kb += entity! { &author @
               literature::firstname: "Fake",
               literature::lastname: "Herbert",
            };
            kb += entity! { &book @
               literature::author: &author,
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::quote: Sentence(5..25).fake::<String>().to_blob().get_handle()
            };
        });

        let r: Vec<_> = find!(
        (author: Inline<_>, book: Inline<_>, title: Inline<_>, quote: Inline<_>),
        pattern!(&kb, [
        {?author @
            literature::firstname: "Frank",
            literature::lastname: "Herbert"},
        {?book @
          literature::author: ?author,
          literature::title: ?title,
          literature::quote: ?quote
        }]))
        .collect();

        assert_eq!(1, r.len())
    }

    #[test]
    fn constant() {
        let r: Vec<_> = find! {
            (string: Inline<_>, number: Inline<_>),
            and!(
                string.is(ShortString::inline_from("Hello World!")),
                number.is(I256BE::inline_from(42))
            )
        }
        .collect();

        assert_eq!(1, r.len())
    }

    #[test]
    fn exists_true() {
        assert!(exists!((a: Inline<_>), a.is(I256BE::inline_from(42))));
    }

    #[test]
    fn exists_false() {
        assert!(!exists!(
            (a: Inline<_>),
            and!(a.is(I256BE::inline_from(1)), a.is(I256BE::inline_from(2)))
        ));
    }

    #[test]
    fn exists_no_variables_true() {
        let mut ctx = VariableContext::new();
        let a = ctx.next_variable::<I256BE>();
        assert!(exists!(a.is(I256BE::inline_from(42))));
    }

    #[test]
    fn find_no_variables_yields_unit() {
        let mut ctx = VariableContext::new();
        let a = ctx.next_variable::<I256BE>();
        let rows: Vec<()> = find!((), a.is(I256BE::inline_from(42))).collect();
        assert_eq!(rows, vec![()]);
    }

    #[test]
    fn temp_variables_span_patterns() {
        use social::*;

        let mut kb = TribleSet::new();
        let alice = fucid();
        let bob = fucid();

        kb += entity! { &alice @ name: "Alice", friend: &bob };
        kb += entity! { &bob @ name: "Bob" };

        let matches: Vec<_> = find!(
            (person_name: Inline<_>),
            temp!((mutual_friend),
                and!(
                    pattern!(&kb, [{ _?person @ name: ?person_name, friend: ?mutual_friend }]),
                    pattern!(&kb, [{ ?mutual_friend @ name: "Bob" }])
                )
            )
        )
        .collect();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0.try_from_inline::<&str>().unwrap(), "Alice");
    }

    #[test]
    fn estimate_override_debug_order() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut ctx = VariableContext::new();
        let a = ctx.next_variable::<ShortString>();
        let b = ctx.next_variable::<ShortString>();

        let base = and!(
            a.is(ShortString::inline_from("A")),
            b.is(ShortString::inline_from("B"))
        );

        let mut wrapper = crate::debug::query::EstimateOverrideConstraint::new(base);
        wrapper.set_estimate(a.index, 10);
        wrapper.set_estimate(b.index, 1);

        let record = Rc::new(RefCell::new(Vec::new()));
        let debug = crate::debug::query::DebugConstraint::new(wrapper, Rc::clone(&record));

        let q: Query<_, _, _> = Query::new(debug, |_| Some(()));
        let r: Vec<_> = q.collect();
        assert_eq!(1, r.len());
        assert_eq!(&*record.borrow(), &[b.index, a.index]);
    }

    #[cfg(feature = "parallel")]
    mod split_fence {
        use super::*;
        use rayon::iter::plumbing::UnindexedProducer;
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        use std::sync::atomic::{AtomicU8, Ordering};

        #[derive(Clone)]
        struct Fixture {
            fanout: u32,
            anchors: [u8; 4],
        }

        /// One proposal per level and no alternate continuation anywhere.
        /// This is the shape on which speculative splitting is most harmful:
        /// cloning a query at every depth prevents the frontier matrices from
        /// descending in place even though no parallel work exists.
        #[derive(Clone)]
        struct OneToOne(usize);

        /// Records whether the frontier handed to a constraint carried the
        /// explicit parallel-query intent. Bit 0 is sequential, bit 1 is
        /// parallel.
        #[derive(Clone)]
        struct IntentRecorder(Arc<AtomicU8>);

        impl<'a> Constraint<'a> for IntentRecorder {
            fn variables(&self) -> VariableSet {
                variable_set([0])
            }

            fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
                (variable == 0).then_some(1)
            }

            fn propose(
                &self,
                _variable: VariableId,
                frontier: &Frontier<'_>,
                proposals: &mut ProposalBuffer,
            ) {
                self.0.fetch_or(
                    if frontier.parallel() { 0b10 } else { 0b01 },
                    Ordering::Relaxed,
                );
                for row in 0..frontier.len() {
                    proposals.open(row as u32);
                    proposals.push(Fixture::value(0x55, row as u32));
                }
            }

            fn confirm(
                &self,
                _variable: VariableId,
                _frontier: &Frontier<'_>,
                _candidates: &mut Candidates<'_>,
            ) {
            }
        }

        impl<'a> Constraint<'a> for OneToOne {
            fn variables(&self) -> VariableSet {
                variable_set(0..self.0)
            }

            fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
                (variable < self.0).then_some(if variable == binding.bound.count() {
                    1
                } else {
                    1 << 20
                })
            }

            fn propose(
                &self,
                variable: VariableId,
                frontier: &Frontier<'_>,
                proposals: &mut ProposalBuffer,
            ) {
                for row in 0..frontier.len() {
                    proposals.open(row as u32);
                    proposals.push(Fixture::value(0x7f, variable as u32));
                }
            }

            fn confirm(
                &self,
                _variable: VariableId,
                _frontier: &Frontier<'_>,
                _candidates: &mut Candidates<'_>,
            ) {
            }
        }

        impl Fixture {
            fn identity_split(fanout: u32) -> Self {
                Self {
                    fanout,
                    // Anchor 3 is consumed by the scalar latency page. The
                    // remaining choices are 1, 2, 3, so stable grouping is
                    // already consecutive identity.
                    anchors: [3, 0, 1, 2],
                }
            }

            fn nonidentity_split(fanout: u32) -> Self {
                Self {
                    fanout,
                    // After anchor 3, choices are 2, 1, 3 and stable grouping
                    // must visit rows 1, 0, 2.
                    anchors: [3, 1, 0, 2],
                }
            }

            fn value(tag: u8, index: u32) -> RawInline {
                let mut value = [0; 32];
                value[0] = tag;
                value[28..].copy_from_slice(&index.to_be_bytes());
                value
            }

            fn count(&self, group: u8, variable: VariableId) -> u32 {
                match (group, variable) {
                    (3 | 0, 1) => 0,
                    (1, 2) => self.fanout,
                    _ => 1,
                }
            }
        }

        impl<'a> Constraint<'a> for Fixture {
            fn variables(&self) -> VariableSet {
                variable_set(0..4)
            }

            fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
                let preferred = binding
                    .get(0)
                    .map(|anchor| match anchor[31] {
                        0 => 1,
                        1 => 2,
                        2 => 3,
                        _ => 1,
                    })
                    .unwrap_or(0);
                (variable < 4).then_some(if variable == 0 {
                    4
                } else if variable == preferred {
                    1
                } else {
                    8
                })
            }

            fn propose(
                &self,
                variable: VariableId,
                frontier: &Frontier<'_>,
                proposals: &mut ProposalBuffer,
            ) {
                for row in 0..frontier.len() {
                    proposals.open(row as u32);
                    if variable == 0 {
                        proposals.extend(
                            self.anchors
                                .into_iter()
                                .map(|group| Self::value(0, group as u32)),
                        );
                    } else {
                        let group = frontier.row(row).get(0).expect("anchor bound")[31];
                        proposals.extend(
                            (0..self.count(group, variable))
                                .map(|index| Self::value(variable as u8, index)),
                        );
                    }
                }
            }

            fn confirm(
                &self,
                _variable: VariableId,
                _frontier: &Frontier<'_>,
                _candidates: &mut Candidates<'_>,
            ) {
            }
        }

        type TestQuery = Query<Fixture, fn(&Binding<'_>) -> Option<RawInline>, RawInline>;

        fn project(binding: &Binding<'_>) -> Option<RawInline> {
            binding.get(0).copied()
        }

        fn query(fanout: u32) -> TestQuery {
            fixture_query(Fixture::identity_split(fanout))
        }

        fn nonidentity_query(fanout: u32) -> TestQuery {
            fixture_query(Fixture::nonidentity_split(fanout))
        }

        fn fixture_query(fixture: Fixture) -> TestQuery {
            Query::new(fixture, project as fn(&Binding<'_>) -> Option<RawInline>)
                .with_frontier_width(4)
        }

        #[test]
        fn only_into_par_iter_sets_parallel_frontier_intent() {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .build()
                .unwrap();

            let sequential = Arc::new(AtomicU8::new(0));
            let sequential_rows = pool.install(|| {
                Query::new(IntentRecorder(Arc::clone(&sequential)), |_| Some(())).count()
            });
            assert_eq!(sequential_rows, 1);
            assert_eq!(
                sequential.load(Ordering::Relaxed),
                0b01,
                "an ordinary iterator stays serial even inside a Rayon pool"
            );

            let parallel = Arc::new(AtomicU8::new(0));
            let parallel_rows = pool.install(|| {
                Query::new(IntentRecorder(Arc::clone(&parallel)), |_| Some(()))
                    .into_par_iter()
                    .count()
            });
            assert_eq!(parallel_rows, 1);
            assert_eq!(parallel.load(Ordering::Relaxed), 0b10);
        }

        fn advance_to_three_groups(query: &mut TestQuery) {
            query.plan();
            query.next_group();
            query.next_chunk();

            // Exhaust the empty one-row latency frontier, then widen the
            // root into three anchors with three preferred variables.
            query.plan();
            query.next_group();
            query.next_chunk();
            query.next_group();
            query.next_chunk();
            query.plan();
            assert_eq!(query.depths[query.depth].plan.group_count(), 3);
            assert_eq!(query.depths[query.depth].group, 0);
            assert_eq!(query.depths[query.depth].group_limit, 3);
        }

        fn split_plan(query: &TestQuery) -> &SplitPlan {
            match &query.depths[query.depth].plan {
                DepthPlan::Split(plan) => plan,
                plan => panic!("expected split plan, got {plan:?}"),
            }
        }

        #[test]
        fn universal_plan_stays_generated_without_choice_storage() {
            let mut representation = query(16);
            assert_eq!(representation.choice.capacity(), 0);

            representation.plan();

            assert!(matches!(
                representation.depths[0].plan,
                DepthPlan::Universal(0)
            ));
            assert_eq!(
                representation.depths[0].selection(),
                RowSelection::identity(1)
            );
            assert_eq!(
                representation.choice.capacity(),
                0,
                "unanimity must not allocate planner choice storage"
            );
        }

        #[test]
        fn identity_partition_omits_the_row_order_override() {
            let mut representation = query(16);
            advance_to_three_groups(&mut representation);

            let plan = split_plan(&representation);
            assert_eq!(plan.groups, [(1, 1), (2, 2), (3, 3)]);
            assert!(plan.order_override.is_empty());
            assert_eq!(
                representation.depths[representation.depth].selection(),
                RowSelection::identity(3)
            );
        }

        #[test]
        fn nonidentity_partition_stores_only_the_row_order_override() {
            let mut representation = nonidentity_query(16);
            advance_to_three_groups(&mut representation);

            let plan = split_plan(&representation);
            assert_eq!(plan.groups, [(1, 1), (2, 2), (3, 3)]);
            assert_eq!(plan.order_override, [1, 0, 2]);
            assert_eq!(
                representation.depths[representation.depth].selection(),
                RowSelection::explicit(&[1, 0, 2])
            );

            let mut expected: Vec<_> = query(16).collect();
            let mut actual: Vec<_> = nonidentity_query(16).collect();
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(
                actual, expected,
                "row permutation must preserve the exact bag"
            );
        }

        #[test]
        fn split_transfers_one_whole_group_and_fences_it() {
            const FANOUT: u32 = 64;
            let mut expected: Vec<_> = query(FANOUT).collect();
            expected.sort_unstable();
            assert_eq!(expected.len(), FANOUT as usize + 1);

            let mut left = query(FANOUT);
            advance_to_three_groups(&mut left);
            let source_len = left.bindings.levels[0].buffer().len();
            let source_pos = left.bindings.levels[0].pos;
            let right = left.split_pending_group().expect("transfer first group");

            assert_eq!(
                (right.depth, right.depths.len(), right.stack.len()),
                (0, 1, 0)
            );
            assert_eq!(
                (
                    right.depths[0].group,
                    right.depths[0].group_limit,
                    right.depths[0].plan.group_count(),
                ),
                (0, 1, 3)
            );
            assert!(Arc::ptr_eq(&left.depths[1].block, &right.depths[0].block));
            assert_eq!(left.depths[1].selection(), right.depths[0].selection());
            match (&left.depths[1].plan, &right.depths[0].plan) {
                (DepthPlan::Split(left), DepthPlan::Split(right)) => {
                    assert!(Arc::ptr_eq(left, right), "fencing must not clone the plan");
                }
                plans => panic!("expected shared split plans, got {plans:?}"),
            }
            assert_eq!(left.depths[1].group, 1, "left skips the owned group");

            // The ancestor source was cloned intact, not bisected. Both
            // halves retain the same complete proposal region and cursor;
            // only their continuation ownership differs.
            assert_eq!(left.bindings.levels[0].buffer().len(), source_len);
            assert_eq!(right.bindings.levels[0].buffer().len(), source_len);
            assert_eq!(left.bindings.levels[0].pos, source_pos);
            assert_eq!(right.bindings.levels[0].pos, source_pos);

            // A fenced sole root group is indivisible. Trying to split it
            // again must enter the work rather than hand the same group back.
            let mut fenced = right.clone();
            assert!(fenced.split_pending_group().is_none());

            let second = left.split_pending_group().expect("transfer second group");
            assert!(
                left.split_pending_group().is_none(),
                "the last group stays with the only producer that can execute it"
            );
            assert_eq!(left.depths[1].group + 1, left.depths[1].group_limit);

            let mut actual: Vec<_> = left.chain(right).chain(second).collect();
            actual.sort_unstable();
            assert_eq!(actual, expected, "splitting must preserve the exact bag");
            assert_eq!(actual.iter().filter(|row| row[31] == 2).count(), 1);
        }

        fn advance_to_emit(query: &mut TestQuery) {
            loop {
                match query.mode {
                    Search::Plan => query.plan(),
                    Search::NextGroup => query.next_group(),
                    Search::NextChunk => query.next_chunk(),
                    Search::Emit => return,
                    Search::Done => panic!("fixture ended before a terminal frontier"),
                }
            }
        }

        #[test]
        fn terminal_page_is_transferred_without_slicing_rows() {
            let mut left = query(32);
            advance_to_emit(&mut left);
            assert!(left.depth > 0);
            let terminal_rows = left.depths[left.depth].rows;
            let terminal_block = Arc::clone(&left.depths[left.depth].block);
            let terminal_plan = left.depths[left.depth].plan.clone();
            let mut expected = left.clone().collect::<Vec<_>>();

            let right = left
                .split_terminal_frontier()
                .expect("terminal page has a parent continuation");
            assert_eq!(right.depth, 0);
            assert_eq!(right.stack.len(), 0);
            assert_eq!(right.mode, Search::Emit);
            assert_eq!(right.depths[0].rows, terminal_rows);
            assert!(Arc::ptr_eq(&terminal_block, &right.depths[0].block));
            assert_eq!(
                terminal_plan.selection(terminal_rows),
                right.depths[0].selection()
            );
            for variable in left.bindings.bound {
                assert!(Arc::ptr_eq(
                    left.bindings.levels[variable]
                        .buffer
                        .as_ref()
                        .expect("bound level has a published buffer"),
                    right.bindings.levels[variable]
                        .buffer
                        .as_ref()
                        .expect("bound level has a published buffer"),
                ));
            }

            let mut actual: Vec<_> = left.chain(right).collect();
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(actual, expected);
        }

        #[test]
        fn indivisible_one_to_one_chain_never_splits_or_forces_copies() {
            const HOPS: usize = 60;
            let query = Query::new(OneToOne(HOPS), |binding: &Binding| {
                binding.get(HOPS - 1).copied()
            });
            let stats = query.stats();

            // `UnindexedProducer::split` is allowed to drive the state
            // machine looking for a stealable unit. This chain has none:
            // every frontier is one sole group/page and every ancestor is
            // already spent. It must therefore stay one producer all the
            // way down rather than manufacture an empty left sibling at
            // each depth.
            let (producer, right) = query.into_par_iter().split();
            assert!(right.is_none());
            let rows = producer.collect::<Vec<_>>();

            assert_eq!(rows, vec![Fixture::value(0x7f, HOPS as u32 - 1)]);
            assert_eq!(stats.inplace_descents(), HOPS as u64);
            assert_eq!(
                stats.copied_descents(),
                0,
                "a fruitless split search must not destroy Arc uniqueness"
            );
        }

        #[test]
        fn repeated_manual_producer_splits_preserve_explicit_order_and_bag() {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .build()
                .unwrap();

            for fixture in [query as fn(u32) -> TestQuery, nonidentity_query] {
                let mut expected: Vec<_> = fixture(96).collect();
                expected.sort_unstable();

                let mut queue = vec![fixture(96).into_par_iter()];
                let mut leaves = Vec::new();
                for _ in 0..64 {
                    let Some(producer) = queue.pop() else {
                        break;
                    };
                    let (left, right) = producer.split();
                    if let Some(right) = right {
                        queue.push(left);
                        queue.push(right);
                    } else {
                        leaves.push(left);
                    }
                }

                let mut actual = Vec::new();
                for producer in queue.into_iter().chain(leaves) {
                    actual.extend(producer.collect::<Vec<_>>());
                }
                actual.sort_unstable();
                assert_eq!(actual, expected);

                for _ in 0..8 {
                    let mut scheduled =
                        pool.install(|| fixture(96).into_par_iter().collect::<Vec<_>>());
                    scheduled.sort_unstable();
                    assert_eq!(scheduled, expected);
                }
            }
        }
    }
}
