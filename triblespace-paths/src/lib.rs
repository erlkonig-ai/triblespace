//! Exact regular-path relations kept outside the core query solver.
//!
//! A [`PathSummary`] is the unionable, constructional form: a canonical fixed
//! automaton, the graph-term domain it requires, and the direct arcs of their
//! product. Nullable automata retain the complete supplied endpoint universe;
//! non-nullable automata need only matched-edge support. A [`PathIndex`]
//! materializes one snapshot with a single algorithm:
//! SCC condensation followed by reverse-topological bitset propagation. No
//! product transitive closure survives materialization: the index retains the
//! constructional summary and the accepted endpoint relation.

mod automaton;
mod constraint;
mod expr;
mod index;
#[cfg(test)]
mod path_collection;
pub mod path_summary_union;
mod persistence;
mod summary;

pub use automaton::{Automaton, AutomatonError, StateId, Step, Transition};
pub use constraint::PathConstraint;
pub use expr::PathExpr;
pub use index::PathIndex;
pub use path_summary_union::{
    regular_path, PathIndexViewError, PathSummaryView, RegularPathMappingError,
    RegularPathMappingV1, REGULAR_PATH_MAPPING_V1,
};
pub use persistence::{
    automaton_fingerprint, path_automaton_accepting_state, path_automaton_fingerprint,
    path_automaton_initial_state, path_automaton_state_count, path_automaton_transition,
    path_transition_from, path_transition_kind, path_transition_label, path_transition_to,
    PathAutomatonBlob, PathAutomatonBlobError, PathSummaryBlob, PathSummaryBlobError,
};
pub use summary::{GraphEdge, PathError, PathSummary};

/// The shared text grammar for path expressions and its parser.
pub mod syntax;

#[cfg(any(kani, test))]
#[path = "../proofs/mod.rs"]
mod proofs;
