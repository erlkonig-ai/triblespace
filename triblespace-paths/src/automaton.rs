use std::error::Error;
use std::fmt;

use triblespace_core::id::RawId;
use triblespace_core::patch::{Entry, PATCH};

/// Dense state number in a fixed automaton.
pub type StateId = u32;

/// One epsilon-free property-path step.
///
/// Empty exclusion lists are wildcards. Exclusion lists are sorted and
/// deduplicated by [`Automaton::new`].
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Step {
    /// Follow an edge with exactly this attribute.
    Forward(RawId),
    /// Follow an edge with exactly this attribute in reverse.
    Reverse(RawId),
    /// Follow any forward edge except the listed attributes.
    ForwardExcept(Vec<RawId>),
    /// Follow any reverse edge except the listed attributes.
    ReverseExcept(Vec<RawId>),
}

impl Step {
    /// Matches every forward edge.
    pub fn forward_any() -> Self {
        Self::ForwardExcept(Vec::new())
    }

    /// Matches every reverse edge.
    pub fn reverse_any() -> Self {
        Self::ReverseExcept(Vec::new())
    }

    fn canonicalize(&mut self) {
        let excluded = match self {
            Self::ForwardExcept(excluded) | Self::ReverseExcept(excluded) => excluded,
            Self::Forward(_) | Self::Reverse(_) => return,
        };
        excluded.sort_unstable();
        excluded.dedup();
    }

    pub(crate) fn matches(&self, attribute: &RawId) -> bool {
        match self {
            Self::Forward(expected) | Self::Reverse(expected) => expected == attribute,
            Self::ForwardExcept(excluded) | Self::ReverseExcept(excluded) => {
                excluded.binary_search(attribute).is_err()
            }
        }
    }

    pub(crate) fn is_reverse(&self) -> bool {
        matches!(self, Self::Reverse(_) | Self::ReverseExcept(_))
    }
}

/// A labeled transition between two automaton states.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transition {
    /// Source state.
    pub from: StateId,
    /// Destination state.
    pub to: StateId,
    /// Graph step consumed by the transition.
    pub step: Step,
}

impl Transition {
    /// Creates one transition.
    pub fn new(from: StateId, to: StateId, step: Step) -> Self {
        Self { from, to, step }
    }
}

/// A canonical fixed, epsilon-free nondeterministic automaton.
///
/// Epsilon behavior belongs in the compiler: nullable expressions accept an
/// initial state, and epsilon transitions are eliminated before construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Automaton {
    state_count: StateId,
    // Big-endian state numbers preserve canonical numeric order in PATCH.
    initial: PATCH<4>,
    accepting: PATCH<4>,
    transitions: Vec<Transition>,
}

/// Invalid fixed-automaton description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomatonError {
    /// An automaton needs at least one state.
    NoStates,
    /// An automaton needs at least one initial state.
    NoInitialState,
    /// A referenced state lies outside `0..state_count`.
    StateOutOfRange {
        /// Invalid state.
        state: StateId,
        /// Exclusive state bound.
        state_count: StateId,
    },
}

impl fmt::Display for AutomatonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoStates => write!(f, "an automaton needs at least one state"),
            Self::NoInitialState => write!(f, "an automaton needs an initial state"),
            Self::StateOutOfRange { state, state_count } => {
                write!(f, "automaton state {state} is outside 0..{state_count}")
            }
        }
    }
}

impl Error for AutomatonError {}

impl Automaton {
    /// Validates and canonicalizes a fixed automaton.
    pub fn new(
        state_count: StateId,
        initial: impl IntoIterator<Item = StateId>,
        accepting: impl IntoIterator<Item = StateId>,
        transitions: impl IntoIterator<Item = Transition>,
    ) -> Result<Self, AutomatonError> {
        if state_count == 0 {
            return Err(AutomatonError::NoStates);
        }

        let mut initial_set = PATCH::new();
        for state in initial {
            initial_set.insert(&Entry::new(&state.to_be_bytes()));
        }
        if initial_set.is_empty() {
            return Err(AutomatonError::NoInitialState);
        }
        let mut accepting_set = PATCH::new();
        for state in accepting {
            accepting_set.insert(&Entry::new(&state.to_be_bytes()));
        }
        let mut transitions = transitions.into_iter().collect::<Vec<_>>();

        for state in initial_set
            .iter_ordered()
            .chain(accepting_set.iter_ordered())
            .map(|state| StateId::from_be_bytes(*state))
            .chain(
                transitions
                    .iter()
                    .flat_map(|transition| [transition.from, transition.to]),
            )
        {
            if state >= state_count {
                return Err(AutomatonError::StateOutOfRange { state, state_count });
            }
        }

        for transition in &mut transitions {
            transition.step.canonicalize();
        }
        transitions.sort_unstable();
        transitions.dedup();

        Ok(Self {
            state_count,
            initial: initial_set,
            accepting: accepting_set,
            transitions,
        })
    }

    /// Number of states, exactly `0..state_count`.
    pub fn state_count(&self) -> StateId {
        self.state_count
    }

    /// Canonically ordered initial states.
    pub fn initial_states(&self) -> impl Iterator<Item = StateId> + '_ {
        self.initial
            .iter_ordered()
            .map(|state| StateId::from_be_bytes(*state))
    }

    /// Canonically ordered accepting states.
    pub fn accepting_states(&self) -> impl Iterator<Item = StateId> + '_ {
        self.accepting
            .iter_ordered()
            .map(|state| StateId::from_be_bytes(*state))
    }

    /// Whether the automaton accepts the empty path.
    ///
    /// The automaton is epsilon-free, so this is exactly the overlap between
    /// its initial and accepting state sets.
    pub fn accepts_empty(&self) -> bool {
        self.initial
            .iter()
            .any(|state| self.accepting.has_prefix(state))
    }

    /// Whether `state` accepts a completed path.
    pub fn is_accepting(&self, state: StateId) -> bool {
        self.accepting.has_prefix(&state.to_be_bytes())
    }

    /// Canonically ordered, duplicate-free transitions.
    pub fn transitions(&self) -> &[Transition] {
        &self.transitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_sets_keep_numeric_order_and_snapshot_independence() {
        let automaton =
            Automaton::new(65_537, [65_536, 256, 1, 256], [256, 65_536, 256], []).unwrap();
        assert_eq!(
            automaton.initial_states().collect::<Vec<_>>(),
            [1, 256, 65_536]
        );
        assert_eq!(
            automaton.accepting_states().collect::<Vec<_>>(),
            [256, 65_536]
        );
        assert!(automaton.accepts_empty());
        assert!(!automaton.is_accepting(1));
        assert_eq!(
            automaton,
            Automaton::new(65_537, [1, 256, 65_536], [65_536, 256], []).unwrap()
        );

        let mut changed = automaton.clone();
        changed.initial.remove(&256_u32.to_be_bytes());
        changed.accepting.remove(&256_u32.to_be_bytes());
        assert!(automaton.is_accepting(256));
        assert!(!changed.is_accepting(256));
        assert_eq!(automaton.initial_states().count(), 3);
        assert_eq!(changed.initial_states().count(), 2);
        assert_ne!(changed, automaton);
    }

    #[test]
    fn invalid_state_selection_remains_canonical() {
        assert_eq!(
            Automaton::new(2, [65_536, 256, 1], [2], []),
            Err(AutomatonError::StateOutOfRange {
                state: 256,
                state_count: 2,
            })
        );
        assert_eq!(
            Automaton::new(2, [1], [65_536, 256], []),
            Err(AutomatonError::StateOutOfRange {
                state: 256,
                state_count: 2,
            })
        );
    }
}
