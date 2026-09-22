//! Local scheduling policy for collection-scoped repair.
//!
//! Collection authority is carried by each repair request. Immutable bytes
//! remain on the independent bearer-addressed demand path.

/// Local direction policy for collection repair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReconcileDirection {
    /// Pull explicitly active collections and serve them to admitted readers.
    #[default]
    Bidirectional,
    /// Pull active collections without serving local collection state or data.
    ReadOnly,
    /// Serve active collection state and resident exact data without initiating repair.
    WriteOnly,
}

impl ReconcileDirection {
    /// Whether the local scheduler initiates collection-repair pulls.
    pub const fn pulls(self) -> bool {
        !matches!(self, Self::WriteOnly)
    }

    /// Whether inbound admitted readers may receive collection state.
    ///
    /// Exact H-authorized bearer transport is orthogonal to this policy.
    pub const fn serves(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// Local-only collection repair policy.
///
/// This value is never sent as authority and cannot widen a collection's READ
/// policy or disclosure boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileQos {
    /// Whether this peer pulls, serves, or does both.
    pub direction: ReconcileDirection,
}
