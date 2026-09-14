//! Construction conveniences for a collection's generic resource policies.
//!
//! Ordinary admission reads the descriptor's binding relation directly. This
//! value is only a producer (or explicit scalar diagnostic), never a catalog
//! loaded to decide which facts are visible.

use crate::blob::{encodings::simplearchive::SimpleArchive, IntoBlob};
use crate::capability::capability_action;
use crate::prelude::entity;
use crate::trible::Fragment;

pub use crate::capability::policy::{
    AdmissionPolicy, AdmissionPolicyError, ValidatedQuorum, KIND_ADMISSION_POLICY_OPEN,
    KIND_ADMISSION_POLICY_QUORUM,
};

use super::{ACTION_READ, ACTION_WRITE};

pub(super) fn read_definition() -> Fragment {
    entity! { capability_action: ACTION_READ }
}

pub(super) fn write_definition() -> Fragment {
    entity! { capability_action: ACTION_WRITE }
}

/// A descriptor producer with READ/WRITE conveniences and generic bindings.
///
/// The descriptor stores only the binding relation returned by `fragment`.
/// The two policy fields preserve the convenient construction/inspection API;
/// runtime admission queries all supported bindings instead of this value.
#[derive(Clone, Debug)]
pub struct CollectionPolicy {
    read: AdmissionPolicy,
    write: AdmissionPolicy,
    bindings: Fragment,
}

impl PartialEq for CollectionPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.read == other.read
            && self.write == other.write
            && self.bindings.facts() == other.bindings.facts()
    }
}

impl Eq for CollectionPolicy {}

impl CollectionPolicy {
    /// State the two standard capability policies explicitly.
    pub fn new(read: AdmissionPolicy, write: AdmissionPolicy) -> Self {
        let bindings =
            bind_definition(read_definition(), &read) + bind_definition(write_definition(), &write);
        Self {
            read,
            write,
            bindings,
        }
    }

    /// Add one custom capability definition and its descriptor-local policy.
    ///
    /// The definition's facts are archived independently. Its invocation actions
    /// select this policy's roots and quorum; grant definitions may separately
    /// permit delegation. A resource, issuer, and recipient belong to the proof,
    /// not to the reusable definition.
    /// The complete supplied attachment store travels with the new binding.
    /// Repeating an identical definition/policy pair is idempotent.
    pub fn with_capability(mut self, definition: Fragment, policy: AdmissionPolicy) -> Self {
        self.bindings += bind_definition(definition, &policy);
        self
    }

    /// The complete generic binding fragment, ready for `resource_policy*:`.
    pub fn fragment(&self) -> Fragment {
        self.bindings.clone()
    }

    /// READ policy supplied to this constructor or scalar diagnostic.
    pub const fn read(&self) -> &AdmissionPolicy {
        &self.read
    }

    /// WRITE policy supplied to this constructor or scalar diagnostic.
    pub const fn write(&self) -> &AdmissionPolicy {
        &self.write
    }

    pub(crate) fn from_bindings(
        read: AdmissionPolicy,
        write: AdmissionPolicy,
        mut bindings: Fragment,
    ) -> Self {
        // The two standard definitions are known by construction. Custom
        // handles and every raw binding fact remain exactly as observed; this
        // diagnostic does not acquire an arbitrary definition closure.
        bindings.put::<SimpleArchive, _>(read_definition().facts().clone());
        bindings.put::<SimpleArchive, _>(write_definition().facts().clone());
        Self {
            read,
            write,
            bindings,
        }
    }
}

fn bind_definition(definition: Fragment, policy: &AdmissionPolicy) -> Fragment {
    let (_, facts, metafacts, blobs) = definition.into_parts();
    let blob = IntoBlob::<SimpleArchive>::to_blob(facts);
    let mut binding = policy.binding(blob.get_handle());
    *binding.metafacts_mut() += metafacts;
    binding.blobs_mut().union(blobs);
    binding.put::<SimpleArchive, _>(blob);
    binding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::policy::{capability_handle, resource_policy};
    use crate::collection::{descriptor, read_capability, write_capability};
    use crate::metadata;
    use crate::prelude::{find, pattern};
    use crate::repo::{BlobStoreGet, SnapshotSource};

    #[test]
    fn generic_binding_construction_is_idempotent_and_preserves_definition_blobs() {
        let definition = entity! { metadata::name: "custom key delivery" };
        let handle = IntoBlob::<SimpleArchive>::to_blob(definition.facts().clone()).get_handle();
        let once = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open)
            .with_capability(definition.clone(), AdmissionPolicy::Open);
        let twice = once
            .clone()
            .with_capability(definition, AdmissionPolicy::Open);
        assert_eq!(once, twice);
        let fragment = descriptor::naming::<SimpleArchive>("capabilities", once);
        let handles: std::collections::BTreeSet<_> = find!(
            handle: crate::capability::CapabilityHandle,
            pattern!(fragment.facts(), [
                { _?descriptor @ resource_policy: _?binding },
                { _?binding @ capability_handle: ?handle },
            ])
        )
        .collect();
        assert_eq!(
            handles,
            [read_capability(), write_capability(), handle].into()
        );
        let blobs = fragment.blobs().clone().snapshot().unwrap();
        for handle in handles {
            assert!(blobs
                .get::<crate::blob::Blob<SimpleArchive>, _>(handle)
                .is_ok());
        }
    }
}
