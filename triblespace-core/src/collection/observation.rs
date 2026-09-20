//! Target-first, passive collection attachment.
//!
//! A read is a lookup in the coverage index: the target's frontier, one
//! support per node, their union. Records are never enumerated.

use std::collections::BTreeSet;

use crate::repo::StoreRead;

use super::observed_store::ObservedStore;
use super::store::CoverageRead;
use super::{
    Collection, CollectionEncoding, CollectionRealizationError, CollectionSnapshot, Cover,
    Support,
};

/// Attach what the target stands on.
///
/// The coverage index says which nodes of the target are its frontier and
/// what each stands for. The read is the same selection maintenance makes:
/// the frontier, widest node first, taking a node whose bytes are here and
/// complete, descending through the MERGE that produced a node whose bytes
/// are not, with one produced-member lookup. No record is enumerated and no
/// support is re-derived; a target the fold has nothing for stands for
/// nothing, honestly, until its records are admitted.
///
/// The read-set charged to the observation is the target's own coverage:
/// its frontier moves only on its own records, so that is the honest
/// dependency of this cover. The one exception is a target record that
/// arrived ahead of its input; while the target holds one, a record landing
/// anywhere in the lineage can drive it, and the whole lineage is charged.
/// The support's lineage is charged when the support is asked for.
pub(super) fn attach<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<CollectionSnapshot<R, E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let observed = ObservedStore::new(snapshot.clone());
    let loaded = super::api::load_collection_descriptor(&observed, target.handle())
        .map_err(|error| CollectionRealizationError::storage("read target descriptor", error))?;
    super::encoding::validate_descriptor_type::<E>(&loaded.fragment)
        .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
    let handle = target.handle();
    // The lineage probe and the settle run on the untracked reader: the
    // descriptors beneath the target are not what this cover depends on.
    let lineage = super::exact_derived::load_record_lineage(observed.inner(), handle)?;
    let handles = lineage.handles();
    let settled = observed
        .inner()
        .coverage(&handles)
        .map_err(|error| CollectionRealizationError::storage("settle downward coverage", error))?;
    let charged = if settled.has_blocked(handle) {
        handles.clone()
    } else {
        BTreeSet::from([handle])
    };
    let coverage = observed
        .coverage(&charged)
        .map_err(|error| CollectionRealizationError::storage("read downward coverage", error))?;
    // The rows read above were decided from admission evidence: each charged
    // collection's descriptor, its policy definitions, and the proofs. A read
    // depends on those the way it depends on the records, so they are read
    // once more through the tracked store, which is what makes a later
    // definition or proof arrival move the observation off current.
    for collection in &charged {
        let loaded = super::api::load_collection_descriptor(&observed, *collection)
            .map_err(|error| CollectionRealizationError::storage("read lineage descriptor", error))?;
        let (policies, _) = super::descriptor::admission_policies_with_missing(
            &observed,
            loaded.fragment.facts(),
            super::ACTION_WRITE,
            None,
        );
        super::api::discover_admission_evidence(
            &observed,
            policies.into_iter(),
            super::ACTION_WRITE,
            *collection,
        )
        .map_err(|error| CollectionRealizationError::storage("read WRITE evidence", error))?;
    }
    let selection = super::maintenance::select(&observed, &coverage, target, &|_| true)?;
    let support = Support::from_patch(lineage.foundation, selection.covered.clone());
    let cover = Cover::from_data(target, selection.nodes());
    Ok(CollectionSnapshot::from_frontier(
        observed.inner().clone(),
        support,
        cover,
        handles,
        observed.tracker(),
    ))
}

#[cfg(test)]
mod tests;
