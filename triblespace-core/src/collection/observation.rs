//! Target-first, passive collection attachment.
//!
//! A read is a lookup in the coverage index: the target's frontier, one
//! support per node, their union. Records are never enumerated.

use std::collections::BTreeSet;

use crate::repo::StoreRead;

use super::observed_store::ObservedStore;
use super::store::CoverageRead;
use super::{
    AttachedSnapshot, Collection, CollectionEncoding, CollectionRealizationError,
    CollectionSnapshot, Cover, Support,
};

/// Attach what the target stands on.
///
/// The coverage index says which nodes of the target are its frontier and
/// what each stands for. The read is the same selection maintenance makes:
/// the frontier, widest node first, taking a node whose bytes are here and
/// complete, descending through the host's driven joins that produced a
/// node whose bytes are not, read from the index by the node's own key. No
/// record is selected or enumerated and no support is re-derived; a target
/// the fold has nothing for stands for nothing, honestly, until its records
/// are admitted.
///
/// Coverage is collection-local: no attestation of the target reads another
/// collection's rows, so the read-set charged is the target's own coverage
/// and its own admission evidence, and nothing beneath it. The support is a
/// cover of the target's own foundations, taken from the same selection.
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
    if !super::descriptor::parents(loaded.fragment.facts())
        .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?
        .is_empty()
    {
        return Err(CollectionRealizationError::InvalidCover(format!(
            "collection {} is an attached collection; read it through `attached`",
            hex::encode_upper(handle.raw),
        )));
    }
    let charged = BTreeSet::from([handle]);
    let coverage = observed
        .coverage(&charged)
        .map_err(|error| CollectionRealizationError::storage("read coverage", error))?;
    // The rows read above were decided from admission evidence: the
    // target's descriptor, its policy definitions, and the proofs. A read
    // depends on those the way it depends on the records, so they are read
    // once more through the tracked store, which is what makes a later
    // definition or proof arrival move the observation off current.
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
        handle,
    )
    .map_err(|error| CollectionRealizationError::storage("read WRITE evidence", error))?;
    let selection = super::maintenance::select(&observed, &coverage, target)?;
    let support = Support::from_patch(target, selection.covered.clone());
    let cover = Cover::from_data(target, selection.nodes());
    Ok(CollectionSnapshot::from_frontier(
        observed.inner().clone(),
        support,
        cover,
        observed.tracker(),
    ))
}

/// Attach what an attached collection holds for its parent: the attached
/// cover, from one observation.
///
/// The read-set charged is the attached collection's records (its MAPs) and
/// the parent's (its lattice), the parent's admission evidence, which
/// decides which of its foundations are believed, and the residency of
/// every attachment and dependency the selection looked at.
pub(super) fn attach_attached<R, E>(
    snapshot: &R,
    attached: Collection<E>,
) -> Result<AttachedSnapshot<R, E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let observed = ObservedStore::new(snapshot.clone());
    let (parent, _, parent_descriptor) = super::maintenance::attached_lineage(&observed, attached)
        .map_err(|error| match error {
            CollectionRealizationError::MissingDependency { member } => {
                CollectionRealizationError::Resolution(format!(
                    "attached lineage descriptor {} is not resident",
                    hex::encode_upper(member.raw),
                ))
            }
            other => other,
        })?;
    let charged = BTreeSet::from([attached.handle(), parent.handle()]);
    let coverage = observed
        .coverage(&charged)
        .map_err(|error| CollectionRealizationError::storage("read coverage", error))?;
    let (policies, _) = super::descriptor::admission_policies_with_missing(
        &observed,
        parent_descriptor.facts(),
        super::ACTION_WRITE,
        None,
    );
    super::api::discover_admission_evidence(
        &observed,
        policies.into_iter(),
        super::ACTION_WRITE,
        parent.handle(),
    )
    .map_err(|error| CollectionRealizationError::storage("read parent WRITE evidence", error))?;
    let selection =
        super::maintenance::select_attached(&observed, &coverage, parent.handle(), attached)?;
    // A reader may read the residual from its own bytes, so their arrival is
    // a change this observation depends on.
    for key in selection.residual.iter_ordered() {
        crate::repo::BlobStoreMeta::metadata(
            &observed,
            crate::inline::Inline::<
                crate::inline::encodings::hash::Handle<
                    crate::blob::encodings::simplearchive::SimpleArchive,
                >,
            >::new(*key),
        )
        .map_err(|error| CollectionRealizationError::storage("read residual residency", error))?;
    }
    let cover = Cover::from_data(
        attached,
        selection.cover.iter().map(|(_, attachment)| *attachment),
    );
    Ok(AttachedSnapshot::new(
        observed.inner().clone(),
        cover,
        Support::from_patch(parent, selection.covered),
        Support::from_patch(parent, selection.residual),
        observed.tracker(),
    ))
}

#[cfg(test)]
mod tests;
