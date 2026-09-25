//! Test-only oracles over the lattice-v2 model.
//!
//! A collection's support is a cover of its OWN foundations, and production
//! code never compares two collections' supports. Tests written against the
//! earlier model asserted that a view "stands for" a set of root commits;
//! [`stood_for`] answers that question the only way the model allows, by
//! following each root foundation up the view's descriptor chain through the
//! leaves (`DERIVE` records) of every hop, by locator.

use std::collections::BTreeSet;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::inline::Inline;
use crate::repo::StoreRead;
use crate::trible::TribleSet;

use super::{
    descriptor, Collection, CollectionEncoding, CollectionSnapshot, SourceLocator, Support,
};

/// The root commits `view` stands for: every admitted foundation `F` of the
/// root beneath it that reaches one of `view`'s own support members through a
/// chain of leaves, one per hop.
pub(crate) fn stood_for<R, E>(view: &CollectionSnapshot<R, E>) -> Support<SimpleArchive>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let snapshot = view.snapshot();
    let mut chain = vec![view.cover().collection().handle()];
    loop {
        let last = *chain.last().expect("the chain starts at the view");
        let facts: TribleSet = snapshot.get(last).expect("a descriptor in the chain");
        match descriptor::source(&facts).expect("a decodable source") {
            Some(source) => chain.push(source),
            None => break,
        }
    }
    let root = *chain.last().expect("the chain ends at a root");
    let scope: BTreeSet<_> = chain.iter().copied().collect();
    let coverage = snapshot.coverage(&scope).expect("coverage of the chain");
    let top: BTreeSet<[u8; 32]> = view
        .support()
        .expect("view support")
        .data_members()
        .map(|member| member.raw)
        .collect();
    let (foundations, _) = coverage.frontier_support(root);
    let mut stood = Vec::new();
    for raw in foundations.iter_ordered() {
        let mut images = BTreeSet::from([*raw]);
        for hop in chain.iter().rev().skip(1) {
            images = images
                .iter()
                .flat_map(|image| coverage.leaf_outputs(*hop, SourceLocator::of(*image)))
                .map(|output| output.raw)
                .collect();
        }
        if images.iter().any(|image| top.contains(image)) {
            stood.push(Inline::new(*raw));
        }
    }
    Support::from_data(Collection::from_handle(root), stood)
}
