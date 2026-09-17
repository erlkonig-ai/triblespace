//! Typed collection sets. Every observable member is part of its PATCH key.

use std::fmt;

use crate::inline::Inline;
use crate::patch::{Entry, IdentitySchema, PATCHIntoOrderedIterator, PATCHOrderedIterator, PATCH};

use super::super::{CollectionCommit, CollectionData, CollectionRecord};

/// An immutable-value set of collection payload identities.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CollectionDataSet(pub(super) PATCH<32>);

impl CollectionDataSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of distinct payload identities.
    pub fn len(&self) -> usize {
        self.0.len() as usize
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Whether one payload belongs to the set.
    pub fn contains(&self, member: &CollectionData) -> bool {
        self.0.get(&member.raw).is_some()
    }
    /// Insert one payload, returning whether it was new.
    pub fn insert(&mut self, member: CollectionData) -> bool {
        let before = self.0.len();
        self.0.insert(&Entry::new(&member.raw));
        self.0.len() != before
    }
    /// Remove one payload, returning whether it was present.
    pub fn remove(&mut self, member: &CollectionData) -> bool {
        let before = self.0.len();
        self.0.remove(&member.raw);
        self.0.len() != before
    }
    /// Clear the set without changing prior clones.
    pub fn clear(&mut self) {
        self.0 = PATCH::new();
    }
    /// Payloads in ascending canonical byte order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = CollectionData> + '_ {
        self.0.iter_ordered().copied().map(Inline::new)
    }
    /// The common payloads of two sets, in canonical order.
    pub fn intersection<'a>(
        &'a self,
        other: &'a Self,
    ) -> impl Iterator<Item = CollectionData> + 'a {
        self.iter().filter(move |member| other.contains(member))
    }
    /// Whether every payload is also in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.difference(&other.0).is_empty()
    }
    /// Return the union, preserving structural sharing with both inputs.
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.0.union(other.0.clone());
        result
    }
}

impl fmt::Debug for CollectionDataSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}
impl Extend<CollectionData> for CollectionDataSet {
    fn extend<T: IntoIterator<Item = CollectionData>>(&mut self, members: T) {
        for member in members {
            self.insert(member);
        }
    }
}
impl FromIterator<CollectionData> for CollectionDataSet {
    fn from_iter<T: IntoIterator<Item = CollectionData>>(members: T) -> Self {
        let mut result = Self::new();
        result.extend(members);
        result
    }
}
impl<const N: usize> From<[CollectionData; N]> for CollectionDataSet {
    fn from(members: [CollectionData; N]) -> Self {
        members.into_iter().collect()
    }
}
impl<'a> IntoIterator for &'a CollectionDataSet {
    type Item = CollectionData;
    type IntoIter = std::iter::Map<
        std::iter::Copied<PATCHOrderedIterator<'a, 32, IdentitySchema, ()>>,
        fn([u8; 32]) -> CollectionData,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_ordered().copied().map(Inline::new)
    }
}
impl IntoIterator for CollectionDataSet {
    type Item = CollectionData;
    type IntoIter = std::iter::Map<
        PATCHIntoOrderedIterator<32, IdentitySchema, ()>,
        fn([u8; 32]) -> CollectionData,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter_ordered().map(Inline::new)
    }
}

// Record keys preserve Rust's canonical record ordering, including every
// signature and witness. Attached typed values are completely named by the key.
fn record_key(record: &CollectionRecord) -> [u8; 289] {
    let bytes = record.to_bytes();
    let mut key = [0; 289];
    key[..bytes.len()].copy_from_slice(&bytes);
    key
}

/// Canonically ordered exact collection records.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CollectionRecordSet(PATCH<289, IdentitySchema, CollectionRecord>);
impl CollectionRecordSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of exact records.
    pub fn len(&self) -> usize {
        self.0.len() as usize
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Whether this exact record is present.
    pub fn contains(&self, record: &CollectionRecord) -> bool {
        self.0.get(&record_key(record)).is_some()
    }
    /// Exact records in canonical value order, not fingerprint order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CollectionRecord> {
        self.0
            .iter_ordered()
            .map(|key| self.0.get(key).expect("record key retains its exact value"))
    }
    pub(super) fn insert(&mut self, record: CollectionRecord) {
        self.0
            .insert(&Entry::with_value(&record_key(&record), record));
    }
}
impl FromIterator<CollectionRecord> for CollectionRecordSet {
    fn from_iter<T: IntoIterator<Item = CollectionRecord>>(records: T) -> Self {
        let mut result = Self::new();
        for record in records {
            result.insert(record);
        }
        result
    }
}
impl fmt::Debug for CollectionRecordSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// Canonically ordered exact supporting commits, including provenance.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct CollectionCommitSet(pub(super) PATCH<192, IdentitySchema, CollectionCommit>);
impl CollectionCommitSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Whether this exact commit is present.
    pub fn contains(&self, commit: &CollectionCommit) -> bool {
        self.0.get(&commit.to_bytes()).is_some()
    }
    /// Number of exact supporting commits.
    pub fn len(&self) -> usize {
        self.0.len() as usize
    }
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Exact commits in canonical value order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CollectionCommit> {
        self.0
            .iter_ordered()
            .map(|key| self.0.get(key).expect("commit key retains its exact value"))
    }
}
impl Extend<CollectionCommit> for CollectionCommitSet {
    fn extend<T: IntoIterator<Item = CollectionCommit>>(&mut self, commits: T) {
        for commit in commits {
            self.0
                .insert(&Entry::with_value(&commit.to_bytes(), commit));
        }
    }
}
impl FromIterator<CollectionCommit> for CollectionCommitSet {
    fn from_iter<T: IntoIterator<Item = CollectionCommit>>(commits: T) -> Self {
        let mut result = Self::new();
        result.extend(commits);
        result
    }
}
impl fmt::Debug for CollectionCommitSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// Rejected exact records and their caller-defined diagnostic values.
#[derive(Clone)]
pub struct CollectionRejections<D>(PATCH<289, IdentitySchema, (CollectionRecord, D)>);
impl<D> Default for CollectionRejections<D> {
    fn default() -> Self {
        Self(PATCH::new())
    }
}
impl<D> CollectionRejections<D> {
    /// Number of rejected records.
    pub fn len(&self) -> usize {
        self.0.len() as usize
    }
    /// Whether no records were rejected.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Diagnostic for one exact record.
    pub fn get(&self, record: &CollectionRecord) -> Option<&D> {
        self.0
            .get(&record_key(record))
            .map(|(_, diagnostic)| diagnostic)
    }
    /// Rejections in canonical record order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&CollectionRecord, &D)> {
        self.0.iter_ordered().map(|key| {
            let (record, diagnostic) = self
                .0
                .get(key)
                .expect("rejection key retains its diagnostic");
            (record, diagnostic)
        })
    }
    pub(super) fn insert(&mut self, record: CollectionRecord, diagnostic: D) {
        self.0.replace(&Entry::with_value(
            &record_key(&record),
            (record, diagnostic),
        ));
    }
}
impl<D: PartialEq> PartialEq for CollectionRejections<D> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl<D: Eq> Eq for CollectionRejections<D> {}
impl<D: fmt::Debug> fmt::Debug for CollectionRejections<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

// Tests deliberately compare the native relations with independent ordered
// collection oracles. These comparisons never enter a retained runtime value.
#[cfg(test)]
impl PartialEq<std::collections::BTreeSet<CollectionData>> for CollectionDataSet {
    fn eq(&self, other: &std::collections::BTreeSet<CollectionData>) -> bool {
        self.iter().eq(other.iter().copied())
    }
}
#[cfg(test)]
impl PartialEq<std::collections::BTreeSet<CollectionCommit>> for CollectionCommitSet {
    fn eq(&self, other: &std::collections::BTreeSet<CollectionCommit>) -> bool {
        self.iter().eq(other.iter())
    }
}
#[cfg(test)]
impl PartialEq<std::collections::BTreeSet<CollectionRecord>> for CollectionRecordSet {
    fn eq(&self, other: &std::collections::BTreeSet<CollectionRecord>) -> bool {
        self.iter().eq(other.iter())
    }
}
#[cfg(test)]
impl<D: PartialEq> PartialEq<std::collections::BTreeMap<CollectionRecord, D>>
    for CollectionRejections<D>
{
    fn eq(&self, other: &std::collections::BTreeMap<CollectionRecord, D>) -> bool {
        self.iter().eq(other.iter())
    }
}
