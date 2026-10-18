//! Typed fixed-record values keyed by collection, member and BLAKE3(body).
//!
//! The discriminator is a hash identity assumption, not injective byte identity.
//! Where bodies meet, unequal bodies under one key refuse insertion. Independent
//! roots can nevertheless hide a forced collision in key-only PATCH difference;
//! the counterexample below records that limit instead of adding a catalogue.
//! The retained value is one typed View owning its actual mmap, not a root cover.
//! Enumeration is streaming, grouped by kind and ordered by this stable key.

use super::*;
use anybytes::View;
use crate::collection::{CollectionRecordView, EncodedCommit, EncodedDerive, EncodedMap};
use crate::patch::PATCHIntoOrderedIterator;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

mod compact {
    pub const KEY_LEN: usize = 96;
    pub const TAIL_LEN: usize = 32;
    crate::key_segmentation!(Segments, 96, [32, 32, 32]);
    crate::key_schema!(Schema, Segments, 96, [0, 1, 2]);
}
use compact::{KEY_LEN, TAIL_LEN};
type Fixed<T> = PATCH<KEY_LEN, compact::Schema, View<T>, XorSip128>;

trait Body: Immutable + IntoBytes + KnownLayout + TryFromBytes + Send + Sync + 'static {
    const KIND: FixedKind;
    fn decode(&self) -> CollectionRecord;
}
impl Body for EncodedCommit {
    const KIND: FixedKind = FixedKind::Commit;
    fn decode(&self) -> CollectionRecord { CollectionRecord::Commit(self.to_record_trusted()) }
}
impl Body for EncodedDerive {
    const KIND: FixedKind = FixedKind::Derive;
    fn decode(&self) -> CollectionRecord { CollectionRecord::Derive(self.to_record_trusted()) }
}
impl Body for EncodedMap {
    const KIND: FixedKind = FixedKind::Map;
    fn decode(&self) -> CollectionRecord { CollectionRecord::Map(self.to_record_trusted()) }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct CollectionRecordIndex {
    commits: Fixed<EncodedCommit>,
    derives: Fixed<EncodedDerive>,
    maps: Fixed<EncodedMap>,
    pub(super) occurrences: CollectionOccurrenceIndex,
}
#[derive(Clone, Copy)]
enum FixedKind { Commit, Derive, Map }
impl FixedKind {
    fn admits(self, selector: &CollectionRecordSelector) -> bool {
        use CollectionRecordSelector::*;
        match selector {
            Collection(_) | ProducedMember(..) => true,
            CommitMember(..) => matches!(self, Self::Commit),
            DeriveTarget(_) => matches!(self, Self::Derive),
            Foundations(_) => !matches!(self, Self::Map),
            MergeCollection(_) => false,
        }
    }
}

#[cfg(test)]
thread_local! { static FORCE_COLLISION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn compact_key(body: &[u8]) -> [u8; KEY_LEN] {
    assert_eq!(body.len(), 224);
    let mut key = [0; KEY_LEN];
    key[..64].copy_from_slice(&body[32..96]);
    // Every physical record pays the body fingerprint. Only a new key pays
    // PATCH's separate leaf hash, which summarizes this 96-byte key.
    key[64..].copy_from_slice(blake3::hash(body).as_bytes());
    #[cfg(test)]
    if FORCE_COLLISION.get() { key[64..].fill(0); }
    key
}

fn member_prefix(collection: CollectionHandle, member: CollectionData) -> [u8; 64] {
    let mut prefix = [0; 64];
    prefix[..32].copy_from_slice(&collection.raw);
    prefix[32..].copy_from_slice(&member.raw);
    prefix
}

fn shares_selected<T: Body>(a: &Fixed<T>, b: &Fixed<T>, s: &CollectionRecordSelector) -> bool {
    use CollectionRecordSelector::*;
    match *s {
        ProducedMember(c, h) | CommitMember(c, h) => a.shares_prefix(b, &member_prefix(c, h)),
        Collection(c) | MergeCollection(c) | DeriveTarget(c) | Foundations(c) => a.shares_prefix(b, &c.raw),
    }
}

fn trusted_view<T: Body>(key: &[u8; KEY_LEN], view: &View<T>) -> CollectionRecordView {
    CollectionRecordView::from_native_fixed(view.clone().bytes())
        .with_native_fingerprint(key[64..].try_into().unwrap())
}

fn selected_keys<T: Body>(root: &Fixed<T>, selectors: &BTreeSet<CollectionRecordSelector>) -> Vec<[u8; KEY_LEN]> {
    // Operation-local, prefix-local route union. Distinct selectors can reach
    // the same leaf; PATCH insertion dedup does not remove these route overlaps.
    let mut keys = Vec::new();
    let mut under_member = |prefix: [u8; 64]| {
        root.infixes(&prefix, |tail: &[u8; TAIL_LEN]| {
            let mut key = [0; KEY_LEN];
            key[..64].copy_from_slice(&prefix);
            key[64..].copy_from_slice(tail);
            keys.push(key);
        });
    };
    for selector in selectors.iter().filter(|s| T::KIND.admits(s)) {
        use CollectionRecordSelector::*;
        match *selector {
            ProducedMember(c, h) | CommitMember(c, h) => under_member(member_prefix(c, h)),
            Collection(c) | MergeCollection(c) | DeriveTarget(c) | Foundations(c) => {
                root.infixes(&c.raw, |h: &[u8; 32]| under_member(member_prefix(c, Inline::new(*h))));
            }
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn selected_views<T: Body>(root: &Fixed<T>, selectors: &BTreeSet<CollectionRecordSelector>) -> Vec<CollectionRecordView> {
    selected_keys(root, selectors).iter().map(|key| trusted_view(key, root.get(key).unwrap())).collect()
}

fn decode<T: Body>(view: &View<T>) -> CollectionRecord {
    #[cfg(test)]
    COLLECTION_RECORD_READS.with(|reads| reads.set(reads.get() + 1));
    view.decode()
}

fn selected_records<T: Body>(root: &Fixed<T>, selectors: &BTreeSet<CollectionRecordSelector>) -> Vec<CollectionRecord> {
    selected_keys(root, selectors).iter().map(|key| decode(root.get(key).unwrap())).collect()
}

fn checked_insert<T: Body>(root: &mut Fixed<T>, key: &[u8; KEY_LEN], body: &[u8], owner: &Arc<MmapRaw>) -> Result<(), ReadError> {
    root.try_insert_with(key, || {
        // SAFETY: the caller decoded these immutable bytes in this mapping;
        // append-only Pile rules prohibit overwriting/truncating applied data.
        // The factory runs only for a new key: duplicates keep the first owner.
        let bytes = unsafe { Bytes::from_raw_parts(body, owner.clone()) };
        bytes.view::<T>().expect("checked fixed layout")
    }, |existing| {
        if existing.as_bytes() == body {
            Ok(())
        } else {
            // Not CorruptPile: automatic tail repair MUST NOT truncate evidence.
            Err(ReadError::IoError(std::io::Error::other("record discriminator collision: unequal canonical bodies")))
        }
    })?;
    Ok(())
}

impl CollectionRecordIndex {
    pub(super) fn new() -> Self {
        Self { commits: PATCH::new(), derives: PATCH::new(), maps: PATCH::new(), occurrences: PATCH::new() }
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> u64 { self.commits.len() + self.derives.len() + self.maps.len() + self.occurrences.len() }
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool { self.len() == 0 }
    pub(super) fn shares_root(&self, other: &Self) -> bool {
        self.commits.shares_root(&other.commits) && self.derives.shares_root(&other.derives)
            && self.maps.shares_root(&other.maps) && self.occurrences.shares_root(&other.occurrences)
    }
    pub(super) fn shares_selected(&self, other: &Self, s: &CollectionRecordSelector) -> bool {
        if (!FixedKind::Commit.admits(s) || shares_selected(&self.commits, &other.commits, s))
            && (!FixedKind::Derive.admits(s) || shares_selected(&self.derives, &other.derives, s))
            && (!FixedKind::Map.admits(s) || shares_selected(&self.maps, &other.maps, s)) {
            use CollectionRecordSelector::*;
            match *s {
                ProducedMember(c, h) => self.occurrences.shares_prefix(&other.occurrences, &member_prefix(c, h)),
                Collection(c) | MergeCollection(c) => self.occurrences.shares_prefix(&other.occurrences, &c.raw),
                _ => true,
            }
        } else { false }
    }
    pub(super) fn difference(&self, other: &Self) -> Self {
        // Hash-identity assumption: this is key-only, NOT a cross-root collision
        // check. The forced independent-root test demonstrates its limitation.
        Self { commits: self.commits.difference(&other.commits), derives: self.derives.difference(&other.derives),
            maps: self.maps.difference(&other.maps), occurrences: self.occurrences.difference(&other.occurrences) }
    }
    pub(super) fn contains_fixed(&self, record: &CollectionRecord) -> bool {
        match record {
            CollectionRecord::Commit(r) => { let b = r.to_bytes(); self.commits.get(&compact_key(&b)).is_some_and(|v| v.as_bytes() == b) }
            CollectionRecord::Derive(r) => { let b = r.to_bytes(); self.derives.get(&compact_key(&b)).is_some_and(|v| v.as_bytes() == b) }
            CollectionRecord::Map(r) => { let b = r.to_bytes(); self.maps.get(&compact_key(&b)).is_some_and(|v| v.as_bytes() == b) }
            CollectionRecord::Merge(_) => false,
        }
    }
    pub(super) fn collections(&self) -> Vec<CollectionHandle> {
        let mut result = Vec::new();
        self.commits.infixes(&[], |c: &[u8; 32]| result.push(Inline::new(*c)));
        self.derives.infixes(&[], |c: &[u8; 32]| result.push(Inline::new(*c)));
        self.maps.infixes(&[], |c: &[u8; 32]| result.push(Inline::new(*c)));
        self.occurrences.infixes(&[], |c: &[u8; 32]| result.push(Inline::new(*c)));
        result.sort_unstable(); result.dedup(); result
    }
    pub(super) fn select_foundation_views(&self, s: &BTreeSet<CollectionRecordSelector>) -> Vec<CollectionRecordView> {
        let mut result = selected_views(&self.commits, s);
        result.extend(selected_views(&self.derives, s));
        result
    }
    pub(super) fn select_fixed(&self, s: &BTreeSet<CollectionRecordSelector>) -> Vec<CollectionRecord> {
        let mut result = selected_records(&self.commits, s);
        result.extend(selected_records(&self.derives, s));
        result.extend(selected_records(&self.maps, s));
        result
    }
    pub(super) fn into_fixed(self) -> FixedRecordIter {
        FixedRecordIter {
            commits: self.commits.into_iter_ordered(),
            derives: self.derives.into_iter_ordered(),
            maps: self.maps.into_iter_ordered(),
        }
    }
    pub(super) fn insert_current_fixed(&mut self, record: &CollectionRecord, frame: &[u8], mmap: &Arc<MmapRaw>) -> Result<(), ReadError> {
        let body = &frame[FRAME_KIND_OFFSET..FRAME_KIND_OFFSET + 224];
        let key = compact_key(body);
        match record {
            CollectionRecord::Commit(_) => checked_insert(&mut self.commits, &key, body, mmap),
            CollectionRecord::Derive(_) => checked_insert(&mut self.derives, &key, body, mmap),
            CollectionRecord::Map(_) => checked_insert(&mut self.maps, &key, body, mmap),
            CollectionRecord::Merge(_) => unreachable!("MERGE occurrence relation unchanged"),
        }
    }
}

pub(super) struct FixedRecordIter {
    commits: PATCHIntoOrderedIterator<KEY_LEN, compact::Schema, View<EncodedCommit>>,
    derives: PATCHIntoOrderedIterator<KEY_LEN, compact::Schema, View<EncodedDerive>>,
    maps: PATCHIntoOrderedIterator<KEY_LEN, compact::Schema, View<EncodedMap>>,
}
impl Iterator for FixedRecordIter {
    type Item = CollectionRecord;
    fn next(&mut self) -> Option<Self::Item> {
        self.commits.next_with(|_, value| decode(value))
            .or_else(|| self.derives.next_with(|_, value| decode(value)))
            .or_else(|| self.maps.next_with(|_, value| decode(value)))
    }
}

#[cfg(test)]
mod tests;
