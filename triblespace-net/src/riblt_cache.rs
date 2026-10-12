//! One source-bound, shared RIBLT prefix per collection component.
//!
//! A generation owns an immutable native PATCH and a serialized grow-only cell
//! prefix. Publication replaces only the latest Arc; running exchanges retain
//! their old source and cells together. Growth never changes an existing cell.
//! It scatters the exact frozen source into the new tail and keeps no second
//! retained symbol/mapping inventory. Updates scatter native PATCH differences
//! into one copy of the already prepared prefix, including removals.
//!
//! Profile 1: exact 32-byte symbols; SipHash-2-4 over precisely those bytes (no
//! Rust Hash length prefix), with the same u64 used as checksum and mapping
//! seed. The 16-byte SipHash key is the first 16 bytes of BLAKE3 over the minted
//! profile domain, collection handle and one-byte WalkKind. Upstream d0737aee's
//! RandomMapping defines the index sequence, using IEEE754 binary64 sqrt/ceil.
//! Wire checksum/count/index scalars are big endian. The map is public and is
//! not an authentication claim; the exact native peer root/count proves closure.

use std::hash::Hasher;
use std::sync::{Arc, Mutex};

use riblt::{CodedSymbol, HashKey, HashedSymbol, RandomMapping, Symbol};
use siphasher::sip::SipHasher24;
use triblespace_core::collection::CollectionHandle;

use crate::exchange::Tree;
use crate::patch_repair::PatchSummary;
use crate::walk::WalkKind;

/// Minted with installed `trible genid`, 2026-10-12.
const PROFILE_DOMAIN: [u8; 16] = hex_literal::hex!("2D1743DA8080C9DBDAEB886FEE34089C");
pub(crate) const INITIAL_CELLS: usize = 1024;
/// 48 MiB of prepared cells per retained generation, excluding its native PATCH.
pub(crate) const MAX_CELLS: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KeySymbol(pub(crate) [u8; 32]);

impl Symbol for KeySymbol {
    type Checksum = u64;

    fn xor(&self, other: &Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ other.0[i]))
    }

    fn hash(&self) -> u64 {
        self.keyed_hash(&[0; 16])
    }

    fn mapping_seed(&self) -> u64 {
        self.hash()
    }

    fn keyed_hash(&self, key: &HashKey) -> u64 {
        let mut hash = SipHasher24::new_with_key(key);
        hash.write(&self.0);
        hash.finish()
    }

    fn keyed_mapping_seed(&self, key: &HashKey) -> u64 {
        self.keyed_hash(key)
    }
}

pub(crate) type Cell = CodedSymbol<KeySymbol>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheError {
    Exhausted,
    Poisoned,
    CountOverflow,
}

/// No peer owns this cache. Old generations survive only through their readers.
pub(crate) struct Generation {
    collection: CollectionHandle,
    kind: WalkKind,
    source: Tree,
    key: HashKey,
    cells: Mutex<Vec<Cell>>,
}

impl Generation {
    pub(crate) fn advance(
        collection: CollectionHandle,
        kind: WalkKind,
        source: Tree,
        previous: Option<&Arc<Self>>,
    ) -> Result<Arc<Self>, CacheError> {
        let previous = previous.filter(|old| old.collection == collection && old.kind == kind);
        let mut cells = Vec::new();
        let mut domain = blake3::Hasher::new();
        domain.update(&PROFILE_DOMAIN);
        domain.update(&collection.raw);
        domain.update(&[kind.wire()]);
        let key: HashKey = domain.finalize().as_bytes()[..16].try_into().unwrap();
        if let Some(old) = previous {
            // Equality observes keys, which completely identify all three
            // components' values. Do not use this for arbitrary PATCH maps.
            let added = source.difference(&old.source);
            let removed = old.source.difference(&source);
            if added.summary().leaf_count() == 0 && removed.summary().leaf_count() == 0 {
                return Ok(old.clone());
            }
            cells = old.cells.lock().map_err(|_| CacheError::Poisoned)?.clone();
            scatter(&removed, &key, &mut cells, 0, -1)?;
            scatter(&added, &key, &mut cells, 0, 1)?;
        }
        Ok(Arc::new(Self {
            collection,
            kind,
            source,
            key,
            cells: Mutex::new(cells),
        }))
    }

    pub(crate) fn source(&self) -> &Tree {
        &self.source
    }

    pub(crate) fn summary(&self) -> PatchSummary {
        self.source.summary()
    }

    pub(crate) fn key(&self) -> HashKey {
        self.key
    }

    pub(crate) fn prepared(&self) -> Result<usize, CacheError> {
        Ok(self.cells.lock().map_err(|_| CacheError::Poisoned)?.len())
    }

    /// Actual retained allocation, including Vec spare capacity, not wire size.
    pub(crate) fn retained_bytes(&self) -> Result<usize, CacheError> {
        Ok(self
            .cells
            .lock()
            .map_err(|_| CacheError::Poisoned)?
            .capacity()
            * std::mem::size_of::<Cell>())
    }

    /// Copy one compact cell. No lock crosses IO or awaits. Contending readers
    /// share growth, not full encoders or a permanent per-peer cache copy.
    pub(crate) fn cell(&self, index: usize) -> Result<Cell, CacheError> {
        if index >= MAX_CELLS {
            return Err(CacheError::Exhausted);
        }
        let mut cells = self.cells.lock().map_err(|_| CacheError::Poisoned)?;
        if index >= cells.len() {
            let length = (index + 1)
                .next_power_of_two()
                .max(INITIAL_CELLS)
                .min(MAX_CELLS);
            let start = cells.len();
            // Construct privately so failed growth cannot publish a partial tail.
            let mut tail = vec![Cell::default(); length - start];
            scatter(&self.source, &self.key, &mut tail, start, 1)?;
            cells.extend(tail);
        }
        Ok(cells[index].clone())
    }
}

/// Scatter only memberships in [offset, offset + cells.len()). Restarting each
/// mapping makes old-generation growth exact after source removals as well.
fn scatter(
    source: &Tree,
    key: &HashKey,
    cells: &mut [Cell],
    offset: usize,
    direction: i64,
) -> Result<(), CacheError> {
    if cells.is_empty() {
        return Ok(());
    }
    let mut failed = false;
    source.for_each_key(|bytes| {
        let symbol = HashedSymbol::new_keyed(KeySymbol(bytes), key);
        let mut mapping = RandomMapping::new(symbol.mapping_seed);
        while mapping.last_index() < offset + cells.len() {
            let index = mapping.last_index();
            if index >= offset {
                let cell = &mut cells[index - offset];
                if let Some(count) = cell.count.checked_add(direction) {
                    cell.symbol = cell.symbol.xor(&symbol.symbol);
                    cell.hash ^= symbol.hash;
                    cell.count = count;
                } else {
                    failed = true;
                }
            }
            mapping.next_index();
        }
    });
    if failed {
        Err(CacheError::CountOverflow)
    } else {
        Ok(())
    }
}
