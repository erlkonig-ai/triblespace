//! One source-bound, shared RIBLT prefix per collection component.
//!
//! A generation owns an immutable native PATCH and a grow-only cell prefix in
//! file-backed chunks ([`crate::riblt_store`]). Publication replaces only the
//! latest Arc; running exchanges retain their old source and cells together.
//! Growth never changes or moves an existing cell, and no configured budget
//! caps it: exchanges bound it by [`cell_bound`] and the wire's u32 index
//! domain. It scatters the exact frozen source into the new tail and keeps no
//! second retained symbol/mapping inventory. Updates scatter native PATCH
//! differences into one copy of at most [`INHERITED_CELLS`] of the already
//! prepared prefix, including removals.
//!
//! Profile 1: exact 32-byte symbols; SipHash-2-4 over precisely those bytes (no
//! Rust Hash length prefix), with the same u64 used as checksum and mapping
//! seed. The 16-byte SipHash key is the first 16 bytes of BLAKE3 over the minted
//! profile domain, collection handle and one-byte WalkKind. Upstream d0737aee's
//! RandomMapping defines the index sequence, using IEEE754 binary64 sqrt/ceil.
//! Wire checksum/count/index scalars are big endian. The map is public and is
//! not an authentication claim; the exact native peer root/count proves closure.
//!
//! A prepared cell is stored as nothing but its canonical RIBLT_CELL wire
//! frame, framing included ([`CELL_FRAME_BYTES`]), so a contiguous run of
//! cells is sent as one immutable view of the mapped chunk
//! ([`Generation::frames`]) instead of being re-encoded cell by cell. That
//! removes only our own encoding and copies: QUIC encrypts every packet in
//! user space, so the transport still copies and coalesces these bytes into
//! its send buffer, and no kernel zero-copy (sendfile) is possible below it.

use std::hash::Hasher;
use std::sync::{Arc, Mutex};

use riblt::{CodedSymbol, HashKey, HashedSymbol, RandomMapping, Symbol};
use siphasher::sip::SipHasher24;
use triblespace_core::collection::CollectionHandle;

use crate::exchange::Tree;
use crate::patch_repair::PatchSummary;
use crate::riblt_store::{Record, Records};
use crate::walk::WalkKind;

/// Minted with installed `trible genid`, 2026-10-12.
const PROFILE_DOMAIN: [u8; 16] = hex_literal::hex!("2D1743DA8080C9DBDAEB886FEE34089C");
pub(crate) const INITIAL_CELLS: usize = 1024;
/// The last cell index a RIBLT_CELL frame can carry (its index is a u32).
/// A structural limit of the wire format, not a tuning constant.
pub(crate) const MAX_INDEX: usize = u32::MAX as usize;
/// Prepared cells a new generation inherits from its predecessor: about 3.56
/// MiB of file per component (57-byte frames; 3 MiB as 48-byte native
/// records before the frames were cached), enough for differences of about
/// 48,000 keys. Cells
/// beyond it are prepared again by the session that needs them, in its own
/// generation, and die with it; this bounds the copy every publication
/// pays, never what a session may grow.
pub(crate) const INHERITED_CELLS: usize = 65_536;
/// Additive headroom of [`cell_bound`], covering the high relative overhead
/// of peeling small differences.
pub(crate) const CELL_HEADROOM: usize = 65_536;

/// Cells an exchange may send or receive, from the two ROOT counts. The
/// difference d is at most `local + peer`, and peeling needs about 1.35 d
/// cells, so twice the sum plus [`CELL_HEADROOM`] is never reached by an
/// honest exchange. It is structural, derived from what both sides declared,
/// not a tuning knob; the u32 index domain still applies beyond it.
pub(crate) fn cell_bound(local: u64, peer: u64) -> usize {
    let bound = local
        .saturating_add(peer)
        .saturating_mul(2)
        .saturating_add(CELL_HEADROOM as u64);
    usize::try_from(bound)
        .unwrap_or(usize::MAX)
        .min(MAX_INDEX.saturating_add(1))
}

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

/// Symbol, checksum and count, native endian: a residual row never leaves the
/// process, and zero bytes are the empty cell.
impl Record for Cell {
    const BYTES: usize = 48;

    fn load(bytes: &[u8]) -> Self {
        Self {
            symbol: KeySymbol(bytes[..32].try_into().unwrap()),
            hash: u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
            count: i64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
        }
    }

    fn store(&self, bytes: &mut [u8]) {
        bytes[..32].copy_from_slice(&self.symbol.0);
        bytes[32..40].copy_from_slice(&self.hash.to_ne_bytes());
        bytes[40..48].copy_from_slice(&self.count.to_ne_bytes());
    }
}

/// RIBLT_CELL's payload: index:u32, symbol32, hash:u64, count:i64.
pub(crate) const CELL_PAYLOAD_BYTES: usize = 4 + 32 + 8 + 8;
/// One whole RIBLT_CELL frame on the wire: kind:u8, length:u32, payload.
pub(crate) const CELL_FRAME_BYTES: usize = 1 + 4 + CELL_PAYLOAD_BYTES;

/// One cell at its index, stored as exactly the bytes its RIBLT_CELL frame
/// puts on the wire (big endian, framing included). All zero bytes load as
/// the empty cell at index 0; a published slot always carries its header.
#[derive(Clone, Debug)]
pub(crate) struct CellFrame {
    pub(crate) index: u32,
    pub(crate) cell: Cell,
}

impl CellFrame {
    /// Parse one canonical frame. `None` unless the header is exactly a
    /// RIBLT_CELL frame of [`CELL_PAYLOAD_BYTES`].
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CELL_FRAME_BYTES
            || bytes[0] != crate::walk_stream::FRAME_RIBLT_CELL
            || bytes[1..5] != (CELL_PAYLOAD_BYTES as u32).to_be_bytes()
        {
            return None;
        }
        Some(Self::load(bytes))
    }
}

impl Record for CellFrame {
    const BYTES: usize = CELL_FRAME_BYTES;

    fn load(bytes: &[u8]) -> Self {
        Self {
            index: u32::from_be_bytes(bytes[5..9].try_into().unwrap()),
            cell: Cell {
                symbol: KeySymbol(bytes[9..41].try_into().unwrap()),
                hash: u64::from_be_bytes(bytes[41..49].try_into().unwrap()),
                count: i64::from_be_bytes(bytes[49..57].try_into().unwrap()),
            },
        }
    }

    fn store(&self, bytes: &mut [u8]) {
        bytes[0] = crate::walk_stream::FRAME_RIBLT_CELL;
        bytes[1..5].copy_from_slice(&(CELL_PAYLOAD_BYTES as u32).to_be_bytes());
        bytes[5..9].copy_from_slice(&self.index.to_be_bytes());
        bytes[9..41].copy_from_slice(&self.cell.symbol.0);
        bytes[41..49].copy_from_slice(&self.cell.hash.to_be_bytes());
        bytes[49..57].copy_from_slice(&self.cell.count.to_be_bytes());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheError {
    /// Beyond [`MAX_INDEX`].
    Exhausted,
    Poisoned,
    CountOverflow,
    /// A chunk file could not be reserved, e.g. on a full disk.
    Storage,
}

/// No peer owns this cache. Old generations survive only through their readers.
pub(crate) struct Generation {
    collection: CollectionHandle,
    kind: WalkKind,
    source: Tree,
    key: HashKey,
    cells: Mutex<Records<CellFrame>>,
}

impl Generation {
    pub(crate) fn advance(
        collection: CollectionHandle,
        kind: WalkKind,
        source: Tree,
        previous: Option<&Arc<Self>>,
    ) -> Result<Arc<Self>, CacheError> {
        let previous = previous.filter(|old| old.collection == collection && old.kind == kind);
        let mut cells = Records::default();
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
            cells = old
                .cells
                .lock()
                .map_err(|_| CacheError::Poisoned)?
                .try_clone_prefix(INHERITED_CELLS)
                .map_err(|_| CacheError::Storage)?;
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

    /// Mapped file bytes reserved for prepared cells, in whole chunks: not
    /// heap, and not wire size.
    pub(crate) fn retained_bytes(&self) -> Result<usize, CacheError> {
        Ok(self
            .cells
            .lock()
            .map_err(|_| CacheError::Poisoned)?
            .reserved_bytes())
    }

    /// Copy one compact cell. No lock crosses network IO or awaits; growth
    /// writes its new chunk files under the lock. Contending readers share
    /// growth, not full encoders or a permanent per-peer cache copy.
    pub(crate) fn cell(&self, index: usize) -> Result<Cell, CacheError> {
        let mut cells = self.cells.lock().map_err(|_| CacheError::Poisoned)?;
        self.prepare(&mut cells, index)?;
        Ok(cells.get(index).expect("prepared through index").cell)
    }

    /// The canonical wire frames of cells `[start, start + n)` as one
    /// immutable view of the mapped cache, for some `1 <= n <= max`: `n`
    /// stops at the prepared end and at a chunk boundary. The bytes are
    /// exactly what encoding each cell as a RIBLT_CELL frame writes, and they
    /// never change, whatever the cache or a newer generation does later.
    pub(crate) fn frames(&self, start: usize, max: usize) -> Result<anybytes::Bytes, CacheError> {
        assert!(max > 0, "a run of at least one cell");
        let mut cells = self.cells.lock().map_err(|_| CacheError::Poisoned)?;
        self.prepare(&mut cells, start)?;
        let chunk_end = (start / crate::riblt_store::CHUNK + 1) * crate::riblt_store::CHUNK;
        let count = max.min(cells.len() - start).min(chunk_end - start);
        cells.view(start, count).map_err(|_| CacheError::Storage)
    }

    /// Prepare the cells through `index`, in doubling steps.
    fn prepare(&self, cells: &mut Records<CellFrame>, index: usize) -> Result<(), CacheError> {
        if index > MAX_INDEX {
            return Err(CacheError::Exhausted);
        }
        if index < cells.len() {
            return Ok(());
        }
        let length = (index + 1)
            .next_power_of_two()
            .max(INITIAL_CELLS)
            .min(MAX_INDEX.saturating_add(1));
        let start = cells.len();
        // A view may share the partial chunk this growth writes into.
        cells.unshare(start).map_err(|_| CacheError::Storage)?;
        cells.resize(length).map_err(|_| CacheError::Storage)?;
        for index in start..length {
            cells.set(index, &CellFrame { index: index as u32, cell: Cell::default() });
        }
        // Failed growth must not publish a partial tail.
        if let Err(error) = scatter(&self.source, &self.key, cells, start, 1) {
            cells.truncate(start);
            return Err(error);
        }
        Ok(())
    }
}

/// Scatter only memberships in [offset, cells.len()). Restarting each mapping
/// makes old-generation growth exact after source removals as well.
fn scatter(
    source: &Tree,
    key: &HashKey,
    cells: &mut Records<CellFrame>,
    offset: usize,
    direction: i64,
) -> Result<(), CacheError> {
    let end = cells.len();
    if offset >= end {
        return Ok(());
    }
    let mut failed = false;
    source.for_each_key(|bytes| {
        let symbol = HashedSymbol::new_keyed(KeySymbol(bytes), key);
        let mut mapping = RandomMapping::new(symbol.mapping_seed);
        while mapping.last_index() < end {
            let index = mapping.last_index();
            if index >= offset {
                let mut frame = cells.get(index).expect("index below len");
                let cell = &mut frame.cell;
                if let Some(count) = cell.count.checked_add(direction) {
                    cell.symbol = cell.symbol.xor(&symbol.symbol);
                    cell.hash ^= symbol.hash;
                    cell.count = count;
                    cells.set(index, &frame);
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
