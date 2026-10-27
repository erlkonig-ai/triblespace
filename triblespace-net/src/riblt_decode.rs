//! Residual-only decoding at the network boundary.
//!
//! The mapping-window mechanics adapt ngerakines/riblt-rs d0737aee
//! (`decoder.rs`/`window.rs`, MIT). Upstream remains our unmodified encoder and
//! mapping oracle. Unlike its general decoder, this owns no complete local set:
//! callers subtract source-bound cached cells before admission. Arithmetic is
//! checked, and a pure symbol must actually map to its triggering cell and be
//! newly recovered.
//!
//! No configured cell, support or work budget fails decoding: its state grows
//! with the difference. Residual rows and recovered symbols live in file-backed
//! chunks ([`crate::riblt_store`]). Per recovered key the heap keeps its
//! mapping frontier (16 bytes), its heap entry (16 bytes) and its entry in the
//! duplicate-recovery PATCH; `ready` holds at most one index per row. Once
//! decoded, [`ResidualDecoder::finish`] releases all of that except the
//! recovered windows. Liveness belongs to the walk's progress deadline, not to
//! this decoder.

/*
MIT License

Copyright (c) 2026 Nick Gerakines

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

use riblt::{HashKey, HashedSymbol, RandomMapping, Symbol};
use triblespace_core::patch::{Entry, IdentitySchema, PATCH};

use crate::riblt_cache::{Cell, KeySymbol};
use crate::riblt_store::{Record, Records};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    Invalid,
    CountOverflow,
    /// A chunk file could not be reserved, e.g. on a full disk.
    Storage,
}

/// A recovered symbol: key, checksum and mapping seed, native endian.
impl Record for HashedSymbol<KeySymbol> {
    const BYTES: usize = 48;

    fn load(bytes: &[u8]) -> Self {
        Self {
            symbol: KeySymbol(bytes[..32].try_into().unwrap()),
            hash: u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
            mapping_seed: u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
        }
    }

    fn store(&self, bytes: &mut [u8]) {
        bytes[..32].copy_from_slice(&self.symbol.0);
        bytes[32..40].copy_from_slice(&self.hash.to_ne_bytes());
        bytes[40..48].copy_from_slice(&self.mapping_seed.to_ne_bytes());
    }
}

/// One residual row and whether it waits in `ready`.
struct Row {
    cell: Cell,
    queued: bool,
}

impl Record for Row {
    const BYTES: usize = Cell::BYTES + 1;

    fn load(bytes: &[u8]) -> Self {
        Self {
            cell: Cell::load(&bytes[..Cell::BYTES]),
            queued: bytes[Cell::BYTES] != 0,
        }
    }

    fn store(&self, bytes: &mut [u8]) {
        self.cell.store(&mut bytes[..Cell::BYTES]);
        bytes[Cell::BYTES] = u8::from(self.queued);
    }
}

fn apply(cell: &mut Cell, symbol: &HashedSymbol<KeySymbol>, sign: i64) -> Result<(), DecodeError> {
    let count = cell
        .count
        .checked_add(sign)
        .ok_or(DecodeError::CountOverflow)?;
    cell.symbol = cell.symbol.xor(&symbol.symbol);
    cell.hash ^= symbol.hash;
    cell.count = count;
    Ok(())
}

fn zero(cell: &Cell) -> bool {
    cell.count == 0 && cell.hash == 0 && cell.symbol == KeySymbol::default()
}

#[derive(Default)]
struct Window {
    symbols: Records<HashedSymbol<KeySymbol>>,
    mappings: Vec<RandomMapping>,
    // A forward mapping frontier per recovered difference key, never a full
    // source index. The heap avoids scanning every known key for every row.
    next: BinaryHeap<Reverse<(usize, usize)>>,
}

impl Window {
    fn apply_known(&mut self, cell: &mut Cell, index: usize, sign: i64) -> Result<(), DecodeError> {
        while let Some(&Reverse((mapped, key))) = self.next.peek() {
            if mapped > index {
                break;
            }
            if mapped < index {
                return Err(DecodeError::Invalid);
            }
            self.next.pop();
            apply(cell, &self.symbols.get(key).expect("recovered"), sign)?;
            self.next
                .push(Reverse((self.mappings[key].next_index(), key)));
        }
        Ok(())
    }

    fn insert(
        &mut self,
        symbol: HashedSymbol<KeySymbol>,
        mapping: RandomMapping,
    ) -> Result<(), DecodeError> {
        self.symbols
            .push(&symbol)
            .map_err(|_| DecodeError::Storage)?;
        self.next
            .push(Reverse((mapping.last_index(), self.mappings.len())));
        self.mappings.push(mapping);
        Ok(())
    }
}

pub(crate) struct ResidualDecoder {
    key: HashKey,
    rows: Records<Row>,
    ready: VecDeque<usize>,
    zeros: usize,
    recovered: PATCH<32, IdentitySchema>,
    local: Window,
    remote: Window,
    finished: bool,
}

impl ResidualDecoder {
    pub(crate) fn with_key(key: HashKey) -> Self {
        Self {
            key,
            rows: Records::default(),
            ready: VecDeque::new(),
            zeros: 0,
            recovered: PATCH::new(),
            local: Window::default(),
            remote: Window::default(),
            finished: false,
        }
    }

    pub(crate) fn local(&self) -> &Records<HashedSymbol<KeySymbol>> {
        &self.local.symbols
    }

    pub(crate) fn remote(&self) -> &Records<HashedSymbol<KeySymbol>> {
        &self.remote.symbols
    }

    pub(crate) fn decoded(&self) -> bool {
        self.finished || (!self.rows.is_empty() && self.zeros == self.rows.len())
    }

    /// Release everything but the recovered windows once decoded: rows,
    /// queue, duplicate PATCH and mapping frontiers. No row may follow.
    pub(crate) fn finish(&mut self) {
        debug_assert!(self.decoded());
        self.finished = true;
        self.rows = Records::default();
        self.ready = VecDeque::new();
        self.recovered = PATCH::new();
        for window in [&mut self.local, &mut self.remote] {
            window.mappings = Vec::new();
            window.next = BinaryHeap::new();
        }
    }

    /// Admit one contiguous residual row and exhaust its cascade.
    /// Any error is terminal: the owning exchange discards the decoder.
    pub(crate) fn add(&mut self, mut cell: Cell) -> Result<(), DecodeError> {
        if self.finished {
            return Err(DecodeError::Invalid);
        }
        let index = self.rows.len();
        self.remote.apply_known(&mut cell, index, -1)?;
        self.local.apply_known(&mut cell, index, 1)?;
        self.zeros += usize::from(zero(&cell));
        let mut row = Row {
            cell,
            queued: false,
        };
        self.enqueue(index, &mut row);
        self.rows.push(&row).map_err(|_| DecodeError::Storage)?;
        while let Some(index) = self.ready.pop_front() {
            let mut row = self.rows.get(index).expect("queued rows exist");
            row.queued = false;
            self.rows.set(index, &row);
            let cell = row.cell;
            // Another peel can invalidate a queued candidate before this turn.
            if !cell.is_pure_with_key(Some(&self.key)) {
                continue;
            }
            let remote = cell.count == 1;
            let symbol = HashedSymbol::new_keyed(cell.symbol, &self.key);
            if self.recovered.get(&symbol.symbol.0).is_some() {
                return Err(DecodeError::Invalid);
            }
            // Purity alone does not prove incidence in an untrusted equation.
            let mut mapping = RandomMapping::new(symbol.mapping_seed);
            while mapping.last_index() < index {
                mapping.next_index();
            }
            if mapping.last_index() != index {
                return Err(DecodeError::Invalid);
            }
            self.recovered.insert(&Entry::new(&symbol.symbol.0));
            let mut mapping = RandomMapping::new(symbol.mapping_seed);
            while mapping.last_index() < self.rows.len() {
                let mapped = mapping.last_index();
                let mut row = self.rows.get(mapped).expect("mapped below len");
                self.zeros -= usize::from(zero(&row.cell));
                apply(&mut row.cell, &symbol, if remote { -1 } else { 1 })?;
                self.zeros += usize::from(zero(&row.cell));
                self.enqueue(mapped, &mut row);
                self.rows.set(mapped, &row);
                mapping.next_index();
            }
            let window = if remote {
                &mut self.remote
            } else {
                &mut self.local
            };
            window.insert(symbol, mapping)?;
        }
        Ok(())
    }

    fn enqueue(&mut self, index: usize, row: &mut Row) {
        if !row.queued && row.cell.is_pure_with_key(Some(&self.key)) {
            row.queued = true;
            self.ready.push_back(index);
        }
    }
}
