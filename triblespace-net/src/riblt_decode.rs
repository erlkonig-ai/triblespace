//! Bounded residual-only decoding at the network boundary.
//!
//! The mapping-window mechanics adapt ngerakines/riblt-rs d0737aee
//! (`decoder.rs`/`window.rs`, MIT). Upstream remains our unmodified encoder and
//! mapping oracle. Unlike its general decoder, this owns no complete local set:
//! callers subtract source-bound cached cells before admission. All cascade and
//! mapping work is charged inside the loops, arithmetic is checked, and a pure
//! symbol must actually map to its triggering cell and be newly recovered.

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

use crate::riblt_cache::{Cell, KeySymbol, MAX_CELLS};

/// Difference keys per sign, independent of the prepared/received cell limit.
const MAX_SUPPORT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) cells: usize,
    pub(crate) support: usize,
    pub(crate) work: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            cells: MAX_CELLS,
            support: MAX_SUPPORT,
            work: 64 * MAX_CELLS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    Limit,
    Invalid,
    CountOverflow,
}

fn charge(work: &mut usize) -> Result<(), DecodeError> {
    *work = work.checked_sub(1).ok_or(DecodeError::Limit)?;
    Ok(())
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
    symbols: Vec<HashedSymbol<KeySymbol>>,
    mappings: Vec<RandomMapping>,
    // A forward mapping frontier per recovered difference key, never a full
    // source index. The heap avoids scanning every known key for every row.
    next: BinaryHeap<Reverse<(usize, usize)>>,
}

impl Window {
    fn apply_known(
        &mut self,
        cell: &mut Cell,
        index: usize,
        sign: i64,
        work: &mut usize,
    ) -> Result<(), DecodeError> {
        while let Some(&Reverse((mapped, key))) = self.next.peek() {
            charge(work)?;
            if mapped > index {
                break;
            }
            if mapped < index {
                return Err(DecodeError::Invalid);
            }
            self.next.pop();
            apply(cell, &self.symbols[key], sign)?;
            self.next
                .push(Reverse((self.mappings[key].next_index(), key)));
        }
        Ok(())
    }

    fn insert(&mut self, symbol: HashedSymbol<KeySymbol>, mapping: RandomMapping) {
        self.next
            .push(Reverse((mapping.last_index(), self.symbols.len())));
        self.symbols.push(symbol);
        self.mappings.push(mapping);
    }
}

pub(crate) struct ResidualDecoder {
    key: HashKey,
    limits: Limits,
    work: usize,
    cells: Vec<Cell>,
    ready: VecDeque<usize>,
    queued: Vec<bool>,
    zeros: usize,
    recovered: PATCH<32, IdentitySchema>,
    local: Window,
    remote: Window,
}

impl ResidualDecoder {
    pub(crate) fn with_key(key: HashKey) -> Self {
        Self::with_limits(key, Limits::default())
    }

    pub(crate) fn with_limits(key: HashKey, limits: Limits) -> Self {
        Self {
            key,
            work: limits.work,
            limits,
            cells: Vec::new(),
            ready: VecDeque::new(),
            queued: Vec::new(),
            zeros: 0,
            recovered: PATCH::new(),
            local: Window::default(),
            remote: Window::default(),
        }
    }

    pub(crate) fn local(&self) -> &[HashedSymbol<KeySymbol>] {
        &self.local.symbols
    }

    pub(crate) fn remote(&self) -> &[HashedSymbol<KeySymbol>] {
        &self.remote.symbols
    }

    pub(crate) fn decoded(&self) -> bool {
        !self.cells.is_empty() && self.zeros == self.cells.len()
    }

    /// Admit one contiguous residual row and exhaust only the bounded cascade.
    /// Any error is terminal: the owning exchange discards the decoder.
    pub(crate) fn add(&mut self, mut cell: Cell) -> Result<(), DecodeError> {
        charge(&mut self.work)?;
        if self.cells.len() >= self.limits.cells
            || cell.count.unsigned_abs() > self.limits.support as u64
        {
            return Err(DecodeError::Limit);
        }
        let index = self.cells.len();
        self.remote
            .apply_known(&mut cell, index, -1, &mut self.work)?;
        self.local
            .apply_known(&mut cell, index, 1, &mut self.work)?;
        self.zeros += usize::from(zero(&cell));
        self.cells.push(cell);
        self.queued.push(false);
        self.enqueue(index)?;
        while let Some(index) = self.ready.pop_front() {
            charge(&mut self.work)?;
            self.queued[index] = false;
            let cell = &self.cells[index];
            // Another peel can invalidate a queued candidate before this turn.
            if !cell.is_pure_with_key(Some(&self.key)) {
                continue;
            }
            let remote = cell.count == 1;
            let symbol = HashedSymbol::new_keyed(cell.symbol, &self.key);
            if self.recovered.get(&symbol.symbol.0).is_some() {
                return Err(DecodeError::Invalid);
            }
            let window = if remote { &self.remote } else { &self.local };
            if window.symbols.len() >= self.limits.support {
                return Err(DecodeError::Limit);
            }
            // Purity alone does not prove incidence in an untrusted equation.
            let mut mapping = RandomMapping::new(symbol.mapping_seed);
            while mapping.last_index() < index {
                charge(&mut self.work)?;
                mapping.next_index();
            }
            if mapping.last_index() != index {
                return Err(DecodeError::Invalid);
            }
            self.recovered.insert(&Entry::new(&symbol.symbol.0));
            let mut mapping = RandomMapping::new(symbol.mapping_seed);
            while mapping.last_index() < self.cells.len() {
                charge(&mut self.work)?;
                let mapped = mapping.last_index();
                self.zeros -= usize::from(zero(&self.cells[mapped]));
                apply(
                    &mut self.cells[mapped],
                    &symbol,
                    if remote { -1 } else { 1 },
                )?;
                self.zeros += usize::from(zero(&self.cells[mapped]));
                self.enqueue(mapped)?;
                mapping.next_index();
            }
            let window = if remote {
                &mut self.remote
            } else {
                &mut self.local
            };
            window.insert(symbol, mapping);
        }
        Ok(())
    }

    fn enqueue(&mut self, index: usize) -> Result<(), DecodeError> {
        charge(&mut self.work)?;
        if !self.queued[index] && self.cells[index].is_pure_with_key(Some(&self.key)) {
            self.queued[index] = true;
            self.ready.push_back(index);
        }
        Ok(())
    }
}
