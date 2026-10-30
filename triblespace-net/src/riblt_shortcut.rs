//! Asymmetric shortcut for cached RIBLT: the larger side peels the smaller
//! side's own cells against the empty set.
//!
//! Symmetric cached discovery decodes the difference d of two whole
//! components, which costs about 1.4 d cells on each side. When this side
//! holds A and the peer holds a much smaller B, d is at least |A| - |B|, while
//! B itself decodes from about 1.4 |B| of the peer's raw cells. The same
//! cells already arrive for the residual decoder; this keeps a second
//! residual decoder fed with them unsubtracted, i.e. B minus the empty set.
//!
//! A raw decode is trusted only whole: every row must be zero, no symbol may
//! recover with a negative count, and the exact native summary of the
//! recovered keys must equal the peer's ROOT. Anything else abandons the
//! shortcut and leaves the symmetric decoder, which saw the same cells, to
//! finish as before. Never a partial set.
//!
//! Standalone: nothing on the wire uses this yet.

use riblt::HashKey;
use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH};

use crate::exchange::Tree;
use crate::patch_repair::PatchSummary;
use crate::riblt_cache::Cell;
use crate::riblt_decode::ResidualDecoder;
use crate::walk::KEY_BYTES;

type Key = [u8; KEY_BYTES];

/// Whether this side should race the raw decode of the peer's set. Only the
/// strictly larger side does, so at most one side ever sends STOP.
pub(crate) fn eligible(local: u64, peer: u64) -> bool {
    local > peer
}

/// The peer's whole set, proven against its ROOT and split against ours.
pub(crate) struct Split {
    /// Peer keys this side lacks: request them.
    pub(crate) remote_only: Vec<Key>,
    /// This side's keys the peer lacks: push them.
    pub(crate) local_only: Tree,
    /// Raw peer cells it took.
    pub(crate) cells: usize,
}

enum State {
    Peeling,
    Abandoned,
    Proven,
}

pub(crate) struct Shortcut {
    decoder: ResidualDecoder,
    peer_root: PatchSummary,
    received: usize,
    state: State,
}

impl Shortcut {
    pub(crate) fn new(key: HashKey, peer_root: PatchSummary) -> Self {
        Self {
            decoder: ResidualDecoder::with_key(key),
            peer_root,
            received: 0,
            state: State::Peeling,
        }
    }

    /// The raw decode failed or did not prove: the symmetric path decides.
    pub(crate) fn abandoned(&self) -> bool {
        matches!(self.state, State::Abandoned)
    }

    /// Admit the peer's next raw cell, as received, before any local
    /// subtraction. Returns the split once, at the cell that proves it.
    pub(crate) fn add(&mut self, raw: Cell, source: &Tree) -> Option<Split> {
        if !matches!(self.state, State::Peeling) {
            return None;
        }
        self.received += 1;
        // Raw cells hold the peer's own members only, each counted +1: a
        // negative recovery is a malformed or foreign stream.
        if self.decoder.add(raw).is_err() || !self.decoder.local().is_empty() {
            self.state = State::Abandoned;
            return None;
        }
        if !self.decoder.decoded() {
            return None;
        }
        self.decoder.finish();
        let keys: Vec<Key> = self.decoder.remote().iter().map(|s| s.symbol.0).collect();
        // The decoder already refused a repeated recovery, so these are
        // distinct; the exact native summary binds them to the peer's ROOT.
        let decoded =
            PATCH::<KEY_BYTES, IdentitySchema, (), Blake3Merkle>::from_keys(keys.iter().copied());
        if source.emptied().summary_with_keys(&decoded) != self.peer_root {
            self.state = State::Abandoned;
            return None;
        }
        self.state = State::Proven;
        let (held, remote_only): (Vec<Key>, Vec<Key>) =
            keys.into_iter().partition(|key| source.at(key).is_some());
        Some(Split {
            remote_only,
            local_only: source.without_keys(held),
            cells: self.received,
        })
    }
}

