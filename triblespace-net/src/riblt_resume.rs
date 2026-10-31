//! The receiver's cache of peer cell prefixes, for resuming an interrupted
//! cached RIBLT exchange (ALPN 36).
//!
//! A peer's cell stream is a pure function of the profile (the minted domain,
//! collection and component, which [`Generation::key`] already hashes) and
//! the peer's record set, and the peer's ROOT names that set exactly. So the
//! cells `[0, N)` received from a peer stay valid for exactly as long as the
//! peer announces the same root, whoever the peer is. Entries are keyed by
//! (profile key, peer root) and never by peer identity: two peers with the
//! same root share an entry, and no agreement about any peer is kept here.
//!
//! An entry holds the RAW received cells, verbatim in their canonical
//! RIBLT_CELL frame bytes, never residual decoder state: the residual also
//! depends on our own set, which may change between connections, so a resumed
//! exchange rebuilds it from these cells against its own current cells.
//!
//! An exchange takes its entry out while it runs (a concurrent exchange with
//! a peer of the same root then starts from 0), keeps it after an exchange
//! that was cut off, and drops it after a successful exchange or one that
//! failed for a reason of its own (including a malformed or truncated frame
//! from the peer): a cut is the only ending whose cells are worth keeping,
//! and cells that failed a proof must not be offered again. Entries beyond
//! [`RESUME_BUDGET_BYTES`] are evicted oldest first; a miss only means a
//! stream starts from 0, never a failure.
//!
//! A ROOT that announces a resume promises exactly one RIBLT_RESUME on any
//! stream that is not reset, even once the exchange is confirmed (equal
//! roots, peer FIN first); readiness to finish waits for it.
//!
//! Accepted limit: the cells are not verified against the root until
//! decoding completes. Because entries are keyed by root and shared across
//! peer identities, a dishonest peer can plant a structurally valid but wrong
//! prefix under an honest peer's root and cut the stream; an honest reconnect
//! with that root then fails or redoes work. The final exact root proof still
//! prevents any false confirmation, and the failed exchange discards the
//! entry it took, so integrity holds and repeated poisoning needs the prefix
//! planted again.
//!
//! [`Generation::key`]: crate::riblt_cache::Generation::key

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use riblt::HashKey;

use crate::patch_repair::PatchSummary;
use crate::riblt_cache::CellFrame;
use crate::riblt_store::Records;

/// Mapped chunk-file bytes the KEPT entries of one host may reserve together:
/// 64 MiB, about 1.1 million cells, or a difference of about 800,000 keys
/// cut off once. Chunks are 912 KiB, so a small entry costs a whole chunk.
/// Entries taken into running exchanges and their recordings are not
/// counted: each running cached exchange may hold one taken entry and its
/// own recording. A recording stops once its logical size reaches this
/// budget, but chunks are reserved whole, so it may reserve up to one more
/// 912 KiB chunk: a host's total is at most this budget times one plus its
/// running cached exchanges, plus one chunk per running exchange.
pub(crate) const RESUME_BUDGET_BYTES: usize = 64 << 20;

/// The profile key of the generation the cells were checked against, and
/// the root the peer announced for them.
pub(crate) type ResumeKey = (HashKey, PatchSummary);

struct Entry {
    stamp: u64,
    cells: Records<CellFrame>,
}

#[derive(Default)]
struct Entries {
    entries: HashMap<ResumeKey, Entry>,
    stamp: u64,
    bytes: usize,
}

pub(crate) struct ResumeCache {
    budget: usize,
    entries: Mutex<Entries>,
}

impl ResumeCache {
    pub(crate) fn new(budget: usize) -> Arc<Self> {
        Arc::new(Self {
            budget,
            entries: Mutex::new(Entries::default()),
        })
    }

    pub(crate) fn budget(&self) -> usize {
        self.budget
    }

    /// Whether any entry has this profile key: the one bit a ROOT discloses.
    pub(crate) fn holds(&self, profile: &HashKey) -> bool {
        self.entries
            .lock()
            .is_ok_and(|entries| entries.entries.keys().any(|(key, _)| key == profile))
    }

    /// Take the entry out, for the one exchange that resumes from it.
    pub(crate) fn take(&self, key: &ResumeKey) -> Option<Records<CellFrame>> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.entries.remove(key)?;
        entries.bytes -= entry.cells.reserved_bytes();
        Some(entry.cells)
    }

    /// Keep the cells received from a cut-off exchange, replacing any entry
    /// for the same key, then evict oldest entries down to the budget. An
    /// entry larger than the whole budget is not kept.
    pub(crate) fn keep(&self, key: ResumeKey, cells: Records<CellFrame>) {
        if cells.is_empty() || cells.reserved_bytes() > self.budget {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.stamp += 1;
        let stamp = entries.stamp;
        entries.bytes += cells.reserved_bytes();
        if let Some(old) = entries.entries.insert(key, Entry { stamp, cells }) {
            entries.bytes -= old.cells.reserved_bytes();
        }
        while entries.bytes > self.budget {
            let oldest = *entries
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.stamp)
                .map(|(key, _)| key)
                .expect("bytes are only held by entries");
            let evicted = entries.entries.remove(&oldest).unwrap();
            entries.bytes -= evicted.cells.reserved_bytes();
        }
    }

    /// Cells held for `key`, without taking them.
    #[cfg(test)]
    pub(crate) fn held(&self, key: &ResumeKey) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.entries.get(key).map_or(0, |entry| entry.cells.len())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().entries.len()
    }
}
