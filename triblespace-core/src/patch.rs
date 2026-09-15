//! Persistent Adaptive Trie with Cuckoo-compression and
//! Hash-maintenance (PATCH).
//!
//! See the [PATCH](../book/src/deep-dive/patch.md) chapter of the Tribles Book
//! for the full design description and hashing scheme.
//!
//! Values stored in leaves are not part of hashing or equality comparisons.
//! Two [`PATCH`](crate::patch::PATCH)es are considered equal if they contain the same set of keys,
//! even if the associated values differ. This allows using the structure as an
//! idempotent blobstore where a value's hash determines its key.
//!
#![allow(unstable_name_collisions)]

mod branch;
/// Byte-indexed lookup tables used by PATCH branch nodes.
pub mod bytetable;
mod entry;
mod leaf;

use arrayvec::ArrayVec;

/// Re-export of [`Entry`](entry::Entry).
use branch::*;
pub use entry::{ArchiveEntry, Entry};
use leaf::*;

/// Re-export of all byte table utilities.
pub use bytetable::*;
use rand::thread_rng;
use rand::RngCore;
use std::cmp::Reverse;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::{Arc, OnceLock};

/// Marker trait for opaque owners of bytes referenced by archive-backed
/// PATCH leaves. An owner exists solely to keep its allocation alive while a
/// [`HeadTag::LocalLeaf`] points into it.
pub trait ArchiveOwner: Send + Sync + 'static {}

impl<T: Send + Sync + 'static + ?Sized> ArchiveOwner for T {}

/// One node in the exact persistent set of retained archive allocations.
///
/// Owners are stored inline in their parent (or directly in [`OwnerCover`]);
/// only branches allocate an [`Arc`]. This is a binary Patricia trie over
/// owner allocation addresses. Masks strictly decrease on each root-to-leaf
/// path, so the shape is canonical for an address set and its height is at
/// most [`usize::BITS`]. Rebuilt paths share every untouched branch Arc with
/// older PATCH snapshots.
#[derive(Clone)]
enum OwnerNode {
    Owner(Arc<dyn ArchiveOwner>),
    Branch(Arc<OwnerBranch>),
}

struct OwnerBranch {
    mask: usize,
    zero: OwnerNode,
    one: OwnerNode,
}

/// Exact persistent set of archive allocations retained by one PATCH.
///
/// Membership is keyed by an allocation's data address. Each address remains
/// unavailable for reuse while its owner leaf is present. `latest_address`
/// keeps repeated archive ingestion O(1) without weakening exact membership
/// for older owners or repeated diamond unions.
#[derive(Clone)]
struct OwnerCover {
    latest_address: usize,
    len: usize,
    root: OwnerNode,
}

impl core::fmt::Debug for OwnerCover {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnerCover")
            .field("len", &self.len)
            .finish()
    }
}

impl OwnerNode {
    #[inline]
    fn takes_one(address: usize, mask: usize) -> bool {
        address & mask != 0
    }

    #[inline]
    fn critical_mask(left: usize, right: usize) -> usize {
        let differing = left ^ right;
        debug_assert_ne!(differing, 0);
        1usize << (usize::BITS - 1 - differing.leading_zeros())
    }

    fn matching_owner(&self, address: usize) -> &Arc<dyn ArchiveOwner> {
        let mut node = self;
        loop {
            match node {
                Self::Owner(owner) => return owner,
                Self::Branch(branch) => {
                    node = if Self::takes_one(address, branch.mask) {
                        &branch.one
                    } else {
                        &branch.zero
                    };
                }
            }
        }
    }

    #[cfg(any(debug_assertions, test))]
    fn contains(&self, address: usize) -> bool {
        OwnerCover::address(self.matching_owner(address)) == address
    }

    #[cfg(test)]
    fn same_shape(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Owner(left), Self::Owner(right)) => {
                OwnerCover::address(left) == OwnerCover::address(right)
            }
            (Self::Branch(left), Self::Branch(right)) => {
                left.mask == right.mask
                    && left.zero.same_shape(&right.zero)
                    && left.one.same_shape(&right.one)
            }
            _ => false,
        }
    }

    /// Persistently insert one owner, returning the unchanged root on a hit.
    fn insert(&self, owner: &Arc<dyn ArchiveOwner>) -> (Self, bool) {
        let address = OwnerCover::address(owner);
        let matching = self.matching_owner(address);
        let existing_address = OwnerCover::address(matching);
        if existing_address == address {
            debug_assert!(Arc::ptr_eq(matching, owner));
            return (self.clone(), false);
        }

        let critical_mask = Self::critical_mask(address, existing_address);
        (
            Self::insert_at(
                self,
                Self::Owner(owner.clone()),
                address,
                existing_address,
                critical_mask,
            ),
            true,
        )
    }

    fn insert_at(
        root: &Self,
        inserted: Self,
        inserted_address: usize,
        existing_address: usize,
        critical_mask: usize,
    ) -> Self {
        if let Self::Branch(branch) = root {
            if branch.mask > critical_mask {
                if Self::takes_one(inserted_address, branch.mask) {
                    return Self::Branch(Arc::new(OwnerBranch {
                        mask: branch.mask,
                        zero: branch.zero.clone(),
                        one: Self::insert_at(
                            &branch.one,
                            inserted,
                            inserted_address,
                            existing_address,
                            critical_mask,
                        ),
                    }));
                }
                return Self::Branch(Arc::new(OwnerBranch {
                    mask: branch.mask,
                    zero: Self::insert_at(
                        &branch.zero,
                        inserted,
                        inserted_address,
                        existing_address,
                        critical_mask,
                    ),
                    one: branch.one.clone(),
                }));
            }
            debug_assert_ne!(branch.mask, critical_mask);
        }

        debug_assert_ne!(
            Self::takes_one(inserted_address, critical_mask),
            Self::takes_one(existing_address, critical_mask),
        );
        let (zero, one) = if Self::takes_one(inserted_address, critical_mask) {
            (root.clone(), inserted)
        } else {
            (inserted, root.clone())
        };
        Self::Branch(Arc::new(OwnerBranch {
            mask: critical_mask,
            zero,
            one,
        }))
    }

    fn for_each_owner<F>(&self, f: &mut F)
    where
        F: FnMut(&Arc<dyn ArchiveOwner>),
    {
        match self {
            Self::Owner(owner) => f(owner),
            Self::Branch(branch) => {
                branch.zero.for_each_owner(f);
                branch.one.for_each_owner(f);
            }
        }
    }
}

impl OwnerCover {
    #[inline]
    fn address(owner: &Arc<dyn ArchiveOwner>) -> usize {
        Arc::as_ptr(owner) as *const () as usize
    }

    fn singleton(owner: &Arc<dyn ArchiveOwner>) -> Arc<Self> {
        Arc::new(Self {
            latest_address: Self::address(owner),
            len: 1,
            root: OwnerNode::Owner(owner.clone()),
        })
    }

    fn retain(current: &mut Option<Arc<Self>>, owner: &Arc<dyn ArchiveOwner>) {
        let address = Self::address(owner);
        let Some(existing) = current.as_mut() else {
            *current = Some(Self::singleton(owner));
            return;
        };
        if existing.latest_address == address {
            return;
        }

        // Finish the persistent path before publishing it. A caught allocation
        // panic therefore leaves the installed lifetime receipt unchanged.
        let (root, inserted) = existing.root.insert(owner);
        let cover = Arc::make_mut(existing);
        cover.root = root;
        cover.len += usize::from(inserted);
        cover.latest_address = address;
    }

    /// Transactionally replace `current` with its exact union with `other`.
    fn merge_into(current: &mut Option<Arc<Self>>, other: &Option<Arc<Self>>) {
        *current = Self::union(current.clone(), other);
    }

    fn union(left: Option<Arc<Self>>, right: &Option<Arc<Self>>) -> Option<Arc<Self>> {
        let Some(right) = right.as_ref() else {
            return left;
        };
        let Some(left) = left else {
            return Some(right.clone());
        };
        if Arc::ptr_eq(&left, right) {
            return Some(left);
        }

        // Insert the smaller exact set into the larger. The canonical Patricia
        // shape makes the result independent of this directional choice.
        let (mut result, additions) = if left.len >= right.len {
            (left.clone(), right)
        } else {
            (right.clone(), &left)
        };
        additions.root.for_each_owner(&mut |owner| {
            let (root, inserted) = result.root.insert(owner);
            if inserted {
                let cover = Arc::make_mut(&mut result);
                cover.root = root;
                cover.len += 1;
            }
        });
        if result.latest_address != right.latest_address {
            Arc::make_mut(&mut result).latest_address = right.latest_address;
        }
        Some(result)
    }

    /// Exact subset check for auditing unsafe cover replacement in debug
    /// builds. Production callers rely on the construction proof documented
    /// at [`PATCH::set_owner_guard`].
    #[cfg(debug_assertions)]
    fn covers(&self, covered: &Self) -> bool {
        if self.len < covered.len {
            return false;
        }
        let mut covers = true;
        covered.root.for_each_owner(&mut |owner| {
            covers &= self.root.contains(Self::address(owner));
        });
        covers
    }
}

// Keep the intended structural cost visible. Owner leaves live inline; only
// Patricia branches and the outer cover allocate.
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<OwnerNode>() == 2 * std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<OwnerBranch>() == 5 * std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<OwnerCover>() == 4 * std::mem::size_of::<usize>());
};

/// Opaque lifetime receipt for archive-backed PATCH leaves.
///
/// Aggregate structures can exactly deduplicate retained provenance, add one
/// archive owner, and install a proved conservative superset. Trie Heads and
/// concrete Patricia nodes remain private to PATCH.
#[derive(Clone, Debug, Default)]
pub(crate) struct PATCHOwnerGuard(Option<Arc<OwnerCover>>);

impl PATCHOwnerGuard {
    /// Retain the exact deduplicated union of owners in both receipts.
    pub(crate) fn join(self, other: Self) -> Self {
        Self(OwnerCover::union(self.0, &other.0))
    }

    /// Add one archive allocation before any LocalLeaf into it is installed.
    pub(crate) fn retain_archive_owner(&mut self, owner: &Arc<dyn ArchiveOwner>) {
        OwnerCover::retain(&mut self.0, owner);
    }

    #[cfg(debug_assertions)]
    fn covers(&self, current: &Option<Arc<OwnerCover>>) -> bool {
        let Some(current) = current else {
            return true;
        };
        let Some(replacement) = self.0.as_ref() else {
            return false;
        };
        Arc::ptr_eq(current, replacement) || replacement.covers(current)
    }

    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn owner_count(&self) -> usize {
        self.0.as_ref().map_or(0, |cover| cover.len)
    }
}

#[cfg(not(target_pointer_width = "64"))]
compile_error!("PATCH tagged pointers require 64-bit targets");

struct HashKeys {
    leaf: [u8; 16],
    exported_fingerprint: [u8; 16],
}

static HASH_KEYS: OnceLock<HashKeys> = OnceLock::new();

mod sealed {
    pub trait Sealed {}
}

/// Hash-maintenance policy used by [`PATCH`].
///
/// Implementations are sealed because PATCH treats equal subtree summaries as
/// equal key sets in `Eq`, union, intersection, and difference. An invalid
/// implementation would therefore be a semantic data-loss bug rather than a
/// merely weak cache hint.
pub trait PatchHash: sealed::Sealed + Send + Sync + 'static {
    /// Cached summary stored in every heap leaf and branch.
    type Digest: Copy + core::fmt::Debug + Eq + Send + Sync + 'static;

    /// Incremental state used while summarizing one branch's children.
    type BranchState;

    /// Whether child summaries form a commutative branch aggregate.
    ///
    /// Commutative policies can scan the physical cuckoo table directly;
    /// ordered policies are fed children by ascending edge byte.
    const COMMUTATIVE_BRANCH: bool;

    /// Whether [`Self::edit_branch`] provides an exact updated digest.
    /// False lets PATCH compile the edit call out and rebuild once on editor
    /// drop; true keeps the default edit path identical to its direct
    /// algebraic update.
    const INCREMENTAL_BRANCH: bool;

    /// Initialize any process-local state required by this policy.
    fn init();

    /// Summarize one complete key. Associated values never participate.
    fn leaf(bytes: &[u8]) -> Self::Digest;

    /// Begin summarizing a canonical branch.
    ///
    /// `representative` is any descendant key. `tree_to_key` identifies the
    /// first `end_depth` bytes that form the branch's canonical compressed
    /// prefix; bytes after that prefix must not affect the summary.
    fn begin_branch(
        representative: &[u8],
        tree_to_key: &[usize],
        end_depth: usize,
        child_count: usize,
        leaf_count: u64,
    ) -> Self::BranchState;

    /// Add one child in ascending edge-byte order.
    fn push_child(state: &mut Self::BranchState, edge: u8, leaf_count: u64, digest: Self::Digest);

    /// Finish one branch summary.
    fn finish_branch(state: Self::BranchState) -> Self::Digest;

    /// Update a branch summary after one child edit.
    ///
    /// PATCH calls this only when [`Self::INCREMENTAL_BRANCH`] is true, which
    /// is a sealed-trait promise that this operation is exact.
    fn edit_branch(
        current: Self::Digest,
        edge: u8,
        old: Option<Self::Digest>,
        new: Option<Self::Digest>,
    ) -> Self::Digest;
}

/// PATCH's default process-private SipHash-leaf/XOR summary policy.
///
/// Its raw aggregates remain crate-private. [`TribleSetFingerprint`](
/// crate::trible::TribleSetFingerprint) exposes only the separately keyed,
/// nonlinear blinding of a root aggregate.
#[derive(Clone, Copy, Debug, Default)]
pub struct XorSip128;

impl sealed::Sealed for XorSip128 {}

impl PatchHash for XorSip128 {
    type Digest = u128;
    type BranchState = u128;
    const COMMUTATIVE_BRANCH: bool = true;
    const INCREMENTAL_BRANCH: bool = true;

    #[inline]
    fn init() {
        init_hash_keys();
    }

    #[inline]
    fn leaf(bytes: &[u8]) -> Self::Digest {
        xor_hash_leaf_bytes(bytes)
    }

    #[inline]
    fn begin_branch(
        _representative: &[u8],
        _tree_to_key: &[usize],
        _end_depth: usize,
        _child_count: usize,
        _leaf_count: u64,
    ) -> Self::BranchState {
        0
    }

    #[inline]
    fn push_child(
        state: &mut Self::BranchState,
        _edge: u8,
        _leaf_count: u64,
        digest: Self::Digest,
    ) {
        *state ^= digest;
    }

    #[inline]
    fn finish_branch(state: Self::BranchState) -> Self::Digest {
        state
    }

    #[inline]
    fn edit_branch(
        mut current: Self::Digest,
        _edge: u8,
        old: Option<Self::Digest>,
        new: Option<Self::Digest>,
    ) -> Self::Digest {
        if let Some(old) = old {
            current ^= old;
        }
        if let Some(new) = new {
            current ^= new;
        }
        current
    }
}

/// Canonical BLAKE3 Merkle summaries for durable or adversarial PATCH uses.
///
/// Unlike [`XorSip128`], this policy commits to the canonical Patricia-trie
/// structure: leaf keys are domain-separated from branches, and every branch
/// commits to its key width, compressed-path bytes, fanout, subtree leaf
/// count, and each ascending `(edge, child leaf count, child digest)` tuple.
/// PATCH's trie shape is a function of its key set, so insertion order and
/// cuckoo-table placement do not affect the result.
///
/// BLAKE3's native chunk tree is intentionally not reused here. Its tree
/// describes fixed-size chunks of one byte stream, whereas PATCH is a sparse
/// radix tree whose fanout and compressed depths change under edits. Branches
/// are therefore framed explicitly and hashed with the ordinary streaming
/// API.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3Merkle;

impl sealed::Sealed for Blake3Merkle {}

impl PatchHash for Blake3Merkle {
    type Digest = [u8; 32];
    type BranchState = blake3::Hasher;
    const COMMUTATIVE_BRANCH: bool = false;
    const INCREMENTAL_BRANCH: bool = false;

    #[inline]
    fn init() {
        bytetable::init();
    }

    fn leaf(bytes: &[u8]) -> Self::Digest {
        let mut state = blake3::Hasher::new();
        state.update(b"triblespace.patch.leaf.v1\0");
        state.update(&(bytes.len() as u64).to_le_bytes());
        state.update(bytes);
        *state.finalize().as_bytes()
    }

    fn begin_branch(
        representative: &[u8],
        tree_to_key: &[usize],
        end_depth: usize,
        child_count: usize,
        leaf_count: u64,
    ) -> Self::BranchState {
        debug_assert_eq!(representative.len(), tree_to_key.len());
        debug_assert!(end_depth <= representative.len());
        let mut state = blake3::Hasher::new();
        state.update(b"triblespace.patch.branch.v2\0");
        state.update(&(representative.len() as u64).to_le_bytes());
        state.update(&(end_depth as u64).to_le_bytes());
        for &key_index in &tree_to_key[..end_depth] {
            state.update(&[representative[key_index]]);
        }
        state.update(&(child_count as u64).to_le_bytes());
        state.update(&leaf_count.to_le_bytes());
        state
    }

    #[inline]
    fn push_child(state: &mut Self::BranchState, edge: u8, leaf_count: u64, digest: Self::Digest) {
        state.update(&[edge]);
        state.update(&leaf_count.to_le_bytes());
        state.update(&digest);
    }

    #[inline]
    fn finish_branch(state: Self::BranchState) -> Self::Digest {
        *state.finalize().as_bytes()
    }

    #[inline]
    fn edit_branch(
        _current: Self::Digest,
        _edge: u8,
        _old: Option<Self::Digest>,
        _new: Option<Self::Digest>,
    ) -> Self::Digest {
        unreachable!("non-incremental PATCH hash policy was asked to edit a branch")
    }
}

/// Fixed input-domain marker for the public
/// [`TribleSetFingerprint`](crate::trible::TribleSetFingerprint)
/// blinding PRF.
///
/// A distinct random key already separates this use from PATCH leaf hashing;
/// the marker additionally prevents this output from being confused with a
/// future use of the same key over an untyped 128-bit value.
const EXPORTED_FINGERPRINT_DOMAIN: [u8; 16] = *b"TribleSet.fp.v1\0";

/// Minimum `other.leaf_count` at which [`Head::par_union`] takes the
/// scatter + bitset + rayon::scope-spawn path on the equal-depth-
/// branch arm. Below this, the per-key `modify_child` loop wins
/// because asymmetric merges only touch a handful of slots.
#[cfg(feature = "parallel")]
const PARALLEL_PATCH_UNION_THRESHOLD: usize = 4096;

/// Parallel-aware PATCH union, with a shared work-stealing budget
/// carried across the entire recursive descent.
///
/// Two-phase model per parallel call:
///   1. Spawn phase (collect sequentially, dispatch per child):
///      drain "both" pairs, for each: claim 1 unit from the
///      shared budget — if successful, spawn the child union as
///      a `rayon::scope` task; if budget is exhausted, run the
///      child serially via `Head::union`.
///   2. Install phase (purely serial): scatter-collected resolved
///      heads + single-side pass-throughs land in the parent
///      branch, then `recompute_aggregates` rebuilds the
///      hash/leaf_count/segment_count/childleaf in one pass.
///
/// The budget is a single shared atomic — `num_threads²` total
/// spawns across the entire descent, after which everything is
/// sequential. This caps overhead without restricting the depth
/// at which parallelism is reached: a heavy subtree near the
/// root claims many units; a balanced descent spreads them.
#[cfg(feature = "parallel")]
mod parallel_union {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Carries the shared spawn budget across recursive
    /// `par_union_with_ctx` calls.
    pub(crate) struct ParUnionCtx {
        pub(crate) budget: AtomicUsize,
    }

    impl ParUnionCtx {
        pub(crate) fn new() -> Self {
            let n = rayon::current_num_threads();
            Self {
                budget: AtomicUsize::new(n.saturating_mul(n).max(2)),
            }
        }

        /// Try to claim one spawn unit. Returns `true` if a unit was
        /// claimed (caller should spawn), `false` if the budget was
        /// already exhausted (caller should run serially).
        ///
        /// A naive `fetch_sub(1)` would wrap `0 → usize::MAX` on
        /// over-subtract, briefly letting other threads see a huge
        /// budget — so we use compare-exchange to refuse the claim
        /// without ever observing the underflow.
        pub(crate) fn try_claim(&self) -> bool {
            let mut current = self.budget.load(Ordering::Relaxed);
            loop {
                if current == 0 {
                    return false;
                }
                match self.budget.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return true,
                    Err(observed) => current = observed,
                }
            }
        }
    }

    /// Raw-pointer wrapper for the scatter-write target. Each
    /// spawned task writes to `resolved[k]` for its specific key
    /// byte `k`; keys are pairwise distinct by construction (each
    /// "both" bit in the partition uniquely identifies a slot), so
    /// the writes are non-aliasing despite sharing a `*mut` across
    /// threads.
    ///
    /// `write_at` exists as an inherent method (rather than callers
    /// reading the `*mut` field directly) so that move closures
    /// capture the whole wrapper — Rust 2021 precise-capture would
    /// otherwise grab the raw pointer field, dropping the manual
    /// `Send`/`Sync` impls and triggering a Send error.
    pub(crate) struct ScatterPtr<T>(pub *mut T);

    // Manual `Copy`/`Clone` impls so `T` doesn't get a spurious
    // `T: Copy` / `T: Clone` bound from derive — the wrapper holds a
    // raw pointer, which is always `Copy` regardless of `T`.
    impl<T> Clone for ScatterPtr<T> {
        fn clone(&self) -> Self {
            *self
        }
    }
    impl<T> Copy for ScatterPtr<T> {}

    // SAFETY: tasks only transfer owned `T` values into pairwise-disjoint
    // output slots. The wrapper never exposes a reference to a stored `T`, so
    // moving those values between threads requires `T: Send`, not `T: Sync`.
    unsafe impl<T: Send> Send for ScatterPtr<T> {}
    unsafe impl<T: Send> Sync for ScatterPtr<T> {}

    impl<T> ScatterPtr<T> {
        /// SAFETY: `i` must be in-bounds of the underlying buffer,
        /// and the caller must guarantee no other thread is writing
        /// to slot `i` concurrently.
        pub(crate) unsafe fn write_at(self, i: usize, v: T) {
            self.0.add(i).write(v);
        }
    }
}

/// Return the immutable process-local PATCH hash-key bundle, initializing all
/// randomness PATCH construction relies on exactly once.
fn hash_keys() -> &'static HashKeys {
    HASH_KEYS.get_or_init(|| {
        bytetable::init();

        let mut rng = thread_rng();
        let mut leaf = [0u8; 16];
        let mut exported_fingerprint = [0u8; 16];
        rng.fill_bytes(&mut leaf);
        // Make key separation exact rather than adding a second, avoidable
        // 2^-128 assumption to the public-boundary argument.
        loop {
            rng.fill_bytes(&mut exported_fingerprint);
            if exported_fingerprint != leaf {
                break;
            }
        }
        HashKeys {
            leaf,
            exported_fingerprint,
        }
    })
}

/// Initialize PATCH's process-local hash and byte-table randomness.
///
/// Hashing entry points also call [`hash_keys`] themselves, so safe `Entry`
/// construction before the first [`PATCH`] cannot observe an uninitialized
/// key.
pub(crate) fn init_hash_keys() {
    let _ = hash_keys();
}

/// Hash one PATCH leaf through the initialized process-local key accessor.
#[inline]
fn xor_hash_leaf_bytes(bytes: &[u8]) -> u128 {
    use siphasher::sip128::SipHasher24;

    SipHasher24::new_with_key(&hash_keys().leaf)
        .hash(bytes)
        .into()
}

/// Apply the public-fingerprint PRF under an explicit key.
///
/// Keeping this transformation separate makes the proof boundary visible:
/// PATCH's internal aggregate is linear, while values crossing the public API
/// pass through this nonlinear keyed function first.
#[inline]
fn blind_root_hash_with_key(root_hash: u128, key: &[u8; 16]) -> u128 {
    use siphasher::sip128::SipHasher24;

    let mut input = [0u8; 32];
    input[..16].copy_from_slice(&EXPORTED_FINGERPRINT_DOMAIN);
    input[16..].copy_from_slice(&root_hash.to_le_bytes());
    SipHasher24::new_with_key(key).hash(&input).into()
}

/// Blind PATCH's internal root aggregate for public, process-local cache keys.
///
/// The raw root is an XOR of keyed leaf hashes and must not be exposed: chosen
/// singleton outputs would reveal vectors from which a linear dependency can
/// be constructed. This distinct-key, domain-separated PRF preserves equality
/// within the process without exposing that algebra. `None` remains the unique
/// empty-set representation.
#[inline]
pub(crate) fn blind_root_hash(root_hash: Option<u128>) -> Option<u128> {
    let root_hash = root_hash?;
    Some(blind_root_hash_with_key(
        root_hash,
        &hash_keys().exported_fingerprint,
    ))
}

/// Hash one PATCH key with the process-local internal leaf key.
///
/// Bulk archive construction calls this once per source row and shares the
/// result across all six index builds. Initializing here is important because
/// that path hashes before it constructs its first [`PATCH`].
#[cfg(any(test, feature = "parallel"))]
#[inline]
pub(crate) fn hash_key(bytes: &[u8]) -> u128 {
    XorSip128::leaf(bytes)
}

/// Builds a per-byte segment map from the segment lengths.
///
/// The returned table maps each key byte to its segment index.
pub const fn build_segmentation<const N: usize, const M: usize>(lens: [usize; M]) -> [usize; N] {
    let mut res = [0; N];
    let mut seg = 0;
    let mut off = 0;
    while seg < M {
        let len = lens[seg];
        let mut i = 0;
        while i < len {
            res[off + i] = seg;
            i += 1;
        }
        off += len;
        seg += 1;
    }
    res
}

/// Builds an identity permutation table of length `N`.
pub const fn identity_map<const N: usize>() -> [usize; N] {
    let mut res = [0; N];
    let mut i = 0;
    while i < N {
        res[i] = i;
        i += 1;
    }
    res
}

/// Builds a table translating indices from key order to tree order.
///
/// `lens` describes the segment lengths in key order and `perm` is the
/// permutation of those segments in tree order.
pub const fn build_key_to_tree<const N: usize, const M: usize>(
    lens: [usize; M],
    perm: [usize; M],
) -> [usize; N] {
    let mut key_starts = [0; M];
    let mut off = 0;
    let mut i = 0;
    while i < M {
        key_starts[i] = off;
        off += lens[i];
        i += 1;
    }

    let mut tree_starts = [0; M];
    off = 0;
    i = 0;
    while i < M {
        let seg = perm[i];
        tree_starts[seg] = off;
        off += lens[seg];
        i += 1;
    }

    let mut res = [0; N];
    let mut seg = 0;
    while seg < M {
        let len = lens[seg];
        let ks = key_starts[seg];
        let ts = tree_starts[seg];
        let mut j = 0;
        while j < len {
            res[ks + j] = ts + j;
            j += 1;
        }
        seg += 1;
    }
    res
}

/// Inverts a permutation table.
pub const fn invert<const N: usize>(arr: [usize; N]) -> [usize; N] {
    let mut res = [0; N];
    let mut i = 0;
    while i < N {
        res[arr[i]] = i;
        i += 1;
    }
    res
}

/// For each tree-depth `d`, the end (exclusive) of the segment that contains
/// `d`, derived from a segmentation table (in key order) and a tree→key map.
///
/// Each logical segment is contiguous in tree order, so the boundary after a
/// depth is simply the first deeper depth whose segment id differs (or
/// `KEY_LEN`). Used by [`KeySchema::next_boundary`] / `SEGMENT_ENDS` to cap
/// variable-width branch spans so they never cross a segment checkpoint.
pub const fn build_segment_ends<const N: usize>(
    segments: [usize; N],
    tree_to_key: [usize; N],
) -> [usize; N] {
    let mut ends = [0usize; N];
    let mut d = 0;
    while d < N {
        let seg = segments[tree_to_key[d]];
        let mut e = d + 1;
        while e < N && segments[tree_to_key[e]] == seg {
            e += 1;
        }
        ends[d] = e;
        d += 1;
    }
    ends
}

#[doc(hidden)]
#[macro_export]
macro_rules! key_segmentation {
    (@count $($e:expr),* $(,)?) => {
        <[()]>::len(&[$($crate::key_segmentation!(@sub $e)),*])
    };
    (@sub $e:expr) => { () };
    ($(#[$meta:meta])* $name:ident, $len:expr, [$($seg_len:expr),+ $(,)?]) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug)]
        pub struct $name;
        impl $name {
            pub const SEG_LENS: [usize; $crate::key_segmentation!(@count $($seg_len),*)] = [$($seg_len),*];
        }
        impl $crate::patch::KeySegmentation<$len> for $name {
            const SEGMENTS: [usize; $len] = $crate::patch::build_segmentation::<$len, {$crate::key_segmentation!(@count $($seg_len),*)}>(Self::SEG_LENS);
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! key_schema {
    (@count $($e:expr),* $(,)?) => {
        <[()]>::len(&[$($crate::key_schema!(@sub $e)),*])
    };
    (@sub $e:expr) => { () };
    ($(#[$meta:meta])* $name:ident, $seg:ty, $len:expr, [$($perm:expr),+ $(,)?]) => {
        $(#[$meta])*
        #[derive(Copy, Clone, Debug)]
        pub struct $name;
        impl $crate::patch::KeySchema<$len> for $name {
            type Segmentation = $seg;
            const SEGMENT_PERM: &'static [usize] = &[$($perm),*];
            const KEY_TO_TREE: [usize; $len] = $crate::patch::build_key_to_tree::<$len, {$crate::key_schema!(@count $($perm),*)}>(<$seg>::SEG_LENS, [$($perm),*]);
            const TREE_TO_KEY: [usize; $len] = $crate::patch::invert(Self::KEY_TO_TREE);
        }
    };
}

/// A trait is used to provide a re-ordered view of the keys stored in the PATCH.
/// This allows for different PATCH instances share the same leaf nodes,
/// independent of the key ordering used in the tree.
pub trait KeySchema<const KEY_LEN: usize>: Copy + Clone + Debug {
    /// The segmentation this ordering operates over.
    type Segmentation: KeySegmentation<KEY_LEN>;
    /// Order of segments from key layout to tree layout.
    const SEGMENT_PERM: &'static [usize];
    /// Maps each key index to its position in the tree view.
    const KEY_TO_TREE: [usize; KEY_LEN];
    /// Maps each tree index to its position in the key view.
    const TREE_TO_KEY: [usize; KEY_LEN];

    /// For each tree-depth, the exclusive end of the segment containing it.
    ///
    /// Purely additive (a provided default derived from `Segmentation` +
    /// `TREE_TO_KEY`); it does not affect single-byte PATCH behaviour. A
    /// variable-width trie would use it to start branch spans segment-wide and
    /// guarantee a span never crosses a checkpoint. For EAV over a 64-byte
    /// trible this yields ends `{16,32,64}`; for VEA `{32,48,64}`.
    const SEGMENT_ENDS: [usize; KEY_LEN] = build_segment_ends::<KEY_LEN>(
        <Self::Segmentation as KeySegmentation<KEY_LEN>>::SEGMENTS,
        Self::TREE_TO_KEY,
    );

    /// The exclusive end of the segment containing tree-depth `tree_depth`.
    ///
    /// A variable-width branch starting at `span_start` may widen its span up
    /// to `next_boundary(span_start)` but no further, so each branch stays
    /// within a single segment.
    fn next_boundary(tree_depth: usize) -> usize {
        Self::SEGMENT_ENDS[tree_depth]
    }

    /// Reorders the key from the shared key ordering to the tree ordering.
    fn tree_ordered(key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let mut new_key = [0; KEY_LEN];
        let mut i = 0;
        while i < KEY_LEN {
            new_key[Self::KEY_TO_TREE[i]] = key[i];
            i += 1;
        }
        new_key
    }

    /// Reorders the key from the tree ordering to the shared key ordering.
    fn key_ordered(tree_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let mut new_key = [0; KEY_LEN];
        let mut i = 0;
        while i < KEY_LEN {
            new_key[Self::TREE_TO_KEY[i]] = tree_key[i];
            i += 1;
        }
        new_key
    }

    /// Return the segment index for the byte at `at_depth` in tree ordering.
    ///
    /// Default implementation reads the static segmentation table and the
    /// tree->key mapping. Having this as a method makes call sites clearer and
    /// reduces the verbosity of expressions that access the segmentation table.
    fn segment_of_tree_depth(at_depth: usize) -> usize {
        <Self::Segmentation as KeySegmentation<KEY_LEN>>::SEGMENTS[Self::TREE_TO_KEY[at_depth]]
    }

    /// Return true if the tree-ordered bytes at `a` and `b` belong to the same
    /// logical segment.
    fn same_segment_tree(a: usize, b: usize) -> bool {
        <Self::Segmentation as KeySegmentation<KEY_LEN>>::SEGMENTS[Self::TREE_TO_KEY[a]]
            == <Self::Segmentation as KeySegmentation<KEY_LEN>>::SEGMENTS[Self::TREE_TO_KEY[b]]
    }
}

/// This trait is used to segment keys stored in the PATCH.
/// The segmentation is used to determine sub-fields of the key,
/// allowing for segment based operations, like counting the number
/// of elements in a segment with a given prefix without traversing the tree.
///
/// Note that the segmentation is defined on the shared key ordering,
/// and should thus be only implemented once, independent of additional key orderings.
///
/// See [TribleSegmentation](crate::trible::TribleSegmentation) for an example that segments keys into entity,
/// attribute, and value segments.
pub trait KeySegmentation<const KEY_LEN: usize>: Copy + Clone + Debug {
    /// Segment index for each position in the key.
    const SEGMENTS: [usize; KEY_LEN];
}

/// A `KeySchema` that does not reorder the keys.
/// This is useful for keys that are already ordered in the desired way.
/// This is the default ordering.
#[derive(Copy, Clone, Debug)]
pub struct IdentitySchema {}

/// A `KeySegmentation` that does not segment the keys.
/// This is useful for keys that do not have a segment structure.
/// This is the default segmentation.
#[derive(Copy, Clone, Debug)]
pub struct SingleSegmentation {}
impl<const KEY_LEN: usize> KeySchema<KEY_LEN> for IdentitySchema {
    type Segmentation = SingleSegmentation;
    const SEGMENT_PERM: &'static [usize] = &[0];
    const KEY_TO_TREE: [usize; KEY_LEN] = identity_map::<KEY_LEN>();
    const TREE_TO_KEY: [usize; KEY_LEN] = identity_map::<KEY_LEN>();
}

impl<const KEY_LEN: usize> KeySegmentation<KEY_LEN> for SingleSegmentation {
    const SEGMENTS: [usize; KEY_LEN] = [0; KEY_LEN];
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[repr(u8)]
pub(crate) enum HeadTag {
    // Stored in the low 4 bits of `Head::tptr` (see Head::new).
    //
    // Branch values encode log2(branch_size) (i.e. `Branch2 == 1`, `Branch256
    // == 8`). `0` is reserved for leaf nodes, which lets us compute the branch
    // size as `1 << tag` without any offset. The derived `Ord` therefore
    // compares branch sizes — `tag_a > tag_b` ⟺ `size_a > size_b`, and the
    // 2× swap threshold reduces to a single tag-byte compare.
    //
    // `LocalLeaf` (9) is appended at the end so the Branch widths' `1 << tag`
    // arithmetic and the Leaf-vs-Branch threshold comparisons are unaffected.
    // It represents a leaf whose key bytes live in an archive's mmap'd buffer,
    // referenced via a thin pointer in the Head body slot rather than via a
    // heap-allocated `Leaf<KEY_LEN, V>`. Lifetime is guaranteed by the exact
    // owner set on the enclosing PATCH value.
    Leaf = 0,
    Branch2 = 1,
    Branch4 = 2,
    Branch8 = 3,
    Branch16 = 4,
    Branch32 = 5,
    Branch64 = 6,
    Branch128 = 7,
    Branch256 = 8,
    LocalLeaf = 9,
}

impl HeadTag {
    #[inline]
    fn from_raw(raw: u8) -> Self {
        debug_assert!(raw <= HeadTag::LocalLeaf as u8);
        // SAFETY: `HeadTag` is `#[repr(u8)]` with a contiguous discriminant
        // range 0..=9. The tag bits are written by Head::new/set_body and
        // Branch::tag, which only emit valid discriminants.
        unsafe { std::mem::transmute(raw) }
    }
}

pub(crate) enum BodyPtr<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> {
    Leaf(NonNull<Leaf<KEY_LEN, V, H>>),
    /// Thin pointer to a `[u8; KEY_LEN]` trible living in an archive's
    /// mmap'd buffer. Lifetime is implicit — guaranteed by the enclosing
    /// PATCH's owner set.
    LocalLeaf(NonNull<[u8; KEY_LEN]>),
    Branch(branch::BranchNN<KEY_LEN, O, V, H>),
}

/// Immutable borrow view of a Head body.
/// Returned by `body_ref()` and tied to the lifetime of the `&Head`.
pub(crate) enum BodyRef<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> {
    Leaf(&'a Leaf<KEY_LEN, V, H>),
    /// Reference to a trible's bytes within an archive. The slice's
    /// lifetime is bound to `&'a Head` via the body pointer; the actual
    /// underlying allocation is kept alive by the enclosing PATCH.
    LocalLeaf(&'a [u8; KEY_LEN]),
    Branch(&'a Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>),
}

/// Mutation-capable borrow view of a Head body.
/// Returned by `body_mut()` and tied to the lifetime of the `&mut Head`.
///
/// Branches are copy-on-write and therefore unique before this view exposes
/// them mutably. Heap leaves, like archive-local leaves, may still be shared
/// by another PATCH snapshot, so both leaf variants are exposed read-only.
pub(crate) enum BodyMut<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> {
    Leaf(&'a Leaf<KEY_LEN, V, H>),
    /// `LocalLeaf` is read-only by construction (it points into immutable
    /// archive bytes), so the mutable view yields a shared reference.
    /// Structural operations may move the Head while its PATCH owner guard
    /// remains live.
    LocalLeaf(&'a [u8; KEY_LEN]),
    Branch(&'a mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>),
}

pub(crate) trait Body {
    fn tag(body: NonNull<Self>) -> HeadTag;
}

#[repr(C)]
pub(crate) struct Head<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash = XorSip128> {
    tptr: std::ptr::NonNull<u8>,
    key_ordering: PhantomData<O>,
    key_segments: PhantomData<O::Segmentation>,
    value: PhantomData<V>,
    hash_policy: PhantomData<H>,
}

// SAFETY: a Head owns a persistent, atomically reference-counted node. Cloned
// Heads may expose the same Leaf<V> on different threads, and the final owner
// may drop V on either thread, so both auto traits require V: Send + Sync.
// O and O::Segmentation are ignored deliberately: they are type-level schemas
// used only through associated constants and functions; no value or reference
// of either type is stored in, or accessed through, a Head.
unsafe impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V: Send + Sync, H: PatchHash> Send
    for Head<KEY_LEN, O, V, H>
{
}

// SAFETY: the same shared-leaf and type-level-schema argument above applies.
unsafe impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V: Send + Sync, H: PatchHash> Sync
    for Head<KEY_LEN, O, V, H>
{
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Head<KEY_LEN, O, V, H> {
    // Tagged pointer layout (64-bit only):
    // - bits 0..=3:   HeadTag (requires 16-byte aligned bodies)
    // - bits 4..=55:  body pointer bits (52 bits)
    // - bits 56..=63: key byte for cuckoo table lookup
    const TAG_MASK: u64 = 0x0f;
    const BODY_MASK: u64 = 0x00_ff_ff_ff_ff_ff_ff_f0;
    const KEY_MASK: u64 = 0xff_00_00_00_00_00_00_00;

    pub(crate) fn new<T: Body + ?Sized>(key: u8, body: NonNull<T>) -> Self {
        unsafe {
            let tptr =
                std::ptr::NonNull::new_unchecked((body.as_ptr() as *mut u8).map_addr(|addr| {
                    debug_assert_eq!(addr as u64 & Self::TAG_MASK, 0);
                    ((addr as u64 & Self::BODY_MASK)
                        | ((key as u64) << 56)
                        | (<T as Body>::tag(body) as u64)) as usize
                }));
            Self {
                tptr,
                key_ordering: PhantomData,
                key_segments: PhantomData,
                value: PhantomData,
                hash_policy: PhantomData,
            }
        }
    }

    /// Constructs a `LocalLeaf` Head pointing directly at a `[u8; KEY_LEN]`
    /// trible inside an archive's mmap'd buffer. The pointer's address must
    /// be 16-byte aligned (so the low 4 bits are free for the `HeadTag`);
    /// for `SimpleArchive` buffers this holds whenever the base allocation
    /// is 16-byte aligned and tribles are 64 bytes wide (every offset is a
    /// multiple of 16).
    ///
    /// # Safety
    /// - `trible_ptr` must remain valid for at least as long as this Head
    ///   exists, which is the caller's responsibility to arrange — typically
    ///   by retaining its `Arc<dyn ArchiveOwner>` in the enclosing PATCH's
    ///   root owner set.
    /// - The pointed-to bytes must remain fully initialized and immutable for
    ///   that lifetime, including through concurrent aliases or interior
    ///   mutability. LocalLeaf routing and fingerprints read them through
    ///   shared references.
    /// - The pointer must be 16-byte aligned; this is debug-asserted.
    pub(crate) unsafe fn new_local_leaf(key: u8, trible_ptr: NonNull<[u8; KEY_LEN]>) -> Self {
        unsafe {
            let tptr = std::ptr::NonNull::new_unchecked((trible_ptr.as_ptr() as *mut u8).map_addr(
                |addr| {
                    debug_assert_eq!(
                        addr as u64 & Self::TAG_MASK,
                        0,
                        "LocalLeaf trible pointer must be 16-byte aligned"
                    );
                    ((addr as u64 & Self::BODY_MASK)
                        | ((key as u64) << 56)
                        | (HeadTag::LocalLeaf as u64)) as usize
                },
            ));
            Self {
                tptr,
                key_ordering: PhantomData,
                key_segments: PhantomData,
                value: PhantomData,
                hash_policy: PhantomData,
            }
        }
    }

    #[inline]
    pub(crate) fn tag(&self) -> HeadTag {
        HeadTag::from_raw((self.tptr.as_ptr() as u64 & Self::TAG_MASK) as u8)
    }

    #[inline]
    pub(crate) fn key(&self) -> u8 {
        (self.tptr.as_ptr() as u64 >> 56) as u8
    }

    #[inline]
    pub(crate) fn with_key(mut self, key: u8) -> Self {
        self.tptr =
            std::ptr::NonNull::new(self.tptr.as_ptr().map_addr(|addr| {
                ((addr as u64 & !Self::KEY_MASK) | ((key as u64) << 56)) as usize
            }))
            .unwrap();
        self
    }

    #[inline]
    pub(crate) fn set_body<T: Body + ?Sized>(&mut self, body: NonNull<T>) {
        unsafe {
            self.tptr = NonNull::new_unchecked((body.as_ptr() as *mut u8).map_addr(|addr| {
                debug_assert_eq!(addr as u64 & Self::TAG_MASK, 0);
                ((addr as u64 & Self::BODY_MASK)
                    | (self.tptr.as_ptr() as u64 & Self::KEY_MASK)
                    | (<T as Body>::tag(body) as u64)) as usize
            }))
        }
    }

    pub(crate) fn with_start(self, new_start_depth: usize) -> Head<KEY_LEN, O, V, H> {
        let leaf_key = self.childleaf_key();
        let i = O::TREE_TO_KEY[new_start_depth];
        let key = leaf_key[i];
        self.with_key(key)
    }

    // Removed childleaf_matches_key_from in favor of composing the existing
    // has_prefix primitives directly at call sites. Use
    // `self.has_prefix::<KEY_LEN>(at_depth, key)` or for partial checks
    // `self.childleaf().has_prefix::<O>(at_depth, &key[..limit])` instead.

    pub(crate) fn body(&self) -> BodyPtr<KEY_LEN, O, V, H> {
        unsafe {
            let ptr = NonNull::new_unchecked(self.tptr.as_ptr().map_addr(|addr| {
                let masked = (addr as u64) & Self::BODY_MASK;
                masked as usize
            }));
            match self.tag() {
                HeadTag::Leaf => BodyPtr::Leaf(ptr.cast()),
                HeadTag::LocalLeaf => BodyPtr::LocalLeaf(ptr.cast()),
                branch_tag => {
                    let count = 1 << (branch_tag as usize);
                    BodyPtr::Branch(NonNull::new_unchecked(std::ptr::slice_from_raw_parts(
                        ptr.as_ptr(),
                        count,
                    )
                        as *mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>))
                }
            }
        }
    }

    pub(crate) fn body_mut(&mut self) -> BodyMut<'_, KEY_LEN, O, V, H> {
        unsafe {
            match self.body() {
                BodyPtr::Leaf(leaf) => BodyMut::Leaf(leaf.as_ref()),
                BodyPtr::LocalLeaf(ptr) => BodyMut::LocalLeaf(ptr.as_ref()),
                BodyPtr::Branch(mut branch) => {
                    // Ensure ownership: try copy-on-write and update local pointer if needed.
                    let mut branch_nn = branch;
                    if Branch::rc_cow(&mut branch_nn).is_some() {
                        self.set_body(branch_nn);
                        BodyMut::Branch(branch_nn.as_mut())
                    } else {
                        BodyMut::Branch(branch.as_mut())
                    }
                }
            }
        }
    }

    /// Returns an immutable borrow of the body (Leaf, LocalLeaf, or Branch)
    /// tied to &self.
    pub(crate) fn body_ref(&self) -> BodyRef<'_, KEY_LEN, O, V, H> {
        match self.body() {
            BodyPtr::Leaf(nn) => BodyRef::Leaf(unsafe { nn.as_ref() }),
            BodyPtr::LocalLeaf(nn) => BodyRef::LocalLeaf(unsafe { nn.as_ref() }),
            BodyPtr::Branch(nn) => BodyRef::Branch(unsafe { nn.as_ref() }),
        }
    }

    pub(crate) fn count(&self) -> u64 {
        match self.body_ref() {
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => 1,
            BodyRef::Branch(branch) => branch.leaf_count,
        }
    }

    #[inline]
    fn is_archive_singleton_pair(&self, other: &Self) -> bool {
        matches!(
            (self.tag(), other.tag()),
            (HeadTag::LocalLeaf, HeadTag::Leaf | HeadTag::LocalLeaf)
                | (HeadTag::Leaf, HeadTag::LocalLeaf)
        )
    }

    /// Returns whether cardinality still permits equal fingerprints when an
    /// archive-backed leaf is involved. A `LocalLeaf` represents exactly one
    /// key, while a Branch's count is cached; all pairs without a `LocalLeaf`
    /// retain the existing fingerprint path unchanged.
    #[inline]
    fn local_leaf_cardinality_allows_equality(&self, other: &Self) -> bool {
        match (self.tag(), other.tag()) {
            (HeadTag::LocalLeaf, _) => other.count() == 1,
            (_, HeadTag::LocalLeaf) => self.count() == 1,
            _ => true,
        }
    }

    pub(crate) fn count_segment(&self, at_depth: usize) -> u64 {
        match self.body_ref() {
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => 1,
            BodyRef::Branch(branch) => branch.count_segment(at_depth),
        }
    }

    pub(crate) fn hash(&self) -> H::Digest {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.hash,
            BodyRef::LocalLeaf(bytes) => H::leaf(&bytes[..]),
            BodyRef::Branch(branch) => branch.hash,
        }
    }

    pub(crate) fn end_depth(&self) -> usize {
        match self.body_ref() {
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => KEY_LEN,
            BodyRef::Branch(branch) => branch.end_depth as usize,
        }
    }

    /// Returns the raw key-bytes pointer of the representative child
    /// leaf for use in low-level operations (Branch construction,
    /// invariant checks). For heap `Leaf`, that's `&leaf.key`; for
    /// `LocalLeaf`, the archive-resident bytes pointer; for `Branch`,
    /// the branch's already-computed childleaf pointer.
    pub(crate) fn childleaf_ptr(&self) -> *const [u8; KEY_LEN] {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => &leaf.key as *const [u8; KEY_LEN],
            BodyRef::LocalLeaf(bytes) => bytes as *const [u8; KEY_LEN],
            BodyRef::Branch(branch) => branch.childleaf_ptr(),
        }
    }

    pub(crate) fn childleaf_key(&self) -> &[u8; KEY_LEN] {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => &leaf.key,
            BodyRef::LocalLeaf(bytes) => bytes,
            BodyRef::Branch(branch) => branch.childleaf_key(),
        }
    }

    // Slot wrapper defined at module level (moved to below the impl block)

    /// Find the first depth in [start_depth, limit) where the tree-ordered
    /// bytes of `self` and `other` differ. The comparison limit is computed
    /// as min(self.end_depth(), other.end_depth(), KEY_LEN) which is the
    /// natural bound for comparing two heads. Returns `Some((depth, a, b))`
    /// where `a` and `b` are the differing bytes at that depth, or `None`
    /// if no divergence is found in the range.
    pub(crate) fn first_divergence(
        &self,
        other: &Self,
        start_depth: usize,
    ) -> Option<(usize, u8, u8)> {
        let limit = std::cmp::min(std::cmp::min(self.end_depth(), other.end_depth()), KEY_LEN);
        debug_assert!(limit <= KEY_LEN);
        let this_key = self.childleaf_key();
        let other_key = other.childleaf_key();
        let mut depth = start_depth;
        while depth < limit {
            let i = O::TREE_TO_KEY[depth];
            let a = this_key[i];
            let b = other_key[i];
            if a != b {
                return Some((depth, a, b));
            }
            depth += 1;
        }
        None
    }

    // Mutable access to the child slots for this head. If the head is a
    // branch, returns a mutable slice referencing the underlying child table
    // (each element is Option<Head>). If the head is a leaf an empty slice
    // is returned.
    //
    // The caller receives a &mut slice tied to the borrow of `self` and may
    // reorder entries in-place (e.g., sort_unstable) and then take them using
    // `Option::take()` to extract Head values. The call uses `body_mut()` so
    // COW semantics are preserved and callers have exclusive access to the
    // branch storage while the mutable borrow lasts.
    // NOTE: mut_children removed — prefer matching on BodyRef returned by
    // `body_mut()` and operating directly on the `&mut Branch` reference.

    /// Remove a matching leaf. A detached heap leaf is returned without being
    /// dropped; archive-local leaves are dropped immediately while the enclosing
    /// PATCH owner cover is still installed. Their backing owner is retired
    /// separately at the public mutation boundary if the root empties.
    #[must_use = "drop the retired heap leaf only after the replacement root is committed"]
    pub(crate) fn remove_leaf(
        slot: &mut Option<Self>,
        leaf_key: &[u8; KEY_LEN],
        start_depth: usize,
    ) -> Option<Self> {
        if let Some(this) = slot {
            let end_depth = std::cmp::min(this.end_depth(), KEY_LEN);
            // Check reachable equality by asking the head to test the prefix
            // up to its end_depth. Using the head/leaf primitive centralises the
            // unsafe deref into Branch::childleaf()/Leaf::has_prefix.
            if !this.has_prefix::<KEY_LEN>(start_depth, leaf_key) {
                return None;
            }
            match this.tag() {
                HeadTag::Leaf => {
                    // Keep the removed value alive until every ancestor has
                    // repaired its aggregates and collapsed any unary branch.
                    slot.take()
                }
                HeadTag::LocalLeaf => {
                    // A LocalLeaf owns no allocation itself. Remove its Head
                    // while the PATCH-level owner cover still guards the raw
                    // bytes; never let a naked LocalLeaf escape as retirement.
                    drop(slot.take());
                    None
                }
                _ => {
                    let mut retired_leaf = None;
                    let mut ed = crate::patch::branch::BranchMut::from_head(this);
                    let key = leaf_key[end_depth];
                    ed.modify_child(key, |mut opt| {
                        retired_leaf = Self::remove_leaf(&mut opt, leaf_key, end_depth);
                        opt
                    });

                    // If the branch now contains a single remaining child we
                    // collapse the branch upward into that child. We must pull
                    // the remaining child out while `ed` is still borrowed,
                    // then drop `ed` before writing back into `slot` to avoid
                    // double mutable borrows of the slot.
                    let occupied_children = ed.child_table.iter().flatten().take(2).count();
                    if occupied_children == 0 {
                        drop(ed);
                        drop(slot.take());
                    } else if occupied_children == 1 {
                        let mut remaining: Option<Head<KEY_LEN, O, V, H>> = None;
                        for slot_child in &mut ed.child_table {
                            if let Some(child) = slot_child.take() {
                                remaining = Some(child.with_start(start_depth));
                                break;
                            }
                        }
                        drop(ed);
                        if let Some(child) = remaining {
                            slot.replace(child);
                        }
                    } else {
                        // Ensure the editor commits the final pointer into the
                        // head when the branch does not collapse.
                        drop(ed);
                    }
                    retired_leaf
                }
            }
        } else {
            None
        }
    }

    // NOTE: slot-level wrappers removed; callers should take the slot and call
    // the owned helpers (insert_leaf / replace_leaf / union)
    // directly. This reduces the indirection and keeps ownership semantics
    // explicit at the call site.

    // Owned variants of the slot-based helpers. These accept the existing
    // Head by value and return the new Head after performing the
    // modification. They are used with the split `insert_child` /
    // `update_child` APIs so we no longer need `Branch::upsert_child`.
    pub(crate) fn insert_leaf(mut this: Self, leaf: Self, start_depth: usize) -> Self {
        if let Some((depth, this_byte_key, leaf_byte_key)) =
            this.first_divergence(&leaf, start_depth)
        {
            let old_key = this.key();
            let new_body = crate::patch::branch::Branch::new(
                depth,
                this.with_key(this_byte_key),
                leaf.with_key(leaf_byte_key),
            );
            return Head::new(old_key, new_body);
        }

        let end_depth = this.end_depth();
        if end_depth != KEY_LEN {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
            let inserted = leaf.with_start(ed.end_depth as usize);
            let key = inserted.key();
            ed.modify_child(key, |opt| match opt {
                Some(old) => Some(Head::insert_leaf(old, inserted, end_depth)),
                None => Some(inserted),
            });
        }
        this
    }
}

// Archive-aware insertion path, available only when V = ().
impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, H: PatchHash> Head<KEY_LEN, O, (), H> {
    /// Inserts a LocalLeaf whose hash was already computed by ArchiveEntry.
    /// The enclosing PATCH retains the leaf's owner independently of trie
    /// shape, so LocalLeaves can use the ordinary structural operations.
    pub(crate) fn insert_archive_leaf(
        mut this: Self,
        leaf: Self,
        leaf_hash: H::Digest,
        start_depth: usize,
    ) -> Self {
        if let Some((depth, this_byte_key, leaf_byte_key)) =
            this.first_divergence(&leaf, start_depth)
        {
            let old_key = this.key();
            let new_body = crate::patch::branch::Branch::new_with_rchild_hash(
                depth,
                this.with_key(this_byte_key),
                leaf.with_key(leaf_byte_key),
                leaf_hash,
            );
            return Head::new(old_key, new_body);
        }

        let end_depth = this.end_depth();
        if end_depth != KEY_LEN {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
            let inserted = leaf.with_start(ed.end_depth as usize);
            let key = inserted.key();
            ed.modify_child_with_inserted_hint(key, leaf_hash, |opt| match opt {
                None => Some(inserted),
                Some(old) => Some(Head::insert_archive_leaf(
                    old, inserted, leaf_hash, end_depth,
                )),
            });
        }
        this
    }
}

// Resume generic-V `Head` impl for the remaining methods (replace_leaf,
// union, intersect, query operations, etc.) which don't care about V
// shape and so remain in the V-generic impl block.
impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Head<KEY_LEN, O, V, H> {
    /// Replace the matching leaf while deferring reclamation of the old leaf.
    ///
    /// The returned retirement slot must be dropped only after the caller has
    /// published the returned head. `V::drop` is arbitrary user code and may
    /// panic; running it from inside a [`BranchMut`] edit would expose a taken
    /// child slot and stale aggregates if the panic were caught.
    pub(crate) fn replace_leaf(
        mut this: Self,
        leaf: Self,
        start_depth: usize,
    ) -> (Self, Option<Self>) {
        if let Some((depth, this_byte_key, leaf_byte_key)) =
            this.first_divergence(&leaf, start_depth)
        {
            let old_key = this.key();
            let new_body = Branch::new(
                depth,
                this.with_key(this_byte_key),
                leaf.with_key(leaf_byte_key),
            );

            return (Head::new(old_key, new_body), None);
        }

        let end_depth = this.end_depth();
        if end_depth == KEY_LEN {
            let old_key = this.key();
            return (leaf.with_key(old_key), Some(this));
        } else {
            // Use the editor view for branch mutation instead of raw pointer ops.
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
            let inserted = leaf.with_start(ed.end_depth as usize);
            let key = inserted.key();
            let mut retired = None;
            ed.modify_child(key, |opt| match opt {
                Some(old) => {
                    let (replacement, old_leaf) = Head::replace_leaf(old, inserted, end_depth);
                    retired = old_leaf;
                    Some(replacement)
                }
                None => Some(inserted),
            });
            drop(ed);
            return (this, retired);
        }
    }

    /// Sequential PATCH-trie union. Always serial; the parallel
    /// dispatch lives in [`Self::par_union`] which calls back into
    /// `union` once budget is exhausted.
    pub(crate) fn union(mut this: Self, mut other: Self, at_depth: usize) -> Self {
        // An archive-backed singleton has no cached fingerprint. Decide its
        // exact identity first; a distinct union then hashes each child once
        // and carries those hashes into the new Branch.
        if this.is_archive_singleton_pair(&other) {
            if let Some((depth, this_byte_key, other_byte_key)) =
                this.first_divergence(&other, at_depth)
            {
                let this_hash = this.hash();
                let other_hash = other.hash();
                let old_key = this.key();
                let new_body = Branch::new_with_child_hashes(
                    depth,
                    this.with_key(this_byte_key),
                    other.with_key(other_byte_key),
                    this_hash,
                    other_hash,
                );
                return Head::new(old_key, new_body);
            }
            return this;
        }

        if this.local_leaf_cardinality_allows_equality(&other) && this.hash() == other.hash() {
            return this;
        }

        if let Some((depth, this_byte_key, other_byte_key)) =
            this.first_divergence(&other, at_depth)
        {
            let old_key = this.key();
            let new_body = Branch::new(
                depth,
                this.with_key(this_byte_key),
                other.with_key(other_byte_key),
            );

            return Head::new(old_key, new_body);
        }

        let this_depth = this.end_depth();
        let other_depth = other.end_depth();
        if this_depth < other_depth {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
            let inserted = other.with_start(ed.end_depth as usize);
            let key = inserted.key();
            ed.modify_child(key, |opt| match opt {
                Some(old) => Some(Head::union(old, inserted, this_depth)),
                None => Some(inserted),
            });
            drop(ed);
            return this;
        }

        if other_depth < this_depth {
            let old_key = this.key();
            let this_head = this;
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut other);
            let inserted = this_head.with_start(ed.end_depth as usize);
            let key = inserted.key();
            ed.modify_child(key, |opt| match opt {
                Some(old) => Some(Head::union(old, inserted, other_depth)),
                None => Some(inserted),
            });
            drop(ed);
            return other.with_key(old_key);
        }

        // Equal depth, hashes differ → walk `other`'s children,
        // resolving collisions via recursive `Head::union` and the
        // `modify_child`'s per-call accounting.
        //
        // Union is commutative; mutating either side in place is
        // semantically equivalent. Swap when `other`'s child_table
        // is at least 2× larger than `this`'s — start with the
        // bigger capacity so cuckoo grows are mostly avoided during
        // insert. Branch tags encode `log2(child_table_size)`, so
        // the 2× ratio reduces to `other_tag > this_tag` (no body
        // deref needed; the tag bits live in the head's pointer).
        if other.tag() > this.tag() {
            std::mem::swap(&mut this, &mut other);
        }
        let BodyMut::Branch(other_branch_ref) = other.body_mut() else {
            unreachable!();
        };
        let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
        for other_child in other_branch_ref
            .child_table
            .iter_mut()
            .filter_map(Option::take)
        {
            let inserted = other_child.with_start(ed.end_depth as usize);
            let key = inserted.key();
            ed.modify_child(key, |opt| match opt {
                Some(old) => Some(Head::union(old, inserted, this_depth)),
                None => Some(inserted),
            });
        }
        drop(ed);
        this
    }

    /// Parallel-aware top-level union entry. Allocates a fresh
    /// [`parallel_union::ParUnionCtx`] with a budget of
    /// `num_threads²` shared spawns, then delegates to
    /// [`Self::par_union_with_ctx`]. The budget persists across the
    /// entire recursive descent — once exhausted, the rest is
    /// sequential.
    #[cfg(feature = "parallel")]
    pub(crate) fn par_union(this: Self, other: Self, at_depth: usize) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        let ctx = parallel_union::ParUnionCtx::new();
        Self::par_union_with_ctx(this, other, at_depth, &ctx)
    }

    /// Recursive parallel-aware union: at the equal-depth-branch
    /// arm, drains the "both" pairs and, for each pair, either
    /// claims a budget unit and spawns a parallel task or falls
    /// back to serial `Self::union`. All other arms (hash-equal,
    /// divergence, asymmetric depth) delegate to `Self::union` —
    /// they don't generate fan-out work for the budget to spend.
    #[cfg(feature = "parallel")]
    pub(crate) fn par_union_with_ctx(
        mut this: Self,
        mut other: Self,
        at_depth: usize,
        ctx: &parallel_union::ParUnionCtx,
    ) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        // Singleton pairs have no fan-out work for Rayon.
        if this.is_archive_singleton_pair(&other) {
            return Self::union(this, other, at_depth);
        }

        if this.local_leaf_cardinality_allows_equality(&other) && this.hash() == other.hash() {
            return this;
        }

        if let Some((depth, this_byte_key, other_byte_key)) =
            this.first_divergence(&other, at_depth)
        {
            let old_key = this.key();
            let new_body = Branch::new(
                depth,
                this.with_key(this_byte_key),
                other.with_key(other_byte_key),
            );
            return Head::new(old_key, new_body);
        }

        let this_depth = this.end_depth();
        let other_depth = other.end_depth();
        if this_depth != other_depth {
            // Asymmetric — no fan-out opportunity, serial path wins.
            return Self::union(this, other, at_depth);
        }

        // Equal depth, hashes differ → branch merge. Swap when
        // `other`'s child_table is ≥2× `this`'s so the in-place
        // target starts with the bigger capacity (fewer cuckoo
        // grows when scattering children back via
        // `install_child_growing`). Branch tags encode
        // `log2(child_table_size)`, so the 2× ratio reduces to
        // `other_tag > this_tag` — single byte compare from the
        // head pointer, no body deref / CoW risk.
        if other.tag() > this.tag() {
            std::mem::swap(&mut this, &mut other);
        }

        // Threshold check via `body_ref` (no CoW); fall back to
        // serial when the source side is too small to amortise the
        // scatter machinery.
        let small = match other.body_ref() {
            BodyRef::Branch(b) => (b.leaf_count as usize) < PARALLEL_PATCH_UNION_THRESHOLD,
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => unreachable!(),
        };
        if small {
            return Self::union(this, other, at_depth);
        }

        let BodyMut::Branch(other_branch_ref) = other.body_mut() else {
            unreachable!();
        };

        {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut this);
            let end_depth = ed.end_depth as usize;

            // Scatter both child tables into key-indexed 256-slot
            // arrays + present bitsets. The bitset partition tells us
            // which keys need a recursive union ("both") vs which are
            // simple pass-throughs ("only").
            let mut this_arr: [Option<Head<KEY_LEN, O, V, H>>; 256] = std::array::from_fn(|_| None);
            let mut other_arr: [Option<Head<KEY_LEN, O, V, H>>; 256] =
                std::array::from_fn(|_| None);
            let mut this_present = crate::patch::bytetable::ByteSet::new_empty();
            let mut other_present = crate::patch::bytetable::ByteSet::new_empty();

            for slot in ed.child_table.iter_mut() {
                if let Some(head) = slot.take() {
                    let key = head.key();
                    this_present.insert(key);
                    this_arr[key as usize] = Some(head);
                }
            }
            for slot in other_branch_ref.child_table.iter_mut() {
                if let Some(head) = slot.take() {
                    let head = head.with_start(end_depth);
                    let key = head.key();
                    other_present.insert(key);
                    other_arr[key as usize] = Some(head);
                }
            }

            let mut both = this_present.intersect(&other_present);
            let mut only = this_present.symmetric_difference(&other_present);

            // Pre-allocated scatter-write target. Each spawned task
            // writes to `resolved[k]` for its specific key byte —
            // disjoint by construction. The raw pointer wrapper
            // (`ScatterPtr`) makes the cross-thread sharing explicit.
            let mut resolved: [Option<Head<KEY_LEN, O, V, H>>; 256] = std::array::from_fn(|_| None);
            let resolved_ptr = parallel_union::ScatterPtr(resolved.as_mut_ptr());

            rayon::scope(|s| {
                // Drain `both` pairs serially in the parent; per
                // pair, either claim a spawn unit and dispatch as a
                // task, or run serially via `Head::union` here on
                // the parent thread. The atomic budget is shared
                // with all nested `par_union_with_ctx` calls.
                while let Some(k) = both.drain_next_ascending() {
                    let i = k as usize;
                    let t = this_arr[i].take().expect("both ⇒ this");
                    let o = other_arr[i].take().expect("both ⇒ other");
                    if ctx.try_claim() {
                        s.spawn(move |_| {
                            let head = Self::par_union_with_ctx(t, o, this_depth, ctx);
                            // SAFETY: each task has a distinct
                            // key `k`, so the writes to
                            // `resolved[i]` are non-aliasing.
                            unsafe {
                                resolved_ptr.write_at(i, Some(head));
                            }
                        });
                    } else {
                        // Budget exhausted — fall back to fully
                        // serial union on this pair, then scatter
                        // the result. SAFETY: same disjointness
                        // invariant; the parent thread races only
                        // with tasks targeting distinct keys.
                        let head = Self::union(t, o, this_depth);
                        unsafe {
                            resolved_ptr.write_at(i, Some(head));
                        }
                    }
                }
            });
            // After scope: all spawned tasks have completed; the
            // scatter writes to `resolved` are all sequenced-before
            // here by rayon's join semantics.

            for slot in resolved.iter_mut() {
                if let Some(head) = slot.take() {
                    ed.install_child_growing(head);
                }
            }
            while let Some(k) = only.drain_next_ascending() {
                let i = k as usize;
                let head = this_arr[i]
                    .take()
                    .or_else(|| other_arr[i].take())
                    .expect("only ⇒ exactly one side");
                ed.install_child_growing(head);
            }

            ed.recompute_aggregates();
        }
        this
    }

    /// Parallel-aware top-level intersect entry. Allocates a fresh
    /// [`parallel_union::ParUnionCtx`] (shared budget across the
    /// descent) and delegates to [`Self::par_intersect_with_ctx`].
    /// Intersect builds a fresh tree, so there is no in-place
    /// target — the parallel work is purely "compute per-pair
    /// intersections in parallel, then collect into a new Branch."
    #[cfg(feature = "parallel")]
    pub(crate) fn par_intersect(&self, other: &Self, at_depth: usize) -> Option<Self>
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        let ctx = parallel_union::ParUnionCtx::new();
        self.par_intersect_with_ctx(other, at_depth, &ctx)
    }

    /// Recursive parallel-aware intersect. At the equal-depth-branch
    /// arm, scatter-spawns one task per matching `(self_child,
    /// other_child)` pair (under budget), then collects results
    /// into a fresh `Branch`. Hash-equal / divergence / asymmetric-
    /// depth arms delegate to serial [`Self::intersect`] — they
    /// don't generate fan-out work.
    #[cfg(feature = "parallel")]
    pub(crate) fn par_intersect_with_ctx(
        &self,
        other: &Self,
        at_depth: usize,
        ctx: &parallel_union::ParUnionCtx,
    ) -> Option<Self>
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        if self.is_archive_singleton_pair(other) {
            return self.intersect(other, at_depth);
        }
        if self.local_leaf_cardinality_allows_equality(other) && self.hash() == other.hash() {
            return Some(self.clone());
        }
        if self.first_divergence(other, at_depth).is_some() {
            return None;
        }
        let self_depth = self.end_depth();
        let other_depth = other.end_depth();
        if self_depth != other_depth {
            return self.intersect(other, at_depth);
        }

        let BodyRef::Branch(self_branch) = self.body_ref() else {
            unreachable!();
        };
        let BodyRef::Branch(other_branch) = other.body_ref() else {
            unreachable!();
        };

        // Intersect work is bounded by the smaller side — pairs only
        // exist where keys appear in both branches.
        let min_leaves = self_branch.leaf_count.min(other_branch.leaf_count) as usize;
        if min_leaves < PARALLEL_PATCH_UNION_THRESHOLD {
            return self.intersect(other, at_depth);
        }

        let mut resolved: [Option<Head<KEY_LEN, O, V, H>>; 256] = std::array::from_fn(|_| None);
        let resolved_ptr = parallel_union::ScatterPtr(resolved.as_mut_ptr());

        // `in_place_scope` runs the outer closure on the calling
        // thread (no `Send` bound), which lets us hold `&Branch`
        // borrows across the spawn loop. `Branch` is `!Sync` due
        // to its raw `*const Leaf` pointer field, so a regular
        // `rayon::scope` would reject the captures.
        rayon::in_place_scope(|s| {
            for slot in self_branch.child_table.iter() {
                let Some(self_child) = slot.as_ref() else {
                    continue;
                };
                let key = self_child.key();
                let Some(other_child) = other_branch.child_table.table_get(key) else {
                    continue;
                };

                if ctx.try_claim() {
                    s.spawn(move |_| {
                        let result =
                            self_child.par_intersect_with_ctx(other_child, self_depth, ctx);
                        // SAFETY: distinct keys → disjoint slots.
                        unsafe {
                            resolved_ptr.write_at(key as usize, result);
                        }
                    });
                } else {
                    let result = self_child.intersect(other_child, self_depth);
                    unsafe {
                        resolved_ptr.write_at(key as usize, result);
                    }
                }
            }
        });

        // Collect non-None results into a fresh Branch. Stick with
        // per-key `modify_child` here — intersect's collection
        // phase typically has FEW children (heavy filtering kept
        // only the matching subset), so the per-call aggregate
        // updates beat the fixed `recompute_aggregates` cost. Bench
        // sanity-checked: install+recompute regressed intersect
        // +18% on the 4M/50%-overlap dataset.
        let mut iter = resolved.into_iter().flatten();
        let first = iter.next()?;
        let Some(second) = iter.next() else {
            return Some(first);
        };
        let new_branch = Branch::new(
            self_depth,
            first.with_start(self_depth),
            second.with_start(self_depth),
        );
        let mut head_for_branch = Head::new(0, new_branch);
        {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut head_for_branch);
            for child in iter {
                let inserted = child.with_start(self_depth);
                let k = inserted.key();
                ed.modify_child(k, |_opt| Some(inserted));
            }
        }
        Some(head_for_branch)
    }

    /// Parallel-aware top-level difference entry. Allocates a fresh
    /// [`parallel_union::ParUnionCtx`] and delegates to
    /// [`Self::par_difference_with_ctx`].
    #[cfg(feature = "parallel")]
    pub(crate) fn par_difference(&self, other: &Self, at_depth: usize) -> Option<Self>
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        let ctx = parallel_union::ParUnionCtx::new();
        self.par_difference_with_ctx(other, at_depth, &ctx)
    }

    /// Recursive parallel-aware difference. Same scatter-and-spawn
    /// shape as `par_intersect_with_ctx`, plus the "no match in
    /// other" branch where we clone `self_child` unchanged into
    /// the resolved array (no recursive work).
    #[cfg(feature = "parallel")]
    pub(crate) fn par_difference_with_ctx(
        &self,
        other: &Self,
        at_depth: usize,
        ctx: &parallel_union::ParUnionCtx,
    ) -> Option<Self>
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        if self.is_archive_singleton_pair(other) {
            return self.difference(other, at_depth);
        }
        if self.local_leaf_cardinality_allows_equality(other) && self.hash() == other.hash() {
            return None;
        }
        if self.first_divergence(other, at_depth).is_some() {
            return Some(self.clone());
        }
        let self_depth = self.end_depth();
        let other_depth = other.end_depth();
        if self_depth != other_depth {
            return self.difference(other, at_depth);
        }

        let BodyRef::Branch(self_branch) = self.body_ref() else {
            unreachable!();
        };
        let BodyRef::Branch(other_branch) = other.body_ref() else {
            unreachable!();
        };

        // Difference work is bounded by `self` (every key in self is
        // either kept or filtered against other).
        if (self_branch.leaf_count as usize) < PARALLEL_PATCH_UNION_THRESHOLD {
            return self.difference(other, at_depth);
        }

        let mut resolved: [Option<Head<KEY_LEN, O, V, H>>; 256] = std::array::from_fn(|_| None);
        let resolved_ptr = parallel_union::ScatterPtr(resolved.as_mut_ptr());

        // See `par_intersect_with_ctx` for why this is
        // `in_place_scope` rather than `scope`.
        rayon::in_place_scope(|s| {
            for slot in self_branch.child_table.iter() {
                let Some(self_child) = slot.as_ref() else {
                    continue;
                };
                let key = self_child.key();

                match other_branch.child_table.table_get(key) {
                    Some(other_child) => {
                        if ctx.try_claim() {
                            s.spawn(move |_| {
                                let result = self_child.par_difference_with_ctx(
                                    other_child,
                                    self_depth,
                                    ctx,
                                );
                                unsafe {
                                    resolved_ptr.write_at(key as usize, result);
                                }
                            });
                        } else {
                            let result = self_child.difference(other_child, self_depth);
                            unsafe {
                                resolved_ptr.write_at(key as usize, result);
                            }
                        }
                    }
                    None => {
                        // No match in other ⇒ keep `self_child`
                        // unchanged. Clone is cheap (Arc-style rc
                        // bump on Branch, leaf is small).
                        let cloned = self_child.clone();
                        unsafe {
                            resolved_ptr.write_at(key as usize, Some(cloned));
                        }
                    }
                }
            }
        });

        // Collect non-None results into a fresh Branch. Difference's
        // collection phase typically has MANY children (most keys
        // in `self` survive — only matching+empty subtrees get
        // filtered), so `install_child_growing` + one
        // `recompute_aggregates` pass wins handily over per-call
        // `modify_child`. Mirror of the union pattern; intersect
        // uses `modify_child` because its collection phase has
        // far fewer children (heavy filtering).
        let mut iter = resolved.into_iter().flatten();
        let first = iter.next()?;
        let Some(second) = iter.next() else {
            return Some(first);
        };
        let new_branch = Branch::new(
            self_depth,
            first.with_start(self_depth),
            second.with_start(self_depth),
        );
        let mut head_for_branch = Head::new(0, new_branch);
        {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut head_for_branch);
            for child in iter {
                ed.install_child_growing(child.with_start(self_depth));
            }
            ed.recompute_aggregates();
        }
        Some(head_for_branch)
    }

    pub(crate) fn infixes<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        f: &mut F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.infixes::<PREFIX_LEN, INFIX_LEN, O, F>(prefix, at_depth, f),
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::infixes::<KEY_LEN, PREFIX_LEN, INFIX_LEN, O, F>(
                    bytes, prefix, at_depth, f,
                )
            }
            BodyRef::Branch(branch) => {
                branch.infixes::<PREFIX_LEN, INFIX_LEN, F>(prefix, at_depth, f)
            }
        }
    }

    pub(crate) fn infixes_range<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
        f: &mut F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.infixes_range::<PREFIX_LEN, INFIX_LEN, O, F>(
                prefix, at_depth, min_infix, max_infix, f,
            ),
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::infixes_range::<KEY_LEN, PREFIX_LEN, INFIX_LEN, O, F>(
                    bytes, prefix, at_depth, min_infix, max_infix, f,
                )
            }
            BodyRef::Branch(branch) => branch.infixes_range::<PREFIX_LEN, INFIX_LEN, F>(
                prefix, at_depth, min_infix, max_infix, f,
            ),
        }
    }

    pub(crate) fn first_infix_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> Option<[u8; INFIX_LEN]> {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.first_infix_range::<PREFIX_LEN, INFIX_LEN, O>(
                prefix, at_depth, min_infix, max_infix,
            ),
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::first_infix_range::<KEY_LEN, PREFIX_LEN, INFIX_LEN, O>(
                    bytes, prefix, at_depth, min_infix, max_infix,
                )
            }
            BodyRef::Branch(branch) => branch
                .first_infix_range::<PREFIX_LEN, INFIX_LEN>(prefix, at_depth, min_infix, max_infix),
        }
    }

    pub(crate) fn count_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> u64 {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => {
                leaf.count_range::<PREFIX_LEN, INFIX_LEN, O>(prefix, at_depth, min_infix, max_infix)
            }
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::count_range::<KEY_LEN, PREFIX_LEN, INFIX_LEN, O>(
                    bytes, prefix, at_depth, min_infix, max_infix,
                )
            }
            BodyRef::Branch(branch) => {
                branch.count_range::<PREFIX_LEN, INFIX_LEN>(prefix, at_depth, min_infix, max_infix)
            }
        }
    }

    pub(crate) fn has_prefix<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> bool {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.has_prefix::<O>(at_depth, prefix),
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::has_prefix::<KEY_LEN, O>(bytes, at_depth, prefix)
            }
            BodyRef::Branch(branch) => branch.has_prefix::<PREFIX_LEN>(at_depth, prefix),
        }
    }

    pub(crate) fn traversal_depth<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> usize {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        match self.body_ref() {
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => 1,
            BodyRef::Branch(branch) => branch.traversal_depth::<PREFIX_LEN>(at_depth, prefix),
        }
    }

    pub(crate) fn get<'a>(&'a self, at_depth: usize, key: &[u8; KEY_LEN]) -> Option<&'a V>
    where
        O: 'a,
    {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.get::<O>(at_depth, key),
            BodyRef::LocalLeaf(bytes) => {
                if !leaf::key_ops::matches::<KEY_LEN, O>(bytes, at_depth, key) {
                    return None;
                }
                // SAFETY: LocalLeaf is only constructed by the SimpleArchive
                // ingestion path (step 3), which constrains the PATCH to
                // `V = ()`. The `Option<&V>` here therefore points at a
                // zero-sized value; a static `()` provides the address.
                // For non-`()` V this branch is unreachable today, and
                // construction will refuse such PATCHes once step 3 lands.
                // The type-system invariant will eventually be enforced
                // via a `LocalLeafSupported: V` trait constraint at
                // `Head::new_local_leaf` callers.
                static UNIT: () = ();
                let unit_ref: &V = unsafe {
                    debug_assert_eq!(std::mem::size_of::<V>(), 0, "LocalLeaf requires V = ()");
                    &*(&UNIT as *const () as *const V)
                };
                Some(unit_ref)
            }
            BodyRef::Branch(branch) => branch.get(at_depth, key),
        }
    }

    pub(crate) fn segmented_len<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> u64 {
        match self.body_ref() {
            BodyRef::Leaf(leaf) => leaf.segmented_len::<O, PREFIX_LEN>(at_depth, prefix),
            BodyRef::LocalLeaf(bytes) => {
                leaf::key_ops::segmented_len::<KEY_LEN, PREFIX_LEN, O>(bytes, at_depth, prefix)
            }
            BodyRef::Branch(branch) => branch.segmented_len::<PREFIX_LEN>(at_depth, prefix),
        }
    }

    /// Locate the shallowest subtree whose keys all share `prefix`.
    ///
    /// Unlike composing [`Self::segmented_len`] with [`Self::infixes`], this
    /// returns the already-located head so a caller can inspect its cached
    /// segment count and then enumerate that same subtree without descending
    /// the fixed prefix a second time.
    fn locate_prefix<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> Option<&Self> {
        let node_end_depth = self.end_depth();
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return None;
        }
        if PREFIX_LEN <= node_end_depth {
            return Some(self);
        }
        let BodyRef::Branch(branch) = self.body_ref() else {
            unreachable!("a leaf always covers the complete key");
        };
        branch
            .child_table
            .table_get(prefix[node_end_depth])
            .and_then(|child| child.locate_prefix(node_end_depth, prefix))
    }

    /// Enumerate a whole infix segment after `prefix` has already been
    /// matched for every key below this head.
    fn infixes_from_matched_prefix<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        for_each: &mut F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        if PREFIX_LEN + INFIX_LEN <= self.end_depth() {
            let infix: [u8; INFIX_LEN] =
                core::array::from_fn(|i| self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]]);
            for_each(&infix);
            return;
        }

        let BodyRef::Branch(branch) = self.body_ref() else {
            unreachable!("a leaf always covers the complete key");
        };
        for child in branch.child_table.iter().flatten() {
            child.infixes_from_matched_prefix::<PREFIX_LEN, INFIX_LEN, F>(for_each);
        }
    }

    /// Diagnostic: accumulate (branch nodes, total child-table slots,
    /// heap-`Leaf` nodes, `LocalLeaf` slots) over the subtree. Used to
    /// decompose a PATCH's *structural* byte size (vs resident RSS).
    /// `branches` × the policy-specific branch header + `slots` × 8 is the
    /// branch allocation total; heap leaves add one `Leaf` node each.
    pub(crate) fn node_stats(&self, acc: &mut (u64, u64, u64, u64)) {
        match self.body_ref() {
            BodyRef::Leaf(_) => acc.2 += 1,
            BodyRef::LocalLeaf(_) => acc.3 += 1,
            BodyRef::Branch(branch) => {
                acc.0 += 1;
                acc.1 += branch.child_table.len() as u64;
                for child in branch.child_table.iter().flatten() {
                    child.node_stats(acc);
                }
            }
        }
    }

    /// Per-end-depth branch census: `hist[d] = (branch_count, filled_children)`
    /// for branches whose branching point is at byte-depth `d`. Reveals where
    /// the branches sit and their fanout — the input to the HOT/variable-width
    /// densification question.
    pub(crate) fn branch_hist(&self, hist: &mut [(u64, u64); 65]) {
        if let BodyRef::Branch(branch) = self.body_ref() {
            let d = self.end_depth().min(64);
            let fanout = branch.child_table.iter().flatten().count() as u64;
            hist[d].0 += 1;
            hist[d].1 += fanout;
            for child in branch.child_table.iter().flatten() {
                child.branch_hist(hist);
            }
        }
    }

    /// Per-fanout branch census: `hist[f] = branch_count` for branches with
    /// exactly `f` filled children.
    pub(crate) fn branch_fanout_hist(&self, hist: &mut [u64; 257]) {
        if let BodyRef::Branch(branch) = self.body_ref() {
            let fanout = branch.child_table.iter().flatten().count();
            hist[fanout.min(256)] += 1;
            for child in branch.child_table.iter().flatten() {
                child.branch_fanout_hist(hist);
            }
        }
    }

    // NOTE: slot-level union wrapper removed; callers should take the slot and
    // call the owned helper `union` directly.

    pub(crate) fn intersect(&self, other: &Self, at_depth: usize) -> Option<Self> {
        if self.is_archive_singleton_pair(other) {
            return if self.first_divergence(other, at_depth).is_none() {
                Some(self.clone())
            } else {
                None
            };
        }

        if self.local_leaf_cardinality_allows_equality(other) && self.hash() == other.hash() {
            return Some(self.clone());
        }

        if self.first_divergence(other, at_depth).is_some() {
            return None;
        }

        let self_depth = self.end_depth();
        let other_depth = other.end_depth();
        if self_depth < other_depth {
            // This means that there can be at most one child in self
            // that might intersect with other.
            let BodyRef::Branch(branch) = self.body_ref() else {
                unreachable!();
            };
            return branch
                .child_table
                .table_get(other.childleaf_key()[O::TREE_TO_KEY[self_depth]])
                .and_then(|self_child| other.intersect(self_child, self_depth));
        }

        if other_depth < self_depth {
            // This means that there can be at most one child in other
            // that might intersect with self.
            // If the depth of other is less than the depth of self, then it can't be a leaf.
            let BodyRef::Branch(other_branch) = other.body_ref() else {
                unreachable!();
            };
            return other_branch
                .child_table
                .table_get(self.childleaf_key()[O::TREE_TO_KEY[other_depth]])
                .and_then(|other_child| self.intersect(other_child, other_depth));
        }

        // If we reached this point then the depths are equal. The only way to have a leaf
        // is if the other is a leaf as well, which is already handled by the hash check if they are equal,
        // and by the key check if they are not equal.
        // If one of them is a leaf and the other is a branch, then they would also have different depths,
        // which is already handled by the above code.
        let BodyRef::Branch(self_branch) = self.body_ref() else {
            unreachable!();
        };
        let BodyRef::Branch(other_branch) = other.body_ref() else {
            unreachable!();
        };

        let mut intersected_children = self_branch
            .child_table
            .iter()
            .filter_map(Option::as_ref)
            .filter_map(|self_child| {
                let other_child = other_branch.child_table.table_get(self_child.key())?;
                self_child.intersect(other_child, self_depth)
            });
        let first_child = intersected_children.next()?;
        let Some(second_child) = intersected_children.next() else {
            return Some(first_child);
        };
        let new_branch = Branch::new(
            self_depth,
            first_child.with_start(self_depth),
            second_child.with_start(self_depth),
        );
        // Use a BranchMut editor to perform all child insertions via the
        // safe editor API instead of manipulating the NonNull pointer
        // directly. The editor will perform COW and commit the final
        // pointer into the Head when it is dropped.
        let mut head_for_branch = Head::new(0, new_branch);
        {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut head_for_branch);
            for child in intersected_children {
                let inserted = child.with_start(self_depth);
                let k = inserted.key();
                ed.modify_child(k, |_opt| Some(inserted));
            }
            // ed dropped here commits the final branch pointer into head_for_branch
        }
        Some(head_for_branch)
    }

    /// Returns the difference between self and other.
    /// This is the set of elements that are in self but not in other.
    /// If the difference is empty, None is returned.
    pub(crate) fn difference(&self, other: &Self, at_depth: usize) -> Option<Self> {
        if self.is_archive_singleton_pair(other) {
            return if self.first_divergence(other, at_depth).is_none() {
                None
            } else {
                Some(self.clone())
            };
        }

        if self.local_leaf_cardinality_allows_equality(other) && self.hash() == other.hash() {
            return None;
        }

        if self.first_divergence(other, at_depth).is_some() {
            return Some(self.clone());
        }

        let self_depth = self.end_depth();
        let other_depth = other.end_depth();
        if self_depth < other_depth {
            // This means that there can be at most one child in self
            // that might intersect with other. It's the only child that may not be in the difference.
            // The other children are definitely in the difference, as they have no corresponding byte in other.
            // Thus the cheapest way to compute the difference is compute the difference of the only child
            // that might intersect with other, copy self with it's correctly filled byte table, then
            // remove the old child, and insert the new child.
            let mut new_branch = self.clone();
            let other_byte_key = other.childleaf_key()[O::TREE_TO_KEY[self_depth]];
            {
                let mut ed = crate::patch::branch::BranchMut::from_head(&mut new_branch);
                ed.modify_child(other_byte_key, |opt| {
                    opt.and_then(|child| child.difference(other, self_depth))
                });

                // The asymmetric edit can delete the only matching child
                // subtree. Preserve the compressed-trie invariant instead of
                // returning a Branch with zero or one child.
                let child_count = ed
                    .child_table
                    .iter()
                    .filter(|child| child.is_some())
                    .take(2)
                    .count();
                if child_count <= 1 {
                    let mut remaining = None;
                    for slot in &mut ed.child_table {
                        if let Some(child) = slot.take() {
                            remaining = Some(child.with_start(at_depth));
                            break;
                        }
                    }
                    drop(ed);
                    return remaining;
                }
            }
            return Some(new_branch);
        }

        if other_depth < self_depth {
            // This means that we need to check if there is a child in other
            // that matches the path at the current depth of self.
            // There is no such child, then then self must be in the difference.
            // If there is such a child, then we have to compute the difference
            // between self and that child.
            // We know that other must be a branch.
            let BodyRef::Branch(other_branch) = other.body_ref() else {
                unreachable!();
            };
            let self_byte_key = self.childleaf_key()[O::TREE_TO_KEY[other_depth]];
            if let Some(other_child) = other_branch.child_table.table_get(self_byte_key) {
                return self.difference(other_child, at_depth);
            } else {
                return Some(self.clone());
            }
        }

        // If we reached this point then the depths are equal. The only way to have a leaf
        // is if the other is a leaf as well, which is already handled by the hash check if they are equal,
        // and by the key check if they are not equal.
        // If one of them is a leaf and the other is a branch, then they would also have different depths,
        // which is already handled by the above code.
        let BodyRef::Branch(self_branch) = self.body_ref() else {
            unreachable!();
        };
        let BodyRef::Branch(other_branch) = other.body_ref() else {
            unreachable!();
        };

        let mut differenced_children = self_branch
            .child_table
            .iter()
            .filter_map(Option::as_ref)
            .filter_map(|self_child| {
                if let Some(other_child) = other_branch.child_table.table_get(self_child.key()) {
                    self_child.difference(other_child, self_depth)
                } else {
                    Some(self_child.clone())
                }
            });

        let first_child = differenced_children.next()?;
        let second_child = match differenced_children.next() {
            Some(sc) => sc,
            None => return Some(first_child),
        };

        let new_branch = Branch::new(
            self_depth,
            first_child.with_start(self_depth),
            second_child.with_start(self_depth),
        );
        let mut head_for_branch = Head::new(0, new_branch);
        {
            let mut ed = crate::patch::branch::BranchMut::from_head(&mut head_for_branch);
            for child in differenced_children {
                let inserted = child.with_start(self_depth);
                let k = inserted.key();
                ed.modify_child(k, |_opt| Some(inserted));
            }
            // ed dropped here commits the final branch pointer into head_for_branch
        }
        // The key will be set later, because we don't know it yet.
        // The difference might remove multiple levels of branches,
        // so we can't just take the key from self or other.
        Some(head_for_branch)
    }
}

unsafe impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> ByteEntry
    for Head<KEY_LEN, O, V, H>
{
    fn key(&self) -> u8 {
        self.key()
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> fmt::Debug
    for Head<KEY_LEN, O, V, H>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.tag().fmt(f)
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Clone
    for Head<KEY_LEN, O, V, H>
{
    fn clone(&self) -> Self {
        unsafe {
            match self.body() {
                BodyPtr::Leaf(leaf) => Self::new(self.key(), Leaf::rc_inc(leaf)),
                BodyPtr::LocalLeaf(ptr) => {
                    // LocalLeaf has no refcount. Its enclosing PATCH snapshots
                    // clone the root owner set alongside the tagged pointer.
                    Self::new_local_leaf(self.key(), ptr)
                }
                BodyPtr::Branch(branch) => Self::new(self.key(), Branch::rc_inc(branch)),
            }
        }
    }
}

// The Slot wrapper was removed in favor of using BranchMut::from_slot(&mut
// Option<Head<...>>) directly. This keeps the API surface smaller and
// avoids an extra helper type that simply forwarded to BranchMut.

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Drop for Head<KEY_LEN, O, V, H> {
    fn drop(&mut self) {
        unsafe {
            match self.body() {
                BodyPtr::Leaf(leaf) => Leaf::rc_dec(leaf),
                BodyPtr::LocalLeaf(_) => {
                    // No-op: LocalLeaf bytes are retained by the enclosing
                    // PATCH's root owner set, not refcounted per leaf.
                }
                BodyPtr::Branch(branch) => Branch::rc_dec(branch),
            }
        }
    }
}

/// A PATCH is a persistent data structure that stores a set of keys.
/// Each key can be reordered and segmented, based on the provided key ordering and segmentation.
///
/// The patch supports efficient set operations, like union, intersection, and difference,
/// because it efficiently maintains a hash for all keys that are part of a sub-tree.
///
/// The tree itself is a path- and node-compressed a 256-ary trie.
/// Each nodes stores its children in a byte oriented cuckoo hash table,
/// allowing for O(1) access to children, while keeping the memory overhead low.
/// Table sizes are powers of two, starting at 2.
///
/// Having a single node type for all branching factors simplifies the implementation,
/// compared to other adaptive trie implementations, like ARTs or Judy Arrays
///
/// The PATCH allows for cheap copy-on-write operations, with `clone` being O(1).
/// Its persistent snapshots can share leaves, so a PATCH is `Send + Sync` only
/// when its associated value is also both `Send` and `Sync`.
///
/// A value that is neither thread-safe cannot make a PATCH thread-safe:
///
/// ```compile_fail
/// use std::rc::Rc;
/// use triblespace_core::patch::{IdentitySchema, PATCH};
///
/// fn assert_send_sync<T: Send + Sync>() {}
/// assert_send_sync::<PATCH<1, IdentitySchema, Rc<()>>>();
/// ```
///
/// `Cell<u64>` is `Send` but not `Sync`. Rejecting this case is important:
/// moving one PATCH snapshot can leave another snapshot reading the same leaf
/// on its original thread.
///
/// ```compile_fail
/// use std::cell::Cell;
/// use triblespace_core::patch::{IdentitySchema, PATCH};
///
/// fn assert_send<T: Send>() {}
/// assert_send::<PATCH<1, IdentitySchema, Cell<u64>>>();
/// ```
#[derive(Debug)]
pub struct PATCH<const KEY_LEN: usize, O = IdentitySchema, V = (), H = XorSip128>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    // Field order is deliberate: Heads drop before the owner cover.
    root: Option<Head<KEY_LEN, O, V, H>>,
    /// Deduplicated conservative lifetime cover for every LocalLeaf anywhere
    /// below `root`. Set operations may retain provenance no longer reachable
    /// from the result, but never duplicate an owner or omit a reachable one.
    /// This thin Arc adds eight bytes per PATCH while removing sixteen bytes
    /// from every Branch.
    owners: Option<Arc<OwnerCover>>,
}

/// A prefix-located PATCH infix traversal whose exact cardinality has already
/// been proved to fit a caller-supplied bound.
///
/// The view borrows the located trie head, so [`Self::for_each`] starts at that
/// same subtree and never repeats the fixed-prefix descent.
#[must_use = "call for_each to enumerate the bounded infixes"]
pub struct PATCHBoundedInfixes<
    'a,
    const KEY_LEN: usize,
    const PREFIX_LEN: usize,
    const INFIX_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    located: Option<&'a Head<KEY_LEN, O, V, H>>,
    count: u64,
}

/// Opaque borrow of one logical node in a canonical BLAKE3 PATCH trie.
///
/// The view exposes reconciliation data, never PATCH's tagged pointers,
/// branches, or physical cuckoo-table layout. It is available only for
/// [`IdentitySchema`], so [`Self::prefix`] and [`Self::representative`] are
/// canonical raw-key bytes rather than a schema-specific tree permutation.
/// Values do not participate in PATCH identity and are intentionally absent.
pub struct PATCHMerkleNode<'a, const KEY_LEN: usize, V> {
    head: &'a Head<KEY_LEN, IdentitySchema, V, Blake3Merkle>,
}

impl<const KEY_LEN: usize, V> Copy for PATCHMerkleNode<'_, KEY_LEN, V> {}

impl<const KEY_LEN: usize, V> Clone for PATCHMerkleNode<'_, KEY_LEN, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, const KEY_LEN: usize, V> PATCHMerkleNode<'a, KEY_LEN, V> {
    fn new(head: &'a Head<KEY_LEN, IdentitySchema, V, Blake3Merkle>) -> Self {
        Self { head }
    }

    /// Canonical digest of this logical subtree.
    pub fn digest(&self) -> [u8; 32] {
        self.head.hash()
    }

    /// Exact number of leaves below this node.
    ///
    /// Branch digests commit to this count. A leaf digest canonically denotes
    /// one complete key, so its count is necessarily one.
    pub fn leaf_count(&self) -> u64 {
        self.head.count()
    }

    /// First raw-key depth not shared by every key below this node.
    ///
    /// Leaves return `KEY_LEN`. For branches, the byte at `end_depth` selects
    /// one of [`Self::children`].
    pub fn end_depth(&self) -> usize {
        self.head.end_depth()
    }

    /// Lexicographically first complete raw key below this node.
    ///
    /// PATCH's internal representative pointer is merely a routing witness
    /// and may depend on construction history. This accessor instead follows
    /// the smallest logical edge at each branch, making the public result
    /// canonical without exposing or changing that hot-path field.
    pub fn representative(&self) -> &'a [u8; KEY_LEN] {
        let mut node = self.head;
        loop {
            match node.body_ref() {
                BodyRef::Leaf(leaf) => return &leaf.key,
                BodyRef::LocalLeaf(key) => return key,
                BodyRef::Branch(branch) => {
                    node = branch
                        .child_table
                        .iter()
                        .flatten()
                        .min_by_key(|child| child.key())
                        .expect("a PATCH branch has at least two children");
                }
            }
        }
    }

    /// Canonical raw-key prefix naming this logical node.
    ///
    /// A lookup prefix may end inside a compressed path. In that case the
    /// returned node's canonical prefix is longer than the requested prefix.
    pub fn prefix(&self) -> &'a [u8] {
        &self.representative()[..self.end_depth()]
    }

    /// Whether this node is a single complete key.
    pub fn is_leaf(&self) -> bool {
        self.end_depth() == KEY_LEN
    }

    /// Iterate over logical children in ascending edge-byte order.
    pub fn children(&self) -> PATCHMerkleChildren<'a, KEY_LEN, V> {
        PATCHMerkleChildren::new(*self)
    }

    /// Iterate over at most `limit` keys in this subtree, strictly after
    /// `after`, in canonical raw-key order.
    ///
    /// The cursor is a complete key, not an implementation node token. It
    /// need not exist in the PATCH. Keys are copied out so neither associated
    /// values nor archive-backed leaf lifetimes escape this borrow. A zero
    /// limit is explicitly empty and performs no traversal.
    pub fn items_after(
        &self,
        after: Option<&[u8; KEY_LEN]>,
        limit: usize,
    ) -> PATCHMerkleItems<'a, KEY_LEN, V> {
        PATCHMerkleItems::new(*self, after.copied(), limit)
    }

    fn may_contain_after(&self, after: &[u8; KEY_LEN]) -> bool {
        let end_depth = self.end_depth();
        self.representative()[..end_depth] >= after[..end_depth]
    }
}

impl<const KEY_LEN: usize, V> core::fmt::Debug for PATCHMerkleNode<'_, KEY_LEN, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PATCHMerkleNode")
            .field("prefix", &self.prefix())
            .field("digest", &self.digest())
            .field("leaf_count", &self.leaf_count())
            .field("end_depth", &self.end_depth())
            .field("representative", self.representative())
            .finish()
    }
}

/// Ascending logical children of a [`PATCHMerkleNode`].
///
/// The iterator contains at most 256 edges regardless of the physical branch
/// allocation. Its fields are private so the cuckoo representation remains an
/// implementation detail.
pub struct PATCHMerkleChildren<'a, const KEY_LEN: usize, V> {
    node: Option<PATCHMerkleNode<'a, KEY_LEN, V>>,
    edges: ByteSet,
}

impl<'a, const KEY_LEN: usize, V> PATCHMerkleChildren<'a, KEY_LEN, V> {
    fn new(node: PATCHMerkleNode<'a, KEY_LEN, V>) -> Self {
        let mut edges = ByteSet::new_empty();
        if let BodyRef::Branch(branch) = node.head.body_ref() {
            for child in branch.child_table.iter().flatten() {
                edges.insert(child.key());
            }
        }
        Self {
            node: (!node.is_leaf()).then_some(node),
            edges,
        }
    }
}

impl<'a, const KEY_LEN: usize, V> Iterator for PATCHMerkleChildren<'a, KEY_LEN, V> {
    type Item = (u8, PATCHMerkleNode<'a, KEY_LEN, V>);

    fn next(&mut self) -> Option<Self::Item> {
        let edge = self.edges.drain_next_ascending()?;
        let node = self.node.expect("a child edge requires a branch node");
        let BodyRef::Branch(branch) = node.head.body_ref() else {
            unreachable!("a leaf cannot carry child edges");
        };
        let child = branch
            .child_table
            .table_get(edge)
            .expect("an enumerated PATCH child remains present");
        Some((edge, PATCHMerkleNode::new(child)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.edges.popcount() as usize;
        (remaining, Some(remaining))
    }
}

impl<const KEY_LEN: usize, V> ExactSizeIterator for PATCHMerkleChildren<'_, KEY_LEN, V> {}
impl<const KEY_LEN: usize, V> std::iter::FusedIterator for PATCHMerkleChildren<'_, KEY_LEN, V> {}

/// Bounded canonical key page below one [`PATCHMerkleNode`].
///
/// Earlier subtrees are rejected from their compressed raw-key prefix rather
/// than scanned leaf-by-leaf. The traversal stack grows only with trie depth;
/// each frame contains a fixed 256-bit edge set.
pub struct PATCHMerkleItems<'a, const KEY_LEN: usize, V> {
    pending: Option<PATCHMerkleNode<'a, KEY_LEN, V>>,
    stack: Vec<PATCHMerkleChildren<'a, KEY_LEN, V>>,
    after: Option<[u8; KEY_LEN]>,
    remaining: usize,
}

impl<'a, const KEY_LEN: usize, V> PATCHMerkleItems<'a, KEY_LEN, V> {
    fn new(
        node: PATCHMerkleNode<'a, KEY_LEN, V>,
        after: Option<[u8; KEY_LEN]>,
        limit: usize,
    ) -> Self {
        Self {
            pending: (limit != 0).then_some(node),
            stack: Vec::new(),
            after,
            remaining: limit,
        }
    }

    fn next_node(&mut self) -> Option<PATCHMerkleNode<'a, KEY_LEN, V>> {
        if let Some(node) = self.pending.take() {
            return Some(node);
        }
        loop {
            let children = self.stack.last_mut()?;
            if let Some((_, node)) = children.next() {
                return Some(node);
            }
            self.stack.pop();
        }
    }
}

impl<'a, const KEY_LEN: usize, V> Iterator for PATCHMerkleItems<'a, KEY_LEN, V> {
    type Item = [u8; KEY_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 {
            let node = self.next_node()?;
            if self
                .after
                .as_ref()
                .is_some_and(|after| !node.may_contain_after(after))
            {
                continue;
            }
            if node.is_leaf() {
                let key = *node.representative();
                if self.after.as_ref().is_some_and(|after| key <= *after) {
                    continue;
                }
                self.remaining -= 1;
                return Some(key);
            }
            self.stack.push(node.children());
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

impl<const KEY_LEN: usize, V> std::iter::FusedIterator for PATCHMerkleItems<'_, KEY_LEN, V> {}

impl<
        'a,
        const KEY_LEN: usize,
        const PREFIX_LEN: usize,
        const INFIX_LEN: usize,
        O: KeySchema<KEY_LEN>,
        V,
        H: PatchHash,
    > PATCHBoundedInfixes<'a, KEY_LEN, PREFIX_LEN, INFIX_LEN, O, V, H>
{
    /// Exact number of distinct infixes this view will emit.
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Whether this bounded traversal has no matching infixes.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enumerate the already-located subtree in the same callback order as
    /// [`PATCH::infixes`].
    pub fn for_each<F>(self, mut for_each: F)
    where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        if let Some(located) = self.located {
            located.infixes_from_matched_prefix::<PREFIX_LEN, INFIX_LEN, F>(&mut for_each);
        }
    }
}

impl<const KEY_LEN: usize, O, V, H> Clone for PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            owners: self.owners.clone(),
        }
    }
}

impl<const KEY_LEN: usize, O, V, H> Default for PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const KEY_LEN: usize, O, V, H> PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    /// Creates a new empty PATCH.
    pub fn new() -> Self {
        H::init();
        PATCH {
            root: None,
            owners: None,
        }
    }

    /// Inserts a shared key into the PATCH.
    ///
    /// Takes an [Entry] object that can be created from a key,
    /// and inserted into multiple PATCH instances.
    ///
    /// If the key is already present, this is a no-op.
    pub fn insert(&mut self, entry: &Entry<KEY_LEN, V, H>) {
        if self.root.is_some() {
            let this = self.root.take().expect("root should not be empty");
            let new_head = Head::insert_leaf(this, entry.leaf(), 0);
            self.root.replace(new_head);
        } else {
            self.root.replace(entry.leaf());
        }
        self.debug_check_owner_invariant();
    }

    /// Inserts a key into the PATCH, replacing the value if it already exists.
    ///
    /// If the replaced value's destructor panics, the replacement is already
    /// fully committed when the panic is raised.
    pub fn replace(&mut self, entry: &Entry<KEY_LEN, V, H>) {
        let retired_leaf = if self.root.is_some() {
            let this = self.root.take().expect("root should not be empty");
            let (new_head, retired_leaf) = Head::replace_leaf(this, entry.leaf(), 0);
            self.root.replace(new_head);
            retired_leaf
        } else {
            self.root.replace(entry.leaf());
            None
        };
        self.debug_check_owner_invariant();

        // Deliberately last: replacement may release the final shared
        // reference to user-owned `V`, whose destructor may panic.
        drop(retired_leaf);
    }

    /// Removes a key from the PATCH.
    ///
    /// `key` is expressed in this PATCH's tree ordering. A key in the shared
    /// key ordering must first be converted with [`KeySchema::tree_ordered`].
    ///
    /// If the key is not present, this is a no-op.
    /// If a removed value or final archive owner's destructor panics, the
    /// removal is already fully committed when the panic is raised.
    pub fn remove(&mut self, key: &[u8; KEY_LEN]) {
        let retired_leaf = Head::remove_leaf(&mut self.root, key, 0);
        let retired_owners = if self.root.is_none() {
            self.owners.take()
        } else {
            None
        };
        self.debug_check_owner_invariant();

        // Deliberately last: owner and value reclamation may execute arbitrary
        // user Drop implementations, so every observable PATCH field and
        // structural invariant must already describe the committed result.
        drop(retired_owners);
        drop(retired_leaf);
    }

    /// Returns the number of keys in the PATCH.
    pub fn len(&self) -> u64 {
        if let Some(root) = &self.root {
            root.count()
        } else {
            0
        }
    }

    /// Diagnostic structural census: returns
    /// `(branch_nodes, child_table_slots, heap_leaf_nodes, local_leaf_slots)`.
    /// Structural branch bytes ≈ `branches * Self::branch_header_bytes() + slots * 8`;
    /// heap leaves add a `Leaf` node each (the key is shared across the six
    /// orderings, so count it once per trible, not once per ordering).
    pub fn node_stats(&self) -> (u64, u64, u64, u64) {
        let mut acc = (0u64, 0u64, 0u64, 0u64);
        if let Some(root) = &self.root {
            root.node_stats(&mut acc);
        }
        acc
    }

    #[cfg(debug_assertions)]
    fn debug_check_owner_invariant(&self) {
        debug_assert!(
            self.root.as_ref().map(|root| root.tag()) != Some(HeadTag::LocalLeaf)
                || self.owners.is_some(),
            "a root LocalLeaf must retain its archive owner",
        );
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    fn debug_check_owner_invariant(&self) {}

    /// Returns the total capacity of all branch child tables.
    ///
    /// This counts allocated table slots (`child_table.len()`), not filled
    /// children.
    pub fn total_table_slots(&self) -> u64 {
        self.node_stats().1
    }

    /// Fixed branch header bytes, excluding the trailing child table.
    pub fn branch_header_bytes() -> usize {
        std::mem::size_of::<Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>; 0], V, H>>()
    }

    /// Per-end-depth `(branch_count, filled_children)` histogram (65 buckets,
    /// byte-depths 0..=64), for analysing trie shape — where branches sit and
    /// their fanout distribution.
    pub fn branch_histogram(&self) -> [(u64, u64); 65] {
        let mut hist = [(0u64, 0u64); 65];
        if let Some(root) = &self.root {
            root.branch_hist(&mut hist);
        }
        hist
    }

    /// Per-fanout branch census: returns `hist[f] = branch_count` for each
    /// exact fanout `0..=256`.
    pub fn branch_fanout_histogram(&self) -> [u64; 257] {
        let mut hist = [0u64; 257];
        if let Some(root) = &self.root {
            root.branch_fanout_hist(&mut hist);
        }
        hist
    }

    /// Test-only root ownership receipt and LocalLeaf count.
    #[cfg(test)]
    pub(crate) fn archive_owner_guard_stats(&self) -> (bool, u64) {
        (self.owners.is_some(), self.node_stats().3)
    }

    /// Returns true if the PATCH contains no keys.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return PATCH's internal root summary.
    ///
    /// The default policy's value is crate-private deliberately. Public cache
    /// keys must pass through [`blind_root_hash`] so callers cannot observe
    /// chosen leaf-hash vectors and exploit its XOR maintenance law.
    pub(crate) fn root_hash(&self) -> Option<H::Digest> {
        self.root.as_ref().map(|root| root.hash())
    }

    /// Whether two snapshots still share the same persistent root allocation.
    ///
    /// This is a lineage-local invalidation primitive, not semantic equality
    /// and not a portable version. Clones share the root; every key or attached
    /// value mutation copy-on-writes it, even when the key-only fingerprint is
    /// unchanged by replacing a value.
    pub(crate) fn shares_root(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (None, None) => true,
            (Some(left), Some(right)) => left.tptr == right.tptr,
            _ => false,
        }
    }

    /// Whether the complete subtree under `prefix` is structurally shared.
    ///
    /// The prefix is in tree order and may end inside a compressed path or a
    /// segment. Two absent prefixes are shared; present prefixes require the
    /// same node body and kind, not equal counts or key-set fingerprints. An
    /// unrelated insertion may re-key that body's incoming edge without
    /// changing its contents, so the edge byte is not part of this comparison.
    ///
    /// Like [`Self::shares_root`], this is conservative, lineage-local
    /// invalidation evidence, not semantic equality or a portable version.
    /// Key changes and attached-value replacements through PATCH are observed;
    /// interior mutations of an attached value are outside this contract.
    pub(crate) fn shares_prefix<const PREFIX_LEN: usize>(
        &self,
        other: &Self,
        prefix: &[u8; PREFIX_LEN],
    ) -> bool {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        let left = self
            .root
            .as_ref()
            .and_then(|root| root.locate_prefix(0, prefix));
        let right = other
            .root
            .as_ref()
            .and_then(|root| root.locate_prefix(0, prefix));
        match (left, right) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                let mask = !(Head::<KEY_LEN, O, V, H>::KEY_MASK as usize);
                (left.tptr.as_ptr().addr() & mask) == (right.tptr.as_ptr().addr() & mask)
            }
            _ => false,
        }
    }

    /// Clone the opaque archive-owner receipt without exposing the root Head.
    pub(crate) fn owner_guard(&self) -> PATCHOwnerGuard {
        PATCHOwnerGuard(self.owners.clone())
    }

    /// Whether this PATCH and another PATCH share one owner-cover Arc.
    pub(crate) fn shares_owner_guard<OO, VV, HH>(&self, other: &PATCH<KEY_LEN, OO, VV, HH>) -> bool
    where
        OO: KeySchema<KEY_LEN>,
        HH: PatchHash,
    {
        match (&self.owners, &other.owners) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    /// Whether `owner` is the most recently adopted member of this cover.
    pub(crate) fn owner_guard_latest_is(&self, owner: &Arc<dyn ArchiveOwner>) -> bool {
        self.owners
            .as_ref()
            .is_some_and(|cover| cover.latest_address == OwnerCover::address(owner))
    }

    /// Install an owner cover proved to be a conservative superset of this
    /// PATCH's current receipt. Empty PATCHes may retain a receipt so all
    /// indexes of an aggregate can share one Arc.
    ///
    /// # Safety
    ///
    /// `guard` must retain every archive allocation retained by the current
    /// owner cover. Violating this can leave a LocalLeaf dangling.
    pub(crate) unsafe fn set_owner_guard(&mut self, guard: &PATCHOwnerGuard) {
        #[cfg(debug_assertions)]
        debug_assert!(
            guard.covers(&self.owners),
            "a PATCH owner guard may only be replaced by an owner-cover superset",
        );
        let already_installed = match (&self.owners, &guard.0) {
            (None, None) => true,
            (Some(current), Some(replacement)) => Arc::ptr_eq(current, replacement),
            _ => false,
        };
        if !already_installed {
            self.owners = guard.0.clone();
        }
        self.debug_check_owner_invariant();
    }

    /// Returns the value associated with `key` if present.
    pub fn get(&self, key: &[u8; KEY_LEN]) -> Option<&V> {
        self.root.as_ref().and_then(|root| root.get(0, key))
    }

    /// Allows iteratig over all infixes of a given length with a given prefix.
    /// Each infix is passed to the provided closure.
    ///
    /// The entire operation is performed over the tree view ordering of the keys.
    ///
    /// The length of the prefix and the infix is provided as type parameters,
    /// but will usually inferred from the arguments.
    ///
    /// The sum of `PREFIX_LEN` and `INFIX_LEN` must be less than or equal to `KEY_LEN`
    /// or a compile-time assertion will fail.
    ///
    /// Because all infixes are iterated in one go, less bookkeeping is required,
    /// than when using an Iterator, allowing for better performance.
    pub fn infixes<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        mut for_each: F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        const {
            assert!(PREFIX_LEN + INFIX_LEN <= KEY_LEN);
        }
        assert!(
            O::same_segment_tree(PREFIX_LEN, PREFIX_LEN + INFIX_LEN - 1)
                && (PREFIX_LEN + INFIX_LEN == KEY_LEN
                    || !O::same_segment_tree(PREFIX_LEN + INFIX_LEN - 1, PREFIX_LEN + INFIX_LEN)),
            "INFIX_LEN must cover a whole segment"
        );
        if let Some(root) = &self.root {
            root.infixes(prefix, 0, &mut for_each);
        }
    }

    /// Locate all distinct infixes for `prefix` only when their exact count is
    /// at most `limit`.
    ///
    /// `Some(view)` is an all-or-nothing proof that [`PATCHBoundedInfixes::len`]
    /// infixes fit the bound; [`PATCHBoundedInfixes::for_each`] then enumerates
    /// every one from the already-located subtree. `None` means the cached
    /// segment count exceeded `limit`. A missing prefix is a successful empty
    /// view.
    ///
    /// Locating the view costs `O(prefix depth)`. Visiting it costs
    /// `O(count)`, where `count <= limit`, so paged callers retain a hard
    /// geometric work bound while reserving output storage from the exact
    /// count before enumeration.
    pub fn bounded_infixes<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        limit: u64,
    ) -> Option<PATCHBoundedInfixes<'_, KEY_LEN, PREFIX_LEN, INFIX_LEN, O, V, H>> {
        const {
            assert!(PREFIX_LEN + INFIX_LEN <= KEY_LEN);
        }
        assert!(
            O::same_segment_tree(PREFIX_LEN, PREFIX_LEN + INFIX_LEN - 1)
                && (PREFIX_LEN + INFIX_LEN == KEY_LEN
                    || !O::same_segment_tree(PREFIX_LEN + INFIX_LEN - 1, PREFIX_LEN + INFIX_LEN)),
            "INFIX_LEN must cover a whole segment"
        );
        const {
            if PREFIX_LEN > 0 && PREFIX_LEN < KEY_LEN {
                assert!(
                    <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                        [O::TREE_TO_KEY[PREFIX_LEN - 1]]
                        != <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                            [O::TREE_TO_KEY[PREFIX_LEN]],
                    "PREFIX_LEN must align to segment boundary",
                );
            }
        }

        let Some(root) = &self.root else {
            return Some(PATCHBoundedInfixes {
                located: None,
                count: 0,
            });
        };
        let Some(located) = root.locate_prefix(0, prefix) else {
            return Some(PATCHBoundedInfixes {
                located: None,
                count: 0,
            });
        };
        let count = located.count_segment(PREFIX_LEN);
        if count > limit {
            return None;
        }
        Some(PATCHBoundedInfixes {
            located: Some(located),
            count,
        })
    }

    /// Like [`infixes`](Self::infixes) but only yields infixes in the
    /// byte range `[min_infix, max_infix]` (inclusive).
    ///
    /// The trie is pruned at each depth: branches whose byte key falls
    /// outside the range at the current infix position are skipped
    /// entirely, avoiding traversal of irrelevant subtrees.
    pub fn infixes_range<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
        mut for_each: F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        const {
            assert!(PREFIX_LEN + INFIX_LEN <= KEY_LEN);
        }
        assert!(
            O::same_segment_tree(PREFIX_LEN, PREFIX_LEN + INFIX_LEN - 1)
                && (PREFIX_LEN + INFIX_LEN == KEY_LEN
                    || !O::same_segment_tree(PREFIX_LEN + INFIX_LEN - 1, PREFIX_LEN + INFIX_LEN)),
            "INFIX_LEN must cover a whole segment"
        );
        if let Some(root) = &self.root {
            root.infixes_range(prefix, 0, min_infix, max_infix, &mut for_each);
        }
    }

    /// Return the lexicographically first distinct infix in the inclusive
    /// range `[min_infix, max_infix]` for `prefix`.
    ///
    /// This performs ordered lower-bound descent through the PATCH trie. It
    /// does not depend on the physical cuckoo-table order and does not
    /// materialize or sort the matching infixes.
    pub fn first_infix_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> Option<[u8; INFIX_LEN]> {
        const {
            assert!(PREFIX_LEN + INFIX_LEN <= KEY_LEN);
        }
        assert!(
            O::same_segment_tree(PREFIX_LEN, PREFIX_LEN + INFIX_LEN - 1)
                && (PREFIX_LEN + INFIX_LEN == KEY_LEN
                    || !O::same_segment_tree(PREFIX_LEN + INFIX_LEN - 1, PREFIX_LEN + INFIX_LEN)),
            "INFIX_LEN must cover a whole segment"
        );
        if min_infix > max_infix {
            return None;
        }
        self.root
            .as_ref()
            .and_then(|root| root.first_infix_range(prefix, 0, min_infix, max_infix))
    }

    /// Return the first distinct infix strictly after `after`, bounded above
    /// by `max_infix` (inclusive).
    ///
    /// The successor is computed in lexicographic byte order and then passed
    /// to [`Self::first_infix_range`]. `None` is returned when `after` is the
    /// all-`0xff` value or when no later infix exists.
    pub fn next_infix_after<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        after: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> Option<[u8; INFIX_LEN]> {
        let mut lower = *after;
        let mut cursor = INFIX_LEN;
        loop {
            if cursor == 0 {
                return None;
            }
            cursor -= 1;
            if lower[cursor] != u8::MAX {
                lower[cursor] += 1;
                for byte in &mut lower[cursor + 1..] {
                    *byte = u8::MIN;
                }
                break;
            }
        }
        self.first_infix_range(prefix, &lower, max_infix)
    }

    /// Count entries whose infix falls within [min_infix, max_infix].
    ///
    /// Uses cached `leaf_count` on branches to skip entire subtrees that
    /// are fully inside the range, making the count O(boundary_nodes)
    /// rather than O(matching_leaves).
    pub fn count_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> u64 {
        const {
            assert!(PREFIX_LEN + INFIX_LEN <= KEY_LEN);
        }
        match &self.root {
            Some(root) => root.count_range(prefix, 0, min_infix, max_infix),
            None => 0,
        }
    }

    /// Returns true if the PATCH has a key with the given prefix.
    ///
    /// `PREFIX_LEN` must be less than or equal to `KEY_LEN` or a compile-time
    /// assertion will fail.
    pub fn has_prefix<const PREFIX_LEN: usize>(&self, prefix: &[u8; PREFIX_LEN]) -> bool {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        if let Some(root) = &self.root {
            root.has_prefix(0, prefix)
        } else {
            PREFIX_LEN == 0
        }
    }

    /// Returns the number of PATCH nodes inspected by a prefix lookup.
    ///
    /// This is a diagnostic companion to [`PATCH::has_prefix`]. A miss counts
    /// the node where the mismatch or missing child is discovered; an empty
    /// PATCH reports zero.
    pub fn traversal_depth<const PREFIX_LEN: usize>(&self, prefix: &[u8; PREFIX_LEN]) -> usize {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        self.root
            .as_ref()
            .map(|root| root.traversal_depth(0, prefix))
            .unwrap_or(0)
    }

    /// Returns the number of unique segments in keys with the given prefix.
    pub fn segmented_len<const PREFIX_LEN: usize>(&self, prefix: &[u8; PREFIX_LEN]) -> u64 {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
            if PREFIX_LEN > 0 && PREFIX_LEN < KEY_LEN {
                assert!(
                    <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                        [O::TREE_TO_KEY[PREFIX_LEN - 1]]
                        != <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                            [O::TREE_TO_KEY[PREFIX_LEN]],
                    "PREFIX_LEN must align to segment boundary",
                );
            }
        }
        if let Some(root) = &self.root {
            root.segmented_len(0, prefix)
        } else {
            0
        }
    }

    /// Iterates over all keys in the PATCH.
    /// The keys are returned in key ordering but random order.
    pub fn iter<'a>(&'a self) -> PATCHIterator<'a, KEY_LEN, O, V, H> {
        PATCHIterator::new(self)
    }

    /// Iterates over all keys in the PATCH in key order.
    ///
    /// The traversal visits every key in lexicographic key order, without
    /// accepting a prefix filter. For prefix-aware iteration, see
    /// [`PATCH::iter_prefix_count`].
    pub fn iter_ordered<'a>(&'a self) -> PATCHOrderedIterator<'a, KEY_LEN, O, V, H> {
        PATCHOrderedIterator::new(self)
    }

    /// Iterate over all prefixes of the given length in the PATCH.
    /// The prefixes are naturally returned in tree ordering and tree order.
    /// A count of the number of elements for the given prefix is also returned.
    pub fn iter_prefix_count<'a, const PREFIX_LEN: usize>(
        &'a self,
    ) -> PATCHPrefixIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H> {
        PATCHPrefixIterator::new(self)
    }

    /// View every distinct tree-ordered prefix as one member of a set.
    ///
    /// `PREFIX_LEN` must end at a declared segment boundary. Bytes in later
    /// segments are deliberately projected away: adding or removing another
    /// suffix under an existing prefix does not change this view's membership.
    pub fn prefix_set<const PREFIX_LEN: usize>(
        &self,
    ) -> PATCHPrefixSet<'_, KEY_LEN, PREFIX_LEN, O, V, H> {
        PATCHPrefixSet::new(self)
    }

    /// Unions this PATCH with another PATCH.
    ///
    /// The other PATCH is consumed, and this PATCH is updated in place.
    /// If both PATCHes contain the same key, one associated value survives,
    /// but this operation does not specify which operand supplies it. Values
    /// do not participate in PATCH key-set identity, and the merge may swap
    /// operands internally.
    pub fn union(&mut self, mut other: Self)
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        if let Some(other_root) = other.root.take() {
            if self.root.is_some() {
                // Install the complete lifetime union before either Head can
                // detach or move LocalLeaves. `other` keeps its own cover
                // until the trie merge completes, including on unwind.
                OwnerCover::merge_into(&mut self.owners, &other.owners);
                let this = self.root.take().expect("root should not be empty");
                #[cfg(feature = "parallel")]
                let merged = Head::par_union(this, other_root, 0);
                #[cfg(not(feature = "parallel"))]
                let merged = Head::union(this, other_root, 0);
                self.root.replace(merged);
            } else {
                self.root.replace(other_root);
                self.owners = other.owners.take();
            }
        }
        self.debug_check_owner_invariant();
    }

    /// Intersects this PATCH with another PATCH.
    ///
    /// Returns a new PATCH that contains only the keys that are present in both PATCHes.
    pub fn intersect(&self, other: &Self) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        let guard = self.owner_guard().join(other.owner_guard());
        // SAFETY: the exact union retains every owner held by either source.
        unsafe { self.intersect_with_guard(other, &guard) }
    }

    /// Intersect under an owner receipt already joined by an aggregate.
    ///
    /// # Safety
    ///
    /// `guard` must retain every archive allocation retained by either input.
    /// Intersection may reuse a LocalLeaf from either trie.
    pub(crate) unsafe fn intersect_with_guard(&self, other: &Self, guard: &PATCHOwnerGuard) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        #[cfg(debug_assertions)]
        debug_assert!(
            guard.covers(&self.owners) && guard.covers(&other.owners),
            "an intersection guard must cover both source PATCHes",
        );
        let root = match (&self.root, &other.root) {
            (Some(root), Some(other_root)) => {
                #[cfg(feature = "parallel")]
                let result = root.par_intersect(other_root, 0);
                #[cfg(not(feature = "parallel"))]
                let result = root.intersect(other_root, 0);
                result.map(|root| root.with_start(0))
            }
            _ => None,
        };
        let owners = root.as_ref().and(guard.0.clone());
        let result = Self { root, owners };
        result.debug_check_owner_invariant();
        result
    }

    /// Returns the difference between this PATCH and another PATCH.
    ///
    /// Returns a new PATCH that contains only the keys that are present in this PATCH,
    /// but not in the other PATCH.
    pub fn difference(&self, other: &Self) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        let guard = self.owner_guard();
        // SAFETY: difference can only reuse LocalLeaves from its left source.
        unsafe { self.difference_with_guard(other, &guard) }
    }

    /// Subtract under a left-owner receipt already combined by an aggregate.
    ///
    /// # Safety
    ///
    /// `guard` must retain every archive allocation retained by `self`.
    /// Difference never introduces a LocalLeaf from `other`.
    pub(crate) unsafe fn difference_with_guard(&self, other: &Self, guard: &PATCHOwnerGuard) -> Self
    where
        O: Send + Sync,
        V: Send + Sync,
    {
        #[cfg(debug_assertions)]
        debug_assert!(
            guard.covers(&self.owners),
            "a difference guard must cover its left source PATCH",
        );
        let root = match (&self.root, &other.root) {
            (Some(root), Some(other_root)) => {
                #[cfg(feature = "parallel")]
                let result = root.par_difference(other_root, 0);
                #[cfg(not(feature = "parallel"))]
                let result = root.difference(other_root, 0);
                result
            }
            (Some(root), None) => Some(root.clone()),
            (None, _) => None,
        };
        let owners = root.as_ref().and(guard.0.clone());
        let result = Self { root, owners };
        result.debug_check_owner_invariant();
        result
    }

    /// Calculates the average fill level for branch nodes grouped by their
    /// branching factor. The returned array contains eight entries for branch
    /// sizes `2`, `4`, `8`, `16`, `32`, `64`, `128` and `256` in that order.
    //#[cfg(debug_assertions)]
    pub fn debug_branch_fill(&self) -> [f32; 8] {
        let mut counts = [0u64; 8];
        let mut used = [0u64; 8];

        if let Some(root) = &self.root {
            let mut stack = Vec::new();
            stack.push(root);

            while let Some(head) = stack.pop() {
                match head.body_ref() {
                    BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => {}
                    BodyRef::Branch(b) => {
                        let size = b.child_table.len();
                        let idx = size.trailing_zeros() as usize - 1;
                        counts[idx] += 1;
                        used[idx] += b.child_table.iter().filter(|c| c.is_some()).count() as u64;
                        for child in b.child_table.iter().filter_map(|c| c.as_ref()) {
                            stack.push(child);
                        }
                    }
                }
            }
        }

        let mut avg = [0f32; 8];
        for i in 0..8 {
            if counts[i] > 0 {
                let size = 1u64 << (i + 1);
                avg[i] = used[i] as f32 / (counts[i] as f32 * size as f32);
            }
        }
        avg
    }
}

impl<const KEY_LEN: usize, O, V> PATCH<KEY_LEN, O, V, Blake3Merkle>
where
    O: KeySchema<KEY_LEN>,
{
    /// Return the canonical BLAKE3 Merkle root for this key set.
    ///
    /// `None` is the unique empty-set representation. The digest is stable
    /// across processes and construction histories; callers that need to
    /// scope anti-entropy to a team should key or domain-separate this root at
    /// that protocol boundary rather than changing PATCH's canonical identity.
    pub fn merkle_root(&self) -> Option<[u8; 32]> {
        self.root_hash()
    }
}

impl<const KEY_LEN: usize, V> PATCH<KEY_LEN, IdentitySchema, V, Blake3Merkle> {
    /// Locate the shallowest logical Merkle node whose compressed path covers
    /// `prefix`.
    ///
    /// Lookup walks raw key bytes from the root; PATCH maintains no
    /// digest-to-node side map. If `prefix` ends inside a compressed path, the
    /// returned node's [`PATCHMerkleNode::prefix`] extends beyond the request
    /// to that node's canonical `end_depth`. A prefix longer than `KEY_LEN`, a
    /// mismatching compressed path, or a missing child returns `None`.
    pub fn merkle_node(&self, prefix: &[u8]) -> Option<PATCHMerkleNode<'_, KEY_LEN, V>> {
        if prefix.len() > KEY_LEN {
            return None;
        }

        let mut node = self.root.as_ref()?;
        let mut at_depth = 0;
        loop {
            let end_depth = node.end_depth();
            let limit = prefix.len().min(end_depth);
            if node.childleaf_key()[at_depth..limit] != prefix[at_depth..limit] {
                return None;
            }
            if prefix.len() <= end_depth {
                return Some(PATCHMerkleNode::new(node));
            }

            let BodyRef::Branch(branch) = node.body_ref() else {
                unreachable!("a leaf covers every raw-key byte");
            };
            node = branch.child_table.table_get(prefix[end_depth])?;
            at_depth = end_depth;
        }
    }
}

impl<const KEY_LEN: usize> PATCH<KEY_LEN, IdentitySchema, (), Blake3Merkle> {
    /// Build an immutable key-only PATCH bottom-up.
    ///
    /// Input order and duplicates are ignored. Already sorted, unique input
    /// takes a linear fast path; all other input is sorted and deduplicated
    /// before construction. Every retained key becomes one owned leaf, and
    /// every final Merkle node is hashed exactly once during construction
    /// while recursion carries child digests upward. Debug builds additionally
    /// recompute branch digests as an invariant audit.
    ///
    /// This is the construction path for canonical inventory snapshots. Use
    /// [`Self::insert`] instead when preserving an existing PATCH and editing
    /// only a small number of keys is more important than whole-set build
    /// throughput.
    pub fn from_keys(keys: impl IntoIterator<Item = [u8; KEY_LEN]>) -> Self {
        Self::from_owned_keys(keys.into_iter().collect())
    }
}

impl<const KEY_LEN: usize, H: PatchHash> PATCH<KEY_LEN, IdentitySchema, (), H> {
    fn from_owned_keys(mut keys: Vec<[u8; KEY_LEN]>) -> Self {
        H::init();
        if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                keys.par_sort_unstable();
            }
            #[cfg(not(feature = "parallel"))]
            keys.sort_unstable();
            keys.dedup();
        }

        let root = (!keys.is_empty()).then(|| Self::build_owned_sorted_head(&keys, 0).0);
        let result = Self { root, owners: None };
        result.debug_check_owner_invariant();
        result
    }

    /// Build one logical node from a nonempty sorted, duplicate-free key run.
    /// The returned digest is carried by the returned Head and is returned
    /// separately so its parent never has to re-read or recompute it.
    fn build_owned_sorted_head(
        keys: &[[u8; KEY_LEN]],
        depth: usize,
    ) -> (Head<KEY_LEN, IdentitySchema, (), H>, H::Digest) {
        debug_assert!(!keys.is_empty());
        if keys.len() == 1 {
            // SAFETY: Leaf::new returns one initialized, 16-byte-aligned,
            // refcount-one allocation. This Head becomes its sole owner.
            let leaf = unsafe { Leaf::<KEY_LEN, (), H>::new(&keys[0], ()) };
            let digest = unsafe { leaf.as_ref().hash };
            return (Head::new(0, leaf), digest);
        }

        // Lexicographic ordering means the first and last keys determine the
        // common prefix of the entire run.
        let first = &keys[0];
        let last = &keys[keys.len() - 1];
        let mut end_depth = depth;
        while end_depth < KEY_LEN && first[end_depth] == last[end_depth] {
            end_depth += 1;
        }
        debug_assert!(
            end_depth < KEY_LEN,
            "deduplicated keys must diverge before their end"
        );

        let mut groups = Vec::with_capacity(256.min(keys.len()));
        let mut start = 0;
        while start < keys.len() {
            let edge = keys[start][end_depth];
            let width = keys[start..].partition_point(|key| key[end_depth] == edge);
            let end = start + width;
            groups.push((edge, &keys[start..end]));
            start = end;
        }
        debug_assert!(groups.len() >= 2);
        let initial_slots = if groups.len() == 2 {
            2
        } else {
            groups.len().next_power_of_two()
        };

        #[cfg(feature = "parallel")]
        let children = if keys.len() >= Self::PARALLEL_PARTITION_THRESHOLD {
            use rayon::prelude::*;
            groups
                .into_par_iter()
                .map(|(edge, child_keys)| {
                    let (head, digest) = Self::build_owned_sorted_head(child_keys, end_depth + 1);
                    (edge, head, digest)
                })
                .collect()
        } else {
            groups
                .into_iter()
                .map(|(edge, child_keys)| {
                    let (head, digest) = Self::build_owned_sorted_head(child_keys, end_depth + 1);
                    (edge, head, digest)
                })
                .collect()
        };
        #[cfg(not(feature = "parallel"))]
        let children = groups
            .into_iter()
            .map(|(edge, child_keys)| {
                let (head, digest) = Self::build_owned_sorted_head(child_keys, end_depth + 1);
                (edge, head, digest)
            })
            .collect();

        Self::assemble_partition_branch(end_depth, initial_slots, children)
    }
}

/// Archive-backed insertion path, available only for `V = ()` because
/// [`ArchiveEntry`] does not carry a value. Newly inserted archive keys remain
/// LocalLeaves while the PATCH's deduplicated root cover retains their
/// allocations.
impl<const KEY_LEN: usize, O, H> PATCH<KEY_LEN, O, (), H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    /// Inserts an archive-backed key and retains its allocation before the
    /// LocalLeaf becomes reachable from the root.
    pub fn insert_archive(&mut self, entry: &ArchiveEntry<'_, KEY_LEN, H>) {
        let (leaf_head, leaf_owner, leaf_hash) = entry.leaf::<O>();
        OwnerCover::retain(&mut self.owners, leaf_owner);
        if let Some(this) = self.root.take() {
            let new_head = Head::insert_archive_leaf(this, leaf_head, leaf_hash, 0);
            self.root.replace(new_head);
        } else {
            self.root.replace(leaf_head);
        }
        self.debug_check_owner_invariant();
    }

    /// Builds a canonical PATCH directly from an unordered row permutation by
    /// partitioning that one buffer in place at each trie depth.
    ///
    /// Archive construction fuses ordering and trie construction: no sorted
    /// pointer array or per-row leaf descriptor is retained. `hashes[row]` is
    /// the one transient key hash shared by every TribleSet index build.
    ///
    /// # Safety
    ///
    /// - `rows` must contain every valid index into `keys` and `hashes` exactly
    ///   once.
    /// - Every key pointer must be 16-byte aligned, immutable, and kept alive
    ///   by `owner`.
    /// - `keys` must contain no duplicates.
    /// - `hashes[row]` must be the PATCH key hash of `keys[row]`.
    #[cfg(test)]
    pub(crate) unsafe fn from_archive_partition(
        keys: &[[u8; KEY_LEN]],
        hashes: &[H::Digest],
        rows: &mut [u32],
        owner: &std::sync::Arc<dyn ArchiveOwner>,
    ) -> Self {
        unsafe {
            Self::from_archive_partition_with_guard(
                keys,
                hashes,
                rows,
                owner,
                &PATCHOwnerGuard::default(),
            )
        }
    }

    /// Build an archive partition under a receipt already shared by an
    /// aggregate. Retaining `owner` is idempotent when it is already the
    /// receipt's latest member, preserving the shared cover Arc.
    #[cfg(any(test, feature = "parallel"))]
    pub(crate) unsafe fn from_archive_partition_with_guard(
        keys: &[[u8; KEY_LEN]],
        hashes: &[H::Digest],
        rows: &mut [u32],
        owner: &std::sync::Arc<dyn ArchiveOwner>,
        guard: &PATCHOwnerGuard,
    ) -> Self {
        // Branch child tables use randomness initialized alongside the
        // hash-key bundle. A pre-hashed caller may reach this constructor
        // before PATCH::new.
        H::init();
        assert_eq!(keys.len(), hashes.len());
        assert_eq!(keys.len(), rows.len());
        assert!(
            u32::try_from(rows.len()).is_ok(),
            "archive row ordinals must fit the partition metadata",
        );
        if rows.is_empty() {
            return Self::new();
        }
        let mut guard = guard.clone();
        guard.retain_archive_owner(owner);
        let owners = guard.0;
        if rows.len() == 1 {
            let row = rows[0] as usize;
            let ptr = NonNull::from(&keys[row]);
            // SAFETY: the caller proves alignment and `owners` retains the
            // archive allocation for the returned PATCH's lifetime.
            let root = unsafe { Head::new_local_leaf(0, ptr) };
            let result = Self {
                root: Some(root),
                owners,
            };
            result.debug_check_owner_invariant();
            return result;
        }

        let (root, _) = unsafe { Self::build_archive_partition_head(keys, hashes, rows, 0) };
        let result = Self {
            root: Some(root.with_start(0)),
            owners,
        };
        result.debug_check_owner_invariant();
        result
    }

    /// Row count at or above which one trie node builds its children on
    /// separate workers instead of recursing into them in order.
    ///
    /// The MSD partition already hands each child a disjoint, contiguous
    /// interval of the one permutation buffer, so the fan-out costs no copy
    /// and no synchronisation — only the task overhead this threshold pays
    /// for. Below it a node is cheaper to walk than to schedule.
    #[cfg(feature = "parallel")]
    pub(crate) const PARALLEL_PARTITION_THRESHOLD: usize = 1 << 12;

    /// Rows one worker is given before a partition pass is worth splitting.
    ///
    /// A counting pass is a sequential read and a scatter is a random write,
    /// so a worker needs enough rows to amortise the histogram reduction and
    /// the second buffer. Below two workers' worth, the in-place American-flag
    /// pass is both cheaper and allocation-free.
    #[cfg(feature = "parallel")]
    pub(crate) const PARTITION_ROWS_PER_WORKER: usize = 1 << 13;

    /// How many workers an out-of-place partition of `rows` should use, and
    /// therefore whether it beats the in-place pass at all.
    #[cfg(feature = "parallel")]
    pub(crate) fn partition_workers(rows: usize) -> usize {
        (rows / Self::PARTITION_ROWS_PER_WORKER)
            .min(rayon::current_num_threads().max(1))
            .max(1)
    }

    /// Representative-LCP plus in-place MSD-radix worker for
    /// [`Self::from_archive_partition`].
    ///
    /// Trie construction is ownership-neutral. One deduplicated conservative
    /// owner cover on the returned PATCH guards every LocalLeaf regardless of
    /// later reshaping.
    ///
    /// With the `parallel` feature a node meets one of three regimes, by
    /// size: wide enough for [`Self::partition_workers`] to want more than one
    /// worker, it is split by the out-of-place counting pass and its children
    /// are built concurrently; merely at or above
    /// [`Self::PARALLEL_PARTITION_THRESHOLD`], it keeps the in-place pass and
    /// only its children go concurrent; below that it is walked in order.
    ///
    /// All three build the same trie. Children own disjoint intervals of the
    /// permutation and disjoint subtrees of the result, the child heads are
    /// reassembled in ascending key order either way, and the node hash is a
    /// canonical summary over edge-sorted children — so neither the order
    /// children are built in nor the order rows sit in within a bucket can
    /// reach the answer.
    #[cfg(any(test, feature = "parallel"))]
    unsafe fn build_archive_partition_head(
        keys: &[[u8; KEY_LEN]],
        hashes: &[H::Digest],
        rows: &mut [u32],
        depth: usize,
    ) -> (Head<KEY_LEN, O, (), H>, H::Digest) {
        debug_assert!(!rows.is_empty());
        if rows.len() == 1 {
            let row = rows[0] as usize;
            let ptr = NonNull::from(&keys[row]);
            // SAFETY: the outer constructor installs its owner cover before
            // returning this LocalLeaf to safe code.
            let head = unsafe { Head::new_local_leaf(0, ptr) };
            return (head, hashes[row]);
        }

        // A node big enough to be worth the extra buffer counts and scatters
        // its children across workers instead of walking them in place; a
        // node merely big enough to be worth a task keeps the in-place pass
        // and only recurses concurrently.
        #[cfg(feature = "parallel")]
        if Self::partition_workers(rows.len()) > 1 {
            let (plan, mut permuted) = Self::partition_archive_rows_parallel(keys, rows, depth);
            // SAFETY: `permuted` is the same multiset of row ordinals as
            // `rows`, grouped by the same key byte.
            return unsafe {
                Self::build_archive_partition_children(keys, hashes, &mut permuted, &plan)
            };
        }

        let plan = Self::partition_archive_rows(keys, rows, depth);
        let end_depth = plan.end_depth;

        #[cfg(feature = "parallel")]
        if rows.len() >= Self::PARALLEL_PARTITION_THRESHOLD {
            // SAFETY: same contract, on the in-place permutation.
            return unsafe { Self::build_archive_partition_children(keys, hashes, rows, &plan) };
        }

        let first_bucket = plan.buckets[0];
        let second_bucket = plan.buckets[1];
        let first_end = plan.ends[first_bucket as usize] as usize;
        let (first_head, first_hash) = unsafe {
            Self::build_archive_partition_head(keys, hashes, &mut rows[..first_end], end_depth + 1)
        };
        let second_end = plan.ends[second_bucket as usize] as usize;
        let (second_head, second_hash) = unsafe {
            Self::build_archive_partition_head(
                keys,
                hashes,
                &mut rows[first_end..second_end],
                end_depth + 1,
            )
        };
        let first_count = first_head.count();
        let second_count = second_head.count();

        let body = if plan.initial_slots == 2 {
            Branch::new_with_child_hashes(
                end_depth,
                first_head.with_key(first_bucket),
                second_head.with_key(second_bucket),
                first_hash,
                second_hash,
            )
        } else {
            Branch::new_with_child_hashes_capacity(
                end_depth,
                first_head.with_key(first_bucket),
                second_head.with_key(second_bucket),
                first_hash,
                second_hash,
                plan.initial_slots,
            )
        };
        let mut root = Head::new(0, body);
        let representative = &keys[rows[0] as usize];
        let mut hash_state = H::begin_branch(
            representative,
            &O::TREE_TO_KEY,
            end_depth,
            plan.fanout,
            rows.len() as u64,
        );
        H::push_child(&mut hash_state, first_bucket, first_count, first_hash);
        H::push_child(&mut hash_state, second_bucket, second_count, second_hash);
        if plan.fanout == 2 {
            debug_assert_eq!(second_end, rows.len());
            return (root, H::finish_branch(hash_state));
        }

        let mut editor = BranchMut::from_head(&mut root);
        let mut range_start = second_end;
        for &byte in &plan.buckets[2..plan.fanout] {
            let range_end = plan.ends[byte as usize] as usize;
            let (child, child_hash) = unsafe {
                Self::build_archive_partition_head(
                    keys,
                    hashes,
                    &mut rows[range_start..range_end],
                    end_depth + 1,
                )
            };
            let child_count = child.count();
            H::push_child(&mut hash_state, byte, child_count, child_hash);
            editor.install_child_growing(child.with_key(byte));
            range_start = range_end;
        }
        debug_assert_eq!(range_start, rows.len());

        // Rebuild structural aggregates once and install the exact canonical
        // summary carried by recursion, avoiding another hash read from direct
        // LocalLeaves.
        let hash = H::finish_branch(hash_state);
        editor.finish_bulk_aggregates(hash);
        drop(editor);
        (root, hash)
    }

    /// Build every child of one already-partitioned node concurrently.
    ///
    /// The partition hands each child a disjoint, contiguous interval of the
    /// permutation, so `split_at_mut` is the whole proof that the concurrent
    /// recursion cannot alias: disjoint rows, disjoint subtrees, and a node
    /// hash summarized over children in canonical edge order.
    ///
    /// # Safety
    ///
    /// The caller's `keys`/`hashes` contract must hold, and `rows` must be
    /// grouped by `plan` as [`Self::partition_archive_rows`] leaves it.
    #[cfg(feature = "parallel")]
    unsafe fn build_archive_partition_children(
        keys: &[[u8; KEY_LEN]],
        hashes: &[H::Digest],
        rows: &mut [u32],
        plan: &ArchivePartitionPlan,
    ) -> (Head<KEY_LEN, O, (), H>, H::Digest) {
        use rayon::prelude::*;

        let end_depth = plan.end_depth;
        let mut remaining: &mut [u32] = rows;
        let mut intervals: Vec<(u8, &mut [u32])> = Vec::with_capacity(plan.fanout);
        let mut previous_end = 0usize;
        for &byte in &plan.buckets[..plan.fanout] {
            let end = plan.ends[byte as usize] as usize;
            let (child, rest) = remaining.split_at_mut(end - previous_end);
            intervals.push((byte, child));
            remaining = rest;
            previous_end = end;
        }
        debug_assert!(remaining.is_empty());

        let children: Vec<(u8, Head<KEY_LEN, O, (), H>, H::Digest)> = intervals
            .into_par_iter()
            .map(|(byte, child_rows)| {
                // SAFETY: the caller's contract holds for every subinterval,
                // and the intervals are pairwise disjoint.
                let (head, hash) = unsafe {
                    Self::build_archive_partition_head(keys, hashes, child_rows, end_depth + 1)
                };
                (byte, head, hash)
            })
            .collect();

        Self::assemble_partition_branch(end_depth, plan.initial_slots, children)
    }

    /// Out-of-place counting-sort twin of [`Self::partition_archive_rows`].
    ///
    /// The in-place American-flag pass is a chain of dependent swaps and can
    /// only ever run on one worker, which is exactly what caps a whole-archive
    /// build: six root passes over every row, each a serial storm of cache
    /// misses. Counting into per-worker histograms and scattering into a
    /// second buffer costs one extra `u32` per row and runs on every worker.
    ///
    /// The result groups the same rows under the same key bytes. It does not
    /// preserve their relative order within a bucket, and does not need to:
    /// keys are distinct, so the trie a bucket produces is a function of its
    /// key set alone, and children are installed in ascending byte order
    /// either way.
    #[cfg(feature = "parallel")]
    fn partition_archive_rows_parallel(
        keys: &[[u8; KEY_LEN]],
        rows: &[u32],
        depth: usize,
    ) -> (ArchivePartitionPlan, Vec<u32>) {
        use rayon::prelude::*;

        let workers = Self::partition_workers(rows.len());
        let stride = rows.len().div_ceil(workers).max(1);

        // Every worker narrows the representative's prefix over its own run;
        // the shortest agreement wins, which is the same minimum the ordered
        // scan converges to.
        let representative = &keys[rows[0] as usize];
        let end_depth = rows[1..]
            .par_chunks(stride)
            .map(|chunk| {
                let mut shortest = KEY_LEN;
                for &row in chunk {
                    let key = &keys[row as usize];
                    let mut candidate_depth = depth;
                    while candidate_depth < shortest {
                        let key_index = O::TREE_TO_KEY[candidate_depth];
                        if representative[key_index] != key[key_index] {
                            shortest = candidate_depth;
                            break;
                        }
                        candidate_depth += 1;
                    }
                    if shortest == depth {
                        break;
                    }
                }
                shortest
            })
            .min()
            .unwrap_or(KEY_LEN);
        assert!(
            end_depth < KEY_LEN,
            "duplicate archive keys cannot form a finite trie",
        );

        let key_index = O::TREE_TO_KEY[end_depth];
        let histograms: Vec<[u32; 256]> = rows
            .par_chunks(stride)
            .map(|chunk| {
                let mut counts = [0u32; 256];
                for &row in chunk {
                    counts[keys[row as usize][key_index] as usize] += 1;
                }
                counts
            })
            .collect();

        let mut totals = [0u32; 256];
        for counts in &histograms {
            for (total, count) in totals.iter_mut().zip(counts.iter()) {
                *total += count;
            }
        }

        let mut buckets = [0u8; 256];
        let mut fanout = 0usize;
        let mut ends = [0u32; 256];
        let mut bases = [0u32; 256];
        let mut offset = 0u32;
        for (byte, &total) in totals.iter().enumerate() {
            if total == 0 {
                continue;
            }
            buckets[fanout] = byte as u8;
            fanout += 1;
            bases[byte] = offset;
            offset += total;
            ends[byte] = offset;
        }
        debug_assert_eq!(offset as usize, rows.len());
        debug_assert!((2..=256).contains(&fanout));
        let initial_slots = if fanout == 2 {
            2
        } else {
            fanout.next_power_of_two()
        };

        // Each worker's rows for a bucket land after every earlier worker's,
        // so the per-worker cursors carve the bucket into disjoint windows.
        let mut cursors: Vec<[u32; 256]> = vec![[0u32; 256]; histograms.len()];
        let mut running = bases;
        for (cursor, counts) in cursors.iter_mut().zip(histograms.iter()) {
            for &byte in &buckets[..fanout] {
                let byte = byte as usize;
                cursor[byte] = running[byte];
                running[byte] += counts[byte];
            }
        }

        let mut permuted: Vec<u32> = Vec::with_capacity(rows.len());
        let scatter = parallel_union::ScatterPtr(permuted.as_mut_ptr());
        rows.par_chunks(stride)
            .zip(cursors.into_par_iter())
            .for_each(|(chunk, mut cursor)| {
                for &row in chunk {
                    let byte = keys[row as usize][key_index] as usize;
                    let slot = cursor[byte] as usize;
                    // SAFETY: slot is inside the buffer and inside this
                    // worker's window of this bucket, so no other worker
                    // writes it.
                    unsafe { scatter.write_at(slot, row) };
                    cursor[byte] += 1;
                }
            });
        // SAFETY: the cursors partition `0..rows.len()`, so every slot was
        // written exactly once above.
        unsafe { permuted.set_len(rows.len()) };

        (
            ArchivePartitionPlan {
                end_depth,
                ends,
                buckets,
                fanout,
                initial_slots,
            },
            permuted,
        )
    }

    /// Install already-built children, in ascending key order, under one
    /// branch at `end_depth`.
    ///
    /// Children arrive as values, so whether they came from archive
    /// partitioning, a sorted owned-key build, or parallel recursion is
    /// invisible here. The final digest is computed before allocation and
    /// installed directly, so no temporary two-child BLAKE node is hashed.
    fn assemble_partition_branch(
        end_depth: usize,
        initial_slots: usize,
        children: Vec<(u8, Head<KEY_LEN, O, (), H>, H::Digest)>,
    ) -> (Head<KEY_LEN, O, (), H>, H::Digest) {
        debug_assert!(children.len() >= 2);
        debug_assert!(children.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let child_count = children.len();
        let leaf_count = children.iter().map(|(_, child, _)| child.count()).sum();
        let mut hash_state = H::begin_branch(
            children[0].1.childleaf_key(),
            &O::TREE_TO_KEY,
            end_depth,
            child_count,
            leaf_count,
        );
        for &(edge, ref child, digest) in &children {
            H::push_child(&mut hash_state, edge, child.count(), digest);
        }
        let hash = H::finish_branch(hash_state);

        let mut drain = children.into_iter();
        let (first_bucket, first_head, _) = drain.next().expect("two children");
        let (second_bucket, second_head, _) = drain.next().expect("two children");
        let body = if initial_slots == 2 {
            Branch::new_with_known_hash(
                end_depth,
                first_head.with_key(first_bucket),
                second_head.with_key(second_bucket),
                hash,
            )
        } else {
            Branch::new_with_known_hash_capacity(
                end_depth,
                first_head.with_key(first_bucket),
                second_head.with_key(second_bucket),
                hash,
                initial_slots,
            )
        };
        let mut root = Head::new(0, body);
        let mut extra = drain.peekable();
        if extra.peek().is_none() {
            return (root, hash);
        }
        let mut editor = BranchMut::from_head(&mut root);
        for (byte, child, _) in extra {
            editor.install_child_growing(child.with_key(byte));
        }
        editor.finish_bulk_aggregates(hash);
        drop(editor);
        (root, hash)
    }

    /// One trie node's split: where its children diverge, which key bytes are
    /// occupied, and where each child's rows now sit inside `rows`.
    ///
    /// The rows are permuted in place by an American-flag pass, so on return
    /// bucket `buckets[i]` owns `rows[ends[buckets[i-1]]..ends[buckets[i]]]`.
    #[cfg(any(test, feature = "parallel"))]
    fn partition_archive_rows(
        keys: &[[u8; KEY_LEN]],
        rows: &mut [u32],
        depth: usize,
    ) -> ArchivePartitionPlan {
        // Tighten the representative's common prefix row-by-row. Once the
        // candidate reaches the incoming depth, no later row can shorten it.
        let representative = &keys[rows[0] as usize];
        let mut end_depth = KEY_LEN;
        for &row in &rows[1..] {
            let key = &keys[row as usize];
            let mut candidate_depth = depth;
            while candidate_depth < end_depth {
                let key_index = O::TREE_TO_KEY[candidate_depth];
                if representative[key_index] != key[key_index] {
                    end_depth = candidate_depth;
                    break;
                }
                candidate_depth += 1;
            }
            if end_depth == depth {
                break;
            }
        }
        assert!(
            end_depth < KEY_LEN,
            "duplicate archive keys cannot form a finite trie",
        );

        let key_index = O::TREE_TO_KEY[end_depth];
        let mut ends = [0u32; 256];
        let mut occupied = ByteSet::new_empty();
        for &row in rows.iter() {
            let byte = keys[row as usize][key_index];
            let count = &mut ends[byte as usize];
            if *count == 0 {
                occupied.insert(byte);
            }
            *count += 1;
        }

        let mut buckets = [0u8; 256];
        let mut fanout = 0usize;
        let mut listing = occupied;
        while let Some(byte) = listing.drain_next_ascending() {
            buckets[fanout] = byte;
            fanout += 1;
        }
        debug_assert!((2..=256).contains(&fanout));
        let initial_slots = if fanout == 2 {
            2
        } else {
            fanout.next_power_of_two()
        };

        // Convert counts into cumulative exclusive ends. `next` tracks the
        // first unfilled position in each occupied interval.
        let mut next = [0u32; 256];
        let mut offset = 0u32;
        for &byte in &buckets[..fanout] {
            let count = ends[byte as usize];
            next[byte as usize] = offset;
            offset += count;
            ends[byte as usize] = offset;
        }
        debug_assert_eq!(offset as usize, rows.len());

        // American-flag partition. Every swap permanently fills one
        // destination position, so this is linear and needs no second buffer.
        for &byte in &buckets[..fanout] {
            let bucket = byte as usize;
            while next[bucket] < ends[bucket] {
                let position = next[bucket] as usize;
                let row = rows[position] as usize;
                let destination = keys[row][key_index] as usize;
                if destination == bucket {
                    next[bucket] += 1;
                } else {
                    let destination_slot = next[destination] as usize;
                    debug_assert!(destination_slot < ends[destination] as usize);
                    rows.swap(position, destination_slot);
                    next[destination] += 1;
                }
            }
        }

        ArchivePartitionPlan {
            end_depth,
            ends,
            buckets,
            fanout,
            initial_slots,
        }
    }
}

/// Where one trie node's children start and end inside the shared permutation.
#[cfg(any(test, feature = "parallel"))]
struct ArchivePartitionPlan {
    /// Tree depth at which this node's children diverge.
    end_depth: usize,
    /// Exclusive end offset of each occupied bucket, indexed by key byte.
    ends: [u32; 256],
    /// The occupied key bytes, ascending, in `buckets[..fanout]`.
    buckets: [u8; 256],
    fanout: usize,
    /// Child-table capacity the branch is born with.
    initial_slots: usize,
}

impl<const KEY_LEN: usize, O, V, H> PartialEq for PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    fn eq(&self, other: &Self) -> bool {
        self.root.as_ref().map(|root| root.hash()) == other.root.as_ref().map(|root| root.hash())
    }
}

impl<const KEY_LEN: usize, O, V, H> Eq for PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
}

impl<'a, const KEY_LEN: usize, O, V, H> IntoIterator for &'a PATCH<KEY_LEN, O, V, H>
where
    O: KeySchema<KEY_LEN>,
    H: PatchHash,
{
    type Item = &'a [u8; KEY_LEN];
    type IntoIter = PATCHIterator<'a, KEY_LEN, O, V, H>;

    fn into_iter(self) -> Self::IntoIter {
        PATCHIterator::new(self)
    }
}

/// An iterator over all keys in a PATCH.
/// The keys are returned in key ordering but in random order.
pub struct PATCHIterator<
    'a,
    const KEY_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    // Root-to-leaf branch depths strictly increase within 0..KEY_LEN, so
    // seeding from the real root branch keeps the live stack within KEY_LEN.
    stack: ArrayVec<std::slice::Iter<'a, Option<Head<KEY_LEN, O, V, H>>>, KEY_LEN>,
    // A singleton root has no branch frame, including when KEY_LEN is zero.
    pending_leaf: Option<&'a [u8; KEY_LEN]>,
    remaining: usize,
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    PATCHIterator<'a, KEY_LEN, O, V, H>
{
    /// Creates an iterator over all keys in `patch`.
    pub fn new(patch: &'a PATCH<KEY_LEN, O, V, H>) -> Self {
        let mut r = PATCHIterator {
            stack: ArrayVec::new(),
            pending_leaf: None,
            remaining: patch.len().min(usize::MAX as u64) as usize,
        };
        if let Some(root) = &patch.root {
            match root.body_ref() {
                BodyRef::Leaf(leaf) => r.pending_leaf = Some(&leaf.key),
                BodyRef::LocalLeaf(key) => r.pending_leaf = Some(key),
                BodyRef::Branch(branch) => r.stack.push(branch.child_table.iter()),
            }
        }
        r
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Iterator
    for PATCHIterator<'a, KEY_LEN, O, V, H>
{
    type Item = &'a [u8; KEY_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(key) = self.pending_leaf.take() {
            self.remaining = self.remaining.saturating_sub(1);
            return Some(key);
        }
        let mut iter = self.stack.last_mut()?;
        loop {
            if let Some(child) = iter.next() {
                if let Some(child) = child {
                    match child.body_ref() {
                        BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => {
                            self.remaining = self.remaining.saturating_sub(1);
                            // Use the safe accessor on the child reference to obtain the leaf key bytes.
                            return Some(child.childleaf_key());
                        }
                        BodyRef::Branch(branch) => {
                            self.stack.push(branch.child_table.iter());
                            iter = self.stack.last_mut()?;
                        }
                    }
                }
            } else {
                self.stack.pop();
                iter = self.stack.last_mut()?;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> ExactSizeIterator
    for PATCHIterator<'a, KEY_LEN, O, V, H>
{
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> std::iter::FusedIterator
    for PATCHIterator<'a, KEY_LEN, O, V, H>
{
}

/// An iterator over every key in a PATCH, returned in key order.
///
/// Keys are yielded in lexicographic key order regardless of their physical
/// layout in the underlying tree. This iterator walks the full tree and does
/// not accept a prefix filter. For prefix-aware iteration, use
/// [`PATCHPrefixIterator`], constructed via [`PATCH::iter_prefix_count`].
pub struct PATCHOrderedIterator<
    'a,
    const KEY_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    stack: Vec<ArrayVec<&'a Head<KEY_LEN, O, V, H>, 256>>,
    remaining: usize,
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    PATCHOrderedIterator<'a, KEY_LEN, O, V, H>
{
    pub fn new(patch: &'a PATCH<KEY_LEN, O, V, H>) -> Self {
        let mut r = PATCHOrderedIterator {
            stack: Vec::with_capacity(KEY_LEN),
            remaining: patch.len().min(usize::MAX as u64) as usize,
        };
        if let Some(root) = &patch.root {
            r.stack.push(ArrayVec::new());
            match root.body_ref() {
                BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => {
                    r.stack[0].push(root);
                }
                BodyRef::Branch(branch) => {
                    let first_level = &mut r.stack[0];
                    first_level.extend(branch.child_table.iter().filter_map(|c| c.as_ref()));
                    first_level.sort_unstable_by_key(|&k| Reverse(k.key())); // We need to reverse here because we pop from the vec.
                }
            }
        }
        r
    }
}

// --- Owned consuming iterators ---
/// Iterator that owns a PATCH and yields keys in key-order. The owner set is
/// retained until every queued LocalLeaf has been copied out.
pub struct PATCHIntoIterator<
    const KEY_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    // Field order is deliberate: queued Heads drop before the owner cover.
    queue: Vec<Head<KEY_LEN, O, V, H>>,
    remaining: usize,
    _owners: Option<Arc<OwnerCover>>,
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    PATCHIntoIterator<KEY_LEN, O, V, H>
{
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Iterator
    for PATCHIntoIterator<KEY_LEN, O, V, H>
{
    type Item = [u8; KEY_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        let q = &mut self.queue;
        while let Some(mut head) = q.pop() {
            // Match on the mutable body directly. For leaves we can return the
            // stored key (the array is Copy), for branches we take children out
            // of the table and push them onto the stack so they are visited
            // depth-first.
            match head.body_mut() {
                BodyMut::Leaf(leaf) => {
                    self.remaining = self.remaining.saturating_sub(1);
                    return Some(leaf.key);
                }
                BodyMut::LocalLeaf(bytes) => {
                    self.remaining = self.remaining.saturating_sub(1);
                    return Some(*bytes);
                }
                BodyMut::Branch(branch) => {
                    for slot in branch.child_table.iter_mut().rev() {
                        if let Some(c) = slot.take() {
                            q.push(c);
                        }
                    }
                }
            }
        }
        None
    }
}

/// Iterator that owns a PATCH and yields keys in key order.
pub struct PATCHIntoOrderedIterator<
    const KEY_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    // Field order is deliberate: queued Heads drop before the owner cover.
    queue: Vec<Head<KEY_LEN, O, V, H>>,
    remaining: usize,
    _owners: Option<Arc<OwnerCover>>,
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Iterator
    for PATCHIntoOrderedIterator<KEY_LEN, O, V, H>
{
    type Item = [u8; KEY_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        let q = &mut self.queue;
        while let Some(mut head) = q.pop() {
            // Match the mutable body directly — we own `head` so calling
            // `body_mut()` is safe and allows returning the copied leaf key
            // or mutating the branch child table in-place.
            match head.body_mut() {
                BodyMut::Leaf(leaf) => {
                    self.remaining = self.remaining.saturating_sub(1);
                    return Some(leaf.key);
                }
                BodyMut::LocalLeaf(bytes) => {
                    self.remaining = self.remaining.saturating_sub(1);
                    return Some(*bytes);
                }
                BodyMut::Branch(branch) => {
                    let slice: &mut [Option<Head<KEY_LEN, O, V, H>>] = &mut branch.child_table;
                    // Sort children by their byte-key, placing empty slots (None)
                    // after all occupied slots. Using `sort_unstable_by_key` with
                    // a simple key projection is clearer than a custom
                    // comparator; it also avoids allocating temporaries. The
                    // old comparator manually handled None/Some cases — we
                    // express that intent directly by sorting on the tuple
                    // (is_none, key_opt).
                    slice
                        .sort_unstable_by_key(|opt| (opt.is_none(), opt.as_ref().map(|h| h.key())));
                    for slot in slice.iter_mut().rev() {
                        if let Some(c) = slot.take() {
                            q.push(c);
                        }
                    }
                }
            }
        }
        None
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> IntoIterator
    for PATCH<KEY_LEN, O, V, H>
{
    type Item = [u8; KEY_LEN];
    type IntoIter = PATCHIntoIterator<KEY_LEN, O, V, H>;

    fn into_iter(self) -> Self::IntoIter {
        let remaining = self.len().min(usize::MAX as u64) as usize;
        let PATCH { root, owners } = self;
        let mut q = Vec::new();
        if let Some(root) = root {
            q.push(root);
        }
        PATCHIntoIterator {
            queue: q,
            remaining,
            _owners: owners,
        }
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> PATCH<KEY_LEN, O, V, H> {
    /// Consume and return an iterator that yields keys in key order.
    pub fn into_iter_ordered(self) -> PATCHIntoOrderedIterator<KEY_LEN, O, V, H> {
        let remaining = self.len().min(usize::MAX as u64) as usize;
        let PATCH { root, owners } = self;
        let mut q = Vec::new();
        if let Some(root) = root {
            q.push(root);
        }
        PATCHIntoOrderedIterator {
            queue: q,
            remaining,
            _owners: owners,
        }
    }

    /// Consume this PATCH and enumerate each distinct tree-ordered prefix once.
    ///
    /// Unlike mapping the full consuming iterator and deduplicating it, this
    /// traversal stops at `PREFIX_LEN`: suffix subtrees are dropped without
    /// visiting their leaves. `PREFIX_LEN` must end at a segment boundary.
    pub fn into_prefixes<const PREFIX_LEN: usize>(
        self,
    ) -> PATCHIntoPrefixSetIterator<KEY_LEN, PREFIX_LEN, O, V, H> {
        const {
            assert!(PREFIX_LEN > 0, "a prefix set needs at least one byte");
            assert!(PREFIX_LEN <= KEY_LEN);
            if PREFIX_LEN < KEY_LEN {
                assert!(
                    <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                        [O::TREE_TO_KEY[PREFIX_LEN - 1]]
                        != <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                            [O::TREE_TO_KEY[PREFIX_LEN]],
                    "PREFIX_LEN must align to a segment boundary",
                );
            }
        }

        let PATCH { root, owners } = self;
        let mut queue = Vec::new();
        if let Some(root) = root {
            queue.push(root);
        }
        PATCHIntoPrefixSetIterator {
            queue,
            _owners: owners,
        }
    }
}

/// Consuming iterator over the distinct prefixes at one PATCH segment boundary.
///
/// The iterator owns an immutable PATCH snapshot and drops every suffix subtree
/// as soon as its one projected member has been emitted. This is useful when an
/// iterator must outlive the snapshot value from which it was constructed.
pub struct PATCHIntoPrefixSetIterator<
    const KEY_LEN: usize,
    const PREFIX_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    // Field order is deliberate: queued Heads drop before the owner cover.
    queue: Vec<Head<KEY_LEN, O, V, H>>,
    _owners: Option<Arc<OwnerCover>>,
}

impl<const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Iterator
    for PATCHIntoPrefixSetIterator<KEY_LEN, PREFIX_LEN, O, V, H>
{
    type Item = [u8; PREFIX_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(head) = self.queue.pop() {
            if head.end_depth() >= PREFIX_LEN {
                let key = O::tree_ordered(head.childleaf_key());
                return Some(key[..PREFIX_LEN].try_into().unwrap());
            }

            let BodyRef::Branch(branch) = head.body_ref() else {
                unreachable!("a leaf cannot end before a valid prefix boundary");
            };
            // Clone one-word persistent Heads from the immutable branch. Using
            // `body_mut` here would copy-on-write every shared branch merely
            // because the iterator owns a clone of the PATCH root.
            let mut children = ArrayVec::<&Head<KEY_LEN, O, V, H>, 256>::new();
            children.extend(branch.child_table.iter().filter_map(Option::as_ref));
            children.sort_unstable_by_key(|child| child.key());
            for child in children.into_iter().rev() {
                self.queue.push((*child).clone());
            }
        }
        None
    }
}

impl<const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    std::iter::FusedIterator for PATCHIntoPrefixSetIterator<KEY_LEN, PREFIX_LEN, O, V, H>
{
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Iterator
    for PATCHOrderedIterator<'a, KEY_LEN, O, V, H>
{
    type Item = &'a [u8; KEY_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        let mut level = self.stack.last_mut()?;
        loop {
            if let Some(child) = level.pop() {
                match child.body_ref() {
                    BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => {
                        self.remaining = self.remaining.saturating_sub(1);
                        return Some(child.childleaf_key());
                    }
                    BodyRef::Branch(branch) => {
                        self.stack.push(ArrayVec::new());
                        level = self.stack.last_mut()?;
                        level.extend(branch.child_table.iter().filter_map(|c| c.as_ref()));
                        level.sort_unstable_by_key(|&k| Reverse(k.key())); // We need to reverse here because we pop from the vec.
                    }
                }
            } else {
                self.stack.pop();
                level = self.stack.last_mut()?;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> ExactSizeIterator
    for PATCHOrderedIterator<'a, KEY_LEN, O, V, H>
{
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> std::iter::FusedIterator
    for PATCHOrderedIterator<'a, KEY_LEN, O, V, H>
{
}

/// A zero-copy set view over distinct prefixes at one PATCH segment boundary.
///
/// The view borrows the physical trie. It neither allocates a second PATCH nor
/// gives suffix multiplicity semantic weight. Iteration collapses every suffix
/// subtree to its one shared prefix.
#[derive(Clone, Copy)]
pub struct PATCHPrefixSet<
    'a,
    const KEY_LEN: usize,
    const PREFIX_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    patch: &'a PATCH<KEY_LEN, O, V, H>,
}

impl<'a, const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    PATCHPrefixSet<'a, KEY_LEN, PREFIX_LEN, O, V, H>
{
    fn new(patch: &'a PATCH<KEY_LEN, O, V, H>) -> Self {
        const {
            assert!(PREFIX_LEN > 0, "a prefix set needs at least one byte");
            assert!(PREFIX_LEN <= KEY_LEN);
            if PREFIX_LEN < KEY_LEN {
                assert!(
                    <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                        [O::TREE_TO_KEY[PREFIX_LEN - 1]]
                        != <O as KeySchema<KEY_LEN>>::Segmentation::SEGMENTS
                            [O::TREE_TO_KEY[PREFIX_LEN]],
                    "PREFIX_LEN must align to a segment boundary",
                );
            }
        }
        Self { patch }
    }

    /// Whether at least one physical key has this projected prefix.
    pub fn contains(&self, prefix: &[u8; PREFIX_LEN]) -> bool {
        self.patch.has_prefix(prefix)
    }

    /// Enumerate each projected prefix once in tree order.
    pub fn iter(&self) -> PATCHPrefixSetIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H> {
        PATCHPrefixSetIterator {
            inner: self.patch.iter_prefix_count(),
        }
    }

    /// Whether this projected set has no members.
    pub fn is_empty(&self) -> bool {
        self.patch.is_empty()
    }

    /// Intersect this projected set with an ordinary key-only PATCH.
    ///
    /// The returned PATCH retains `other`'s hash policy, making this suitable
    /// for filtering a typed semantic cover through a larger physical index.
    pub fn intersection<OH: PatchHash>(
        &self,
        other: &PATCH<PREFIX_LEN, IdentitySchema, (), OH>,
    ) -> PATCH<PREFIX_LEN, IdentitySchema, (), OH> {
        let keys = other
            .iter_ordered()
            .filter(|key| self.contains(key))
            .copied()
            .collect();
        PATCH::from_owned_keys(keys)
    }
}

/// Iterator over a [`PATCHPrefixSet`].
pub struct PATCHPrefixSetIterator<
    'a,
    const KEY_LEN: usize,
    const PREFIX_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    inner: PATCHPrefixIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H>,
}

impl<'a, const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    Iterator for PATCHPrefixSetIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H>
{
    type Item = [u8; PREFIX_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(prefix, _count)| prefix)
    }
}

impl<'a, const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    std::iter::FusedIterator for PATCHPrefixSetIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H>
{
}

/// An iterator over all keys in a PATCH that have a given prefix.
/// The keys are returned in tree ordering and in tree order.
pub struct PATCHPrefixIterator<
    'a,
    const KEY_LEN: usize,
    const PREFIX_LEN: usize,
    O: KeySchema<KEY_LEN>,
    V,
    H: PatchHash = XorSip128,
> {
    stack: Vec<ArrayVec<&'a Head<KEY_LEN, O, V, H>, 256>>,
}

impl<'a, const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    PATCHPrefixIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H>
{
    fn new(patch: &'a PATCH<KEY_LEN, O, V, H>) -> Self {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        let mut r = PATCHPrefixIterator {
            stack: Vec::with_capacity(PREFIX_LEN),
        };
        if let Some(root) = &patch.root {
            r.stack.push(ArrayVec::new());
            if root.end_depth() >= PREFIX_LEN {
                r.stack[0].push(root);
            } else {
                let BodyRef::Branch(branch) = root.body_ref() else {
                    unreachable!();
                };
                let first_level = &mut r.stack[0];
                first_level.extend(branch.child_table.iter().filter_map(|c| c.as_ref()));
                first_level.sort_unstable_by_key(|&k| Reverse(k.key())); // We need to reverse here because we pop from the vec.
            }
        }
        r
    }
}

impl<'a, const KEY_LEN: usize, const PREFIX_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    Iterator for PATCHPrefixIterator<'a, KEY_LEN, PREFIX_LEN, O, V, H>
{
    type Item = ([u8; PREFIX_LEN], u64);

    fn next(&mut self) -> Option<Self::Item> {
        let mut level = self.stack.last_mut()?;
        loop {
            if let Some(child) = level.pop() {
                if child.end_depth() >= PREFIX_LEN {
                    let key = O::tree_ordered(child.childleaf_key());
                    let suffix_count = child.count();
                    return Some((key[0..PREFIX_LEN].try_into().unwrap(), suffix_count));
                } else {
                    let BodyRef::Branch(branch) = child.body_ref() else {
                        unreachable!();
                    };
                    self.stack.push(ArrayVec::new());
                    level = self.stack.last_mut()?;
                    level.extend(branch.child_table.iter().filter_map(|c| c.as_ref()));
                    level.sort_unstable_by_key(|&k| Reverse(k.key())); // We need to reverse here because we pop from the vec.
                }
            } else {
                self.stack.pop();
                level = self.stack.last_mut()?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::convert::TryInto;
    use std::iter::FromIterator;
    use std::mem;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[repr(C, align(16))]
    struct AlignedArchivePair([[u8; 16]; 2]);

    #[repr(C, align(16))]
    struct AlignedArchiveKey<const KEY_LEN: usize>([u8; KEY_LEN]);

    fn blake_patch<const KEY_LEN: usize>(
        keys: &[[u8; KEY_LEN]],
    ) -> PATCH<KEY_LEN, IdentitySchema, (), Blake3Merkle> {
        let mut patch = PATCH::new();
        for key in keys {
            patch.insert(&Entry::<KEY_LEN, (), Blake3Merkle>::new(key));
        }
        patch
    }

    fn inventory_keys<const KEY_LEN: usize>(len: usize) -> Vec<[u8; KEY_LEN]> {
        assert!(KEY_LEN >= 8);
        (0..len)
            .map(|index| {
                let mut key = [0u8; KEY_LEN];
                key[..8].copy_from_slice(&(index as u64).to_be_bytes());
                let mut state = (index as u64) ^ 0x243f_6a88_85a3_08d3;
                for byte in &mut key[8..] {
                    state ^= state >> 12;
                    state ^= state << 25;
                    state ^= state >> 27;
                    *byte = state.wrapping_mul(0x2545_f491_4f6c_dd1d) as u8;
                }
                key
            })
            .collect()
    }

    #[test]
    fn bulk_owned_build_canonicalizes_order_duplicates_and_edit_history() {
        let keys = inventory_keys::<16>(4_097);
        let mut noisy = keys.clone();
        noisy.reverse();
        noisy.extend(keys.iter().step_by(7).copied());
        noisy.rotate_left(997);

        let bulk = PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_keys(noisy.clone());
        let bulk_reversed =
            PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_keys(noisy.into_iter().rev());
        let inserted = blake_patch(&keys);
        let mut edited = blake_patch(&keys.iter().rev().copied().collect::<Vec<_>>());
        for key in keys.iter().step_by(5) {
            edited.remove(key);
        }
        for key in keys.iter().step_by(5).rev() {
            edited.insert(&Entry::new(key));
        }

        let expected_root = inserted.merkle_root();
        assert_eq!(bulk.len(), keys.len() as u64);
        assert_eq!(bulk.merkle_root(), expected_root);
        assert_eq!(bulk_reversed.merkle_root(), expected_root);
        assert_eq!(edited.merkle_root(), expected_root);
        assert_eq!(bulk, inserted);
        assert_eq!(
            bulk.merkle_node(&[])
                .unwrap()
                .items_after(None, usize::MAX)
                .collect::<Vec<_>>(),
            keys
        );
    }

    #[test]
    fn bulk_owned_build_handles_empty_singleton_and_already_canonical_input() {
        let empty = PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_keys([]);
        assert!(empty.is_empty());
        assert_eq!(empty.merkle_root(), None);

        let key = [42; 16];
        let singleton = PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_keys([key]);
        assert_eq!(singleton.len(), 1);
        assert_eq!(singleton.merkle_node(&[]).unwrap().representative(), &key);

        let canonical = inventory_keys::<16>(1_024);
        let bulk = PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_keys(canonical.clone());
        assert_eq!(
            bulk.merkle_node(&[])
                .unwrap()
                .items_after(None, usize::MAX)
                .collect::<Vec<_>>(),
            canonical
        );
    }

    static BULK_LEAF_HASHES: AtomicUsize = AtomicUsize::new(0);
    static BULK_BRANCH_HASHES: AtomicUsize = AtomicUsize::new(0);

    struct CountingBlake3;
    impl sealed::Sealed for CountingBlake3 {}
    impl PatchHash for CountingBlake3 {
        type Digest = [u8; 32];
        type BranchState = blake3::Hasher;
        const COMMUTATIVE_BRANCH: bool = false;
        const INCREMENTAL_BRANCH: bool = false;

        fn init() {
            Blake3Merkle::init();
        }

        fn leaf(bytes: &[u8]) -> Self::Digest {
            BULK_LEAF_HASHES.fetch_add(1, Ordering::Relaxed);
            Blake3Merkle::leaf(bytes)
        }

        fn begin_branch(
            representative: &[u8],
            tree_to_key: &[usize],
            end_depth: usize,
            child_count: usize,
            leaf_count: u64,
        ) -> Self::BranchState {
            Blake3Merkle::begin_branch(
                representative,
                tree_to_key,
                end_depth,
                child_count,
                leaf_count,
            )
        }

        fn push_child(
            state: &mut Self::BranchState,
            edge: u8,
            leaf_count: u64,
            digest: Self::Digest,
        ) {
            Blake3Merkle::push_child(state, edge, leaf_count, digest);
        }

        fn finish_branch(state: Self::BranchState) -> Self::Digest {
            BULK_BRANCH_HASHES.fetch_add(1, Ordering::Relaxed);
            Blake3Merkle::finish_branch(state)
        }

        fn edit_branch(
            _current: Self::Digest,
            _edge: u8,
            _old: Option<Self::Digest>,
            _new: Option<Self::Digest>,
        ) -> Self::Digest {
            unreachable!("the counting Merkle policy is not incremental")
        }
    }

    #[test]
    fn bulk_owned_build_hashes_each_final_node_once_plus_debug_audit() {
        BULK_LEAF_HASHES.store(0, Ordering::Relaxed);
        BULK_BRANCH_HASHES.store(0, Ordering::Relaxed);
        let keys = inventory_keys::<16>(10_000);
        let patch = PATCH::<16, IdentitySchema, (), CountingBlake3>::from_owned_keys(keys.clone());
        let (branches, _, heap_leaves, archive_leaves) = patch.node_stats();

        assert_eq!(patch.len(), keys.len() as u64);
        assert_eq!(heap_leaves, keys.len() as u64);
        assert_eq!(archive_leaves, 0);
        assert_eq!(BULK_LEAF_HASHES.load(Ordering::Relaxed), keys.len());
        // The build itself finishes each branch once. Debug builds then
        // deliberately recompute it once inside Branch's invariant audit;
        // optimized production builds compile that verification away.
        let expected_branch_hashes = branches as usize * if cfg!(debug_assertions) { 2 } else { 1 };
        assert_eq!(
            BULK_BRANCH_HASHES.load(Ordering::Relaxed),
            expected_branch_hashes
        );
    }

    struct BulkUnwindProbe(Arc<AtomicUsize>);

    impl Drop for BulkUnwindProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn wider_known_hash_branch_owns_every_child_during_unwind() {
        let drops = Arc::new(AtomicUsize::new(0));
        let keys = [[1, 0], [2, 0], [3, 0]];
        let digests = keys.map(|key| Blake3Merkle::leaf(&key));
        let mut state = Blake3Merkle::begin_branch(
            &keys[0],
            &<IdentitySchema as KeySchema<2>>::TREE_TO_KEY,
            0,
            keys.len(),
            keys.len() as u64,
        );
        for (edge, digest) in [1, 2, 3].into_iter().zip(digests) {
            Blake3Merkle::push_child(&mut state, edge, 1, digest);
        }
        let final_hash = Blake3Merkle::finish_branch(state);

        let leaf = |key: &[u8; 2]| {
            // SAFETY: every returned allocation is immediately transferred
            // into exactly one owning Head.
            unsafe {
                Leaf::<2, BulkUnwindProbe, Blake3Merkle>::new(key, BulkUnwindProbe(drops.clone()))
            }
        };
        type ProbeHead = Head<2, IdentitySchema, BulkUnwindProbe, Blake3Merkle>;
        let first = ProbeHead::new(0, leaf(&keys[0])).with_key(1);
        let second = ProbeHead::new(0, leaf(&keys[1])).with_key(2);
        let third = ProbeHead::new(0, leaf(&keys[2])).with_key(3);
        let body = Branch::new_with_known_hash_capacity(0, first, second, final_hash, 4);
        let mut root = Head::new(0, body);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut editor = BranchMut::from_head(&mut root);
            editor.install_child_growing(third);
            // This is the only interval where the branch contains every
            // child but its structural counts still describe the initial
            // pair. BranchMut's Drop must nevertheless return the current
            // allocation to `root`, whose ordinary destructor owns all three.
            panic!("interrupt wider bottom-up assembly");
        }));
        assert!(panic.is_err());
        drop(root);
        assert_eq!(drops.load(Ordering::Relaxed), keys.len());
    }

    fn merkle_inventory<const KEY_LEN: usize, V>(
        node: PATCHMerkleNode<'_, KEY_LEN, V>,
        out: &mut Vec<(Vec<u8>, [u8; 32], u64, usize, [u8; KEY_LEN], Vec<u8>)>,
    ) {
        let child_edges = node.children().map(|(edge, _)| edge).collect::<Vec<_>>();
        out.push((
            node.prefix().to_vec(),
            node.digest(),
            node.leaf_count(),
            node.end_depth(),
            *node.representative(),
            child_edges,
        ));
        for (_, child) in node.children() {
            merkle_inventory(child, out);
        }
    }

    #[test]
    fn merkle_prefix_lookup_canonicalizes_compressed_paths_and_orders_children() {
        let patch = blake_patch(&[[1, 2, 3, 255], [1, 2, 3, 0]]);
        let root = patch.merkle_node(&[]).expect("nonempty PATCH");
        assert_eq!(root.end_depth(), 3);
        assert_eq!(root.prefix(), &[1, 2, 3]);
        assert_eq!(root.leaf_count(), 2);
        assert!(!root.is_leaf());

        for request in [&[][..], &[1][..], &[1, 2][..], &[1, 2, 3][..]] {
            let located = patch.merkle_node(request).expect("compressed prefix");
            assert_eq!(located.digest(), root.digest());
            assert_eq!(located.prefix(), &[1, 2, 3]);
        }
        assert!(patch.merkle_node(&[1, 2, 4]).is_none());
        assert!(patch.merkle_node(&[1, 2, 3, 0, 0]).is_none());

        let children = root.children().collect::<Vec<_>>();
        assert_eq!(
            children.iter().map(|(edge, _)| *edge).collect::<Vec<_>>(),
            [0, 255]
        );
        for (edge, child) in children {
            assert!(child.is_leaf());
            assert_eq!(child.leaf_count(), 1);
            assert_eq!(child.end_depth(), 4);
            assert_eq!(child.representative()[3], edge);
            assert_eq!(child.prefix(), child.representative());
            assert_eq!(child.children().len(), 0);
        }

        let debug = format!("{root:?}");
        assert!(debug.contains("PATCHMerkleNode"));
        assert!(!debug.contains("child_table"));
        assert!(!debug.contains("Branch"));
    }

    #[test]
    fn merkle_prefix_lookup_reports_compressed_shape_mismatches_without_aliasing_nodes() {
        let compressed = blake_patch(&[[1, 2, 3, 0], [1, 2, 3, 255]]);
        let split_earlier = blake_patch(&[[1, 2, 3, 0], [1, 2, 4, 0]]);

        let compressed_root = compressed.merkle_node(&[]).expect("root");
        assert_eq!(compressed_root.prefix(), &[1, 2, 3]);
        let corresponding = split_earlier
            .merkle_node(compressed_root.prefix())
            .expect("the shared key still exists");
        assert!(corresponding.is_leaf());
        assert_eq!(corresponding.prefix(), &[1, 2, 3, 0]);
        assert_ne!(corresponding.digest(), compressed_root.digest());
        assert_ne!(corresponding.leaf_count(), compressed_root.leaf_count());

        let earlier_root = split_earlier.merkle_node(&[]).expect("root");
        assert_eq!(earlier_root.prefix(), &[1, 2]);
        let covered = compressed
            .merkle_node(earlier_root.prefix())
            .expect("request ends inside compressed path");
        assert_eq!(covered.prefix(), &[1, 2, 3]);
        assert_eq!(covered.digest(), compressed_root.digest());
    }

    #[test]
    fn merkle_traversal_is_history_independent() {
        let keys: Vec<[u8; 4]> = (0u8..64)
            .map(|i| [i.wrapping_mul(73), i / 4, i.wrapping_mul(11), 255 - i])
            .collect();
        let forward = blake_patch(&keys);
        let mut reversed_keys = keys.clone();
        reversed_keys.reverse();
        let reversed = blake_patch(&reversed_keys);
        let mut edited = reversed.clone();
        for key in keys.iter().step_by(3) {
            edited.remove(key);
        }
        for key in keys.iter().step_by(3).rev() {
            edited.insert(&Entry::<4, (), Blake3Merkle>::new(key));
        }

        let inventory = |patch: &PATCH<4, IdentitySchema, (), Blake3Merkle>| {
            let mut out = Vec::new();
            merkle_inventory(patch.merkle_node(&[]).expect("root"), &mut out);
            out
        };
        assert_eq!(inventory(&forward), inventory(&reversed));
        assert_eq!(inventory(&forward), inventory(&edited));

        let mut expected = keys.clone();
        expected.sort_unstable();
        for patch in [&forward, &reversed, &edited] {
            let root = patch.merkle_node(&[]).expect("root");
            let mut paged = Vec::new();
            let mut after = None;
            loop {
                let page = root.items_after(after.as_ref(), 7).collect::<Vec<_>>();
                if page.is_empty() {
                    break;
                }
                after = page.last().copied();
                paged.extend(page);
            }
            assert_eq!(paged, expected);
        }
    }

    #[test]
    fn merkle_items_are_prefix_scoped_exclusive_and_hard_bounded() {
        let mut keys = Vec::new();
        for i in 0u8..32 {
            keys.push([7, i, i.wrapping_mul(17), 255 - i]);
            keys.push([8, i, 0, 0]);
        }
        let patch = blake_patch(&keys);
        let node = patch.merkle_node(&[7]).expect("prefix seven");

        let mut empty = node.items_after(None, 0);
        assert_eq!(empty.size_hint(), (0, Some(0)));
        assert_eq!(empty.next(), None);
        assert_eq!(empty.next(), None);

        let first_five = node.items_after(None, 5).collect::<Vec<_>>();
        assert_eq!(first_five.len(), 5);
        assert!(first_five.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(first_five.iter().all(|key| key[0] == 7));

        let cursor = [7, 4, 128, 0];
        let after = node.items_after(Some(&cursor), 3).collect::<Vec<_>>();
        assert_eq!(after.len(), 3);
        assert!(after.iter().all(|key| key > &cursor && key[0] == 7));

        let exact = keys
            .iter()
            .copied()
            .filter(|key| key[0] == 7)
            .nth(12)
            .unwrap();
        let exclusive = node
            .items_after(Some(&exact), usize::MAX)
            .collect::<Vec<_>>();
        assert!(exclusive.iter().all(|key| key > &exact && key[0] == 7));
        assert!(!exclusive.contains(&exact));
        assert_eq!(exclusive.len(), 19);

        assert_eq!(node.items_after(Some(&[255; 4]), 10).next(), None);
        let mut one = node.items_after(None, 1);
        assert_eq!(one.size_hint(), (0, Some(1)));
        assert!(one.next().is_some());
        assert_eq!(one.size_hint(), (0, Some(0)));
        assert_eq!(one.next(), None);
    }

    #[test]
    fn merkle_views_do_not_require_or_expose_values() {
        struct NotDebug(u8);

        let key = [9, 8, 7, 6];
        let entry = Entry::<4, NotDebug, Blake3Merkle>::with_value(&key, NotDebug(42));
        let mut patch = PATCH::<4, IdentitySchema, NotDebug, Blake3Merkle>::new();
        patch.insert(&entry);
        let node = patch.merkle_node(&[]).expect("root");
        assert_eq!(node.items_after(None, 1).collect::<Vec<_>>(), [key]);
        assert!(format!("{node:?}").contains("PATCHMerkleNode"));
        assert_eq!(entry.value().0, 42);
    }

    #[test]
    fn blake3_merkle_authenticates_reconciliation_descriptor() {
        fn framed(representative: [u8; 16], leaf_count: u64, child_counts: [u64; 2]) -> [u8; 32] {
            let mut state = Blake3Merkle::begin_branch(
                &representative,
                &<IdentitySchema as KeySchema<16>>::TREE_TO_KEY,
                4,
                2,
                leaf_count,
            );
            Blake3Merkle::push_child(&mut state, 3, child_counts[0], [7; 32]);
            Blake3Merkle::push_child(&mut state, 9, child_counts[1], [11; 32]);
            Blake3Merkle::finish_branch(state)
        }

        let representative = [5; 16];
        let canonical = framed(representative, 4, [1, 3]);
        assert_ne!(canonical, framed(representative, 5, [1, 3]));
        assert_ne!(canonical, framed(representative, 4, [2, 2]));

        let mut different_prefix = representative;
        different_prefix[2] ^= 1;
        assert_ne!(canonical, framed(different_prefix, 4, [1, 3]));

        let mut different_suffix = representative;
        different_suffix[7] ^= 1;
        assert_eq!(canonical, framed(different_suffix, 4, [1, 3]));
    }

    #[test]
    fn blake3_merkle_is_history_independent_across_edits_and_set_operations() {
        let keys = [
            [0, 0, 0, 0],
            [0, 0, 1, 0],
            [0, 2, 0, 0],
            [3, 0, 0, 0],
            [3, 0, 0, 9],
            [255, 1, 2, 3],
        ];

        let forward = blake_patch(&keys);
        let mut reversed_keys = keys;
        reversed_keys.reverse();
        let reversed = blake_patch(&reversed_keys);
        assert_eq!(forward.merkle_root(), reversed.merkle_root());
        assert_eq!(forward, reversed);

        let mut edited = forward.clone();
        edited.remove(&keys[2]);
        edited.insert(&Entry::<4, (), Blake3Merkle>::new(&keys[2]));
        assert_eq!(edited.merkle_root(), forward.merkle_root());

        let left = blake_patch(&keys[..4]);
        let right = blake_patch(&keys[2..]);
        let mut union = left.clone();
        union.union(right.clone());
        assert_eq!(union.merkle_root(), forward.merkle_root());

        let expected_intersection = blake_patch(&keys[2..4]);
        assert_eq!(
            left.intersect(&right).merkle_root(),
            expected_intersection.merkle_root()
        );

        let expected_difference = blake_patch(&keys[..2]);
        assert_eq!(
            left.difference(&right).merkle_root(),
            expected_difference.merkle_root()
        );
    }

    #[test]
    fn blake3_merkle_heap_and_archive_construction_have_the_same_root() {
        #[repr(C, align(16))]
        struct AlignedBlakeArchive([[u8; 16]; 6]);

        let storage = Arc::new(AlignedBlakeArchive([
            [0; 16], [1; 16], [2; 16], [3; 16], [17; 16], [255; 16],
        ]));
        let owner: Arc<dyn ArchiveOwner> = storage.clone();
        let hashes = storage.0.map(|key| Blake3Merkle::leaf(&key));
        let mut rows = [5, 3, 1, 4, 0, 2];

        // SAFETY: the aligned wrapper makes every 16-byte row 16-byte
        // aligned, the rows are a permutation, the keys are distinct and
        // immutable, and `owner` retains the allocation.
        let archive = unsafe {
            PATCH::<16, IdentitySchema, (), Blake3Merkle>::from_archive_partition(
                &storage.0, &hashes, &mut rows, &owner,
            )
        };
        let heap = blake_patch(&storage.0);

        assert_eq!(archive.merkle_root(), heap.merkle_root());
        assert_eq!(archive, heap);
        let archive_root = archive.merkle_node(&[]).expect("archive root");
        assert_eq!(archive_root.leaf_count(), 6);
        assert_eq!(
            archive_root
                .items_after(None, usize::MAX)
                .collect::<Vec<_>>(),
            storage.0
        );
    }

    crate::key_segmentation!(PermutedInfixSegments, 12, [4, 4, 4]);
    crate::key_schema!(PermutedInfixSchema, PermutedInfixSegments, 12, [1, 2, 0]);
    crate::key_segmentation!(PrefixProjectionSegments, 6, [4, 2]);
    crate::key_schema!(PrefixProjectionSchema, PrefixProjectionSegments, 6, [0, 1]);
    crate::key_segmentation!(PrefixSharingBlobSegments, 40, [32, 8]);
    crate::key_schema!(
        PrefixSharingBlobSchema,
        PrefixSharingBlobSegments,
        40,
        [0, 1]
    );

    #[test]
    fn shares_prefix_handles_empty_and_full_prefixes() {
        let empty = PATCH::<4, IdentitySchema>::new();
        let key = [1, 2, 3, 4];
        assert!(empty.shares_prefix(&empty.clone(), &[]));
        assert!(empty.shares_prefix(&empty.clone(), &key));

        let mut populated = empty.clone();
        populated.insert(&Entry::new(&key));
        assert!(!empty.shares_prefix(&populated, &[]));
        assert!(!empty.shares_prefix(&populated, &key));
        assert!(!populated.shares_prefix(&empty, &[1, 2]));
        assert!(populated.shares_prefix(&empty, &[1, 9]));
        assert!(populated.shares_prefix(&populated.clone(), &[]));
        assert!(populated.shares_prefix(&populated.clone(), &key));

        let mut rebuilt = PATCH::<4, IdentitySchema>::new();
        rebuilt.insert(&Entry::new(&key));
        assert_eq!(populated, rebuilt);
        assert!(!populated.shares_prefix(&rebuilt, &[]));
        assert!(!populated.shares_prefix(&rebuilt, &key));
    }

    #[test]
    fn shares_prefix_retains_compressed_subtrees_after_unrelated_insertions() {
        let mut original = PATCH::<4, IdentitySchema>::new();
        original.insert(&Entry::new(&[1, 2, 3, 0]));
        original.insert(&Entry::new(&[1, 2, 3, 255]));
        assert_eq!(original.root.as_ref().unwrap().end_depth(), 3);

        let mut outside = original.clone();
        outside.insert(&Entry::new(&[9, 8, 7, 6]));
        // The old compressed root becomes a child with a different edge byte.
        assert!(!original.shares_prefix(&outside, &[]));
        assert!(original.shares_prefix(&outside, &[1]));
        assert!(original.shares_prefix(&outside, &[1, 2]));
        assert!(original.shares_prefix(&outside, &[1, 2, 3]));
        assert!(original.shares_prefix(&outside, &[1, 2, 3, 0]));
        assert!(original.shares_prefix(&outside, &[1, 2, 4]));

        let mut split = outside.clone();
        split.insert(&Entry::new(&[1, 2, 4, 0]));
        assert!(!outside.shares_prefix(&split, &[1]));
        assert!(!outside.shares_prefix(&split, &[1, 2]));
        assert!(!outside.shares_prefix(&split, &[1, 2, 4]));
        assert!(outside.shares_prefix(&split, &[1, 2, 3]));
        assert!(outside.shares_prefix(&split, &[9]));

        let mut inside = split.clone();
        inside.insert(&Entry::new(&[1, 2, 3, 127]));
        assert!(!split.shares_prefix(&inside, &[1, 2, 3]));
        assert!(split.shares_prefix(&inside, &[1, 2, 3, 0]));
        assert!(split.shares_prefix(&inside, &[1, 2, 4]));
    }

    #[test]
    fn shares_prefix_detects_an_additional_physical_blob_occurrence() {
        let physical_key = |hash: [u8; 32], offset: u64| {
            let mut key = [0; 40];
            key[..32].copy_from_slice(&hash);
            key[32..].copy_from_slice(&offset.to_be_bytes());
            key
        };
        let hash = [7; 32];
        let other_hash = [9; 32];
        let first = physical_key(hash, 512);
        let mut before = PATCH::<40, PrefixSharingBlobSchema>::new();
        before.insert(&Entry::new(&first));
        before.insert(&Entry::new(&physical_key(other_hash, 1024)));
        let mut after = before.clone();
        after.insert(&Entry::new(&physical_key(hash, 2048)));

        assert_eq!(
            before.prefix_set::<32>().iter().collect::<Vec<_>>(),
            after.prefix_set::<32>().iter().collect::<Vec<_>>()
        );
        assert!(!before.shares_prefix(&after, &hash));
        assert!(before.shares_prefix(&after, &first));
        assert!(before.shares_prefix(&after, &other_hash));
    }

    #[test]
    fn shares_prefix_observes_replaced_values_with_unchanged_keys() {
        let key = [1, 2, 3, 4];
        let sibling = [1, 2, 3, 9];
        let unrelated = [9, 8, 7, 6];
        let mut before = PATCH::<4, IdentitySchema, u64>::new();
        for key in [key, sibling, unrelated] {
            before.insert(&Entry::with_value(&key, 10));
        }
        let mut after = before.clone();
        after.replace(&Entry::with_value(&key, 11));

        assert_eq!(before, after);
        assert_eq!(before.get(&key), Some(&10));
        assert_eq!(after.get(&key), Some(&11));
        assert!(!before.shares_prefix(&after, &key));
        assert!(!before.shares_prefix(&after, &[1, 2, 3]));
        assert!(before.shares_prefix(&after, &sibling));
        assert!(before.shares_prefix(&after, &[9]));
    }

    #[test]
    fn shares_prefix_uses_tree_order_inside_permuted_segments() {
        let first = [30, 31, 32, 33, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut sibling = first;
        sibling[0] = 40;
        let mut before = PATCH::<12, PermutedInfixSchema>::new();
        before.insert(&Entry::new(&first));
        before.insert(&Entry::new(&sibling));

        let mut unrelated = first;
        unrelated[4..8].copy_from_slice(&[9, 8, 7, 6]);
        let mut after = before.clone();
        after.insert(&Entry::new(&unrelated));
        assert!(before.shares_prefix(&after, &[1, 2]));
        assert!(before.shares_prefix(&after, &[1, 2, 3, 4]));
        assert!(before.shares_prefix(
            &after,
            &<PermutedInfixSchema as KeySchema<12>>::tree_ordered(&first)
        ));
        assert!(!before.shares_prefix(&after, &[9, 8]));

        let mut added = first;
        added[6] = 8;
        let mut split = after.clone();
        split.insert(&Entry::new(&added));
        assert!(!after.shares_prefix(&split, &[1, 2]));
        assert!(after.shares_prefix(&split, &[1, 2, 3, 4]));
    }

    #[test]
    fn prefix_set_projects_away_suffix_multiplicity_and_order() {
        let first = [1, 2, 3, 4];
        let second = [5, 6, 7, 8];
        let physical_key = |prefix: [u8; 4], suffix: [u8; 2]| {
            let mut key = [0; 6];
            key[..4].copy_from_slice(&prefix);
            key[4..].copy_from_slice(&suffix);
            key
        };

        let mut left = PATCH::<6, PrefixProjectionSchema>::new();
        for key in [
            physical_key(first, [0, 2]),
            physical_key(second, [0, 9]),
            physical_key(first, [0, 1]),
        ] {
            left.insert(&Entry::new(&key));
        }
        let mut right = PATCH::<6, PrefixProjectionSchema>::new();
        for key in [physical_key(second, [7, 7]), physical_key(first, [8, 8])] {
            right.insert(&Entry::new(&key));
        }

        assert_eq!(
            left.clone().into_prefixes::<4>().collect::<Vec<_>>(),
            vec![first, second]
        );
        let left = left.prefix_set::<4>();
        let right = right.prefix_set::<4>();
        assert_eq!(left.iter().collect::<Vec<_>>(), vec![first, second]);
        assert_eq!(right.iter().collect::<Vec<_>>(), vec![first, second]);
        assert!(left.contains(&first));
        assert!(left.contains(&second));
        assert!(!left.contains(&[9; 4]));
        assert_eq!(
            left.iter().collect::<Vec<_>>(),
            right.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn prefix_set_intersection_retains_the_other_patch_policy() {
        let physical_key = |prefix: [u8; 4], suffix: [u8; 2]| {
            let mut key = [0; 6];
            key[..4].copy_from_slice(&prefix);
            key[4..].copy_from_slice(&suffix);
            key
        };
        let resident = [[1; 4], [3; 4], [5; 4]];
        let mut physical = PATCH::<6, PrefixProjectionSchema>::new();
        for (prefix, suffix) in [
            (resident[0], [0, 1]),
            (resident[0], [0, 2]),
            (resident[1], [0, 3]),
            (resident[2], [0, 4]),
        ] {
            physical.insert(&Entry::new(&physical_key(prefix, suffix)));
        }

        let requested = PATCH::<4, IdentitySchema, (), Blake3Merkle>::from_keys([
            [0; 4],
            resident[0],
            [2; 4],
            resident[1],
            [4; 4],
            resident[2],
            [6; 4],
        ]);
        let actual = physical.prefix_set::<4>().intersection(&requested);
        let expected = PATCH::<4, IdentitySchema, (), Blake3Merkle>::from_keys(resident);
        assert_eq!(actual, expected);
        assert_eq!(actual.merkle_root(), expected.merkle_root());
    }

    struct PanicOnDrop(bool);

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            if self.0 {
                panic!("intentional value drop panic");
            }
        }
    }

    /// Build the smallest all-LocalLeaf PATCH and return a weak witness for
    /// its backing allocation. The returned PATCH is the allocation's only
    /// strong owner, so liveness assertions fail before a dangling pointer is
    /// ever dereferenced.
    fn owned_archive_pair(
        keys: [[u8; 16]; 2],
    ) -> (
        PATCH<16, IdentitySchema>,
        std::sync::Weak<AlignedArchivePair>,
    ) {
        let storage = std::sync::Arc::new(AlignedArchivePair(keys));
        let weak = std::sync::Arc::downgrade(&storage);
        let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
        let hashes = [hash_key(&storage.0[0]), hash_key(&storage.0[1])];
        let mut rows = [0, 1];
        // SAFETY: AlignedArchivePair is 16-byte aligned, each 16-byte row has
        // the same alignment, the two keys are distinct in every fixture, and
        // `owner` retains the immutable storage throughout construction.
        let patch =
            unsafe { PATCH::from_archive_partition(&storage.0, &hashes, &mut rows, &owner) };
        assert_eq!(patch.node_stats(), (1, 2, 0, 2));
        drop(owner);
        drop(storage);
        (patch, weak)
    }

    /// The out-of-place pass exists only to do what the in-place one does,
    /// on more than one worker. Pin that: same split depth, same occupied
    /// bytes, same interval per byte, same rows inside each interval.
    ///
    /// Order *within* an interval is deliberately unspecified — keys are
    /// distinct, so a bucket's subtrie is a function of its key set — and the
    /// assertion is written to say so rather than to accidentally depend on
    /// it.
    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_partition_pass_agrees_with_the_in_place_pass() {
        type Subject = PATCH<16, IdentitySchema>;
        let len = 4 * Subject::PARTITION_ROWS_PER_WORKER;
        let mut keys: Vec<[u8; 16]> = Vec::with_capacity(len);
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for index in 0..len {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^= mixed >> 31;
            let mut key = [0u8; 16];
            // Nine rows in ten share a first byte, and every row shares the
            // seven bytes after it, so the representative's prefix has to be
            // walked rather than rejected on the second row.
            key[0] = if index % 10 == 0 {
                (mixed & 0xff) as u8
            } else {
                0x5a
            };
            key[1..8].copy_from_slice(&[0x5a; 7]);
            key[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            keys.push(key);
        }
        keys.sort_unstable();
        keys.dedup();
        assert!(
            keys.len() > 2 * Subject::PARTITION_ROWS_PER_WORKER,
            "the fixture must be wide enough for the out-of-place pass",
        );
        assert!(Subject::partition_workers(keys.len()) > 1);

        let rows: Vec<u32> = (0..keys.len() as u32).collect();
        let mut in_place = rows.clone();
        let ordered = Subject::partition_archive_rows(&keys, &mut in_place, 0);
        let (concurrent, permuted) = Subject::partition_archive_rows_parallel(&keys, &rows, 0);

        assert_eq!(ordered.end_depth, concurrent.end_depth);
        assert_eq!(ordered.fanout, concurrent.fanout);
        assert_eq!(ordered.initial_slots, concurrent.initial_slots);
        assert_eq!(
            ordered.buckets[..ordered.fanout],
            concurrent.buckets[..concurrent.fanout],
        );
        assert_eq!(ordered.ends, concurrent.ends);

        let mut start = 0usize;
        for &byte in &ordered.buckets[..ordered.fanout] {
            let end = ordered.ends[byte as usize] as usize;
            let mut ordered_rows: Vec<u32> = in_place[start..end].to_vec();
            let mut concurrent_rows: Vec<u32> = permuted[start..end].to_vec();
            ordered_rows.sort_unstable();
            concurrent_rows.sort_unstable();
            assert_eq!(ordered_rows, concurrent_rows, "bucket {byte:#04x}");
            start = end;
        }
        assert_eq!(start, keys.len());
    }

    fn key(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn singleton_patch(key: [u8; 16]) -> PATCH<16, IdentitySchema> {
        let mut patch = PATCH::new();
        let entry = Entry::new(&key);
        patch.insert(&entry);
        patch
    }

    #[test]
    fn exported_fingerprint_blinding_is_not_xor_homomorphic() {
        let key = [0x5au8; 16];
        let left = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        let right = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128;
        let blind_left = blind_root_hash_with_key(left, &key);
        let blind_right = blind_root_hash_with_key(right, &key);

        assert_ne!(blind_left, left);
        assert_ne!(
            blind_root_hash_with_key(left ^ right, &key),
            blind_left ^ blind_right
        );
    }

    #[test]
    fn owner_cover_shape_is_canonical_and_membership_is_exact() {
        let owners: Vec<Arc<dyn ArchiveOwner>> = (0u8..8)
            .map(|byte| Arc::new([byte]) as Arc<dyn ArchiveOwner>)
            .collect();
        let build = |order: &[usize]| {
            let mut cover = None;
            for &index in order {
                OwnerCover::retain(&mut cover, &owners[index]);
            }
            cover.unwrap()
        };

        let forward = build(&[0, 1, 2, 3, 4, 5, 6, 7]);
        let shuffled = build(&[6, 2, 7, 0, 5, 1, 4, 3]);
        assert_eq!(forward.len, owners.len());
        assert_eq!(shuffled.len, owners.len());
        assert!(forward.root.same_shape(&shuffled.root));
        for owner in &owners {
            assert!(forward.root.contains(OwnerCover::address(owner)));
        }
        let unrelated: Arc<dyn ArchiveOwner> = Arc::new([0xff]);
        assert!(!forward.root.contains(OwnerCover::address(&unrelated)));
    }

    #[test]
    fn owner_cover_overlapping_diamond_does_not_accumulate_duplicates() {
        let first_backing = Arc::new([0x11]);
        let second_backing = Arc::new([0x22]);
        let first_weak = Arc::downgrade(&first_backing);
        let second_weak = Arc::downgrade(&second_backing);
        let first: Arc<dyn ArchiveOwner> = first_backing.clone();
        let second: Arc<dyn ArchiveOwner> = second_backing.clone();

        let mut left = Some(OwnerCover::singleton(&first));
        OwnerCover::retain(&mut left, &second);
        let mut right = Some(OwnerCover::singleton(&second));
        OwnerCover::retain(&mut right, &first);
        let left_root = match &left.as_ref().unwrap().root {
            OwnerNode::Branch(branch) => Arc::downgrade(branch),
            OwnerNode::Owner(_) => panic!("two owners require one Patricia branch"),
        };
        let right_root = match &right.as_ref().unwrap().root {
            OwnerNode::Branch(branch) => Arc::downgrade(branch),
            OwnerNode::Owner(_) => panic!("two owners require one Patricia branch"),
        };

        for _ in 0..4_096 {
            let next_left = OwnerCover::union(left.clone(), &right);
            let next_right = OwnerCover::union(right.clone(), &left);
            left = next_left;
            right = next_right;
            assert_eq!(left.as_ref().unwrap().len, 2);
            assert_eq!(right.as_ref().unwrap().len, 2);
            assert!(matches!(
                &left.as_ref().unwrap().root,
                OwnerNode::Branch(branch) if Arc::as_ptr(branch) == left_root.as_ptr()
            ));
            assert!(matches!(
                &right.as_ref().unwrap().root,
                OwnerNode::Branch(branch) if Arc::as_ptr(branch) == right_root.as_ptr()
            ));
        }

        drop(first);
        drop(second);
        drop(first_backing);
        drop(second_backing);
        assert!(first_weak.upgrade().is_some());
        assert!(second_weak.upgrade().is_some());
        drop(left);
        drop(right);
        assert!(first_weak.upgrade().is_none());
        assert!(second_weak.upgrade().is_none());
    }

    #[test]
    fn repeated_latest_owner_retention_reuses_the_cover() {
        let owner: Arc<dyn ArchiveOwner> = Arc::new([0x55]);
        let mut cover = None;
        OwnerCover::retain(&mut cover, &owner);
        let original = cover.as_ref().unwrap().clone();

        for _ in 0..4_096 {
            OwnerCover::retain(&mut cover, &owner);
        }

        let cover = cover.unwrap();
        assert!(Arc::ptr_eq(&cover, &original));
        assert_eq!(cover.len, 1);
        assert!(matches!(&cover.root, OwnerNode::Owner(_)));
    }

    proptest! {
        #[test]
        fn owner_cover_union_matches_address_set(
            left in prop::collection::btree_set(0usize..24, 0..24),
            right in prop::collection::btree_set(0usize..24, 0..24),
        ) {
            let owners: Vec<Arc<dyn ArchiveOwner>> = (0u8..24)
                .map(|byte| Arc::new([byte]) as Arc<dyn ArchiveOwner>)
                .collect();
            let build = |indices: Vec<usize>| {
                let mut cover = None;
                for index in indices {
                    OwnerCover::retain(&mut cover, &owners[index]);
                }
                cover
            };
            let left_cover = build(left.iter().copied().collect());
            let right_cover = build(right.iter().rev().copied().collect());
            let joined = OwnerCover::union(left_cover, &right_cover);
            let expected: std::collections::BTreeSet<_> =
                left.union(&right).copied().collect();

            if expected.is_empty() {
                prop_assert!(joined.is_none());
            } else {
                let joined = joined.unwrap();
                let mut actual = HashSet::new();
                joined.root.for_each_owner(&mut |owner| {
                    assert!(actual.insert(OwnerCover::address(owner)));
                });
                let expected_addresses: HashSet<_> = expected
                    .iter()
                    .map(|&index| OwnerCover::address(&owners[index]))
                    .collect();
                prop_assert_eq!(actual, expected_addresses);
                prop_assert_eq!(joined.len, expected.len());

                let canonical = build(expected.iter().copied().collect()).unwrap();
                prop_assert!(joined.root.same_shape(&canonical.root));
            }
        }
    }

    #[test]
    fn disjoint_cross_owner_union_retains_both_archives() {
        let (mut left, left_owner) = owned_archive_pair([key(0x10), key(0x20)]);
        let (right, right_owner) = owned_archive_pair([key(0x30), key(0x40)]);

        left.union(right);

        assert!(
            left_owner.upgrade().is_some(),
            "union dropped its left archive"
        );
        assert!(
            right_owner.upgrade().is_some(),
            "union dropped its consumed right archive"
        );
        assert_eq!(
            left.iter().copied().collect::<HashSet<_>>(),
            HashSet::from([key(0x10), key(0x20), key(0x30), key(0x40)])
        );
        drop(left);
        assert!(left_owner.upgrade().is_none());
        assert!(right_owner.upgrade().is_none());
    }

    #[test]
    fn one_key_intersection_retains_both_source_archives() {
        let (left, left_owner) = owned_archive_pair([key(0x10), key(0x20)]);
        let (right, right_owner) = owned_archive_pair([key(0x10), key(0x30)]);

        let intersection = left.intersect(&right);
        drop(left);
        drop(right);

        assert!(
            left_owner.upgrade().is_some(),
            "intersection dropped the archive backing its surviving LocalLeaf"
        );
        assert!(
            right_owner.upgrade().is_some(),
            "intersection must conservatively retain both source covers"
        );
        assert_eq!(intersection.iter().copied().collect_vec(), vec![key(0x10)]);
        drop(intersection);
        assert!(left_owner.upgrade().is_none());
        assert!(right_owner.upgrade().is_none());
    }

    #[test]
    fn one_key_difference_retains_its_left_archive() {
        let (left, left_owner) = owned_archive_pair([key(0x10), key(0x20)]);
        let (right, right_owner) = owned_archive_pair([key(0x10), key(0x30)]);

        let difference = left.difference(&right);
        drop(left);
        drop(right);

        assert!(
            left_owner.upgrade().is_some(),
            "difference dropped the archive backing its surviving LocalLeaf"
        );
        assert!(
            right_owner.upgrade().is_none(),
            "difference should not retain an archive used only for subtraction"
        );
        assert_eq!(difference.iter().copied().collect_vec(), vec![key(0x20)]);
        drop(difference);
        assert!(left_owner.upgrade().is_none());
        assert!(right_owner.upgrade().is_none());
    }

    #[test]
    fn asymmetric_difference_collapses_its_surviving_child() {
        let (left, owner) = owned_archive_pair([key(0x10), key(0x20)]);
        assert_eq!(left.root.as_ref().map(Head::tag), Some(HeadTag::Branch2));
        let removed = singleton_patch(key(0x10));

        let survivor = left.difference(&removed);
        drop(left);
        drop(removed);

        assert_eq!(survivor.len(), 1);
        assert_eq!(survivor.node_stats(), (0, 0, 0, 1));
        assert_eq!(
            survivor.root.as_ref().map(Head::tag),
            Some(HeadTag::LocalLeaf),
            "Branch-minus-Leaf left a unary Branch instead of its child",
        );
        assert_eq!(survivor.iter().copied().collect_vec(), vec![key(0x20)]);
        assert!(owner.upgrade().is_some());

        let final_key = singleton_patch(key(0x20));
        let empty = survivor.difference(&final_key);
        drop(survivor);
        drop(final_key);

        assert!(empty.root.is_none());
        assert!(empty.owners.is_none());
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn clone_and_consuming_iterator_retain_the_archive() {
        let (patch, owner) = owned_archive_pair([key(0x10), key(0x20)]);
        let clone = patch.clone();
        drop(patch);
        assert!(owner.upgrade().is_some(), "clone lost the archive owner");

        let mut iter = clone.into_iter();
        assert!(
            owner.upgrade().is_some(),
            "consuming iterator lost the archive owner"
        );
        assert!(matches!(iter.next(), Some(value) if value == key(0x10) || value == key(0x20)));
        drop(iter);
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn ordered_consuming_iterator_retains_the_archive() {
        let (patch, owner) = owned_archive_pair([key(0x10), key(0x20)]);

        let mut iter = patch.into_iter_ordered();
        assert!(
            owner.upgrade().is_some(),
            "ordered consuming iterator lost the archive owner"
        );
        assert_eq!(iter.next(), Some(key(0x10)));
        drop(iter);
        assert!(owner.upgrade().is_none());
    }

    #[test]
    fn removal_retains_collapsed_local_root_and_releases_empty_cover() {
        let (mut patch, owner) = owned_archive_pair([key(0x10), key(0x20)]);

        patch.remove(&key(0x10));
        assert!(
            owner.upgrade().is_some(),
            "removal lost the owner of the surviving LocalLeaf"
        );
        assert_eq!(patch.iter().copied().collect_vec(), vec![key(0x20)]);

        patch.remove(&key(0x20));
        assert!(patch.is_empty());
        assert!(owner.upgrade().is_none(), "empty PATCH retained its cover");
    }

    #[test]
    fn head_tag() {
        let head = Head::<64, IdentitySchema, ()>::new::<Leaf<64, ()>>(0, NonNull::dangling());
        assert_eq!(head.tag(), HeadTag::Leaf);
        mem::forget(head);
    }

    #[test]
    fn head_key() {
        for k in 0..=255 {
            let head = Head::<64, IdentitySchema, ()>::new::<Leaf<64, ()>>(k, NonNull::dangling());
            assert_eq!(head.key(), k);
            mem::forget(head);
        }
    }

    #[test]
    fn head_size() {
        assert_eq!(mem::size_of::<Head<64, IdentitySchema, ()>>(), 8);
    }

    #[test]
    fn option_head_size() {
        assert_eq!(mem::size_of::<Option<Head<64, IdentitySchema, ()>>>(), 8);
    }

    #[test]
    fn empty_tree() {
        let _tree = PATCH::<64, IdentitySchema, ()>::new();
    }

    #[test]
    fn tree_put_one() {
        const KEY_SIZE: usize = 64;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        let entry = Entry::new(&[0; KEY_SIZE]);
        tree.insert(&entry);
    }

    #[test]
    fn tree_clone_one() {
        const KEY_SIZE: usize = 64;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        let entry = Entry::new(&[0; KEY_SIZE]);
        tree.insert(&entry);
        let _clone = tree.clone();
    }

    #[test]
    fn consuming_shared_leaf_does_not_mutably_alias_value() {
        const KEY_SIZE: usize = 4;
        let key = [1u8; KEY_SIZE];
        let mut retained = PATCH::<KEY_SIZE, IdentitySchema, String>::new();
        let entry = Entry::with_value(&key, String::from("still borrowed"));
        retained.insert(&entry);
        drop(entry);

        let unordered = retained.clone();
        let value = retained.get(&key).expect("inserted value");
        assert_eq!(unordered.into_iter().collect::<Vec<_>>(), vec![key]);
        assert_eq!(value, "still borrowed");

        let ordered = retained.clone();
        let value = retained.get(&key).expect("inserted value");
        assert_eq!(ordered.into_iter_ordered().collect::<Vec<_>>(), vec![key]);
        assert_eq!(value, "still borrowed");
    }

    #[test]
    fn tree_put_same() {
        const KEY_SIZE: usize = 64;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        let entry = Entry::new(&[0; KEY_SIZE]);
        tree.insert(&entry);
        tree.insert(&entry);
    }

    #[test]
    fn ordered_infix_bounds_include_all_zero_and_all_ff() {
        let mut tree = PATCH::<4, IdentitySchema, ()>::new();
        tree.insert(&Entry::new(&[0x00; 4]));
        tree.insert(&Entry::new(&[0x80, 0x00, 0x00, 0x00]));
        tree.insert(&Entry::new(&[0xff; 4]));

        assert_eq!(
            tree.first_infix_range(&[], &[0x00; 4], &[0xff; 4]),
            Some([0x00; 4]),
        );
        assert_eq!(
            tree.next_infix_after(&[], &[0x00; 4], &[0xff; 4]),
            Some([0x80, 0x00, 0x00, 0x00]),
        );
        assert_eq!(
            tree.first_infix_range(&[], &[0xff; 4], &[0xff; 4]),
            Some([0xff; 4]),
        );
        assert_eq!(tree.next_infix_after(&[], &[0xff; 4], &[0xff; 4]), None,);
        assert_eq!(tree.first_infix_range(&[], &[0xff; 4], &[0x00; 4]), None,);
    }

    #[test]
    fn ordered_infix_descent_reads_local_leaves() {
        #[repr(C, align(16))]
        struct AlignedKey([u8; 16]);

        let storage = std::sync::Arc::new([
            AlignedKey([0x10; 16]),
            AlignedKey([0x20; 16]),
            AlignedKey([0xf0; 16]),
        ]);
        let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
        let mut tree = PATCH::<16, IdentitySchema, ()>::new();
        for key in storage.iter() {
            let entry = unsafe { ArchiveEntry::new(NonNull::from(&key.0), &owner) };
            tree.insert_archive(&entry);
        }

        assert!(tree.node_stats().3 > 0, "fixture must contain a LocalLeaf");
        assert_eq!(
            tree.first_infix_range(&[], &[0x11; 16], &[0xff; 16]),
            Some([0x20; 16]),
        );
        assert_eq!(
            tree.next_infix_after(&[], &[0x20; 16], &[0xff; 16]),
            Some([0xf0; 16]),
        );
    }

    #[test]
    fn ordered_infix_descent_honors_permuted_segments_in_local_leaves() {
        fn physical_key(prefix: [u8; 4], infix: [u8; 4], suffix: [u8; 4]) -> [u8; 12] {
            let mut key = [0; 12];
            key[..4].copy_from_slice(&suffix);
            key[4..8].copy_from_slice(&prefix);
            key[8..].copy_from_slice(&infix);
            key
        }

        let selected = [0x10; 4];
        let other = [0x20; 4];
        let first = [0x11; 4];
        let second = [0x22; 4];
        let storage = std::sync::Arc::new([
            AlignedArchiveKey(physical_key(other, [0x33; 4], [0x44; 4])),
            AlignedArchiveKey(physical_key(selected, second, [0x44; 4])),
            AlignedArchiveKey(physical_key(selected, first, [0x55; 4])),
            AlignedArchiveKey(physical_key(selected, first, [0x44; 4])),
        ]);
        let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
        let mut tree = PATCH::<12, PermutedInfixSchema, ()>::new();
        for key in storage.iter() {
            // SAFETY: every key is aligned and remains immutable and alive
            // through `owner` for the lifetime of the archive-backed PATCH.
            let entry = unsafe { ArchiveEntry::new(NonNull::from(&key.0), &owner) };
            tree.insert_archive(&entry);
        }

        assert!(tree.node_stats().3 > 0, "fixture must contain a LocalLeaf");
        assert_eq!(
            tree.first_infix_range(&selected, &[u8::MIN; 4], &[u8::MAX; 4]),
            Some(first),
        );
        assert_eq!(
            tree.next_infix_after(&selected, &first, &[u8::MAX; 4]),
            Some(second),
        );
        assert_eq!(
            tree.next_infix_after(&selected, &second, &[u8::MAX; 4]),
            None,
        );
    }

    #[test]
    fn bounded_infixes_are_atomic_over_archive_local_leaves() {
        #[repr(C, align(16))]
        struct AlignedKey([u8; 16]);

        let storage = std::sync::Arc::new([
            AlignedKey([0x10; 16]),
            AlignedKey([0x20; 16]),
            AlignedKey([0xf0; 16]),
        ]);
        let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
        let mut tree = PATCH::<16, IdentitySchema, ()>::new();
        for key in storage.iter() {
            let entry = unsafe { ArchiveEntry::new(NonNull::from(&key.0), &owner) };
            tree.insert_archive(&entry);
        }
        assert!(tree.node_stats().3 > 0, "fixture must contain a LocalLeaf");

        assert!(tree.bounded_infixes::<0, 16>(&[], 2).is_none());

        let mut expected = Vec::new();
        tree.infixes(&[], |value: &[u8; 16]| expected.push(*value));
        let mut accepted = Vec::new();
        let bounded = tree
            .bounded_infixes::<0, 16>(&[], 3)
            .expect("the exact count fits");
        assert_eq!(bounded.len(), 3);
        bounded.for_each(|value: &[u8; 16]| accepted.push(*value));
        assert_eq!(accepted, expected);
    }

    #[test]
    fn archive_singleton_pairs_follow_exact_key_identity() {
        const KEY_SIZE: usize = 64;
        #[repr(C, align(16))]
        struct AlignedKey([u8; KEY_SIZE]);

        let key_a = [0x44; KEY_SIZE];
        let mut key_b = key_a;
        key_b[KEY_SIZE - 1] = 0x55;
        let storage = std::sync::Arc::new([AlignedKey(key_a), AlignedKey(key_b)]);
        let _owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();

        let local_a = unsafe { Head::new_local_leaf(0, NonNull::from(&storage[0].0)) };
        let local_b = unsafe { Head::new_local_leaf(0, NonNull::from(&storage[1].0)) };
        let heap_a_entry = Entry::new(&key_a);
        let heap_b_entry = Entry::new(&key_b);
        let heap_a = heap_a_entry.leaf::<IdentitySchema>();
        let heap_b = heap_b_entry.leaf::<IdentitySchema>();

        fn assert_pair(
            left: &Head<64, IdentitySchema, ()>,
            right: &Head<64, IdentitySchema, ()>,
            equal: bool,
        ) {
            let union = Head::union(left.clone(), right.clone(), 0);
            assert_eq!(union.count(), if equal { 1 } else { 2 });
            assert_eq!(
                left.intersect(right, 0).as_ref().map(Head::count),
                equal.then_some(1)
            );
            assert_eq!(
                left.difference(right, 0).as_ref().map(Head::count),
                (!equal).then_some(1)
            );
        }

        assert_pair(&local_a, &local_a, true);
        assert_pair(&local_a, &local_b, false);
        assert_pair(&heap_a, &local_a, true);
        assert_pair(&local_a, &heap_a, true);
        assert_pair(&heap_a, &local_b, false);
        assert_pair(&local_a, &heap_b, false);
        assert_pair(&heap_a, &heap_a, true);
        assert_pair(&heap_a, &heap_b, false);
    }

    #[test]
    fn local_leaf_and_unary_branch_keep_equal_fingerprint_path() {
        const KEY_SIZE: usize = 16;
        #[repr(C, align(16))]
        struct AlignedKey([u8; KEY_SIZE]);

        let storage =
            std::sync::Arc::new([AlignedKey([0x10; KEY_SIZE]), AlignedKey([0x20; KEY_SIZE])]);
        let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
        let mut pair = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        for key in storage.iter() {
            let entry = unsafe { ArchiveEntry::new(NonNull::from(&key.0), &owner) };
            pair.insert_archive(&entry);
        }

        // Deliberately retain a unary Branch representation. Cardinality one
        // is not enough to infer its tag or reject equality with a LocalLeaf.
        let mut unary = pair.root.as_ref().expect("pair has a root").clone();
        let removed_slot = match unary.body_ref() {
            BodyRef::Branch(branch) => branch
                .child_table
                .iter()
                .flatten()
                .find(|child| child.childleaf_key() == &storage[0].0)
                .expect("first archive key is present")
                .key(),
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => panic!("pair root must be a Branch"),
        };
        {
            let mut editor = crate::patch::branch::BranchMut::from_head(&mut unary);
            editor.modify_child(removed_slot, |_| None);
        }
        assert!(matches!(unary.body_ref(), BodyRef::Branch(_)));
        assert_eq!(unary.count(), 1);

        let local = match unary.body_ref() {
            BodyRef::Branch(branch) => branch
                .child_table
                .iter()
                .flatten()
                .next()
                .expect("unary Branch has one child")
                .clone(),
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => unreachable!(),
        };
        assert_eq!(local.tag(), HeadTag::LocalLeaf);
        assert_eq!(local.count(), 1);
        assert_eq!(local.hash(), unary.hash());

        // The equal-fingerprint shortcut returns its left operand unchanged.
        // These shape checks therefore prove that the count-one case reaches
        // fingerprints rather than taking the unequal-cardinality descent.
        let union = Head::union(local.clone(), unary.clone(), 0);
        assert_eq!(union.tag(), HeadTag::LocalLeaf);
        let intersection = unary
            .intersect(&local, 0)
            .expect("equal singleton sets intersect");
        assert!(matches!(intersection.body_ref(), BodyRef::Branch(_)));
        assert!(unary.difference(&local, 0).is_none());

        #[cfg(feature = "parallel")]
        {
            let union = Head::par_union(local.clone(), unary.clone(), 0);
            assert_eq!(union.tag(), HeadTag::LocalLeaf);
            let intersection = unary
                .par_intersect(&local, 0)
                .expect("equal singleton sets intersect");
            assert!(matches!(intersection.body_ref(), BodyRef::Branch(_)));
            assert!(unary.par_difference(&local, 0).is_none());
        }
    }

    #[test]
    fn archive_set_ops_retain_shared_backing() {
        const KEY_SIZE: usize = 16;
        #[repr(C, align(16))]
        struct AlignedKey([u8; KEY_SIZE]);

        let key_a = [0x10; KEY_SIZE];
        let key_b = [0x20; KEY_SIZE];
        let key_c = [0x30; KEY_SIZE];
        let (left, right) = {
            let storage =
                std::sync::Arc::new([AlignedKey(key_a), AlignedKey(key_b), AlignedKey(key_c)]);
            let owner: std::sync::Arc<dyn ArchiveOwner> = storage.clone();
            let mut left = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
            let mut right = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
            for index in [0, 1] {
                let entry = unsafe { ArchiveEntry::new(NonNull::from(&storage[index].0), &owner) };
                left.insert_archive(&entry);
            }
            for index in [1, 2] {
                let entry = unsafe { ArchiveEntry::new(NonNull::from(&storage[index].0), &owner) };
                right.insert_archive(&entry);
            }
            assert!(left.node_stats().3 > 0);
            assert!(right.node_stats().3 > 0);
            (left, right)
        };

        let mut union = left.clone();
        union.union(right.clone());
        assert_eq!(union.len(), 3);
        assert!(union.get(&key_a).is_some());
        assert!(union.get(&key_b).is_some());
        assert!(union.get(&key_c).is_some());

        let intersection = left.intersect(&right);
        assert_eq!(intersection.len(), 1);
        assert!(intersection.get(&key_b).is_some());

        let difference = left.difference(&right);
        assert_eq!(difference.len(), 1);
        assert!(difference.get(&key_a).is_some());
    }

    #[test]
    fn tree_replace_existing() {
        const KEY_SIZE: usize = 64;
        let key = [1u8; KEY_SIZE];
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let entry1 = Entry::with_value(&key, 1);
        tree.insert(&entry1);
        let entry2 = Entry::with_value(&key, 2);
        tree.replace(&entry2);
        assert_eq!(tree.get(&key), Some(&2));
    }

    #[test]
    fn tree_replace_childleaf_updates_branch() {
        const KEY_SIZE: usize = 64;
        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let entry1 = Entry::with_value(&key1, 1);
        let entry2 = Entry::with_value(&key2, 2);
        tree.insert(&entry1);
        tree.insert(&entry2);
        let entry1b = Entry::with_value(&key1, 3);
        tree.replace(&entry1b);
        assert_eq!(tree.get(&key1), Some(&3));
        assert_eq!(tree.get(&key2), Some(&2));
    }

    #[test]
    fn update_child_refreshes_childleaf_on_replace() {
        const KEY_SIZE: usize = 4;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        tree.insert(&Entry::with_value(&key1, 1));
        tree.insert(&Entry::with_value(&key2, 2));

        // Determine which child currently provides the branch childleaf.
        let root_ref = tree.root.as_ref().expect("root exists");
        let before_childleaf = *root_ref.childleaf_key();

        // Find the slot key (the byte index used in the branch table) for the child
        // that currently provides the childleaf.
        let slot_key = match root_ref.body_ref() {
            BodyRef::Branch(branch) => branch
                .child_table
                .iter()
                .filter_map(|c| c.as_ref())
                .find(|c| c.childleaf_key() == &before_childleaf)
                .expect("child exists")
                .key(),
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => panic!("root should be a branch"),
        };

        // Replace that child with a new leaf that has a different childleaf key.
        let new_key = [2u8; KEY_SIZE];
        {
            let mut ed = crate::patch::branch::BranchMut::from_slot(&mut tree.root);
            ed.modify_child(slot_key, |_| {
                Some(Entry::with_value(&new_key, 42).leaf::<IdentitySchema>())
            });
            // drop(ed) commits
        }

        let after = tree.root.as_ref().expect("root exists");
        assert_eq!(after.childleaf_key(), &new_key);
    }

    #[test]
    fn replace_commits_nested_structure_before_value_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 4;
        let replaced = [0, 0, 0, 0];
        let nested_sibling = [0, 0, 0, 1];
        let root_sibling = [1, 0, 0, 0];
        let mut patch = PATCH::<KEY_LEN, IdentitySchema, PanicOnDrop>::new();

        for (key, should_panic) in [
            (replaced, true),
            (nested_sibling, false),
            (root_sibling, false),
        ] {
            let entry = Entry::with_value(&key, PanicOnDrop(should_panic));
            patch.insert(&entry);
            drop(entry);
        }
        let old_hash = patch.root_hash().expect("fixture hash");
        let old_nodes = patch.node_stats();

        let replacement = Entry::with_value(&replaced, PanicOnDrop(false));
        let result = catch_unwind(AssertUnwindSafe(|| patch.replace(&replacement)));
        assert!(result.is_err());

        assert_eq!(patch.len(), 3);
        assert_eq!(patch.get(&replaced).map(|value| value.0), Some(false));
        assert_eq!(patch.get(&nested_sibling).map(|value| value.0), Some(false));
        assert_eq!(patch.get(&root_sibling).map(|value| value.0), Some(false));
        assert_eq!(patch.root_hash(), Some(old_hash));
        assert_eq!(patch.node_stats(), old_nodes);
        assert_eq!(
            patch.iter_ordered().copied().collect::<Vec<_>>(),
            vec![replaced, nested_sibling, root_sibling],
        );
    }

    #[test]
    fn replace_commits_singleton_root_before_value_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 4;
        let key = [7; KEY_LEN];
        let mut patch = PATCH::<KEY_LEN, IdentitySchema, PanicOnDrop>::new();
        let original = Entry::with_value(&key, PanicOnDrop(true));
        patch.insert(&original);
        drop(original);

        let replacement = Entry::with_value(&key, PanicOnDrop(false));
        let result = catch_unwind(AssertUnwindSafe(|| patch.replace(&replacement)));
        assert!(result.is_err());

        assert_eq!(patch.len(), 1);
        assert_eq!(patch.get(&key).map(|value| value.0), Some(false));
        assert_eq!(patch.root_hash(), Some(hash_key(&key)));
        assert!(matches!(
            patch.root.as_ref().expect("replacement root").body_ref(),
            BodyRef::Leaf(_),
        ));
    }

    #[test]
    fn remove_commits_nested_structure_before_value_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 4;
        let removed = [0, 0, 0, 0];
        let nested_sibling = [0, 0, 0, 1];
        let root_sibling = [1, 0, 0, 0];
        let mut patch = PATCH::<KEY_LEN, IdentitySchema, PanicOnDrop>::new();

        for (key, should_panic) in [
            (removed, true),
            (nested_sibling, false),
            (root_sibling, false),
        ] {
            let entry = Entry::with_value(&key, PanicOnDrop(should_panic));
            patch.insert(&entry);
            drop(entry);
        }
        assert_eq!(patch.node_stats().0, 2, "fixture must contain two branches");
        assert_eq!(
            patch.root.as_ref().expect("root branch").childleaf_key(),
            &removed,
            "the removed leaf must back the ancestor representative pointer",
        );
        let old_hash = patch.root_hash().expect("fixture hash");

        let result = catch_unwind(AssertUnwindSafe(|| patch.remove(&removed)));
        assert!(result.is_err());

        assert_eq!(patch.len(), 2);
        assert!(patch.get(&removed).is_none());
        assert!(patch.get(&nested_sibling).is_some());
        assert!(patch.get(&root_sibling).is_some());
        assert_eq!(
            patch.iter_ordered().copied().collect::<Vec<_>>(),
            vec![nested_sibling, root_sibling],
        );
        assert_eq!(patch.node_stats().0, 1, "the nested unary branch collapsed");
        assert_ne!(
            patch.root.as_ref().expect("surviving root").childleaf_key(),
            &removed,
            "the surviving branch must not retain a dangling representative",
        );
        assert_eq!(patch.root_hash(), Some(old_hash ^ hash_key(&removed)));
        let fanout = patch.branch_fanout_histogram();
        assert_eq!(fanout[0], 0);
        assert_eq!(fanout[1], 0);
    }

    #[test]
    fn remove_collapses_root_before_value_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 4;
        let removed = [0; KEY_LEN];
        let retained = [1; KEY_LEN];
        let mut patch = PATCH::<KEY_LEN, IdentitySchema, PanicOnDrop>::new();
        for (key, should_panic) in [(removed, true), (retained, false)] {
            let entry = Entry::with_value(&key, PanicOnDrop(should_panic));
            patch.insert(&entry);
            drop(entry);
        }

        let result = catch_unwind(AssertUnwindSafe(|| patch.remove(&removed)));
        assert!(result.is_err());
        assert_eq!(patch.len(), 1);
        assert!(patch.get(&removed).is_none());
        assert!(patch.get(&retained).is_some());
        assert_eq!(patch.root_hash(), Some(hash_key(&retained)));
        assert!(matches!(
            patch.root.as_ref().expect("retained root").body_ref(),
            BodyRef::Leaf(_),
        ));
    }

    #[test]
    fn remove_commits_cow_snapshot_before_deferred_value_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 4;
        let removed = [0; KEY_LEN];
        let retained = [1; KEY_LEN];
        let mut edited = PATCH::<KEY_LEN, IdentitySchema, PanicOnDrop>::new();
        for (key, should_panic) in [(removed, true), (retained, false)] {
            let entry = Entry::with_value(&key, PanicOnDrop(should_panic));
            edited.insert(&entry);
            drop(entry);
        }
        let snapshot = edited.clone();

        // The untouched snapshot still owns the removed leaf, so this is not
        // yet its final release and the edit itself cannot run `V::drop`.
        edited.remove(&removed);
        assert!(edited.get(&removed).is_none());
        assert!(edited.get(&retained).is_some());
        assert_eq!(edited.root_hash(), Some(hash_key(&retained)));
        assert!(snapshot.get(&removed).is_some());

        let result = catch_unwind(AssertUnwindSafe(|| drop(snapshot)));
        assert!(result.is_err());
        assert_eq!(edited.len(), 1);
        assert!(edited.get(&retained).is_some());
    }

    #[test]
    fn remove_retains_archive_owner_until_empty_then_commits_before_drop_panics() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        const KEY_LEN: usize = 16;
        #[repr(C, align(16))]
        struct PanickingOwner {
            keys: [AlignedArchiveKey<KEY_LEN>; 2],
            drops: Arc<AtomicUsize>,
        }

        impl Drop for PanickingOwner {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::Relaxed);
                panic!("intentional archive owner drop panic");
            }
        }

        let first = [7; KEY_LEN];
        let second = [8; KEY_LEN];
        let drops = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(PanickingOwner {
            keys: [AlignedArchiveKey(first), AlignedArchiveKey(second)],
            drops: drops.clone(),
        });
        let erased: Arc<dyn ArchiveOwner> = owner.clone();
        let mut patch = PATCH::<KEY_LEN, IdentitySchema>::new();
        for index in 0..2 {
            let entry = unsafe { ArchiveEntry::new(NonNull::from(&owner.keys[index].0), &erased) };
            patch.insert_archive(&entry);
        }
        drop(erased);
        drop(owner);

        // Removing one LocalLeaf may collapse its parent, but must retain the
        // owner cover for the promoted survivor.
        patch.remove(&first);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(patch.owners.is_some());
        assert_eq!(patch.iter().copied().collect::<Vec<_>>(), vec![second]);
        assert!(matches!(
            patch.root.as_ref().expect("archive root").body_ref(),
            BodyRef::LocalLeaf(_),
        ));

        let result = catch_unwind(AssertUnwindSafe(|| patch.remove(&second)));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(patch.root.is_none(), "the empty root was committed first");
        assert!(
            patch.owners.is_none(),
            "the owner cover was detached before reclamation"
        );
        assert!(patch.is_empty());
    }

    #[test]
    fn remove_promotes_a_multi_leaf_only_child_subtree() {
        const KEY_LEN: usize = 4;
        let removed = [0, 0, 0, 0];
        let retained_a = [1, 0, 0, 0];
        let retained_b = [1, 1, 0, 0];
        let mut patch = PATCH::<KEY_LEN, IdentitySchema>::new();
        for key in [removed, retained_a, retained_b] {
            patch.insert(&Entry::new(&key));
        }
        assert_eq!(patch.node_stats().0, 2, "fixture must contain two branches");

        patch.remove(&removed);

        assert_eq!(patch.len(), 2);
        assert_eq!(patch.node_stats().0, 1, "unary root must be removed");
        assert_eq!(patch.branch_fanout_histogram()[1], 0);
        assert!(patch.get(&retained_a).is_some());
        assert!(patch.get(&retained_b).is_some());
    }

    #[test]
    fn remove_childleaf_updates_branch() {
        const KEY_SIZE: usize = 4;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        tree.insert(&Entry::with_value(&key1, 1));
        tree.insert(&Entry::with_value(&key2, 2));

        let childleaf_before = *tree.root.as_ref().unwrap().childleaf_key();
        // remove the leaf that currently provides the branch.childleaf
        tree.remove(&childleaf_before);

        // Ensure the removed key is gone and the other key remains and is now the childleaf.
        let other = if childleaf_before == key1 { key2 } else { key1 };
        assert_eq!(tree.get(&childleaf_before), None);
        assert_eq!(tree.get(&other), Some(&2u32));
        let after_childleaf = tree.root.as_ref().unwrap().childleaf_key();
        assert_eq!(after_childleaf, &other);
    }

    #[test]
    fn remove_collapses_branch_to_single_child() {
        const KEY_SIZE: usize = 4;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let key1 = [0u8; KEY_SIZE];
        let key2 = [1u8; KEY_SIZE];
        tree.insert(&Entry::with_value(&key1, 1));
        tree.insert(&Entry::with_value(&key2, 2));

        // Remove one key and ensure the root collapses to the remaining child.
        tree.remove(&key1);
        assert_eq!(tree.get(&key1), None);
        assert_eq!(tree.get(&key2), Some(&2u32));
        let root = tree.root.as_ref().expect("root exists");
        match root.body_ref() {
            BodyRef::Leaf(_) | BodyRef::LocalLeaf(_) => {}
            BodyRef::Branch(_) => panic!("root should have collapsed to a leaf"),
        }
    }

    #[test]
    fn branch_size() {
        // Ownership lives once on PATCH, leaving the original 48-byte Branch
        // header. Each child is an 8-byte tagged Head.
        assert_eq!(
            mem::size_of::<Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 2], ()>>(
            ),
            48 + 8 * 2
        );
        assert_eq!(
            mem::size_of::<Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 4], ()>>(
            ),
            48 + 8 * 4
        );
        assert_eq!(
            mem::size_of::<Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 8], ()>>(
            ),
            48 + 8 * 8
        );
        assert_eq!(
            mem::size_of::<
                Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 16], ()>,
            >(),
            48 + 8 * 16
        );
        assert_eq!(
            mem::size_of::<
                Branch<64, IdentitySchema, [Option<Head<32, IdentitySchema, ()>>; 32], ()>,
            >(),
            48 + 8 * 32
        );
        assert_eq!(
            mem::size_of::<
                Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 64], ()>,
            >(),
            48 + 8 * 64
        );
        assert_eq!(
            mem::size_of::<
                Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 128], ()>,
            >(),
            48 + 8 * 128
        );
        assert_eq!(
            mem::size_of::<
                Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 256], ()>,
            >(),
            48 + 8 * 256
        );
    }

    #[test]
    fn patch_root_owner_cover_is_one_thin_arc() {
        // Default-policy layout is a compatibility and performance contract:
        // making PATCH generic must not charge TribleSet for the stronger
        // digest it does not use.
        assert_eq!(mem::size_of::<Entry<64, ()>>(), 8);
        assert_eq!(mem::size_of::<Leaf<64, ()>>(), 96);
        assert_eq!(mem::size_of::<Head<64, IdentitySchema, ()>>(), 8);
        assert_eq!(
            mem::size_of::<Branch<64, IdentitySchema, [Option<Head<64, IdentitySchema, ()>>; 0], ()>>(
            ),
            48
        );
        assert_eq!(mem::size_of::<Option<Arc<OwnerCover>>>(), 8);
        assert_eq!(mem::size_of::<PATCH<64, IdentitySchema, ()>>(), 16);

        assert_eq!(mem::size_of::<Entry<64, (), Blake3Merkle>>(), 8);
        assert_eq!(mem::size_of::<Leaf<64, (), Blake3Merkle>>(), 112);
        assert_eq!(
            mem::size_of::<
                Branch<
                    64,
                    IdentitySchema,
                    [Option<Head<64, IdentitySchema, (), Blake3Merkle>>; 0],
                    (),
                    Blake3Merkle,
                >,
            >(),
            64
        );
        assert_eq!(
            mem::size_of::<PATCH<64, IdentitySchema, (), Blake3Merkle>>(),
            16
        );
    }

    /// Checks what happens if we join two PATCHes that
    /// only contain a single element each, that differs in the last byte.
    #[test]
    fn tree_union_single() {
        const KEY_SIZE: usize = 8;
        let mut left = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        let mut right = PATCH::<KEY_SIZE, IdentitySchema, ()>::new();
        let left_entry = Entry::new(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let right_entry = Entry::new(&[0, 0, 0, 0, 0, 0, 0, 1]);
        left.insert(&left_entry);
        right.insert(&right_entry);
        left.union(right);
        assert_eq!(left.len(), 2);
    }

    // Small unit tests that ensure BranchMut-based editing is used by
    // the higher-level set operations like intersect/difference. These are
    // ordinary unit tests (not proptest) and must appear outside the
    // `proptest!` macro below.

    proptest! {
        #[test]
        fn tree_insert(keys in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 1..1024)) {
            let mut tree = PATCH::<64, IdentitySchema, ()>::new();
            for key in keys {
                let key: [u8; 64] = key.try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
            }
        }

        #[test]
        fn tree_len(keys in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 1..1024)) {
            let mut tree = PATCH::<64, IdentitySchema, ()>::new();
            let mut set = HashSet::new();
            for key in keys {
                let key: [u8; 64] = key.try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
                set.insert(key);
            }

            prop_assert_eq!(set.len() as u64, tree.len())
        }

        #[test]
        fn tree_infixes(keys in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 1..1024)) {
            let mut tree = PATCH::<64, IdentitySchema, ()>::new();
            let mut set = HashSet::new();
            for key in keys {
                let key: [u8; 64] = key.try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
                set.insert(key);
            }
            let mut set_vec = Vec::from_iter(set.into_iter());
            let mut tree_vec = vec![];
            tree.infixes(&[0; 0], &mut |&x: &[u8; 64]| tree_vec.push(x));

            set_vec.sort();
            tree_vec.sort();

            prop_assert_eq!(set_vec, tree_vec);
        }

        #[test]
        fn tree_iter(keys in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 1..1024)) {
            let mut tree = PATCH::<64, IdentitySchema, ()>::new();
            let mut set = HashSet::new();
            for key in keys {
                let key: [u8; 64] = key.try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
                set.insert(key);
            }
            let mut set_vec = Vec::from_iter(set.into_iter());
            let mut tree_vec = vec![];
            for key in &tree {
                tree_vec.push(*key);
            }

            set_vec.sort();
            tree_vec.sort();

            prop_assert_eq!(set_vec, tree_vec);
        }

        #[test]
        fn tree_union(left in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 200),
                        right in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 200)) {
            let mut set = HashSet::new();

            let mut left_tree = PATCH::<64, IdentitySchema, ()>::new();
            for entry in left {
                let mut key = [0; 64];
                key.iter_mut().set_from(entry.iter().cloned());
                let entry = Entry::new(&key);
                left_tree.insert(&entry);
                set.insert(key);
            }

            let mut right_tree = PATCH::<64, IdentitySchema, ()>::new();
            for entry in right {
                let mut key = [0; 64];
                key.iter_mut().set_from(entry.iter().cloned());
                let entry = Entry::new(&key);
                right_tree.insert(&entry);
                set.insert(key);
            }

            left_tree.union(right_tree);

            let mut set_vec = Vec::from_iter(set.into_iter());
            let mut tree_vec = vec![];
            left_tree.infixes(&[0; 0], &mut |&x: &[u8;64]| tree_vec.push(x));

            set_vec.sort();
            tree_vec.sort();

            prop_assert_eq!(set_vec, tree_vec);
            }

        #[test]
        fn tree_union_empty(left in prop::collection::vec(prop::collection::vec(0u8..=255, 64), 2)) {
            let mut set = HashSet::new();

            let mut left_tree = PATCH::<64, IdentitySchema, ()>::new();
            for entry in left {
                let mut key = [0; 64];
                key.iter_mut().set_from(entry.iter().cloned());
                let entry = Entry::new(&key);
                left_tree.insert(&entry);
                set.insert(key);
            }

            let right_tree = PATCH::<64, IdentitySchema, ()>::new();

            left_tree.union(right_tree);

            let mut set_vec = Vec::from_iter(set.into_iter());
            let mut tree_vec = vec![];
            left_tree.infixes(&[0; 0], &mut |&x: &[u8;64]| tree_vec.push(x));

            set_vec.sort();
            tree_vec.sort();

            prop_assert_eq!(set_vec, tree_vec);
            }

        // I got a feeling that we're not testing COW properly.
        // We should check if a tree remains the same after a clone of it
        // is modified by inserting new keys.

    #[test]
    fn cow_on_insert(base_keys in prop::collection::vec(prop::collection::vec(0u8..=255, 8), 1..1024),
                         new_keys in prop::collection::vec(prop::collection::vec(0u8..=255, 8), 1..1024)) {
            // Note that we can't compare the trees directly, as that uses the hash,
            // which might not be affected by nodes in lower levels being changed accidentally.
            // Instead we need to iterate over the keys and check if they are the same.

            let mut tree = PATCH::<8, IdentitySchema, ()>::new();
            for key in base_keys {
                let key: [u8; 8] = key[..].try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
            }
            let base_tree_content: Vec<[u8; 8]> = tree.iter().copied().collect();

            let mut tree_clone = tree.clone();
            for key in new_keys {
                let key: [u8; 8] = key[..].try_into().unwrap();
                let entry = Entry::new(&key);
                tree_clone.insert(&entry);
            }

            let new_tree_content: Vec<[u8; 8]> = tree.iter().copied().collect();
            prop_assert_eq!(base_tree_content, new_tree_content);
        }

        #[test]
    fn cow_on_union(base_keys in prop::collection::vec(prop::collection::vec(0u8..=255, 8), 1..1024),
                         new_keys in prop::collection::vec(prop::collection::vec(0u8..=255, 8), 1..1024)) {
            // Note that we can't compare the trees directly, as that uses the hash,
            // which might not be affected by nodes in lower levels being changed accidentally.
            // Instead we need to iterate over the keys and check if they are the same.

            let mut tree = PATCH::<8, IdentitySchema, ()>::new();
            for key in base_keys {
                let key: [u8; 8] = key[..].try_into().unwrap();
                let entry = Entry::new(&key);
                tree.insert(&entry);
            }
            let base_tree_content: Vec<[u8; 8]> = tree.iter().copied().collect();

            let mut tree_clone = tree.clone();
            let mut new_tree = PATCH::<8, IdentitySchema, ()>::new();
            for key in new_keys {
                let key: [u8; 8] = key[..].try_into().unwrap();
                let entry = Entry::new(&key);
                new_tree.insert(&entry);
            }
            tree_clone.union(new_tree);

            let new_tree_content: Vec<[u8; 8]> = tree.iter().copied().collect();
            prop_assert_eq!(base_tree_content, new_tree_content);
        }
    }

    #[test]
    fn intersect_multiple_common_children_commits_branchmut() {
        const KEY_SIZE: usize = 4;
        let mut left = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let mut right = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let a = [0u8, 0u8, 0u8, 1u8];
        let b = [0u8, 0u8, 0u8, 2u8];
        let c = [0u8, 0u8, 0u8, 3u8];
        let d = [2u8, 0u8, 0u8, 0u8];
        let e = [3u8, 0u8, 0u8, 0u8];

        left.insert(&Entry::with_value(&a, 1));
        left.insert(&Entry::with_value(&b, 2));
        left.insert(&Entry::with_value(&c, 3));
        left.insert(&Entry::with_value(&d, 4));

        right.insert(&Entry::with_value(&a, 10));
        right.insert(&Entry::with_value(&b, 11));
        right.insert(&Entry::with_value(&c, 12));
        right.insert(&Entry::with_value(&e, 13));

        let res = left.intersect(&right);
        // A, B, C are common
        assert_eq!(res.len(), 3);
        assert!(res.get(&a).is_some());
        assert!(res.get(&b).is_some());
        assert!(res.get(&c).is_some());
    }

    #[test]
    fn difference_multiple_children_commits_branchmut() {
        const KEY_SIZE: usize = 4;
        let mut left = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let mut right = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let a = [0u8, 0u8, 0u8, 1u8];
        let b = [0u8, 0u8, 0u8, 2u8];
        let c = [0u8, 0u8, 0u8, 3u8];
        let d = [2u8, 0u8, 0u8, 0u8];
        let e = [3u8, 0u8, 0u8, 0u8];

        left.insert(&Entry::with_value(&a, 1));
        left.insert(&Entry::with_value(&b, 2));
        left.insert(&Entry::with_value(&c, 3));
        left.insert(&Entry::with_value(&d, 4));

        right.insert(&Entry::with_value(&a, 10));
        right.insert(&Entry::with_value(&b, 11));
        right.insert(&Entry::with_value(&c, 12));
        right.insert(&Entry::with_value(&e, 13));

        let res = left.difference(&right);
        // left only has d
        assert_eq!(res.len(), 1);
        assert!(res.get(&d).is_some());
    }

    #[test]
    fn difference_equal_singleton_after_survivor_collapse_is_empty() {
        const KEY_SIZE: usize = 16;
        let removed_key = [0x10; KEY_SIZE];
        let survivor_key = [0x20; KEY_SIZE];

        let mut pair = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        pair.insert(&Entry::with_value(&removed_key, 1));
        pair.insert(&Entry::with_value(&survivor_key, 2));

        let mut removed = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        removed.insert(&Entry::with_value(&removed_key, 1));
        let collapsed_survivor = pair.difference(&removed);
        assert_eq!(collapsed_survivor.len(), 1);
        assert_eq!(
            collapsed_survivor.root.as_ref().map(Head::tag),
            Some(HeadTag::Leaf),
        );

        let mut survivor = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        survivor.insert(&Entry::with_value(&survivor_key, 2));
        assert_eq!(collapsed_survivor, survivor);
        assert!(collapsed_survivor.difference(&survivor).root.is_none());
    }

    #[test]
    fn difference_empty_left_is_empty() {
        const KEY_SIZE: usize = 4;
        let left = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let mut right = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let key = [1u8, 2u8, 3u8, 4u8];
        right.insert(&Entry::with_value(&key, 7));

        let res = left.difference(&right);
        assert_eq!(res.len(), 0);
    }

    #[test]
    fn difference_empty_right_returns_left() {
        const KEY_SIZE: usize = 4;
        let mut left = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let right = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();
        let key = [1u8, 2u8, 3u8, 4u8];
        left.insert(&Entry::with_value(&key, 7));

        let res = left.difference(&right);
        assert_eq!(res.len(), 1);
        assert!(res.get(&key).is_some());
    }

    #[test]
    fn slot_edit_branchmut_insert_update() {
        // Small unit test demonstrating the Slot::edit -> BranchMut insert/update pattern.
        const KEY_SIZE: usize = 8;
        let mut tree = PATCH::<KEY_SIZE, IdentitySchema, u32>::new();

        let entry1 = Entry::with_value(&[0u8; KEY_SIZE], 1u32);
        let entry2 = Entry::with_value(&[1u8; KEY_SIZE], 2u32);
        tree.insert(&entry1);
        tree.insert(&entry2);
        assert_eq!(tree.len(), 2);

        // Edit the root slot in-place using the BranchMut editor.
        {
            let mut ed = crate::patch::branch::BranchMut::from_slot(&mut tree.root);

            // Compute the insertion start depth first to avoid borrowing `ed` inside the closure.
            let start_depth = ed.end_depth as usize;
            let inserted = Entry::with_value(&[2u8; KEY_SIZE], 3u32)
                .leaf::<IdentitySchema>()
                .with_start(start_depth);
            let key = inserted.key();

            ed.modify_child(key, |opt| match opt {
                Some(old) => Some(Head::insert_leaf(old, inserted, start_depth)),
                None => Some(inserted),
            });
            // BranchMut is dropped here and commits the updated branch pointer back into the head.
        }

        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(&[2u8; KEY_SIZE]), Some(&3u32));
    }
}
