use super::*;
use core::sync::atomic;
use core::sync::atomic::Ordering::Acquire;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::Ordering::Release;
use std::alloc::alloc_zeroed;
use std::alloc::dealloc;
use std::alloc::handle_alloc_error;
use std::alloc::Layout;
use std::mem::{align_of, size_of};
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr::addr_of;
use std::ptr::addr_of_mut;

#[inline]
pub(crate) fn dst_len<T>(ptr: *const [T]) -> usize {
    let ptr: *const [()] = ptr as _;
    // SAFETY: There is no aliasing as () is zero-sized
    let slice: &[()] = unsafe { &*ptr };
    slice.len()
}

// Mutable editor for a Branch body. This lives in the branch module and
// encapsulates NonNull/pointer handling for mutating operations. When the
// editor is dropped it automatically writes the final pointer back into the
// owning Head via Head::set_body.
pub(crate) type BranchNN<const KEY_LEN: usize, O, V, H> =
    NonNull<Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>>;

pub(crate) struct BranchMut<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> {
    head: &'a mut Head<KEY_LEN, O, V, H>,
    branch_nn: BranchNN<KEY_LEN, O, V, H>,
    hash_dirty: bool,
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    BranchMut<'a, KEY_LEN, O, V, H>
{
    pub(crate) fn from_head(head: &'a mut Head<KEY_LEN, O, V, H>) -> Self {
        match head.body_mut() {
            BodyMut::Branch(branch_ref) => {
                let nn = unsafe { NonNull::new_unchecked(branch_ref as *mut _) };
                Self {
                    head,
                    branch_nn: nn,
                    hash_dirty: false,
                }
            }
            BodyMut::Leaf(_) | BodyMut::LocalLeaf(_) => {
                panic!("BranchMut requires a Branch body")
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_slot(slot: &'a mut Option<Head<KEY_LEN, O, V, H>>) -> Self {
        let head = slot.as_mut().expect("slot should not be empty");
        Self::from_head(head)
    }

    pub fn modify_child<F>(&mut self, key: u8, f: F)
    where
        F: FnOnce(Option<Head<KEY_LEN, O, V, H>>) -> Option<Head<KEY_LEN, O, V, H>>,
    {
        // Delegate to the low-level NonNull based primitive which may grow and
        // update the pointer in-place.
        self.hash_dirty |= Branch::modify_child(&mut self.branch_nn, key, !self.hash_dirty, f);
    }

    /// Checked insertion's unique-path update. Unlike `modify_child`, the
    /// child stays installed while the callback can fail or panic. The private
    /// callback must leave the child unchanged on error/panic, and report true
    /// only after a successful insertion with no further user callbacks.
    pub(super) fn try_update_child<E>(
        &mut self,
        key: u8,
        update: impl FnOnce(&mut Head<KEY_LEN, O, V, H>) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let branch = unsafe { self.branch_nn.as_mut() };
        let depth = branch.end_depth as usize;
        let child = branch.child_table.table_get_slot(key).unwrap().as_mut().unwrap();
        let old_hash = child.hash();
        let old_segments = child.count_segment(depth);
        let old_count = child.count();
        let represented = child.childleaf_ptr() == branch.childleaf;
        if !update(child)? {
            return Ok(false);
        }
        if H::INCREMENTAL_BRANCH && !self.hash_dirty {
            branch.hash = H::edit_branch(branch.hash, key, Some(old_hash), Some(child.hash()));
        } else {
            self.hash_dirty = true;
        }
        branch.segment_count = branch.segment_count - old_segments + child.count_segment(depth);
        branch.leaf_count = branch.leaf_count - old_count + child.count();
        if represented {
            branch.childleaf = child.childleaf_ptr();
        }
        #[cfg(debug_assertions)]
        if !self.hash_dirty {
            branch.debug_check_invariants();
        }
        Ok(true)
    }

    /// Like [`modify_child`] but uses the supplied `inserted_hash`
    /// for the empty-slot insertion case instead of calling
    /// `inserted.hash()`. Lets archive ingest avoid recomputing
    /// the LocalLeaf digest once per index — the caller already
    /// has it from `ArchiveEntry::hash`.
    ///
    /// The hint MUST equal the hash of whatever `f(None)` returns.
    /// When the slot is non-empty and `f(Some(_))` runs, the result
    /// is hashed normally (recursion result, hash already cached on
    /// the Branch).
    pub fn modify_child_with_inserted_hint<F>(&mut self, key: u8, inserted_hash: H::Digest, f: F)
    where
        F: FnOnce(Option<Head<KEY_LEN, O, V, H>>) -> Option<Head<KEY_LEN, O, V, H>>,
    {
        self.hash_dirty |= Branch::modify_child_with_inserted_hint(
            &mut self.branch_nn,
            key,
            inserted_hash,
            !self.hash_dirty,
            f,
        );
    }

    /// Insert `head` into the child table, growing the allocation if cuckoo
    /// placement fails. Does *not* update the branch's aggregates —
    /// pair with [`Self::recompute_aggregates`] for bulk rewrites.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    pub fn install_child_growing(&mut self, head: Head<KEY_LEN, O, V, H>) {
        unsafe {
            Branch::install_child_growing(&mut self.branch_nn, head);
        }
    }

    /// Rebuild aggregates (hash/leaf_count/segment_count/childleaf) in one
    /// linear pass over `child_table`. Call once after a batch of
    /// [`Self::install_child_growing`] mutations.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    pub fn recompute_aggregates(&mut self) {
        unsafe {
            Branch::recompute_aggregates(&mut self.branch_nn);
        }
        self.hash_dirty = false;
    }

    /// Finish a bulk rewrite while installing an independently accumulated
    /// exact hash.
    ///
    /// Counts and the representative child pointer are rebuilt in one table
    /// scan, but child hashes are deliberately not read. Archive construction
    /// already hashes each row once and carries the exact branch summary
    /// through its recursion, so re-reading direct `LocalLeaf` children here
    /// would repeat that work for every index.
    pub fn finish_bulk_aggregates(&mut self, known_hash: H::Digest) {
        unsafe {
            Branch::finish_bulk_aggregates(&mut self.branch_nn, known_hash);
        }
        self.hash_dirty = false;
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Deref
    for BranchMut<'a, KEY_LEN, O, V, H>
{
    type Target = Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>;

    fn deref(&self) -> &Self::Target {
        unsafe { self.branch_nn.as_ref() }
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> DerefMut
    for BranchMut<'a, KEY_LEN, O, V, H>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.branch_nn.as_mut() }
    }
}

impl<'a, const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Drop
    for BranchMut<'a, KEY_LEN, O, V, H>
{
    fn drop(&mut self) {
        if !H::INCREMENTAL_BRANCH && self.hash_dirty {
            unsafe {
                Branch::recompute_hash(&mut self.branch_nn);
            }
        }
        // Commit the final branch pointer into the owning Head.
        self.head.set_body(self.branch_nn);
    }
}

#[repr(C, align(16))]
pub(crate) struct Branch<
    const KEY_LEN: usize,
    O: KeySchema<KEY_LEN>,
    Table: ?Sized,
    V,
    H: PatchHash = XorSip128,
> {
    key_ordering: PhantomData<O>,
    key_segments: PhantomData<O::Segmentation>,
    /// Phantom `V`: the value type is no longer stored on the branch
    /// itself (the childleaf is just `*const [u8; KEY_LEN]`), but it
    /// stays carried so child `Head<KEY_LEN, O, V, H>` slots in
    /// `child_table` and the `Body` impl for the concrete child-table
    /// shape stay generic in `V`.
    _value: PhantomData<fn() -> V>,
    _hash_policy: PhantomData<H>,

    rc: atomic::AtomicU32,
    pub end_depth: u32,
    /// Thin pointer to the key bytes of a representative descendant
    /// leaf, used for prefix-matching shortcuts. Points either into a
    /// heap [`Leaf`]'s inline `key` field (offset 0 thanks to
    /// `#[repr(C)]`) or into archive memory referenced by a
    /// `LocalLeaf`. The unified `*const [u8; KEY_LEN]` representation
    /// lets both leaf flavors serve as the childleaf.
    pub childleaf: *const [u8; KEY_LEN],
    pub leaf_count: u64,
    pub segment_count: u64,
    pub hash: H::Digest,
    pub child_table: Table,
}

impl<
        const KEY_LEN: usize,
        O: KeySchema<KEY_LEN>,
        Table: ?Sized + core::fmt::Debug,
        V: core::fmt::Debug,
        H: PatchHash,
    > core::fmt::Debug for Branch<KEY_LEN, O, Table, V, H>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Branch")
            .field("rc", &self.rc)
            .field("end_depth", &self.end_depth)
            .field("childleaf", &self.childleaf)
            .field("leaf_count", &self.leaf_count)
            .field("segment_count", &self.segment_count)
            .field("hash", &self.hash)
            .field("child_table", &&self.child_table)
            .finish()
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, Table: ?Sized, V, H: PatchHash>
    Branch<KEY_LEN, O, Table, V, H>
{
    pub(super) fn is_unique(&self) -> bool {
        self.rc.load(Acquire) == 1
    }

    /// Returns the key bytes of the representative child leaf. The
    /// pointer is set to a heap `Leaf`'s `key` field (offset 0) or to
    /// a `LocalLeaf`'s archive-resident bytes; both yield the same
    /// reference shape.
    pub fn childleaf_key(&self) -> &[u8; KEY_LEN] {
        unsafe { &*self.childleaf }
    }

    /// Returns the raw key-bytes pointer of the representative child
    /// leaf. Used for pointer-identity comparisons during invariant
    /// checks and for propagating the representative through
    /// branch-construction paths.
    pub fn childleaf_ptr(&self) -> *const [u8; KEY_LEN] {
        self.childleaf
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash> Body
    for Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>
{
    fn tag(body: NonNull<Self>) -> HeadTag {
        unsafe {
            let ptr = addr_of!((*body.as_ptr()).child_table);
            let exp = dst_len(ptr).ilog2() as u8;
            debug_assert!((1..=8).contains(&exp));
            HeadTag::from_raw(exp)
        }
    }
}

impl<const KEY_LEN: usize, O: KeySchema<KEY_LEN>, V, H: PatchHash>
    Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>
{
    #[inline]
    fn allocation_layout(size: usize) -> Layout {
        let base = size_of::<Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>; 0], V, H>>();
        let bytes = base + size_of::<Option<Head<KEY_LEN, O, V, H>>>() * size;
        // SAFETY: every caller bounds `size` to 2..=256; `base`, the Head
        // stride, and the concrete Branch alignment are valid type layouts.
        unsafe {
            Layout::from_size_align_unchecked(
                bytes,
                align_of::<Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>; 0], V, H>>(),
            )
        }
    }

    #[inline]
    fn hash_two_children(
        end_depth: usize,
        lchild: &Head<KEY_LEN, O, V, H>,
        lchild_hash: H::Digest,
        rchild: &Head<KEY_LEN, O, V, H>,
        rchild_hash: H::Digest,
    ) -> H::Digest {
        let leaf_count = lchild.count() + rchild.count();
        let mut state = H::begin_branch(
            lchild.childleaf_key(),
            &O::TREE_TO_KEY,
            end_depth,
            2,
            leaf_count,
        );
        if H::COMMUTATIVE_BRANCH {
            H::push_child(&mut state, 0, lchild.count(), lchild_hash);
            H::push_child(&mut state, 0, rchild.count(), rchild_hash);
        } else if lchild.key() <= rchild.key() {
            H::push_child(&mut state, lchild.key(), lchild.count(), lchild_hash);
            H::push_child(&mut state, rchild.key(), rchild.count(), rchild_hash);
        } else {
            H::push_child(&mut state, rchild.key(), rchild.count(), rchild_hash);
            H::push_child(&mut state, lchild.key(), lchild.count(), lchild_hash);
        }
        H::finish_branch(state)
    }

    pub(super) fn new(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
    ) -> NonNull<Self> {
        // Compute rchild's hash via the normal path. For LocalLeaf
        // this computes the configured leaf digest; the
        // [`new_with_rchild_hash`] variant skips it when
        // the caller has the hash already.
        let rchild_hash = rchild.hash();
        Self::new_with_rchild_hash(end_depth, lchild, rchild, rchild_hash)
    }

    /// Variant of [`Self::new`] that takes a precomputed
    /// `rchild_hash` and uses it instead of calling `rchild.hash()`.
    /// Lets archive-ingest divergence paths reuse the
    /// `ArchiveEntry::hash` they already have instead of recomputing
    /// the configured digest over the LocalLeaf bytes.
    ///
    /// `rchild_hash` MUST equal `rchild.hash()`. The lchild hash
    /// still goes through the normal path — it's typically a Branch
    /// (cached) or heap Leaf (cached), so the only LocalLeaf hash
    /// recompute that matters is on the freshly inserted side.
    pub(super) fn new_with_rchild_hash(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
        rchild_hash: H::Digest,
    ) -> NonNull<Self> {
        let lchild_hash = lchild.hash();
        Self::new_with_child_hashes(end_depth, lchild, rchild, lchild_hash, rchild_hash)
    }

    /// Variant used when both child hashes are already known. Bottom-up
    /// archive construction and exact singleton union can therefore create a
    /// binary Branch without hashing either child a second time.
    pub(super) fn new_with_child_hashes(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
        lchild_hash: H::Digest,
        rchild_hash: H::Digest,
    ) -> NonNull<Self> {
        let hash = Self::hash_two_children(end_depth, &lchild, lchild_hash, &rchild, rchild_hash);
        Self::new_with_known_hash(end_depth, lchild, rchild, hash)
    }

    /// Allocate a binary Branch whose complete canonical digest is already
    /// known. Bottom-up builders use this to avoid hashing a temporary
    /// two-child node before installing the rest of a wider fanout.
    ///
    /// `hash` MUST summarize exactly `lchild` and `rchild` at `end_depth`.
    pub(super) fn new_with_known_hash(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
        hash: H::Digest,
    ) -> NonNull<Self> {
        unsafe {
            let size = 2;
            let layout = Self::allocation_layout(size);
            let Some(ptr) =
                NonNull::new(std::ptr::slice_from_raw_parts(alloc_zeroed(layout), size)
                    as *mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>)
            else {
                handle_alloc_error(layout);
            };
            addr_of_mut!((*ptr.as_ptr()).rc).write(atomic::AtomicU32::new(1));
            addr_of_mut!((*ptr.as_ptr()).end_depth).write(end_depth as u32);
            addr_of_mut!((*ptr.as_ptr()).childleaf).write(lchild.childleaf_ptr());
            addr_of_mut!((*ptr.as_ptr()).leaf_count).write(lchild.count() + rchild.count());
            addr_of_mut!((*ptr.as_ptr()).segment_count)
                .write(lchild.count_segment(end_depth) + rchild.count_segment(end_depth));
            addr_of_mut!((*ptr.as_ptr()).hash).write(hash);
            (*ptr.as_ptr()).child_table[0] = Some(lchild);
            (*ptr.as_ptr()).child_table[1] = Some(rchild);

            ptr
        }
    }

    /// Direct-capacity variant for a Branch whose complete fanout is known
    /// before allocation. Binary Branches keep the two-slot constructor above;
    /// wider Branches begin at the smallest power-of-two capacity that can
    /// hold their known fanout and grow only if cuckoo placement still needs
    /// it.
    #[cfg(any(test, feature = "parallel"))]
    pub(super) fn new_with_child_hashes_capacity(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
        lchild_hash: H::Digest,
        rchild_hash: H::Digest,
        size: usize,
    ) -> NonNull<Self> {
        let hash = Self::hash_two_children(end_depth, &lchild, lchild_hash, &rchild, rchild_hash);
        Self::new_with_known_hash_capacity(end_depth, lchild, rchild, hash, size)
    }

    /// Direct-capacity twin of [`Self::new_with_known_hash`] for a wider
    /// bottom-up node whose final fanout and digest are already known.
    ///
    /// `hash` may summarize children not installed yet. The constructor is
    /// private and callers must finish installing the complete child set and
    /// rebuild structural aggregates before the Branch can escape.
    pub(super) fn new_with_known_hash_capacity(
        end_depth: usize,
        lchild: Head<KEY_LEN, O, V, H>,
        rchild: Head<KEY_LEN, O, V, H>,
        hash: H::Digest,
        size: usize,
    ) -> NonNull<Self> {
        assert!(
            size > 2 && size <= 256 && size.is_power_of_two(),
            "direct Branch capacity must be a power of two in 4..=256",
        );
        unsafe {
            let layout = Self::allocation_layout(size);
            let Some(ptr) =
                NonNull::new(std::ptr::slice_from_raw_parts(alloc_zeroed(layout), size)
                    as *mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>)
            else {
                handle_alloc_error(layout);
            };

            addr_of_mut!((*ptr.as_ptr()).rc).write(atomic::AtomicU32::new(1));
            addr_of_mut!((*ptr.as_ptr()).end_depth).write(end_depth as u32);
            addr_of_mut!((*ptr.as_ptr()).childleaf).write(lchild.childleaf_ptr());
            addr_of_mut!((*ptr.as_ptr()).leaf_count).write(lchild.count() + rchild.count());
            addr_of_mut!((*ptr.as_ptr()).segment_count)
                .write(lchild.count_segment(end_depth) + rchild.count_segment(end_depth));
            addr_of_mut!((*ptr.as_ptr()).hash).write(hash);

            if let Some(displaced) = (*ptr.as_ptr()).child_table.table_insert(lchild) {
                Self::rc_dec(ptr);
                drop(displaced);
                unreachable!("the first child must fit an empty direct-capacity Branch");
            }
            if let Some(displaced) = (*ptr.as_ptr()).child_table.table_insert(rchild) {
                // The first child is owned by the Branch and is reclaimed by
                // rc_dec; the returned second child has not entered the table.
                Self::rc_dec(ptr);
                drop(displaced);
                unreachable!("two distinct children must fit a direct-capacity Branch");
            }
            ptr
        }
    }

    pub(super) unsafe fn rc_inc(branch: NonNull<Self>) -> NonNull<Self> {
        unsafe {
            let branch = branch.as_ptr();
            let mut current = (*branch).rc.load(Relaxed);
            loop {
                if current == u32::MAX {
                    panic!("max refcount exceeded");
                }
                match (*branch)
                    .rc
                    .compare_exchange(current, current + 1, Relaxed, Relaxed)
                {
                    Ok(_) => return NonNull::new_unchecked(branch),
                    Err(v) => current = v,
                }
            }
        }
    }

    pub(super) unsafe fn rc_dec(branch: NonNull<Self>) {
        unsafe {
            let branch = branch.as_ptr();
            if (*branch).rc.fetch_sub(1, Release) != 1 {
                return;
            }
            (*branch).rc.load(Acquire);

            let size = dst_len(addr_of!((*branch).child_table));

            std::ptr::drop_in_place(branch);

            let layout = Self::allocation_layout(size);
            let ptr = branch as *mut u8;
            dealloc(ptr, layout);
        }
    }

    /// Ensure the branch is uniquely owned. If it is shared (rc > 1) a
    /// copy is allocated and `*branch_nn` is updated to point to the new unique
    /// allocation. Returns `Some(())` if a copy was made, or `None` if the
    /// branch was already unique.
    pub(super) unsafe fn rc_cow(branch_nn: &mut NonNull<Self>) -> Option<()> {
        unsafe {
            let branch = branch_nn.as_ptr();
            if (*branch).rc.load(Acquire) == 1 {
                None
            } else {
                let size = dst_len(addr_of!((*branch).child_table));
                let layout = Self::allocation_layout(size);
                if let Some(ptr) =
                    NonNull::new(std::ptr::slice_from_raw_parts(alloc_zeroed(layout), size)
                        as *mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>)
                {
                    addr_of_mut!((*ptr.as_ptr()).rc).write(atomic::AtomicU32::new(1));
                    addr_of_mut!((*ptr.as_ptr()).end_depth).write((*branch).end_depth);
                    addr_of_mut!((*ptr.as_ptr()).childleaf).write((*branch).childleaf);
                    addr_of_mut!((*ptr.as_ptr()).leaf_count).write((*branch).leaf_count);
                    addr_of_mut!((*ptr.as_ptr()).segment_count).write((*branch).segment_count);
                    addr_of_mut!((*ptr.as_ptr()).hash).write((*branch).hash);
                    (*ptr.as_ptr())
                        .child_table
                        .clone_from_slice(&(*branch).child_table);

                    Self::rc_dec(NonNull::new_unchecked(branch));
                    *branch_nn = ptr;
                    Some(())
                } else {
                    handle_alloc_error(layout);
                }
            }
        }
    }

    /// Grow the branch's allocation in-place by updating the provided
    /// `branch_nn` to point to a larger allocation. The caller must provide a
    /// mutable reference to the owned pointer; this function updates it when a
    /// new allocation is made.
    pub(crate) fn grow(branch_nn: &mut NonNull<Self>) {
        unsafe {
            let branch = branch_nn.as_ptr();
            let old_size = dst_len(addr_of!((*branch).child_table));
            let new_size = old_size * 2;
            assert!(new_size <= 256);

            let layout = Self::allocation_layout(new_size);
            if let Some(ptr) = NonNull::new(std::ptr::slice_from_raw_parts(
                alloc_zeroed(layout),
                new_size,
            )
                as *mut Branch<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>)
            {
                addr_of_mut!((*ptr.as_ptr()).rc).write(atomic::AtomicU32::new(1));
                addr_of_mut!((*ptr.as_ptr()).end_depth).write((*branch).end_depth);
                addr_of_mut!((*ptr.as_ptr()).leaf_count).write((*branch).leaf_count);
                addr_of_mut!((*ptr.as_ptr()).segment_count).write((*branch).segment_count);
                addr_of_mut!((*ptr.as_ptr()).childleaf).write((*branch).childleaf);
                addr_of_mut!((*ptr.as_ptr()).hash).write((*branch).hash);
                // Note that the child_table is already zeroed by the allocator and therefore None initialized.

                (*branch)
                    .child_table
                    .table_grow(&mut (*ptr.as_ptr()).child_table);

                Branch::<KEY_LEN, O, [Option<Head<KEY_LEN, O, V, H>>], V, H>::rc_dec(
                    NonNull::new_unchecked(branch),
                );

                *branch_nn = ptr;
            } else {
                handle_alloc_error(layout);
            }
        }
    }

    // Insert-child helper removed — use `modify_child` which consolidates
    // insert/update/remove logic and handles potential growth in-place.

    /// Generalized modify/insert/remove primitive for a child slot.
    ///
    /// The closure receives the current child if present (Some) or None when
    /// the slot is empty and should return the new child to place into the
    /// slot (Some) or None to remove/leave empty. This consolidates the
    /// insert/update/remove logic in one place and updates branch aggregates
    /// and `childleaf` as needed. The `branch_nn` pointer may be updated in
    /// place when the underlying allocation grows.
    pub(super) fn modify_child<F>(
        branch_nn: &mut NonNull<Self>,
        key: u8,
        hash_is_current: bool,
        f: F,
    ) -> bool
    where
        F: FnOnce(Option<Head<KEY_LEN, O, V, H>>) -> Option<Head<KEY_LEN, O, V, H>>,
    {
        unsafe {
            let branch = branch_nn.as_ptr();
            let end_depth = (*branch).end_depth as usize;
            let mut hash_dirty = !hash_is_current;

            // If a slot exists, operate on the existing child in-place.
            if let Some(slot) = (*branch).child_table.table_get_slot(key) {
                let child = slot.take().unwrap();
                let old_child_hash = child.hash();
                let old_child_segment_count = child.count_segment(end_depth);
                let old_child_leaf_count = child.count();

                let replaced_childleaf = child.childleaf_ptr() == (*branch).childleaf;

                if let Some(new_child) = f(Some(child)) {
                    // Replace existing child
                    let new_child_hash = new_child.hash();
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash = H::edit_branch(
                            (*branch).hash,
                            key,
                            Some(old_child_hash),
                            Some(new_child_hash),
                        );
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }
                    (*branch).segment_count = ((*branch).segment_count - old_child_segment_count)
                        + new_child.count_segment(end_depth);
                    (*branch).leaf_count =
                        ((*branch).leaf_count - old_child_leaf_count) + new_child.count();

                    if replaced_childleaf {
                        (*branch).childleaf = new_child.childleaf_ptr();
                    }

                    if slot.replace(new_child.with_key(key)).is_some() {
                        unreachable!();
                    }
                } else {
                    // Remove existing child
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash =
                            H::edit_branch((*branch).hash, key, Some(old_child_hash), None);
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }
                    (*branch).segment_count -= old_child_segment_count;
                    (*branch).leaf_count -= old_child_leaf_count;

                    if replaced_childleaf {
                        if let Some(other) = (*branch).child_table.iter().find_map(|s| s.as_ref()) {
                            (*branch).childleaf = other.childleaf_ptr();
                        }
                    }
                }
            } else {
                // No current slot — the closure can choose to insert a child.
                if let Some(mut inserted) = f(None) {
                    // The caller is expected to pass an inserted Head that is
                    // already prepared (with_start set to the appropriate depth).
                    // Update aggregates before attempting insertion.
                    (*branch).leaf_count += inserted.count();
                    (*branch).segment_count += inserted.count_segment(end_depth);
                    let inserted_hash = inserted.hash();
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash =
                            H::edit_branch((*branch).hash, key, None, Some(inserted_hash));
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }

                    // Cuckoo insert loop, growing the table when necessary.
                    let mut branch_ptr = branch_nn.as_ptr();
                    while let Some(new_displaced) = (*branch_ptr).child_table.table_insert(inserted)
                    {
                        inserted = new_displaced;
                        Self::grow(branch_nn);
                        // Refresh local pointer after potential reallocation.
                        branch_ptr = branch_nn.as_ptr();
                    }
                }
            }
            // Debug invariant check (no-op in release builds).
            #[cfg(debug_assertions)]
            if !hash_dirty {
                branch_nn.as_ref().debug_check_invariants();
            }
            hash_dirty
        }
    }

    /// Variant of [`Self::modify_child`] that takes a precomputed
    /// `inserted_hash` and uses it for the empty-slot insertion path
    /// instead of calling `inserted.hash()`. The hint MUST equal the
    /// hash of whatever `f(None)` returns. The non-empty path uses
    /// `new_child.hash()` as normal (the recursive result is a Branch
    /// whose hash is already cached, so the call is O(1)).
    pub(super) fn modify_child_with_inserted_hint<F>(
        branch_nn: &mut NonNull<Self>,
        key: u8,
        inserted_hash: H::Digest,
        hash_is_current: bool,
        f: F,
    ) -> bool
    where
        F: FnOnce(Option<Head<KEY_LEN, O, V, H>>) -> Option<Head<KEY_LEN, O, V, H>>,
    {
        unsafe {
            let branch = branch_nn.as_ptr();
            let end_depth = (*branch).end_depth as usize;
            let mut hash_dirty = !hash_is_current;

            if let Some(slot) = (*branch).child_table.table_get_slot(key) {
                let child = slot.take().unwrap();
                let old_child_hash = child.hash();
                let old_child_segment_count = child.count_segment(end_depth);
                let old_child_leaf_count = child.count();

                let replaced_childleaf = child.childleaf_ptr() == (*branch).childleaf;

                if let Some(new_child) = f(Some(child)) {
                    // Recursion result — its hash is cached on the
                    // returned Head (Branch.hash field), so calling
                    // .hash() is cheap.
                    let new_child_hash = new_child.hash();
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash = H::edit_branch(
                            (*branch).hash,
                            key,
                            Some(old_child_hash),
                            Some(new_child_hash),
                        );
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }
                    (*branch).segment_count = ((*branch).segment_count - old_child_segment_count)
                        + new_child.count_segment(end_depth);
                    (*branch).leaf_count =
                        ((*branch).leaf_count - old_child_leaf_count) + new_child.count();

                    if replaced_childleaf {
                        (*branch).childleaf = new_child.childleaf_ptr();
                    }

                    if slot.replace(new_child.with_key(key)).is_some() {
                        unreachable!();
                    }
                } else {
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash =
                            H::edit_branch((*branch).hash, key, Some(old_child_hash), None);
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }
                    (*branch).segment_count -= old_child_segment_count;
                    (*branch).leaf_count -= old_child_leaf_count;

                    if replaced_childleaf {
                        if let Some(other) = (*branch).child_table.iter().find_map(|s| s.as_ref()) {
                            (*branch).childleaf = other.childleaf_ptr();
                        }
                    }
                }
            } else {
                if let Some(mut inserted) = f(None) {
                    // Use the caller-supplied hint instead of
                    // recomputing the configured digest over the LocalLeaf bytes.
                    (*branch).leaf_count += inserted.count();
                    (*branch).segment_count += inserted.count_segment(end_depth);
                    if hash_is_current && H::INCREMENTAL_BRANCH {
                        (*branch).hash =
                            H::edit_branch((*branch).hash, key, None, Some(inserted_hash));
                    } else if !H::INCREMENTAL_BRANCH {
                        hash_dirty = true;
                    }

                    let mut branch_ptr = branch_nn.as_ptr();
                    while let Some(new_displaced) = (*branch_ptr).child_table.table_insert(inserted)
                    {
                        inserted = new_displaced;
                        Self::grow(branch_nn);
                        branch_ptr = branch_nn.as_ptr();
                    }
                }
            }
            #[cfg(debug_assertions)]
            if !hash_dirty {
                branch_nn.as_ref().debug_check_invariants();
            }
            hash_dirty
        }
    }

    // Note: upsert_child removed in favor of explicit insert_child / update_child

    // The old in-place `update_child` helper has been superseded by
    // `modify_child` which accepts an Option<Head> and handles insert/update/remove
    // uniformly. The thin adapter was removed to centralize behavior; callers
    // should use `modify_child` or BranchMut::modify_child.

    /// Insert `head` into the child table, growing if cuckoo placement
    /// fails. Does NOT touch aggregates — used by bulk-rewrite paths
    /// that recompute aggregates in one pass at the end via
    /// [`recompute_aggregates`](Self::recompute_aggregates).
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    pub(crate) unsafe fn install_child_growing(
        branch_nn: &mut NonNull<Self>,
        head: Head<KEY_LEN, O, V, H>,
    ) {
        let mut to_insert = head;
        let mut branch_ptr = branch_nn.as_ptr();
        while let Some(displaced) = (*branch_ptr).child_table.table_insert(to_insert) {
            to_insert = displaced;
            Self::grow(branch_nn);
            branch_ptr = branch_nn.as_ptr();
        }
    }

    /// Rebuild aggregate fields (`hash`, `leaf_count`, `segment_count`,
    /// `childleaf`) from the current child table in one linear pass.
    /// Cheaper than paying `modify_child`'s per-call accounting when
    /// many children are being installed in bulk.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    pub(crate) unsafe fn recompute_aggregates(branch_nn: &mut NonNull<Self>) {
        let branch = branch_nn.as_ptr();
        let end_depth = (*branch).end_depth as usize;
        let mut agg_leaf_count: u64 = 0;
        let mut agg_segment_count: u64 = 0;
        let mut first_childleaf: *const [u8; KEY_LEN] = std::ptr::null();

        for child in (*branch).child_table.iter().flatten() {
            agg_leaf_count += child.count();
            agg_segment_count += child.count_segment(end_depth);
            if first_childleaf.is_null() {
                first_childleaf = child.childleaf_ptr();
            }
        }

        (*branch).leaf_count = agg_leaf_count;
        (*branch).segment_count = agg_segment_count;
        Self::recompute_hash(branch_nn);
        if !first_childleaf.is_null() {
            (*branch).childleaf = first_childleaf;
        }

        #[cfg(debug_assertions)]
        branch_nn.as_ref().debug_check_invariants();
    }

    /// Rebuild only the hash summary in canonical child-edge order.
    pub(crate) unsafe fn recompute_hash(branch_nn: &mut NonNull<Self>) {
        let branch = branch_nn.as_ptr();
        let mut edges = ByteSet::new_empty();
        let mut representative = None;
        for child in (*branch).child_table.iter().flatten() {
            edges.insert(child.key());
            representative.get_or_insert_with(|| child.childleaf_key());
        }
        let empty_representative = [0; KEY_LEN];
        let representative = representative.unwrap_or(&empty_representative);
        let mut state = H::begin_branch(
            representative,
            &O::TREE_TO_KEY,
            (*branch).end_depth as usize,
            edges.popcount() as usize,
            (*branch).leaf_count,
        );
        while let Some(edge) = edges.drain_next_ascending() {
            let child = (*branch)
                .child_table
                .table_get(edge)
                .expect("enumerated PATCH child must remain present");
            H::push_child(&mut state, edge, child.count(), child.hash());
        }
        (*branch).hash = H::finish_branch(state);
    }

    /// Rebuild structural aggregates after a batch of child installations and
    /// install a caller-proven exact hash without traversing child hashes.
    pub(crate) unsafe fn finish_bulk_aggregates(
        branch_nn: &mut NonNull<Self>,
        known_hash: H::Digest,
    ) {
        let branch = branch_nn.as_ptr();
        let end_depth = (*branch).end_depth as usize;
        let mut agg_leaf_count: u64 = 0;
        let mut agg_segment_count: u64 = 0;
        let mut first_childleaf: *const [u8; KEY_LEN] = std::ptr::null();

        for child in (*branch).child_table.iter().flatten() {
            agg_leaf_count += child.count();
            agg_segment_count += child.count_segment(end_depth);
            if first_childleaf.is_null() {
                first_childleaf = child.childleaf_ptr();
            }
        }

        (*branch).leaf_count = agg_leaf_count;
        (*branch).segment_count = agg_segment_count;
        (*branch).hash = known_hash;
        if !first_childleaf.is_null() {
            (*branch).childleaf = first_childleaf;
        }

        #[cfg(debug_assertions)]
        branch_nn.as_ref().debug_check_invariants();
    }

    pub fn count_segment(&self, at_depth: usize) -> u64 {
        let node_end = self.end_depth as usize;
        if !O::same_segment_tree(at_depth, node_end) {
            1
        } else {
            self.segment_count
        }
    }

    /// Debug-only invariant checker. Validates that the aggregate fields
    /// (leaf_count, segment_count, hash, childleaf) are consistent with the
    /// current child table. Exists only in debug builds so it adds zero
    /// overhead in release binaries.
    #[cfg(debug_assertions)]
    pub fn debug_check_invariants(&self) {
        let end_depth: usize = self.end_depth as usize;
        let mut agg_leaf_count: u64 = 0;
        let mut agg_segment_count: u64 = 0;
        let mut match_found = false;
        let mut representative = None;

        let mut edges = ByteSet::new_empty();

        for child in self.child_table.iter().flatten() {
            agg_leaf_count = agg_leaf_count.saturating_add(child.count());
            agg_segment_count = agg_segment_count.saturating_add(child.count_segment(end_depth));
            edges.insert(child.key());
            representative.get_or_insert_with(|| child.childleaf_key());
            if child.childleaf_ptr() == self.childleaf {
                match_found = true;
            }
        }

        debug_assert_eq!(
            agg_leaf_count, self.leaf_count,
            "branch.leaf_count mismatch"
        );
        debug_assert_eq!(
            agg_segment_count, self.segment_count,
            "branch.segment_count mismatch"
        );
        let empty_representative = [0; KEY_LEN];
        let representative = representative.unwrap_or(&empty_representative);
        let mut state = H::begin_branch(
            representative,
            &O::TREE_TO_KEY,
            end_depth,
            edges.popcount() as usize,
            self.leaf_count,
        );
        while let Some(edge) = edges.drain_next_ascending() {
            let child = self
                .child_table
                .table_get(edge)
                .expect("enumerated PATCH child must remain present");
            H::push_child(&mut state, edge, child.count(), child.hash());
        }
        debug_assert_eq!(H::finish_branch(state), self.hash, "branch.hash mismatch");

        // If there are any leaves aggregated in this branch then the
        // `childleaf` pointer must match one of the children. When the
        // aggregate count is zero the equality check above already guarantees
        // `self.leaf_count == 0`, so the explicit empty-branch assertion is
        // redundant and can be omitted.
        if agg_leaf_count > 0 {
            debug_assert!(match_found, "branch.childleaf pointer mismatch");
        }
    }

    /// Return true if this branch's childleaf key matches the provided
    /// `prefix` for all tree-ordered bytes in [at_depth, PREFIX_LEN).
    pub fn infixes<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        f: &mut F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        // Early-prune: if the branch's representative childleaf doesn't match
        // the prefix then no child in this branch can match.
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        // If the branch's representative childleaf does NOT match the
        // provided prefix then no child in this branch can match and we can
        // early-return. The previous logic inverted this check which caused
        // branches to be pruned incorrectly.
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return;
        }

        // The infix ends within the current node.
        if PREFIX_LEN + INFIX_LEN <= node_end_depth {
            let infix: [u8; INFIX_LEN] =
                core::array::from_fn(|i| self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]]);
            f(&infix);
            return;
        }
        // The prefix ends in a child of this node.
        if PREFIX_LEN > node_end_depth {
            if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
                child.infixes(prefix, node_end_depth, f);
            }
            return;
        }

        // The prefix ends in this node, but the infix ends in a child.
        for entry in self.child_table.iter().flatten() {
            entry.infixes(prefix, node_end_depth, f);
        }
    }

    /// Like [`infixes`](Self::infixes) but only yields infixes in the
    /// byte range `[min_infix, max_infix]` (inclusive).
    ///
    /// In Case 3 (prefix ends in this node, infix in children), filters
    /// children by their byte key against the range bounds at the current
    /// depth, pruning entire subtrees outside the range.
    pub fn infixes_range<const PREFIX_LEN: usize, const INFIX_LEN: usize, F>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
        f: &mut F,
    ) where
        F: FnMut(&[u8; INFIX_LEN]),
    {
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return;
        }

        // Case 1: infix ends within this node — extract and range-check.
        if PREFIX_LEN + INFIX_LEN <= node_end_depth {
            let infix: [u8; INFIX_LEN] =
                core::array::from_fn(|i| self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]]);
            if &infix >= min_infix && &infix <= max_infix {
                f(&infix);
            }
            return;
        }

        // Case 2: prefix extends into a specific child.
        if PREFIX_LEN > node_end_depth {
            if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
                child.infixes_range(prefix, node_end_depth, min_infix, max_infix, f);
            }
            return;
        }

        // Case 3: prefix ends here, infix spans children.
        // First check the compressed path (bytes PREFIX_LEN..node_end_depth)
        // against the range. All children share these bytes (path compression).
        let infix_byte_idx = node_end_depth - PREFIX_LEN;
        let mut min_tight = true; // still on the min boundary
        let mut max_tight = true; // still on the max boundary
        for i in 0..infix_byte_idx {
            let path_byte = self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]];
            if min_tight {
                if path_byte < min_infix[i] {
                    return;
                } // whole branch below min
                if path_byte > min_infix[i] {
                    min_tight = false;
                } // safely above min
            }
            if max_tight {
                if path_byte > max_infix[i] {
                    return;
                } // whole branch above max
                if path_byte < max_infix[i] {
                    max_tight = false;
                } // safely below max
            }
        }

        // Now iterate children, filtering by their byte at infix_byte_idx
        // only when we're still tight on that boundary.
        for entry in self.child_table.iter().flatten() {
            let child_byte = entry.key();
            if min_tight && infix_byte_idx < INFIX_LEN && child_byte < min_infix[infix_byte_idx] {
                continue;
            }
            if max_tight && infix_byte_idx < INFIX_LEN && child_byte > max_infix[infix_byte_idx] {
                continue;
            }
            entry.infixes_range(prefix, node_end_depth, min_infix, max_infix, f);
        }
    }

    /// Return the lexicographically first infix in the inclusive range.
    ///
    /// Child slots are cuckoo-ordered rather than lexicographically ordered,
    /// so lower-bound descent probes child byte values in order and follows
    /// only the first subtree that can contain a match. This keeps the cursor
    /// independent of the branch's physical table layout.
    pub fn first_infix_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> Option<[u8; INFIX_LEN]> {
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return None;
        }

        // The complete infix lies on this compressed path, so every
        // descendant represents the same infix value.
        if PREFIX_LEN + INFIX_LEN <= node_end_depth {
            let infix: [u8; INFIX_LEN] =
                core::array::from_fn(|i| self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]]);
            return (&infix >= min_infix && &infix <= max_infix).then_some(infix);
        }

        // The prefix fixes the one child that can contain a result.
        if PREFIX_LEN > node_end_depth {
            return self
                .child_table
                .table_get(prefix[node_end_depth])
                .and_then(|child| {
                    child.first_infix_range(prefix, node_end_depth, min_infix, max_infix)
                });
        }

        // The fixed part of this compressed path must be compatible with the
        // range. Track whether the next branching byte is still constrained
        // by either boundary.
        let infix_byte_idx = node_end_depth - PREFIX_LEN;
        let mut min_tight = true;
        let mut max_tight = true;
        for i in 0..infix_byte_idx {
            let path_byte = self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]];
            if min_tight {
                if path_byte < min_infix[i] {
                    return None;
                }
                if path_byte > min_infix[i] {
                    min_tight = false;
                }
            }
            if max_tight {
                if path_byte > max_infix[i] {
                    return None;
                }
                if path_byte < max_infix[i] {
                    max_tight = false;
                }
            }
        }

        let lower = if min_tight {
            min_infix[infix_byte_idx]
        } else {
            u8::MIN
        };
        let upper = if max_tight {
            max_infix[infix_byte_idx]
        } else {
            u8::MAX
        };

        for child_byte in lower..=upper {
            let Some(child) = self.child_table.table_get(child_byte) else {
                continue;
            };
            if let Some(infix) =
                child.first_infix_range(prefix, node_end_depth, min_infix, max_infix)
            {
                return Some(infix);
            }
        }
        None
    }

    /// Count leaves whose infix falls within [min_infix, max_infix].
    ///
    /// Counts **distinct first-segment values** under this branch whose
    /// infix falls within `[min_infix, max_infix]` — matching the
    /// cardinality that `infixes_range` would yield for the same range.
    ///
    /// Interior children (strictly inside the range at the current byte)
    /// contribute their cached `segment_count` via [`count_segment`]
    /// without recursion. Only the min- and max-boundary children recurse
    /// deeper.
    pub fn count_range<const PREFIX_LEN: usize, const INFIX_LEN: usize>(
        &self,
        prefix: &[u8; PREFIX_LEN],
        at_depth: usize,
        min_infix: &[u8; INFIX_LEN],
        max_infix: &[u8; INFIX_LEN],
    ) -> u64 {
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return 0;
        }

        // Case 1: infix ends within this node's compressed path. The full
        // infix is determined by this branch's path, so every leaf below
        // shares it — exactly one distinct infix value exists under self.
        if PREFIX_LEN + INFIX_LEN <= node_end_depth {
            let infix: [u8; INFIX_LEN] =
                core::array::from_fn(|i| self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]]);
            return if &infix >= min_infix && &infix <= max_infix {
                1
            } else {
                0
            };
        }

        // Case 2: prefix extends into a specific child.
        if PREFIX_LEN > node_end_depth {
            if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
                return child.count_range(prefix, node_end_depth, min_infix, max_infix);
            }
            return 0;
        }

        // Case 3: prefix ends here, infix spans children.
        // Check compressed path against range (same logic as infixes_range).
        let infix_byte_idx = node_end_depth - PREFIX_LEN;
        let mut min_tight = true;
        let mut max_tight = true;
        for i in 0..infix_byte_idx {
            let path_byte = self.childleaf_key()[O::TREE_TO_KEY[PREFIX_LEN + i]];
            if min_tight {
                if path_byte < min_infix[i] {
                    return 0;
                }
                if path_byte > min_infix[i] {
                    min_tight = false;
                }
            }
            if max_tight {
                if path_byte > max_infix[i] {
                    return 0;
                }
                if path_byte < max_infix[i] {
                    max_tight = false;
                }
            }
        }

        let mut total = 0u64;
        for entry in self.child_table.iter().flatten() {
            let child_byte = entry.key();
            let below_min = min_tight && child_byte < min_infix[infix_byte_idx];
            let above_max = max_tight && child_byte > max_infix[infix_byte_idx];
            if below_min || above_max {
                continue;
            }
            let on_min = min_tight && child_byte == min_infix[infix_byte_idx];
            let on_max = max_tight && child_byte == max_infix[infix_byte_idx];
            if on_min || on_max {
                total += entry.count_range(prefix, node_end_depth, min_infix, max_infix);
            } else {
                total += entry.count_segment(node_end_depth);
            }
        }
        total
    }

    pub fn has_prefix<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> bool {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return false;
        }

        if PREFIX_LEN <= node_end_depth {
            return true;
        }

        if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
            return child.has_prefix::<PREFIX_LEN>(node_end_depth, prefix);
        }

        false
    }

    pub(crate) fn traversal_depth<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> usize {
        const {
            assert!(PREFIX_LEN <= KEY_LEN);
        }
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return 1;
        }

        if PREFIX_LEN <= node_end_depth {
            return 1;
        }

        if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
            return 1 + child.traversal_depth::<PREFIX_LEN>(node_end_depth, prefix);
        }

        1
    }

    pub(super) fn get_key<'a>(&'a self, at_depth: usize, key: &[u8; KEY_LEN]) -> Option<&'a [u8; KEY_LEN]> {
        let end = self.end_depth as usize;
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(self.childleaf_key(), at_depth, &key[..end.min(KEY_LEN)]) {
            return None;
        }
        if end >= KEY_LEN { return Some(self.childleaf_key()); }
        self.child_table.table_get(key[end]).and_then(|child| child.get_key(end, key))
    }

    pub fn get<'a>(&'a self, at_depth: usize, key: &[u8; KEY_LEN]) -> Option<&'a V>
    where
        O: 'a,
    {
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(KEY_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &key[..limit],
        ) {
            return None;
        }
        if node_end_depth >= KEY_LEN {
            // Childleaf prefix matched and end_depth == KEY_LEN means the
            // representative IS the lookup target. For ZST `V` (the only
            // shape compatible with `LocalLeaf`-backed childleaves) we
            // synthesize a reference from a dangling pointer; otherwise
            // the childleaf points at a heap `Leaf<KEY_LEN, V, H>` whose
            // `key` field is at offset 0, so casting recovers the Leaf.
            if std::mem::size_of::<V>() == 0 {
                return Some(unsafe { std::ptr::NonNull::<V>::dangling().as_ref() });
            }
            let leaf_ptr = self.childleaf as *const Leaf<KEY_LEN, V, H>;
            return Some(unsafe { &(*leaf_ptr).value });
        }

        if let Some(child) = self.child_table.table_get(key[node_end_depth]) {
            return child.get(node_end_depth, key);
        }
        None
    }

    pub fn segmented_len<const PREFIX_LEN: usize>(
        &self,
        at_depth: usize,
        prefix: &[u8; PREFIX_LEN],
    ) -> u64 {
        let node_end_depth = self.end_depth as usize;
        let limit = std::cmp::min(PREFIX_LEN, node_end_depth);
        if !super::leaf::key_ops::has_prefix::<KEY_LEN, O>(
            self.childleaf_key(),
            at_depth,
            &prefix[..limit],
        ) {
            return 0;
        }
        if PREFIX_LEN <= node_end_depth {
            if !O::same_segment_tree(PREFIX_LEN, node_end_depth) {
                return 1;
            } else {
                return self.segment_count;
            }
        }
        if let Some(child) = self.child_table.table_get(prefix[node_end_depth]) {
            child.segmented_len::<PREFIX_LEN>(node_end_depth, prefix)
        } else {
            0
        }
    }

    // Instance methods implemented directly on &Branch — these contain any
    // required unsafe access (childleaf deref) locally and avoid forwarding
    // through more wrappers. This keeps the call graph minimal and makes the
    // logic easier to maintain.
}
