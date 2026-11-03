mod triblesetconstraint;
pub mod triblesetidrangeconstraint;
pub mod triblesetrangeconstraint;

use triblesetconstraint::*;

use crate::inline::Inline;
use crate::query::TriblePattern;

use crate::id::Id;
use crate::id::RawId;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Blake3;
use crate::inline::InlineEncoding;
use crate::patch::ArchiveEntry;
use crate::patch::ArchiveOwner;
use crate::patch::Entry;
use crate::patch::PATCHOwnerGuard;
use crate::patch::PATCH;
use crate::query::Variable;
use crate::trible::AEVOrder;
use crate::trible::AVEOrder;
use crate::trible::EAVOrder;
use crate::trible::EVAOrder;
use crate::trible::IntrinsicEntityRow;
use crate::trible::Trible;
use crate::trible::VAEOrder;
use crate::trible::VEAOrder;
use crate::trible::TRIBLE_LEN;

use std::iter::FromIterator;
use std::iter::Map;
use std::ops::Add;
use std::ops::AddAssign;
use std::sync::Arc;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;

/// Why a trible-set key always views as a [`Trible`]: every key was inserted
/// from a valid `Trible` (non-nil entity and attribute), and a PATCH key lives
/// in a 16-byte-aligned heap `Leaf` or in archive bytes whose rows an
/// `ArchiveEntry` requires to be 16-byte aligned.
const PATCH_KEY_IS_TRIBLE: &str =
    "trible-set keys are 16-byte-aligned rows inserted from valid tribles";

/// Canonicalizes and stores the facts of one content-derived entity.
///
/// Each input row has the shape `NIL || attribute || value`. Rows are sorted
/// and deduplicated, then their complete contiguous 64-byte representations
/// are hashed with BLAKE3. The final 16 digest bytes become the entity id and
/// are written into every row in place before ordinary shared PATCH leaves are
/// constructed from the canonical rows.
///
/// The leading NIL bytes deliberately participate in the hash. Consequently
/// this identity scheme is not compatible with the historical `A || V`
/// stream used by `entity!`.
///
/// The returned root is a reproducible plain [`Id`], never an exclusive write
/// capability. This function materializes exactly the canonical rows whose
/// bytes define that root and does not register it with an ID owner.
#[doc(hidden)]
pub fn build_intrinsic_entity(rows: Vec<IntrinsicEntityRow>) -> (Id, TribleSet) {
    build_intrinsic_entity_inner(rows, None)
}

/// Reproduce the first intrinsic-entity identity epoch over canonical
/// `(attribute, value)` pairs.
///
/// Before [`build_intrinsic_entity`] made complete NIL-prefixed rows the hash
/// domain, `entity!` sorted and deduplicated 48-byte `A || V` pairs, hashed
/// their concatenation with BLAKE3, and retained the final 16 digest bytes.
/// Historical durable identities must be verified under that exact rule
/// rather than reinterpreted under the current epoch.
///
/// New entities must use [`build_intrinsic_entity`]. This function exists only
/// for explicit legacy admission and migration boundaries.
#[doc(hidden)]
pub fn intrinsic_entity_id_v1(mut pairs: Vec<(Id, crate::inline::RawInline)>) -> Id {
    pairs.sort_unstable();
    pairs.dedup();

    let mut hasher = Blake3::new();
    for (attribute, value) in pairs {
        hasher.update(&attribute[..]);
        hasher.update(&value);
    }
    let digest = hasher.finalize();
    let mut raw_id: RawId = [0; crate::id::ID_LEN];
    raw_id.copy_from_slice(&digest[digest.len() - crate::id::ID_LEN..]);
    Id::new(raw_id).expect("BLAKE3-derived legacy entity ids must be non-nil")
}

/// Canonicalizes and stores a content-derived entity inside a caller-supplied
/// namespace. The namespace prefixes the same canonical row byte stream used
/// by [`build_intrinsic_entity`]. Because the namespace is configuration rather
/// than an emitted fact, the result is reproducible only within that namespace;
/// it is not self-certifying from the returned rows alone.
pub(crate) fn build_namespaced_intrinsic_entity(
    rows: Vec<IntrinsicEntityRow>,
    namespace: &[u8],
) -> (Id, TribleSet) {
    build_intrinsic_entity_inner(rows, Some(namespace))
}

fn build_intrinsic_entity_inner(
    mut rows: Vec<IntrinsicEntityRow>,
    namespace: Option<&[u8]>,
) -> (Id, TribleSet) {
    rows.sort_unstable();
    rows.dedup();

    let digest = match namespace {
        Some(namespace) => {
            let mut hasher = Blake3::new();
            hasher.update(namespace);
            hasher.update(rows.as_slice().as_bytes());
            hasher.finalize()
        }
        None => Blake3::digest(rows.as_slice().as_bytes()),
    };
    let mut raw_id: RawId = [0; crate::id::ID_LEN];
    raw_id.copy_from_slice(&digest[digest.len() - crate::id::ID_LEN..]);
    let id = Id::new(raw_id).expect("BLAKE3-derived entity ids must be non-nil");

    for row in &mut rows {
        row.fill_entity(id);
    }

    let mut set = TribleSet::new();
    for row in &rows {
        let trible = Trible::force_raw(*row.raw())
            .expect("intrinsic rows carry a BLAKE3-derived non-nil entity and a non-nil attribute");
        set.insert(&trible);
    }

    (id, set)
}

/// A collection of [`Trible`]s.
///
/// A [`TribleSet`] is a collection of [`Trible`]s that can be queried and manipulated.
/// It supports efficient set operations like union, intersection, and difference.
///
/// The stored [`Trible`]s are indexed by the six possible orderings of their fields
/// in corresponding [`PATCH`]es.
///
/// Clone is extremely cheap and can be used to create a snapshot of the current state of the [`TribleSet`].
///
/// Note that the [`TribleSet`] does not support an explicit `delete`/`remove` operation,
/// as this would conflict with the CRDT semantics of the [`TribleSet`] and CALM principles as a whole.
/// It does allow for set subtraction, but that operation is meant to compute the difference between two sets
/// and not to remove elements from the set. A subtle but important distinction.
#[derive(Debug, Clone)]
pub struct TribleSet {
    /// Entity → Attribute → Inline index.
    pub eav: PATCH<TRIBLE_LEN, EAVOrder, ()>,
    /// Inline → Entity → Attribute index.
    pub vea: PATCH<TRIBLE_LEN, VEAOrder, ()>,
    /// Attribute → Inline → Entity index.
    pub ave: PATCH<TRIBLE_LEN, AVEOrder, ()>,
    /// Inline → Attribute → Entity index.
    pub vae: PATCH<TRIBLE_LEN, VAEOrder, ()>,
    /// Entity → Inline → Attribute index.
    pub eva: PATCH<TRIBLE_LEN, EVAOrder, ()>,
    /// Attribute → Entity → Inline index.
    pub aev: PATCH<TRIBLE_LEN, AEVOrder, ()>,
}

/// O(1) opaque cache token for a [`TribleSet`].
///
/// Equal sets have equal fingerprints within one process. The token is a
/// distinct-key, nonlinear blinding of PATCH's internal root aggregate, so it
/// neither exposes the aggregate's XOR structure nor remains stable across
/// process boundaries. As with any 128-bit fingerprint, a match is a cache
/// hint rather than proof of set equality.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TribleSetFingerprint(Option<u128>);

impl TribleSetFingerprint {
    /// Fingerprint of an empty set.
    pub const EMPTY: Self = Self(None);

    /// Returns `true` for the empty-set fingerprint.
    pub fn is_empty(self) -> bool {
        self.0.is_none()
    }

    /// Returns the opaque 128-bit process-local token, or `None` for an empty
    /// set.
    ///
    /// The returned value is already nonlinearly blinded; PATCH's internal
    /// XOR aggregate is never exposed through this API.
    pub fn as_u128(self) -> Option<u128> {
        self.0
    }
}

type TribleSetInner<'a> =
    Map<crate::patch::PATCHIterator<'a, 64, EAVOrder, ()>, fn(&[u8; 64]) -> &Trible>;

/// Iterator over the tribles in a [`TribleSet`], yielded in EAV order.
pub struct TribleSetIterator<'a> {
    inner: TribleSetInner<'a>,
}

/// Minimum `other.len()` at which [`TribleSet::union`] fans out across
/// rayon. Below this, the nested-join overhead dominates the saved
/// per-index work. Tuned for the `entities/union*/5M` bench family.
#[cfg(feature = "parallel")]
pub const PARALLEL_UNION_THRESHOLD: usize = 4096;

impl TribleSet {
    /// Whether all six public indexes share one owner-cover Arc.
    fn owner_guards_are_shared(&self) -> bool {
        self.eav.shares_owner_guard(&self.eva)
            && self.eav.shares_owner_guard(&self.aev)
            && self.eav.shares_owner_guard(&self.ave)
            && self.eav.shares_owner_guard(&self.vea)
            && self.eav.shares_owner_guard(&self.vae)
    }

    /// The common-case archive-adoption check. Older owners remain exactly
    /// deduplicated inside the Patricia cover; only the latest member is O(1).
    fn shared_owner_guard_latest_is(&self, owner: &Arc<dyn ArchiveOwner>) -> bool {
        self.owner_guards_are_shared() && self.eav.owner_guard_latest_is(owner)
    }

    /// Deduplicate retained provenance from all six publicly mutable indexes.
    fn combined_owner_guard(&self) -> PATCHOwnerGuard {
        let guard = self.eav.owner_guard();
        if self.owner_guards_are_shared() {
            return guard;
        }
        guard
            .join(self.eva.owner_guard())
            .join(self.aev.owner_guard())
            .join(self.ave.owner_guard())
            .join(self.vea.owner_guard())
            .join(self.vae.owner_guard())
    }

    fn set_owner_guard(&mut self, guard: &PATCHOwnerGuard) {
        // SAFETY: callers construct `guard` by joining every existing index
        // receipt before optionally retaining more owners.
        unsafe {
            self.eav.set_owner_guard(guard);
            self.eva.set_owner_guard(guard);
            self.aev.set_owner_guard(guard);
            self.ave.set_owner_guard(guard);
            self.vea.set_owner_guard(guard);
            self.vae.set_owner_guard(guard);
        }
    }

    /// Union of two [`TribleSet`]s.
    ///
    /// The other [`TribleSet`] is consumed, and this [`TribleSet`] is updated
    /// in place.
    ///
    /// With the `parallel` feature enabled and `other` above
    /// `PARALLEL_UNION_THRESHOLD` tribles, the six index unions
    /// (`eav`/`eva`/`aev`/`ave`/`vea`/`vae`) fan out via nested
    /// [`rayon::join`] — they touch disjoint memory so there's no
    /// contention. The threshold gates on `other.len()` because PATCH
    /// union work is bounded by the smaller side (each key from `other`
    /// is inserted into `self`); when `other` is tiny (e.g. the per-
    /// `entity!{}` `+=` in a serial fold) the rayon overhead would
    /// dominate even at large `self`.
    pub fn union(&mut self, mut other: Self) {
        // Join all twelve receipts once. Per-index PATCH unions then hit the
        // shared Arc identity path instead of rebuilding the same Patricia
        // union six times.
        let owners = self
            .combined_owner_guard()
            .join(other.combined_owner_guard());
        self.set_owner_guard(&owners);
        other.set_owner_guard(&owners);

        #[cfg(feature = "parallel")]
        {
            if other.len() >= PARALLEL_UNION_THRESHOLD {
                let Self {
                    eav,
                    eva,
                    aev,
                    ave,
                    vea,
                    vae,
                } = self;
                let Self {
                    eav: oeav,
                    eva: oeva,
                    aev: oaev,
                    ave: oave,
                    vea: ovea,
                    vae: ovae,
                } = other;
                // Nested join trees the six tasks across rayon workers
                // with much lower per-call overhead than `scope`.
                rayon::join(
                    || rayon::join(|| eav.union(oeav), || eva.union(oeva)),
                    || {
                        rayon::join(
                            || rayon::join(|| aev.union(oaev), || ave.union(oave)),
                            || rayon::join(|| vea.union(ovea), || vae.union(ovae)),
                        )
                    },
                );
                return;
            }
        }

        self.eav.union(other.eav);
        self.eva.union(other.eva);
        self.aev.union(other.aev);
        self.ave.union(other.ave);
        self.vea.union(other.vea);
        self.vae.union(other.vae);
    }

    /// Returns a new set containing only tribles present in both sets.
    ///
    /// With the `parallel` feature enabled and either side above
    /// `PARALLEL_UNION_THRESHOLD` tribles, the six index intersects
    /// fan out via nested [`rayon::join`] on the same disjoint-memory
    /// property as `union`. Threshold gates on `min(self, other)`
    /// because intersect work is bounded by the smaller side.
    pub fn intersect(&self, other: &Self) -> Self {
        // Join all twelve receipts once. This is a conservative superset for
        // every result index because intersection may reuse a LocalLeaf from
        // either source trie.
        let owners = self
            .combined_owner_guard()
            .join(other.combined_owner_guard());
        macro_rules! intersect_index {
            ($left:expr, $right:expr) => {{
                // SAFETY: `owners` joins every receipt in both aggregates.
                unsafe { $left.intersect_with_guard($right, &owners) }
            }};
        }
        #[cfg(feature = "parallel")]
        {
            if self.len().min(other.len()) >= PARALLEL_UNION_THRESHOLD {
                let ((eav, eva), ((aev, ave), (vea, vae))) = rayon::join(
                    || {
                        rayon::join(
                            || intersect_index!(&self.eav, &other.eav),
                            || intersect_index!(&self.eva, &other.eva),
                        )
                    },
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || intersect_index!(&self.aev, &other.aev),
                                    || intersect_index!(&self.ave, &other.ave),
                                )
                            },
                            || {
                                rayon::join(
                                    || intersect_index!(&self.vea, &other.vea),
                                    || intersect_index!(&self.vae, &other.vae),
                                )
                            },
                        )
                    },
                );
                return Self {
                    eav,
                    eva,
                    aev,
                    ave,
                    vea,
                    vae,
                };
            }
        }
        Self {
            eav: intersect_index!(&self.eav, &other.eav),
            eva: intersect_index!(&self.eva, &other.eva),
            aev: intersect_index!(&self.aev, &other.aev),
            ave: intersect_index!(&self.ave, &other.ave),
            vea: intersect_index!(&self.vea, &other.vea),
            vae: intersect_index!(&self.vae, &other.vae),
        }
    }

    /// Returns a new set containing tribles in `self` but not in `other`.
    ///
    /// With the `parallel` feature enabled and `self` above
    /// `PARALLEL_UNION_THRESHOLD` tribles, the six index differences
    /// fan out via nested [`rayon::join`]. Threshold gates on
    /// `self.len()` because difference work is bounded by the left
    /// side (each key from `self` is either kept or filtered).
    pub fn difference(&self, other: &Self) -> Self {
        // Difference can only reuse LocalLeaves from the left aggregate, so
        // combine its six receipts once and share that cover across results.
        let owners = self.combined_owner_guard();
        macro_rules! difference_index {
            ($left:expr, $right:expr) => {{
                // SAFETY: `owners` joins every left-aggregate receipt.
                unsafe { $left.difference_with_guard($right, &owners) }
            }};
        }
        #[cfg(feature = "parallel")]
        {
            if self.len() >= PARALLEL_UNION_THRESHOLD {
                let ((eav, eva), ((aev, ave), (vea, vae))) = rayon::join(
                    || {
                        rayon::join(
                            || difference_index!(&self.eav, &other.eav),
                            || difference_index!(&self.eva, &other.eva),
                        )
                    },
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || difference_index!(&self.aev, &other.aev),
                                    || difference_index!(&self.ave, &other.ave),
                                )
                            },
                            || {
                                rayon::join(
                                    || difference_index!(&self.vea, &other.vea),
                                    || difference_index!(&self.vae, &other.vae),
                                )
                            },
                        )
                    },
                );
                return Self {
                    eav,
                    eva,
                    aev,
                    ave,
                    vea,
                    vae,
                };
            }
        }
        Self {
            eav: difference_index!(&self.eav, &other.eav),
            eva: difference_index!(&self.eva, &other.eva),
            aev: difference_index!(&self.aev, &other.aev),
            ave: difference_index!(&self.ave, &other.ave),
            vea: difference_index!(&self.vea, &other.vea),
            vae: difference_index!(&self.vae, &other.vae),
        }
    }

    /// Creates an empty set.
    pub fn new() -> TribleSet {
        TribleSet {
            eav: PATCH::<TRIBLE_LEN, EAVOrder, ()>::new(),
            eva: PATCH::<TRIBLE_LEN, EVAOrder, ()>::new(),
            aev: PATCH::<TRIBLE_LEN, AEVOrder, ()>::new(),
            ave: PATCH::<TRIBLE_LEN, AVEOrder, ()>::new(),
            vea: PATCH::<TRIBLE_LEN, VEAOrder, ()>::new(),
            vae: PATCH::<TRIBLE_LEN, VAEOrder, ()>::new(),
        }
    }

    /// Returns the number of tribles in the set.
    pub fn len(&self) -> usize {
        self.eav.len() as usize
    }

    /// Returns `true` when the set contains no tribles.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a fast fingerprint suitable for in-memory caching.
    ///
    /// Equal sets have equal fingerprints within this process. The value is an
    /// opaque, nonlinear keyed blinding of PATCH's internal aggregate and is
    /// neither a durable identity nor proof that two sets are equal.
    pub fn fingerprint(&self) -> TribleSetFingerprint {
        TribleSetFingerprint(crate::patch::blind_root_hash(self.eav.root_hash()))
    }

    /// Inserts a trible into all six covering indexes.
    pub fn insert(&mut self, trible: &Trible) {
        let key = Entry::new(trible.as_raw());
        self.eav.insert(&key);
        self.eva.insert(&key);
        self.aev.insert(&key);
        self.ave.insert(&key);
        self.vea.insert(&key);
        self.vae.insert(&key);
    }

    /// Builds all six indexes over one validated archive slice.
    ///
    /// A single `u32` row permutation is reset to archive order and
    /// partitioned in place for each schema. Resetting preserves source-row
    /// locality for each build, while `hashes` is shared across all six so no
    /// per-index leaf descriptors or hash arrays survive construction.
    ///
    /// # Safety
    ///
    /// Every row must be immutable, duplicate-free, and kept alive by
    /// `owner`. `hashes[row]` must be the PATCH key hash of `rows[row]`.
    /// (Alignment and the row rule are guaranteed by `&[Trible]`.)
    #[cfg(any(test, feature = "parallel"))]
    pub(crate) unsafe fn from_archive_partition(
        rows: &[Trible],
        hashes: &[u128],
        owner: &std::sync::Arc<dyn ArchiveOwner>,
    ) -> Self {
        assert_eq!(rows.len(), hashes.len());
        assert!(
            u32::try_from(rows.len()).is_ok(),
            "archive row ordinals must fit the partition metadata",
        );
        if rows.is_empty() {
            return Self::new();
        }
        if rows.len() == 1 {
            // Preserve the established heap singleton path: all six indexes
            // share one Leaf allocation and need no archive-owner receipt.
            let mut set = Self::new();
            set.insert(&rows[0]);
            return set;
        }
        let keys: &[[u8; TRIBLE_LEN]] = zerocopy::transmute_ref!(rows);

        let mut permutation = vec![0u32; rows.len()];
        let mut owner_guard = PATCHOwnerGuard::default();
        owner_guard.retain_archive_owner(owner);
        fn reset(permutation: &mut [u32]) {
            for (row, slot) in permutation.iter_mut().enumerate() {
                *slot = row as u32;
            }
        }

        macro_rules! build_index {
            ($order:ty) => {{
                reset(&mut permutation);
                unsafe {
                    PATCH::<TRIBLE_LEN, $order>::from_archive_partition_with_guard(
                        keys,
                        hashes,
                        &mut permutation,
                        owner,
                        &owner_guard,
                    )
                }
            }};
        }

        let eav = build_index!(EAVOrder);
        let aev = build_index!(AEVOrder);
        let vae = build_index!(VAEOrder);
        let eva = build_index!(EVAOrder);
        let vea = build_index!(VEAOrder);
        let ave = build_index!(AVEOrder);

        Self {
            eav,
            eva,
            aev,
            ave,
            vea,
            vae,
        }
    }

    /// Inserts an archive-backed trible into all six covering indexes
    /// using [`PATCH::insert_archive`], so each index may land the new
    /// entry as a `LocalLeaf` instead of a freshly allocated heap
    /// `Leaf`. Each PATCH's root owner set keeps the underlying archive
    /// bytes alive independently of trie shape.
    pub fn insert_archive(&mut self, entry: &ArchiveEntry<'_, TRIBLE_LEN>) {
        if !self.shared_owner_guard_latest_is(entry.owner()) {
            let mut owners = self.combined_owner_guard();
            owners.retain_archive_owner(entry.owner());
            self.set_owner_guard(&owners);
        }
        self.eav.insert_archive(entry);
        self.eva.insert_archive(entry);
        self.aev.insert_archive(entry);
        self.ave.insert_archive(entry);
        self.vea.insert_archive(entry);
        self.vae.insert_archive(entry);
    }

    /// Returns `true` when the exact trible is present in the set.
    pub fn contains(&self, trible: &Trible) -> bool {
        self.eav.has_prefix(trible.as_raw())
    }

    /// Creates a constraint over the intersection of the set's V-axis domain
    /// and the inclusive byte range `[min, max]`, using the VEA index with
    /// `infixes_range`.
    ///
    /// Use with `and!` alongside a `pattern!` for efficient range queries:
    ///
    /// ```rust,ignore
    /// find!(ts: Inline<NsTAIInterval>,
    ///     and!(
    ///         pattern!(&data, [{ ?id @ attr: ?ts }]),
    ///         data.value_in_range(ts, min_ts, max_ts),
    ///     )
    /// )
    /// ```
    pub fn value_in_range<V: InlineEncoding>(
        &self,
        variable: Variable<V>,
        min: Inline<V>,
        max: Inline<V>,
    ) -> triblesetrangeconstraint::TribleSetRangeConstraint {
        triblesetrangeconstraint::TribleSetRangeConstraint::new(variable, min, max, self.clone())
    }

    /// Creates a constraint over the intersection of the set's E-axis domain
    /// and the inclusive byte range `[min, max]`, using the EAV index with
    /// `infixes_range`.
    ///
    /// ```rust,ignore
    /// find!(id: Id,
    ///     and!(
    ///         pattern!(&data, [{ ?id @ attr: value }]),
    ///         data.entity_in_range(id, min_id, max_id),
    ///     )
    /// )
    /// ```
    pub fn entity_in_range(
        &self,
        variable: Variable<GenId>,
        min: Id,
        max: Id,
    ) -> triblesetidrangeconstraint::EntityRangeConstraint {
        triblesetidrangeconstraint::EntityRangeConstraint::new(variable, min, max, self.clone())
    }

    /// Creates a constraint over the intersection of the set's A-axis domain
    /// and the inclusive byte range `[min, max]`, using the AEV index with
    /// `infixes_range`.
    ///
    /// ```rust,ignore
    /// find!(attr: Id,
    ///     and!(
    ///         pattern!(&data, [{ entity @ ?attr: _ }]),
    ///         data.attribute_in_range(attr, min_attr, max_attr),
    ///     )
    /// )
    /// ```
    pub fn attribute_in_range(
        &self,
        variable: Variable<GenId>,
        min: Id,
        max: Id,
    ) -> triblesetidrangeconstraint::AttributeRangeConstraint {
        triblesetidrangeconstraint::AttributeRangeConstraint::new(variable, min, max, self.clone())
    }

    /// Iterates over all tribles in the index's native traversal order.
    ///
    /// Use [`Self::iter_ordered`] when physical representation must not affect
    /// the sequence.
    pub fn iter(&self) -> TribleSetIterator<'_> {
        TribleSetIterator {
            inner: self
                .eav
                .iter()
                .map(|data| Trible::try_ref_from_bytes(data).expect(PATCH_KEY_IS_TRIBLE)),
        }
    }

    /// Iterates over all tribles in canonical byte-lexicographic EAV order.
    pub fn iter_ordered(&self) -> impl Iterator<Item = &Trible> {
        self.eav
            .iter_ordered()
            .map(|data| Trible::try_ref_from_bytes(data).expect(PATCH_KEY_IS_TRIBLE))
    }
}

impl PartialEq for TribleSet {
    fn eq(&self, other: &Self) -> bool {
        self.eav == other.eav
    }
}

impl Eq for TribleSet {}

impl Default for TribleSetFingerprint {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl From<&TribleSet> for TribleSetFingerprint {
    fn from(set: &TribleSet) -> Self {
        set.fingerprint()
    }
}

impl AddAssign for TribleSet {
    fn add_assign(&mut self, rhs: Self) {
        self.union(rhs);
    }
}

impl Add for TribleSet {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.union(rhs);
        self
    }
}

impl FromIterator<Trible> for TribleSet {
    fn from_iter<I: IntoIterator<Item = Trible>>(iter: I) -> Self {
        let mut set = TribleSet::new();

        for t in iter {
            set.insert(&t);
        }

        set
    }
}

impl TriblePattern for TribleSet {
    type PatternConstraint<'a> = TribleSetConstraint;

    fn pattern<V: InlineEncoding>(
        &self,
        e: impl Into<crate::query::Term<GenId>>,
        a: impl Into<crate::query::Term<GenId>>,
        v: impl Into<crate::query::Term<V>>,
    ) -> Self::PatternConstraint<'static> {
        TribleSetConstraint::new(e, a, v, self.clone())
    }
}

impl<'a> Iterator for TribleSetIterator<'a> {
    type Item = &'a Trible;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<'a> IntoIterator for &'a TribleSet {
    type Item = &'a Trible;
    type IntoIter = TribleSetIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Default for TribleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::examples::literature;
    use crate::prelude::*;

    use super::*;
    use fake::faker::lorem::en::Words;
    use fake::faker::name::raw::FirstName;
    use fake::faker::name::raw::LastName;
    use fake::locales::EN;
    use fake::Fake;

    use rayon::iter::IntoParallelIterator;
    use rayon::iter::ParallelIterator;

    #[repr(C, align(16))]
    struct AlignedRows([[u8; TRIBLE_LEN]; 2]);

    fn archive_set(first: u8, second: u8) -> TribleSet {
        let storage = Arc::new([
            Trible::force_raw([first; TRIBLE_LEN]).unwrap(),
            Trible::force_raw([second; TRIBLE_LEN]).unwrap(),
        ]);
        let owner: Arc<dyn ArchiveOwner> = storage.clone();
        let hashes = [
            crate::patch::hash_key(storage[0].as_raw()),
            crate::patch::hash_key(storage[1].as_raw()),
        ];
        // SAFETY: the keys are distinct, immutable, and retained by `owner`
        // during build.
        unsafe { TribleSet::from_archive_partition(&storage[..], &hashes, &owner) }
    }

    #[test]
    fn intrinsic_entity_v1_reproduces_the_historical_av_stream() {
        let attribute = Id::new([0x11; 16]).unwrap();
        let low = [0x22; 32];
        let high = [0x33; 32];
        let expected = Id::new(hex_literal::hex!("ECBA4194366B3AD966A7912E5B641750")).unwrap();

        assert_eq!(
            intrinsic_entity_id_v1(vec![(attribute, high), (attribute, low), (attribute, high),]),
            expected,
        );
    }

    fn assert_shared_owner_guard(set: &TribleSet, owner_count: usize) {
        assert!(set.owner_guards_are_shared());
        let guard = set.eav.owner_guard();
        assert_eq!(guard.owner_count(), owner_count);
        for index_guard in [
            set.eva.owner_guard(),
            set.aev.owner_guard(),
            set.ave.owner_guard(),
            set.vea.owner_guard(),
            set.vae.owner_guard(),
        ] {
            assert!(guard.ptr_eq(&index_guard));
        }
    }

    fn insert_archive_row_into_eav_only(set: &mut TribleSet, byte: u8) {
        let storage = Arc::new(AlignedRows([
            [byte; TRIBLE_LEN],
            [byte.wrapping_add(1); TRIBLE_LEN],
        ]));
        let owner: Arc<dyn ArchiveOwner> = storage.clone();
        // SAFETY: AlignedRows makes this immutable row 16-byte aligned, and
        // `owner` retains its allocation while EAV adopts the LocalLeaf.
        let entry = unsafe { ArchiveEntry::new(std::ptr::NonNull::from(&storage.0[0]), &owner) };
        set.eav.insert_archive(&entry);
    }

    #[test]
    fn public_fingerprint_blinds_the_internal_root_aggregate() {
        let set = archive_set(0x11, 0x22);
        let root_hash = set.eav.root_hash();

        assert_eq!(
            set.fingerprint().as_u128(),
            crate::patch::blind_root_hash(root_hash)
        );

        let cloned = set.clone();
        assert_eq!(set.fingerprint(), cloned.fingerprint());
        assert_eq!(TribleSet::new().fingerprint(), TribleSetFingerprint::EMPTY);
    }

    #[test]
    fn archive_set_algebra_shares_one_owner_cover_across_all_indexes() {
        let mut unioned = archive_set(0x11, 0x22);
        let union_right = archive_set(0x33, 0x44);
        assert_shared_owner_guard(&unioned, 1);
        assert_shared_owner_guard(&union_right, 1);

        unioned.union(union_right);
        assert_eq!(unioned.len(), 4);
        assert_shared_owner_guard(&unioned, 2);

        let left = archive_set(0x11, 0x22);
        let right = archive_set(0x11, 0x33);
        let intersection = left.intersect(&right);
        assert_eq!(intersection.len(), 1);
        assert_shared_owner_guard(&intersection, 2);

        let difference = left.difference(&right);
        assert_eq!(difference.len(), 1);
        assert_shared_owner_guard(&difference, 1);

        // Public indexes can be mutated independently. Difference must first
        // reconcile all six left receipts, not merely preserve six divergent
        // per-index covers.
        let mut divergent = archive_set(0x11, 0x22);
        insert_archive_row_into_eav_only(&mut divergent, 0x55);
        assert!(!divergent.owner_guards_are_shared());
        let reconciled = divergent.difference(&TribleSet::new());
        assert_shared_owner_guard(&reconciled, 2);
    }

    #[test]
    fn union() {
        let mut kb = TribleSet::new();
        for _i in 0..100 {
            let author = ufoid();
            let book = ufoid();
            kb += entity! { &author @
               literature::firstname: FirstName(EN).fake::<String>(),
               literature::lastname: LastName(EN).fake::<String>(),
            };
            kb += entity! { &book @
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::author: &author
            };
        }
        assert_eq!(kb.len(), 400);
    }

    #[test]
    fn union_parallel() {
        let kb = (0..1000)
            .into_par_iter()
            .flat_map(|_| {
                let author = ufoid();
                let book = ufoid();
                [
                    entity! { &author @
                       literature::firstname: FirstName(EN).fake::<String>(),
                       literature::lastname: LastName(EN).fake::<String>(),
                    },
                    entity! { &book @
                       literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
                       literature::author: &author
                    },
                ]
            })
            .reduce(Fragment::default, |a, b| a + b);
        assert_eq!(kb.len(), 4000);
    }

    #[test]
    fn intersection() {
        let mut kb1 = TribleSet::new();
        let mut kb2 = TribleSet::new();
        for _i in 0..100 {
            let author = ufoid();
            let book = ufoid();
            kb1 += entity! { &author @
               literature::firstname: FirstName(EN).fake::<String>(),
               literature::lastname: LastName(EN).fake::<String>(),
            };
            kb1 += entity! { &book @
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::author: &author
            };
            kb2 += entity! { &author @
               literature::firstname: FirstName(EN).fake::<String>(),
               literature::lastname: LastName(EN).fake::<String>(),
            };
            kb2 += entity! { &book @
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::author: &author
            };
        }
        let intersection = kb1.intersect(&kb2);
        // Verify that the intersection contains only elements present in both kb1 and kb2
        for trible in &intersection {
            assert!(kb1.contains(trible));
            assert!(kb2.contains(trible));
        }
    }

    #[test]
    fn difference() {
        let mut kb1 = TribleSet::new();
        let mut kb2 = TribleSet::new();
        for _i in 0..100 {
            let author = ufoid();
            let book = ufoid();
            kb1 += entity! { &author @
               literature::firstname: FirstName(EN).fake::<String>(),
               literature::lastname: LastName(EN).fake::<String>(),
            };
            kb1 += entity! { &book @
               literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
               literature::author: &author
            };
            if _i % 2 == 0 {
                kb2 += entity! { &author @
                   literature::firstname: FirstName(EN).fake::<String>(),
                   literature::lastname: LastName(EN).fake::<String>(),
                };
                kb2 += entity! { &book @
                   literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
                   literature::author: &author
                };
            }
        }
        let difference = kb1.difference(&kb2);
        // Verify that the difference contains only elements present in kb1 but not in kb2
        for trible in &difference {
            assert!(kb1.contains(trible));
            assert!(!kb2.contains(trible));
        }
    }

    #[test]
    fn test_contains() {
        let mut kb = TribleSet::new();
        let author = ufoid();
        let book = ufoid();
        let author_tribles = entity! { &author @
           literature::firstname: FirstName(EN).fake::<String>(),
           literature::lastname: LastName(EN).fake::<String>(),
        };
        let book_tribles = entity! { &book @
           literature::title: Words(1..3).fake::<Vec<String>>().join(" "),
           literature::author: &author
        };

        kb += author_tribles.clone();
        kb += book_tribles.clone();

        for trible in &author_tribles {
            assert!(kb.contains(trible));
        }
        for trible in &book_tribles {
            assert!(kb.contains(trible));
        }

        let non_existent_trible = entity! { &ufoid() @
           literature::firstname: FirstName(EN).fake::<String>(),
           literature::lastname: LastName(EN).fake::<String>(),
        };

        for trible in &non_existent_trible {
            assert!(!kb.contains(trible));
        }
    }
}
