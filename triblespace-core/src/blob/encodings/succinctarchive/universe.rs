use crate::inline::RawInline;

use std::convert::Infallible;

use anybytes::area::{SectionHandle, SectionWriter};
use anybytes::Bytes;
use anybytes::View;
use indxvec::Search;
use jerky::serialization::Serializable;
use quick_cache::sync::Cache;

/// Maps between raw 32-byte values and compact integer codes used by the
/// [`SuccinctArchive`](super::SuccinctArchive) wavelet matrices.
pub trait Universe: Serializable {
    /// Interprets the portable ordered domain. Alternative universes may
    /// explicitly transform this domain; [`OrderedUniverse`] borrows it.
    fn from_ordered_values(values: View<[RawInline]>) -> Self {
        let mut area = anybytes::area::ByteArea::new().expect("universe byte area");
        let mut sections = area.sections();
        Self::with_sorted_dedup(values.iter().copied(), &mut sections)
    }

    /// Builds a universe from a sorted, deduplicated iterator of raw values.
    fn with_sorted_dedup<I>(values: I, sections: &mut SectionWriter<'_>) -> Self
    where
        I: Iterator<Item = RawInline>;

    /// Builds a universe from an arbitrary iterator, sorting and deduplicating internally.
    fn with<I>(iter: I, sections: &mut SectionWriter<'_>) -> Self
    where
        I: Iterator<Item = RawInline>,
    {
        let mut values: Vec<_> = iter.collect();
        values.sort_unstable();
        values.dedup();
        Self::with_sorted_dedup(values.into_iter(), sections)
    }

    /// Returns the raw value at integer code `pos`.
    ///
    /// Implementations promise that `access` is *monotonic in `pos`*:
    /// if `i < j` and both are valid codes, then `access(i) <= access(j)`
    /// in byte-lexicographic order. This is what makes [`Self::search`]
    /// and [`Self::search_range`] log-time over the universe size.
    fn access(&self, pos: usize) -> RawInline;
    /// Returns the integer code for `v`, or `None` if absent.
    fn search(&self, v: &RawInline) -> Option<usize>;
    /// Returns the number of distinct values in the universe.
    fn len(&self) -> usize;
    /// Returns `true` if the universe contains no values.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns the smallest code `c` such that `access(c) >= v`, or
    /// `len()` if every value is `< v`. Equivalent to a `lower_bound` /
    /// `partition_point(|x| x < v)` on the value-ordered code domain.
    ///
    /// The default implementation does one binary search via
    /// [`Self::access`] — O(log n) on the universe size, given the
    /// monotonicity promise on [`Self::access`]. Implementations with a
    /// flat sorted slice should override to skip the virtual-call
    /// overhead.
    fn search_lower(&self, v: &RawInline) -> usize {
        let mut lo = 0usize;
        let mut hi = self.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.access(mid) < *v {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Returns the smallest code `c` such that `access(c) > v`, or
    /// `len()` if every value is `<= v`. Equivalent to an `upper_bound` /
    /// `partition_point(|x| x <= v)` on the value-ordered code domain.
    ///
    /// The default implementation does one binary search via
    /// [`Self::access`] — O(log n) on the universe size, given the
    /// monotonicity promise on [`Self::access`]. Implementations with a
    /// flat sorted slice should override to skip the virtual-call
    /// overhead.
    fn search_upper(&self, v: &RawInline) -> usize {
        let mut lo = 0usize;
        let mut hi = self.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.access(mid) <= *v {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Returns the half-open code range `[lo, hi)` such that for every
    /// `lo <= code < hi`, `access(code)` is in the inclusive value range
    /// `[min, max]`. An empty range (`lo == hi`) means no values match.
    ///
    /// Composes [`Self::search_lower`] and [`Self::search_upper`];
    /// override only if a fused implementation can beat two independent
    /// binary searches.
    fn search_range(&self, min: &RawInline, max: &RawInline) -> std::ops::Range<usize> {
        if min > max {
            return 0..0;
        }
        self.search_lower(min)..self.search_upper(max)
    }
}

/// Universe backed by a flat sorted array of raw values.
///
/// Access and search are O(1) and O(log n) respectively. Simple to
/// construct but uses 32 bytes per distinct value.
#[derive(Debug, Clone)]
pub struct OrderedUniverse {
    values: View<[RawInline]>,
    handle: Option<SectionHandle<RawInline>>,
}

impl Universe for OrderedUniverse {
    fn from_ordered_values(values: View<[RawInline]>) -> Self {
        Self {
            values,
            handle: None,
        }
    }

    fn with_sorted_dedup<I>(iter: I, sections: &mut SectionWriter<'_>) -> Self
    where
        I: Iterator<Item = RawInline>,
    {
        let collected: Vec<_> = iter.collect();
        OrderedUniverse::from_slice(&collected, sections)
    }

    fn access(&self, pos: usize) -> RawInline {
        self.values[pos]
    }

    fn search(&self, v: &RawInline) -> Option<usize> {
        self.values.binary_search(v).ok()
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    /// O(log n) `partition_point` on the byte-sorted values slice;
    /// avoids the virtual-call overhead of the default `access`-driven
    /// binary search.
    fn search_lower(&self, v: &RawInline) -> usize {
        self.values.partition_point(|x| x < v)
    }

    /// O(log n) `partition_point` on the byte-sorted values slice;
    /// avoids the virtual-call overhead of the default `access`-driven
    /// binary search.
    fn search_upper(&self, v: &RawInline) -> usize {
        self.values.partition_point(|x| x <= v)
    }
}

impl OrderedUniverse {
    /// Borrows the stored ordered values without copying their byte backing.
    pub fn values(&self) -> &[RawInline] {
        self.values.as_ref()
    }

    fn from_slice(values: &[RawInline], sections: &mut SectionWriter<'_>) -> Self {
        let mut section = sections.reserve::<RawInline>(values.len()).unwrap();
        section.as_mut_slice().copy_from_slice(values);
        Self::from_section(section)
    }

    fn from_section(section: anybytes::area::Section<'_, RawInline>) -> Self {
        let handle = section.handle();
        let bytes = section.freeze().unwrap();
        let values = bytes.view::<[RawInline]>().expect("view");
        Self {
            values,
            handle: Some(handle),
        }
    }

    /// Returns the number of values in this universe.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if this universe contains no values.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Serializable for OrderedUniverse {
    type Meta = SectionHandle<RawInline>;
    type Error = jerky::error::Error;

    fn metadata(&self) -> Self::Meta {
        self.handle
            .expect("ordered universe has no serialized section handle")
    }

    fn from_bytes(meta: Self::Meta, bytes: Bytes) -> Result<Self, Self::Error> {
        let values = meta.view(&bytes).map_err(Self::Error::from)?;
        Ok(Self {
            values,
            handle: Some(meta),
        })
    }
}

/// Universe that stores every 32-byte value as two 16-byte halves and elides
/// the zero first half shared by intrinsic entity identifiers.
///
/// Values are byte-sorted, so all values beginning with sixteen zero bytes
/// form one contiguous prefix. The representation stores every second half,
/// only the nonzero first halves, and the length of that prefix. Its payload is
/// exactly `32N - 16Z` bytes for `N` values and `Z` zero-first-half values: it
/// is never larger than [`OrderedUniverse`] and retains direct access plus
/// binary search without a dictionary or variable-length decoding.
#[derive(Debug, Clone)]
pub struct CompressedUniverse {
    zero_prefix_len: usize,
    suffixes: View<[[u8; 16]]>,
    suffixes_handle: SectionHandle<[u8; 16]>,
    nonzero_prefixes: View<[[u8; 16]]>,
    nonzero_prefixes_handle: SectionHandle<[u8; 16]>,
}

impl CompressedUniverse {
    fn validate_layout(
        meta: &CompressedUniverseMeta,
        bytes: &Bytes,
        limit: usize,
    ) -> Result<(), jerky::error::Error> {
        if limit > bytes.len() {
            return Err(super::invalid_rank9_metadata(format!(
                "compressed-universe prefix limit {limit} exceeds {} bytes",
                bytes.len()
            )));
        }
        super::checked_section_range(meta.suffixes, limit, "compressed-universe suffixes")?;
        super::checked_section_range(
            meta.nonzero_prefixes,
            limit,
            "compressed-universe nonzero prefixes",
        )?;

        let suffix_count = meta.suffixes.len / std::mem::size_of::<[u8; 16]>();
        if meta.zero_prefix_len > suffix_count {
            return Err(super::invalid_rank9_metadata(format!(
                "compressed-universe zero-prefix boundary {} exceeds {suffix_count} values",
                meta.zero_prefix_len
            )));
        }
        let nonzero_count = meta.nonzero_prefixes.len / std::mem::size_of::<[u8; 16]>();
        let expected_nonzero = suffix_count - meta.zero_prefix_len;
        if nonzero_count != expected_nonzero {
            return Err(super::invalid_rank9_metadata(format!(
                "compressed-universe stores {nonzero_count} nonzero prefixes, expected {expected_nonzero}"
            )));
        }
        Ok(())
    }

    fn attach(meta: CompressedUniverseMeta, bytes: Bytes) -> Result<Self, jerky::error::Error> {
        Self::validate_layout(&meta, &bytes, bytes.len())?;
        let suffixes = meta
            .suffixes
            .view(&bytes)
            .map_err(jerky::error::Error::from)?;
        let nonzero_prefixes = meta
            .nonzero_prefixes
            .view(&bytes)
            .map_err(jerky::error::Error::from)?;

        Ok(Self {
            zero_prefix_len: meta.zero_prefix_len,
            suffixes,
            suffixes_handle: meta.suffixes,
            nonzero_prefixes,
            nonzero_prefixes_handle: meta.nonzero_prefixes,
        })
    }

    /// Explicitly audits sortedness and the compressed-domain partition.
    /// Ordinary typed attachment checks only metadata geometry.
    pub fn validate(&self) -> Result<(), jerky::error::Error> {
        let Self {
            zero_prefix_len,
            suffixes,
            nonzero_prefixes,
            ..
        } = self;
        if nonzero_prefixes
            .first()
            .is_some_and(|prefix| *prefix == [0; 16])
        {
            return Err(super::invalid_rank9_metadata(
                "compressed-universe tail contains a zero prefix",
            ));
        }
        if !suffixes[..*zero_prefix_len]
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(super::invalid_rank9_metadata(
                "compressed-universe zero-prefix values are not strictly increasing",
            ));
        }
        if (1..nonzero_prefixes.len()).any(|position| {
            let previous = (
                &nonzero_prefixes[position - 1],
                &suffixes[*zero_prefix_len + position - 1],
            );
            let current = (
                &nonzero_prefixes[position],
                &suffixes[*zero_prefix_len + position],
            );
            previous >= current
        }) {
            return Err(super::invalid_rank9_metadata(
                "compressed-universe nonzero-prefix values are not strictly increasing",
            ));
        }

        Ok(())
    }

    #[inline]
    fn tail_cmp(&self, tail_pos: usize, value: &RawInline) -> std::cmp::Ordering {
        self.nonzero_prefixes[tail_pos]
            .as_slice()
            .cmp(&value[..16])
            .then_with(|| {
                self.suffixes[self.zero_prefix_len + tail_pos]
                    .as_slice()
                    .cmp(&value[16..])
            })
    }

    fn tail_partition_point(
        &self,
        mut predicate: impl FnMut(std::cmp::Ordering) -> bool,
        value: &RawInline,
    ) -> usize {
        let mut lo = 0usize;
        let mut hi = self.nonzero_prefixes.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if predicate(self.tail_cmp(mid, value)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

impl Universe for CompressedUniverse {
    fn with_sorted_dedup<I>(iter: I, sections: &mut SectionWriter<'_>) -> Self
    where
        I: Iterator<Item = RawInline>,
    {
        let mut suffixes = Vec::<[u8; 16]>::new();
        let mut nonzero_prefixes = Vec::<[u8; 16]>::new();
        let mut previous = None;
        let mut saw_nonzero_prefix = false;

        for value in iter {
            debug_assert!(previous.is_none_or(|prior| prior < value));
            previous = Some(value);

            let mut suffix = [0; 16];
            suffix.copy_from_slice(&value[16..]);
            suffixes.push(suffix);

            if value[..16] == [0; 16] {
                debug_assert!(!saw_nonzero_prefix);
            } else {
                saw_nonzero_prefix = true;
                let mut prefix = [0; 16];
                prefix.copy_from_slice(&value[..16]);
                nonzero_prefixes.push(prefix);
            }
        }

        let zero_prefix_len = suffixes.len() - nonzero_prefixes.len();

        let mut suffixes_section = sections.reserve::<[u8; 16]>(suffixes.len()).unwrap();
        suffixes_section.as_mut_slice().copy_from_slice(&suffixes);
        let suffixes_handle = suffixes_section.handle();
        let suffixes_bytes = suffixes_section.freeze().unwrap();
        let suffixes = suffixes_bytes.view::<[[u8; 16]]>().expect("view");

        let mut prefixes_section = sections
            .reserve::<[u8; 16]>(nonzero_prefixes.len())
            .unwrap();
        prefixes_section
            .as_mut_slice()
            .copy_from_slice(&nonzero_prefixes);
        let nonzero_prefixes_handle = prefixes_section.handle();
        let prefixes_bytes = prefixes_section.freeze().unwrap();
        let nonzero_prefixes = prefixes_bytes.view::<[[u8; 16]]>().expect("view");

        Self {
            zero_prefix_len,
            suffixes,
            suffixes_handle,
            nonzero_prefixes,
            nonzero_prefixes_handle,
        }
    }

    fn access(&self, pos: usize) -> RawInline {
        let mut value: RawInline = [0; 32];
        value[16..].copy_from_slice(&self.suffixes[pos]);
        if pos >= self.zero_prefix_len {
            value[..16].copy_from_slice(&self.nonzero_prefixes[pos - self.zero_prefix_len]);
        }
        value
    }

    fn search(&self, value: &RawInline) -> Option<usize> {
        let position = self.search_lower(value);
        let matches = if value[..16] == [0; 16] {
            position < self.zero_prefix_len && self.suffixes[position].as_slice() == &value[16..]
        } else {
            position >= self.zero_prefix_len
                && position < self.len()
                && self
                    .tail_cmp(position - self.zero_prefix_len, value)
                    .is_eq()
        };
        matches.then_some(position)
    }

    fn search_lower(&self, value: &RawInline) -> usize {
        if value[..16] == [0; 16] {
            return self.suffixes[..self.zero_prefix_len]
                .partition_point(|suffix| suffix.as_slice() < &value[16..]);
        }
        self.zero_prefix_len + self.tail_partition_point(|ordering| ordering.is_lt(), value)
    }

    fn search_upper(&self, value: &RawInline) -> usize {
        if value[..16] == [0; 16] {
            return self.suffixes[..self.zero_prefix_len]
                .partition_point(|suffix| suffix.as_slice() <= &value[16..]);
        }
        self.zero_prefix_len + self.tail_partition_point(|ordering| !ordering.is_gt(), value)
    }

    #[inline]
    fn len(&self) -> usize {
        self.suffixes.len()
    }
}

/// Serialisation metadata header for a [`CompressedUniverse`].
#[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
#[repr(C)]
pub struct CompressedUniverseMeta {
    /// Number of leading values whose first sixteen bytes are all zero.
    pub zero_prefix_len: usize,
    /// Second sixteen bytes of every value, in value order.
    pub suffixes: SectionHandle<[u8; 16]>,
    /// First sixteen bytes of values after the zero-prefix range.
    pub nonzero_prefixes: SectionHandle<[u8; 16]>,
}

impl Serializable for CompressedUniverse {
    type Meta = CompressedUniverseMeta;
    type Error = jerky::error::Error;

    fn metadata(&self) -> Self::Meta {
        CompressedUniverseMeta {
            zero_prefix_len: self.zero_prefix_len,
            suffixes: self.suffixes_handle,
            nonzero_prefixes: self.nonzero_prefixes_handle,
        }
    }

    fn from_bytes(meta: Self::Meta, bytes: Bytes) -> Result<Self, Self::Error> {
        Self::attach(meta, bytes)
    }
}

/// Wrapper that adds LRU caches around an inner [`Universe`].
///
/// `ACCESS_CACHE` sets the capacity for `access` lookups and
/// `SEARCH_CACHE` for `search` lookups.
#[derive(Debug)]
pub struct CachedUniverse<const ACCESS_CACHE: usize, const SEARCH_CACHE: usize, U: Universe> {
    access_cache: Cache<usize, RawInline>,
    search_cache: Cache<RawInline, Option<usize>>,
    inner: U,
}

impl<const ACCESS_CACHE: usize, const SEARCH_CACHE: usize, U> Universe
    for CachedUniverse<ACCESS_CACHE, SEARCH_CACHE, U>
where
    U: Universe,
{
    fn from_ordered_values(values: View<[RawInline]>) -> Self {
        Self {
            access_cache: Cache::new(ACCESS_CACHE),
            search_cache: Cache::new(SEARCH_CACHE),
            inner: U::from_ordered_values(values),
        }
    }

    fn with_sorted_dedup<I>(values: I, sections: &mut SectionWriter<'_>) -> Self
    where
        I: Iterator<Item = RawInline>,
    {
        Self {
            access_cache: Cache::new(ACCESS_CACHE),
            search_cache: Cache::new(SEARCH_CACHE),
            inner: U::with_sorted_dedup(values, sections),
        }
    }

    fn access(&self, pos: usize) -> RawInline {
        self.access_cache
            .get_or_insert_with::<_, Infallible>(&pos, || Ok(self.inner.access(pos)))
            .unwrap()
    }

    fn search(&self, v: &RawInline) -> Option<usize> {
        if self.len() == 0 {
            return None;
        }

        self.search_cache
            .get_or_insert_with::<_, Infallible>(v, || {
                Ok((0..=self.len() - 1)
                    .binary_by(|p| self.access(p).cmp(v))
                    .ok())
            })
            .unwrap()
    }

    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<const ACCESS_CACHE: usize, const SEARCH_CACHE: usize, U> Serializable
    for CachedUniverse<ACCESS_CACHE, SEARCH_CACHE, U>
where
    U: Universe + Serializable,
{
    type Meta = U::Meta;
    type Error = U::Error;

    fn metadata(&self) -> Self::Meta {
        self.inner.metadata()
    }

    fn from_bytes(meta: Self::Meta, bytes: Bytes) -> Result<Self, Self::Error> {
        let inner = U::from_bytes(meta, bytes)?;
        Ok(Self {
            access_cache: Cache::new(ACCESS_CACHE),
            search_cache: Cache::new(SEARCH_CACHE),
            inner,
        })
    }
}

#[cfg(test)]
mod tests {
    use anybytes::area::ByteArea;
    use anybytes::Bytes;
    use jerky::Serializable;

    use crate::id::id_into_value;

    use super::CachedUniverse;
    use super::CompressedUniverse;
    use super::OrderedUniverse;
    use super::Universe;

    #[test]
    fn ordered_universe_zero_copy() {
        let values: Vec<_> = (0..4u128)
            .map(|id| id_into_value(&id.to_be_bytes()))
            .collect();

        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let u = OrderedUniverse::with_sorted_dedup(values.iter().copied(), &mut sections);
        let handle = u.metadata();
        drop(sections);
        let bytes = area.freeze().unwrap();
        let rebuilt = OrderedUniverse::from_bytes(handle, bytes.clone()).unwrap();
        let view = handle.view(&bytes).unwrap();
        assert_eq!(rebuilt.values.as_ref().as_ptr(), view.as_ref().as_ptr());
    }

    #[test]
    fn compressed_universe_empty_search() {
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let u = CompressedUniverse::with_sorted_dedup(std::iter::empty(), &mut sections);
        assert_eq!(u.search(&[0u8; 32]), None);
    }

    #[test]
    fn compressed_universe_roundtrips_with_exact_zero_prefix_payload() {
        let mut values = vec![[0; 32], [0; 32], [0; 32], [0x11; 32], [0x22; 32]];
        values[1][31] = 7;
        values[2][16] = 9;
        values[3][16..].fill(0x44);
        values.sort_unstable();
        values.dedup();
        let zero_prefix_len = values.partition_point(|value| value[..16] == [0; 16]);

        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let universe = CompressedUniverse::with_sorted_dedup(values.iter().copied(), &mut sections);
        let metadata = universe.metadata();
        drop(sections);
        let bytes = area.freeze().unwrap();

        assert_eq!(bytes.len(), 32 * values.len() - 16 * zero_prefix_len);
        let rebuilt = CompressedUniverse::from_bytes(metadata, bytes).unwrap();
        for (position, value) in values.iter().enumerate() {
            assert_eq!(rebuilt.access(position), *value);
            assert_eq!(rebuilt.search(value), Some(position));
            assert_eq!(rebuilt.search_lower(value), position);
            assert_eq!(rebuilt.search_upper(value), position + 1);
        }
        assert_eq!(rebuilt.search(&[0xff; 32]), None);
        assert_eq!(rebuilt.search_lower(&[0xff; 32]), values.len());
        assert_eq!(rebuilt.search_upper(&[0xff; 32]), values.len());
    }

    #[test]
    fn compressed_universe_searches_match_ordered_universe() {
        let mut values = Vec::new();
        for suffix in 0..128u32 {
            let mut value = [0; 32];
            value[28..].copy_from_slice(&(suffix * 2).to_be_bytes());
            values.push(value);
        }
        for prefix in 1..=8u8 {
            for suffix in 0..17u32 {
                let mut value = [0; 32];
                value[15] = prefix;
                value[28..].copy_from_slice(&(suffix * 3).to_be_bytes());
                values.push(value);
            }
        }
        values.sort_unstable();

        let mut probes = values.clone();
        for suffix in 0..128u32 {
            let mut value = [0; 32];
            value[28..].copy_from_slice(&(suffix * 2 + 1).to_be_bytes());
            probes.push(value);
        }
        for prefix in 1..=9u8 {
            for suffix in 0..17u32 {
                let mut value = [0; 32];
                value[15] = prefix;
                value[28..].copy_from_slice(&(suffix * 3 + 1).to_be_bytes());
                probes.push(value);
            }
        }
        probes.push([0xff; 32]);

        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let ordered = OrderedUniverse::with_sorted_dedup(values.iter().copied(), &mut sections);
        let compressed =
            CompressedUniverse::with_sorted_dedup(values.iter().copied(), &mut sections);

        assert_eq!(compressed.len(), ordered.len());
        for position in 0..values.len() {
            assert_eq!(compressed.access(position), ordered.access(position));
        }
        for probe in probes {
            assert_eq!(compressed.search(&probe), ordered.search(&probe));
            assert_eq!(
                compressed.search_lower(&probe),
                ordered.search_lower(&probe)
            );
            assert_eq!(
                compressed.search_upper(&probe),
                ordered.search_upper(&probe)
            );
        }
    }

    #[test]
    fn compressed_universe_rejects_malformed_metadata_and_content() {
        let mut values = vec![[0; 32], [0x11; 32], [0x22; 32]];
        values[0][31] = 1;
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let universe = CompressedUniverse::with_sorted_dedup(values.iter().copied(), &mut sections);
        let metadata = universe.metadata();
        drop(sections);
        let bytes = area.freeze().unwrap();

        let mut boundary = metadata;
        boundary.zero_prefix_len = values.len() + 1;
        assert!(CompressedUniverse::from_bytes(boundary, bytes.clone()).is_err());

        let mut count = metadata;
        count.nonzero_prefixes.len -= 16;
        assert!(CompressedUniverse::from_bytes(count, bytes.clone()).is_err());

        let mut misaligned = metadata;
        misaligned.suffixes.len -= 1;
        assert!(CompressedUniverse::from_bytes(misaligned, bytes.clone()).is_err());

        let mut outside = metadata;
        outside.nonzero_prefixes.offset = bytes.len() + 16;
        assert!(CompressedUniverse::from_bytes(outside, bytes.clone()).is_err());

        let mut zero_tail = bytes.as_ref().to_vec();
        let start = metadata.nonzero_prefixes.offset;
        zero_tail[start..start + 16].fill(0);
        assert!(
            CompressedUniverse::from_bytes(metadata, Bytes::from_source(zero_tail))
                .unwrap()
                .validate()
                .is_err()
        );

        let mut unordered = bytes.as_ref().to_vec();
        let prefixes = metadata.nonzero_prefixes.offset;
        unordered.swap(prefixes, prefixes + 16);
        assert!(
            CompressedUniverse::from_bytes(metadata, Bytes::from_source(unordered))
                .unwrap()
                .validate()
                .is_err()
        );

        assert!(
            CompressedUniverse::from_bytes(metadata, bytes.clone().slice(0..bytes.len() - 1),)
                .is_err()
        );
    }

    #[test]
    fn cached_universe_empty_search() {
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let u: CachedUniverse<1, 1, OrderedUniverse> =
            CachedUniverse::with(std::iter::empty(), &mut sections);
        assert_eq!(u.search(&[0u8; 32]), None);
    }
}
