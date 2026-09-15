//! Canonical, portable raw bytes for an ordered-domain succinct archive.
//!
//! This codec stays internal because its public identity is the external
//! [`SuccinctArchiveBlob`](super::SuccinctArchiveBlob) schema ID. It has no
//! magic bytes or version word: a future incompatible layout receives a fresh
//! schema ID, so the payload contains only information needed to decode the
//! archive. Native runtime arenas are reproducible caches, not a second format.
//!
//! The payload is a gapless sequence of little-endian sections:
//!
//! ```text
//! [u8; 32] domain[D]            strictly increasing raw values
//! u64 prefix[3][ceil((N+D+1)/64)]
//! u64 changed[6][ceil(N/64)]
//! u64 wavelet[6][W(D)][ceil(N/64)]
//! u64 N                         number of tribles
//! u64 D                         ordered-domain cardinality
//! ```
//!
//! The domain starts at global offset zero so its 32-byte values participate
//! in the repository's schema-independent conservative child-handle scan. The
//! fixed count footer is read first; `N` and `D` then derive every preceding
//! boundary and the exact EOF position without padding or a section table.
//!
//! `W(D) = max(1, bit_length(D - 1))`: codes inhabit `0..D`, so the largest
//! code is `D - 1`. Logical bit `i` is bit `i % 64` of little-endian word
//! `i / 64`; unused high bits are zero. Prefix vectors encode domain group
//! sizes as `1 0^c0 1 ... 0^c[D-1] 1`.
//!
//! # Semantic boundary
//!
//! Ordinary attachment checks only section framing and typed-view geometry.
//! The producer endorses the mathematical contents. Full domain, prefix,
//! histogram and canonical-derivation checks remain an explicit audit, never
//! a prerequisite for borrowing the stored query sections.

use std::fmt;
use std::ops::Range;

use crate::id::{id_from_value, Id};
use crate::inline::RawInline;

use super::{SuccinctRotation, WaveletMatrixFreezeBackend};

const COUNT_FOOTER_LEN: usize = 16;
const RAW_INLINE_LEN: usize = 32;
const WORD_LEN: usize = 8;
const PREFIX_COUNT: usize = 3;
const CHANGE_COUNT: usize = 6;
const WAVELET_COUNT: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixAxis {
    Entity,
    Attribute,
    Value,
}

impl PrefixAxis {
    const ALL: [Self; PREFIX_COUNT] = [Self::Entity, Self::Attribute, Self::Value];

    const fn index(self) -> usize {
        match self {
            Self::Entity => 0,
            Self::Attribute => 1,
            Self::Value => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Entity => "entity prefix",
            Self::Attribute => "attribute prefix",
            Self::Value => "value prefix",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeAxis {
    EntityAttribute,
    EntityValue,
    AttributeEntity,
    AttributeValue,
    ValueEntity,
    ValueAttribute,
}

impl ChangeAxis {
    const ALL: [Self; CHANGE_COUNT] = [
        Self::EntityAttribute,
        Self::EntityValue,
        Self::AttributeEntity,
        Self::AttributeValue,
        Self::ValueEntity,
        Self::ValueAttribute,
    ];

    const fn index(self) -> usize {
        match self {
            Self::EntityAttribute => 0,
            Self::EntityValue => 1,
            Self::AttributeEntity => 2,
            Self::AttributeValue => 3,
            Self::ValueEntity => 4,
            Self::ValueAttribute => 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::EntityAttribute => "changed entity-attribute",
            Self::EntityValue => "changed entity-value",
            Self::AttributeEntity => "changed attribute-entity",
            Self::AttributeValue => "changed attribute-value",
            Self::ValueEntity => "changed value-entity",
            Self::ValueAttribute => "changed value-attribute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rotation {
    Eav,
    Vea,
    Ave,
    Vae,
    Eva,
    Aev,
}

impl Rotation {
    const ALL: [Self; WAVELET_COUNT] = [
        Self::Eav,
        Self::Vea,
        Self::Ave,
        Self::Vae,
        Self::Eva,
        Self::Aev,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Eav => 0,
            Self::Vea => 1,
            Self::Ave => 2,
            Self::Vae => 3,
            Self::Eva => 4,
            Self::Aev => 5,
        }
    }

    const fn last_axis(self) -> PrefixAxis {
        match self {
            Self::Eav | Self::Aev => PrefixAxis::Value,
            Self::Vea | Self::Eva => PrefixAxis::Attribute,
            Self::Ave | Self::Vae => PrefixAxis::Entity,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Eav => "EAV wavelet",
            Self::Vea => "VEA wavelet",
            Self::Ave => "AVE wavelet",
            Self::Vae => "VAE wavelet",
            Self::Eva => "EVA wavelet",
            Self::Aev => "AEV wavelet",
        }
    }
}

/// Borrowed sections supplied to the portable writer.
///
/// Wavelet slices are flattened in plane-major order. Every prefix/change
/// slice and every individual wavelet plane stores little-endian logical words;
/// the writer normalizes their byte order while copying them.
#[derive(Clone, Copy)]
pub(crate) struct PortableParts<'a> {
    pub(crate) triple_count: usize,
    pub(crate) domain: &'a [RawInline],
    pub(crate) prefixes: [&'a [u64]; PREFIX_COUNT],
    pub(crate) changes: [&'a [u64]; CHANGE_COUNT],
    pub(crate) wavelets: [&'a [u64]; WAVELET_COUNT],
}

/// A structurally validated, deliberately non-queryable view of portable bytes.
#[derive(Debug)]
pub(crate) struct PortableView<'a> {
    bytes: &'a [u8],
    layout: Layout,
    prefix_counts: [Vec<usize>; PREFIX_COUNT],
}

/// Exact, runtime-independent logical content of one canonical portable
/// archive. Codes are local to `domain`; `rows` are strictly increasing EAV.
pub(super) struct CanonicalEavU32 {
    pub(super) domain: Vec<RawInline>,
    pub(super) rows: Vec<[u32; 3]>,
}

impl PortableView<'_> {
    pub(crate) fn domain_value(&self, code: usize) -> RawInline {
        let start = self.layout.domain.start + code * RAW_INLINE_LEN;
        self.bytes[start..start + RAW_INLINE_LEN]
            .try_into()
            .expect("validated domain range")
    }

    pub(crate) fn wavelet_word(&self, rotation: Rotation, depth: usize, word: usize) -> u64 {
        let word = depth * self.layout.row_words + word;
        read_word(self.bytes, &self.layout.wavelets[rotation.index()], word)
    }

    /// Prove that every byte is the exact canonical derivation of the EAV
    /// source ring.
    ///
    /// The candidate rows are decoded without consulting a changed-pair mask.
    /// A small, independent canonical writer then derives all three prefixes,
    /// all six masks, and all six wavelet matrices from those rows. Only exact
    /// byte equality succeeds. This makes the proof independent of Jerky's
    /// native runtime and its source-bound Rank9 accelerated root.
    pub(crate) fn prove_canonical(&self) -> Result<(), PortableError> {
        let rows = self.candidate_eav_codes()?;
        if rows.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PortableError::new(
                "decoded EAV source rows are not strictly increasing",
            ));
        }

        let expected = canonical_bytes_from_eav(self, &rows)?;
        if expected != self.bytes {
            return Err(PortableError::new(
                "payload is not the exact canonical derivation of its EAV source ring",
            ));
        }

        Ok(())
    }

    /// Proves exact canonical bytes and returns only the logical EAV source.
    ///
    /// Unlike [`Self::prove_canonical`], this path never constructs native
    /// runtime sections or a second portable payload. It rederives every
    /// prefix run, pair-change bit, and stable wavelet plane from EAV and
    /// compares them in place as an independent explicit-audit test oracle.
    #[cfg(test)]
    pub(super) fn prove_canonical_eav_u32(&self) -> Result<CanonicalEavU32, PortableError> {
        if self.layout.triple_count > u32::MAX as usize {
            return Err(PortableError::new(format!(
                "archive contains {} rows, exceeding u32 construction offsets",
                self.layout.triple_count
            )));
        }
        if self.layout.domain_len > u32::MAX as usize {
            return Err(PortableError::new(format!(
                "ordered domain contains {} values, exceeding u32 construction codes",
                self.layout.domain_len
            )));
        }

        let source = self.decode_eav_u32()?;
        verify_canonical_eav_u32(self, &source.rows)?;
        Ok(source)
    }

    /// Decodes just the source ring needed by a raw union. Secondary
    /// rotations and changed masks are not rederived or compared.
    pub(super) fn decode_eav_u32(&self) -> Result<CanonicalEavU32, PortableError> {
        let rows = self.candidate_eav_codes_as(|code| {
            u32::try_from(code)
                .map_err(|_| PortableError::new("archive-local code does not fit a u32 lane"))
        })?;
        if rows.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PortableError::new(
                "decoded EAV source rows are not strictly increasing",
            ));
        }
        let domain = (0..self.layout.domain_len)
            .map(|code| self.domain_value(code))
            .collect::<Vec<_>>();

        Ok(CanonicalEavU32 { domain, rows })
    }

    fn candidate_eav_codes(&self) -> Result<Vec<[usize; 3]>, PortableError> {
        self.candidate_eav_codes_as(Ok)
    }

    fn candidate_eav_codes_as<T>(
        &self,
        mut convert: impl FnMut(usize) -> Result<T, PortableError>,
    ) -> Result<Vec<[T; 3]>, PortableError> {
        let starts: [Vec<usize>; PREFIX_COUNT] = std::array::from_fn(|axis| {
            let mut cursor = 0usize;
            self.prefix_counts[axis]
                .iter()
                .copied()
                .map(|count| {
                    let start = cursor;
                    cursor += count;
                    start
                })
                .collect::<Vec<_>>()
        });

        let eav = PortableWavelet::new(self, Rotation::Eav);
        let vea = PortableWavelet::new(self, Rotation::Vea);
        let ave = PortableWavelet::new(self, Rotation::Ave);
        let value_starts = &starts[PrefixAxis::Value.index()];
        let attribute_starts = &starts[PrefixAxis::Attribute.index()];

        let mut candidate = Vec::with_capacity(self.layout.triple_count);
        for eav_position in 0..self.layout.triple_count {
            let value = eav.access(eav_position).ok_or_else(|| {
                PortableError::new(format!("EAV wavelet cannot decode row {eav_position}"))
            })?;
            let vea_position = value_starts
                .get(value)
                .ok_or_else(|| PortableError::new("EAV value code is outside the domain"))?
                .checked_add(eav.rank(eav_position, value).ok_or_else(|| {
                    PortableError::new(format!(
                        "EAV rank cannot rotate row {eav_position} for value code {value}"
                    ))
                })?)
                .filter(|position| *position < self.layout.triple_count)
                .ok_or_else(|| {
                    PortableError::new(format!(
                        "EAV row {eav_position} rotates outside the VEA column"
                    ))
                })?;

            let attribute = vea.access(vea_position).ok_or_else(|| {
                PortableError::new(format!(
                    "VEA wavelet cannot decode rotated row {vea_position}"
                ))
            })?;
            let ave_position = attribute_starts
                .get(attribute)
                .ok_or_else(|| PortableError::new("VEA attribute code is outside the domain"))?
                .checked_add(vea.rank(vea_position, attribute).ok_or_else(|| {
                    PortableError::new(format!(
                        "VEA rank cannot rotate row {vea_position} for attribute code {attribute}"
                    ))
                })?)
                .filter(|position| *position < self.layout.triple_count)
                .ok_or_else(|| {
                    PortableError::new(format!(
                        "VEA row {vea_position} rotates outside the AVE column"
                    ))
                })?;

            let entity = ave.access(ave_position).ok_or_else(|| {
                PortableError::new(format!(
                    "AVE wavelet cannot decode rotated row {ave_position}"
                ))
            })?;
            if entity >= self.layout.domain_len {
                return Err(PortableError::new("AVE entity code is outside the domain"));
            }
            candidate.push([convert(entity)?, convert(attribute)?, convert(value)?]);
        }
        Ok(candidate)
    }
}

#[cfg(test)]
fn verify_canonical_eav_u32(
    view: &PortableView<'_>,
    rows: &[[u32; 3]],
) -> Result<(), PortableError> {
    let mut work = rows.to_vec();
    let mut row_scratch = Vec::with_capacity(rows.len());
    let mut radix_counts = vec![0u32; view.layout.domain_len];
    let mut sequence = Vec::with_capacity(rows.len());
    let mut sequence_scratch = Vec::with_capacity(rows.len());

    verify_canonical_rotation(
        view,
        &work,
        [0, 1, 2],
        Some(PrefixAxis::Entity),
        ChangeAxis::EntityAttribute,
        Rotation::Eav,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    stable_sort_rows_by_component(&mut work, &mut row_scratch, &mut radix_counts, 2)?;
    verify_canonical_rotation(
        view,
        &work,
        [2, 0, 1],
        Some(PrefixAxis::Value),
        ChangeAxis::ValueEntity,
        Rotation::Vea,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    stable_sort_rows_by_component(&mut work, &mut row_scratch, &mut radix_counts, 1)?;
    verify_canonical_rotation(
        view,
        &work,
        [1, 2, 0],
        Some(PrefixAxis::Attribute),
        ChangeAxis::AttributeValue,
        Rotation::Ave,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    stable_sort_rows_by_component(&mut work, &mut row_scratch, &mut radix_counts, 2)?;
    verify_canonical_rotation(
        view,
        &work,
        [2, 1, 0],
        None,
        ChangeAxis::ValueAttribute,
        Rotation::Vae,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    stable_sort_rows_by_component(&mut work, &mut row_scratch, &mut radix_counts, 0)?;
    verify_canonical_rotation(
        view,
        &work,
        [0, 2, 1],
        None,
        ChangeAxis::EntityValue,
        Rotation::Eva,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    stable_sort_rows_by_component(&mut work, &mut row_scratch, &mut radix_counts, 1)?;
    verify_canonical_rotation(
        view,
        &work,
        [1, 0, 2],
        None,
        ChangeAxis::AttributeEntity,
        Rotation::Aev,
        &mut sequence,
        &mut sequence_scratch,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_canonical_rotation(
    view: &PortableView<'_>,
    rows: &[[u32; 3]],
    components: [usize; 3],
    prefix_axis: Option<PrefixAxis>,
    change_axis: ChangeAxis,
    rotation: Rotation,
    sequence: &mut Vec<u32>,
    sequence_scratch: &mut Vec<u32>,
) -> Result<(), PortableError> {
    let [first_component, middle_component, last_component] = components;
    if let Some(axis) = prefix_axis {
        let mut position = 0usize;
        for (code, expected) in view.prefix_counts[axis.index()].iter().copied().enumerate() {
            let start = position;
            while rows
                .get(position)
                .is_some_and(|row| row[first_component] as usize == code)
            {
                position += 1;
            }
            if position - start != expected {
                return Err(PortableError::new(format!(
                    "{} disagrees with canonical {:?} row runs at code {code}",
                    axis.name(),
                    rotation
                )));
            }
        }
        if position != rows.len() {
            return Err(PortableError::new(format!(
                "{} leaves rows outside the ordered domain",
                axis.name()
            )));
        }
    }

    let change_range = &view.layout.changes[change_axis.index()];
    let mut previous_pair = None;
    sequence.clear();
    for (position, row) in rows.iter().enumerate() {
        let pair = [row[first_component], row[middle_component]];
        let expected_change = previous_pair != Some(pair);
        if bit(view.bytes, change_range, position) != expected_change {
            return Err(PortableError::new(format!(
                "{} disagrees with canonical {:?} pair runs at row {position}",
                change_axis.name(),
                rotation
            )));
        }
        previous_pair = Some(pair);
        sequence.push(row[last_component]);
    }

    sequence_scratch.resize(sequence.len(), 0);
    for depth in 0..view.layout.alphabet_width {
        let shift = view.layout.alphabet_width - depth - 1;
        let mut zeros = 0usize;
        for (position, code) in sequence.iter().copied().enumerate() {
            let expected_one = code & (1u32 << shift) != 0;
            let word = view.wavelet_word(rotation, depth, position / u64::BITS as usize);
            let actual_one = word & (1u64 << (position % u64::BITS as usize)) != 0;
            if actual_one != expected_one {
                return Err(PortableError::new(format!(
                    "{} disagrees with its canonical source at depth {depth}, row {position}",
                    rotation.name()
                )));
            }
            if !expected_one {
                zeros += 1;
            }
        }

        if depth + 1 < view.layout.alphabet_width {
            let (mut zero, mut one) = (0usize, zeros);
            for code in sequence.iter().copied() {
                if code & (1u32 << shift) == 0 {
                    sequence_scratch[zero] = code;
                    zero += 1;
                } else {
                    sequence_scratch[one] = code;
                    one += 1;
                }
            }
            std::mem::swap(sequence, sequence_scratch);
        }
    }
    sequence.clear();
    sequence_scratch.clear();
    Ok(())
}

fn canonical_bytes_from_eav(
    view: &PortableView<'_>,
    eav_rows: &[[usize; 3]],
) -> Result<Vec<u8>, PortableError> {
    let domain_len = view.layout.domain_len;
    let domain: Vec<_> = (0..domain_len)
        .map(|code| view.domain_value(code))
        .collect();

    let mut axis_counts: [Vec<usize>; PREFIX_COUNT] =
        std::array::from_fn(|_| vec![0usize; domain_len]);
    for &[entity, attribute, value] in eav_rows {
        axis_counts[PrefixAxis::Entity.index()][entity] += 1;
        axis_counts[PrefixAxis::Attribute.index()][attribute] += 1;
        axis_counts[PrefixAxis::Value.index()][value] += 1;
    }
    let prefixes = axis_counts.map(|counts| encode_prefix(&counts, eav_rows.len()));

    let mut rotations: [Vec<[usize; 3]>; WAVELET_COUNT] =
        std::array::from_fn(|_| Vec::with_capacity(eav_rows.len()));
    for &[entity, attribute, value] in eav_rows {
        rotations[Rotation::Eav.index()].push([entity, attribute, value]);
        rotations[Rotation::Vea.index()].push([value, entity, attribute]);
        rotations[Rotation::Ave.index()].push([attribute, value, entity]);
        rotations[Rotation::Vae.index()].push([value, attribute, entity]);
        rotations[Rotation::Eva.index()].push([entity, value, attribute]);
        rotations[Rotation::Aev.index()].push([attribute, entity, value]);
    }
    for rows in &mut rotations {
        rows.sort_unstable();
    }

    let rotation_changes: [Vec<u64>; WAVELET_COUNT] =
        std::array::from_fn(|rotation| encode_changes(&rotations[rotation]));
    let wavelets: [Vec<u64>; WAVELET_COUNT] = std::array::from_fn(|rotation| {
        encode_wavelet(
            rotations[rotation].iter().map(|row| row[2]),
            eav_rows.len(),
            domain_len,
        )
    });

    let [eav_changes, vea_changes, ave_changes, vae_changes, eva_changes, aev_changes] =
        rotation_changes;
    let changes = [
        eav_changes,
        eva_changes,
        aev_changes,
        ave_changes,
        vea_changes,
        vae_changes,
    ];
    let bytes = encode(PortableParts {
        triple_count: eav_rows.len(),
        domain: &domain,
        prefixes: [&prefixes[0], &prefixes[1], &prefixes[2]],
        changes: [
            &changes[0],
            &changes[1],
            &changes[2],
            &changes[3],
            &changes[4],
            &changes[5],
        ],
        wavelets: [
            &wavelets[Rotation::Eav.index()],
            &wavelets[Rotation::Vea.index()],
            &wavelets[Rotation::Ave.index()],
            &wavelets[Rotation::Vae.index()],
            &wavelets[Rotation::Eva.index()],
            &wavelets[Rotation::Aev.index()],
        ],
    })?;
    Ok(bytes)
}

fn encode_prefix(counts: &[usize], row_count: usize) -> Vec<u64> {
    let mut words = vec![0u64; words_for_bits(row_count + counts.len() + 1)];
    let mut rows_seen = 0usize;
    for (code, count) in counts.iter().copied().enumerate() {
        set_bit(&mut words, rows_seen + code);
        rows_seen += count;
    }
    debug_assert_eq!(rows_seen, row_count);
    set_bit(&mut words, row_count + counts.len());
    words
}

fn encode_changes(rows: &[[usize; 3]]) -> Vec<u64> {
    let mut words = vec![0u64; words_for_bits(rows.len())];
    let mut previous = None;
    for (position, row) in rows.iter().enumerate() {
        let pair = [row[0], row[1]];
        if previous != Some(pair) {
            set_bit(&mut words, position);
            previous = Some(pair);
        }
    }
    words
}

fn encode_wavelet(
    sequence: impl IntoIterator<Item = usize>,
    row_count: usize,
    domain_len: usize,
) -> Vec<u64> {
    let width = alphabet_width(domain_len);
    let row_words = words_for_bits(row_count);
    let mut current: Vec<_> = sequence.into_iter().collect();
    let mut next = vec![0usize; row_count];
    let mut result = Vec::with_capacity(width * row_words);
    for depth in 0..width {
        let shift = width - depth - 1;
        let mut plane = vec![0u64; row_words];
        let mut zeros = 0usize;
        for (position, code) in current.iter().copied().enumerate() {
            if code & (1usize << shift) == 0 {
                zeros += 1;
            } else {
                set_bit(&mut plane, position);
            }
        }
        let (mut zero, mut one) = (0usize, zeros);
        for code in current.iter().copied() {
            if code & (1usize << shift) == 0 {
                next[zero] = code;
                zero += 1;
            } else {
                next[one] = code;
                one += 1;
            }
        }
        result.extend(plane);
        std::mem::swap(&mut current, &mut next);
    }
    result
}

fn set_bit(words: &mut [u64], position: usize) {
    words[position / u64::BITS as usize] |= 1u64 << (position % u64::BITS as usize);
}

/// Temporary rank directory used by explicit audits and EAV source decoding
/// during MERGE. Ordinary query attachment neither constructs nor retains it.
struct PortableWavelet<'a> {
    view: &'a PortableView<'a>,
    rotation: Rotation,
    ranks: Vec<usize>,
    rank_stride: usize,
    zero_counts: Vec<usize>,
}

impl<'a> PortableWavelet<'a> {
    fn new(view: &'a PortableView<'a>, rotation: Rotation) -> Self {
        let rank_stride = view.layout.row_words + 1;
        let mut ranks = vec![0usize; view.layout.alphabet_width * rank_stride];
        let mut zero_counts = vec![0usize; view.layout.alphabet_width];
        for (depth, zero_count) in zero_counts.iter_mut().enumerate() {
            let base = depth * rank_stride;
            for word in 0..view.layout.row_words {
                ranks[base + word + 1] = ranks[base + word]
                    + view.wavelet_word(rotation, depth, word).count_ones() as usize;
            }
            *zero_count = view.layout.triple_count - ranks[base + view.layout.row_words];
        }
        Self {
            view,
            rotation,
            ranks,
            rank_stride,
            zero_counts,
        }
    }

    fn rank1(&self, depth: usize, position: usize) -> usize {
        let word = position / u64::BITS as usize;
        let offset = position % u64::BITS as usize;
        let complete = self.ranks[depth * self.rank_stride + word];
        if offset == 0 {
            complete
        } else {
            let mask = (1u64 << offset) - 1;
            complete
                + (self.view.wavelet_word(self.rotation, depth, word) & mask).count_ones() as usize
        }
    }

    fn access(&self, mut position: usize) -> Option<usize> {
        if position >= self.view.layout.triple_count {
            return None;
        }
        let mut value = 0usize;
        for depth in 0..self.view.layout.alphabet_width {
            value <<= 1;
            let word = self
                .view
                .wavelet_word(self.rotation, depth, position / u64::BITS as usize);
            let one = word & (1u64 << (position % u64::BITS as usize)) != 0;
            let ones_before = self.rank1(depth, position);
            if one {
                value |= 1;
                position = self.zero_counts[depth] + ones_before;
            } else {
                position -= ones_before;
            }
        }
        (value < self.view.layout.domain_len).then_some(value)
    }

    fn rank(&self, position: usize, value: usize) -> Option<usize> {
        if position > self.view.layout.triple_count || value >= self.view.layout.domain_len {
            return None;
        }
        let mut start = 0usize;
        let mut end = position;
        for depth in 0..self.view.layout.alphabet_width {
            let shift = self.view.layout.alphabet_width - depth - 1;
            if value & (1usize << shift) != 0 {
                start = self.zero_counts[depth] + self.rank1(depth, start);
                end = self.zero_counts[depth] + self.rank1(depth, end);
            } else {
                start -= self.rank1(depth, start);
                end -= self.rank1(depth, end);
            }
        }
        Some(end - start)
    }
}

/// Failure to encode or validate the portable layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortableError {
    message: String,
}

impl PortableError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PortableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid portable succinct archive: {}",
            self.message
        )
    }
}

impl std::error::Error for PortableError {}

#[derive(Debug, Clone)]
pub(super) struct Layout {
    pub(super) triple_count: usize,
    pub(super) domain_len: usize,
    pub(super) alphabet_width: usize,
    pub(super) prefix_bits: usize,
    prefix_words: usize,
    pub(super) row_words: usize,
    pub(super) domain: Range<usize>,
    pub(super) prefixes: [Range<usize>; PREFIX_COUNT],
    pub(super) changes: [Range<usize>; CHANGE_COUNT],
    pub(super) wavelets: [Range<usize>; WAVELET_COUNT],
    count_footer: Range<usize>,
    byte_len: usize,
}

impl Layout {
    fn new(triple_count: usize, domain_len: usize) -> Result<Self, PortableError> {
        let prefix_bits = triple_count
            .checked_add(domain_len)
            .and_then(|sum| sum.checked_add(1))
            .ok_or_else(|| PortableError::new("prefix bit length overflows usize"))?;
        let prefix_words = words_for_bits(prefix_bits);
        let row_words = words_for_bits(triple_count);
        let alphabet_width = alphabet_width(domain_len);

        let domain_bytes = domain_len
            .checked_mul(RAW_INLINE_LEN)
            .ok_or_else(|| PortableError::new("ordered-domain byte length overflows usize"))?;
        let prefix_bytes = prefix_words
            .checked_mul(WORD_LEN)
            .ok_or_else(|| PortableError::new("prefix section byte length overflows usize"))?;
        let change_bytes = row_words
            .checked_mul(WORD_LEN)
            .ok_or_else(|| PortableError::new("change section byte length overflows usize"))?;
        let wavelet_bytes = row_words
            .checked_mul(alphabet_width)
            .and_then(|words| words.checked_mul(WORD_LEN))
            .ok_or_else(|| PortableError::new("wavelet section byte length overflows usize"))?;

        let mut cursor = 0;
        let domain = take_range(&mut cursor, domain_bytes)?;
        let prefixes = ranges(&mut cursor, prefix_bytes)?;
        let changes = ranges(&mut cursor, change_bytes)?;
        let wavelets = ranges(&mut cursor, wavelet_bytes)?;
        let count_footer = take_range(&mut cursor, COUNT_FOOTER_LEN)?;

        Ok(Self {
            triple_count,
            domain_len,
            alphabet_width,
            prefix_bits,
            prefix_words,
            row_words,
            domain,
            prefixes,
            changes,
            wavelets,
            count_footer,
            byte_len: cursor,
        })
    }
}

fn ranges<const N: usize>(
    cursor: &mut usize,
    section_len: usize,
) -> Result<[Range<usize>; N], PortableError> {
    let mut result = Vec::with_capacity(N);
    for _ in 0..N {
        result.push(take_range(cursor, section_len)?);
    }
    Ok(result.try_into().expect("exact range count"))
}

fn take_range(cursor: &mut usize, len: usize) -> Result<Range<usize>, PortableError> {
    let start = *cursor;
    let end = start
        .checked_add(len)
        .ok_or_else(|| PortableError::new("portable layout byte length overflows usize"))?;
    *cursor = end;
    Ok(start..end)
}

const fn words_for_bits(bits: usize) -> usize {
    bits.div_ceil(u64::BITS as usize)
}

/// Minimal number of planes needed for codes in `0..domain_len`.
pub(crate) const fn alphabet_width(domain_len: usize) -> usize {
    let max_code = domain_len.saturating_sub(1);
    let width = usize::BITS as usize - max_code.leading_zeros() as usize;
    if width == 0 {
        1
    } else {
        width
    }
}

/// Writes one portable payload and validates its raw-layout invariants.
pub(crate) fn encode(parts: PortableParts<'_>) -> Result<Vec<u8>, PortableError> {
    let layout = Layout::new(parts.triple_count, parts.domain.len())?;

    for (axis, words) in PrefixAxis::ALL.into_iter().zip(parts.prefixes) {
        expect_words(axis.name(), words, layout.prefix_words)?;
    }
    for (axis, words) in ChangeAxis::ALL.into_iter().zip(parts.changes) {
        expect_words(axis.name(), words, layout.row_words)?;
    }
    let expected_wavelet_words = layout
        .row_words
        .checked_mul(layout.alphabet_width)
        .expect("layout already checked wavelet length");
    for (rotation, words) in Rotation::ALL.into_iter().zip(parts.wavelets) {
        expect_words(rotation.name(), words, expected_wavelet_words)?;
    }

    let triple_count = u64::try_from(parts.triple_count)
        .map_err(|_| PortableError::new("triple count does not fit u64"))?;
    let domain_len = u64::try_from(parts.domain.len())
        .map_err(|_| PortableError::new("domain cardinality does not fit u64"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.byte_len)
        .map_err(|_| PortableError::new("cannot allocate portable payload"))?;
    for value in parts.domain {
        bytes.extend_from_slice(value);
    }
    for words in parts.prefixes {
        push_words(&mut bytes, words);
    }
    for words in parts.changes {
        push_words(&mut bytes, words);
    }
    for words in parts.wavelets {
        push_words(&mut bytes, words);
    }
    push_word(&mut bytes, triple_count);
    push_word(&mut bytes, domain_len);
    debug_assert_eq!(bytes.len(), layout.byte_len);

    parse(&bytes)?;
    Ok(bytes)
}

/// Writes the canonical portable payload directly from one EAV-sorted row set.
///
/// This is the raw construction spine shared by source-format derivation and
/// future raw archive merges. `rows` contains archive-local ordered-domain
/// codes and must be a strictly increasing set in EAV order. The function
/// walks the other five Ring rotations through stable counting-sort passes:
///
/// ```text
/// EAV -> VEA -> AVE -> VAE -> EVA -> AEV
/// ```
///
/// All logical sections are written in place into the final portable byte
/// allocation. No native query arena, Rank9 directory, or second completed
/// portable buffer is constructed. Row codes and wavelet partition scratch
/// stay `u32`; the caller must reject wider domains before entering here.
pub(super) fn encode_canonical_eav_u32(
    domain: &[RawInline],
    rows: Vec<[u32; 3]>,
) -> Result<Vec<u8>, PortableError> {
    encode_canonical_eav_u32_using(
        domain,
        rows,
        &mut |bytes, layout, rotation, sequence, scratch| {
            write_wavelet(
                bytes,
                &layout.wavelets[rotation.index()],
                layout.alphabet_width,
                layout.row_words,
                sequence,
                scratch,
            );
            Ok(())
        },
    )
}

pub(super) fn encode_canonical_eav_u32_with_backend<B>(
    domain: &[RawInline],
    rows: Vec<[u32; 3]>,
    backend: &B,
) -> Result<Vec<u8>, PortableError>
where
    B: WaveletMatrixFreezeBackend,
    B::Error: fmt::Display,
{
    // Vec<u8> promises no u64 alignment. Use one reusable rotation-sized
    // allocation and serialize its words explicitly, without pointer casts or
    // host-endian assumptions. The other five output rotations stay in place.
    let mut packed = Vec::<u64>::new();
    encode_canonical_eav_u32_using(
        domain,
        rows,
        &mut |bytes, layout, rotation, sequence, scratch| {
            if layout.row_words == 0 {
                return Ok(());
            }
            let range = &layout.wavelets[rotation.index()];
            packed.resize(range.len() / WORD_LEN, 0);
            packed.fill(0);
            let rotation = match rotation {
                Rotation::Eav => SuccinctRotation::Eav,
                Rotation::Vea => SuccinctRotation::Vea,
                Rotation::Ave => SuccinctRotation::Ave,
                Rotation::Vae => SuccinctRotation::Vae,
                Rotation::Eva => SuccinctRotation::Eva,
                Rotation::Aev => SuccinctRotation::Aev,
            };
            {
                let mut planes: Vec<_> = packed.chunks_mut(layout.row_words).collect();
                backend
                    .freeze_rotation(rotation, layout.domain_len, sequence, &mut planes)
                    .map_err(|error| {
                        PortableError::new(format!("wavelet backend for {rotation:?}: {error}"))
                    })?;
            }
            // Validate our owned output, not slice references a backend could
            // have shortened or replaced while filling it.
            let planes: Vec<&[u64]> = packed.chunks(layout.row_words).collect();
            super::validate_wavelet_plane_prefix(sequence, &planes).map_err(|depth| {
                PortableError::new(format!(
                    "wavelet backend wrote invalid {rotation:?} prefix plane {depth}"
                ))
            })?;
            if !super::wavelet_tail_is_zero(sequence.len(), planes.iter().copied()) {
                return Err(PortableError::new(format!(
                    "wavelet backend wrote nonzero {rotation:?} padding"
                )));
            }
            for (destination, word) in bytes[range.clone()].chunks_exact_mut(WORD_LEN).zip(&packed)
            {
                destination.copy_from_slice(&word.to_le_bytes());
            }
            sequence.clear();
            scratch.clear();
            Ok(())
        },
    )
}

fn encode_canonical_eav_u32_using(
    domain: &[RawInline],
    mut rows: Vec<[u32; 3]>,
    freeze: &mut impl FnMut(
        &mut [u8],
        &Layout,
        Rotation,
        &mut Vec<u32>,
        &mut Vec<u32>,
    ) -> Result<(), PortableError>,
) -> Result<Vec<u8>, PortableError> {
    if domain.len() > u32::MAX as usize {
        return Err(PortableError::new(format!(
            "ordered domain contains {} values, exceeding u32 construction codes",
            domain.len()
        )));
    }
    if rows.len() > u32::MAX as usize {
        return Err(PortableError::new(format!(
            "archive contains {} rows, exceeding u32 construction offsets",
            rows.len()
        )));
    }
    if (rows.is_empty()) != (domain.is_empty()) {
        return Err(PortableError::new(
            "row set and ordered domain must be empty together",
        ));
    }
    for (code, pair) in domain.windows(2).enumerate() {
        if pair[0] >= pair[1] {
            return Err(PortableError::new(format!(
                "ordered domain is not strictly increasing at code {}",
                code + 1
            )));
        }
    }
    for (position, row) in rows.iter().enumerate() {
        if row.iter().any(|code| *code as usize >= domain.len()) {
            return Err(PortableError::new(format!(
                "EAV row {position} contains an out-of-domain code"
            )));
        }
        if id_from_value(&domain[row[0] as usize])
            .and_then(Id::new)
            .is_none()
            || id_from_value(&domain[row[1] as usize])
                .and_then(Id::new)
                .is_none()
        {
            return Err(PortableError::new(format!(
                "EAV row {position} contains a non-canonical entity or attribute ID"
            )));
        }
        if position != 0 && rows[position - 1] >= *row {
            return Err(PortableError::new(format!(
                "EAV rows are not strictly increasing at position {position}"
            )));
        }
    }

    let layout = Layout::new(rows.len(), domain.len())?;
    let triple_count = u64::try_from(rows.len())
        .map_err(|_| PortableError::new("triple count does not fit u64"))?;
    let domain_len = u64::try_from(domain.len())
        .map_err(|_| PortableError::new("domain cardinality does not fit u64"))?;
    let mut bytes = vec![0u8; layout.byte_len];
    for (code, value) in domain.iter().enumerate() {
        let start = layout.domain.start + code * RAW_INLINE_LEN;
        bytes[start..start + RAW_INLINE_LEN].copy_from_slice(value);
    }
    bytes[layout.count_footer.start..layout.count_footer.start + WORD_LEN]
        .copy_from_slice(&triple_count.to_le_bytes());
    bytes[layout.count_footer.start + WORD_LEN..layout.count_footer.end]
        .copy_from_slice(&domain_len.to_le_bytes());

    let mut row_scratch = Vec::with_capacity(rows.len());
    let mut radix_counts = vec![0u32; domain.len()];
    let mut sequence = Vec::with_capacity(rows.len());
    let mut sequence_scratch = Vec::with_capacity(rows.len());

    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [0, 1, 2],
        Some(PrefixAxis::Entity),
        ChangeAxis::EntityAttribute,
        Rotation::Eav,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;
    stable_sort_rows_by_component(&mut rows, &mut row_scratch, &mut radix_counts, 2)?;
    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [2, 0, 1],
        Some(PrefixAxis::Value),
        ChangeAxis::ValueEntity,
        Rotation::Vea,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;
    stable_sort_rows_by_component(&mut rows, &mut row_scratch, &mut radix_counts, 1)?;
    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [1, 2, 0],
        Some(PrefixAxis::Attribute),
        ChangeAxis::AttributeValue,
        Rotation::Ave,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;
    stable_sort_rows_by_component(&mut rows, &mut row_scratch, &mut radix_counts, 2)?;
    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [2, 1, 0],
        None,
        ChangeAxis::ValueAttribute,
        Rotation::Vae,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;
    stable_sort_rows_by_component(&mut rows, &mut row_scratch, &mut radix_counts, 0)?;
    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [0, 2, 1],
        None,
        ChangeAxis::EntityValue,
        Rotation::Eva,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;
    stable_sort_rows_by_component(&mut rows, &mut row_scratch, &mut radix_counts, 1)?;
    write_canonical_rotation(
        &mut bytes,
        &layout,
        &rows,
        [1, 0, 2],
        None,
        ChangeAxis::AttributeEntity,
        Rotation::Aev,
        &mut sequence,
        &mut sequence_scratch,
        freeze,
    )?;

    // The construction above owns every bit in the gapless layout. Keep a
    // debug-only structural oracle close to the writer without charging the
    // production build path for a second full scan and rank scratch.
    debug_assert!(parse(&bytes).is_ok());
    Ok(bytes)
}

fn stable_sort_rows_by_component(
    rows: &mut Vec<[u32; 3]>,
    scratch: &mut Vec<[u32; 3]>,
    counts: &mut [u32],
    component: usize,
) -> Result<(), PortableError> {
    counts.fill(0);
    for row in rows.iter() {
        let count = &mut counts[row[component] as usize];
        *count = count
            .checked_add(1)
            .ok_or_else(|| PortableError::new("rotation cardinality exceeds u32"))?;
    }

    let mut offset = 0u32;
    for count in counts.iter_mut() {
        let len = *count;
        *count = offset;
        offset = offset
            .checked_add(len)
            .ok_or_else(|| PortableError::new("rotation offset exceeds u32"))?;
    }
    if offset as usize != rows.len() {
        return Err(PortableError::new(
            "rotation counting sort did not cover every row",
        ));
    }

    scratch.resize(rows.len(), [0; 3]);
    for row in rows.iter().copied() {
        let destination = &mut counts[row[component] as usize];
        scratch[*destination as usize] = row;
        *destination += 1;
    }
    std::mem::swap(rows, scratch);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_canonical_rotation(
    bytes: &mut [u8],
    layout: &Layout,
    rows: &[[u32; 3]],
    components: [usize; 3],
    prefix_axis: Option<PrefixAxis>,
    change_axis: ChangeAxis,
    rotation: Rotation,
    sequence: &mut Vec<u32>,
    sequence_scratch: &mut Vec<u32>,
    freeze: &mut impl FnMut(
        &mut [u8],
        &Layout,
        Rotation,
        &mut Vec<u32>,
        &mut Vec<u32>,
    ) -> Result<(), PortableError>,
) -> Result<(), PortableError> {
    let [first_component, middle_component, last_component] = components;
    let mut previous_first = None;
    let mut previous_pair = None;
    sequence.clear();

    for (position, row) in rows.iter().enumerate() {
        let first = row[first_component] as usize;
        if let Some(axis) = prefix_axis {
            if previous_first != Some(first) {
                let start = previous_first.map_or(0, |last| last + 1);
                for code in start..=first {
                    set_range_bit(bytes, &layout.prefixes[axis.index()], position + code);
                }
                previous_first = Some(first);
            }
        }

        let pair = [row[first_component], row[middle_component]];
        if previous_pair != Some(pair) {
            set_range_bit(bytes, &layout.changes[change_axis.index()], position);
            previous_pair = Some(pair);
        }
        sequence.push(row[last_component]);
    }

    if let Some(axis) = prefix_axis {
        let start = previous_first.map_or(0, |last| last + 1);
        for code in start..=layout.domain_len {
            set_range_bit(
                bytes,
                &layout.prefixes[axis.index()],
                layout.triple_count + code,
            );
        }
    }

    freeze(bytes, layout, rotation, sequence, sequence_scratch)
}

fn write_wavelet(
    bytes: &mut [u8],
    range: &Range<usize>,
    width: usize,
    row_words: usize,
    sequence: &mut Vec<u32>,
    scratch: &mut Vec<u32>,
) {
    scratch.resize(sequence.len(), 0);
    for depth in 0..width {
        let shift = width - depth - 1;
        let plane = range.start + depth * row_words * WORD_LEN
            ..range.start + (depth + 1) * row_words * WORD_LEN;
        let mut zeros = 0usize;
        for (position, code) in sequence.iter().copied().enumerate() {
            if code & (1u32 << shift) == 0 {
                zeros += 1;
            } else {
                set_range_bit(bytes, &plane, position);
            }
        }

        if depth + 1 < width {
            let (mut zero, mut one) = (0usize, zeros);
            for code in sequence.iter().copied() {
                if code & (1u32 << shift) == 0 {
                    scratch[zero] = code;
                    zero += 1;
                } else {
                    scratch[one] = code;
                    one += 1;
                }
            }
            std::mem::swap(sequence, scratch);
        }
    }
    sequence.clear();
    scratch.clear();
}

fn set_range_bit(bytes: &mut [u8], range: &Range<usize>, position: usize) {
    debug_assert!(position / 8 < range.len());
    bytes[range.start + position / 8] |= 1u8 << (position % 8);
}

fn expect_words(name: &str, actual: &[u64], expected: usize) -> Result<(), PortableError> {
    if actual.len() == expected {
        Ok(())
    } else {
        Err(PortableError::new(format!(
            "{name} contains {} words, expected {expected}",
            actual.len()
        )))
    }
}

fn push_word(bytes: &mut Vec<u8>, word: u64) {
    bytes.extend_from_slice(&word.to_le_bytes());
}

fn push_words(bytes: &mut Vec<u8>, words: &[u64]) {
    for word in words {
        push_word(bytes, *word);
    }
}

/// Explicitly audits the local invariants of one portable payload.
///
/// Validation scans every raw section once, then checks the `D` possible codes
/// through `W(D)` rank steps per wavelet. Its temporary rank directories use
/// `O(W(D) * ceil(N/64))` words for one wavelet at a time. It proves the exact
/// gapless layout, ordered-domain and ID-role invariants, canonical unary
/// prefixes and bit tails, in-domain wavelet codes, and last-column
/// histograms. Full canonical equality is the subsequent explicit
/// `prove_canonical` audit. Ordinary readers use `parse_layout` instead.
pub(crate) fn parse(bytes: &[u8]) -> Result<PortableView<'_>, PortableError> {
    let layout = parse_layout(bytes)?;
    let mut view = PortableView {
        bytes,
        layout,
        prefix_counts: std::array::from_fn(|_| Vec::new()),
    };
    validate_domain(&view)?;
    view.prefix_counts = validate_prefixes(&view)?;
    validate_changes(&view)?;
    validate_wavelets(&view, &view.prefix_counts)?;
    Ok(view)
}

/// Exact framing and checked section ranges, without reading section contents.
pub(super) fn parse_layout(bytes: &[u8]) -> Result<Layout, PortableError> {
    if bytes.len() < COUNT_FOOTER_LEN {
        return Err(PortableError::new(format!(
            "count footer is truncated: found {} bytes, need {COUNT_FOOTER_LEN}",
            bytes.len()
        )));
    }
    let footer_start = bytes.len() - COUNT_FOOTER_LEN;
    let triple_count = usize::try_from(read_count_word(bytes, footer_start))
        .map_err(|_| PortableError::new("triple count does not fit usize"))?;
    let domain_len = usize::try_from(read_count_word(bytes, footer_start + WORD_LEN))
        .map_err(|_| PortableError::new("domain cardinality does not fit usize"))?;
    let layout = Layout::new(triple_count, domain_len)?;
    if bytes.len() != layout.byte_len {
        return Err(PortableError::new(format!(
            "payload has {} bytes, canonical layout requires {}",
            bytes.len(),
            layout.byte_len
        )));
    }
    debug_assert_eq!(layout.count_footer.start, footer_start);

    Ok(layout)
}

/// Reads the unary group sizes needed to rotate EAV rows during MERGE.
/// This is decoding the chosen source ring, not auditing secondary indexes.
pub(super) fn decode_eav(bytes: &[u8]) -> Result<CanonicalEavU32, PortableError> {
    let layout = parse_layout(bytes)?;
    if layout.triple_count > u32::MAX as usize || layout.domain_len > u32::MAX as usize {
        return Err(PortableError::new(
            "raw MERGE input exceeds the u32 code/row domain",
        ));
    }
    let mut view = PortableView {
        bytes,
        layout,
        prefix_counts: std::array::from_fn(|_| Vec::new()),
    };
    // The source rotation needs these counts; unrelated masks/columns stay unread.
    view.prefix_counts = decode_prefixes(&view)?;
    view.decode_eav_u32()
}

fn read_count_word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + WORD_LEN]
            .try_into()
            .expect("checked count-footer range"),
    )
}

fn read_word(bytes: &[u8], range: &Range<usize>, word: usize) -> u64 {
    let start = range.start + word * WORD_LEN;
    debug_assert!(start + WORD_LEN <= range.end);
    u64::from_le_bytes(
        bytes[start..start + WORD_LEN]
            .try_into()
            .expect("validated word range"),
    )
}

fn bit(bytes: &[u8], range: &Range<usize>, position: usize) -> bool {
    read_word(bytes, range, position / u64::BITS as usize) & (1 << (position % u64::BITS as usize))
        != 0
}

fn validate_domain(view: &PortableView<'_>) -> Result<(), PortableError> {
    for code in 1..view.layout.domain_len {
        if view.domain_value(code - 1) >= view.domain_value(code) {
            return Err(PortableError::new(format!(
                "ordered domain is not strictly increasing at code {code}"
            )));
        }
    }
    if (view.layout.triple_count == 0) != (view.layout.domain_len == 0) {
        return Err(PortableError::new(
            "triple count and domain cardinality must be empty together",
        ));
    }
    Ok(())
}

fn decode_prefixes(view: &PortableView<'_>) -> Result<[Vec<usize>; PREFIX_COUNT], PortableError> {
    let mut axis_counts = Vec::with_capacity(PREFIX_COUNT);
    for axis in PrefixAxis::ALL {
        let range = &view.layout.prefixes[axis.index()];
        let mut counts = vec![0usize; view.layout.domain_len];
        let mut separators = 0usize;
        for position in 0..view.layout.prefix_bits {
            if bit(view.bytes, range, position) {
                separators += 1;
                if separators > view.layout.domain_len + 1 {
                    return Err(PortableError::new(format!(
                        "{} has too many separators",
                        axis.name()
                    )));
                }
            } else if separators == 0 {
                return Err(PortableError::new(format!(
                    "{} does not start with a separator",
                    axis.name()
                )));
            } else if separators > view.layout.domain_len {
                return Err(PortableError::new(format!(
                    "{} contains rows after its final separator",
                    axis.name()
                )));
            } else {
                counts[separators - 1] += 1;
            }
        }
        if separators != view.layout.domain_len + 1 {
            return Err(PortableError::new(format!(
                "{} contains {separators} separators, expected {}",
                axis.name(),
                view.layout.domain_len + 1
            )));
        }
        axis_counts.push(counts);
    }

    Ok(axis_counts.try_into().expect("three prefix axes"))
}

fn validate_prefixes(view: &PortableView<'_>) -> Result<[Vec<usize>; PREFIX_COUNT], PortableError> {
    let axis_counts = decode_prefixes(view)?;
    for axis in PrefixAxis::ALL {
        validate_tail(
            view.bytes,
            &view.layout.prefixes[axis.index()],
            view.layout.prefix_bits,
            axis.name(),
        )?;
    }
    for (code, ((entity_uses, attribute_uses), value_uses)) in axis_counts
        [PrefixAxis::Entity.index()]
    .iter()
    .zip(&axis_counts[PrefixAxis::Attribute.index()])
    .zip(&axis_counts[PrefixAxis::Value.index()])
    .enumerate()
    {
        if *entity_uses == 0 && *attribute_uses == 0 && *value_uses == 0 {
            return Err(PortableError::new(format!(
                "ordered-domain code {code} is unused"
            )));
        }
        if *entity_uses != 0 || *attribute_uses != 0 {
            let value = view.domain_value(code);
            let valid_id = id_from_value(&value).and_then(Id::new).is_some();
            if !valid_id {
                return Err(PortableError::new(format!(
                    "ordered-domain code {code} is not a canonical non-nil ID"
                )));
            }
        }
    }
    Ok(axis_counts)
}

fn validate_changes(view: &PortableView<'_>) -> Result<(), PortableError> {
    for axis in ChangeAxis::ALL {
        let range = &view.layout.changes[axis.index()];
        validate_tail(view.bytes, range, view.layout.triple_count, axis.name())?;
        if view.layout.triple_count != 0 && !bit(view.bytes, range, 0) {
            return Err(PortableError::new(format!(
                "{} does not mark its first row",
                axis.name()
            )));
        }
    }
    Ok(())
}

fn validate_wavelets(
    view: &PortableView<'_>,
    prefix_counts: &[Vec<usize>; PREFIX_COUNT],
) -> Result<(), PortableError> {
    for rotation in Rotation::ALL {
        let range = &view.layout.wavelets[rotation.index()];
        for depth in 0..view.layout.alphabet_width {
            let plane_start = range.start + depth * view.layout.row_words * WORD_LEN;
            let plane_end = plane_start + view.layout.row_words * WORD_LEN;
            validate_tail(
                view.bytes,
                &(plane_start..plane_end),
                view.layout.triple_count,
                rotation.name(),
            )?;
        }

        let histogram = wavelet_histogram(view, rotation);
        let axis = rotation.last_axis();
        if histogram != prefix_counts[axis.index()] {
            return Err(PortableError::new(format!(
                "{} last-column histogram disagrees with {}",
                rotation.name(),
                axis.name()
            )));
        }
    }
    Ok(())
}

fn wavelet_histogram(view: &PortableView<'_>, rotation: Rotation) -> Vec<usize> {
    let wavelet = PortableWavelet::new(view, rotation);
    (0..view.layout.domain_len)
        .map(|code| {
            wavelet
                .rank(view.layout.triple_count, code)
                .expect("code belongs to the validated domain")
        })
        .collect()
}

fn validate_tail(
    bytes: &[u8],
    range: &Range<usize>,
    bit_len: usize,
    name: &str,
) -> Result<(), PortableError> {
    let remainder = bit_len % u64::BITS as usize;
    if remainder == 0 {
        return Ok(());
    }
    let word_count = words_for_bits(bit_len);
    let last = read_word(bytes, range, word_count - 1);
    let used_mask = (1u64 << remainder) - 1;
    if last & !used_mask != 0 {
        Err(PortableError::new(format!(
            "{name} has non-zero unused high bits"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::blob::encodings::UnknownBlob;
    use crate::blob::{Blob, Bytes, MemoryBlobStore};
    use crate::repo::{BlobChildren, SnapshotSource};

    const ID_ONE: RawInline =
        hex!("0000000000000000000000000000000000000000000000000000000000000001");
    const ID_TWO: RawInline =
        hex!("0000000000000000000000000000000000000000000000000000000000000002");
    const VALUE_ONE: RawInline =
        hex!("0100000000000000000000000000000000000000000000000000000000000000");
    const ID_THREE: RawInline =
        hex!("0000000000000000000000000000000000000000000000000000000000000003");
    const ID_FOUR: RawInline =
        hex!("0000000000000000000000000000000000000000000000000000000000000004");

    const EMPTY_GOLDEN: [u8; 40] = hex!(
        "010000000000000001000000000000000100000000000000"
        "00000000000000000000000000000000"
    );
    const SINGLETON_GOLDEN: [u8; 280] = hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0100000000000000000000000000000000000000000000000000000000000000"
        "1d000000000000001b000000000000001700000000000000"
        "010000000000000001000000000000000100000000000000"
        "010000000000000001000000000000000100000000000000"
        "01000000000000000000000000000000"
        "00000000000000000100000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000100000000000000"
        "01000000000000000000000000000000"
        "01000000000000000300000000000000"
    );
    const MULTI_GOLDEN: [u8; 312] = hex!(
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000002"
        "0000000000000000000000000000000000000000000000000000000000000003"
        "0000000000000000000000000000000000000000000000000000000000000004"
        "6d000000000000005d000000000000006b00000000000000"
        "030000000000000003000000000000000300000000000000"
        "030000000000000003000000000000000300000000000000"
        "01000000000000000100000000000000"
        "02000000000000000200000000000000"
        "01000000000000000000000000000000"
        "01000000000000000000000000000000"
        "01000000000000000200000000000000"
        "02000000000000000100000000000000"
        "02000000000000000400000000000000"
    );

    #[test]
    fn width_is_minimal_for_cardinality() {
        let cases = [
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 2),
            (255, 8),
            (256, 8),
            (257, 9),
        ];
        for (domain_len, expected) in cases {
            assert_eq!(alphabet_width(domain_len), expected, "D={domain_len}");
        }
    }

    #[test]
    fn empty_archive_has_exact_canonical_bytes() {
        let encoded = encode(PortableParts {
            triple_count: 0,
            domain: &[],
            prefixes: [&[1], &[1], &[1]],
            changes: [&[]; CHANGE_COUNT],
            wavelets: [&[]; WAVELET_COUNT],
        })
        .unwrap();
        assert_eq!(encoded, EMPTY_GOLDEN);
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "2a5c88cdcc7a9df5e0815cadb233b5dcf192e7c21e8393afc681c940ab7aa0dd"
        );
        let decoded = parse(&EMPTY_GOLDEN).unwrap();
        assert_eq!(decoded.layout.triple_count, 0);
        assert_eq!(decoded.layout.domain_len, 0);
        assert_eq!(decoded.layout.alphabet_width, 1);
    }

    #[test]
    fn singleton_archive_has_exact_canonical_bytes() {
        let encoded = encode(PortableParts {
            triple_count: 1,
            domain: &[ID_ONE, ID_TWO, VALUE_ONE],
            prefixes: [&[0x1d], &[0x1b], &[0x17]],
            changes: [&[1]; CHANGE_COUNT],
            wavelets: [&[1, 0], &[0, 1], &[0, 0], &[0, 0], &[0, 1], &[1, 0]],
        })
        .unwrap();
        assert_eq!(encoded, SINGLETON_GOLDEN);
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "c55fa61e822974f3cb0e5b2d156dbf35b0e5bbb7599595209e6672ec91d8b8c1"
        );
        let decoded = parse(&SINGLETON_GOLDEN).unwrap();
        assert_eq!(decoded.layout.triple_count, 1);
        assert_eq!(decoded.layout.domain_len, 3);
        assert_eq!(decoded.layout.alphabet_width, 2);
        assert_eq!(decoded.domain_value(2), VALUE_ONE);
    }

    #[test]
    fn multi_row_archive_has_exact_canonical_bytes() {
        let encoded = encode(PortableParts {
            triple_count: 2,
            domain: &[ID_ONE, ID_TWO, ID_THREE, ID_FOUR],
            prefixes: [&[0x6d], &[0x5d], &[0x6b]],
            changes: [&[3]; CHANGE_COUNT],
            wavelets: [&[1, 1], &[2, 2], &[1, 0], &[1, 0], &[1, 2], &[2, 1]],
        })
        .unwrap();
        assert_eq!(encoded, MULTI_GOLDEN);
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            "a2ea03cd06c60f36762dee4a65add3cfa84545f55ab0a717f924333183691aee"
        );
        let decoded = parse(&MULTI_GOLDEN).unwrap();
        assert_eq!(decoded.layout.triple_count, 2);
        assert_eq!(decoded.layout.domain_len, 4);
        assert_eq!(decoded.layout.alphabet_width, 2);
        assert_eq!(decoded.wavelet_word(Rotation::Eav, 1, 0), 1);
    }

    #[test]
    fn rejects_wrong_lengths_and_trailing_bytes() {
        assert!(parse(&EMPTY_GOLDEN[..COUNT_FOOTER_LEN - 1]).is_err());
        assert!(parse(&EMPTY_GOLDEN[..EMPTY_GOLDEN.len() - 1]).is_err());
        let mut trailing = EMPTY_GOLDEN.to_vec();
        trailing.push(0);
        assert!(parse(&trailing).is_err());

        let mut overflowing = EMPTY_GOLDEN.to_vec();
        let domain_count = overflowing.len() - WORD_LEN;
        overflowing[domain_count..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(&overflowing).is_err());
    }

    #[test]
    fn rejects_noncanonical_domain_and_prefixes() {
        let mut duplicate_domain = SINGLETON_GOLDEN.to_vec();
        duplicate_domain[RAW_INLINE_LEN..2 * RAW_INLINE_LEN].copy_from_slice(&ID_ONE);
        assert!(parse(&duplicate_domain).is_err());

        let mut nil_entity = SINGLETON_GOLDEN.to_vec();
        nil_entity[..RAW_INLINE_LEN].fill(0);
        assert!(parse(&nil_entity).is_err());

        let layout = Layout::new(1, 3).unwrap();
        let mut bad_prefix = SINGLETON_GOLDEN.to_vec();
        bad_prefix[layout.prefixes[0].start] = 0;
        assert!(parse(&bad_prefix).is_err());

        let mut dirty_tail = SINGLETON_GOLDEN.to_vec();
        let prefix = &layout.prefixes[0];
        dirty_tail[prefix.start + 7] |= 0x80;
        assert!(parse(&dirty_tail).is_err());
    }

    #[test]
    fn rejects_noncanonical_changes_and_wavelets() {
        let layout = Layout::new(1, 3).unwrap();

        let mut unmarked_first_row = SINGLETON_GOLDEN.to_vec();
        unmarked_first_row[layout.changes[0].start] = 0;
        assert!(parse(&unmarked_first_row).is_err());

        let mut dirty_change_tail = SINGLETON_GOLDEN.to_vec();
        dirty_change_tail[layout.changes[0].start + 7] |= 0x80;
        assert!(parse(&dirty_change_tail).is_err());

        let mut out_of_domain = SINGLETON_GOLDEN.to_vec();
        let eav = &layout.wavelets[Rotation::Eav.index()];
        out_of_domain[eav.start + WORD_LEN] = 1;
        assert!(parse(&out_of_domain).is_err());

        let mut wrong_histogram = SINGLETON_GOLDEN.to_vec();
        wrong_histogram[eav.start] = 0;
        wrong_histogram[eav.start + WORD_LEN] = 1;
        assert!(parse(&wrong_histogram).is_err());

        let mut dirty_wavelet_tail = SINGLETON_GOLDEN.to_vec();
        dirty_wavelet_tail[eav.start + 7] |= 0x80;
        assert!(parse(&dirty_wavelet_tail).is_err());
    }

    #[test]
    fn writer_rejects_noncanonical_section_shapes() {
        let error = encode(PortableParts {
            triple_count: 0,
            domain: &[],
            prefixes: [&[], &[1], &[1]],
            changes: [&[]; CHANGE_COUNT],
            wavelets: [&[]; WAVELET_COUNT],
        })
        .unwrap_err();
        assert!(error.to_string().contains("entity prefix contains 0 words"));
    }

    #[test]
    fn rank_validation_crosses_words_and_stable_partitions() {
        let domain: Vec<RawInline> = (1..=5)
            .map(|last| {
                let mut value = [0; RAW_INLINE_LEN];
                value[RAW_INLINE_LEN - 1] = last;
                value
            })
            .collect();
        // 57..59 put the prefix length N+D+1 across 63/64/65; 63..65
        // independently exercise row-vector boundaries.
        for len in [57, 58, 59, 63, 64, 65, 130] {
            let sequence: Vec<usize> = (0..len).map(|position| (position * 3 + 2) % 5).collect();
            let mut counts = vec![0usize; domain.len()];
            for code in &sequence {
                counts[*code] += 1;
            }
            let prefix = prefix_words(&counts);
            let changed_bits = vec![true; sequence.len()];
            let changed = packed_bits(&changed_bits);
            let wavelet = wavelet_words(&sequence, alphabet_width(domain.len()));

            let bytes = encode(PortableParts {
                triple_count: sequence.len(),
                domain: &domain,
                prefixes: [prefix.as_slice(); PREFIX_COUNT],
                changes: [changed.as_slice(); CHANGE_COUNT],
                wavelets: [wavelet.as_slice(); WAVELET_COUNT],
            })
            .unwrap();
            let view = parse(&bytes).unwrap();
            assert_eq!(view.layout.triple_count, len);
            assert_eq!(view.layout.alphabet_width, 3);
        }
    }

    #[test]
    fn ordered_domain_participates_in_conservative_child_scanning() {
        let child = Blob::<UnknownBlob>::new(Bytes::from(b"portable child".to_vec()));
        let child_handle = child.get_handle();
        let mut domain = vec![ID_ONE, ID_TWO, child_handle.raw];
        domain.sort_unstable();
        domain.dedup();
        assert_eq!(domain.len(), 3);

        let entity_code = domain.binary_search(&ID_ONE).unwrap();
        let attribute_code = domain.binary_search(&ID_TWO).unwrap();
        let value_code = domain.binary_search(&child_handle.raw).unwrap();
        let prefix_storage = [
            singleton_prefix(domain.len(), entity_code),
            singleton_prefix(domain.len(), attribute_code),
            singleton_prefix(domain.len(), value_code),
        ];
        let last_codes = [
            value_code,
            attribute_code,
            entity_code,
            entity_code,
            attribute_code,
            value_code,
        ];
        let wavelet_storage: Vec<Vec<u64>> = last_codes
            .into_iter()
            .map(|code| wavelet_words(&[code], alphabet_width(domain.len())))
            .collect();
        let changed = [1u64];
        let bytes = encode(PortableParts {
            triple_count: 1,
            domain: &domain,
            prefixes: std::array::from_fn(|axis| prefix_storage[axis].as_slice()),
            changes: [changed.as_slice(); CHANGE_COUNT],
            wavelets: std::array::from_fn(|rotation| wavelet_storage[rotation].as_slice()),
        })
        .unwrap();
        for code in 0..domain.len() {
            assert_eq!(code * RAW_INLINE_LEN % crate::inline::INLINE_LEN, 0);
            assert_eq!(
                bytes[code * RAW_INLINE_LEN..(code + 1) * RAW_INLINE_LEN],
                domain[code]
            );
        }

        let parent = Blob::<UnknownBlob>::new(Bytes::from(bytes));
        let parent_handle = parent.get_handle();
        let mut store = MemoryBlobStore::new();
        store.insert(child);
        store.insert(parent);
        let reader = store.snapshot().unwrap();
        assert!(reader.children(parent_handle).contains(&child_handle));
    }

    fn prefix_words(counts: &[usize]) -> Vec<u64> {
        let mut bits = Vec::with_capacity(counts.iter().sum::<usize>() + counts.len() + 1);
        for count in counts {
            bits.push(true);
            bits.extend(std::iter::repeat_n(false, *count));
        }
        bits.push(true);
        packed_bits(&bits)
    }

    fn singleton_prefix(domain_len: usize, code: usize) -> Vec<u64> {
        let mut counts = vec![0usize; domain_len];
        counts[code] = 1;
        prefix_words(&counts)
    }

    fn wavelet_words(sequence: &[usize], width: usize) -> Vec<u64> {
        let mut current = sequence.to_vec();
        let mut result = Vec::with_capacity(width * words_for_bits(sequence.len()));
        for depth in 0..width {
            let shift = width - depth - 1;
            let bits: Vec<bool> = current
                .iter()
                .map(|value| value & (1usize << shift) != 0)
                .collect();
            result.extend(packed_bits(&bits));
            let mut next = Vec::with_capacity(current.len());
            next.extend(
                current
                    .iter()
                    .copied()
                    .filter(|value| value & (1 << shift) == 0),
            );
            next.extend(
                current
                    .iter()
                    .copied()
                    .filter(|value| value & (1 << shift) != 0),
            );
            current = next;
        }
        result
    }

    fn packed_bits(bits: &[bool]) -> Vec<u64> {
        let mut words = vec![0u64; words_for_bits(bits.len())];
        for (position, bit) in bits.iter().copied().enumerate() {
            if bit {
                words[position / u64::BITS as usize] |= 1 << (position % u64::BITS as usize);
            }
        }
        words
    }
}
