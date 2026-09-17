use crate::query::Frontier;
use std::ops::Not;
use std::ops::Range;

use smallvec::SmallVec;

use super::*;
use crate::inline::encodings::genid::GenId;
use crate::query::Candidates;
use crate::query::ProposalBuffer;
use crate::query::*;
use jerky::bit_vector::Select;

/// Batch size at which this source stops probing in frontier order and
/// probes in **index order** instead.
///
/// A batched `propose`/`confirm` is N archive lookups for N parent
/// bindings, and every one of them opens by translating a value into a
/// domain code — [`Universe::search`], a binary search over the whole
/// domain, then a `select1` on the axis bit vector. Ordering them by key
/// buys two things:
///
/// * **Duplicate keys collapse.** Several frontier rows routinely
///   project to the *same* key — a join whose parents fan in, or a
///   pattern with no bound position, where every row's key is empty and
///   the loop re-walked the whole rotation once per row. Sorted, those
///   rows are adjacent, so the archive is walked once and the result
///   fanned out to each row's own segment; and in `confirm` one
///   `base_range` covers the whole group instead of one per parent.
///   This is the half that pays, and it pays a lot.
/// * **Locality.** The domain is sorted on exactly the bytes being
///   searched for, so consecutive searches share their upper levels.
///   Measured, this half is worth little — see [`SORTED_REGION_MIN`],
///   which is the same idea applied where there is far more of it to do,
///   and which is off.
///
/// The two halves have different economics, so they have their own
/// thresholds. Ordering the *rows* costs `O(rows log rows)` — bounded by
/// the frontier width — and buys the collapses above, which are savings
/// in work rather than in cache misses. Ordering a *region* costs
/// `O(candidates log candidates)`, which is unbounded by the frontier
/// and buys only locality: it is worth it exactly when a probe is
/// expensive enough to amortise a comparison.
///
/// This pair is the whole boundary between the two strategies: both
/// paths run the same code over a permutation of the batch and differ
/// solely in whether that permutation is sorted. Set either to
/// `usize::MAX` to measure that half as the plain frontier-order loop.
///
/// On for this source, and the larger of the two effects by far: over a
/// 2M-trible DBLP archive the collapses are worth 2.6x on the arm's
/// widest-result join, 27% on a type/signature join and 20% on a
/// three-way star. A batched frontier fans in hard — many parents reach
/// the same hub — and without this each of them re-walked the archive
/// for an answer it had already computed.
const SORTED_PROBE_MIN: usize = 2;

/// Region size at which `confirm` orders its candidates by value rather
/// than walking the region as it lies. See [`SORTED_PROBE_MIN`] for what
/// the ordering buys.
///
/// **Off, and measured off in both sources.** The idea is sound — the
/// archive's domain and the PATCH's leaves are both laid out in value
/// order, so probing a region in value order should sweep them — but as
/// written it does not pay anywhere: within 3% on every archive query at
/// 4M and at 8M tribles, and 33-46% *worse* on the Harkonnen fixtures
/// whose regions are large enough to sort (F9, F11, F14).
///
/// The reason looks structural rather than incidental, which is why the
/// switch is off rather than tuned: sorting a region means sorting an
/// index permutation, and the comparator then gathers from `parents`
/// and the values through those indices. Both arrays are region-sized,
/// so at exactly the width where the ordering was supposed to earn its
/// keep, the sort itself misses cache once or twice per comparison —
/// and it does that `n log n` times to save `n` probes. A version worth
/// re-measuring would sort *packed keys* (a `(group, value-prefix,
/// index)` record) so the sort streams instead of gathering, or would
/// leave the ordering to a tier that wants the region sorted anyway.
///
/// The row ordering above is a different trade and is on: it sorts at
/// most `frontier width` entries and saves whole index walks rather
/// than cache misses.
const SORTED_REGION_MIN: usize = usize::MAX;

/// Live candidates at or above which a range confirm collects independent
/// wavelet probes and descends them layer-major.
///
/// Small confirms stay allocation-free. Jerky uses the same floor inside its
/// batched entry point; keeping it here avoids building scratch for a call
/// that Jerky would answer with its scalar loop anyway.
const MIN_BATCHED_CONFIRM: usize = 8;

/// Distinct adjacent values carried through one batched wavelet descent.
///
/// A frontier region can contain hundreds of thousands of candidates. This
/// bound keeps the caller's scratch in tens of KiB while remaining much wider
/// than the memory system can keep in flight. Runs of equal live values are
/// never cut at this boundary, so the existing adjacent-value reuse survives.
const CONFIRM_CHUNK: usize = 1024;

/// Kills every entry named by `order` whose value fails `keep`, skipping
/// entries that are already dead — [`Candidates::retain`] over a
/// permutation instead of the region's own order.
///
/// The verdict is memoised across *adjacent equal values*, which costs
/// one 32-byte compare and saves a domain binary search: a key-run
/// fanned out over several frontier rows carries each candidate once per
/// row, and sorted they arrive back to back.
#[inline]
fn retain_at(cands: &mut Candidates<'_>, order: &[u32], mut keep: impl FnMut(&RawInline) -> bool) {
    let mut memo: Option<(RawInline, bool)> = None;
    for &i in order {
        let i = i as usize;
        if !cands.is_live(i) {
            continue;
        }
        let value = cands.values()[i];
        let verdict = match memo {
            Some((seen, verdict)) if seen == value => verdict,
            _ => {
                let verdict = keep(&value);
                memo = Some((value, verdict));
                verdict
            }
        };
        if !verdict {
            cands.kill(i);
        }
    }
}

/// Kills the candidates named by `order` that do not occur in row range `r`
/// of wavelet column `column`.
///
/// This is deliberately narrower than [`restrict_range`]. A confirm only
/// asks whether the restricted range is empty, so its prefix-bitvector base
/// cancels and `rank_range` carries both endpoints through one wavelet descent
/// instead of performing two ranks plus a select. For a sufficiently wide
/// run the independent descents are issued layer-major through Jerky's batch
/// API, exposing memory-level parallelism without changing the frontier or
/// accelerator routing.
///
/// `order` is the current probe group's permutation. Runs are formed over its
/// live subsequence, exactly like [`retain_at`]: dead entries neither revive
/// nor break adjacent duplicate reuse. A batch boundary is placed only after
/// a complete run, and verdicts are fanned back over that run's original
/// candidate indices.
fn retain_occurring_at<U>(
    domain: &U,
    column: &WaveletMatrix<SuccinctIndex>,
    r: &Range<usize>,
    cands: &mut Candidates<'_>,
    order: &[u32],
) where
    U: Universe,
{
    if r.is_empty() {
        for &candidate in order {
            let candidate = candidate as usize;
            if cands.is_live(candidate) {
                cands.kill(candidate);
            }
        }
        return;
    }

    let live = order
        .iter()
        .filter(|&&candidate| cands.is_live(candidate as usize))
        .count();
    if live < MIN_BATCHED_CONFIRM {
        retain_at(cands, order, |value| {
            let Some(code) = domain.search(value) else {
                return false;
            };
            column
                .rank_range(r.clone(), code)
                .expect("archive-derived row range stays inside its wavelet column")
                != 0
        });
        return;
    }

    #[derive(Clone, Copy)]
    struct Run {
        start: usize,
        end: usize,
        probe: Option<usize>,
    }

    let cap = live.min(CONFIRM_CHUNK);
    let mut runs = Vec::with_capacity(cap);
    let mut codes = Vec::with_capacity(cap);
    let mut ranks = vec![None; cap];
    let mut cursor = 0usize;

    while cursor < order.len() {
        runs.clear();
        codes.clear();

        while cursor < order.len() && runs.len() < cap {
            while cursor < order.len() && !cands.is_live(order[cursor] as usize) {
                cursor += 1;
            }
            if cursor == order.len() {
                break;
            }

            let start = cursor;
            let value = cands.values()[order[cursor] as usize];
            cursor += 1;
            while cursor < order.len() {
                let candidate = order[cursor] as usize;
                if !cands.is_live(candidate) {
                    cursor += 1;
                    continue;
                }
                if cands.values()[candidate] != value {
                    break;
                }
                cursor += 1;
            }

            let probe = domain.search(&value).map(|code| {
                let slot = codes.len();
                codes.push(code);
                slot
            });
            runs.push(Run {
                start,
                end: cursor,
                probe,
            });
        }

        if !codes.is_empty() {
            column
                .rank_range_batch_into(r.clone(), &codes, &mut ranks[..codes.len()])
                .expect("probe and verdict slices are built with equal lengths");
        }

        for run in &runs {
            let keep = match run.probe {
                Some(slot) => {
                    ranks[slot].expect("archive-derived row range stays inside its wavelet column")
                        != 0
                }
                None => false,
            };
            if !keep {
                for &candidate in &order[run.start..run.end] {
                    let candidate = candidate as usize;
                    if cands.is_live(candidate) {
                        cands.kill(candidate);
                    }
                }
            }
        }
    }
}

pub struct SuccinctArchiveConstraint<'a, U>
where
    U: Universe,
{
    term_e: RawTerm,
    term_a: RawTerm,
    term_v: RawTerm,
    archive: &'a SuccinctArchive<U>,
}

impl<'a, U> Clone for SuccinctArchiveConstraint<'a, U>
where
    U: Universe,
{
    fn clone(&self) -> Self {
        SuccinctArchiveConstraint {
            term_e: self.term_e,
            term_a: self.term_a,
            term_v: self.term_v,
            archive: self.archive,
        }
    }
}

impl<'a, U> SuccinctArchiveConstraint<'a, U>
where
    U: Universe,
{
    pub fn new<V: InlineEncoding>(
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
        archive: &'a SuccinctArchive<U>,
    ) -> Self {
        SuccinctArchiveConstraint {
            term_e: e.into().erase(),
            term_a: a.into().erase(),
            term_v: v.into().erase(),
            archive,
        }
    }
}

pub(super) fn base_range<U>(
    universe: &U,
    a: &BitVector<SuccinctIndex>,
    value: &RawInline,
) -> Range<usize>
where
    U: Universe,
{
    if let Some(d) = universe.search(value) {
        let s = a.select1(d).unwrap() - d;
        let e = a.select1(d + 1).unwrap() - (d + 1);
        s..e
    } else {
        0..0
    }
}

fn restrict_range<U>(
    universe: &U,
    a: &BitVector<SuccinctIndex>,
    c: &WaveletMatrix<SuccinctIndex>,
    value: &RawInline,
    r: &Range<usize>,
) -> Range<usize>
where
    U: Universe,
{
    let s = r.start;
    let e = r.end;
    if let Some(d) = universe.search(value) {
        let base = a.select1(d).unwrap() - d;
        let s_ = base + c.rank(s, d).unwrap();
        let e_ = base + c.rank(e, d).unwrap();
        s_..e_
    } else {
        0..0
    }
}

impl<'a, U> SuccinctArchiveConstraint<'a, U>
where
    U: Universe,
{
    fn propose_row(&self, variable: VariableId, binding: &Binding, proposals: &mut ProposalBuffer) {
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return;
        }

        let e_bound = self.term_e.position_value(binding);
        let a_bound = self.term_a.position_value(binding);
        let v_bound = self.term_v.position_value(binding);

        match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            (None, None, None, true, false, false) => {
                proposals.extend(self.archive.enumerate_domain(&self.archive.e_a))
            }
            (None, None, None, false, true, false) => {
                proposals.extend(self.archive.enumerate_domain(&self.archive.a_a))
            }
            (None, None, None, false, false, true) => {
                proposals.extend(self.archive.enumerate_domain(&self.archive.v_a))
            }
            (Some(e), None, None, false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_e_a,
                            &r,
                            &self.archive.eav_c,
                            &self.archive.v_a,
                        )
                        .map(|i| self.archive.vea_c.access(i).unwrap())
                        .map(|a| self.archive.domain.access(a)),
                )
            }
            (Some(e), None, None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_e_v,
                            &r,
                            &self.archive.eva_c,
                            &self.archive.a_a,
                        )
                        .map(|i| self.archive.aev_c.access(i).unwrap())
                        .map(|v| self.archive.domain.access(v)),
                )
            }

            (None, Some(a), None, true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_a_e,
                            &r,
                            &self.archive.aev_c,
                            &self.archive.v_a,
                        )
                        .map(|i| self.archive.vae_c.access(i).unwrap())
                        .map(|e| self.archive.domain.access(e)),
                )
            }
            (None, Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_a_v,
                            &r,
                            &self.archive.ave_c,
                            &self.archive.e_a,
                        )
                        .map(|i| self.archive.eav_c.access(i).unwrap())
                        .map(|v| self.archive.domain.access(v)),
                )
            }

            (None, None, Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_v_e,
                            &r,
                            &self.archive.vea_c,
                            &self.archive.a_a,
                        )
                        .map(|i| self.archive.ave_c.access(i).unwrap())
                        .map(|e| self.archive.domain.access(e)),
                )
            }
            (None, None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                proposals.extend(
                    self.archive
                        .enumerate_in(
                            &self.archive.changed_v_a,
                            &r,
                            &self.archive.vae_c,
                            &self.archive.e_a,
                        )
                        .map(|i| self.archive.eva_c.access(i).unwrap())
                        .map(|a| self.archive.domain.access(a)),
                )
            }
            (None, Some(a), Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                proposals.extend(
                    restrict_range(
                        &self.archive.domain,
                        &self.archive.v_a,
                        &self.archive.aev_c,
                        v,
                        &r,
                    )
                    .map(|e| self.archive.vae_c.access(e).unwrap())
                    .unique()
                    .map(|e| self.archive.domain.access(e)),
                )
            }
            (Some(e), None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                proposals.extend(
                    restrict_range(
                        &self.archive.domain,
                        &self.archive.v_a,
                        &self.archive.eav_c,
                        v,
                        &r,
                    )
                    .map(|a| self.archive.vea_c.access(a).unwrap())
                    .unique()
                    .map(|a| self.archive.domain.access(a)),
                )
            }
            (Some(e), Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                proposals.extend(
                    restrict_range(
                        &self.archive.domain,
                        &self.archive.a_a,
                        &self.archive.eva_c,
                        a,
                        &r,
                    )
                    .map(|v| self.archive.aev_c.access(v).unwrap())
                    .unique()
                    .map(|v| self.archive.domain.access(v)),
                )
            }
            _ => unreachable!(),
        }
    }

    /// Kills the entries `order` names — indices into `cands` — whose
    /// value is inconsistent with `binding`.
    ///
    /// `order` is a permutation of some part of the region rather than a
    /// range, because the region spans a whole [`Frontier`] and the
    /// caller decides in which order the archive is probed. Every entry
    /// it names must belong to a row whose bound positions equal
    /// `binding`'s; the caller establishes that by grouping the region by
    /// probe key — which is also what makes the parent's `base_range`
    /// worth computing once here.
    fn confirm_at(
        &self,
        variable: VariableId,
        binding: &Binding,
        cands: &mut Candidates<'_>,
        order: &[u32],
    ) {
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return;
        }

        let e_bound = self.term_e.position_value(binding);
        let a_bound = self.term_a.position_value(binding);
        let v_bound = self.term_v.position_value(binding);

        match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            (None, None, None, true, false, false) => {
                retain_at(cands, order, |e| {
                    base_range(&self.archive.domain, &self.archive.e_a, e)
                        .is_empty()
                        .not()
                });
            }
            (None, None, None, false, true, false) => {
                retain_at(cands, order, |a| {
                    base_range(&self.archive.domain, &self.archive.a_a, a)
                        .is_empty()
                        .not()
                });
            }
            (None, None, None, false, false, true) => {
                retain_at(cands, order, |v| {
                    base_range(&self.archive.domain, &self.archive.v_a, v)
                        .is_empty()
                        .not()
                });
            }
            (Some(e), None, None, false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                retain_occurring_at(&self.archive.domain, &self.archive.eva_c, &r, cands, order);
            }
            (Some(e), None, None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                retain_occurring_at(&self.archive.domain, &self.archive.eav_c, &r, cands, order);
            }
            (None, Some(a), None, true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                retain_occurring_at(&self.archive.domain, &self.archive.ave_c, &r, cands, order);
            }
            (None, Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                retain_occurring_at(&self.archive.domain, &self.archive.aev_c, &r, cands, order);
            }
            (None, None, Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                retain_occurring_at(&self.archive.domain, &self.archive.vae_c, &r, cands, order);
            }
            (None, None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                retain_occurring_at(&self.archive.domain, &self.archive.vea_c, &r, cands, order);
            }
            (None, Some(a), Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.v_a,
                    &self.archive.aev_c,
                    v,
                    &r,
                );
                retain_occurring_at(&self.archive.domain, &self.archive.vae_c, &r, cands, order);
            }
            (Some(e), None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.v_a,
                    &self.archive.eav_c,
                    v,
                    &r,
                );
                retain_occurring_at(&self.archive.domain, &self.archive.vea_c, &r, cands, order);
            }
            (Some(e), Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.a_a,
                    &self.archive.eva_c,
                    a,
                    &r,
                );
                retain_occurring_at(&self.archive.domain, &self.archive.aev_c, &r, cands, order);
            }
            _ => unreachable!("invalid trible constraint state"),
        }
    }

    /// Whether `variable` occupies any position of this pattern — the
    /// relevance check every protocol method opens with, hoisted so the
    /// batched entry points can skip building a probe-key matrix for a
    /// variable they have no opinion about.
    fn touches(&self, variable: VariableId) -> bool {
        self.term_e.is_var(variable) || self.term_a.is_var(variable) || self.term_v.is_var(variable)
    }

    /// Appends the bytes of every position this constraint reads under
    /// `binding` — the bound ones and the constants, in e-a-v order — to
    /// `out`. This is the row's **probe key**.
    ///
    /// Two rows with the same key are indistinguishable to
    /// [`propose_row`](Self::propose_row) and
    /// [`confirm_at`](Self::confirm_at): both dispatch on *which*
    /// positions have a value, which a [`Frontier`] shares by
    /// construction, and read nothing else from the binding. So the key
    /// is a complete summary of a row for this source's purposes — equal
    /// keys may be answered once, and the key's byte order is the
    /// domain's own order, which is the order the archive wants to be
    /// probed in.
    ///
    /// Every row of a frontier writes the same number of bytes, so the
    /// keys form a fixed-stride matrix.
    fn write_probe_key(&self, binding: &Binding, out: &mut SmallVec<[u8; 128]>) {
        for term in [&self.term_e, &self.term_a, &self.term_v] {
            if let Some(value) = term.position_value(binding) {
                out.extend_from_slice(value);
            }
        }
    }

    /// Labels the frontier's rows by **probe group** — rows that project
    /// to the same probe key share a label — and returns the labels
    /// alongside the row permutation that visits the groups in key order.
    ///
    /// The label is what the batch is actually sorted and grouped on
    /// afterwards, so the byte keys are compared exactly once per row
    /// here rather than once per comparison in the region-sized sort
    /// below: a group is a `u32`, and a region of a quarter-million
    /// candidates then sorts on integers instead of on 32- to 64-byte
    /// keys reached through their parent row.
    ///
    /// Below [`SORTED_PROBE_MIN`] no keys are built at all and every row
    /// is its own group, which is exactly the frontier-order loop: one
    /// index walk per row in `propose`, and one run per parent tag in
    /// `confirm`. The threshold therefore costs nothing on the side it
    /// turns off, which is what makes the two strategies comparable.
    fn probe_groups(&self, frontier: &Frontier<'_>) -> (Vec<u32>, Vec<u32>) {
        let rows = frontier.len();
        let order: Vec<u32> = (0..rows as u32).collect();
        if rows < SORTED_PROBE_MIN {
            // Below the threshold nothing is gained by asking what the
            // keys are, so we do not build them: every row is its own
            // group, which makes `propose` a plain per-row loop and
            // `confirm` a walk of the region's own parent runs.
            return (order.clone(), order);
        }

        let mut keys: SmallVec<[u8; 128]> = SmallVec::new();
        for row in 0..rows {
            self.write_probe_key(&frontier.row(row), &mut keys);
        }
        let stride = keys.len() / rows;
        let key = |row: u32| {
            let row = row as usize;
            &keys[row * stride..(row + 1) * stride]
        };

        let mut order = order;
        if stride != 0 {
            // Ties break on the row number, so the permutation is a
            // deterministic function of the frontier rather than of the
            // sort's internal choices.
            order.sort_unstable_by(|&a, &b| key(a).cmp(key(b)).then(a.cmp(&b)));
        }

        let mut group = vec![0u32; rows];
        let mut label = 0u32;
        for i in 1..rows {
            if key(order[i]) != key(order[i - 1]) {
                label += 1;
            }
            group[order[i] as usize] = label;
        }
        (group, order)
    }
}

impl<'a, U> Constraint<'a> for SuccinctArchiveConstraint<'a, U>
where
    U: Universe,
{
    fn variables(&self) -> VariableSet {
        let mut variables = VariableSet::new_empty();
        self.term_e.add_to(&mut variables);
        self.term_a.add_to(&mut variables);
        self.term_v.add_to(&mut variables);
        variables
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return None;
        }

        let e_bound = self.term_e.position_value(binding);
        let a_bound = self.term_a.position_value(binding);
        let v_bound = self.term_v.position_value(binding);

        Some(match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            (None, None, None, true, false, false) => self.archive.entity_count(),
            (None, None, None, false, true, false) => self.archive.attribute_count(),
            (None, None, None, false, false, true) => self.archive.value_count(),
            (Some(e), None, None, false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                self.archive.distinct_in(&self.archive.changed_e_a, &r)
            }
            (Some(e), None, None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                self.archive.distinct_in(&self.archive.changed_e_v, &r)
            }
            (None, Some(a), None, true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                self.archive.distinct_in(&self.archive.changed_a_e, &r)
            }
            (None, Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                self.archive.distinct_in(&self.archive.changed_a_v, &r)
            }
            (None, None, Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                self.archive.distinct_in(&self.archive.changed_v_e, &r)
            }
            (None, None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.v_a, v);
                self.archive.distinct_in(&self.archive.changed_v_a, &r)
            }
            (None, Some(a), Some(v), true, false, false) => {
                let r = base_range(&self.archive.domain, &self.archive.a_a, a);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.v_a,
                    &self.archive.aev_c,
                    v,
                    &r,
                );
                r.len()
            }
            (Some(e), None, Some(v), false, true, false) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.v_a,
                    &self.archive.eav_c,
                    v,
                    &r,
                );
                r.len()
            }
            (Some(e), Some(a), None, false, false, true) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.a_a,
                    &self.archive.eva_c,
                    a,
                    &r,
                );
                r.len()
            }
            _ => unreachable!(),
        })
    }

    /// Enumerates matching values for every row of the batch: N archive
    /// lookups for N parent bindings, into one segmented buffer.
    ///
    /// Which rotation the enumeration walks depends only on the bound
    /// *set*, which the frontier shares, so the rows differ only in the
    /// value each one looks up. Those values are looked up in **key
    /// order** rather than frontier order (see [`SORTED_PROBE_MIN`]),
    /// which makes the domain searches an ordered sweep instead of N
    /// independent binary searches, and lets rows that share a value be
    /// answered once and fanned out. Segment order follows the probe
    /// order; a proposer may visit rows in any order, and each row's
    /// candidates still arrive contiguously under its own tag.
    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        let rows = frontier.len();
        if rows == 0 || !self.touches(variable) {
            return;
        }
        let (group, order) = self.probe_groups(frontier);

        let mut shared: Vec<RawInline> = Vec::new();
        let mut run_start = 0;
        while run_start < rows {
            let lead = order[run_start];
            let label = group[lead as usize];
            let mut run_end = run_start + 1;
            while run_end < rows && group[order[run_end] as usize] == label {
                run_end += 1;
            }

            let base = proposals.len();
            proposals.open(lead);
            self.propose_row(variable, &frontier.row(lead as usize), proposals);
            if run_end - run_start > 1 {
                // The remaining rows of the run look the same value up,
                // so they have the same candidates: copy rather than walk
                // the archive again.
                shared.clear();
                shared.extend_from_slice(&proposals[base..]);
                for &row in &order[run_start + 1..run_end] {
                    proposals.open(row);
                    proposals.extend_from_slice(&shared);
                }
            }
            run_start = run_end;
        }
    }

    /// Confirms each candidate against its own row's bound positions.
    ///
    /// The region spans the whole batch, so it is walked in **probe
    /// order**: grouped by probe key — coarser than by parent tag, since
    /// distinct rows that agree on this constraint's positions confirm
    /// identically and can share one `base_range` — and, within a group,
    /// in value order, which is the domain's own order. Below
    /// [`SORTED_PROBE_MIN`] the region is walked in its own order
    /// instead, which is the same grouping the tags already carry.
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        let entries = cands.len();
        if entries == 0 || frontier.is_empty() || !self.touches(variable) {
            return;
        }
        let (group, _) = self.probe_groups(frontier);
        // The tags are read after the region turns mutable, so take a
        // copy of them rather than holding a borrow across the kills.
        let parents: SmallVec<[u32; 64]> = SmallVec::from_slice(cands.parents());

        let mut order: SmallVec<[u32; 64]> = (0..entries as u32).collect();
        if entries >= SORTED_REGION_MIN {
            let values = cands.values();
            order.sort_unstable_by(|&a, &b| {
                group[parents[a as usize] as usize]
                    .cmp(&group[parents[b as usize] as usize])
                    .then_with(|| values[a as usize].cmp(&values[b as usize]))
                    .then(a.cmp(&b))
            });
        }

        let mut run_start = 0;
        while run_start < entries {
            let lead = parents[order[run_start] as usize];
            let label = group[lead as usize];
            let mut run_end = run_start + 1;
            while run_end < entries && group[parents[order[run_end] as usize] as usize] == label {
                run_end += 1;
            }
            let binding = frontier.row(lead as usize);
            self.confirm_at(variable, &binding, cands, &order[run_start..run_end]);
            run_start = run_end;
        }
    }

    /// When all three positions have values (bound or constant), checks
    /// whether the triple exists in the archive. Returns `true`
    /// optimistically when any position is still unbound. Exactness in
    /// the fully-bound case is what lets `Query::new` settle
    /// fully-constant patterns with a single probe, and what lets
    /// composite constraints prune dead branches.
    fn satisfied(&self, binding: &Binding) -> bool {
        match (
            self.term_e.position_value(binding),
            self.term_a.position_value(binding),
            self.term_v.position_value(binding),
        ) {
            (Some(e), Some(a), Some(v)) => {
                let r = base_range(&self.archive.domain, &self.archive.e_a, e);
                let r = restrict_range(
                    &self.archive.domain,
                    &self.archive.a_a,
                    &self.archive.eva_c,
                    a,
                    &r,
                );
                restrict_range(
                    &self.archive.domain,
                    &self.archive.v_a,
                    &self.archive.aev_c,
                    v,
                    &r,
                )
                .is_empty()
                .not()
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "parallel")]
    use std::collections::BTreeSet;

    use super::*;
    #[cfg(feature = "parallel")]
    use crate::and;
    #[cfg(feature = "parallel")]
    use crate::find;
    #[cfg(feature = "parallel")]
    use crate::id::rngid;
    #[cfg(feature = "parallel")]
    use crate::inline::encodings::UnknownInline;
    #[cfg(feature = "parallel")]
    use crate::inline::Inline;
    #[cfg(feature = "parallel")]
    use crate::query::TriblePattern;
    use crate::trible::{Trible, TribleSet};
    #[cfg(feature = "parallel")]
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    fn id(tag: u8, ordinal: u32) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0x80 | tag;
        id[12..].copy_from_slice(&ordinal.to_be_bytes());
        id
    }

    fn id_value(id: [u8; 16]) -> RawInline {
        let mut value = [0u8; 32];
        value[16..].copy_from_slice(&id);
        value
    }

    fn value(tag: u8, ordinal: u32) -> RawInline {
        let mut value = [0u8; 32];
        value[0] = tag;
        value[28..].copy_from_slice(&ordinal.to_be_bytes());
        value
    }

    fn insert(set: &mut TribleSet, e: [u8; 16], a: [u8; 16], v: RawInline) {
        let mut data = [0u8; 64];
        data[..16].copy_from_slice(&e);
        data[16..32].copy_from_slice(&a);
        data[32..].copy_from_slice(&v);
        set.insert(&Trible { data });
    }

    /// Exercises the actual batching boundary rather than only Jerky's batch
    /// primitive: more than one caller chunk, duplicate live values separated
    /// by dead entries, absent domain values, a non-identity order, and packed
    /// candidate regions beginning at several bit offsets.
    #[test]
    fn batched_occurrence_matches_two_scalar_ranks_in_bounded_regions() {
        let target = id(1, 0);
        let other = id(1, 1);
        let attribute = id(2, 0);
        let mut set = TribleSet::new();
        for ordinal in 0..(CONFIRM_CHUNK as u32 + 193) {
            let candidate = value(0x10, ordinal);
            insert(&mut set, other, attribute, candidate);
            if ordinal % 2 == 0 {
                insert(&mut set, target, attribute, candidate);
            }
        }
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let range = base_range(&archive.domain, &archive.e_a, &id_value(target));
        assert!(!range.is_empty());

        let mut candidates = Vec::new();
        let mut prekill = Vec::new();
        for ordinal in 0..(CONFIRM_CHUNK as u32 + 193) {
            let candidate = value(0x10, ordinal);
            candidates.push(candidate);
            if ordinal % 17 == 0 {
                // `retain_at` treats these equal values as adjacent in the
                // live subsequence; the batching path must do the same.
                let dead = candidates.len();
                candidates.push(value(0x30, ordinal));
                prekill.push(dead);
                candidates.push(candidate);
            }
            if ordinal % 29 == 0 {
                candidates.push(value(0x40, ordinal));
            }
        }

        let mut order: Vec<u32> = (0..candidates.len() as u32).collect();
        order.reverse();

        for base in [0usize, 1, 31, 33, 1000] {
            let prefix: Vec<_> = (0..base as u32).map(|i| value(0x70, i)).collect();
            let mut buffer = ProposalBuffer::new();
            buffer.extend_from_slice(&prefix);
            buffer.extend_from_slice(&candidates);
            let mut region = buffer.region(base);
            for &candidate in &prekill {
                region.kill(candidate);
            }

            let mut expected: Vec<_> = (0..region.len()).map(|i| region.is_live(i)).collect();
            for &candidate in &order {
                let candidate = candidate as usize;
                if !expected[candidate] {
                    continue;
                }
                expected[candidate] = match archive.domain.search(&candidates[candidate]) {
                    Some(code) => {
                        let start = archive.eav_c.rank(range.start, code).unwrap();
                        let end = archive.eav_c.rank(range.end, code).unwrap();
                        let one_descent = archive
                            .eav_c
                            .rank_range(range.clone(), code)
                            .expect("archive-derived range is in bounds");
                        assert_eq!(one_descent, end - start);
                        one_descent != 0
                    }
                    None => false,
                };
            }

            retain_occurring_at(&archive.domain, &archive.eav_c, &range, &mut region, &order);
            let actual: Vec<_> = (0..region.len()).map(|i| region.is_live(i)).collect();
            assert_eq!(actual, expected, "region base {base}");
            drop(region);
            assert!(
                (0..base).all(|i| buffer.is_live(i)),
                "confirm touched the packed prefix at base {base}"
            );
        }
    }

    #[test]
    fn empty_range_kills_only_named_live_candidates() {
        let set = {
            let mut set = TribleSet::new();
            insert(&mut set, id(1, 0), id(2, 0), value(0x10, 0));
            set
        };
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let candidates: Vec<_> = (0..12).map(|i| value(0x10, i)).collect();
        let mut buffer = ProposalBuffer::new();
        buffer.extend_from_slice(&candidates);
        let mut region = buffer.region(0);
        region.kill(3);

        retain_occurring_at(
            &archive.domain,
            &archive.eav_c,
            &(0..0),
            &mut region,
            &[1, 3, 8],
        );

        for i in 0..region.len() {
            assert_eq!(region.is_live(i), !matches!(i, 1 | 3 | 8), "candidate {i}");
        }
    }

    #[test]
    fn nonempty_range_touches_only_named_live_candidates() {
        let target = id(1, 0);
        let attribute = id(2, 0);
        let mut set = TribleSet::new();
        for ordinal in (0..12).step_by(2) {
            insert(&mut set, target, attribute, value(0x10, ordinal));
        }
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let range = base_range(&archive.domain, &archive.e_a, &id_value(target));
        assert!(!range.is_empty());

        let candidates: Vec<_> = (0..12).map(|i| value(0x10, i)).collect();
        let mut buffer = ProposalBuffer::new();
        buffer.extend_from_slice(&candidates);
        let mut region = buffer.region(0);
        region.kill(3);

        // Nine named entries with one pre-kill leave eight live probes, so
        // this exercises the batched path. Indices 0, 10, and 11 are not
        // owned by this frontier group and must remain untouched, including
        // the absent value at 11.
        retain_occurring_at(
            &archive.domain,
            &archive.eav_c,
            &range,
            &mut region,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        );

        for i in 0..region.len() {
            let expected = match i {
                1 | 3 | 5 | 7 | 9 => false,
                _ => true,
            };
            assert_eq!(region.is_live(i), expected, "candidate {i}");
        }
    }

    #[cfg(feature = "parallel")]
    fn inline(i: u64) -> Inline<UnknownInline> {
        let mut raw = [0u8; 32];
        raw[24..].copy_from_slice(&i.to_be_bytes());
        Inline::new(raw)
    }

    #[cfg(feature = "parallel")]
    fn id_inline(id: &[u8; 16]) -> Inline<GenId> {
        Inline::new(id_value(*id))
    }

    #[cfg(feature = "parallel")]
    fn row_digest(rows: &[(Inline<UnknownInline>,)]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        for (value,) in rows {
            hasher.update(&value.raw);
        }
        hasher.finalize()
    }

    /// The CPU batch is an implementation detail inside one canonical
    /// confirm. Sequential solving and every Rayon pool size must therefore
    /// emit exactly the same bag; set and digest checks make accidental
    /// duplication and omission explicit, while `take_any` covers early
    /// cancellation.
    #[cfg(feature = "parallel")]
    #[test]
    fn succinct_batched_confirm_preserves_parallel_bag_set_and_digest() {
        const PROPOSALS: u64 = 8192;
        let entity = rngid();
        let attribute = rngid();
        let entity_inline = id_inline(&entity);
        let attribute_inline = id_inline(&attribute);

        let mut proposer = TribleSet::new();
        for i in 0..PROPOSALS {
            proposer.insert(&Trible::new(&entity, &attribute, &inline(i)));
        }

        let mut confirmer = TribleSet::new();
        for i in (0..PROPOSALS).step_by(2) {
            confirmer.insert(&Trible::new(&entity, &attribute, &inline(i)));
        }
        // Keep the archive's estimate above the proposer's while adding no
        // further intersection results, so the TribleSet proposes and the
        // SuccinctArchive exercises its range-confirm path.
        for i in PROPOSALS * 2..PROPOSALS * 3 {
            confirmer.insert(&Trible::new(&entity, &attribute, &inline(i)));
        }
        let confirmer: SuccinctArchive<OrderedUniverse> = (&confirmer).into();

        let mut expected: Vec<_> = (0..PROPOSALS).step_by(2).map(|i| (inline(i),)).collect();
        expected.sort_unstable();
        let expected_set: BTreeSet<_> = expected.iter().copied().collect();

        macro_rules! query {
            () => {
                find! {
                    (value: Inline<UnknownInline>),
                    and!(
                        proposer.pattern(entity_inline, attribute_inline, value),
                        confirmer.pattern(entity_inline, attribute_inline, value)
                    )
                }
            };
        }

        let mut sequential: Vec<_> = query!().collect();
        sequential.sort_unstable();
        assert_eq!(sequential, expected);
        let digest = row_digest(&sequential);

        for threads in [1, 2, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let mut parallel = pool.install(|| query!().into_par_iter().collect::<Vec<_>>());
            parallel.sort_unstable();
            assert_eq!(parallel, sequential, "{threads}-thread bag");
            assert_eq!(row_digest(&parallel), digest, "{threads}-thread digest");
            assert_eq!(
                parallel.iter().copied().collect::<BTreeSet<_>>(),
                expected_set,
                "{threads}-thread set"
            );
        }

        let four = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let partial: Vec<_> = four.install(|| query!().into_par_iter().take_any(17).collect());
        assert_eq!(partial.len(), 17);
        let partial_set: BTreeSet<_> = partial.iter().copied().collect();
        assert_eq!(
            partial_set.len(),
            partial.len(),
            "cancellation duplicated rows"
        );
        assert!(partial_set.is_subset(&expected_set));
    }
}
