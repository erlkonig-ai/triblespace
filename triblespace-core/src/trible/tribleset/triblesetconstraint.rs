use core::ops::Range;
use core::panic;

use smallvec::SmallVec;

use crate::id::id_from_value;
use crate::id::id_into_value;
use crate::id::ID_LEN;
use crate::inline::encodings::genid::GenId;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;
use crate::inline::INLINE_LEN;
use crate::query::Binding;
use crate::query::Candidates;
use crate::query::Cardinality;
use crate::query::Constraint;
use crate::query::Frontier;
use crate::query::ProposalBuffer;
use crate::query::RawTerm;
use crate::query::Term;
use crate::query::VariableId;
use crate::query::VariableSet;
use crate::trible::TribleSet;

/// Batch size at which this source stops probing in frontier order and
/// probes in **index order** instead.
///
/// A batched `propose`/`confirm` is N covering-index lookups for N
/// parent bindings, taken in whatever order the frontier happens to
/// hold them. Ordering them by key buys two things:
///
/// * **Duplicate keys collapse.** Several frontier rows routinely
///   project to the *same* key — a join whose parents fan in, or a
///   pattern with no bound position at all, where every row's key is
///   empty and the loop re-enumerated the whole relation once per row.
///   Sorted, those rows are adjacent, so the index is walked once and
///   the result is fanned out to each row's own segment. This is the
///   half that pays.
/// * **Locality.** The keys are byte arrays and the PATCH is ordered on
///   exactly those bytes (a prefix passed to `has_prefix`/`infixes` is
///   in *tree* order, so a lexicographic sort of the prefixes is the
///   tree's own descent order), so consecutive probes share their upper
///   path. Measured, this half is worth less than duplicate collapse but
///   comes with the same bounded row permutation.
///
/// Ordering the rows costs `O(rows log rows)` — bounded by the frontier
/// width — and buys the collapses above, which are savings in work rather
/// than only cache misses. Candidate regions deliberately stay in proposer
/// order: the former region-sized sort cost `O(candidates log candidates)`
/// and lost 33--46% on the Harkonnen fixtures that crossed it, while buying
/// no more than 3% anywhere measured. Keeping that disabled machinery still
/// forced every CPU-confirm shard to allocate and copy an index permutation,
/// so it is removed rather than retained behind a dead threshold.
///
/// On for this source, and measured on the suite's Harkonnen fixtures:
/// the collapses are worth 16% and 12% on F8 (bag and distinct) and 6%
/// on F14, against 11% on F5 and 6% on F12 where the rows have distinct
/// keys and the sort only reorders. Net favourable, and the shapes it
/// loses on are the ones a wider frontier makes rarer, not commoner.
const SORTED_PROBE_MIN: usize = 2;

/// Candidate-region size at which a CPU confirmation becomes worth dividing
/// across the current Rayon pool.
///
/// This is an internal execution crossover, not a query-planning knob. The
/// logical frontier remains whole: proposal, probe grouping, and any device
/// routing happen before this point. Only the CPU membership probes divide,
/// at packed-word boundaries, into disjoint kill-only regions. With a 1024
/// crossover the recursive leaves are about 512 candidates wide, so medium
/// common-plan CPU regions divide without touching GPU routing, which is
/// decided before this leaf.
#[cfg(feature = "parallel")]
const PARALLEL_CONFIRM_MIN: usize = 1024;

#[cfg(all(test, feature = "parallel"))]
static PARALLEL_CONFIRM_SPLITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Kills every entry in `range` whose value fails `keep`, skipping entries
/// that are already dead.
///
/// The verdict is memoised across *adjacent equal values*, which costs
/// one 32-byte compare and pays for itself when a proposer fanned the same
/// candidate run out to adjacent rows of one probe group.
#[inline]
fn retain_range(
    cands: &mut Candidates<'_>,
    range: Range<usize>,
    mut keep: impl FnMut(&RawInline) -> bool,
) {
    let mut memo: Option<(RawInline, bool)> = None;
    for i in range {
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

/// Kills every entry in `range`, used where a row's own bound positions are
/// malformed.
#[inline]
fn kill_range(cands: &mut Candidates<'_>, range: Range<usize>) {
    for i in range {
        cands.kill(i);
    }
}

/// A triple-pattern lookup against a [`TribleSet`].
///
/// Created by [`TribleSet::pattern`](crate::query::TriblePattern::pattern)
/// (typically via the [`pattern!`](crate::pattern) macro). Each position —
/// entity, attribute, value — is a [`Term`]: a variable to solve for or a
/// constant pinned at construction. The constraint uses the six covering
/// indexes (EAV, EVA, AEV, AVE, VEA, VAE) to provide tight estimates and
/// fast proposals regardless of which positions are bound; a constant
/// position simply enters that dispatch as bound from the start.
///
/// When all three positions have values, [`satisfied`](Constraint::satisfied)
/// checks whether the triple exists in the set, enabling composite
/// constraints to prune dead branches early.
pub struct TribleSetConstraint {
    term_e: RawTerm,
    term_a: RawTerm,
    term_v: RawTerm,
    set: TribleSet,
}

impl TribleSetConstraint {
    /// Creates a triple-pattern constraint over `set` for the given
    /// entity, attribute, and value terms.
    pub fn new<V: InlineEncoding>(
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
        set: TribleSet,
    ) -> Self {
        TribleSetConstraint {
            term_e: e.into().erase(),
            term_a: a.into().erase(),
            term_v: v.into().erase(),
            set,
        }
    }
}

impl TribleSetConstraint {
    /// Kills the entries in `range` whose value is inconsistent with
    /// `binding`.
    ///
    /// Every entry in the range belongs to a row whose bound positions equal
    /// `binding`'s; the caller establishes that by walking adjacent probe-key
    /// groups in the region's existing order.
    fn confirm_at(
        &self,
        variable: VariableId,
        binding: &Binding,
        cands: &mut Candidates<'_>,
        range: Range<usize>,
    ) {
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return;
        }

        let e_bound = if let Some(e) = self.term_e.position_value(binding) {
            let Some(e) = id_from_value(e) else {
                kill_range(cands, range);
                return;
            };
            Some(e)
        } else {
            None
        };
        let a_bound = if let Some(a) = self.term_a.position_value(binding) {
            let Some(a) = id_from_value(a) else {
                kill_range(cands, range);
                return;
            };
            Some(a)
        } else {
            None
        };
        let v_bound = self.term_v.position_value(binding);

        match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            (None, None, None, true, false, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                self.set.eav.has_prefix(&id)
            }),
            (None, None, None, false, true, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                self.set.aev.has_prefix(&id)
            }),
            (None, None, None, false, false, true) => {
                retain_range(cands, range, |value| self.set.vea.has_prefix(value))
            }
            (Some(e), None, None, false, true, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                self.set.eav.has_prefix(&prefix)
            }),
            (Some(e), None, None, false, false, true) => retain_range(cands, range, |value| {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(value);
                self.set.eva.has_prefix(&prefix)
            }),
            (None, Some(a), None, true, false, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a[..]);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                self.set.aev.has_prefix(&prefix)
            }),
            (None, Some(a), None, false, false, true) => retain_range(cands, range, |value| {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a[..]);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(value);
                self.set.ave.has_prefix(&prefix)
            }),
            (None, None, Some(v), true, false, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; INLINE_LEN + ID_LEN];
                prefix[0..INLINE_LEN].copy_from_slice(&v[..]);
                prefix[INLINE_LEN..INLINE_LEN + ID_LEN].copy_from_slice(&id);
                self.set.vea.has_prefix(&prefix)
            }),
            (None, None, Some(v), false, true, false) => retain_range(cands, range, |value| {
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; INLINE_LEN + ID_LEN];
                prefix[0..INLINE_LEN].copy_from_slice(&v[..]);
                prefix[INLINE_LEN..INLINE_LEN + ID_LEN].copy_from_slice(&id);
                self.set.vae.has_prefix(&prefix)
            }),
            (None, Some(a), Some(v), true, false, false) => {
                retain_range(cands, range, |value: &[u8; 32]| {
                    let Some(id) = id_from_value(value) else {
                        return false;
                    };
                    let mut prefix = [0u8; ID_LEN + INLINE_LEN + ID_LEN];
                    prefix[0..ID_LEN].copy_from_slice(&a);
                    prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(v);
                    prefix[ID_LEN + INLINE_LEN..ID_LEN + INLINE_LEN + ID_LEN].copy_from_slice(&id);
                    self.set.ave.has_prefix(&prefix)
                })
            }
            (Some(e), None, Some(v), false, true, false) => {
                retain_range(cands, range, |value: &[u8; 32]| {
                    let Some(id) = id_from_value(value) else {
                        return false;
                    };
                    let mut prefix = [0u8; ID_LEN + INLINE_LEN + ID_LEN];
                    prefix[0..ID_LEN].copy_from_slice(&e);
                    prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(v);
                    prefix[ID_LEN + INLINE_LEN..ID_LEN + INLINE_LEN + ID_LEN].copy_from_slice(&id);
                    self.set.eva.has_prefix(&prefix)
                })
            }
            (Some(e), Some(a), None, false, false, true) => {
                retain_range(cands, range, |value: &[u8; 32]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(&e);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a);
                    prefix[ID_LEN + ID_LEN..ID_LEN + ID_LEN + INLINE_LEN].copy_from_slice(value);
                    self.set.eav.has_prefix(&prefix)
                })
            }

            // Same-Variable arms. The proposal value plays two roles
            // (e and v, or e and a, or a and v); we build a full
            // 64-byte trible key from each proposal and check
            // `has_prefix` against the appropriate index.
            (_, Some(a), _, true, false, true) => retain_range(cands, range, |value| {
                // pattern(x, a, x): proposal is both entity and value.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a[..]);
                prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(&id));
                self.set.eav.has_prefix(&prefix)
            }),
            (_, None, _, true, false, true) => retain_range(cands, range, |value| {
                // pattern(x, ?, x): proposal is entity == value, any attr.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..].copy_from_slice(&id_into_value(&id));
                self.set.eva.has_prefix(&prefix)
            }),
            (_, _, Some(v), true, true, false) => retain_range(cands, range, |value| {
                // pattern(x, x, v): proposal is entity == attribute.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN + ID_LEN..].copy_from_slice(&v[..]);
                self.set.eav.has_prefix(&prefix)
            }),
            (_, _, None, true, true, false) => retain_range(cands, range, |value| {
                // pattern(x, x, ?): proposal is entity == attribute, any v.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                self.set.eav.has_prefix(&prefix)
            }),
            (Some(e), _, _, false, true, true) => retain_range(cands, range, |value| {
                // pattern(e, x, x): proposal is attribute == value.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(&id));
                self.set.eav.has_prefix(&prefix)
            }),
            (None, _, _, false, true, true) => retain_range(cands, range, |value| {
                // pattern(?, x, x): proposal is attribute == value, any e.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..].copy_from_slice(&id_into_value(&id));
                self.set.ave.has_prefix(&prefix)
            }),
            (_, _, _, true, true, true) => retain_range(cands, range, |value| {
                // pattern(x, x, x): proposal plays all three roles.
                let Some(id) = id_from_value(value) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&id);
                prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(&id));
                self.set.eav.has_prefix(&prefix)
            }),
            _ => panic!("invalid trible constraint state"),
        }
    }

    /// Serial confirmation over one candidate region, given the probe-group
    /// labels already computed for the region's logical frontier.
    ///
    /// Keeping this as the leaf of both execution paths makes the
    /// non-parallel build and every below-crossover region run the exact same
    /// code. Candidate order is the proposer's order; a parallel division
    /// merely creates two shorter regions in that same order. Reading parent
    /// tags one at a time avoids the former region-sized parent copy and dead
    /// sort permutation.
    fn confirm_grouped(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        group: &[u32],
        cands: &mut Candidates<'_>,
    ) {
        let entries = cands.len();
        let mut run_start = 0;
        while run_start < entries {
            let lead = cands.parent(run_start);
            let label = group[lead as usize];
            let mut run_end = run_start + 1;
            while run_end < entries && group[cands.parent(run_end) as usize] == label {
                run_end += 1;
            }
            let binding = frontier.row(lead as usize);
            self.confirm_at(variable, &binding, cands, run_start..run_end);
            run_start = run_end;
        }
    }

    /// Confirms one logical region with nested Rayon work only inside the
    /// CPU leaf. The split consumes `Candidates`, so Rust itself proves that
    /// the two closures own disjoint packed liveness words.
    #[cfg(feature = "parallel")]
    fn confirm_parallel(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        group: &[u32],
        cands: Candidates<'_>,
    ) {
        if cands.len() < PARALLEL_CONFIRM_MIN || rayon::current_num_threads() == 1 {
            let mut cands = cands;
            self.confirm_grouped(variable, frontier, group, &mut cands);
            return;
        }

        // Choose the packed-word boundary nearest the region midpoint. At
        // this crossover the rounded division is necessarily interior; keep
        // the check explicit so the ownership law remains local if the
        // crossover or liveness geometry ever changes.
        let bit_offset = cands.bit_offset();
        let midpoint = bit_offset + cands.len() / 2;
        let boundary =
            midpoint / crate::query::LIVENESS_WORD_BITS * crate::query::LIVENESS_WORD_BITS;
        let mid = boundary.saturating_sub(bit_offset);
        if mid == 0 || mid >= cands.len() {
            let mut cands = cands;
            self.confirm_grouped(variable, frontier, group, &mut cands);
            return;
        }

        let (left, right) = cands.split_at_word_boundary(mid);
        #[cfg(test)]
        PARALLEL_CONFIRM_SPLITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        rayon::join(
            || self.confirm_parallel(variable, frontier, group, left),
            || self.confirm_parallel(variable, frontier, group, right),
        );
    }

    fn propose_row(&self, variable: VariableId, binding: &Binding, proposals: &mut ProposalBuffer) {
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return;
        }

        let e_bound = if let Some(e) = self.term_e.position_value(binding) {
            let Some(e) = id_from_value(e) else {
                return;
            };
            Some(e)
        } else {
            None
        };
        let a_bound = if let Some(a) = self.term_a.position_value(binding) {
            let Some(a) = id_from_value(a) else {
                return;
            };
            Some(a)
        } else {
            None
        };
        let v_bound = self.term_v.position_value(binding);

        match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            // Distinct-position combinations: the queried variable
            // appears in exactly one trible slot. Drive enumeration
            // from the most selective covering index.
            (None, None, None, true, false, false) => {
                self.set.eav.infixes(&[0; 0], &mut |e: &[u8; 16]| {
                    proposals.push(id_into_value(e))
                });
            }
            (None, None, None, false, true, false) => {
                self.set.aev.infixes(&[0; 0], &mut |a: &[u8; 16]| {
                    proposals.push(id_into_value(a))
                });
            }
            (None, None, None, false, false, true) => {
                self.set
                    .vea
                    .infixes(&[0; 0], &mut |&v: &[u8; 32]| proposals.push(v));
            }

            (Some(e), None, None, false, true, false) => {
                self.set
                    .eav
                    .infixes(&e, &mut |a: &[u8; 16]| proposals.push(id_into_value(a)));
            }
            (Some(e), None, None, false, false, true) => {
                self.set
                    .eva
                    .infixes(&e, &mut |&v: &[u8; 32]| proposals.push(v));
            }

            (None, Some(a), None, true, false, false) => {
                self.set
                    .aev
                    .infixes(&a, &mut |e: &[u8; 16]| proposals.push(id_into_value(e)));
            }
            (None, Some(a), None, false, false, true) => {
                self.set
                    .ave
                    .infixes(&a, &mut |&v: &[u8; 32]| proposals.push(v));
            }

            (None, None, Some(v), true, false, false) => {
                self.set
                    .vea
                    .infixes(v, &mut |e: &[u8; 16]| proposals.push(id_into_value(e)));
            }
            (None, None, Some(v), false, true, false) => {
                self.set
                    .vae
                    .infixes(v, &mut |a: &[u8; 16]| proposals.push(id_into_value(a)));
            }
            (None, Some(a), Some(v), true, false, false) => {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a[..]);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(&v[..]);
                self.set.ave.infixes(&prefix, &mut |e: &[u8; 16]| {
                    proposals.push(id_into_value(e))
                });
            }
            (Some(e), None, Some(v), false, true, false) => {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(&v[..]);
                self.set.eva.infixes(&prefix, &mut |a: &[u8; 16]| {
                    proposals.push(id_into_value(a))
                });
            }
            (Some(e), Some(a), None, false, false, true) => {
                let mut prefix = [0u8; ID_LEN + ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a[..]);
                self.set
                    .eav
                    .infixes(&prefix, &mut |&v: &[u8; 32]| proposals.push(v));
            }

            // Same-Variable arms. The covering indexes already
            // dedup; the equality constraint between two positions
            // is enforced inline via `has_prefix`. No HashSet — the
            // index walk pays the dedup cost once.
            (_, Some(a), _, true, false, true) => {
                // pattern(x, a, x) — entity equals value, attr bound.
                self.set.aev.infixes(&a, &mut |e: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(e);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a[..]);
                    prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(e));
                    if self.set.eav.has_prefix(&prefix) {
                        proposals.push(id_into_value(e));
                    }
                });
            }
            (_, None, _, true, false, true) => {
                // pattern(x, ?, x) — entity equals value, attr free.
                // Enumerate distinct entities; keep those with ∃ a . (e, a, e).
                self.set.eav.infixes(&[0; 0], &mut |e: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(e);
                    prefix[ID_LEN..].copy_from_slice(&id_into_value(e));
                    if self.set.eva.has_prefix(&prefix) {
                        proposals.push(id_into_value(e));
                    }
                });
            }
            (_, _, Some(v), true, true, false) => {
                // pattern(x, x, v) — entity equals attribute, value bound.
                self.set.vae.infixes(v, &mut |a: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(a);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(a);
                    prefix[ID_LEN + ID_LEN..].copy_from_slice(&v[..]);
                    if self.set.eav.has_prefix(&prefix) {
                        proposals.push(id_into_value(a));
                    }
                });
            }
            (_, _, None, true, true, false) => {
                // pattern(x, x, ?) — entity equals attribute, value free.
                self.set.aev.infixes(&[0; 0], &mut |a: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN];
                    prefix[0..ID_LEN].copy_from_slice(a);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(a);
                    if self.set.eav.has_prefix(&prefix) {
                        proposals.push(id_into_value(a));
                    }
                });
            }
            (Some(e), _, _, false, true, true) => {
                // pattern(e, x, x) — attribute equals value, entity bound.
                self.set.eav.infixes(&e, &mut |a: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(&e[..]);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(a);
                    prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(a));
                    if self.set.eav.has_prefix(&prefix) {
                        proposals.push(id_into_value(a));
                    }
                });
            }
            (None, _, _, false, true, true) => {
                // pattern(?, x, x) — attribute equals value, entity free.
                self.set.aev.infixes(&[0; 0], &mut |a: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(a);
                    prefix[ID_LEN..].copy_from_slice(&id_into_value(a));
                    if self.set.ave.has_prefix(&prefix) {
                        proposals.push(id_into_value(a));
                    }
                });
            }
            (_, _, _, true, true, true) => {
                // pattern(x, x, x) — all three positions share one
                // Variable. Enumerate distinct entities; keep those
                // with (e, e, id_into_value(e)) in the set.
                self.set.eav.infixes(&[0; 0], &mut |e: &[u8; 16]| {
                    let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                    prefix[0..ID_LEN].copy_from_slice(e);
                    prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(e);
                    prefix[ID_LEN + ID_LEN..].copy_from_slice(&id_into_value(e));
                    if self.set.eav.has_prefix(&prefix) {
                        proposals.push(id_into_value(e));
                    }
                });
            }
            _ => panic!("TribleSetConstraint: unreachable position-bound combo"),
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
    /// keys may be answered once, and the key's byte order is the order
    /// the covering index wants to be probed in.
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

impl TribleSetConstraint {
    /// Distinct values of the queried position and tribles under the bound
    /// prefix, read from the covering index in one descent.
    fn counts(&self, variable: VariableId, binding: &Binding) -> Option<Cardinality> {
        // The covering subtree's cached segment and leaf counts, from one
        // walk (`PATCH::prefix_counts`).
        macro_rules! count {
            ($index:ident, $prefix:expr) => {
                self.set.$index.prefix_counts($prefix)
            };
        }
        // Where both other positions are bound, or the variable repeats,
        // the distinct-value count stands for both.
        let same = |n: u64| (n, n);
        let e_var = self.term_e.is_var(variable);
        let a_var = self.term_a.is_var(variable);
        let v_var = self.term_v.is_var(variable);

        if !e_var && !a_var && !v_var {
            return None;
        }

        let e_bound = if let Some(e) = self.term_e.position_value(binding) {
            let Some(e) = id_from_value(e) else {
                return Some(Cardinality {
                    distinct: 0,
                    rows: 0,
                });
            };
            Some(e)
        } else {
            None
        };
        let a_bound = if let Some(a) = self.term_a.position_value(binding) {
            let Some(a) = id_from_value(a) else {
                return Some(Cardinality {
                    distinct: 0,
                    rows: 0,
                });
            };
            Some(a)
        } else {
            None
        };
        let v_bound = self.term_v.position_value(binding);

        let (distinct, rows) = match (e_bound, a_bound, v_bound, e_var, a_var, v_var) {
            // Legal distinct-position combinations (queried var
            // appears in exactly one trible position). These are the cases
            // where the queried variable's partner position is unbound, the
            // only ones in which distinct values and rows differ.
            (None, None, None, true, false, false) => count!(eav, &[0; 0]),
            (None, None, None, false, true, false) => count!(aev, &[0; 0]),
            (None, None, None, false, false, true) => count!(vea, &[0; 0]),
            (Some(e), None, None, false, true, false) => {
                let mut prefix = [0u8; ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                count!(eav, &prefix)
            }
            (Some(e), None, None, false, false, true) => {
                let mut prefix = [0u8; ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e[..]);
                count!(eva, &prefix)
            }
            (None, Some(a), None, true, false, false) => {
                let mut prefix = [0u8; ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a[..]);
                count!(aev, &prefix)
            }
            (None, Some(a), None, false, false, true) => {
                let mut prefix = [0u8; ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a[..]);
                count!(ave, &prefix)
            }
            (None, None, Some(v), true, false, false) => {
                let mut prefix = [0u8; INLINE_LEN];
                prefix[0..INLINE_LEN].copy_from_slice(&v[..]);
                count!(vea, &prefix)
            }
            (None, None, Some(v), false, true, false) => {
                let mut prefix = [0u8; INLINE_LEN];
                prefix[0..INLINE_LEN].copy_from_slice(&v[..]);
                count!(vae, &prefix)
            }
            (None, Some(a), Some(v), true, false, false) => {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&a);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(v);
                same(self.set.ave.segmented_len(&prefix))
            }
            (Some(e), None, Some(v), false, true, false) => {
                let mut prefix = [0u8; ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e);
                prefix[ID_LEN..ID_LEN + INLINE_LEN].copy_from_slice(v);
                same(self.set.eva.segmented_len(&prefix))
            }
            (Some(e), Some(a), None, false, false, true) => {
                let mut prefix = [0u8; ID_LEN + ID_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a);
                same(self.set.eav.segmented_len(&prefix))
            }

            // Same-Variable in two positions. Conservative upper
            // bounds via covering-index `segmented_len` — the
            // actual count would require a `has_prefix` check per
            // candidate, which the planner doesn't need: any tight
            // upper bound drives variable-ordering decisions just
            // as well. `propose` does the real per-candidate work.
            (_, Some(a), _, true, false, true) => {
                // e == v (self-edge), attribute bound.
                let mut prefix = [0u8; ID_LEN];
                prefix.copy_from_slice(&a[..]);
                same(self.set.aev.segmented_len(&prefix))
            }
            (_, None, _, true, false, true) => {
                // e == v, attribute free.
                same(self.set.eav.segmented_len(&[0; 0]))
            }
            (_, _, Some(v), true, true, false) => {
                // e == a, value bound.
                let mut prefix = [0u8; INLINE_LEN];
                prefix.copy_from_slice(&v[..]);
                same(self.set.vae.segmented_len(&prefix))
            }
            (_, _, None, true, true, false) => {
                // e == a, value free.
                same(self.set.aev.segmented_len(&[0; 0]))
            }
            (Some(e), _, _, false, true, true) => {
                // a == v, entity bound.
                let mut prefix = [0u8; ID_LEN];
                prefix.copy_from_slice(&e[..]);
                same(self.set.eav.segmented_len(&prefix))
            }
            (None, _, _, false, true, true) => {
                // a == v, entity free.
                same(self.set.aev.segmented_len(&[0; 0]))
            }
            (_, _, _, true, true, true) => {
                // pattern(x, x, x) — all three positions share one
                // Variable. Conservative upper bound: distinct
                // entities in the set.
                same(self.set.eav.segmented_len(&[0; 0]))
            }
            _ => panic!("TribleSetConstraint: unreachable position-bound combo"),
        };
        Some(Cardinality {
            distinct: distinct as usize,
            rows: rows as usize,
        })
    }
}

impl<'a> Constraint<'a> for TribleSetConstraint {
    /// Returns the set of variable positions (constant positions are
    /// invisible to the engine).
    fn variables(&self) -> VariableSet {
        let mut variables = VariableSet::new_empty();
        self.term_e.add_to(&mut variables);
        self.term_a.add_to(&mut variables);
        self.term_v.add_to(&mut variables);
        variables
    }

    /// Uses the covering indexes (EAV, EVA, AEV, AVE, VEA, VAE) to
    /// count matching entries via `segmented_len`. The index chosen
    /// depends on which of the other two positions are already bound,
    /// giving tight estimates regardless of access pattern.
    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.counts(variable, binding).map(|c| c.distinct)
    }

    /// `rows` is the tribles under the bound prefix: while the queried
    /// variable's partner position is unbound it counts every row the
    /// variable's values lead to, not the values themselves. Where both
    /// other positions are bound the two counts agree.
    fn cardinality(&self, variable: VariableId, binding: &Binding) -> Option<Cardinality> {
        self.counts(variable, binding)
    }

    /// Enumerates matching values for every row of the batch: N covering
    /// index walks for N parent bindings, into one segmented buffer.
    ///
    /// The bound *set* is shared across the frontier, so every row takes
    /// the same covering index and differs only in its prefix bytes —
    /// there is no per-row re-plan, just N prefixes. Those prefixes are
    /// visited in **key order** rather than frontier order (see
    /// [`SORTED_PROBE_MIN`]), which makes the walks an ordered sweep of
    /// the PATCH instead of N descents from its root, and lets rows that
    /// share a prefix be answered once and fanned out. Segment order
    /// follows the probe order; a proposer may visit rows in any order,
    /// and each row's candidates still arrive contiguously under its own
    /// tag.
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
                // The remaining rows of the run have the same prefix, so
                // they have the same candidates: copy rather than walk
                // the index again.
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

    /// Retains only proposals whose combined key (their own row's bound
    /// positions + the proposed value) has a matching prefix in the
    /// appropriate index.
    ///
    /// The region spans the whole batch and stays in proposer order. Adjacent
    /// entries whose parent rows agree on this constraint's probe key share
    /// one bound-position setup; non-adjacent equal keys are still correct,
    /// but form separate runs. This intentionally avoids the former
    /// region-sized candidate permutation: it never paid for its sort and
    /// made parallel CPU leaves allocate and copy an index array per shard.
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        let entries = cands.len();
        if entries == 0 || frontier.is_empty() || !self.touches(variable) {
            return;
        }
        let (group, _) = self.probe_groups(frontier);
        #[cfg(feature = "parallel")]
        {
            if frontier.parallel() {
                self.confirm_parallel(variable, frontier, &group, cands.reborrow());
            } else {
                self.confirm_grouped(variable, frontier, &group, cands);
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            self.confirm_grouped(variable, frontier, &group, cands);
        }
    }

    /// When all three positions have values (bound or constant), checks
    /// whether the triple exists in the EAV index. Returns `true`
    /// optimistically when any position is still unbound.
    fn satisfied(&self, binding: &Binding) -> bool {
        let e = self.term_e.position_value(binding);
        let a = self.term_a.position_value(binding);
        let v = self.term_v.position_value(binding);
        match (e, a, v) {
            (Some(e_raw), Some(a_raw), Some(v_raw)) => {
                let Some(e) = id_from_value(e_raw) else {
                    return false;
                };
                let Some(a) = id_from_value(a_raw) else {
                    return false;
                };
                let mut prefix = [0u8; ID_LEN + ID_LEN + INLINE_LEN];
                prefix[0..ID_LEN].copy_from_slice(&e);
                prefix[ID_LEN..ID_LEN + ID_LEN].copy_from_slice(&a);
                prefix[ID_LEN + ID_LEN..].copy_from_slice(v_raw);
                self.set.eav.has_prefix(&prefix)
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "parallel")]
    use std::collections::BTreeSet;

    #[cfg(feature = "parallel")]
    use crate::and;
    use crate::find;
    use crate::id::rngid;
    use crate::inline::encodings::UnknownInline;
    use crate::inline::Inline;
    use crate::query::TriblePattern;
    use crate::query::Variable;
    use crate::trible::Trible;
    use crate::trible::TribleSet;

    #[cfg(feature = "parallel")]
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    #[cfg(feature = "parallel")]
    fn raw_value(i: u64) -> Inline<UnknownInline> {
        let mut raw = [0u8; 32];
        raw[24..].copy_from_slice(&i.to_be_bytes());
        Inline::new(raw)
    }

    #[cfg(feature = "parallel")]
    fn id_inline(id: &[u8; 16]) -> Inline<crate::inline::encodings::genid::GenId> {
        let mut raw = [0u8; 32];
        raw[16..].copy_from_slice(id);
        Inline::new(raw)
    }

    #[cfg(feature = "parallel")]
    fn row_digest(rows: &[(Inline<UnknownInline>,)]) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        for (value,) in rows {
            hasher.update(&value.raw);
        }
        hasher.finalize()
    }

    /// Exercises the leaf-local split through the public query path. The
    /// smaller relation proposes 8192 values; the larger relation confirms
    /// them and retains exactly the even half. Sequential iteration is the
    /// control. Parallel iteration on a one-thread pool must stay on the
    /// serial leaf, while two- and four-thread pools must cross the split
    /// boundary and produce the identical ordered bag after normalization.
    /// Early cancellation may return any unique subset of that bag.
    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_confirm_preserves_bag_set_digest_and_cancellation() {
        const PROPOSALS: u64 = 8192;
        let entity = rngid();
        let attribute = rngid();
        let entity_inline = id_inline(&entity);
        let attribute_inline = id_inline(&attribute);

        let mut proposer = TribleSet::new();
        for i in 0..PROPOSALS {
            proposer.insert(&Trible::new(&entity, &attribute, &raw_value(i)));
        }

        let mut confirmer = TribleSet::new();
        for i in (0..PROPOSALS).step_by(2) {
            confirmer.insert(&Trible::new(&entity, &attribute, &raw_value(i)));
        }
        // Keep this source's estimate above the proposer's while adding no
        // further intersection results.
        for i in PROPOSALS * 2..PROPOSALS * 3 {
            confirmer.insert(&Trible::new(&entity, &attribute, &raw_value(i)));
        }

        let mut expected: Vec<_> = (0..PROPOSALS).step_by(2).map(|i| (raw_value(i),)).collect();
        expected.sort_unstable();

        let mut sequential: Vec<_> = find! {
            (value: Inline<UnknownInline>),
            and!(
                proposer.pattern(entity_inline, attribute_inline, value),
                confirmer.pattern(entity_inline, attribute_inline, value)
            )
        }
        .collect();
        sequential.sort_unstable();
        assert_eq!(sequential, expected);

        let expected_set: BTreeSet<_> = expected.iter().copied().collect();

        macro_rules! collect_parallel {
            ($pool:expr) => {
                $pool.install(|| {
                    find! {
                        (value: Inline<UnknownInline>),
                        and!(
                            proposer.pattern(entity_inline, attribute_inline, value),
                            confirmer.pattern(entity_inline, attribute_inline, value)
                        )
                    }
                    .into_par_iter()
                    .collect::<Vec<_>>()
                })
            };
        }

        let one_thread = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let splits_before =
            super::PARALLEL_CONFIRM_SPLITS.load(std::sync::atomic::Ordering::Relaxed);
        let mut one_thread_rows = collect_parallel!(&one_thread);
        assert_eq!(
            super::PARALLEL_CONFIRM_SPLITS.load(std::sync::atomic::Ordering::Relaxed),
            splits_before,
            "a one-thread pool should use the serial confirm leaf"
        );
        one_thread_rows.sort_unstable();
        assert_eq!(one_thread_rows, sequential);

        for threads in [2, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let splits_before =
                super::PARALLEL_CONFIRM_SPLITS.load(std::sync::atomic::Ordering::Relaxed);
            let mut parallel = collect_parallel!(&pool);
            assert!(
                super::PARALLEL_CONFIRM_SPLITS.load(std::sync::atomic::Ordering::Relaxed)
                    > splits_before,
                "fixture did not split on a {threads}-thread pool"
            );
            parallel.sort_unstable();
            assert_eq!(parallel, sequential, "parallel execution changed the bag");
            assert_eq!(row_digest(&parallel), row_digest(&sequential));
            assert_eq!(
                parallel.iter().copied().collect::<BTreeSet<_>>(),
                expected_set
            );

            if threads == 4 {
                let partial: Vec<_> = pool.install(|| {
                    find! {
                        (value: Inline<UnknownInline>),
                        and!(
                            proposer.pattern(entity_inline, attribute_inline, value),
                            confirmer.pattern(entity_inline, attribute_inline, value)
                        )
                    }
                    .into_par_iter()
                    .take_any(17)
                    .collect()
                });
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
    }

    #[test]
    fn constant() {
        let mut set = TribleSet::new();
        set.insert(&Trible::new(
            &rngid(),
            &rngid(),
            &Inline::<UnknownInline>::new([0; 32]),
        ));

        let q = find! {
            (e: Inline<_>, a: Inline<_>, v: Inline<_>),
            set.pattern(e, a, v as Variable<UnknownInline>)
        };
        let r: Vec<_> = q.collect();

        assert_eq!(1, r.len())
    }

    #[test]
    fn self_edge_pattern_e_eq_v() {
        // Verify `pattern(x, a, x)` (same Variable in entity and
        // value positions) enumerates self-edge entities without
        // panicking. Adds 3 self-edges and 2 non-self tribles for
        // the same attribute; the query should return exactly 3.
        use crate::and;
        use crate::inline::encodings::genid::GenId;

        // Helper: encode a 16-byte id as a GenId-style Inline value
        // (32 bytes: upper 16 zero, lower 16 = id).
        fn id_as_inline(id: &[u8; 16]) -> Inline<GenId> {
            let mut bytes = [0u8; 32];
            bytes[16..32].copy_from_slice(id);
            Inline::<GenId>::new(bytes)
        }

        let mut set = TribleSet::new();
        let a = rngid();
        let self1 = rngid();
        let self2 = rngid();
        let self3 = rngid();
        let other = rngid();

        // 3 self-edges: x has attribute a with value x
        for x in [&self1, &self2, &self3] {
            set.insert(&Trible::new(x, &a, &id_as_inline(x)));
        }
        // 2 non-self tribles with the same attribute
        set.insert(&Trible::new(&self1, &a, &id_as_inline(&other)));
        set.insert(&Trible::new(&other, &a, &id_as_inline(&self2)));

        // Free attribute: count all self-edges
        let q = find! {
            (x: Inline<GenId>, attr: Inline<GenId>),
            set.pattern(x, attr, x)
        };
        let r: Vec<_> = q.collect();
        assert_eq!(3, r.len(), "expected 3 self-edges, got {}", r.len());

        // Bound attribute: should still be 3 since only attribute a
        // appears in our self-edges
        let q = find! {
            (x: Inline<GenId>, attr: Inline<GenId>),
            and!(
                attr.is(id_as_inline(&a)),
                set.pattern(x, attr, x)
            )
        };
        let r: Vec<_> = q.collect();
        assert_eq!(
            3,
            r.len(),
            "expected 3 self-edges with bound attr, got {}",
            r.len()
        );
    }

    #[test]
    fn entity_attr_dup_pattern() {
        // `pattern(x, x, v)` — entity equals attribute.
        use crate::inline::encodings::genid::GenId;

        fn id_as_inline(id: &[u8; 16]) -> Inline<GenId> {
            let mut bytes = [0u8; 32];
            bytes[16..32].copy_from_slice(id);
            Inline::<GenId>::new(bytes)
        }

        let mut set = TribleSet::new();
        // Two entities that double as their own attributes.
        let dup1 = rngid();
        let dup2 = rngid();
        let other = rngid();
        let v1 = rngid();
        let v2 = rngid();

        set.insert(&Trible::new(&dup1, &dup1, &id_as_inline(&v1)));
        set.insert(&Trible::new(&dup2, &dup2, &id_as_inline(&v2)));
        // Non-dup tribles
        set.insert(&Trible::new(&dup1, &other, &id_as_inline(&v1)));
        set.insert(&Trible::new(&other, &dup1, &id_as_inline(&v1)));

        let q = find! {
            (x: Inline<GenId>, val: Inline<GenId>),
            set.pattern(x, x, val)
        };
        let r: Vec<_> = q.collect();
        assert_eq!(2, r.len(), "expected 2 entity-attr dups, got {}", r.len());
    }

    #[test]
    fn attr_value_dup_pattern() {
        // `pattern(e, x, x)` — attribute equals value.
        use crate::inline::encodings::genid::GenId;

        fn id_as_inline(id: &[u8; 16]) -> Inline<GenId> {
            let mut bytes = [0u8; 32];
            bytes[16..32].copy_from_slice(id);
            Inline::<GenId>::new(bytes)
        }

        let mut set = TribleSet::new();
        let dup1 = rngid(); // attribute id (and value id)
        let dup2 = rngid();
        let other_attr = rngid();
        let e1 = rngid();
        let e2 = rngid();
        let e3 = rngid();

        // attribute equals value tribles
        set.insert(&Trible::new(&e1, &dup1, &id_as_inline(&dup1)));
        set.insert(&Trible::new(&e2, &dup2, &id_as_inline(&dup2)));
        // Non-dup: different value
        set.insert(&Trible::new(&e3, &dup1, &id_as_inline(&dup2)));
        // Non-dup: attribute differs from value's id portion
        set.insert(&Trible::new(&e3, &other_attr, &id_as_inline(&dup1)));

        let q = find! {
            (e: Inline<GenId>, x: Inline<GenId>),
            set.pattern(e, x, x)
        };
        let r: Vec<_> = q.collect();
        assert_eq!(2, r.len(), "expected 2 attr-value dups, got {}", r.len());
    }

    #[test]
    fn all_three_same_pattern() {
        // `pattern(x, x, x)` — entity, attribute, and value all
        // share one Variable. The natural Wikidata meta-class
        // example: Q35120 (entity) is itself, instances-of itself.
        // Here: 2 entities that fully self-assert (e == a, value
        // encodes e) and several near-misses that share two of
        // the three roles.
        use crate::inline::encodings::genid::GenId;

        fn id_as_inline(id: &[u8; 16]) -> Inline<GenId> {
            let mut bytes = [0u8; 32];
            bytes[16..32].copy_from_slice(id);
            Inline::<GenId>::new(bytes)
        }

        let mut set = TribleSet::new();
        let xxx1 = rngid();
        let xxx2 = rngid();
        let other = rngid();

        // 2 full triples: (x, x, x)
        set.insert(&Trible::new(&xxx1, &xxx1, &id_as_inline(&xxx1)));
        set.insert(&Trible::new(&xxx2, &xxx2, &id_as_inline(&xxx2)));
        // Near-miss: e == a but value differs
        set.insert(&Trible::new(&xxx1, &xxx1, &id_as_inline(&other)));
        // Near-miss: e == v but attribute differs
        set.insert(&Trible::new(&xxx2, &other, &id_as_inline(&xxx2)));
        // Near-miss: a == v but entity differs
        set.insert(&Trible::new(&other, &xxx1, &id_as_inline(&xxx1)));

        let q = find! {
            (x: Inline<GenId>),
            set.pattern(x, x, x)
        };
        let r: Vec<_> = q.collect();
        assert_eq!(
            2,
            r.len(),
            "expected 2 self-self-self triples, got {}",
            r.len()
        );
    }
}
