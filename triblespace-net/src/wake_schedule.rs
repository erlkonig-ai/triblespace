//! Bounded, randomized announcements of one collection's root to its
//! neighbours; never a forwarding rule.
//!
//! The caller retains the latest collection root and its neighbours, and
//! compares incoming announcements with that root. This timer retains no
//! roots and no change queue, only which neighbours the current interval
//! already covers. The neighbours [`WakeSchedule::poll`] returns are offered
//! the caller's *current* root once, even when several observations or
//! intervals were skipped.
//!
//! The Trickle-style policy uses two- to sixty-second intervals, a transmit
//! opportunity in the interval's second half, and redundancy threshold one
//! per neighbour. Announcements are unicast and nobody overhears them, so an
//! equal root heard from one neighbour suppresses only the announcement to
//! that neighbour. It does not authorize content or establish repair
//! completion. Failed sends receive later periodic opportunities rather than
//! an immediate retry loop.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::clock::Mono;

const MIN_INTERVAL: Duration = Duration::from_secs(2);
const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Pure operational soft state for one collection's outgoing announcements
/// to its neighbours `N`.
///
/// Supply independent uniform random words when an interval may begin. Random
/// input is explicit so tests need neither wall-clock sleeps nor a global RNG.
/// Fresh randomness gives peers opportunities to exchange which one speaks;
/// suppression is not a guarantee that each particular peer eventually speaks.
#[derive(Debug)]
pub(crate) struct WakeSchedule<N> {
    interval: Duration,
    interval_end: Mono,
    transmit_at: Option<Mono>,
    /// Neighbours this interval's opportunity skips: each announced the root
    /// the caller holds, or got the caller's reply.
    heard_equal: BTreeSet<N>,
    /// Neighbours owed an announcement despite `heard_equal`: they joined
    /// since the last opportunity.
    force_offer: BTreeSet<N>,
    short_next: bool,
}

impl<N: Copy + Ord> WakeSchedule<N> {
    /// Begin a short cold-start interval without requiring a root change.
    pub(crate) fn new(now: Mono, random: u64) -> Self {
        Self::begin(now, MIN_INTERVAL, random)
    }

    /// Next time the caller should poll, even after emission or suppression.
    ///
    /// Once the transmit opportunity is consumed, this is the interval end,
    /// not a stale transmit deadline. All normal deadlines are strictly in
    /// the future after a due poll (within `Mono`'s representable lifetime).
    pub(crate) fn deadline(&self) -> Mono {
        self.transmit_at.unwrap_or(self.interval_end)
    }

    /// Consume at most one current-state transmit opportunity: the
    /// `neighbours` to announce to now, which is none of them before the
    /// opportunity and each one this interval does not cover at it.
    ///
    /// At a boundary this also schedules the next interval. A late poll does
    /// not replay missed intervals: it offers at most the latest root and
    /// starts one fresh interval at `now`. The return value is scheduling,
    /// not evidence of send success or peer receipt.
    pub(crate) fn poll(
        &mut self,
        now: Mono,
        random: u64,
        neighbours: impl IntoIterator<Item = N>,
    ) -> Vec<N> {
        let mut transmit = Vec::new();
        if self.transmit_at.is_some_and(|at| now >= at) {
            transmit.extend(neighbours.into_iter().filter(|neighbour| {
                self.force_offer.contains(neighbour) || !self.heard_equal.contains(neighbour)
            }));
            self.transmit_at = None;
            self.force_offer.clear();
        }
        if now >= self.interval_end {
            let interval = if self.short_next {
                MIN_INTERVAL
            } else {
                self.interval.saturating_mul(2).min(MAX_INTERVAL)
            };
            // A neighbour arriving after the consumed opportunity needs an
            // offer in the next interval.
            let force_offer = std::mem::take(&mut self.force_offer);
            *self = Self::begin(now, interval, random);
            self.force_offer = force_offer;
        }
        transmit
    }

    /// The caller's current root changed; old equal notices no longer count.
    ///
    /// Coalesced changes do not keep sliding a minimum-interval deadline.
    /// A change after its opportunity was consumed requests a short next
    /// interval. An equal notice for the *new* root may still suppress us.
    pub(crate) fn local_changed(&mut self, now: Mono, random: u64) {
        self.expedite(now, random);
        self.heard_equal.clear();
    }

    /// Count `neighbour`'s equal-root announcement toward redundancy
    /// threshold one: this interval's opportunity skips it.
    ///
    /// This neither creates an echo nor moves a deadline. A notice observed
    /// after the interval expired is not charged to its future replacement;
    /// the already-due timer will begin that replacement on the next poll.
    pub(crate) fn consistent_root(&mut self, now: Mono, neighbour: N) {
        if now < self.interval_end {
            self.heard_equal.insert(neighbour);
        }
    }

    /// The caller answered `neighbour` with its current root at once. The
    /// answer counts as this interval's announcement to it.
    pub(crate) fn replied(&mut self, now: Mono, neighbour: N) {
        self.force_offer.remove(&neighbour);
        self.consistent_root(now, neighbour);
    }

    /// Offer our current root to a new neighbour, even if it announced an
    /// equal root. This is one scheduled offer, never an immediate echo.
    ///
    /// Repeated joins coalesce. There is at most one local emission per
    /// interval; a join after its opportunity carries to a short next interval.
    /// The offer is attempted within two minimum intervals when polled on
    /// time. Equal notices alone never force an offer.
    pub(crate) fn neighbor_joined(&mut self, now: Mono, random: u64, neighbour: N) {
        self.expedite(now, random);
        self.force_offer.insert(neighbour);
    }

    fn expedite(&mut self, now: Mono, random: u64) {
        if now >= self.interval_end || self.interval > MIN_INTERVAL {
            let force_offer = std::mem::take(&mut self.force_offer);
            *self = Self::begin(now, MIN_INTERVAL, random);
            self.force_offer = force_offer;
        } else {
            // Preserve this interval's opportunity, including one already
            // consumed. Activity asks for another short interval, not a queue
            // of old roots or a second emission from this same interval.
            self.short_next = true;
        }
    }

    fn begin(now: Mono, interval: Duration, random: u64) -> Self {
        // Intervals are bounded by sixty seconds, so these nanoseconds fit
        // u64. Multiply-high scales a uniform word to [0, width) with bin
        // populations differing by at most one, without a rejection loop.
        let half_ns = (interval.as_nanos() / 2) as u64;
        let width_ns = interval.as_nanos() as u64 - half_ns;
        let jitter_ns = ((u128::from(random) * u128::from(width_ns)) >> 64) as u64;
        Self {
            interval,
            interval_end: now + interval,
            transmit_at: Some(now + Duration::from_nanos(half_ns + jitter_ns)),
            heard_equal: BTreeSet::new(),
            force_offer: BTreeSet::new(),
            short_next: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u8 = 1;
    const B: u8 = 2;
    const BOTH: [u8; 2] = [A, B];

    #[test]
    fn cold_start_randomizes_inside_the_second_half() {
        let now = crate::clock::mono_now();
        let earliest = WakeSchedule::<u8>::new(now, 0);
        let latest = WakeSchedule::<u8>::new(now, u64::MAX);
        assert_eq!(earliest.deadline(), now + Duration::from_secs(1));
        assert_eq!(latest.deadline(), now + Duration::from_nanos(1_999_999_999));
        assert!(latest.deadline() < latest.interval_end);
    }

    #[test]
    fn equal_notices_suppress_only_their_neighbour_without_echo_or_stale_deadline() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for _ in 0..10_000 {
            schedule.consistent_root(now, A);
            assert_eq!(schedule.deadline(), due);
        }
        assert_eq!(schedule.poll(due, 0, BOTH), [B]);
        assert!(schedule.deadline() > due);
        assert!(schedule.poll(due, 0, BOTH).is_empty());
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, BOTH).is_empty());
        assert!(schedule.deadline() > boundary);
        assert_eq!(schedule.poll(schedule.deadline(), 0, BOTH), BOTH);
    }

    #[test]
    fn minimum_interval_changes_do_not_postpone_transmission() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for milliseconds in 0..1_000 {
            schedule.local_changed(now + Duration::from_millis(milliseconds), u64::MAX);
            assert_eq!(schedule.deadline(), due);
        }
        assert_eq!(schedule.poll(due, 0, [A]), [A]);
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, [A]).is_empty());
        assert_eq!(schedule.interval, MIN_INTERVAL);
    }

    #[test]
    fn a_change_expedites_a_long_interval() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::<u8>::begin(now, MAX_INTERVAL, 0);
        let notice = now + Duration::from_secs(3);
        schedule.local_changed(notice, 0);
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert_eq!(schedule.deadline(), notice + Duration::from_secs(1));
    }

    #[test]
    fn changed_root_discards_old_consistency_but_new_equal_can_suppress() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        schedule.consistent_root(now, A);
        let due = schedule.deadline();
        schedule.local_changed(now + Duration::from_millis(100), u64::MAX);
        assert_eq!(schedule.deadline(), due);
        assert_eq!(schedule.poll(due, 0, [A]), [A]);

        let mut schedule = WakeSchedule::new(now, 0);
        schedule.local_changed(now, 0);
        schedule.consistent_root(now, A);
        assert!(schedule.poll(schedule.deadline(), 0, [A]).is_empty());
    }

    #[test]
    fn local_change_after_suppression_gets_a_fresh_short_opportunity() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        schedule.consistent_root(now, A);
        let due = schedule.deadline();
        assert!(schedule.poll(due, 0, [A]).is_empty());
        schedule.local_changed(due + Duration::from_millis(1), 0);
        assert!(schedule.deadline() > due);
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, [A]).is_empty());
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert_eq!(schedule.poll(schedule.deadline(), 0, [A]), [A]);
    }

    #[test]
    fn local_change_after_send_does_not_send_twice_in_one_interval() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        assert_eq!(schedule.poll(due, 0, [A]), [A]);
        schedule.local_changed(due, u64::MAX);
        assert!(schedule.poll(due, 0, [A]).is_empty());
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, [A]).is_empty());
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert_eq!(schedule.poll(schedule.deadline(), 0, [A]), [A]);
    }

    #[test]
    fn new_neighbour_gets_one_forced_offer_despite_equal_notices() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for milliseconds in 0..1_000 {
            let at = now + Duration::from_millis(milliseconds);
            schedule.neighbor_joined(at, u64::MAX, A);
            schedule.consistent_root(at, A);
            schedule.consistent_root(at, B);
            assert_eq!(schedule.deadline(), due);
        }
        assert_eq!(schedule.poll(due, 0, BOTH), [A]);
        assert!(schedule.poll(due, 0, BOTH).is_empty());
        assert!(schedule.deadline() > due);
    }

    #[test]
    fn neighbour_after_consumed_opportunity_is_carried_once() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        assert_eq!(schedule.poll(due, 0, BOTH), BOTH);
        for _ in 0..100 {
            schedule.neighbor_joined(due, u64::MAX, A);
            schedule.consistent_root(due, A);
        }
        assert!(schedule.poll(due, 0, BOTH).is_empty());
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, BOTH).is_empty());
        schedule.consistent_root(boundary, A);
        schedule.consistent_root(boundary, B);
        assert_eq!(schedule.poll(schedule.deadline(), 0, BOTH), [A]);
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, BOTH).is_empty());
        schedule.consistent_root(boundary, A);
        schedule.consistent_root(boundary, B);
        assert!(schedule.poll(schedule.deadline(), 0, BOTH).is_empty());
    }

    #[test]
    fn a_reply_counts_as_the_interval_announcement_until_the_root_changes() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        schedule.neighbor_joined(now, 0, A);
        schedule.replied(now, A);
        assert_eq!(schedule.poll(schedule.deadline(), 0, BOTH), [B]);

        let mut schedule = WakeSchedule::new(now, 0);
        schedule.replied(now, A);
        schedule.local_changed(now, 0);
        assert_eq!(schedule.poll(schedule.deadline(), 0, BOTH), BOTH);
    }

    #[test]
    fn quiet_intervals_grow_to_a_cap_and_never_leave_a_busy_deadline() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        for expected in [2, 4, 8, 16, 32, 60, 60, 60] {
            assert_eq!(schedule.interval, Duration::from_secs(expected));
            let due = schedule.deadline();
            assert_eq!(schedule.poll(due, 0, [A]), [A]);
            assert!(schedule.deadline() > due);
            let boundary = schedule.deadline();
            assert!(schedule.poll(boundary, u64::MAX, [A]).is_empty());
            assert!(schedule.deadline() > boundary);
        }
    }

    #[test]
    fn one_lost_announcement_does_not_exhaust_future_offers() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let lost = schedule.deadline();
        assert_eq!(schedule.poll(lost, 0, [A]), [A]);
        let boundary = schedule.deadline();
        assert!(schedule.poll(boundary, 0, [A]).is_empty());
        let retry = schedule.deadline();
        assert!(retry > lost);
        assert_eq!(schedule.poll(retry, 0, [A]), [A]);
    }

    /// `a` announces to its neighbour B and `b` to its neighbour A.
    #[test]
    fn fresh_randomness_can_exchange_the_suppressed_speaker() {
        let now = crate::clock::mono_now();
        let mut a = WakeSchedule::new(now, 0);
        let mut b = WakeSchedule::new(now, u64::MAX);
        let first = a.deadline();
        assert_eq!(a.poll(first, 0, [B]), [B]);
        b.consistent_root(first, A);
        assert!(b.poll(b.deadline(), 0, [A]).is_empty());
        let boundary = a.deadline();
        assert!(a.poll(boundary, u64::MAX, [B]).is_empty());
        assert!(b.poll(boundary, 0, [A]).is_empty());
        let second = b.deadline();
        assert_eq!(b.poll(second, 0, [A]), [A]);
        a.consistent_root(second, B);
        assert!(a.poll(a.deadline(), 0, [B]).is_empty());
    }

    #[test]
    fn late_poll_rebases_without_replaying_missed_intervals() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let late = now + Duration::from_secs(3_600);
        assert_eq!(schedule.poll(late, 0, [A]), [A]);
        assert!(schedule.deadline() > late);
        assert!(schedule.poll(late, 0, [A]).is_empty());
    }
}
