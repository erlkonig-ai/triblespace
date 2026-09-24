//! Bounded, randomized local wake announcements; never a gossip-forwarding rule.
//!
//! The caller retains the latest collection root and compares incoming notices
//! with that root. This timer retains no roots, peer roster, or change queue.
//! A `true` result from [`WakeSchedule::poll`] offers the caller's *current*
//! root once, even when several observations or intervals were skipped.
//!
//! The Trickle-style policy uses two- to sixty-second intervals, a transmit
//! opportunity in the interval's second half, and redundancy threshold one.
//! Hearing an equal root suppresses only this node's local opportunity. It
//! does not suppress the separate downstream relay obligation, authorize content, or
//! establish repair completion. Failed broadcasts receive later periodic
//! opportunities rather than an immediate retry loop.

use std::time::Duration;

use crate::clock::Mono;

const MIN_INTERVAL: Duration = Duration::from_secs(2);
const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Pure operational soft state for one active collection's outgoing wake.
///
/// Supply independent uniform random words when an interval may begin. Random
/// input is explicit so tests need neither wall-clock sleeps nor a global RNG.
/// Fresh randomness gives peers opportunities to exchange which one speaks;
/// suppression is not a guarantee that each particular peer eventually speaks.
#[derive(Debug)]
pub(crate) struct WakeSchedule {
    interval: Duration,
    interval_end: Mono,
    transmit_at: Option<Mono>,
    heard_equal: bool,
    force_offer: bool,
    short_next: bool,
}

impl WakeSchedule {
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

    /// Consume at most one current-state transmit opportunity.
    ///
    /// At a boundary this also schedules the next interval. A late poll does
    /// not replay missed intervals: it offers at most the latest root and
    /// starts one fresh interval at `now`. The return value is scheduling,
    /// not evidence of broadcast success or peer receipt.
    pub(crate) fn poll(&mut self, now: Mono, random: u64) -> bool {
        let due = self.transmit_at.is_some_and(|at| now >= at);
        let transmit = due && (self.force_offer || !self.heard_equal);
        if due {
            self.transmit_at = None;
            self.force_offer = false;
        }
        if now >= self.interval_end {
            let interval = if self.short_next {
                MIN_INTERVAL
            } else {
                self.interval.saturating_mul(2).min(MAX_INTERVAL)
            };
            // A neighbor arriving after the consumed opportunity needs an
            // offer in the next interval. Multiple arrivals share this bit.
            let force_offer = self.force_offer;
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
        self.heard_equal = false;
    }

    /// A signed notice differs from the caller's current root.
    ///
    /// Repeated mismatches at minimum interval never restart that interval:
    /// traffic cannot indefinitely postpone its scheduled opportunity. Equal
    /// notices already heard in this interval still suppress redundant local
    /// emission; remote disagreement did not itself change our local root.
    pub(crate) fn different_root(&mut self, now: Mono, random: u64) {
        self.expedite(now, random);
    }

    /// Count an equal-root notice toward redundancy threshold one.
    ///
    /// This neither creates an echo nor moves a deadline. A notice observed
    /// after the interval expired is not charged to its future replacement;
    /// the already-due timer will begin that replacement on the next poll.
    pub(crate) fn consistent_root(&mut self, now: Mono) {
        if now < self.interval_end {
            self.heard_equal = true;
        }
    }

    /// Offer our current root to a new neighbor, even if another equal root
    /// was heard. This is one scheduled offer, never an immediate echo.
    ///
    /// Repeated joins coalesce. There is at most one local emission per
    /// interval; a join after its opportunity carries to a short next interval.
    /// The offer is attempted within two minimum intervals when polled on
    /// time. Equal notices alone never set this force-offer bit.
    pub(crate) fn neighbor_joined(&mut self, now: Mono, random: u64) {
        self.expedite(now, random);
        self.force_offer = true;
    }

    fn expedite(&mut self, now: Mono, random: u64) {
        if now >= self.interval_end || self.interval > MIN_INTERVAL {
            let force_offer = self.force_offer;
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
            heard_equal: false,
            force_offer: false,
            short_next: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_randomizes_inside_the_second_half() {
        let now = crate::clock::mono_now();
        let earliest = WakeSchedule::new(now, 0);
        let latest = WakeSchedule::new(now, u64::MAX);
        assert_eq!(earliest.deadline(), now + Duration::from_secs(1));
        assert_eq!(latest.deadline(), now + Duration::from_nanos(1_999_999_999));
        assert!(latest.deadline() < latest.interval_end);
    }

    #[test]
    fn equal_notices_suppress_without_echo_or_stale_deadline() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for _ in 0..10_000 {
            schedule.consistent_root(now);
            assert_eq!(schedule.deadline(), due);
        }
        assert!(!schedule.poll(due, 0));
        assert!(schedule.deadline() > due);
        assert!(!schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert!(schedule.deadline() > boundary);
        assert!(schedule.poll(schedule.deadline(), 0));
    }

    #[test]
    fn minimum_interval_mismatches_do_not_postpone_transmission() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for milliseconds in 0..1_000 {
            schedule.different_root(now + Duration::from_millis(milliseconds), u64::MAX);
            assert_eq!(schedule.deadline(), due);
        }
        assert!(schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert_eq!(schedule.interval, MIN_INTERVAL);
    }

    #[test]
    fn mismatch_expedites_a_long_interval() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::begin(now, MAX_INTERVAL, 0);
        let notice = now + Duration::from_secs(3);
        schedule.different_root(notice, 0);
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert_eq!(schedule.deadline(), notice + Duration::from_secs(1));
    }

    #[test]
    fn changed_root_discards_old_consistency_but_new_equal_can_suppress() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        schedule.consistent_root(now);
        let due = schedule.deadline();
        schedule.local_changed(now + Duration::from_millis(100), u64::MAX);
        assert_eq!(schedule.deadline(), due);
        assert!(schedule.poll(due, 0));

        let mut schedule = WakeSchedule::new(now, 0);
        schedule.local_changed(now, 0);
        schedule.consistent_root(now);
        assert!(!schedule.poll(schedule.deadline(), 0));
    }

    #[test]
    fn local_change_after_suppression_gets_a_fresh_short_opportunity() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        schedule.consistent_root(now);
        let due = schedule.deadline();
        assert!(!schedule.poll(due, 0));
        schedule.local_changed(due + Duration::from_millis(1), 0);
        assert!(schedule.deadline() > due);
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert!(schedule.poll(schedule.deadline(), 0));
    }

    #[test]
    fn local_change_after_send_does_not_send_twice_in_one_interval() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        assert!(schedule.poll(due, 0));
        schedule.local_changed(due, u64::MAX);
        assert!(!schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert!(schedule.poll(schedule.deadline(), 0));
    }

    #[test]
    fn new_neighbor_gets_one_forced_offer_despite_equal_notices() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for milliseconds in 0..1_000 {
            let at = now + Duration::from_millis(milliseconds);
            schedule.neighbor_joined(at, u64::MAX);
            schedule.consistent_root(at);
            assert_eq!(schedule.deadline(), due);
        }
        assert!(schedule.poll(due, 0));
        assert!(!schedule.poll(due, 0));
        assert!(schedule.deadline() > due);
    }

    #[test]
    fn neighbor_after_consumed_opportunity_is_carried_once() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        assert!(schedule.poll(due, 0));
        for _ in 0..100 {
            schedule.neighbor_joined(due, u64::MAX);
            schedule.consistent_root(due);
        }
        assert!(!schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        schedule.consistent_root(boundary);
        assert!(schedule.poll(schedule.deadline(), 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        schedule.consistent_root(boundary);
        assert!(!schedule.poll(schedule.deadline(), 0));
    }

    #[test]
    fn quiet_intervals_grow_to_a_cap_and_never_leave_a_busy_deadline() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        for expected in [2, 4, 8, 16, 32, 60, 60, 60] {
            assert_eq!(schedule.interval, Duration::from_secs(expected));
            let due = schedule.deadline();
            assert!(schedule.poll(due, 0));
            assert!(schedule.deadline() > due);
            let boundary = schedule.deadline();
            assert!(!schedule.poll(boundary, u64::MAX));
            assert!(schedule.deadline() > boundary);
        }
    }

    #[test]
    fn one_lost_announcement_does_not_exhaust_future_offers() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let lost = schedule.deadline();
        assert!(schedule.poll(lost, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        let retry = schedule.deadline();
        assert!(retry > lost);
        assert!(schedule.poll(retry, 0));
    }

    #[test]
    fn fresh_randomness_can_exchange_the_suppressed_speaker() {
        let now = crate::clock::mono_now();
        let mut a = WakeSchedule::new(now, 0);
        let mut b = WakeSchedule::new(now, u64::MAX);
        let first = a.deadline();
        assert!(a.poll(first, 0));
        b.consistent_root(first);
        assert!(!b.poll(b.deadline(), 0));
        let boundary = a.deadline();
        assert!(!a.poll(boundary, u64::MAX));
        assert!(!b.poll(boundary, 0));
        let second = b.deadline();
        assert!(b.poll(second, 0));
        a.consistent_root(second);
        assert!(!a.poll(a.deadline(), 0));
    }

    #[test]
    fn late_poll_rebases_without_replaying_missed_intervals() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let late = now + Duration::from_secs(3_600);
        assert!(schedule.poll(late, 0));
        assert!(schedule.deadline() > late);
        assert!(!schedule.poll(late, 0));
    }
}
