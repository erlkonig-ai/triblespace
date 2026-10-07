//! Bounded, randomized push opportunities for one collection; never a
//! forwarding rule.
//!
//! The caller keeps the collection's root and its neighbours and pushes the
//! root to every neighbour it sends to when [`WakeSchedule::poll`] says an
//! opportunity is due. This timer keeps no roots and no change queue, only
//! its interval and whether the interval's one opportunity was taken. A
//! late poll offers at most the caller's current root once, even when
//! several observations or intervals were skipped.
//!
//! The Trickle-style policy uses two- to sixty-second intervals and a
//! transmit opportunity in the interval's second half. A quiet collection
//! doubles its interval to the cap; a local change, a neighbour that joined
//! or a push that landed here asks for a short one. The schedule authorizes
//! no content and establishes no completion: a push that fails gets a later
//! periodic opportunity rather than an immediate retry loop.

use std::time::Duration;

use crate::clock::Mono;

const MIN_INTERVAL: Duration = Duration::from_secs(2);
const MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Pure operational soft state for one collection's outgoing pushes.
///
/// Supply independent uniform random words when an interval may begin. Random
/// input is explicit so tests need neither wall-clock sleeps nor a global RNG.
#[derive(Debug)]
pub(crate) struct WakeSchedule {
    interval: Duration,
    interval_end: Mono,
    transmit_at: Option<Mono>,
    short_next: bool,
}

impl WakeSchedule {
    /// Begin a short cold-start interval without requiring a root change.
    pub(crate) fn new(now: Mono, random: u64) -> Self {
        Self::begin(now, MIN_INTERVAL, random)
    }

    /// Next time the caller should poll, even after an opportunity was taken.
    ///
    /// Once the transmit opportunity is consumed, this is the interval end,
    /// not a stale transmit deadline. All normal deadlines are strictly in
    /// the future after a due poll (within `Mono`'s representable lifetime).
    pub(crate) fn deadline(&self) -> Mono {
        self.transmit_at.unwrap_or(self.interval_end)
    }

    /// Consume at most one transmit opportunity: whether the caller pushes
    /// its current root to its neighbours now, which it does once per
    /// interval, at the opportunity.
    ///
    /// At a boundary this also schedules the next interval. A late poll does
    /// not replay missed intervals: it offers at most the latest root and
    /// starts one fresh interval at `now`. The return value is scheduling,
    /// not evidence of send success or peer receipt.
    pub(crate) fn poll(&mut self, now: Mono, random: u64) -> bool {
        let transmit = self.transmit_at.is_some_and(|at| now >= at);
        if transmit {
            self.transmit_at = None;
        }
        if now >= self.interval_end {
            let interval = if self.short_next {
                MIN_INTERVAL
            } else {
                self.interval.saturating_mul(2).min(MAX_INTERVAL)
            };
            *self = Self::begin(now, interval, random);
        }
        transmit
    }

    /// The caller's current root changed, or a push landed here.
    ///
    /// Coalesced changes do not keep sliding a minimum-interval deadline.
    /// A change after its opportunity was consumed requests a short next
    /// interval.
    pub(crate) fn local_changed(&mut self, now: Mono, random: u64) {
        self.expedite(now, random);
    }

    /// Offer the current root to a new neighbour. This is one scheduled
    /// offer, never an immediate push.
    ///
    /// Repeated joins coalesce. There is at most one local emission per
    /// interval; a join after its opportunity carries to a short next
    /// interval. The offer is attempted within two minimum intervals when
    /// polled on time.
    pub(crate) fn neighbour_joined(&mut self, now: Mono, random: u64) {
        self.expedite(now, random);
    }

    fn expedite(&mut self, now: Mono, random: u64) {
        if now >= self.interval_end || self.interval > MIN_INTERVAL {
            *self = Self::begin(now, MIN_INTERVAL, random);
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
    fn one_opportunity_per_interval_and_no_stale_deadline() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        assert!(!schedule.poll(now, 0));
        assert_eq!(schedule.deadline(), due);
        assert!(schedule.poll(due, 0));
        assert!(schedule.deadline() > due);
        assert!(!schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert!(schedule.deadline() > boundary);
        assert!(schedule.poll(schedule.deadline(), 0));
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
        assert!(schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert_eq!(schedule.interval, MIN_INTERVAL);
    }

    #[test]
    fn a_change_expedites_a_long_interval() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::begin(now, MAX_INTERVAL, 0);
        let notice = now + Duration::from_secs(3);
        schedule.local_changed(notice, 0);
        assert_eq!(schedule.interval, MIN_INTERVAL);
        assert_eq!(schedule.deadline(), notice + Duration::from_secs(1));
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

    /// A neighbour that joins is offered the root within two minimum
    /// intervals: at this interval's opportunity, or at the short next
    /// interval's when this one's was already taken.
    #[test]
    fn a_joined_neighbour_is_offered_within_two_minimum_intervals() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let due = schedule.deadline();
        for milliseconds in 0..1_000 {
            schedule.neighbour_joined(now + Duration::from_millis(milliseconds), u64::MAX);
            assert_eq!(schedule.deadline(), due);
        }
        assert!(schedule.poll(due, 0));
        for _ in 0..100 {
            schedule.neighbour_joined(due, u64::MAX);
        }
        assert!(!schedule.poll(due, 0));
        let boundary = schedule.deadline();
        assert!(!schedule.poll(boundary, 0));
        assert_eq!(schedule.interval, MIN_INTERVAL);
        let offered = schedule.deadline();
        assert!(offered <= due + 2 * MIN_INTERVAL);
        assert!(schedule.poll(offered, 0));

        // A join during a long interval shortens it.
        let mut schedule = WakeSchedule::begin(now, MAX_INTERVAL, 0);
        schedule.neighbour_joined(now + Duration::from_secs(10), 0);
        assert!(schedule.deadline() <= now + Duration::from_secs(10) + MIN_INTERVAL);
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
    fn one_failed_push_does_not_exhaust_future_offers() {
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
    fn late_poll_rebases_without_replaying_missed_intervals() {
        let now = crate::clock::mono_now();
        let mut schedule = WakeSchedule::new(now, 0);
        let late = now + Duration::from_secs(3_600);
        assert!(schedule.poll(late, 0));
        assert!(schedule.deadline() > late);
        assert!(!schedule.poll(late, 0));
    }
}
