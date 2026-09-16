use ed25519_dalek::SigningKey;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

use super::*;

const NS: u128 = 1_000_000_000;

fn interval(lower_seconds: i128, upper_seconds: i128) -> Inline<inlineencodings::NsTAIInterval> {
    let epoch = |seconds| {
        hifitime::Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(
            seconds * NS as i128,
        ))
    };
    (epoch(lower_seconds), epoch(upper_seconds))
        .try_to_inline()
        .unwrap()
}

fn subject(seed: u8, worker: &str, role: &str) -> (Id, Fragment) {
    let id = genid();
    let node = SigningKey::from_bytes(&[seed; 32]).verifying_key();
    let facts = entity! { &id @
        health_record::attrs::endpoint: node,
        attrs::worker: worker,
        attrs::role: role,
    };
    (id.id, facts)
}

fn sample(
    subject: Id,
    session: Id,
    at_seconds: i128,
    elapsed_seconds: u128,
) -> (ExclusiveId, Fragment) {
    let id = genid();
    let facts = entity! { &id @
        metadata::tag: &KIND_SAMPLE,
        attrs::subject: &subject,
        health_record::attrs::session: &session,
        metadata::created_at: interval(at_seconds, at_seconds),
        attrs::elapsed_ns: elapsed_seconds * NS,
    };
    (id, facts)
}

fn metric(report: &WorkerReport, wanted: Metric) -> &MetricValue {
    report
        .metrics
        .iter()
        .find(|value| value.metric == wanted)
        .expect("every known metric has a projection, including absence")
}

fn reports(facts: &Fragment, now_seconds: i128, max_age_seconds: u64) -> Vec<WorkerReport> {
    observe(
        facts.facts(),
        now_seconds * NS as i128,
        Duration::from_secs(max_age_seconds),
    )
}

#[test]
fn three_nodes_distinguish_busy_measured_idle_and_unobserved_or_stale() {
    let session = genid().id;
    let (busy, mut facts) = subject(1, "maintainer", "maintenance");
    let (idle, idle_subject) = subject(2, "maintainer", "maintenance");
    let (unobserved, third_subject) = subject(3, "maintainer", "maintenance");
    facts += idle_subject;
    facts += third_subject;

    let (busy_sample, busy_facts) = sample(busy, session, 100, 80);
    facts += busy_facts;
    facts += entity! { &busy_sample @
        attrs::active: 1_u128,
        attrs::queued: 8_u128,
        attrs::pending_merges: 3_u128,
        attrs::pending_derives: 5_u128,
        attrs::backend: "cpu",
        attrs::parallelism: 4_u128,
    };
    let (idle_sample, idle_facts) = sample(idle, session, 100, 80);
    facts += idle_facts;
    facts += entity! { &idle_sample @
        attrs::active: 0_u128,
        attrs::queued: 0_u128,
        attrs::pending_merges: 0_u128,
        attrs::pending_derives: 0_u128,
    };

    let observed = reports(&facts, 101, 30);
    assert_eq!(
        observed.len(),
        2,
        "no sample does not manufacture an idle worker"
    );
    let running = observed
        .iter()
        .find(|report| report.subject == busy)
        .unwrap();
    assert_eq!(running.freshness, Freshness::Fresh);
    assert_eq!(metric(running, Metric::Active).value, CountMetric::Value(1));
    assert_eq!(
        metric(running, Metric::Parallelism).value,
        CountMetric::Value(4)
    );
    assert_eq!(metric(running, Metric::CpuNs).value, CountMetric::Absent);
    let resting = observed
        .iter()
        .find(|report| report.subject == idle)
        .unwrap();
    assert_eq!(resting.freshness, Freshness::Fresh);
    assert_eq!(metric(resting, Metric::Active).value, CountMetric::Value(0));
    assert_eq!(metric(resting, Metric::Queued).value, CountMetric::Value(0));

    let (old_sample, old_facts) = sample(unobserved, session, 10, 5);
    facts += old_facts;
    facts += entity! { &old_sample @ attrs::active: 0_u128 };
    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 3);
    let old = observed
        .iter()
        .find(|report| report.subject == unobserved)
        .unwrap();
    assert_eq!(old.freshness, Freshness::Stale);
    assert_eq!(old.age_seconds, Some(91));
    assert_eq!(metric(old, Metric::Active).value, CountMetric::Value(0));
    assert!(old.metrics.iter().all(|value| value.per_second.is_none()));
}

#[test]
fn same_session_rates_use_monotonic_elapsed_and_cpu_can_exceed_one_core() {
    let session = genid().id;
    let (worker, mut facts) = subject(4, "custody-process", "process");
    let (first, first_facts) = sample(worker, session, 80, 100);
    facts += first_facts;
    facts += entity! { &first @
        attrs::completed: 10_u128,
        attrs::received_bytes: 1_024_u128,
        attrs::cpu_ns: 20 * NS,
        attrs::queued: 8_u128,
    };
    let (second, second_facts) = sample(worker, session, 100, 110);
    facts += second_facts;
    facts += entity! { &second @
        attrs::completed: 30_u128,
        attrs::received_bytes: 3_072_u128,
        attrs::cpu_ns: 45 * NS,
        attrs::queued: 4_u128,
    };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 1);
    let worker = &observed[0];
    assert_eq!(metric(worker, Metric::Completed).per_second, Some(2.0));
    assert_eq!(
        metric(worker, Metric::ReceivedBytes).per_second,
        Some(204.8)
    );
    assert_eq!(
        metric(worker, Metric::CpuNs)
            .per_second
            .map(|rate| rate / 1e9),
        Some(2.5)
    );
    assert_eq!(
        metric(worker, Metric::Queued).per_second,
        None,
        "a gauge is not a counter"
    );
}

#[test]
fn zero_is_measured_but_missing_current_or_previous_metrics_have_no_rate() {
    let session = genid().id;
    let (worker, mut facts) = subject(5, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @
        attrs::completed: 0_u128,
        attrs::received_bytes: 12_u128,
    };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @
        attrs::active: 0_u128,
        attrs::completed: 0_u128,
        attrs::sent_bytes: 0_u128,
    };

    let observed = reports(&facts, 101, 30);
    let worker = &observed[0];
    assert_eq!(
        metric(worker, Metric::Completed).value,
        CountMetric::Value(0)
    );
    assert_eq!(metric(worker, Metric::Completed).per_second, Some(0.0));
    assert_eq!(metric(worker, Metric::Active).value, CountMetric::Value(0));
    assert_eq!(metric(worker, Metric::Active).per_second, None);
    assert_eq!(
        metric(worker, Metric::ReceivedBytes).value,
        CountMetric::Absent
    );
    assert_eq!(metric(worker, Metric::ReceivedBytes).per_second, None);
    assert_eq!(
        metric(worker, Metric::SentBytes).value,
        CountMetric::Value(0)
    );
    assert_eq!(metric(worker, Metric::SentBytes).per_second, None);
}

#[test]
fn reset_counters_do_not_become_negative_or_wrapped_rates() {
    let session = genid().id;
    let (worker, mut facts) = subject(6, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::completed: u128::MAX };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @ attrs::completed: 1_u128 };

    let observed = reports(&facts, 101, 30);
    assert_eq!(
        metric(&observed[0], Metric::Completed).value,
        CountMetric::Value(1)
    );
    assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
}

#[test]
fn a_new_process_session_does_not_inherit_the_previous_process_rate() {
    let (worker, mut facts) = subject(7, "maintainer", "maintenance");
    let (first, first_facts) = sample(worker, genid().id, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::completed: 10_u128 };
    let session = genid().id;
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @ attrs::completed: 20_u128 };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed[0].session, session);
    assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
}

#[test]
fn equal_or_reversed_elapsed_times_suppress_rates() {
    for elapsed_seconds in [10, 9] {
        let session = genid().id;
        let (worker, mut facts) = subject(8, "custody", "custody");
        let (first, first_facts) = sample(worker, session, 90, 10);
        facts += first_facts;
        facts += entity! { &first @ attrs::completed: 10_u128 };
        let (second, second_facts) = sample(worker, session, 100, elapsed_seconds);
        facts += second_facts;
        facts += entity! { &second @ attrs::completed: 20_u128 };

        let observed = reports(&facts, 101, 30);
        assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
    }
}

#[test]
fn stale_future_or_old_prior_observations_suppress_rates() {
    for (previous_at, current_at, now, max_age, freshness) in [
        (90, 100, 130, 30, Freshness::Stale),
        (90, 100, 99, 30, Freshness::Future),
        (70, 100, 101, 30, Freshness::Fresh),
    ] {
        let session = genid().id;
        let (worker, mut facts) = subject(9, "custody", "custody");
        let (first, first_facts) = sample(worker, session, previous_at, 10);
        facts += first_facts;
        facts += entity! { &first @ attrs::completed: 10_u128 };
        let (second, second_facts) = sample(worker, session, current_at, 20);
        facts += second_facts;
        facts += entity! { &second @ attrs::completed: 20_u128 };

        let observed = reports(&facts, now, max_age);
        assert_eq!(observed[0].freshness, freshness);
        assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
        if freshness == Freshness::Future {
            assert_eq!(observed[0].age_seconds, None);
        }
    }
}

#[test]
fn opaque_ids_and_unknown_additive_facts_preserve_visibility() {
    for _ in 0..8 {
        let session = genid().id;
        let (worker, mut facts) = subject(10, "future-worker", "future-role");
        let (report, report_facts) = sample(worker, session, 100, 20);
        facts += report_facts;
        facts += entity! { &report @ attrs::active: 3_u128 };
        let before = reports(&facts, 101, 30);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].subject, worker);
        assert_eq!(before[0].report, report.id);
        assert_eq!(before[0].role, "future-role");

        let annotation = genid();
        facts.facts_mut().insert(&Trible::new(
            &report,
            &annotation,
            &Inline::<UnknownInline>::new([0xff; 32]),
        ));
        // A U256 that the u128 projection cannot decode is skipped rather
        // than poisoning this row or any unrelated worker's observation.
        facts.facts_mut().insert(&Trible::new(
            &report,
            &attrs::active.id(),
            &Inline::<inlineencodings::U256BE>::new([0xff; 32]),
        ));
        facts += entity! { &report @ metadata::tag: &genid() };
        assert_eq!(reports(&facts, 101, 30), before);
    }
}

#[test]
fn undecodable_newer_header_does_not_hide_a_readable_sample() {
    let session = genid().id;
    let (worker, mut facts) = subject(11, "custody", "custody");
    let (readable, readable_facts) = sample(worker, session, 90, 10);
    facts += readable_facts;
    facts += entity! { &readable @ attrs::active: 1_u128 };
    let unknown = genid();
    facts += entity! { &unknown @
        metadata::tag: &KIND_SAMPLE,
        attrs::subject: &worker,
        health_record::attrs::session: &session,
        metadata::created_at: interval(100, 100),
    };
    facts.facts_mut().insert(&Trible::new(
        &unknown,
        &attrs::elapsed_ns.id(),
        &Inline::<inlineencodings::U256BE>::new([0xff; 32]),
    ));

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].report, readable.id);
    assert_eq!(
        metric(&observed[0], Metric::Active).value,
        CountMetric::Value(1)
    );
}

#[test]
fn repeated_metrics_remain_ambiguous_without_failing_other_rates_or_workers() {
    let session = genid().id;
    let (worker, mut facts) = subject(12, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @
        attrs::completed: 10_u128,
        attrs::sent_bytes: 100_u128,
    };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @
        attrs::active*: [3_u128, 2, 3],
        attrs::completed*: [20_u128, 21],
        attrs::sent_bytes: 200_u128,
    };
    let (other, other_subject) = subject(13, "maintainer", "maintenance");
    facts += other_subject;
    let (other_sample, other_facts) = sample(other, session, 100, 20);
    facts += other_facts;
    facts += entity! { &other_sample @ attrs::active: 0_u128 };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 2);
    let worker = observed
        .iter()
        .find(|report| report.subject == worker)
        .unwrap();
    assert_eq!(
        metric(worker, Metric::Active).value,
        CountMetric::Ambiguous(vec![2, 3])
    );
    assert_eq!(
        metric(worker, Metric::Completed).value,
        CountMetric::Ambiguous(vec![20, 21])
    );
    assert_eq!(metric(worker, Metric::Completed).per_second, None);
    assert_eq!(metric(worker, Metric::SentBytes).per_second, Some(10.0));
    let other = observed
        .iter()
        .find(|report| report.subject == other)
        .unwrap();
    assert_eq!(metric(other, Metric::Active).value, CountMetric::Value(0));
}

#[test]
fn an_ambiguous_previous_counter_does_not_supply_a_rate() {
    let session = genid().id;
    let (worker, mut facts) = subject(14, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::completed*: [10_u128, 11] };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @ attrs::completed: 20_u128 };

    let observed = reports(&facts, 101, 30);
    assert_eq!(
        metric(&observed[0], Metric::Completed).value,
        CountMetric::Value(20)
    );
    assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
}

#[test]
fn duplicate_projected_header_witnesses_leave_room_for_the_previous_sample() {
    let session = genid().id;
    let (worker, mut facts) = subject(15, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::completed: 10_u128 };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @
        // Both stated intervals project the same upper observation time.
        metadata::created_at: interval(99, 100),
        attrs::completed: 30_u128,
    };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].report, second.id);
    assert_eq!(
        metric(&observed[0], Metric::Completed).per_second,
        Some(2.0)
    );
}

#[test]
fn distinct_header_alternatives_do_not_invent_an_earlier_report() {
    let session = genid().id;
    let (worker, mut facts) = subject(16, "custody", "custody");
    let (first, first_facts) = sample(worker, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::completed: 10_u128 };
    let (second, second_facts) = sample(worker, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @
        attrs::elapsed_ns: 21 * NS,
        attrs::completed: 30_u128,
    };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].report, second.id);
    assert_eq!(
        metric(&observed[0], Metric::Completed).value,
        CountMetric::Value(30)
    );
    assert_eq!(metric(&observed[0], Metric::Completed).per_second, None);
}

#[test]
fn subject_labels_are_whole_witnesses_and_optional_scope_is_preserved() {
    let session = genid().id;
    let subject = genid();
    let node = SigningKey::from_bytes(&[17; 32]).verifying_key();
    let peer = SigningKey::from_bytes(&[18; 32]).verifying_key();
    // This is opaque test data, not a newly defined schema or protocol ID.
    let target = triblespace_core::collection::CollectionHandle::new([19; 32]);
    let mut facts = entity! { &subject @
        health_record::attrs::endpoint: node,
        attrs::worker*: ["custody", "reader", "custody"],
        attrs::role: "link",
        health_record::attrs::peer*: [peer, peer],
        health_record::attrs::collection: target,
    };
    let (report, report_facts) = sample(subject.id, session, 100, 20);
    facts += report_facts;
    facts += entity! { &report @
        attrs::backend*: ["quic", "quic"],
        attrs::path*: ["direct", "direct"],
    };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 2);
    assert_eq!(
        observed
            .iter()
            .map(|row| row.worker.as_str())
            .collect::<Vec<_>>(),
        vec!["custody", "reader"]
    );
    for row in observed {
        assert_eq!(row.node, node.to_bytes());
        assert_eq!(row.role, "link");
        assert_eq!(row.peers, vec![peer.to_bytes()]);
        assert_eq!(row.targets, vec![target.raw]);
        assert_eq!(row.backends, vec!["quic"]);
        assert_eq!(row.paths, vec!["direct"]);
    }
}

#[test]
fn separate_stage_subjects_keep_work_durations_distinct_from_process_cpu() {
    let session = genid().id;
    let node = SigningKey::from_bytes(&[21; 32]).verifying_key();
    let mapping = genid();
    let joining = genid();
    let mut facts = Fragment::empty();
    for (scope, stage, first_work, last_work) in [
        (&mapping, "mapping", 10_u128, 30_u128),
        (&joining, "joining", 100_u128, 104_u128),
    ] {
        facts += entity! { scope @
            health_record::attrs::endpoint: node,
            attrs::worker: "maintainer",
            attrs::role: "maintenance",
            attrs::stage*: [stage, stage],
        };
        let (first, first_facts) = sample(scope.id, session, 90, 10);
        facts += first_facts;
        facts += entity! { &first @ attrs::work_ns: first_work * NS };
        let (second, second_facts) = sample(scope.id, session, 100, 20);
        facts += second_facts;
        facts += entity! { &second @ attrs::work_ns: last_work * NS };
    }
    let (process, process_facts) = subject(21, "maintainer-process", "process");
    facts += process_facts;
    let (first, first_facts) = sample(process, session, 90, 10);
    facts += first_facts;
    facts += entity! { &first @ attrs::cpu_ns: 20 * NS };
    let (second, second_facts) = sample(process, session, 100, 20);
    facts += second_facts;
    facts += entity! { &second @ attrs::cpu_ns: 30 * NS };

    let observed = reports(&facts, 101, 30);
    assert_eq!(observed.len(), 3);
    for (scope, stage, work_rate) in [(mapping.id, "mapping", 2e9), (joining.id, "joining", 0.4e9)]
    {
        let row = observed.iter().find(|row| row.subject == scope).unwrap();
        assert_eq!(row.stages, vec![stage]);
        // Completed operation wall durations can overlap. This is not a CPU
        // measurement and must not be subtracted from the other stage's total.
        assert_eq!(metric(row, Metric::WorkNs).per_second, Some(work_rate));
        assert_eq!(metric(row, Metric::CpuNs).value, CountMetric::Absent);
        assert_eq!(metric(row, Metric::CpuNs).per_second, None);
    }
    let process = observed.iter().find(|row| row.subject == process).unwrap();
    assert!(process.stages.is_empty());
    assert_eq!(metric(process, Metric::CpuNs).per_second, Some(1e9));
    assert_eq!(metric(process, Metric::WorkNs).value, CountMetric::Absent);
}

#[test]
fn compiled_capabilities_and_a_costly_noop_do_not_imply_active_work() {
    let session = genid().id;
    let (worker, mut facts) = subject(22, "maintainer", "maintenance");
    for (at, elapsed, work) in [(90, 10, 0_u128), (100, 20, 8_u128)] {
        let (report, report_facts) = sample(worker, session, at, elapsed);
        facts += report_facts;
        facts += entity! { &report @
            attrs::parallel_compiled: true,
            attrs::compiled_backend*: ["cpu", "cuda"],
            attrs::backend: "cpu",
            attrs::parallelism: 4_u128,
            attrs::active: 0_u128,
            attrs::completed: 0_u128,
            attrs::work_ns: work * NS,
        };
    }
    let observed = reports(&facts, 101, 30);
    let report = &observed[0];
    assert_eq!(report.parallel_compiled, vec![true]);
    assert_eq!(report.compiled_backends, vec!["cpu", "cuda"]);
    assert_eq!(report.backends, vec!["cpu"]);
    assert_eq!(metric(report, Metric::Active).value, CountMetric::Value(0));
    assert_eq!(metric(report, Metric::Completed).per_second, Some(0.0));
    assert_eq!(metric(report, Metric::WorkNs).per_second, Some(0.8e9));
    assert_eq!(metric(report, Metric::CpuNs).value, CountMetric::Absent);
}

#[test]
fn telemetry_collection_roundtrip_is_an_ordinary_read_without_appends() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("telemetry.pile");
    std::fs::File::create(&path).unwrap();
    let key = SigningKey::from_bytes(&[20; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    );
    let (worker, mut facts) = subject(20, "maintainer", "maintenance");
    let (report, report_facts) = sample(worker, genid().id, 100, 20);
    facts += report_facts;
    facts += entity! { &report @
        attrs::active: 1_u128,
        attrs::completed_merges: 7_u128,
    };
    let expected = reports(&facts, 101, 30);

    let mut pile = Pile::open(&path).unwrap();
    let collection = pile.collection("telemetry-test", policy).unwrap();
    pile.commit(collection, &key, facts).unwrap();
    pile.close().unwrap();
    let before = std::fs::read(&path).unwrap();

    let mut pile = Pile::open(&path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let admitted: TribleSet = collection.read(&snapshot).unwrap();
    assert_eq!(
        observe(&admitted, 101 * NS as i128, Duration::from_secs(30)),
        expected,
    );
    drop(snapshot);
    pile.close().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
