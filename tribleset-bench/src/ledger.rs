//! Results ledger: canonical telemetry sessions/spans plus bench
//! outcome entities, written DIRECTLY (no tracing) through the pinned
//! native-collection LEDGER dependency — measurement I/O never depends
//! on the era of the subject.
//!
//! DISCIPLINE: this module uses ONLY the ledger's umbrella surface
//! (`triblespace::prelude`, `triblespace::core::…`). The umbrella
//! macros expand to absolute `::triblespace::core` paths, which in
//! this crate resolve to the ledger; the core-macro flavor (what the
//! subject-side modules use) expands to `::triblespace_core`, which
//! resolves to the SUBJECT's core and must never appear here.
//!
//! The telemetry schema ids are declared byte-for-byte identical to
//! `june-on-tip/src/telemetry.rs` — the minted ids are the contract;
//! GORBIE's telemetry-viewer renders the axis.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;

use triblespace::core::collection::{
    discover_collection_records, reach, CollectionHandle, CollectionStoreExt,
    SimpleArchiveCollection,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

/// Canonical telemetry attributes — byte-for-byte the ids of
/// `triblespace::telemetry::schema` (read from
/// `june-on-tip/src/telemetry.rs`).
pub mod tele {
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
    use triblespace::prelude::*;

    attributes! {
        "3E062AA7E3554C8F2DB94883CE639BFE" unsafe as pub session: GenId;
        "146E5AA2F7CB3D8B654BC7742A13CAB3" unsafe as pub parent: GenId;
        "CCB0147D20C4C6FCAC0E3D87FAFF71D1" unsafe as pub name: Handle<UTF8String>;
        "8A4BE2C4D0E90D2B9EE0E1A07ECA2CFA" as pub category: Handle<UTF8String>;
        "E11A84A30CC112650DC860B66B8BD8A9" unsafe as pub begin_ns: U256BE;
        "2786FA563372FB6EF469EC7710719A49" unsafe as pub end_ns: U256BE;
        "7593602383D0B0D21BBE382A67E5BD9F" unsafe as pub duration_ns: U256BE;
        "7E96DD9A0B5002796B645ED25F5E99AC" unsafe as pub source: Handle<UTF8String>;
    }
}

/// Bench decorations — minted for this suite (`trible genid`, never
/// guessed): session provenance (commit/engine/config) and per-measure
/// outcome entities (of_run/workload/outcome/rows).
pub mod bench {
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::inlineencodings::{GenId, Handle, U256BE};
    use triblespace::prelude::*;

    attributes! {
        /// Subject git rev (short=12) the session measured.
        "2C96F6429B3E772B15A0AB630C2B394F" as pub commit: Handle<UTF8String>;
        /// Engine label (--label) naming the subject on the axis.
        "2C899A2497B9565328A42A44996BD6A1" as pub engine: Handle<UTF8String>;
        /// Full run configuration: CLI + dataset + suite crate version.
        "8A3D02A290208D39DC18C69FAF38F1E1" unsafe as pub config: Handle<UTF8String>;
        /// Outcome entity -> its session.
        "75342A5BCA3BAD27285C5B76DB22CFCF" unsafe as pub of_run: GenId;
        /// Outcome entity -> measure key (e.g. "harkonnen/F5/total").
        "81ADFDA915ABA850EE23FEE3B88FC02F" unsafe as pub workload: Handle<UTF8String>;
        /// signal | skip:<reason> | panic:<reason> | gate_fail:<reason>.
        "5ACAF4FD8D71F0205694F646520707B5" as pub outcome: Handle<UTF8String>;
        /// Result cardinality of the measure, where meaningful.
        "B5A378BDC1A7F1C4576B2DC6902B5995" unsafe as pub rows: U256BE;
    }
}

/// Tag id of a telemetry session entity.
pub static KIND_SESSION: LazyLock<Id> =
    LazyLock::new(|| Id::from_hex("2701F7019B865D461F0169B1303026D6").expect("kind_session id"));
/// Tag id of a telemetry span entity.
pub static KIND_SPAN: LazyLock<Id> =
    LazyLock::new(|| Id::from_hex("0AF9FEB9A2BFEB1BE8A8229829181085").expect("kind_span id"));
/// Name carried by the benchmark-results root descriptor.
pub const RESULTS_COLLECTION_NAME: &str = "tribleset-bench-results";

/// Mandatory authority of the benchmark-results collection.
///
/// The old ledger admitted every strictly self-signed commit in its local pile,
/// so its signatures never claimed a private writer set. The authority epoch
/// makes that policy part of descriptor identity instead: every run uses this
/// fixed, deliberately public signing key. Forgeability is unchanged, while
/// all runs still converge on one collection handle and ordinary descriptor
/// admission can read them.
///
/// It is derived from the id this suite already minted for its results
/// (`F6D99F76BC15E78C0BBD44F9D28A0C0A`, the extrinsic *scope* back when that was
/// how a root was anchored) rather than minting a second constant. Result piles
/// written under earlier descriptors remain inert historical evidence; this is
/// an explicit descriptor-identity cutover, not a compatibility alias.
fn results_collection_key() -> SigningKey {
    let minted = Id::from_hex("F6D99F76BC15E78C0BBD44F9D28A0C0A").expect("results collection id");
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(&minted.raw());
    seed[16..].copy_from_slice(&minted.raw());
    SigningKey::from_bytes(&seed)
}

pub static RESULTS_COLLECTION_AUTHORITY: LazyLock<VerifyingKey> =
    LazyLock::new(|| results_collection_key().verifying_key());

/// The read-side facade naming the results collection.
fn results_collection() -> SimpleArchiveCollection {
    SimpleArchiveCollection::new(
        RESULTS_COLLECTION_NAME,
        *RESULTS_COLLECTION_AUTHORITY,
        reach::private(),
    )
}

/// Complete schema description stored beside every results element.
///
/// `entity!` already carries descriptions for the attributes it uses. Adding
/// the two tag entities and the full attribute namespaces here also makes a
/// partial run fragment intelligible without depending on Rust source or on a
/// separate repository metadata commit.
fn ledger_metadata() -> Fragment {
    let mut description = tele::describe();
    description += bench::describe();
    description += entity! { ExclusiveId::force_ref(&*KIND_SESSION) @
        metadata::name: "telemetry_session",
        metadata::description:
            "A benchmark session grouping raw timing spans and measure outcomes.",
        metadata::tag: metadata::KIND_TAG,
    };
    description += entity! { ExclusiveId::force_ref(&*KIND_SPAN) @
        metadata::name: "telemetry_span",
        metadata::description:
            "One raw measured iteration with begin, end, and duration in nanoseconds.",
        metadata::tag: metadata::KIND_TAG,
    };
    description
}

/// One open results collection. Facts accumulate until a checkpoint publishes
/// and flushes one self-contained fragment. `finish` alone adds the session end
/// marker before publishing the final fragment and closing the pile.
pub struct ResultsLedger {
    pile: Pile,
    collection: CollectionHandle,
    signing_key: SigningKey,
    session: Id,
    pending: Fragment,
}

impl ResultsLedger {
    /// Open (creating the file as needed) and start a session entity decorated
    /// with the bench provenance attributes.
    pub fn open(path: &Path, commit: &str, label: &str, config: &str) -> Result<Self> {
        if !path.exists() {
            std::fs::OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(path)
                .with_context(|| format!("create results pile {}", path.display()))?;
        }
        let mut pile =
            Pile::open(path).map_err(|e| anyhow!("open results pile {}: {e:?}", path.display()))?;
        pile.refresh()
            .map_err(|e| anyhow!("load results pile: {e:?}"))?;
        let signing_key = results_collection_key();
        let collection = pile
            .collection(results_collection().descriptor())
            .map_err(|e| anyhow!("register results collection: {e:?}"))?;

        let session_owner = genid();
        let session = *session_owner;
        let mut pending = Fragment::empty();
        let name_handle = pending.put("tribleset-bench".to_string());
        let config_handle = pending.put(config.to_string());
        pending += entity! { &session_owner @
            metadata::tag: *KIND_SESSION,
            tele::category: "session",
            tele::name: name_handle,
            tele::begin_ns: 0u64,
            bench::commit: commit,
            bench::engine: label,
            bench::config: config_handle,
        };

        let mut ledger = Self {
            pile,
            collection,
            signing_key,
            session,
            pending,
        };
        // A session printed by the runner must already exist durably. Publishing
        // the start here also means a run interrupted before its first measure
        // remains queryable as incomplete rather than disappearing entirely.
        ledger
            .checkpoint()
            .context("publish results session start")?;
        Ok(ledger)
    }

    /// The session entity id (for logging).
    pub fn session(&self) -> Id {
        self.session
    }

    /// Record one measured iteration as a telemetry span.
    pub fn span(&mut self, name: &str, begin_ns: u64, duration_ns: u64) {
        let span_owner = genid();
        let name_handle = self.pending.put(name.to_string());
        self.pending += entity! { &span_owner @
            metadata::tag: *KIND_SPAN,
            tele::session: self.session,
            tele::category: "bench",
            tele::name: name_handle,
            tele::begin_ns: begin_ns,
            tele::end_ns: begin_ns + duration_ns,
            tele::duration_ns: duration_ns,
        };
    }

    /// Record a per-measure outcome entity.
    pub fn outcome(&mut self, workload: &str, outcome: &str, rows: Option<u64>) {
        let outcome_owner = genid();
        let workload_handle = self.pending.put(workload.to_string());
        self.pending += entity! { &outcome_owner @
            bench::of_run: self.session,
            bench::workload: workload_handle,
            bench::outcome: outcome,
        };
        if let Some(r) = rows {
            self.pending += entity! { &outcome_owner @ bench::rows: r };
        }
    }

    /// Durably publish everything accumulated so far, keeping the session open.
    ///
    /// The complete schema description is attached to every collection commit,
    /// and the pending fragment carries every long-string attachment referenced
    /// by its facts. Collection publication deliberately has no implicit
    /// durability barrier, so the commit is followed by an explicit flush
    /// before the pending fragment is cleared or its result may be announced.
    ///
    /// The clone is intentional. If dependency publication, record insertion,
    /// or the durability flush fails, `pending` remains byte-identical and can
    /// be retried. Callers propagate that failure and do not print the normal
    /// result line: continuing would make stdout claim more than the pile can
    /// prove.
    ///
    /// Checkpoints never add [`tele::end_ns`]. Only [`finish`](Self::finish)
    /// closes the session, so an interrupted run remains identifiable by the
    /// durable session and measures without an end marker.
    pub fn checkpoint(&mut self) -> Result<()> {
        if self.pending.facts().is_empty() {
            return Ok(());
        }

        let mut checkpoint = self.pending.clone();
        checkpoint.describe_with(ledger_metadata());
        self.pile
            .commit(self.collection, &self.signing_key, checkpoint)
            .map_err(|e| anyhow!("publish results checkpoint: {e:?}"))?;
        self.pile
            .flush()
            .map_err(|e| anyhow!("flush results checkpoint: {e:?}"))?;
        self.pending = Fragment::empty();
        Ok(())
    }

    /// Close the session, durably publish its end marker, and close the pile.
    pub fn finish(mut self, end_ns: u64) -> Result<()> {
        let session_ref = ExclusiveId::force_ref(&self.session);
        self.pending += entity! { session_ref @
            tele::end_ns: end_ns,
            tele::duration_ns: end_ns,
        };
        self.checkpoint().context("publish results session end")?;
        self.pile
            .close()
            .map_err(|e| anyhow!("close results pile: {e:?}"))?;
        Ok(())
    }

    #[cfg(test)]
    fn close_incomplete(self) -> Result<()> {
        debug_assert!(self.pending.facts().is_empty());
        self.pile
            .close()
            .map_err(|e| anyhow!("close incomplete results pile: {e:?}"))
    }
}

/// The acceptance instrument: reopen a results pile read-only, discover and
/// snapshot every authority-signed commit in the deterministic results
/// collection, and print session + span + outcome counts.
///
/// The authority key is deliberately public because the pile itself remains
/// the trust scope, matching the old open-admission ledger. No commit is
/// selected as a mutable or latest head.
pub fn verify(path: &Path) -> Result<()> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow!("open results pile {}: {e:?}", path.display()))?;
    pile.refresh()
        .map_err(|e| anyhow!("load results pile: {e:?}"))?;
    let discovered = discover_collection_records(&mut pile)
        .map_err(|e| anyhow!("discover results collection records: {e:?}"))?;
    if !discovered.diagnostics().is_empty() {
        bail!(
            "results pile contains invalid signed collection records: {:?}",
            discovered.diagnostics()
        );
    }

    let collection = results_collection().collection();
    let snapshot = pile
        .snapshot(collection, &[])
        .map_err(|e| anyhow!("snapshot results collection: {e:?}"))?;
    if snapshot.ticket().is_empty() {
        bail!(
            "results collection {} has no signed commits",
            RESULTS_COLLECTION_NAME
        );
    }
    let commits = snapshot.ticket().len();
    let facts = snapshot.facts().clone();
    let reader = snapshot.reader();

    let kind_session: Id = *KIND_SESSION;
    let kind_span: Id = *KIND_SPAN;

    let sessions: Vec<Id> = find!(
        (s: Id),
        pattern!(&facts, [{ ?s @ metadata::tag: kind_session }])
    )
    .map(|(s,)| s)
    .collect();
    let ended_sessions: BTreeSet<Id> = find!(
        (s: Id, end: u64),
        pattern!(&facts, [{ ?s @
            metadata::tag: kind_session,
            tele::end_ns: ?end
        }])
    )
    .map(|(s, _)| s)
    .collect();

    let span_count = find!(
        (s: Id),
        pattern!(&facts, [{ ?s @ metadata::tag: kind_span }])
    )
    .count();

    println!(
        "verify   : {} — {} signed commits, {} tribles in the results collection",
        path.display(),
        commits,
        facts.len()
    );
    println!("sessions : {}", sessions.len());
    for (s, c, eng, cfg) in find!(
        (
            s: Id,
            c: Inline<Handle<UTF8String>>,
            eng: Inline<Handle<UTF8String>>,
            cfg: Inline<Handle<UTF8String>>
        ),
        pattern!(&facts, [{ ?s @ bench::commit: ?c, bench::engine: ?eng, bench::config: ?cfg }])
    ) {
        let commit: anybytes::View<str> =
            reader.get(c).map_err(|e| anyhow!("commit blob: {e:?}"))?;
        let engine: anybytes::View<str> =
            reader.get(eng).map_err(|e| anyhow!("engine blob: {e:?}"))?;
        let config: anybytes::View<str> =
            reader.get(cfg).map_err(|e| anyhow!("config blob: {e:?}"))?;
        let status = if ended_sessions.contains(&s) {
            "complete"
        } else {
            "incomplete"
        };
        println!(
            "  {s:X}  commit={} engine={} status={status}",
            commit.as_ref(),
            engine.as_ref()
        );
        println!("    config: {}", config.as_ref());
    }

    println!("spans    : {span_count}");
    // Project the span id too: find! heads have SET semantics, so a
    // name-only head would collapse the per-iteration spans to one row
    // per distinct name.
    //
    // The runner deliberately stores raw per-iteration observations and
    // never aggregates; reading a duration out of them is the viewer's
    // job, and this is the suite's own minimal viewer. `min` leads the
    // summary on purpose: on a contended machine the fastest observed
    // iteration is the least contaminated estimate of the work itself,
    // while the spread against `max` shows how much interference the
    // run actually absorbed.
    //
    // Keyed by (session, name), never by name alone: a results pile
    // accumulates every run ever made against it, so collapsing on the
    // name would silently average one rung's arm into another's — the
    // exact confusion a comparative arm exists to avoid.
    let mut span_times: std::collections::BTreeMap<(Id, String), Vec<u64>> = Default::default();
    for (_s, run, n, d) in find!(
        (s: Id, run: Id, n: Inline<Handle<UTF8String>>, d: u64),
        pattern!(&facts, [{ ?s @
            metadata::tag: kind_span,
            tele::session: ?run,
            tele::name: ?n,
            tele::duration_ns: ?d
        }])
    ) {
        let name: anybytes::View<str> = reader
            .get(n)
            .map_err(|e| anyhow!("span name blob: {e:?}"))?;
        span_times
            .entry((run, name.as_ref().to_owned()))
            .or_default()
            .push(d);
    }
    let mut current: Option<Id> = None;
    for ((run, name), times) in &mut span_times {
        if current != Some(*run) {
            current = Some(*run);
            println!("  session {run:X}");
            println!(
                "  {:<45}{:>4}{:>12}{:>12}{:>12}",
                "span", "n", "min ms", "median ms", "max ms"
            );
        }
        times.sort_unstable();
        let ms = |ns: u64| ns as f64 / 1e6;
        println!(
            "  {name:<45}{:>4}{:>12.3}{:>12.3}{:>12.3}",
            times.len(),
            ms(times[0]),
            ms(times[times.len() / 2]),
            ms(times[times.len() - 1]),
        );
    }

    // Optional rows per outcome entity (the engine is monotone; the
    // optional join happens here in Rust).
    let mut rows_of: std::collections::HashMap<Id, u64> = Default::default();
    for (o, r) in find!(
        (o: Id, r: u64),
        pattern!(&facts, [{ ?o @ bench::rows: ?r }])
    ) {
        rows_of.insert(o, r);
    }

    let mut outcome_rows: Vec<(String, String, Option<u64>)> = Vec::new();
    for (o, w, v) in find!(
        (o: Id, w: Inline<Handle<UTF8String>>, v: Inline<Handle<UTF8String>>),
        pattern!(&facts, [{ ?o @ bench::workload: ?w, bench::outcome: ?v }])
    ) {
        let workload: anybytes::View<str> =
            reader.get(w).map_err(|e| anyhow!("workload blob: {e:?}"))?;
        let outcome: anybytes::View<str> =
            reader.get(v).map_err(|e| anyhow!("outcome blob: {e:?}"))?;
        outcome_rows.push((
            workload.as_ref().to_owned(),
            outcome.as_ref().to_owned(),
            rows_of.get(&o).copied(),
        ));
    }
    println!("outcomes : {}", outcome_rows.len());
    let mut histogram: std::collections::BTreeMap<(String, String), usize> = Default::default();
    for (workload, outcome, _) in &outcome_rows {
        let group = workload.split('/').next().unwrap_or(workload).to_owned();
        *histogram.entry((group, outcome.clone())).or_default() += 1;
    }
    for ((group, outcome), count) in &histogram {
        println!("  {group:<14} {outcome:<28} x{count}");
    }
    outcome_rows.sort();
    let mut any_rows = false;
    for (workload, outcome, rows) in &outcome_rows {
        if let Some(n) = rows {
            if !any_rows {
                println!("rows     :");
                any_rows = true;
            }
            println!("  {workload:<45} {outcome:<10} rows={n}");
        }
    }

    pile.close()
        .map_err(|e| anyhow!("close results pile: {e:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_collection_roundtrip_accumulates_runs_with_metadata_and_attachments() {
        let path = std::env::temp_dir().join(format!("tribleset-bench-ledger-{:X}.pile", *genid()));

        let mut ledger = ResultsLedger::open(
            &path,
            "0123456789abcdef",
            "native-collection-test",
            "argv: test | suite: tribleset-bench test",
        )
        .unwrap();
        ledger.span("fixture/total", 11, 13);
        ledger.outcome("fixture/total", "signal", Some(7));
        ledger.finish(29).unwrap();

        let mut second = ResultsLedger::open(
            &path,
            "fedcba9876543210",
            "native-collection-test-2",
            "argv: test-2 | suite: tribleset-bench test",
        )
        .unwrap();
        second.outcome("fixture/other", "skip:test", None);
        second.finish(3).unwrap();

        verify(&path).unwrap();

        let mut pile = Pile::open(&path).unwrap();
        let collection = results_collection().collection();
        let snapshot = pile.snapshot(collection, &[]).unwrap();
        // Each run publishes a durable start checkpoint and a final checkpoint.
        assert_eq!(snapshot.ticket().len(), 4);

        let facts = snapshot.facts();
        let reader = snapshot.reader();
        for commit in snapshot.ticket().commits() {
            let metadata: TribleSet = reader.get(commit.metadata()).unwrap();
            assert!(!metadata.is_empty());
        }
        assert_eq!(
            find!(
                session: Id,
                pattern!(facts, [{ ?session @ metadata::tag: *KIND_SESSION }])
            )
            .count(),
            2
        );
        assert_eq!(
            find!(
                (session: Id, end: u64),
                pattern!(facts, [{ ?session @
                    metadata::tag: *KIND_SESSION,
                    tele::end_ns: ?end
                }])
            )
            .count(),
            2
        );
        let configs: BTreeSet<String> = find!(
            cfg: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ bench::config: ?cfg }])
        )
        .map(|config| {
            let config: anybytes::View<str> = reader.get(config).unwrap();
            config.as_ref().to_owned()
        })
        .collect();
        assert_eq!(configs.len(), 2);
        assert!(configs
            .iter()
            .all(|config| config.contains("suite: tribleset-bench test")));

        drop(snapshot);
        pile.close().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn checkpointed_interruption_keeps_results_without_an_end_marker() {
        let path =
            std::env::temp_dir().join(format!("tribleset-bench-interrupted-{:X}.pile", *genid()));

        let mut ledger = ResultsLedger::open(
            &path,
            "0123456789abcdef",
            "interrupted-test",
            "argv: interrupted | suite: tribleset-bench test",
        )
        .unwrap();
        let session = ledger.session();
        ledger.span("fixture/interrupted", 11, 13);
        ledger.outcome("fixture/interrupted", "signal", Some(7));
        ledger.checkpoint().unwrap();
        ledger.close_incomplete().unwrap();

        // The ordinary reader accepts an incomplete run: incompleteness is
        // represented by the absent session end marker, not a corrupt pile.
        verify(&path).unwrap();

        let mut pile = Pile::open(&path).unwrap();
        let collection = results_collection().collection();
        let snapshot = pile.snapshot(collection, &[]).unwrap();
        assert_eq!(snapshot.ticket().len(), 2);

        let facts = snapshot.facts();
        let reader = snapshot.reader();
        for commit in snapshot.ticket().commits() {
            let metadata: TribleSet = reader.get(commit.metadata()).unwrap();
            assert!(!metadata.is_empty());
        }

        assert_eq!(
            find!(
                span: Id,
                pattern!(facts, [{ ?span @
                    metadata::tag: *KIND_SPAN,
                    tele::session: session
                }])
            )
            .count(),
            1
        );
        assert_eq!(
            find!(
                outcome: Id,
                pattern!(facts, [{ ?outcome @ bench::of_run: session }])
            )
            .count(),
            1
        );
        assert_eq!(
            find!(
                end: u64,
                pattern!(facts, [{ session @ tele::end_ns: ?end }])
            )
            .count(),
            0
        );
        assert_eq!(
            find!(
                duration: u64,
                pattern!(facts, [{ session @ tele::duration_ns: ?duration }])
            )
            .count(),
            0
        );
        let configs: Vec<Inline<Handle<UTF8String>>> = find!(
            config: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ session @ bench::config: ?config }])
        )
        .collect();
        assert_eq!(configs.len(), 1);
        let config: anybytes::View<str> = reader.get(configs[0]).unwrap();
        assert!(config.contains("suite: tribleset-bench test"));

        drop(snapshot);
        pile.close().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
