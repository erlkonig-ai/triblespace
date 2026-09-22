//! Generated-pile coverage and an explicitly opted-in visual fixture.
//!
//! The ordinary test does not initialize a renderer. The ignored capture needs
//! TRIBLESPACE_DASHBOARD_CAPTURE_DIR naming an existing, absolute evidence
//! directory. It retains PNGs and a text manifest in a new child directory;
//! the generated pile and signing key remain disposable. No live input path,
//! networking, sampler, window, or production dashboard option is involved.
//!
//! Capture still initializes wgpu. Run it only inside an externally bounded,
//! reserved rendering scope. Headless does NOT imply CPU-only: this GORBIE
//! version uses Instance::default(), not WGPU_BACKEND selection. Restrict the
//! Vulkan ICD and EGL driver to software and verify CPU/device containment
//! before execution. The output caps below are not renderer memory quotas or
//! a process deadline.

use super::*;
use std::fs::{self, OpenOptions};
use std::path::Path;

use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace_core::prelude::*;
use triblespace_core::{metadata, signing_key_file};
use GORBIE::{CaptureOptions, HeadlessTheme};

const MIB: u128 = 1024 * 1024;
const SECOND: u128 = 1_000_000_000;

/// Produce selected resident facts, close the writer, then use the real reader.
/// The fixed sample offsets make rates reproducible without a sleep or network.
fn generated_frame(directory: &Path) -> Result<(Frame, i128)> {
    let path = directory.join("generated-telemetry.pile");
    let key_path = directory.join("generated.key");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let signer = signing_key_file::init(&key_path)?;
    let authority = signer.verifying_key();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut writer = Pile::open(&path)?;
    let collection: Collection<SimpleArchive> =
        writer.collection("generated-dashboard-telemetry", policy.clone())?;
    let health: Collection<SimpleArchive> =
        writer.collection(health_record::COLLECTION_NAME, policy.clone())?;
    // A registered derivation that is never maintained. It has no records at
    // all, so it is exactly the case a record-seeded walk would omit: the
    // lattice must show the declared-but-unperformed derivation as a hole.
    let derived = writer.derive::<SuccinctArchiveBlob>(collection, (), policy)?;
    // These are disposable, public fixture endpoint labels, not any node's key.
    let nodes = [11, 12, 13, 14, 15]
        .map(|seed| ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key());
    let observed_at = triblespace_core::clock::epoch_now();
    let observed_ns = observed_at.to_tai_duration().total_nanoseconds();
    let mut facts = Fragment::empty();
    for (node, worker, role, stage) in [
        (nodes[0], "custody-busy", "custody", "body receive"),
        (nodes[0], "maintenance-process", "process", ""),
        (nodes[0], "maintenance-busy", "maintenance", "derive"),
        (nodes[1], "maintenance-idle", "maintenance", "pass"),
        (
            nodes[1],
            "no-publication-pass",
            "maintenance",
            "no-publication-pass",
        ),
        (nodes[2], "maintenance-stale", "maintenance", "derive"),
        (nodes[3], "maintenance-unknown", "maintenance", "pass"),
        (nodes[0], "link-direct", "link", "transport"),
        (nodes[1], "link-relay", "link", "transport"),
    ] {
        let subject = genid();
        let session = genid();
        let peer = match worker {
            "link-direct" => Some(nodes[1]),
            "link-relay" => Some(nodes[2]),
            _ => None,
        };
        facts += entity! { &subject @
            health_record::attrs::endpoint: node,
            health_record::attrs::peer?: peer,
            health_record::attrs::collection?:
                (role == "maintenance").then_some(collection.handle()),
            telemetry::attrs::worker: worker,
            telemetry::attrs::role: role,
            telemetry::attrs::stage?: (role != "process").then_some(stage),
        };
        for tick in 0_u128..2 {
            let report = genid();
            let age = if worker == "maintenance-stale" {
                601.0 - tick as f64
            } else {
                2.0 - tick as f64
            };
            let at = observed_at - hifitime::Duration::from_seconds(age);
            facts += entity! { &report @
                metadata::tag: &telemetry::KIND_SAMPLE,
                telemetry::attrs::subject: &subject,
                health_record::attrs::session: &session,
                metadata::created_at: (at, at).try_to_inline().unwrap(),
                telemetry::attrs::elapsed_ns: (10 + tick) * SECOND,
            };
            facts += match worker {
                "custody-busy" => entity! { &report @
                    telemetry::attrs::queued: 32_u128 - tick * 4,
                    telemetry::attrs::active: 4_u128,
                    telemetry::attrs::parallelism: 4_u128,
                    telemetry::attrs::parallel_compiled: true,
                    telemetry::attrs::compiled_backend: "cpu",
                    telemetry::attrs::backend: "cpu",
                    telemetry::attrs::completed: 100_u128 + tick * 4,
                    telemetry::attrs::failed: 0_u128,
                    telemetry::attrs::received_bytes: (64 + tick * 48) * MIB,
                    telemetry::attrs::sent_bytes: (32 + tick * 16) * MIB,
                },
                "maintenance-process" => entity! { &report @
                    telemetry::attrs::cpu_ns: 7 * SECOND + tick * 750_000_000,
                },
                "maintenance-busy" => entity! { &report @
                    telemetry::attrs::queued: 9_u128 - tick * 2,
                    telemetry::attrs::active: 1_u128,
                    telemetry::attrs::parallelism: 8_u128,
                    telemetry::attrs::parallel_compiled: false,
                    telemetry::attrs::compiled_backend: "cpu",
                    telemetry::attrs::backend: "cpu",
                    telemetry::attrs::completed: 11_u128 + tick * 4,
                    telemetry::attrs::failed: 0_u128,
                    telemetry::attrs::pending_merges: 2_u128,
                    telemetry::attrs::pending_derives: 5_u128,
                    telemetry::attrs::completed_merges: 4_u128 + tick,
                    telemetry::attrs::completed_derives: 7_u128 + tick * 3,
                    telemetry::attrs::work_ns: (20 + tick * 2) * SECOND,
                },
                "maintenance-idle" => entity! { &report @
                    telemetry::attrs::queued: 0_u128,
                    telemetry::attrs::active: 0_u128,
                    telemetry::attrs::parallelism: 1_u128,
                    telemetry::attrs::parallel_compiled: false,
                    telemetry::attrs::compiled_backend: "cpu",
                    telemetry::attrs::completed: 20_u128,
                    telemetry::attrs::failed: 0_u128,
                    telemetry::attrs::pending_merges: 0_u128,
                    telemetry::attrs::pending_derives: 0_u128,
                    telemetry::attrs::completed_merges: 8_u128,
                    telemetry::attrs::completed_derives: 12_u128,
                },
                // Successful passes with no successful merge/derive publication
                // calls may still spend time computing; this is not an idle row.
                "no-publication-pass" => entity! { &report @
                    telemetry::attrs::queued: 0_u128,
                    telemetry::attrs::active: 0_u128,
                    telemetry::attrs::parallelism: 1_u128,
                    telemetry::attrs::parallel_compiled: false,
                    telemetry::attrs::compiled_backend: "cpu",
                    telemetry::attrs::completed: 100_u128 + tick,
                    telemetry::attrs::failed: 0_u128,
                    telemetry::attrs::pending_merges: 0_u128,
                    telemetry::attrs::pending_derives: 0_u128,
                    telemetry::attrs::completed_merges: 4_u128,
                    telemetry::attrs::completed_derives: 8_u128,
                    telemetry::attrs::work_ns: 500_000_000_u128 + tick * 10_000_000,
                },
                "maintenance-stale" => entity! { &report @
                    telemetry::attrs::queued: 0_u128,
                    telemetry::attrs::active: 0_u128,
                    telemetry::attrs::parallelism: 8_u128,
                    telemetry::attrs::completed: 10_u128 + tick,
                    telemetry::attrs::completed_derives: 10_u128 + tick,
                },
                "link-direct" => entity! { &report @
                    telemetry::attrs::path: "direct",
                    telemetry::attrs::rtt_ns: 1_200_000_u128,
                    telemetry::attrs::received_bytes: (128 + tick * 64) * MIB,
                    telemetry::attrs::sent_bytes: (64 + tick * 8) * MIB,
                },
                "link-relay" => entity! { &report @
                    telemetry::attrs::path: "relay",
                    telemetry::attrs::rtt_ns: 80_000_000_u128,
                    telemetry::attrs::received_bytes: (16 + tick * 2) * MIB,
                    telemetry::attrs::sent_bytes: (8 + tick) * MIB,
                },
                // A real observation with no effort metrics is not idle.
                "maintenance-unknown" => Fragment::empty(),
                _ => unreachable!(),
            };
        }
    }
    writer.commit(collection, &signer, facts)?;
    let health_facts = health_record::Recorder::new(nodes[4]).record(
        observed_at - hifitime::Duration::from_seconds(1.0),
        [
            health_record::Condition {
                component: health_record::Component::Host,
                collection: None,
                peer: None,
                state: health_record::State::Current,
                alert: false,
            },
            health_record::Condition {
                component: health_record::Component::Collection,
                collection: Some(collection.handle()),
                peer: Some(nodes[0]),
                state: health_record::State::Stalled,
                alert: true,
            },
            // An observer naming the derivation. This is the realistic way a
            // never-maintained collection becomes visible: it has no records
            // of its own, so only a handle from outside the record set reaches
            // it, and a health condition is exactly such a handle.
            health_record::Condition {
                component: health_record::Component::Collection,
                collection: Some(derived.handle()),
                peer: Some(nodes[1]),
                state: health_record::State::Stalled,
                alert: true,
            },
        ],
    )?;
    writer.commit(health, &signer, health_facts)?;
    writer.close()?;

    let before = fs::read(&path)?;
    let mut reader = Reader::open(&Options {
        pile: path.clone(),
        key: Some(key_path),
        telemetry: vec![collection.handle()],
        max_age: Duration::from_secs(180),
        interval: Duration::from_secs(1),
        once: true,
        gui: false,
        lattice: true,
    })?;
    // Stand in for a viewer's click, so the capture also exercises the member
    // lattice the renderer requests through the sampler.
    reader.focus = Some(collection.handle().raw);
    let sampled = reader.sample();
    let closed = reader.close();
    closed?;
    assert_eq!(fs::read(path)?, before, "observation must not publish");
    Ok((sampled?.at(observed_ns), observed_ns))
}

fn assert_mixed_states(frame: &Frame) {
    assert_eq!((frame.readable_sources, frame.selected_sources), (1, 1));
    let lattice = frame.lattice.as_ref().expect("the lattice was requested");
    let derived: Vec<_> = lattice.iter().filter(|c| c.source.is_some()).collect();
    assert_eq!(derived.len(), 1, "one derivation is registered");
    assert_eq!(
        derived[0].stored(),
        0,
        "and never maintained, which must draw as an unperformed derivation"
    );
    assert!(
        lattice.iter().any(|c| c.name.as_deref()
            == Some("generated-dashboard-telemetry")
            && c.commits > 0),
        "the source root is present with its commits"
    );
    let members = frame.members.as_ref().expect("the selection was answered");
    assert!(members.too_large.is_none());
    assert!(
        !members.members.is_empty(),
        "the selected collection has members to draw"
    );
    assert_eq!(frame.nodes().len(), 5);
    assert_eq!(frame.workers.len(), 9);
    assert_eq!(frame.health.len(), 1);
    assert!(frame.warnings.is_empty(), "{:?}", frame.warnings);
    let worker = |name| {
        frame
            .workers
            .iter()
            .find(|worker| worker.worker == name)
            .expect("generated worker must be observed")
    };
    let busy = worker("custody-busy");
    assert_eq!(count(busy, Metric::Queued), "28");
    assert_eq!(count(busy, Metric::Active), "4");
    assert_eq!(process_effort(busy), None);
    assert_eq!(rate(busy, Metric::ReceivedBytes, true), "48.00 MiB/s");
    let process = worker("maintenance-process");
    assert!(process.stages.is_empty());
    assert_eq!(
        process_effort(process).as_deref(),
        Some("0.75 effective cores")
    );
    let maintenance = worker("maintenance-busy");
    assert_eq!(count(maintenance, Metric::Active), "1");
    assert_eq!(count(maintenance, Metric::Parallelism), "8");
    assert_eq!(compiled_parallel(maintenance), "no");
    assert_eq!(process_effort(maintenance), None);
    assert!(serial_configuration_mismatch(maintenance));
    assert!(execution_summary(maintenance).contains("active 1 · configured 8"));
    assert!(execution_summary(maintenance).contains("PARALLEL PATH NOT COMPILED"));
    assert_eq!(wall_work(maintenance), "2.00 seconds/second");
    assert_eq!(rate(maintenance, Metric::CompletedDerives, false), "3.00/s");
    let idle = worker("maintenance-idle");
    assert_eq!(count(idle, Metric::Active), "0");
    assert_eq!(rate(idle, Metric::Completed, false), "0.00/s");
    assert_eq!(cpu(idle), "unmeasured");
    assert!(idle.backends.is_empty(), "idle has no executing backend");
    let noop = worker("no-publication-pass");
    assert_eq!(rate(noop, Metric::Completed, false), "1.00/s");
    assert_eq!(rate(noop, Metric::CompletedDerives, false), "0.00/s");
    assert_eq!(wall_work(noop), "0.01 seconds/second");
    assert_eq!(cpu(noop), "unmeasured");
    let stale = worker("maintenance-stale");
    assert_eq!(stale.freshness, Freshness::Stale);
    assert!(observation_age(stale).contains("historical"));
    assert_eq!(rate(stale, Metric::Completed, false), "unmeasured");
    let unknown = worker("maintenance-unknown");
    assert_eq!(unknown.freshness, Freshness::Fresh);
    assert_eq!(count(unknown, Metric::Active), "unknown");
    assert_eq!(count(unknown, Metric::PendingDerives), "unknown");
    assert_eq!(cpu(unknown), "unmeasured");
    assert!(execution_summary(unknown).contains("active unknown · configured unknown"));
    assert!(execution_summary(stale).starts_with("Historical / uncertain:"));
    assert_eq!(labels(&worker("link-direct").paths), "direct");
    assert_eq!(rtt(worker("link-direct")), "1.20 ms");
    assert_eq!(
        rate(worker("link-direct"), Metric::ReceivedBytes, true),
        "64.00 MiB/s"
    );
    assert_eq!(labels(&worker("link-relay").paths), "relay");
    assert_eq!(rtt(worker("link-relay")), "80.00 ms");
    assert_eq!(
        rate(worker("link-relay"), Metric::ReceivedBytes, true),
        "2.00 MiB/s"
    );
    assert_eq!(frame.health[0].freshness, Freshness::Fresh);
    assert!(frame.health[0]
        .conditions
        .iter()
        .any(|condition| condition.alert));
    assert!(frame.health[0]
        .endpoints
        .iter()
        .all(|node| frame.workers.iter().all(|worker| &worker.node != node)));
    assert!(
        render_terminal(frame).contains("Health endpoint observed; worker telemetry not observed.")
    );
}

#[test]
fn generated_colony_reader_preserves_mixed_states_and_pile_bytes() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let (frame, _) = generated_frame(fixture.path())?;
    assert_mixed_states(&frame);
    Ok(())
}

#[test]
#[ignore = "requires explicit evidence directory and externally bounded software-renderer scope"]
fn capture_generated_colony_dashboard() -> Result<()> {
    /// One producer, one selector, four consumers. Asserting the count is what
    /// catches a card that silently stops rendering -- the failure that once
    /// read as a 2px stub and got misdiagnosed as a GPU fault.
    const EXPECTED_CARDS: usize = 6;

    // The opt-in driver can record wgpu's actual adapter selection. This is
    // diagnostic evidence, not a substitute for selecting software drivers.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let evidence = PathBuf::from(
        std::env::var_os("TRIBLESPACE_DASHBOARD_CAPTURE_DIR").context(
            "set TRIBLESPACE_DASHBOARD_CAPTURE_DIR to an existing task-local evidence directory",
        )?,
    );
    anyhow::ensure!(
        evidence.is_absolute() && evidence.is_dir(),
        "capture evidence directory must be absolute and already exist"
    );
    let artifacts = tempfile::Builder::new()
        .prefix("generated-colony-")
        .tempdir_in(evidence)?
        .keep();
    let fixture = tempfile::Builder::new()
        .prefix("disposable-input-")
        .tempdir_in(&artifacts)?;
    let (frame, observed_ns) = generated_frame(fixture.path())?;
    assert_mixed_states(&frame);
    let pile_path = fixture.path().join("generated-telemetry.pile");
    let before = fs::read(&pile_path)?;
    let mut manifest = format!(
        "Generated telemetry only; no live pile or network.\nObservation TAI nanoseconds: {observed_ns}\nTheme: dark; pixels_per_point: 1; settle_timeout: 2s\nGenerated pile before BLAKE3: {}\n\n{}\n",
        blake3::hash(&before),
        render_terminal(&frame)
    );
    let mut images = 0_usize;
    let mut encoded_bytes = 0_usize;
    let mut rendered_height = 0_usize;
    let mut card_heights: Vec<usize> = Vec::new();
    let capture = NotebookConfig::new("Generated colony dashboard fixture")
        .with_headless_theme(HeadlessTheme::Dark)
        .capture(
            CaptureOptions {
                pixels_per_point: 1.0,
                settle_timeout: Duration::from_secs(2),
            },
            move |notebook| {
                // The capture exercises the LIVE card graph over a fixed
                // observation, rather than a second arrangement that merely
                // resembles it: only the pull and the publish differ.
                let frame = frame.clone();
                super::compose(
                    notebook,
                    move || (Some(Ok(frame.clone())), None),
                    |_chosen| {},
                );
                notebook.settled();
            },
            |image| {
                // Bound retained evidence, not wgpu's allocations before emit.
                if images >= 16
                    || image.bytes.len() > 8 * 1024 * 1024
                    || encoded_bytes + image.bytes.len() > 32 * 1024 * 1024
                {
                    return Err(
                        io::Error::other("generated capture exceeded its output budget").into(),
                    );
                }
                assert!(image.width > 0 && image.height > 0);
                assert!(image.tile_count > 0 && image.tile_index < image.tile_count);
                assert!(image.bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
                let name = image.filename();
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(artifacts.join(&name))?
                    .write_all(&image.bytes)?;
                use std::fmt::Write as _;
                writeln!(
                    manifest,
                    "{name}: {}x{}, {} bytes, BLAKE3 {}",
                    image.width,
                    image.height,
                    image.bytes.len(),
                    blake3::hash(&image.bytes)
                )?;
                images += 1;
                encoded_bytes += image.bytes.len();
                rendered_height += image.height as usize;
                card_heights.push(image.height as usize);
                Ok(())
            },
        );
    let after = fs::read(&pile_path)?;
    assert_eq!(
        after, before,
        "rendering must not mutate the generated pile"
    );
    use std::fmt::Write as _;
    writeln!(
        manifest,
        "\nGenerated pile after BLAKE3: {}\nPile unchanged: true\nCapture succeeded: {}\nImages: {images}; encoded bytes: {encoded_bytes}; total height: {rendered_height}px",
        blake3::hash(&after),
        capture.is_ok()
    )?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join("capture.txt"))?
        .write_all(manifest.as_bytes())?;
    fixture.close()?;
    eprintln!(
        "generated dashboard capture evidence: {}",
        artifacts.display()
    );
    capture.map_err(|error| anyhow!("generated dashboard capture: {error}"))?;
    anyhow::ensure!(images != 0, "capture emitted no PNGs");
    // Preserve failed screenshots first, so an expanded-layout regression can
    // be inspected.
    //
    // The budget is PER CARD, not over their sum. It exists to stop one card
    // becoming a dump, and the dashboard is now a card graph: summing every
    // card measures the whole page instead, which grows with each card added
    // and would charge a tax for the decomposition rather than guarding
    // anything. The overview this assertion was written for is 143px now
    // precisely because the rest moved into cards of their own.
    anyhow::ensure!(
        card_heights.len() == EXPECTED_CARDS,
        "expected {EXPECTED_CARDS} cards, captured {}: {card_heights:?}",
        card_heights.len()
    );
    if let Some((index, tallest)) = card_heights
        .iter()
        .enumerate()
        .max_by_key(|(_, height)| **height)
    {
        anyhow::ensure!(
            *tallest <= 1800,
            "card {} is too tall: {tallest}px (budget 1800px per card); all cards {card_heights:?}, \
             total {rendered_height}px",
            index + 1
        );
    }
    Ok(())
}
