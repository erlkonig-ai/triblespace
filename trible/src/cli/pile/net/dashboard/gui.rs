//! Embedded GORBIE frontend. It borrows only the latest read-only sampler frame;
//! the parent owns stop/join/close even if window creation fails.

use super::*;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::widgets::{Column, TableBuilder};
use GORBIE::NotebookConfig;

pub(super) fn run(options: Options) -> Result<()> {
    let mut sampler = Sampler::start(options)?;
    let shared = Arc::clone(&sampler.shared);
    let result = NotebookConfig::new("TribleSpace colony").run(move |notebook| {
        let shared = Arc::clone(&shared);
        notebook.view(move |ctx| {
            ctx.ctx().request_repaint_after(Duration::from_millis(250));
            let latest = shared
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .latest
                .clone();
            ctx.with_padding(DEFAULT_CARD_PADDING, |ctx| match latest {
                Some(Ok(frame)) => render(
                    ctx,
                    &frame.at(triblespace_core::clock::epoch_now()
                        .to_tai_duration()
                        .total_nanoseconds()),
                ),
                Some(Err(error)) => {
                    ctx.heading("Colony state unknown");
                    ctx.label(clean(&error, 200));
                }
                None => {
                    ctx.heading("Observing colony");
                    ctx.label("Opening one local reader; no networking or maintenance is started.");
                }
            });
        });
    });
    let closed = sampler.finish();
    result.map_err(|error| anyhow!("open colony notebook: {error}"))?;
    closed
}

fn render(ui: &mut egui::Ui, frame: &Frame) {
    ui.heading("Colony · work distribution");
    ui.label(frame.coverage());
    ui.small(format!(
        "Observation took {:.2}s; completed {:.1}s ago. Partial coverage; missing telemetry is not idle.",
        frame.observation_time.as_secs_f64(), frame.sampled.elapsed().as_secs_f64()
    ));
    ui.label("Measured payload rates are not link capacity. CPU is consumed process time, not configured threads.");
    ui.separator();

    for node in frame.nodes() {
        ui.heading(format!("Node {}", short(&node)));
        let workers: Vec<_> = frame
            .workers
            .iter()
            .filter(|worker| worker.node == node)
            .collect();
        if workers.is_empty() {
            ui.label("Health endpoint observed; worker telemetry not observed.");
        } else {
            TableBuilder::new(ui)
                .id_salt(("colony-workers", node))
                .striped(true)
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::remainder())
                .header(24.0, |mut header| {
                    for title in [
                        "Worker / role",
                        "Queued",
                        "Active",
                        "Parallelism",
                        "CPU effort",
                    ] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|mut body| {
                    for worker in &workers {
                        body.row(30.0, |mut row| {
                            row.col(|ui| {
                                ui.label(format!(
                                    "{} / {} [{}]",
                                    clean(&worker.worker, 32),
                                    clean(&worker.role, 20),
                                    freshness(worker.freshness)
                                ))
                                .on_hover_text(observation_age(worker));
                            });
                            row.col(|ui| {
                                ui.label(count(worker, Metric::Queued));
                            });
                            row.col(|ui| {
                                ui.label(count(worker, Metric::Active));
                            });
                            row.col(|ui| {
                                ui.label(count(worker, Metric::Parallelism));
                            });
                            row.col(|ui| {
                                ui.label(cpu(worker));
                            });
                        });
                    }
                });

            for worker in workers {
                ui.label(format!(
                    "Compiled parallel {} · compiled backends {}",
                    compiled_parallel(worker),
                    labels(&worker.compiled_backends)
                ));
                // Freshness is always visible, not hidden behind expansion.
                ui.label(format!(
                    "{} · {}",
                    clean(&worker.worker, 36),
                    observation_age(worker)
                ));
                egui::CollapsingHeader::new(format!(
                    "{} · throughput, maintenance and links",
                    clean(&worker.worker, 36)
                ))
                .id_salt((
                    "colony-worker",
                    worker.subject.raw(),
                    &worker.worker,
                    &worker.role,
                ))
                .default_open(true)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!(
                            "Receive {}",
                            rate(worker, Metric::ReceivedBytes, true)
                        ));
                        ui.separator();
                        ui.label(format!("Send {}", rate(worker, Metric::SentBytes, true)));
                        ui.separator();
                        ui.label(format!(
                            "Completed {}",
                            rate(worker, Metric::Completed, false)
                        ));
                    });
                    ui.label(format!(
                        "Stage {} · backend {} · failed {}",
                        labels(&worker.stages),
                        labels(&worker.backends),
                        count(worker, Metric::Failed)
                    ));
                    if has_metric(worker, Metric::WorkNs) {
                        ui.label(format!(
                            "Completed-operation wall work {} (operations may overlap; not CPU)",
                            wall_work(worker)
                        ));
                    }
                    if worker.role == "maintenance"
                        || has_metric(worker, Metric::PendingMerges)
                        || has_metric(worker, Metric::PendingDerives)
                    {
                        ui.label(format!(
                            "Merges: {} pending, {} completed · Derives: {} pending, {} completed",
                            count(worker, Metric::PendingMerges),
                            rate(worker, Metric::CompletedMerges, false),
                            count(worker, Metric::PendingDerives),
                            rate(worker, Metric::CompletedDerives, false)
                        ));
                    }
                    if !worker.peers.is_empty() || worker.role == "link" {
                        ui.label(format!(
                            "Peer {} · path {} · RTT {}",
                            handles(&worker.peers),
                            labels(&worker.paths),
                            rtt(worker)
                        ));
                    }
                    if !worker.targets.is_empty() {
                        ui.label(format!("Selected targets {}", handles(&worker.targets)));
                    }
                });
            }
        }
        for observer in frame
            .health
            .iter()
            .filter(|observer| observer.endpoints.contains(&node))
        {
            let alerts = observer
                .conditions
                .iter()
                .filter(|condition| condition.alert)
                .count();
            ui.label(format!(
                "Health: {} · {}s old · {alerts} scoped alerts",
                freshness(observer.freshness),
                observer
                    .age_seconds
                    .map_or_else(|| "?".into(), |age| age.to_string())
            ));
            if alerts != 0 {
                egui::CollapsingHeader::new("Reported sync conditions")
                    .id_salt(("colony-health", observer.node.raw()))
                    .show(ui, |ui| {
                        for condition in observer
                            .conditions
                            .iter()
                            .filter(|condition| condition.alert)
                        {
                            ui.label(format!(
                                "{:?}: {:?} · peer {} · collection {}",
                                condition.components,
                                condition.states,
                                handles(&condition.peers),
                                handles(&condition.collections)
                            ));
                        }
                    });
            }
        }
        ui.separator();
    }
    if frame.workers.is_empty() {
        ui.label("Worker effort, backlog and throughput are not observed. Select the producer telemetry collections; health alone cannot establish them.");
    }
    for warning in &frame.warnings {
        ui.label(format!("! {warning}"));
    }
    ui.small("Known queues cover their reporting selection only; unknown descendants and unobserved nodes are not counted.");
}
