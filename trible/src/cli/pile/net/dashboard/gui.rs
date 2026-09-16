//! Embedded GORBIE frontend. It borrows only the latest read-only sampler frame;
//! the parent owns stop/join/close even if window creation fails.

use super::*;
use GORBIE::NotebookConfig;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use anyhow::anyhow;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "gui_capture_tests.rs"]
mod capture_tests;

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
                    ctx.label(error.message());
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
    // A dashboard has denser information than a prose notebook. Keep the
    // notebook's font families and theme, but scope spacing and sizes locally.
    ui.scope(|ui| {
        for (style, size) in [
            (egui::TextStyle::Heading, 25.0),
            (egui::TextStyle::Body, 16.0),
            (egui::TextStyle::Button, 16.0),
            (egui::TextStyle::Monospace, 16.0),
        ] {
            if let Some(font) = ui.style_mut().text_styles.get_mut(&style) {
                font.size = size;
            }
        }
        ui.spacing_mut().item_spacing = egui::vec2(8.0, 4.0);
        ui.spacing_mut().interact_size.y = 20.0;
        ui.heading("Colony overview");
        ui.label(frame.coverage());
        let scopes = |freshness| {
            frame.workers.iter()
                .filter(|worker| worker.freshness == freshness)
                .map(|worker| worker.subject)
                .collect::<BTreeSet<_>>().len()
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{} fresh scopes", scopes(Freshness::Fresh)));
            for (kind, label) in [
                (Freshness::Stale, "stale / historical"),
                (Freshness::Future, "future-dated / unknown"),
            ] {
                let count = scopes(kind);
                if count != 0 {
                    ui.colored_label(ui.visuals().warn_fg_color, format!("{count} {label}"));
                }
            }
        });
        ui.small(format!(
            "Partial coverage · sampled {:.1}s ago in {:.2}s · expand arrows for scope details",
            frame.sampled.elapsed().as_secs_f64(), frame.observation_time.as_secs_f64()
        ));
        ui.small("Missing is not idle. Scope values may overlap; they are not added together.");
        for warning in &frame.warnings {
            ui.colored_label(ui.visuals().warn_fg_color, warning);
        }
        ui.separator();

        for node in frame.nodes() {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new(format!("Node {}", short(&node))).strong().size(19.0));
                if !frame.workers.iter().any(|worker| worker.node == node && worker.role == "process") {
                    ui.small("process CPU unobserved");
                }
            });
            let mut workers: Vec<_> = frame.workers.iter()
                .filter(|worker| worker.node == node && worker.role != "link")
                .collect();
            workers.sort_by(|left, right| {
                (left.role != "process", &left.role, &left.worker, left.subject)
                    .cmp(&(right.role != "process", &right.role, &right.worker, right.subject))
            });
            if workers.is_empty() {
                ui.small(if frame.workers.iter().any(|worker| worker.node == node) {
                    "Only link telemetry observed; node workload is unknown."
                } else {
                    "Health endpoint observed; worker telemetry not observed."
                });
            }
            for worker in workers {
                render_worker(ui, worker);
            }
            for observer in frame.health.iter()
                .filter(|observer| observer.endpoints.contains(&node))
            {
                let alerts = observer.conditions.iter().filter(|condition| condition.alert).count();
                ui.horizontal_wrapped(|ui| {
                    ui.small(format!(
                        "Health {} · {}s old",
                        freshness(observer.freshness),
                        observer.age_seconds.map_or_else(|| "?".into(), |age| age.to_string())
                    ));
                    if alerts != 0 {
                        ui.colored_label(ui.visuals().warn_fg_color, format!("{alerts} scoped sync alerts"));
                    }
                });
                if alerts != 0 {
                    egui::CollapsingHeader::new("Sync conditions")
                        .id_salt(("colony-health", observer.node.raw()))
                        .default_open(false)
                        .show(ui, |ui| {
                            for condition in observer.conditions.iter().filter(|condition| condition.alert) {
                                ui.label(format!(
                                    "{:?}: {:?} · peer {} · collection {}",
                                    condition.components, condition.states,
                                    handles(&condition.peers), handles(&condition.collections)
                                ));
                            }
                        });
                }
            }
            ui.add_space(3.0);
        }

        ui.separator();
        ui.label(egui::RichText::new("Observed links").strong().size(19.0));
        ui.small("Observer → peer · measured payload rates, not link capacity.");
        let mut links: Vec<_> = frame.workers.iter()
            .filter(|worker| worker.role == "link")
            .collect();
        links.sort_by(|left, right| {
            (left.node, &left.peers, &left.worker, left.subject)
                .cmp(&(right.node, &right.peers, &right.worker, right.subject))
        });
        if links.is_empty() {
            ui.label("Link paths, RTT and transfer rates are not observed.");
        }
        for link in links {
            let id = ui.make_persistent_id(("colony-link", link.subject.raw(), &link.worker));
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
                .show_header(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(format!("{} → {}", short(&link.node), handles(&link.peers)));
                            ui.label(labels(&link.paths));
                            render_freshness(ui, link);
                        });
                        ui.label(format!(
                            "Receive {} · send {} · RTT {}",
                            rate(link, Metric::ReceivedBytes, true),
                            rate(link, Metric::SentBytes, true), rtt(link)
                        ));
                    });
                })
                .body(|ui| render_details(ui, link));
        }
        if frame.workers.is_empty() {
            ui.label("No worker telemetry. Health alone cannot establish backlog, effort or throughput.");
        }
        ui.small("Known queues cover only their reporting selection; unknown descendants and unobserved nodes are not counted.");
    });
}

fn render_worker(ui: &mut egui::Ui, worker: &WorkerReport) {
    let id = ui.make_persistent_id((
        "colony-work",
        worker.subject.raw(),
        &worker.worker,
        &worker.role,
    ));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
        .show_header(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(clean(&worker.worker, 36));
                    ui.weak(if worker.stages.is_empty() {
                        clean(&worker.role, 24)
                    } else {
                        format!("{} / {}", clean(&worker.role, 24), labels(&worker.stages))
                    });
                    render_freshness(ui, worker);
                });
                if let Some(effort) = process_effort(worker) {
                    ui.label(format!(
                        "Process CPU: {effort} · no node-wide total inferred"
                    ));
                    return;
                }
                if worker.role == "maintenance" {
                    ui.label(format!(
                        "Pending: {} merges · {} derives",
                        count(worker, Metric::PendingMerges),
                        count(worker, Metric::PendingDerives)
                    ));
                    ui.label(format!(
                        "Completed: work {} · merges {} · derives {}",
                        rate(worker, Metric::Completed, false),
                        rate(worker, Metric::CompletedMerges, false),
                        rate(worker, Metric::CompletedDerives, false)
                    ));
                } else {
                    ui.label(format!(
                        "Known queue {} · receive {} · send {}",
                        count(worker, Metric::Queued),
                        rate(worker, Metric::ReceivedBytes, true),
                        rate(worker, Metric::SentBytes, true)
                    ));
                }
                let execution = execution_summary(worker);
                if serial_configuration_mismatch(worker) {
                    ui.colored_label(ui.visuals().warn_fg_color, execution);
                } else {
                    ui.label(execution);
                }
                if worker
                    .stages
                    .iter()
                    .any(|stage| stage == "no-publication-pass")
                {
                    ui.small(
                        "Zero successful merge/derive publications does not mean no computation.",
                    );
                }
            });
        })
        .body(|ui| render_details(ui, worker));
}

fn render_freshness(ui: &mut egui::Ui, worker: &WorkerReport) {
    let label = match worker.freshness {
        Freshness::Fresh => format!(
            "fresh · {}s",
            worker
                .age_seconds
                .map_or_else(|| "?".into(), |age| age.to_string())
        ),
        Freshness::Stale => format!(
            "STALE · {}s · historical",
            worker
                .age_seconds
                .map_or_else(|| "?".into(), |age| age.to_string())
        ),
        Freshness::Future => "FUTURE · current state unknown".into(),
    };
    let color = if worker.freshness == Freshness::Fresh {
        ui.visuals().weak_text_color()
    } else {
        ui.visuals().warn_fg_color
    };
    ui.label(egui::RichText::new(label).small().color(color));
}

fn process_effort(worker: &WorkerReport) -> Option<String> {
    // CPU time is process evidence, not an attribution to every maintenance
    // stage or target. No process subject means effort remains unobserved.
    (worker.role == "process").then(|| cpu(worker))
}

fn serial_configuration_mismatch(worker: &WorkerReport) -> bool {
    worker.parallel_compiled.as_slice() == [false]
        && worker.metrics.iter().any(|metric| {
            metric.metric == Metric::Parallelism
                && matches!(&metric.value, CountMetric::Value(value) if *value > 1)
        })
}

fn execution_summary(worker: &WorkerReport) -> String {
    let compiled = if serial_configuration_mismatch(worker) {
        "PARALLEL PATH NOT COMPILED"
    } else {
        match worker.parallel_compiled.as_slice() {
            [true] => "parallel path compiled",
            [false] => "serial build",
            [] => "compiled parallelism unknown",
            _ => "compiled parallelism ambiguous",
        }
    };
    format!(
        "{}active {} · configured {} · {}",
        if worker.freshness == Freshness::Fresh {
            ""
        } else {
            "Historical / uncertain: "
        },
        count(worker, Metric::Active),
        count(worker, Metric::Parallelism),
        compiled
    )
}

fn render_details(ui: &mut egui::Ui, worker: &WorkerReport) {
    ui.label(format!(
        "{} / {} · stage {} · {}",
        clean(&worker.worker, 36),
        clean(&worker.role, 24),
        labels(&worker.stages),
        observation_age(worker)
    ));
    ui.label(format!(
        "Backend executing {} · compiled {}",
        labels(&worker.backends),
        labels(&worker.compiled_backends)
    ));
    ui.label(format!(
        "Known queued {} · failed {} · completed {}",
        count(worker, Metric::Queued),
        count(worker, Metric::Failed),
        count(worker, Metric::Completed)
    ));
    if let Some(effort) = process_effort(worker) {
        ui.label(format!("Process CPU {effort}"));
    }
    if has_metric(worker, Metric::WorkNs) {
        ui.label(format!(
            "Completed-operation wall work {} (may overlap; not CPU)",
            wall_work(worker)
        ));
    }
    ui.label(format!(
        "Receive {} · send {}",
        rate(worker, Metric::ReceivedBytes, true),
        rate(worker, Metric::SentBytes, true)
    ));
    if !worker.targets.is_empty() {
        ui.label(format!("Selected targets {}", handles(&worker.targets)));
    }
    if !worker.peers.is_empty() {
        ui.label(format!(
            "Peers {} · path {} · RTT {}",
            handles(&worker.peers),
            labels(&worker.paths),
            rtt(worker)
        ));
    }
}
