//! Embedded GORBIE frontend. It borrows only the latest read-only sampler frame;
//! the parent owns stop/join/close even if window creation fails.

use super::*;
use anyhow::anyhow;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::NotebookConfig;

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
            // Forward the viewer's selection to the sampler, which owns the
            // store. Only a change is published, and it bumps the revision the
            // sampler waits on so a click is answered on the next pass rather
            // than at the end of the current interval.
            let chosen: Option<[u8; 32]> =
                ctx.ctx().data(|data| data.get_temp(selection_id()));
            {
                let mut state = shared
                    .0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if state.focus != chosen {
                    state.focus = chosen;
                    state.focus_revision = state.focus_revision.wrapping_add(1);
                    shared.1.notify_all();
                }
            }
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

/// The observed mesh, drawn once above the per-node detail.
///
/// The link rows already exist in the sampler and the terminal view prints
/// them, but this frontend filtered them out entirely, so who-observes-whom
/// was the one thing the colony view could not show. Nodes are placed by the
/// widget; this function only decides what is true.
///
/// Convergence is `completed / (completed + pending)` over merges and derives.
/// That is backlog, which is what "behind" actually means here — it is not a
/// record count, and it is deliberately `None` rather than 1.0 when a node
/// reported no work at all, because no evidence is not agreement.
fn render_mesh(ui: &mut egui::Ui, frame: &Frame) {
    use GORBIE::widgets::{MeshGraph, MeshLink, MeshNode, MeshNodeState};

    // `frame.nodes()` counts reporters: worker nodes and health endpoints. A peer
    // named inside a health condition is also part of the mesh even though it
    // never reported here, and on a live pile that is usually the ONLY edge
    // evidence available — worker link telemetry is opt-in and often absent.
    // Including them is what makes this draw anything outside the fixture.
    let mut nodes: BTreeSet<[u8; 32]> = frame.nodes();
    for observer in &frame.health {
        for condition in &observer.conditions {
            nodes.extend(condition.peers.iter().copied());
        }
    }
    for worker in &frame.workers {
        nodes.extend(worker.peers.iter().copied());
    }
    let nodes: Vec<[u8; 32]> = nodes.into_iter().collect();
    if nodes.len() < 2 {
        return;
    }
    let index = |handle: &[u8; 32]| nodes.iter().position(|node| node == handle);

    let mesh_nodes: Vec<MeshNode> = nodes
        .iter()
        .map(|node| {
            let reports = || frame.workers.iter().filter(|worker| worker.node == *node);
            let health = || {
                frame
                    .health
                    .iter()
                    .filter(|observer| observer.endpoints.iter().any(|endpoint| endpoint == node))
            };
            let fresh = reports().any(|worker| worker.freshness == Freshness::Fresh)
                || health().any(|observer| observer.freshness == Freshness::Fresh);
            let stale = reports().any(|worker| worker.freshness == Freshness::Stale)
                || health().any(|observer| observer.freshness == Freshness::Stale);
            let state = if fresh {
                MeshNodeState::Fresh
            } else if stale {
                MeshNodeState::Stale
            } else {
                MeshNodeState::Unknown
            };
            let mut done = 0u128;
            let mut pending = 0u128;
            for worker in reports() {
                for measured in &worker.metrics {
                    let Some(value) = measured.value.value() else {
                        continue;
                    };
                    match measured.metric {
                        Metric::CompletedMerges | Metric::CompletedDerives => done += value,
                        Metric::PendingMerges | Metric::PendingDerives => pending += value,
                        _ => {}
                    }
                }
            }
            let total = done + pending;
            MeshNode {
                label: short(node),
                state,
                convergence: (total > 0).then(|| done as f32 / total as f32),
            }
        })
        .collect();

    let mut links: Vec<MeshLink> = Vec::new();
    // Health conditions name who observed whom, and are the live pile's edges.
    for observer in &frame.health {
        for endpoint in &observer.endpoints {
            let Some(from) = index(endpoint) else {
                continue;
            };
            for condition in &observer.conditions {
                for peer in &condition.peers {
                    if let Some(to) = index(peer) {
                        if from != to && !links.contains(&MeshLink { from, to }) {
                            links.push(MeshLink { from, to });
                        }
                    }
                }
            }
        }
    }
    for worker in &frame.workers {
        if worker.role != "link" && worker.peers.is_empty() {
            continue;
        }
        let Some(from) = index(&worker.node) else {
            continue;
        };
        for peer in &worker.peers {
            if let Some(to) = index(peer) {
                if from != to && !links.contains(&MeshLink { from, to }) {
                    links.push(MeshLink { from, to });
                }
            }
        }
    }

    ui.add(MeshGraph::new(&mesh_nodes, &links).height(260.0));
    ui.small(
        "Ring: observed peers. Filled square fresh, open stale, slashed unknown. \
         Arc: merge and derive work completed over work seen; an empty track is \
         no evidence, not agreement. Barb points at the observed peer.",
    );
    if links.is_empty() {
        ui.small("No link telemetry observed, so no edges are drawn.");
    }
    ui.separator();
}

/// The collection lattice, and the one panel in this dashboard you can walk.
///
/// Every other panel answers "how is it going". This one answers "what is
/// there, what is not, and where did it come from" — the three questions the
/// cluster view was wanted for. They are one picture because they come from
/// one frozen observation: a node is a collection, a left-to-right edge is a
/// derivation, a short arc is endorsed work whose bytes are not here, and a
/// dashed mark is a collection this store knows only by name.
///
/// Clicking a node dims everything off its chain and prints that chain in full
/// underneath, which is how a derived collection gets walked back to the root
/// it was computed from.
fn render_lattice(ui: &mut egui::Ui, frame: &Frame) {
    use GORBIE::widgets::{LatticeEdge, LatticeGraph, LatticeMark, LatticeNode, LatticePresence};

    ui.label(
        egui::RichText::new("Collection lattice")
            .strong()
            .size(19.0),
    );
    let Some(collections) = &frame.lattice else {
        ui.small("Not sampled. Rerun with --lattice; an unsampled lattice is not an empty one.");
        ui.separator();
        return;
    };
    if collections.is_empty() {
        ui.small("Sampled: this pile references no collections.");
        ui.separator();
        return;
    }

    let label = |collection: &LatticeCollection| {
        collection
            .name
            .clone()
            .unwrap_or_else(|| short(&collection.handle))
    };
    let position = |handle: [u8; 32]| collections.iter().position(|c| c.handle == handle);

    let nodes: Vec<LatticeNode> = collections
        .iter()
        .map(|collection| LatticeNode {
            label: label(collection),
            // A root is authored — someone named it. A derivation is
            // computed, and could in principle be rebuilt from its source.
            mark: match collection.source {
                Some(_) => LatticeMark::Computed,
                None => LatticeMark::Authored,
            },
            presence: match collection.descriptor_resident {
                true => LatticePresence::Present,
                false => LatticePresence::Absent,
            },
            // No records naming it means nothing to divide, which draws as an
            // empty track. That is absence of evidence, not full residency.
            coverage: (collection.stored() > 0)
                .then(|| collection.result_resident as f32 / collection.stored() as f32),
        })
        .collect();

    let edges: Vec<LatticeEdge> = collections
        .iter()
        .enumerate()
        .filter_map(|(to, collection)| {
            let from = position(collection.source?)?;
            Some(LatticeEdge {
                from,
                to,
                // The descriptor declares the derivation; a DERIVE record is
                // what performs it. Declared but never performed is exactly
                // the missing step this view exists to show, so it draws as a
                // dashed edge rather than as an ordinary one.
                endorsed: collection.derives > 0,
            })
        })
        .collect();

    // The selection is stored as a handle, not as an index: the projection is
    // re-sorted every observation, and an index would quietly come to mean a
    // different collection. The id is fixed rather than salted by the Ui stack
    // so the sampler thread can read the same value back.
    let id = selection_id();
    let chosen: Option<[u8; 32]> = ui.data(|data| data.get_temp::<[u8; 32]>(id));
    let selected = chosen.and_then(position);
    let drawn = LatticeGraph::new(&nodes, &edges).selected(selected).show(ui);
    if let Some(clicked) = drawn.clicked {
        let handle = collections[clicked].handle;
        ui.data_mut(|data| {
            if chosen == Some(handle) {
                data.remove::<[u8; 32]>(id);
            } else {
                data.insert_temp(id, handle);
            }
        });
    }

    let derived = collections.iter().filter(|c| c.source.is_some()).count();
    let absent = collections
        .iter()
        .filter(|c| !c.descriptor_resident)
        .count();
    ui.horizontal_wrapped(|ui| {
        ui.small(format!(
            "{} collections · {derived} derived",
            collections.len()
        ));
        if absent != 0 {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!("{absent} with no resident descriptor"),
            );
        }
    });
    ui.small(
        "Left to right is derivation; sources are always to the left. Square authored, \
         circle computed. Dashed is a hole: a collection known only by name, or a \
         derivation declared and never performed. Arc: result blobs resident over \
         records naming that collection, per collection, in this pile alone.",
    );

    // Hover previews a chain; a click pins it. Previewing on hover is what
    // makes a wide lattice explorable without committing to a selection.
    match drawn.hovered.or(selected) {
        None => ui.small("Click a collection to walk its source chain."),
        Some(index) => {
            let mut chain = Vec::new();
            let mut visited = BTreeSet::new();
            let mut at = Some(index);
            let mut dangling = None;
            while let Some(current) = at {
                if !visited.insert(current) {
                    break;
                }
                chain.push(current);
                at = match collections[current].source {
                    None => None,
                    Some(source) => match position(source) {
                        Some(found) => Some(found),
                        None => {
                            dangling = Some(source);
                            None
                        }
                    },
                };
            }
            chain.reverse();
            let focus = &collections[index];
            ui.small(format!(
                "{} · {} commit / {} merge / {} derive · {} of {} result blobs resident{}",
                label(focus),
                focus.commits,
                focus.merges,
                focus.derives,
                focus.result_resident,
                focus.stored(),
                match focus.descriptor_resident {
                    true => "",
                    false => " · descriptor not resident here",
                }
            ));
            let walked = chain
                .iter()
                .map(|step| label(&collections[*step]))
                .collect::<Vec<_>>()
                .join(" -> ");
            ui.small(match dangling {
                Some(handle) => format!(
                    "source chain: [{} not in this observation] -> {walked}",
                    short(&handle)
                ),
                None => format!("source chain: {walked}"),
            })
        }
    };
    render_members(ui, frame, chosen);
    ui.separator();
}

/// The fixed key the selected collection is stored under.
///
/// Fixed, not salted by the Ui stack, because two different holders read it:
/// the panel that draws the lattice and the loop that forwards the selection
/// to the sampler.
fn selection_id() -> egui::Id {
    egui::Id::new("colony-lattice-selection")
}

/// The join lattice inside the selected collection.
///
/// `MERGE(C, low, high, result)` states `low ⊔ high = result`, so the two
/// edges under each join mark are the equation itself. A member with no edge
/// below it was committed or derived rather than joined; a member with none
/// above it is a maximal element — nothing has joined it into anything yet,
/// which is the merge work this collection still owes.
fn render_members(ui: &mut egui::Ui, frame: &Frame, chosen: Option<[u8; 32]>) {
    use GORBIE::widgets::{LatticeEdge, LatticeGraph, LatticeMark, LatticeNode, LatticePresence};

    let Some(chosen) = chosen else { return };
    let Some(members) = &frame.members else {
        ui.small("Reading the selected collection's members...");
        return;
    };
    if members.collection != chosen {
        // The sampler answers the previous selection until its next pass.
        ui.small("Reading the selected collection's members...");
        return;
    }
    if let Some(count) = members.too_large {
        ui.small(format!(
            "{count} members: more than can be drawn legibly. A truncated lattice              would hide the joins that ran through the dropped members, so none is drawn."
        ));
        return;
    }
    if members.members.is_empty() {
        ui.small("No members: nothing has been committed to or derived into this collection.");
        return;
    }

    let nodes: Vec<LatticeNode> = members
        .members
        .iter()
        .map(|member| LatticeNode {
            label: short(&member.handle),
            // A COMMIT is the one thing here no machine can recompute.
            mark: match member.committed {
                true => LatticeMark::Authored,
                false => LatticeMark::Computed,
            },
            presence: match member.resident {
                true => LatticePresence::Present,
                false => LatticePresence::Absent,
            },
            // Residency is already carried by the mark's stroke; a second
            // channel saying the same thing would be decoration.
            coverage: None,
        })
        .collect();
    let edges: Vec<LatticeEdge> = members
        .joins
        .iter()
        .map(|(from, to)| LatticeEdge {
            from: *from,
            to: *to,
            // Every edge here comes from a stored MERGE. Absence of a join is
            // a member with nothing above it, not a dashed edge.
            endorsed: true,
        })
        .collect();

    let maximal = (0..nodes.len())
        .filter(|node| !edges.iter().any(|edge| edge.from == *node))
        .count();
    ui.add(LatticeGraph::new(&nodes, &edges));
    ui.horizontal_wrapped(|ui| {
        ui.small(format!(
            "{} members · {} joins · {maximal} not yet joined into anything",
            nodes.len(),
            edges.len()
        ));
        if members.unproduced != 0 {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!(
                    "{} reached only as a join input; what produced them is elsewhere",
                    members.unproduced
                ),
            );
        }
    });
    ui.small(
        "Inside the selection: square is a commit, circle a join result or mapping \
         output, dashed a member whose bytes are not here. Each join's two edges are \
         its MERGE inputs.",
    );
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
        render_mesh(ui, frame);
        render_lattice(ui, frame);

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
