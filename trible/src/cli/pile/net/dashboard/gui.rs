//! Embedded GORBIE frontend. It borrows only the latest read-only sampler frame;
//! the parent owns stop/join/close even if window creation fails.

use super::*;
use anyhow::anyhow;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::{CardCtx, NotebookConfig};

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "gui_capture_tests.rs"]
mod capture_tests;

/// One read-only part of the colony. The lattice is deliberately NOT here:
/// it owns the selection, so it is a `state` card rather than a `view` one.
///
/// Each of these becomes its OWN notebook card rather than a heading inside one
/// long card. That is not cosmetic: GORBIE detaches a card, so one card per
/// section is what lets a reader pull the mesh onto one side of the workspace
/// and keep the members list on the other. A single card detaches whole or not
/// at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section {
    Overview,
    Mesh,
    Members,
    Nodes,
    Links,
}

impl Section {
    /// Shown before a frame arrives, so an empty workspace still says what each
    /// card is going to be instead of showing identical placeholders.
    const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Colony overview",
            Self::Mesh => "Observed mesh",
            Self::Members => "Collection members",
            Self::Nodes => "Nodes and workers",
            Self::Links => "Observed links",
        }
    }

    fn draw(self, ui: &mut egui::Ui, frame: &Frame, selected: Option<[u8; 32]>) {
        match self {
            Self::Overview => render_overview(ui, frame),
            Self::Mesh => styled(ui, |ui| render_mesh(ui, frame)),
            Self::Members => styled(ui, |ui| render_members(ui, frame, selected)),
            Self::Nodes => render_nodes(ui, frame),
            Self::Links => render_links(ui, frame),
        }
    }
}

/// The cards that only READ. The overview is drawn by the producer and the
/// lattice by the selector, because each of those owns a value.
const CONSUMERS: [Section; 4] = [
    Section::Mesh,
    Section::Members,
    Section::Nodes,
    Section::Links,
];

/// What a card has to draw from: the latest frame, the reason there is none,
/// or nothing observed yet.
type Observed = Option<std::result::Result<Frame, ReadFailure>>;

/// What the sampler can say right now: the latest observation, and when the
/// pass currently running began, if one is.
type Pulled = (Observed, Option<Instant>);

/// Say that a pass is running, and how long it has been.
///
/// A bar needs a denominator. The only one available is how long the LAST pass
/// took, so there is no bar on the first observation -- which is exactly the
/// one that keeps a reader waiting longest on a large pile. Drawing a fraction
/// there would mean inventing the denominator, and a bar that fills at an
/// invented rate is worse than a number that is merely honest.
fn render_loading(ui: &mut egui::Ui, elapsed: Duration, previous: Option<Duration>) {
    let waited = elapsed.as_secs_f64();
    match previous.map(|previous| previous.as_secs_f32()).filter(|seconds| *seconds > 0.0) {
        Some(expected) if elapsed.as_secs_f32() <= expected => {
            ui.add(
                GORBIE::widgets::ProgressBar::new(elapsed.as_secs_f32() / expected)
                    .text(format!("observing · {waited:.1}s of about {expected:.1}s")),
            );
            ui.small("The estimate is the previous pass's duration, not a measured remainder.");
        }
        Some(expected) => {
            ui.add(GORBIE::widgets::ProgressBar::new(1.0).text(format!(
                "observing · {waited:.1}s, longer than the previous pass ({expected:.1}s)"
            )));
            ui.small("Past the estimate, so the bar is full and the number is the real one.");
        }
        None => {
            ui.label(format!("Observing · {waited:.1}s"));
            ui.small(
                "No previous pass to estimate from, so no bar: a fraction here would need a \
                 denominator nobody has.",
            );
        }
    }
}

/// Draw one card's body, or say why there is nothing to draw.
fn draw<F>(ctx: &mut CardCtx<'_>, observed: &Observed, title: &str, body: F)
where
    F: FnOnce(&mut egui::Ui, &Frame),
{
    ctx.with_padding(DEFAULT_CARD_PADDING, |ctx| match observed {
        Some(Ok(frame)) => body(ctx, frame),
        Some(Err(error)) => {
            ctx.heading(title);
            ctx.label(error.message());
        }
        None => {
            ctx.heading(title);
            ctx.label("Opening one local reader; no networking or maintenance is started.");
        }
    });
}

/// The dashboard's card graph: one producer, one selector, four consumers.
///
/// GORBIE's cards are a DATAFLOW model rather than a layout. A `state` card
/// produces a value and hands back a handle; every card that `read`s that
/// handle thereby declares a dependency on it. Written this way the graph says
/// what it is — one observation feeds every panel, and the selected collection
/// feeds only the member list — and detachable cards fall out of it rather
/// than being the reason for it.
///
/// What this replaces drew the same pixels and said none of that: one card for
/// everything, a selection smuggled through `egui` temp storage so a second
/// reader could find it, and — in the intermediate version — five stateless
/// cards each locking the sampler and cloning the whole frame for itself. The
/// last one is the instructive failure: it looked decomposed, and the shared
/// dependency was still invisible, so the frame was cloned once per card per
/// repaint instead of once.
///
/// `pull` and `publish` are the only things that differ between the live
/// dashboard and a capture of a fixed frame, so a capture exercises this exact
/// graph rather than a second arrangement that merely resembles it.
fn compose<P, S>(notebook: &mut GORBIE::NotebookCtx, pull: P, publish: S)
where
    P: Fn() -> Pulled + 'static,
    S: Fn(Option<[u8; 32]>) + 'static,
{
    // The producer. It draws the overview because a card IS a node: the value
    // it publishes and the panel it draws are the same thing, not two.
    let observed = notebook.state(
        "colony-frame",
        None as Observed,
        move |ctx, held: &mut Observed| {
            ctx.ctx().request_repaint_after(Duration::from_millis(250));
            let (observed, since) = pull();
            *held = observed;
            // The previous pass's duration is the only estimate available, and
            // it lives on the frame the previous pass produced.
            let previous = held
                .as_ref()
                .and_then(|observed| observed.as_ref().ok())
                .map(|frame| frame.observation_time);
            ctx.with_padding(DEFAULT_CARD_PADDING, |ctx| {
                styled(ctx, |ui| {
                    if let Some(since) = since {
                        render_loading(ui, since.elapsed(), previous);
                        ui.separator();
                    }
                    match held.as_ref() {
                        Some(Ok(frame)) => render_overview(ui, frame),
                        Some(Err(error)) => {
                            ui.heading(Section::Overview.title());
                            ui.label(error.message());
                        }
                        None => {
                            ui.heading(Section::Overview.title());
                            ui.label(
                                "Opening one local reader; no networking or maintenance is \
                                 started.",
                            );
                        }
                    }
                });
            });
        },
    );

    // The selector. Reading `observed` here is safe and is the point: each
    // state is its own lock, so a card may hold its own value for writing
    // while reading another's.
    let selection = notebook.state(
        "colony-selection",
        None as Option<[u8; 32]>,
        move |ctx, selected: &mut Option<[u8; 32]>| {
            let held = observed.read(ctx);
            draw(ctx, &held, "Collection lattice", |ui, frame| {
                styled(ui, |ui| render_lattice(ui, frame, selected));
            });
            // Publish only a change. It bumps the revision the sampler waits
            // on, so a click is answered on the next pass rather than at the
            // end of the current interval.
            publish(*selected);
        },
    );

    for section in CONSUMERS {
        notebook.view(move |ctx| {
            let held = observed.read(ctx);
            let chosen = *selection.read(ctx);
            draw(ctx, &held, section.title(), |ui, frame| {
                section.draw(ui, frame, chosen);
            });
        });
    }
}

pub(super) fn run(options: Options) -> Result<()> {
    let mut sampler = Sampler::start(options)?;
    let shared = Arc::clone(&sampler.shared);
    let result = NotebookConfig::new("TribleSpace colony").run(move |notebook| {
        let pulling = Arc::clone(&shared);
        let publishing = Arc::clone(&shared);
        compose(
            notebook,
            move || {
                let state = pulling
                    .0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let since = state.sampling_since;
                let latest = state.latest.clone();
                drop(state);
                (
                    latest.map(|latest| {
                        latest.map(|frame| {
                            frame.at(triblespace_core::clock::epoch_now()
                                .to_tai_duration()
                                .total_nanoseconds())
                        })
                    }),
                    since,
                )
            },
            move |chosen| {
                let mut state = publishing
                    .0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if state.focus != chosen {
                    state.focus = chosen;
                    state.focus_revision = state.focus_revision.wrapping_add(1);
                    publishing.1.notify_all();
                }
            },
        );
    });
    let closed = sampler.finish();
    result.map_err(|error| anyhow!("open colony notebook: {error}"))?;
    closed
}

/// The dashboard type scale, applied per card.
///
/// A dashboard carries denser information than a prose notebook. This keeps the
/// notebook's font families and theme and scopes only the sizes and spacing --
/// and it has to be applied in EVERY card, because each one is now its own
/// `Ui` and none of them inherits a scope from a sibling.
fn styled(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
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
        body(ui);
    });
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
            // The conflation that used to live here is gone. `MeshNodeState`
            // grew the fourth variant it needed, so the split is on whether a
            // report EXISTS at all rather than on what one contains: a node
            // nobody here has heard from is an absence, and a node that
            // reported something we cannot place in time is a clock fault. They
            // are different questions with different answers and they now draw
            // differently — dashed for the hole, slashed for the fault.
            //
            // `Freshness` is deliberately untouched: it describes a report, so
            // there is no freshness value for "no report exists".
            let fresh = reports().any(|worker| worker.freshness == Freshness::Fresh)
                || health().any(|observer| observer.freshness == Freshness::Fresh);
            let stale = reports().any(|worker| worker.freshness == Freshness::Stale)
                || health().any(|observer| observer.freshness == Freshness::Stale);
            let reported = reports().next().is_some() || health().next().is_some();
            let state = if fresh {
                MeshNodeState::Fresh
            } else if stale {
                MeshNodeState::Stale
            } else if reported {
                MeshNodeState::Unknown
            } else {
                MeshNodeState::Unreported
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
                label: super::node_label(frame, node),
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
        "Filled square: this node reported, inside the freshness window. Open \
         square: it reported, but older than the window — stale describes a \
         report, so only a node that sent one can be stale. Dashed square: \
         never heard from here; it is in this picture because a peer named it. \
         Slashed square: it reported, and the report cannot be placed in time — \
         a clock fault, not a silence. Arc: merge and derive work completed \
         over work seen. Barb points at the observed peer.",
    );
    // One conflation remains, and the marks do not separate it. Saying so is
    // not a style note: a legend that reads cleanly over a mark that cannot
    // support the reading certifies the wrong answer, which is worse than
    // saying nothing.
    ui.small(
        "The empty track is still both no measurement and a measured zero: \
         convergence is None when nothing was reported AND when nothing was \
         pending, so an empty ring cannot be read as agreement OR as a zero. \
         Separating them needs the sampler to say whether the node reported \
         these metrics at all, which it does not currently carry.",
    );
    // An edge here is an OBSERVATION, not a link, and the difference is the
    // whole reading. Worker link telemetry would give real edges and is
    // usually absent, so on a live pile every line comes from a health
    // condition naming a peer. A pair with nothing to report therefore draws
    // NO line, which means a healthy, fully connected colony draws an empty
    // graph. Saying so is the point: a mesh picture invites "these two are
    // connected", and the marks cannot support it.
    let from_telemetry = frame
        .workers
        .iter()
        .any(|worker| worker.role == "link" || !worker.peers.is_empty());
    ui.small(if links.is_empty() {
        "No edges. Nothing reported a peer, which is NOT the same as nothing \
         being connected: edges here come from reports, so an idle healthy \
         colony draws none."
    } else if from_telemetry {
        "A line is an observation, not a link. Some edges come from worker \
         link telemetry and some from a health condition naming a peer; the \
         marks do not separate them. A missing line means neither reported \
         that pair, never that they cannot reach each other."
    } else {
        "A line is an observation, not a link. No worker link telemetry was \
         observed, so every edge here is a health condition naming a peer — \
         which means edges appear where something was REPORTED about a pair. A \
         missing line means nothing was reported, never that they cannot reach \
         each other."
    });
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
fn render_lattice(ui: &mut egui::Ui, frame: &Frame, selected: &mut Option<[u8; 32]>) {
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
            // A collection is named or derived, so something produced it by
            // construction; "reached only as an input" is a fact about members,
            // not about collections.
            produced: true,
            // Not claimed. The widget can draw "this label is a stand-in for a
            // name whose bytes are missing", but this observation cannot tell
            // that apart from "this collection has no name at all" —
            // `LatticeCollection::name` is `None` for both. Asserting either
            // would be inventing a fact, so it asserts neither until the
            // sampler carries whether a name attribute was present.
            label_known: true,
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
    // different collection. The selection lives in notebook state, owned by
    // this card and readable by every other one, so a detached card keeps
    // answering for the same collection.
    let chosen = *selected;
    let position_of = chosen.and_then(position);
    let drawn = LatticeGraph::new(&nodes, &edges).selected(position_of).show(ui);
    if let Some(clicked) = drawn.clicked {
        let handle = collections[clicked].handle;
        *selected = (chosen != Some(handle)).then_some(handle);
    }

    let derived = collections.iter().filter(|c| c.source.is_some()).count();
    let absent = collections
        .iter()
        .filter(|c| !c.descriptor_resident)
        .count();
    let unadmitted: u64 = collections.iter().map(|c| c.unadmitted).sum();
    let holding = collections.iter().filter(|c| c.unadmitted > 0).count();
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
        // Deliberately its own line rather than folded into the one above.
        // Missing bytes arrive on their own once replication catches up; an
        // unadmitted signer waits on a grant somebody has to issue. Folding
        // them together would report work as weather.
        //
        // Both the total and the spread, because they answer different
        // questions: the total says how much is waiting on a grant, the count
        // of collections says how many places to go and look. The whole-pile
        // aggregate on its own is the figure nobody can act on.
        if unadmitted != 0 {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!("{unadmitted} unadmitted across {holding}"),
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
    match drawn.hovered.or(position_of) {
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
    ui.separator();
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
            // A commit is produced by definition — an author asserted it. For
            // the rest, this is whether a record HERE made it. False is the
            // member reached only as somebody else's join input, which until
            // now was a count printed beside a mark that looked exactly like a
            // fully-produced one.
            produced: member.committed || member.produced,
            label_known: true,
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
            ui.small(format!(
                "{} reached only as a join input — each one drawn with a gap at \
                 the bottom of its mark, so you can point at them",
                members.unproduced
            ));
        }
    });
    ui.small(
        "Inside the selection: square is a commit, circle a join result or mapping \
         output, a circle with a gap at the bottom a member nothing here produced — \
         it was reached as somebody else's join input and the record that made it is \
         elsewhere. Dashed is a member whose bytes are not here. Each join's two \
         edges are its MERGE inputs.",
    );
}

/// Heading, coverage and the warnings, as their own card.
fn render_overview(ui: &mut egui::Ui, frame: &Frame) {
    styled(ui, |ui| {
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
    });
}

/// Per-node worker scopes and each node's health conditions.
fn render_nodes(ui: &mut egui::Ui, frame: &Frame) {
    styled(ui, |ui| {
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
    });
}

/// Observed links, which are measured payload rates and not link capacity.
fn render_links(ui: &mut egui::Ui, frame: &Frame) {
    styled(ui, |ui| {
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
