//! Embedded GORBIE frontend. It borrows only the latest read-only sampler frame;
//! the parent owns stop/join/close even if window creation fails.

use super::*;
use anyhow::anyhow;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::{
    CaptureOptions, CaptureResult, CapturedPng, CardCtx, HeadlessTheme, NotebookConfig,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "gui_capture_tests.rs"]
mod capture_tests;

#[cfg(test)]
mod family_tests {
    use super::*;

    fn collection(byte: u8, kind: CollectionKind, source: Option<u8>) -> LatticeCollection {
        LatticeCollection {
            handle: [byte; 32],
            name: None,
            source: source.map(|byte| [byte; 32]),
            kind,
            mapping: None,
            descriptor_resident: true,
            commits: 0,
            merges: 0,
            derives: 0,
            maps: 0,
            foundations_resident: 0,
            unadmitted: 0,
        }
    }

    #[test]
    fn a_family_is_a_root_and_everything_whose_chain_reaches_it() {
        // The lattice card draws one family. Two unrelated roots must never
        // land in one picture, and a derivation of a derivation, or an index
        // attached to a derivation, belongs to the root at the end of its chain.
        let collections = vec![
            collection(1, CollectionKind::Root, None),
            collection(2, CollectionKind::Derived, Some(1)),
            collection(3, CollectionKind::Derived, Some(2)),
            collection(4, CollectionKind::Attached, Some(3)),
            collection(5, CollectionKind::Root, None),
            collection(6, CollectionKind::Attached, Some(5)),
            // Its source is not in the observation: it stands as its own root.
            collection(7, CollectionKind::Derived, Some(99)),
        ];
        assert_eq!(families(&collections), vec![0, 0, 0, 0, 4, 4, 6]);
    }

    #[test]
    fn a_descriptor_loop_is_one_family_rather_than_none() {
        // Open world: descriptors may name each other. Every member of the
        // loop, and what hangs off it, must still reach the picker.
        let collections = vec![
            collection(1, CollectionKind::Derived, Some(2)),
            collection(2, CollectionKind::Derived, Some(1)),
            collection(3, CollectionKind::Attached, Some(2)),
        ];
        let families = families(&collections);
        assert_eq!(families, vec![0, 0, 0]);
        assert_eq!(families[0], 0, "the loop's root is its own family's root");
    }
}

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

    fn draw(
        self,
        ui: &mut egui::Ui,
        frame: &Frame,
        selected: Option<[u8; 32]>,
        hidden: &BTreeSet<[u8; 32]>,
    ) {
        match self {
            Self::Overview => render_overview(ui, frame),
            Self::Mesh => styled(ui, |ui| render_mesh(ui, frame)),
            Self::Members => styled(ui, |ui| render_members(ui, frame, selected, hidden)),
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
/// Wire the card graph.
///
/// `selected` is the selection the graph opens on. It is a parameter rather
/// than a hardcoded `None` because the capture needs to open on a collection:
/// with nothing selected the member card correctly draws nothing, and the
/// evidence was then blind to exactly the card it claims to guard.
fn compose<P, S>(
    notebook: &mut GORBIE::NotebookCtx,
    pull: P,
    publish: S,
    selected: Option<[u8; 32]>,
) where
    P: Fn() -> Pulled + 'static,
    S: Fn(Option<[u8; 32]>) + 'static,
{
    // The producer. It draws the overview because a card IS a node: the value
    // it publishes and the panel it draws are the same thing, not two.
    let observed = notebook.state(
        "colony-frame",
        || None as Observed,
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
        move || selected,
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

    // The dependency view. It owns which attached collections the member card
    // overlays, so it is a state card of its own rather than a widget inside
    // the member card: the tree is a question about the collection lattice,
    // the overlay an answer drawn over the member lattice, and keeping them
    // apart is what lets a reader detach one beside the other.
    //
    // It holds what is HIDDEN, not what is shown. The store is an open world
    // and an attachment that appears next observation should appear in the
    // picture too, rather than wait for somebody to tick a box they cannot
    // know exists.
    let hidden = notebook.state(
        "colony-hidden-attached",
        BTreeSet::<[u8; 32]>::new,
        move |ctx, hidden: &mut BTreeSet<[u8; 32]>| {
            let held = observed.read(ctx);
            let chosen = *selection.read(ctx);
            draw(ctx, &held, ATTACHED_TITLE, |ui, frame| {
                styled(ui, |ui| render_attached_tree(ui, frame, chosen, hidden));
            });
        },
    );

    for section in CONSUMERS {
        notebook.view(move |ctx| {
            let held = observed.read(ctx);
            let chosen = *selection.read(ctx);
            let hidden = hidden.read(ctx).clone();
            draw(ctx, &held, section.title(), |ui, frame| {
                section.draw(ui, frame, chosen, &hidden);
            });
        });
    }
}

pub(super) fn run(options: Options) -> Result<()> {
    let focus = options.focus;
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
            // A live dashboard opens on `--focus`, else on nothing: the
            // reader picks.
            focus,
        );
    });
    let closed = sampler.finish();
    result.map_err(|error| anyhow!("open colony notebook: {error}"))?;
    closed
}

/// Render one fixed observation through the LIVE card graph, headlessly.
///
/// Only the pull and the publish differ from [`run`]: the pull always answers
/// `frame`, and a selection goes nowhere because nothing samples again. `emit`
/// receives each card's PNG in card order; its first error stops the capture.
/// This is the one capture path, shared by `--capture` and the generated-pile
/// visual fixture, so the fixture cannot drift from what the command draws.
///
/// It initializes wgpu with GORBIE's adapter choice (`Instance::default()`,
/// high performance), which on a machine with a GPU is the GPU unless the
/// caller restricts the Vulkan ICD and EGL vendor to a software driver.
fn capture_frame(
    frame: Frame,
    selected: Option<[u8; 32]>,
    emit: impl FnMut(CapturedPng) -> CaptureResult<()>,
) -> CaptureResult<()> {
    NotebookConfig::new("TribleSpace colony")
        .with_headless_theme(HeadlessTheme::Dark)
        .capture(
            CaptureOptions {
                pixels_per_point: 1.0,
                settle_timeout: Duration::from_secs(2),
            },
            move |notebook| {
                let frame = frame.clone();
                compose(
                    notebook,
                    move || (Some(Ok(frame.clone())), None),
                    |_chosen| {},
                    selected,
                );
                notebook.settled();
            },
            emit,
        )
}

/// `--capture DIR`: take ONE observation through the ordinary reader, close
/// it, then write each card's PNG and the terminal render of the same frame
/// into `DIR`. Files are created new, never overwritten, so a second capture
/// into the same directory fails instead of mixing two observations.
pub(super) fn capture(options: Options, directory: &std::path::Path) -> Result<()> {
    use std::io::Write as _;
    anyhow::ensure!(
        directory.is_dir(),
        "capture directory {} must already exist",
        directory.display()
    );
    let mut reader =
        Reader::open(&options).map_err(|error| anyhow!("open reader: {}", error.message()))?;
    let sampled = reader.sample();
    let closed = reader.close();
    let frame = sampled.map_err(|error| anyhow!("observe: {}", error.message()))?;
    closed.map_err(|error| anyhow!("close reader: {}", error.message()))?;
    let selected = frame.members.as_ref().map(|members| members.collection);
    let create = |name: &str| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
    };
    create("terminal.txt")?.write_all(render_terminal(&frame).as_bytes())?;
    let mut manifest = String::new();
    let captured = capture_frame(frame, selected, |image| {
        let name = image.filename();
        create(&name)?.write_all(&image.bytes)?;
        manifest.push_str(&format!(
            "{name}: {}x{}, {} bytes\n",
            image.width,
            image.height,
            image.bytes.len()
        ));
        Ok(())
    });
    create("cards.txt")?.write_all(manifest.as_bytes())?;
    captured.map_err(|error| anyhow!("capture dashboard: {error}"))?;
    eprint!("{manifest}");
    Ok(())
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
    // The heading is drawn before the early return: a card that draws nothing
    // at all is a 24-pixel strip nobody can tell from a failed render.
    ui.label(
        egui::RichText::new(Section::Mesh.title())
            .strong()
            .size(19.0),
    );
    if nodes.len() < 2 {
        ui.small(match nodes.len() {
            0 => "No nodes observed: no worker telemetry is selected and no readable health \
                  report names a peer. That is no evidence, not an empty colony.",
            _ => "One node observed and no peer named, so there is no mesh to draw. A peer \
                  nobody reported is not a peer that is absent.",
        });
        ui.separator();
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

/// The collection lattice, one family at a time, and the panel you can walk.
///
/// A family is a root and everything derived from it. The whole store is not
/// one picture: on sky's pile it is 128 collections, nearly all of them
/// unrelated roots and the indexes attached to them, and laid out together
/// they were one rank of overlapping labels. The order this panel exists to
/// show -- what derives from what -- only runs WITHIN a family, so a family is
/// the population (JP's design, 2026-09-21: "one collection family at a
/// time"). The picker names the families; the graph draws the chosen one.
///
/// Attached collections are not drawn here. They have no lattice of their
/// own; they stand over the member lattice in depth, and the attached
/// collections card is where they are listed and chosen.
fn render_lattice(ui: &mut egui::Ui, frame: &Frame, selected: &mut Option<[u8; 32]>) {
    use GORBIE::widgets::{
        LatticeAdmission, LatticeEdge, LatticeGraph, LatticeMark, LatticeNode, LatticePresence,
    };

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

    let position = |handle: [u8; 32]| collections.iter().position(|c| c.handle == handle);
    let families = families(collections);
    let chosen = *selected;
    let family = chosen.and_then(position).map(|index| families[index]);

    // The picker. A family is named by its root; the count beside it is what
    // choosing it will draw, so a reader can find the ones with a derivation.
    let roots: Vec<usize> = (0..collections.len())
        .filter(|index| families[*index] == *index)
        .collect();
    let size = |root: usize| {
        (0..collections.len())
            .filter(|index| families[*index] == root)
            .filter(|index| collections[*index].kind != CollectionKind::Attached)
            .count()
    };
    let attached_in = |root: usize| {
        (0..collections.len())
            .filter(|index| families[*index] == root)
            .filter(|index| collections[*index].kind == CollectionKind::Attached)
            .count()
    };
    let family_text = |root: usize| {
        let derived = size(root) - 1;
        let attached = attached_in(root);
        let mut text = collections[root].label();
        match (derived, attached) {
            (0, 0) => {}
            (0, a) => text.push_str(&format!(" · {a} attached")),
            (d, 0) => text.push_str(&format!(" · {d} derived")),
            (d, a) => text.push_str(&format!(" · {d} derived, {a} attached")),
        }
        text
    };
    let mut pick = family;
    egui::ComboBox::from_id_salt("colony-family")
        .width(ui.available_width().min(420.0))
        .selected_text(match family {
            Some(root) => family_text(root),
            None => "Choose a collection family".to_owned(),
        })
        .show_ui(ui, |ui| {
            for root in &roots {
                ui.selectable_value(&mut pick, Some(*root), family_text(*root));
            }
        });
    if pick != family {
        // Choosing a family selects its root; a click in the graph then
        // walks down to a derivation.
        *selected = pick.map(|root| collections[root].handle);
    }

    let count = |kind| collections.iter().filter(|c| c.kind == kind).count();
    let absent = collections
        .iter()
        .filter(|c| !c.descriptor_resident)
        .count();
    let unadmitted: u64 = collections.iter().map(|c| c.unadmitted).sum();
    let holding = collections.iter().filter(|c| c.unadmitted > 0).count();
    let totals = |ui: &mut egui::Ui| {
        ui.horizontal_wrapped(|ui| {
            ui.small(format!(
                "{} collections in this pile: {} root, {} derived, {} attached",
                collections.len(),
                count(CollectionKind::Root),
                count(CollectionKind::Derived),
                count(CollectionKind::Attached),
            ));
            if absent != 0 {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("{absent} with no resident descriptor"),
                );
            }
            // Deliberately its own line rather than folded into the one above.
            // Missing bytes arrive on their own once replication catches up;
            // an unadmitted signer waits on a grant somebody has to issue.
            // Folding them together would report work as weather.
            if unadmitted != 0 {
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("{unadmitted} unadmitted across {holding}"),
                );
            }
        });
    };

    let Some(root) = pick else {
        totals(ui);
        ui.small(
            "Choose a family to draw it. A family is a root and what derives from it; the \
             roots of this pile are unrelated to one another, so they are not one picture.",
        );
        ui.separator();
        return;
    };

    // The family, without its attached indexes. `drawn[i]` is the collection
    // index of graph node `i`.
    let drawn: Vec<usize> = (0..collections.len())
        .filter(|index| families[*index] == root)
        .filter(|index| collections[*index].kind != CollectionKind::Attached)
        .collect();
    let node_of = |handle: [u8; 32]| {
        drawn
            .iter()
            .position(|index| collections[*index].handle == handle)
    };

    let nodes: Vec<LatticeNode> = drawn
        .iter()
        .map(|index| {
            let collection = &collections[*index];
            LatticeNode {
                label: collection.label(),
                // A root is authored — someone named it. A derivation is
                // computed, and could in principle be rebuilt from its source.
                mark: match collection.kind {
                    CollectionKind::Root => LatticeMark::Authored,
                    _ => LatticeMark::Computed,
                },
                presence: match collection.descriptor_resident {
                    true => LatticePresence::Present,
                    false => LatticePresence::Absent,
                },
                // Deliberately not the admission channel. A collection is not
                // itself admitted or waiting; some of its MEMBERS are, and that
                // count already has a home in the text below.
                admission: LatticeAdmission::Unknown,
                // Over the foundations alone: a MERGE never replicates, so its
                // result being absent is nothing a peer will send. No COMMIT or
                // DERIVE naming it draws an empty track: absence of evidence,
                // not full residency.
                coverage: (collection.foundations() > 0).then(|| {
                    collection.foundations_resident as f32 / collection.foundations() as f32
                }),
                // A collection is named or derived, so something produced it by
                // construction.
                produced: true,
                // Not claimed: `name` is `None` both for "no name" and for "a
                // name whose bytes are missing", so neither is asserted.
                label_known: true,
            }
        })
        .collect();

    let edges: Vec<LatticeEdge> = drawn
        .iter()
        .enumerate()
        .filter_map(|(to, index)| {
            let collection = &collections[*index];
            let from = node_of(collection.source?)?;
            Some(LatticeEdge {
                from,
                to,
                // The descriptor declares the derivation; a DERIVE record is
                // what performs it. Declared but never performed draws dashed.
                endorsed: collection.derives > 0,
            })
        })
        .collect();

    // The selection is stored as a handle, not as an index: the projection is
    // re-sorted every observation, and an index would quietly come to mean a
    // different collection.
    let position_of = chosen.and_then(node_of);
    let shown = LatticeGraph::new(&nodes, &edges)
        .selected(position_of)
        .id_salt("colony-family-graph")
        .show(ui);
    if let Some(clicked) = shown.clicked {
        let handle = collections[drawn[clicked]].handle;
        // Unselecting a node keeps the family: fall back to its root.
        *selected = Some(match chosen == Some(handle) {
            true => collections[root].handle,
            false => handle,
        });
    }

    totals(ui);
    let attached_here = attached_in(root);
    ui.small(format!(
        "This family: {} drawn ({} derived){}.",
        drawn.len(),
        drawn.len() - 1,
        match attached_here {
            0 => String::new(),
            n => format!(
                ", {n} attached index{} not drawn here",
                if n == 1 { "" } else { "es" }
            ),
        }
    ));
    ui.small(
        "Left to right is derivation; sources are always to the left. Square authored, \
         circle computed. Dashed is a hole: a collection known only by name, or a \
         derivation declared and never performed. Arc: payloads resident over the \
         COMMITs and DERIVEs naming that collection, per collection, in this pile \
         alone. MERGEs never replicate, so their results are not in the arc. Attached \
         indexes have no lattice of their own: they stand over the member lattice in \
         depth, and the attached collections card chooses which.",
    );

    // Hover previews a chain; a click pins it.
    match shown
        .hovered
        .map(|node| drawn[node])
        .or(chosen.and_then(position))
    {
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
                "{} · {} commit / {} derive · {} of {} resident · {} merge / {} map stored{}",
                focus.label(),
                focus.commits,
                focus.derives,
                focus.foundations_resident,
                focus.foundations(),
                focus.merges,
                focus.maps,
                match focus.descriptor_resident {
                    true => "",
                    false => " · descriptor not resident here",
                }
            ));
            let walked = chain
                .iter()
                .map(|step| collections[*step].label())
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

/// Each collection's family: the index of the root its source chain ends at.
///
/// A chain that leaves the observation ends at the last collection it reached
/// here, which then stands as the family's root: the honest picture of what
/// this observation can place. Descriptors that loop (an open-world
/// possibility) form one family rooted at the loop's first collection in
/// display order, so every member of it is still reachable from the picker.
fn families(collections: &[LatticeCollection]) -> Vec<usize> {
    let position = |handle: [u8; 32]| collections.iter().position(|c| c.handle == handle);
    (0..collections.len())
        .map(|start| {
            let mut path = vec![start];
            let mut at = start;
            while let Some(next) = collections[at].source.and_then(position) {
                if let Some(loop_start) = path.iter().position(|seen| *seen == next) {
                    return path[loop_start..].iter().copied().min().unwrap_or(next);
                }
                path.push(next);
                at = next;
            }
            at
        })
        .collect()
}

/// The join lattice inside the selected collection.
///
/// `MERGE(C, low, high, result)` states `low ⊔ high = result`, so the two
/// edges under each join mark are the equation itself. A member with no edge
/// below it was committed or derived rather than joined; a member with none
/// above it is a maximal element — nothing has joined it into anything yet,
/// which is the merge work this collection still owes.
fn render_members(
    ui: &mut egui::Ui,
    frame: &Frame,
    chosen: Option<[u8; 32]>,
    hidden: &BTreeSet<[u8; 32]>,
) {
    use GORBIE::widgets::{
        LatticeAdmission, LatticeEdge, LatticeGraph, LatticeMark, LatticeNode, LatticeOverlay,
        LatticePresence,
    };

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
            // The absence the record scan cannot see: a COMMIT nobody is
            // allowed to write names its payload exactly as an admitted one
            // does, so without this the member waiting on a grant and the one
            // folded in drew the same mark.
            admission: match member.admission {
                Admission::Admitted => LatticeAdmission::Admitted,
                Admission::Unadmitted => LatticeAdmission::Unadmitted,
                Admission::Unknown => LatticeAdmission::Unknown,
            },
            // A commit is produced by definition — an author asserted it. For
            // the rest, this is whether a record HERE made it. False is the
            // member reached only as an input of a waiting join, which until
            // now was a count printed beside a mark that looked exactly like a
            // fully-produced one.
            produced: member.committed || member.produced,
            label_known: true,
        })
        .collect();
    // Every edge here comes from one of the host's MERGEs; another key's
    // draws nothing. A driven join is solid. A join still waiting for an
    // input's support is dashed: declared, and not performed, since no reader
    // descends it until every input has a support -- the same meaning a
    // dashed edge has in the collection lattice. Absence of a join is a
    // member with nothing above it, not a dashed edge.
    let edges: Vec<LatticeEdge> = members
        .joins
        .iter()
        .map(|(from, to)| (from, to, true))
        .chain(members.waiting.iter().map(|(from, to)| (from, to, false)))
        .map(|(from, to, endorsed)| LatticeEdge {
            from: *from,
            to: *to,
            endorsed,
        })
        .collect();

    // A waiting join has consumed nothing: its inputs are still on the
    // frontier, so only driven edges make a member joined.
    let maximal = (0..nodes.len())
        .filter(|node| !members.joins.iter().any(|(from, _)| from == node))
        .count();
    // Each visible attached collection is one layer, stacked in tree order.
    // Its depth on screen is its place in that stack, not its depth in the
    // tree, so two collections attached side by side do not draw on top of
    // one another; the tree card says which is attached to which.
    let shown = visible_layers(&members.attached, hidden);
    let nodes_ref = &nodes;
    let overlays: Vec<LatticeOverlay> = shown
        .iter()
        .enumerate()
        .flat_map(|(slot, layer)| {
            let depth = u8::try_from(slot + 1).unwrap_or(u8::MAX);
            layer.marks.iter().map(move |mark| LatticeOverlay {
                anchor: mark.anchor,
                depth,
                presence: match mark.resident {
                    true => LatticePresence::Present,
                    false => LatticePresence::Absent,
                },
                // A MAP needs no grant: the host's own is believed as it
                // stands. What can still be waiting is the node it indexes,
                // so the attachment says what its anchor says.
                admission: nodes_ref[mark.anchor].admission,
            })
        })
        .collect();
    let drawn = LatticeGraph::new(&nodes, &edges).overlays(&overlays).show(ui);
    ui.horizontal_wrapped(|ui| {
        ui.small(format!(
            "{} members · {} join edges · {maximal} not yet joined into anything",
            nodes.len(),
            members.joins.len()
        ));
        if !members.waiting.is_empty() {
            ui.small(format!(
                "· {} dashed edges of joins still waiting for an input's support",
                members.waiting.len()
            ));
        }
        if !shown.is_empty() {
            ui.small(format!(
                "· {} attachments in depth from {} attached collection{}",
                drawn.overlaid,
                shown.len(),
                if shown.len() == 1 { "" } else { "s" }
            ));
        }
        // The clauses are separate labels so the row can wrap between them,
        // which means each one carries its own separator: without it they run
        // together into one unreadable sentence at any width that fits them
        // both on a line.
        if members.unproduced != 0 {
            ui.small(format!(
                "· {} reached only as a waiting join's input — each one drawn with \
                 a gap at the bottom of its mark, so you can point at them",
                members.unproduced
            ));
        }
        // The one absence here with a named owner: a grant somebody has to
        // issue. Said in the summary as well as drawn, because it is the line
        // that tells a reader the picture is waiting on a person rather than
        // on the network.
        let waiting = members
            .members
            .iter()
            .filter(|member| matches!(member.admission, Admission::Unadmitted))
            .count();
        if waiting != 0 {
            ui.small(format!(
                "· {waiting} waiting on a capability grant — drawn as outlines, \
                 and they stay put until somebody issues one"
            ));
        }
    });
    ui.small(
        "Inside the selection: square is a commit, circle a join result or mapping \
         output, a circle with a gap at the bottom a member nothing here produced — \
         it was reached only as a waiting join's input and the record that made it is \
         elsewhere. A solid mark is vouched for, an outline is a member here that no \
         capability proof admits yet, and dashed is a member whose bytes are not here \
         at all. Each join's edges are the inputs of one of this host's MERGEs: solid \
         when every input has a support and a reader descends it, dashed while one \
         still waits. Another key's MERGEs are not believed and are not drawn. \
         Up and to the right of a member, one step per layer, stand the attachments \
         the attached collections ticked in the dependency card give it: one small \
         circle per MAP of this host's, dashed when its bytes are not here. A member \
         with nothing above it has no attachment; none is invented for it.",
    );
}

const ATTACHED_TITLE: &str = "Attached collections";

/// The layers to draw: every attached collection not hidden and with no
/// hidden ancestor. An attachment of a hidden layer indexes nodes the reader
/// has put away, so drawing it would float a stack with nothing under it.
fn visible_layers<'a>(
    layers: &'a [AttachedLayer],
    hidden: &BTreeSet<[u8; 32]>,
) -> Vec<&'a AttachedLayer> {
    let mut off: BTreeSet<[u8; 32]> = hidden.clone();
    // Layers arrive shallowest first, so one pass carries hiding downward.
    for layer in layers {
        if off.contains(&layer.parent) {
            off.insert(layer.collection);
        }
    }
    layers
        .iter()
        .filter(|layer| !off.contains(&layer.collection))
        .collect()
}

/// The dependency tree under the selection, and the switch for each layer.
///
/// The collection lattice says which collection is attached to which; this
/// card says it for the selection alone, as a tree, and decides which of those
/// the member card overlays. Every attached collection the descriptors place
/// here is listed, including one nothing has mapped yet, because "attached
/// and never maintained" is a fact worth seeing and an empty overlay cannot
/// show it.
fn render_attached_tree(
    ui: &mut egui::Ui,
    frame: &Frame,
    chosen: Option<[u8; 32]>,
    hidden: &mut BTreeSet<[u8; 32]>,
) {
    ui.label(egui::RichText::new(ATTACHED_TITLE).strong().size(19.0));
    let Some(chosen) = chosen else {
        ui.small("Select a collection in the lattice to see what is attached to it.");
        return;
    };
    let Some(members) = frame.members.as_ref().filter(|m| m.collection == chosen) else {
        ui.small("Reading the selected collection's attachments...");
        return;
    };
    if members.too_large.is_some() {
        ui.small("The member lattice is too large to draw, so nothing is overlaid on it.");
        return;
    }
    if members.attached.is_empty() {
        ui.small("Nothing is attached to this collection.");
        return;
    }
    let name = |handle: [u8; 32]| {
        frame
            .lattice
            .as_ref()
            .and_then(|lattice| lattice.iter().find(|c| c.handle == handle))
            .map(|c| c.label())
            .unwrap_or_else(|| short(&handle))
    };
    let shown: BTreeSet<[u8; 32]> = visible_layers(&members.attached, hidden)
        .iter()
        .map(|layer| layer.collection)
        .collect();
    ui.small(name(chosen));
    // Depth-first in descriptor order, so a child sits under its parent.
    fn walk(
        layers: &[AttachedLayer],
        parent: [u8; 32],
        out: &mut Vec<usize>,
    ) {
        for (index, layer) in layers.iter().enumerate() {
            if layer.parent == parent {
                out.push(index);
                walk(layers, layer.collection, out);
            }
        }
    }
    let mut order = Vec::new();
    walk(&members.attached, chosen, &mut order);
    for index in order {
        let layer = &members.attached[index];
        ui.horizontal_wrapped(|ui| {
            ui.add_space(16.0 * layer.depth as f32);
            let mut on = !hidden.contains(&layer.collection);
            let ancestor_off = on && !shown.contains(&layer.collection);
            if ui.checkbox(&mut on, name(layer.collection)).changed() {
                match on {
                    true => hidden.remove(&layer.collection),
                    false => hidden.insert(layer.collection),
                };
            }
            let resident = layer.marks.iter().filter(|mark| mark.resident).count();
            ui.small(match layer.marks.len() {
                0 => "nothing mapped yet".to_owned(),
                mapped => format!("{mapped} mapped · {resident} resident"),
            });
            if layer.unanchored != 0 {
                ui.small(format!("· {} over nodes this lattice does not reach", layer.unanchored));
            }
            if layer.foreign != 0 {
                ui.small(format!("· {} by another key, not believed", layer.foreign));
            }
            if ancestor_off {
                ui.small("· hidden with its parent");
            }
        });
    }
    ui.small(
        "Ticked layers stand over the member lattice in depth. Only the host's MAPs \
         over a node drawn there are overlaid; the rest are counted here and drawn \
         nowhere.",
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
        ui.label(
            egui::RichText::new(Section::Nodes.title())
                .strong()
                .size(19.0),
        );
        if frame.nodes().is_empty() {
            ui.small(
                "No node reported here: no selected worker telemetry, and no readable \
                 health report. Missing is not idle.",
            );
        }
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
