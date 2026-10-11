//! Span-based profiling that persists `tracing` spans into a TribleSpace
//! collection.
//!
//! # The destination is never inferred
//!
//! [`Telemetry::layer_from_env`] writes only to the pile named by
//! `TELEMETRY_PILE`. It used to fall back to `PILE` when that was unset, and
//! that fallback is gone: `PILE` is the variable an application points at its
//! *own* store, so the fallback aimed a per-span firehose at whatever durable
//! file the process happened to be working with. A pile is append-only, so
//! nothing written there can ever be removed, and a replicated pile carries
//! the exhaust to every machine that holds a copy. A telemetry sink that
//! silently picks a destination the caller did not name is worse than no
//! telemetry, so an unset `TELEMETRY_PILE` now disables telemetry outright.
//!
//! # Why this writes to a `Pile`, and what would have to change
//!
//! Telemetry is exhaust: high volume, and worth less the older it gets. A
//! [`Pile`] can only grow, so it is the wrong *kind* of store for it, and
//! [`Yard`](crate::core::repo::yard::Yard) — generational piles whose
//! retention and compaction evict blobs without breaking Pile's append-only
//! contract — is the right kind. Retargeting at one today would nonetheless
//! reclaim **nothing**: [`Yard::collect`](crate::core::repo::yard::Yard::collect)
//! conservatively treats every signature-valid collection commit as a
//! *recursive retention root*, and every span this layer writes is such a
//! commit, so the whole firehose stays live. A yard mode that cannot reclaim
//! would look like a fix and be none, which is worse than not having one.
//!
//! Yard becomes the right destination once retention is an operator-supplied
//! policy whose semantics can actually retire old telemetry commits. That is
//! a policy decision — how long spans live, what triggers `collect`/`reclaim`
//! — and not a default this module should invent: a sink that silently
//! discards diagnostics is the same class of bug as one that silently picks a
//! destination. Finding and framing are Sol's (`liora-gpt`, 2026-08-27), who
//! owns this retention model; ask there before building on this note. Until
//! then an explicitly named `TELEMETRY_PILE` is the working destination.
//!
//! # Timestamps are process-local
//!
//! [`schema::begin_ns`], [`schema::end_ns`] and [`schema::duration_ns`] count
//! nanoseconds from an [`Instant`] captured when the sink starts. Durations are
//! meaningful; the begin/end instants are comparable only *within* one process,
//! and never across processes or runs.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::core::blob::encodings::simplearchive::SimpleArchive;
use crate::core::collection::{AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt};
use crate::core::metadata;
use crate::core::repo::pile::{Pile, ReadError};
use crate::prelude::blobencodings::UTF8String;
use crate::prelude::inlineencodings::{GenId, Handle, U256BE};
use crate::prelude::*;
use ed25519_dalek::SigningKey;
use rand_core06::OsRng;
use thread_local::ThreadLocal;
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

const ENV_TELEMETRY_PILE: &str = "TELEMETRY_PILE";
const ENV_TELEMETRY_COLLECTION_NAME: &str = "TELEMETRY_COLLECTION_NAME";
const ENV_TELEMETRY_FLUSH_MS: &str = "TELEMETRY_FLUSH_MS";

pub mod schema {
    use super::*;

    attributes! {
        "3E062AA7E3554C8F2DB94883CE639BFE" unsafe as pub session: GenId;
        "146E5AA2F7CB3D8B654BC7742A13CAB3" unsafe as pub parent: GenId;
        "CCB0147D20C4C6FCAC0E3D87FAFF71D1" unsafe as pub name: Handle<UTF8String>;
        "8A4BE2C4D0E90D2B9EE0E1A07ECA2CFA" as pub category: Handle<UTF8String>;
        "E11A84A30CC112650DC860B66B8BD8A9" unsafe as pub begin_ns: U256BE;
        "2786FA563372FB6EF469EC7710719A49" unsafe as pub end_ns: U256BE;
        "7593602383D0B0D21BBE382A67E5BD9F" unsafe as pub duration_ns: U256BE;
        "7E96DD9A0B5002796B645ED25F5E99AC" unsafe as pub source: Handle<UTF8String>;
        /// Links a span to one captured tracing field.
        ///
        /// Repeated: a span carries one of these per field it recorded, at
        /// creation or later. Field entities are intrinsic, so the same
        /// name/value pair recorded by a thousand spans is one entity a
        /// thousand spans point at.
        "CB99FD67D62C020DDE788F6281393131" as pub field: GenId;
        /// The tracing field's name, as written at the callsite.
        ///
        /// This is the key a consumer queries by. `pattern!` compares it
        /// against a plain string through the text's content handle, so names
        /// of any length are captured.
        "097951EF7FC4C64A4AE9ADBD9ED89482" as pub field_name: Handle<UTF8String>;
        /// The field's value, rendered as text.
        ///
        /// Text because the layer cannot know a consumer's encodings, and a
        /// wrong encoding is worse than an honest rendering. A consumer that
        /// needs typed facts writes its own tribles and joins them to the span
        /// through [`super::current_span_entity`].
        "14EC66BA540E0625F67DE25C9F15AAA8" as pub field_value: Handle<UTF8String>;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_session: Id = crate::macros::id_hex!("2701F7019B865D461F0169B1303026D6");
    #[allow(non_upper_case_globals)]
    pub const kind_span: Id = crate::macros::id_hex!("0AF9FEB9A2BFEB1BE8A8229829181085");
    #[allow(non_upper_case_globals)]
    pub const kind_field: Id = crate::macros::id_hex!("78ED1365CC69B4DCA54BC7EBA8444D30");

    #[allow(non_upper_case_globals)]
    pub const telemetry_metadata: Id = crate::macros::id_hex!("BCFDE38F7E452924C72803239392EA05");

    /// Build the telemetry-protocol metadata fragment.
    ///
    /// After the Fragment-self-contained refactor, `describe` is no longer
    /// fallible and doesn't take a blob store — each entity!{} auto-puts
    /// long-form bytes (descriptions, names) into the fragment's own
    /// MemoryBlobStore. The returned Fragment is self-contained.
    pub fn build_telemetry_metadata() -> Fragment {
        let attrs = describe();

        let mut protocol = entity! { ExclusiveId::force_ref(&telemetry_metadata) @
            metadata::name: "triblespace_telemetry",
            metadata::description:
                "Span-based profiling events emitted by TribleSpace telemetry.",
            metadata::tag: metadata::KIND_PROTOCOL,
            metadata::attribute*: attrs,
        };

        protocol += entity! { ExclusiveId::force_ref(&kind_session) @
            metadata::name: "telemetry_session",
            metadata::description:
                "A profiling session. Groups spans emitted during one telemetry run.",
            metadata::tag: metadata::KIND_TAG,
        };
        protocol += entity! { ExclusiveId::force_ref(&kind_span) @
            metadata::name: "telemetry_span",
            metadata::description:
                "A begin/end span with optional parent links.",
            metadata::tag: metadata::KIND_TAG,
        };
        protocol += entity! { ExclusiveId::force_ref(&kind_field) @
            metadata::name: "telemetry_field",
            metadata::description:
                "One tracing field captured from a span: its name, and its value rendered \
                 as text. Identity is the name/value pair, so spans sharing a field share \
                 its entity.",
            metadata::tag: metadata::KIND_TAG,
        };

        protocol
    }
}

struct ThreadTelemetry {
    batch: Fragment,
    last_flush: Instant,
}

struct TelemetryInner {
    destination: Mutex<Option<TelemetryDestination>>,
    batches: ThreadLocal<Arc<Mutex<ThreadTelemetry>>>,
    registry: Mutex<Vec<Arc<Mutex<ThreadTelemetry>>>>,
    session: Id,
    base: Instant,
    flush_interval: Duration,
    shutdown: AtomicBool,
}

struct TelemetryDestination {
    pile: Pile,
    collection: Collection<SimpleArchive>,
    signing_key: SigningKey,
}

impl TelemetryDestination {
    fn commit(&mut self, fragment: Fragment) -> Result<(), String> {
        self.pile
            .commit(self.collection, &self.signing_key, fragment)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }

    fn flush(&mut self) -> Result<(), String> {
        self.pile.flush().map_err(|error| format!("{error:?}"))
    }

    fn close(self) -> Result<(), String> {
        self.pile.close().map_err(|error| format!("{error:?}"))
    }
}

fn self_describing(mut batch: Fragment) -> Fragment {
    batch.describe_with(schema::build_telemetry_metadata());
    batch
}

fn pile_refresh_diagnostic(path: &Path, error: &ReadError) -> String {
    let failure = format!(
        "telemetry pile {} failed to load ({error}); telemetry disabled.",
        path.display()
    );

    match error {
        ReadError::UnsupportedRecord { .. } => format!(
            "{failure} This is likely format/version skew; upgrade to a reader that recognizes \
             the record marker. The pile was left unchanged."
        ),
        ReadError::CorruptPile { .. } => format!(
            "{failure} A malformed or incomplete known record does not prove that the remaining \
             suffix is a disposable torn write. The pile was left unchanged; inspect it with \
             current pile diagnostics before choosing recovery."
        ),
        _ => format!("{failure} The pile was left unchanged."),
    }
}

/// Publish a clone of the pending batch and clear the retained in-memory copy
/// only after the caller's complete publication policy succeeds. A partial
/// backend failure can therefore be retried with the exact same
/// content-addressed commit.
fn publish_pending<E>(
    state: &mut ThreadTelemetry,
    publish: impl FnOnce(Fragment) -> Result<(), E>,
) -> Result<bool, E> {
    if state.batch.facts().is_empty() {
        return Ok(false);
    }

    publish(self_describing(state.batch.clone()))?;
    state.batch = Fragment::empty();
    Ok(true)
}

impl TelemetryInner {
    fn now_ns(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }

    fn get_or_init_thread(&self) -> &Arc<Mutex<ThreadTelemetry>> {
        self.batches.get_or(|| {
            let arc = Arc::new(Mutex::new(ThreadTelemetry {
                batch: Fragment::empty(),
                last_flush: Instant::now(),
            }));
            self.registry
                .lock()
                .expect("telemetry registry lock")
                .push(arc.clone());
            arc
        })
    }

    fn maybe_flush(&self, state: &mut ThreadTelemetry) {
        if state.last_flush.elapsed() < self.flush_interval {
            return;
        }

        if state.batch.facts().is_empty() {
            state.last_flush = Instant::now();
            return;
        }

        let mut destination_guard = self.destination.lock().expect("telemetry destination lock");
        if let Some(destination) = destination_guard.as_mut() {
            if let Err(e) = publish_pending(state, |batch| {
                destination.commit(batch)?;
                destination.flush()
            }) {
                log::warn!("telemetry flush failed: {e:?}");
                return;
            }
        }
        state.last_flush = Instant::now();
    }
}

#[derive(Debug, Clone, Copy)]
struct TelemetrySpanData {
    span: Id,
    start_ns: u64,
}

/// Render a `Debug` value the way a reader expects to see it: a string field
/// debug-formats to `"quoted"`, and the quotes are formatting, not content.
fn unquoted_debug(value: &dyn std::fmt::Debug) -> String {
    let raw = format!("{value:?}");
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw
    }
}

/// Every field a span records, plus `source` promoted to its own attribute.
///
/// `source` is promoted only when it arrives with the span's creation, which
/// is the only thing [`schema::source`] has ever meant. A `source` recorded
/// later is an ordinary captured field, so no span ever grows a second value
/// under an attribute that existing consumers read as single-valued.
#[derive(Default)]
struct FieldCapture {
    source: Option<String>,
    fields: Vec<(&'static str, String)>,
}

impl FieldCapture {
    fn capture(&mut self, field: &tracing::field::Field, value: String) {
        if value.is_empty() {
            return;
        }
        let name = field.name();
        if name == "source" && self.source.is_none() {
            self.source = Some(value.clone());
        }
        self.fields.push((name, value));
    }
}

impl tracing::field::Visit for FieldCapture {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.capture(field, value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.capture(field, unquoted_debug(value));
    }
}

thread_local! {
    /// Telemetry entities for the spans entered on this thread, innermost last.
    ///
    /// The layer keeps this in step with `on_enter`/`on_exit` because the
    /// entity id lives in the span's registry extensions, which an ordinary
    /// caller has no handle on — it would need the concrete subscriber type to
    /// look one up. Mirroring the enter/exit stack instead answers the only
    /// question a caller inside a span actually asks, for any subscriber.
    /// A slot is `None` for a span this layer did not record.
    static ENTERED_SPANS: RefCell<Vec<Option<Id>>> = const { RefCell::new(Vec::new()) };
}

/// The telemetry entity of the innermost telemetry span entered on this
/// thread, or `None` when none is.
///
/// This is what makes a consumer's own records *joinable* to the layer's
/// spans rather than merely correlated with them by a string: write this id
/// into your own tribles and "this span" and "this turn" are the same entity
/// in a query.
///
/// ```rust,ignore
/// let span = tracing::info_span!(target: "drive", "turn");
/// let _entered = span.enter();
/// if let Some(span_entity) = triblespace::telemetry::current_span_entity() {
///     facts += entity! { turn @ my::span: span_entity };
/// }
/// ```
///
/// The value is thread-local and scope-bound, exactly like
/// [`tracing::Span::current`]: call it inside the span, on the thread that
/// entered it. It reports the innermost *recorded* span, so a span the layer
/// skipped does not hide the telemetry span enclosing it.
pub fn current_span_entity() -> Option<Id> {
    ENTERED_SPANS.with(|entered| entered.borrow().iter().rev().find_map(|recorded| *recorded))
}

/// Tracing layer that turns spans into TribleSpace telemetry.
///
/// Construct via [`Telemetry::layer_from_env`] and attach to your application's subscriber.
pub struct TelemetryLayer {
    inner: Arc<TelemetryInner>,
}

impl TelemetryLayer {
    fn parent_id<S>(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        ctx: &Context<'_, S>,
    ) -> Option<Id>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        if let Some(parent) = attrs.parent() {
            if let Some(span) = ctx.span(parent) {
                if let Some(data) = span.extensions().get::<TelemetrySpanData>() {
                    return Some(data.span);
                }
            }
        }

        if let Some(id) = ctx.current_span().id() {
            if let Some(span) = ctx.span(id) {
                if let Some(data) = span.extensions().get::<TelemetrySpanData>() {
                    return Some(data.span);
                }
            }
        }

        None
    }
}

impl<S> Layer<S> for TelemetryLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if self.inner.shutdown.load(Ordering::Relaxed) {
            return;
        }

        let Some(span) = ctx.span(id) else {
            return;
        };

        let meta = attrs.metadata();
        let mut fields = FieldCapture::default();
        attrs.record(&mut fields);

        let start_ns = self.inner.now_ns();
        let span_id = *genid();
        let parent = self.parent_id(attrs, &ctx);

        span.extensions_mut().insert(TelemetrySpanData {
            span: span_id,
            start_ns,
        });

        let thread_state = self.inner.get_or_init_thread();
        let mut state = thread_state.lock().expect("telemetry thread state lock");

        let target = meta.target();
        let category = target.split("::").next().unwrap_or(target);

        span_begin(
            &mut state.batch,
            self.inner.session,
            span_id,
            parent,
            start_ns,
            category,
            meta.name(),
            fields.source,
        );
        span_fields(&mut state.batch, span_id, &fields.fields);
    }

    /// Persist fields recorded after the span opened.
    ///
    /// Without this, a fact the caller only learns mid-span is lost, which
    /// rules out every consumer whose facts are not all known at creation.
    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        if self.inner.shutdown.load(Ordering::Relaxed) {
            return;
        }

        let Some(span) = ctx.span(id) else {
            return;
        };
        let Some(data) = span.extensions().get::<TelemetrySpanData>().copied() else {
            return;
        };

        let mut fields = FieldCapture::default();
        values.record(&mut fields);
        if fields.fields.is_empty() {
            return;
        }

        let thread_state = self.inner.get_or_init_thread();
        let mut state = thread_state.lock().expect("telemetry thread state lock");
        span_fields(&mut state.batch, data.span, &fields.fields);
    }

    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        // Pushed unconditionally, including as `None`, so that `on_exit` pops
        // this thread's own frame no matter what the layer knows about the
        // span — an unbalanced stack would misattribute every later span.
        let recorded = ctx
            .span(id)
            .and_then(|span| span.extensions().get::<TelemetrySpanData>().map(|d| d.span));
        ENTERED_SPANS.with(|entered| entered.borrow_mut().push(recorded));
    }

    fn on_exit(&self, _id: &tracing::span::Id, _ctx: Context<'_, S>) {
        ENTERED_SPANS.with(|entered| {
            entered.borrow_mut().pop();
        });
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        if self.inner.shutdown.load(Ordering::Relaxed) {
            return;
        }

        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(data) = span.extensions().get::<TelemetrySpanData>().copied() else {
            return;
        };

        let end_ns = self.inner.now_ns();

        let thread_state = self.inner.get_or_init_thread();
        let mut state = thread_state.lock().expect("telemetry thread state lock");

        span_end(
            &mut state.batch,
            data.span,
            end_ns,
            end_ns.saturating_sub(data.start_ns),
        );

        self.inner.maybe_flush(&mut state);
    }
}

pub struct Telemetry {
    inner: Arc<TelemetryInner>,
}

impl Telemetry {
    /// Start a telemetry sink and return a layer that writes spans into it.
    ///
    /// This does **not** install a tracing subscriber. Embed the returned layer into your
    /// application's subscriber, and keep the returned [`Telemetry`] guard alive to
    /// flush and close the sink on shutdown.
    ///
    /// The destination is `TELEMETRY_PILE` and nothing else. When it is unset
    /// or empty this returns `None`, and it does **not** fall back to `PILE`:
    /// see the [module documentation](self) for why a telemetry sink must
    /// never infer a durable destination the caller did not name.
    pub fn layer_from_env(session_name: &str) -> Option<(TelemetryLayer, Self)> {
        let pile_path = std::env::var(ENV_TELEMETRY_PILE).unwrap_or_default();
        let pile_path = pile_path.trim();
        if pile_path.is_empty() {
            // Silence is right when nothing asked for telemetry, and wrong once
            // something did: a caller that named a collection has stated its
            // intent, and the missing destination is then a misconfiguration
            // rather than an absence.
            if std::env::var_os(ENV_TELEMETRY_COLLECTION_NAME).is_some() {
                log::warn!(
                    "{ENV_TELEMETRY_COLLECTION_NAME} is set but {ENV_TELEMETRY_PILE} is not; \
                     telemetry is disabled. The destination is never inferred — this no longer \
                     falls back to PILE, which names an application's own append-only store."
                );
            }
            return None;
        }
        let pile_path = PathBuf::from(pile_path);

        let collection_name = std::env::var(ENV_TELEMETRY_COLLECTION_NAME).ok()?;
        let collection_name = collection_name.trim();
        if collection_name.is_empty() {
            log::warn!("TELEMETRY_COLLECTION_NAME is empty; telemetry is disabled");
            return None;
        }

        let flush_ms = std::env::var(ENV_TELEMETRY_FLUSH_MS)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(250);
        let flush_interval = Duration::from_millis(flush_ms.max(10));

        let base = Instant::now();
        let session_id = *genid();

        // Open the pile with the non-mutating refresh. Any read failure
        // disables telemetry without changing the pile; the error alone does
        // not establish that any suffix is safe to discard.
        if let Some(parent) = pile_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).ok()?;
        }
        let mut pile = Pile::open(&pile_path).ok()?;
        if let Err(err) = pile.refresh() {
            log::warn!("{}", pile_refresh_diagnostic(&pile_path, &err));
            let _ = pile.close();
            return None;
        }

        // The sink generates its own signing key per session. Both collection
        // actions use that key as their one-root direct admission policy.
        let signing_key = SigningKey::generate(&mut OsRng);
        let root = signing_key.verifying_key();
        let collection = match pile.collection(
            collection_name,
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root)),
        ) {
            Ok(collection) => collection,
            Err(error) => {
                log::warn!("telemetry descriptor registration failed: {error:?}");
                let _ = pile.close();
                return None;
            }
        };
        let mut destination = TelemetryDestination {
            pile,
            collection,
            signing_key,
        };

        // Commit session start entity.
        let session_entity = ExclusiveId::force_ref(&session_id);
        let mut init = Fragment::empty();
        let session_name = init.put(session_name.to_string());
        init += entity! { session_entity @
            metadata::tag: schema::kind_session,
            schema::category: "session",
            schema::name: session_name,
            schema::begin_ns: 0u64,
        };
        if destination.commit(self_describing(init)).is_err() || destination.flush().is_err() {
            let _ = destination.close();
            return None;
        }

        let inner = Arc::new(TelemetryInner {
            destination: Mutex::new(Some(destination)),
            batches: ThreadLocal::new(),
            registry: Mutex::new(Vec::new()),
            session: session_id,
            base,
            flush_interval,
            shutdown: AtomicBool::new(false),
        });

        let layer = TelemetryLayer {
            inner: inner.clone(),
        };

        Some((layer, Self { inner }))
    }

    /// Convenience for standalone processes: start telemetry and install a global subscriber
    /// (only if none exists).
    pub fn install_global_from_env(session_name: &str) -> Option<Self> {
        let (layer, guard) = Self::layer_from_env(session_name)?;

        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry().with(filter).with(layer);

        if tracing::subscriber::set_global_default(subscriber).is_err() {
            log::warn!("triblespace telemetry disabled: tracing subscriber already set");
            drop(guard);
            return None;
        }

        Some(guard)
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);

        // Flush all thread-local batches. Each flush takes the locks in the
        // same state-then-collection order as the tracing callbacks.
        let registry = self.inner.registry.lock().expect("telemetry registry lock");
        for state_arc in registry.iter() {
            let mut state = state_arc.lock().expect("telemetry thread state lock");
            let mut destination_guard = self
                .inner
                .destination
                .lock()
                .expect("telemetry destination lock");
            if let Some(destination) = destination_guard.as_mut() {
                if let Err(e) = publish_pending(&mut state, |batch| {
                    destination.commit(batch)?;
                    destination.flush()
                }) {
                    log::warn!("telemetry shutdown flush failed: {e:?}");
                }
            }
        }
        drop(registry);

        // Commit the terminal session facts and close the pile.
        let end_ns = self.inner.now_ns();
        let session_entity = ExclusiveId::force_ref(&self.inner.session);
        let mut end = Fragment::empty();
        end += entity! { session_entity @
            schema::end_ns: end_ns,
            schema::duration_ns: end_ns,
        };

        let mut destination_guard = self
            .inner
            .destination
            .lock()
            .expect("telemetry destination lock");
        if let Some(mut destination) = destination_guard.take() {
            if let Err(e) = destination.commit(self_describing(end)) {
                log::warn!("telemetry session end commit failed: {e:?}");
            }
            if let Err(e) = destination.close() {
                log::warn!("telemetry pile close failed: {e:?}");
            }
        }
    }
}

fn span_begin(
    batch: &mut Fragment,
    session: Id,
    span_id: Id,
    parent: Option<Id>,
    at_ns: u64,
    category: &str,
    name: &str,
    source: Option<String>,
) {
    let span_entity = ExclusiveId::force_ref(&span_id);
    let name = batch.put(name.to_string());
    let source = source.map(|source| batch.put(source));
    *batch += entity! { span_entity @
        metadata::tag: schema::kind_span,
        schema::session: session,
        schema::category: category,
        schema::name: name,
        schema::begin_ns: at_ns,
    };
    if let Some(parent) = parent {
        *batch += entity! { span_entity @ schema::parent: parent };
    }
    if let Some(source) = source {
        *batch += entity! { span_entity @ schema::source: source };
    }
}

/// Attach captured fields to a span.
///
/// Called both at span creation and from `on_record`, because a fact learned
/// later is the same kind of fact. Field entities are intrinsic, so recording
/// the same name and value twice is idempotent. Recording the same *name* with
/// two different values leaves both, and the layer records no ordering between
/// them: facts accumulate, they do not overwrite.
fn span_fields(batch: &mut Fragment, span_id: Id, fields: &[(&'static str, String)]) {
    if fields.is_empty() {
        return;
    }

    let span_entity = ExclusiveId::force_ref(&span_id);
    for (name, value) in fields {
        let field = entity! { _ @
            metadata::tag: schema::kind_field,
            schema::field_name: *name,
            schema::field_value: value.clone(),
        };
        let Some(field_id) = field.root() else {
            continue;
        };
        *batch += field;
        *batch += entity! { span_entity @ schema::field: field_id };
    }
}

fn span_end(batch: &mut Fragment, span_id: Id, at_ns: u64, duration_ns: u64) {
    let span_entity = ExclusiveId::force_ref(&span_id);
    *batch += entity! { span_entity @
        schema::end_ns: at_ns,
        schema::duration_ns: duration_ns,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::blob::encodings::UnknownBlob;
    use crate::core::blob::encodings::simplearchive::SimpleArchive;
    use crate::core::collection::CollectionRead;
    use crate::core::repo::SnapshotSource;

    static TELEMETRY_ENV: Mutex<()> = Mutex::new(());

    /// Every fact the pile holds, read back through a fresh `Pile` with no
    /// state carried over from the writing process.
    ///
    /// The sink signs with a per-session key it never exposes, so this reads
    /// the committed archives directly rather than through a `Collection`
    /// facade. Blobs that are not archives simply fail to decode.
    fn cold_read_facts(path: &Path) -> TribleSet {
        let mut pile = Pile::open(path).expect("reopen the telemetry pile");
        pile.refresh().expect("refresh the reopened pile");
        let snapshot = pile.snapshot().expect("read the reopened pile");

        let handles: Vec<_> = snapshot
            .blobs()
            .map(|info| info.expect("list a blob").handle)
            .collect();
        let mut facts = TribleSet::new();
        for handle in handles {
            let Ok(blob) = snapshot.get::<Blob<UnknownBlob>, UnknownBlob>(handle) else {
                continue;
            };
            if let Ok(archived) = blob
                .transmute::<SimpleArchive>()
                .try_from_blob::<TribleSet>()
            {
                facts += archived;
            }
        }

        drop(snapshot);
        pile.close().expect("close the reopened pile");
        facts
    }

    #[test]
    fn layer_from_env_uses_a_direct_process_local_collection() {
        let _env = TELEMETRY_ENV.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.pile");
        std::fs::File::create(&path).unwrap();
        std::env::set_var(ENV_TELEMETRY_PILE, &path);
        std::env::set_var(ENV_TELEMETRY_COLLECTION_NAME, "telemetry-test");

        let (layer, telemetry) =
            Telemetry::layer_from_env("test session").expect("telemetry starts");
        std::env::remove_var(ENV_TELEMETRY_PILE);
        std::env::remove_var(ENV_TELEMETRY_COLLECTION_NAME);
        drop(layer);
        drop(telemetry);

        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        let snapshot = pile.snapshot().unwrap();
        let records = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(snapshot);
        assert_eq!(
            records.len(),
            2,
            "session start and end are the only collection records"
        );
        pile.close().unwrap();
    }

    /// THE JOIN GATE. A consumer inside a span can read the entity the layer
    /// minted for it, and a field the consumer only learns mid-span still
    /// reaches the pile — both proved against a cold reopen, because an
    /// in-memory assertion proves the API and not the persistence.
    #[test]
    fn a_span_entity_and_a_late_field_survive_a_cold_reopen() {
        let _env = TELEMETRY_ENV.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telemetry.pile");
        std::fs::File::create(&path).unwrap();
        std::env::set_var(ENV_TELEMETRY_PILE, &path);
        std::env::set_var(ENV_TELEMETRY_COLLECTION_NAME, "telemetry-join");

        let (layer, telemetry) = Telemetry::layer_from_env("join gate").expect("telemetry starts");
        std::env::remove_var(ENV_TELEMETRY_PILE);
        std::env::remove_var(ENV_TELEMETRY_COLLECTION_NAME);

        let subscriber = tracing_subscriber::registry().with(layer);
        let observed = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                target: "telemetry_gate",
                "turn",
                source = "turn-7",
                // Known at creation, and not the one field the layer used to
                // capture.
                disposition = "spoke",
                // Not known until the work is done.
                work_type = tracing::field::Empty,
            );
            let entered = span.enter();
            let observed =
                current_span_entity().expect("a consumer inside the span sees its entity");
            span.record("work_type", "decided-mid-span");
            drop(entered);
            observed
        });

        assert_eq!(
            current_span_entity(),
            None,
            "the entered-span stack unwinds with the span"
        );

        // Dropping the guard flushes every thread batch and closes the pile.
        drop(telemetry);

        let facts = cold_read_facts(&path);

        let categories: Vec<Inline<Handle<UTF8String>>> = find!(
            category: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{ observed @ schema::category: ?category }])
        )
        .collect();
        assert_eq!(
            categories,
            vec!["telemetry_gate".to_inline()],
            "the id the accessor handed out is the entity the layer persisted, so a \
             consumer's own tribles can join to it"
        );

        let expect = |text: &str| {
            let mut probe = Fragment::empty();
            let handle: Inline<Handle<UTF8String>> = probe.put(text.to_string());
            handle
        };
        let value_of = |name: &'static str| -> Vec<Inline<Handle<UTF8String>>> {
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(&facts, [
                    { observed @ schema::field: _?field },
                    { _?field @ schema::field_name: name, schema::field_value: ?value },
                ])
            )
            .collect()
        };

        assert_eq!(
            value_of("work_type"),
            vec![expect("decided-mid-span")],
            "a field recorded AFTER the span opened reaches the pile"
        );
        assert_eq!(
            value_of("disposition"),
            vec![expect("spoke")],
            "and so does a creation-time field that is not named `source`"
        );
        assert_eq!(
            value_of("source"),
            vec![expect("turn-7")],
            "`source` is captured as an ordinary field too"
        );

        let sources: Vec<Inline<Handle<UTF8String>>> = find!(
            source: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{ observed @ schema::source: ?source }])
        )
        .collect();
        assert_eq!(
            sources,
            vec![expect("turn-7")],
            "and it is still promoted to the attribute existing consumers read"
        );
    }

    /// The sink writes where it was told and nowhere else. `PILE` names an
    /// application's own append-only store, so inferring it turned a missing
    /// telemetry destination into a permanent, replicated firehose aimed at
    /// data the caller never offered.
    #[test]
    fn an_unset_telemetry_pile_never_falls_back_to_the_ambient_pile() {
        let _env = TELEMETRY_ENV.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ambient = dir.path().join("ambient.pile");
        std::fs::File::create(&ambient).unwrap();

        std::env::remove_var(ENV_TELEMETRY_PILE);
        std::env::set_var("PILE", &ambient);
        std::env::set_var(ENV_TELEMETRY_COLLECTION_NAME, "telemetry-test");

        let started = Telemetry::layer_from_env("test session");

        std::env::remove_var("PILE");
        std::env::remove_var(ENV_TELEMETRY_COLLECTION_NAME);

        assert!(
            started.is_none(),
            "an unset TELEMETRY_PILE disables telemetry instead of guessing a destination"
        );
        assert_eq!(
            std::fs::metadata(&ambient).unwrap().len(),
            0,
            "the ambient pile was never opened, let alone written to"
        );
    }

    #[test]
    fn unsupported_record_diagnostic_prioritizes_version_skew_without_destructive_advice() {
        let diagnostic = pile_refresh_diagnostic(
            Path::new("telemetry.pile"),
            &ReadError::UnsupportedRecord {
                offset: 256,
                marker: [0xA5; 16],
            },
        );

        assert!(diagnostic.contains("likely format/version skew"));
        assert!(diagnostic.contains("upgrade to a reader"));
        assert!(diagnostic.contains("pile was left unchanged"));
        assert!(!diagnostic.contains("amputate"));
    }

    #[test]
    fn no_refresh_failure_diagnostic_recommends_amputation() {
        let failures = [
            ReadError::CorruptPile { valid_length: 7 },
            ReadError::IoError(std::io::Error::other("unavailable")),
            ReadError::FileTooLarge { length: usize::MAX },
        ];

        for failure in &failures {
            let diagnostic = pile_refresh_diagnostic(Path::new("telemetry.pile"), failure);
            assert!(diagnostic.contains("telemetry disabled"));
            assert!(diagnostic.contains("pile was left unchanged"));
            assert!(!diagnostic.contains("amputate"));
        }
    }

    fn pending_span() -> Fragment {
        let mut batch = Fragment::empty();
        span_begin(
            &mut batch,
            *genid(),
            *genid(),
            None,
            7,
            "telemetry",
            "pending_span",
            Some("telemetry::tests".to_owned()),
        );
        batch
    }

    #[test]
    fn failed_publish_keeps_the_exact_pending_batch_for_retry() {
        let batch = pending_span();
        let mut state = ThreadTelemetry {
            batch: batch.clone(),
            last_flush: Instant::now(),
        };

        let result = publish_pending(&mut state, |_| Err::<(), _>("backend unavailable"));

        assert_eq!(result, Err("backend unavailable"));
        assert_eq!(state.batch, batch);
    }

    #[test]
    fn successful_publish_is_self_describing_and_clears_the_batch() {
        let batch = pending_span();
        assert!(!batch.facts().is_empty());
        assert!(!batch.blobs().is_empty());

        let mut state = ThreadTelemetry {
            batch: batch.clone(),
            last_flush: Instant::now(),
        };
        let mut published = None;

        let result = publish_pending(&mut state, |candidate| {
            published = Some(candidate);
            Ok::<(), ()>(())
        });

        assert_eq!(result, Ok(true));
        assert_eq!(state.batch, Fragment::empty());

        let published = published.expect("publisher received the batch");
        assert_eq!(published.facts(), batch.facts());
        let description = schema::build_telemetry_metadata();
        for fact in description.facts() {
            assert!(published.metafacts().contains(fact));
        }
        for fact in description.metafacts() {
            assert!(published.metafacts().contains(fact));
        }
    }
}
