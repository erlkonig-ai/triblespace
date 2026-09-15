use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use triblespace_core::blob::{Blob, BlobEncoding};
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::id_hex;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace_core::inline::encodings::iu256::U256BE;
use triblespace_core::inline::Inline;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::{attributes, entity};
use triblespace_core::trible::Fragment;

use crate::{Automaton, GraphEdge, PathError, PathSummary, Step};

const HEADER_LEN: usize = 48;
const AUTOMATON_BLOB_HEADER_LEN: usize = 40;
const AUTOMATON_BLOB_VERSION: u32 = 1;
// The automaton blob domain separator is the bytes of the stable
// path-summary-v2 algorithm anchor `341216BFE738E2D82BFFF96F52E7FE06`, minted
// with `trible genid` on 2026-07-28 when canonical summaries were restricted
// to matched support plus nullable identity. This is deliberately the exact
// wire previously hashed by `automaton_fingerprint`: retaining those bytes as
// a blob turns every existing fingerprint into its content handle without
// changing one path-summary byte.
const AUTOMATON_BLOB_DOMAIN: [u8; 16] = [
    0x34, 0x12, 0x16, 0xbf, 0xe7, 0x38, 0xe2, 0xd8, 0x2b, 0xff, 0xf9, 0x6f, 0x52, 0xe7, 0xfe, 0x06,
];

attributes! {
    /// Canonical BLAKE3 fingerprint of the fixed path automaton. Minted with
    /// `trible genid` on 2026-07-28.
    "77DF5A905CCE3B0643BB02999F73BE4C" unsafe as pub path_automaton_fingerprint: Hash<Blake3>;
    /// Number of states in the canonical path automaton. Minted with
    /// `trible genid` on 2026-08-29.
    "562D157447DBE25FE8E6DCB95C5A5AB4" as pub path_automaton_state_count: U256BE;
    /// Initial state of the canonical path automaton. Repeated on the
    /// concrete mapping entity. Minted with `trible genid` on 2026-08-29.
    "EE0D84553EB07FD3E75CD2709ED50E79" as pub path_automaton_initial_state: U256BE;
    /// Accepting state of the canonical path automaton. Repeated on the
    /// concrete mapping entity. Minted with `trible genid` on 2026-08-29.
    "4D10E8C83A816E1D888AD243B1DBD5C7" as pub path_automaton_accepting_state: U256BE;
    /// Intrinsic transition entity belonging to the canonical path automaton.
    /// Repeated on the concrete mapping entity. Minted with `trible genid` on
    /// 2026-08-29.
    "4828A5918A259F89038041053EA720CC" as pub path_automaton_transition: GenId;
    /// Source state of one path-automaton transition. Minted with
    /// `trible genid` on 2026-08-29.
    "15FBA850D9AC99B7CF8D7842FC5F77B3" as pub path_transition_from: U256BE;
    /// Target state of one path-automaton transition. Minted with
    /// `trible genid` on 2026-08-29.
    "A8F46B12D94B7400F052C45ED579873E" as pub path_transition_to: U256BE;
    /// Canonical transition opcode: forward, reverse, forward-except, or
    /// reverse-except. Minted with `trible genid` on 2026-08-29.
    "08B0B01EFE6E68AB85DF4F0967D914B8" as pub path_transition_kind: U256BE;
    /// Attribute label carried by one transition. Exact forward/reverse
    /// transitions have one; exclusion transitions have zero or more. Minted
    /// with `trible genid` on 2026-08-29.
    "FD88EA3256CD24545BEB7759E7DBA6FA" as pub path_transition_label: U256BE;
}

/// Canonical portable bytes of one fixed epsilon-free path automaton.
///
/// A [`PathSummaryBlob`] stores this blob's content handle in its first 32
/// bytes. The automaton is therefore an immutable representation dependency,
/// not descriptor-local decoding state. The canonical wire is byte-for-byte
/// the input historically used by [`automaton_fingerprint`], preserving every
/// existing summary handle.
pub struct PathAutomatonBlob;

impl BlobEncoding for PathAutomatonBlob {}

impl MetaDescribe for PathAutomatonBlob {
    fn describe() -> Fragment {
        // Minted with `trible genid` on 2026-09-04:
        // 5360AFD4486A38C31C5D73A290D8B54A
        let id: Id = id_hex!("5360AFD4486A38C31C5D73A290D8B54A");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "path-automaton-v1",
            metadata::description: "Canonical portable epsilon-free path automaton: fixed domain and version, state count, ordered initial and accepting state sets, and ordered labeled transitions. Its content handle is embedded by PathSummaryBlob as an immutable representation dependency.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Failure to decode one canonical [`PathAutomatonBlob`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathAutomatonBlobError {
    /// The fixed prefix or one count-delimited section is truncated.
    BadLength,
    /// The blob does not carry the canonical path-automaton domain.
    WrongDomain,
    /// The blob uses an unknown canonical wire version.
    UnsupportedVersion(u32),
    /// A transition carries an unknown step opcode.
    InvalidOpcode(u8),
    /// An exact forward or reverse transition does not carry one label.
    InvalidExactLabelCount,
    /// State numbers or mandatory state sets do not form an automaton.
    InvalidAutomaton(crate::AutomatonError),
    /// The decoded automaton re-encodes to different bytes.
    NonCanonical,
}

impl fmt::Display for PathAutomatonBlobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength => formatter.write_str("path-automaton blob has an invalid length"),
            Self::WrongDomain => formatter.write_str("path-automaton blob has the wrong domain"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported path-automaton blob version {version}"
                )
            }
            Self::InvalidOpcode(opcode) => {
                write!(
                    formatter,
                    "path-automaton transition has invalid opcode {opcode}"
                )
            }
            Self::InvalidExactLabelCount => formatter
                .write_str("an exact path-automaton transition must carry exactly one label"),
            Self::InvalidAutomaton(source) => source.fmt(formatter),
            Self::NonCanonical => {
                formatter.write_str("path-automaton blob is not canonically encoded")
            }
        }
    }
}

impl Error for PathAutomatonBlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidAutomaton(source) => Some(source),
            Self::BadLength
            | Self::WrongDomain
            | Self::UnsupportedVersion(_)
            | Self::InvalidOpcode(_)
            | Self::InvalidExactLabelCount
            | Self::NonCanonical => None,
        }
    }
}

/// Canonical direct-product summary bytes for one fixed automaton.
pub struct PathSummaryBlob;

impl BlobEncoding for PathSummaryBlob {}

impl MetaDescribe for PathSummaryBlob {
    fn describe() -> Fragment {
        // Minted with `trible genid` on 2026-07-28 when canonical-domain
        // validation changed to matched support plus nullable identity.
        let id: Id = id_hex!("F15A8487F9372278E10F220DC37C2888");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "path-summary-v2",
            metadata::description: "Canonical fixed-header path summary: the sorted graph-term domain required by one fixed automaton followed by sorted direct product arcs. Nullable automata retain the complete supplied endpoint universe; the 48-byte zero-vertex form is the canonical empty summary.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Canonical path-summary validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathSummaryBlobError {
    /// The fixed header or payload length is invalid.
    BadLength,
    /// The blob belongs to a different fixed automaton.
    DifferentAutomaton,
    /// A non-nullable summary retained vertices outside matched-edge support.
    NoncanonicalDomain,
    /// Vertex values are not strictly increasing.
    VertexOrder,
    /// Product arcs are not strictly increasing.
    ArcOrder,
    /// A product ordinal lies outside the declared carrier.
    ArcOutOfBounds,
    /// An arc's source/destination state pair is absent from the automaton.
    InvalidStatePair,
    /// Two individually valid summaries could not be joined.
    Join(PathError),
    /// A length or carrier calculation overflowed its representation.
    CapacityOverflow,
}

impl fmt::Display for PathSummaryBlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Join(source) = self {
            return write!(f, "cannot join path summaries: {source}");
        }
        let message = match self {
            Self::BadLength => "path-summary blob has an invalid length",
            Self::DifferentAutomaton => "path-summary blob belongs to a different automaton",
            Self::NoncanonicalDomain => {
                "a non-nullable path summary contains vertices outside matched-edge support"
            }
            Self::VertexOrder => "path-summary vertices are not strictly ordered",
            Self::ArcOrder => "path-summary arcs are not strictly ordered",
            Self::ArcOutOfBounds => "path-summary arc is outside the product carrier",
            Self::InvalidStatePair => "path-summary arc uses an impossible automaton state pair",
            Self::CapacityOverflow => "path-summary dimensions overflow their representation",
            Self::Join(_) => unreachable!("handled above"),
        };
        f.write_str(message)
    }
}

impl Error for PathSummaryBlobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Join(source) => Some(source),
            _ => None,
        }
    }
}

impl PathSummaryBlob {
    /// Read the canonical automaton dependency embedded at offset zero.
    ///
    /// The 32 bytes were historically described as the automaton fingerprint.
    /// Because that fingerprint hashes the exact canonical
    /// [`PathAutomatonBlob`] bytes, it is also the typed content handle without
    /// any format change.
    pub fn automaton_handle(
        blob: &Blob<Self>,
    ) -> Result<Inline<Handle<PathAutomatonBlob>>, PathSummaryBlobError> {
        if blob.bytes.len() < HEADER_LEN {
            return Err(PathSummaryBlobError::BadLength);
        }
        Ok(Inline::new(
            blob.bytes.as_ref()[..32]
                .try_into()
                .expect("checked 32-byte automaton handle"),
        ))
    }

    /// Canonical bottom element for one fixed automaton.
    pub fn empty(automaton: &Automaton) -> Blob<Self> {
        let summary = PathSummary::from_edges(automaton.clone(), std::iter::empty::<GraphEdge>());
        Self::encode(&summary).expect("the fixed empty path-summary construction cannot fail")
    }

    /// Encode one canonical constructional summary.
    ///
    /// Product arcs use full-domain `u32` ordinals on disk. A persisted
    /// nullable summary therefore still requires `|U| * |Q| <= u32::MAX`,
    /// even though materialization closes only the smaller matched support.
    /// The empty summary is the fixed 48-byte header with zero vertices and
    /// arcs; retaining it makes derivation a total join homomorphism.
    pub fn encode(summary: &PathSummary) -> Result<Blob<Self>, PathSummaryBlobError> {
        if !summary.has_canonical_domain() {
            return Err(PathSummaryBlobError::NoncanonicalDomain);
        }
        let vertex_count = u32::try_from(summary.vertices().len())
            .map_err(|_| PathSummaryBlobError::CapacityOverflow)?;
        checked_product_count(summary.vertices().len(), summary.automaton().state_count())?;
        let arcs = summary.ordinal_arcs().collect::<Vec<_>>();
        let arc_count =
            u64::try_from(arcs.len()).map_err(|_| PathSummaryBlobError::CapacityOverflow)?;
        let vertex_bytes = summary
            .vertices()
            .len()
            .checked_mul(32)
            .ok_or(PathSummaryBlobError::CapacityOverflow)?;
        let arc_bytes = arcs
            .len()
            .checked_mul(8)
            .ok_or(PathSummaryBlobError::CapacityOverflow)?;
        let capacity = HEADER_LEN
            .checked_add(vertex_bytes)
            .and_then(|length| length.checked_add(arc_bytes))
            .ok_or(PathSummaryBlobError::CapacityOverflow)?;
        let automaton = PathAutomatonBlob::encode(summary.automaton()).get_handle();

        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&automaton.raw);
        bytes.extend_from_slice(&summary.automaton().state_count().to_le_bytes());
        bytes.extend_from_slice(&vertex_count.to_le_bytes());
        bytes.extend_from_slice(&arc_count.to_le_bytes());
        for vertex in summary.vertices() {
            bytes.extend_from_slice(vertex);
        }
        for (source, target) in arcs {
            bytes.extend_from_slice(&source.to_le_bytes());
            bytes.extend_from_slice(&target.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), capacity);
        Ok(Blob::new(bytes.into()))
    }

    /// Decode stored canonical bytes structurally for one fixed automaton.
    ///
    /// A collection member is trusted materialized work, so a read checks only
    /// what safe interpretation needs: the header's lengths, the automaton's
    /// state count, and every arc inside the product carrier. The vertex
    /// order, the arc order and the domain are taken as stored. Nothing is
    /// re-encoded or hashed; the automaton handle in the header is the
    /// caller's to compare against the collection's, as a typed view does.
    /// [`audit`](Self::audit) is the explicit canonical check.
    pub fn decode(
        blob: Blob<Self>,
        automaton: &Automaton,
    ) -> Result<PathSummary, PathSummaryBlobError> {
        let bytes = blob.bytes.as_ref();
        let header = structural_header(bytes, automaton.state_count())?;
        let vertex_count = header.vertex_count;
        let vertex_bytes = header.vertex_bytes;
        let product_count = header.product_count;

        let mut vertices = Vec::with_capacity(vertex_count);
        for chunk in bytes[HEADER_LEN..HEADER_LEN + vertex_bytes].chunks_exact(32) {
            vertices.push(chunk.try_into().expect("chunks_exact yields 32 bytes"));
        }
        let mut arcs = Vec::with_capacity(header.arc_count);
        for chunk in bytes[HEADER_LEN + vertex_bytes..].chunks_exact(8) {
            let source = u32::from_le_bytes(chunk[..4].try_into().expect("four bytes"));
            let target = u32::from_le_bytes(chunk[4..].try_into().expect("four bytes"));
            if source as usize >= product_count || target as usize >= product_count {
                return Err(PathSummaryBlobError::ArcOutOfBounds);
            }
            arcs.push((source, target));
        }
        PathSummary::from_canonical_ordinals(automaton.clone(), vertices, arcs)
            .map_err(|_| PathSummaryBlobError::CapacityOverflow)
    }

    /// Audit canonical bytes against the expected automaton.
    ///
    /// Everything [`decode`](Self::decode) checks, and then the canonical law
    /// itself: the header names exactly this automaton, vertices and arcs are
    /// strictly ordered, every arc follows one of the automaton's transitions,
    /// and the vertex domain is the canonical one for it. This is the
    /// producer's, ingress's and offline auditor's check; a warm read of a
    /// stored member does not run it.
    pub fn audit(
        blob: Blob<Self>,
        automaton: &Automaton,
    ) -> Result<PathSummary, PathSummaryBlobError> {
        let bytes = blob.bytes.as_ref();
        let header = validate_header(bytes, automaton)?;
        let vertex_count = header.vertex_count;
        let vertex_bytes = header.vertex_bytes;
        let state_count = automaton.state_count();
        let product_count = header.product_count;

        let mut vertices = Vec::with_capacity(vertex_count);
        for chunk in bytes[HEADER_LEN..HEADER_LEN + vertex_bytes].chunks_exact(32) {
            vertices.push(chunk.try_into().expect("chunks_exact yields 32 bytes"));
        }
        if vertices.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PathSummaryBlobError::VertexOrder);
        }

        let allowed_state_pairs = automaton
            .transitions()
            .iter()
            .map(|transition| (transition.from, transition.to))
            .collect::<BTreeSet<_>>();
        let mut arcs = Vec::with_capacity(header.arc_count);
        let mut previous = None;
        for chunk in bytes[HEADER_LEN + vertex_bytes..].chunks_exact(8) {
            let source = u32::from_le_bytes(chunk[..4].try_into().expect("four bytes"));
            let target = u32::from_le_bytes(chunk[4..].try_into().expect("four bytes"));
            if source as usize >= product_count || target as usize >= product_count {
                return Err(PathSummaryBlobError::ArcOutOfBounds);
            }
            if !allowed_state_pairs.contains(&(source % state_count, target % state_count)) {
                return Err(PathSummaryBlobError::InvalidStatePair);
            }
            let arc = (source, target);
            if previous.is_some_and(|previous| previous >= arc) {
                return Err(PathSummaryBlobError::ArcOrder);
            }
            previous = Some(arc);
            arcs.push(arc);
        }
        let summary = PathSummary::from_canonical_ordinals(automaton.clone(), vertices, arcs)
            .map_err(|_| PathSummaryBlobError::CapacityOverflow)?;
        if !summary.has_canonical_domain() {
            return Err(PathSummaryBlobError::NoncanonicalDomain);
        }
        Ok(summary)
    }

    /// Compute the exact canonical join of two summaries for one automaton.
    ///
    /// This is new work by a producer, so both inputs are audited; a reader
    /// joining resident members decodes them structurally and merges the
    /// decoded summaries instead, without encoding a growing prefix.
    pub fn join(
        left: &Blob<Self>,
        right: &Blob<Self>,
        automaton: &Automaton,
    ) -> Result<Blob<Self>, PathSummaryBlobError> {
        let left = Self::audit(left.clone(), automaton)?;
        let right = Self::audit(right.clone(), automaton)?;
        let joined = left.merge(&right).map_err(PathSummaryBlobError::Join)?;
        Self::encode(&joined)
    }
}

#[derive(Clone, Copy, Debug)]
struct ValidatedHeader {
    vertex_count: usize,
    vertex_bytes: usize,
    arc_count: usize,
    product_count: usize,
}

/// The audit's header check: the canonical automaton handle, then the shape.
fn validate_header(
    bytes: &[u8],
    automaton: &Automaton,
) -> Result<ValidatedHeader, PathSummaryBlobError> {
    if bytes.len() < HEADER_LEN {
        return Err(PathSummaryBlobError::BadLength);
    }
    let expected_automaton = PathAutomatonBlob::encode(automaton).get_handle();
    if bytes[..32] != expected_automaton.raw {
        return Err(PathSummaryBlobError::DifferentAutomaton);
    }
    structural_header(bytes, automaton.state_count())
}

/// The shape a read needs: lengths that agree with the counts, and a product
/// carrier the arcs can index. No hashing, no re-encoding.
fn structural_header(
    bytes: &[u8],
    expected_state_count: u32,
) -> Result<ValidatedHeader, PathSummaryBlobError> {
    if bytes.len() < HEADER_LEN {
        return Err(PathSummaryBlobError::BadLength);
    }
    let state_count = read_u32(bytes, 32);
    if state_count != expected_state_count {
        return Err(PathSummaryBlobError::DifferentAutomaton);
    }
    let vertex_count = read_u32(bytes, 36) as usize;
    let arc_count =
        usize::try_from(read_u64(bytes, 40)).map_err(|_| PathSummaryBlobError::CapacityOverflow)?;
    let vertex_bytes = vertex_count
        .checked_mul(32)
        .ok_or(PathSummaryBlobError::CapacityOverflow)?;
    let arc_bytes = arc_count
        .checked_mul(8)
        .ok_or(PathSummaryBlobError::CapacityOverflow)?;
    let expected_length = HEADER_LEN
        .checked_add(vertex_bytes)
        .and_then(|length| length.checked_add(arc_bytes))
        .ok_or(PathSummaryBlobError::CapacityOverflow)?;
    if bytes.len() != expected_length {
        return Err(PathSummaryBlobError::BadLength);
    }
    let product_count = checked_product_count(vertex_count, state_count)?;
    Ok(ValidatedHeader {
        vertex_count,
        vertex_bytes,
        arc_count,
        product_count,
    })
}

fn checked_product_count(
    vertex_count: usize,
    state_count: u32,
) -> Result<usize, PathSummaryBlobError> {
    let product_count = vertex_count
        .checked_mul(state_count as usize)
        .ok_or(PathSummaryBlobError::CapacityOverflow)?;
    if product_count > u32::MAX as usize {
        return Err(PathSummaryBlobError::CapacityOverflow);
    }
    Ok(product_count)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked header"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked header"),
    )
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn transition_wire(transition: &crate::Transition) -> Vec<u8> {
    let (opcode, labels): (u8, &[triblespace_core::id::RawId]) = match &transition.step {
        Step::Forward(label) => (0, std::slice::from_ref(label)),
        Step::Reverse(label) => (1, std::slice::from_ref(label)),
        Step::ForwardExcept(labels) => (2, labels),
        Step::ReverseExcept(labels) => (3, labels),
    };
    let mut bytes = Vec::with_capacity(17 + labels.len() * 16);
    push_u32(&mut bytes, transition.from);
    push_u32(&mut bytes, transition.to);
    bytes.push(opcode);
    push_u64(
        &mut bytes,
        u64::try_from(labels.len()).expect("label vector length fits in u64"),
    );
    for label in labels {
        bytes.extend_from_slice(label);
    }
    bytes
}

fn automaton_wire(automaton: &Automaton) -> Vec<u8> {
    let initial = automaton.initial_states().collect::<Vec<_>>();
    let accepting = automaton.accepting_states().collect::<Vec<_>>();
    let mut transitions = automaton
        .transitions()
        .iter()
        .map(transition_wire)
        .collect::<Vec<_>>();
    transitions.sort_unstable();

    let mut wire = Vec::new();
    wire.extend_from_slice(&AUTOMATON_BLOB_DOMAIN);
    push_u32(&mut wire, AUTOMATON_BLOB_VERSION);
    push_u32(&mut wire, automaton.state_count());
    push_u32(
        &mut wire,
        u32::try_from(initial.len()).expect("automaton state count is u32"),
    );
    push_u32(
        &mut wire,
        u32::try_from(accepting.len()).expect("automaton state count is u32"),
    );
    push_u64(
        &mut wire,
        u64::try_from(transitions.len()).expect("transition vector length fits in u64"),
    );
    for state in initial {
        push_u32(&mut wire, state);
    }
    for state in accepting {
        push_u32(&mut wire, state);
    }
    for transition in transitions {
        wire.extend_from_slice(&transition);
    }
    wire
}

struct AutomatonWireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> AutomatonWireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PathAutomatonBlobError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PathAutomatonBlobError::BadLength)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PathAutomatonBlobError::BadLength)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, PathAutomatonBlobError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, PathAutomatonBlobError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four checked bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, PathAutomatonBlobError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight checked bytes"),
        ))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

impl PathAutomatonBlob {
    /// Encode one canonical automaton into its portable content-addressed form.
    pub fn encode(automaton: &Automaton) -> Blob<Self> {
        Blob::new(automaton_wire(automaton).into())
    }

    /// Decode one automaton blob structurally.
    ///
    /// The bytes are a content-addressed representation dependency of every
    /// summary that names them; a read takes them as stored and builds the
    /// automaton they describe. [`audit`](Self::audit) additionally proves
    /// they are the canonical wire for that automaton.
    pub fn decode(blob: &Blob<Self>) -> Result<Automaton, PathAutomatonBlobError> {
        let bytes = blob.bytes.as_ref();
        if bytes.len() < AUTOMATON_BLOB_HEADER_LEN {
            return Err(PathAutomatonBlobError::BadLength);
        }

        let mut wire = AutomatonWireReader::new(bytes);
        if wire.take(AUTOMATON_BLOB_DOMAIN.len())? != AUTOMATON_BLOB_DOMAIN {
            return Err(PathAutomatonBlobError::WrongDomain);
        }
        let version = wire.u32()?;
        if version != AUTOMATON_BLOB_VERSION {
            return Err(PathAutomatonBlobError::UnsupportedVersion(version));
        }
        let state_count = wire.u32()?;
        let initial_count = wire.u32()? as usize;
        let accepting_count = wire.u32()? as usize;
        let transition_count =
            usize::try_from(wire.u64()?).map_err(|_| PathAutomatonBlobError::BadLength)?;

        let state_bytes = initial_count
            .checked_add(accepting_count)
            .and_then(|count| count.checked_mul(4))
            .ok_or(PathAutomatonBlobError::BadLength)?;
        if state_bytes > wire.remaining() {
            return Err(PathAutomatonBlobError::BadLength);
        }
        let mut initial = Vec::with_capacity(initial_count);
        for _ in 0..initial_count {
            initial.push(wire.u32()?);
        }
        let mut accepting = Vec::with_capacity(accepting_count);
        for _ in 0..accepting_count {
            accepting.push(wire.u32()?);
        }

        // Every transition needs at least from, to, opcode, and label count.
        // Bound the allocation before trusting the count from untrusted bytes.
        if transition_count > wire.remaining() / 17 {
            return Err(PathAutomatonBlobError::BadLength);
        }
        let mut transitions = Vec::with_capacity(transition_count);
        for _ in 0..transition_count {
            let from = wire.u32()?;
            let to = wire.u32()?;
            let opcode = wire.u8()?;
            let label_count =
                usize::try_from(wire.u64()?).map_err(|_| PathAutomatonBlobError::BadLength)?;
            let label_bytes = label_count
                .checked_mul(16)
                .ok_or(PathAutomatonBlobError::BadLength)?;
            if label_bytes > wire.remaining() {
                return Err(PathAutomatonBlobError::BadLength);
            }
            let mut labels = Vec::with_capacity(label_count);
            for _ in 0..label_count {
                labels.push(wire.take(16)?.try_into().expect("sixteen checked bytes"));
            }
            let step = match (opcode, labels.as_slice()) {
                (0, [label]) => Step::Forward(*label),
                (1, [label]) => Step::Reverse(*label),
                (0 | 1, _) => return Err(PathAutomatonBlobError::InvalidExactLabelCount),
                (2, labels) => Step::ForwardExcept(labels.to_vec()),
                (3, labels) => Step::ReverseExcept(labels.to_vec()),
                (opcode, _) => return Err(PathAutomatonBlobError::InvalidOpcode(opcode)),
            };
            transitions.push(crate::Transition::new(from, to, step));
        }
        if !wire.is_empty() {
            return Err(PathAutomatonBlobError::BadLength);
        }

        Automaton::new(state_count, initial, accepting, transitions)
            .map_err(PathAutomatonBlobError::InvalidAutomaton)
    }

    /// Decode one automaton blob and prove its bytes are the canonical wire.
    pub fn audit(blob: &Blob<Self>) -> Result<Automaton, PathAutomatonBlobError> {
        let automaton = Self::decode(blob)?;
        if automaton_wire(&automaton) != blob.bytes.as_ref() {
            return Err(PathAutomatonBlobError::NonCanonical);
        }
        Ok(automaton)
    }
}

/// Content handle of the canonical automaton wire, exposed under its historic
/// fingerprint schema.
///
/// The raw bytes are also an `Inline<Handle<PathAutomatonBlob>>`; the Hash
/// return type is retained because this function and the existing mapping fact
/// predate the retained automaton blob.
pub fn automaton_fingerprint(automaton: &Automaton) -> Inline<Hash<Blake3>> {
    Inline::new(PathAutomatonBlob::encode(automaton).get_handle().raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    use triblespace_core::inline::RawInline;

    use crate::{GraphEdge, Transition};

    fn vertex(byte: u8) -> RawInline {
        [byte; 32]
    }

    fn label(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn edge(source: u8, attribute: u8, target: u8) -> GraphEdge {
        GraphEdge {
            source: vertex(source),
            attribute: label(attribute),
            target: vertex(target),
        }
    }

    fn plus(attribute: u8) -> Automaton {
        let attribute = label(attribute);
        Automaton::new(
            2,
            [0],
            [1],
            [
                Transition::new(0, 1, Step::Forward(attribute)),
                Transition::new(1, 1, Step::Forward(attribute)),
            ],
        )
        .unwrap()
    }

    #[test]
    fn automaton_blob_retains_the_historic_fingerprint_wire() {
        let automaton = Automaton::new(
            3,
            [0, 1],
            [1, 2],
            [
                Transition::new(0, 1, Step::Forward(label(7))),
                Transition::new(1, 2, Step::ReverseExcept(vec![label(9), label(8)])),
            ],
        )
        .unwrap();
        let blob = PathAutomatonBlob::encode(&automaton);

        assert_eq!(blob.get_handle().raw, automaton_fingerprint(&automaton).raw);
        assert_eq!(PathAutomatonBlob::decode(&blob).unwrap(), automaton);

        let summary = PathSummary::from_edges(automaton, [edge(1, 7, 2)]);
        let summary = PathSummaryBlob::encode(&summary).unwrap();
        assert_eq!(
            PathSummaryBlob::automaton_handle(&summary).unwrap(),
            blob.get_handle()
        );
    }

    #[test]
    fn automaton_blob_rejects_noncanonical_and_trailing_bytes() {
        let automaton = Automaton::new(3, [0, 1], [2], []).unwrap();
        let canonical = PathAutomatonBlob::encode(&automaton);

        let mut noncanonical = canonical.bytes.as_ref().to_vec();
        noncanonical[40..44].copy_from_slice(&1u32.to_le_bytes());
        noncanonical[44..48].copy_from_slice(&0u32.to_le_bytes());
        let noncanonical = Blob::<PathAutomatonBlob>::new(noncanonical.into());
        // A structural read takes the wire as stored; only the audit re-encodes.
        assert_eq!(PathAutomatonBlob::decode(&noncanonical).unwrap(), automaton);
        assert_eq!(
            PathAutomatonBlob::audit(&noncanonical).unwrap_err(),
            PathAutomatonBlobError::NonCanonical,
        );

        let mut trailing = canonical.bytes.as_ref().to_vec();
        trailing.push(0);
        assert_eq!(
            PathAutomatonBlob::decode(&Blob::new(trailing.into())).unwrap_err(),
            PathAutomatonBlobError::BadLength,
        );
    }

    #[test]
    fn canonical_bytes_are_input_order_invariant_and_golden() {
        let automaton = Automaton::new(
            1,
            [0, 0],
            [0],
            [
                Transition::new(0, 0, Step::Forward(label(9))),
                Transition::new(0, 0, Step::Forward(label(9))),
            ],
        )
        .unwrap();
        let first = PathSummary::from_edges(automaton.clone(), [edge(1, 9, 2), edge(1, 9, 2)]);
        let second = PathSummary::from_edges(automaton, [edge(1, 9, 2)]);
        let first_blob = PathSummaryBlob::encode(&first).unwrap();
        let second_blob = PathSummaryBlob::encode(&second).unwrap();

        assert_eq!(first_blob.bytes, second_blob.bytes);
        assert_eq!(first_blob.get_handle(), second_blob.get_handle());
        assert_eq!(
            hex(first_blob.bytes.as_ref()),
            "5f73d0cf0230edf0512144e14a5e96132e661e1925556060b8036f217dc9b7f801000000020000000100000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000001000000"
        );

        let ordered = plus(7);
        let reversed = Automaton::new(
            2,
            [0],
            [1],
            [
                Transition::new(1, 1, Step::Forward(label(7))),
                Transition::new(0, 1, Step::Forward(label(7))),
            ],
        )
        .unwrap();
        assert_eq!(
            automaton_fingerprint(&ordered),
            automaton_fingerprint(&reversed)
        );
    }

    #[test]
    fn malformed_length_fingerprint_order_bounds_and_state_pair_are_rejected() {
        let automaton = plus(9);
        let summary = PathSummary::from_edges(automaton.clone(), [edge(1, 9, 2)]);
        let blob = PathSummaryBlob::encode(&summary).unwrap();

        // The shape a read needs is checked by both the read and the audit.
        let mut bad = blob.bytes.as_ref().to_vec();
        bad.pop();
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert_eq!(
            PathSummaryBlob::decode(bad.clone(), &automaton).unwrap_err(),
            PathSummaryBlobError::BadLength
        );
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::BadLength
        );

        let arc_offset = HEADER_LEN + 2 * 32;
        let mut bad = blob.bytes.as_ref().to_vec();
        bad[arc_offset + 4..arc_offset + 8].copy_from_slice(&4u32.to_le_bytes());
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert_eq!(
            PathSummaryBlob::decode(bad.clone(), &automaton).unwrap_err(),
            PathSummaryBlobError::ArcOutOfBounds
        );
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::ArcOutOfBounds
        );

        // The canonical law is the audit's alone: a read takes the automaton
        // handle, the orders and the transitions as stored.
        let mut bad = blob.bytes.as_ref().to_vec();
        bad[0] ^= 1;
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert!(PathSummaryBlob::decode(bad.clone(), &automaton).is_ok());
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::DifferentAutomaton
        );

        let mut bad = blob.bytes.as_ref().to_vec();
        bad[48..80].copy_from_slice(&vertex(2));
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert!(PathSummaryBlob::decode(bad.clone(), &automaton).is_ok());
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::VertexOrder
        );

        let mut bad = blob.bytes.as_ref().to_vec();
        bad[arc_offset + 4..arc_offset + 8].copy_from_slice(&2u32.to_le_bytes());
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert!(PathSummaryBlob::decode(bad.clone(), &automaton).is_ok());
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::InvalidStatePair
        );

        let mut bad = blob.bytes.as_ref().to_vec();
        let first_arc = bad[arc_offset..arc_offset + 8].to_vec();
        bad[arc_offset + 8..arc_offset + 16].copy_from_slice(&first_arc);
        let bad = Blob::<PathSummaryBlob>::new(bad.into());
        assert!(PathSummaryBlob::decode(bad.clone(), &automaton).is_ok());
        assert_eq!(
            PathSummaryBlob::audit(bad, &automaton).unwrap_err(),
            PathSummaryBlobError::ArcOrder
        );
    }

    #[test]
    fn a_read_and_an_audit_agree_on_canonical_bytes() {
        let automaton = plus(9);
        let summary = PathSummary::from_edges(automaton.clone(), [edge(1, 9, 2), edge(2, 9, 3)]);
        let blob = PathSummaryBlob::encode(&summary).unwrap();
        let read = PathSummaryBlob::decode(blob.clone(), &automaton).unwrap();
        let audited = PathSummaryBlob::audit(blob, &automaton).unwrap();
        assert_eq!(read, summary);
        assert_eq!(audited, summary);
    }

    #[test]
    fn product_carrier_dimensions_are_checked_before_ordinal_lowering() {
        assert_eq!(checked_product_count(2, 3).unwrap(), 6);
        assert_eq!(
            checked_product_count(u32::MAX as usize, 2).unwrap_err(),
            PathSummaryBlobError::CapacityOverflow
        );
        assert_eq!(
            checked_product_count(usize::MAX, 2).unwrap_err(),
            PathSummaryBlobError::CapacityOverflow
        );
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0xf) as usize] as char);
        }
        out
    }
}
