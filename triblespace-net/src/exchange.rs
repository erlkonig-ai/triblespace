//! Symmetric, continuous FIFO exchange of prefix/hash/count delta subtrees.
//!
//! Each connection retains sound common-held agreement G. Asymmetric final
//! failures can leave unequal local bases; both still contain only jointly
//! held keys. A successful symmetric exchange computes the same union. An
//! exchange freezes each sender's native PATCH difference Δ = pinned \ G.
//! Its ordinary empty-prefix SUBTREE commits to Δ, not to the collection or
//! to the union. Every visited subtree then announces only its prefix, hash
//! and leaf count; children appear as separate later FIFO announcements.
//! There are no full child arrays, level barriers, HELD frames or reply waits.
//!
//! A matching announcement is compared with our own Δ. We still announce
//! that subtree once, but prune queued descendants and do not descend into
//! it. Scheduling and network delay determine how much was already sent.
//! G omission comes from the immutable difference itself, not wire siblings.
//!
//! The receiver reconstructs a peer-only Δ PATCH: initially empty, populated
//! from received leaves and exact locally held subtree grafts. Typed values
//! come from the latest serving observation or are pulled by key and checked.
//! Every announced prefix/hash/count and the root must match that peer view
//! before LANDED. Unknown intermediate hashes are provisional until this
//! closure; leaf keys authenticate their own domain-separated digest on arrival.
//! The local union is never the peer's membership proof.
//!
//! Successful agreement is G ∪ Δlocal ∪ Δpeer, after both LANDEDs and actual
//! stream writes/finish succeed in the driver. Failure forgets reusable G;
//! already landed values remain. Publication lag creates an empty difference
//! for already agreed keys and cannot shrink G. Within a connection held trees
//! are assumed to grow. A receive-only side advertises the empty delta and
//! serves no value, including no private pinned digest/count.
//!
//! State grows on demand within explicit budgets: FIFO positions, received
//! commitments, matched announcements, and peer-delta leaves each have at
//! most FLOOD_LOCATORS entries; withheld values have FLOOD_WANTED entries.
//! Honest larger deltas can be refused too. Requests/fetches and pending
//! landings retain their separate bounded windows and transport backpressure.

use std::collections::VecDeque;
use std::sync::Arc;

use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::{CollectionHandle, CollectionRecord};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH, PatchHash};

use crate::channel::NetEvent;
use crate::collection_activation::CollectionRepairOverlay;
use crate::host::{CollectionSnapshot, StoreSnapshot};
use crate::patch_repair::PatchSummary;
use crate::protocol::RawHash;
use crate::walk::{
    Admit, KEY_BYTES, MAX_WALK_REQUESTS, MAX_WALK_UNLANDED, Value, WalkKind, admit_fetched,
    admit_missing, admit_value, node_summary, summary, value,
};
use crate::walk_stream::Frame;

/// Missing leaves awaiting a value beyond which the exchange fails.
pub(crate) const FLOOD_WANTED: usize = 32 * 1024;
/// Grow-on-demand frontier and delta-proof budget, independent of value waits.
const FLOOD_LOCATORS: usize = 1024 * 1024;

fn locator_key(locator: &[u8]) -> [u8; KEY_BYTES + 1] {
    let mut key = [0; KEY_BYTES + 1];
    key[0] = u8::try_from(locator.len()).expect("a checked locator fits its key");
    key[1..1 + locator.len()].copy_from_slice(locator);
    key
}

/// One kind's tree as both sides agreed on it: a persistent PATCH, the
/// prior acknowledged base plus both deltas of the last confirmed exchange,
/// possibly ahead of lagging physical pins, kept per
/// peer, collection and kind ([`crate::walk::Walks`]).
#[derive(Clone)]
pub(crate) enum Tree {
    Records(PATCH<KEY_BYTES, IdentitySchema, CollectionRecord, Blake3Merkle>),
    /// Keyed by the collection, then the proof id.
    Authorization(
        CollectionHandle,
        PATCH<64, IdentitySchema, CapabilityProof, Blake3Merkle>,
    ),
    References(PATCH<KEY_BYTES, IdentitySchema, (), Blake3Merkle>),
}

impl Tree {
    /// The `kind` tree of `overlay`, shared with it.
    pub(crate) fn pinned(kind: WalkKind, overlay: &CollectionRepairOverlay) -> Self {
        match kind {
            WalkKind::Records => Self::Records(overlay.records().patch().clone()),
            WalkKind::Authorization => Self::Authorization(
                overlay.collection(),
                overlay.authorization_evidence().patch().clone(),
            ),
            WalkKind::References => Self::References(overlay.blob_inventory().clone()),
        }
    }

    fn empty(kind: WalkKind, collection: CollectionHandle) -> Self {
        match kind {
            WalkKind::Records => Self::Records(PATCH::new()),
            WalkKind::Authorization => Self::Authorization(collection, PATCH::new()),
            WalkKind::References => Self::References(PATCH::new()),
        }
    }

    pub(crate) fn summary(&self) -> PatchSummary {
        self.at(&[]).unwrap_or_else(empty)
    }

    /// A newer serving observation needs another exchange only for keys
    /// outside the agreed union. Publication may still lag landings; a
    /// strict subset is not new work and must not trigger an empty repush.
    pub(crate) fn has_new_keys(&self, current: &Self) -> bool {
        match (self, current) {
            (Self::Records(agreed), Self::Records(current)) => {
                !current.difference(agreed).is_empty()
            }
            (Self::Authorization(_, agreed), Self::Authorization(_, current)) => {
                !current.difference(agreed).is_empty()
            }
            (Self::References(agreed), Self::References(current)) => {
                !current.difference(agreed).is_empty()
            }
            _ => unreachable!("one agreement contains one kind"),
        }
    }

    fn union(&mut self, other: Self) {
        match (self, other) {
            (Self::Records(target), Self::Records(other)) => target.union(other),
            (
                Self::Authorization(collection, target),
                Self::Authorization(other_collection, other),
            ) => {
                assert_eq!(*collection, other_collection);
                target.union(other);
            }
            (Self::References(target), Self::References(other)) => target.union(other),
            _ => unreachable!("one agreement contains one kind"),
        }
    }

    /// The summary of the subtree at `locator`, relative to the kind's base,
    /// if present.
    pub(crate) fn at(&self, locator: &[u8]) -> Option<PatchSummary> {
        match self {
            Self::Records(patch) => node_summary(patch, locator),
            Self::Authorization(collection, patch) => {
                node_summary(patch, &[&collection.raw[..], locator].concat())
            }
            Self::References(patch) => node_summary(patch, locator),
        }
    }

    /// Exactly the immutable set difference against the shared agreement.
    fn difference(&self, agreed: &Self) -> Self {
        match (self, agreed) {
            (Self::Records(patch), Self::Records(agreed)) => {
                Self::Records(patch.difference(agreed))
            }
            (Self::Authorization(collection, patch), Self::Authorization(_, agreed)) => {
                Self::Authorization(*collection, patch.difference(agreed))
            }
            (Self::References(patch), Self::References(agreed)) => {
                Self::References(patch.difference(agreed))
            }
            _ => unreachable!("one agreement contains one kind"),
        }
    }

    /// The canonical prefix and immediate child prefixes of a local subtree.
    /// These are traversal positions, never a child-list wire payload.
    fn shape(&self, prefix: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
        fn shape<const N: usize, V>(
            patch: &PATCH<N, IdentitySchema, V, Blake3Merkle>,
            base: &[u8],
            prefix: &[u8],
        ) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
            let absolute = [base, prefix].concat();
            let node = patch.merkle_node(&absolute)?;
            let canonical = node.prefix().strip_prefix(base)?.to_vec();
            let children = node
                .children()
                .map(|(_, child)| child.prefix().strip_prefix(base).unwrap().to_vec())
                .collect();
            Some((canonical, children))
        }
        match self {
            Self::Records(patch) => shape(patch, &[], prefix),
            Self::Authorization(collection, patch) => shape(patch, &collection.raw, prefix),
            Self::References(patch) => shape(patch, &[], prefix),
        }
    }

    fn insert(&mut self, key: [u8; KEY_BYTES], value: Value) {
        match (self, value) {
            (Self::Records(patch), Value::Record(record)) => {
                patch.insert(&Entry::with_value(&key, record));
            }
            (Self::Authorization(collection, patch), Value::Proof(proof)) => {
                let mut absolute = [0; 64];
                absolute[..KEY_BYTES].copy_from_slice(&collection.raw);
                absolute[KEY_BYTES..].copy_from_slice(&key);
                patch.insert(&Entry::with_value(&absolute, proof));
            }
            (Self::References(patch), Value::Handle) => patch.insert(&Entry::new(&key)),
            _ => unreachable!("a value of another kind"),
        }
    }

    /// Populate peer membership from an exact held subtree commitment.
    /// A whole root shares its immutable PATCH; non-root inclusion currently
    /// enumerates only that subtree, not a catalogue of the live store.
    fn include_at(&mut self, source: &Self, locator: &[u8]) {
        if locator.is_empty() {
            self.union(source.clone());
            return;
        }
        match (self, source) {
            (Self::Records(target), Self::Records(source)) => {
                if let Some(node) = source.merkle_node(locator) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::with_value(&key, *source.get(&key).unwrap()));
                    }
                }
            }
            (Self::Authorization(collection, target), Self::Authorization(_, source)) => {
                let absolute = [&collection.raw[..], locator].concat();
                if let Some(node) = source.merkle_node(&absolute) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::with_value(&key, source.get(&key).unwrap().clone()));
                    }
                }
            }
            (Self::References(target), Self::References(source)) => {
                if let Some(node) = source.merkle_node(locator) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::new(&key));
                    }
                }
            }
            _ => unreachable!("one agreement contains one kind"),
        }
    }
}

fn empty() -> PatchSummary {
    PatchSummary::new(None, 0).expect("the empty summary is canonical")
}

/// What an exchange asks of its driver.
#[derive(Debug)]
pub(crate) enum Out {
    Send(Frame),
    Land(Vec<NetEvent>),
    Fetch {
        handle: RawHash,
        proof: Option<CapabilityProof>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Confirmed,
    Failed(Failure),
}

/// What landed stays; any failure forgets reusable agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    Unavailable,
    Protocol,
    /// A noncanonical prefix, wrong commitment or leaf digest.
    BadNode,
    BadValue,
    /// The reconstructed peer delta is not its advertised complete tree.
    CountMismatch,
    InsertFailed,
    DeferredProof,
}

pub(crate) struct Ended {
    pub(crate) sends: bool,
    pub(crate) receives: bool,
    /// Directional receipt: the peer's LANDED, independently of shared G.
    pub(crate) confirmed: bool,
    pub(crate) landed: bool,
    /// Physical pinned observation, not the advertised delta summary.
    pub(crate) root: PatchSummary,
    /// Logical peer held view G ∪ Δpeer, not a physical publication frontier.
    pub(crate) peer_root: Option<PatchSummary>,
    pub(crate) agreed: Option<Arc<Tree>>,
}

pub(crate) struct Exchange {
    collection: CollectionHandle,
    kind: WalkKind,
    pinned: Arc<CollectionSnapshot>,
    sends: bool,
    receives: bool,
    agreed: Option<Arc<Tree>>,
    /// Immutable native PATCH difference pinned \ G, empty if not sending.
    delta: Tree,
    /// Essential protocol membership proof of ONLY the peer's delta. This
    /// shares known immutable trees; it is not a catalogue of the local store.
    peer: Tree,
    snapshot: Option<Arc<StoreSnapshot>>,
    root_sent: bool,
    queue: VecDeque<Vec<u8>>,
    announced: PATCH<33, IdentitySchema, ()>,
    done_sent: bool,
    peer_root: Option<PatchSummary>,
    /// Every received commitment, once. Unknown hashes remain provisional.
    commitments: PATCH<33, IdentitySchema, PatchSummary>,
    wanted: VecDeque<[u8; KEY_BYTES]>,
    requests: PATCH<KEY_BYTES, IdentitySchema, ()>,
    fetching: usize,
    unlanded: usize,
    failed: u64,
    deferred: bool,
    peer_done: bool,
    landed_sent: bool,
    landed_received: bool,
    outcome: Option<Outcome>,
}

impl Exchange {
    pub(crate) fn start(
        collection: CollectionHandle,
        kind: WalkKind,
        pinned: Arc<CollectionSnapshot>,
        agreed: Option<Arc<Tree>>,
        sends: bool,
        receives: bool,
    ) -> Self {
        let mine = Tree::pinned(kind, pinned.repair());
        let delta = if sends {
            agreed
                .as_ref()
                .map_or_else(|| mine.clone(), |agreed| mine.difference(agreed))
        } else {
            Tree::empty(kind, collection)
        };
        Self {
            collection,
            kind,
            pinned,
            sends,
            receives,
            agreed,
            delta,
            peer: Tree::empty(kind, collection),
            snapshot: None,
            root_sent: false,
            queue: VecDeque::new(),
            announced: PATCH::new(),
            done_sent: false,
            peer_root: None,
            commitments: PATCH::new(),
            wanted: VecDeque::new(),
            requests: PATCH::new(),
            fetching: 0,
            unlanded: 0,
            failed: 0,
            deferred: false,
            peer_done: false,
            landed_sent: false,
            landed_received: false,
            outcome: None,
        }
    }

    pub(crate) fn receives(&self) -> bool {
        self.receives
    }
    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// Root is an ordinary empty-prefix announcement. A singleton additionally
    /// needs its full-depth key announcement. No read or reply gates this FIFO.
    pub(crate) fn next_delta(&mut self) -> Option<Frame> {
        if self.outcome.is_some() || self.done_sent {
            return None;
        }
        let prefix = if !self.root_sent {
            self.root_sent = true;
            Vec::new()
        } else {
            match self.queue.pop_front() {
                Some(prefix) => prefix,
                None => {
                    self.done_sent = true;
                    return Some(Frame::Done);
                }
            }
        };
        let declared = self.delta.at(&prefix).unwrap_or_else(empty);
        if declared.root().is_some() {
            let matched = self.announced.get(&locator_key(&prefix)).is_some();
            self.announced.remove(&locator_key(&prefix));
            if !matched {
                let (canonical, mut children) = self.delta.shape(&prefix).expect("local subtree");
                if prefix.is_empty() && !canonical.is_empty() {
                    children = vec![canonical];
                }
                for child in children {
                    self.queue.push_back(child);
                    if self.queue.len() > FLOOD_LOCATORS {
                        self.fail(Failure::Protocol);
                        return None;
                    }
                }
            }
        }
        Some(Frame::Subtree {
            prefix,
            summary: declared,
        })
    }

    pub(crate) fn on_frame(
        &mut self,
        frame: Frame,
        snapshot: Option<Arc<StoreSnapshot>>,
    ) -> Vec<Out> {
        let mut outs = Vec::new();
        if self.outcome.is_some() {
            return outs;
        }
        self.snapshot = snapshot;
        if let Err(failure) = self.frame(frame, &mut outs) {
            self.fail(failure);
        }
        self.settle(&mut outs);
        outs
    }

    pub(crate) fn on_landed_ack(&mut self, landed: u64, failed: u64) -> Vec<Out> {
        let mut outs = Vec::new();
        self.unlanded = self
            .unlanded
            .saturating_sub(usize::try_from(landed + failed).unwrap_or(usize::MAX));
        self.failed += failed;
        self.settle(&mut outs);
        outs
    }

    pub(crate) fn on_fetched(
        &mut self,
        handle: RawHash,
        proof: Option<CapabilityProof>,
        blob: Option<Blob<UnknownBlob>>,
    ) -> Vec<Out> {
        let mut outs = Vec::new();
        self.fetching = self.fetching.saturating_sub(1);
        let admit = admit_fetched(self.collection, handle, proof, blob);
        self.admit(admit, &mut outs);
        self.settle(&mut outs);
        outs
    }

    pub(crate) fn want_read(&self) -> bool {
        self.outcome.is_none() && self.unlanded < MAX_WALK_UNLANDED
    }

    pub(crate) fn awaits(&self) -> bool {
        !self.peer_done || !self.requests.is_empty()
    }

    pub(crate) fn end(self) -> Ended {
        let confirmed = self.outcome == Some(Outcome::Confirmed);
        let next = confirmed.then(|| self.union_tree());
        let peer_root = self.peer_root.map(|_| {
            let mut peer = self
                .agreed
                .as_deref()
                .cloned()
                .unwrap_or_else(|| Tree::empty(self.kind, self.collection));
            peer.union(self.peer);
            peer.summary()
        });
        Ended {
            sends: self.sends,
            receives: self.receives,
            confirmed: self.landed_received,
            landed: self.landed_sent,
            root: summary(self.kind, self.pinned.repair()),
            peer_root,
            agreed: next.map(Arc::new),
        }
    }

    fn union_tree(&self) -> Tree {
        let mut union = self
            .agreed
            .as_deref()
            .cloned()
            .unwrap_or_else(|| Tree::empty(self.kind, self.collection));
        union.union(self.delta.clone());
        union.union(self.peer.clone());
        union
    }

    fn frame(&mut self, frame: Frame, outs: &mut Vec<Out>) -> Result<(), Failure> {
        match frame {
            Frame::Open { .. } => Err(Failure::Protocol),
            Frame::Subtree {
                prefix,
                summary: declared,
            } => {
                if prefix.len() > KEY_BYTES {
                    return Err(Failure::BadNode);
                }
                if self.peer_done {
                    return Err(Failure::Protocol);
                }
                if prefix.is_empty() {
                    if self.peer_root.is_some() {
                        return Err(Failure::Protocol);
                    }
                    self.peer_root = Some(declared);
                } else {
                    self.arriving()?;
                    if declared.root().is_none() {
                        return Err(Failure::BadNode);
                    }
                }
                if declared.leaf_count() > FLOOD_LOCATORS as u64 {
                    return Err(Failure::Protocol);
                }
                let key = locator_key(&prefix);
                if self.commitments.get(&key).is_some() {
                    return Err(Failure::Protocol);
                }
                if self.commitments.len() >= FLOOD_LOCATORS as u64 {
                    return Err(Failure::Protocol);
                }
                self.commitments.insert(&Entry::with_value(&key, declared));

                // Our outgoing DIFFERENCE is the only tree whose traversal
                // this claim can prune. Still emit this prefix once ourselves.
                if declared.root().is_some() && self.delta.at(&prefix) == Some(declared) {
                    if self.announced.len() >= FLOOD_LOCATORS as u64 {
                        return Err(Failure::Protocol);
                    }
                    self.announced.insert(&Entry::new(&key));
                    self.queue
                        .retain(|queued| queued == &prefix || !queued.starts_with(&prefix));
                }
                if !self.receives || declared.root().is_none() {
                    return Ok(());
                }
                if prefix.len() == KEY_BYTES {
                    let leaf: [u8; KEY_BYTES] = prefix.clone().try_into().unwrap();
                    let base = crate::walk::base(self.kind, self.collection);
                    if declared.leaf_count() != 1
                        || declared.root()
                            != Some(<Blake3Merkle as PatchHash>::leaf(&[base, prefix].concat()))
                    {
                        return Err(Failure::BadNode);
                    }
                    return self.leaf(leaf);
                }
                // An exact held subtree can close this portion without any
                // descendants, but only into the peer's separate delta view.
                let held = if self.delta.at(&prefix) == Some(declared) {
                    Some(self.delta.clone())
                } else if self.agreed.as_ref().and_then(|tree| tree.at(&prefix)) == Some(declared) {
                    self.agreed.as_deref().cloned()
                } else {
                    let pinned = Tree::pinned(self.kind, self.pinned.repair());
                    (pinned.at(&prefix) == Some(declared)).then_some(pinned)
                };
                if let Some(held) = held {
                    self.peer.include_at(&held, &prefix);
                    self.proof_budget()?;
                }
                Ok(())
            }
            Frame::Value { key, bytes } => {
                if self.requests.get(&key).is_none() {
                    return Err(Failure::Protocol);
                }
                self.requests.remove(&key);
                let live = self.live()?;
                let (value, admit) = admit_value(
                    self.kind,
                    self.collection,
                    key,
                    &bytes,
                    live.repair().authorization_evidence(),
                )
                .map_err(|_| Failure::BadValue)?;
                self.peer.insert(key, value);
                self.proof_budget()?;
                self.admit(admit, outs);
                Ok(())
            }
            Frame::ValueRequest { key } => {
                if !self.sends {
                    return Err(Failure::Protocol);
                }
                // Only the immutable advertised delta serves requests, never
                // an unrelated private key or an omitted AGREED sibling.
                let bytes = self
                    .delta_value(key)
                    .and_then(|value| value.bytes(self.collection))
                    .ok_or(Failure::Protocol)?;
                outs.push(Out::Send(Frame::Value { key, bytes }));
                Ok(())
            }
            Frame::Done => {
                self.arriving()?;
                self.peer_done = true;
                Ok(())
            }
            Frame::Landed => {
                if !self.done_sent || self.landed_received {
                    return Err(Failure::Protocol);
                }
                self.landed_received = true;
                Ok(())
            }
        }
    }

    fn delta_value(&self, key: [u8; KEY_BYTES]) -> Option<Value> {
        match &self.delta {
            Tree::Records(patch) => patch.get(&key).copied().map(Value::Record),
            Tree::Authorization(collection, patch) => {
                let absolute: [u8; 64] = [collection.raw.as_slice(), key.as_slice()]
                    .concat()
                    .try_into()
                    .unwrap();
                patch.get(&absolute).cloned().map(Value::Proof)
            }
            Tree::References(_) => None,
        }
    }

    fn arriving(&self) -> Result<PatchSummary, Failure> {
        match self.peer_root {
            Some(root) if !self.peer_done => Ok(root),
            _ => Err(Failure::Protocol),
        }
    }

    fn live(&self) -> Result<Arc<CollectionSnapshot>, Failure> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(self.collection))
            .ok_or(Failure::Unavailable)
    }

    fn proof_budget(&self) -> Result<(), Failure> {
        if self.peer.summary().leaf_count() > FLOOD_LOCATORS as u64 {
            Err(Failure::Protocol)
        } else {
            Ok(())
        }
    }

    fn leaf(&mut self, key: [u8; KEY_BYTES]) -> Result<(), Failure> {
        if self.remember(key)? {
            return Ok(());
        }
        if self.wanted.len() >= FLOOD_WANTED {
            return Err(Failure::Protocol);
        }
        self.wanted.push_back(key);
        Ok(())
    }

    /// Live held typed values avoid refetch even when publication moved since
    /// our pin; only the declared leaf enters the independent peer proof.
    fn remember(&mut self, key: [u8; KEY_BYTES]) -> Result<bool, Failure> {
        let live = self.live()?;
        let Some(value) = value(self.kind, live.repair(), key) else {
            return Ok(false);
        };
        self.peer.insert(key, value);
        self.proof_budget()?;
        Ok(true)
    }

    /// Close actual membership, not frame counts or the local union hash.
    fn verify_delta(&self) -> Result<(), Failure> {
        let root = self.peer_root.ok_or(Failure::Protocol)?;
        if self.peer.summary() != root {
            return Err(Failure::CountMismatch);
        }
        for key in self.commitments.iter() {
            let depth = usize::from(key[0]);
            let prefix = &key[1..1 + depth];
            let declared = *self.commitments.get(key).unwrap();
            if self.peer.at(prefix).unwrap_or_else(empty) != declared {
                return Err(Failure::BadNode);
            }
            if !prefix.is_empty()
                && self
                    .peer
                    .shape(prefix)
                    .as_ref()
                    .map(|(canonical, _)| canonical.as_slice())
                    != Some(prefix)
            {
                return Err(Failure::BadNode);
            }
        }
        Ok(())
    }

    fn admit(&mut self, admit: Admit, outs: &mut Vec<Out>) {
        match admit {
            Admit::Land(events) => {
                self.unlanded += events.len();
                outs.push(Out::Land(events));
            }
            Admit::Fetch { handle, proof } => {
                self.fetching += 1;
                outs.push(Out::Fetch { handle, proof });
            }
            Admit::Defer => self.deferred = true,
            Admit::Fail => self.failed += 1,
        }
    }

    fn fail(&mut self, failure: Failure) {
        self.outcome = Some(Outcome::Failed(failure));
    }

    fn settle(&mut self, outs: &mut Vec<Out>) {
        if self.outcome.is_some() {
            return;
        }
        while self.requests.len() as usize + self.fetching < MAX_WALK_REQUESTS
            && let Some(key) = self.wanted.pop_front()
        {
            match admit_missing(self.kind, self.collection, key, self.snapshot.as_deref()) {
                Some(admit) => {
                    self.peer.insert(key, Value::Handle);
                    if let Err(failure) = self.proof_budget() {
                        return self.fail(failure);
                    }
                    self.admit(admit, outs);
                }
                None => {
                    self.requests.insert(&Entry::new(&key));
                    outs.push(Out::Send(Frame::ValueRequest { key }));
                }
            }
        }
        if !self.landed_sent
            && self.peer_done
            && self.wanted.is_empty()
            && self.requests.is_empty()
            && self.fetching == 0
            && self.unlanded == 0
        {
            if self.failed > 0 {
                return self.fail(Failure::InsertFailed);
            }
            if self.deferred {
                return self.fail(Failure::DeferredProof);
            }
            if self.receives
                && let Err(failure) = self.verify_delta()
            {
                return self.fail(failure);
            }
            self.landed_sent = true;
            outs.push(Out::Send(Frame::Landed));
        }
        if self.landed_sent && self.landed_received {
            self.outcome = Some(Outcome::Confirmed);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use triblespace_core::capability::CapabilityProofId;
    use triblespace_core::collection::{
        CollectionData, CollectionMerge, CollectionRecord, CollectionRecordFingerprint,
        CollectionStore,
    };

    use crate::patch_repair::{PatchBranch, PatchChild, PatchNode};
    use crate::walk::node;

    use crate::collection_delta::{decode_record, encode_record};
    use crate::walk::tests::walking::{Node, open};

    fn root(summary: PatchSummary) -> Frame {
        Frame::Subtree {
            prefix: Vec::new(),
            summary,
        }
    }

    fn leaf(key: [u8; KEY_BYTES]) -> Frame {
        Frame::Subtree {
            prefix: key.to_vec(),
            summary: PatchSummary::new(Some(<Blake3Merkle as PatchHash>::leaf(&key)), 1).unwrap(),
        }
    }

    fn announcement(prefix: Vec<u8>, node: PatchNode<()>) -> Frame {
        Frame::Subtree {
            prefix,
            summary: PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap(),
        }
    }

    fn roundtrip(frame: Frame) -> Frame {
        let (kind, payload) = frame.encode();
        Frame::decode(kind, &payload).unwrap().unwrap()
    }

    pub(crate) struct Side {
        pub(crate) node: Node,
        pub(crate) exchange: Exchange,
        /// Every frame this side sent, in order.
        pub(crate) sent: Vec<Frame>,
        /// Every frame this side heard, in order.
        pub(crate) heard: Vec<Frame>,
        outbox: VecDeque<Frame>,
        pub(crate) hold: bool,
        /// Whether this harness publishes a new serving observation for each
        /// individual landing. Physical insertion/ack is still immediate.
        observe_landings: bool,
        pub(crate) held: Vec<Vec<NetEvent>>,
        pub(crate) fetches: Vec<(RawHash, Option<CapabilityProof>)>,
    }

    impl Side {
        /// `node`'s side of an exchange of C's `kind` tree against `agreed`.
        pub(crate) fn new(
            node: Node,
            collection: CollectionHandle,
            kind: WalkKind,
            agreed: Option<Arc<Tree>>,
            sends: bool,
            receives: bool,
        ) -> Self {
            let pinned = node.pinned(collection);
            Self {
                exchange: Exchange::start(collection, kind, pinned, agreed, sends, receives),
                node,
                sent: Vec::new(),
                heard: Vec::new(),
                outbox: VecDeque::new(),
                hold: false,
                observe_landings: true,
                held: Vec::new(),
                fetches: Vec::new(),
            }
        }

        /// Both ways, against nothing.
        pub(crate) fn both(node: Node, collection: CollectionHandle, kind: WalkKind) -> Self {
            Self::new(node, collection, kind, None, true, true)
        }

        /// Hear one frame, keeping the answers for [`Self::next`].
        pub(crate) fn hear(&mut self, frame: Frame) {
            let frame = roundtrip(frame);
            self.heard.push(frame.clone());
            let outs = self.exchange.on_frame(frame, Some(self.node.snapshot()));
            self.outputs(outs);
        }

        /// Hear one frame; the frames sent back.
        pub(crate) fn feed(&mut self, frame: Frame) -> Vec<Frame> {
            self.hear(frame);
            self.replies()
        }

        /// Take every frame waiting to be sent.
        pub(crate) fn replies(&mut self) -> Vec<Frame> {
            let replies = std::mem::take(&mut self.outbox);
            self.sent.extend(replies.iter().cloned());
            replies.into()
        }

        /// The next frame to send: an answer, or the next of the delta.
        pub(crate) fn next(&mut self) -> Option<Frame> {
            let frame = self
                .outbox
                .pop_front()
                .or_else(|| self.exchange.next_delta())?;
            self.sent.push(frame.clone());
            Some(frame)
        }

        pub(crate) fn outputs(&mut self, outs: Vec<Out>) {
            for out in outs {
                match out {
                    Out::Send(frame) => self.outbox.push_back(frame),
                    Out::Land(events) if self.hold => self.held.push(events),
                    Out::Land(events) => self.land(events),
                    Out::Fetch { handle, proof } => self.fetches.push((handle, proof)),
                }
            }
        }

        /// Insert, publish and acknowledge, as the landing task does.
        pub(crate) fn land(&mut self, events: Vec<NetEvent>) {
            let (landed, failed) = self.node.insert(events);
            if self.observe_landings {
                self.node.observe();
            }
            let outs = self.exchange.on_landed_ack(landed, failed);
            self.outputs(outs);
        }

        pub(crate) fn release(&mut self) {
            self.hold = false;
            for events in std::mem::take(&mut self.held) {
                self.land(events);
            }
        }

        pub(crate) fn requested(&self) -> BTreeSet<[u8; 32]> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::ValueRequest { key } => Some(*key),
                    _ => None,
                })
                .collect()
        }

        /// The prefixes of the NODEs sent, in order.
        pub(crate) fn nodes(&self) -> Vec<Vec<u8>> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Subtree { prefix, .. } if prefix.len() < KEY_BYTES => {
                        Some(prefix.clone())
                    }
                    _ => None,
                })
                .collect()
        }

        /// The keys of the LEAFs sent, in order.
        pub(crate) fn leaves(&self) -> Vec<[u8; 32]> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Subtree { prefix, .. } if prefix.len() == KEY_BYTES => {
                        Some(prefix.as_slice().try_into().unwrap())
                    }
                    _ => None,
                })
                .collect()
        }

        pub(crate) fn count(&self, same: impl Fn(&Frame) -> bool) -> usize {
            self.sent.iter().filter(|frame| same(frame)).count()
        }

        pub(crate) fn outcome(&self) -> Option<Outcome> {
            self.exchange.outcome()
        }

        /// The agreed root the exchange ended with, if it confirmed.
        pub(crate) fn agreed(&self) -> Option<PatchSummary> {
            (self.outcome() == Some(Outcome::Confirmed))
                .then(|| self.exchange.union_tree().summary())
        }
    }

    pub(crate) fn carry(a: &mut Side, b: &mut Side) {
        loop {
            let mut moved = false;
            if let Some(frame) = a.next() {
                b.hear(frame);
                moved = true;
            }
            if let Some(frame) = b.next() {
                a.hear(frame);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    pub(crate) fn burst(a: &mut Side, b: &mut Side) {
        loop {
            let mut moved = false;
            while let Some(frame) = a.next() {
                b.hear(frame);
                moved = true;
            }
            while let Some(frame) = b.next() {
                a.hear(frame);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    fn fingerprints(records: impl IntoIterator<Item = CollectionRecord>) -> BTreeSet<[u8; 32]> {
        records
            .into_iter()
            .map(|record| record.fingerprint().raw())
            .collect()
    }

    fn value_of(
        node: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        key: [u8; 32],
    ) -> Vec<u8> {
        let overlay = node.pinned(collection);
        match kind {
            WalkKind::Records => overlay
                .repair()
                .records()
                .get(CollectionRecordFingerprint::from_raw(key))
                .map(|record| encode_record(collection, record).unwrap())
                .unwrap(),
            WalkKind::Authorization => overlay
                .repair()
                .authorization_evidence()
                .get(CapabilityProofId::new(key))
                .map(|proof| proof.as_bytes().to_vec())
                .unwrap(),
            WalkKind::References => panic!("held references carry no values"),
        }
    }

    fn tree(
        sender: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        omit: &BTreeSet<[u8; 32]>,
    ) -> Vec<Frame> {
        let mut exchange = Exchange::start(
            collection,
            kind,
            sender.pinned(collection),
            None,
            true,
            false,
        );
        let mut frames = Vec::new();
        while let Some(frame) = exchange.next_delta() {
            if let Frame::Subtree { prefix, .. } = &frame
                && prefix.len() == KEY_BYTES
                && omit.contains(&<[u8; 32]>::try_from(prefix.as_slice()).unwrap())
            {
                continue;
            }
            frames.push(frame);
        }
        frames
    }

    fn stream(
        side: &mut Side,
        sender: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        omit: &BTreeSet<[u8; 32]>,
    ) -> Vec<Frame> {
        let mut streamed = Vec::new();
        let mut landed = false;
        let mut send = |side: &mut Side, frame: Frame| {
            streamed.push(frame.clone());
            let mut replies = side.feed(frame);
            while let Some(reply) = replies.pop() {
                match reply {
                    Frame::ValueRequest { key } => {
                        let value = Frame::Value {
                            key,
                            bytes: value_of(sender, collection, kind, key),
                        };
                        streamed.push(value.clone());
                        replies.extend(side.feed(value));
                    }
                    Frame::Done if !landed => {
                        landed = true;
                        streamed.push(Frame::Landed);
                        replies.extend(side.feed(Frame::Landed));
                    }
                    _ => {}
                }
            }
        };
        for frame in tree(sender, collection, kind, omit) {
            send(side, frame);
        }
        // The side's own delta, which the scripted peer ignores.
        while let Some(frame) = side.next() {
            if frame == Frame::Done && !landed {
                landed = true;
                streamed.push(Frame::Landed);
                for reply in side.feed(Frame::Landed) {
                    if let Frame::ValueRequest { key } = reply {
                        let value = Frame::Value {
                            key,
                            bytes: value_of(sender, collection, kind, key),
                        };
                        streamed.push(value.clone());
                        side.feed(value);
                    }
                }
            }
        }
        streamed
    }

    fn fabricated(wide: usize, deep: usize) -> (PatchSummary, Frame, Vec<(Frame, Vec<Frame>)>) {
        let tree_to_key = (0..KEY_BYTES).collect::<Vec<_>>();
        let branch = |representative: Vec<u8>, end_depth: usize, children: Vec<PatchChild>| {
            let leaf_count = children.iter().map(|child| child.leaf_count).sum();
            let mut state = <Blake3Merkle as PatchHash>::begin_branch(
                &representative,
                &tree_to_key,
                end_depth,
                children.len(),
                leaf_count,
            );
            for child in &children {
                <Blake3Merkle as PatchHash>::push_child(
                    &mut state,
                    child.edge,
                    child.leaf_count,
                    child.digest,
                );
            }
            PatchNode::Branch {
                digest: <Blake3Merkle as PatchHash>::finish_branch(state),
                leaf_count,
                branch: PatchBranch {
                    representative,
                    end_depth: end_depth as u8,
                    children,
                },
            }
        };
        let mut branches = Vec::new();
        let mut children = Vec::new();
        for edge in 0..wide {
            let edge = u8::try_from(edge).unwrap();
            let (mut leaves, mut under) = (Vec::new(), Vec::new());
            for index in 0..deep {
                let mut key = [0; KEY_BYTES];
                key[0] = edge;
                key[1] = u8::try_from(index).unwrap();
                under.push(PatchChild {
                    edge: key[1],
                    digest: <Blake3Merkle as PatchHash>::leaf(&key),
                    leaf_count: 1,
                });
                leaves.push(leaf(key));
            }
            let mut representative = vec![0; KEY_BYTES];
            representative[0] = edge;
            let node = branch(representative, 1, under);
            children.push(PatchChild {
                edge,
                digest: node.digest(),
                leaf_count: node.leaf_count(),
            });
            branches.push((announcement(vec![edge], node), leaves));
        }
        let node = branch(vec![0; KEY_BYTES], 0, children);
        let root = PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap();
        (root, announcement(Vec::new(), node), branches)
    }

    fn holding(
        byte: u8,
        name: &str,
        count: u64,
    ) -> (Node, CollectionHandle, Vec<CollectionRecord>) {
        let mut node = Node::new(byte);
        let collection = node.hold(name, open());
        let records = (0..count)
            .map(|data| node.commit(collection, data))
            .collect::<Vec<_>>();
        node.observe();
        (node, collection, records)
    }

    fn sharing(byte: u8, name: &str, records: &[CollectionRecord]) -> (Node, CollectionHandle) {
        let mut node = Node::new(byte);
        let collection = node.hold(name, open());
        for record in records {
            node.store.insert(*record).unwrap();
        }
        node.observe();
        (node, collection)
    }

    #[test]
    fn a_first_exchange_streams_the_whole_tree_to_an_empty_peer() {
        let (full, collection, records) = holding(30, "whole", 300);
        let (empty, _) = sharing(31, "whole", &[]);
        let expected = tree(&full, collection, WalkKind::Records, &BTreeSet::new());
        let root_summary = summary(WalkKind::Records, full.pinned(collection).repair());
        let mut full = Side::both(full, collection, WalkKind::Records);
        let mut empty = Side::both(empty, collection, WalkKind::Records);
        burst(&mut full, &mut empty);
        assert_eq!(full.outcome(), Some(Outcome::Confirmed));
        assert_eq!(empty.outcome(), Some(Outcome::Confirmed));
        assert_eq!(full.sent[..expected.len()], expected);
        assert_eq!(
            full.leaves().into_iter().collect::<BTreeSet<_>>(),
            fingerprints(records.iter().copied())
        );
        assert_eq!(empty.nodes(), [Vec::<u8>::new()]);
        assert!(empty.leaves().is_empty());
        assert_eq!(empty.requested(), fingerprints(records.iter().copied()));
        assert_eq!(empty.sent.len(), 303);
        assert_eq!(
            empty.node.records(collection),
            records.iter().copied().collect()
        );
        assert_eq!(full.agreed(), Some(root_summary));
        assert_eq!(empty.agreed(), Some(root_summary));
        eprintln!(
            "PREFIX_FIRST_EMPTY leaves=300 subtree_frames={} reply_waits=0 scheduler=full_delta_burst_before_peer_replies",
            full.nodes().len() + full.leaves().len()
        );
    }

    #[test]
    fn an_unchanged_tree_against_the_agreed_tree_is_root_then_done() {
        let (a, collection, records) = holding(32, "same", 50);
        let (b, _) = sharing(33, "same", &records);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, a.pinned(collection).repair()));
        let mut a = Side::new(a, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b, collection, kind, Some(agreed.clone()), true, true);
        carry(&mut a, &mut b);
        for side in [&a, &b] {
            assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            assert_eq!(side.sent[0], root(empty()));
            assert!(
                side.sent[1..] == [Frame::Done, Frame::Landed]
                    || side.sent[1..] == [Frame::Landed, Frame::Done]
            );
            assert_eq!(side.agreed(), Some(agreed.summary()));
        }
        let (blank, collection) = sharing(34, "empty", &[]);
        let mut blank = Side::both(blank, collection, WalkKind::Authorization);
        assert_eq!(blank.next(), Some(root(empty())));
        assert_eq!(blank.next(), Some(Frame::Done));
        assert_eq!(blank.next(), None);
    }

    #[test]
    fn a_match_that_arrives_mid_level_drops_the_work_queued_under_it() {
        let (a, collection, _) = holding(35, "mid", 300);
        let mut a = Side::new(a, collection, WalkKind::Records, None, true, false);
        assert!(matches!(a.next(), Some(Frame::Subtree { prefix, .. }) if prefix.is_empty()));
        let first = loop {
            match a.next() {
                Some(Frame::Subtree { prefix, .. }) if prefix.len() < KEY_BYTES => break prefix,
                Some(Frame::Subtree { .. }) => continue,
                other => panic!("first branch: {other:?}"),
            }
        };
        assert!(
            a.exchange
                .queue
                .iter()
                .any(|queued| queued.starts_with(&first))
        );
        let declared = a.exchange.delta.at(&first).unwrap();
        a.hear(root(PatchSummary::new(Some([0xAA; 32]), 300).unwrap()));
        a.hear(Frame::Subtree {
            prefix: first.clone(),
            summary: declared,
        });
        assert!(
            a.exchange
                .queue
                .iter()
                .all(|queued| !queued.starts_with(&first))
        );
        while let Some(frame) = a.next() {
            if let Frame::Subtree { prefix, .. } = frame {
                assert!(!prefix.starts_with(&first));
            }
        }
        assert!(a.sent.contains(&Frame::Done));
    }

    #[test]
    fn an_equal_root_announcement_ends_the_delta() {
        let (a, collection, _) = holding(36, "equal", 300);
        let kind = WalkKind::Records;
        let root = summary(kind, a.pinned(collection).repair());
        let mut a = Side::new(a, collection, kind, None, true, true);
        assert_eq!(
            a.next(),
            Some(Frame::Subtree {
                prefix: Vec::new(),
                summary: root
            })
        );
        assert_eq!(
            a.feed(Frame::Subtree {
                prefix: Vec::new(),
                summary: root
            }),
            []
        );
        assert_eq!(a.next(), Some(Frame::Done));
        assert_eq!(a.feed(Frame::Done), [Frame::Landed]);
        assert_eq!(a.feed(Frame::Landed), []);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.agreed(), Some(root));
    }

    #[test]
    fn both_sides_compute_the_same_agreed_tree() {
        let (a, collection, records) = holding(37, "union", 200);
        let (mut b, _) = sharing(38, "union", &records[100..]);
        let own = (0..100)
            .map(|data| b.commit(collection, 1_000 + data))
            .collect::<Vec<_>>();
        b.observe();
        let kind = WalkKind::Records;
        let mut a = Side::both(a, collection, kind);
        let mut b = Side::both(b, collection, kind);
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.requested().len(), 100);
        assert_eq!(b.requested().len(), 100);
        let union = records.iter().chain(&own).copied().collect::<BTreeSet<_>>();
        assert_eq!(a.node.records(collection), union);
        assert_eq!(b.node.records(collection), union);
        let expected = summary(kind, a.node.pinned(collection).repair());
        assert_eq!(a.agreed(), Some(expected));
        assert_eq!(b.agreed(), Some(expected));
        for locator in [
            &[][..],
            &[own[0].fingerprint().raw()[0]],
            &records[0].fingerprint().raw()[..2],
        ] {
            assert_eq!(
                a.exchange.union_tree().at(locator),
                b.exchange.union_tree().at(locator)
            );
        }
    }

    #[test]
    fn a_side_that_sends_nothing_agrees_on_the_peer_s_tree() {
        let (writer, collection, records) = holding(39, "one way", 20);
        let (mut owner, _) = sharing(40, "one way", &records[..10]);
        owner.commit(collection, 1_000);
        owner.observe();
        let kind = WalkKind::Records;
        let mut writer = Side::new(writer, collection, kind, None, true, false);
        let mut owner = Side::new(owner, collection, kind, None, false, true);
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.requested().len(), 10);
        assert_eq!(owner.node.records(collection).len(), 21);
        assert_eq!(
            owner.sent.first(),
            Some(&Frame::Subtree {
                prefix: Vec::new(),
                summary: empty()
            })
        );
        assert!(
            owner.sent.iter().all(|frame| !matches!(frame, Frame::Subtree {prefix, summary} if !prefix.is_empty() || summary.leaf_count()!=0) && !matches!(frame, Frame::Value {..})),
            "a non-sending peer discloses no private tree or values"
        );
        assert_eq!(writer.node.records(collection).len(), 20);
        let agreed = summary(kind, writer.node.pinned(collection).repair());
        assert_eq!(writer.agreed(), Some(agreed));
        assert_eq!(owner.agreed(), Some(agreed));
        let tree = Arc::new(Tree::pinned(kind, writer.node.pinned(collection).repair()));

        let mut writer = Side::new(
            writer.node,
            collection,
            kind,
            Some(tree.clone()),
            true,
            false,
        );
        let mut owner = Side::new(owner.node, collection, kind, Some(tree), false, true);
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(writer.sent, [root(empty()), Frame::Done, Frame::Landed]);
        assert_eq!(owner.sent.len(), 3);
        assert_eq!(
            owner.sent.first(),
            Some(&Frame::Subtree {
                prefix: Vec::new(),
                summary: empty()
            })
        );
        assert_eq!(owner.agreed(), Some(agreed));
    }

    #[test]
    fn missing_leaves_are_requested_and_land() {
        let (sender, collection, records) = holding(41, "missing", 300);
        let (mut receiver, _) = sharing(42, "missing", &records[..100]);
        let foreign = receiver.commit(collection, 1_000);
        receiver.observe();
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.sent.last(), Some(&Frame::Landed));
        let requested = receiver.requested();
        assert_eq!(requested.len(), 200);
        assert!(
            records
                .iter()
                .skip(100)
                .all(|record| requested.contains(&record.fingerprint().raw()))
        );
        assert_eq!(
            sender.requested(),
            BTreeSet::from([foreign.fingerprint().raw()])
        );
        let mut union = records.iter().copied().collect::<BTreeSet<_>>();
        union.insert(foreign);
        assert_eq!(receiver.node.records(collection), union);
        assert_eq!(sender.node.records(collection), union);
    }

    #[test]
    fn a_subtree_the_peer_announces_is_neither_streamed_nor_asked_for() {
        let (sender, collection, records) = holding(43, "pruned", 400);
        let Some(PatchNode::Branch { branch, .. }) =
            node(WalkKind::Records, sender.pinned(collection).repair(), &[])
        else {
            panic!("400 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        let edge = branch.children[0].edge;
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw()[0] == edge)
            .copied()
            .collect::<Vec<_>>();
        assert!(!shared.is_empty() && shared.len() < records.len());
        let (receiver, _) = sharing(44, "pruned", &shared);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        let streamed = sender.leaves().into_iter().collect::<BTreeSet<_>>();
        let requested = receiver.requested();
        for record in &shared {
            assert!(!streamed.contains(&record.fingerprint().raw()));
            assert!(!requested.contains(&record.fingerprint().raw()));
        }
        assert_eq!(streamed.len(), records.len() - shared.len());
        assert_eq!(requested, streamed);
        assert!(
            sender
                .nodes()
                .iter()
                .all(|prefix| prefix.len() < 2 || prefix[0] != edge)
        );
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
    }

    #[test]
    fn the_root_node_s_announcements_prune_exactly_the_children_the_peer_holds() {
        let (sender, collection, records) = holding(45, "prefix overlap", 3000);
        let edges = [0, 7, 8, 255];
        let held = records
            .iter()
            .filter(|record| edges.contains(&record.fingerprint().raw()[0]))
            .copied()
            .collect::<Vec<_>>();
        let (receiver, _) = sharing(46, "prefix overlap", &held);
        let mut sender = Side::both(sender, collection, WalkKind::Records);
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        for edge in edges {
            let exact = sender
                .nodes()
                .iter()
                .filter(|prefix| **prefix == vec![edge])
                .count();
            assert_eq!(exact, 1);
            assert!(sender.leaves().iter().all(|key| key[0] != edge));
        }
        assert_eq!(receiver.requested().len(), records.len() - held.len());
        assert!(
            receiver
                .leaves()
                .iter()
                .all(|key| held.iter().any(|record| record.fingerprint().raw() == *key))
        );
        eprintln!(
            "PREFIX_PARTIAL_OVERLAP shared_leaves={} small_side_in_flight_leaf_announcements={} scheduler=one_frame_each_direction unequal_frontiers",
            held.len(),
            receiver.leaves().len()
        );
        assert_eq!(sender.agreed(), receiver.agreed());
    }

    #[test]
    fn the_delta_goes_breadth_first() {
        let (sender, collection, _) = holding(47, "breadth", 3000);
        let mut sender = Side::new(sender, collection, WalkKind::Records, None, true, false);
        assert!(matches!(sender.next(), Some(Frame::Subtree { prefix, .. }) if prefix.is_empty()));
        let mut positions = 0;
        while !sender.exchange.queue.is_empty() {
            let front = sender.exchange.queue.front().unwrap().clone();
            let Some(Frame::Subtree { prefix, .. }) = sender.next() else {
                panic!("queued position");
            };
            assert_eq!(prefix, front, "FIFO, including compressed leaf paths");
            positions += 1;
        }
        assert!(positions > 256);
        assert_eq!(sender.next(), Some(Frame::Done));
    }

    #[test]
    fn the_count_proof_fails_on_a_delta_that_omits_a_leaf() {
        let (sender, collection, records) = holding(48, "omitted", 60);
        let (receiver, _) = sharing(49, "omitted", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        let omit = BTreeSet::from([records[7].fingerprint().raw()]);
        stream(&mut receiver, &sender, collection, kind, &omit);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
        assert_eq!(receiver.node.records(collection).len(), 59);
    }

    #[test]
    fn a_failed_insert_yields_no_landed() {
        let (sender, collection, _) = holding(50, "failed", 20);
        let (receiver, _) = sharing(51, "failed", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.hold = true;
        stream(&mut receiver, &sender, collection, kind, &BTreeSet::new());
        assert_eq!(receiver.outcome(), None);
        assert_eq!(receiver.held.len(), 20);
        // One landing comes back failed.
        let failed = receiver.held.pop().unwrap();
        receiver.release();
        assert_eq!(receiver.outcome(), None, "a landing is still owed");
        let outs = receiver.exchange.on_landed_ack(0, failed.len() as u64);
        receiver.outputs(outs);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::InsertFailed))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
        assert_eq!(receiver.node.records(collection).len(), 19);

        // A value that is not a foundation record fails the exchange at
        // once.
        let (receiver, _) = sharing(52, "failed", &[]);
        let mut receiver = Side::both(receiver, collection, kind);
        let Some(Frame::ValueRequest { key }) = tree(&sender, collection, kind, &BTreeSet::new())
            .into_iter()
            .find_map(|frame| {
                receiver
                    .feed(frame)
                    .into_iter()
                    .find(|reply| matches!(reply, Frame::ValueRequest { .. }))
            })
        else {
            panic!("a value was requested");
        };
        let merge = CollectionRecord::Merge(
            CollectionMerge::sign(
                &sender.key,
                collection,
                [CollectionData::new([2; 32]), CollectionData::new([3; 32])],
                CollectionData::new([4; 32]),
            )
            .unwrap(),
        );
        receiver.feed(Frame::Value {
            key,
            bytes: merge.to_bytes(),
        });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadValue)));
        assert!(receiver.node.records(collection).is_empty());
    }

    #[test]
    fn requests_are_windowed_and_reading_stops_at_unlanded_values() {
        let (sender, collection, records) = holding(53, "window", MAX_WALK_UNLANDED as u64 + 100);
        let (receiver, _) = sharing(54, "window", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.hold = true;
        let mut requests = Vec::new();
        for frame in tree(&sender, collection, kind, &BTreeSet::new()) {
            assert!(receiver.exchange.want_read(), "a value is owed");
            requests.extend(
                receiver
                    .feed(frame)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
        }
        assert_eq!(requests.len(), MAX_WALK_REQUESTS);
        assert_eq!(
            receiver.exchange.wanted.len(),
            records.len() - MAX_WALK_REQUESTS
        );
        // Each value answered lets the next leaf be asked for, until the
        // landing task holds the most it may.
        let mut answered = 0;
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value_of(&sender, collection, kind, key),
            };
            requests.extend(
                receiver
                    .feed(value)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
            answered += 1;
            if !receiver.exchange.want_read() {
                break;
            }
        }
        assert_eq!(answered, MAX_WALK_UNLANDED);
        assert_eq!(receiver.held.len(), MAX_WALK_UNLANDED);
        assert!(!receiver.exchange.want_read());
        assert_eq!(receiver.exchange.requests.len(), MAX_WALK_REQUESTS as u64);
        receiver.release();
        assert!(receiver.exchange.want_read());
        // The rest is answered, and once the peer's DONE is in and its
        // LANDED too, everything landed.
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value_of(&sender, collection, kind, key),
            };
            requests.extend(
                receiver
                    .feed(value)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
        }
        assert!(receiver.sent.contains(&Frame::Landed));
        while receiver.next().is_some() {}
        receiver.feed(Frame::Landed);
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
    }

    #[test]
    fn frames_out_of_place_fail_the_exchange() {
        let (sender, collection, records) = holding(55, "order", 1);
        let root_summary = summary(WalkKind::Records, sender.pinned(collection).repair());
        let fresh = |byte| {
            let (node, _) = sharing(byte, "order", &[]);
            Side::both(node, collection, WalkKind::Records)
        };
        for frame in [
            leaf(records[0].fingerprint().raw()),
            Frame::Landed,
            Frame::Open {
                collection,
                kind: WalkKind::Records,
            },
            Frame::ValueRequest { key: [9; 32] },
            Frame::Done,
            Frame::Value {
                key: [1; 32],
                bytes: vec![0],
            },
        ] {
            let mut receiver = fresh(56);
            receiver.feed(frame);
            assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        }
        let mut receiver = fresh(57);
        receiver.feed(root(root_summary));
        receiver.feed(root(root_summary));
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        let mut receiver = fresh(58);
        receiver.feed(root(empty()));
        receiver.feed(Frame::Done);
        receiver.feed(leaf(records[0].fingerprint().raw()));
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        let mut owner = Side::new(sender, collection, WalkKind::Records, None, false, true);
        owner.feed(Frame::ValueRequest {
            key: records[0].fingerprint().raw(),
        });
        assert_eq!(owner.outcome(), Some(Outcome::Failed(Failure::Protocol)));
    }

    #[test]
    fn an_exchange_that_ends_before_both_landed_is_not_confirmed() {
        let (sender, collection, _) = holding(63, "closed", 30);
        let (receiver, _) = sharing(64, "closed", &[]);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::new(receiver, collection, kind, None, true, true);
        // The receiver's LANDED never crosses.
        loop {
            let mut moved = false;
            if let Some(frame) = sender.next() {
                receiver.hear(frame);
                moved = true;
            }
            if let Some(frame) = receiver.next() {
                if frame != Frame::Landed {
                    sender.hear(frame);
                }
                moved = true;
            }
            if !moved {
                break;
            }
        }
        // The receiver heard the sender's LANDED and sent its own: from
        // where it stands the exchange confirmed. The sender never heard
        // it: not confirmed, and no agreed tree.
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(sender.outcome(), None);
        assert!(sender.sent.contains(&Frame::Landed));
        let ended = sender.exchange.end();
        assert!(!ended.confirmed && ended.landed && ended.agreed.is_none());
        // Closed mid-delta: nothing confirmed, nothing landed.
        let (sender, collection, _) = holding(86, "closed", 30);
        let mut sender = Side::both(sender, collection, kind);
        assert!(matches!(sender.next(), Some(Frame::Subtree { .. })));
        assert!(matches!(sender.next(), Some(Frame::Subtree { .. })));
        let ended = sender.exchange.end();
        assert!(!ended.confirmed && !ended.landed && ended.agreed.is_none());
    }

    #[test]
    fn the_peer_s_landed_counts_a_push_but_not_a_shared_agreement() {
        let (sender, collection, _) = holding(100, "one LANDED", 1);
        let mut sender = Side::both(sender, collection, WalkKind::Records);
        while sender.next().is_some() {}
        sender.feed(Frame::Landed);
        assert_eq!(sender.outcome(), None);
        let ended = sender.exchange.end();
        assert!(ended.confirmed);
        assert!(!ended.landed);
        assert!(ended.agreed.is_none());
    }

    #[test]
    fn a_deferred_proof_fails_the_exchange_until_its_descriptor_arrives() {
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::{resource_collection, resource_policy};
        use triblespace_core::capability::{CapabilityProof, CapabilityResource};
        use triblespace_core::collection::AdmissionPolicy;
        use triblespace_core::macros::entity;
        use triblespace_core::repo::{
            BlobStoreGet, BlobStorePut, CapabilityProofStore, SnapshotSource,
        };

        use crate::walk::tests::walking::key;

        let mut sender = Node::new(65);
        let mut receiver = Node::new(66);
        let collection = sender.hold("deferred", open());
        receiver.hold("deferred", open());
        let resource_root = key(67);
        let capability = triblespace_core::inline::Inline::new([10; 32]);
        let resource = sender
            .store
            .put::<SimpleArchive, _>(
                entity! {
                    resource_collection: collection,
                    resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key())
                        .binding(capability),
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::from(resource),
            &resource_root,
            capability,
            receiver.key.verifying_key(),
        );
        sender.store.insert_proof(proof.clone()).unwrap();
        sender.observe();
        receiver.observe();
        let evidence = |node: &Node| {
            node.pinned(collection)
                .repair()
                .authorization_evidence()
                .get(proof.id())
                .cloned()
        };
        assert_eq!(evidence(&sender), Some(proof.clone()));
        let kind = WalkKind::Authorization;

        for attempt in 0..2 {
            let mut side = Side::both(receiver, collection, kind);
            stream(&mut side, &sender, collection, kind, &BTreeSet::new());
            assert_eq!(side.outcome(), None, "a fetch is owed");
            let (descriptor, fetched) = side.fetches.pop().unwrap();
            assert_eq!((fetched, descriptor), (Some(proof.clone()), resource.raw));
            // The first fetch fails; the second gets the descriptor.
            let blob = (attempt == 1).then(|| {
                BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(
                    &sender.store.snapshot().unwrap(),
                    triblespace_core::inline::Inline::new(resource.raw),
                )
                .unwrap()
            });
            let outs = side
                .exchange
                .on_fetched(resource.raw, Some(proof.clone()), blob);
            side.outputs(outs);
            if attempt == 0 {
                assert_eq!(
                    side.outcome(),
                    Some(Outcome::Failed(Failure::DeferredProof))
                );
            } else {
                assert!(side.replies().contains(&Frame::Landed));
                side.feed(Frame::Landed);
                assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            }
            assert_eq!(evidence(&side.node).is_some(), attempt == 1);
            receiver = side.node;
        }
    }

    #[test]
    fn a_duplicated_or_foreign_leaf_does_not_close_the_count_proof() {
        let (sender, collection, records) = holding(68, "duplicated", 60);
        let (receiver, _) = sharing(69, "duplicated", &[]);
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        receiver.feed(root(summary(
            WalkKind::Records,
            sender.pinned(collection).repair(),
        )));
        let key = records[0].fingerprint().raw();
        assert_eq!(receiver.feed(leaf(key)), [Frame::ValueRequest { key }]);
        receiver.feed(leaf(key));
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_node_whose_digest_is_not_the_parent_s_child_digest_fails_the_exchange() {
        let (sender, collection, records) = holding(70, "commitment", 400);
        let (receiver, _) = sharing(72, "commitment", &[]);
        let mut frames = tree(&sender, collection, WalkKind::Records, &BTreeSet::new());
        let changed = frames.iter_mut().find(|frame| matches!(frame, Frame::Subtree {prefix, summary} if !prefix.is_empty() && prefix.len()<KEY_BYTES && summary.leaf_count()>1)).unwrap();
        let Frame::Subtree { summary, .. } = changed else {
            unreachable!()
        };
        *summary = PatchSummary::new(Some([0xAB; 32]), summary.leaf_count()).unwrap();
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        for frame in frames {
            for reply in receiver.feed(frame) {
                if let Frame::ValueRequest { key } = reply {
                    receiver.feed(Frame::Value {
                        key,
                        bytes: value_of(&sender, collection, WalkKind::Records, key),
                    });
                }
            }
        }
        assert_eq!(receiver.node.records(collection).len(), records.len());
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadNode)));
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_leaf_outside_the_peer_s_tree_fails_the_exchange() {
        let (sender, collection, records) = holding(73, "outside", 60);
        let (receiver, _) = sharing(74, "outside", &[]);
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        receiver.feed(root(summary(
            WalkKind::Records,
            sender.pinned(collection).repair(),
        )));
        let key = records[0].fingerprint().raw();
        let mut wrong = leaf(key);
        let Frame::Subtree { summary, .. } = &mut wrong else {
            unreachable!()
        };
        *summary = PatchSummary::new(Some([0xAA; 32]), 1).unwrap();
        assert!(receiver.feed(wrong).is_empty());
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadNode)));
        assert!(receiver.requested().is_empty());
        assert!(receiver.exchange.end().agreed.is_none());
    }

    #[test]
    fn a_leaf_flood_with_withheld_values_fails_the_exchange_and_an_overcount_fails_at_once() {
        let (receiver, collection) = sharing(76, "flood", &[]);
        let (root, root_node, branches) = fabricated(256, FLOOD_WANTED / 256 + 2);
        assert!(root.leaf_count() as usize > FLOOD_WANTED + MAX_WALK_REQUESTS);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.feed(Frame::Subtree {
            prefix: Vec::new(),
            summary: root,
        });
        let _ = root_node;
        let mut fed = 0;
        'flood: for (node, leaves) in branches {
            receiver.feed(node);
            for leaf in leaves {
                assert!(receiver.exchange.want_read(), "values are owed");
                receiver.feed(leaf);
                fed += 1;
                if receiver.outcome().is_some() {
                    break 'flood;
                }
            }
        }
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert_eq!(receiver.exchange.wanted.len(), FLOOD_WANTED);
        assert_eq!(fed, FLOOD_WANTED + MAX_WALK_REQUESTS + 1);
        assert_eq!(receiver.requested().len(), MAX_WALK_REQUESTS);

        // A sixty-first leaf against a root of sixty fails at once.
        let (sender, collection, _) = holding(77, "overcount", 60);
        let (receiver, _) = sharing(78, "overcount", &[]);
        let mut receiver = Side::both(receiver, collection, kind);
        let mut frames = tree(&sender, collection, kind, &BTreeSet::new());
        assert_eq!(frames.pop(), Some(Frame::Done));
        let again = frames
            .iter()
            .find(|frame| matches!(frame, Frame::Subtree { prefix, .. } if prefix.len()==KEY_BYTES))
            .unwrap()
            .clone();
        for frame in frames {
            receiver.feed(frame);
        }
        assert_eq!(receiver.outcome(), None);
        receiver.feed(again);
        assert!(
            matches!(receiver.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            receiver.outcome()
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_wide_owed_frontier_is_not_mistaken_for_withheld_values() {
        let (receiver, collection) = sharing(79, "nodes", &[]);
        let (declared, _, branches) = fabricated(256, 256);
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        receiver.feed(root(declared));
        for (branch, _) in &branches {
            receiver.feed(branch.clone());
        }
        assert_eq!(receiver.exchange.commitments.len(), 257);
        assert_eq!(receiver.outcome(), None);
        assert!(receiver.exchange.wanted.is_empty());
        receiver.feed(Frame::Done);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_first_exchange_above_32k_frontier_completes_without_dfs() {
        let (sender, collection, records) = holding(90, "wide FIFO", 70_000);
        let (receiver, _) = sharing(91, "wide FIFO", &[]);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.observe_landings = false;
        let mut peak = 0;
        let mut depths = Vec::new();
        loop {
            let mut moved = false;
            if let Some(frame) = sender.next() {
                if let Frame::Subtree { prefix, .. } = &frame {
                    depths.push(prefix.len());
                }
                peak = peak.max(sender.exchange.queue.len());
                receiver.hear(frame);
                moved = true;
            }
            if let Some(frame) = receiver.next() {
                sender.hear(frame);
                moved = true;
            }
            if !moved {
                break;
            }
        }
        assert!(peak > 32_768, "frontier only {peak}");
        // Canonical compressed prefix lengths need not be monotonic in logical FIFO.
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(
            receiver.exchange.peer.summary(),
            receiver.exchange.peer_root.unwrap()
        );
        receiver.node.observe();
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
        assert_eq!(sender.agreed(), receiver.agreed());
        eprintln!(
            "W8_WIDE leaves=70000 peak_fifo_locators={peak} locator_ceiling={FLOOD_LOCATORS} scheduling=one_frame_each_direction immediate_individual_insert_ack frozen_resident_observation_until_end"
        );
    }

    #[test]
    fn a_shared_subtree_is_announced_once_each_way_on_the_first_exchange() {
        let (mut a, collection, records) = holding(93, "first shared", 1000);
        let (mut b, _) = sharing(94, "first shared", &records);
        let own_a = a.commit(collection, 1_000);
        let own_b = b.commit(collection, 2_000);
        a.observe();
        b.observe();
        let kind = WalkKind::Records;
        let root_a = node(kind, a.pinned(collection).repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_a else {
            panic!("the root branches");
        };
        let shared = branch
            .children
            .iter()
            .find(|child| {
                child.leaf_count > 1
                    && child.edge != own_a.fingerprint().raw()[0]
                    && child.edge != own_b.fingerprint().raw()[0]
            })
            .unwrap();
        let prefix = vec![shared.edge];
        let mut a = Side::both(a, collection, kind);
        let mut b = Side::both(b, collection, kind);
        carry(&mut a, &mut b);
        for side in [&a, &b] {
            assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            let announcements = side.sent.iter().filter(|frame| matches!(frame,
                Frame::Subtree {prefix: at, summary} if at == &prefix && summary.root()==Some(shared.digest) && summary.leaf_count()==shared.leaf_count
            )).count();
            assert_eq!(announcements, 1);
            assert!(
                side.nodes()
                    .iter()
                    .all(|at| at == &prefix || !at.starts_with(&prefix))
            );
            assert!(side.leaves().iter().all(|key| !key.starts_with(&prefix)));
            assert_eq!(side.requested().len(), 1);
        }
        assert_eq!(a.agreed(), b.agreed());
        eprintln!(
            "W8_FIRST_SHARED agreed_before=none shared_leaves={} announcements_per_direction=1 descendants_streamed=0 scheduling=one_frame_each_direction",
            shared.leaf_count
        );
    }

    #[test]
    fn a_receive_only_side_remembers_accounted_subtrees_without_leaf_frames() {
        let (sender, collection, records) = holding(95, "one-way shared", 1000);
        let kind = WalkKind::Records;
        let root = node(kind, sender.pinned(collection).repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root else {
            panic!("the root branches");
        };
        let child = branch
            .children
            .iter()
            .find(|child| child.leaf_count > 1)
            .unwrap();
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw()[0] == child.edge)
            .copied()
            .collect::<Vec<_>>();
        let (receiver, _) = sharing(96, "one-way shared", &shared);
        let expected = summary(kind, sender.pinned(collection).repair());
        let mut receiver = Side::new(receiver, collection, kind, None, false, true);
        // A scripted delta omits an already-held authenticated subtree;
        // this is a membership/agreement-construction control, not a claim
        // that a send-disabled peer emitted subtree announcements.
        stream(
            &mut receiver,
            &sender,
            collection,
            kind,
            &fingerprints(shared),
        );
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert!(
            receiver
                .heard
                .iter()
                .all(|frame| !matches!(frame, Frame::Subtree {prefix:key,..} if key.len()==32 && key[0] == child.edge))
        );
        assert_eq!(receiver.agreed(), Some(expected));
    }

    #[test]
    fn a_lagging_pinned_snapshot_cannot_shrink_the_agreed_union() {
        let (b, collection, records) = holding(101, "lagged union", 100);
        let (a, _) = sharing(102, "lagged union", &records[..50]);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, b.pinned(collection).repair()));
        let expected = agreed.summary();
        let mut a = Side::new(a, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b, collection, kind, Some(agreed), true, true);
        // The physical store holds the agreement; only the exchange's
        // captured serving observation lagged those previous landings.
        for record in &records[50..] {
            a.node.store.insert(*record).unwrap();
        }
        a.node.observe();
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.agreed(), Some(expected));
        assert_eq!(b.agreed(), Some(expected));
        assert!(a.requested().is_empty() && b.requested().is_empty());
    }

    #[test]
    fn a_receive_only_lagged_root_cannot_shrink_prior_agreement() {
        let (prior, collection, records) = holding(111, "one-way lag", 100);
        let (writer, _) = sharing(112, "one-way lag", &records[..50]);
        let (owner, _) = sharing(113, "one-way lag", &records[..50]);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, prior.pinned(collection).repair()));
        let expected = agreed.summary();
        let mut writer = Side::new(writer, collection, kind, Some(agreed.clone()), true, false);
        let mut owner = Side::new(owner, collection, kind, Some(agreed), false, true);
        for side in [&mut writer, &mut owner] {
            for record in &records[50..] {
                side.node.store.insert(*record).unwrap();
            }
            side.node.observe();
        }
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(writer.agreed(), Some(expected));
        assert_eq!(owner.agreed(), Some(expected));
        assert!(writer.requested().is_empty() && owner.requested().is_empty());
        assert_eq!(
            owner.sent.first(),
            Some(&Frame::Subtree {
                prefix: Vec::new(),
                summary: empty()
            })
        );
    }

    #[test]
    fn an_already_held_node_authenticates_children_before_announcing_them() {
        let (node, collection, _) = holding(97, "bounds", 300);
        let declared = summary(WalkKind::Records, node.pinned(collection).repair());
        let mut side = Side::both(node, collection, WalkKind::Records);
        side.feed(root(declared));
        let outs = side.exchange.on_frame(
            Frame::Subtree {
                prefix: vec![0; 33],
                summary: declared,
            },
            Some(side.node.snapshot()),
        );
        assert!(outs.is_empty());
        assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::BadNode)));
    }

    #[test]
    fn exceeding_the_locator_budget_fails_instead_of_switching_to_dfs() {
        let (sender, collection, _) = holding(92, "bounded FIFO", 300);
        let mut sender = Side::both(sender, collection, WalkKind::Records);
        sender.exchange.root_sent = true;
        sender.exchange.queue = std::iter::repeat_n(Vec::new(), FLOOD_LOCATORS).collect();
        assert_eq!(sender.next(), None);
        assert_eq!(sender.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(sender.agreed().is_none());
    }

    #[test]
    fn an_equal_or_agreed_root_is_accounted_whole() {
        let (sender, collection, records) = holding(80, "equal", 50);
        let (receiver, _) = sharing(81, "equal", &records);
        let declared = summary(WalkKind::Records, sender.pinned(collection).repair());
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        receiver.feed(root(declared));
        assert_eq!(receiver.feed(Frame::Done), [Frame::Landed]);
        while receiver.next().is_some() {}
        receiver.feed(Frame::Landed);
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.agreed(), Some(declared));
        assert_eq!(receiver.nodes(), [Vec::<u8>::new()]);
        assert!(receiver.leaves().is_empty() && receiver.requested().is_empty());
    }

    #[test]
    fn a_subtree_equal_to_the_agreed_tree_is_accounted_however_this_side_grew() {
        let (a, collection, records) = holding(82, "grew", 300);
        let (b, _) = sharing(83, "grew", &records);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, a.pinned(collection).repair()));
        let mut a = Side::new(a, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b, collection, kind, Some(agreed.clone()), true, true);
        // A gains one record, B three: every exchange lands only those.
        let one = a.node.commit(collection, 1_000);
        a.node.observe();
        let three = (0..3)
            .map(|data| b.node.commit(collection, 2_000 + data))
            .collect::<Vec<_>>();
        b.node.observe();
        let mut a = Side::new(a.node, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b.node, collection, kind, Some(agreed), true, true);
        burst(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.requested(), fingerprints(three.iter().copied()));
        assert_eq!(b.requested(), fingerprints([one]));
        let expected = BTreeSet::from([Vec::new()]);
        assert_eq!(a.nodes().into_iter().collect::<BTreeSet<_>>(), expected);
        assert_eq!(a.agreed(), b.agreed());
        assert_eq!(a.node.records(collection).len(), 304);
        assert_eq!(b.node.records(collection), a.node.records(collection));
    }

    #[test]
    fn values_are_served_from_the_pinned_tree() {
        let (sender, collection, records) = holding(84, "served", 5);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let key = records[0].fingerprint().raw();
        let replies = sender.feed(Frame::ValueRequest { key });
        let [Frame::Value { key: served, bytes }] = &replies[..] else {
            panic!("one value: {replies:?}");
        };
        assert_eq!(*served, key);
        assert_eq!(decode_record(collection, bytes).unwrap(), records[0]);
        sender.feed(Frame::ValueRequest { key: [9; 32] });
        assert_eq!(sender.outcome(), Some(Outcome::Failed(Failure::Protocol)));
    }

    #[test]
    fn matching_prefix_before_or_after_our_announcement_sends_it_once_not_its_recursion() {
        for late in [false, true] {
            let (sender, collection, _) = holding(115, "match order", 1000);
            let mut side = Side::new(sender, collection, WalkKind::Records, None, true, false);
            side.next().unwrap(); // [] first, with all logical children queued.
            let prefix = side
                .exchange
                .queue
                .iter()
                .find(|prefix| prefix.len() < KEY_BYTES)
                .unwrap()
                .clone();
            let declared = side.exchange.delta.at(&prefix).unwrap();
            if late {
                while !side
                    .sent
                    .iter()
                    .any(|frame| matches!(frame,Frame::Subtree {prefix:at,..} if at==&prefix))
                {
                    side.next().unwrap();
                }
                assert!(side.exchange.queue.iter().any(|at| at.starts_with(&prefix)));
            }
            side.hear(root(PatchSummary::new(Some([0xAB; 32]), 1000).unwrap()));
            side.hear(Frame::Subtree {
                prefix: prefix.clone(),
                summary: declared,
            });
            while side.next().is_some() {}
            let own = side
                .sent
                .iter()
                .filter(|frame| matches!(frame,Frame::Subtree {prefix:at,..} if at==&prefix))
                .count();
            assert_eq!(own, 1, "late={late}");
            assert!(side.sent.iter().all(|frame| !matches!(frame,Frame::Subtree {prefix:at,..} if at.len()>prefix.len() && at.starts_with(&prefix))));
        }
    }

    #[test]
    fn a_compressed_delta_root_meets_the_same_prefix_inside_a_larger_delta() {
        let (large, collection, records) = holding(116, "compressed overlap", 1000);
        let tree = Tree::pinned(WalkKind::Records, large.pinned(collection).repair());
        let (_, children) = tree.shape(&[]).unwrap();
        let prefix = children
            .into_iter()
            .find(|prefix| prefix.len() < KEY_BYTES && tree.at(prefix).unwrap().leaf_count() > 1)
            .unwrap();
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw().starts_with(&prefix))
            .copied()
            .collect::<Vec<_>>();
        let (small, _) = sharing(117, "compressed overlap", &shared);
        let mut large = Side::both(large, collection, WalkKind::Records);
        let mut small = Side::both(small, collection, WalkKind::Records);
        carry(&mut large, &mut small);
        for side in [&large, &small] {
            assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            assert_eq!(
                side.sent
                    .iter()
                    .filter(|frame| matches!(frame,Frame::Subtree {prefix:at,..} if at==&prefix))
                    .count(),
                1
            );
        }
        assert!(large.leaves().iter().all(|key| !key.starts_with(&prefix)));
        assert_eq!(
            small.sent[1],
            Frame::Subtree {
                prefix,
                summary: small.exchange.delta.summary()
            }
        );
        assert_eq!(large.agreed(), small.agreed());
    }

    #[test]
    fn a_foreign_but_valid_leaf_cannot_replace_an_omitted_leaf_at_equal_count() {
        let (sender, collection, records) = holding(118, "foreign membership", 2);
        let (mut receiver, _) = sharing(119, "foreign membership", &[]);
        let foreign = receiver.commit(collection, 1000);
        receiver.observe();
        let mut side = Side::both(receiver, collection, WalkKind::Records);
        side.feed(root(summary(
            WalkKind::Records,
            sender.pinned(collection).repair(),
        )));
        let key = records[0].fingerprint().raw();
        assert_eq!(side.feed(leaf(key)), [Frame::ValueRequest { key }]);
        side.feed(Frame::Value {
            key,
            bytes: value_of(&sender, collection, WalkKind::Records, key),
        });
        assert!(side.feed(leaf(foreign.fingerprint().raw())).is_empty());
        assert_eq!(side.exchange.peer.summary().leaf_count(), 2);
        side.feed(Frame::Done);
        assert_eq!(
            side.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!side.sent.contains(&Frame::Landed));
        assert_eq!(
            side.node.records(collection).len(),
            2,
            "actual valid landing remains"
        );
    }

    #[test]
    fn a_wrong_prefix_cannot_close_even_with_the_right_hash_and_count() {
        let (sender, collection, records) = holding(120, "wrong prefix", 1000);
        let (receiver, _) = sharing(121, "wrong prefix", &records);
        let tree = Tree::pinned(WalkKind::Records, sender.pinned(collection).repair());
        let (_, children) = tree.shape(&[]).unwrap();
        let prefix = children
            .into_iter()
            .find(|prefix| prefix.len() < KEY_BYTES)
            .unwrap();
        let declared = tree.at(&prefix).unwrap();
        let mut wrong = prefix.clone();
        wrong[0] ^= 0x80;
        let mut side = Side::both(receiver, collection, WalkKind::Records);
        side.feed(root(tree.summary()));
        side.feed(Frame::Subtree {
            prefix: wrong,
            summary: declared,
        });
        side.feed(Frame::Done);
        assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::BadNode)));
        assert!(!side.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_noncanonical_alias_of_a_compressed_prefix_cannot_close() {
        let (sender, collection, records) = holding(122, "compressed alias", 3000);
        let pair = records
            .iter()
            .enumerate()
            .find_map(|(i, a)| {
                records[i + 1..]
                    .iter()
                    .find(|b| a.fingerprint().raw()[..2] == b.fingerprint().raw()[..2])
                    .map(|b| [*a, *b])
            })
            .unwrap();
        let (holder, _) = sharing(123, "compressed alias", &pair);
        let tree = Tree::pinned(WalkKind::Records, holder.pinned(collection).repair());
        let (canonical, _) = tree.shape(&[]).unwrap();
        assert!(canonical.len() >= 2);
        let mut side = Side::both(holder, collection, WalkKind::Records);
        side.feed(root(tree.summary()));
        side.feed(Frame::Subtree {
            prefix: canonical[..1].to_vec(),
            summary: tree.summary(),
        });
        side.feed(Frame::Done);
        assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::BadNode)));
        assert!(!side.sent.contains(&Frame::Landed));
        drop(sender);
    }

    #[test]
    fn a_declared_delta_above_the_honest_proof_budget_is_refused() {
        let (node, collection) = sharing(124, "proof ceiling", &[]);
        let mut side = Side::both(node, collection, WalkKind::Records);
        side.feed(root(
            PatchSummary::new(Some([0xAA; 32]), FLOOD_LOCATORS as u64 + 1).unwrap(),
        ));
        assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(side.exchange.peer.summary().root().is_none());
        assert!(side.exchange.end().agreed.is_none());
    }

    #[test]
    fn unequal_sound_bases_after_a_failed_finish_and_publication_lag_converge() {
        let (a, collection, records) = holding(127, "unequal bases", 2);
        let (b, _) = sharing(128, "unequal bases", &records[..1]);
        let mut a = Side::both(a, collection, WalkKind::Records);
        let mut b = Side::both(b, collection, WalkKind::Records);
        b.observe_landings = false;
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        let complete = Arc::new(a.exchange.union_tree());
        assert_eq!(
            b.node.records(collection).len(),
            2,
            "both values actually landed despite lag"
        );
        assert_eq!(b.node.pinned(collection).repair().records().len(), 1);
        // The separately tested real shutdown failure clears only B's G.
        // A retains sound jointly-held knowledge; no connection policy changes.
        let mut a = Side::new(
            a.node,
            collection,
            WalkKind::Records,
            Some(complete.clone()),
            true,
            true,
        );
        let mut b = Side::new(b.node, collection, WalkKind::Records, None, true, true);
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.exchange.peer.summary().leaf_count(), 1);
        assert_eq!(
            b.exchange.peer.summary(),
            empty(),
            "empty delta is not a full collection"
        );
        assert_eq!(a.agreed(), Some(complete.summary()));
        assert_eq!(
            b.agreed().unwrap().leaf_count(),
            1,
            "unequal bookkeeping is permitted"
        );
        assert_eq!(
            b.node.records(collection).len(),
            2,
            "no already-landed value is lost"
        );
        let b_base = Arc::new(b.exchange.union_tree());
        b.node.observe();
        let mut a = Side::new(
            a.node,
            collection,
            WalkKind::Records,
            Some(complete.clone()),
            true,
            true,
        );
        let mut b = Side::new(
            b.node,
            collection,
            WalkKind::Records,
            Some(b_base),
            true,
            true,
        );
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.agreed(), Some(complete.summary()));
        assert_eq!(b.agreed(), Some(complete.summary()));
        assert!(a.requested().is_empty() && b.requested().is_empty());
    }

    #[test]
    fn first_contact_and_an_agreed_single_change_have_exact_wire_byte_receipts() {
        fn receipt(label: &str, a: &Side, b: &Side) {
            let bytes = |side: &Side| {
                side.sent
                    .iter()
                    .map(|frame| 5 + frame.encode().1.len())
                    .sum::<usize>()
            };
            let subtrees = |side: &Side| {
                side.sent
                    .iter()
                    .filter(|frame| matches!(frame, Frame::Subtree { .. }))
                    .count()
            };
            eprintln!(
                "PREFIX_BYTES fixture={label} a_total={} b_total={} a_subtrees={} b_subtrees={} a_subtree_bytes={} b_subtree_bytes={} a_values={} b_values={} a_requests={} b_requests={} framing=5 payload=73 scheduler=one_frame_each_direction",
                bytes(a),
                bytes(b),
                subtrees(a),
                subtrees(b),
                78 * subtrees(a),
                78 * subtrees(b),
                a.count(|f| matches!(f, Frame::Value { .. })),
                b.count(|f| matches!(f, Frame::Value { .. })),
                a.requested().len(),
                b.requested().len()
            );
        }
        let (a, collection, records) = holding(125, "bytes", 3000);
        let (b, _) = sharing(126, "bytes", &[]);
        let mut a = Side::both(a, collection, WalkKind::Records);
        let mut b = Side::both(b, collection, WalkKind::Records);
        b.observe_landings = false;
        carry(&mut a, &mut b);
        b.node.observe();
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        receipt("first_contact_3000_empty", &a, &b);
        let agreed = Arc::new(a.exchange.union_tree());
        let mut node = a.node;
        let added = node.commit(collection, 9999);
        node.observe();
        let mut a = Side::new(
            node,
            collection,
            WalkKind::Records,
            Some(agreed.clone()),
            true,
            true,
        );
        let mut b = Side::new(
            b.node,
            collection,
            WalkKind::Records,
            Some(agreed),
            true,
            true,
        );
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.exchange.delta.summary().leaf_count(), 1);
        assert_eq!(a.nodes(), [Vec::<u8>::new()]);
        assert_eq!(a.leaves(), [added.fingerprint().raw()]);
        assert_eq!(a.count(|f| matches!(f, Frame::Subtree { .. })), 2);
        assert_eq!(b.requested(), fingerprints([added]));
        assert_eq!(b.node.records(collection).len(), records.len() + 1);
        receipt("agreed_3000_plus_one", &a, &b);
    }

    #[test]
    fn the_agreed_tree_mirrors_the_overlay_s_tree() {
        let (mut node, collection, records) = holding(85, "tree", 40);
        for kind in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ] {
            let pinned = node.pinned(collection);
            let tree = Tree::pinned(kind, pinned.repair());
            assert_eq!(tree.summary(), summary(kind, pinned.repair()));
            for locator in [&[][..], &records[0].fingerprint().raw()[..1]] {
                assert_eq!(
                    tree.at(locator),
                    crate::walk::local_summary(kind, pinned.repair(), locator)
                );
            }
        }
        let before = Tree::pinned(WalkKind::Records, node.pinned(collection).repair());
        let mut tree = before.clone();
        let record = node.commit(collection, 1_000);
        node.observe();
        tree.insert(record.fingerprint().raw(), Value::Record(record));
        assert_eq!(
            tree.summary(),
            summary(WalkKind::Records, node.pinned(collection).repair())
        );
        assert_ne!(before.summary(), tree.summary(), "the clone is its own");
        assert!(
            !tree.has_new_keys(&before),
            "a lagging subset is not a local append"
        );
        assert!(
            before.has_new_keys(&tree),
            "a genuinely new key needs another exchange"
        );
    }
}
