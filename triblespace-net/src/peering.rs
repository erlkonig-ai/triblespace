//! Per-collection peering on `recon/1` (design 2.3, 2.6).
//!
//! Peering for a collection C is two keys' wish to sync C over the one
//! connection between them. A side asks only for collections it selects. It
//! accepts only if it selects C and the asker passes READ for C under its
//! evidence, or the asker set its send flag and passes WRITE. A side's send
//! flag says whether it admits the other side, and C flows only in a
//! direction whose sender set it. Peerings belong to their connection: a
//! replaced `recon/1` stream keeps them and a closed connection ends them.
//!
//! A side that refuses a request remembers it for the connection. When a
//! credential, an arriving definition, a new proof or its own selection
//! admits the asker, it invites it: a request in the other direction. The
//! asker never asks again on its own.
//!
//! Each selected collection has up to [`MAX_ASKED`] neighbours this side asked
//! for, plus up to [`MAX_INBOUND_PEERINGS`] peerings others asked for or were
//! invited to. Candidates come in tiers -- grant-chain keys and owners that
//! pass READ here, the other grant-chain keys and owners, then DHT providers
//! -- each tier ranked by `blake3(salt || key)`. The walk through that order
//! is the only retry state: a refusal, a failed dial or an ended peering is
//! replaced by the next candidate, and the end of the order draws a new salt.
//! Every [`SWAP_INTERVAL`] one healthy asked-for neighbour makes room for the
//! next candidate, so groups formed during a partition meet again after it.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use rand::seq::SliceRandom as _;
use triblespace_core::capability::{CapabilityHandle, CapabilityProof, QuorumOutcome};
use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_activation::MAX_PROOFS_PER_EXCHANGE;
use crate::connection::{ConnectionTable, Link, ReconEvent, Service};
use crate::health::{Health, PeeringHealth};
use crate::host::{CollectionSnapshot, StoreSnapshot};
use crate::protocol::RawHash;
use crate::recon::{Flags, Frame, credential_frames, request_frames};
use crate::transport::{PeerId, Transport};

/// Neighbours per collection this side asks for.
pub(crate) const MAX_ASKED: usize = 5;
/// Peerings per collection others asked for or were invited to. A request
/// beyond it is refused.
pub(crate) const MAX_INBOUND_PEERINGS: usize = 16;
/// How often one healthy asked-for neighbour is replaced.
pub(crate) const SWAP_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// An exhausted candidate order is drawn again no sooner than this, unless
/// its candidates changed. Without it a collection whose candidates are all
/// unreachable would redial them as fast as the dials fail.
pub(crate) const MIN_RESHUFFLE_INTERVAL: Duration = Duration::from_secs(60);
/// How often neighbour sets are refilled and swaps come due.
pub(crate) const PEERING_TICK: Duration = Duration::from_secs(1);
/// Connection events waiting for the peering task.
pub(crate) const RECON_EVENTS: usize = 256;

/// One connection's peering for one collection, as this side sees it.
#[derive(Clone, Copy, Debug, Default)]
enum Side {
    #[default]
    Idle,
    /// This side sent a request, or an invitation (`asked` unset), and waits.
    Asked { asked: bool, mine: Flags },
    /// Both sides accepted. `asked` says this side asked for it.
    Peered {
        asked: bool,
        mine: Flags,
        theirs: Flags,
    },
}

#[derive(Default)]
struct Peering {
    side: Side,
    /// The peer's request this side refused: the peer's flags, and the
    /// definitions whose arrival could admit it.
    refused: Option<(Flags, Vec<CapabilityHandle>)>,
    /// The peer refused this side's request.
    refused_by_them: bool,
    /// The peer's credentials for the collection that this side validated.
    presented: Vec<CapabilityProof>,
}

impl Peering {
    fn asked(&self) -> bool {
        matches!(
            self.side,
            Side::Asked { asked: true, .. } | Side::Peered { asked: true, .. }
        )
    }

    fn inbound(&self) -> bool {
        matches!(
            self.side,
            Side::Asked { asked: false, .. } | Side::Peered { asked: false, .. }
        )
    }

    fn peered(&self) -> bool {
        matches!(self.side, Side::Peered { .. })
    }

    fn is_empty(&self) -> bool {
        matches!(self.side, Side::Idle)
            && self.refused.is_none()
            && !self.refused_by_them
            && self.presented.is_empty()
    }
}

/// The walk through one collection's candidates.
#[derive(Default)]
struct Order {
    /// Every candidate when the order was drawn, in order.
    peers: Vec<PeerId>,
    /// The next position.
    next: usize,
    drawn_at: Option<Mono>,
    /// The candidates may have changed since the order was drawn.
    stale: bool,
}

#[derive(Default)]
struct Mesh {
    /// By connection id.
    peerings: HashMap<u64, Peering>,
    order: Order,
    /// Candidates being dialled, to be asked once connected.
    dialling: BTreeSet<PeerId>,
    /// The latest DHT providers of the collection's locator.
    providers: Vec<PeerId>,
    next_swap: Option<Mono>,
}

/// Every collection's peerings on every connection of one node.
pub(crate) struct Peerings {
    local: PeerId,
    snapshot: Option<Arc<StoreSnapshot>>,
    links: HashMap<u64, Link>,
    meshes: HashMap<RawHash, Mesh>,
    changed: bool,
}

/// Whether `peer` may READ (or WRITE) C under this side's evidence and the
/// credentials it presented.
fn admits(
    collection: &CollectionSnapshot,
    peer: PeerId,
    presented: &[CapabilityProof],
    write: bool,
) -> QuorumOutcome {
    let Ok(peer) = VerifyingKey::from_bytes(&peer) else {
        return QuorumOutcome::Unmet;
    };
    let evidence = collection.repair().authorization_evidence();
    let proofs = evidence
        .proofs()
        .chain(presented)
        .cloned()
        .collect::<Vec<_>>();
    if write {
        evidence.writer_is_admitted_by(peer, &proofs)
    } else {
        evidence.reader_is_admitted_by(peer, &proofs)
    }
}

/// This side's flags towards `peer`: it sends exactly when `peer` reads.
fn flags(collection: &CollectionSnapshot, peer: PeerId, presented: &[CapabilityProof]) -> Flags {
    Flags {
        send: matches!(
            admits(collection, peer, presented, false),
            QuorumOutcome::Met
        ),
        // Replication mode reaches the host with the reference comparison.
        full: false,
    }
}

/// This side's answer to a request from `peer` with `theirs`: its own flags
/// if it admits the peering, else the definitions whose arrival could.
fn decide(
    collection: Option<&CollectionSnapshot>,
    peer: PeerId,
    theirs: Flags,
    presented: &[CapabilityProof],
) -> Result<Flags, Vec<CapabilityHandle>> {
    let Some(collection) = collection else {
        return Err(Vec::new());
    };
    let mut undefined = Vec::new();
    let mut outcomes = vec![admits(collection, peer, presented, false)];
    if theirs.send {
        outcomes.push(admits(collection, peer, presented, true));
    }
    for outcome in outcomes {
        match outcome {
            QuorumOutcome::Met => return Ok(flags(collection, peer, presented)),
            QuorumOutcome::Unmet => {}
            QuorumOutcome::Undefined(handles) => undefined.extend(handles),
        }
    }
    Err(undefined)
}

/// The keys a node may ask to peer for C, in order: grant-chain keys and
/// owners that pass READ under local evidence, the other grant-chain keys
/// and owners, then DHT `providers`, each tier ranked by
/// `blake3(salt || key)`. Owners are the signers of records whose signer may
/// WRITE C. `local` is left out.
pub(crate) fn candidate_order(
    collection: &CollectionSnapshot,
    providers: &[PeerId],
    local: PeerId,
    salt: &[u8; 32],
) -> Vec<PeerId> {
    let evidence = collection.repair().authorization_evidence();
    let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
    let signers = collection
        .repair()
        .records()
        .records()
        .map(|record| record.public_key().raw)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|signer| {
            VerifyingKey::from_bytes(signer).is_ok_and(|signer| {
                matches!(
                    evidence.writer_is_admitted_by(signer, &proofs),
                    QuorumOutcome::Met
                )
            })
        });
    let keys = evidence
        .discovery_candidates()
        .map(|key| key.to_bytes())
        .chain(signers)
        .filter(|key| *key != local)
        .collect::<BTreeSet<_>>();
    let rank = |key: &PeerId| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(salt);
        hasher.update(key);
        *hasher.finalize().as_bytes()
    };
    let mut ranked = keys
        .iter()
        .map(|key| {
            let reads = VerifyingKey::from_bytes(key).is_ok_and(|key| {
                matches!(
                    evidence.reader_is_admitted_by(key, &proofs),
                    QuorumOutcome::Met
                )
            });
            ((if reads { 1 } else { 2 }, rank(key)), *key)
        })
        .chain(
            providers
                .iter()
                .filter(|provider| **provider != local && !keys.contains(*provider))
                .map(|provider| ((3, rank(provider)), *provider)),
        )
        .collect::<Vec<_>>();
    ranked.sort_unstable();
    ranked.dedup_by_key(|(_, key)| *key);
    ranked.into_iter().map(|(_, key)| key).collect()
}

impl Peerings {
    pub(crate) fn new(local: PeerId) -> Self {
        Self {
            local,
            snapshot: None,
            links: HashMap::new(),
            meshes: HashMap::new(),
            changed: false,
        }
    }

    pub(crate) fn event(&mut self, event: ReconEvent) {
        match event {
            ReconEvent::Opened(link) => {
                if link.closed() {
                    return;
                }
                self.links.insert(link.id(), link.clone());
                if !link.retired() {
                    self.ask_dialled(link.peer());
                }
            }
            ReconEvent::Frame(link, frame) => {
                if link.closed() {
                    return;
                }
                self.links.entry(link.id()).or_insert_with(|| link.clone());
                self.frame(&link, frame);
            }
            ReconEvent::Closed(link) => {
                self.links.remove(&link.id());
                let successor = self.link_to(link.peer());
                let mut asked = Vec::new();
                for (raw, mesh) in &mut self.meshes {
                    if let Some(peering) = mesh.peerings.remove(&link.id()) {
                        self.changed = true;
                        if peering.asked() {
                            asked.push(CollectionHandle::new(*raw));
                        }
                    }
                    // A dial that ended on this connection asks nobody now.
                    if successor.is_none() {
                        mesh.dialling.remove(&link.peer());
                    }
                }
                // A tie-break closes the connection, not the neighbour: what
                // this side asked for on it, it asks for on the one kept.
                let Some(successor) = successor else {
                    return;
                };
                for collection in asked {
                    self.ask(collection, &successor, false);
                }
            }
        }
    }

    /// A dial this node started for `peer` ended.
    pub(crate) fn dialled(&mut self, peer: PeerId, connected: bool) {
        if connected {
            self.ask_dialled(peer);
        } else {
            for mesh in self.meshes.values_mut() {
                mesh.dialling.remove(&peer);
            }
        }
    }

    /// The latest DHT providers of a collection's locator.
    pub(crate) fn providers(&mut self, collection: CollectionHandle, providers: Vec<PeerId>) {
        let mesh = self.meshes.entry(collection.raw).or_default();
        mesh.providers = providers;
        mesh.order.stale = true;
    }

    /// Take a new store observation: end the peerings of collections no
    /// longer selected, revisit admissions whose evidence or selection
    /// changed, and send this side's credentials where they changed.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) {
        let previous = self.snapshot.replace(snapshot.clone());
        let local = VerifyingKey::from_bytes(&self.local).ok();
        let collections = self.meshes.keys().copied().collect::<Vec<_>>();
        for raw in collections {
            let collection = CollectionHandle::new(raw);
            let before = previous
                .as_ref()
                .and_then(|previous| previous.selected(collection));
            let after = snapshot.selected(collection);
            if before.is_some() && after.is_none() {
                self.unpeer(collection);
            }
            let Some(after) = after else {
                continue;
            };
            let evidence = |collection: &CollectionSnapshot| {
                let repair = collection.repair();
                (
                    repair.authorization_evidence().summary(),
                    repair.records().summary(),
                )
            };
            let changed = before
                .as_ref()
                .is_none_or(|before| evidence(before) != evidence(&after));
            let mesh = self.meshes.get_mut(&raw).unwrap();
            if changed {
                mesh.order.stale = true;
            }
            let revisit = mesh
                .peerings
                .iter()
                .filter(|(_, peering)| {
                    changed
                        || peering.refused.as_ref().is_some_and(|(_, undefined)| {
                            undefined
                                .iter()
                                .any(|handle| snapshot.get_blob(&handle.raw).is_some())
                        })
                })
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for id in revisit {
                self.revisit(collection, id);
            }
            let own = |collection: &CollectionSnapshot| {
                local.map(|local| {
                    collection
                        .repair()
                        .authorization_evidence()
                        .proof_digest(local)
                })
            };
            // A newly selected collection's requests carry the credentials.
            if before
                .as_ref()
                .is_some_and(|before| own(before) != own(&after))
            {
                self.send_credentials(collection, &after);
            }
        }
    }

    /// Ask for the peerings each selected collection's neighbour set lacks,
    /// and swap a neighbour where one is due. Returns the keys to dial.
    pub(crate) fn fill(&mut self, now: Mono) -> Vec<PeerId> {
        let Some(snapshot) = self.snapshot.clone() else {
            return Vec::new();
        };
        let mut dials = Vec::new();
        for collection in snapshot.active() {
            let Some(selected) = snapshot.selected(collection) else {
                continue;
            };
            let mesh = self.meshes.entry(collection.raw).or_default();
            let mut asked = mesh.dialling.len()
                + mesh
                    .peerings
                    .values()
                    .filter(|peering| peering.asked())
                    .count();
            let swap = *mesh.next_swap.get_or_insert(now + SWAP_INTERVAL);
            if now >= swap {
                mesh.next_swap = Some(now + SWAP_INTERVAL);
                if asked >= MAX_ASKED
                    && let Some(peer) = self.next_candidate(collection, &selected, now)
                {
                    self.swap_out(collection);
                    self.ask_or_dial(collection, peer, &mut dials);
                }
            }
            while asked < MAX_ASKED {
                let Some(peer) = self.next_candidate(collection, &selected, now) else {
                    break;
                };
                self.ask_or_dial(collection, peer, &mut dials);
                asked += 1;
            }
        }
        dials.sort_unstable();
        dials.dedup();
        dials
    }

    /// Set each connection's neighbour flag and publish the peerings, if
    /// anything changed since the last call.
    pub(crate) fn publish(&mut self, health: &Health) {
        if !std::mem::take(&mut self.changed) {
            return;
        }
        for (id, link) in &self.links {
            link.set_neighbour(self.meshes.values().any(|mesh| {
                mesh.peerings
                    .get(id)
                    .is_some_and(|peering| peering.peered())
            }));
        }
        let peerings = self.health();
        health.update(|health| health.peerings = peerings);
    }

    fn health(&self) -> Vec<PeeringHealth> {
        let mut peerings = Vec::new();
        for (raw, mesh) in &self.meshes {
            for (id, peering) in &mesh.peerings {
                let Some(link) = self.links.get(id) else {
                    continue;
                };
                let (sends, receives) = match peering.side {
                    Side::Peered { mine, theirs, .. } => (mine.send, theirs.send),
                    _ => (false, false),
                };
                peerings.push(PeeringHealth {
                    collection: CollectionHandle::new(*raw),
                    peer: link.peer(),
                    asked: peering.asked(),
                    peered: peering.peered(),
                    sends,
                    receives,
                    refused_by_me: peering.refused.is_some(),
                    refused_by_them: peering.refused_by_them,
                });
            }
        }
        peerings.sort_unstable_by_key(|peering| (peering.collection.raw, peering.peer));
        peerings
    }

    fn frame(&mut self, link: &Link, frame: Frame) {
        let Some(collection) = frame.collection() else {
            return;
        };
        let known = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.collection(collection).is_some());
        // A collection this side does not hold keeps no state: nothing could
        // admit a request for it, and nothing it sent is outstanding.
        if !known {
            if let Frame::PeerRequest { .. } = frame {
                link.send(Frame::PeerRefuse { collection });
            }
            return;
        }
        self.changed = true;
        match frame {
            Frame::PeerRequest {
                flags: theirs,
                invitation,
                credentials,
                ..
            } => {
                self.present(collection, link, credentials);
                self.answer(collection, link, theirs, invitation);
            }
            Frame::Credential { credentials, .. } => {
                self.present(collection, link, credentials);
                self.revisit(collection, link.id());
            }
            frame => {
                let peering = self.peering(collection, link.id());
                peering.side = match (peering.side, frame) {
                    (Side::Asked { asked, mine }, Frame::PeerAccept { flags: theirs, .. }) => {
                        peering.refused_by_them = false;
                        Side::Peered {
                            asked,
                            mine,
                            theirs,
                        }
                    }
                    (Side::Asked { .. }, Frame::PeerRefuse { .. }) => {
                        peering.refused_by_them = true;
                        Side::Idle
                    }
                    (Side::Peered { asked, mine, .. }, Frame::PeerFlags { flags: theirs, .. }) => {
                        if mine.send || theirs.send {
                            Side::Peered {
                                asked,
                                mine,
                                theirs,
                            }
                        } else {
                            Side::Idle
                        }
                    }
                    (_, Frame::Unpeer { .. }) => Side::Idle,
                    // An answer to a request this side has since withdrawn.
                    (side, _) => side,
                };
            }
        }
        self.prune(collection, link.id());
    }

    fn peering(&mut self, collection: CollectionHandle, id: u64) -> &mut Peering {
        self.meshes
            .entry(collection.raw)
            .or_default()
            .peerings
            .entry(id)
            .or_default()
    }

    fn prune(&mut self, collection: CollectionHandle, id: u64) {
        if let Some(mesh) = self.meshes.get_mut(&collection.raw)
            && mesh.peerings.get(&id).is_some_and(Peering::is_empty)
        {
            mesh.peerings.remove(&id);
        }
    }

    /// Keep the credentials that are evidence for C and name the peer.
    fn present(
        &mut self,
        collection: CollectionHandle,
        link: &Link,
        credentials: Vec<CapabilityProof>,
    ) {
        let Some(local) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(collection))
        else {
            return;
        };
        let evidence = local.repair().authorization_evidence();
        let peer = link.peer();
        let peering = self.peering(collection, link.id());
        for proof in credentials {
            if peering.presented.len() >= MAX_PROOFS_PER_EXCHANGE {
                break;
            }
            let valid = proof
                .prefixes()
                .any(|prefix| prefix.subject().to_bytes() == peer)
                && evidence.validate_proof(&proof).is_ok();
            if valid && !peering.presented.contains(&proof) {
                peering.presented.push(proof);
            }
        }
    }

    fn answer(
        &mut self,
        collection: CollectionHandle,
        link: &Link,
        theirs: Flags,
        invitation: bool,
    ) {
        let local = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.selected(collection));
        let room = self.inbound(collection, link.id()) < MAX_INBOUND_PEERINGS;
        let peering = self.peering(collection, link.id());
        let decision = decide(local.as_deref(), link.peer(), theirs, &peering.presented);
        match decision {
            Ok(mine) if room || peering.peered() => {
                link.send(Frame::PeerAccept {
                    collection,
                    flags: mine,
                });
                let asked = matches!(
                    peering.side,
                    Side::Asked { asked: true, .. } | Side::Peered { asked: true, .. }
                );
                peering.side = Side::Peered {
                    asked,
                    mine,
                    theirs,
                };
                peering.refused = None;
                if invitation {
                    peering.refused_by_them = false;
                }
            }
            decision => {
                link.send(Frame::PeerRefuse { collection });
                if peering.peered() {
                    peering.side = Side::Idle;
                }
                peering.refused = Some((theirs, decision.err().unwrap_or_default()));
            }
        }
    }

    /// Peerings for C that others asked for or this side invited, on other
    /// connections than `except`.
    fn inbound(&self, collection: CollectionHandle, except: u64) -> usize {
        self.meshes.get(&collection.raw).map_or(0, |mesh| {
            mesh.peerings
                .iter()
                .filter(|(id, peering)| **id != except && peering.inbound())
                .count()
        })
    }

    /// Re-evaluate one connection's peering for C after its evidence, its
    /// credentials or the selection changed: a peering's send flag follows
    /// admission, and a refused request that is now admitted is invited.
    fn revisit(&mut self, collection: CollectionHandle, id: u64) {
        let Some(link) = self.links.get(&id).cloned() else {
            return;
        };
        let local = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.selected(collection));
        let room = self.inbound(collection, id) < MAX_INBOUND_PEERINGS;
        let peering = self.peering(collection, id);
        match peering.side {
            Side::Peered {
                asked,
                mut mine,
                theirs,
            } => {
                let Some(local) = &local else {
                    return;
                };
                let send = flags(local, link.peer(), &peering.presented).send;
                if send != mine.send {
                    mine.send = send;
                    link.send(Frame::PeerFlags {
                        collection,
                        flags: mine,
                    });
                    peering.side = if mine.send || theirs.send {
                        Side::Peered {
                            asked,
                            mine,
                            theirs,
                        }
                    } else {
                        Side::Idle
                    };
                    self.changed = true;
                }
            }
            Side::Idle => {
                let Some((theirs, _)) = peering.refused else {
                    return;
                };
                match decide(local.as_deref(), link.peer(), theirs, &peering.presented) {
                    Ok(_) if room => self.ask(collection, &link, true),
                    Ok(_) => {}
                    Err(undefined) => peering.refused = Some((theirs, undefined)),
                }
            }
            Side::Asked { .. } => {}
        }
    }

    /// Send a request, or an invitation, for C on `link`.
    fn ask(&mut self, collection: CollectionHandle, link: &Link, invitation: bool) {
        let Some(local) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.selected(collection))
        else {
            return;
        };
        let credentials = self.credentials(&local);
        let peering = self.peering(collection, link.id());
        // A peering or request already on this connection stands.
        if !matches!(peering.side, Side::Idle) {
            return;
        }
        let mine = flags(&local, link.peer(), &peering.presented);
        for frame in request_frames(collection, mine, invitation, &credentials) {
            link.send(frame);
        }
        peering.side = Side::Asked {
            asked: !invitation,
            mine,
        };
        if invitation {
            peering.refused = None;
        }
        self.changed = true;
    }

    /// This side's credentials for C: its proofs naming itself, truncated
    /// there.
    fn credentials(&self, collection: &CollectionSnapshot) -> Vec<CapabilityProof> {
        let Ok(local) = VerifyingKey::from_bytes(&self.local) else {
            return Vec::new();
        };
        collection
            .repair()
            .authorization_evidence()
            .proofs_naming(local)
            .take(MAX_PROOFS_PER_EXCHANGE)
            .cloned()
            .collect()
    }

    /// Send this side's credentials for C to C's neighbours and to keys that
    /// refused its request.
    fn send_credentials(&mut self, collection: CollectionHandle, local: &CollectionSnapshot) {
        let Some(mesh) = self.meshes.get(&collection.raw) else {
            return;
        };
        let targets = mesh
            .peerings
            .iter()
            .filter(|(_, peering)| !matches!(peering.side, Side::Idle) || peering.refused_by_them)
            .filter_map(|(id, _)| self.links.get(id))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return;
        }
        let frames = credential_frames(collection, &self.credentials(local));
        for link in targets {
            for frame in &frames {
                link.send(frame.clone());
            }
        }
    }

    /// End every peering for C: the collection is no longer selected.
    fn unpeer(&mut self, collection: CollectionHandle) {
        let Some(mesh) = self.meshes.get_mut(&collection.raw) else {
            return;
        };
        mesh.dialling.clear();
        for (id, peering) in &mut mesh.peerings {
            if !matches!(peering.side, Side::Idle)
                && let Some(link) = self.links.get(id)
            {
                link.send(Frame::Unpeer { collection });
            }
            peering.side = Side::Idle;
            peering.refused_by_them = false;
        }
        mesh.peerings.retain(|_, peering| !peering.is_empty());
        self.changed = true;
    }

    /// End one healthy asked-for peering for C, chosen at random.
    fn swap_out(&mut self, collection: CollectionHandle) {
        let Some(mesh) = self.meshes.get_mut(&collection.raw) else {
            return;
        };
        let healthy = mesh
            .peerings
            .iter()
            .filter(|(_, peering)| matches!(peering.side, Side::Peered { asked: true, .. }))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let Some(id) = healthy.choose(&mut rand::thread_rng()) else {
            return;
        };
        if let Some(link) = self.links.get(id) {
            link.send(Frame::Unpeer { collection });
        }
        mesh.peerings.get_mut(id).unwrap().side = Side::Idle;
        mesh.peerings.retain(|_, peering| !peering.is_empty());
        self.changed = true;
    }

    /// The next candidate in C's order that is not already a neighbour, being
    /// dialled, or refusing this side. The end of the order draws it again,
    /// if that is due.
    fn next_candidate(
        &mut self,
        collection: CollectionHandle,
        local: &CollectionSnapshot,
        now: Mono,
    ) -> Option<PeerId> {
        let mesh = self.meshes.get_mut(&collection.raw)?;
        let taken = mesh
            .peerings
            .iter()
            .filter(|(_, peering)| !matches!(peering.side, Side::Idle) || peering.refused_by_them)
            .filter_map(|(id, _)| self.links.get(id).map(Link::peer))
            .chain(mesh.dialling.iter().copied())
            .collect::<BTreeSet<_>>();
        let order = &mut mesh.order;
        loop {
            while let Some(peer) = order.peers.get(order.next).copied() {
                order.next += 1;
                if !taken.contains(&peer) {
                    return Some(peer);
                }
            }
            let due = order
                .drawn_at
                .is_none_or(|drawn| order.stale || now >= drawn + MIN_RESHUFFLE_INTERVAL);
            if !due {
                return None;
            }
            order.peers = candidate_order(local, &mesh.providers, self.local, &rand::random());
            order.next = 0;
            order.drawn_at = Some(now);
            order.stale = false;
        }
    }

    fn ask_or_dial(&mut self, collection: CollectionHandle, peer: PeerId, dials: &mut Vec<PeerId>) {
        match self.link_to(peer) {
            Some(link) => self.ask(collection, &link, false),
            None => {
                self.meshes
                    .entry(collection.raw)
                    .or_default()
                    .dialling
                    .insert(peer);
                dials.push(peer);
            }
        }
    }

    /// Ask `peer` for each collection waiting on its dial.
    fn ask_dialled(&mut self, peer: PeerId) {
        let Some(link) = self.link_to(peer) else {
            return;
        };
        let waiting = self
            .meshes
            .iter_mut()
            .filter_map(|(raw, mesh)| {
                mesh.dialling
                    .remove(&peer)
                    .then_some(CollectionHandle::new(*raw))
            })
            .collect::<Vec<_>>();
        for collection in waiting {
            self.ask(collection, &link, false);
        }
    }

    /// The connection to `peer` new requests go on: an open one the
    /// tie-break has not retired.
    fn link_to(&self, peer: PeerId) -> Option<Link> {
        self.links
            .values()
            .filter(|link| link.peer() == peer && !link.closed() && !link.retired())
            .max_by_key(|link| link.id())
            .cloned()
    }
}

/// Run one node's peerings until its store observations end: hear its
/// connections' events, follow its observations, refill its neighbour sets
/// every [`PEERING_TICK`], and publish what changed into `health`.
pub(crate) async fn run<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    mut snapshots: tokio::sync::watch::Receiver<Option<Arc<StoreSnapshot>>>,
    mut events: tokio::sync::mpsc::Receiver<ReconEvent>,
    mut providers: tokio::sync::mpsc::UnboundedReceiver<(CollectionHandle, Vec<PeerId>)>,
    health: Health,
) {
    let mut peerings = Peerings::new(connections.transport().local_id());
    let (dialled_tx, mut dialled) = tokio::sync::mpsc::unbounded_channel();
    let mut tick = tokio::time::interval(PEERING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    if let Some(snapshot) = snapshots.borrow_and_update().clone() {
        peerings.observe(snapshot);
    }
    loop {
        tokio::select! {
            changed = snapshots.changed() => {
                if changed.is_err() {
                    return;
                }
                // A withdrawn observation is not an unselection; the next
                // one is compared with the last one seen.
                if let Some(snapshot) = snapshots.borrow_and_update().clone() {
                    peerings.observe(snapshot);
                }
            }
            Some(event) = events.recv() => peerings.event(event),
            Some((peer, connected)) = dialled.recv() => peerings.dialled(peer, connected),
            Some((collection, found)) = providers.recv() => {
                peerings.providers(collection, found);
            }
            _ = tick.tick() => {
                for peer in peerings.fill(crate::clock::mono_now()) {
                    let connections = connections.clone();
                    let dialled = dialled_tx.clone();
                    tokio::spawn(async move {
                        let connected = connections.connect(peer).await.is_ok();
                        let _ = dialled.send((peer, connected));
                    });
                }
            }
        }
        peerings.publish(&health);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use tokio::sync::mpsc::UnboundedReceiver;
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::capability::CapabilityResource;
    use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
    use triblespace_core::collection::{
        AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt, private_policy,
        read_capability, write_capability,
    };
    use triblespace_core::patch::Entry as PatchEntry;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{CapabilityProofStore, SnapshotSource, StoreChanges};

    use crate::host::ActiveCollections;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn grant(
        root: &SigningKey,
        subject: &SigningKey,
        action: CapabilityHandle,
        collection: CollectionHandle,
    ) -> CapabilityProof {
        CapabilityProof::new(
            CapabilityResource::from(collection),
            root,
            action,
            subject.verifying_key(),
        )
    }

    /// One node's pile: its store, its configuration and its active
    /// collections.
    struct Pile {
        key: SigningKey,
        store: MemoryRepo,
        config: Collection<SimpleArchive>,
        active: ActiveCollections,
    }

    impl Pile {
        fn new(byte: u8) -> Self {
            let key = key(byte);
            let mut store = MemoryRepo::default();
            let config = store
                .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
                .unwrap();
            Self {
                key,
                store,
                config,
                active: ActiveCollections::new(),
            }
        }

        fn id(&self) -> PeerId {
            self.key.verifying_key().to_bytes()
        }

        /// Hold and activate the collection `policy` names.
        fn hold(&mut self, policy: CollectionPolicy) -> CollectionHandle {
            self.hold_named("peering", policy)
        }

        fn hold_named(&mut self, name: &str, policy: CollectionPolicy) -> CollectionHandle {
            let collection = self.store.collection(name, policy).unwrap().handle();
            self.active.insert(&PatchEntry::new(&collection.raw));
            collection
        }

        fn write_selection(&mut self, collection: CollectionHandle, selected: bool) {
            write_sync_selection(
                &mut self.store,
                self.config,
                &self.key,
                collection,
                selected,
            )
            .unwrap();
        }

        fn snapshot(&mut self) -> Arc<StoreSnapshot> {
            Arc::new(
                StoreSnapshot::from_store_changes(
                    self.store.snapshot().unwrap(),
                    &self.active,
                    self.key.verifying_key(),
                    None,
                    None,
                    StoreChanges::ALL,
                )
                .unwrap(),
            )
        }
    }

    /// One node's pile and peerings, with its connections faked by links
    /// whose frames the test carries.
    struct Node {
        pile: Pile,
        key: SigningKey,
        peerings: Peerings,
    }

    impl Node {
        fn new(byte: u8) -> Self {
            let pile = Pile::new(byte);
            Self {
                peerings: Peerings::new(pile.id()),
                key: pile.key.clone(),
                pile,
            }
        }

        fn id(&self) -> PeerId {
            self.pile.id()
        }

        fn hold(&mut self, policy: CollectionPolicy) -> CollectionHandle {
            self.pile.hold(policy)
        }

        fn select(&mut self, collection: CollectionHandle, selected: bool) {
            self.pile.write_selection(collection, selected);
            self.observe();
        }

        fn learn(&mut self, proof: CapabilityProof) {
            self.pile.store.insert_proof(proof).unwrap();
            self.observe();
        }

        fn observe(&mut self) {
            let snapshot = self.pile.snapshot();
            self.peerings.observe(snapshot);
        }

        fn health(&self) -> Vec<PeeringHealth> {
            self.peerings.health()
        }
    }

    /// A connection between two nodes: each side's link and the frames
    /// queued on it.
    struct Wire {
        to_right: Link,
        from_left: UnboundedReceiver<Frame>,
        to_left: Link,
        from_right: UnboundedReceiver<Frame>,
    }

    fn connect(left: &mut Node, right: &mut Node, id: u64) -> Wire {
        let (to_right, from_left) = Link::detached(id, right.id());
        let (to_left, from_right) = Link::detached(id, left.id());
        left.peerings.event(ReconEvent::Opened(to_right.clone()));
        right.peerings.event(ReconEvent::Opened(to_left.clone()));
        Wire {
            to_right,
            from_left,
            to_left,
            from_right,
        }
    }

    /// Carry frames both ways until neither side sends; returns them in
    /// delivery order, marked with the sending side.
    fn carry(left: &mut Node, right: &mut Node, wire: &mut Wire) -> Vec<(&'static str, Frame)> {
        let mut carried = Vec::new();
        loop {
            if let Ok(frame) = wire.from_left.try_recv() {
                carried.push(("left", frame.clone()));
                right
                    .peerings
                    .event(ReconEvent::Frame(wire.to_left.clone(), frame));
            } else if let Ok(frame) = wire.from_right.try_recv() {
                carried.push(("right", frame.clone()));
                left.peerings
                    .event(ReconEvent::Frame(wire.to_right.clone(), frame));
            } else {
                return carried;
            }
        }
    }

    fn kinds(carried: &[(&'static str, Frame)]) -> Vec<(&'static str, u8)> {
        carried
            .iter()
            .map(|(side, frame)| (*side, frame.encode().0))
            .collect()
    }

    fn peering(node: &Node, peer: PeerId) -> Option<PeeringHealth> {
        node.health()
            .into_iter()
            .find(|peering| peering.peer == peer)
    }

    use crate::recon::{
        FRAME_CREDENTIAL, FRAME_PEER_ACCEPT, FRAME_PEER_FLAGS, FRAME_PEER_REFUSE,
        FRAME_PEER_REQUEST, FRAME_UNPEER,
    };

    /// The owner selects C and asks a reader that holds C without selecting
    /// it. The reader refuses and asks nothing; the refusal is a frame on the
    /// open connection. Once the reader selects C it invites the owner.
    #[test]
    fn a_node_that_does_not_select_c_refuses_and_invites_once_it_does() {
        let mut owner = Node::new(1);
        let mut reader = Node::new(2);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.key.verifying_key()),
            AdmissionPolicy::direct(owner.key.verifying_key()),
        );
        let collection = owner.hold(policy.clone());
        assert_eq!(reader.hold(policy), collection);
        let read = grant(&owner.key, &reader.key, read_capability(), collection);
        owner.learn(read.clone());
        reader.learn(read);
        owner.select(collection, true);
        reader.observe();
        let mut wire = connect(&mut owner, &mut reader, 1);

        assert!(reader.peerings.fill(crate::clock::mono_now()).is_empty());
        assert!(owner.peerings.fill(crate::clock::mono_now()).is_empty());
        let carried = carry(&mut owner, &mut reader, &mut wire);
        assert_eq!(
            kinds(&carried),
            [("left", FRAME_PEER_REQUEST), ("right", FRAME_PEER_REFUSE)]
        );
        let refused = peering(&owner, reader.id()).unwrap();
        assert!(refused.refused_by_them && !refused.peered && !refused.asked);
        assert!(peering(&reader, owner.id()).unwrap().refused_by_me);
        // The owner does not ask again, and the reader never asks for C.
        assert!(owner.peerings.fill(crate::clock::mono_now()).is_empty());
        assert!(reader.peerings.fill(crate::clock::mono_now()).is_empty());
        assert!(carry(&mut owner, &mut reader, &mut wire).is_empty());

        reader.select(collection, true);
        let carried = carry(&mut owner, &mut reader, &mut wire);
        assert_eq!(
            kinds(&carried),
            [("right", FRAME_PEER_REQUEST), ("left", FRAME_PEER_ACCEPT)]
        );
        assert!(matches!(
            carried[0].1,
            Frame::PeerRequest {
                invitation: true,
                ..
            }
        ));
        for (node, peer) in [(&owner, reader.id()), (&reader, owner.id())] {
            let peered = peering(node, peer).unwrap();
            assert!(
                peered.peered && peered.sends && peered.receives,
                "{peered:?}"
            );
            assert!(!peered.asked && !peered.refused_by_me && !peered.refused_by_them);
        }
    }

    /// WRITE admits a peering only with the asker's send flag set, and the
    /// acceptor then sends nothing back unless the asker also reads.
    #[test]
    fn a_send_only_request_needs_write() {
        let reader_root = key(10);
        let writer_root = key(11);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(reader_root.verifying_key()),
            AdmissionPolicy::direct(writer_root.verifying_key()),
        );
        for writes in [false, true] {
            let mut acceptor = Node::new(3);
            let mut asker = Node::new(4);
            let collection = acceptor.hold(policy.clone());
            asker.hold(policy.clone());
            // Both know the acceptor reads, so the asker sends to it.
            let read = grant(&reader_root, &acceptor.key, read_capability(), collection);
            acceptor.learn(read.clone());
            asker.learn(read);
            if writes {
                asker.learn(grant(
                    &writer_root,
                    &asker.key,
                    write_capability(),
                    collection,
                ));
            }
            acceptor.select(collection, true);
            asker.select(collection, true);
            let mut wire = connect(&mut asker, &mut acceptor, 1);
            // The policy roots are candidates too; they are dialled.
            asker.peerings.fill(crate::clock::mono_now());
            let carried = carry(&mut asker, &mut acceptor, &mut wire);
            let answer = if writes {
                FRAME_PEER_ACCEPT
            } else {
                FRAME_PEER_REFUSE
            };
            assert_eq!(
                kinds(&carried),
                [("left", FRAME_PEER_REQUEST), ("right", answer)]
            );
            let seen = peering(&asker, acceptor.id()).unwrap();
            assert_eq!(seen.peered, writes);
            if writes {
                assert!(seen.sends && !seen.receives, "{seen:?}");
            }
        }
    }

    /// A request refused for want of credentials is followed by an
    /// invitation once the asker's credential reaches the refuser.
    #[test]
    fn an_invitation_follows_a_later_credential() {
        let mut owner = Node::new(5);
        let mut reader = Node::new(6);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.key.verifying_key()),
            AdmissionPolicy::direct(owner.key.verifying_key()),
        );
        let collection = owner.hold(policy.clone());
        reader.hold(policy);
        owner.select(collection, true);
        reader.select(collection, true);
        let mut wire = connect(&mut reader, &mut owner, 1);
        assert!(reader.peerings.fill(crate::clock::mono_now()).is_empty());
        let carried = carry(&mut reader, &mut owner, &mut wire);
        assert_eq!(
            kinds(&carried),
            [("left", FRAME_PEER_REQUEST), ("right", FRAME_PEER_REFUSE)]
        );

        // Only the reader learns its grant, and it tells the refuser.
        reader.learn(grant(
            &owner.key,
            &reader.key,
            read_capability(),
            collection,
        ));
        let carried = carry(&mut reader, &mut owner, &mut wire);
        assert_eq!(
            kinds(&carried),
            [
                ("left", FRAME_CREDENTIAL),
                ("right", FRAME_PEER_REQUEST),
                ("left", FRAME_PEER_ACCEPT)
            ]
        );
        assert!(matches!(
            carried[1].1,
            Frame::PeerRequest {
                invitation: true,
                ..
            }
        ));
        for (node, peer) in [(&owner, reader.id()), (&reader, owner.id())] {
            let peered = peering(node, peer).unwrap();
            assert!(
                peered.peered && peered.sends && peered.receives,
                "{peered:?}"
            );
            assert!(
                !peered.asked,
                "an invitation counts as inbound on both sides"
            );
        }
    }

    /// Proofs the acceptor learns later, from another peer, change what it
    /// admits on connections already open: an open peering's send flag
    /// follows, and a refused key is invited.
    #[test]
    fn a_proof_learned_later_changes_admission_on_open_connections() {
        let mut owner = Node::new(7);
        let mut writer = Node::new(8);
        let mut stranger = Node::new(9);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.key.verifying_key()),
            AdmissionPolicy::direct(owner.key.verifying_key()),
        );
        let collection = owner.hold(policy.clone());
        writer.hold(policy.clone());
        stranger.hold(policy);
        writer.learn(grant(
            &owner.key,
            &writer.key,
            write_capability(),
            collection,
        ));
        for node in [&mut owner, &mut writer, &mut stranger] {
            node.select(collection, true);
        }
        let mut to_writer = connect(&mut writer, &mut owner, 1);
        let mut to_stranger = connect(&mut stranger, &mut owner, 2);
        assert!(writer.peerings.fill(crate::clock::mono_now()).is_empty());
        assert!(stranger.peerings.fill(crate::clock::mono_now()).is_empty());
        carry(&mut writer, &mut owner, &mut to_writer);
        carry(&mut stranger, &mut owner, &mut to_stranger);
        let delivering = peering(&writer, owner.id()).unwrap();
        assert!(delivering.peered && delivering.sends && !delivering.receives);
        assert!(peering(&stranger, owner.id()).unwrap().refused_by_them);

        owner.learn(grant(
            &owner.key,
            &writer.key,
            read_capability(),
            collection,
        ));
        owner.learn(grant(
            &owner.key,
            &stranger.key,
            read_capability(),
            collection,
        ));
        let carried = carry(&mut writer, &mut owner, &mut to_writer);
        assert_eq!(kinds(&carried), [("right", FRAME_PEER_FLAGS)]);
        let both = peering(&writer, owner.id()).unwrap();
        assert!(both.peered && both.sends && both.receives);
        let carried = carry(&mut stranger, &mut owner, &mut to_stranger);
        assert_eq!(
            kinds(&carried),
            [("right", FRAME_PEER_REQUEST), ("left", FRAME_PEER_ACCEPT)]
        );
        let invited = peering(&stranger, owner.id()).unwrap();
        assert!(invited.peered && invited.receives);
    }

    /// Unselecting C ends its peerings with an UNPEER and drops them.
    #[test]
    fn unselecting_sends_unpeer_and_drops_the_peering() {
        let mut owner = Node::new(12);
        let mut reader = Node::new(13);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.key.verifying_key()),
            AdmissionPolicy::direct(owner.key.verifying_key()),
        );
        let collection = owner.hold(policy.clone());
        reader.hold(policy);
        let read = grant(&owner.key, &reader.key, read_capability(), collection);
        owner.learn(read.clone());
        reader.learn(read);
        owner.select(collection, true);
        reader.select(collection, true);
        let mut wire = connect(&mut owner, &mut reader, 1);
        owner.peerings.fill(crate::clock::mono_now());
        carry(&mut owner, &mut reader, &mut wire);
        assert!(peering(&reader, owner.id()).unwrap().peered);

        reader.select(collection, false);
        let carried = carry(&mut owner, &mut reader, &mut wire);
        assert_eq!(kinds(&carried), [("right", FRAME_UNPEER)]);
        assert!(owner.health().is_empty());
        assert!(reader.health().is_empty());
    }

    /// Tiers order the candidates whatever the salt, a failed dial is not
    /// retried before the order is drawn again, and the end of the order
    /// draws it again once that is due.
    #[test]
    fn the_candidate_order_walks_tiers_and_draws_again_at_its_end() {
        let mut node = Node::new(20);
        let root = key(21);
        let reader = key(22);
        let writer = key(23);
        let provider = [24; 32];
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::direct(root.verifying_key()),
        );
        let collection = node.hold(policy);
        node.learn(grant(&root, &reader, read_capability(), collection));
        node.learn(grant(&root, &writer, write_capability(), collection));
        node.select(collection, true);
        let local = node
            .peerings
            .snapshot
            .as_ref()
            .unwrap()
            .selected(collection)
            .unwrap();
        let read_tier = BTreeSet::from([
            root.verifying_key().to_bytes(),
            reader.verifying_key().to_bytes(),
        ]);
        for salt in [[0; 32], [1; 32], [2; 32]] {
            let order = candidate_order(&local, &[provider], node.id(), &salt);
            assert_eq!(order.len(), 4);
            assert_eq!(
                order[..2].iter().copied().collect::<BTreeSet<_>>(),
                read_tier
            );
            assert_eq!(order[2..], [writer.verifying_key().to_bytes(), provider]);
        }

        let now = crate::clock::mono_now();
        node.peerings.providers(collection, vec![provider]);
        let mut dialled = node.peerings.fill(now);
        dialled.sort_unstable();
        let mut every = read_tier.iter().copied().collect::<Vec<_>>();
        every.extend([writer.verifying_key().to_bytes(), provider]);
        every.sort_unstable();
        assert_eq!(dialled, every);
        node.peerings.dialled(provider, false);
        assert!(node.peerings.fill(now + PEERING_TICK).is_empty());
        assert!(
            node.peerings
                .fill(now + (MIN_RESHUFFLE_INTERVAL - PEERING_TICK))
                .is_empty()
        );
        assert_eq!(node.peerings.fill(now + MIN_RESHUFFLE_INTERVAL), [provider]);
    }

    /// Peerings over real connection tables on the simulated transport,
    /// each node driven by [`run`].
    #[cfg(feature = "sim")]
    mod sim {
        use super::*;

        use iroh_base::EndpointId;
        use tokio::sync::watch;

        use crate::connection::{Connection, Service};
        use crate::transport::sim::{SimConfig, SimConn, SimNet, SimTransport};
        use crate::transport::{RecvStream, SendStream};

        /// Hands `recon/1` events to the node's peering task and serves no
        /// request stream.
        #[derive(Clone)]
        struct Forward(tokio::sync::mpsc::Sender<ReconEvent>);

        impl Service for Forward {
            async fn serve<W, R>(
                &self,
                _peer: PeerId,
                _tag: u8,
                _send: &mut W,
                _recv: &mut R,
            ) -> anyhow::Result<()>
            where
                W: SendStream,
                R: RecvStream,
            {
                anyhow::bail!("no request streams here")
            }

            async fn recon(&self, event: ReconEvent) {
                let _ = self.0.send(event).await;
            }
        }

        struct Host {
            pile: Pile,
            table: ConnectionTable<SimTransport, Forward>,
            snapshots: watch::Sender<Option<Arc<StoreSnapshot>>>,
            health: Health,
            tasks: Vec<tokio::task::JoinHandle<()>>,
        }

        impl Host {
            fn join(net: &SimNet, pile: Pile) -> Self {
                let mut harness = net.join(&pile.key);
                let (events, recon) = tokio::sync::mpsc::channel(RECON_EVENTS);
                let table = ConnectionTable::new(harness.transport.clone(), Forward(events));
                let connections = table.clone();
                let accept = tokio::spawn(async move {
                    while let Some(incoming) = harness.incoming.recv().await {
                        connections.accept(incoming.conn);
                    }
                });
                let (snapshots, observed) = watch::channel(None);
                let health = Health::new(EndpointId::from_bytes(&pile.id()).unwrap());
                let (_providers, found) = tokio::sync::mpsc::unbounded_channel();
                let peering =
                    tokio::spawn(run(table.clone(), observed, recon, found, health.clone()));
                Self {
                    pile,
                    table,
                    snapshots,
                    health,
                    tasks: vec![accept, peering],
                }
            }

            fn id(&self) -> PeerId {
                self.pile.id()
            }

            fn select(&mut self, collection: CollectionHandle, selected: bool) {
                self.pile.write_selection(collection, selected);
                self.snapshots.send_replace(Some(self.pile.snapshot()));
            }

            fn peerings(&self) -> Vec<PeeringHealth> {
                self.health.snapshot().peerings.clone()
            }

            fn peered(&self, collection: CollectionHandle) -> bool {
                self.peerings().iter().any(|peering| {
                    peering.collection == collection
                        && peering.peered
                        && peering.sends
                        && peering.receives
                })
            }
        }

        impl Drop for Host {
            fn drop(&mut self) {
                for task in &self.tasks {
                    task.abort();
                }
            }
        }

        /// An owner and a reader of every collection named in `names`, each
        /// holding the reader's READ grant.
        fn pair(net: &SimNet, names: &[&str]) -> (Host, Host, Vec<CollectionHandle>) {
            let mut owner = Pile::new(30);
            let mut reader = Pile::new(31);
            let policy = CollectionPolicy::new(
                AdmissionPolicy::direct(owner.key.verifying_key()),
                AdmissionPolicy::direct(owner.key.verifying_key()),
            );
            let mut collections = Vec::new();
            for name in names {
                let collection = owner.hold_named(name, policy.clone());
                assert_eq!(reader.hold_named(name, policy.clone()), collection);
                let read = grant(&owner.key, &reader.key, read_capability(), collection);
                owner.store.insert_proof(read.clone()).unwrap();
                reader.store.insert_proof(read).unwrap();
                collections.push(collection);
            }
            (Host::join(net, owner), Host::join(net, reader), collections)
        }

        async fn until(what: &str, mut done: impl FnMut() -> bool) {
            for _ in 0..600 {
                if done() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("{what} did not happen within a minute");
        }

        fn current(from: &Host, to: &Host) -> Connection<SimConn> {
            from.table.current(to.id()).expect("a connection")
        }

        #[tokio::test(start_paused = true)]
        async fn a_refused_peering_keeps_the_connection_and_an_invitation_crosses_it() {
            let net = SimNet::new(0x9EE7_0001, SimConfig::default());
            let (mut owner, mut reader, collections) = pair(&net, &["refused"]);
            let collection = collections[0];
            owner.select(collection, true);
            reader.snapshots.send_replace(Some(reader.pile.snapshot()));
            until("the refusal", || {
                owner
                    .peerings()
                    .iter()
                    .any(|peering| peering.refused_by_them)
            })
            .await;
            let connection = current(&owner, &reader);
            assert!(reader.peerings()[0].refused_by_me);

            // Long after the refusal, the connection is the one it came on.
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert!(current(&owner, &reader) == connection);
            reader.select(collection, true);
            until("the invited peering", || {
                owner.peered(collection) && reader.peered(collection)
            })
            .await;
            assert!(current(&owner, &reader) == connection);
            assert_eq!(net.dial_count(owner.id(), reader.id()), 1);
            assert_eq!(net.dial_count(reader.id(), owner.id()), 0);
            assert_eq!(owner.table.len(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn peerings_survive_a_recon_replacement() {
            let net = SimNet::new(0x9EE7_0002, SimConfig::default());
            let (mut owner, mut reader, collections) = pair(&net, &["first", "second"]);
            for collection in &collections {
                owner.pile.write_selection(*collection, true);
                reader.pile.write_selection(*collection, true);
            }
            owner.snapshots.send_replace(Some(owner.pile.snapshot()));
            reader.snapshots.send_replace(Some(reader.pile.snapshot()));
            // Both dial at once, and the tie-break closes one connection.
            until("both peerings, on one connection", || {
                collections
                    .iter()
                    .all(|collection| owner.peered(*collection) && reader.peered(*collection))
                    && owner.peerings().len() == 2
                    && reader.peerings().len() == 2
                    && owner.table.len() == 1
                    && reader.table.len() == 1
            })
            .await;
            assert!(
                owner.table.len() + reader.table.len() == 2
                    && net.dial_count(owner.id(), reader.id()) == 1
                    && net.dial_count(reader.id(), owner.id()) == 1,
                "the dials crossed"
            );

            let (dialler, acceptor) = if current(&owner, &reader).dialler() == owner.id() {
                (&mut owner, &mut reader)
            } else {
                (&mut reader, &mut owner)
            };
            let connection = current(dialler, acceptor);
            dialler.table.reopen_recon(&connection).await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            for collection in &collections {
                assert!(dialler.peered(*collection) && acceptor.peered(*collection));
            }

            // Frames cross the new stream both ways: each side ends one
            // peering, and the other hears it.
            dialler.select(collections[0], false);
            until("the dialler's unpeer", || !acceptor.peered(collections[0])).await;
            assert!(acceptor.peered(collections[1]));
            acceptor.select(collections[1], false);
            until("the acceptor's unpeer", || !dialler.peered(collections[1])).await;
            assert!(current(dialler, acceptor) == connection);
        }
    }
}
