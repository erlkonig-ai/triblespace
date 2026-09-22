//! Opaque, collection-scoped wakeups over stock `iroh-gossip` membership.
//!
//! A collection handle derives a domain-separated opaque gossip topic id and
//! is the discovery capability for that topic. Joining therefore has no
//! separate authorization exchange. The only application payload is a
//! fixed-width signed wake: it
//! says that one endpoint has some anti-entropy state under an opaque root.
//! Records, counts, blobs, proofs, and the anti-entropy protocol itself stay
//! outside this plane. Neighbor-only delivery lets the application coalesce
//! state by root, update repair contacts, and decide when to relay after repair.
//! Stock gossip does not forward these messages on the application's behalf.

use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures::StreamExt as _;
use iroh_base::EndpointId;
use iroh_gossip::api::{ApiError, Event as GossipEvent, GossipReceiver, GossipSender, Message};
use iroh_gossip::proto::DeliveryScope;
use iroh_gossip::{Gossip, TopicId};
use triblespace_core::collection::CollectionHandle;

/// Domain prefix for the signed wake transcript.
pub const COLLECTION_WAKE_TRANSCRIPT_DOMAIN: &[u8] = b"triblespace.collection.wake";

/// Current dense wake-envelope and signature-transcript version.
pub const COLLECTION_WAKE_VERSION: u8 = 4;

/// Exact number of bytes in a collection wake.
pub const COLLECTION_WAKE_WIRE_LEN: usize = 1 + 32 + 32 + 16 + 64;

const COLLECTION_WAKE_TRANSCRIPT_LEN: usize =
    COLLECTION_WAKE_TRANSCRIPT_DOMAIN.len() + 1 + 32 + 32 + 32 + 16;

/// An opaque root naming the state an origin can reconcile for one collection.
///
/// The wake plane neither interprets this value nor uses it as authority. Its
/// meaning belongs to the separately authorized anti-entropy protocol.
/// A collection implementation may derive it from a domain-separated product
/// of several summaries; no individual PATCH root or leaf count is privileged
/// by this wire format. After a wake, the receiver opens READ(C)-authorized
/// repair against the signed [`CollectionWake::origin`] and obtains the current
/// component summaries there.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionWakeRoot([u8; 32]);

impl CollectionWakeRoot {
    /// Wrap one opaque anti-entropy root.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the root bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for CollectionWakeRoot {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

/// A fixed-width collection wake signed by its claimed endpoint origin.
///
/// The collection is deliberately absent from the wire envelope because the
/// enclosing gossip topic already names it. It is nevertheless part of the
/// signature transcript, so replaying identical bytes on another collection
/// topic fails strict verification.
#[derive(Clone, Eq, PartialEq)]
pub struct CollectionWake {
    origin: EndpointId,
    root: CollectionWakeRoot,
    nonce: [u8; 16],
    signature: [u8; 64],
}

impl fmt::Debug for CollectionWake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectionWake")
            .field("origin", &self.origin)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl CollectionWake {
    /// Sign a wake with the same Ed25519 key used by the local iroh endpoint.
    pub fn sign(
        collection: CollectionHandle,
        root: CollectionWakeRoot,
        nonce: [u8; 16],
        signing_key: &SigningKey,
    ) -> Self {
        let origin = EndpointId::from_bytes(signing_key.verifying_key().as_bytes())
            .expect("an Ed25519 verifying key is a valid endpoint id");
        let transcript = wake_transcript(collection, origin, root, nonce);
        let signature = signing_key.sign(&transcript).to_bytes();
        Self {
            origin,
            root,
            nonce,
            signature,
        }
    }

    /// Decode exactly one dense envelope and strictly verify it for `collection`.
    pub fn decode_and_verify(
        collection: CollectionHandle,
        bytes: &[u8],
    ) -> Result<Self, CollectionWakeError> {
        if bytes.len() != COLLECTION_WAKE_WIRE_LEN {
            return Err(CollectionWakeError::InvalidLength {
                expected: COLLECTION_WAKE_WIRE_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != COLLECTION_WAKE_VERSION {
            return Err(CollectionWakeError::UnsupportedVersion(bytes[0]));
        }

        let mut origin_bytes = [0; 32];
        origin_bytes.copy_from_slice(&bytes[1..33]);
        let origin = EndpointId::from_bytes(&origin_bytes)
            .map_err(|_| CollectionWakeError::InvalidOrigin)?;

        let mut root = [0; 32];
        root.copy_from_slice(&bytes[33..65]);

        let mut nonce = [0; 16];
        nonce.copy_from_slice(&bytes[65..81]);

        let mut signature = [0; 64];
        signature.copy_from_slice(&bytes[81..]);
        let wake = Self {
            origin,
            root: CollectionWakeRoot::new(root),
            nonce,
            signature,
        };
        wake.verify(collection)?;
        Ok(wake)
    }

    /// Strictly verify this origin signature for the exact collection topic.
    pub fn verify(&self, collection: CollectionHandle) -> Result<(), CollectionWakeError> {
        let verifying_key = VerifyingKey::from_bytes(self.origin.as_bytes())
            .map_err(|_| CollectionWakeError::InvalidOrigin)?;
        let transcript = wake_transcript(collection, self.origin, self.root, self.nonce);
        verifying_key
            .verify_strict(&transcript, &Signature::from_bytes(&self.signature))
            .map_err(|_| CollectionWakeError::InvalidSignature)
    }

    /// Claimed origin, authenticated by the envelope signature.
    pub const fn origin(&self) -> EndpointId {
        self.origin
    }

    /// Opaque per-collection anti-entropy root.
    pub const fn root(&self) -> CollectionWakeRoot {
        self.root
    }

    /// Authenticated transport freshness annotation, not semantic identity.
    /// It has no ordering or authority meaning.
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    /// Encode this wake in its exact dense wire form.
    pub fn to_bytes(&self) -> [u8; COLLECTION_WAKE_WIRE_LEN] {
        let mut bytes = [0; COLLECTION_WAKE_WIRE_LEN];
        bytes[0] = COLLECTION_WAKE_VERSION;
        bytes[1..33].copy_from_slice(self.origin.as_bytes());
        bytes[33..65].copy_from_slice(self.root.as_bytes());
        bytes[65..81].copy_from_slice(&self.nonce);
        bytes[81..].copy_from_slice(&self.signature);
        bytes
    }

    /// Semantic state identity within the exact collection topic.
    ///
    /// Repair contacts, signatures, and freshness annotations may change
    /// without creating a new state. Callers must scope this key by collection
    /// and may still consume those annotations on a repeated root. Stock
    /// gossip's wire hash is deliberately not this application identity;
    /// neighbor-only delivery leaves semantic suppression to the application.
    pub const fn dedup_id(&self) -> [u8; 32] {
        self.root.0
    }
}

/// Structural or cryptographic rejection of a collection wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionWakeError {
    /// The envelope was not exactly [`COLLECTION_WAKE_WIRE_LEN`] bytes.
    InvalidLength { expected: usize, actual: usize },
    /// The envelope used an unsupported version byte.
    UnsupportedVersion(u8),
    /// The claimed origin bytes were not a valid Ed25519 endpoint key.
    InvalidOrigin,
    /// Strict Ed25519 verification failed for this collection and root.
    InvalidSignature,
}

impl fmt::Display for CollectionWakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid collection wake length: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported collection wake version {version}")
            }
            Self::InvalidOrigin => formatter.write_str("invalid collection wake origin"),
            Self::InvalidSignature => formatter.write_str("invalid collection wake signature"),
        }
    }
}

impl std::error::Error for CollectionWakeError {}

/// Transport-neutral collection wake plane used by the host protocol.
pub trait CollectionWakeNetwork: Clone + Send + Sync + 'static {
    /// One live exact-topic subscription.
    type Topic: CollectionWakeSubscription;

    /// Join the exact collection topic through transport-specific bootstrap
    /// peers. Possession of the collection handle is the discovery capability.
    fn subscribe_network(
        &self,
        collection: CollectionHandle,
        bootstrap: Vec<EndpointId>,
    ) -> impl std::future::Future<Output = anyhow::Result<Self::Topic>> + Send;
}

/// Transport-neutral live subscription for signed collection wakes.
pub trait CollectionWakeSubscription: Send + 'static {
    /// Try candidate contacts from authority, descriptor providers or prior wakes.
    fn join_wake_peers(
        &self,
        peers: Vec<EndpointId>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// Offer the local serving endpoint's current root to direct neighbors.
    fn broadcast_wake(
        &self,
        root: CollectionWakeRoot,
    ) -> impl std::future::Future<Output = anyhow::Result<CollectionWake>> + Send;

    /// Forward an existing offer unchanged to direct neighbors.
    ///
    /// The exact collection signature is checked before sending. Relaying
    /// neither claims that this endpoint serves the root nor changes the
    /// original authenticated repair contact.
    fn relay_wake(
        &self,
        wake: &CollectionWake,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    /// Receive the next typed transport or wake event.
    fn next_wake_event(
        &mut self,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<CollectionWakeEvent>>> + Send;
}

/// The stock gossip lifecycle and signing capability for collection wakes.
///
/// This type intentionally does not expose the underlying untyped gossip API.
/// Knowing a collection handle is sufficient to subscribe; authorization is
/// checked only when a receiver follows a wake into the separate anti-entropy
/// protocol.
#[derive(Clone)]
pub struct CollectionWakePlane {
    gossip: Gossip,
    signing_key: Arc<SigningKey>,
}

impl fmt::Debug for CollectionWakePlane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectionWakePlane")
            .field("origin", &self.origin())
            .finish_non_exhaustive()
    }
}

impl CollectionWakePlane {
    pub(crate) fn spawn(endpoint: &iroh::Endpoint) -> Self {
        let signing_key = SigningKey::from_bytes(&endpoint.secret_key().to_bytes());
        debug_assert_eq!(
            signing_key.verifying_key().as_bytes(),
            endpoint.id().as_bytes()
        );
        let gossip = Gossip::builder()
            // Stock gossip enforces a 512-byte minimum. The typed API below
            // emits only the 145-byte envelope and rejects every other size.
            .max_message_size(iroh_gossip::proto::MIN_MAX_MESSAGE_SIZE)
            .spawn(endpoint.clone());
        Self {
            gossip,
            signing_key: Arc::new(signing_key),
        }
    }

    pub(crate) fn protocol_handler(&self) -> Gossip {
        self.gossip.clone()
    }

    /// Local endpoint identity used to sign wakes.
    pub fn origin(&self) -> EndpointId {
        EndpointId::from_bytes(self.signing_key.verifying_key().as_bytes())
            .expect("an Ed25519 verifying key is a valid endpoint id")
    }

    /// Derive an opaque rendezvous topic from the collection handle.
    /// Gossip routers see only this domain-separated one-way image; the raw
    /// collection handle remains in local state and signed repair transcripts.
    ///
    /// This namespace isolates neighbor-only application relaying from the
    /// former v1 topic's automatic Swarm forwarding and duplicate pruning.
    pub fn topic_id(collection: CollectionHandle) -> TopicId {
        TopicId::from_bytes(blake3::derive_key(
            "triblespace/collection-wake-topic/v2",
            &collection.raw,
        ))
    }

    /// Join the collection mesh through zero or more stock gossip peers.
    ///
    /// No topic authorization is performed: possession of `collection` is
    /// intentionally the discovery capability.
    pub async fn subscribe(
        &self,
        collection: CollectionHandle,
        bootstrap: Vec<EndpointId>,
    ) -> Result<CollectionWakeTopic, ApiError> {
        let topic = self
            .gossip
            .subscribe(Self::topic_id(collection), bootstrap)
            .await?;
        let (sender, receiver) = topic.split();
        Ok(CollectionWakeTopic {
            collection,
            signing_key: self.signing_key.clone(),
            sender,
            receiver,
        })
    }
}

/// One subscription to the stock gossip mesh for an exact collection.
pub struct CollectionWakeTopic {
    collection: CollectionHandle,
    signing_key: Arc<SigningKey>,
    sender: GossipSender,
    receiver: GossipReceiver,
}

impl fmt::Debug for CollectionWakeTopic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectionWakeTopic")
            .field("collection", &self.collection)
            .field("neighbors", &self.receiver.neighbors().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl CollectionWakeTopic {
    /// Collection from which this topic's opaque id is derived.
    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Current direct stock-gossip neighbors.
    pub fn neighbors(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.receiver.neighbors()
    }

    /// Whether at least one direct gossip neighbor is present.
    pub fn is_joined(&self) -> bool {
        self.receiver.is_joined()
    }

    /// Wait until at least one direct stock-gossip neighbor is present.
    pub async fn joined(&mut self) -> Result<(), ApiError> {
        self.receiver.joined().await
    }

    /// Ask stock gossip to join additional bootstrap peers.
    pub async fn join_peers(&self, peers: Vec<EndpointId>) -> Result<(), ApiError> {
        self.sender.join_peers(peers).await
    }

    /// Sign and offer a local serving root to direct topic neighbors only.
    pub async fn broadcast(&self, root: CollectionWakeRoot) -> Result<CollectionWake, ApiError> {
        let wake = CollectionWake::sign(
            self.collection,
            root,
            rand::random::<[u8; 16]>(),
            &self.signing_key,
        );
        self.sender
            .broadcast_neighbors(wake.to_bytes().to_vec().into())
            .await?;
        Ok(wake)
    }

    /// Relay an existing signed offer without substituting the local identity.
    pub async fn relay(&self, wake: &CollectionWake) -> anyhow::Result<()> {
        wake.verify(self.collection)?;
        self.sender
            .broadcast_neighbors(wake.to_bytes().to_vec().into())
            .await?;
        Ok(())
    }

    /// Receive the next typed topology, wake, rejection, or lag event.
    pub async fn next_event(&mut self) -> Result<Option<CollectionWakeEvent>, ApiError> {
        let Some(event) = self.receiver.next().await else {
            return Ok(None);
        };
        let event = event?;
        Ok(Some(match event {
            GossipEvent::NeighborUp(peer) => CollectionWakeEvent::NeighborUp(peer),
            GossipEvent::NeighborDown(peer) => CollectionWakeEvent::NeighborDown(peer),
            GossipEvent::Lagged => CollectionWakeEvent::Lagged,
            GossipEvent::Received(message) => decode_received(self.collection, message),
        }))
    }
}

impl CollectionWakeNetwork for CollectionWakePlane {
    type Topic = CollectionWakeTopic;

    async fn subscribe_network(
        &self,
        collection: CollectionHandle,
        bootstrap: Vec<EndpointId>,
    ) -> anyhow::Result<Self::Topic> {
        Ok(self.subscribe(collection, bootstrap).await?)
    }
}

impl CollectionWakeSubscription for CollectionWakeTopic {
    async fn join_wake_peers(&self, peers: Vec<EndpointId>) -> anyhow::Result<()> {
        self.join_peers(peers).await.map_err(anyhow::Error::new)
    }
    async fn broadcast_wake(&self, root: CollectionWakeRoot) -> anyhow::Result<CollectionWake> {
        Ok(self.broadcast(root).await?)
    }

    async fn relay_wake(&self, wake: &CollectionWake) -> anyhow::Result<()> {
        self.relay(wake).await
    }

    async fn next_wake_event(&mut self) -> anyhow::Result<Option<CollectionWakeEvent>> {
        Ok(self.next_event().await?)
    }
}

/// A typed event from one collection wake mesh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionWakeEvent {
    /// A direct stock-gossip neighbor joined this collection mesh.
    NeighborUp(EndpointId),
    /// A direct stock-gossip neighbor left this collection mesh.
    NeighborDown(EndpointId),
    /// A strictly verified signed wake arrived.
    Received(ReceivedCollectionWake),
    /// An invalid application envelope arrived and was not exposed as a wake.
    Rejected {
        /// Immediate gossip hop that delivered the invalid bytes.
        delivered_from: EndpointId,
        /// Stock gossip delivery scope.
        scope: DeliveryScope,
        /// Reason the envelope was rejected.
        error: CollectionWakeError,
    },
    /// The bounded upstream subscription queue lagged.
    Lagged,
}

/// A verified wake plus transport delivery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedCollectionWake {
    /// Signed envelope. [`CollectionWake::origin`] is its authenticated author.
    pub wake: CollectionWake,
    /// Immediate gossip hop, which may be a relay and is not an author claim.
    pub delivered_from: EndpointId,
    /// Transport scope, not evidence that the signed origin is the last hop.
    /// Application-relayed offers arrive with neighbor scope too.
    pub scope: DeliveryScope,
}

fn decode_received(collection: CollectionHandle, message: Message) -> CollectionWakeEvent {
    match CollectionWake::decode_and_verify(collection, &message.content) {
        Ok(wake) => CollectionWakeEvent::Received(ReceivedCollectionWake {
            wake,
            delivered_from: message.delivered_from,
            scope: message.scope,
        }),
        Err(error) => CollectionWakeEvent::Rejected {
            delivered_from: message.delivered_from,
            scope: message.scope,
            error,
        },
    }
}

fn wake_transcript(
    collection: CollectionHandle,
    origin: EndpointId,
    root: CollectionWakeRoot,
    nonce: [u8; 16],
) -> [u8; COLLECTION_WAKE_TRANSCRIPT_LEN] {
    let mut transcript = [0; COLLECTION_WAKE_TRANSCRIPT_LEN];
    let mut offset = 0;
    transcript[..COLLECTION_WAKE_TRANSCRIPT_DOMAIN.len()]
        .copy_from_slice(COLLECTION_WAKE_TRANSCRIPT_DOMAIN);
    offset += COLLECTION_WAKE_TRANSCRIPT_DOMAIN.len();
    transcript[offset] = COLLECTION_WAKE_VERSION;
    offset += 1;
    transcript[offset..offset + 32].copy_from_slice(&collection.raw);
    offset += 32;
    transcript[offset..offset + 32].copy_from_slice(origin.as_bytes());
    offset += 32;
    transcript[offset..offset + 32].copy_from_slice(root.as_bytes());
    offset += 32;
    transcript[offset..].copy_from_slice(&nonce);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collection(byte: u8) -> CollectionHandle {
        CollectionHandle::new([byte; 32])
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn exact_codec_fixture_and_signature_round_trip() {
        let collection = collection(0x11);
        let wake = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x22; 32]),
            [0x23; 16],
            &key(7),
        );
        let encoded = wake.to_bytes();
        assert_eq!(encoded.len(), COLLECTION_WAKE_WIRE_LEN);
        assert_eq!(
            CollectionWake::decode_and_verify(collection, &encoded),
            Ok(wake)
        );
    }

    #[test]
    fn strict_verification_binds_collection_origin_and_root() {
        let expected = collection(0x31);
        let wake = CollectionWake::sign(
            expected,
            CollectionWakeRoot::new([0x41; 32]),
            [0x42; 16],
            &key(9),
        );
        let encoded = wake.to_bytes();

        assert_eq!(
            CollectionWake::decode_and_verify(collection(0x32), &encoded),
            Err(CollectionWakeError::InvalidSignature)
        );

        for index in [1, 33, 65, COLLECTION_WAKE_WIRE_LEN - 1] {
            let mut tampered = encoded;
            tampered[index] ^= 1;
            assert!(
                CollectionWake::decode_and_verify(expected, &tampered).is_err(),
                "tampering byte {index} must fail"
            );
        }

        let mut wrong_version = encoded;
        wrong_version[0] = COLLECTION_WAKE_VERSION + 1;
        assert_eq!(
            CollectionWake::decode_and_verify(expected, &wrong_version),
            Err(CollectionWakeError::UnsupportedVersion(
                COLLECTION_WAKE_VERSION + 1
            ))
        );
        assert_eq!(
            CollectionWake::decode_and_verify(expected, &encoded[..encoded.len() - 1]),
            Err(CollectionWakeError::InvalidLength {
                expected: COLLECTION_WAKE_WIRE_LEN,
                actual: COLLECTION_WAKE_WIRE_LEN - 1,
            })
        );
    }

    #[test]
    fn semantic_dedup_is_root_scoped_not_contact_or_nonce_identity() {
        let collection = collection(0x51);
        let signing_key = key(0x61);
        let first = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x71; 32]),
            [0x72; 16],
            &signing_key,
        );
        let same = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x71; 32]),
            [0x72; 16],
            &signing_key,
        );
        let next_root = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x72; 32]),
            [0x72; 16],
            &signing_key,
        );
        let next_nonce = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x71; 32]),
            [0x73; 16],
            &signing_key,
        );
        let next_origin = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x71; 32]),
            [0x72; 16],
            &key(0x62),
        );

        assert_eq!(first.to_bytes(), same.to_bytes());
        assert_eq!(first.dedup_id(), same.dedup_id());
        assert_ne!(first.dedup_id(), next_root.dedup_id());
        assert_eq!(first.dedup_id(), next_nonce.dedup_id());
        assert_eq!(first.dedup_id(), next_origin.dedup_id());
        assert_eq!(first.dedup_id(), *first.root().as_bytes());
        assert_ne!(first.to_bytes(), next_nonce.to_bytes());
        assert_ne!(first.to_bytes(), next_origin.to_bytes());
        assert!(next_nonce.verify(collection).is_ok());
        assert!(next_origin.verify(collection).is_ok());
    }

    #[test]
    fn wake_topic_is_a_deterministic_opaque_image_of_collection() {
        let handle = collection(0x52);
        let topic = CollectionWakePlane::topic_id(handle);
        assert_eq!(topic, CollectionWakePlane::topic_id(handle));
        assert_ne!(topic.as_bytes(), &handle.raw);
        assert_ne!(topic, CollectionWakePlane::topic_id(collection(0x53)));
        let legacy_swarm_topic = TopicId::from_bytes(blake3::derive_key(
            "triblespace/collection-wake-topic/v1",
            &handle.raw,
        ));
        assert_ne!(topic, legacy_swarm_topic);
    }

    #[test]
    fn signed_origin_is_independent_of_immediate_delivery_hop() {
        let collection = collection(0x81);
        let origin_key = key(0x82);
        let wake = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x83; 32]),
            [0x85; 16],
            &origin_key,
        );
        let relay = EndpointId::from_bytes(key(0x84).verifying_key().as_bytes()).unwrap();
        let event = decode_received(
            collection,
            Message {
                content: wake.to_bytes().to_vec().into(),
                scope: DeliveryScope::Neighbors,
                delivered_from: relay,
            },
        );

        let CollectionWakeEvent::Received(received) = event else {
            panic!("valid signed wake was rejected");
        };
        assert_eq!(received.wake.origin(), wake.origin());
        assert_ne!(received.wake.origin(), received.delivered_from);
        assert_eq!(received.delivered_from, relay);
        // Neighbor scope describes the transport hop even for an application
        // relay. The signed serving origin remains independent of that hop.
        assert!(received.scope.is_direct());
        assert_eq!(received.wake.to_bytes(), wake.to_bytes());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn neighbor_transport_relays_unchanged_offers_and_delivers_same_root_contacts() {
        use std::time::Duration;

        use iroh::endpoint::presets;
        use iroh::protocol::Router;
        use iroh::test_utils::test_transport::TestNetwork;

        async fn endpoint(network: &TestNetwork, key: &SigningKey) -> iroh::Endpoint {
            let secret = crate::identity::iroh_secret(key);
            let transport = network.create_transport(secret.public()).unwrap();
            iroh::Endpoint::builder(presets::N0)
                .secret_key(secret)
                .relay_mode(iroh::RelayMode::Disabled)
                .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
                .add_custom_transport(transport)
                .clear_ip_transports()
                .clear_address_lookup()
                .address_lookup(network.address_lookup())
                .bind()
                .await
                .unwrap()
        }

        async fn receive(topic: &mut CollectionWakeTopic) -> ReceivedCollectionWake {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match topic.next_wake_event().await.unwrap().unwrap() {
                        CollectionWakeEvent::Received(received) => return received,
                        CollectionWakeEvent::NeighborUp(_) => {}
                        other => panic!("unexpected wake event: {other:?}"),
                    }
                }
            })
            .await
            .expect("signed neighbor offer must arrive")
        }

        let network = TestNetwork::new();
        let relay_endpoint = endpoint(&network, &key(0x91)).await;
        let reader_endpoint = endpoint(&network, &key(0x92)).await;
        let relay_plane = CollectionWakePlane::spawn(&relay_endpoint);
        let reader_plane = CollectionWakePlane::spawn(&reader_endpoint);
        let relay_router = Router::builder(relay_endpoint)
            .accept(iroh_gossip::ALPN, relay_plane.protocol_handler())
            .spawn();
        let reader_router = Router::builder(reader_endpoint)
            .accept(iroh_gossip::ALPN, reader_plane.protocol_handler())
            .spawn();
        let collection = collection(0x93);
        let mut relay = relay_plane.subscribe(collection, Vec::new()).await.unwrap();
        let mut reader = reader_plane
            .subscribe(collection, vec![relay_plane.origin()])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            relay.joined().await.unwrap();
            reader.joined().await.unwrap();
        })
        .await
        .expect("stock topic neighbors must join");

        // This serving origin is not the forwarding endpoint. Relaying it
        // must not claim that the forwarding endpoint can serve the root.
        let offered = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x94; 32]),
            [0x95; 16],
            &key(0x90),
        );
        for _ in 0..2 {
            relay.relay_wake(&offered).await.unwrap();
            let received = receive(&mut reader).await;
            assert_eq!(received.wake.to_bytes(), offered.to_bytes());
            assert_eq!(received.delivered_from, relay_plane.origin());
            assert_ne!(received.wake.origin(), received.delivered_from);
            assert_eq!(received.scope, DeliveryScope::Neighbors);
        }

        // A new serving contact for the same semantic state must reach the
        // application, even after identical signed offers were delivered.
        let local_offer = relay.broadcast_wake(offered.root()).await.unwrap();
        let received = receive(&mut reader).await;
        assert_eq!(received.wake, local_offer);
        assert_eq!(received.wake.origin(), relay_plane.origin());
        assert_eq!(received.wake.dedup_id(), offered.dedup_id());
        assert_eq!(received.scope, DeliveryScope::Neighbors);

        let other_collection = CollectionHandle::new([0x96; 32]);
        let wrong_context =
            CollectionWake::sign(other_collection, offered.root(), [0x97; 16], &key(0x90));
        let error = relay.relay_wake(&wrong_context).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<CollectionWakeError>(),
            Some(&CollectionWakeError::InvalidSignature)
        );

        drop((relay, reader));
        tokio::time::timeout(Duration::from_secs(10), async {
            relay_router.shutdown().await.unwrap();
            reader_router.shutdown().await.unwrap();
        })
        .await
        .expect("stock gossip routers must shut down");
    }
}
