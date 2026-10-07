//! The frames of one bidirectional FIFO delta-subtree exchange.
//!
//! | kind | frame         | payload                         |
//! |------|---------------|---------------------------------|
//! | 0x01 | OPEN          | collection32, walk kind:u8      |
//! | 0x03 | SUBTREE       | depth:u8, prefix32, hash32, u64  |
//! | 0x05 | VALUE_REQUEST | key32                           |
//! | 0x06 | VALUE         | key32, nonempty bytes           |
//! | 0x07 | DONE          | empty                           |
//! | 0x08 | LANDED        | empty                           |
//!
//! SUBTREE has exactly73 payload bytes, or78 bytes with the ordinary five-byte
//! frame header. Integers are big-endian. Prefix bytes outside depth are zero;
//! depth0 is the ordinary empty-prefix delta-root commitment. An empty delta
//! has zero hash/count. A nonempty delta root can be compressed or a singleton;
//! its descendants arrive as more SUBTREE frames, not embedded child arrays.
//! Root/leaf have no separate frame kinds. Retired0x02/0x04 are unknown.
//!
//! A kind or OPEN walk kind not understood is skipped. A known payload must
//! decode completely and canonically; malformed frames end only the exchange.

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::PatchSummary;
use crate::recon::Malformed;
use crate::walk::{Reader, WalkKind, push_summary};

pub const FRAME_OPEN: u8 = 0x01;
pub const FRAME_SUBTREE: u8 = 0x03;
pub const FRAME_VALUE_REQUEST: u8 = 0x05;
pub const FRAME_VALUE: u8 = 0x06;
pub const FRAME_DONE: u8 = 0x07;
pub const FRAME_LANDED: u8 = 0x08;
pub const SUBTREE_BYTES: usize = 1 + 32 + 32 + 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    Open {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    Subtree {
        prefix: Vec<u8>,
        summary: PatchSummary,
    },
    ValueRequest {
        key: [u8; 32],
    },
    Value {
        key: [u8; 32],
        bytes: Vec<u8>,
    },
    Done,
    Landed,
}

impl Frame {
    pub(crate) fn encode(&self) -> (u8, Vec<u8>) {
        let mut payload = Vec::new();
        let kind = match self {
            Self::Open { collection, kind } => {
                payload.extend_from_slice(&collection.raw);
                payload.push(kind.wire());
                FRAME_OPEN
            }
            Self::Subtree { prefix, summary } => {
                assert!(prefix.len() <= 32, "a local subtree prefix fits its key");
                payload.push(prefix.len() as u8);
                let mut padded = [0; 32];
                padded[..prefix.len()].copy_from_slice(prefix);
                payload.extend_from_slice(&padded);
                push_summary(&mut payload, *summary);
                FRAME_SUBTREE
            }
            Self::ValueRequest { key } => {
                payload.extend_from_slice(key);
                FRAME_VALUE_REQUEST
            }
            Self::Value { key, bytes } => {
                payload.extend_from_slice(key);
                payload.extend_from_slice(bytes);
                FRAME_VALUE
            }
            Self::Done => FRAME_DONE,
            Self::Landed => FRAME_LANDED,
        };
        (kind, payload)
    }

    pub(crate) fn decode(kind: u8, payload: &[u8]) -> Result<Option<Self>, Malformed> {
        let mut rest = Reader(payload);
        let frame = match kind {
            FRAME_OPEN => {
                let collection = CollectionHandle::new(rest.hash()?);
                let Some(kind) = WalkKind::from_wire(rest.byte()?) else {
                    return Ok(None);
                };
                Self::Open { collection, kind }
            }
            FRAME_SUBTREE => {
                if payload.len() != SUBTREE_BYTES {
                    return Err(Malformed("subtree payload is not73 bytes"));
                }
                let depth = usize::from(rest.byte()?);
                if depth > 32 {
                    return Err(Malformed("subtree depth exceeds its key"));
                }
                let prefix = rest.hash()?;
                if prefix[depth..].iter().any(|byte| *byte != 0) {
                    return Err(Malformed("subtree prefix has nonzero padding"));
                }
                let summary = rest.summary()?;
                if depth != 0 && summary.root().is_none() {
                    return Err(Malformed("only the empty prefix may name an empty delta"));
                }
                Self::Subtree {
                    prefix: prefix[..depth].to_vec(),
                    summary,
                }
            }
            FRAME_VALUE_REQUEST => Self::ValueRequest { key: rest.hash()? },
            FRAME_VALUE => {
                let key = rest.hash()?;
                if rest.0.is_empty() {
                    return Err(Malformed("walk value without bytes"));
                }
                if rest.0.len() > MAX_COLLECTION_LEAF_BYTES {
                    return Err(Malformed("walk value larger than a leaf"));
                }
                Self::Value {
                    key,
                    bytes: rest.take(rest.0.len())?,
                }
            }
            FRAME_DONE => Self::Done,
            FRAME_LANDED => Self::Landed,
            _ => return Ok(None),
        };
        if !rest.0.is_empty() {
            return Err(Malformed("trailing bytes after a walk/1 frame"));
        }
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::MAX_RECON_FRAME_BYTES;

    fn roundtrip(frame: Frame) -> Vec<u8> {
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
        payload
    }

    #[test]
    fn every_frame_round_trips() {
        for kind in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ] {
            assert_eq!(
                roundtrip(Frame::Open {
                    collection: CollectionHandle::new([7; 32]),
                    kind
                })
                .len(),
                33
            );
        }
        for depth in 0..=32 {
            assert_eq!(
                roundtrip(Frame::Subtree {
                    prefix: vec![6; depth],
                    summary: PatchSummary::new(Some([5; 32]), 600).unwrap(),
                })
                .len(),
                SUBTREE_BYTES
            );
        }
        assert_eq!(
            roundtrip(Frame::Subtree {
                prefix: Vec::new(),
                summary: PatchSummary::new(None, 0).unwrap()
            })
            .len(),
            73
        );
        roundtrip(Frame::ValueRequest { key: [12; 32] });
        roundtrip(Frame::Value {
            key: [13; 32],
            bytes: vec![14],
        });
        roundtrip(Frame::Value {
            key: [13; 32],
            bytes: vec![15; MAX_COLLECTION_LEAF_BYTES],
        });
        assert!(roundtrip(Frame::Done).is_empty());
        assert!(roundtrip(Frame::Landed).is_empty());
    }

    #[test]
    fn subtree_wire_size_is_constant_and_has_no_child_array() {
        for count in [1, 2, 256, 70_000, u64::MAX] {
            for depth in [0, 1, 31, 32] {
                let payload = roundtrip(Frame::Subtree {
                    prefix: vec![6; depth],
                    summary: PatchSummary::new(Some([9; 32]), count).unwrap(),
                });
                assert_eq!(payload.len(), 73);
                assert_eq!(payload.len() + 5, 78);
                assert_eq!(payload[0], depth as u8);
                assert!(payload[1 + depth..33].iter().all(|byte| *byte == 0));
                assert_eq!(&payload[33..65], &[9; 32]);
                assert_eq!(&payload[65..], &count.to_be_bytes());
            }
        }
    }

    #[test]
    fn root_and_leaf_have_no_special_wire_kind() {
        assert_eq!(
            [
                FRAME_OPEN,
                FRAME_SUBTREE,
                FRAME_VALUE_REQUEST,
                FRAME_VALUE,
                FRAME_DONE,
                FRAME_LANDED
            ],
            [1, 3, 5, 6, 7, 8]
        );
        assert_eq!(Frame::decode(0x02, &[]), Ok(None));
        assert_eq!(Frame::decode(0x04, &[]), Ok(None));
        assert_eq!(Frame::decode(0x09, &[]), Ok(None));
    }

    #[test]
    fn malformed_payloads_are_malformed_and_unknown_kinds_are_skipped() {
        let (_, open) = Frame::Open {
            collection: CollectionHandle::new([7; 32]),
            kind: WalkKind::Records,
        }
        .encode();
        let (_, subtree) = Frame::Subtree {
            prefix: vec![6; 3],
            summary: PatchSummary::new(Some([5; 32]), 2).unwrap(),
        }
        .encode();
        let mut deep = subtree.clone();
        deep[0] = 33;
        let mut padding = subtree.clone();
        padding[32] = 1;
        let mut empty_child = subtree.clone();
        empty_child[33..].fill(0);
        let mut no_count = subtree.clone();
        no_count[65..].fill(0);
        let mut no_hash = subtree.clone();
        no_hash[33..65].fill(0);
        let (_, value) = Frame::Value {
            key: [13; 32],
            bytes: vec![14],
        }
        .encode();
        let (_, too_large) = Frame::Value {
            key: [13; 32],
            bytes: vec![14; MAX_COLLECTION_LEAF_BYTES + 1],
        }
        .encode();
        for (kind, payload) in [
            (FRAME_OPEN, &open[..32]),
            (FRAME_OPEN, &[&open[..], &[0]].concat()[..]),
            (FRAME_SUBTREE, &subtree[..72]),
            (FRAME_SUBTREE, &[&subtree[..], &[0]].concat()[..]),
            (FRAME_SUBTREE, &deep[..]),
            (FRAME_SUBTREE, &padding[..]),
            (FRAME_SUBTREE, &empty_child[..]),
            (FRAME_SUBTREE, &no_count[..]),
            (FRAME_SUBTREE, &no_hash[..]),
            (FRAME_VALUE_REQUEST, &subtree[..31]),
            (FRAME_VALUE_REQUEST, &subtree[..33]),
            (FRAME_VALUE, &value[..32]),
            (FRAME_VALUE, &value[..31]),
            (FRAME_VALUE, &too_large[..]),
            (FRAME_DONE, &[0][..]),
            (FRAME_LANDED, &[0][..]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let mut unknown = open.clone();
        unknown[32] = 3;
        assert_eq!(Frame::decode(FRAME_OPEN, &unknown), Ok(None));
        assert_eq!(Frame::decode(0x7F, b"anything"), Ok(None));
        assert_eq!(Frame::decode(0, &[]), Ok(None));
    }
}

/// `walk/1` streams over the simulated transport: opened on a connection,
/// accepted by its table, and handed to the walk task.
#[cfg(all(test, feature = "sim"))]
mod sim_tests {
    use super::*;

    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use tokio::io::AsyncReadExt as _;
    use tokio::sync::mpsc;

    use crate::connection::{
        ConnectionTable, MAX_REQUESTS_GLOBAL, MAX_REQUESTS_PER_CONNECTION, RESET_UNKNOWN,
        RESET_WALK_FAILED, Service, open_walk, read_frame, write_frame,
    };
    use crate::protocol::{PILE_SYNC_ALPN, TAG_WALK, send_u8};
    use crate::transport::sim::{SimConfig, SimNet, SimTransport};
    use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport, reset_code};
    use crate::walk::{Command, WalksHandle};

    /// A service that serves no request stream.
    #[derive(Clone)]
    struct NoRequests;

    impl Service for NoRequests {
        async fn serve<W, R>(
            &self,
            _peer: PeerId,
            tag: u8,
            _send: &mut W,
            _recv: &mut R,
        ) -> anyhow::Result<()>
        where
            W: SendStream,
            R: RecvStream,
        {
            anyhow::bail!("no request stream is served here: {tag:#x}")
        }
    }

    /// A node whose table dials and accepts.
    struct Node {
        peer: PeerId,
        table: ConnectionTable<SimTransport, NoRequests>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Node {
        fn join(net: &SimNet, key: &SigningKey) -> Self {
            let mut harness = net.join(key);
            let peer = harness.transport.local_id();
            let table = ConnectionTable::new(harness.transport.clone(), NoRequests);
            let accepting = table.clone();
            let server = tokio::spawn(async move {
                while let Some(incoming) = harness.incoming.recv().await {
                    accepting.accept(incoming.conn);
                }
            });
            Self {
                peer,
                table,
                server,
            }
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// Whether a read fails with the stream reset carrying `code`.
    async fn reads_reset<R: tokio::io::AsyncRead + Unpin>(recv: &mut R, code: u32) -> bool {
        match tokio::time::timeout(Duration::from_secs(30), recv.read(&mut [0; 1])).await {
            Ok(Err(error)) => reset_code(&error) == Some(code),
            _ => false,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_walk_stream_reaches_the_walk_task_with_its_opener_collection_and_kind() {
        let net = SimNet::new(
            0x3A1C,
            SimConfig {
                latency: Duration::from_millis(10)..Duration::from_millis(10),
            },
        );
        let opener = Node::join(&net, &SigningKey::from_bytes(&[1; 32]));
        let acceptor = Node::join(&net, &SigningKey::from_bytes(&[2; 32]));
        let collection = CollectionHandle::new([3; 32]);
        let connection = opener.table.connect(acceptor.peer).await.unwrap();

        // Before a walk task runs, a walk stream is reset; the connection
        // stays.
        let (_send, mut recv) = open_walk(&connection, collection, WalkKind::Records)
            .await
            .unwrap();
        assert!(reads_reset(&mut recv, RESET_WALK_FAILED).await);
        assert_eq!(opener.table.len(), 1);
        assert_eq!(acceptor.table.len(), 1);

        let (commands, mut incoming) = mpsc::unbounded_channel();
        acceptor.table.walks(WalksHandle(commands));
        for (index, kind) in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ]
        .into_iter()
        .enumerate()
        {
            let collection = CollectionHandle::new([index as u8; 32]);
            let (mut send, _recv) = open_walk(&connection, collection, kind).await.unwrap();
            let root = Frame::Subtree {
                prefix: Vec::new(),
                summary: PatchSummary::new(Some([5; 32]), 600).unwrap(),
            };
            let (frame, payload) = root.encode();
            write_frame(&mut send, frame, &payload).await.unwrap();
            let Some(Command::Incoming {
                peer,
                collection: opened,
                kind: opened_kind,
                mut recv,
                ..
            }) = incoming.recv().await
            else {
                panic!("the walk task never got the stream");
            };
            assert_eq!(peer, opener.peer);
            assert_eq!(opened, collection);
            assert_eq!(opened_kind, kind);
            // The stream carries on from the Open frame.
            let (frame, payload) = read_frame(&mut recv).await.unwrap().unwrap();
            assert_eq!(Frame::decode(frame, &payload), Ok(Some(root)));
        }

        // A walk stream takes no request permit, on either side.
        let mut opened = Vec::new();
        for _ in 0..MAX_REQUESTS_PER_CONNECTION + 1 {
            let halves = tokio::time::timeout(
                Duration::from_secs(1),
                open_walk(&connection, collection, WalkKind::Records),
            )
            .await
            .expect("opening a walk stream waits for no request permit")
            .unwrap();
            opened.push(halves);
            assert!(matches!(
                incoming.recv().await,
                Some(Command::Incoming { .. })
            ));
        }
        assert_eq!(acceptor.table.available_requests(), MAX_REQUESTS_GLOBAL);
        assert_eq!(opener.table.available_requests(), MAX_REQUESTS_GLOBAL);
        drop(opened);

        // A stream whose first frame is not an Open is reset, as is one that
        // sends nothing after its tag, and an unknown tag still resets.
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_u8(&mut send, TAG_WALK).await.unwrap();
        let (frame, payload) = Frame::Done.encode();
        write_frame(&mut send, frame, &payload).await.unwrap();
        assert!(reads_reset(&mut recv, RESET_WALK_FAILED).await);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_u8(&mut send, TAG_WALK).await.unwrap();
        assert!(reads_reset(&mut recv, RESET_WALK_FAILED).await);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_u8(&mut send, 0x7E).await.unwrap();
        assert!(reads_reset(&mut recv, RESET_UNKNOWN).await);
        assert!(incoming.try_recv().is_err());
        assert_eq!(opener.table.len(), 1);
        assert_eq!(acceptor.table.len(), 1);
    }

    /// Frames beyond the stream's credit wait for the reader: a sender whose
    /// receiver stops reading stalls instead of queueing without bound.
    #[tokio::test(start_paused = true)]
    async fn frames_beyond_the_stream_credit_wait_for_the_reader() {
        let net = SimNet::new(
            0x3A1D,
            SimConfig {
                latency: Duration::ZERO..Duration::ZERO,
            },
        );
        let dialer = net.join(&SigningKey::from_bytes(&[1; 32]));
        let mut acceptor = net.join(&SigningKey::from_bytes(&[2; 32]));
        let dialed = dialer
            .transport
            .dial(acceptor.transport.local_id(), PILE_SYNC_ALPN)
            .await
            .unwrap();
        let accepted = acceptor.incoming.recv().await.unwrap().conn;
        let (mut send, _recv) = dialed.open_bi().await.unwrap();
        let (_send, mut recv) = accepted.accept_bi().await.unwrap();
        // Twenty thousand constant-sized announcements exceed stream credit;
        // no hidden representative or child array is needed for the fixture.
        let (frame, payload) = Frame::Subtree {
            prefix: vec![6; 3],
            summary: PatchSummary::new(Some([1; 32]), 256).unwrap(),
        }
        .encode();
        assert_eq!(payload.len(), SUBTREE_BYTES);
        let frames = 20_000;
        let writer = async {
            for _ in 0..frames {
                write_frame(&mut send, frame, &payload).await.unwrap();
            }
        };
        tokio::pin!(writer);
        assert!(
            futures::poll!(writer.as_mut()).is_pending(),
            "the writer ran past the stream's credit without a reader"
        );
        let reader = async {
            let mut read = 0;
            while read < frames {
                let (kind, bytes) = read_frame(&mut recv).await.unwrap().unwrap();
                assert_eq!((kind, bytes.len()), (frame, payload.len()));
                read += 1;
            }
            read
        };
        let ((), read) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(writer, reader)
        })
        .await
        .expect("reading lets the writer finish");
        assert_eq!(read, frames);
    }
}
