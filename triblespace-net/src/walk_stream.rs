//! The frames of `walk/1`, the stream one exchange of a collection's tree
//! rides.
//!
//! A `walk/1` stream carries one collection's tree of one kind both ways:
//! each side's delta against the tree the two agreed on, and each side's
//! requests for the values the other's delta names. A frame is its kind
//! (one byte), a big-endian `u32` payload length and the payload, at most
//! [`crate::recon::MAX_RECON_FRAME_BYTES`], the framing
//! [`crate::connection`] reads and writes.
//!
//! | kind | frame         | payload                                | from   |
//! |------|---------------|----------------------------------------|--------|
//! | 0x01 | OPEN          | collection, walk kind (u8)             | opener |
//! | 0x02 | ROOT          | summary: root, leaf count              | both   |
//! | 0x03 | NODE          | tag, prefix, node                      | both   |
//! | 0x04 | LEAF          | key                                    | both   |
//! | 0x05 | VALUE_REQUEST | key                                    | both   |
//! | 0x06 | VALUE         | key, bytes (at least one)              | both   |
//! | 0x07 | DONE          | empty                                  | both   |
//! | 0x08 | LANDED        | empty                                  | both   |
//!
//! The opener sends OPEN; then each side sends its ROOT and the NODEs and
//! LEAFs of its delta, breadth first, and DONE. A NODE at a prefix carries
//! the node there, whose children announce, by digest, what the side holds
//! under it; a LEAF names a leaf by key alone. Values stay pull: a side
//! asks with VALUE_REQUEST for the leaves it lacks, and a VALUE answers one.
//! LANDED says everything a side asked for landed; once both have crossed,
//! the exchange is confirmed ([`crate::exchange`]).
//!
//! A prefix is a length byte and at most 32 bytes. A summary and a node are
//! laid out by [`crate::walk`]'s own code; a node's tag byte says whether it
//! is a branch or a leaf. Integers are big-endian. A kind this reader does
//! not know, or an OPEN of a walk kind it does not know, is skipped; a known
//! kind whose payload does not parse is malformed, and so is a VALUE without
//! bytes.

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::{PatchNode, PatchSummary};
use crate::recon::Malformed;
use crate::walk::{Reader, WalkKind, node_tag, push_node, push_summary};

/// The opener's first frame: the collection and the kind of tree exchanged.
pub const FRAME_OPEN: u8 = 0x01;
/// The summary of a side's pinned tree.
pub const FRAME_ROOT: u8 = 0x02;
/// One node of a side's delta, at its prefix.
pub const FRAME_NODE: u8 = 0x03;
/// One leaf of a side's delta, by key.
pub const FRAME_LEAF: u8 = 0x04;
/// A side asks for the value under a key.
pub const FRAME_VALUE_REQUEST: u8 = 0x05;
/// The value under a key.
pub const FRAME_VALUE: u8 = 0x06;
/// A side sent its whole delta.
pub const FRAME_DONE: u8 = 0x07;
/// Everything a side asked for landed.
pub const FRAME_LANDED: u8 = 0x08;

/// One frame of a `walk/1` stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    Open {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    Root {
        summary: PatchSummary,
    },
    /// A node at a prefix. A leaf carries its key, not its value.
    Node {
        prefix: Vec<u8>,
        node: PatchNode<()>,
    },
    Leaf {
        key: [u8; 32],
    },
    ValueRequest {
        key: [u8; 32],
    },
    /// Never empty: a value is at least one byte.
    Value {
        key: [u8; 32],
        bytes: Vec<u8>,
    },
    Done,
    Landed,
}

impl Frame {
    /// The frame's kind and payload.
    pub(crate) fn encode(&self) -> (u8, Vec<u8>) {
        let mut payload = Vec::new();
        let kind = match self {
            Self::Open { collection, kind } => {
                payload.extend_from_slice(&collection.raw);
                payload.push(kind.wire());
                FRAME_OPEN
            }
            Self::Root { summary } => {
                push_summary(&mut payload, *summary);
                FRAME_ROOT
            }
            Self::Node { prefix, node } => {
                payload.push(node_tag(node));
                push_node(&mut payload, prefix, node);
                FRAME_NODE
            }
            Self::Leaf { key } => {
                payload.extend_from_slice(key);
                FRAME_LEAF
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

    /// Decode one frame. `None` is a kind, or an Open of a walk kind, this
    /// reader does not know.
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
            FRAME_ROOT => Self::Root {
                summary: rest.summary()?,
            },
            FRAME_NODE => {
                let tag = rest.byte()?;
                let (prefix, node) = rest.node(tag)?;
                Self::Node { prefix, node }
            }
            FRAME_LEAF => Self::Leaf { key: rest.hash()? },
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

    use crate::patch_repair::{PatchBranch, PatchChild, PatchLeaf};
    use crate::recon::MAX_RECON_FRAME_BYTES;

    fn roundtrip(frame: Frame) -> Vec<u8> {
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
        payload
    }

    fn branch(prefix: Vec<u8>, children: u8) -> Frame {
        Frame::Node {
            prefix,
            node: PatchNode::Branch {
                digest: [1; 32],
                leaf_count: 1 << 40,
                branch: PatchBranch {
                    representative: vec![2; 32],
                    end_depth: 31,
                    children: (0..children)
                        .map(|edge| PatchChild {
                            edge,
                            digest: [edge; 32],
                            leaf_count: u64::from(edge) + 1,
                        })
                        .collect(),
                },
            },
        }
    }

    fn leaf(prefix: Vec<u8>) -> Frame {
        Frame::Node {
            prefix,
            node: PatchNode::Leaf {
                digest: [3; 32],
                leaf: PatchLeaf {
                    key: vec![4; 32],
                    value: (),
                },
            },
        }
    }

    #[test]
    fn every_frame_round_trips() {
        for kind in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ] {
            let open = roundtrip(Frame::Open {
                collection: CollectionHandle::new([7; 32]),
                kind,
            });
            assert_eq!(open.len(), 33);
        }
        roundtrip(Frame::Root {
            summary: PatchSummary::new(None, 0).unwrap(),
        });
        roundtrip(Frame::Root {
            summary: PatchSummary::new(Some([5; 32]), 600).unwrap(),
        });
        roundtrip(branch(Vec::new(), 255));
        roundtrip(branch(vec![6; 31], 2));
        roundtrip(branch(vec![6; 32], 0));
        roundtrip(leaf(Vec::new()));
        roundtrip(leaf(vec![8; 32]));
        roundtrip(Frame::Leaf { key: [9; 32] });
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

    /// The kinds are 0x01 to 0x08 in the order of the table: no HELD exists.
    #[test]
    fn the_kinds_are_dense_from_open_to_landed() {
        assert_eq!(
            [
                FRAME_OPEN,
                FRAME_ROOT,
                FRAME_NODE,
                FRAME_LEAF,
                FRAME_VALUE_REQUEST,
                FRAME_VALUE,
                FRAME_DONE,
                FRAME_LANDED
            ],
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(Frame::decode(0x09, &[]), Ok(None));
    }

    #[test]
    fn malformed_payloads_are_malformed_and_unknown_kinds_are_skipped() {
        let (_, open) = Frame::Open {
            collection: CollectionHandle::new([7; 32]),
            kind: WalkKind::Records,
        }
        .encode();
        let (_, root) = Frame::Root {
            summary: PatchSummary::new(Some([5; 32]), 2).unwrap(),
        }
        .encode();
        let mut empty_root_with_leaves = root.clone();
        empty_root_with_leaves[..32].fill(0);
        let mut root_without_leaves = root.clone();
        root_without_leaves[32..].fill(0);
        let (_, node) = branch(vec![6; 3], 4).encode();
        let mut third_node_tag = node.clone();
        third_node_tag[0] = 3;
        let mut long_prefix = node.clone();
        long_prefix[1] = 33;
        let (_, value) = Frame::Value {
            key: [13; 32],
            bytes: vec![14; 2],
        }
        .encode();
        let (_, too_large) = Frame::Value {
            key: [13; 32],
            bytes: vec![14; MAX_COLLECTION_LEAF_BYTES],
        }
        .encode();
        let too_large = [&too_large[..], &[0]].concat();
        for (kind, payload) in [
            (FRAME_OPEN, &open[..32]),
            (FRAME_OPEN, &[&open[..], &[0]].concat()[..]),
            (FRAME_ROOT, &root[..39]),
            (FRAME_ROOT, &[&root[..], &[0]].concat()[..]),
            (FRAME_ROOT, &empty_root_with_leaves[..]),
            (FRAME_ROOT, &root_without_leaves[..]),
            (FRAME_NODE, &node[..node.len() - 1]),
            (FRAME_NODE, &[&node[..], &[0]].concat()[..]),
            (FRAME_NODE, &third_node_tag[..]),
            (FRAME_NODE, &long_prefix[..]),
            (FRAME_NODE, &node[..36]),
            (FRAME_LEAF, &node[..31]),
            (FRAME_LEAF, &node[..33]),
            (FRAME_VALUE_REQUEST, &node[..31]),
            (FRAME_VALUE_REQUEST, &node[..33]),
            // A value is at least one byte.
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
        let mut unknown_walk_kind = open.clone();
        unknown_walk_kind[32] = 3;
        assert_eq!(Frame::decode(FRAME_OPEN, &unknown_walk_kind), Ok(None));
        assert_eq!(Frame::decode(0x7F, b"anything"), Ok(None));
        assert_eq!(Frame::decode(0x00, &[]), Ok(None));
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
    use crate::patch_repair::{PatchBranch, PatchChild};
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
            let root = Frame::Root {
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
        // Two hundred full branches: about two megabytes, more than a
        // stream's credit.
        let (frame, payload) = Frame::Node {
            prefix: vec![6; 3],
            node: PatchNode::Branch {
                digest: [1; 32],
                leaf_count: 256,
                branch: PatchBranch {
                    representative: vec![2; 32],
                    end_depth: 4,
                    children: (0..=255)
                        .map(|edge| PatchChild {
                            edge,
                            digest: [edge; 32],
                            leaf_count: 1,
                        })
                        .collect(),
                },
            },
        }
        .encode();
        let frames = 200;
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
