//! The frames of `walk/1`, the stream one push of a collection's tree rides.
//!
//! A `walk/1` stream carries one collection's tree of one kind one way: from
//! the side that opened it, the sender, to the side that accepted it, the
//! receiver. A frame is its kind (one byte), a big-endian `u32` payload
//! length and the payload, at most [`crate::recon::MAX_RECON_FRAME_BYTES`],
//! the framing [`crate::connection`] reads and writes.
//!
//! | kind | frame         | payload                                | from     |
//! |------|---------------|----------------------------------------|----------|
//! | 0x01 | OPEN          | collection, walk kind (u8)             | sender   |
//! | 0x02 | ROOT          | summary: root, leaf count              | sender   |
//! | 0x03 | NODE          | tag, prefix, node                      | sender   |
//! | 0x04 | LEAF          | key                                    | sender   |
//! | 0x05 | HELD          | prefix, 256-bit child bitmap           | receiver |
//! | 0x06 | VALUE_REQUEST | key                                    | receiver |
//! | 0x07 | VALUE         | key, bytes (at least one)              | sender   |
//! | 0x08 | DONE          | empty                                  | sender   |
//! | 0x09 | LANDED        | empty                                  | receiver |
//!
//! The sender opens with OPEN and its ROOT, then pushes the nodes of its
//! tree the receiver has not confirmed, each a NODE at a prefix. The
//! receiver answers each NODE with a HELD whose bit `i` (byte `i / 8`, bit
//! `i % 8`, least significant first: [`hold`] sets it and [`held`] reads it)
//! says it holds the child at branch byte `i` with the same digest, and the
//! sender skips those subtrees. A LEAF names a leaf by key alone. Values stay pull: the receiver
//! asks with VALUE_REQUEST for the leaves it lacks, and a VALUE answers one.
//! DONE ends the push, and LANDED says everything the receiver asked for
//! landed: the pushed root is then the one the sender knows the receiver
//! holds.
//!
//! A prefix is a length byte and at most 32 bytes. A summary and a node are
//! laid out as the pull walk's frames lay them out, by [`crate::walk`]'s own
//! code; a node's tag byte says whether it is a branch or a leaf. Integers
//! are big-endian. A kind this reader does not know, or an OPEN of a walk
//! kind it does not know, is skipped; a known kind whose payload does not
//! parse is malformed, and so is a VALUE without bytes.

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::{PatchNode, PatchSummary};
use crate::recon::Malformed;
use crate::walk::{Reader, WalkKind, node_tag, push_node, push_prefix, push_summary};

/// The sender's first frame: the collection and the kind of tree it pushes.
pub(crate) const FRAME_OPEN: u8 = 0x01;
/// The summary of the pushed tree.
pub(crate) const FRAME_ROOT: u8 = 0x02;
/// One node of the pushed tree, at its prefix.
pub(crate) const FRAME_NODE: u8 = 0x03;
/// One leaf of the pushed tree, by key.
pub(crate) const FRAME_LEAF: u8 = 0x04;
/// The receiver's answer to a NODE: which children it holds with the same
/// digest.
pub(crate) const FRAME_HELD: u8 = 0x05;
/// The receiver asks for the value under a key.
pub(crate) const FRAME_VALUE_REQUEST: u8 = 0x06;
/// The value under a key.
pub(crate) const FRAME_VALUE: u8 = 0x07;
/// The sender pushed everything.
pub(crate) const FRAME_DONE: u8 = 0x08;
/// Everything the receiver asked for landed.
pub(crate) const FRAME_LANDED: u8 = 0x09;

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
    /// Bit `i` of `children` set: the child at branch byte `i` of the node at
    /// `prefix` is held with the same digest.
    Held {
        prefix: Vec<u8>,
        children: [u8; 32],
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
            Self::Held { prefix, children } => {
                push_prefix(&mut payload, prefix);
                payload.extend_from_slice(children);
                FRAME_HELD
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
            FRAME_HELD => Self::Held {
                prefix: rest.prefix()?,
                children: rest.hash()?,
            },
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

/// Whether the held-children bitmap of a HELD frame marks the child at
/// `edge`: bit `edge` is byte `edge / 8`, bit `edge % 8`, least significant
/// first. The receiver builds the bitmap with [`hold`], and the sender reads
/// it with this.
pub(crate) fn held(children: &[u8; 32], edge: u8) -> bool {
    children[usize::from(edge >> 3)] & (1 << (edge & 7)) != 0
}

/// Mark the child at `edge` in the held-children bitmap of a HELD frame.
pub(crate) fn hold(children: &mut [u8; 32], edge: u8) {
    children[usize::from(edge >> 3)] |= 1 << (edge & 7);
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
        roundtrip(Frame::Held {
            prefix: Vec::new(),
            children: [0xFF; 32],
        });
        roundtrip(Frame::Held {
            prefix: vec![10; 32],
            children: [0; 32],
        });
        roundtrip(Frame::Held {
            prefix: vec![11; 3],
            children: [0x80; 32],
        });
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

    /// The held bitmap puts branch byte `i` at byte `i / 8`, bit `i % 8`,
    /// least significant first, and a HELD carries it as it is.
    #[test]
    fn held_bits_are_byte_i_over_8_bit_i_mod_8_least_significant_first() {
        let mut children = [0; 32];
        for edge in [0, 7, 8, 9, 255] {
            assert!(!held(&children, edge));
            hold(&mut children, edge);
            assert!(held(&children, edge));
        }
        let mut expected = [0; 32];
        expected[0] = 0b1000_0001;
        expected[1] = 0b0000_0011;
        expected[31] = 0b1000_0000;
        assert_eq!(children, expected);
        assert!(!held(&children, 10) && !held(&children, 254));
        assert_eq!(
            (0..=255).filter(|edge| held(&children, *edge)).count(),
            5
        );
        let payload = roundtrip(Frame::Held {
            prefix: vec![1, 2, 3],
            children,
        });
        assert_eq!(payload[4..], children);
    }

    /// A node is laid out as the pull walk lays it out, after its tag.
    #[test]
    fn nodes_and_summaries_share_the_pull_walks_layout() {
        use crate::recon::Frame as ReconFrame;
        use crate::walk::{Response, WalkBody, WalkFrame, WalkId};

        let walk = WalkId {
            collection: CollectionHandle::new([7; 32]),
            kind: WalkKind::Records,
            number: 0,
        };
        for frame in [branch(vec![6; 3], 4), leaf(vec![6; 3])] {
            let (_, pushed) = frame.encode();
            let Frame::Node { prefix, node } = frame else {
                unreachable!()
            };
            let (_, pulled) = ReconFrame::Walk(WalkFrame {
                walk,
                body: WalkBody::Response(Response::Node { prefix, node }),
            })
            .encode();
            // The pull walk's header is its collection, kind, number and
            // the node's tag as its operation.
            assert_eq!(pushed, pulled[35..]);
        }
        let summary = PatchSummary::new(Some([5; 32]), 600).unwrap();
        let (_, pushed) = Frame::Root { summary }.encode();
        let (_, pulled) = ReconFrame::Walk(WalkFrame {
            walk,
            body: WalkBody::Response(Response::Summary(summary)),
        })
        .encode();
        assert_eq!(pushed, pulled[36..]);
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
        let (_, held) = Frame::Held {
            prefix: vec![1; 2],
            children: [0xFF; 32],
        }
        .encode();
        let mut held_long_prefix = held.clone();
        held_long_prefix[0] = 33;
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
            (FRAME_HELD, &held[..held.len() - 1]),
            (FRAME_HELD, &[&held[..], &[0]].concat()[..]),
            (FRAME_HELD, &held_long_prefix[..]),
            (FRAME_HELD, &[][..]),
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
    use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport};
    use crate::walk::{Command, Pulls};

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
            Ok(Err(error)) => {
                error.kind() == std::io::ErrorKind::ConnectionReset
                    && error.to_string().contains(&format!("code {code}"))
            }
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
        acceptor.table.walks(Pulls(commands));
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
