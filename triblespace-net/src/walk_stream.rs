//! The frames of `walk/1`: one push of one collection tree.
//!
//! The opener is the sender. After the stream's tag it sends one
//! [`Frame::Open`] naming the collection and the tree, then the tree's root
//! and, top down, the nodes the receiver has not confirmed. The receiver
//! answers every node with the children it already holds under the same
//! digest, which the sender then skips, asks for the values of the leaves it
//! lacks, and, once everything it asked for landed, says so with
//! [`Frame::Landed`]. [`crate::receive`] is the receiving side.
//!
//! A frame is its kind (one byte), a big-endian `u32` payload length and the
//! payload: the framing of `recon/1`, which [`crate::connection`] reads and
//! writes.
//!
//! | kind | frame         | payload                                 | from     |
//! |------|---------------|-----------------------------------------|----------|
//! | 0x01 | OPEN          | collection, kind                        | sender   |
//! | 0x02 | ROOT          | root, count                             | sender   |
//! | 0x03 | NODE          | node type, prefix, node                 | sender   |
//! | 0x04 | LEAF          | key                                     | sender   |
//! | 0x05 | HELD          | prefix, children                        | receiver |
//! | 0x06 | VALUE_REQUEST | key                                     | receiver |
//! | 0x07 | VALUE         | key, bytes                              | sender   |
//! | 0x08 | DONE          | empty                                   | sender   |
//! | 0x09 | LANDED        | empty                                   | receiver |
//!
//! A root is a digest, all zeros for the empty tree, and a `u64` leaf count;
//! a node type is 0 for a branch and 1 for a leaf; a prefix is a length byte
//! and the bytes; a node is what [`crate::walk`] puts on `recon/1`, after its
//! prefix. Children are 32 bytes: bit `i` (byte `i / 8`, bit `i % 8`) set
//! says the child at branch byte `i` is held under the same digest. Every key
//! is 32 bytes relative to its kind's base, and integers are big-endian.

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::{PatchNode, PatchSummary};
use crate::recon::Malformed;
use crate::walk::{Reader, WalkKind, push_node, push_summary, read_node, read_summary};

pub(crate) const FRAME_OPEN: u8 = 0x01;
pub(crate) const FRAME_ROOT: u8 = 0x02;
pub(crate) const FRAME_NODE: u8 = 0x03;
pub(crate) const FRAME_LEAF: u8 = 0x04;
pub(crate) const FRAME_HELD: u8 = 0x05;
pub(crate) const FRAME_VALUE_REQUEST: u8 = 0x06;
pub(crate) const FRAME_VALUE: u8 = 0x07;
pub(crate) const FRAME_DONE: u8 = 0x08;
pub(crate) const FRAME_LANDED: u8 = 0x09;

const BRANCH: u8 = 0;
const LEAF: u8 = 1;

/// One frame of a walk stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    /// The sender's first frame: the tree it pushes.
    Open {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    /// The pushed tree's root and count.
    Root {
        summary: PatchSummary,
    },
    /// A branch of the pushed tree, or a leaf without its value.
    Node {
        prefix: Vec<u8>,
        node: PatchNode<()>,
    },
    /// A leaf of the pushed tree, by key.
    Leaf {
        key: [u8; 32],
    },
    /// The children of the node at `prefix` the receiver holds under the
    /// same digest.
    Held {
        prefix: Vec<u8>,
        children: [u8; 32],
    },
    /// The receiver lacks the value under `key`.
    ValueRequest {
        key: [u8; 32],
    },
    Value {
        key: [u8; 32],
        bytes: Vec<u8>,
    },
    /// The sender pushed everything the receiver did not hold.
    Done,
    /// Everything the receiver asked for landed.
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
                payload.push(match node {
                    PatchNode::Branch { .. } => BRANCH,
                    PatchNode::Leaf { .. } => LEAF,
                });
                push_node(&mut payload, prefix, node);
                FRAME_NODE
            }
            Self::Leaf { key } => {
                payload.extend_from_slice(key);
                FRAME_LEAF
            }
            Self::Held { prefix, children } => {
                let length = u8::try_from(prefix.len()).expect("a prefix fits its key");
                payload.push(length);
                payload.extend_from_slice(prefix);
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

    /// Decode one frame. `None` is a kind, or a walk kind, this reader does
    /// not know.
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
                summary: read_summary(&mut rest)?,
            },
            FRAME_NODE => {
                let leaf = match rest.byte()? {
                    BRANCH => false,
                    LEAF => true,
                    _ => return Err(Malformed("walk node of an unknown type")),
                };
                let (prefix, node) = read_node(&mut rest, leaf)?;
                Self::Node { prefix, node }
            }
            FRAME_LEAF => Self::Leaf { key: rest.hash()? },
            FRAME_HELD => {
                let length = usize::from(rest.byte()?);
                if length > 32 {
                    return Err(Malformed("walk held prefix longer than its key"));
                }
                Self::Held {
                    prefix: rest.take(length)?,
                    children: rest.hash()?,
                }
            }
            FRAME_VALUE_REQUEST => Self::ValueRequest { key: rest.hash()? },
            FRAME_VALUE => {
                let key = rest.hash()?;
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
            return Err(Malformed("trailing bytes after a walk stream frame"));
        }
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::patch_repair::{PatchBranch, PatchChild, PatchLeaf};

    fn roundtrip(frame: Frame) {
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= crate::recon::MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
    }

    #[test]
    fn every_walk_stream_frame_round_trips() {
        roundtrip(Frame::Open {
            collection: CollectionHandle::new([7; 32]),
            kind: WalkKind::Authorization,
        });
        for summary in [
            PatchSummary::new(None, 0).unwrap(),
            PatchSummary::new(Some([5; 32]), 600).unwrap(),
        ] {
            roundtrip(Frame::Root { summary });
        }
        let children = (0..=255)
            .map(|edge| PatchChild {
                edge,
                digest: [edge; 32],
                leaf_count: u64::from(edge) + 1,
            })
            .collect();
        roundtrip(Frame::Node {
            prefix: vec![6; 32],
            node: PatchNode::Branch {
                digest: [1; 32],
                leaf_count: 1 << 40,
                branch: PatchBranch {
                    representative: vec![2; 32],
                    end_depth: 31,
                    children,
                },
            },
        });
        roundtrip(Frame::Node {
            prefix: Vec::new(),
            node: PatchNode::Leaf {
                digest: [3; 32],
                leaf: PatchLeaf {
                    key: vec![4; 32],
                    value: (),
                },
            },
        });
        roundtrip(Frame::Leaf { key: [8; 32] });
        roundtrip(Frame::Held {
            prefix: vec![1, 2, 3],
            children: [0xA5; 32],
        });
        roundtrip(Frame::ValueRequest { key: [9; 32] });
        roundtrip(Frame::Value {
            key: [8; 32],
            bytes: vec![9; MAX_COLLECTION_LEAF_BYTES],
        });
        roundtrip(Frame::Done);
        roundtrip(Frame::Landed);
    }

    #[test]
    fn malformed_walk_stream_frames_are_violations_and_unknown_ones_are_skipped() {
        let (_, open) = Frame::Open {
            collection: CollectionHandle::new([7; 32]),
            kind: WalkKind::Records,
        }
        .encode();
        let (_, root) = Frame::Root {
            summary: PatchSummary::new(Some([5; 32]), 2).unwrap(),
        }
        .encode();
        let (_, held) = Frame::Held {
            prefix: vec![1],
            children: [0; 32],
        }
        .encode();
        let (_, value) = Frame::Value {
            key: [8; 32],
            bytes: vec![9; MAX_COLLECTION_LEAF_BYTES],
        }
        .encode();
        let mut empty_root_with_leaves = root.clone();
        empty_root_with_leaves[..32].fill(0);
        let mut unknown_node_type = vec![2];
        unknown_node_type.extend_from_slice(&held[..2]);
        for (kind, payload) in [
            (FRAME_OPEN, &open[..32]),
            (FRAME_OPEN, &[&open[..], &[0]].concat()[..]),
            (FRAME_ROOT, &root[..39]),
            (FRAME_ROOT, &empty_root_with_leaves[..]),
            (FRAME_NODE, &unknown_node_type[..]),
            (FRAME_LEAF, &open[..31]),
            (FRAME_HELD, &held[..33]),
            (FRAME_VALUE_REQUEST, &[&open[..32], &[0]].concat()[..]),
            (FRAME_VALUE, &[&value[..], &[0]].concat()[..]),
            (FRAME_DONE, &[0][..]),
            (FRAME_LANDED, &[0][..]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let mut unknown_kind = open.clone();
        unknown_kind[32] = 3;
        assert_eq!(Frame::decode(FRAME_OPEN, &unknown_kind), Ok(None));
        assert_eq!(Frame::decode(0x7F, b"anything"), Ok(None));
    }
}
