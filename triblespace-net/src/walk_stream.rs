//! The frames of `walk/1`: one push of one collection tree (design: walk
//! streams). The opener sends the stream's tag ([`TAG_WALK`]), then OPEN,
//! and is the push's sender; the acceptor is its receiver. A frame is its
//! kind, a big-endian `u32` payload length and the payload, as `recon/1`
//! frames it ([`crate::connection::write_frame`]).
//!
//! | kind | frame         | payload                                | from     |
//! |------|---------------|----------------------------------------|----------|
//! | 0x01 | OPEN          | collection, kind (u8)                  | sender   |
//! | 0x02 | ROOT          | root (zeros for empty), count (u64)    | sender   |
//! | 0x03 | NODE          | node                                   | sender   |
//! | 0x04 | LEAF          | key                                    | sender   |
//! | 0x05 | HELD          | prefix, held children (32 bytes)       | receiver |
//! | 0x06 | VALUE_REQUEST | key                                    | receiver |
//! | 0x07 | VALUE         | key, bytes                             | sender   |
//! | 0x08 | DONE          | empty                                  | sender   |
//! | 0x09 | LANDED        | empty                                  | receiver |
//!
//! A node is encoded as a pull walk's node response is ([`crate::walk`]): a
//! branch byte (1) or leaf byte (2), its prefix (a length byte and the
//! bytes), its digest, then for a branch its leaf count (u64), its
//! representative, its end depth (u8) and its children, each an edge byte, a
//! digest and a leaf count (u64); for a leaf its key. A root is encoded as a
//! walk summary is. Every key is 32 bytes relative to its kind's base, and
//! integers are big-endian. The held children of a HELD frame are a bitmap:
//! bit `i` (byte `i / 8`, bit `i % 8`, least significant first) set means
//! the receiver holds the child at edge byte `i` of the node at that prefix
//! with the same digest. A kind this reader does not know skips the frame;
//! a known one that does not parse is malformed.
//!
//! [`TAG_WALK`]: crate::connection::TAG_WALK

// The walks task reads and writes these on `walk/1`; until it does, only
// the push and the tests use them.
#![allow(dead_code)]

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::{PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchSummary};
use crate::recon::Malformed;
use crate::walk::WalkKind;

/// Bytes of every key a push enumerates, relative to its kind's base.
pub(crate) const KEY_BYTES: usize = 32;
/// One child of a branch: edge, digest and leaf count.
const CHILD_BYTES: usize = 1 + 32 + 8;

pub(crate) const OPEN: u8 = 0x01;
pub(crate) const ROOT: u8 = 0x02;
pub(crate) const NODE: u8 = 0x03;
pub(crate) const LEAF: u8 = 0x04;
pub(crate) const HELD: u8 = 0x05;
pub(crate) const VALUE_REQUEST: u8 = 0x06;
pub(crate) const VALUE: u8 = 0x07;
pub(crate) const DONE: u8 = 0x08;
pub(crate) const LANDED: u8 = 0x09;

/// A node's first byte: a branch or a leaf, as the pull walk writes them.
const BRANCH: u8 = 1;
const LEAF_NODE: u8 = 2;

/// One frame of a `walk/1` push.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    /// The sender's first frame: which tree it pushes.
    Open {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    /// The summary of the pinned tree.
    Root {
        summary: PatchSummary,
    },
    /// One node of the pinned tree the receiver may lack.
    Node {
        prefix: Vec<u8>,
        node: PatchNode<()>,
    },
    /// One leaf of the pinned tree the receiver may lack; it asks for the
    /// value if it lacks it.
    Leaf {
        key: [u8; KEY_BYTES],
    },
    /// The receiver's answer to a NODE: the children it holds with the same
    /// digest, which the sender then skips.
    Held {
        prefix: Vec<u8>,
        children: [u8; 32],
    },
    ValueRequest {
        key: [u8; KEY_BYTES],
    },
    Value {
        key: [u8; KEY_BYTES],
        bytes: Vec<u8>,
    },
    /// The sender walked everything and every NODE was answered.
    Done,
    /// Everything the receiver asked for landed: the pushed root is
    /// confirmed.
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
                OPEN
            }
            Self::Root { summary } => {
                payload.extend_from_slice(&summary.root().unwrap_or_default());
                payload.extend_from_slice(&summary.leaf_count().to_be_bytes());
                ROOT
            }
            Self::Node { prefix, node } => {
                payload.push(match node {
                    PatchNode::Branch { .. } => BRANCH,
                    PatchNode::Leaf { .. } => LEAF_NODE,
                });
                push_prefix(&mut payload, prefix);
                payload.extend_from_slice(&node.digest());
                match node {
                    PatchNode::Branch {
                        leaf_count, branch, ..
                    } => {
                        payload.extend_from_slice(&leaf_count.to_be_bytes());
                        payload.extend_from_slice(&branch.representative);
                        payload.push(branch.end_depth);
                        for child in &branch.children {
                            payload.push(child.edge);
                            payload.extend_from_slice(&child.digest);
                            payload.extend_from_slice(&child.leaf_count.to_be_bytes());
                        }
                    }
                    PatchNode::Leaf { leaf, .. } => payload.extend_from_slice(&leaf.key),
                }
                NODE
            }
            Self::Leaf { key } => {
                payload.extend_from_slice(key);
                LEAF
            }
            Self::Held { prefix, children } => {
                push_prefix(&mut payload, prefix);
                payload.extend_from_slice(children);
                HELD
            }
            Self::ValueRequest { key } => {
                payload.extend_from_slice(key);
                VALUE_REQUEST
            }
            Self::Value { key, bytes } => {
                payload.extend_from_slice(key);
                payload.extend_from_slice(bytes);
                VALUE
            }
            Self::Done => DONE,
            Self::Landed => LANDED,
        };
        (kind, payload)
    }

    /// Decode one frame. `None` is a kind, or a walk kind, this reader does
    /// not know.
    pub(crate) fn decode(kind: u8, payload: &[u8]) -> Result<Option<Self>, Malformed> {
        let mut rest = Reader(payload);
        let frame = match kind {
            OPEN => {
                let collection = CollectionHandle::new(rest.hash()?);
                let Some(kind) = WalkKind::from_wire(rest.byte()?) else {
                    return Ok(None);
                };
                Self::Open { collection, kind }
            }
            ROOT => {
                let root = rest.hash()?;
                let count = rest.u64()?;
                // A real root is a digest; all zeros stands for the empty set.
                let root = (root != [0; 32]).then_some(root);
                let summary = PatchSummary::new(root, count)
                    .map_err(|_| Malformed("walk root and count disagree"))?;
                Self::Root { summary }
            }
            NODE => {
                let shape = rest.byte()?;
                let prefix = rest.prefix()?;
                let digest = rest.hash()?;
                let node = match shape {
                    LEAF_NODE => PatchNode::Leaf {
                        digest,
                        leaf: PatchLeaf {
                            key: rest.take(KEY_BYTES)?,
                            value: (),
                        },
                    },
                    BRANCH => {
                        let leaf_count = rest.u64()?;
                        let representative = rest.take(KEY_BYTES)?;
                        let end_depth = rest.byte()?;
                        if rest.0.len() % CHILD_BYTES != 0 {
                            return Err(Malformed("walk branch children overrun their frame"));
                        }
                        let mut children = Vec::with_capacity(rest.0.len() / CHILD_BYTES);
                        while !rest.0.is_empty() {
                            children.push(PatchChild {
                                edge: rest.byte()?,
                                digest: rest.hash()?,
                                leaf_count: rest.u64()?,
                            });
                        }
                        PatchNode::Branch {
                            digest,
                            leaf_count,
                            branch: PatchBranch {
                                representative,
                                end_depth,
                                children,
                            },
                        }
                    }
                    _ => return Err(Malformed("walk node neither branch nor leaf")),
                };
                Self::Node { prefix, node }
            }
            LEAF => Self::Leaf { key: rest.hash()? },
            HELD => Self::Held {
                prefix: rest.prefix()?,
                children: rest.hash()?,
            },
            VALUE_REQUEST => Self::ValueRequest { key: rest.hash()? },
            VALUE => {
                let key = rest.hash()?;
                if rest.0.len() > MAX_COLLECTION_LEAF_BYTES {
                    return Err(Malformed("walk value larger than a leaf"));
                }
                Self::Value {
                    key,
                    bytes: rest.take(rest.0.len())?,
                }
            }
            DONE => Self::Done,
            LANDED => Self::Landed,
            _ => return Ok(None),
        };
        if !rest.0.is_empty() {
            return Err(Malformed("trailing bytes after a walk frame"));
        }
        Ok(Some(frame))
    }
}

/// Whether the held-children bitmap of a HELD frame marks `edge`.
pub(crate) fn held(children: &[u8; 32], edge: u8) -> bool {
    children[usize::from(edge >> 3)] & (1 << (edge & 7)) != 0
}

/// Mark `edge` in the held-children bitmap of a HELD frame.
pub(crate) fn hold(children: &mut [u8; 32], edge: u8) {
    children[usize::from(edge >> 3)] |= 1 << (edge & 7);
}

fn push_prefix(payload: &mut Vec<u8>, prefix: &[u8]) {
    payload.push(u8::try_from(prefix.len()).expect("a prefix fits its key"));
    payload.extend_from_slice(prefix);
}

/// The unread rest of a frame.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<Vec<u8>, Malformed> {
        if self.0.len() < length {
            return Err(Malformed("walk frame shorter than its fields"));
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken.to_vec())
    }

    fn byte(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn hash(&mut self) -> Result<[u8; 32], Malformed> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn prefix(&mut self) -> Result<Vec<u8>, Malformed> {
        let length = usize::from(self.byte()?);
        if length > KEY_BYTES {
            return Err(Malformed("walk prefix longer than its key"));
        }
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(frame: Frame) {
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= crate::recon::MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
    }

    #[test]
    fn every_walk_stream_frame_round_trips() {
        for kind in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ] {
            roundtrip(Frame::Open {
                collection: CollectionHandle::new([7; 32]),
                kind,
            });
        }
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
        roundtrip(Frame::Leaf { key: [4; 32] });
        let mut held_children = [0; 32];
        hold(&mut held_children, 0);
        hold(&mut held_children, 9);
        hold(&mut held_children, 255);
        assert!(held(&held_children, 9) && !held(&held_children, 10));
        roundtrip(Frame::Held {
            prefix: vec![1, 2, 3],
            children: held_children,
        });
        roundtrip(Frame::ValueRequest { key: [8; 32] });
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
            collection: CollectionHandle::new([1; 32]),
            kind: WalkKind::Records,
        }
        .encode();
        let (_, root) = Frame::Root {
            summary: PatchSummary::new(Some([5; 32]), 2).unwrap(),
        }
        .encode();
        let (_, node) = Frame::Node {
            prefix: vec![1; 32],
            node: PatchNode::Leaf {
                digest: [3; 32],
                leaf: PatchLeaf {
                    key: vec![4; 32],
                    value: (),
                },
            },
        }
        .encode();
        let (_, held) = Frame::Held {
            prefix: vec![1],
            children: [0; 32],
        }
        .encode();
        let mut empty_root_with_leaves = root.clone();
        empty_root_with_leaves[..32].fill(0);
        let mut nonzero_root_without_leaves = root.clone();
        nonzero_root_without_leaves[32..].fill(0);
        let mut long_prefix = node.clone();
        long_prefix[1] = 33;
        let mut odd_shape = node.clone();
        odd_shape[0] = 3;
        for (kind, payload) in [
            (OPEN, &open[..32]),
            (OPEN, &[&open[..], &[0]].concat()[..]),
            (ROOT, &root[..root.len() - 1]),
            (ROOT, &empty_root_with_leaves[..]),
            (ROOT, &nonzero_root_without_leaves[..]),
            (NODE, &node[..node.len() - 1]),
            (NODE, &long_prefix[..]),
            (NODE, &odd_shape[..]),
            (LEAF, &[0; 31][..]),
            (HELD, &held[..held.len() - 1]),
            (VALUE_REQUEST, &[0; 33][..]),
            (VALUE, &[0; 31][..]),
            (DONE, &[0][..]),
            (LANDED, &[0][..]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let mut unknown_walk_kind = open;
        unknown_walk_kind[32] = 3;
        assert_eq!(Frame::decode(OPEN, &unknown_walk_kind), Ok(None));
        assert_eq!(Frame::decode(0x7F, b"anything"), Ok(None));
    }
}
