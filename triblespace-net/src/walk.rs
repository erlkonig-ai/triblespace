//! Pull walks on `recon/1` (design 2.4, 2.5, D8).
//!
//! A walk frame names its collection, its kind and its number. The kind is
//! the PATCH walked: records, authorization evidence or held blob references.
//! The number is the puller's, counted per peer, collection and kind, so a
//! frame of an ended walk is told apart from its successor's. The frame kind
//! is the role: a request comes from the puller, a response from the
//! responder, and an end from either side, which a side byte says.
//!
//! | frame         | payload after collection, kind (u8), number (u16)                |
//! |---------------|------------------------------------------------------------------|
//! | WALK_REQUEST  | 0 open; 1 node: prefix; 2 value: key                              |
//! | WALK_RESPONSE | 0 summary: root, count; 1 branch; 2 leaf; 3 value: key, bytes    |
//! | WALK_END      | side (0 puller, 1 responder), reason (0 done, 1 refused, 2 failed)|
//!
//! A branch is its prefix (a length byte and the bytes), digest, leaf count
//! (u64), representative, end depth (u8) and children, each an edge byte, a
//! digest and a leaf count. A leaf is its prefix, digest and key: a value
//! travels only when the puller asks for it. Every key is 32 bytes relative
//! to its kind's base, and integers are big-endian. A kind or operation this
//! reader does not know skips the frame; a known one that does not parse is
//! malformed.

use triblespace_core::collection::CollectionHandle;

use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::patch_repair::{PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchSummary};
use crate::recon::{FRAME_WALK_END, FRAME_WALK_REQUEST, FRAME_WALK_RESPONSE, Malformed};

/// Bytes of every key a walk enumerates, relative to its kind's base.
const KEY_BYTES: usize = 32;
/// Collection handle, kind, number and operation.
const HEADER_BYTES: usize = 32 + 1 + 2 + 1;
/// One child of a branch: edge, digest and leaf count.
const CHILD_BYTES: usize = 1 + 32 + 8;

const OPEN: u8 = 0;
const NODE: u8 = 1;
const VALUE: u8 = 2;

const SUMMARY: u8 = 0;
const BRANCH: u8 = 1;
const LEAF: u8 = 2;
const VALUED: u8 = 3;

/// What a walk enumerates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum WalkKind {
    /// The collection's records: its COMMITs and DERIVEs.
    Records,
    /// Its authorization evidence, keyed by proof id under the collection.
    Authorization,
    /// The blobs it holds, as handles without values.
    References,
}

impl WalkKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Records => 0,
            Self::Authorization => 1,
            Self::References => 2,
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Records),
            1 => Some(Self::Authorization),
            2 => Some(Self::References),
            _ => None,
        }
    }
}

/// One walk, as both of its sides name it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WalkId {
    pub(crate) collection: CollectionHandle,
    pub(crate) kind: WalkKind,
    pub(crate) number: u16,
}

/// Why a walk ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndReason {
    /// The puller has what it walked for.
    Done,
    /// The responder does not send this collection to the puller.
    Refused,
    /// A side could not go on: an absent prefix or value, a failed check, or
    /// a deadline.
    Failed,
}

/// A puller's request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    /// Pin a snapshot and answer with its summary.
    Open,
    /// The node at this prefix of the pinned snapshot.
    Node(Vec<u8>),
    /// The value under this key.
    Value([u8; KEY_BYTES]),
}

/// A responder's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Response {
    Summary(PatchSummary),
    /// The node at a requested prefix. A leaf carries its key, not its value.
    Node {
        prefix: Vec<u8>,
        node: PatchNode<()>,
    },
    Value {
        key: [u8; KEY_BYTES],
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WalkBody {
    Request(Request),
    Response(Response),
    /// The walk ended at the side that sent this, the puller's or the
    /// responder's; its number retires.
    End {
        by_puller: bool,
        reason: EndReason,
    },
}

/// One frame of a pull walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkFrame {
    pub(crate) walk: WalkId,
    pub(crate) body: WalkBody,
}

impl WalkFrame {
    pub(crate) fn collection(&self) -> CollectionHandle {
        self.walk.collection
    }

    /// Append the payload after its collection; returns the frame kind.
    pub(crate) fn encode(&self, payload: &mut Vec<u8>) -> u8 {
        payload.push(self.walk.kind.wire());
        payload.extend_from_slice(&self.walk.number.to_be_bytes());
        match &self.body {
            WalkBody::Request(request) => {
                match request {
                    Request::Open => payload.push(OPEN),
                    Request::Node(prefix) => {
                        payload.push(NODE);
                        payload.extend_from_slice(prefix);
                    }
                    Request::Value(key) => {
                        payload.push(VALUE);
                        payload.extend_from_slice(key);
                    }
                }
                FRAME_WALK_REQUEST
            }
            WalkBody::Response(response) => {
                match response {
                    Response::Summary(summary) => {
                        payload.push(SUMMARY);
                        payload.extend_from_slice(&summary.root().unwrap_or_default());
                        payload.extend_from_slice(&summary.leaf_count().to_be_bytes());
                    }
                    Response::Node { prefix, node } => {
                        payload.push(match node {
                            PatchNode::Branch { .. } => BRANCH,
                            PatchNode::Leaf { .. } => LEAF,
                        });
                        let length = u8::try_from(prefix.len()).expect("a prefix fits its key");
                        payload.push(length);
                        payload.extend_from_slice(prefix);
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
                    }
                    Response::Value { key, bytes } => {
                        payload.push(VALUED);
                        payload.extend_from_slice(key);
                        payload.extend_from_slice(bytes);
                    }
                }
                FRAME_WALK_RESPONSE
            }
            WalkBody::End { by_puller, reason } => {
                payload.push(if *by_puller { 0 } else { 1 });
                payload.push(match reason {
                    EndReason::Done => 0,
                    EndReason::Refused => 1,
                    EndReason::Failed => 2,
                });
                FRAME_WALK_END
            }
        }
    }

    /// Decode a walk frame's whole payload, collection first. `None` is a
    /// walk kind or operation this reader does not know.
    pub(crate) fn decode(kind: u8, payload: &[u8]) -> Result<Option<Self>, Malformed> {
        if payload.len() < HEADER_BYTES {
            return Err(Malformed("walk frame shorter than its header"));
        }
        let collection = CollectionHandle::new(payload[..32].try_into().unwrap());
        let Some(walk_kind) = WalkKind::from_wire(payload[32]) else {
            return Ok(None);
        };
        let walk = WalkId {
            collection,
            kind: walk_kind,
            number: u16::from_be_bytes([payload[33], payload[34]]),
        };
        let operation = payload[35];
        let mut rest = Reader(&payload[HEADER_BYTES..]);
        let body = match (kind, operation) {
            (FRAME_WALK_REQUEST, OPEN) => WalkBody::Request(Request::Open),
            (FRAME_WALK_REQUEST, NODE) => {
                if rest.0.len() > KEY_BYTES {
                    return Err(Malformed("walk node prefix longer than its key"));
                }
                WalkBody::Request(Request::Node(rest.take(rest.0.len())?))
            }
            (FRAME_WALK_REQUEST, VALUE) => WalkBody::Request(Request::Value(rest.hash()?)),
            (FRAME_WALK_RESPONSE, SUMMARY) => {
                let root = rest.hash()?;
                let count = rest.u64()?;
                // A real root is a digest; all zeros stands for the empty set.
                let root = (root != [0; 32]).then_some(root);
                let summary = PatchSummary::new(root, count)
                    .map_err(|_| Malformed("walk summary root and count disagree"))?;
                WalkBody::Response(Response::Summary(summary))
            }
            (FRAME_WALK_RESPONSE, BRANCH | LEAF) => {
                let length = usize::from(rest.byte()?);
                if length > KEY_BYTES {
                    return Err(Malformed("walk node prefix longer than its key"));
                }
                let prefix = rest.take(length)?;
                let digest = rest.hash()?;
                let node = if operation == LEAF {
                    PatchNode::Leaf {
                        digest,
                        leaf: PatchLeaf {
                            key: rest.take(KEY_BYTES)?,
                            value: (),
                        },
                    }
                } else {
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
                };
                WalkBody::Response(Response::Node { prefix, node })
            }
            (FRAME_WALK_RESPONSE, VALUED) => {
                let key = rest.hash()?;
                if rest.0.len() > MAX_COLLECTION_LEAF_BYTES {
                    return Err(Malformed("walk value larger than a leaf"));
                }
                WalkBody::Response(Response::Value {
                    key,
                    bytes: rest.take(rest.0.len())?,
                })
            }
            (FRAME_WALK_END, side) => {
                if side > 1 {
                    return Err(Malformed("walk end from neither side"));
                }
                let reason = match rest.byte()? {
                    0 => EndReason::Done,
                    1 => EndReason::Refused,
                    // A reason this reader does not know still ends the walk.
                    _ => EndReason::Failed,
                };
                WalkBody::End {
                    by_puller: side == 0,
                    reason,
                }
            }
            _ => return Ok(None),
        };
        if !rest.0.is_empty() {
            return Err(Malformed("trailing bytes after a walk frame"));
        }
        Ok(Some(Self { walk, body }))
    }
}

/// The unread rest of a walk frame.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recon::Frame;

    fn walk(kind: WalkKind, number: u16) -> WalkId {
        WalkId {
            collection: CollectionHandle::new([7; 32]),
            kind,
            number,
        }
    }

    fn roundtrip(walk: WalkId, body: WalkBody) {
        let frame = Frame::Walk(WalkFrame { walk, body });
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= crate::recon::MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
    }

    #[test]
    fn every_walk_frame_round_trips() {
        let records = walk(WalkKind::Records, 0);
        roundtrip(records, WalkBody::Request(Request::Open));
        roundtrip(records, WalkBody::Request(Request::Node(Vec::new())));
        roundtrip(
            walk(WalkKind::Authorization, 9),
            WalkBody::Request(Request::Node(vec![1, 2, 3])),
        );
        roundtrip(records, WalkBody::Request(Request::Value([4; 32])));
        for summary in [
            PatchSummary::new(None, 0).unwrap(),
            PatchSummary::new(Some([5; 32]), 600).unwrap(),
        ] {
            roundtrip(records, WalkBody::Response(Response::Summary(summary)));
        }
        let children = (0..=255)
            .map(|edge| PatchChild {
                edge,
                digest: [edge; 32],
                leaf_count: u64::from(edge) + 1,
            })
            .collect();
        roundtrip(
            walk(WalkKind::References, u16::MAX),
            WalkBody::Response(Response::Node {
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
            }),
        );
        roundtrip(
            records,
            WalkBody::Response(Response::Node {
                prefix: Vec::new(),
                node: PatchNode::Leaf {
                    digest: [3; 32],
                    leaf: PatchLeaf {
                        key: vec![4; 32],
                        value: (),
                    },
                },
            }),
        );
        roundtrip(
            records,
            WalkBody::Response(Response::Value {
                key: [8; 32],
                bytes: vec![9; MAX_COLLECTION_LEAF_BYTES],
            }),
        );
        for (by_puller, reason) in [
            (true, EndReason::Done),
            (false, EndReason::Refused),
            (true, EndReason::Failed),
        ] {
            roundtrip(records, WalkBody::End { by_puller, reason });
        }
    }

    #[test]
    fn malformed_walk_frames_are_violations_and_unknown_ones_are_skipped() {
        let encode = |body| {
            Frame::Walk(WalkFrame {
                walk: walk(WalkKind::Records, 1),
                body,
            })
            .encode()
        };
        let (_, node) = encode(WalkBody::Request(Request::Node(vec![1; 32])));
        let (_, summary) = encode(WalkBody::Response(Response::Summary(
            PatchSummary::new(Some([5; 32]), 2).unwrap(),
        )));
        let (_, end) = encode(WalkBody::End {
            by_puller: true,
            reason: EndReason::Done,
        });
        let mut empty_root_with_leaves = summary.clone();
        empty_root_with_leaves[36..68].fill(0);
        let mut nonzero_root_without_leaves = summary.clone();
        nonzero_root_without_leaves[68..].fill(0);
        let mut third_side = end.clone();
        third_side[35] = 2;
        for (kind, payload) in [
            (FRAME_WALK_REQUEST, &node[..35]),
            (FRAME_WALK_REQUEST, &[&node[..], &[1]].concat()[..]),
            (FRAME_WALK_RESPONSE, &summary[..summary.len() - 1]),
            (FRAME_WALK_RESPONSE, &empty_root_with_leaves[..]),
            (FRAME_WALK_RESPONSE, &nonzero_root_without_leaves[..]),
            (FRAME_WALK_END, &end[..end.len() - 1]),
            (FRAME_WALK_END, &third_side[..]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let mut unknown_kind = node.clone();
        unknown_kind[32] = 3;
        assert_eq!(Frame::decode(FRAME_WALK_REQUEST, &unknown_kind), Ok(None));
        let mut unknown_operation = node;
        unknown_operation[35] = 9;
        assert_eq!(
            Frame::decode(FRAME_WALK_REQUEST, &unknown_operation),
            Ok(None)
        );
    }
}
