//! The frames of `recon/1`, the one long-lived stream on each connection.
//!
//! A frame is its kind (one byte), a big-endian `u32` payload length and the
//! payload, at most [`MAX_RECON_FRAME_BYTES`]; [`crate::connection`] reads and
//! writes that framing. Every frame about a collection starts with the
//! collection's 32-byte handle, so the frames of every collection share the
//! stream. A reader skips a kind it does not know. A known kind whose payload
//! does not parse is a protocol violation and closes the connection.
//!
//! | kind | frame          | payload                                      | from |
//! |------|----------------|----------------------------------------------|------|
//! | 0x01 | OPEN           | dialler sequence number, `u64`               | M6   |
//! | 0x02 | PROOF_DIGEST   | reserved                                     | M10  |
//! | 0x10 | PEER_REQUEST   | collection, flags, credentials               | M7   |
//! | 0x11 | PEER_ACCEPT    | collection, flags                            | M7   |
//! | 0x12 | PEER_REFUSE    | collection                                   | M7   |
//! | 0x13 | PEER_FLAGS     | collection, flags                            | M7   |
//! | 0x14 | CREDENTIAL     | collection, credentials                      | M7   |
//! | 0x15 | UNPEER         | collection                                   | M7   |
//! | 0x20 | ANNOUNCE       | collection, root, flags, held-set digest     | M8   |
//! | 0x30 | WALK_REQUEST   | reserved                                     | M9   |
//! | 0x31 | WALK_RESPONSE  | reserved                                     | M9   |
//! | 0x32 | WALK_END       | reserved                                     | M9   |
//!
//! Flags are one byte: bit 0 is the send flag, bit 1 the full flag, and in a
//! PEER_REQUEST bit 2 marks an invitation. An ANNOUNCE has its own flags
//! byte after the root: bit 0 marks a reply, and bit 1 says the sender's
//! 32-byte held-set digest follows. Other bits are ignored.
//!
//! Credentials are a big-endian `u16` count followed by that many proofs, each
//! a big-endian `u16` length and the proof's bytes, ending exactly at the end
//! of the payload. A proof whose bytes do not decode is skipped, as anything
//! a reader cannot model is; a list that overruns the payload is malformed.
//! Credentials that do not fit one PEER_REQUEST go first, in CREDENTIAL
//! frames ([`request_frames`]).

use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::CollectionHandle;

use crate::protocol::RawHash;

/// Largest `recon/1` frame payload.
pub const MAX_RECON_FRAME_BYTES: u32 = 64 * 1024;

/// The dialler's first frame: its sequence number as a big-endian `u64`.
pub const FRAME_OPEN: u8 = 0x01;
/// Ask to peer for a collection, or invite a key whose request was refused.
pub const FRAME_PEER_REQUEST: u8 = 0x10;
/// Accept a peering request, with the acceptor's flags.
pub const FRAME_PEER_ACCEPT: u8 = 0x11;
/// Refuse a peering request. `recon/1` stays open.
pub const FRAME_PEER_REFUSE: u8 = 0x12;
/// A side's flags on an existing peering changed.
pub const FRAME_PEER_FLAGS: u8 = 0x13;
/// More of the sender's credentials for a collection.
pub const FRAME_CREDENTIAL: u8 = 0x14;
/// End the peering for a collection.
pub const FRAME_UNPEER: u8 = 0x15;
/// The sender's root for a collection.
pub const FRAME_ANNOUNCE: u8 = 0x20;

const FLAG_SEND: u8 = 0x01;
const FLAG_FULL: u8 = 0x02;
const FLAG_INVITATION: u8 = 0x04;
const ANNOUNCE_REPLY: u8 = 0x01;
const ANNOUNCE_HELD: u8 = 0x02;

/// Collection handle, flags byte and credential count.
const REQUEST_HEADER_BYTES: usize = 32 + 1 + 2;

/// One side's flags on a peering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flags {
    /// The side admits its peer: the collection flows from it to the peer.
    pub send: bool,
    /// The side replicates the collection in full.
    pub full: bool,
}

/// One decoded `recon/1` frame after the opening one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// The asker's flags and its credentials for the collection: its proofs
    /// naming itself, truncated there. An invitation comes from a side that
    /// refused the receiver's request and now admits it.
    PeerRequest {
        collection: CollectionHandle,
        flags: Flags,
        invitation: bool,
        credentials: Vec<CapabilityProof>,
    },
    PeerAccept {
        collection: CollectionHandle,
        flags: Flags,
    },
    PeerRefuse {
        collection: CollectionHandle,
    },
    PeerFlags {
        collection: CollectionHandle,
        flags: Flags,
    },
    Credential {
        collection: CollectionHandle,
        credentials: Vec<CapabilityProof>,
    },
    Unpeer {
        collection: CollectionHandle,
    },
    /// The sender's root for the collection, to a neighbour it sends to.
    /// Between two full neighbours it carries the sender's held-set digest.
    /// A reply answers a different announcement and is never answered.
    Announce {
        collection: CollectionHandle,
        root: RawHash,
        held_digest: Option<RawHash>,
        reply: bool,
    },
}

/// A frame of a known kind whose payload does not parse.
#[derive(Debug, Eq, PartialEq)]
pub struct Malformed(pub &'static str);

impl Frame {
    /// The collection the frame is about.
    pub fn collection(&self) -> CollectionHandle {
        match self {
            Self::PeerRequest { collection, .. }
            | Self::PeerAccept { collection, .. }
            | Self::PeerRefuse { collection }
            | Self::PeerFlags { collection, .. }
            | Self::Credential { collection, .. }
            | Self::Unpeer { collection }
            | Self::Announce { collection, .. } => *collection,
        }
    }

    /// The frame's kind and payload.
    pub fn encode(&self) -> (u8, Vec<u8>) {
        let mut payload = self.collection().raw.to_vec();
        let kind = match self {
            Self::PeerRequest {
                flags,
                invitation,
                credentials,
                ..
            } => {
                let invitation = if *invitation { FLAG_INVITATION } else { 0 };
                payload.push(flag_byte(*flags) | invitation);
                push_credentials(&mut payload, credentials);
                FRAME_PEER_REQUEST
            }
            Self::PeerAccept { flags, .. } => {
                payload.push(flag_byte(*flags));
                FRAME_PEER_ACCEPT
            }
            Self::PeerRefuse { .. } => FRAME_PEER_REFUSE,
            Self::PeerFlags { flags, .. } => {
                payload.push(flag_byte(*flags));
                FRAME_PEER_FLAGS
            }
            Self::Credential { credentials, .. } => {
                push_credentials(&mut payload, credentials);
                FRAME_CREDENTIAL
            }
            Self::Unpeer { .. } => FRAME_UNPEER,
            Self::Announce {
                root,
                held_digest,
                reply,
                ..
            } => {
                payload.extend_from_slice(root);
                payload.push(
                    (if *reply { ANNOUNCE_REPLY } else { 0 })
                        | (if held_digest.is_some() {
                            ANNOUNCE_HELD
                        } else {
                            0
                        }),
                );
                if let Some(held) = held_digest {
                    payload.extend_from_slice(held);
                }
                FRAME_ANNOUNCE
            }
        };
        (kind, payload)
    }

    /// Decode one frame. `None` is a kind this reader does not know.
    pub fn decode(kind: u8, payload: &[u8]) -> Result<Option<Self>, Malformed> {
        let fixed = |length: usize| {
            if payload.len() == length {
                Ok(CollectionHandle::new(payload[..32].try_into().unwrap()))
            } else {
                Err(Malformed("recon/1 frame has the wrong length"))
            }
        };
        Ok(Some(match kind {
            FRAME_PEER_REQUEST => {
                let (collection, rest) = collection(payload)?;
                let (&flags, rest) = rest
                    .split_first()
                    .ok_or(Malformed("peer request without flags"))?;
                Self::PeerRequest {
                    collection,
                    flags: flags_of(flags),
                    invitation: flags & FLAG_INVITATION != 0,
                    credentials: credentials(rest)?,
                }
            }
            FRAME_PEER_ACCEPT => Self::PeerAccept {
                collection: fixed(33)?,
                flags: flags_of(payload[32]),
            },
            FRAME_PEER_REFUSE => Self::PeerRefuse {
                collection: fixed(32)?,
            },
            FRAME_PEER_FLAGS => Self::PeerFlags {
                collection: fixed(33)?,
                flags: flags_of(payload[32]),
            },
            FRAME_CREDENTIAL => {
                let (collection, rest) = collection(payload)?;
                Self::Credential {
                    collection,
                    credentials: credentials(rest)?,
                }
            }
            FRAME_UNPEER => Self::Unpeer {
                collection: fixed(32)?,
            },
            FRAME_ANNOUNCE => {
                let flags = *payload
                    .get(64)
                    .ok_or(Malformed("announcement without flags"))?;
                let held = flags & ANNOUNCE_HELD != 0;
                Self::Announce {
                    collection: fixed(if held { 97 } else { 65 })?,
                    root: payload[32..64].try_into().unwrap(),
                    held_digest: held.then(|| payload[65..].try_into().unwrap()),
                    reply: flags & ANNOUNCE_REPLY != 0,
                }
            }
            _ => return Ok(None),
        }))
    }
}

/// A peering request carrying `credentials`. Those that do not fit the
/// request go first, in CREDENTIAL frames, so the receiver holds them all
/// when it decides.
pub fn request_frames(
    collection: CollectionHandle,
    flags: Flags,
    invitation: bool,
    credentials: &[CapabilityProof],
) -> Vec<Frame> {
    let mut chunks = chunks(credentials);
    let last = chunks.pop().unwrap_or_default();
    let mut frames = chunks
        .into_iter()
        .map(|credentials| Frame::Credential {
            collection,
            credentials,
        })
        .collect::<Vec<_>>();
    frames.push(Frame::PeerRequest {
        collection,
        flags,
        invitation,
        credentials: last,
    });
    frames
}

/// `credentials` in as few CREDENTIAL frames as hold them.
pub fn credential_frames(
    collection: CollectionHandle,
    credentials: &[CapabilityProof],
) -> Vec<Frame> {
    chunks(credentials)
        .into_iter()
        .map(|credentials| Frame::Credential {
            collection,
            credentials,
        })
        .collect()
}

/// Split credentials into lists that each fit one frame beside the largest
/// header, a PEER_REQUEST's. At least one list, possibly empty.
fn chunks(credentials: &[CapabilityProof]) -> Vec<Vec<CapabilityProof>> {
    let budget = MAX_RECON_FRAME_BYTES as usize - REQUEST_HEADER_BYTES;
    let mut chunks = vec![Vec::new()];
    let mut used = 0;
    for proof in credentials {
        let cost = 2 + proof.as_bytes().len();
        let full = used + cost > budget || chunks.last().unwrap().len() == usize::from(u16::MAX);
        if full {
            chunks.push(Vec::new());
            used = 0;
        }
        chunks.last_mut().unwrap().push(proof.clone());
        used += cost;
    }
    chunks
}

fn flag_byte(flags: Flags) -> u8 {
    (if flags.send { FLAG_SEND } else { 0 }) | (if flags.full { FLAG_FULL } else { 0 })
}

fn flags_of(byte: u8) -> Flags {
    Flags {
        send: byte & FLAG_SEND != 0,
        full: byte & FLAG_FULL != 0,
    }
}

fn collection(payload: &[u8]) -> Result<(CollectionHandle, &[u8]), Malformed> {
    if payload.len() < 32 {
        return Err(Malformed("recon/1 frame shorter than its collection"));
    }
    let (handle, rest) = payload.split_at(32);
    Ok((CollectionHandle::new(handle.try_into().unwrap()), rest))
}

fn push_credentials(payload: &mut Vec<u8>, credentials: &[CapabilityProof]) {
    let count = u16::try_from(credentials.len()).expect("credentials are chunked per frame");
    payload.extend_from_slice(&count.to_be_bytes());
    for proof in credentials {
        let bytes = proof.as_bytes();
        let length = u16::try_from(bytes.len()).expect("a proof is shorter than 64 KiB");
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(bytes);
    }
}

fn credentials(mut rest: &[u8]) -> Result<Vec<CapabilityProof>, Malformed> {
    let mut take = |length: usize| {
        if rest.len() < length {
            return Err(Malformed("credentials overrun their frame"));
        }
        let (taken, remaining) = rest.split_at(length);
        rest = remaining;
        Ok(taken)
    };
    let count = u16::from_be_bytes(take(2)?.try_into().unwrap());
    let mut proofs = Vec::new();
    for _ in 0..count {
        let length = u16::from_be_bytes(take(2)?.try_into().unwrap());
        if let Ok(proof) = CapabilityProof::from_bytes(take(usize::from(length))?) {
            proofs.push(proof);
        }
    }
    if !rest.is_empty() {
        return Err(Malformed("trailing bytes after credentials"));
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use triblespace_core::capability::CapabilityResource;
    use triblespace_core::collection::read_capability;

    fn handle(byte: u8) -> CollectionHandle {
        CollectionHandle::new([byte; 32])
    }

    fn proof(byte: u8) -> CapabilityProof {
        CapabilityProof::new(
            CapabilityResource::from(handle(1)),
            &SigningKey::from_bytes(&[byte; 32]),
            read_capability(),
            SigningKey::from_bytes(&[byte.wrapping_add(1); 32]).verifying_key(),
        )
    }

    fn roundtrip(frame: Frame) {
        let (kind, payload) = frame.encode();
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
    }

    #[test]
    fn every_frame_round_trips() {
        let flags = Flags {
            send: true,
            full: false,
        };
        roundtrip(Frame::PeerRequest {
            collection: handle(1),
            flags,
            invitation: true,
            credentials: vec![proof(2), proof(3)],
        });
        roundtrip(Frame::PeerRequest {
            collection: handle(1),
            flags: Flags::default(),
            invitation: false,
            credentials: Vec::new(),
        });
        roundtrip(Frame::PeerAccept {
            collection: handle(2),
            flags: Flags {
                send: false,
                full: true,
            },
        });
        roundtrip(Frame::PeerRefuse {
            collection: handle(3),
        });
        roundtrip(Frame::PeerFlags {
            collection: handle(4),
            flags,
        });
        roundtrip(Frame::Credential {
            collection: handle(5),
            credentials: vec![proof(6)],
        });
        roundtrip(Frame::Unpeer {
            collection: handle(6),
        });
        roundtrip(Frame::Announce {
            collection: handle(7),
            root: [8; 32],
            held_digest: None,
            reply: false,
        });
        roundtrip(Frame::Announce {
            collection: handle(9),
            root: [10; 32],
            held_digest: Some([11; 32]),
            reply: true,
        });
    }

    #[test]
    fn credentials_beyond_one_request_go_first_in_credential_frames() {
        let one = proof(2);
        let per_frame =
            (MAX_RECON_FRAME_BYTES as usize - REQUEST_HEADER_BYTES) / (2 + one.as_bytes().len());
        let credentials = (0..per_frame * 2 + 1)
            .map(|index| proof(index as u8))
            .collect::<Vec<_>>();
        let frames = request_frames(handle(1), Flags::default(), false, &credentials);
        assert_eq!(frames.len(), 3);
        let mut carried = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let (kind, payload) = frame.encode();
            assert!(payload.len() <= MAX_RECON_FRAME_BYTES as usize);
            let expected = if index == 2 {
                FRAME_PEER_REQUEST
            } else {
                FRAME_CREDENTIAL
            };
            assert_eq!(kind, expected);
            match Frame::decode(kind, &payload).unwrap().unwrap() {
                Frame::Credential { credentials, .. } | Frame::PeerRequest { credentials, .. } => {
                    carried.extend(credentials)
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(carried, credentials);
        assert_eq!(credential_frames(handle(1), &[]).len(), 1);
    }

    #[test]
    fn malformed_payloads_are_violations_and_unknown_kinds_are_skipped() {
        let (_, request) = Frame::PeerRequest {
            collection: handle(1),
            flags: Flags::default(),
            invitation: false,
            credentials: vec![proof(2)],
        }
        .encode();
        for (kind, payload) in [
            (FRAME_PEER_REQUEST, &request[..31]),
            (FRAME_PEER_REQUEST, &request[..32]),
            (FRAME_PEER_REQUEST, &request[..34]),
            (FRAME_PEER_REQUEST, &request[..request.len() - 1]),
            (FRAME_PEER_ACCEPT, &request[..32]),
            (FRAME_PEER_REFUSE, &request[..33]),
            (FRAME_PEER_FLAGS, &request[..34]),
            (FRAME_UNPEER, &request[..31]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let trailing = [&request[..], &[0]].concat();
        assert!(Frame::decode(FRAME_PEER_REQUEST, &trailing).is_err());

        // An announcement's length follows its held-digest flag.
        let (_, announce) = Frame::Announce {
            collection: handle(1),
            root: [2; 32],
            held_digest: Some([3; 32]),
            reply: false,
        }
        .encode();
        let without_held = [&announce[..64], &[ANNOUNCE_REPLY]].concat();
        for payload in [
            &announce[..64],
            &announce[..65],
            &announce[..96],
            &[&announce[..], &[0]].concat()[..],
            &[&without_held[..], &[0]].concat()[..],
        ] {
            assert!(
                Frame::decode(FRAME_ANNOUNCE, payload).is_err(),
                "{}",
                payload.len()
            );
        }
        assert!(matches!(
            Frame::decode(FRAME_ANNOUNCE, &without_held),
            Ok(Some(Frame::Announce {
                held_digest: None,
                reply: true,
                ..
            }))
        ));
        assert_eq!(Frame::decode(0x7F, b"anything"), Ok(None));

        // A proof this reader cannot decode is skipped, not a violation.
        let mut undecodable = handle(1).raw.to_vec();
        undecodable.push(0);
        undecodable.extend_from_slice(&1_u16.to_be_bytes());
        undecodable.extend_from_slice(&3_u16.to_be_bytes());
        undecodable.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            Frame::decode(FRAME_PEER_REQUEST, &undecodable),
            Ok(Some(Frame::PeerRequest {
                collection: handle(1),
                flags: Flags::default(),
                invitation: false,
                credentials: Vec::new(),
            }))
        );
    }
}
