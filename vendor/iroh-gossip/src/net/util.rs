//! Utilities for iroh-gossip networking

use std::{io, time::Duration};

use bytes::{Bytes, BytesMut};
use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    EndpointId,
};
use n0_error::{e, stack_error};
use n0_future::time::{sleep_until, Instant};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::debug;

use super::{InEvent, ProtoMessage};
use crate::proto::util::TimerMap;

// Keep the stock per-topic message allowance: multiplexing adds the fixed
// postcard encoding of TopicId ([u8; 32]) to each frame, not to its payload.
const TOPIC_FRAME_OVERHEAD: usize = 32;

fn max_frame_size(max_message_size: usize) -> usize {
    max_message_size.saturating_add(TOPIC_FRAME_OVERHEAD)
}

/// Errors related to message writing
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub(crate) enum WriteError {
    /// Connection error
    #[error("Connection error")]
    Connection {
        #[error(std_err)]
        source: iroh::endpoint::ConnectionError,
    },
    /// Serialization failed
    #[error("Serialization failed")]
    Ser {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// IO error
    #[error("IO error")]
    Io {
        #[error(std_err)]
        source: std::io::Error,
    },
    /// Message was larger than the configured maximum message size
    #[error("message too large")]
    TooLarge {},
}

pub(crate) struct RecvLoop {
    remote_endpoint_id: EndpointId,
    conn: Connection,
    max_message_size: usize,
    in_event_tx: mpsc::Sender<InEvent>,
}

impl RecvLoop {
    pub(crate) fn new(
        remote_endpoint_id: EndpointId,
        conn: Connection,
        in_event_tx: mpsc::Sender<InEvent>,
        max_message_size: usize,
    ) -> Self {
        Self {
            remote_endpoint_id,
            conn,
            max_message_size,
            in_event_tx,
        }
    }

    pub(crate) async fn run(&mut self) -> Result<(), ReadError> {
        // One stream carries every topic in sender order. Rotating streams per
        // message lets same-topic membership controls overtake each other;
        // keeping a stream per topic instead exhausts QUIC's stream credit.
        let Ok(mut stream) = self.conn.accept_uni().await else {
            return Ok(());
        };
        let mut buffer = BytesMut::new();
        while let Some(message) = read_frame::<ProtoMessage>(
            &mut stream,
            &mut buffer,
            max_frame_size(self.max_message_size),
        )
        .await?
        {
            if self
                .in_event_tx
                .send(InEvent::RecvMessage(self.remote_endpoint_id, message))
                .await
                .is_err()
            {
                debug!("stop recv loop: actor closed");
                break;
            }
        }
        debug!("recv loop closed");
        Ok(())
    }
}

pub(crate) struct SendLoop {
    conn: Connection,
    stream: Option<SendStream>,
    buffer: Vec<u8>,
    max_message_size: usize,
    send_rx: mpsc::Receiver<ProtoMessage>,
}

impl SendLoop {
    pub(crate) fn new(
        conn: Connection,
        send_rx: mpsc::Receiver<ProtoMessage>,
        max_message_size: usize,
    ) -> Self {
        Self {
            conn,
            max_message_size,
            buffer: Default::default(),
            stream: None,
            send_rx,
        }
    }

    pub(crate) async fn run(&mut self, queue: Vec<ProtoMessage>) -> Result<(), WriteError> {
        for msg in queue {
            self.write_message(&msg).await?;
        }
        let conn_clone = self.conn.clone();
        let closed = conn_clone.closed();
        tokio::pin!(closed);
        loop {
            tokio::select! {
                biased;
                _ = &mut closed => break,
                msg = self.send_rx.recv() => match msg {
                    Some(msg) => self.write_message(&msg).await?,
                    None => break,
                },
            }
        }

        if let Some(mut stream) = self.stream.take() {
            stream.finish().ok();
            // Bound graceful shutdown if the peer stops acknowledging reads.
            let _ = n0_future::time::timeout(Duration::from_secs(5), stream.stopped()).await;
        }
        debug!("send loop closed");
        Ok(())
    }

    /// Write a topic-tagged message on the connection's ordered stream.
    ///
    /// Topics remain independent mesh memberships; only their wire frames are
    /// multiplexed. A topic disconnect must not close this shared stream.
    /// This function is not cancellation-safe.
    pub async fn write_message(&mut self, message: &ProtoMessage) -> Result<(), WriteError> {
        if self.stream.is_none() {
            self.stream = Some(self.conn.open_uni().await?);
            debug!("multiplexed stream opened");
        }
        write_frame(
            self.stream.as_mut().expect("stream opened above"),
            message,
            &mut self.buffer,
            max_frame_size(self.max_message_size),
        )
        .await
    }
}

/// Errors related to message reading
#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub(crate) enum ReadError {
    /// Deserialization failed
    #[error("Deserialization failed")]
    De {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// IO error
    #[error("IO error")]
    Io {
        #[error(std_err)]
        source: std::io::Error,
    },
    /// Message was larger than the configured maximum message size
    #[error("message too large")]
    TooLarge {},
}

/// Read a length-prefixed frame and decode with postcard.
pub async fn read_frame<T: DeserializeOwned>(
    reader: &mut RecvStream,
    buffer: &mut BytesMut,
    max_message_size: usize,
) -> Result<Option<T>, ReadError> {
    match read_lp(reader, buffer, max_message_size).await? {
        None => Ok(None),
        Some(data) => {
            let message = postcard::from_bytes(&data)?;
            Ok(Some(message))
        }
    }
}

/// Reads a length prefixed buffer.
///
/// Returns the frame as raw bytes.  If the end of the stream is reached before
/// the frame length starts, `None` is returned.
pub async fn read_lp(
    reader: &mut RecvStream,
    buffer: &mut BytesMut,
    max_message_size: usize,
) -> Result<Option<Bytes>, ReadError> {
    let size = match reader.read_u32().await {
        Ok(size) => size,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let size = usize::try_from(size).map_err(|_| e!(ReadError::TooLarge))?;
    if size > max_message_size {
        return Err(e!(ReadError::TooLarge));
    }
    buffer.resize(size, 0u8);
    reader
        .read_exact(&mut buffer[..])
        .await
        .map_err(io::Error::other)?;
    Ok(Some(buffer.split_to(size).freeze()))
}

/// Writes a length-prefixed frame.
pub async fn write_frame<T: Serialize>(
    stream: &mut SendStream,
    message: &T,
    buffer: &mut Vec<u8>,
    max_message_size: usize,
) -> Result<(), WriteError> {
    let len = postcard::experimental::serialized_size(&message)?;
    if len >= max_message_size {
        return Err(e!(WriteError::TooLarge));
    }
    buffer.clear();
    buffer.resize(len, 0u8);
    let slice = postcard::to_slice(&message, buffer)?;
    stream.write_u32(len as u32).await?;
    stream.write_all(slice).await.map_err(io::Error::other)?;
    Ok(())
}

/// A [`TimerMap`] with an async method to wait for the next timer expiration.
#[derive(Debug)]
pub struct Timers<T> {
    map: TimerMap<T>,
}

impl<T> Default for Timers<T> {
    fn default() -> Self {
        Self {
            map: TimerMap::default(),
        }
    }
}

impl<T> Timers<T> {
    /// Creates a new timer map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a new entry at the specified instant
    pub fn insert(&mut self, instant: Instant, item: T) {
        self.map.insert(instant, item);
    }

    /// Waits for the next timer to elapse.
    pub async fn wait_next(&mut self) -> Instant {
        match self.map.first() {
            None => std::future::pending::<Instant>().await,
            Some(instant) => {
                sleep_until(*instant).await;
                *instant
            }
        }
    }

    /// Pops the earliest timer that expires at or before `now`.
    pub fn pop_before(&mut self, now: Instant) -> Option<(Instant, T)> {
        self.map.pop_before(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{self, PeerData, TopicId};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn multiplex_frame_preserves_topic_and_inner_message_allowance() {
        for payload_len in [0, 64, 500, 512] {
            let me = iroh::SecretKey::from_bytes(&[1; 32]).public();
            let other = iroh::SecretKey::from_bytes(&[2; 32]).public();
            let mut state = proto::State::new(
                me,
                PeerData::new(vec![19; payload_len]),
                proto::Config::default(),
                StdRng::seed_from_u64(1),
            );
            let message = state
                .handle(
                    InEvent::Command(
                        TopicId::from_bytes([37; 32]),
                        proto::Command::Join(vec![other]),
                    ),
                    Instant::now(),
                    None,
                )
                .find_map(|event| match event {
                    proto::OutEvent::SendMessage(_, message) => Some(message),
                    _ => None,
                })
                .unwrap();
            let inner_len = postcard::experimental::serialized_size(&message.message).unwrap();
            let encoded = postcard::to_stdvec(&message).unwrap();
            assert_eq!(encoded.len(), inner_len + TOPIC_FRAME_OVERHEAD);
            assert_eq!(encoded.len() < max_frame_size(512), inner_len < 512);
            let decoded: ProtoMessage = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(decoded.topic, message.topic);
            assert_eq!(decoded.message, message.message);
        }
    }
}
