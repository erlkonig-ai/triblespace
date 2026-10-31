//! File-backed, grow-only record arrays for the cached RIBLT state that grows
//! with a set difference: the sender's prepared cells, the receiver's residual
//! rows and its recovered-key windows. Their size follows the difference, not
//! a configured budget.
//!
//! Record `i` lives in chunk `i / CHUNK` at slot `i % CHUNK`. Growth maps one
//! more chunk and never moves a written record. Each chunk is an anybytes
//! [`Section::anonymous_allocated`]: its own temporary file without a name,
//! so a killed process leaves no file behind, closed once mapped, so no
//! descriptor stays open, and written in full before it is mapped, so a full
//! disk fails the reservation with an error instead of a SIGBUS on a later
//! store into a sparse hole. The pages are shared file pages: under memory
//! pressure the kernel writes them out and reclaims them, instead of keeping
//! them as anonymous heap.
//!
//! Records are encoded byte by byte, never by layout punning. Every slot at
//! or beyond `len` holds zero bytes.
//!
//! [`Records::view`] hands out published records as an immutable [`Bytes`]
//! over the mapped chunk, without copying. A view never changes: the chunk is
//! frozen in place first ([`Section::freeze`], so its pages are read-only and
//! the frozen map is the view's owner), and a later write into a frozen chunk
//! first copies it into a fresh chunk ([`Records::unshare`], copy on write),
//! leaving the views the old map. Records that nobody views (the receiver's
//! residual rows) never pay either cost.

use std::io;
use std::marker::PhantomData;

use anybytes::area::Section;
use anybytes::Bytes;

/// Records per chunk: 912 KiB of 57-byte cell frames.
pub(crate) const CHUNK: usize = 1 << 14;

/// One chunk's map. `Open` is written in place and nothing else sees it;
/// `Frozen` is read-only, may be viewed, and is never written again.
enum Chunk {
    Open(Section<'static, u8>),
    Frozen(Bytes),
}

impl Chunk {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Open(section) => section,
            Self::Frozen(bytes) => bytes,
        }
    }
}

/// A fixed-size value with an explicit byte encoding. All zero bytes must
/// decode to the value's empty state.
pub(crate) trait Record: Sized {
    const BYTES: usize;
    fn load(bytes: &[u8]) -> Self;
    fn store(&self, bytes: &mut [u8]);
}

pub(crate) struct Records<T> {
    chunks: Vec<Chunk>,
    len: usize,
    _record: PhantomData<fn() -> T>,
}

impl<T: Record> Default for Records<T> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
            _record: PhantomData,
        }
    }
}

impl<T: Record> Records<T> {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mapped file bytes in whole chunks: neither heap nor wire size.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.chunks.len() * CHUNK * T::BYTES
    }

    fn slot(&self, index: usize) -> &[u8] {
        let at = (index % CHUNK) * T::BYTES;
        &self.chunks[index / CHUNK].bytes()[at..at + T::BYTES]
    }

    /// The only path to a writable chunk. A frozen chunk must have been made
    /// private by [`Records::unshare`] first; writing one is a bug, and
    /// panics rather than change a published view.
    fn slot_mut(&mut self, index: usize) -> &mut [u8] {
        let at = (index % CHUNK) * T::BYTES;
        match &mut self.chunks[index / CHUNK] {
            Chunk::Open(section) => &mut section[at..at + T::BYTES],
            Chunk::Frozen(_) => panic!("a frozen chunk is unshared before writes"),
        }
    }

    /// Make every chunk holding records from `first` on privately writable:
    /// a frozen chunk is copied into a fresh chunk, which replaces it here
    /// while the views keep the frozen map. Callers unshare before writing,
    /// so a failed copy is a storage error rather than a panic half way
    /// through a write.
    pub(crate) fn unshare(&mut self, first: usize) -> io::Result<()> {
        for slot in self.chunks.iter_mut().skip(first / CHUNK) {
            if let Chunk::Frozen(bytes) = slot {
                *slot = Chunk::Open(copy(bytes)?);
            }
        }
        Ok(())
    }

    /// Records `[start, start + count)` as one immutable view over their
    /// mapped chunk, without copying. The range must be published and lie in
    /// one chunk. The chunk is frozen read-only in place first, and copied
    /// by the next [`Records::unshare`] that reaches it.
    pub(crate) fn view(&mut self, start: usize, count: usize) -> io::Result<Bytes> {
        assert!(count > 0 && start + count <= self.len, "a view of unpublished records");
        let index = start / CHUNK;
        assert_eq!(index, (start + count - 1) / CHUNK, "a view across chunks");
        if let Chunk::Open(_) = self.chunks[index] {
            let Chunk::Open(section) =
                std::mem::replace(&mut self.chunks[index], Chunk::Frozen(Bytes::empty()))
            else {
                unreachable!("checked open")
            };
            match section.freeze() {
                Ok(bytes) => self.chunks[index] = Chunk::Frozen(bytes),
                Err(error) => {
                    // The map is gone with the failed call. Unpublish from
                    // this chunk on, so the records stay a consistent prefix;
                    // views already handed out keep their own maps.
                    self.chunks.truncate(index);
                    self.len = self.len.min(index * CHUNK);
                    return Err(error);
                }
            }
        }
        let Chunk::Frozen(bytes) = &self.chunks[index] else {
            unreachable!("frozen above")
        };
        let at = (start % CHUNK) * T::BYTES;
        Ok(bytes.slice(at..at + count * T::BYTES))
    }

    pub(crate) fn get(&self, index: usize) -> Option<T> {
        (index < self.len).then(|| T::load(self.slot(index)))
    }

    /// Overwrite a published record. Panics at or beyond `len`.
    pub(crate) fn set(&mut self, index: usize, value: &T) {
        assert!(index < self.len, "record {index} is beyond {}", self.len);
        value.store(self.slot_mut(index));
    }

    pub(crate) fn push(&mut self, value: &T) -> io::Result<()> {
        self.resize(self.len + 1)?;
        self.set(self.len - 1, value);
        Ok(())
    }

    /// Grow to `len` records; the new ones are zero. All or nothing: on
    /// error the chunks this call mapped are dropped again, so a failed growth
    /// leaves no unpublished file reserved.
    pub(crate) fn resize(&mut self, len: usize) -> io::Result<()> {
        let mapped = self.chunks.len();
        while self.chunks.len() * CHUNK < len {
            match chunk(CHUNK * T::BYTES) {
                Ok(chunk) => self.chunks.push(Chunk::Open(chunk)),
                Err(error) => {
                    self.chunks.truncate(mapped);
                    return Err(error);
                }
            }
        }
        self.len = self.len.max(len);
        Ok(())
    }

    /// Unpublish the records from `len` on, zeroing their slots.
    pub(crate) fn truncate(&mut self, len: usize) {
        for index in len..self.len {
            self.slot_mut(index).fill(0);
        }
        self.len = self.len.min(len);
    }

    /// An independent copy of the first `len` records in fresh chunk files.
    /// Only the chunks holding them are copied.
    pub(crate) fn try_clone_prefix(&self, len: usize) -> io::Result<Self> {
        let len = len.min(self.len);
        let chunks = self.chunks[..len.div_ceil(CHUNK)]
            .iter()
            .map(|source| Ok(Chunk::Open(copy(source.bytes())?)))
            .collect::<io::Result<_>>()?;
        let mut copy = Self {
            chunks,
            len: self.len.min(len.div_ceil(CHUNK) * CHUNK),
            _record: PhantomData,
        };
        copy.truncate(len);
        Ok(copy)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.iter_from(0)
    }

    pub(crate) fn iter_from(&self, start: usize) -> impl Iterator<Item = T> + '_ {
        (start..self.len).map(|index| T::load(self.slot(index)))
    }
}

#[cfg(test)]
thread_local! {
    static CHUNKS_LEFT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Test-only failure injection: on this thread, let `left` more chunk
/// allocations succeed and fail every later one, or (`None`) never fail.
#[cfg(test)]
pub(crate) fn fail_chunks_after(left: Option<usize>) {
    CHUNKS_LEFT.with(|cell| cell.set(left));
}

/// One zeroed chunk of `bytes`, its storage claimed before it is mapped.
fn chunk(bytes: usize) -> io::Result<Section<'static, u8>> {
    #[cfg(test)]
    if let Some(left) = CHUNKS_LEFT.with(|cell| cell.get()) {
        if left == 0 {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "injected"));
        }
        CHUNKS_LEFT.with(|cell| cell.set(Some(left - 1)));
    }
    Section::anonymous_allocated(bytes)
}

/// A fresh chunk holding a copy of `contents`.
fn copy(contents: &[u8]) -> io::Result<Section<'static, u8>> {
    let mut section = chunk(contents.len())?;
    section.copy_from_slice(contents);
    Ok(section)
}
