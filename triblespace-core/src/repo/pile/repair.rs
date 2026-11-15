//! A resynchronising record walk: the read side of `trible pile repair`.
//!
//! Ordinary reading stops at the first malformed record and says where
//! ([`ReadError::CorruptPile`]), and nothing here softens that. This walk is
//! the separate, explicit tool for the case where an operator has decided to
//! salvage what lies *after* such a record: it yields every record that
//! validates, in file order, and every byte range it had to step over to find
//! the next one.
//!
//! A record counts by exactly the rules the reader applies, through the same
//! [`decode_record`](super::decode_record), and a blob additionally has to
//! match the hash its header names, through the same
//! [`compute_validation_state`](super::compute_validation_state) a blob read
//! uses. The hash check is what makes a record's extent trustworthy here: a
//! torn blob whose header survived declares a span that the bytes written
//! after the crash happen to fill, so the decoder alone accepts it and would
//! walk on into the middle of the next record.
//!
//! After a defect at byte `p`, the walk scans forward from `p + 1` for the
//! next occurrence of the 28-byte frame magic at which a complete record
//! validates. A magic match alone is never enough: the magic can sit inside a
//! blob's payload, and a pile stored as a blob is full of them. Once a record
//! validates, its declared extent is taken whole, exactly as the reader would
//! take it, and nothing inside it is ever considered. Only the current frame
//! magic is a resynchronisation point; legacy unenveloped records are copied
//! when the sequential walk reaches them, but a damaged region is never ended
//! by one, because their 16-byte markers carry no span and no recovery prefix.

use anybytes::Bytes;
use std::path::Path;

use super::{
    compute_validation_state, decode_record, PileRecord, PileRecordContent, PileRecords, ReadError,
    ValidationState, ValidationStrategy, FRAME_MAGIC, FRAME_MAGIC_LEN,
};
use crate::id::RawId;

/// Why the walk could not take a record at the start of a [`SkippedRange`].
///
/// Only the first defect of a range is named; the bytes the scan crossed
/// after it are, by construction, no record at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairDefect {
    /// The reader's [`ReadError::CorruptPile`]: a malformed, torn or
    /// truncated frame.
    Corrupt,
    /// The reader's [`ReadError::UnsupportedRecord`]: sixteen bytes that name
    /// no marker this reader knows. Usually garbage; it can also be a record
    /// from a newer format, so the source is worth keeping.
    Unsupported {
        /// The unrecognized 16-byte marker.
        marker: RawId,
    },
    /// A blob frame that decodes, but whose payload does not hash to the
    /// handle its header names.
    BlobHash,
}

/// A byte range of the source that holds no record the walk could take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedRange {
    /// First skipped byte: where the defect was found.
    pub start: usize,
    /// One past the last skipped byte: the next valid record, or end of file.
    pub end: usize,
    /// What was wrong at `start`.
    pub defect: RepairDefect,
}

impl SkippedRange {
    /// Number of skipped bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the range is empty; it never is, a skip spans at least a byte.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// One step of a [`ResyncingRecords`] walk.
#[derive(Debug, Clone, Copy)]
pub enum RepairStep {
    /// A record that validates. Its frame is
    /// `bytes()[record.offset..record.offset + record.len]`.
    Record(PileRecord),
    /// Bytes stepped over to reach the next record.
    Skipped(SkippedRange),
}

/// A walk over a pile file that steps over torn and invalid regions instead
/// of stopping at the first one. See the [module documentation](self).
///
/// Read-only, and never a fallback: nothing on the ordinary read path uses it.
#[derive(Debug)]
pub struct ResyncingRecords {
    bytes: Bytes,
    offset: usize,
    /// A record the scan already validated, so a blob is hashed once.
    pending: Option<PileRecord>,
}

impl ResyncingRecords {
    /// Maps the pile file at `path` read-only, exactly as
    /// [`PileRecords::open`] does.
    pub fn open(path: &Path) -> Result<Self, ReadError> {
        Ok(Self::new(PileRecords::open(path)?.bytes().clone()))
    }

    /// Walks `bytes` as if they were a pile file.
    pub fn new(bytes: Bytes) -> Self {
        Self {
            bytes,
            offset: 0,
            pending: None,
        }
    }

    /// The bytes being walked, to copy a yielded record's frame from.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The record at `offset`, if one validates there.
    fn record_at(&self, offset: usize) -> Result<PileRecord, RepairDefect> {
        let record = decode_record(&self.bytes[offset..], offset).map_err(|error| match error {
            ReadError::UnsupportedRecord { marker, .. } => RepairDefect::Unsupported { marker },
            _ => RepairDefect::Corrupt,
        })?;
        if let PileRecordContent::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } = record.content
        {
            let payload = self.bytes.slice(data_offset..data_offset + data_len);
            let state =
                compute_validation_state(&payload, &hash, ValidationStrategy::ParallelIfLarge);
            if state != ValidationState::Validated {
                return Err(RepairDefect::BlobHash);
            }
        }
        Ok(record)
    }

    /// The first record at or after `from` that starts with the frame magic
    /// and validates whole.
    fn resynchronise(&self, mut from: usize) -> Option<PileRecord> {
        while let Some(found) = self.bytes.get(from..).and_then(|rest| {
            rest.windows(FRAME_MAGIC_LEN)
                .position(|window| window == FRAME_MAGIC)
        }) {
            let candidate = from + found;
            if let Ok(record) = self.record_at(candidate) {
                return Some(record);
            }
            from = candidate + 1;
        }
        None
    }
}

impl Iterator for ResyncingRecords {
    type Item = RepairStep;

    fn next(&mut self) -> Option<RepairStep> {
        let record = match self.pending.take() {
            Some(record) => record,
            None if self.offset >= self.bytes.len() => return None,
            None => match self.record_at(self.offset) {
                Ok(record) => record,
                Err(defect) => {
                    let start = self.offset;
                    self.pending = self.resynchronise(start + 1);
                    let end = self.pending.map_or(self.bytes.len(), |next| next.offset);
                    self.offset = end;
                    return Some(RepairStep::Skipped(SkippedRange { start, end, defect }));
                }
            },
        };
        self.offset = record.offset + record.len;
        Some(RepairStep::Record(record))
    }
}

#[cfg(test)]
mod tests;
