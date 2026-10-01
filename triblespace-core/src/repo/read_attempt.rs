//! Error accounting for one operation whose open-world queries may skip a
//! failed candidate. Missing bytes still supply no authority; a broken local
//! read must not be mistaken for a policy denial or an empty collection.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::{BlobStoreGet, CapabilityProofRead};
use crate::blob::{BlobEncoding, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};

/// A backend failure retained across an operation's query boundary.
#[derive(Clone, Debug)]
pub struct ReadFailure(Arc<dyn Error + Send + Sync>);

impl ReadFailure {
    pub(crate) fn new(error: impl Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for ReadFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(crate) struct ReadAttempt<'a, R> {
    reader: &'a R,
    // One call's first fault, not a retained blob/error catalogue.
    fault: RefCell<Option<ReadFailure>>,
}

impl<'a, R> ReadAttempt<'a, R> {
    pub(crate) fn new(reader: &'a R) -> Self {
        Self {
            reader,
            fault: RefCell::new(None),
        }
    }

    fn failure(&self, error: impl Error + Send + Sync + 'static) -> ReadFailure {
        let error = ReadFailure::new(error);
        if !super::is_missing_blob(&error) {
            self.fault.borrow_mut().get_or_insert_with(|| error.clone());
        }
        error
    }

    pub(crate) fn finish(&self) -> Result<(), ReadFailure> {
        self.fault.borrow().clone().map_or(Ok(()), Err)
    }
}

impl<R: BlobStoreGet> BlobStoreGet for ReadAttempt<'_, R> {
    type GetError<E: Error + Send + Sync + 'static> = ReadFailure;

    fn get<T, E>(&self, handle: Inline<Handle<E>>) -> Result<T, ReadFailure>
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.reader.get(handle).map_err(|error| self.failure(error))
    }
}

impl<R: CapabilityProofRead> CapabilityProofRead for ReadAttempt<'_, R> {
    type ProofsError = ReadFailure;
    type ProofIter<'a>
        = Box<dyn Iterator<Item = Result<CapabilityProof, ReadFailure>> + 'a>
    where
        Self: 'a;

    fn proofs(&self) -> Result<Self::ProofIter<'_>, ReadFailure> {
        let proofs = self.reader.proofs().map_err(|error| self.failure(error))?;
        Ok(Box::new(
            proofs.map(|proof| proof.map_err(|error| self.failure(error))),
        ))
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, ReadFailure> {
        self.reader.proof(id).map_err(|error| self.failure(error))
    }
}
