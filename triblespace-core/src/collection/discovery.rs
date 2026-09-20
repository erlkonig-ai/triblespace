//! The error of one complete record enumeration.
//!
//! Reads select from the coverage index and never enumerate records. The
//! tooling that still walks them -- generation surveys and migrations --
//! reports a store that could not start or finish that walk with this type.

use std::error::Error;
use std::fmt;

/// A native-store failure that prevents one complete record enumeration.
#[derive(Debug)]
pub enum CollectionDiscoveryError<RecordsError> {
    /// The store could not start or complete record enumeration.
    Records(RecordsError),
}

impl<RecordsError> fmt::Display for CollectionDiscoveryError<RecordsError>
where
    RecordsError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records(error) => write!(f, "failed to enumerate collection records: {error}"),
        }
    }
}

impl<RecordsError> Error for CollectionDiscoveryError<RecordsError>
where
    RecordsError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Records(error) => Some(error),
        }
    }
}
