//! Reusable services used by the trible CLI and native applications.
/// Command implementations behind the `trible` and `trible-migrate`
/// binaries. Each binary references only the commands it offers, so the
/// linker leaves the other's code out.
#[doc(hidden)]
pub mod cli;
pub mod maintenance;
pub mod process;
