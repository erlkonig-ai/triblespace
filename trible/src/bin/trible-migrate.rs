//! `trible-migrate`: bring a pile written by any earlier format up to the
//! current one. Kept out of `trible` so the everyday binary carries none of
//! the migration code; this binary references only the migrate commands.
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use trible::cli::pile::migrate;

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Migrate a pile from earlier formats to the current one.
struct Cli {
    /// The pile to read (and, for the in-place migrations, to append to).
    pile: PathBuf,
    #[command(subcommand)]
    cmd: migrate::Command,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let Cli { pile, cmd } = Cli::parse();
    migrate::run(pile, cmd)
}
