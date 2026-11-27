//! `trible yard`: old piles kept as differences in a folder of piles.
//!
//! A yard is a folder whose piles, together with the live pile, hold
//! everything ever kept; concatenation is the merge. `yard diff` keeps an old
//! pile as only what it adds to the live pile and every pile already in the
//! yard, and `yard pack` writes the union of a yard as one deduplicated pile.
//! Both are the `pile subtract` writer and checker over several piles: the
//! same frame identities, the same hash-valid blob presence, the same exact
//! bytes for frames this reader cannot interpret, and order-sensitive log
//! frames copied at every occurrence.
//!
//! Nothing here opens a pile for writing, deletes an input, or reclaims a
//! yard. The output is written to a hidden sibling, verified there, and
//! published by hard link only after the yard has been listed again and every
//! input stat'ed unchanged, so an output that exists is one that verified.
//!
//! This is not [`triblespace_core::repo::yard::Yard`]: that type opens its
//! generations for writing and keeps retention state. A folder yard is read
//! here as a set of read-only snapshots.

use std::ffi::OsString;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;

use super::subtract::{
    check_union, copy_new, finish, publish, refuse_existing, temporary_sibling, Checked, Input,
    KeepEvery, Side, Stamp, Tally,
};

const DIFF_EXAMPLE: &str = "\
Example:
  trible yard diff ~/yard old.pile --live live.pile --into ~/yard/old.minus-yard.pile
  # later, or after the yard changed:
  trible yard diff ~/yard old.pile --live live.pile --check ~/yard/old.minus-yard.pile";

const PACK_EXAMPLE: &str = "\
Example:
  trible yard pack ~/yard --into ~/yard-packed/all.pile
  trible yard pack ~/yard --live live.pile --into ~/backup/self-contained.pile
  trible yard pack ~/yard --check ~/yard-packed/all.pile";

#[derive(Subcommand)]
pub enum YardCommand {
    /// Keep OLD as only what it adds to LIVE plus every pile in YARD.
    ///
    /// YARD's members are the entries directly in it whose names end in
    /// `.pile` and do not start with a dot, resolving to regular files; the
    /// report lists every other entry it ignored. Each member, OLD and LIVE
    /// is read through one read-only snapshot. They must all be distinct
    /// files by device and inode: an alias is refused, never dropped. The
    /// output named by --into or --check is excluded from membership by name.
    ///
    /// Every frame of OLD whose content neither LIVE nor any member holds is
    /// copied byte for byte, in OLD's order, by the rules of `pile subtract`
    /// (see its --help): blobs by hash-valid presence, records by identity.
    /// Legacy pin and retired WANT frames, and every frame this reader cannot
    /// interpret (which it cannot assume idempotent), are copied at every
    /// occurrence in OLD's order, as exact bytes. A blob frame failing its
    /// hash is harmless when a valid copy is anywhere else; otherwise it
    /// refuses unless --allow-corrupt.
    ///
    /// The difference is written to a hidden sibling of INTO and verified
    /// there before it is published: reopened from disk, every item of OLD
    /// must be in LIVE, a member, or the difference; the difference must
    /// hold nothing OLD does not; and its order-sensitive log must be OLD's
    /// exactly. Then YARD is listed again and every input stat'ed: a member
    /// added, removed or renamed, OLD or a member changed (size, mtime,
    /// ctime), or LIVE replaced or shrunk, refuses. Only then is INTO
    /// published by hard link, which never replaces a file. On any failure
    /// nothing is published and the error says why.
    ///
    /// LIVE may keep growing: it is read as the prefix its snapshot
    /// accepted, which the report gives in bytes; writers append under the
    /// pile's exclusive lock and the snapshot replays under the shared one,
    /// so an append never shows half-written. OLD and the members must be
    /// complete: a torn or malformed record refuses (`pile repair` copies
    /// the valid records into a fresh pile).
    ///
    /// `cat LIVE YARD/*.pile INTO` then holds every item OLD held, while
    /// LIVE and the members the report lists as covering keep what they
    /// held. Nothing is deleted; removing OLD is the caller's decision.
    ///
    /// --check DIFF writes nothing and verifies the same way against the
    /// current LIVE and members, DIFF excluded. It proves OLD is contained
    /// in them now; a member removed without being needed goes unnoticed,
    /// because nothing depended on it.
    #[command(after_long_help = DIFF_EXAMPLE)]
    Diff {
        /// Folder of piles, read-only.
        yard: PathBuf,
        /// Old pile to keep as a difference, read-only.
        old: PathBuf,
        /// The live pile, read-only, at the prefix its snapshot accepts.
        #[arg(long, value_name = "LIVE")]
        live: PathBuf,
        /// Fresh difference pile to create; must not exist.
        #[arg(
            long,
            value_name = "INTO",
            required_unless_present = "check",
            conflicts_with = "check"
        )]
        into: Option<PathBuf>,
        /// Verify an existing difference instead of writing one.
        #[arg(long, value_name = "DIFF")]
        check: Option<PathBuf>,
        /// Omit blob frames that fail their hash with no valid copy anywhere,
        /// counting them, instead of refusing.
        #[arg(long)]
        allow_corrupt: bool,
    },
    /// Write the union of every pile in YARD as one deduplicated pile.
    ///
    /// Membership and aliasing are as for `yard diff`. With --live, LIVE is
    /// an input too, read at the prefix its snapshot accepts, and the
    /// result is self-contained. Inputs are read LIVE first, then members by
    /// name.
    ///
    /// Every distinct item of the inputs is written once, byte for byte, in
    /// the order first met, under its native contract: blobs by hash, with a
    /// hash-valid occurrence (a corrupt one is harmless when any input holds
    /// a valid copy); COMMIT, MERGE, DERIVE, MAP, AUTH proofs and WANTs by
    /// their native identity; retired kinds by their exact bytes. Frames this
    /// reader cannot interpret cannot be assumed idempotent and are written
    /// at every occurrence, in input order. No state is projected, unlike
    /// `pile compact`.
    ///
    /// WHAT IS LOST: the replay order and repeats of legacy pin heads and
    /// tombstones and retired WANT assert/retract frames. Each distinct such
    /// record is kept once (a pin head by pin and head, a tombstone by pin,
    /// a retired WANT frame by its exact bytes), so different records all
    /// survive, but a pin log head A, tombstone, head A packs as A and the
    /// tombstone, and replaying it ends deleted. Use `yard diff`, or keep
    /// the inputs, when that history matters.
    ///
    /// Nothing present in the inputs is dropped for what it means: a pin
    /// removal is kept as evidence beside the heads it followed, and never
    /// removes a head or a blob, so the union can be read under today's
    /// monotonic model. Coverage is of the bytes supplied: a payload a pin
    /// names but no input holds cannot be recovered from the pin.
    ///
    /// The output is written to a hidden sibling and verified there: every
    /// distinct input item is in it, it holds nothing no input holds (an
    /// exact union), and its uninterpreted frames are the inputs', occurrence
    /// for occurrence, in input order. YARD is then listed again and every
    /// input stat'ed unchanged, and only then is INTO published by hard
    /// link, never replacing a file. Inputs are never modified or removed.
    ///
    /// --check PACKED verifies an existing pack against the current inputs
    /// the same way, PACKED excluded: a pack holding items of an input that
    /// is gone fails as not exact.
    #[command(after_long_help = PACK_EXAMPLE)]
    Pack {
        /// Folder of piles, read-only.
        yard: PathBuf,
        /// Also take the live pile as an input, at its accepted prefix.
        #[arg(long, value_name = "LIVE")]
        live: Option<PathBuf>,
        /// Fresh pile to create; must not exist.
        #[arg(
            long,
            value_name = "INTO",
            required_unless_present = "check",
            conflicts_with = "check"
        )]
        into: Option<PathBuf>,
        /// Verify an existing pack instead of writing one.
        #[arg(long, value_name = "PACKED")]
        check: Option<PathBuf>,
        /// Omit blob frames that fail their hash with no valid copy anywhere,
        /// counting them, instead of refusing.
        #[arg(long)]
        allow_corrupt: bool,
    },
}

pub fn run(cmd: YardCommand) -> Result<()> {
    match cmd {
        YardCommand::Diff {
            yard,
            old,
            live,
            into,
            check,
            allow_corrupt,
        } => diff(
            &yard,
            &old,
            &live,
            into.as_deref(),
            check.as_deref(),
            allow_corrupt,
        ),
        YardCommand::Pack {
            yard,
            live,
            into,
            check,
            allow_corrupt,
        } => pack(
            &yard,
            live.as_deref(),
            into.as_deref(),
            check.as_deref(),
            allow_corrupt,
        ),
    }
}

/// The yard's members and what its listing passed over.
#[derive(PartialEq)]
struct Listing {
    members: Vec<(OsString, PathBuf)>,
    ignored: Vec<(OsString, &'static str)>,
}

/// List the members of `yard`: entries directly in it named `*.pile`, not
/// hidden, resolving to regular files, in name order. `output` is left out
/// when it names an entry of `yard`.
fn list(yard: &Path, output: &Path) -> Result<Listing> {
    let canonical =
        fs::canonicalize(yard).with_context(|| format!("open yard {}", yard.display()))?;
    let output_name = match (output.parent(), output.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            match fs::canonicalize(parent) {
                Ok(parent) if parent == canonical => Some(name.to_os_string()),
                _ => None,
            }
        }
        _ => None,
    };
    let mut listing = Listing {
        members: Vec::new(),
        ignored: Vec::new(),
    };
    for entry in fs::read_dir(yard).with_context(|| format!("list yard {}", yard.display()))? {
        let entry = entry.with_context(|| format!("list yard {}", yard.display()))?;
        let name = entry.file_name();
        let path = entry.path();
        if name.to_string_lossy().starts_with('.') {
            listing.ignored.push((name, "hidden"));
            continue;
        }
        if path.extension() != Some(std::ffi::OsStr::new("pile")) {
            listing.ignored.push((name, "not named *.pile"));
            continue;
        }
        if output_name.as_ref() == Some(&name) {
            listing.ignored.push((name, "the output"));
            continue;
        }
        let metadata = fs::metadata(&path).with_context(|| {
            format!("refusing: yard entry {} cannot be stat'ed", path.display())
        })?;
        if !metadata.is_file() {
            listing.ignored.push((name, "not a regular file"));
            continue;
        }
        listing.members.push((name, path));
    }
    listing.members.sort();
    listing.ignored.sort();
    Ok(listing)
}

/// Open every member through its own snapshot; an error closes the rest.
fn open_members(listing: &Listing) -> Result<Vec<Side>> {
    listing
        .members
        .iter()
        .map(|(_, path)| {
            Side::open(path).with_context(|| format!("open yard member {}", path.display()))
        })
        .collect()
}

/// Refuse unless every role names a different file.
fn require_unaliased(roles: &[(String, &Side)]) -> Result<()> {
    for (at, (role, side)) in roles.iter().enumerate() {
        if let Some((other, _)) = roles[..at]
            .iter()
            .find(|(_, earlier)| earlier.stamp.identity == side.stamp.identity)
        {
            bail!(
                "refusing: {other} and {role} are the same file ({:?}); every input and the \
                 output must be distinct, so that no pile can cover itself",
                side.stamp.identity
            );
        }
    }
    Ok(())
}

/// Refuse a static pile with bytes past what its snapshot accepted. Replay
/// already refuses a torn record; this catches a pile written to between
/// replay and the stat, which a static pile must not be.
fn require_complete(role: &str, side: &Side) -> Result<()> {
    let unaccepted = side.unaccepted();
    if unaccepted == 0 {
        return Ok(());
    }
    bail!(
        "refusing: {role} {} has {unaccepted} byte(s) past the {} its snapshot accepted; it is \
         being written to, and a static pile must not be",
        side.path.display(),
        side.len
    )
}

/// Refuse unless the yard lists as it did and every input is as it was:
/// static piles identical in identity, size and change times, a live pile
/// the same file and no shorter.
fn require_unchanged(
    yard: &Path,
    output: &Path,
    listing: &Listing,
    statics: &[&Side],
    live: Option<&Side>,
) -> Result<()> {
    let now = list(yard, output)?;
    if now.members != listing.members {
        let names = |listing: &Listing| {
            listing
                .members
                .iter()
                .map(|(name, _)| name.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let (before, after) = (names(listing), names(&now));
        let gone: Vec<_> = before.iter().filter(|name| !after.contains(name)).collect();
        let new: Vec<_> = after.iter().filter(|name| !before.contains(name)).collect();
        bail!(
            "refusing: the members of yard {} changed while it was read (gone: {gone:?}; new: \
             {new:?}); nothing was published",
            yard.display()
        );
    }
    for side in statics {
        let stamp = Stamp::now(&side.path)
            .with_context(|| format!("refusing: {} is gone", side.path.display()))?;
        if stamp != side.stamp {
            bail!(
                "refusing: {} changed while it was read (was {:?}, is {:?}); nothing was \
                 published",
                side.path.display(),
                side.stamp,
                stamp
            );
        }
    }
    if let Some(side) = live {
        let stamp = Stamp::now(&side.path)
            .with_context(|| format!("refusing: live pile {} is gone", side.path.display()))?;
        if stamp.identity != side.stamp.identity || stamp.len < side.len as u64 {
            bail!(
                "refusing: live pile {} was replaced or shrank below the {} bytes read (was \
                 {:?}, is {:?}); nothing was published",
                side.path.display(),
                side.len,
                side.stamp,
                stamp
            );
        }
    }
    Ok(())
}

fn print_listing(yard: &Path, listing: &Listing, members: &[Side]) {
    println!("yard {}: {} member pile(s)", yard.display(), members.len());
    for side in members {
        println!("  member {} ({} bytes)", side.path.display(), side.len);
    }
    for (name, why) in &listing.ignored {
        println!("  ignored {} ({why})", name.to_string_lossy());
    }
}

fn print_live(side: &Side) {
    println!(
        "live {}: read as its first {} bytes (the file was {} bytes when its snapshot was \
         taken; later appends are not read)",
        side.path.display(),
        side.len,
        side.stamp.len
    );
}

/// The piles of `baseline` that covered items of the source, by `covered`.
fn print_coverage(baseline: &[&Side], covered: &[u64]) {
    let used: Vec<_> = baseline
        .iter()
        .zip(covered)
        .filter(|(_, count)| **count > 0)
        .collect();
    println!(
        "covered by {} of {} baseline pile(s); the difference is complete only together with:",
        used.len(),
        baseline.len()
    );
    for (side, count) in used {
        println!("  {} ({count} item(s))", side.path.display());
    }
}

/// Write `inputs` minus `baseline` to a hidden sibling of `into`, verify it
/// there with `verify`, run `unchanged`, and publish it.
fn write_verified(
    into: &Path,
    verb: &str,
    write: impl FnOnce(&mut BufWriter<fs::File>, &Path) -> Result<Tally>,
    verify: impl FnOnce(&Side) -> Result<()>,
    unchanged: impl FnOnce() -> Result<()>,
) -> Result<()> {
    refuse_existing(into)?;
    let temporary = temporary_sibling(into, verb)?;
    let file = super::compact::create_fresh_destination(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let written = file
        .metadata()
        .map_err(|error| anyhow!(error))
        .and_then(|metadata| Stamp::of(&metadata, &temporary));
    let result = (|| -> Result<()> {
        let written = written?.identity;
        let mut out = BufWriter::with_capacity(8 << 20, file);
        let tally = write(&mut out, &temporary)?;
        drop(finish(out, &temporary)?);
        tally.warn_stopped(into);
        let out = Side::open(&temporary)?;
        if out.stamp.identity != written {
            bail!(
                "refusing: {} is no longer the file that was written",
                temporary.display()
            );
        }
        let verified = verify(&out);
        out.close()?;
        verified.context("verification of the written file failed; nothing was published")?;
        unchanged()?;
        publish(&temporary, into)?;
        let published = Stamp::now(into)?;
        if published.identity != written {
            bail!(
                "{} exists but is not the verified file; inspect it",
                into.display()
            );
        }
        println!("published {} ({} bytes)", into.display(), published.len);
        Ok(())
    })();
    result.map_err(|error| {
        if temporary.exists() {
            super::compact::cleanup_incomplete_destination(&temporary, error)
        } else {
            error
        }
    })
}

fn diff(
    yard: &Path,
    old: &Path,
    live: &Path,
    into: Option<&Path>,
    check: Option<&Path>,
    allow_corrupt: bool,
) -> Result<()> {
    let output = into
        .or(check)
        .ok_or_else(|| anyhow!("yard diff needs --into or --check"))?;
    if let Some(into) = into {
        refuse_existing(into)?;
    }
    let listing = list(yard, output)?;
    let old_side = Side::open(old).context("open OLD")?;
    let live_side = Side::open(live).context("open LIVE")?;
    let members = open_members(&listing)?;
    let checked_side = check.map(Side::open).transpose().context("open DIFF")?;

    let mut roles = vec![
        (format!("OLD {}", old.display()), &old_side),
        (format!("LIVE {}", live.display()), &live_side),
    ];
    roles.extend(
        members
            .iter()
            .map(|side| (format!("yard member {}", side.path.display()), side)),
    );
    if let Some(side) = &checked_side {
        roles.push((format!("DIFF {}", side.path.display()), side));
    }
    require_unaliased(&roles)?;
    require_complete("OLD", &old_side)?;
    for side in &members {
        require_complete("yard member", side)?;
    }

    println!(
        "yard diff {} against {} and yard {}",
        old.display(),
        live.display(),
        yard.display()
    );
    print_live(&live_side);
    print_listing(yard, &listing, &members);
    let mut baseline: Vec<&Side> = vec![&live_side];
    baseline.extend(members.iter());
    let mut statics: Vec<&Side> = vec![&old_side];
    statics.extend(members.iter());
    statics.extend(checked_side.iter());
    let unchanged = || require_unchanged(yard, output, &listing, &statics, Some(&live_side));
    let old_input = || Input {
        path: old.to_path_buf(),
        scan: old_side.scan(),
    };
    let label = format!("{} nor any pile of {}", live.display(), yard.display());
    let verify = |out: &Side| -> Result<Checked> {
        let checked = check_union(
            vec![old_input()],
            &baseline,
            out,
            Some(&[&old_side][..]),
            allow_corrupt,
            KeepEvery::LogAndUnknown,
        )?;
        println!(
            "check {} = {} + yard {} + {}",
            old.display(),
            live.display(),
            yard.display(),
            out.path.display()
        );
        println!(
            "scope: {} frames of {}'s {} bytes",
            checked.frames,
            old.display(),
            checked.bytes
        );
        checked.print_table("in LIVE/yard", "in DIFF");
        print_coverage(&baseline, &checked.covered);
        checked.verdict(
            &old.display().to_string(),
            &format!("{}, any pile of yard {}", live.display(), yard.display()),
            &out.path.display().to_string(),
            allow_corrupt,
        )?;
        Ok(checked)
    };

    match (into, &checked_side) {
        (Some(into), _) => write_verified(
            into,
            "yard-diff",
            |out, temporary| {
                let tally = copy_new(
                    vec![old_input()],
                    &baseline,
                    &label,
                    out,
                    temporary,
                    allow_corrupt,
                    KeepEvery::LogAndUnknown,
                )?;
                println!("written: {} frames of {}", tally.frames, old.display());
                tally.print_table("in LIVE/yard");
                Ok(tally)
            },
            |out| verify(out).map(drop),
            unchanged,
        ),
        (None, Some(side)) => {
            verify(side)?;
            unchanged()?;
            println!("verified {}", side.path.display());
            Ok(())
        }
        (None, None) => unreachable!("output is --into or --check"),
    }
}

fn pack(
    yard: &Path,
    live: Option<&Path>,
    into: Option<&Path>,
    check: Option<&Path>,
    allow_corrupt: bool,
) -> Result<()> {
    let output = into
        .or(check)
        .ok_or_else(|| anyhow!("yard pack needs --into or --check"))?;
    if let Some(into) = into {
        refuse_existing(into)?;
    }
    let listing = list(yard, output)?;
    let live_side = live
        .map(|live| Side::open(live).context("open LIVE"))
        .transpose()?;
    let members = open_members(&listing)?;
    let checked_side = check.map(Side::open).transpose().context("open PACKED")?;

    let mut roles = Vec::new();
    if let Some(side) = &live_side {
        roles.push((format!("LIVE {}", side.path.display()), side));
    }
    roles.extend(
        members
            .iter()
            .map(|side| (format!("yard member {}", side.path.display()), side)),
    );
    if let Some(side) = &checked_side {
        roles.push((format!("PACKED {}", side.path.display()), side));
    }
    require_unaliased(&roles)?;
    for side in &members {
        require_complete("yard member", side)?;
    }
    // LIVE first, then members by name: the order unknown frames are
    // written and checked in.
    let inputs: Vec<&Side> = live_side.iter().chain(members.iter()).collect();

    println!("yard pack {}", yard.display());
    if let Some(side) = &live_side {
        print_live(side);
    }
    print_listing(yard, &listing, &members);
    println!(
        "legacy pin and retired WANT frames are kept once each, without their order; \
         uninterpreted frames at every occurrence, in input order"
    );
    let statics: Vec<&Side> = members.iter().chain(checked_side.iter()).collect();
    let unchanged = || require_unchanged(yard, output, &listing, &statics, live_side.as_ref());
    let scans = || -> Vec<Input> {
        inputs
            .iter()
            .map(|side| Input {
                path: side.path.clone(),
                scan: side.scan(),
            })
            .collect()
    };
    let verify = |out: &Side| -> Result<()> {
        let checked = check_union(
            scans(),
            &[],
            out,
            Some(inputs.as_slice()),
            allow_corrupt,
            KeepEvery::Unknown,
        )?;
        println!(
            "check {} = union of {} input(s)",
            out.path.display(),
            inputs.len()
        );
        println!(
            "scope: {} frames of {} input bytes",
            checked.frames, checked.bytes
        );
        checked.print_table("in baseline", "in PACKED");
        checked.verdict(
            &format!("the {} input(s)", inputs.len()),
            "",
            &out.path.display().to_string(),
            allow_corrupt,
        )
    };

    match (into, &checked_side) {
        (Some(into), _) => write_verified(
            into,
            "yard-pack",
            |out, temporary| {
                let tally = copy_new(
                    scans(),
                    &[],
                    "any input",
                    out,
                    temporary,
                    allow_corrupt,
                    KeepEvery::Unknown,
                )?;
                println!(
                    "written: {} frames of {} input(s)",
                    tally.frames,
                    inputs.len()
                );
                tally.print_table("in baseline");
                Ok(tally)
            },
            verify,
            unchanged,
        ),
        (None, Some(side)) => {
            verify(side)?;
            unchanged()?;
            println!("verified {}", side.path.display());
            Ok(())
        }
        (None, None) => unreachable!("output is --into or --check"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    /// The guard run just before publication sees every kind of change.
    #[test]
    fn a_changed_yard_or_input_refuses_publication() {
        let dir = tempfile::tempdir().unwrap();
        let yard = dir.path().join("yard");
        fs::create_dir(&yard).unwrap();
        let (member, live, output) = (
            yard.join("g1.pile"),
            dir.path().join("live.pile"),
            yard.join("out.pile"),
        );
        // Empty files are empty piles.
        fs::File::create(&member).unwrap();
        fs::File::create(&live).unwrap();

        let listing = list(&yard, &output).unwrap();
        let members = open_members(&listing).unwrap();
        let live_side = Side::open(&live).unwrap();
        let statics: Vec<&Side> = members.iter().collect();
        let guard = || require_unchanged(&yard, &output, &listing, &statics, Some(&live_side));
        guard().unwrap();

        // The output appearing under its own name is not a new member.
        fs::File::create(&output).unwrap();
        guard().unwrap();
        fs::remove_file(&output).unwrap();

        // A live pile may grow.
        append(&live, &[0; 64]);
        guard().unwrap();

        // A new member.
        fs::File::create(yard.join("g2.pile")).unwrap();
        assert!(format!("{:#}", guard().unwrap_err()).contains("new: [\"g2.pile\"]"));
        fs::remove_file(yard.join("g2.pile")).unwrap();
        guard().unwrap();

        // A member rewritten in place.
        append(&member, &[0; 64]);
        assert!(format!("{:#}", guard().unwrap_err()).contains("changed"));

        // A member replaced under the same name.
        let replacement = yard.join(".replacement");
        fs::File::create(&replacement).unwrap();
        fs::rename(&replacement, &member).unwrap();
        assert!(format!("{:#}", guard().unwrap_err()).contains("changed"));

        // A member gone.
        fs::remove_file(&member).unwrap();
        assert!(format!("{:#}", guard().unwrap_err()).contains("gone: [\"g1.pile\"]"));
    }

    #[test]
    fn a_replaced_live_pile_refuses_publication() {
        let dir = tempfile::tempdir().unwrap();
        let yard = dir.path().join("yard");
        fs::create_dir(&yard).unwrap();
        let live = dir.path().join("live.pile");
        fs::File::create(&live).unwrap();
        let listing = list(&yard, &yard.join("out.pile")).unwrap();
        let live_side = Side::open(&live).unwrap();
        let replacement = dir.path().join("replacement.pile");
        fs::File::create(&replacement).unwrap();
        fs::rename(&replacement, &live).unwrap();
        let refused = require_unchanged(
            &yard,
            &yard.join("out.pile"),
            &listing,
            &[],
            Some(&live_side),
        );
        assert!(format!("{:#}", refused.unwrap_err()).contains("replaced or shrank"));
    }
}
