//! Raw, record-complete capture of one native snapshot; never a repair.

use anyhow::Result;
use std::path::Path;

pub(super) fn run(source: &Path, into: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        capture(source, into, &mut std::io::stdout().lock())
    }
    #[cfg(not(unix))]
    {
        let _ = (source, into);
        anyhow::bail!(
            "pile capture currently requires Unix private-file and directory-sync semantics"
        )
    }
}

#[cfg(unix)]
use {
    anyhow::{anyhow, bail, Context},
    std::fs,
    std::io::{self, Write},
    std::os::unix::fs::MetadataExt,
    std::path::PathBuf,
    triblespace_core::repo::pile::{PileFile, PileFileSnapshot},
    triblespace_core::repo::SnapshotSource,
};

/// Resolve an existing private parent, including `.` for a bare filename.
/// Passing an absolute child to publish also ensures it syncs that directory.
#[cfg(unix)]
fn private_destination(into: &Path) -> Result<PathBuf> {
    let name = into
        .file_name()
        .ok_or_else(|| anyhow!("destination {} names no file", into.display()))?;
    let parent = into
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("resolve staging directory {}", parent.display()))?;
    let metadata = fs::metadata(&parent)
        .with_context(|| format!("stat staging directory {}", parent.display()))?;
    // SAFETY: geteuid only reads this process's effective user identity.
    let owner = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        bail!(
            "staging directory {} must be owned by this user with no group/other permissions; \
             no permissions were changed",
            parent.display()
        );
    }
    let destination = parent.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => bail!(
            "refusing: destination {} already exists; capture never overwrites",
            destination.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect capture destination"),
    }
    Ok(destination)
}

/// Write/hash bounded chunks from precisely the snapshot's own mapping.
#[cfg(unix)]
fn write_snapshot(
    snapshot: &PileFileSnapshot,
    out: &mut impl Write,
) -> Result<(u64, blake3::Hash)> {
    let raw = snapshot.raw_records();
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    for chunk in raw.bytes().chunks(1024 * 1024) {
        out.write_all(chunk).context("write captured prefix")?;
        hasher.update(chunk);
        bytes += chunk.len() as u64;
    }
    if bytes != u64::try_from(snapshot.prefix_len())? {
        bail!("captured length differs from the snapshot's record boundary");
    }
    Ok((bytes, hasher.finalize()))
}

/// Never remove `into`: publication may already have succeeded before an
/// unlink, directory sync or receipt failed. Only our hidden output is cleaned.
#[cfg(unix)]
fn unaccepted(temporary: &Path, into: &Path, error: anyhow::Error) -> anyhow::Error {
    let error = error.context(format!(
        "capture not accepted; source left unchanged; destination {} may exist but is \
         unaccepted and was not removed",
        into.display()
    ));
    match fs::symlink_metadata(temporary) {
        Ok(_) => super::compact::cleanup_incomplete_destination(temporary, error),
        Err(missing) if missing.kind() == io::ErrorKind::NotFound => error,
        Err(check) => error.context(format!(
            "could not inspect unaccepted temporary {} for cleanup: {check}",
            temporary.display()
        )),
    }
}

#[cfg(unix)]
fn capture(source: &Path, into: &Path, receipt: &mut impl Write) -> Result<()> {
    let into = private_destination(into)?;
    let mut pile =
        PileFile::open_read_only(source).map_err(|error| super::pile_read_error(source, error))?;
    let observed = (|| -> Result<_> {
        let metadata = pile.backing_file_metadata().context("stat opened source")?;
        let identity = super::subtract::opened_identity(&metadata, source)?;
        let snapshot = pile
            .snapshot()
            .map_err(|error| super::pile_read_error(source, error))?;
        Ok((identity, snapshot))
    })();
    // Close even after a failed snapshot. On success the snapshot itself pins
    // the mapping; no source pathname is reopened during the copy.
    let closed = pile.close();
    let (identity, snapshot) = observed?;
    closed.context("close read-only capture source")?;

    let temporary = super::subtract::temporary_sibling(&into, "capture")?;
    let mut output = super::compact::create_fresh_destination(&temporary)
        .with_context(|| format!("create private capture {}", temporary.display()))?;
    let written = (|| -> Result<()> {
        let output_identity = super::subtract::opened_identity(&output.metadata()?, &temporary)?;
        if identity == output_identity {
            bail!("refusing capture: source and temporary destination are the same file");
        }
        let (bytes, digest) = write_snapshot(&snapshot, &mut output)?;
        output
            .sync_all()
            .with_context(|| format!("sync captured file {}", temporary.display()))?;
        drop(output);
        super::subtract::publish(&temporary, &into)?;
        // Paths are display spellings, not global identities. Device/inode
        // identify this local observation; digest/length describe its bytes.
        let summary = serde_json::json!({
            "status": "captured",
            "source": {
                "path": source.to_string_lossy(),
                "device": identity.0,
                "inode": identity.1,
            },
            "destination": into.to_string_lossy(),
            "bytes": bytes,
            "blake3": digest.to_hex().to_string(),
            "record_complete": true,
            "integrity_checked": false,
        });
        serde_json::to_writer(&mut *receipt, &summary).context("write capture receipt")?;
        receipt.write_all(b"\n").context("write capture receipt")?;
        receipt.flush().context("flush capture receipt")?;
        Ok(())
    })();
    written.map_err(|error| unaccepted(&temporary, &into, error))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::repo::pile::Pile;
    use triblespace_core::repo::BlobStorePut;

    /// A temporary directory that is private regardless of the ambient umask,
    /// because capture refuses a staging parent with group/other permissions.
    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn append(path: &Path, text: &str) {
        if !path.exists() {
            fs::File::create(path).unwrap();
        }
        let mut pile = Pile::open(path).unwrap();
        pile.put::<UTF8String, _>(text).unwrap();
        pile.close().unwrap();
    }

    #[test]
    fn receipt_and_reopened_capture_match_raw_bytes_including_duplicates() {
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        let into = directory.path().join("capture.pile");
        append(&source, "captured bytes");
        let first = fs::read(&source).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap()
            .write_all(&first)
            .unwrap();
        let expected = fs::read(&source).unwrap();
        let mut receipt = Vec::new();
        capture(&source, &into, &mut receipt).unwrap();
        assert_eq!(fs::read(&into).unwrap(), expected);
        assert_eq!(fs::read(&source).unwrap(), expected);
        assert_eq!(fs::metadata(&into).unwrap().mode() & 0o077, 0);
        let metadata = fs::metadata(&source).unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        assert_eq!(receipt["bytes"], expected.len() as u64);
        assert_eq!(receipt["blake3"], blake3::hash(&expected).to_hex().as_str());
        assert_eq!(receipt["source"]["device"], metadata.dev());
        assert_eq!(receipt["source"]["inode"], metadata.ino());
        assert_eq!(receipt["record_complete"], true);
        assert_eq!(receipt["integrity_checked"], false);
        let mut reopened = PileFile::open_read_only(&into).unwrap();
        assert_eq!(reopened.snapshot().unwrap().raw_records().count(), 2);
        reopened.close().unwrap();
    }

    #[test]
    fn pinned_snapshot_copy_excludes_later_appends() {
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        append(&source, "before");
        let expected = fs::read(&source).unwrap();
        let mut pile = PileFile::open_read_only(&source).unwrap();
        let snapshot = pile.snapshot().unwrap();
        pile.close().unwrap();
        append(&source, "after");
        let mut copied = Vec::new();
        let (length, digest) = write_snapshot(&snapshot, &mut copied).unwrap();
        assert_eq!(copied, expected);
        assert_eq!(length, expected.len() as u64);
        assert_eq!(digest, blake3::hash(&expected));
        assert!(fs::metadata(&source).unwrap().len() > length);
    }

    #[test]
    fn existing_file_hardlink_and_dangling_symlink_are_never_overwritten() {
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        append(&source, "unchanged");
        let expected = fs::read(&source).unwrap();
        let into = directory.path().join("capture.pile");
        fs::write(&into, b"preexisting").unwrap();
        assert!(capture(&source, &into, &mut Vec::new()).is_err());
        assert_eq!(fs::read(&into).unwrap(), b"preexisting");
        assert!(capture(&source, &source, &mut Vec::new()).is_err());
        let alias = directory.path().join("hardlink.pile");
        fs::hard_link(&source, &alias).unwrap();
        assert!(capture(&source, &alias, &mut Vec::new()).is_err());
        let dangling = directory.path().join("dangling.pile");
        symlink(directory.path().join("missing"), &dangling).unwrap();
        assert!(capture(&source, &dangling, &mut Vec::new()).is_err());
        assert!(fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&source).unwrap(), expected);
        assert!(!directory.path().join("missing").exists());
    }

    #[test]
    fn malformed_source_creates_no_output_and_empty_source_is_valid() {
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        append(&source, "complete record");
        let mut malformed = fs::read(&source).unwrap();
        malformed.pop();
        fs::write(&source, &malformed).unwrap();
        let into = directory.path().join("capture.pile");
        assert!(capture(&source, &into, &mut Vec::new()).is_err());
        assert!(!into.exists());
        assert_eq!(fs::read(&source).unwrap(), malformed);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        fs::write(&source, []).unwrap();
        capture(&source, &into, &mut Vec::new()).unwrap();
        assert_eq!(fs::metadata(&into).unwrap().len(), 0);
    }

    #[test]
    fn staging_parent_must_be_private_and_is_not_chmodded() {
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        append(&source, "private");
        let staging = directory.path().join("public");
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(capture(&source, &staging.join("capture"), &mut Vec::new()).is_err());
        assert_eq!(fs::metadata(&staging).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[test]
    fn no_clobber_publication_failure_cleans_only_our_temporary() {
        let directory = private_tempdir();
        let into = directory.path().join("capture");
        let temporary = super::super::subtract::temporary_sibling(&into, "capture").unwrap();
        fs::write(&temporary, b"ours").unwrap();
        fs::write(&into, b"another writer").unwrap();
        let error = super::super::subtract::publish(&temporary, &into).unwrap_err();
        let error = unaccepted(&temporary, &into, error);
        assert!(format!("{error:#}").contains("capture not accepted"));
        assert!(!temporary.exists());
        assert_eq!(fs::read(&into).unwrap(), b"another writer");
    }

    #[test]
    fn failures_after_publication_never_remove_the_published_file() {
        let directory = private_tempdir();
        let into = directory.path().join("capture");
        let temporary = directory.path().join("hidden");
        fs::write(&temporary, b"complete").unwrap();
        fs::hard_link(&temporary, &into).unwrap();
        // The states at failed temporary unlink and at failed directory sync.
        let error = unaccepted(&temporary, &into, anyhow!("unlink failed"));
        assert!(format!("{error:#}").contains("unlink failed"));
        assert!(!temporary.exists());
        let error = unaccepted(&temporary, &into, anyhow!("directory sync failed"));
        assert!(format!("{error:#}").contains("directory sync failed"));
        assert_eq!(fs::read(&into).unwrap(), b"complete");
    }

    #[test]
    fn failed_receipt_leaves_an_explicitly_unaccepted_complete_capture() {
        struct BrokenReceipt;
        impl Write for BrokenReceipt {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "receipt closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let directory = private_tempdir();
        let source = directory.path().join("source.pile");
        let into = directory.path().join("capture.pile");
        append(&source, "retain on receipt failure");
        let error = capture(&source, &into, &mut BrokenReceipt).unwrap_err();
        assert!(format!("{error:#}").contains("capture not accepted"));
        assert_eq!(fs::read(&source).unwrap(), fs::read(&into).unwrap());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }
}
