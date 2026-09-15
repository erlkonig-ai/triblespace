//! Build a small, explicitly owner-approved collection grant bundle.
//!
//! Usage: collection_grant_bundle SOURCE_PILE REQUESTS_TSV SIGNING_KEY OUTPUT_PILE
//! Each nonempty, non-comment TSV row is exactly:
//! collection-handle<TAB>root-public-key<TAB>recipient-public-key<TAB>READ|WRITE
//! Handles accept an optional `blake3:` prefix; public keys are 64 hex digits.
//! Exact duplicate rows are idempotent. READ and WRITE are separate grants.
//!
//! This issues fresh invoke-only, non-expiring READ/WRITE proofs from one
//! explicitly supplied existing owner key. It does not translate old proofs,
//! infer authority, preserve delegation rights or expiry, or migrate Secrets
//! delivery capabilities. Every tuple must have been independently approved.
//! Existing descriptor bytes and collection identities are preserved exactly.
//!
//! SOURCE is read only through PileRecords: only requested descriptor payloads
//! are copied and freshly hashed, with corrupt duplicates skipped. No source
//! writer, full index, or member payload is opened; historical proof authority
//! is neither inferred nor copied. Ordinary grant helpers check every request
//! against a small MemoryRepo before OUTPUT
//! is created exclusively. The new pile contains those descriptor blobs, the
//! unchanged standard capability definitions, and the resulting proof records.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, Bytes};
use triblespace_core::capability::{capability_action, CapabilityProofId};
use triblespace_core::collection::{
    grant_collection_read, grant_collection_write, AdmissionPolicy, CollectionHandle, ACTION_READ,
    ACTION_WRITE,
};
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    SnapshotSource,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GrantAction {
    Read,
    Write,
}

impl GrantAction {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Request {
    collection: CollectionHandle,
    root: [u8; 32],
    recipient: [u8; 32],
    action: GrantAction,
}

struct Prepared {
    store: MemoryRepo,
    receipts: Vec<(Request, CapabilityProofId)>,
    descriptors: usize,
    duplicate_requests: usize,
    corrupt_occurrences: usize,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_public_key(text: &str) -> Result<VerifyingKey> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    // Reuse the existing principal validator, including canonical/non-weak
    // checks, rather than reaching the grant constructor's assertions.
    AdmissionPolicy::quorum([key], 1, None)?;
    Ok(key)
}

fn parse_requests(text: &str, signer: VerifyingKey) -> Result<(BTreeSet<Request>, usize)> {
    let mut requests = BTreeSet::new();
    let mut duplicates = 0;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').map(str::trim).collect();
        let [collection, root, recipient, action] = fields.as_slice() else {
            return Err(invalid(format!(
                "line {}: expected exactly four tab-separated fields",
                index + 1,
            ))
            .into());
        };
        let parse = || -> Result<Request> {
            let mut handle = [0; 32];
            hex::decode_to_slice(
                collection.strip_prefix("blake3:").unwrap_or(collection),
                &mut handle,
            )?;
            let root = parse_public_key(root)?;
            if root != signer {
                return Err(invalid("requested root does not equal the supplied signer").into());
            }
            let recipient = parse_public_key(recipient)?;
            let action = match *action {
                "READ" => GrantAction::Read,
                "WRITE" => GrantAction::Write,
                _ => return Err(invalid("action must be READ or WRITE").into()),
            };
            Ok(Request {
                collection: CollectionHandle::new(handle),
                root: root.to_bytes(),
                recipient: recipient.to_bytes(),
                action,
            })
        };
        let request = parse().map_err(|error| invalid(format!("line {}: {error}", index + 1)))?;
        if !requests.insert(request) {
            duplicates += 1;
        }
    }
    if requests.is_empty() {
        return Err(invalid("no grant requests were supplied").into());
    }
    Ok((requests, duplicates))
}

fn prepare(source: &Path, text: &str, signer: &SigningKey) -> Result<Prepared> {
    let (requests, duplicate_requests) = parse_requests(text, signer.verifying_key())?;
    let mut missing: BTreeSet<_> = requests.iter().map(|request| request.collection).collect();
    let descriptors = missing.len();
    let mut store = MemoryRepo::default();
    for action in [ACTION_READ, ACTION_WRITE] {
        store.put::<SimpleArchive, _>(entity! { capability_action: action }.facts().clone())?;
    }

    let mut corrupt_occurrences = 0;
    let mut records = PileRecords::open(source)?;
    while let Some(record) = records.next() {
        let record = record?;
        let PileRecordContent::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } = record.content
        else {
            continue;
        };
        let collection = CollectionHandle::new(hash.raw);
        if !missing.contains(&collection) {
            continue;
        }
        let end = data_offset
            .checked_add(data_len)
            .ok_or_else(|| invalid("descriptor payload range overflow"))?;
        // Hash the requested occurrence, never trust its advertised header H.
        // A corrupt duplicate does not prevent a later valid copy from working.
        let mut blob = Blob::<SimpleArchive>::new(records.bytes().slice(data_offset..end));
        if blob.get_handle() != collection {
            corrupt_occurrences += 1;
            continue;
        }
        // Keep only the selected small bytes, not a lease on the whole source
        // mmap. Replacing bytes with an identical copy preserves the fresh H.
        blob.bytes = Bytes::from_source(blob.bytes.as_ref().to_vec());
        store.put::<SimpleArchive, _>(blob)?;
        missing.remove(&collection);
        if missing.is_empty() {
            break;
        }
    }
    drop(records);
    if !missing.is_empty() {
        return Err(invalid(format!(
            "missing {} valid requested descriptor blob(s): {}",
            missing.len(),
            missing
                .iter()
                .map(|handle| format!("blake3:{}", hex::encode(handle.raw)))
                .collect::<Vec<_>>()
                .join(", "),
        ))
        .into());
    }

    let mut receipts = Vec::with_capacity(requests.len());
    for request in requests {
        let recipient = VerifyingKey::from_bytes(&request.recipient)?;
        let proof = match request.action {
            GrantAction::Read => {
                grant_collection_read(&mut store, request.collection, signer, recipient)
            }
            GrantAction::Write => {
                grant_collection_write(&mut store, request.collection, signer, recipient)
            }
        }
        .map_err(|error| {
            invalid(format!(
                "blake3:{} {} {}: {error}",
                hex::encode(request.collection.raw),
                hex::encode_upper(request.recipient),
                request.action.name(),
            ))
        })?;
        receipts.push((request, proof.id()));
    }
    Ok(Prepared {
        store,
        receipts,
        descriptors,
        duplicate_requests,
        corrupt_occurrences,
    })
}

fn write_output(output: &Path, prepared: &mut Prepared) -> Result<()> {
    let snapshot = prepared.store.snapshot()?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Never truncate or append to an existing destination, including SOURCE.
    let created = options.open(output)?;
    let result = (|| -> Result<()> {
        let mut pile = Pile::open(output)?;
        for info in snapshot.blobs() {
            let blob: Blob<UnknownBlob> = snapshot.get(info?.handle)?;
            pile.put::<UnknownBlob, _>(blob)?;
        }
        for proof in snapshot.proofs()? {
            pile.insert_proof(proof?)?;
        }
        pile.close()?;
        Ok(())
    })();
    drop(created);
    if let Err(error) = result {
        // This path was created by this operation, never supplied as a source.
        // A failed write must not leave a bundle that looks ready to import.
        if let Err(cleanup) = fs::remove_file(output) {
            return Err(io::Error::other(format!(
                "bundle write failed: {error}; removing its partial output failed: {cleanup}"
            ))
            .into());
        }
        return Err(error);
    }
    Ok(())
}

fn run(source: &Path, requests: &Path, key: &Path, output: &Path) -> Result<()> {
    let text = fs::read_to_string(requests)?;
    let signer = triblespace_core::signing_key_file::load_existing(key)?;
    let mut prepared = prepare(source, &text, &signer)?;
    write_output(output, &mut prepared)?;
    println!("# collection\troot\trecipient\taction\tproof");
    for (request, proof) in &prepared.receipts {
        println!(
            "blake3:{}\t{}\t{}\t{}\tblake3:{}",
            hex::encode(request.collection.raw),
            hex::encode_upper(request.root),
            hex::encode_upper(request.recipient),
            request.action.name(),
            hex::encode(proof.raw),
        );
    }
    println!(
        "# created {}: {} descriptor blobs, 2 standard capability definitions, {} proofs; {} duplicate requests and {} corrupt descriptor occurrences skipped",
        output.display(), prepared.descriptors, prepared.receipts.len(), prepared.duplicate_requests, prepared.corrupt_occurrences,
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("collection_grant_bundle SOURCE_PILE REQUESTS_TSV SIGNING_KEY OUTPUT_PILE\nTSV: collection-handle<TAB>root-public-key<TAB>recipient-public-key<TAB>READ|WRITE\nFresh owner-approved invoke-only grants, not an automatic historical-proof migration.");
        return Ok(());
    }
    let [source, requests, key, output] = args.as_slice() else {
        return Err(invalid(
            "usage: collection_grant_bundle SOURCE_PILE REQUESTS_TSV SIGNING_KEY OUTPUT_PILE",
        )
        .into());
    };
    run(
        Path::new(source),
        Path::new(requests),
        Path::new(key),
        Path::new(output),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::{NamedTempFile, TempDir};
    use triblespace_core::capability::{CapabilityRequest, CapabilityResource};
    use triblespace_core::collection::{
        read_capability, write_capability, Collection, CollectionPolicy, CollectionRead,
        CollectionStoreExt,
    };
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::metadata;

    use super::*;

    struct Fixture {
        directory: TempDir,
        source: NamedTempFile,
        signer: SigningKey,
        recipient: VerifyingKey,
        collection: Collection<SimpleArchive>,
        descriptor: Vec<u8>,
        member: CollectionHandle,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = TempDir::new()?;
            let source = NamedTempFile::new_in(directory.path())?;
            let signer = SigningKey::from_bytes(&[17; 32]);
            let recipient = SigningKey::from_bytes(&[18; 32]).verifying_key();
            let policy = CollectionPolicy::new(
                AdmissionPolicy::direct(signer.verifying_key()),
                AdmissionPolicy::direct(signer.verifying_key()),
            );
            let mut pile = Pile::open(source.path())?;
            let collection = pile.collection("exact existing collection", policy.clone())?;
            pile.collection("not requested", policy)?;
            let commit = pile.commit(
                collection,
                &signer,
                entity! { metadata::tag: metadata::KIND_MULTI },
            )?;
            let snapshot = pile.snapshot()?;
            let descriptor: Blob<SimpleArchive> = snapshot.get(collection.handle())?;
            let descriptor = descriptor.bytes.as_ref().to_vec();
            pile.close()?;
            Ok(Self {
                directory,
                source,
                signer,
                recipient,
                collection,
                descriptor,
                member: Handle::<SimpleArchive>::from_hash(commit.data()),
            })
        }

        fn row(&self, action: &str) -> String {
            format!(
                "blake3:{}\t{}\t{}\t{action}\n",
                hex::encode(self.collection.handle().raw),
                hex::encode(self.signer.verifying_key().to_bytes()),
                hex::encode(self.recipient.to_bytes())
            )
        }

        fn build(&self, text: &str, output: &Path) -> Result<Prepared> {
            let mut prepared = prepare(self.source.path(), text, &self.signer)?;
            write_output(output, &mut prepared)?;
            Ok(prepared)
        }
    }

    #[test]
    fn exact_descriptor_subject_actions_and_standard_definitions_are_preserved() -> Result<()> {
        let fixture = Fixture::new()?;
        let original = fs::read(fixture.source.path())?;
        let output = fixture.directory.path().join("grants.pile");
        let prepared = fixture.build(&(fixture.row("READ") + &fixture.row("WRITE")), &output)?;
        assert_eq!(prepared.descriptors, 1);
        assert_eq!(prepared.receipts.len(), 2);
        let mut pile = Pile::open(&output)?;
        let snapshot = pile.snapshot()?;
        let descriptor: Blob<SimpleArchive> = snapshot.get(fixture.collection.handle())?;
        assert_eq!(descriptor.bytes.as_ref(), fixture.descriptor);
        let handles = snapshot
            .blobs()
            .map(|info| info.map(|info| info.handle.raw))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        assert_eq!(
            handles,
            BTreeSet::from([
                fixture.collection.handle().raw,
                read_capability().raw,
                write_capability().raw
            ])
        );
        assert!(!snapshot.contains_blob(fixture.member)?);
        assert_eq!(snapshot.records()?.count(), 0);
        for (request, id) in prepared.receipts {
            let proof = snapshot.proof(id)?.expect("staged proof was written");
            assert_eq!(
                proof.resource(),
                CapabilityResource::from(fixture.collection.handle())
            );
            assert_eq!(proof.root_key(), fixture.signer.verifying_key());
            assert_eq!(proof.leaf_key(), fixture.recipient);
            assert_eq!(proof.step_count(), 1);
            let (definition, action) = match request.action {
                GrantAction::Read => (read_capability(), ACTION_READ),
                GrantAction::Write => (write_capability(), ACTION_WRITE),
            };
            assert_eq!(proof.capabilities().collect::<Vec<_>>(), vec![definition]);
            proof.verify(
                &snapshot,
                fixture.signer.verifying_key(),
                fixture.recipient,
                CapabilityRequest::new(
                    CapabilityResource::from(fixture.collection.handle()),
                    action,
                ),
            )?;
        }
        assert!(fixture
            .collection
            .reader_is_admitted(&snapshot, fixture.recipient)?);
        assert!(fixture
            .collection
            .writer_is_admitted(&snapshot, fixture.recipient)?);
        pile.close()?;
        assert_eq!(fs::read(fixture.source.path())?, original);
        Ok(())
    }

    #[test]
    fn exact_duplicate_requests_are_idempotent_and_destination_is_exclusive() -> Result<()> {
        let fixture = Fixture::new()?;
        let row = fixture.row("READ");
        let text = format!("# explicitly approved\n\n{row}{row}");
        let output = fixture.directory.path().join("grants.pile");
        let prepared = fixture.build(&text, &output)?;
        assert_eq!(prepared.duplicate_requests, 1);
        assert_eq!(prepared.receipts.len(), 1);
        let second = prepare(fixture.source.path(), &row, &fixture.signer)?;
        assert_eq!(prepared.receipts, second.receipts);
        let before = fs::read(&output)?;
        assert!(fixture.build(&text, &output).is_err());
        assert_eq!(fs::read(&output)?, before);
        assert!(fixture.build(&row, fixture.source.path()).is_err());
        Ok(())
    }

    #[test]
    fn missing_descriptor_and_wrong_root_create_no_output() -> Result<()> {
        let fixture = Fixture::new()?;
        let output = fixture.directory.path().join("grants.pile");
        let absent = Blob::<SimpleArchive>::new(Bytes::from_source(Vec::<u8>::new())).get_handle();
        let missing = fixture.row("READ").replace(
            &hex::encode(fixture.collection.handle().raw),
            &hex::encode(absent.raw),
        );
        assert!(fixture.build(&missing, &output).is_err());
        assert!(!output.exists());
        let wrong_root = fixture.row("READ").replace(
            &hex::encode(fixture.signer.verifying_key().to_bytes()),
            &hex::encode(fixture.recipient.to_bytes()),
        );
        assert!(fixture.build(&wrong_root, &output).is_err());
        assert!(!output.exists());
        assert!(fixture
            .build(&(fixture.row("READ") + &wrong_root), &output)
            .is_err());
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn policy_failure_after_staging_other_requests_creates_no_output() -> Result<()> {
        let fixture = Fixture::new()?;
        let other = SigningKey::from_bytes(&[19; 32]);
        let mut source = Pile::open(fixture.source.path())?;
        let foreign = source.collection(
            "separate read and write owners",
            CollectionPolicy::new(
                AdmissionPolicy::direct(fixture.signer.verifying_key()),
                AdmissionPolicy::direct(other.verifying_key()),
            ),
        )?;
        source.close()?;
        let foreign_rows = (fixture.row("READ") + &fixture.row("WRITE")).replace(
            &hex::encode(fixture.collection.handle().raw),
            &hex::encode(foreign.handle().raw),
        );
        let output = fixture.directory.path().join("grants.pile");
        // Same collection/root/recipient orders READ before WRITE: the first
        // proof is staged, then the ordinary WRITE policy check rejects.
        assert!(fixture.build(&foreign_rows, &output).is_err());
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn malformed_or_weak_public_keys_and_actions_are_errors_not_panics() -> Result<()> {
        let fixture = Fixture::new()?;
        for text in [
            String::new(),
            "# no requests".to_owned(),
            fixture.row("DELEGATE"),
            fixture.row("READ") + "extra column\textra\textra\textra\textra\n",
            fixture
                .row("READ")
                .replace(&hex::encode(fixture.recipient.to_bytes()), &"00".repeat(32)),
            fixture
                .row("READ")
                .replace(&hex::encode(fixture.recipient.to_bytes()), "not a key"),
        ] {
            assert!(parse_requests(&text, fixture.signer.verifying_key()).is_err());
        }
        Ok(())
    }

    #[test]
    fn interface_loads_an_existing_key_without_creating_or_replacing_it() -> Result<()> {
        let fixture = Fixture::new()?;
        let requests = fixture.directory.path().join("requests.tsv");
        fs::write(&requests, fixture.row("READ"))?;
        let absent_key = fixture.directory.path().join("absent.key");
        let output = fixture.directory.path().join("grants.pile");
        assert!(run(fixture.source.path(), &requests, &absent_key, &output).is_err());
        assert!(!absent_key.exists());
        assert!(!output.exists());

        let key = NamedTempFile::new_in(fixture.directory.path())?;
        let key_bytes = hex::encode(fixture.signer.to_bytes());
        fs::write(key.path(), key_bytes.as_bytes())?;
        let source_bytes = fs::read(fixture.source.path())?;
        run(fixture.source.path(), &requests, key.path(), &output)?;
        assert_eq!(fs::read(key.path())?, key_bytes.as_bytes());
        assert_eq!(fs::read(fixture.source.path())?, source_bytes);
        Ok(())
    }

    #[test]
    fn corrupt_descriptor_duplicate_is_skipped_before_valid_occurrence() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut records = PileRecords::open(fixture.source.path())?;
        let mut corrupt = None;
        while let Some(record) = records.next() {
            let record = record?;
            if let PileRecordContent::Blob {
                hash, data_offset, ..
            } = record.content
            {
                if hash.raw == fixture.collection.handle().raw {
                    let mut frame =
                        records.bytes()[record.offset..record.offset + record.len].to_vec();
                    frame[data_offset - record.offset] ^= 1;
                    corrupt = Some(frame);
                    break;
                }
            }
        }
        let corrupt = corrupt.expect("descriptor frame");
        let mut source = NamedTempFile::new_in(fixture.directory.path())?;
        source.write_all(&corrupt)?;
        source.write_all(&fs::read(fixture.source.path())?)?;
        source.flush()?;
        let mut prepared = prepare(source.path(), &fixture.row("READ"), &fixture.signer)?;
        assert_eq!(prepared.corrupt_occurrences, 1);
        let output = fixture.directory.path().join("grants.pile");
        write_output(&output, &mut prepared)?;
        let staged: Blob<SimpleArchive> = prepared
            .store
            .snapshot()?
            .get(fixture.collection.handle())?;
        assert_eq!(staged.bytes.as_ref(), fixture.descriptor);

        let mut only_corrupt = NamedTempFile::new_in(fixture.directory.path())?;
        only_corrupt.write_all(&corrupt)?;
        only_corrupt.flush()?;
        assert!(prepare(only_corrupt.path(), &fixture.row("READ"), &fixture.signer).is_err());
        Ok(())
    }
}
