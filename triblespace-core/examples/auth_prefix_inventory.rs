//! Temporary, read-only AUTH-v4 cutover inventory, pinned to SDK a365f8aa.
//!
//! This is evidence for an explicit owner-approved reissue, not a migration or
//! an authorization decision. It never opens a Pile writer, fetches a blob,
//! reads a private key, or issues a proof. In particular it does not turn an
//! expired/bounded grant into a non-expiring grant or classify Secrets grants
//! as collection grants merely because they have a familiar action.
//!
//! Two canonical PileRecords scans cover one observed append-only prefix:
//! first collect every v4 proof and the explicitly selected C descriptors;
//! then read only the definition handles named by those proofs/descriptors.
//! No member archives, recursive blob references, or whole-pile blob index.
//! The source must not be compacted, replaced, or mutated during the scan.
//! A partial/corrupt frame is an error, not an implicitly complete inventory.
//!
//! Every exact prefix is checked independently. A bad later signature cannot
//! hide earlier signed authority. Structural corruption that the canonical
//! record decoder cannot delimit still fails the scan; this is not a salvage
//! parser. Actions come from definition facts on arbitrary entity IDs. The
//! v4 kernel itself compares exact definition handles, not action equality.
//!
//! Output is escaped TSV: record kind followed by `key=value` cells. All
//! resources are inventoried; `selected` is a routing/review label, never a
//! filter. Repeated prefixes retain their exact IDs and must not be counted
//! as distinct root shares. Raw facts preserve unknown policy/definition
//! annotations and the legacy identity-bearing delegation-threshold field.
//! Exit 0 means a complete observation, not permission to reissue its grants.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anybytes::Bytes;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, TryFromBlob};
use triblespace_core::capability::policy::{capability_handle, resource_policy};
use triblespace_core::capability::{
    capability_action, Capability, CapabilityHandle, CapabilityMode, CapabilityProof,
    CapabilityProofError, CAPABILITY_PROOF_EDGE_LEN, CAPABILITY_PROOF_HEADER_LEN,
    CAPABILITY_PROOF_MAGIC,
};
use triblespace_core::collection::{
    descriptor, ACTION_READ, ACTION_WRITE, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace_core::metadata;
use triblespace_core::prelude::{find, pattern, Id, TribleSet, UnknownInline};
use triblespace_core::repo::pile::{PileRecordContent, PileRecords};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Hash = [u8; 32];

const SDK_REVISION: &str = "a365f8aa2df988ab8a61b0cf6a5ea09447d15b03";
const USAGE: &str = "auth_prefix_inventory PILE [HANDLE ...] [--selected HANDLE] [--selected-file FILE] [--at-tai-ns N]

Select at least one exact collection descriptor handle (64 hex, optionally
prefixed by blake3:). Selection files contain one handle per line; blank lines
and # comments are ignored. The selection labels the report; proofs for other
resources are also reported, so recipients, delegated paths and Secrets-only
restrictions cannot disappear from the inventory.

No writes, reissue, network, key access or collection materialization. Times
are inclusive TAI nanosecond bounds as encoded by AUTH v4, not Unix timestamps.
Output is TSV with escaped key=value cells. Exit 0 is NOT a reissue approval.
Run only while the source obeys its append-only contract (no compaction/swap).";

struct Options {
    pile: PathBuf,
    selected: BTreeSet<Hash>,
    at_tai_ns: i128,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_handle(text: &str) -> Result<Hash> {
    let text = text.strip_prefix("blake3:").unwrap_or(text);
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|error| invalid(format!("invalid descriptor handle {text:?}: {error}")))?;
    Ok(bytes)
}

fn parse_options(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>> {
    let mut args = args.into_iter();
    let mut pile = None;
    let mut selected = BTreeSet::new();
    let mut at_tai_ns = None;
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        } else if arg == "--selected" {
            let value = args
                .next()
                .ok_or_else(|| invalid("--selected needs a handle"))?;
            selected.insert(parse_handle(
                value.to_str().ok_or_else(|| invalid("non-UTF8 handle"))?,
            )?);
        } else if arg == "--selected-file" {
            let file = args
                .next()
                .ok_or_else(|| invalid("--selected-file needs a path"))?;
            for (line, value) in fs::read_to_string(&file)?.lines().enumerate() {
                let value = value.split('#').next().unwrap_or("").trim();
                if !value.is_empty() {
                    selected.insert(parse_handle(value).map_err(|error| {
                        invalid(format!(
                            "{}:{}: {error}",
                            Path::new(&file).display(),
                            line + 1
                        ))
                    })?);
                }
            }
        } else if arg == "--at-tai-ns" {
            let value = args
                .next()
                .ok_or_else(|| invalid("--at-tai-ns needs an integer"))?;
            if at_tai_ns.is_some() {
                return Err(invalid("--at-tai-ns supplied more than once").into());
            }
            at_tai_ns = Some(
                value
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF8 timestamp"))?
                    .parse()?,
            );
        } else if arg.to_string_lossy().starts_with('-') {
            return Err(invalid(format!("unknown option {}", arg.to_string_lossy())).into());
        } else if pile.is_none() {
            pile = Some(PathBuf::from(arg));
        } else {
            selected.insert(parse_handle(
                arg.to_str().ok_or_else(|| invalid("non-UTF8 handle"))?,
            )?);
        }
    }
    let pile = pile.ok_or_else(|| invalid(USAGE))?;
    if selected.is_empty() {
        return Err(invalid("at least one selected descriptor handle is required").into());
    }
    Ok(Some(Options {
        pile,
        selected,
        at_tai_ns: at_tai_ns.unwrap_or_else(|| {
            triblespace_core::clock::epoch_now()
                .to_tai_duration()
                .total_nanoseconds()
        }),
    }))
}

#[derive(Default)]
struct ReferencedArchive {
    facts: Option<TribleSet>,
    invalid_occurrences: usize,
    last_error: Option<String>,
}

impl ReferencedArchive {
    fn observe(&mut self, hash: Hash, bytes: &[u8]) {
        if self.facts.is_some() {
            return;
        }
        // Raw PileRecords intentionally did not authenticate this payload.
        // Hash only a requested descriptor/definition, never unrelated blobs.
        let blob = Blob::<SimpleArchive>::new(Bytes::from_source(bytes.to_vec()));
        let facts = if blob.get_handle().raw == hash {
            TribleSet::try_from_blob(blob).map_err(|error| error.to_string())
        } else {
            Err("payload does not match the BLOB header hash".to_owned())
        };
        match facts {
            Ok(facts) => self.facts = Some(facts),
            Err(error) => {
                self.invalid_occurrences += 1;
                self.last_error = Some(error);
            }
        }
    }

    fn status(&self) -> &'static str {
        if self.facts.is_some() {
            "resident"
        } else if self.invalid_occurrences != 0 {
            "invalid-resident"
        } else {
            "missing"
        }
    }
}

struct LocatedProof {
    proof: CapabilityProof,
    first_offset: usize,
    occurrences: usize,
}

struct Inventory {
    metadata: fs::Metadata,
    covered_len: usize,
    records: usize,
    opaque_records: usize,
    retired_proofs: usize,
    proofs: BTreeMap<Hash, LocatedProof>,
    archives: BTreeMap<Hash, ReferencedArchive>,
    definitions: BTreeSet<Hash>,
}

// The canonical descriptor query selects tagged entities, not a reconstructed
// intrinsic ID. Keep even bindings whose policy vocabulary is unsupported.
fn descriptor_definitions(facts: &TribleSet) -> BTreeSet<Hash> {
    find!(
        (descriptor: Id, binding: Id, capability: CapabilityHandle),
        pattern!(facts, [
            { ?descriptor @ metadata::tag: KIND_COLLECTION_DESCRIPTOR, resource_policy: ?binding },
            { ?binding @ capability_handle: ?capability },
        ])
    )
    .map(|(_, _, capability)| capability.raw)
    .collect()
}

fn same_source(before: &fs::Metadata, after: &fs::Metadata, covered_len: usize) -> Result<()> {
    if after.len() < covered_len as u64 {
        return Err(
            invalid("pile shrank below the observed prefix; retry on a stable source").into(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(invalid(
                "pile path was replaced during the audit; retry on a stable source",
            )
            .into());
        }
    }
    #[cfg(not(unix))]
    let _ = before;
    Ok(())
}

fn scan_proofs_and_selected(options: &Options) -> Result<Inventory> {
    let metadata = fs::metadata(&options.pile)?;
    let mut records = PileRecords::open(&options.pile)?;
    let covered_len = records.bytes().len();
    same_source(&metadata, &fs::metadata(&options.pile)?, covered_len)?;
    let mut inventory = Inventory {
        metadata,
        covered_len,
        records: 0,
        opaque_records: 0,
        retired_proofs: 0,
        proofs: BTreeMap::new(),
        archives: options
            .selected
            .iter()
            .map(|hash| (*hash, ReferencedArchive::default()))
            .collect(),
        definitions: BTreeSet::new(),
    };
    while let Some(record) = records.next() {
        let record = record?;
        inventory.records += 1;
        match record.content {
            PileRecordContent::CapabilityProof {
                data_offset,
                data_len,
                ..
            } => {
                let proof = CapabilityProof::from_bytes(
                    &records.bytes()[data_offset..data_offset + data_len],
                )?;
                inventory.definitions.extend(
                    proof
                        .capabilities()
                        .map(|capability| capability.handle().raw),
                );
                inventory
                    .proofs
                    .entry(proof.id().raw)
                    .and_modify(|entry| entry.occurrences += 1)
                    .or_insert(LocatedProof {
                        proof,
                        first_offset: record.offset,
                        occurrences: 1,
                    });
            }
            PileRecordContent::Blob {
                hash,
                data_offset,
                data_len,
                ..
            } => {
                if let Some(archive) = inventory.archives.get_mut(&hash.raw) {
                    archive.observe(
                        hash.raw,
                        &records.bytes()[data_offset..data_offset + data_len],
                    );
                }
            }
            PileRecordContent::Opaque { .. } => inventory.opaque_records += 1,
            PileRecordContent::RetiredCapabilityProof => inventory.retired_proofs += 1,
            _ => {}
        }
    }
    same_source(
        &inventory.metadata,
        &fs::metadata(&options.pile)?,
        covered_len,
    )?;
    for archive in inventory.archives.values() {
        if let Some(facts) = &archive.facts {
            inventory.definitions.extend(descriptor_definitions(facts));
        }
    }
    for hash in &inventory.definitions {
        inventory.archives.entry(*hash).or_default();
    }
    Ok(inventory)
}

fn scan_definitions(options: &Options, inventory: &mut Inventory) -> Result<()> {
    let path = &options.pile;
    same_source(
        &inventory.metadata,
        &fs::metadata(path)?,
        inventory.covered_len,
    )?;
    let mut records = PileRecords::open(path)?;
    if records.bytes().len() < inventory.covered_len {
        return Err(invalid("second mapping lost the observed prefix").into());
    }
    let mut end = 0;
    // Do not even decode an append beyond the first scan's boundary. A later
    // partial frame or definition is not part of this observation.
    while end < inventory.covered_len {
        let record = records
            .next()
            .ok_or_else(|| invalid("observed prefix disappeared"))??;
        end = record.offset + record.len;
        if end > inventory.covered_len {
            return Err(invalid("record boundary changed below the observed prefix").into());
        }
        if let PileRecordContent::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } = record.content
        {
            // Selected descriptor hashes were already exhausted in pass 1.
            // If one also names a definition, do not count its bad physical
            // occurrences twice by revisiting the same observed prefix.
            if inventory.definitions.contains(&hash.raw) && !options.selected.contains(&hash.raw) {
                inventory
                    .archives
                    .get_mut(&hash.raw)
                    .expect("definition was selected in first scan")
                    .observe(
                        hash.raw,
                        &records.bytes()[data_offset..data_offset + data_len],
                    );
            }
        }
    }
    same_source(
        &inventory.metadata,
        &fs::metadata(path)?,
        inventory.covered_len,
    )
}

fn action_ids(facts: &TribleSet) -> BTreeSet<Id> {
    find!((entity: Id, action: Id), pattern!(facts, [{ ?entity @ capability_action: ?action }]))
        .map(|(_, action)| action)
        .collect()
}

fn hash_text(hash: Hash) -> String {
    format!("blake3:{}", hex::encode(hash))
}

fn actions_text(archive: Option<&ReferencedArchive>) -> String {
    match archive.and_then(|archive| archive.facts.as_ref()) {
        Some(facts) => action_ids(facts)
            .iter()
            .map(|id| hex::encode(&id[..]))
            .collect::<Vec<_>>()
            .join(","),
        None => "unknown".to_owned(),
    }
}

fn mode_text(capability: Option<Capability>) -> &'static str {
    match capability.map(Capability::mode) {
        Some(CapabilityMode::Invoke) => "invoke",
        Some(CapabilityMode::Delegate) => "delegate",
        Some(CapabilityMode::InvokeAndDelegate) => "invoke+delegate",
        None => "invalid-path",
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn emit(out: &mut impl Write, kind: &str, fields: &[(&str, String)]) -> io::Result<()> {
    write!(out, "{kind}")?;
    for (key, value) in fields {
        write!(out, "\t{key}={}", escape(value))?;
    }
    writeln!(out)
}

#[derive(Clone, Copy, Default)]
struct Bounds {
    lower: Option<i128>,
    upper: Option<i128>,
}

impl Bounds {
    fn include(&mut self, bounds: Option<(i128, i128)>) {
        if let Some((lower, upper)) = bounds {
            self.lower = Some(self.lower.map_or(lower, |old| old.max(lower)));
            self.upper = Some(self.upper.map_or(upper, |old| old.min(upper)));
        }
    }

    fn state(self, at: i128) -> &'static str {
        if matches!((self.lower, self.upper), (Some(lower), Some(upper)) if lower > upper) {
            "empty"
        } else if self.lower.is_some_and(|lower| at < lower) {
            "not-yet-valid"
        } else if self.upper.is_some_and(|upper| at > upper) {
            "expired"
        } else if self.lower.is_none() && self.upper.is_none() {
            "unbounded"
        } else {
            "within-bounds"
        }
    }
}

fn bound(value: Option<i128>) -> String {
    value.map_or_else(|| "unbounded".to_owned(), |value| value.to_string())
}

fn report_prefixes(
    out: &mut impl Write,
    proof: &CapabilityProof,
    options: &Options,
    archives: &BTreeMap<Hash, ReferencedArchive>,
) -> Result<usize> {
    let mut effective = None;
    let mut bounds = Bounds::default();
    let mut issuer = proof.root_key();
    let mut valid_count = 0;
    for (step, ((subject, capability), validity)) in proof
        .delegated_keys()
        .zip(proof.capabilities())
        .zip(proof.validities())
        .enumerate()
    {
        let prefix = CapabilityProof::from_bytes(
            &proof.as_bytes()
                [..CAPABILITY_PROOF_HEADER_LEN + (step + 1) * CAPABILITY_PROOF_EDGE_LEN],
        )?;
        let validation = prefix.validate_structure();
        let signature_valid = !matches!(
            &validation,
            Err(CapabilityProofError::InvalidSignature { .. })
        );
        let path_valid = validation.is_ok();
        valid_count += usize::from(path_valid);
        effective = if step == 0 {
            Some(capability)
        } else {
            effective.and_then(|parent: Capability| parent.meet(capability))
        };
        bounds.include(validity.map(|validity| validity.bounds_ns()));
        let raw_bounds = validity.map(|validity| validity.bounds_ns());
        let flags =
            proof.as_bytes()[CAPABILITY_PROOF_HEADER_LEN + step * CAPABILITY_PROOF_EDGE_LEN + 32];
        let selected = options.selected.contains(proof.resource().as_bytes());
        let bound_root = if selected {
            match archives
                .get(proof.resource().as_bytes())
                .and_then(|archive| archive.facts.as_ref())
            {
                Some(facts) => descriptor::capability_policies(facts, None)
                    .any(|(handle, policy)| {
                        handle == capability.handle()
                            && policy
                                .roots()
                                .is_some_and(|roots| roots.contains(&proof.root_key()))
                    })
                    .to_string(),
                None => "unknown".to_owned(),
            }
        } else {
            "not-selected".to_owned()
        };
        emit(
            out,
            "PREFIX",
            &[
                ("proof", hash_text(proof.id().raw)),
                ("prefix", hash_text(prefix.id().raw)),
                ("edges", (step + 1).to_string()),
                ("resource", hash_text(proof.resource().into_bytes())),
                ("selected", selected.to_string()),
                ("root", hex::encode(proof.root_key().to_bytes())),
                ("issuer", hex::encode(issuer.to_bytes())),
                ("subject", hex::encode(subject.to_bytes())),
                ("capability", hash_text(capability.handle().raw)),
                (
                    "action_ids",
                    actions_text(archives.get(&capability.handle().raw)),
                ),
                ("edge_flags_hex", format!("{flags:02x}")),
                ("edge_mode", mode_text(Some(capability)).to_owned()),
                (
                    "edge_invokes",
                    capability
                        .mode()
                        .satisfies(CapabilityMode::Invoke)
                        .to_string(),
                ),
                ("edge_delegates", capability.mode().delegates().to_string()),
                (
                    "edge_lower_tai_ns",
                    bound(raw_bounds.map(|(lower, _)| lower)),
                ),
                (
                    "edge_upper_tai_ns",
                    bound(raw_bounds.map(|(_, upper)| upper)),
                ),
                (
                    "effective_mode",
                    if path_valid {
                        mode_text(effective)
                    } else {
                        "invalid-path"
                    }
                    .to_owned(),
                ),
                (
                    "effective_lower_tai_ns",
                    if path_valid {
                        bound(bounds.lower)
                    } else {
                        "invalid-path".to_owned()
                    },
                ),
                (
                    "effective_upper_tai_ns",
                    if path_valid {
                        bound(bounds.upper)
                    } else {
                        "invalid-path".to_owned()
                    },
                ),
                (
                    "time_state",
                    if path_valid {
                        bounds.state(options.at_tai_ns)
                    } else {
                        "invalid-path"
                    }
                    .to_owned(),
                ),
                (
                    "signatures",
                    if signature_valid { "valid" } else { "invalid" }.to_owned(),
                ),
                (
                    "attenuation",
                    if path_valid {
                        "valid"
                    } else if signature_valid {
                        "invalid"
                    } else {
                        "unchecked"
                    }
                    .to_owned(),
                ),
                ("root_bound_to_exact_capability", bound_root),
                (
                    "error",
                    validation
                        .err()
                        .map_or_else(String::new, |error| error.to_string()),
                ),
            ],
        )?;
        issuer = subject;
    }
    Ok(valid_count)
}

fn report(out: &mut impl Write, options: &Options, inventory: &Inventory) -> Result<()> {
    emit(
        out,
        "INVENTORY",
        &[
            ("sdk", SDK_REVISION.to_owned()),
            ("proof_magic", hex::encode(CAPABILITY_PROOF_MAGIC)),
            ("pile", options.pile.display().to_string()),
            ("covered_len", inventory.covered_len.to_string()),
            ("at_tai_ns", options.at_tai_ns.to_string()),
            ("read_action", hex::encode(&ACTION_READ[..])),
            ("write_action", hex::encode(&ACTION_WRITE[..])),
        ],
    )?;
    emit(out, "LIMIT", &[
        ("meaning", "Evidence only: no reissue approval, quorum decision, expiry removal or Secrets conversion".to_owned()),
        ("scope", "all v4 proof resources; only selected descriptors and directly named definitions".to_owned()),
        ("time_bounds", "inclusive TAI nanoseconds; signed restrictions remain authoritative".to_owned()),
    ])?;
    for (hash, archive) in &inventory.archives {
        let selected = options.selected.contains(hash);
        emit(
            out,
            "ARCHIVE",
            &[
                ("handle", hash_text(*hash)),
                ("selected_descriptor", selected.to_string()),
                (
                    "capability_definition",
                    inventory.definitions.contains(hash).to_string(),
                ),
                ("status", archive.status().to_owned()),
                (
                    "invalid_occurrences",
                    archive.invalid_occurrences.to_string(),
                ),
                ("last_error", archive.last_error.clone().unwrap_or_default()),
                ("action_ids", actions_text(Some(archive))),
            ],
        )?;
        let Some(facts) = &archive.facts else {
            continue;
        };
        for fact in facts.iter() {
            emit(
                out,
                "FACT",
                &[
                    ("archive", hash_text(*hash)),
                    ("entity", hex::encode(&fact.e()[..])),
                    ("attribute", hex::encode(&fact.a()[..])),
                    ("value", hex::encode(fact.v::<UnknownInline>().raw)),
                ],
            )?;
        }
        if selected {
            for (capability, policy) in descriptor::capability_policies(facts, None) {
                emit(
                    out,
                    "POLICY",
                    &[
                        ("collection", hash_text(*hash)),
                        ("capability", hash_text(capability.raw)),
                        (
                            "action_ids",
                            actions_text(inventory.archives.get(&capability.raw)),
                        ),
                        (
                            "kind",
                            if policy.roots().is_some() {
                                "quorum"
                            } else {
                                "open"
                            }
                            .to_owned(),
                        ),
                        (
                            "roots",
                            policy.roots().map_or_else(String::new, |roots| {
                                roots
                                    .iter()
                                    .map(|key| hex::encode(key.to_bytes()))
                                    .collect::<Vec<_>>()
                                    .join(",")
                            }),
                        ),
                        (
                            "invoke_threshold",
                            policy.invoke_threshold().map_or_else(
                                || "none".to_owned(),
                                |threshold| threshold.to_string(),
                            ),
                        ),
                        (
                            "legacy_delegate_threshold",
                            "see raw FACT rows; not an invocation/delegation rule".to_owned(),
                        ),
                    ],
                )?;
            }
        }
    }
    let mut prefixes = 0;
    let mut valid_prefixes = 0;
    for located in inventory.proofs.values() {
        let proof = &located.proof;
        emit(
            out,
            "PROOF",
            &[
                ("id", hash_text(proof.id().raw)),
                ("resource", hash_text(proof.resource().into_bytes())),
                ("root", hex::encode(proof.root_key().to_bytes())),
                ("edges", proof.step_count().to_string()),
                ("first_offset", located.first_offset.to_string()),
                ("physical_occurrences", located.occurrences.to_string()),
            ],
        )?;
        prefixes += proof.step_count();
        valid_prefixes += report_prefixes(out, proof, options, &inventory.archives)?;
    }
    emit(
        out,
        "SUMMARY",
        &[
            ("observed_records", inventory.records.to_string()),
            ("v4_proofs", inventory.proofs.len().to_string()),
            ("prefix_observations", prefixes.to_string()),
            (
                "valid_signed_path_prefix_observations",
                valid_prefixes.to_string(),
            ),
            (
                "unreadable_requested_archives",
                inventory
                    .archives
                    .values()
                    .filter(|archive| archive.facts.is_none())
                    .count()
                    .to_string(),
            ),
            (
                "opaque_records_not_interpreted",
                inventory.opaque_records.to_string(),
            ),
            (
                "older_retired_proofs_not_interpreted",
                inventory.retired_proofs.to_string(),
            ),
            ("complete_observed_prefix", "true".to_owned()),
            ("reissue_approved", "false".to_owned()),
        ],
    )?;
    Ok(())
}

fn run() -> Result<()> {
    let Some(options) = parse_options(std::env::args_os().skip(1))? else {
        println!("{USAGE}");
        return Ok(());
    };
    let mut inventory = scan_proofs_and_selected(&options)?;
    scan_definitions(&options, &mut inventory)?;
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    report(&mut out, &options, &inventory)?;
    out.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("auth_prefix_inventory: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::capability::{CapabilityResource, CapabilityValidity};
    use triblespace_core::collection::AdmissionPolicy;
    use triblespace_core::prelude::{entity, rngid, Inline};
    use triblespace_core::repo::pile::Pile;
    use triblespace_core::repo::{BlobStorePut, CapabilityProofStore};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn options(resource: Hash, at_tai_ns: i128) -> Options {
        Options {
            pile: PathBuf::from("synthetic.pile"),
            selected: [resource].into(),
            at_tai_ns,
        }
    }

    fn definition() -> Blob<SimpleArchive> {
        let entity_id = rngid();
        entity! { &entity_id @ capability_action: ACTION_READ }
            .facts()
            .to_blob()
    }

    fn archives(blob: Blob<SimpleArchive>) -> BTreeMap<Hash, ReferencedArchive> {
        [(
            blob.get_handle().raw,
            ReferencedArchive {
                facts: Some(TribleSet::try_from_blob(blob).unwrap()),
                ..Default::default()
            },
        )]
        .into()
    }

    fn prefix_report(
        proof: &CapabilityProof,
        options: &Options,
        archives: &BTreeMap<Hash, ReferencedArchive>,
    ) -> (String, usize) {
        let mut output = Vec::new();
        let valid = report_prefixes(&mut output, proof, options, archives).unwrap();
        (String::from_utf8(output).unwrap(), valid)
    }

    #[test]
    fn expired_prefix_is_retained_with_raw_and_effective_bounds() {
        let definition = definition();
        let validity =
            CapabilityValidity::new(Epoch::from_tai_seconds(1.0), Epoch::from_tai_seconds(2.0))
                .unwrap();
        let proof = CapabilityProof::issue_root(
            &key(1),
            CapabilityResource::new([9; 32]),
            Capability::new(definition.get_handle(), CapabilityMode::Invoke),
            Some(validity),
            key(2).verifying_key(),
        );
        let at = Epoch::from_tai_seconds(3.0)
            .to_tai_duration()
            .total_nanoseconds();
        let (report, valid) = prefix_report(&proof, &options([9; 32], at), &archives(definition));
        assert_eq!(valid, 1);
        assert!(report.contains("\ttime_state=expired\t"));
        assert!(report.contains(&format!("\tedge_upper_tai_ns={}\t", validity.bounds_ns().1)));
        assert!(report.contains(&format!(
            "\teffective_upper_tai_ns={}\t",
            validity.bounds_ns().1
        )));
        assert!(report.contains("\tsignatures=valid\tattenuation=valid\t"));
    }

    #[test]
    fn invalid_later_signature_does_not_erase_valid_earlier_prefix() {
        let definition = definition();
        let capability =
            Capability::new(definition.get_handle(), CapabilityMode::InvokeAndDelegate);
        let first = CapabilityProof::issue_root(
            &key(1),
            CapabilityResource::new([9; 32]),
            capability,
            None,
            key(2).verifying_key(),
        );
        let second = first
            .extend(&key(2), capability, None, key(3).verifying_key())
            .unwrap();
        let mut bytes = second.as_bytes().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let corrupt = CapabilityProof::from_bytes(&bytes).unwrap();
        let (report, valid) = prefix_report(&corrupt, &options([9; 32], 0), &archives(definition));
        let lines: Vec<_> = report.lines().collect();
        assert_eq!(valid, 1);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(&format!("\tprefix={}\t", hash_text(first.id().raw))));
        assert!(lines[0].contains("\tsignatures=valid\tattenuation=valid\t"));
        assert!(lines[1].contains("\tsignatures=invalid\tattenuation=unchecked\t"));

        // Exercise the production canonical scanner too: the old Pile stores
        // structural proof bytes, so this is real audit input, not a hand-made
        // alternative record parser.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.pile");
        fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        pile.insert_proof(corrupt).unwrap();
        pile.close().unwrap();
        let mut options = options([9; 32], 0);
        options.pile = path;
        let inventory = scan_proofs_and_selected(&options).unwrap();
        assert_eq!(inventory.proofs.len(), 1);
        let mut output = Vec::new();
        super::report(&mut output, &options, &inventory).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("\tvalid_signed_path_prefix_observations=1\t"));
    }

    #[test]
    fn later_bounds_do_not_erase_the_earlier_expiry() {
        let definition = definition();
        let capability =
            Capability::new(definition.get_handle(), CapabilityMode::InvokeAndDelegate);
        let parent_bounds =
            CapabilityValidity::new(Epoch::from_tai_seconds(1.0), Epoch::from_tai_seconds(3.0))
                .unwrap();
        let child_bounds =
            CapabilityValidity::new(Epoch::from_tai_seconds(2.0), Epoch::from_tai_seconds(5.0))
                .unwrap();
        let parent = CapabilityProof::issue_root(
            &key(1),
            CapabilityResource::new([9; 32]),
            capability,
            Some(parent_bounds),
            key(2).verifying_key(),
        );
        let proof = parent
            .extend(
                &key(2),
                capability,
                Some(child_bounds),
                key(3).verifying_key(),
            )
            .unwrap();
        let at = Epoch::from_tai_seconds(4.0)
            .to_tai_duration()
            .total_nanoseconds();
        let (report, valid) = prefix_report(&proof, &options([9; 32], at), &archives(definition));
        let child = report.lines().nth(1).unwrap();
        assert_eq!(valid, 2);
        assert!(child.contains(&format!(
            "\tedge_upper_tai_ns={}\t",
            child_bounds.bounds_ns().1
        )));
        assert!(child.contains(&format!(
            "\teffective_lower_tai_ns={}\t",
            child_bounds.bounds_ns().0
        )));
        assert!(child.contains(&format!(
            "\teffective_upper_tai_ns={}\t",
            parent_bounds.bounds_ns().1
        )));
        assert!(child.contains("\ttime_state=expired\t"));
    }

    #[test]
    fn definition_action_query_ignores_the_entity_id_not_the_exact_handle() {
        let a = definition();
        let b = definition();
        assert_ne!(a.get_handle(), b.get_handle());
        let facts_a = TribleSet::try_from_blob(a).unwrap();
        let facts_b = TribleSet::try_from_blob(b).unwrap();
        assert_eq!(action_ids(&facts_a), action_ids(&facts_b));
        assert_eq!(action_ids(&facts_a), [ACTION_READ].into());
    }

    #[test]
    fn missing_definition_is_unknown_not_an_empty_or_granted_action_set() {
        let proof = CapabilityProof::issue_root(
            &key(1),
            CapabilityResource::new([9; 32]),
            Capability::new(Inline::new([7; 32]), CapabilityMode::Delegate),
            None,
            key(2).verifying_key(),
        );
        let (report, valid) = prefix_report(&proof, &options([9; 32], 0), &BTreeMap::new());
        assert_eq!(valid, 1);
        assert!(report.contains("\taction_ids=unknown\t"));
        assert!(report.contains("\tedge_invokes=false\tedge_delegates=true\t"));
        assert!(report.contains("\troot_bound_to_exact_capability=unknown\t"));
    }

    #[test]
    fn repeated_resource_keeps_distinct_roots_and_definitions_before_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.pile");
        fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let definition = definition();
        let handle = pile.put(definition).unwrap();
        for seed in [1, 2] {
            let proof = CapabilityProof::issue_root(
                &key(seed),
                CapabilityResource::new([9; 32]),
                Capability::new(handle, CapabilityMode::Invoke),
                None,
                key(3).verifying_key(),
            );
            pile.insert_proof(proof).unwrap();
        }
        pile.close().unwrap();
        let mut options = options([9; 32], 0);
        options.pile = path;
        let mut inventory = scan_proofs_and_selected(&options).unwrap();
        scan_definitions(&options, &mut inventory).unwrap();
        assert_eq!(inventory.proofs.len(), 2);
        assert_eq!(
            inventory
                .proofs
                .values()
                .map(|entry| entry.proof.root_key().to_bytes())
                .collect::<BTreeSet<_>>(),
            [
                key(1).verifying_key().to_bytes(),
                key(2).verifying_key().to_bytes()
            ]
            .into()
        );
        assert!(inventory.archives[&handle.raw].facts.is_some());
        let mut report_bytes = Vec::new();
        report(&mut report_bytes, &options, &inventory).unwrap();
        let report = String::from_utf8(report_bytes).unwrap();
        assert_eq!(
            report
                .lines()
                .filter(|line| line.starts_with("PREFIX\t"))
                .count(),
            2
        );
    }

    #[test]
    fn second_scan_ignores_definitions_appended_after_the_observed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.pile");
        let definition = definition();
        let handle = definition.get_handle();
        fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        pile.insert_proof(CapabilityProof::issue_root(
            &key(1),
            CapabilityResource::new([9; 32]),
            Capability::new(handle, CapabilityMode::Invoke),
            None,
            key(2).verifying_key(),
        ))
        .unwrap();
        pile.close().unwrap();
        let mut options = options([9; 32], 0);
        options.pile = path;
        let mut inventory = scan_proofs_and_selected(&options).unwrap();
        let boundary = inventory.covered_len;
        let mut writer = Pile::open(&options.pile).unwrap();
        writer.put::<SimpleArchive, _>(definition).unwrap();
        writer.close().unwrap();
        scan_definitions(&options, &mut inventory).unwrap();
        assert!(fs::metadata(&options.pile).unwrap().len() > boundary as u64);
        assert!(inventory.archives[&handle.raw].facts.is_none());
    }

    #[test]
    fn selected_policy_definitions_are_found_without_a_proof_or_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.pile");
        fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        // The definition precedes the descriptor; no AUTH mentions it. Pass 1
        // must discover the link before pass 2 examines this earlier blob.
        let capability = pile.put(definition()).unwrap();
        let policy =
            AdmissionPolicy::quorum([key(1).verifying_key(), key(2).verifying_key()], 2, Some(1))
                .unwrap();
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: policy.binding(capability),
        };
        let blob: Blob<SimpleArchive> = descriptor.facts().to_blob();
        let handle = pile.put::<SimpleArchive, _>(blob).unwrap();
        pile.close().unwrap();
        let mut options = options(handle.raw, 0);
        options.pile = path;
        let mut inventory = scan_proofs_and_selected(&options).unwrap();
        assert_eq!(inventory.proofs.len(), 0);
        assert!(inventory.definitions.contains(&capability.raw));
        scan_definitions(&options, &mut inventory).unwrap();
        assert!(inventory.archives[&capability.raw].facts.is_some());
        let mut output = Vec::new();
        report(&mut output, &options, &inventory).unwrap();
        let output = String::from_utf8(output).unwrap();
        let policy_line = output
            .lines()
            .find(|line| line.starts_with("POLICY\t"))
            .unwrap();
        assert!(policy_line.contains("\tinvoke_threshold=2\t"));
        assert!(policy_line.contains(&hex::encode(key(1).verifying_key().to_bytes())));
        assert!(policy_line.contains(&hex::encode(key(2).verifying_key().to_bytes())));
        // All descriptor facts, including the legacy threshold, remain exact.
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("FACT\t")
                    && line.contains(&format!("\tarchive={}\t", hash_text(handle.raw))))
                .count(),
            descriptor.facts().len()
        );
    }

    #[test]
    fn invalid_blob_occurrence_does_not_hide_a_later_good_definition() {
        let definition = definition();
        let mut archive = ReferencedArchive::default();
        archive.observe(definition.get_handle().raw, b"wrong payload");
        assert_eq!(archive.status(), "invalid-resident");
        archive.observe(definition.get_handle().raw, &definition.bytes);
        assert_eq!(archive.status(), "resident");
        assert_eq!(archive.invalid_occurrences, 1);
    }

    #[test]
    fn explicit_handles_and_selector_files_are_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let selectors = dir.path().join("selected.txt");
        fs::write(
            &selectors,
            format!("# selected descriptors\n{}\n\n", hash_text([9; 32])),
        )
        .unwrap();
        let options = parse_options([
            OsString::from("audit.pile"),
            OsString::from(hash_text([9; 32])),
            OsString::from("--selected-file"),
            selectors.into_os_string(),
            OsString::from("--at-tai-ns"),
            OsString::from("123"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(options.selected, [[9; 32]].into());
        assert_eq!(options.at_tai_ns, 123);
        assert!(parse_handle("not-a-handle").is_err());
    }
}
