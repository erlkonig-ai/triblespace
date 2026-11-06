//! A synchronous, session-only authoring driver. See the Incremental Queries book.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, Write as _};
use std::path::Path;

use ed25519_dalek::SigningKey;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::metadata;
use triblespace_core::prelude::blobencodings::{SimpleArchive, UTF8String};
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;
use triblespace_core::query::register::Resolution;
use triblespace_core::reactive::collection::{schema as c, CollectionEnvironment};
use triblespace_core::reactive::{schema as r, text};
use triblespace_core::repo::memoryrepo::MemoryRepo;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const HELP: &str = "Session-only MemoryRepo; source files survive, execution state does not.\n\
load PATH                         parse saved facts, then commit; no execution\n\
select REV[,REV] after READ[,READ]  explicit revisions and predecessor readings\n\
                                  use - for either empty list\n\
step [BUDGET]                     observe, advance once, publish (default 16)\n\
show                              observe; show reading and demo descriptions\n\
quit                              discard this in-memory session";

fn ids(list: &str) -> Result<Vec<Id>> {
    if list == "-" {
        return Ok(Vec::new());
    }
    list.split(',')
        .map(|id| Id::from_hex(id).ok_or_else(|| format!("invalid ID: {id}").into()))
        .collect()
}

fn display_ids(ids: impl IntoIterator<Item = Id>) -> String {
    let ids: Vec<_> = ids.into_iter().map(|id| format!("{id:x}")).collect();
    if ids.is_empty() {
        "-".into()
    } else {
        ids.join(",")
    }
}

fn display_reading(reading: &Resolution) -> String {
    match reading {
        Resolution::Empty => "Empty".into(),
        Resolution::Sole(id) => format!("Sole({id:x})"),
        Resolution::Fork(heads) => format!("Fork({})", display_ids(heads.iter().copied())),
    }
}

// This holds capabilities and a continuation, never a second model of the facts.
pub struct Session {
    store: MemoryRepo,
    key: SigningKey,
    root: Collection<SimpleArchive>,
    anchor: Id,
    environment: CollectionEnvironment,
}

impl Session {
    pub fn new() -> Result<Self> {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut store = MemoryRepo::for_host(key.verifying_key());
        let policy = AdmissionPolicy::direct(key.verifying_key());
        let root = store.collection(
            "live text example",
            CollectionPolicy::new(policy.clone(), policy),
        )?;
        let anchor = *genid();
        Ok(Self {
            store,
            key,
            root,
            anchor,
            environment: CollectionEnvironment::new(root, anchor),
        })
    }

    /// Execute one command, retaining the same environment across every call.
    /// Errors leave the command loop alive; no command implicitly selects a rule.
    pub fn command(&mut self, line: &str, output: &mut impl io::Write) -> Result<bool> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(true);
        }
        if let Some(path) = line.strip_prefix("load ") {
            // Finish parsing before any mutation, including blob insertion.
            let fragment = text::parse(fs::read(path.trim())?.into())?;
            let revisions = find!(revision: Id, pattern!(fragment.facts(), [
                { ?revision @ r::operation: r::POSITIVE }
            ]))
            .collect::<Vec<_>>();
            self.store.commit(self.root, &self.key, fragment)?;
            writeln!(
                output,
                "loaded; revisions {} (not selected)",
                display_ids(revisions)
            )?;
            return Ok(true);
        }
        let words: Vec<_> = line.split_whitespace().collect();
        match words.as_slice() {
            ["select", revisions, "after", predecessors] => {
                let selected = ids(revisions)?;
                let prior = ids(predecessors)?;
                let reading = genid();
                self.store.commit(
                    self.root,
                    &self.key,
                    entity! { &reading @
                        c::reading_of: self.anchor,
                        c::selects*: selected.iter().copied(),
                        metadata::supersedes*: prior.iter().copied(),
                    },
                )?;
                writeln!(
                    output,
                    "reading {:x} selects {} after {}",
                    *reading,
                    display_ids(selected),
                    display_ids(prior)
                )?;
            }
            ["step"] | ["step", _] => {
                let budget = words.get(1).map_or(Ok(16), |n| n.parse::<usize>())?;
                // Retry any uncertain publication before adopting a new reading.
                self.environment.publish(&mut self.store, &self.key)?;
                let snapshot = self.store.snapshot()?;
                let reading = self.environment.observe(&snapshot)?;
                writeln!(output, "reading {}", display_reading(&reading))?;
                let computation = self.environment.advance(budget, &snapshot);
                // Successful conclusions preceding an evaluation failure still publish.
                let publication = self.environment.publish(&mut self.store, &self.key);
                if let Err(error) = &computation {
                    writeln!(output, "evaluation: {error}")?;
                }
                if let Err(error) = &publication {
                    writeln!(output, "publication: {error}")?;
                }
                let published = publication?.is_some();
                let advanced = computation?;
                writeln!(
                    output,
                    "firings {} progress {:?} published {published}",
                    advanced.firings.len(),
                    advanced.progress
                )?;
            }
            ["show"] => {
                let snapshot = self.store.snapshot()?;
                let reading = self.environment.observe(&snapshot)?;
                writeln!(
                    output,
                    "reading {}; selected {}",
                    display_reading(&reading),
                    display_ids(self.environment.selected().iter().copied())
                )?;
                writeln!(output, "demo projection: metadata::description")?;
                for (item, description) in find!((item: Id, description: Inline<Handle<UTF8String>>),
                    pattern!(self.environment.facts(), [{ ?item @ metadata::description: ?description }])
                ) {
                    let description: View<str> = snapshot.get(description)?;
                    writeln!(output, "{item:x}: {}", &*description)?;
                }
            }
            ["quit"] => return Ok(false),
            _ => return Err(format!("unknown command\n{HELP}").into()),
        }
        Ok(true)
    }
}

/// Create independent fresh authoring templates, not a clone/remapping of stored facts.
/// A new directory is required so existing source files are never overwritten.
pub fn initialize(directory: &Path) -> Result<()> {
    fs::create_dir(directory)?;
    for name in ["v1.rules", "v2.rules"] {
        let mut source = String::new();
        for alias in [
            "revision", "item", "text", "needle", "match", "contains", "emit",
        ] {
            writeln!(source, "alias {alias} = id\"{:x}\";", *genid())?;
        }
        writeln!(source, "alias name = id\"{:x}\";", metadata::name.id())?;
        writeln!(
            source,
            "alias description = id\"{:x}\";",
            metadata::description.id()
        )?;
        source.push_str(
            r#"
// Edit only before first load; a semantic edit after publication needs fresh IDs.
rule @revision {
  operation POSITIVE;
  matches @match (?item @name ?text);
  literal ?needle utf8("red");
  constraint @contains STRING_CONTAINS(?text, ?needle);
  emits @emit (?item @description ?text);
}
"#,
        );
        fs::write(directory.join(name), source)?;
    }
    for (name, labels) in [
        ("initial.facts", ["red lantern", "blue lantern"]),
        ("later.facts", ["red comet", "blue comet"]),
    ] {
        let mut source = String::new();
        for label in labels {
            writeln!(
                source,
                "fact id\"{:x}\" id\"{:x}\" utf8(\"{label}\");",
                *genid(),
                metadata::name.id()
            )?;
        }
        fs::write(directory.join(name), source)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, directory] if flag == "--init" => {
            initialize(Path::new(directory))?;
            println!("Created fresh example IDs in {directory}; edit v2.rules before first load.");
            return Ok(());
        }
        [] => {}
        _ => return Err("usage: reactive_live [--init NEW_DIRECTORY]".into()),
    }
    println!("{HELP}");
    let mut session = Session::new()?;
    let mut output = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        match session.command(&line?, &mut output) {
            Ok(false) => break,
            Ok(true) => {}
            Err(error) => writeln!(output, "error: {error}")?,
        }
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/support/reactive_live.rs"]
mod tests;
