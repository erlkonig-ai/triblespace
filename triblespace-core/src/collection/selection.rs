//! Which collections this pile syncs: one register per collection, kept in
//! the pile's own configuration collection.
//!
//! The sync daemon peers for a collection only while the pile selects it. The
//! selection is written by more than one program -- the faculties, the
//! daemon's own CLI, a menu-bar app -- and read by a daemon that depends on
//! none of them, so its schema and the configuration collection it lives in
//! are defined here, in the crate all of them share.
//!
//! # The configuration collection
//!
//! [`config_handle`] derives the collection from the pile's signing key and
//! the fixed name [`CONFIG_COLLECTION_NAME`] under [`private_policy`]. Nothing
//! has to remember the handle: a process holding the key already knows where
//! to look. [`config_facts`] reads it, and a host that was never configured
//! holds no descriptor there and reads an empty configuration, in which every
//! register is unset. The derivation is byte-for-byte the faculties' own,
//! because a daemon reading one collection while the faculties write another
//! would sync nothing.
//!
//! # One register per collection
//!
//! A state names the collection whose selection it is a version of
//! ([`sync_collection`], the register's anchor) and says whether that
//! collection is selected ([`sync_selected`]). States are ordered by
//! [`metadata::supersedes`]: a write supersedes every head it saw, so an
//! ordinary change needs no clock and no retraction, and the history of what
//! was selected stays readable.
//!
//! Every write mints a fresh id for its state. An id derived from the state's
//! own facts would make two writes that say the same thing one state, and
//! that is wrong here whether or not the supersession edges are among those
//! facts. Without them, "select C again, replacing the unselect" re-mints the
//! original "select C", which then both supersedes and is superseded by the
//! unselect. With them, a writer whose frame is stale repeats an earlier
//! state exactly: "select C" written having seen nothing IS the first
//! "select C", already superseded, so a write that disagrees with the current
//! head would vanish into the history instead of standing beside it as a
//! conflict. A fresh id gives up only idempotence, and that buys nothing
//! here: writes that agree already read as one value.
//!
//! # Reading
//!
//! [`sync_selection`] reports the heads rather than choosing among them.
//! Heads that agree give their value, including several concurrent ones: two
//! programs selecting the same collection at once is not a conflict. Heads
//! that disagree give [`Selection::Conflicted`] with every head, and the
//! reader decides; inventing an order between concurrent states is the one
//! thing a register here never does. One write superseding them settles it.
//!
//! A head whose value the reader cannot decode is skipped, as any fact it
//! cannot model is, so every outcome speaks for the heads it can decode. The
//! state that head superseded stays superseded: skipping a head never brings
//! back an older value.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::id::{genid, Id};
use crate::inline::encodings::boolean::Boolean;
use crate::inline::encodings::hash::Handle;
use crate::macros::{attributes, entity};
use crate::metadata;
use crate::prelude::{and, find, pattern};
use crate::query::register::{maximal, ObservationOrder};
use crate::query::TriblePattern;
use crate::repo::{BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource, StoreRead};
use crate::trible::TribleSet;

use super::simplearchive_union::FactViewError;
use super::{
    descriptor, private_policy, Collection, CollectionCommit, CollectionCommitError,
    CollectionHandle, CollectionReadError, CollectionStore, CollectionStoreExt,
};

/// The name of every pile's own configuration collection.
///
/// The same on every host. The policy names each host's key, so the handles
/// differ while the name says they play the same role.
pub const CONFIG_COLLECTION_NAME: &str = "config";

/// The configuration collection of the pile `authority` signs for.
///
/// Derived, never configured: the root of a resolution cannot be resolved by
/// the thing it roots. A reader may open the handle without registering it;
/// a writer registers `CONFIG_COLLECTION_NAME` under [`private_policy`] and
/// receives the same handle.
pub fn config_handle(authority: VerifyingKey) -> CollectionHandle {
    descriptor::root_handle_to_read(CONFIG_COLLECTION_NAME, private_policy(authority))
}

/// The configuration `snapshot` holds for the pile `authority` signs for.
///
/// A pile that was never configured holds no descriptor at
/// [`config_handle`], and that reads as an empty configuration rather than
/// as an error. Whether the descriptor is there is observed, never fetched,
/// so an unconfigured host does not ask its peers for one.
pub fn config_facts<S>(
    snapshot: &S,
    authority: VerifyingKey,
) -> Result<
    TribleSet,
    ConfigReadError<<S as BlobStoreList>::Err, <S as BlobStoreGet>::GetError<Infallible>>,
>
where
    S: StoreRead,
{
    let handle = config_handle(authority);
    if !snapshot
        .contains_blob(handle)
        .map_err(ConfigReadError::Residency)?
    {
        return Ok(TribleSet::new());
    }
    Collection::<SimpleArchive>::from_handle(handle)
        .read::<TribleSet, _>(snapshot)
        .map_err(ConfigReadError::Read)
}

attributes! {
    /// The collection whose sync selection this state is a version of.
    ///
    /// The register's anchor. A reader asks for the states of one collection
    /// by its descriptor handle, so a state about another collection is never
    /// in this register.
    ///
    /// Anchor minted with `trible genid` on 2026-10-05:
    /// `99D9A2B7C5636FEFDE482DB3A6D01EE6`.
    "99D9A2B7C5636FEFDE482DB3A6D01EE6" as pub sync_collection: Handle<SimpleArchive>;
    /// Whether this state selects its collection for sync.
    ///
    /// Unselecting is a state, not an absence, so that it can supersede a
    /// selection; a register nobody wrote carries no value at all.
    ///
    /// Anchor minted with `trible genid` on 2026-10-05:
    /// `24EB46425226C0025A3C85D34F8919CE`.
    "24EB46425226C0025A3C85D34F8919CE" as pub sync_selected: Boolean;
}

/// What the decodable heads of one collection's register say.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Selection {
    /// No head this reader can decode names the collection.
    Unset,
    /// Every head this reader can decode selects the collection.
    Selected,
    /// Every head this reader can decode unselects the collection.
    Unselected,
    /// The heads this reader can decode disagree, and these are all of them.
    Conflicted(BTreeSet<Id>),
}

/// The sync selection `facts` holds for `collection`.
///
/// `facts` is the configuration collection as the caller reads it, for
/// example through [`config_facts`]. The heads are the states nothing in
/// `facts` supersedes; a head whose value this reader cannot decode is
/// skipped.
pub fn sync_selection<P>(facts: &P, collection: CollectionHandle) -> Selection
where
    P: TriblePattern + Sync,
{
    let order = ObservationOrder::new(facts, metadata::supersedes.id());
    let heads: Vec<(Id, bool)> = find!(
        (state: Id, selected: bool),
        and!(
            pattern!(facts, [{ ?state @
                sync_collection: collection,
                sync_selected: ?selected,
            }]),
            maximal(state, &order),
        )
    )
    .collect();

    if heads.is_empty() {
        Selection::Unset
    } else if heads.iter().all(|(_, selected)| *selected) {
        Selection::Selected
    } else if heads.iter().all(|(_, selected)| !*selected) {
        Selection::Unselected
    } else {
        Selection::Conflicted(heads.into_iter().map(|(state, _)| state).collect())
    }
}

/// Select or unselect `collection` in `config`, superseding every head.
///
/// The heads are read from one snapshot of `config` and the new state is
/// committed under `signing_key` with a fresh id. Every state of the
/// register that nothing supersedes is superseded, whatever it says, so a
/// conflict is settled by this write and a head this reader cannot decode
/// does not survive it.
pub fn write_sync_selection<S>(
    store: &mut S,
    config: Collection<SimpleArchive>,
    signing_key: &SigningKey,
    collection: CollectionHandle,
    selected: bool,
) -> Result<
    CollectionCommit,
    SelectionWriteError<
        <S as SnapshotSource>::SnapshotError,
        <<S as SnapshotSource>::Snapshot as BlobStoreGet>::GetError<Infallible>,
        <S as BlobStorePut>::PutError,
        <S as CollectionStore>::InsertError,
    >,
>
where
    S: CollectionStoreExt + SnapshotSource,
    <S as SnapshotSource>::Snapshot: StoreRead,
{
    let snapshot = store.snapshot().map_err(SelectionWriteError::Snapshot)?;
    let facts = config
        .read::<TribleSet, _>(&snapshot)
        .map_err(SelectionWriteError::Read)?;
    let order = ObservationOrder::new(&facts, metadata::supersedes.id());
    let heads: BTreeSet<Id> = find!(
        state: Id,
        and!(
            pattern!(&facts, [{ ?state @ sync_collection: collection }]),
            maximal(state, &order),
        )
    )
    .collect();
    drop(snapshot);

    let state = entity! { &genid() @
        sync_collection: collection,
        sync_selected: selected,
        metadata::supersedes*: heads,
    };
    store
        .commit(config, signing_key, state)
        .map_err(SelectionWriteError::Commit)
}

/// Failure to write one sync selection state.
#[derive(Debug)]
pub enum SelectionWriteError<SnapshotError, GetError, PutError, InsertError> {
    /// The store could not freeze the observation the heads are read from.
    Snapshot(SnapshotError),
    /// The configuration collection could not be read.
    Read(CollectionReadError<GetError, FactViewError>),
    /// The new state could not be committed.
    Commit(CollectionCommitError<PutError, InsertError>),
}

impl<SnapshotError, GetError, PutError, InsertError> fmt::Display
    for SelectionWriteError<SnapshotError, GetError, PutError, InsertError>
where
    SnapshotError: fmt::Display,
    GetError: fmt::Display,
    PutError: fmt::Display,
    InsertError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(source) => {
                write!(formatter, "failed to freeze store snapshot: {source}")
            }
            Self::Read(source) => {
                write!(formatter, "failed to read the sync selection: {source}")
            }
            Self::Commit(source) => {
                write!(formatter, "failed to commit the sync selection: {source}")
            }
        }
    }
}

impl<SnapshotError, GetError, PutError, InsertError> Error
    for SelectionWriteError<SnapshotError, GetError, PutError, InsertError>
where
    SnapshotError: Error + 'static,
    GetError: Error + 'static,
    PutError: Error + 'static,
    InsertError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Snapshot(source) => Some(source),
            Self::Read(source) => Some(source),
            Self::Commit(source) => Some(source),
        }
    }
}

/// Failure to read a pile's configuration.
#[derive(Debug)]
pub enum ConfigReadError<ResidencyError, GetError> {
    /// The snapshot could not say whether the configuration exists.
    Residency(ResidencyError),
    /// The configuration exists and could not be read.
    Read(CollectionReadError<GetError, FactViewError>),
}

impl<ResidencyError, GetError> fmt::Display for ConfigReadError<ResidencyError, GetError>
where
    ResidencyError: fmt::Display,
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Residency(source) => {
                write!(formatter, "failed to look for the configuration: {source}")
            }
            Self::Read(source) => {
                write!(formatter, "failed to read the configuration: {source}")
            }
        }
    }
}

impl<ResidencyError, GetError> Error for ConfigReadError<ResidencyError, GetError>
where
    ResidencyError: Error + 'static,
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Residency(source) => Some(source),
            Self::Read(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::id::ExclusiveId;
    use crate::inline::Inline;
    use crate::prelude::exists;
    use crate::repo::memoryrepo::MemoryRepo;

    fn signer(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn handle(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    /// One state with an explicit id, so a frame can hold concurrent states
    /// however they were minted.
    fn state(id: Id, collection: CollectionHandle, selected: bool, supersedes: &[Id]) -> TribleSet {
        entity! { ExclusiveId::force_ref(&id) @
            sync_collection: collection,
            sync_selected: selected,
            metadata::supersedes*: supersedes.iter().copied(),
        }
        .facts()
        .clone()
    }

    fn config(store: &mut MemoryRepo, key: &SigningKey) -> Collection<SimpleArchive> {
        store
            .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
            .unwrap()
    }

    fn read(store: &mut MemoryRepo, config: Collection<SimpleArchive>) -> TribleSet {
        let snapshot = store.snapshot().unwrap();
        config.read::<TribleSet, _>(&snapshot).unwrap()
    }

    /// Every state of `collection`'s register in `facts`, superseded or not.
    fn states(facts: &TribleSet, collection: CollectionHandle) -> BTreeSet<Id> {
        find!(
            state: Id,
            pattern!(facts, [{ ?state @ sync_collection: collection }])
        )
        .collect()
    }

    /// The handle `trible` and the faculties must both derive for one key.
    ///
    /// The name, the policy and the descriptor shape all enter it, so a change
    /// to any of them points every host at an empty configuration. The
    /// faculties pin the same value for the same key.
    #[test]
    fn config_handle_is_pinned() {
        let authority = signer(0x2A).verifying_key();
        assert_eq!(
            hex::encode_upper(config_handle(authority).raw),
            "127AF2EB0A3CD05103BEA7996297584A856B34533002F5B921303C0BDD01E9F7",
        );
    }

    /// A reader that derives the handle finds what a writer registered.
    #[test]
    fn config_handle_is_the_registered_collection() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        assert_eq!(
            config(&mut store, &key).handle(),
            config_handle(key.verifying_key())
        );
        assert_ne!(
            config_handle(signer(1).verifying_key()),
            config_handle(signer(2).verifying_key()),
            "one pile's configuration must not be another's"
        );
    }

    /// A pile nobody configured reads as an empty configuration, not as an
    /// error, and a configured one reads as what was written to it.
    #[test]
    fn an_unconfigured_pile_reads_as_empty() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let facts = config_facts(&store.snapshot().unwrap(), key.verifying_key()).unwrap();
        assert_eq!(sync_selection(&facts, handle(1)), Selection::Unset);

        let config = config(&mut store, &key);
        write_sync_selection(&mut store, config, &key, handle(1), true).unwrap();
        let snapshot = store.snapshot().unwrap();
        let facts = config_facts(&snapshot, key.verifying_key()).unwrap();
        assert_eq!(sync_selection(&facts, handle(1)), Selection::Selected);
        let facts = config_facts(&snapshot, signer(2).verifying_key()).unwrap();
        assert_eq!(
            sync_selection(&facts, handle(1)),
            Selection::Unset,
            "another pile's configuration is not this one's"
        );
    }

    #[test]
    fn an_unwritten_register_is_unset() {
        assert_eq!(
            sync_selection(&TribleSet::new(), handle(1)),
            Selection::Unset
        );

        let facts = state(genid().id, handle(1), true, &[]);
        assert_eq!(
            sync_selection(&facts, handle(2)),
            Selection::Unset,
            "one collection's register must not answer for another's"
        );
    }

    #[test]
    fn select_unselect_and_supersede() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let config = config(&mut store, &key);
        let synced = handle(1);
        let other = handle(2);

        write_sync_selection(&mut store, config, &key, synced, true).unwrap();
        write_sync_selection(&mut store, config, &key, other, true).unwrap();
        assert_eq!(
            sync_selection(&read(&mut store, config), synced),
            Selection::Selected
        );

        write_sync_selection(&mut store, config, &key, synced, false).unwrap();
        let facts = read(&mut store, config);
        assert_eq!(sync_selection(&facts, synced), Selection::Unselected);
        assert_eq!(
            sync_selection(&facts, other),
            Selection::Selected,
            "a write supersedes only its own collection's states"
        );
        assert_eq!(
            states(&facts, synced).len(),
            2,
            "the superseded selection stays readable"
        );

        write_sync_selection(&mut store, config, &key, other, false).unwrap();
        let facts = read(&mut store, config);
        assert_eq!(sync_selection(&facts, synced), Selection::Unselected);
        assert_eq!(sync_selection(&facts, other), Selection::Unselected);
    }

    /// Two programs selecting one collection at once agree; that is not a
    /// conflict.
    #[test]
    fn agreeing_concurrent_heads_give_their_value() {
        let synced = handle(1);
        let original = genid().id;
        for selected in [true, false] {
            let mut facts = state(original, synced, !selected, &[]);
            facts += state(genid().id, synced, selected, &[original]);
            facts += state(genid().id, synced, selected, &[original]);
            let expected = if selected {
                Selection::Selected
            } else {
                Selection::Unselected
            };
            assert_eq!(sync_selection(&facts, synced), expected);
        }
    }

    #[test]
    fn disagreeing_concurrent_heads_are_conflicted() {
        let synced = handle(1);
        let original = genid().id;
        let select = genid().id;
        let unselect = genid().id;
        let mut facts = state(original, synced, true, &[]);
        facts += state(select, synced, true, &[original]);
        facts += state(unselect, synced, false, &[original]);

        assert_eq!(
            sync_selection(&facts, synced),
            Selection::Conflicted(BTreeSet::from([select, unselect]))
        );
    }

    /// One write supersedes every head, whatever each says.
    #[test]
    fn a_write_settles_a_conflict() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let config = config(&mut store, &key);
        let synced = handle(1);
        for selected in [true, false] {
            store
                .commit(
                    config,
                    &key,
                    entity! { sync_collection: synced, sync_selected: selected },
                )
                .unwrap();
        }
        assert!(matches!(
            sync_selection(&read(&mut store, config), synced),
            Selection::Conflicted(heads) if heads.len() == 2
        ));

        write_sync_selection(&mut store, config, &key, synced, false).unwrap();
        assert_eq!(
            sync_selection(&read(&mut store, config), synced),
            Selection::Unselected
        );
    }

    /// Reverting to an earlier value is a new statement, not the old state
    /// again; otherwise the old state would supersede its own successor.
    #[test]
    fn reverting_mints_a_new_state() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let config = config(&mut store, &key);
        let synced = handle(1);

        write_sync_selection(&mut store, config, &key, synced, true).unwrap();
        let first = states(&read(&mut store, config), synced);
        write_sync_selection(&mut store, config, &key, synced, false).unwrap();
        write_sync_selection(&mut store, config, &key, synced, true).unwrap();

        let facts = read(&mut store, config);
        let all = states(&facts, synced);
        assert_eq!(all.len(), 3, "select, unselect and select are three states");
        assert_eq!(sync_selection(&facts, synced), Selection::Selected);

        let first = *first.iter().next().unwrap();
        let superseding_first: Vec<Id> = find!(
            later: Id,
            pattern!(&facts, [{ ?later @ metadata::supersedes: first }])
        )
        .collect();
        assert_eq!(superseding_first.len(), 1);
        assert!(
            !exists!(
                (earlier: Id),
                pattern!(&facts, [{ first @ metadata::supersedes: ?earlier }])
            ),
            "the first state supersedes nothing, so the history has no cycle"
        );
    }

    /// A write from a stale frame stands beside the head it never saw.
    ///
    /// The stale writer saw nothing, so it says exactly what the first state
    /// of the other history said. Merged, the two histories must still hold
    /// two heads that disagree, not one history that silently absorbed the
    /// stale write.
    #[test]
    fn a_stale_write_that_disagrees_is_a_conflict() {
        let key = signer(1);
        let synced = handle(1);

        let mut current = MemoryRepo::default();
        let current_config = config(&mut current, &key);
        write_sync_selection(&mut current, current_config, &key, synced, true).unwrap();
        write_sync_selection(&mut current, current_config, &key, synced, false).unwrap();
        let current = read(&mut current, current_config);

        let mut stale = MemoryRepo::default();
        let stale_config = config(&mut stale, &key);
        write_sync_selection(&mut stale, stale_config, &key, synced, true).unwrap();
        let stale = read(&mut stale, stale_config);

        let mut heads = states(&stale, synced);
        heads.extend(find!(
            state: Id,
            pattern!(&current, [{ ?state @ sync_selected: false }])
        ));
        let mut merged = current;
        merged += stale;
        assert_eq!(heads.len(), 2);
        assert_eq!(
            sync_selection(&merged, synced),
            Selection::Conflicted(heads)
        );
    }

    /// A head this reader cannot decode is not read, and the next write
    /// supersedes it all the same.
    #[test]
    fn an_undecodable_head_is_skipped_and_superseded() {
        let key = signer(1);
        let mut store = MemoryRepo::default();
        let config = config(&mut store, &key);
        let synced = handle(1);

        let undecodable = entity! {
            sync_collection: synced,
            sync_selected: Inline::<Boolean>::new([0x5A; 32]),
        };
        let undecodable_id = undecodable.root().unwrap();
        store.commit(config, &key, undecodable).unwrap();
        store
            .commit(
                config,
                &key,
                entity! { sync_collection: synced, sync_selected: true },
            )
            .unwrap();
        assert_eq!(
            sync_selection(&read(&mut store, config), synced),
            Selection::Selected,
            "the undecodable head is not a disagreeing one"
        );

        write_sync_selection(&mut store, config, &key, synced, false).unwrap();
        let facts = read(&mut store, config);
        assert_eq!(sync_selection(&facts, synced), Selection::Unselected);
        assert!(
            exists!(
                (later: Id),
                pattern!(&facts, [{ ?later @ metadata::supersedes: undecodable_id }])
            ),
            "the write supersedes the head it could not decode"
        );
    }

    /// Skipping a head this reader cannot decode does not bring back the
    /// state that head superseded.
    #[test]
    fn a_skipped_head_still_supersedes() {
        let synced = handle(1);
        let earlier = genid().id;
        let later = genid().id;
        let mut facts = state(earlier, synced, true, &[]);
        facts += entity! { ExclusiveId::force_ref(&later) @
            sync_collection: synced,
            sync_selected: Inline::<Boolean>::new([0x5A; 32]),
            metadata::supersedes: earlier,
        };
        assert_eq!(sync_selection(&facts, synced), Selection::Unset);
    }
}
