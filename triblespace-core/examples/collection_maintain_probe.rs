//! Steady-state maintenance probe for the faculties fact chain shape.
//!
//! Usage:
//!   collection_maintain_probe build PILE N
//!   collection_maintain_probe steady PILE REPS
//!
//! `build` creates a fresh pile holding one root `SimpleArchive` collection
//! with N signed COMMITs, derives the SuccinctArchive and Rank9 hops the
//! faculties fact chain uses, and maintains both to convergence. `steady`
//! reopens that converged pile and runs the no-op maintain of both hops REPS
//! times, reporting wall and CPU seconds. Nothing is published in `steady`.

use std::path::Path;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::id::Id;
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::pile::Pile;

fn policy(key: &SigningKey) -> CollectionPolicy {
    let authority = key.verifying_key();
    CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    )
}

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn cpu_seconds() -> f64 {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(ok, 0, "getrusage");
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1e6;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1e6;
    user + system
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("steady");
    let path = args.get(2).expect("pile path");
    let count: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1);

    let key = SigningKey::from_bytes(&[7; 32]);
    if !Path::new(path).exists() {
        std::fs::File::create(path).expect("create pile");
    }
    let mut pile = Pile::open(Path::new(path)).expect("open pile");
    pile.refresh().expect("refresh pile");
    let source = pile
        .collection("probe-facts", policy(&key))
        .expect("root collection");
    let succinct = pile
        .derive::<SuccinctArchiveBlob>(source, (), policy(&key))
        .expect("succinct hop");
    let rank9 = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy(&key))
        .expect("rank9 hop");

    match mode {
        "build" => {
            for index in 0..count {
                let fragment = entity! {
                    metadata::tag: &id(9),
                    metadata::name: format!("probe fact {index}"),
                };
                pile.commit(source, &key, fragment).expect("commit");
            }
            futures::executor::block_on(async {
                drop(pile.ensure(source, &key).await.expect("ensure source"));
                drop(pile.maintain(succinct, &key).await.expect("maintain succinct"));
                drop(pile.maintain(rank9, &key).await.expect("maintain rank9"));
                // Second pass so the recorded pile is already at the fixed point.
                drop(pile.maintain(succinct, &key).await.expect("maintain succinct"));
                drop(pile.maintain(rank9, &key).await.expect("maintain rank9"));
            });
            pile.flush().expect("flush");
            println!("built records={count}");
        }
        "steady" => {
            for rep in 0..count {
                let wall = Instant::now();
                let cpu = cpu_seconds();
                futures::executor::block_on(async {
                    drop(pile.maintain(succinct, &key).await.expect("maintain succinct"));
                    drop(pile.maintain(rank9, &key).await.expect("maintain rank9"));
                });
                println!(
                    "rep={rep} wall_s={:.3} cpu_s={:.3}",
                    wall.elapsed().as_secs_f64(),
                    cpu_seconds() - cpu,
                );
            }
        }
        other => panic!("unknown mode {other}"),
    }
}
