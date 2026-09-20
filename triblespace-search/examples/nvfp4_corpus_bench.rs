//! End-to-end NVFP4 benchmark over an extracted exact-embedding corpus.
//!
//! Input format: `NOM1 | count:u64-le | dimension:u32-le |
//! (handle:[u8;32] | vector:[f32;dimension]-le)*`.

use std::cell::Cell;
use std::error::Error;
use std::fs;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use mary::nn::nvfp4_cosine::CpuF64UpperScanner;
use triblespace_core::attribute::Attribute;
use triblespace_core::blob::{BlobEncoding, TryFromBlob};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, BlobStorePut};
use triblespace_core::trible::{Fragment, Trible, TribleSet};

use triblespace_search::nvfp4::{
    NvFp4CosineIndex, NvFp4CosineSet, NvFp4EmbeddingAttribute, SimilarityHit,
};
use triblespace_search::schemas::Embedding;

struct Corpus {
    handles: Vec<[u8; 32]>,
    vectors: Vec<Vec<f32>>,
    dimension: usize,
}

fn read_corpus(path: &str) -> Result<Corpus, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if bytes.get(..4) != Some(b"NOM1") {
        return Err("not an NOM1 corpus".into());
    }
    let count = u64::from_le_bytes(bytes[4..12].try_into()?) as usize;
    let dimension = u32::from_le_bytes(bytes[12..16].try_into()?) as usize;
    let row_len = 32usize
        .checked_add(dimension.checked_mul(4).ok_or("dimension overflow")?)
        .ok_or("row width overflow")?;
    if bytes.len() != 16 + count.checked_mul(row_len).ok_or("corpus size overflow")? {
        return Err("corpus length does not match its header".into());
    }
    let mut handles = Vec::with_capacity(count);
    let mut vectors = Vec::with_capacity(count);
    for row in bytes[16..].chunks_exact(row_len) {
        handles.push(row[..32].try_into()?);
        let mut vector = Vec::with_capacity(dimension);
        for value in row[32..].chunks_exact(4) {
            vector.push(f32::from_le_bytes(value.try_into()?));
        }
        vectors.push(vector);
    }
    Ok(Corpus {
        handles,
        vectors,
        dimension,
    })
}

fn direct_policy(authority: &SigningKey) -> CollectionPolicy {
    let root = authority.verifying_key();
    CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
}

struct Counting<'a, R> {
    inner: &'a R,
    gets: Cell<usize>,
}

impl<'a, R> Counting<'a, R> {
    fn new(inner: &'a R) -> Self {
        Self {
            inner,
            gets: Cell::new(0),
        }
    }

    fn gets(&self) -> usize {
        self.gets.get()
    }
}

impl<R: BlobStoreGet> BlobStoreGet for Counting<'_, R> {
    type GetError<E: Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.gets.set(self.gets.get() + 1);
        self.inner.get(handle)
    }
}

fn normalized(values: &[f32]) -> Vec<f64> {
    let norm = values
        .iter()
        .map(|&value| f64::from(value) * f64::from(value))
        .sum::<f64>()
        .sqrt();
    if norm == 0.0 {
        vec![0.0; values.len()]
    } else {
        values
            .iter()
            .map(|&value| f64::from(value) / norm)
            .collect()
    }
}

fn exact_top(
    corpus: &Corpus,
    normalized_corpus: &[Vec<f64>],
    query: &[f32],
    k: usize,
) -> Vec<([u8; 32], f64)> {
    let query = normalized(query);
    let mut scores: Vec<_> = normalized_corpus
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let score = query
                .iter()
                .zip(vector)
                .map(|(&left, &right)| left * right)
                .sum::<f64>()
                .clamp(-1.0, 1.0);
            (corpus.handles[index], score)
        })
        .collect();
    scores.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scores.truncate(k.min(scores.len()));
    scores
}

fn percentile(mut values: Vec<f64>, percentile: f64) -> f64 {
    values.sort_unstable_by(f64::total_cmp);
    let index = ((values.len() - 1) as f64 * percentile).round() as usize;
    values[index]
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: nvfp4_corpus_bench CORPUS [QUERIES]")?;
    let query_count = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(128usize);
    let corpus = read_corpus(&path)?;
    if corpus.vectors.is_empty() || query_count == 0 {
        return Err("corpus and query count must be nonzero".into());
    }
    let normalized_corpus: Vec<_> = corpus.vectors.iter().map(|v| normalized(v)).collect();

    let authority = SigningKey::from_bytes(&[113; 32]);
    let policy = direct_policy(&authority);
    let attribute = Attribute::<Handle<Embedding>>::named("nvfp4-corpus-embedding");
    let mut store = MemoryRepo::default();
    let mut facts = TribleSet::new();
    for (index, (&expected, vector)) in corpus.handles.iter().zip(&corpus.vectors).enumerate() {
        let handle = store.put::<Embedding, _>(vector.clone())?;
        if handle.raw != expected {
            return Err(format!("corpus handle mismatch at row {index}").into());
        }
        let mut raw_id = [0u8; 16];
        raw_id[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        raw_id[8..].copy_from_slice(&0x4e564650345f424du64.to_le_bytes());
        let entity = Id::new(raw_id).ok_or("generated a nil entity id")?;
        facts.insert(&Trible::force(&entity, &attribute.id(), &handle));
    }

    let source = store.collection("nvfp4-corpus-source", policy.clone())?;
    let target = store.derive::<NvFp4CosineSet<Embedding>>(
        source,
        NvFp4EmbeddingAttribute::new(attribute.id(), corpus.dimension)?,
        policy,
    )?;
    store.commit(source, &authority, Fragment::from(facts))?;

    let construction_start = Instant::now();
    let snapshot = block_on(store.maintain(target, &authority))?;
    let construction = construction_start.elapsed();
    let collection = snapshot.collection(target)?;
    let snapshot = collection.snapshot();
    let members = collection
        .cover()
        .members()
        .map(|handle| {
            snapshot.get::<triblespace_core::blob::Blob<NvFp4CosineSet<Embedding>>, _>(handle)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encoded_bytes = members
        .iter()
        .map(|blob| blob.bytes.len())
        .into_iter()
        .sum::<usize>();
    let physical_dimension = corpus.dimension.div_ceil(256) * 256;
    let blocks_per_row = physical_dimension / 16;
    let codes_per_row = physical_dimension / 2;
    let mut row_errors = Vec::new();
    let mut center_errors = Vec::new();
    for blob in &members {
        let bytes = blob.bytes.as_ref();
        let footer = bytes.len() - 16;
        let rows = u64::from_le_bytes(bytes[footer..footer + 8].try_into()?) as usize;
        let stage_width = 4 + blocks_per_row + codes_per_row;
        let error_start = rows * (32 + 2 * stage_width + 4);
        let norm_start = error_start - rows * 4;
        for (norm, error) in bytes[norm_start..error_start]
            .chunks_exact(4)
            .zip(bytes[error_start..error_start + rows * 4].chunks_exact(4))
        {
            let norm = f32::from_le_bytes(norm.try_into()?) as f64;
            let error = f32::from_le_bytes(error.try_into()?) as f64;
            row_errors.push(error);
            center_errors.push(if norm == 0.0 {
                error
            } else {
                error + (norm - 1.0).abs()
            });
        }
    }
    let attach_start = Instant::now();
    let index: NvFp4CosineIndex<Embedding> = collection.view()?;
    let attach = attach_start.elapsed();

    let mut latencies_us = Vec::with_capacity(query_count);
    let mut fetches = Vec::with_capacity(query_count);
    let mut cutoffs = Vec::with_capacity(query_count);
    let mut brute_us = Vec::with_capacity(query_count);
    let scanner = CpuF64UpperScanner;
    for query_index in 0..query_count {
        let row = query_index * corpus.vectors.len() / query_count;
        let query = &corpus.vectors[row];
        let counting = Counting::new(snapshot);
        let start = Instant::now();
        let actual = index.top_k(&counting, query, 10, &scanner)?;
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        fetches.push(counting.gets() as f64);
        let brute_start = Instant::now();
        let expected = exact_top(&corpus, &normalized_corpus, query, 10);
        brute_us.push(brute_start.elapsed().as_secs_f64() * 1_000_000.0);
        cutoffs.push(expected.last().map(|hit| hit.1).unwrap_or(-1.0));
        let actual: Vec<_> = actual
            .into_iter()
            .map(|SimilarityHit { embedding, score }| (embedding.raw, score))
            .collect();
        if actual != expected {
            return Err(format!("exact top-10 mismatch for corpus row {row}").into());
        }
    }

    let raw_bytes = corpus.vectors.len() * corpus.dimension * 4;
    println!(
        "vectors={} dimension={} queries={query_count}",
        corpus.vectors.len(),
        corpus.dimension
    );
    println!(
        "construct_ms={:.3} attach_us={:.3} members={}",
        construction.as_secs_f64() * 1_000.0,
        attach.as_secs_f64() * 1_000_000.0,
        index.segment_count(),
    );
    println!(
        "encoded_bytes={encoded_bytes} raw_bytes={raw_bytes} ratio={:.4}",
        encoded_bytes as f64 / raw_bytes as f64,
    );
    println!(
        "row_error_p50={:.6} row_error_p95={:.6} row_error_max={:.6}",
        percentile(row_errors.clone(), 0.50),
        percentile(row_errors.clone(), 0.95),
        row_errors.into_iter().fold(0.0, f64::max),
    );
    println!(
        "center_error_p50={:.6} center_error_p95={:.6} center_error_max={:.6}",
        percentile(center_errors.clone(), 0.50),
        percentile(center_errors.clone(), 0.95),
        center_errors.into_iter().fold(0.0, f64::max),
    );
    println!(
        "top10_cutoff_min={:.6} top10_cutoff_p50={:.6} top10_cutoff_max={:.6}",
        cutoffs.iter().copied().fold(1.0, f64::min),
        percentile(cutoffs.clone(), 0.50),
        cutoffs.into_iter().fold(-1.0, f64::max),
    );
    println!(
        "query_us_p50={:.3} query_us_p95={:.3} query_us_max={:.3}",
        percentile(latencies_us.clone(), 0.50),
        percentile(latencies_us.clone(), 0.95),
        latencies_us.into_iter().fold(0.0, f64::max),
    );
    println!(
        "brute_exact_us_p50={:.3} brute_exact_us_p95={:.3}",
        percentile(brute_us.clone(), 0.50),
        percentile(brute_us, 0.95),
    );
    println!(
        "exact_fetches_p50={:.0} exact_fetches_p95={:.0} exact_fetches_max={:.0}",
        percentile(fetches.clone(), 0.50),
        percentile(fetches.clone(), 0.95),
        fetches.into_iter().fold(0.0, f64::max),
    );
    Ok(())
}
