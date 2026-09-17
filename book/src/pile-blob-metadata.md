# Pile Blob Metadata

Every blob stored in a pile begins with a compact header. Besides the payload
hash (covered in [Pile Format](./pile-format.md)), the header records *when* the
blob was appended and *how long* the payload is. The `Pile` implementation
surfaces this information so tooling can answer questions such as "when did this
blob arrive?" without walking the raw bytes on disk.

## Header fields at a glance

The current 256-byte generic envelope written ahead of every blob contains:

| Field | Offset | Size | Purpose |
|---|---:|---:|---|
| Framing magic | `0..28` | 28 | Identifies the current forward-compatible framing. |
| Span | `28..32` | 4 | Total record size in 256-byte blocks, little-endian. |
| Blob record kind | `32..64` | 32 | Handle of the description of this layout. |
| Timestamp | `64..72` | 8 | Unix milliseconds when the payload was appended, little-endian. |
| Length | `72..80` | 8 | Exact payload bytes excluding padding, little-endian. |
| Reserved | `80..96` | 16 | Required zeros, aligning the hash to a 32-byte boundary. |
| Hash | `96..128` | 32 | Digest used to validate and address the payload. |
| Reserved | `128..256` | 128 | Required zeros. |

The pile snapshot also accepts the legacy envelope and legacy V1/V3 blob headers, and
projects their timestamp, length, and hash through the same API.

[`BlobMetadata`][blobmetadata] re-exposes the timestamp and length fields so
callers can read when a blob was appended and how large the payload is.

## `BlobMetadata`

[`BlobMetadata`][blobmetadata] is a lightweight struct shared by blob-store
implementations. It mirrors the timestamp/length pair in the header and leaves
validation to the snapshot:

- `timestamp`: the write time stored in the blob header as a `u64`. A convenient
  way to turn this into a `SystemTime` is shown below. `Pile::put` records this
  value using `SystemTime::now()`, so it reflects wall-clock time and can move
  forward or backward if the system clock is adjusted.
- `length`: the size of the blob payload in bytes. Padding that aligns current
  entries to 256-byte boundaries is excluded from this value, so it matches the slice
  returned by [`PileSnapshot::get`][get].

[blobmetadata]: ../../src/repo.rs
[get]: ../../src/repo/pile.rs

## Looking up blob metadata

`PileSnapshot::metadata` accepts the same `Inline<Handle<_, _>>` that other blob
store APIs use. The snapshot consults its persistent in-memory index and, on the first
request for a handle, lazily hashes the payload to confirm the bytes match the
handle. Subsequent metadata lookups for the same handle reuse that cached
validation result. When the payload passes validation the method returns
`Some(BlobMetadata)`; otherwise it yields `None`.

`PileSnapshot` is the immutable prefix frozen by [`Pile::snapshot`][snapshot].
Request another snapshot to refresh the pile and observe blobs appended
afterwards. `PileSnapshot::metadata` never fails for valid snapshots—its error
type is [`Infallible`](core::convert::Infallible).

[snapshot]: ../../src/repo/pile.rs

```rust,ignore
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anybytes::Bytes;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStoreMeta, BlobStorePut, SnapshotSource, StorageClose};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pile = Pile::open("/tmp/example.pile")?;

    let blob = Blob::<UnknownBlob>::new(Bytes::from_source(b"hello world".to_vec()));
    let handle = pile.put(blob)?;

    let snapshot = pile.snapshot()?;
    if let Some(meta) = snapshot.metadata(handle).unwrap() {
        let appended_at = UNIX_EPOCH + Duration::from_millis(meta.timestamp);
        println!(
            "Blob length: {} bytes, appended at {:?}",
            meta.length, appended_at
        );
    }

    drop(snapshot);
    pile.close()?;
    Ok(())
}
```

## Failure cases

`metadata` returns `None` in a few situations:

- the handle does not correspond to any blob stored in the pile;
- the snapshot predates the blob (create a new snapshot to refresh and see
  later writes);
- validation previously failed because the on-disk bytes did not match the
  recorded hash, for example after the pile file was corrupted before this
  process opened it.

When `None` is returned, callers can treat it the same way they would handle a
missing blob from `get`: the data is considered absent from the snapshot they
are reading. Validation is cached in the content-keyed representative's
persistent PATCH leaf, which immutable snapshots share. A unique representative
is validated on demand; duplicate replay may already have validated it. A future
snapshot can recover when replay replaces an invalid representative with a
valid occurrence of the same handle. Metadata then comes from that first valid
occurrence. Older snapshots retain the original representative and verdict.

For additional background on the binary layout and how the header interacts
with padding, see the [Pile Format](./pile-format.md) chapter.
