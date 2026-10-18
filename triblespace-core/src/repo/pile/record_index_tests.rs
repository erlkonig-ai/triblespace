// Included in pile::tests: fixture scratch is local to each operation.

#[test]
fn collection_prefix_native_frames_match_canonical_bytes_and_old_kinds_stay_opaque() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_empty_pile_path(&dir, "old-prefix-layout.pile");
    let destination_path = fresh_empty_pile_path(&dir, "retained-prefix-layout.pile");
    let signer = SigningKey::from_bytes(&[43; 32]);
    let collection = Inline::new([7; 32]);
    let produced = Inline::new([9; 32]);
    let records = [
        (
            CollectionRecord::Derive(CollectionDerive::sign(
                &signer,
                collection,
                SourceLocator::of([8; 32]),
                produced,
            )),
            record_kind::KIND_COLLECTION_DERIVE_V11,
        ),
        (
            CollectionRecord::Map(crate::collection::CollectionMap::sign(
                &signer,
                collection,
                Inline::new([8; 32]),
                produced,
            )),
            record_kind::KIND_COLLECTION_MAP_V1,
        ),
    ];
    let mut old_frames = Vec::new();
    for (record, old_kind) in records {
        let frame = collection_record_header(&record);
        assert_eq!(&frame[32..], record.to_bytes().as_slice());
        assert_eq!(&frame[64..96], &collection.raw);
        assert_eq!(&frame[96..128], &produced.raw);
        assert!(matches!(decode_record(&frame, 0).unwrap().content,
            PileRecordContent::Collection { record: decoded } if decoded == record));
        let mut old = frame;
        old[32..64].copy_from_slice(&old_kind);
        for n in 0..32 {
            old.swap(96 + n, 128 + n);
        }
        assert!(matches!(
            decode_record(&old, 0).unwrap().content,
            PileRecordContent::Opaque { .. }
        ));
        append_test_bytes(&path, &old);
        old_frames.push(old);
    }
    let mut source = PileFile::open(&path).unwrap();
    let snapshot = source.snapshot().unwrap();
    assert_eq!(source.opaque_record_count().unwrap(), 2);
    assert_eq!(snapshot.records().unwrap().count(), 0);
    let mut destination = PileFile::open(&destination_path).unwrap();
    let stats = source
        .rewrite_retained_into(
            &mut destination,
            &crate::repo::RetentionRoots::default(),
            WantRewritePolicy::Drop,
        )
        .unwrap();
    assert_eq!(stats.opaque_frames, 2);
    let output = std::fs::read(&destination_path).unwrap();
    for old in old_frames {
        assert!(output.chunks_exact(256).any(|frame| frame == old));
    }
    assert_eq!(
        destination.snapshot().unwrap().records().unwrap().count(),
        0
    );
    source.close().unwrap();
    destination.close().unwrap();
}

#[test]
fn collection_prefix_reorder_does_not_change_retired_v9_header() {
    let equation = RetiredCollectionEquation::sign_derive_v9(
        &SigningKey::from_bytes(&[44; 32]),
        Inline::new([7; 32]),
        Inline::new([8; 32]),
        Inline::new([9; 32]),
    );
    let frame = retired_equation_frame(&equation);
    assert_eq!(&frame[96..128], &[8; 32]);
    assert_eq!(&frame[128..160], &[9; 32]);
    assert!(matches!(decode_record(&frame, 0).unwrap().content,
        PileRecordContent::RetiredCollectionEquation { equation: decoded } if decoded == equation));
    equation.verify_strict().unwrap();
}

#[test]
fn native_fixed_index_matches_raw_oracle_and_selected_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_empty_pile_path(&dir, "native-fixed-oracle.pile");
    let mut records = collection_test_records();
    let collection = records[0].collection();
    let member = collection_record_output(&records[0]);
    let key = SigningKey::from_bytes(&[19; 32]);
    records.push(CollectionRecord::Commit(CollectionCommit::sign(
        &key,
        collection,
        member,
        empty_metadata_handle(),
    )));
    records.push(CollectionRecord::Commit(CollectionCommit::sign(
        &key,
        collection,
        member,
        Inline::new([77; 32]),
    )));
    records.push(CollectionRecord::Map(
        crate::collection::CollectionMap::sign(&key, collection, collection_test_hash(91), member),
    ));
    records.push(CollectionRecord::Derive(CollectionDerive::sign(
        &key,
        collection,
        SourceLocator::of([93; 32]),
        member,
    )));
    let mut pile = PileFile::open(&path).unwrap();
    for record in records.iter().rev() {
        pile.insert(*record).unwrap();
    }
    let before = pile.snapshot().unwrap();
    for record in &records {
        append_test_bytes(&path, &collection_record_header(record));
    }
    let after = pile.snapshot().unwrap();
    // The old occurrence reader's semantic oracle, without retaining its
    // physical catalogue alongside the candidate.
    let oracle: BTreeSet<_> = PileRecords::open(&path)
        .unwrap()
        .filter_map(|r| match r.unwrap().content {
            PileRecordContent::Collection { record } => Some(record),
            _ => None,
        })
        .collect();
    let all = after
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(all.iter().copied().collect::<BTreeSet<_>>(), oracle);
    assert_eq!(all.len(), oracle.len());
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        all
    );
    assert_eq!(after.collection_records.occurrences.len(), 2);
    assert_eq!(after.collection_records.len(), oracle.len() as u64 + 1);
    assert_eq!(
        after.collection_occurrences().unwrap().len(),
        2 * records.len()
    );
    let expected_collections: BTreeSet<_> = oracle.iter().map(|r| r.collection()).collect();
    assert_eq!(
        after.collections().unwrap(),
        expected_collections.into_iter().collect::<Vec<_>>()
    );
    let routes = [
        CollectionRecordSelector::Collection(collection),
        CollectionRecordSelector::ProducedMember(collection, member),
        CollectionRecordSelector::CommitMember(collection, member),
        CollectionRecordSelector::DeriveTarget(collection),
        CollectionRecordSelector::Foundations(collection),
        CollectionRecordSelector::MergeCollection(collection),
    ];
    for bits in 0_u32..(1 << routes.len()) {
        let selectors: BTreeSet<_> = routes
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (bits & (1 << i) != 0).then_some(*s))
            .collect();
        let expected: Vec<_> = all
            .iter()
            .copied()
            .filter(|r| selectors_match_record(&selectors, *r))
            .collect();
        assert_eq!(after.select_records(&selectors).unwrap(), expected);
        assert_eq!(
            after.select_record_changes(&before, &selectors).unwrap(),
            (vec![], vec![])
        );
    }
    let iterator = after.records().unwrap();
    drop(after);
    drop(before);
    pile.close().unwrap();
    assert_eq!(
        iterator.collect::<Result<Vec<_>, _>>().unwrap(),
        all,
        "iterator owns all backing maps"
    );
}

#[test]
fn native_fixed_index_preserves_opaque_old_frames_without_promoting_assertions() {
    let dir = tempfile::tempdir().unwrap();
    let CollectionRecord::Commit(commit) = collection_test_records()[0] else {
        unreachable!()
    };
    let canonical = commit.to_bytes();
    let mut v4 = vec![0_u8; 256];
    v4[..16].copy_from_slice(&MAGIC_MARKER_COLLECTION_COMMIT_V4);
    // Historical framing carries six fields, not the new complete assertion.
    // Those opaque bytes must never acquire the current kind or signature meaning.
    v4[16..208].copy_from_slice(&canonical[32..]);
    let mut v1 = test_envelope_v1_bytes(MAGIC_MARKER_COLLECTION_COMMIT_V4, 1, 256);
    v1[36..228].copy_from_slice(&canonical[32..]);
    v1[228..].fill(0);
    for (n, frame) in [v4, v1].into_iter().enumerate() {
        let source = fresh_empty_pile_path(&dir, &format!("legacy-{n}.pile"));
        let destination = fresh_empty_pile_path(&dir, &format!("current-{n}.pile"));
        append_test_bytes(&source, &frame);
        let mut retained = PileFile::open(&source).unwrap();
        retained.refresh().unwrap();
        assert_eq!(retained.applied_length, 256);
        assert!(retained.collection_records.is_empty());
        assert_eq!(retained.opaque_record_count().unwrap(), 1);
        retained.amputate().unwrap();
        assert!(!retained.amputate_at(0).unwrap());
        assert_eq!(std::fs::read(&source).unwrap(), frame);
        let raw = PileRecords::open(&source).unwrap().next().unwrap().unwrap();
        assert!(matches!(raw.content, PileRecordContent::Opaque { .. }));

        // Reframing cannot relabel an old signature as a current assertion.
        // Its preflight refuses before writing any destination bytes.
        let mut output = PileFile::open(&destination).unwrap();
        assert!(matches!(
            reframe_into(&source, &mut output),
            Err(PileReframeError::OpaqueRecord { offset: 0, .. })
        ));
        assert!(std::fs::read(&destination).unwrap().is_empty());
        let stats = retained
            .rewrite_retained_into(
                &mut output,
                &crate::repo::RetentionRoots::default(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.opaque_frames, 1);
        let snapshot = output.snapshot().unwrap();
        assert_eq!(snapshot.records().unwrap().count(), 0);
        assert_eq!(snapshot.opaque_record_count(), 1);
        let output_bytes = std::fs::read(&destination).unwrap();
        assert_eq!(output_bytes, frame);
        assert_eq!(std::fs::read(&source).unwrap(), frame);
        drop(snapshot);
        output.close().unwrap();
        retained.close().unwrap();
    }
}

#[test]
fn native_fixed_index_reuses_map_owner_and_duplicate_remap_does_not_adopt_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_empty_pile_path(&dir, "owner-reuse.pile");
    let mut pile = PileFile::open(&path).unwrap();
    let record = collection_test_records()[0];
    pile.insert(record).unwrap();
    let first = pile.snapshot().unwrap();
    let old_owner = Arc::downgrade(&first.mmap);
    let initial_address = Arc::as_ptr(&first.mmap);
    // Holding a snapshot doesn't cause remapping below capacity.
    pile.insert(collection_test_records()[2]).unwrap();
    assert_eq!(Arc::as_ptr(&pile.mmap), initial_address);
    let fixed_only = first.collection_records.clone();
    pile.ensure_mapped(pile.mmap.len() + 1).unwrap();
    let unused_owner = Arc::downgrade(&pile.mmap);
    assert!(!std::ptr::eq(Arc::as_ptr(&pile.mmap), initial_address));
    append_test_bytes(&path, &collection_record_header(&record));
    let latest = pile.snapshot().unwrap();
    let latest_roots = latest.collection_records.clone();
    drop(first);
    drop(latest);
    pile.close().unwrap();
    assert!(
        unused_owner.upgrade().is_none(),
        "duplicate-only map is not adopted by any root"
    );
    assert!(old_owner.upgrade().is_some());
    assert_eq!(
        fixed_only.clone().into_fixed().collect::<Vec<_>>(),
        vec![record]
    );
    drop(fixed_only);
    assert!(old_owner.upgrade().is_some());
    drop(latest_roots);
    assert!(
        old_owner.upgrade().is_none(),
        "last root releases the full mapping"
    );
}

/// Explicit read-only physical framing census. No normal replay, signature
/// checks, blob/fixed-record hashes, writer locks, source writes or retained
/// record catalogue. The canonical decoder still computes AUTH proof IDs.
#[test]
#[ignore = "requires explicit NATIVE_RECORD_CENSUS_PATH; read-only diagnostic"]
fn native_fixed_record_physical_census() {
    use std::os::unix::fs::MetadataExt;
    let path = std::env::var_os("NATIVE_RECORD_CENSUS_PATH")
        .expect("explicit NATIVE_RECORD_CENSUS_PATH required");
    let before = std::fs::metadata(&path).unwrap();
    let mut records = PileRecords::open(Path::new(&path)).unwrap();
    let frozen = records.bytes().len();
    let after_open = std::fs::metadata(&path).unwrap();
    assert_eq!(
        (before.dev(), before.ino()),
        (after_open.dev(), after_open.ino())
    );
    println!(
        "native-census device={} inode={} observed_len={} frozen_prefix={}",
        before.dev(),
        before.ino(),
        before.len(),
        frozen
    );
    let mut counts = [0_u64; 3]; // canonical COMMIT/DERIVE/MAP at frame offset +32
    let mut examples: [Vec<usize>; 3] = std::array::from_fn(|_| Vec::new());
    let mut physical = 0_u64;
    let mut opaque = 0_u64;
    let mut end = 0;
    let mut failure = None;
    while let Some(next) = records.next() {
        let decoded = match next {
            Ok(decoded) => decoded,
            Err(error) => {
                failure = Some(format!("{error}"));
                break;
            }
        };
        physical += 1;
        end = decoded.offset + decoded.len;
        let kind = match decoded.content {
            PileRecordContent::Collection {
                record: CollectionRecord::Commit(_),
            } => 0,
            PileRecordContent::Collection {
                record: CollectionRecord::Derive(_),
            } => 1,
            PileRecordContent::Collection {
                record: CollectionRecord::Map(_),
            } => 2,
            PileRecordContent::Opaque { .. } => {
                opaque += 1;
                continue;
            }
            _ => continue,
        };
        // Classification only after canonical decoding accepted the frame.
        let frame = &records.bytes()[decoded.offset..end];
        if !frame.starts_with(&FRAME_MAGIC) {
            failure = Some(format!("unclassified fixed framing at {}", decoded.offset));
            break;
        }
        counts[kind] += 1;
        if examples[kind].len() < 4 {
            examples[kind].push(decoded.offset);
        }
    }
    for (kind, name) in ["COMMIT", "DERIVE", "MAP"].into_iter().enumerate() {
        println!(
            "native-census kind={name} canonical_offset=32 count={} examples={:?}",
            counts[kind], examples[kind]
        );
    }
    let final_stat = std::fs::metadata(&path).unwrap();
    let same_file = (before.dev(), before.ino()) == (final_stat.dev(), final_stat.ino());
    let traversal_complete =
        failure.is_none() && end == frozen && same_file && final_stat.len() >= frozen as u64;
    let classification_complete = traversal_complete && opaque == 0;
    println!("native-census physical={physical} opaque={opaque} decoded_end={end} frozen_prefix={frozen} final_len={} same_inode={same_file} traversal_complete={traversal_complete} classification_complete={classification_complete} error={failure:?}", final_stat.len());
    assert!(
        classification_complete,
        "partial or opaque scan cannot certify absence"
    );
}

#[test]
fn native_fixed_census_requires_complete_known_classification() {
    let dir = tempfile::tempdir().unwrap();
    let record = collection_test_records()[0];
    let CollectionRecord::Commit(commit) = record else {
        unreachable!()
    };
    let bytes = collection_record_header(&record);
    let mut old_v4 = vec![0; 256];
    old_v4[..16].copy_from_slice(&MAGIC_MARKER_COLLECTION_COMMIT_V4);
    old_v4[16..208].copy_from_slice(&commit.to_bytes()[32..]);
    let mut old_v1 = test_envelope_v1_bytes(MAGIC_MARKER_COLLECTION_COMMIT_V4, 1, 256);
    old_v1[36..228].copy_from_slice(&commit.to_bytes()[32..]);
    old_v1[228..].fill(0);
    for case in ["complete", "legacy-v4", "legacy-v1", "opaque", "torn"] {
        let path = fresh_empty_pile_path(&dir, &format!("census-{case}.pile"));
        append_test_bytes(&path, &bytes);
        match case {
            "legacy-v4" => append_test_bytes(&path, &old_v4),
            "legacy-v1" => append_test_bytes(&path, &old_v1),
            "opaque" => append_test_bytes(&path, &test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, 256)),
            "torn" => append_test_bytes(&path, &FRAME_MAGIC[..8]),
            _ => {}
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "repo::pile::tests::native_fixed_record_physical_census",
                "--ignored",
                "--nocapture",
            ])
            .env("NATIVE_RECORD_CENSUS_PATH", &path)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("kind=COMMIT canonical_offset=32 count=1"),
            "{stdout}"
        );
        assert_eq!(output.status.success(), case == "complete", "{stdout}");
        assert!(
            stdout.contains(if case == "torn" {
                "traversal_complete=false"
            } else {
                "traversal_complete=true"
            }),
            "{stdout}"
        );
        assert!(
            stdout.contains(if case == "complete" {
                "classification_complete=true"
            } else {
                "classification_complete=false"
            }),
            "{stdout}"
        );
    }
}

#[test]
fn native_fixed_many_small_appends_retain_mapping_generations_not_append_owners() {
    for keep_old in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "append-generations.pile");
        let mut pile = PileFile::open(&path).unwrap();
        let mut generations = vec![Arc::downgrade(&pile.mmap)];
        let mut old_snapshots = Vec::new();
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        for batch in 0..320_u64 {
            for item in 0..128_u64 {
                let mut member = [0; 32];
                member[..8].copy_from_slice(&(batch * 128 + item).to_le_bytes());
                // Structural fixture at the trusted local-reader boundary;
                // no cryptographic validity claim or signing in this test.
                let record = CollectionRecord::Commit(CollectionCommit::from_parts(
                    Inline::new([1; 32]),
                    Inline::new(member),
                    Inline::new([2; 32]),
                    Inline::new([3; 32]),
                    Inline::new([4; 32]),
                    Inline::new([5; 32]),
                ));
                writer
                    .write_all(&collection_record_header(&record))
                    .unwrap();
            }
            let snapshot = pile.snapshot().unwrap();
            if generations.last().unwrap().as_ptr() != Arc::as_ptr(&pile.mmap) {
                generations.push(Arc::downgrade(&pile.mmap));
            }
            assert_eq!(snapshot.collection_records.len(), (batch + 1) * 128);
            if keep_old {
                old_snapshots.push(snapshot);
            }
        }
        drop(writer);
        let latest = pile.snapshot().unwrap();
        let roots = latest.collection_records.clone();
        let empty = roots.difference(&roots);
        assert!(empty.is_empty());
        assert!(empty.collections().is_empty());
        assert!(empty.clone().into_fixed().next().is_none());
        assert_eq!(
            generations.len(),
            3,
            "4/8/16 MiB maps, not 320 append owners"
        );
        for (i, snapshot) in old_snapshots.iter().enumerate() {
            assert_eq!(snapshot.collection_records.len(), (i as u64 + 1) * 128);
        }
        pile.close().unwrap();
        let alive = || {
            generations
                .iter()
                .filter(|weak| weak.upgrade().is_some())
                .count()
        };
        assert_eq!(
            alive(),
            3,
            "latest native root alone conservatively owns all three maps"
        );
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let suffix = path.to_str().unwrap();
        let (mut matching, mut maps, mut size_kib, mut rss_kib) = (false, 0, 0_u64, 0_u64);
        for line in smaps.lines() {
            if line
                .split_whitespace()
                .next()
                .is_some_and(|word| word.contains('-'))
            {
                matching = line.ends_with(suffix);
                maps += usize::from(matching);
            } else if matching && (line.starts_with("Size:") || line.starts_with("Rss:")) {
                let value: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
                if line.starts_with("Size:") {
                    size_kib += value;
                } else {
                    rss_kib += value;
                }
            }
        }
        println!("native-owners keep_old={keep_old} appends=320 records=40960 generations={} maps={maps} virtual_kib={size_kib} summed_mapping_rss_kib={rss_kib}", generations.len());
        assert_eq!(maps, 3);
        assert_eq!(size_kib, 28 * 1024);
        drop(latest);
        drop(old_snapshots);
        assert_eq!(
            alive(),
            3,
            "root cover, not snapshot history, retains old allocations"
        );
        assert_eq!(roots.clone().into_fixed().count(), 40960);
        drop(roots);
        assert_eq!(
            alive(),
            0,
            "empty difference does not keep source owner cover"
        );
        drop(empty);
    }
}

#[test]
fn native_fixed_merge_delta_never_scans_prior_same_output_witnesses() {
    use crate::collection::covered::RecordDelta;
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_empty_pile_path(&dir, "merge-delta-history.pile");
    let mut pile =
        Pile::open_as(&path, SigningKey::from_bytes(&[0xAA; 32]).verifying_key()).unwrap();
    let collection = register_simplearchive_collection(&mut pile, "merge delta").handle();
    let key = SigningKey::from_bytes(&[0xAA; 32]);
    let output = collection_test_hash(200);
    for input in 0..128_u8 {
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            collection,
            collection_test_hash(input),
            empty_metadata_handle(),
        )))
        .unwrap();
    }
    let witness = |n: u8| {
        // Each half has 32 overlapping eight-member windows over 64 committed
        // inputs. The second half adds a disjoint set of 64 covered members.
        let inputs =
            (0..8).map(|offset| collection_test_hash((n / 32) * 64 + ((n % 32) * 2 + offset) % 64));
        CollectionRecord::Merge(CollectionMerge::sign(&key, collection, inputs, output).unwrap())
    };
    for n in 0..32 {
        pile.insert(witness(n)).unwrap();
    }
    let before = pile.snapshot().unwrap();
    assert_eq!(before.coverage().of(collection, output).unwrap().len(), 64);
    for n in 32..64 {
        pile.insert(witness(n)).unwrap();
    }
    // A repeated historical physical frame must not trigger an old-body scan.
    append_test_bytes(&path, &collection_record_header(&witness(0)));
    let after = pile.snapshot().unwrap();
    COLLECTION_RECORD_READS.with(|reads| reads.set(0));
    let mut offered = Vec::new();
    after.for_each_record_since(Some(&before), &mut |record| offered.push(*record));
    assert_eq!(offered.len(), 33);
    assert_eq!(
        COLLECTION_RECORD_READS.with(|reads| reads.get()),
        33,
        "only 33 fresh frames decoded, zero old witnesses"
    );
    assert_eq!(after.coverage().of(collection, output).unwrap().len(), 128);
    assert_eq!(before.coverage().of(collection, output).unwrap().len(), 64);
    let selectors = BTreeSet::from([CollectionRecordSelector::MergeCollection(collection)]);
    let (added, removed) = after.select_record_changes(&before, &selectors).unwrap();
    assert_eq!(added.len(), 32);
    assert!(removed.is_empty());
    // Independent mapping/origin: semantic MERGE comparison reads each prior
    // witness once per member, not once for each new witness.
    let mut reopened = Pile::open_as(&path, key.verifying_key()).unwrap();
    let independent = reopened.snapshot().unwrap();
    COLLECTION_RECORD_READS.with(|reads| reads.set(0));
    let mut offered = Vec::new();
    independent.for_each_record_since(Some(&before), &mut |record| offered.push(*record));
    assert_eq!(offered.len(), 32);
    assert_eq!(COLLECTION_RECORD_READS.with(|reads| reads.get()), 65 + 32);
    reopened.close().unwrap();
    pile.close().unwrap();
}

#[test]
fn native_fixed_opaque_after_accepted_prefix_preserves_both_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = fresh_empty_pile_path(&dir, "prefix-refusal.pile");
    let record = collection_test_records()[0];
    let CollectionRecord::Commit(commit) = record else {
        unreachable!()
    };
    let mut bytes = collection_record_header(&record);
    let mut old = [0; 256];
    old[..16].copy_from_slice(&MAGIC_MARKER_COLLECTION_COMMIT_V4);
    old[16..208].copy_from_slice(&commit.to_bytes()[32..]);
    bytes.extend_from_slice(&old);
    append_test_bytes(&path, &bytes);
    let mut pile = PileFile::open(&path).unwrap();
    pile.refresh().unwrap();
    assert_eq!(pile.applied_length, 512);
    assert_eq!(pile.collection_records.len(), 1);
    assert_eq!(pile.opaque_record_count().unwrap(), 1);
    assert_eq!(
        pile.snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![record]
    );
    pile.amputate().unwrap();
    assert!(!pile.amputate_at(256).unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    pile.close().unwrap();
}

#[test]
fn native_fixed_cross_owner_mixed_deltas_and_invalidation_match_set_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let a = fresh_empty_pile_path(&dir, "cross-owner-a.pile");
    let b = fresh_empty_pile_path(&dir, "cross-owner-b.pile");
    let key = SigningKey::from_bytes(&[17; 32]);
    let mut old = collection_test_records();
    let c = old[0].collection();
    old.push(CollectionRecord::Map(
        crate::collection::CollectionMap::sign(
            &key,
            c,
            collection_test_hash(9),
            collection_test_hash(10),
        ),
    ));
    let mut new = vec![old[0], old[2], old[3]]; // remove one MERGE
    new.push(CollectionRecord::Commit(CollectionCommit::sign(
        &key,
        c,
        collection_test_hash(6),
        empty_metadata_handle(),
    )));
    new.push(CollectionRecord::Derive(CollectionDerive::sign(
        &key,
        c,
        SourceLocator::of([23; 32]),
        collection_test_hash(6),
    )));
    new.push(CollectionRecord::Map(
        crate::collection::CollectionMap::sign(
            &key,
            c,
            collection_test_hash(11),
            collection_test_hash(10),
        ),
    ));
    new.push(CollectionRecord::Merge(
        CollectionMerge::sign(
            &key,
            c,
            [6, 7, 8, 9, 10, 11, 13, 14].map(collection_test_hash),
            collection_test_hash(12),
        )
        .unwrap(),
    ));
    for record in old.iter().chain(old.iter()) {
        append_test_bytes(&a, &collection_record_header(record));
    }
    for record in new.iter().rev() {
        append_test_bytes(&b, &collection_record_header(record));
    }
    let mut first = PileFile::open(&a).unwrap();
    let mut second = PileFile::open(&b).unwrap();
    let before = first.snapshot().unwrap();
    let after = second.snapshot().unwrap();
    assert!(!Arc::ptr_eq(&before.record_origin, &after.record_origin));
    let old_set: BTreeSet<_> = old.into_iter().collect();
    let new_set: BTreeSet<_> = new.into_iter().collect();
    for selector in [
        CollectionRecordSelector::Collection(c),
        CollectionRecordSelector::CommitMember(c, collection_test_hash(6)),
        CollectionRecordSelector::ProducedMember(c, collection_test_hash(10)),
        CollectionRecordSelector::DeriveTarget(c),
        CollectionRecordSelector::Foundations(c),
        CollectionRecordSelector::MergeCollection(c),
    ] {
        let selectors = BTreeSet::from([selector]);
        let expected_added: Vec<_> = new_set
            .difference(&old_set)
            .copied()
            .filter(|r| selectors_match_record(&selectors, *r))
            .collect();
        let expected_removed: Vec<_> = old_set
            .difference(&new_set)
            .copied()
            .filter(|r| selectors_match_record(&selectors, *r))
            .collect();
        assert_eq!(
            after.select_record_changes(&before, &selectors).unwrap(),
            (expected_added, expected_removed)
        );
        assert!(after
            .changes_for(
                &before,
                &StoreDependencies {
                    records: selectors,
                    ..StoreDependencies::default()
                }
            )
            .contains(StoreChanges::COLLECTION_RECORDS));
    }
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap(),
        old_set
    );
    first.close().unwrap();
    second.close().unwrap();
    assert_eq!(
        after
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap(),
        new_set
    );
}
