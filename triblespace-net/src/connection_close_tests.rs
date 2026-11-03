/// A real accept loop queues its close, then the walk task opens work on
/// the replacement before consuming that close. Both dials authenticate as
/// the same peer; their recon sequence numbers make the replacement win.
async fn queued_old_connection_close(incoming: bool) {
    use crate::connection::{DRAIN_GRACE, write_frame};
    use crate::protocol::{PILE_SYNC_ALPN, TAG_RECON, send_u8};

    let net = SimNet::new(0x3A71, SimConfig::default());
    let mut node = Node::new(119);
    let collection = node.hold("queued connection close", open());
    node.commit(collection, 1);
    node.observe();
    let remote = Node::new(120);
    let peer = remote.id();
    let mut harness = net.join(&node.key);
    let remote = net.join(&remote.key);
    let local = harness.transport.local_id();
    let table = ConnectionTable::new(harness.transport, NoRequests);
    let (commands, mut commanded) = mpsc::unbounded_channel();
    let commands = WalksHandle(commands);
    table.walks(commands.clone());
    let (snapshots, snapshot) = watch::channel(Some(node.snapshot()));
    let (landing, _landings) = mpsc::unbounded_channel();
    let (events, _events) = mpsc::unbounded_channel();
    let mut task = Task {
        connections: table.clone(),
        snapshots: snapshot,
        walks: Walks::new(node.health.clone()),
        commands,
        landing,
        events,
        grants: mpsc::unbounded_channel().0,
        grant_queue: GrantQueue::default(),
        unknown_joins: PATCH::new(),
        running: HashMap::new(),
        next_id: 0,
    };
    task.observe(node.snapshot());

    let mut conns = Vec::new();
    let mut recons = Vec::new();
    for sequence in [1_u64, 2] {
        let conn = remote.transport.dial(local, PILE_SYNC_ALPN).await.unwrap();
        table.accept(harness.incoming.recv().await.unwrap().conn);
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send_u8(&mut send, TAG_RECON).await.unwrap();
        write_frame(&mut send, crate::recon::FRAME_OPEN, &sequence.to_be_bytes())
            .await
            .unwrap();
        recons.push((send, recv));
        conns.push(conn);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(table.current(peer).unwrap().sequence(), Some(sequence));
    }
    tokio::time::sleep(DRAIN_GRACE + Duration::from_millis(100)).await;
    assert_eq!(table.len(), 1, "the retired connection really drained");
    let close = commanded
        .try_recv()
        .expect("the accept loop queued its close");
    let old = match &close {
        Command::Closed { link } => link.id(),
        _ => panic!("expected the accept loop's close"),
    };

    let key = (peer, collection.raw, WalkKind::Commit);
    let mut incoming_stream = None;
    if incoming {
        let (mut send, recv) = conns[1].open_bi().await.unwrap();
        send_u8(&mut send, TAG_WALK).await.unwrap();
        let (tag, payload) = Frame::Open {
            collection,
            kind: WalkKind::Commit,
            algorithm: crate::walk_stream::Algorithm::CachedRiblt,
            offer: None,
        }
        .encode();
        write_frame(&mut send, tag, &payload).await.unwrap();
        let command = commanded.recv().await.unwrap();
        assert!(matches!(command, Command::Incoming { .. }));
        task.command(command);
        incoming_stream = Some((send, recv));
    } else {
        task.open(peer, collection, WalkKind::Commit);
    }
    let replacement_link = table.current(peer).unwrap().link();
    let replacement = replacement_link.id();
    assert_eq!(task.running[&key].connection, replacement);
    // These peer-scoped observations belong to work already using the
    // replacement, and must not be discarded by the old queued close.
    let queued = absent(700);
    assert!(task.grant_queue.push(peer, queued));
    let mut charged = [0; 64];
    charged[..32].copy_from_slice(&peer);
    charged[32..].copy_from_slice(&absent(701).raw);
    task.unknown_joins.insert(&Entry::new(&charged));
    let agreement = agreed_key(peer, collection.raw, WalkKind::References);
    task.walks.agreed.insert(&Entry::with_value(
        &agreement,
        Agreement {
            connection: replacement,
            tree: Arc::new(Tree::pinned(
                WalkKind::References,
                node.pinned(collection).repair(),
            )),
        },
    ));
    let old_agreement = agreed_key(peer, collection.raw, WalkKind::Derive);
    task.walks.agreed.insert(&Entry::with_value(
        &old_agreement,
        Agreement {
            connection: old,
            tree: Arc::new(Tree::pinned(
                WalkKind::Derive,
                node.pinned(collection).repair(),
            )),
        },
    ));
    task.walks.health.with_peer(collection, peer, |health| {
        health.received(
            crate::clock::mono_now(),
            WalkKind::Commit,
            Some(summary(WalkKind::Commit, node.pinned(collection).repair())),
            true,
        );
    });
    let health = task.walks.health.snapshot();
    task.command(close);
    assert_eq!(task.walks.health.snapshot().collections, health.collections);
    assert!(task.walks.agreed.get(&old_agreement).is_none());
    assert!(
        task.running.contains_key(&key),
        "the replacement walk survives"
    );
    assert_eq!(task.grant_queue.queued(peer).count(), 1);
    assert!(task.unknown_joins.get(&charged).is_some());
    assert!(task.walks.agreed.get(&agreement).is_some());

    // Positive control: closing the replacement still cancels its own
    // work and forgets the peer state once no current connection remains.
    conns[1].close(0, b"test complete");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let command = commanded.recv().await.unwrap();
            let closed = matches!(command, Command::Closed { .. });
            task.command(command);
            if closed {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(task.running.is_empty());
    assert_eq!(task.grant_queue.queued(peer).count(), 0);
    assert!(task.unknown_joins.get(&charged).is_none());
    assert!(task.walks.agreed.get(&agreement).is_none());
    // Even an incoming command delivered after its Closed cannot recreate
    // work for that dead connection. The Link carries the actual closed bit.
    let (_script, stream) = tokio::io::duplex(1024);
    let (recv, send) = tokio::io::split(stream);
    let reset = Arc::new(Mutex::new(None));
    task.incoming(
        replacement_link,
        collection,
        WalkKind::Commit,
        crate::walk_stream::Algorithm::CachedRiblt,
        None,
        Box::new(Tx(send, reset.clone())),
        Box::new(Rx(recv, reset.clone())),
    );
    assert!(task.running.is_empty());
    assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_FAILED));
    drop((snapshots, recons, incoming_stream));
}

#[tokio::test(start_paused = true)]
async fn a_queued_old_connection_close_preserves_replacement_walks() {
    queued_old_connection_close(false).await;
}

#[tokio::test(start_paused = true)]
async fn a_queued_old_connection_close_preserves_incoming_replacement_walks() {
    queued_old_connection_close(true).await;
}

/// A restarted peer can redial before the old connection drains. Prefix
/// must send the full source on that new connection, not reuse the base
/// confirmed with the previous process carrying the same peer identity.
#[tokio::test(start_paused = true)]
async fn a_replacement_connection_does_not_reuse_the_old_prefix_agreement() {
    let net = SimNet::new(0x3A72, SimConfig::default());
    let mut source = Node::new(121);
    let mut before = Node::new(122);
    let policy = one_way(&source, &before);
    let collection = source.hold("connection scoped prefix", policy.clone());
    source.commit(collection, 1);
    source.observe();
    before.hold("connection scoped prefix", policy.clone());
    let source = Hosted::new(source, &net);
    let before = Hosted::new(before, &net);
    let _old = before.table.connect(source.peer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(source.table.current(before.peer).is_some());
    let health = source
        .exchange(before.peer, collection, WalkKind::Commit)
        .await;
    assert!(health.pushes.last_ok);
    assert_eq!(before.records(collection), source.records(collection));

    let mut after = Node::new(122);
    after.hold("connection scoped prefix", policy);
    let after = Hosted::new(after, &net);
    let _new = after.table.connect(source.peer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        source.table.len(),
        2,
        "the previous connection has not drained"
    );
    assert!(
        after.records(collection).is_empty(),
        "the restarted peer lost its base"
    );
    let health = source
        .exchange(after.peer, collection, WalkKind::Commit)
        .await;
    assert!(
        health.pushes.last_ok,
        "the replacement confirms its own full exchange"
    );
    assert_eq!(after.records(collection), source.records(collection));
}
