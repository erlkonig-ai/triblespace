use super::*;

fn command(session: &mut Session, line: impl AsRef<str>) -> String {
    let mut output = Vec::new();
    assert!(session.command(line.as_ref(), &mut output).unwrap());
    String::from_utf8(output).unwrap()
}

fn load(session: &mut Session, path: &Path) -> String {
    command(session, format!("load {}", path.display()))
}

fn revision(source: &str) -> String {
    source
        .lines()
        .next()
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap()
        .into()
}

fn select(session: &mut Session, revisions: &str, prior: &str) -> String {
    command(session, format!("select {revisions} after {prior}"))
        .split_whitespace()
        .nth(1)
        .unwrap()
        .into()
}

#[test]
fn saved_revision_changes_one_continuing_session_and_forks_require_explicit_merge() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path().join("fresh namespace");
    initialize(&directory).unwrap();
    let first_path = directory.join("v1.rules");
    let next_path = directory.join("v2.rules");
    let first = fs::read_to_string(&first_path).unwrap();
    let second = fs::read_to_string(&next_path).unwrap();
    let v1 = revision(&first);
    let v2 = revision(&second);
    assert_ne!(v1, v2);
    let mut session = Session::new().unwrap();
    load(&mut session, &first_path);
    load(&mut session, &directory.join("initial.facts"));
    assert!(command(&mut session, "show").contains("reading Empty"));
    let one = select(&mut session, &v1, "-");
    let first_step = command(&mut session, "step");
    assert!(first_step.starts_with(&format!("reading Sole({one})\n")));
    assert!(first_step.contains("firings 1"));
    let old = command(&mut session, "show");
    assert_eq!(
        old.lines().next(),
        Some(format!("reading Sole({one}); selected {v1}").as_str())
    );
    assert!(old.contains("red lantern"));
    assert!(!old.contains("blue lantern"));

    // Save a changed predicate to an independently fresh revision while this
    // same environment stays alive. The driver reads bytes from disk on load.
    fs::write(
        &next_path,
        second.replace("utf8(\"red\")", "utf8(\"blue\")"),
    )
    .unwrap();
    load(&mut session, &next_path);
    assert!(command(&mut session, "step").contains("firings 0"));
    assert!(!command(&mut session, "show").contains("blue lantern"));
    let two = select(&mut session, &v2, &one);
    assert!(command(&mut session, "step").contains("firings 1"));
    let changed = command(&mut session, "show");
    assert!(changed.contains("red lantern"));
    assert!(changed.contains("blue lantern")); // New selection seeds old input.
    load(&mut session, &directory.join("later.facts"));
    assert!(command(&mut session, "step").contains("firings 1"));
    let later = command(&mut session, "show");
    assert!(later.contains("blue comet"));
    assert!(!later.contains("red comet")); // Retired revision cannot fire.
    assert!(later.contains("red lantern")); // Its old consequence survives.

    let left = select(&mut session, &v1, &two);
    let right = select(&mut session, &v2, &two);
    let support = session
        .root
        .admitted(&session.store.snapshot().unwrap())
        .unwrap();
    let mut refused = Vec::new();
    let error = session.command("step", &mut refused).unwrap_err();
    assert!(error
        .to_string()
        .contains("unresolved execution reading: Fork"));
    assert_eq!(
        support,
        session
            .root
            .admitted(&session.store.snapshot().unwrap())
            .unwrap()
    );
    let fork = command(&mut session, "show");
    let headline = fork.lines().next().unwrap();
    let heads = headline
        .strip_prefix("reading Fork(")
        .unwrap()
        .strip_suffix("); selected -")
        .unwrap();
    assert_eq!(
        heads.split(',').collect::<std::collections::BTreeSet<_>>(),
        [left.as_str(), right.as_str()].into_iter().collect()
    );
    assert_eq!(
        String::from_utf8(refused).unwrap().lines().next(),
        Some(format!("reading Fork({heads})").as_str())
    );
    assert!(!fork.contains("red comet"));
    let merged = select(&mut session, &v1, &format!("{left},{right}"));
    assert!(command(&mut session, "step").contains("firings 1"));
    assert!(command(&mut session, "show").contains("red comet"));
    select(&mut session, "-", &merged);
    assert!(command(&mut session, "step 1").contains("firings 0"));
    assert!(command(&mut session, "show").contains("selected -"));
    assert_eq!(fs::read_to_string(&first_path).unwrap(), first);
    assert!(!session.command("quit", &mut Vec::new()).unwrap());
}

#[test]
fn malformed_saved_text_commits_nothing_and_initializer_never_overwrites() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("example");
    initialize(&directory).unwrap();
    let path = directory.join("v1.rules");
    let original = fs::read(&path).unwrap();
    assert!(initialize(&directory).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut session = Session::new().unwrap();
    load(&mut session, &path);
    let before = session
        .root
        .admitted(&session.store.snapshot().unwrap())
        .unwrap();
    let malformed = directory.join("malformed.rules");
    let mut source = fs::read_to_string(directory.join("v2.rules")).unwrap();
    source.push_str("\nfact @revision @revision utf8(\"partial\");\nnot a statement;");
    fs::write(&malformed, source).unwrap();
    assert!(session
        .command(&format!("load {}", malformed.display()), &mut Vec::new())
        .is_err());
    assert_eq!(
        before,
        session
            .root
            .admitted(&session.store.snapshot().unwrap())
            .unwrap()
    );
    assert!(command(&mut session, "show").contains("reading Empty"));
    // The failed command did not kill the continuing session.
    select(
        &mut session,
        &revision(std::str::from_utf8(&original).unwrap()),
        "-",
    );
    load(&mut session, &directory.join("initial.facts"));
    assert!(command(&mut session, "step").contains("firings 1"));
}
