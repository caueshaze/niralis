
#[test]
fn group_lookup_uses_canonical_username_and_primary_gid() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: vec![(GroupLookupResult::Success, 3, vec![1002, 1000, 1001])],
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    let groups = resolve_groups_with(&group_identity("canonical-user", 1000), &lookup)
        .expect("groups should resolve");

    assert_eq!(groups, vec![1001, 1002]);
    assert_eq!(lookup.username.take().as_deref(), Some("canonical-user"));
    assert_eq!(lookup.primary_gid.take(), Some(1000));
}

#[test]
fn group_lookup_removes_primary_and_deduplicates() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: vec![(
            GroupLookupResult::Success,
            5,
            vec![1002, 1000, 1002, 1001, 1000],
        )],
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    assert_eq!(
        resolve_groups_with(&group_identity("user", 1000), &lookup).expect("groups"),
        vec![1001, 1002]
    );
}

#[test]
fn group_lookup_retries_after_buffer_shortage() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: vec![
            (GroupLookupResult::BufferTooSmall, 17, vec![0; 16]),
            (GroupLookupResult::Success, 3, vec![1002, 1000, 1001]),
        ],
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    assert_eq!(
        resolve_groups_with(&group_identity("user", 1000), &lookup).expect("groups"),
        vec![1001, 1002]
    );
    assert_eq!(lookup.calls.get(), 2);
}

#[test]
fn group_lookup_rejects_inconsistent_shortage() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: vec![(GroupLookupResult::BufferTooSmall, 16, vec![0; 16])],
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    assert_eq!(
        resolve_groups_with(&group_identity("user", 1000), &lookup),
        Err(GroupResolutionError::LookupFailed)
    );
}

#[test]
fn group_lookup_stops_after_maximum_attempts() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: (17..25)
            .map(|count| (GroupLookupResult::BufferTooSmall, count, vec![0; 16]))
            .collect(),
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    assert_eq!(
        resolve_groups_with(&group_identity("user", 1000), &lookup),
        Err(GroupResolutionError::LookupFailed)
    );
    assert_eq!(lookup.calls.get(), 8);
}

#[test]
fn group_lookup_rejects_required_count_above_limit() {
    let lookup = GroupStub {
        calls: Cell::new(0),
        responses: vec![(GroupLookupResult::BufferTooSmall, 65_538, vec![0; 16])],
        username: Cell::new(None),
        primary_gid: Cell::new(None),
    };

    assert_eq!(
        resolve_groups_with(&group_identity("user", 1000), &lookup),
        Err(GroupResolutionError::TooManyGroups)
    );
}

#[test]
fn group_lookup_rejects_username_with_nul() {
    let resolver = NssSupplementaryGroupsResolver;
    let error = resolver
        .resolve(&group_identity("bad\0user", 1000))
        .expect_err("NUL should fail");
    assert_eq!(error, GroupResolutionError::InvalidUsername);
}
