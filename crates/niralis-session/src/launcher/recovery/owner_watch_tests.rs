use super::*;

#[test]
fn owner_change_invalidates_authority_before_runtime_lookup() {
    let watch = OwnerWatch::scripted();
    watch.invalidate_for_test();
    assert!(watch.stable().is_err());
    assert!(matches!(
        watch.state().unwrap(),
        AuthorityWatchState::Changed { generation: 1, .. }
    ));
}

#[test]
fn invalidated_authority_never_becomes_stable_again_in_the_same_attempt() {
    let watch = OwnerWatch::scripted();
    let snapshot = AuthoritySnapshot {
        unique_owner: "test.owner".to_owned(),
        generation: 0,
    };
    watch.invalidate_for_test();
    watch.invalidate_for_test();
    assert!(watch.still_authorizes(&snapshot).is_err());
    assert!(matches!(
        watch.state().unwrap(),
        AuthorityWatchState::Changed { .. }
    ));
}
