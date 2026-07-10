use super::*;

fn proof() -> PostDropIsolationProof {
    PostDropIsolationProof {
        capabilities: CapabilityState {
            effective: vec![],
            permitted: vec![],
            inheritable: vec![],
            ambient: vec![1],
            bounding: vec![0, 1],
            cap_last_cap: 2,
        },
        securebits: 0,
        no_new_privs: false,
        open_fds: vec![0, 1, 2],
    }
}

#[test]
fn policy_rejects_active_sets_and_dangerous_state() {
    for mutate in [
        |p: &mut PostDropIsolationProof| p.capabilities.effective = vec![1],
        |p: &mut PostDropIsolationProof| p.capabilities.permitted = vec![1],
        |p: &mut PostDropIsolationProof| p.capabilities.inheritable = vec![1],
        |p: &mut PostDropIsolationProof| p.capabilities.ambient = vec![1],
        |p: &mut PostDropIsolationProof| p.securebits = 1,
        |p: &mut PostDropIsolationProof| p.open_fds = vec![0, 1, 2, 9],
    ] {
        let mut value = proof();
        mutate(&mut value);
        assert!(validate_isolation_proof(&value).is_err());
    }
}

#[test]
fn policy_allows_bounding_and_no_new_privs() {
    let mut value = proof();
    value.capabilities.ambient.clear();
    value.no_new_privs = true;
    assert_eq!(validate_isolation_proof(&value), Ok(()));
}
