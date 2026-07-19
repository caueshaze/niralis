use super::*;
use std::os::unix::fs::MetadataExt;

fn current_identity() -> (u32, u64, (u64, u64), String) {
    let pid = std::process::id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let starttime = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let executable = fs::metadata(format!("/proc/{pid}/exe")).unwrap();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .unwrap();
    (pid, starttime, (executable.dev(), executable.ino()), cgroup)
}

#[test]
fn current_process_rehydrates_only_with_all_identity_fields() {
    let (pid, starttime, executable, cgroup) = current_identity();
    assert!(matches!(
        rehydrate_process_identity(pid, Some(starttime), Some(executable), Some(&cgroup)),
        PersistedProcessIdentity::OriginalStillAlive { .. }
    ));
    assert!(matches!(
        rehydrate_process_identity(pid, Some(starttime + 1), Some(executable), Some(&cgroup)),
        PersistedProcessIdentity::PidReused
    ));
}
