use super::*;

pub(crate) fn fixture_process_cgroup(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        })
        .unwrap_or_else(|| "/fixture/payload".to_owned())
}
