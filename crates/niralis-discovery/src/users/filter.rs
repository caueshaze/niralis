use std::collections::HashSet;
use std::path::Path;

use niralis_protocol::UserInfo;

use crate::users::UserDiscoveryConfig;

pub(super) fn filter_users(users: Vec<SystemUser>, config: &UserDiscoveryConfig) -> Vec<UserInfo> {
    let excluded: HashSet<&str> = config.exclude.iter().map(String::as_str).collect();
    let mut result: Vec<UserInfo> = users
        .into_iter()
        .filter(|user| user.uid >= config.min_uid)
        .filter(|user| config.allow_root || user.uid != 0)
        .filter(|user| !excluded.contains(user.username.as_str()))
        .filter(|user| !has_noninteractive_shell(&user.shell))
        .map(|user| UserInfo {
            uid: user.uid,
            username: user.username.clone(),
            display_name: display_name_from_gecos(&user.gecos, &user.username),
        })
        .collect();

    result.sort_by(|left, right| {
        left.display_name
            .cmp(&right.display_name)
            .then_with(|| left.username.cmp(&right.username))
    });
    result
}

fn display_name_from_gecos(gecos: &str, username: &str) -> String {
    let name = gecos.split(',').next().unwrap_or_default().trim();
    if name.is_empty() {
        username.to_owned()
    } else {
        name.to_owned()
    }
}

fn has_noninteractive_shell(shell: &str) -> bool {
    let shell_name = Path::new(shell)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(shell);

    matches!(shell_name, "nologin" | "false")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SystemUser {
    pub(super) uid: u32,
    pub(super) username: String,
    pub(super) gecos: String,
    pub(super) shell: String,
}
