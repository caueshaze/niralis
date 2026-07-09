use niralis_protocol::UserInfo;

use super::filter::{filter_users, SystemUser};
use super::UserDiscoveryConfig;

fn user(uid: u32, username: &str, gecos: &str, shell: &str) -> SystemUser {
    SystemUser {
        uid,
        username: username.to_owned(),
        gecos: gecos.to_owned(),
        shell: shell.to_owned(),
    }
}

fn config() -> UserDiscoveryConfig {
    UserDiscoveryConfig::default()
}

#[test]
fn includes_normal_user() {
    let users = filter_users(
        vec![user(1000, "caue", "Caue Sousa", "/bin/bash")],
        &config(),
    );

    assert_eq!(
        users,
        vec![UserInfo {
            uid: 1000,
            username: "caue".to_owned(),
            display_name: "Caue Sousa".to_owned(),
        }]
    );
}

#[test]
fn omits_uid_below_min_uid() {
    let users = filter_users(vec![user(999, "daemon", "Daemon", "/bin/bash")], &config());
    assert!(users.is_empty());
}

#[test]
fn omits_root_by_default() {
    let mut cfg = config();
    cfg.min_uid = 0;
    let users = filter_users(vec![user(0, "root", "root", "/bin/bash")], &cfg);
    assert!(users.is_empty());
}

#[test]
fn permits_root_when_configured() {
    let mut cfg = config();
    cfg.min_uid = 0;
    cfg.allow_root = true;
    let users = filter_users(vec![user(0, "root", "root", "/bin/bash")], &cfg);
    assert_eq!(users[0].username, "root");
}

#[test]
fn omits_excluded_user() {
    let users = filter_users(
        vec![user(65534, "nobody", "Nobody", "/bin/bash")],
        &config(),
    );
    assert!(users.is_empty());
}

#[test]
fn omits_noninteractive_shells_and_sorts() {
    let users = filter_users(
        vec![
            user(1000, "svc1", "Svc", "/usr/sbin/nologin"),
            user(1000, "svc2", "Svc", "/bin/false"),
            user(1001, "zara", "Zed", "/bin/bash"),
            user(1002, "ana2", "Ana", "/bin/bash"),
            user(1000, "ana1", "Ana", "/bin/bash"),
        ],
        &config(),
    );

    let usernames: Vec<String> = users.into_iter().map(|user| user.username).collect();
    assert_eq!(usernames, vec!["ana1", "ana2", "zara"]);
}

#[test]
fn empty_gecos_uses_username() {
    let users = filter_users(vec![user(1000, "caue", "", "/bin/bash")], &config());
    assert_eq!(users[0].display_name, "caue");
}
