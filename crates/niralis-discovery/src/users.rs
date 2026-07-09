use std::collections::HashSet;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use niralis_protocol::UserInfo;

use crate::DiscoveryError;

pub trait UserDirectory: Send + Sync {
    fn list_users(&self) -> Result<Vec<UserInfo>, DiscoveryError>;
}

impl<T> UserDirectory for Box<T>
where
    T: UserDirectory + ?Sized,
{
    fn list_users(&self) -> Result<Vec<UserInfo>, DiscoveryError> {
        (**self).list_users()
    }
}

#[derive(Debug, Clone)]
pub struct UserDiscoveryConfig {
    pub min_uid: u32,
    pub allow_root: bool,
    pub exclude: Vec<String>,
}

impl Default for UserDiscoveryConfig {
    fn default() -> Self {
        Self {
            min_uid: 1000,
            allow_root: false,
            exclude: vec!["nobody".to_owned()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct NssUserDirectory {
    config: UserDiscoveryConfig,
}

impl NssUserDirectory {
    pub fn new(config: UserDiscoveryConfig) -> Self {
        Self { config }
    }
}

impl UserDirectory for NssUserDirectory {
    fn list_users(&self) -> Result<Vec<UserInfo>, DiscoveryError> {
        let users = enumerate_system_users()?;
        Ok(filter_users(users, &self.config))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemUser {
    uid: u32,
    username: String,
    gecos: String,
    shell: String,
}

fn filter_users(users: Vec<SystemUser>, config: &UserDiscoveryConfig) -> Vec<UserInfo> {
    let excluded: HashSet<&str> = config.exclude.iter().map(String::as_str).collect();
    let mut result: Vec<UserInfo> = users
        .into_iter()
        .filter(|user| user.uid >= config.min_uid)
        .filter(|user| config.allow_root || user.uid != 0)
        .filter(|user| !excluded.contains(user.username.as_str()))
        .filter(|user| !has_noninteractive_shell(&user.shell))
        .map(|user| {
            let display_name = display_name_from_gecos(&user.gecos, &user.username);
            UserInfo {
                uid: user.uid,
                username: user.username,
                display_name,
            }
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

fn enumerate_system_users() -> Result<Vec<SystemUser>, DiscoveryError> {
    let _guard = PasswordDatabaseGuard::new();
    let mut users = Vec::new();

    loop {
        let entry = unsafe { libc::getpwent() };
        if entry.is_null() {
            break;
        }

        let user = unsafe {
            let entry = &*entry;
            SystemUser {
                uid: entry.pw_uid,
                username: c_string_lossy(entry.pw_name),
                gecos: c_string_lossy(entry.pw_gecos),
                shell: c_string_lossy(entry.pw_shell),
            }
        };

        if !user.username.is_empty() {
            users.push(user);
        }
    }

    Ok(users)
}

struct PasswordDatabaseGuard;

impl PasswordDatabaseGuard {
    fn new() -> Self {
        unsafe {
            libc::setpwent();
        }
        Self
    }
}

impl Drop for PasswordDatabaseGuard {
    fn drop(&mut self) {
        unsafe {
            libc::endpwent();
        }
    }
}

unsafe fn c_string_lossy(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn omits_nologin_shell() {
        let users = filter_users(
            vec![user(1000, "svc", "Svc", "/usr/sbin/nologin")],
            &config(),
        );

        assert!(users.is_empty());
    }

    #[test]
    fn omits_false_shell() {
        let users = filter_users(vec![user(1000, "svc", "Svc", "/bin/false")], &config());

        assert!(users.is_empty());
    }

    #[test]
    fn empty_gecos_uses_username() {
        let users = filter_users(vec![user(1000, "caue", "", "/bin/bash")], &config());

        assert_eq!(users[0].display_name, "caue");
    }

    #[test]
    fn sorts_deterministically() {
        let users = filter_users(
            vec![
                user(1001, "zara", "Zed", "/bin/bash"),
                user(1002, "ana2", "Ana", "/bin/bash"),
                user(1000, "ana1", "Ana", "/bin/bash"),
            ],
            &config(),
        );

        let usernames: Vec<String> = users.into_iter().map(|user| user.username).collect();
        assert_eq!(usernames, vec!["ana1", "ana2", "zara"]);
    }
}
