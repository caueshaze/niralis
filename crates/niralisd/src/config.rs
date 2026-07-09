use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{NiralisdError, Result};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/niralis/niralis.toml";
pub const DEFAULT_SOCKET_PATH: &str = "/run/niralis/niralisd.sock";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub greeter: GreeterConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub users: UsersConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    pub socket: PathBuf,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GreeterConfig {
    pub command: String,
    pub user: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBackend {
    Mock,
    #[default]
    Pam,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub backend: AuthBackend,
    pub pam_service: String,
    pub max_attempts: u32,
    pub cooldown_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsersConfig {
    pub min_uid: u32,
    pub allow_root: bool,
    pub exclude: Vec<String>,
}

impl Default for UsersConfig {
    fn default() -> Self {
        Self {
            min_uid: 1000,
            allow_root: false,
            exclude: vec!["nobody".to_owned()],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionsConfig {
    pub wayland_dirs: Vec<PathBuf>,
    pub include_x11: bool,
    pub x11_dirs: Vec<PathBuf>,
    pub exec_search_path: Vec<PathBuf>,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            wayland_dirs: vec![PathBuf::from("/usr/share/wayland-sessions")],
            include_x11: false,
            x11_dirs: vec![PathBuf::from("/usr/share/xsessions")],
            exec_search_path: vec![
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/local/sbin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    pub default: String,
    pub command: String,
    #[serde(default)]
    pub launcher: SessionLauncherBackend,
    #[serde(default = "default_worker_path")]
    pub worker_path: PathBuf,
    #[serde(default = "default_worker_timeout_seconds")]
    pub worker_timeout_seconds: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLauncherBackend {
    #[default]
    Mock,
    Worker,
}

fn default_worker_path() -> PathBuf {
    PathBuf::from("/usr/libexec/niralis-session-worker")
}

fn default_worker_timeout_seconds() -> u64 {
    5
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|source| NiralisdError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;

        toml::from_str(&raw).map_err(|source| NiralisdError::ConfigParse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn load_default_or_builtin(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(config) => Ok(config),
            Err(NiralisdError::ConfigRead { source, .. })
                if path == Path::new(DEFAULT_CONFIG_PATH)
                    && source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig {
                socket: PathBuf::from(DEFAULT_SOCKET_PATH),
                log_level: "info".to_owned(),
            },
            greeter: GreeterConfig {
                command: "/usr/bin/niralis-greeter".to_owned(),
                user: "niralis".to_owned(),
            },
            auth: AuthConfig {
                backend: AuthBackend::Pam,
                pam_service: "niralis".to_owned(),
                max_attempts: 5,
                cooldown_seconds: 10,
            },
            users: UsersConfig::default(),
            sessions: SessionsConfig::default(),
            session: SessionConfig {
                default: "niri".to_owned(),
                command: "niri-session".to_owned(),
                launcher: SessionLauncherBackend::Mock,
                worker_path: default_worker_path(),
                worker_timeout_seconds: default_worker_timeout_seconds(),
            },
        }
    }
}
