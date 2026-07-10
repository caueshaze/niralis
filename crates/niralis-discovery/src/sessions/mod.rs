mod desktop_entry;
mod discovery;
mod launch;
mod trust;

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::path::PathBuf;

use niralis_protocol::SessionInfo;

use crate::DiscoveryError;

pub trait SessionDirectory: Send + Sync {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError>;

    fn find_session(&self, id: &str) -> Result<Option<SessionInfo>, DiscoveryError>;

    fn resolve_launch_spec(
        &self,
        id: &str,
    ) -> Result<Option<ResolvedSessionLaunchSpec>, DiscoveryError>;
}

impl<T> SessionDirectory for Box<T>
where
    T: SessionDirectory + ?Sized,
{
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError> {
        (**self).list_sessions()
    }

    fn find_session(&self, id: &str) -> Result<Option<SessionInfo>, DiscoveryError> {
        (**self).find_session(id)
    }

    fn resolve_launch_spec(
        &self,
        id: &str,
    ) -> Result<Option<ResolvedSessionLaunchSpec>, DiscoveryError> {
        (**self).resolve_launch_spec(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSourceTrustPolicy {
    Permissive,
    RootOwned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSessionLaunchSpec {
    pub session: SessionInfo,
    pub source_path: PathBuf,
    pub executable: PathBuf,
    pub argv: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct SessionDiscoveryConfig {
    pub wayland_dirs: Vec<PathBuf>,
    pub include_x11: bool,
    pub x11_dirs: Vec<PathBuf>,
    pub exec_search_path: Vec<PathBuf>,
    pub source_trust: SessionSourceTrustPolicy,
}

impl Default for SessionDiscoveryConfig {
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
            source_trust: SessionSourceTrustPolicy::RootOwned,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DesktopSessionDirectory {
    config: SessionDiscoveryConfig,
}

impl DesktopSessionDirectory {
    pub fn new(config: SessionDiscoveryConfig) -> Self {
        Self { config }
    }
}

impl SessionDirectory for DesktopSessionDirectory {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>, DiscoveryError> {
        discovery::list_sessions(&self.config)
    }

    fn find_session(&self, id: &str) -> Result<Option<SessionInfo>, DiscoveryError> {
        Ok(discovery::find_entry(&self.config, id)?.map(|entry| entry.session))
    }

    fn resolve_launch_spec(
        &self,
        id: &str,
    ) -> Result<Option<ResolvedSessionLaunchSpec>, DiscoveryError> {
        discovery::find_entry(&self.config, id)?
            .map(|entry| launch::resolve(entry, &self.config.exec_search_path))
            .transpose()
    }
}
