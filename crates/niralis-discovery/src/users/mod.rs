mod filter;
mod nss;

#[cfg(test)]
mod tests;

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
        let users = nss::enumerate_system_users()?;
        Ok(filter::filter_users(users, &self.config))
    }
}
