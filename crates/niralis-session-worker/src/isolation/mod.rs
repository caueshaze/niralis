mod linux;

pub use linux::{LinuxInheritedFdSanitizer, LinuxPostDropAuditor};

pub const HARD_MAX_CAPABILITY_ID: u32 = 63;
pub const DANGEROUS_SECUREBITS_MASK: u32 = (1 << 0) | (1 << 2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityState {
    pub effective: Vec<u32>,
    pub permitted: Vec<u32>,
    pub inheritable: Vec<u32>,
    pub ambient: Vec<u32>,
    pub bounding: Vec<u32>,
    pub cap_last_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostDropIsolationProof {
    pub capabilities: CapabilityState,
    pub securebits: u32,
    pub no_new_privs: bool,
    pub open_fds: Vec<i32>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IsolationPolicyError {
    #[error("active capabilities present")]
    ActiveCapabilitiesPresent,
    #[error("dangerous securebits present")]
    DangerousSecurebits,
    #[error("unexpected file descriptors present")]
    UnexpectedFileDescriptors,
    #[error("invalid capability proof structure")]
    InvalidCapabilityStructure,
    #[error("invalid file descriptor proof structure")]
    InvalidFdStructure,
}

pub fn validate_isolation_proof(
    proof: &PostDropIsolationProof,
) -> Result<(), IsolationPolicyError> {
    let caps = &proof.capabilities;
    if caps.cap_last_cap > HARD_MAX_CAPABILITY_ID
        || !valid_capabilities(&caps.effective, caps.cap_last_cap)
        || !valid_capabilities(&caps.permitted, caps.cap_last_cap)
        || !valid_capabilities(&caps.inheritable, caps.cap_last_cap)
        || !valid_capabilities(&caps.ambient, caps.cap_last_cap)
        || !valid_capabilities(&caps.bounding, caps.cap_last_cap)
    {
        return Err(IsolationPolicyError::InvalidCapabilityStructure);
    }
    if !valid_fds(&proof.open_fds) {
        return Err(IsolationPolicyError::InvalidFdStructure);
    }
    if !caps.effective.is_empty()
        || !caps.permitted.is_empty()
        || !caps.inheritable.is_empty()
        || !caps.ambient.is_empty()
    {
        return Err(IsolationPolicyError::ActiveCapabilitiesPresent);
    }
    if proof.securebits & DANGEROUS_SECUREBITS_MASK != 0 {
        return Err(IsolationPolicyError::DangerousSecurebits);
    }
    if proof.open_fds != [0, 1, 2] {
        return Err(IsolationPolicyError::UnexpectedFileDescriptors);
    }
    Ok(())
}

fn valid_capabilities(values: &[u32], last: u32) -> bool {
    values.windows(2).all(|w| w[0] < w[1]) && values.iter().all(|value| *value <= last)
}

fn valid_fds(values: &[i32]) -> bool {
    values.windows(2).all(|w| w[0] < w[1]) && values.iter().all(|value| *value >= 0)
}

pub trait InheritedFdSanitizer: Send + Sync {
    fn sanitize(&self) -> Result<(), FdSanitizationError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FdSanitizationError {
    #[error("failed to sanitize inherited file descriptors")]
    Failed,
}

pub trait PostDropAuditor: Send + Sync {
    fn audit(&self) -> Result<PostDropIsolationProof, PostDropAuditError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PostDropAuditError {
    #[error("failed to audit post-drop isolation")]
    Failed,
    #[error("unsupported capability range")]
    UnsupportedCapabilityRange,
}

#[cfg(test)]
mod tests;
