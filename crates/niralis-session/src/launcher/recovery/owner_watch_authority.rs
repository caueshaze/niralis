use super::*;

/// A stable authority is usable only in the generation in which it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthoritySnapshot {
    pub(crate) unique_owner: String,
    pub(crate) generation: u64,
}

impl OwnerWatch {
    pub(crate) fn stable_snapshot(&self) -> Result<AuthoritySnapshot, SupervisorRecoveryError> {
        self.stable()?;
        match self
            .state()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
        {
            AuthorityWatchState::Stable {
                unique_owner,
                generation,
            } => Ok(AuthoritySnapshot {
                unique_owner,
                generation,
            }),
            AuthorityWatchState::Changed { .. } | AuthorityWatchState::Lost { .. } => {
                Err(SupervisorRecoveryError::BusUnavailable)
            }
        }
    }

    pub(crate) fn still_authorizes(
        &self,
        snapshot: &AuthoritySnapshot,
    ) -> Result<(), SupervisorRecoveryError> {
        self.stable()?;
        match self
            .state()
            .map_err(|_| SupervisorRecoveryError::BusUnavailable)?
        {
            AuthorityWatchState::Stable {
                unique_owner,
                generation,
            } if unique_owner == snapshot.unique_owner && generation == snapshot.generation => {
                Ok(())
            }
            _ => Err(SupervisorRecoveryError::BusUnavailable),
        }
    }
}
