use super::*;
use std::io;

impl PersistentRecoveryLedger {
    pub(crate) fn operation_intent(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::IntentPersisted { attempt_id },
        )
    }

    pub(crate) fn operation_confirmed(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::Confirmed { attempt_id },
        )
    }

    pub(crate) fn operation_failed(
        &mut self,
        id: &str,
        operation: &str,
        attempt_id: u64,
        failure_class: i32,
    ) -> io::Result<()> {
        self.update_operation(
            id,
            operation,
            DurableOperationState::Failed {
                attempt_id,
                failure_class,
            },
        )
    }

    fn update_operation(
        &mut self,
        id: &str,
        operation: &str,
        state: DurableOperationState,
    ) -> io::Result<()> {
        let mut next = self
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "recovery record"))?;
        match operation {
            "payload_kill" => next.operation_ledger.payload_kill = state,
            "supervisor_unref" => next.operation_ledger.supervisor_unref = state,
            "logind_termination" => next.operation_ledger.logind_termination = state,
            "vt_activation" => next.operation_ledger.vt_activation = state,
            "vt_disallocate" => next.operation_ledger.vt_disallocate = state,
            "runtime_release" => next.operation_ledger.runtime_release = state,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown operation",
                ))
            }
        }
        let current = next.state.clone();
        next.transition(&current)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.commit(next)
    }
}
