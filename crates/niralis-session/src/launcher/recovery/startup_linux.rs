use super::*;

pub(crate) fn reconcile_linux_startup(
    record: &SameBootRecoveryRecord,
    ledger: &mut PersistentRecoveryLedger,
) -> StartupRecoveryOutcome {
    reconcile_same_boot_record(record, ledger)
}
