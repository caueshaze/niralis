use super::*;
use std::io;

impl PersistentRecoveryLedger {
    pub(crate) fn issue_seat_free_permit(
        &self,
        receipt: RecordRemovedReceipt,
    ) -> io::Result<SeatFreePermit> {
        if self
            .records
            .values()
            .any(|record| record.seat == receipt.seat)
            || self.seat_startup_quarantined(&receipt.seat)
            || self.startup_quarantined()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "competing record or active quarantine",
            ));
        }
        Ok(SeatFreePermit {
            boot_id: receipt.boot_id,
            record_id: receipt.record_id,
            lifecycle_id: receipt.lifecycle_id,
            sequence: receipt.sequence,
            seat: receipt.seat,
        })
    }

    pub(crate) fn consume_seat_free_permit(&self, permit: SeatFreePermit) -> io::Result<()> {
        if self
            .records
            .values()
            .any(|record| record.seat == permit.seat)
            || self.seat_startup_quarantined(&permit.seat)
            || self.startup_quarantined()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seat free precondition changed",
            ));
        }
        Ok(())
    }
}
