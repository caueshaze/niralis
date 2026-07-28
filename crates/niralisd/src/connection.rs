use niralis_protocol::{GreeterConnectionId, SeatId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatedPeerIdentity {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) pid: Option<i32>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GreeterConnectionAuthority {
    connection_id: GreeterConnectionId,
    connection_epoch: u64,
    seat: SeatId,
    peer_identity: ValidatedPeerIdentity,
}

impl GreeterConnectionAuthority {
    pub(crate) fn issue(
        connection_id: GreeterConnectionId,
        connection_epoch: u64,
        seat: SeatId,
        peer_identity: ValidatedPeerIdentity,
    ) -> Self {
        Self {
            connection_id,
            connection_epoch,
            seat,
            peer_identity,
        }
    }

    pub(crate) fn connection_id(&self) -> &GreeterConnectionId {
        &self.connection_id
    }
    pub(crate) fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }
    pub(crate) fn seat(&self) -> &SeatId {
        &self.seat
    }
    pub(crate) fn matches(&self, id: &GreeterConnectionId, epoch: u64, seat: &SeatId) -> bool {
        &self.connection_id == id && self.connection_epoch == epoch && &self.seat == seat
    }
}
