use std::collections::HashMap;
use std::sync::Mutex;

use niralis_protocol::NiralisResponse;

use super::DaemonHandler;
use crate::connection::GreeterConnectionAuthority;
use crate::login_backend::LoginBackend;
use niralis_discovery::{SessionDirectory, UserDirectory};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct TransactionKey {
    pub(super) connection_id: String,
    pub(super) epoch: u64,
    pub(super) request_id: u64,
    pub(super) seat: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransactionState {
    PreCommit,
    Committed,
}

pub(super) type TransactionTable = Mutex<HashMap<TransactionKey, TransactionState>>;

pub(super) fn begin(table: &TransactionTable, binding: &niralis_session::LoginRequestBinding) {
    if let Ok(mut transactions) = table.lock() {
        transactions.insert(key(binding), TransactionState::PreCommit);
    }
}

pub(super) fn finish(
    table: &TransactionTable,
    binding: &niralis_session::LoginRequestBinding,
    committed: bool,
) {
    if let Ok(mut transactions) = table.lock() {
        let key = key(binding);
        if committed {
            transactions.insert(key, TransactionState::Committed);
        } else {
            transactions.remove(&key);
        }
    }
}

pub(super) fn disconnect<L, U, D>(
    handler: &DaemonHandler<L, U, D>,
    table: &TransactionTable,
    authority: &GreeterConnectionAuthority,
) where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    if let Ok(mut transactions) = table.lock() {
        let cancelled = transactions
            .iter()
            .filter(|(key, state)| {
                **state == TransactionState::PreCommit
                    && key.connection_id == authority.connection_id().as_str()
                    && key.epoch == authority.connection_epoch()
                    && key.seat == authority.seat().as_str()
            })
            .map(|(key, _)| niralis_session::LoginRequestBinding {
                connection_id: key.connection_id.clone(),
                connection_epoch: key.epoch,
                request_id: key.request_id,
                seat: key.seat.clone(),
            })
            .collect::<Vec<_>>();
        for binding in cancelled {
            let _ = handler.login_backend.cancel_login(&binding);
        }
        transactions.retain(|key, state| {
            !(key.connection_id == authority.connection_id().as_str()
                && key.epoch == authority.connection_epoch()
                && key.seat == authority.seat().as_str()
                && *state == TransactionState::PreCommit)
        });
    }
}

pub(super) fn cancel<L, U, D>(
    handler: &DaemonHandler<L, U, D>,
    table: &TransactionTable,
    authority: &GreeterConnectionAuthority,
    target_request_id: u64,
) -> NiralisResponse
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    let binding = niralis_session::LoginRequestBinding {
        connection_id: authority.connection_id().as_str().to_owned(),
        connection_epoch: authority.connection_epoch(),
        request_id: target_request_id,
        seat: authority.seat().as_str().to_owned(),
    };
    let removed = table
        .lock()
        .ok()
        .map(|mut transactions| {
            matches!(
                transactions.remove(&key(&binding)),
                Some(TransactionState::PreCommit)
            )
        })
        .unwrap_or(false);
    if removed {
        let _ = handler.login_backend.cancel_login(&binding);
    }
    if removed {
        NiralisResponse::Error {
            message: "login cancelled".to_owned(),
        }
    } else {
        NiralisResponse::Error {
            message: "request is not cancellable".to_owned(),
        }
    }
}

fn key(binding: &niralis_session::LoginRequestBinding) -> TransactionKey {
    TransactionKey {
        connection_id: binding.connection_id.clone(),
        epoch: binding.connection_epoch,
        request_id: binding.request_id,
        seat: binding.seat.clone(),
    }
}
