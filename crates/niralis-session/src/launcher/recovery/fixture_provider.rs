use super::*;

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
#[derive(Debug)]
pub(crate) struct SupervisorFixtureRecoveryProvider {
    pub(crate) mode: SupervisorFixtureBoundaryMode,
    pub(crate) counters: Arc<SupervisorFixtureCounters>,
    pub(crate) logind_already_gone: bool,
    pub(crate) vt_result: Result<(), SupervisorRecoveryError>,
    pub(crate) payload_members: Arc<Mutex<Vec<u32>>>,
    pub(crate) completion_event: Arc<OwnedFd>,
    pub(crate) prepare_gate_enabled: std::sync::atomic::AtomicBool,
    pub(crate) prepare_gate: Arc<OwnedFd>,
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
impl SupervisorFixtureRecoveryProvider {
    pub(crate) fn successful() -> Self {
        let completion_event = fixture_eventfd().expect("fixture eventfd");
        let prepare_gate = fixture_eventfd().expect("fixture prepare gate eventfd");
        Self {
            mode: SupervisorFixtureBoundaryMode::AlreadyEmpty,
            counters: Arc::new(SupervisorFixtureCounters::default()),
            logind_already_gone: true,
            vt_result: Ok(()),
            payload_members: Arc::new(Mutex::new(Vec::new())),
            completion_event: Arc::new(completion_event),
            prepare_gate_enabled: std::sync::atomic::AtomicBool::new(false),
            prepare_gate: Arc::new(prepare_gate),
        }
    }
}

#[cfg(any(
    test,
    feature = "integration-test-control",
    feature = "supervisor-test-fixtures"
))]
impl SupervisorRecoveryProvider for SupervisorFixtureRecoveryProvider {
    fn capture_previous_vt(
        &self,
        seat: &str,
    ) -> Result<PreviousVtIdentity, SupervisorRecoveryError> {
        if seat == "seat0" {
            Ok(PreviousVtIdentity { number: 1 })
        } else {
            Err(SupervisorRecoveryError::VtIdentityChanged)
        }
    }

    fn prepare_payload(
        &self,
        identity: &crate::PayloadScopeIdentity,
        authoritative_leader_pid: u32,
        _worker_pid: u32,
        _launcher_pid: u32,
        previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPreparedPayload, SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        if self.prepare_gate_enabled.load(Ordering::SeqCst) {
            wait_fixture_event(&self.prepare_gate)?;
        }
        self.counters.prepares.fetch_add(1, Ordering::SeqCst);
        Ok(SupervisorPreparedPayload {
            boundary: Box::new(SupervisorFixtureBoundary {
                identity: identity.clone(),
                leader_pid: authoritative_leader_pid,
                mode: self.mode,
                counters: Arc::clone(&self.counters),
                payload_members: Arc::clone(&self.payload_members),
                completion_event: Arc::clone(&self.completion_event),
                released: false,
            }),
            logind: SupervisorLogindSessionIdentity {
                id: identity.logind_session_id.clone(),
                object_path: format!(
                    "/org/freedesktop/login1/session/{}",
                    identity.logind_session_id.as_str()
                ),
                uid: identity.expected_uid,
                username: "fixture-user".to_owned(),
                leader: authoritative_leader_pid,
                seat: "seat0".to_owned(),
                vt_number: 2,
                session_type: "wayland".to_owned(),
                class: "user".to_owned(),
                desktop: "niri".to_owned(),
                state: "active".to_owned(),
                scope: "session-fixture.scope".to_owned(),
            },
            vt: SupervisorVtIdentity {
                seat: "seat0".to_owned(),
                number: 2,
                previous: previous_vt.clone(),
                device_major: 4,
                device_minor: 2,
            },
            target_gid: 1000,
        })
    }

    fn recover_pre_payload(
        &self,
        _worker_pid: u32,
        _expected_username: &str,
        _session_name: &str,
        _previous_vt: &PreviousVtIdentity,
    ) -> Result<SupervisorPrePayloadRecoveryResult, SupervisorRecoveryError> {
        Err(SupervisorRecoveryError::InvalidRecord)
    }

    fn cleanup_logind(
        &self,
        _identity: &SupervisorLogindSessionIdentity,
    ) -> Result<SupervisorLogindCleanupResult, SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        if self.logind_already_gone {
            Ok(SupervisorLogindCleanupResult::AlreadyGone)
        } else {
            self.counters
                .logind_terminations
                .fetch_add(1, Ordering::SeqCst);
            Ok(SupervisorLogindCleanupResult::Removed)
        }
    }

    fn confirm_logind_absent(
        &self,
        _identity: &SupervisorLogindSessionIdentity,
    ) -> Result<bool, SupervisorRecoveryError> {
        Ok(self.logind_already_gone)
    }

    fn recover_vt(&self, _identity: &SupervisorVtIdentity) -> Result<(), SupervisorRecoveryError> {
        use std::sync::atomic::Ordering;
        self.counters.vt_recoveries.fetch_add(1, Ordering::SeqCst);
        let result = self.vt_result.clone();
        signal_fixture_completion(&self.completion_event);
        result
    }
}
