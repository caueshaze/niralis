impl WorkerSessionLauncher {
    pub fn recovery_admin(
        &self,
        request: crate::RecoveryAdminRequest,
    ) -> Result<crate::RecoveryAdminResponse, SessionError> {
        self.supervisor.recovery_admin(request)
    }
}
