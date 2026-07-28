impl<L, U, D> DaemonHandler<L, U, D>
where
    L: LoginBackend,
    U: UserDirectory,
    D: SessionDirectory,
{
    fn handle_login_with_conversation(
        &self,
        authority: &crate::connection::GreeterConnectionAuthority,
        request_id: u64,
        request: NiralisRequest,
        conversation: Arc<dyn niralis_session::PamConversationTransport>,
    ) -> NiralisResponse {
        match request {
            NiralisRequest::Login { username, password, session } => {
                let binding = niralis_session::LoginRequestBinding {
                    connection_id: authority.connection_id().as_str().to_owned(),
                    connection_epoch: authority.connection_epoch(), request_id,
                    seat: authority.seat().as_str().to_owned(),
                };
                transactions::begin(&self.transactions, &binding);
                let result = login::handle_login_with_binding(
                    self, username, password, session, Some(binding.clone()), Some(conversation),
                );
                transactions::finish(&self.transactions, &binding, matches!(result, NiralisResponse::LoginOk { .. }));
                result
            }
            other => self.handle_authenticated(authority, request_id, other),
        }
    }
}
