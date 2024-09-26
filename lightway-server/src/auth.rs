use lightway_server::{AuthState, ServerAuth, ServerAuthResult};

pub struct Auth {
    pub user: String,
    pub password: String,
}

impl<'a> ServerAuth<AuthState<'a>> for Auth {
    fn authorize_user_password(
        &self,
        user: &str,
        password: &str,
        _app_state: &mut AuthState<'a>,
    ) -> ServerAuthResult {
        if user == self.user && password == self.password {
            ServerAuthResult::Granted {
                handle: None,
                tunnel_protocol_version: None,
            }
        } else {
            ServerAuthResult::Denied
        }
    }
}
