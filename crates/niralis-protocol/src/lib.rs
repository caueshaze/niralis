use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NiralisRequest {
    Status,
    GetUsers,
    GetSessions,
    Login {
        username: String,
        password: String,
        session: String,
    },
    Shutdown,
    Reboot,
}

impl std::fmt::Debug for NiralisRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status => f.write_str("Status"),
            Self::GetUsers => f.write_str("GetUsers"),
            Self::GetSessions => f.write_str("GetSessions"),
            Self::Shutdown => f.write_str("Shutdown"),
            Self::Reboot => f.write_str("Reboot"),
            Self::Login {
                username, session, ..
            } => f
                .debug_struct("Login")
                .field("username", username)
                .field("password", &"[redacted]")
                .field("session", session)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NiralisResponse {
    Status { status: DaemonStatus },
    Users { users: Vec<UserInfo> },
    Sessions { sessions: Vec<SessionInfo> },
    LoginOk { session: SessionInfo },
    SessionUnavailable { message: String },
    LoginFailed { message: String },
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub socket: String,
    pub default_session: String,
    pub greeter_user: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub uid: u32,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub kind: SessionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Wayland,
    X11,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_login_request_without_shape_drift() {
        let request = NiralisRequest::Login {
            username: "test".to_owned(),
            password: "test".to_owned(),
            session: "niri".to_owned(),
        };

        let encoded =
            serde_json::to_string(&request).expect("login request should serialize to json");

        assert_eq!(
            encoded,
            r#"{"type":"login","username":"test","password":"test","session":"niri"}"#
        );
    }

    #[test]
    fn login_request_debug_redacts_password() {
        let request = NiralisRequest::Login {
            username: "test".to_owned(),
            password: "secret".to_owned(),
            session: "niri".to_owned(),
        };

        let debug = format!("{request:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn deserializes_status_response() {
        let decoded: NiralisResponse = serde_json::from_str(
            r#"{"type":"status","status":{"version":"0.1.0","socket":"/tmp/n.sock","default_session":"niri","greeter_user":"niralis"}}"#,
        )
        .expect("status response should deserialize");

        assert_eq!(
            decoded,
            NiralisResponse::Status {
                status: DaemonStatus {
                    version: "0.1.0".to_owned(),
                    socket: "/tmp/n.sock".to_owned(),
                    default_session: "niri".to_owned(),
                    greeter_user: "niralis".to_owned(),
                }
            }
        );
    }

    #[test]
    fn serializes_get_sessions_request() {
        let encoded =
            serde_json::to_string(&NiralisRequest::GetSessions).expect("request should serialize");

        assert_eq!(encoded, r#"{"type":"get_sessions"}"#);
    }

    #[test]
    fn serializes_sessions_response() {
        let response = NiralisResponse::Sessions {
            sessions: vec![
                SessionInfo {
                    id: "niri".to_owned(),
                    name: "Niri".to_owned(),
                    kind: SessionKind::Wayland,
                },
                SessionInfo {
                    id: "plasma".to_owned(),
                    name: "Plasma".to_owned(),
                    kind: SessionKind::X11,
                },
            ],
        };

        let encoded = serde_json::to_string(&response).expect("response should serialize");

        assert_eq!(
            encoded,
            r#"{"type":"sessions","sessions":[{"id":"niri","name":"Niri","kind":"wayland"},{"id":"plasma","name":"Plasma","kind":"x11"}]}"#
        );
    }

    #[test]
    fn serializes_session_unavailable_response() {
        let response = NiralisResponse::SessionUnavailable {
            message: "session unavailable".to_owned(),
        };

        let encoded = serde_json::to_string(&response).expect("response should serialize");

        assert_eq!(
            encoded,
            r#"{"type":"session_unavailable","message":"session unavailable"}"#
        );
    }

    #[test]
    fn deserializes_session_unavailable_response() {
        let decoded: NiralisResponse = serde_json::from_str(
            r#"{"type":"session_unavailable","message":"session unavailable"}"#,
        )
        .expect("response should deserialize");

        assert_eq!(
            decoded,
            NiralisResponse::SessionUnavailable {
                message: "session unavailable".to_owned(),
            }
        );
    }
}
