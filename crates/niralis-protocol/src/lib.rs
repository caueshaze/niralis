use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NiralisRequest {
    Status,
    GetUsers,
    Login {
        username: String,
        password: String,
        session: String,
    },
    Shutdown,
    Reboot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NiralisResponse {
    Status { status: DaemonStatus },
    Users { users: Vec<UserInfo> },
    LoginOk { session: SessionInfo },
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
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub username: String,
    pub session: String,
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
}
