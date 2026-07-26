use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct WorkerSecret(Zeroizing<String>);

/// Secret supplied to a login transaction. It is intentionally opaque and
/// single-owner; callers must consume it when handing it to authentication.
pub struct LoginSecret(Zeroizing<String>);

impl LoginSecret {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }
    pub fn consume(self) -> Zeroizing<String> {
        self.0
    }
}

impl From<LoginSecret> for WorkerSecret {
    fn from(secret: LoginSecret) -> Self {
        Self(secret.consume())
    }
}

impl WorkerSecret {
    pub fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for WorkerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkerSecret(\"[redacted]\")")
    }
}

impl Serialize for WorkerSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for WorkerSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}
