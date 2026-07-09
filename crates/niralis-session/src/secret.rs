use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(PartialEq, Eq)]
pub struct WorkerSecret(Zeroizing<String>);

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
