use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};

/// Wrapper for compatibility with both clap and twelf at the same time
#[serde_as]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Duration(#[serde_as(as = "DisplayFromStr")] humantime::Duration);

impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Duration> for std::time::Duration {
    fn from(d: Duration) -> Self {
        d.0.into()
    }
}

impl std::str::FromStr for Duration {
    type Err = humantime::DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Duration(s.parse::<humantime::Duration>()?))
    }
}
