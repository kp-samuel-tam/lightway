use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Copy, Clone, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    Default,
    Lan,
    NoExec,
}

