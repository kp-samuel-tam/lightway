use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Verifies whether input `path` points to a valid configuration file
/// present in filesystem.
pub fn validate_configuration_file_path(path: &PathBuf) -> Result<()> {
    let metadata = fs::metadata(path)?;

    // Check whether it is a file and not a directory
    if !metadata.is_file() {
        return Err(anyhow!("Not a file"));
    }

    Ok(())
}
