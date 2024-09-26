use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

use anyhow::{anyhow, Result};

/// Verifies whether input `path` points to a valid configuration file
/// present in filesystem. Validates that the ownership permissions
/// are acceptable.
pub fn validate_configuration_file_path(path: &PathBuf) -> Result<()> {
    let metadata = fs::metadata(path)?;

    // Check whether it is a file and not a directory
    if !metadata.is_file() {
        return Err(anyhow!("Not a file"));
    }

    let mode = metadata.permissions().mode();
    if mode & 0o007 != 0 {
        return Err(anyhow!("Configuration file is world accessible"));
    }

    Ok(())
}
