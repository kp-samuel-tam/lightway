use std::path::PathBuf;

use anyhow::Result;
use fs_mistrust::Mistrust;

/// Verifies whether input `path` points to a valid configuration file
/// present in filesystem. Validates that the ownership permissions
/// are acceptable.
pub fn validate_configuration_file_path(path: &PathBuf) -> Result<()> {
    Mistrust::builder()
        .controlled_by_env_var("LW_DANGEROUSLY_DISABLE_PERMISSIONS_CHECKS")
        .build()?
        .verifier()
        .require_file()
        .check(path)?;
    Ok(())
}
