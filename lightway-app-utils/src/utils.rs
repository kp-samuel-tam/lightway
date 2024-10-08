use std::path::PathBuf;

use anyhow::Result;
use fs_mistrust::Mistrust;

/// Specifies the limits which `validate_configuration_file_path`
/// should enforce.
pub enum Validate {
    /// Ensure that only the file's owner can access (read or write)
    OwnerOnly,
    /// Ensure that only the file's owner can write but allow anyone
    /// to read
    AllowWorldRead,
}

/// Verifies whether input `path` points to a valid configuration file
/// present in filesystem. Validates that the ownership permissions
/// are acceptable.
pub fn validate_configuration_file_path(path: &PathBuf, validate: Validate) -> Result<()> {
    let mistrust = Mistrust::builder()
        .controlled_by_env_var("LW_DANGEROUSLY_DISABLE_PERMISSIONS_CHECKS")
        .build()?;

    let verifier = mistrust.verifier().require_file();
    let verifier = match validate {
        Validate::OwnerOnly => verifier,
        Validate::AllowWorldRead => verifier.permit_readable(),
    };

    verifier.check(path)?;
    Ok(())
}
