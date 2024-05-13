use std::fs;
use std::path::PathBuf;

/// Verifies whether input `path` points to a valid
/// file present in filesystem
/// Returns bool
pub fn is_file_path_valid(path: &PathBuf) -> bool {
    let config_metadata = fs::metadata(path);
    let Ok(metadata) = config_metadata else {
        return false;
    };

    // Check whether it is a file and not a directory
    if !metadata.is_file() {
        return false;
    }
    true
}
