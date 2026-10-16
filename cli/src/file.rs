//! A file replaced whole, never half-written.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::device::Error;

/// `path` replaced whole: written beside it and renamed over it, so a crash leaves the
/// old file or the new one - for a PAM file, never half of `sudo`'s configuration; for
/// the source map or an `op` cache, never a file that no longer parses.
pub fn replace(path: &Path, contents: &[u8], mode: u32) -> Result<(), Error> {
    let mut tmp = path.as_os_str().to_owned();
    // Per process: two vkeys replacing the same file must not write into one another's.
    tmp.push(format!(".vkey-new.{}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    // The mode given at creation is narrowed by the umask; this is the mode meant.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}
