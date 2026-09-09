//! `vkey install`: this very binary copied to ~/.local/bin/vkey. The one thing a
//! rebuild needs afterwards, so it is a command rather than a path to remember.

use crate::device::Error;

pub fn install() -> Result<(), Error> {
    let me = std::env::current_exe()?;
    let dir = dirs::home_dir()
        .ok_or_else(|| Error::Value("cannot find your home directory".into()))?
        .join(".local")
        .join("bin");
    let target = dir.join("vkey");
    std::fs::create_dir_all(&dir)?;
    // Copied under a temporary name first: a running copy at the target is never
    // half-overwritten, and the rename is atomic on the same filesystem.
    let tmp = dir.join(".vkey.new");
    std::fs::copy(&me, &tmp)?;
    std::fs::rename(&tmp, &target)?;
    println!(
        "installed vkey {} -> {}",
        env!("CARGO_PKG_VERSION"),
        target.display()
    );
    Ok(())
}
