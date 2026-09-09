//! A backup file: every entry and blob on the key, each sealed by the device itself
//! under a key made from a passphrase, so the file opens on any key that is told the
//! passphrase - and on nothing else. This side never sees inside an item; it keeps
//! them in the order they came out, which is the order the device will take them.
//!
//! ```text
//! "VKB1" | salt(16) | m_kib u32le | t u32le | count u32le | (len u16le | item)*
//! ```
//!
//! The head is what the device needs to make the key again; the count is how a
//! truncated file is told from a complete one.

use std::path::{Path, PathBuf};

use crate::device::{BackupHead, Device, Error, Passphrase};

const MAGIC: &[u8; 4] = b"VKB1";
const FIXED: usize = MAGIC.len() + BackupHead::WIRE_LEN + 4;

/// The file a backup goes to: `path` itself, or `vault.vkb` inside it when `path`
/// is a directory. Checked before the device is asked for anything - a wrong path
/// found after two taps would waste them.
pub fn target(path: &Path) -> Result<PathBuf, Error> {
    let file = if path.is_dir() {
        path.join("vault.vkb")
    } else {
        path.to_path_buf()
    };
    let parent = file.parent().filter(|p| !p.as_os_str().is_empty());
    if parent.is_some_and(|p| !p.is_dir()) {
        return Err(Error::Value(format!(
            "cannot write {}: no such directory",
            file.display()
        )));
    }
    Ok(file)
}

/// Every item off the device into `path`; how many there were. Nothing is written
/// until the last item is in hand, so a refused tap or a pulled cable leaves no
/// half file behind.
pub fn export(dev: &mut Device, path: &Path, pass: Passphrase<'_>) -> Result<usize, Error> {
    let path = &target(path)?;
    let head = dev.export_begin(pass)?;
    let mut items = Vec::new();
    while let Some(item) = dev.export_next()? {
        items.push(item);
    }
    let count = u32::try_from(items.len()).map_err(|_| Error::BadArg)?;
    let mut file = Vec::with_capacity(FIXED + items.iter().map(|i| 2 + i.len()).sum::<usize>());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&head.wire());
    file.extend_from_slice(&count.to_le_bytes());
    for item in &items {
        let len = u16::try_from(item.len()).map_err(|_| Error::BadArg)?;
        file.extend_from_slice(&len.to_le_bytes());
        file.extend_from_slice(item);
    }
    write_private(path, &file)
        .map_err(|e| Error::Value(format!("cannot write {}: {e}", path.display())))?;
    Ok(items.len())
}

/// Written readable by the owner alone where the filesystem has owners: the file
/// needs the passphrase, but a backup is not something to leave world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    open.open(path)?.write_all(bytes)
}

/// The file a restore reads: `path` itself, or `vault.vkb` inside it when `path` is a
/// directory; it must exist. Checked before the passphrase is asked for.
pub fn source(path: &Path) -> Result<PathBuf, Error> {
    let file = if path.is_dir() {
        path.join("vault.vkb")
    } else {
        path.to_path_buf()
    };
    if !file.is_file() {
        return Err(Error::Value(format!(
            "cannot read {}: no such file",
            file.display()
        )));
    }
    Ok(file)
}

/// Every item in `path` onto the device; how many there were. The device decides what
/// each item means: an entry of the same name is replaced, and one of the other kind
/// makes way.
pub fn import(dev: &mut Device, path: &Path, pass: Passphrase<'_>) -> Result<usize, Error> {
    let (head, items) = read(&source(path)?)?;
    dev.import_begin(pass, head)?;
    for item in &items {
        dev.import_item(item)?;
    }
    dev.import_end()?;
    Ok(items.len())
}

/// The file's head and items, checked for shape only: what is inside an item is the
/// device's to judge.
fn read(path: &Path) -> Result<(BackupHead, Vec<Vec<u8>>), Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Value(format!("cannot read {}: {e}", path.display())))?;
    let bad = || Error::Value(format!("{} is not a vkey backup", path.display()));
    let rest = bytes.strip_prefix(MAGIC).ok_or_else(bad)?;
    let (head, rest) = rest
        .split_first_chunk::<{ BackupHead::WIRE_LEN }>()
        .ok_or_else(bad)?;
    let head = BackupHead::from_wire(*head).ok_or_else(bad)?;
    let (count, mut rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
    let count = usize::try_from(u32::from_le_bytes(*count)).map_err(|_| bad())?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, tail) = rest.split_first_chunk::<2>().ok_or_else(bad)?;
        let (item, tail) = tail
            .split_at_checked(usize::from(u16::from_le_bytes(*len)))
            .ok_or_else(bad)?;
        items.push(item.to_vec());
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok((head, items))
}
