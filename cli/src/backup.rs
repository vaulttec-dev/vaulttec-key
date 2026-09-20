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

use vaultkey_core::item::{Category, Class, FieldKind, Item as CoreItem};
use vaultkey_core::oath::{Name, Params};
use vaultkey_core::vault::{
    self, BACKUP_AAD, Block, CryptoRng, KDF_BLOCKS, NONCE_LEN, RngCore, TAG_LEN,
};

use crate::item::{Item, OwnedField};

struct BackupRng;

impl RngCore for BackupRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS entropy is available");
    }
}

impl CryptoRng for BackupRng {}

fn convert_legacy_item(
    key: &[u8; vault::KEY_LEN],
    item_idx: u32,
    sealed: &[u8],
) -> Option<Vec<u8>> {
    let mut aad = [0u8; BACKUP_AAD.len() + 4];
    aad[..BACKUP_AAD.len()].copy_from_slice(BACKUP_AAD);
    aad[BACKUP_AAD.len()..].copy_from_slice(&item_idx.to_le_bytes());

    let mut buf = sealed.to_vec();
    let n = vault::open_in_place(key, &aad, &mut buf)?;
    let plain = &buf[NONCE_LEN..NONCE_LEN + n];

    // Already v2?
    if let Some((&category, rest)) = plain.split_first()
        && let Some((_, body)) = Name::take(rest)
        && CoreItem::parse(body).is_some()
        && Category::from_wire(category).is_some()
    {
        return Some(sealed.to_vec());
    }

    // Legacy format: Kind::WIRE_LEN (4) | name_len u8 | name | secret
    let (kind_bytes, rest) = plain.split_first_chunk::<4>()?;
    let (name, secret) = Name::take(rest)?;
    let item = match *kind_bytes {
        [1, algo, digits, period] => {
            let params = Params::from_wire([algo, digits, period])?;
            let sf = crate::totp::seed_field(params, secret).ok()?;
            Item::new(Category::Login).with(sf)
        }
        [2, 0, 0, 0] => {
            let (&login_len, rest) = secret.split_first()?;
            let (login, rest) = rest.split_at_checked(usize::from(login_len))?;
            let (&pw_len, note) = rest.split_first()?;
            let (password, note) = note.split_at_checked(usize::from(pw_len))?;
            crate::device::login_item(
                std::str::from_utf8(login).ok()?,
                std::str::from_utf8(password).ok()?,
                std::str::from_utf8(note).ok()?,
            )
            .ok()?
        }
        [3, 0, 0, 0] => Item::new(Category::Env).with(OwnedField::new(
            Class::Secret,
            FieldKind::String,
            ".env",
            secret,
        )),
        [4, 0, 0, 0] => Item::new(Category::Auth).with(OwnedField::new(
            Class::Secret,
            FieldKind::Concealed,
            "seed",
            secret,
        )),
        _ => return None,
    };

    let packed = item.pack().ok()?;
    let name_bytes = name.as_bytes();
    let name_len = u8::try_from(name_bytes.len()).ok()?;
    let mut new_plain = Vec::with_capacity(2 + name_bytes.len() + packed.len());
    new_plain.push(item.category.wire());
    new_plain.push(name_len);
    new_plain.extend_from_slice(name_bytes);
    new_plain.extend_from_slice(&packed);

    let total = new_plain.len();
    let mut out_buf = vec![0u8; NONCE_LEN + total + TAG_LEN];
    out_buf[NONCE_LEN..NONCE_LEN + total].copy_from_slice(&new_plain);
    let sealed_len = vault::seal_in_place(key, &mut BackupRng, &aad, &mut out_buf, total)?;
    out_buf.truncate(sealed_len);
    Some(out_buf)
}

/// Every item in `path` onto the device; how many there were. The items go back sealed,
/// and the device opens them - except for a backup written before items existed, which
/// this side converts first, because the device no longer speaks the old shape.
pub fn import(dev: &mut Device, path: &Path, pass: Passphrase<'_>) -> Result<Restored, Error> {
    let (head, items) = read(&source(path)?)?;
    let mut mem = vec![Block::new(); KDF_BLOCKS];
    let key = vault::backup_key(pass, &head.salt, head.cost, &mut mem);
    let converted: Vec<Vec<u8>> = match key {
        Some(k) => items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let idx = u32::try_from(i).unwrap_or(0);
                convert_legacy_item(&k, idx, item).unwrap_or_else(|| item.clone())
            })
            .collect(),
        None => items,
    };

    dev.import_begin(pass, head)?;
    for item in &converted {
        dev.import_item(item)?;
    }
    dev.import_end()?;
    Ok(Restored {
        count: converted.len(),
        skipped: Vec::new(),
    })
}

/// What a restore did: how many items are on the key, and what the file held that this
/// build could not store. Nothing is left behind by a backup this version wrote; the
/// field is what a caller prints when one is.
pub struct Restored {
    pub count: usize,
    pub skipped: Vec<String>,
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
