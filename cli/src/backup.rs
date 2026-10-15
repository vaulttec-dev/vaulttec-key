//! A backup file: every entry and blob on the key, each sealed by the device itself
//! under a key made from a passphrase, so the file opens on any key that is told the
//! passphrase - and on nothing else. Making one, this side never sees inside an item;
//! it keeps them in the order they came out, which is the order the device will take
//! them. Restoring, it has the passphrase, and opens them (`import`).
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

/// What a backup holds: the items, and the sectors of the board's passkeys.
pub struct Exported {
    pub items: usize,
    pub sectors: usize,
}

impl Exported {
    /// "50 items" or "50 items and the passkeys", for the line that reports it.
    pub fn describe(&self) -> String {
        let items = format!(
            "{} item{}",
            self.items,
            if self.items == 1 { "" } else { "s" }
        );
        if self.sectors == 0 {
            items
        } else {
            format!("{items} and the passkeys")
        }
    }
}

/// Every item off the device into `path`, and the passkeys after them on a board that
/// keeps them. Nothing is written until the last one is in hand, so a refused tap or a
/// pulled cable leaves no half file behind; and before saying it is done, this side
/// opens every one with the passphrase it was given, so a file that would not open is
/// never reported as a backup.
pub fn export(dev: &mut Device, path: &Path, pass: Passphrase<'_>) -> Result<Exported, Error> {
    let path = &target(path)?;
    let head = dev.export_begin(pass)?;
    let mut items = Vec::new();
    while let Some(item) = dev.export_next()? {
        items.push(item);
    }
    let mut mem = vec![Block::new(); KDF_BLOCKS];
    let key = vault::backup_key(pass, &head.salt, head.cost, &mut mem)
        .ok_or_else(|| Error::Value("the backup's key cannot be made here".into()))?;
    let mut exported = Exported {
        items: 0,
        sectors: 0,
    };
    for (i, sealed) in (0u32..).zip(&items) {
        match open_item(&key, i, sealed) {
            Some(Incoming::Region(_)) => exported.sectors += 1,
            Some(_) => exported.items += 1,
            None => {
                return Err(Error::Value(
                    "the key's backup does not open with the passphrase; nothing was written"
                        .into(),
                ));
            }
        }
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
    Ok(exported)
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
    self, BACKUP_AAD, Block, CryptoRng, KDF_BLOCKS, NONCE_LEN, REGION_AAD, RngCore, TAG_LEN,
};
use zeroize::Zeroizing;

use crate::item::{Item, OwnedField};

struct BackupRng {
    failed: bool,
}

impl BackupRng {
    fn new() -> Self {
        Self { failed: false }
    }
}

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
        if getrandom::getrandom(dest).is_err() {
            self.failed = true;
        }
    }
}

impl CryptoRng for BackupRng {}

/// `vkey auth`'s category, and its kind in a backup older than items: the login secret
/// it served, removed 2026-10-15 (restorable from 4bd49f3). An older backup may still
/// hold one. Nothing here uses it any more and the device refuses its category, so a
/// restore leaves it in the file and says so.
const RETIRED_AUTH: u8 = 201;
const RETIRED_AUTH_KIND: [u8; 4] = [4, 0, 0, 0];

/// One backup item as this side reads it: what goes back on the key, as the plaintext
/// the device packed - `category | name_len | name | item` - a sector of the board's
/// passkeys, or a retired item's name.
enum Incoming {
    Keep(Zeroizing<Vec<u8>>),
    Region(Zeroizing<Vec<u8>>),
    Retired(String),
}

/// Where item `item_idx` sits in the file, as its seal binds it: after `BACKUP_AAD` for
/// an item, `REGION_AAD` for a sector.
fn aad(prefix: &[u8], item_idx: u32) -> Vec<u8> {
    let mut aad = prefix.to_vec();
    aad.extend_from_slice(&item_idx.to_le_bytes());
    aad
}

/// Item `item_idx` opened, and converted when it comes from a backup written before
/// items existed. None when it does not open or parse.
fn open_item(key: &[u8; vault::KEY_LEN], item_idx: u32, sealed: &[u8]) -> Option<Incoming> {
    let mut buf = Zeroizing::new(sealed.to_vec());
    let Some(n) = vault::open_in_place(key, &aad(BACKUP_AAD, item_idx), &mut buf) else {
        // Not an item: a sector of the passkeys, or nothing this key opens.
        let mut buf = Zeroizing::new(sealed.to_vec());
        let n = vault::open_in_place(key, &aad(REGION_AAD, item_idx), &mut buf)?;
        return Some(Incoming::Region(Zeroizing::new(
            buf[NONCE_LEN..NONCE_LEN + n].to_vec(),
        )));
    };
    let plain = &buf[NONCE_LEN..NONCE_LEN + n];

    if let Some((&category, rest)) = plain.split_first()
        && let Some((name, body)) = Name::take(rest)
    {
        // Before the body is parsed: its own category byte is the retired one too, and
        // the parser refuses a category it cannot name. No legacy kind is 201.
        if category == RETIRED_AUTH {
            return Some(retired(name));
        }
        if CoreItem::parse(body).is_some() && Category::from_wire(category).is_some() {
            return Some(Incoming::Keep(Zeroizing::new(plain.to_vec())));
        }
    }

    // Legacy format: Kind::WIRE_LEN (4) | name_len u8 | name | secret
    let (kind_bytes, rest) = plain.split_first_chunk::<4>()?;
    let (name, secret) = Name::take(rest)?;
    if *kind_bytes == RETIRED_AUTH_KIND {
        return Some(retired(name));
    }
    let item = match *kind_bytes {
        [1, algo, digits, period] => {
            let params = Params::from_wire([algo, digits, period])?;
            Item::new(Category::Login).with(crate::totp::seed_field(params, secret).ok()?)
        }
        [2, 0, 0, 0] => {
            let (&login_len, rest) = secret.split_first()?;
            let (login, rest) = rest.split_at_checked(usize::from(login_len))?;
            let (&pw_len, note) = rest.split_first()?;
            let (password, note) = note.split_at_checked(usize::from(pw_len))?;
            let (Ok(login), Ok(password), Ok(note)) = (
                std::str::from_utf8(login),
                std::str::from_utf8(password),
                std::str::from_utf8(note),
            ) else {
                return None;
            };
            crate::device::login_item(login, password, note).ok()?
        }
        [3, 0, 0, 0] => Item::new(Category::Env).with(OwnedField::new(
            Class::Secret,
            FieldKind::String,
            ".env",
            secret,
        )),
        _ => return None,
    };

    let packed = item.pack().ok()?;
    let name_bytes = name.as_bytes();
    let name_len = u8::try_from(name_bytes.len()).ok()?;
    let mut new_plain = Zeroizing::new(Vec::with_capacity(2 + name_bytes.len() + packed.len()));
    new_plain.push(item.category.wire());
    new_plain.push(name_len);
    new_plain.extend_from_slice(name_bytes);
    new_plain.extend_from_slice(&packed);
    Some(Incoming::Keep(new_plain))
}

fn retired(name: Name<'_>) -> Incoming {
    Incoming::Retired(format!(
        "{}: a `vkey auth` login secret, which vkey no longer has",
        String::from_utf8_lossy(name.as_bytes())
    ))
}

/// `plain` sealed as backup item `item_idx`, as the device would have sealed it.
fn seal_item(key: &[u8; vault::KEY_LEN], item_idx: u32, plain: &[u8]) -> Result<Vec<u8>, Error> {
    seal_at(key, &aad(BACKUP_AAD, item_idx), plain)
}

fn seal_at(key: &[u8; vault::KEY_LEN], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    let total = plain.len();
    let mut out = vec![0u8; NONCE_LEN + total + TAG_LEN];
    out[NONCE_LEN..NONCE_LEN + total].copy_from_slice(plain);
    let mut rng = BackupRng::new();
    let sealed = vault::seal_in_place(key, &mut rng, aad, &mut out, total);
    if rng.failed {
        return Err(Error::Value("no randomness from OS".into()));
    }
    out.truncate(sealed.ok_or(Error::BadArg)?);
    Ok(out)
}

/// Every item in `path` onto the device; how many there were. This side holds the
/// passphrase too, so it opens each item on the way: an item from a backup written
/// before items existed is converted, because the device no longer speaks that shape,
/// and a retired one is left out. What remains is sealed again in its new position -
/// the position is in the seal, and an item left out moves every later one up. A file
/// that does not open here goes as it is, for the device to refuse.
pub fn import(dev: &mut Device, path: &Path, pass: Passphrase<'_>) -> Result<Restored, Error> {
    let (head, items) = read(&source(path)?)?;
    let passkeys = keeps_passkeys(dev)?;
    let mut mem = vec![Block::new(); KDF_BLOCKS];
    let prepared = match vault::backup_key(pass, &head.salt, head.cost, &mut mem) {
        Some(key) => prepare(&key, items, passkeys)?,
        None => Restored {
            count: items.len(),
            blobs: items,
            skipped: Vec::new(),
            passkeys: false,
        },
    };

    dev.import_begin(pass, head)?;
    for blob in &prepared.blobs {
        dev.import_item(blob)?;
    }
    dev.import_end()?;
    Ok(prepared)
}

/// The items called `names` out of the backup at `path`, put on the key beside what it
/// holds, under the PIN: a restore of a few things that replaces nothing. An item the
/// key already has under that name is refused, never overwritten. The names put on.
pub fn pick(
    dev: &mut Device,
    path: &Path,
    pass: Passphrase<'_>,
    names: &[String],
) -> Result<Vec<String>, Error> {
    let (head, blobs) = read(&source(path)?)?;
    let mut mem = vec![Block::new(); KDF_BLOCKS];
    let key = vault::backup_key(pass, &head.salt, head.cost, &mut mem)
        .ok_or_else(|| Error::Value("the backup's key cannot be made here".into()))?;
    let mut found = Vec::new();
    for (i, sealed) in (0u32..).zip(&blobs) {
        let Some(incoming) = open_item(&key, i, sealed) else {
            return Err(Error::Value(format!(
                "{} does not open with that passphrase",
                path.display()
            )));
        };
        let Incoming::Keep(plain) = incoming else {
            continue;
        };
        let Some((_, rest)) = plain.split_first() else {
            continue;
        };
        let Some((name, body)) = Name::take(rest) else {
            continue;
        };
        let name = String::from_utf8_lossy(name.as_bytes()).into_owned();
        if names.contains(&name) {
            found.push((name, Item::unpack(body)?));
        }
    }
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| !found.iter().any(|(f, _)| f == *n))
        .collect();
    if !missing.is_empty() {
        return Err(Error::Value(format!(
            "not in {}: {}; nothing was added",
            path.display(),
            missing
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    for (name, item) in &found {
        dev.put(name, item, false)?;
    }
    Ok(found.into_iter().map(|(name, _)| name).collect())
}

/// Whether the board on the other end keeps passkeys, as its folder says.
fn keeps_passkeys(dev: &mut Device) -> Result<bool, Error> {
    let version = dev.info()?;
    Ok(version
        .rsplit(' ')
        .next()
        .and_then(crate::boards::by_name)
        .is_some_and(|b| b.passkeys))
}

/// The items and the passkeys as the device takes them back - the passkeys only on a
/// board that keeps them - and the names of what is left out.
fn prepare(
    key: &[u8; vault::KEY_LEN],
    items: Vec<Vec<u8>>,
    passkeys: bool,
) -> Result<Restored, Error> {
    let opened = (0u32..)
        .zip(&items)
        .map(|(i, sealed)| open_item(key, i, sealed))
        .collect::<Option<Vec<Incoming>>>();
    let Some(opened) = opened else {
        return Ok(Restored {
            count: items.len(),
            blobs: items,
            skipped: Vec::new(),
            passkeys: false,
        });
    };
    let mut out = Restored {
        count: 0,
        blobs: Vec::with_capacity(opened.len()),
        skipped: Vec::new(),
        passkeys: false,
    };
    let mut sectors_left = 0;
    for item in opened {
        let at = u32::try_from(out.blobs.len()).map_err(|_| Error::BadArg)?;
        match item {
            Incoming::Keep(plain) => {
                out.blobs.push(seal_item(key, at, &plain)?);
                out.count += 1;
            }
            Incoming::Region(plain) if passkeys => {
                out.blobs.push(seal_at(key, &aad(REGION_AAD, at), &plain)?);
                out.passkeys = true;
            }
            Incoming::Region(_) => sectors_left += 1,
            Incoming::Retired(name) => out.skipped.push(name),
        }
    }
    if sectors_left > 0 {
        out.skipped
            .push("the passkeys: this board does not keep passkeys".to_string());
    }
    Ok(out)
}

/// What a restore did: how many items are on the key, whether the passkeys went back
/// too - the key then restarts to load them - and what the file held that this board
/// could not take: the passkeys on one without them, a retired `vkey auth` secret from
/// an older backup.
pub struct Restored {
    pub count: usize,
    pub passkeys: bool,
    pub skipped: Vec<String>,
    /// The sealed items and sectors as they went to the device.
    blobs: Vec<Vec<u8>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_login_with_invalid_utf8_fails_conversion() {
        let key = [42u8; vault::KEY_LEN];
        let item_idx = 0u32;
        let mut aad = [0u8; BACKUP_AAD.len() + 4];
        aad[..BACKUP_AAD.len()].copy_from_slice(BACKUP_AAD);
        aad[BACKUP_AAD.len()..].copy_from_slice(&item_idx.to_le_bytes());

        // Kind [2, 0, 0, 0], name "test", login [0xFF, 0xFF] (invalid utf8), password "pw", note "n"
        let name = b"test";
        let name_len = u8::try_from(name.len()).expect("fits");
        let mut plain = vec![2u8, 0, 0, 0];
        plain.push(name_len);
        plain.extend_from_slice(name);
        plain.push(2); // login len
        plain.extend_from_slice(&[0xFF, 0xFF]); // invalid UTF-8 login
        plain.push(2); // pw len
        plain.extend_from_slice(b"pw");
        plain.extend_from_slice(b"n"); // note

        let total = plain.len();
        let mut sealed = vec![0u8; NONCE_LEN + total + TAG_LEN];
        sealed[NONCE_LEN..NONCE_LEN + total].copy_from_slice(&plain);
        let mut rng = BackupRng::new();
        let sealed_len =
            vault::seal_in_place(&key, &mut rng, &aad, &mut sealed, total).expect("seals");
        sealed.truncate(sealed_len);

        let res = open_item(&key, item_idx, &sealed);
        assert!(res.is_none(), "invalid UTF-8 in login must fail conversion");

        // Invalid UTF-8 in note
        let mut plain2 = vec![2u8, 0, 0, 0];
        plain2.push(name_len);
        plain2.extend_from_slice(name);
        plain2.push(4); // login len
        plain2.extend_from_slice(b"user");
        plain2.push(2); // pw len
        plain2.extend_from_slice(b"pw");
        plain2.extend_from_slice(&[0xFE, 0xFE]); // invalid UTF-8 note

        let total2 = plain2.len();
        let mut sealed2 = vec![0u8; NONCE_LEN + total2 + TAG_LEN];
        sealed2[NONCE_LEN..NONCE_LEN + total2].copy_from_slice(&plain2);
        let sealed_len2 =
            vault::seal_in_place(&key, &mut rng, &aad, &mut sealed2, total2).expect("seals");
        sealed2.truncate(sealed_len2);

        let res2 = open_item(&key, item_idx, &sealed2);
        assert!(res2.is_none(), "invalid UTF-8 in note must fail conversion");

        // Valid legacy login
        let mut plain3 = vec![2u8, 0, 0, 0];
        plain3.push(name_len);
        plain3.extend_from_slice(name);
        plain3.push(4); // login len
        plain3.extend_from_slice(b"user");
        plain3.push(2); // pw len
        plain3.extend_from_slice(b"pw");
        plain3.extend_from_slice(b"note");

        let total3 = plain3.len();
        let mut sealed3 = vec![0u8; NONCE_LEN + total3 + TAG_LEN];
        sealed3[NONCE_LEN..NONCE_LEN + total3].copy_from_slice(&plain3);
        let sealed_len3 =
            vault::seal_in_place(&key, &mut rng, &aad, &mut sealed3, total3).expect("seals");
        sealed3.truncate(sealed_len3);

        let res3 = open_item(&key, item_idx, &sealed3);
        assert!(
            matches!(res3, Some(Incoming::Keep(_))),
            "valid legacy login must convert"
        );
    }

    /// `category | name_len | name | item` for an item of `category` holding one field.
    fn backup_plain(category: u8, name: &str, body_category: u8) -> Vec<u8> {
        let mut plain = vec![category, u8::try_from(name.len()).expect("fits")];
        plain.extend_from_slice(name.as_bytes());
        // An item of no fields: `category | count`.
        plain.extend_from_slice(&[body_category, 0]);
        plain
    }

    #[test]
    fn a_retired_auth_item_is_left_out_and_the_rest_move_up() {
        let key = [7u8; vault::KEY_LEN];
        let login = Category::Login.wire();
        let env = Category::Env.wire();
        let file = [
            backup_plain(login, "github", login),
            backup_plain(RETIRED_AUTH, "hifes@pop-os", RETIRED_AUTH),
            backup_plain(env, "app", env),
        ];
        let sealed: Vec<Vec<u8>> = (0u32..)
            .zip(&file)
            .map(|(i, p)| seal_item(&key, i, p).expect("seals"))
            .collect();

        let Restored {
            blobs: items,
            skipped,
            ..
        } = prepare(&key, sealed, true).expect("prepares");
        assert_eq!(items.len(), 2, "the auth secret stays in the file");
        assert_eq!(skipped.len(), 1, "and is named: {skipped:?}");
        assert!(skipped[0].starts_with("hifes@pop-os:"), "{skipped:?}");
        for (i, (item, want)) in (0u32..).zip(items.iter().zip([&file[0], &file[2]])) {
            let Some(Incoming::Keep(plain)) = open_item(&key, i, item) else {
                panic!("item {i} opens at its new position");
            };
            assert_eq!(
                plain.as_slice(),
                want.as_slice(),
                "item {i} unchanged inside"
            );
        }
    }

    #[test]
    fn a_file_that_does_not_open_here_goes_as_it_is() {
        let key = [7u8; vault::KEY_LEN];
        let login = Category::Login.wire();
        let sealed =
            vec![seal_item(&key, 0, &backup_plain(login, "github", login)).expect("seals")];
        let out = prepare(&[8u8; vault::KEY_LEN], sealed.clone(), true).expect("prepares");
        assert_eq!(
            out.blobs, sealed,
            "a wrong passphrase is the device's to refuse"
        );
        assert!(out.skipped.is_empty());
    }

    #[test]
    fn passkeys_move_up_behind_the_items_or_stay_in_the_file() {
        let key = [7u8; vault::KEY_LEN];
        let login = Category::Login.wire();
        let sector = vec![0x5A; 16];
        let file = [
            seal_item(
                &key,
                0,
                &backup_plain(RETIRED_AUTH, "hifes@pop-os", RETIRED_AUTH),
            )
            .expect("seals"),
            seal_item(&key, 1, &backup_plain(login, "github", login)).expect("seals"),
            seal_at(&key, &aad(REGION_AAD, 2), &sector).expect("seals"),
        ];

        let out = prepare(&key, file.to_vec(), true).expect("prepares");
        assert_eq!((out.count, out.passkeys, out.blobs.len()), (1, true, 2));
        let Some(Incoming::Region(plain)) = open_item(&key, 1, &out.blobs[1]) else {
            panic!("the sector opens one place up, under the sectors' associated data");
        };
        assert_eq!(plain.as_slice(), sector.as_slice());

        let out = prepare(&key, file.to_vec(), false).expect("prepares");
        assert_eq!((out.count, out.passkeys, out.blobs.len()), (1, false, 1));
        assert!(
            out.skipped.iter().any(|s| s.starts_with("the passkeys")),
            "a board without passkeys takes the items and names what it leaves: {:?}",
            out.skipped
        );
    }
}
