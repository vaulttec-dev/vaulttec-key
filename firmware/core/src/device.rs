//! What the key does, independent of how bytes arrive: PIN lifecycle and entries.
//! One owner of the flash, the keys, the button, the entropy source and the chip key.

use embedded_storage::nor_flash::NorFlash;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::hal::{Clock, DeviceKey, Ui};
use crate::oath::{self, ENV_MAX, Entry, Kind, NAME_MAX, Name, SECRET_MAX, len_u8};
use crate::store::{
    ENV_BUF_LEN, ENV_SLOTS, Header, MAX_ATTEMPTS, MAX_ENTRIES, Record, State, Store, StoredName,
};
use crate::ui;
use crate::vault::{
    self, BACKUP_AAD, Block, Cost, KEY_LEN, Keys, NONCE_LEN, Passphrase, Pin, SALT_LEN,
};
use crate::wire::{BackupHead, Fail, ITEM_MAX, PinStatus};

/// Unlocked and idle this long, the device forgets the key on its own. Two minutes:
/// long enough to finish a login, short enough that a key left on the desk is a
/// locked key.
const AUTOLOCK_MS: u64 = 120_000;
const TOUCH_TIMEOUT_MS: u64 = 30_000;
/// A wipe after five seconds of red: no reflex reaches it.
const WIPE_HOLD_MS: u64 = 5_000;

/// The board's working buffer: one env blob, sealed or open, or one backup item,
/// which is a blob with a kind and a name in front and the AEAD overhead behind.
pub const BUF_LEN: usize = ITEM_MAX;
const _: () = assert!(BUF_LEN >= ENV_BUF_LEN, "the buffer holds a sealed blob");

/// A resident copy of the data key that scrubs itself when dropped.
type Dek = Zeroizing<[u8; KEY_LEN]>;

/// A backup in flight: the passphrase key, and how far it got. Ended by the last
/// item, by a lock, or by any operation that reloads the table it walks.
enum Session {
    Export {
        key: Dek,
        /// The table slot to look at next; the blobs follow the table.
        slot: usize,
        /// Items handed out so far: the next one's position in the file.
        item: u32,
    },
    Import {
        key: Dek,
        item: u32,
        /// Whether the table in RAM differs from flash: `import_end` writes it.
        dirty: bool,
    },
}

pub struct Device<'m, F: NorFlash, R: RngCore + CryptoRng, U: Ui, C: Clock, K: DeviceKey> {
    store: Store<F>,
    ui: U,
    rng: R,
    clock: C,
    key: K,
    /// The Argon2 working memory, owned by the board for the life of the program.
    mem: &'m mut [Block],
    /// The persistent state as last read from flash, owned by the board the same way:
    /// it is ~80 KiB, and passing it by value once per call level blew the stack.
    /// Every operation reloads it before looking at it.
    state: &'m mut State,
    /// The working buffer, owned by the board too: 8 KiB, held once, and scrubbed at
    /// the end of every operation that used it.
    buf: &'m mut [u8; BUF_LEN],
    dek: Option<Dek>,
    backup: Option<Session>,
    last_activity_ms: u64,
}

/// The front of the buffer, sized as the store's blob functions want it.
fn env_part(buf: &mut [u8; BUF_LEN]) -> &mut [u8; ENV_BUF_LEN] {
    let (env, _) = buf
        .split_first_chunk_mut()
        .expect("BUF_LEN >= ENV_BUF_LEN, asserted above");
    env
}

/// `BACKUP_AAD` followed by the item's position in the file.
fn item_aad(item: u32) -> [u8; BACKUP_AAD.len() + 4] {
    let mut aad = [0u8; BACKUP_AAD.len() + 4];
    aad[..BACKUP_AAD.len()].copy_from_slice(BACKUP_AAD);
    aad[BACKUP_AAD.len()..].copy_from_slice(&item.to_le_bytes());
    aad
}

/// `kind | name_len | name` at the front of an item's plaintext, which starts after
/// the nonce; how many bytes that took.
fn item_prefix(kind: Kind, name: Name<'_>, buf: &mut [u8; BUF_LEN]) -> usize {
    let name = name.as_bytes();
    let mut at = NONCE_LEN;
    buf[at..at + Kind::WIRE_LEN].copy_from_slice(&kind.wire());
    at += Kind::WIRE_LEN;
    buf[at] = len_u8(name.len());
    at += 1;
    buf[at..at + name.len()].copy_from_slice(name);
    at + name.len() - NONCE_LEN
}

impl<'m, F: NorFlash, R: RngCore + CryptoRng, U: Ui, C: Clock, K: DeviceKey>
    Device<'m, F, R, U, C, K>
{
    #[expect(
        clippy::too_many_arguments,
        reason = "the board hands over every part it owns; grouping them into a struct would only move the same list one level out"
    )]
    pub fn new(
        store: Store<F>,
        ui: U,
        rng: R,
        clock: C,
        key: K,
        mem: &'m mut [Block],
        state: &'m mut State,
        buf: &'m mut [u8; BUF_LEN],
    ) -> Self {
        let now = clock.now_ms();
        Device {
            store,
            ui,
            rng,
            clock,
            key,
            mem,
            state,
            buf,
            dek: None,
            backup: None,
            last_activity_ms: now,
        }
    }

    // --- lock state -------------------------------------------------------------

    /// Call once per request: enforces the idle timeout before anything else runs.
    pub fn tick(&mut self) {
        if self.dek.is_some()
            && self.clock.now_ms().saturating_sub(self.last_activity_ms) > AUTOLOCK_MS
        {
            self.lock();
        }
    }

    fn touch(&mut self) {
        self.last_activity_ms = self.clock.now_ms();
    }

    pub fn lock(&mut self) {
        self.dek = None; // Zeroizing scrubs it on drop
        self.backup = None;
        self.buf.zeroize();
    }

    /// Factory reset: every secret and the PIN. Confirmed by the longest hold, never
    /// by the tap that approves a code. Whoever holds the key can empty it anyway
    /// (eight wrong PINs, or the flash tools); this protects the owner who did not
    /// mean to.
    pub fn wipe(&mut self) -> Result<(), Fail> {
        if !ui::await_hold(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS, WIPE_HOLD_MS) {
            return Err(Fail::Refused);
        }
        self.lock();
        self.store.wipe().map_err(|_| Fail::Internal)
    }

    /// A private copy of the key for one operation; gone when the operation is.
    fn dek(&self) -> Result<Dek, Fail> {
        self.dek
            .as_ref()
            .map(|d| Zeroizing::new(**d))
            .ok_or(Fail::Locked)
    }

    /// The persistent state into `self.state`. Unreadable flash is an error, never
    /// "empty": nothing gets written over it without `wipe`. A backup in flight
    /// walks the table as it was when it began; reloading ends it.
    fn load(&mut self) -> Result<(), Fail> {
        self.backup = None;
        self.store.load(self.state).map_err(|_| Fail::Internal)
    }

    // --- PIN ----------------------------------------------------------------------

    /// Asked every second by the shell's status row: answered from the image heads
    /// and the attempt words alone, never a full load.
    pub fn pin_status(&mut self) -> PinStatus {
        let has_pin = self.store.has_pin().unwrap_or(false);
        let used = self.store.attempts_used().unwrap_or(MAX_ATTEMPTS);
        PinStatus {
            has_pin,
            unlocked: self.dek.is_some(),
            retries_left: if has_pin {
                MAX_ATTEMPTS - used
            } else {
                MAX_ATTEMPTS
            },
            chip_bound: self.key.bound(),
        }
    }

    fn derive(&mut self, pin: Pin<'_>, salt: &[u8; SALT_LEN], cost: Cost) -> Result<Keys, Fail> {
        vault::derive(pin, salt, cost, &mut self.key, self.mem).ok_or(Fail::Internal)
    }

    /// New salt and verifier for `pin` into the state, `env_key` sealed under the new
    /// dek next to them, and the resident key switched to match. The caller saves the
    /// state; until it does, flash still holds the old PIN.
    fn install_pin(&mut self, pin: Pin<'_>, env_key: &[u8; KEY_LEN]) -> Result<(), Fail> {
        let mut salt = [0u8; SALT_LEN];
        self.rng.fill_bytes(&mut salt);
        let keys = self.derive(pin, &salt, Cost::CURRENT)?;
        let mut wrapped = [0u8; KEY_LEN + vault::OVERHEAD];
        vault::seal(
            &keys.dek,
            &mut self.rng,
            vault::ENV_KEY_AAD,
            env_key,
            &mut wrapped,
        )
        .ok_or(Fail::Internal)?;
        self.state.header = Some(Header {
            salt,
            cost: Cost::CURRENT,
            bound: self.key.bound(),
            verifier: vault::verifier_of(&keys.kek),
            env_key: wrapped,
        });
        self.dek = Some(Zeroizing::new(keys.dek));
        Ok(())
    }

    /// The env key out of the loaded header, under `dek`.
    fn unwrap_env_key(&self, dek: &[u8; KEY_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>, Fail> {
        let hdr = self.state.header.ok_or(Fail::NoPin)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        vault::open(dek, vault::ENV_KEY_AAD, &hdr.env_key, &mut *key).ok_or(Fail::Internal)?;
        Ok(key)
    }

    pub fn pin_set(&mut self, pin: Pin<'_>) -> Result<(), Fail> {
        self.load()?;
        if self.state.header.is_some() {
            return Err(Fail::PinExists);
        }
        self.store.reset_attempts().map_err(|_| Fail::Internal)?;
        let mut env_key = Zeroizing::new([0u8; KEY_LEN]);
        self.rng.fill_bytes(&mut *env_key);
        self.install_pin(pin, &env_key)?;
        if self.store.save(self.state).is_err() {
            self.lock();
            return Err(Fail::Internal);
        }
        self.touch();
        Ok(())
    }

    pub fn pin_unlock(&mut self, pin: Pin<'_>) -> Result<(), Fail> {
        self.load()?;
        let Some(hdr) = self.state.header else {
            return Err(Fail::NoPin);
        };
        // A vault from a firmware with the other key setup would fail every PIN;
        // say so instead of spending the attempts.
        if hdr.bound != self.key.bound() {
            return Err(Fail::Incompatible);
        }
        let used = self.store.attempts_used().map_err(|_| Fail::Internal)?;
        if used >= MAX_ATTEMPTS {
            // Should have been wiped already; make sure.
            self.lock();
            let _ = self.store.wipe();
            return Err(Fail::Wiped);
        }
        // Spend the attempt before checking, so a power cut during the check cannot
        // be used to try for free. Restored to the maximum only after success.
        let used = self.store.spend_attempt().map_err(|_| Fail::Internal)?;

        let keys = self.derive(pin, &hdr.salt, hdr.cost)?;
        if !vault::verifier_matches(&keys.kek, &hdr.verifier) {
            if used >= MAX_ATTEMPTS {
                self.lock();
                let _ = self.store.wipe();
                return Err(Fail::Wiped);
            }
            return Err(Fail::WrongPin(MAX_ATTEMPTS - used));
        }
        // The counter reset must land before the device counts as unlocked: if it
        // fails, the device stays locked rather than unlocked-with-an-error.
        self.lock();
        self.store.reset_attempts().map_err(|_| Fail::Internal)?;
        self.dek = Some(Zeroizing::new(keys.dek));
        self.touch();
        Ok(())
    }

    /// Verifies the old PIN, re-seals every entry and the env key under the new one,
    /// writes all of it in a single image. A host that found the device unlocked still
    /// cannot take it over. The env blobs themselves stay as they are: their key did
    /// not change, only its wrapping.
    pub fn pin_change(&mut self, old: Pin<'_>, new: Pin<'_>) -> Result<(), Fail> {
        self.pin_unlock(old)?; // loads the state too
        let old_dek = self.dek()?;
        let env_key = self.unwrap_env_key(&old_dek)?;
        if let Err(f) = self.install_pin(new, &env_key) {
            self.lock();
            return Err(f);
        }
        let new_dek = self.dek()?;
        // Re-sealed in RAM one entry at a time; flash is written only once every
        // entry made it, so a failure half-way leaves the old PIN and the old image.
        // Each plaintext `Entry` zeroizes itself as soon as it is sealed again.
        let mut resealed = true;
        for slot in self.state.slots.iter_mut().filter(|r| !r.is_empty()) {
            let Some(r) = Self::open_record(&old_dek, slot)
                .and_then(|e| Self::seal_record(&new_dek, &mut self.rng, &e))
            else {
                resealed = false;
                break;
            };
            *slot = r;
        }
        if !resealed || self.store.save(self.state).is_err() {
            self.lock();
            return Err(Fail::Internal);
        }
        Ok(())
    }

    // --- entries ---------------------------------------------------------------

    /// What the AEAD binds a secret to: its name and its kind. The kind sits in flash
    /// as plaintext; without it under the tag, one rewritten byte would turn a TOTP
    /// seed into a "password" and hand it out through the reveal gesture.
    fn aad<'b>(
        name: Name<'_>,
        kind: Kind,
        buf: &'b mut [u8; NAME_MAX + Kind::WIRE_LEN],
    ) -> &'b [u8] {
        let name = name.as_bytes();
        buf[..name.len()].copy_from_slice(name);
        buf[name.len()..name.len() + Kind::WIRE_LEN].copy_from_slice(&kind.wire());
        &buf[..name.len() + Kind::WIRE_LEN]
    }

    fn seal_record(dek: &[u8; KEY_LEN], rng: &mut R, e: &Entry) -> Option<Record> {
        let mut aad = [0u8; NAME_MAX + Kind::WIRE_LEN];
        let mut sealed = [0u8; SECRET_MAX + vault::OVERHEAD];
        let aad = Self::aad(e.name(), e.kind, &mut aad);
        let n = vault::seal(dek, rng, aad, e.secret(), &mut sealed)?;
        Record::new(e.name(), e.kind, &sealed[..n])
    }

    fn open_record(dek: &[u8; KEY_LEN], r: &Record) -> Option<Entry> {
        let mut aad = [0u8; NAME_MAX + Kind::WIRE_LEN];
        let mut plain = Zeroizing::new([0u8; SECRET_MAX]);
        let aad = Self::aad(r.name(), r.kind, &mut aad);
        let n = vault::open(dek, aad, r.sealed(), &mut *plain)?;
        Entry::new(r.name(), r.kind, &plain[..n])
    }

    /// The stored entry called `name`, decrypted.
    fn entry(&mut self, dek: &[u8; KEY_LEN], name: Name<'_>) -> Result<Entry, Fail> {
        self.load()?;
        let i = self.state.find(name).ok_or(Fail::NotFound)?;
        let r = &self.state.slots[i];
        Self::open_record(dek, r).ok_or(Fail::Internal)
    }

    /// Whether a blob answers to `name`. Names are one namespace across the table and
    /// the blobs: `get` by name must have one meaning.
    fn env_exists(&mut self, name: Name<'_>) -> Result<bool, Fail> {
        Ok(self
            .store
            .env_find(name)
            .map_err(|_| Fail::Internal)?
            .is_some())
    }

    pub fn add(&mut self, e: &Entry, replace: bool) -> Result<(), Fail> {
        let dek = self.dek()?;
        self.load()?;
        if self.env_exists(e.name())? {
            return Err(Fail::Exists);
        }
        let slot = match self.state.find(e.name()) {
            Some(_) if !replace => return Err(Fail::Exists),
            Some(i) => i,
            None => self.state.free_slot().ok_or(Fail::Full)?,
        };
        let sealed = Self::seal_record(&dek, &mut self.rng, e).ok_or(Fail::Internal)?;
        self.state.slots[slot] = sealed;
        self.store.save(self.state).map_err(|_| Fail::Internal)?;
        self.touch();
        Ok(())
    }

    /// Name and kind of every stored entry and blob. Needs the PIN: which services
    /// someone uses is theirs to know, not any program's that found the port.
    pub fn list(&mut self, mut each: impl FnMut(Name<'_>, Kind)) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        for r in self.state.used() {
            each(r.name(), r.kind);
        }
        self.store
            .env_names(|n| each(n, Kind::Env))
            .map_err(|_| Fail::Internal)
    }

    /// A TOTP code, after a tap. Only a TOTP entry has one.
    pub fn code(
        &mut self,
        name: Name<'_>,
        unix_time: u64,
        out: &mut [u8; 8],
    ) -> Result<usize, Fail> {
        let dek = self.dek()?;
        let e = self.entry(&dek, name)?;
        let Kind::Totp(params) = e.kind else {
            return Err(Fail::BadArg);
        };
        if !ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
            return Err(Fail::Refused);
        }
        let n = oath::totp(params, e.secret(), unix_time, out);
        self.touch();
        Ok(n)
    }

    /// The login of a password entry: the PIN is enough, no gesture - it is not the
    /// secret, and the site asks for it first.
    pub fn login(&mut self, name: Name<'_>, out: &mut [u8; SECRET_MAX]) -> Result<usize, Fail> {
        let dek = self.dek()?;
        let e = self.entry(&dek, name)?;
        let login = e.login().ok_or(Fail::BadArg)?;
        out[..login.len()].copy_from_slice(login);
        self.touch();
        Ok(login.len())
    }

    /// A password entry as stored - `login_len | login | password_len | password |
    /// note`, the host unpacks it with the same `Entry` - after a tap, the same gesture
    /// as a code. A TOTP seed never comes out this way: `Entry::password_bytes` is None
    /// for it, and this is the one place that asks.
    pub fn reveal(&mut self, name: Name<'_>, out: &mut [u8; SECRET_MAX]) -> Result<usize, Fail> {
        let dek = self.dek()?;
        let e = self.entry(&dek, name)?;
        if e.password_bytes().is_none() {
            return Err(Fail::BadArg);
        }
        if !ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
            return Err(Fail::Refused);
        }
        let packed = e.secret();
        out[..packed.len()].copy_from_slice(packed);
        self.touch();
        Ok(packed.len())
    }

    /// An entry or a blob, gone.
    pub fn delete(&mut self, name: Name<'_>) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        if let Some(i) = self.state.find(name) {
            self.state.slots[i] = Record::EMPTY;
            self.store.save(self.state).map_err(|_| Fail::Internal)?;
        } else {
            let slot = self
                .store
                .env_find(name)
                .map_err(|_| Fail::Internal)?
                .ok_or(Fail::NotFound)?;
            self.store.env_delete(slot).map_err(|_| Fail::Internal)?;
        }
        self.touch();
        Ok(())
    }

    /// The entry called `from`, now called `to`, in the same slot. The name is under
    /// the AEAD tag, so this is a decrypt and a re-seal, not a metadata edit - and
    /// therefore the device's job: the secret never leaves it. No gesture, like `add`
    /// and `delete`: nothing comes out, and a rename can be renamed back.
    pub fn rename(&mut self, from: Name<'_>, to: Name<'_>) -> Result<(), Fail> {
        let dek = self.dek()?;
        self.load()?;
        let i = self.state.find(from).ok_or(Fail::NotFound)?;
        if self.state.find(to).is_some() || self.env_exists(to)? {
            return Err(Fail::Exists);
        }
        let r = &self.state.slots[i];
        let e = Self::open_record(&dek, r).ok_or(Fail::Internal)?;
        let e = Entry::new(to, e.kind, e.secret()).ok_or(Fail::Internal)?;
        let sealed = Self::seal_record(&dek, &mut self.rng, &e).ok_or(Fail::Internal)?;
        self.state.slots[i] = sealed;
        self.store.save(self.state).map_err(|_| Fail::Internal)?;
        self.touch();
        Ok(())
    }

    // --- env blobs -----------------------------------------------------------------

    /// The env key for one operation: the state reloaded, the wrapped key opened.
    fn env_key(&mut self, dek: &[u8; KEY_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>, Fail> {
        self.load()?;
        self.unwrap_env_key(dek)
    }

    /// Stores `plain` as the blob called `name`. The PIN is enough, like `add`: nothing
    /// comes out. Sealed in the board's buffer and written from there.
    pub fn env_put(&mut self, name: Name<'_>, plain: &[u8], replace: bool) -> Result<(), Fail> {
        let dek = self.dek()?;
        let key = self.env_key(&dek)?;
        if plain.is_empty() || plain.len() > ENV_MAX {
            return Err(Fail::BadArg);
        }
        if self.state.find(name).is_some() {
            return Err(Fail::Exists);
        }
        let slot = match self.store.env_find(name).map_err(|_| Fail::Internal)? {
            Some(_) if !replace => return Err(Fail::Exists),
            Some(i) => i,
            None => self
                .store
                .env_free()
                .map_err(|_| Fail::Internal)?
                .ok_or(Fail::Full)?,
        };
        self.buf.zeroize();
        self.buf[NONCE_LEN..NONCE_LEN + plain.len()].copy_from_slice(plain);
        let written = Self::seal_env(&key, &mut self.rng, name, self.buf, plain.len()).map_or(
            Err(Fail::Internal),
            |len| {
                self.store
                    .env_write(slot, name, env_part(self.buf), len)
                    .map_err(|_| Fail::Internal)
            },
        );
        self.buf.zeroize();
        written?;
        self.touch();
        Ok(())
    }

    /// A blob sitting open in `buf` at `NONCE_LEN`, `len` bytes of it, the rest zero,
    /// sealed in place under the env key as `name`: the sealed length.
    fn seal_env(
        key: &[u8; KEY_LEN],
        rng: &mut R,
        name: Name<'_>,
        buf: &mut [u8; BUF_LEN],
        len: usize,
    ) -> Option<usize> {
        let mut aad = [0u8; NAME_MAX + Kind::WIRE_LEN];
        let aad = Self::aad(name, Kind::Env, &mut aad);
        vault::seal_in_place(key, rng, aad, buf, len)
    }

    /// The blob called `name`, open, to `f` - after a tap, the same gesture as a
    /// password. It is handed over from the board's buffer and scrubbed right after.
    pub fn env_get(&mut self, name: Name<'_>, f: impl FnOnce(&[u8])) -> Result<(), Fail> {
        let dek = self.dek()?;
        let key = self.env_key(&dek)?;
        let slot = self
            .store
            .env_find(name)
            .map_err(|_| Fail::Internal)?
            .ok_or(Fail::NotFound)?;
        self.buf.zeroize();
        let opened = self
            .open_env(&key, slot)
            .and_then(|found| found.ok_or(Fail::NotFound));
        let r = opened.and_then(|(n, _)| {
            if ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
                f(&self.buf[NONCE_LEN..NONCE_LEN + n]);
                Ok(())
            } else {
                Err(Fail::Refused)
            }
        });
        self.buf.zeroize();
        r?;
        self.touch();
        Ok(())
    }

    /// The blob in `slot`, read and opened in the buffer: its length - it sits at
    /// `NONCE_LEN` - and its name, or None for a free slot.
    fn open_env(
        &mut self,
        key: &[u8; KEY_LEN],
        slot: usize,
    ) -> Result<Option<(usize, StoredName)>, Fail> {
        let Some((len, name)) = self
            .store
            .env_read(slot, env_part(self.buf))
            .map_err(|_| Fail::Internal)?
        else {
            return Ok(None);
        };
        let mut aad = [0u8; NAME_MAX + Kind::WIRE_LEN];
        let aad = Self::aad(name.get(), Kind::Env, &mut aad);
        let n = vault::open_in_place(key, aad, &mut self.buf[..len]).ok_or(Fail::Internal)?;
        Ok(Some((n, name)))
    }

    // --- backup ----------------------------------------------------------------------
    //
    // Every entry and blob leaves the device once, sealed under a key made from a
    // passphrase alone - no chip key, so the file opens on another board - one item
    // per request, in the order of the table and then the blob slots. The gesture is
    // two taps at blue: a tap alone is the code reflex, a hold is the wipe, and
    // neither must be turned into an export by a host that asks at the right moment.

    /// Starts a backup: the double tap, then the key for `pass` under a fresh salt.
    /// What the host needs to make that key again comes back; the items follow.
    pub fn export_begin(&mut self, pass: Passphrase<'_>) -> Result<BackupHead, Fail> {
        self.dek()?;
        self.load()?;
        if !ui::await_double_tap(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
            return Err(Fail::Refused);
        }
        let mut salt = [0u8; SALT_LEN];
        self.rng.fill_bytes(&mut salt);
        let cost = Cost::CURRENT;
        let key = vault::backup_key(pass, &salt, cost, self.mem).ok_or(Fail::Internal)?;
        self.backup = Some(Session::Export {
            key,
            slot: 0,
            item: 0,
        });
        self.touch();
        Ok(BackupHead { salt, cost })
    }

    /// The next item to `f`, sealed, out of the buffer; an empty slice once every
    /// entry and blob has been handed out, which also ends the backup.
    pub fn export_next(&mut self, f: impl FnOnce(&[u8])) -> Result<(), Fail> {
        let r = self.export_item();
        match r {
            Ok(Some(n)) => f(&self.buf[..n]),
            Ok(None) => f(&[]),
            Err(_) => {}
        }
        self.buf.zeroize();
        if !matches!(r, Ok(Some(_))) {
            self.backup = None;
        }
        r.map(|_| self.touch())
    }

    /// The next non-empty slot sealed into the buffer: the sealed length, or None
    /// when there is nothing left.
    fn export_item(&mut self) -> Result<Option<usize>, Fail> {
        let dek = self.dek()?;
        let Some(Session::Export { key, slot, item }) = &self.backup else {
            return Err(Fail::BadBackup);
        };
        let (key, mut slot, item) = (Zeroizing::new(**key), *slot, *item);
        let n = loop {
            if slot >= MAX_ENTRIES + ENV_SLOTS {
                return Ok(None);
            }
            let plain = if slot < MAX_ENTRIES {
                let r = &self.state.slots[slot];
                if r.is_empty() {
                    None
                } else {
                    let e = Self::open_record(&dek, r).ok_or(Fail::Internal)?;
                    let prefix = item_prefix(e.kind, e.name(), self.buf);
                    let at = NONCE_LEN + prefix;
                    self.buf[at..at + e.secret().len()].copy_from_slice(e.secret());
                    Some(prefix + e.secret().len())
                }
            } else {
                let env_key = self.unwrap_env_key(&dek)?;
                self.open_env(&env_key, slot - MAX_ENTRIES)?
                    .map(|(n, name)| {
                        // The blob sits right after the nonce; the prefix goes in front.
                        let prefix = Kind::WIRE_LEN + 1 + name.get().as_bytes().len();
                        self.buf
                            .copy_within(NONCE_LEN..NONCE_LEN + n, NONCE_LEN + prefix);
                        item_prefix(Kind::Env, name.get(), self.buf) + n
                    })
            };
            slot += 1;
            if let Some(n) = plain {
                break n;
            }
        };
        let sealed = vault::seal_in_place(&key, &mut self.rng, &item_aad(item), self.buf, n)
            .ok_or(Fail::Internal)?;
        self.backup = Some(Session::Export {
            key,
            slot,
            item: item + 1,
        });
        Ok(Some(sealed))
    }

    /// Starts a restore: the key for `pass` as the backup's head describes it. The
    /// PIN is enough, like `add`: nothing comes out.
    pub fn import_begin(&mut self, pass: Passphrase<'_>, head: BackupHead) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        let key = vault::backup_key(pass, &head.salt, head.cost, self.mem).ok_or(Fail::Internal)?;
        self.backup = Some(Session::Import {
            key,
            item: 0,
            dirty: false,
        });
        self.touch();
        Ok(())
    }

    /// One item back in, under the name it carries: an entry of that name is
    /// replaced, a blob of that name too, and one of the other kind is removed, since
    /// names are one namespace. Entries land in the table in RAM and reach flash at
    /// `import_end`, in one image; a blob is written as it arrives, after any table
    /// change before it, so flash never holds a name twice. Any failure ends the
    /// restore: what reached flash stays, what did not is gone, and the file can be
    /// restored again.
    pub fn import_item(&mut self, sealed: &[u8]) -> Result<(), Fail> {
        let dek = self.dek()?;
        let Some(Session::Import { key, item, dirty }) = &self.backup else {
            return Err(Fail::BadBackup);
        };
        let (key, item, dirty) = (Zeroizing::new(**key), *item, *dirty);
        let r = self.import_sealed(&dek, &key, item, dirty, sealed);
        self.buf.zeroize();
        match r {
            Ok(dirty) => {
                self.backup = Some(Session::Import {
                    key,
                    item: item + 1,
                    dirty,
                });
                self.touch();
                Ok(())
            }
            Err(f) => {
                self.backup = None;
                Err(f)
            }
        }
    }

    /// `import_item` with the session's parts in hand: whether the table in RAM is
    /// now ahead of flash.
    fn import_sealed(
        &mut self,
        dek: &[u8; KEY_LEN],
        key: &[u8; KEY_LEN],
        item: u32,
        dirty: bool,
        sealed: &[u8],
    ) -> Result<bool, Fail> {
        if sealed.len() > BUF_LEN {
            return Err(Fail::BadBackup);
        }
        self.buf[..sealed.len()].copy_from_slice(sealed);
        let n = vault::open_in_place(key, &item_aad(item), &mut self.buf[..sealed.len()])
            .ok_or(Fail::BadBackup)?;
        let plain = &self.buf[NONCE_LEN..NONCE_LEN + n];
        let (meta, rest) = plain
            .split_first_chunk::<{ Kind::WIRE_LEN }>()
            .ok_or(Fail::BadBackup)?;
        let kind = Kind::from_wire(*meta).ok_or(Fail::BadBackup)?;
        let (name, secret) = Name::take(rest).ok_or(Fail::BadBackup)?;
        if kind == Kind::Env {
            if secret.is_empty() || secret.len() > ENV_MAX {
                return Err(Fail::BadBackup);
            }
            let name = StoredName::of(name);
            let (at, len) = (NONCE_LEN + n - secret.len(), secret.len());
            self.import_env(dek, name.get(), at, len, dirty)?;
            return Ok(false);
        }
        let e = Entry::new(name, kind, secret).ok_or(Fail::BadBackup)?;
        if let Some(slot) = self.store.env_find(e.name()).map_err(|_| Fail::Internal)? {
            self.store.env_delete(slot).map_err(|_| Fail::Internal)?;
        }
        let slot = match self.state.find(e.name()) {
            Some(i) => i,
            None => self.state.free_slot().ok_or(Fail::Full)?,
        };
        self.state.slots[slot] = Self::seal_record(dek, &mut self.rng, &e).ok_or(Fail::Internal)?;
        Ok(true)
    }

    /// The blob open in the buffer at `at`, `len` bytes, stored as `name`; the table
    /// written first if it is dirty or loses an entry of that name here.
    fn import_env(
        &mut self,
        dek: &[u8; KEY_LEN],
        name: Name<'_>,
        at: usize,
        len: usize,
        dirty: bool,
    ) -> Result<(), Fail> {
        let mut dirty = dirty;
        if let Some(i) = self.state.find(name) {
            self.state.slots[i] = Record::EMPTY;
            dirty = true;
        }
        if dirty {
            self.store.save(self.state).map_err(|_| Fail::Internal)?;
        }
        let slot = match self.store.env_find(name).map_err(|_| Fail::Internal)? {
            Some(i) => i,
            None => self
                .store
                .env_free()
                .map_err(|_| Fail::Internal)?
                .ok_or(Fail::Full)?,
        };
        let env_key = self.unwrap_env_key(dek)?;
        // Back to where a blob is sealed from; what trailed it must not reach flash.
        self.buf.copy_within(at..at + len, NONCE_LEN);
        self.buf[NONCE_LEN + len..].zeroize();
        let sealed =
            Self::seal_env(&env_key, &mut self.rng, name, self.buf, len).ok_or(Fail::Internal)?;
        self.store
            .env_write(slot, name, env_part(self.buf), sealed)
            .map_err(|_| Fail::Internal)
    }

    /// The restored table to flash, in one image, and the restore over.
    pub fn import_end(&mut self) -> Result<(), Fail> {
        let Some(Session::Import { dirty, .. }) = &self.backup else {
            return Err(Fail::BadBackup);
        };
        let r = if *dirty {
            self.store.save(self.state).map_err(|_| Fail::Internal)
        } else {
            Ok(())
        };
        self.backup = None;
        r?;
        self.touch();
        Ok(())
    }
}
