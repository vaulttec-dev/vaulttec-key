//! What the key does, independent of how bytes arrive: PIN lifecycle and items.
//! One owner of the flash, the keys, the button, the entropy source and the chip key.
//!
//! The rule that matters is here and nowhere else: **a field's class decides what may
//! leave**. `Open` needs the PIN, `Secret` needs a tap, `Seed` needs the double tap
//! that a backup needs - a whole secret leaving the key is one act with one gesture.
//! Categories are labels; classes are the boundary.

use embedded_storage::nor_flash::NorFlash;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::hal::{Attachment, Clock, DeviceKey, Ui};
use crate::item::{Category, Class, Item, Writer};
use crate::login::Login;
use crate::oath::{self, NAME_MAX, Name, Params, len_u8};
use crate::store::{self, Header, ITEM_BUF_LEN, Index, MAX_ATTEMPTS, Slot, Store, StoredName};
use crate::ui;
use crate::vault::{
    self, BACKUP_AAD, Block, Cost, KDF_BLOCKS, KEY_LEN, Keys, NONCE_LEN, Passphrase, Pin,
    REGION_AAD, REGION_HEAD, SALT_LEN,
};
use crate::wire::{BackupHead, Fail, HAS_OPEN, HAS_SECRET, HAS_SEED, PinStatus};

/// Unlocked and idle this long, the device forgets the key on its own. Two minutes:
/// long enough to finish a login, short enough that a key left on the desk is a
/// locked key.
const AUTOLOCK_MS: u64 = 120_000;
const TOUCH_TIMEOUT_MS: u64 = 30_000;
/// A wipe, or a restore that replaces everything, after five seconds of red: no reflex
/// reaches it.
const WIPE_HOLD_MS: u64 = 5_000;

/// The board's working buffer: two item-sized halves. Two, because rewriting the image
/// carries items across one at a time while the new item waits its turn - one buffer
/// would have the copying tread on what is being written.
pub const BUF_LEN: usize = 2 * ITEM_BUF_LEN;

/// A resident copy of the data key that scrubs itself when dropped.
type Dek = Zeroizing<[u8; KEY_LEN]>;

/// Argon2's working memory, 128 KiB on the stack for one derivation: it exists only
/// while `f` runs, and `vault` scrubs it before handing the key back. Never inlined, so
/// the frame that holds it is gone before the key waits for its next request. A board
/// can then run other deep work in that same RAM between derivations - the nRF52840's
/// passkeys - where a static would hold it for the life of the program.
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "on the stack on purpose: there is no heap, and a static would hold the 128 KiB for good"
)]
fn with_kdf_memory<T>(f: impl FnOnce(&mut [Block]) -> T) -> T {
    let mut mem = [Block::new(); KDF_BLOCKS];
    f(&mut mem)
}

/// Which classes a request may have. The device never returns a field outside it, and
/// the gesture is decided by the highest class in it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// The PIN alone.
    Open,
    /// A tap: everything but seeds.
    Secret,
    /// The double tap: seeds too - the whole item, as an export or a backup needs it.
    Seed,
}

impl Reach {
    const fn allows(self, class: Class) -> bool {
        matches!(
            (self, class),
            (Reach::Open, Class::Open)
                | (Reach::Secret, Class::Open | Class::Secret)
                | (Reach::Seed, _)
        )
    }
}

/// A backup in flight: the passphrase key, and how far it got. Ended by the last item,
/// by a lock, or by any operation that reloads the index it walks - always through
/// `end_session`, which lets the board's attachment go.
enum Session {
    Export {
        key: Dek,
        /// What to look at next: an index position, and past the last item the
        /// attachment's sectors, counted on from there.
        slot: usize,
        /// Items handed out so far: the next one's position in the file.
        item: u32,
    },
    Import {
        key: Dek,
        item: u32,
        /// The first sector the next one may be, once a sector has come; None while
        /// the file is still on items.
        sector: Option<u32>,
        /// Whether a sector was rewritten: the board restarts what uses them.
        changed: bool,
    },
}

/// A sector of the attachment, as `store` counts them.
const SECTOR_LEN: usize = store::SECTOR as usize;

pub struct Device<
    'm,
    F: NorFlash,
    R: RngCore + CryptoRng,
    U: Ui,
    C: Clock,
    K: DeviceKey,
    A: Attachment,
> {
    store: Store<F>,
    ui: U,
    rng: R,
    clock: C,
    key: K,
    /// What a backup carries besides the items, on a board that has it.
    attachment: A,
    /// What a new vault and a new backup are derived at: the board's measure of about a
    /// second. An existing vault opens at the cost its header records.
    cost: Cost,
    /// Where every item is, as last read from flash. The bodies stay in flash; this is
    /// ~10 KiB and the board owns it. Every operation reloads it before looking at it.
    index: &'m mut Index,
    /// The working buffer, owned by the board too: two item-sized halves, held once,
    /// and scrubbed at the end of every operation that used it.
    buf: &'m mut [u8; BUF_LEN],
    dek: Option<Dek>,
    backup: Option<Session>,
    last_activity_ms: u64,
}

/// One class as a bit of the mask an `ItemGet` answers with.
const fn class_bit(class: Class) -> u8 {
    match class {
        Class::Open => HAS_OPEN,
        Class::Secret => HAS_SECRET,
        Class::Seed => HAS_SEED,
    }
}

/// `BACKUP_AAD` followed by the item's position in the file.
fn item_aad(item: u32) -> [u8; BACKUP_AAD.len() + 4] {
    let mut aad = [0u8; BACKUP_AAD.len() + 4];
    aad[..BACKUP_AAD.len()].copy_from_slice(BACKUP_AAD);
    aad[BACKUP_AAD.len()..].copy_from_slice(&item.to_le_bytes());
    aad
}

/// `REGION_AAD` followed by the sector's position in the file.
fn region_aad(item: u32) -> [u8; REGION_AAD.len() + 4] {
    let mut aad = [0u8; REGION_AAD.len() + 4];
    aad[..REGION_AAD.len()].copy_from_slice(REGION_AAD);
    aad[REGION_AAD.len()..].copy_from_slice(&item.to_le_bytes());
    aad
}

/// A little-endian u32 at `at` in `bytes`.
fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let word = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

impl<'m, F: NorFlash, R: RngCore + CryptoRng, U: Ui, C: Clock, K: DeviceKey, A: Attachment>
    Device<'m, F, R, U, C, K, A>
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
        attachment: A,
        cost: Cost,
        index: &'m mut Index,
        buf: &'m mut [u8; BUF_LEN],
    ) -> Self {
        let now = clock.now_ms();
        Device {
            store,
            ui,
            rng,
            clock,
            key,
            attachment,
            cost,
            index,
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
        self.end_session();
        self.store.save_abort();
        self.buf.zeroize();
    }

    /// A backup or a restore begins: the board keeps its own user of the attachment off
    /// it until `end_session`.
    fn start_session(&mut self, session: Session) {
        self.end_session();
        self.attachment.freeze();
        self.backup = Some(session);
    }

    /// The backup or restore in flight, if any, is over, however it ended, and the
    /// board's attachment is let go - told whether a restore rewrote it. Every way a
    /// session ends comes through here.
    fn end_session(&mut self) {
        match self.backup.take() {
            Some(Session::Import { changed, .. }) => self.attachment.thaw(changed),
            Some(Session::Export { .. }) => self.attachment.thaw(false),
            None => {}
        }
    }

    /// Factory reset: every secret and the PIN. Confirmed by the longest hold, never by
    /// the tap that approves a code. Whoever holds the key can empty it anyway (eight
    /// wrong PINs, or the flash tools); this protects the owner who did not mean to.
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

    /// The index into `self.index`. Unreadable flash is an error, never "empty":
    /// nothing gets written over it without `wipe`. A backup in flight walks the index
    /// as it was when it began; reloading ends it.
    fn load(&mut self) -> Result<(), Fail> {
        self.end_session();
        self.store.save_abort();
        self.store.load(self.index).map_err(|_| Fail::Internal)
    }

    // --- PIN ----------------------------------------------------------------------

    /// Asked every second by the shell's status row: answered from the image heads and
    /// the attempt words alone, never a full load.
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
        let key = &mut self.key;
        with_kdf_memory(|mem| vault::derive(pin, salt, cost, key, mem)).ok_or(Fail::Internal)
    }

    /// A header for `pin`, and the resident key switched to match. The caller writes it;
    /// until it does, flash still holds the old PIN.
    fn install_pin(&mut self, pin: Pin<'_>) -> Result<Header, Fail> {
        let mut salt = [0u8; SALT_LEN];
        self.rng.fill_bytes(&mut salt);
        let keys = self.derive(pin, &salt, self.cost)?;
        let header = Header {
            salt,
            cost: self.cost,
            bound: self.key.bound(),
            verifier: vault::verifier_of(&keys.kek),
        };
        self.dek = Some(Zeroizing::new(keys.dek));
        Ok(header)
    }

    pub fn pin_set(&mut self, pin: Pin<'_>) -> Result<(), Fail> {
        self.load()?;
        if self.index.header.is_some() {
            return Err(Fail::PinExists);
        }
        self.store.reset_attempts().map_err(|_| Fail::Internal)?;
        let header = self.install_pin(pin)?;
        let written = self
            .store
            .save_begin(Some(&header))
            .and_then(|()| self.store.save_finish(self.index));
        if written.is_err() {
            self.lock();
            return Err(Fail::Internal);
        }
        self.touch();
        Ok(())
    }

    pub fn pin_unlock(&mut self, pin: Pin<'_>) -> Result<(), Fail> {
        self.load()?;
        let Some(hdr) = self.index.header else {
            return Err(Fail::NoPin);
        };
        // A vault from a firmware with the other key setup would fail every PIN; say so
        // instead of spending the attempts.
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
        // Spend the attempt before checking, so a power cut during the check cannot be
        // used to try for free. Restored to the maximum only after success.
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

    /// Verifies the old PIN, re-seals every item under the new one, writes all of it as
    /// a single image. A host that found the device unlocked still cannot take it over.
    pub fn pin_change(&mut self, old: Pin<'_>, new: Pin<'_>) -> Result<(), Fail> {
        self.pin_unlock(old)?; // loads the index too
        let old_dek = self.dek()?;
        let header = match self.install_pin(new) {
            Ok(h) => h,
            Err(f) => {
                self.lock();
                return Err(f);
            }
        };
        let new_dek = self.dek()?;
        let r = self.reseal_all(&old_dek, &new_dek, &header);
        self.buf.zeroize();
        if r.is_err() {
            // Nothing was made visible: the copy being written has no magic word yet.
            self.store.save_abort();
            self.lock();
            return Err(Fail::Internal);
        }
        Ok(())
    }

    /// Every item opened under `old` and sealed under `new`, into one fresh image.
    fn reseal_all(&mut self, old: &Dek, new: &Dek, header: &Header) -> Result<(), Fail> {
        self.store
            .save_begin(Some(header))
            .map_err(|_| Fail::Internal)?;
        for i in 0..self.index.len() {
            let slot = *self.index.get(i).ok_or(Fail::Internal)?;
            let n = {
                let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
                self.store
                    .save_read(&slot, work)
                    .map_err(|_| Fail::Internal)?
            };
            let name = StoredName::of(slot.name());
            let opened = {
                let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
                Self::open_in(old, name.get(), slot.category, &mut work[..n])
            }
            .ok_or(Fail::Internal)?;
            let sealed = {
                let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
                // The plaintext sits after the nonce, which `seal_in_place` overwrites.
                work.copy_within(NONCE_LEN..NONCE_LEN + opened, NONCE_LEN);
                Self::seal_in(new, &mut self.rng, name.get(), slot.category, work, opened)
            }
            .ok_or(Fail::Internal)?;
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            let body = &work[..sealed];
            self.store
                .save_put(name.get(), slot.category, body)
                .map_err(|_| Fail::Internal)?;
        }
        self.store
            .save_finish(self.index)
            .map_err(|_| Fail::Internal)
    }

    // --- items ---------------------------------------------------------------------

    /// What the AEAD binds an item to: its name and its category. The category sits in
    /// flash as plaintext; without it under the tag, one rewritten byte would turn a
    /// TOTP seed into some other category and change which gesture reaches it.
    fn aad<'b>(name: Name<'_>, category: u8, buf: &'b mut [u8; NAME_MAX + 1]) -> &'b [u8] {
        let name = name.as_bytes();
        buf[..name.len()].copy_from_slice(name);
        buf[name.len()] = category;
        &buf[..=name.len()]
    }

    /// Seals `len` plaintext bytes sitting at `NONCE_LEN` in `buf`, in place.
    fn seal_in(
        key: &[u8; KEY_LEN],
        rng: &mut R,
        name: Name<'_>,
        category: u8,
        buf: &mut [u8],
        len: usize,
    ) -> Option<usize> {
        let mut aad = [0u8; NAME_MAX + 1];
        let aad = Self::aad(name, category, &mut aad);
        vault::seal_in_place(key, rng, aad, buf, len)
    }

    /// Opens a sealed item in place; the plaintext then sits at `NONCE_LEN`.
    fn open_in(key: &[u8; KEY_LEN], name: Name<'_>, category: u8, buf: &mut [u8]) -> Option<usize> {
        let mut aad = [0u8; NAME_MAX + 1];
        let aad = Self::aad(name, category, &mut aad);
        vault::open_in_place(key, aad, buf)
    }

    /// Stores an item. The PIN is enough, like every write: nothing comes out.
    pub fn put(
        &mut self,
        name: Name<'_>,
        category: Category,
        plain: &[u8],
        replace: bool,
    ) -> Result<(), Fail> {
        let dek = self.dek()?;
        self.load()?;
        let item = Item::parse(plain).ok_or(Fail::BadArg)?;
        if item.category() != category {
            return Err(Fail::BadArg);
        }
        let at = self.index.find(name);
        if at.is_some() && !replace {
            return Err(Fail::Exists);
        }
        let capacity = self.store.capacity();
        if !self
            .index
            .room_for(name, plain.len() + vault::OVERHEAD, at, capacity)
        {
            return Err(Fail::Full);
        }
        let r = self.write_item(&dek, name, category.wire(), plain, at);
        self.buf.zeroize();
        r?;
        self.touch();
        Ok(())
    }

    /// Seals `plain` and rewrites the image with it in place of the item at `at`, or
    /// appended when there is none.
    fn write_item(
        &mut self,
        key: &[u8; KEY_LEN],
        name: Name<'_>,
        category: u8,
        plain: &[u8],
        at: Option<usize>,
    ) -> Result<(), Fail> {
        let sealed = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work[NONCE_LEN..NONCE_LEN + plain.len()].copy_from_slice(plain);
            Self::seal_in(key, &mut self.rng, name, category, work, plain.len())
                .ok_or(Fail::Internal)?
        };
        self.store
            .save_begin(self.index.header.as_ref())
            .map_err(|_| Fail::Internal)?;
        let r = self.rewrite(at, Some((name, category, sealed)));
        if r.is_err() {
            self.store.save_abort();
        }
        r
    }

    /// Writes the image: every item of the index, with the one at `at` replaced by
    /// `new` (or dropped when `new` is None), and `new` appended when `at` is None.
    fn rewrite(
        &mut self,
        at: Option<usize>,
        new: Option<(Name<'_>, u8, usize)>,
    ) -> Result<(), Fail> {
        for i in 0..self.index.len() {
            if Some(i) == at {
                if let Some((name, category, sealed)) = new {
                    let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
                    self.store
                        .save_put(name, category, &work[..sealed])
                        .map_err(|_| Fail::Internal)?;
                }
                continue;
            }
            let slot = *self.index.get(i).ok_or(Fail::Internal)?;
            let (_, carry) = self.buf.split_at_mut(ITEM_BUF_LEN);
            self.store
                .save_keep(&slot, carry)
                .map_err(|_| Fail::Internal)?;
        }
        if at.is_none()
            && let Some((name, category, sealed)) = new
        {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            self.store
                .save_put(name, category, &work[..sealed])
                .map_err(|_| Fail::Internal)?;
        }
        self.store
            .save_finish(self.index)
            .map_err(|_| Fail::Internal)
    }

    /// Name and category of every stored item. Needs the PIN: which services someone
    /// uses is theirs to know, not any program's that found the port.
    pub fn list(&mut self, mut each: impl FnMut(Name<'_>, u8)) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        for slot in self.index.used_slots() {
            each(slot.name(), slot.category);
        }
        Ok(())
    }

    /// The item called `name`, opened into the working half of the buffer: how many
    /// plaintext bytes, sitting at `NONCE_LEN`.
    fn open_named(&mut self, dek: &[u8; KEY_LEN], name: Name<'_>) -> Result<(usize, u8), Fail> {
        self.load()?;
        let i = self.index.find(name).ok_or(Fail::NotFound)?;
        let slot = *self.index.get(i).ok_or(Fail::Internal)?;
        let n = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            self.store
                .read_item(&slot, work)
                .map_err(|_| Fail::Internal)?
        };
        let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
        let opened =
            Self::open_in(dek, name, slot.category, &mut work[..n]).ok_or(Fail::Internal)?;
        Ok((opened, slot.category))
    }

    /// The fields of `name` that `reach` allows, packed as an item, to `f`. The gesture
    /// is the reach's: none for open fields, a tap for secrets, the double tap for
    /// seeds. This is the only way a field's value leaves the device.
    pub fn get(
        &mut self,
        name: Name<'_>,
        reach: Reach,
        f: impl FnOnce(u8, u8, &[u8]),
    ) -> Result<(), Fail> {
        let dek = self.dek()?;
        let r = self.get_into(&dek, name, reach, f);
        self.buf.zeroize();
        r?;
        self.touch();
        Ok(())
    }

    fn get_into(
        &mut self,
        dek: &[u8; KEY_LEN],
        name: Name<'_>,
        reach: Reach,
        f: impl FnOnce(u8, u8, &[u8]),
    ) -> Result<(), Fail> {
        let (n, category) = self.open_named(dek, name)?;
        let gesture = match reach {
            Reach::Open => true,
            Reach::Secret => ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS),
            Reach::Seed => ui::await_double_tap(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS),
        };
        if !gesture {
            return Err(Fail::Refused);
        }
        let (work, out) = self.buf.split_at_mut(ITEM_BUF_LEN);
        let item = Item::parse(&work[NONCE_LEN..NONCE_LEN + n]).ok_or(Fail::Internal)?;
        let cat = Category::from_wire(category).ok_or(Fail::Internal)?;
        // Which classes the item holds at all, so the host knows a code can be had from
        // it without spending a gesture to find out. A field's existence is not its
        // value: the sealed length already says roughly how much is in there.
        let present = item
            .fields()
            .fold(0u8, |m, field| m | class_bit(field.class));
        let mut w = Writer::new(out, cat).ok_or(Fail::Internal)?;
        for field in item.fields().filter(|field| reach.allows(field.class)) {
            if !w.push(&field) {
                return Err(Fail::Full);
            }
        }
        let len = w.finish();
        f(category, present, &out[..len]);
        Ok(())
    }

    /// A TOTP code, after a tap: from the item's first seed field, whose value is the
    /// parameters and then the seed. A seed never leaves this way - only the code does.
    pub fn code(
        &mut self,
        name: Name<'_>,
        unix_time: u64,
        out: &mut [u8; 8],
    ) -> Result<(usize, u8), Fail> {
        let dek = self.dek()?;
        let r = self.code_into(&dek, name, unix_time, out);
        self.buf.zeroize();
        let (n, period) = r?;
        self.touch();
        Ok((n, period))
    }

    fn code_into(
        &mut self,
        dek: &[u8; KEY_LEN],
        name: Name<'_>,
        unix_time: u64,
        out: &mut [u8; 8],
    ) -> Result<(usize, u8), Fail> {
        let (n, _) = self.open_named(dek, name)?;
        if !ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
            return Err(Fail::Refused);
        }
        let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
        let item = Item::parse(&work[NONCE_LEN..NONCE_LEN + n]).ok_or(Fail::Internal)?;
        let seed = item.first(Class::Seed).ok_or(Fail::BadArg)?;
        let (params, secret) = seed
            .value()
            .split_first_chunk::<{ Params::WIRE_LEN }>()
            .ok_or(Fail::BadArg)?;
        let params = Params::from_wire(*params).ok_or(Fail::BadArg)?;
        let len = oath::totp(params, secret, unix_time, out);
        Ok((len, params.period.get()))
    }

    /// An item, gone.
    pub fn delete(&mut self, name: Name<'_>) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        let at = self.index.find(name).ok_or(Fail::NotFound)?;
        self.store
            .save_begin(self.index.header.as_ref())
            .map_err(|_| Fail::Internal)?;
        let r = self.rewrite(Some(at), None);
        self.buf.zeroize();
        if r.is_err() {
            self.store.save_abort();
            return r;
        }
        self.touch();
        Ok(())
    }

    /// The item called `from`, now called `to`. The name is under the AEAD tag, so this
    /// is a decrypt and a re-seal, not a metadata edit - and therefore the device's job:
    /// the secret never leaves it. No gesture, like `put` and `delete`: nothing comes
    /// out, and a rename can be renamed back.
    pub fn rename(&mut self, from: Name<'_>, to: Name<'_>) -> Result<(), Fail> {
        let dek = self.dek()?;
        self.load()?;
        let at = self.index.find(from).ok_or(Fail::NotFound)?;
        if self.index.find(to).is_some() {
            return Err(Fail::Exists);
        }
        let slot = *self.index.get(at).ok_or(Fail::Internal)?;
        let r = self.rename_into(&dek, &slot, from, to, at);
        self.buf.zeroize();
        r?;
        self.touch();
        Ok(())
    }

    fn rename_into(
        &mut self,
        key: &[u8; KEY_LEN],
        slot: &Slot,
        from: Name<'_>,
        to: Name<'_>,
        at: usize,
    ) -> Result<(), Fail> {
        let n = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            self.store
                .read_item(slot, work)
                .map_err(|_| Fail::Internal)?
        };
        let opened = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            Self::open_in(key, from, slot.category, &mut work[..n]).ok_or(Fail::Internal)?
        };
        let sealed = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work.copy_within(NONCE_LEN..NONCE_LEN + opened, NONCE_LEN);
            Self::seal_in(key, &mut self.rng, to, slot.category, work, opened)
                .ok_or(Fail::Internal)?
        };
        self.store
            .save_begin(self.index.header.as_ref())
            .map_err(|_| Fail::Internal)?;
        let r = self.rewrite(Some(at), Some((to, slot.category, sealed)));
        if r.is_err() {
            self.store.save_abort();
        }
        r
    }

    /// The login password a board's keyboard types, handed to `keep` after the PIN and a
    /// tap, or forgotten when `None`. It leaves the vault's care for good: the board keeps
    /// it where the login screen can reach it, which is outside the vault.
    pub fn login<'a>(
        &mut self,
        login: Option<Login<'a>>,
        keep: impl FnOnce(Option<Login<'a>>) -> bool,
    ) -> Result<(), Fail> {
        self.dek()?;
        if !ui::await_confirmation(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS) {
            return Err(Fail::Refused);
        }
        if !keep(login) {
            return Err(Fail::Internal);
        }
        self.touch();
        Ok(())
    }

    // --- backup ----------------------------------------------------------------------
    //
    // Every item leaves the device once, sealed under a key made from a passphrase
    // alone - no chip key, so the file opens on another board - one item per request.
    // The gesture is two taps at blue: a tap alone is the code reflex, a hold is the
    // wipe, and neither must be turned into an export by a host that asks at the right
    // moment.

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
        let cost = self.cost;
        let key = with_kdf_memory(|mem| vault::backup_key(pass, &salt, cost, mem))
            .ok_or(Fail::Internal)?;
        self.start_session(Session::Export {
            key,
            slot: 0,
            item: 0,
        });
        self.touch();
        Ok(BackupHead { salt, cost })
    }

    /// The next item to `f`, sealed, out of the buffer; an empty slice once every item
    /// has been handed out, which also ends the backup.
    pub fn export_next(&mut self, f: impl FnOnce(&[u8])) -> Result<(), Fail> {
        let r = self.export_item();
        match r {
            Ok(Some(n)) => {
                let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
                f(&work[..n]);
            }
            Ok(None) => f(&[]),
            Err(_) => {}
        }
        self.buf.zeroize();
        if !matches!(r, Ok(Some(_))) {
            self.end_session();
        }
        r.map(|_| self.touch())
    }

    /// The next item sealed into the working half: its length, or None when there is
    /// nothing left. A backup item is `category | name_len | name | plaintext item`.
    fn export_item(&mut self) -> Result<Option<usize>, Fail> {
        let dek = self.dek()?;
        let Some(Session::Export { key, slot, item }) = &self.backup else {
            return Err(Fail::BadBackup);
        };
        let (key, at, item) = (Zeroizing::new(**key), *slot, *item);
        if at >= self.index.len() {
            let first = u32::try_from(at - self.index.len()).map_err(|_| Fail::Internal)?;
            return self.export_sector(&key, first, item);
        }
        let slot = *self.index.get(at).ok_or(Fail::Internal)?;
        let name = StoredName::of(slot.name());

        let n = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            self.store
                .read_item(&slot, work)
                .map_err(|_| Fail::Internal)?
        };
        let opened = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            Self::open_in(&dek, name.get(), slot.category, &mut work[..n]).ok_or(Fail::Internal)?
        };
        // The plaintext moves back to make room for the prefix, which goes after the
        // nonce that `seal_in_place` writes over.
        let prefix = 2 + name.get().as_bytes().len();
        let total = prefix + opened;
        if NONCE_LEN + total > ITEM_BUF_LEN {
            return Err(Fail::Internal);
        }
        {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work.copy_within(NONCE_LEN..NONCE_LEN + opened, NONCE_LEN + prefix);
            let bytes = name.get().as_bytes();
            work[NONCE_LEN] = slot.category;
            work[NONCE_LEN + 1] = len_u8(bytes.len());
            work[NONCE_LEN + 2..NONCE_LEN + 2 + bytes.len()].copy_from_slice(bytes);
        }
        let sealed = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            vault::seal_in_place(&key, &mut self.rng, &item_aad(item), work, total)
                .ok_or(Fail::Internal)?
        };
        self.advance_export(at + 1);
        Ok(Some(sealed))
    }

    /// The export moves on to `slot`, one more item handed out.
    fn advance_export(&mut self, next: usize) {
        if let Some(Session::Export { slot, item, .. }) = &mut self.backup {
            *slot = next;
            *item += 1;
        }
    }

    /// The first sector of the attachment from `first` on that is not blank, sealed into
    /// the working half: its length, or None once there are no more. A blank sector is
    /// not carried; a restore makes every sector the file leaves out blank.
    fn export_sector(
        &mut self,
        key: &[u8; KEY_LEN],
        first: u32,
        item: u32,
    ) -> Result<Option<usize>, Fail> {
        let count = self.attachment.sectors();
        for sector in first..count {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            let data = &mut work[NONCE_LEN + REGION_HEAD..NONCE_LEN + REGION_HEAD + SECTOR_LEN];
            if !self.attachment.read(sector, data) {
                return Err(Fail::Internal);
            }
            if data.iter().all(|&b| b == 0xFF) {
                continue;
            }
            work[NONCE_LEN..NONCE_LEN + 4].copy_from_slice(&store::SECTOR.to_le_bytes());
            work[NONCE_LEN + 4..NONCE_LEN + 8].copy_from_slice(&count.to_le_bytes());
            work[NONCE_LEN + 8..NONCE_LEN + 12].copy_from_slice(&sector.to_le_bytes());
            let sealed = vault::seal_in_place(
                key,
                &mut self.rng,
                &region_aad(item),
                work,
                REGION_HEAD + SECTOR_LEN,
            )
            .ok_or(Fail::Internal)?;
            let next = usize::try_from(sector).map_err(|_| Fail::Internal)?;
            self.advance_export(self.index.len() + next + 1);
            return Ok(Some(sealed));
        }
        Ok(None)
    }

    /// Starts a restore: the wipe's hold, then the key for `pass` as the backup's head
    /// describes it, and a fresh image to write the items into. Everything already
    /// stored is replaced - the vault, and on a board with passkeys those too - so it
    /// takes what a wipe and erasing every passkey take, never the PIN alone: a host
    /// that learned the PIN must not swap in passkeys of its own. Nothing comes out, so
    /// a hold is enough, and it is asked before anything is touched.
    pub fn import_begin(&mut self, pass: Passphrase<'_>, head: BackupHead) -> Result<(), Fail> {
        self.dek()?;
        self.load()?;
        if !ui::await_hold(&mut self.ui, &self.clock, TOUCH_TIMEOUT_MS, WIPE_HOLD_MS) {
            return Err(Fail::Refused);
        }
        let key = with_kdf_memory(|mem| vault::backup_key(pass, &head.salt, head.cost, mem))
            .ok_or(Fail::Internal)?;
        self.store
            .save_begin(self.index.header.as_ref())
            .map_err(|_| Fail::Internal)?;
        self.start_session(Session::Import {
            key,
            item: 0,
            sector: None,
            changed: false,
        });
        self.touch();
        Ok(())
    }

    /// One item back in, under the name it carries. Items are appended to the image
    /// being written and become visible together at `import_end`; any failure ends the
    /// restore and leaves what was there before, because the new image never got its
    /// magic word.
    ///
    /// The attachment's sectors come after the items and are written in place as they
    /// arrive - there is no second copy of them to switch to. A restore cut short leaves
    /// that region torn, and the board formats it on its next start; the file still
    /// holds it. A file with no sectors leaves the region as it was.
    pub fn import_item(&mut self, sealed: &[u8]) -> Result<(), Fail> {
        let dek = self.dek()?;
        let Some(Session::Import {
            key, item, sector, ..
        }) = &self.backup
        else {
            return Err(Fail::BadBackup);
        };
        let (key, item, sector) = (Zeroizing::new(**key), *item, *sector);
        let r = self.import_sealed(&dek, &key, item, sector, sealed);
        self.buf.zeroize();
        match r {
            Ok(next) => {
                if let Some(Session::Import { item, sector, .. }) = &mut self.backup {
                    *item += 1;
                    if next.is_some() {
                        *sector = next;
                    }
                }
                self.touch();
                Ok(())
            }
            Err(f) => {
                self.end_session();
                self.store.save_abort();
                Err(f)
            }
        }
    }

    /// An item, or a sector of the attachment: for a sector, the first sector the next
    /// one may be.
    fn import_sealed(
        &mut self,
        dek: &[u8; KEY_LEN],
        key: &[u8; KEY_LEN],
        item: u32,
        sector: Option<u32>,
        sealed: &[u8],
    ) -> Result<Option<u32>, Fail> {
        if sealed.len() > ITEM_BUF_LEN {
            return Err(Fail::BadBackup);
        }
        let n = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work[..sealed.len()].copy_from_slice(sealed);
            vault::open_in_place(key, &item_aad(item), &mut work[..sealed.len()])
        };
        let Some(n) = n else {
            return self.import_region(key, item, sector, sealed).map(Some);
        };
        // Items come before sectors; one after them was never written by a backup.
        if sector.is_some() {
            return Err(Fail::BadBackup);
        }
        // `category | name_len | name | item`, as `export_item` packed it.
        let (category, name, body_at, body_len) = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            let plain = &work[NONCE_LEN..NONCE_LEN + n];
            let (&category, rest) = plain.split_first().ok_or(Fail::BadBackup)?;
            let (name, body) = Name::take(rest).ok_or(Fail::BadBackup)?;
            if Item::parse(body).is_none() || Category::from_wire(category).is_none() {
                return Err(Fail::BadBackup);
            }
            (
                category,
                StoredName::of(name),
                NONCE_LEN + n - body.len(),
                body.len(),
            )
        };
        let resealed = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work.copy_within(body_at..body_at + body_len, NONCE_LEN);
            Self::seal_in(dek, &mut self.rng, name.get(), category, work, body_len)
                .ok_or(Fail::Internal)?
        };
        let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
        self.store
            .save_put(name.get(), category, &work[..resealed])
            .map_err(|_| Fail::Full)
            .map(|()| None)
    }

    /// A sector of the attachment back in its place, every sector the file skipped
    /// before it made blank: the sector after it. Refused by a board without the
    /// attachment, or laid out differently from the one the file came from, and out
    /// of order.
    fn import_region(
        &mut self,
        key: &[u8; KEY_LEN],
        item: u32,
        sector: Option<u32>,
        sealed: &[u8],
    ) -> Result<u32, Fail> {
        let count = self.attachment.sectors();
        if count == 0 {
            return Err(Fail::BadBackup);
        }
        let at = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            work[..sealed.len()].copy_from_slice(sealed);
            let n = vault::open_in_place(key, &region_aad(item), &mut work[..sealed.len()])
                .ok_or(Fail::BadBackup)?;
            let plain = &work[NONCE_LEN..NONCE_LEN + n];
            if n != REGION_HEAD + SECTOR_LEN
                || le_u32(plain, 0) != Some(store::SECTOR)
                || le_u32(plain, 4) != Some(count)
            {
                return Err(Fail::BadBackup);
            }
            le_u32(plain, 8).ok_or(Fail::BadBackup)?
        };
        let from = sector.unwrap_or(0);
        if at < from || at >= count {
            return Err(Fail::BadBackup);
        }
        for blank in from..at {
            self.region_blank(blank)?;
        }
        let changed = {
            let (work, _) = self.buf.split_at_mut(ITEM_BUF_LEN);
            let data = &work[NONCE_LEN + REGION_HEAD..NONCE_LEN + REGION_HEAD + SECTOR_LEN];
            self.attachment.put(at, Some(data)).ok_or(Fail::Internal)?
        };
        self.region_changed(changed);
        Ok(at + 1)
    }

    fn region_blank(&mut self, sector: u32) -> Result<(), Fail> {
        let changed = self.attachment.put(sector, None).ok_or(Fail::Internal)?;
        self.region_changed(changed);
        Ok(())
    }

    /// Noted at once, so a restore that fails later still has the board restart.
    fn region_changed(&mut self, now: bool) {
        if let Some(Session::Import { changed, .. }) = &mut self.backup {
            *changed |= now;
        }
    }

    /// The restored items become the image, the sectors after the last one the file
    /// carried are made blank, and the restore is over.
    pub fn import_end(&mut self) -> Result<(), Fail> {
        let Some(Session::Import { sector, .. }) = &self.backup else {
            return Err(Fail::BadBackup);
        };
        if let Some(from) = *sector {
            for blank in from..self.attachment.sectors() {
                if let Err(f) = self.region_blank(blank) {
                    self.end_session();
                    self.store.save_abort();
                    return Err(f);
                }
            }
        }
        let r = self.store.save_finish(self.index);
        self.end_session();
        r.map_err(|_| Fail::Internal)?;
        self.touch();
        Ok(())
    }
}
