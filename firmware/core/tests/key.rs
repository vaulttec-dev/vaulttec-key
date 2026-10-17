//! The key on a flash made of RAM: every rule the firmware enforces, on the host, in a
//! second. Nothing here touches a pin; `vkey check --wipe-everything` does that on the
//! board. What these prove is the part that would be expensive to prove there: power
//! cuts, torn writes, damaged flash, a taped-down button, two idle minutes, a vault
//! moved between a chip-bound firmware and a plain one, and - since items replaced
//! entries - a field whose class was rewritten in flash.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use vaultkey_core::device::{self, Device, Reach};
use vaultkey_core::hal::{Attachment, Clock, DeviceKey, NoAttachment, Ui};
use vaultkey_core::item::{Category, Class, Field, FieldKind, Item, Writer};
use vaultkey_core::login::{LOGIN_MAX, Login};
use vaultkey_core::oath::{Algo, Digits, Name, Params};
use vaultkey_core::store::{self, Layout, MAX_ATTEMPTS, Store};
use vaultkey_core::ui::{self, State};
use vaultkey_core::vault::{self, Block, Cost, KDF_BLOCKS, Passphrase, Pin};
use vaultkey_core::wire::{
    BackupHead, Cmd, Fail, HAS_OPEN, HAS_SECRET, HAS_SEED, OK, REACH_OPEN, REACH_SECRET, REACH_SEED,
};

// --- the hardware, faked -------------------------------------------------------------

/// Few passes: these tests are about what the key does, not how long it takes, and a
/// board's own cost is its measure, not theirs.
const COST: Cost = Cost::from_wire(128, 2).expect("a cost Argon2 runs");

const LAYOUT: Layout = Layout {
    attempts: 0x0000,
    state_a: 0x1000,
    state_b: 0x36000,
    state_sectors: 53,
};
const _: () = assert!(LAYOUT.fits(), "the test layout is one a board could use");
const FLASH_BYTES: usize = 0x6B000;
/// How many times a word may be written between erases: the strictest flash
/// controller a board has. A third write is a fault here, so it cannot pass on the
/// host and corrupt a word on the chip.
const WRITES_PER_WORD: u8 = 2;

/// A flash chip with NOR semantics: erase sets 0xFF, a write can only clear bits, and a
/// word takes `WRITES_PER_WORD` writes between erases. The bytes, then the writes each
/// word has taken since its last erase. Shared by reference so a "power cycle" is just a
/// second `Device` on the same chip.
#[derive(Clone)]
struct MemFlash(Rc<RefCell<Vec<u8>>>, Rc<RefCell<Vec<u8>>>);

#[derive(Debug)]
struct Fault;

impl NorFlashError for Fault {
    fn kind(&self) -> NorFlashErrorKind {
        NorFlashErrorKind::Other
    }
}

fn at(offset: u32) -> usize {
    usize::try_from(offset).expect("flash offsets fit usize")
}

impl ErrorType for MemFlash {
    type Error = Fault;
}

impl ReadNorFlash for MemFlash {
    // Whole words only, like the board's driver: an unaligned read is a fault here so
    // it cannot pass on the host and fail on the chip.
    const READ_SIZE: usize = 4;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Fault> {
        if !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
            return Err(Fault);
        }
        let o = at(offset);
        bytes.copy_from_slice(&self.0.borrow()[o..o + bytes.len()]);
        Ok(())
    }

    fn capacity(&self) -> usize {
        FLASH_BYTES
    }
}

impl NorFlash for MemFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Fault> {
        self.0.borrow_mut()[at(from)..at(to)].fill(0xFF);
        self.1.borrow_mut()[at(from) / 4..at(to) / 4].fill(0);
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Fault> {
        if !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
            return Err(Fault);
        }
        let words = at(offset) / 4..(at(offset) + bytes.len()) / 4;
        let mut writes = self.1.borrow_mut();
        if writes[words.clone()].iter().any(|w| *w >= WRITES_PER_WORD) {
            return Err(Fault);
        }
        for w in &mut writes[words] {
            *w += 1;
        }
        let mut chip = self.0.borrow_mut();
        for (cell, b) in chip[at(offset)..].iter_mut().zip(bytes) {
            *cell &= *b;
        }
        Ok(())
    }
}

impl MemFlash {
    fn blank() -> Self {
        MemFlash(
            Rc::new(RefCell::new(vec![0xFF; FLASH_BYTES])),
            Rc::new(RefCell::new(vec![0; FLASH_BYTES / 4])),
        )
    }

    fn word(&self, offset: u32) -> u32 {
        let o = at(offset);
        let chip = self.0.borrow();
        u32::from_le_bytes([chip[o], chip[o + 1], chip[o + 2], chip[o + 3]])
    }

    /// Damages one byte, whatever it held.
    fn flip(&self, offset: u32) {
        self.0.borrow_mut()[at(offset)] ^= 0xFF;
    }

    /// Rewrites bytes the way an attacker with the flash tools would.
    fn patch(&self, offset: u32, bytes: &[u8]) {
        let o = at(offset);
        self.0.borrow_mut()[o..o + bytes.len()].copy_from_slice(bytes);
    }

    /// Where a byte sequence sits in the whole chip, for a test that has to reach into
    /// an image without knowing its layout.
    fn find(&self, needle: &[u8]) -> Option<u32> {
        let chip = self.0.borrow();
        chip.windows(needle.len())
            .position(|w| w == needle)
            .map(|p| u32::try_from(p).expect("offsets fit u32"))
    }

    /// Recomputes an image copy's CRC over what the copy now holds: what an attacker
    /// with the flash tools does after editing it. A CRC catches damage, not an
    /// attacker - only the AEAD tag does that, and that is what the test is for.
    fn repair_crc(&self, addr: u32) {
        let (magic, used) = {
            let chip = self.0.borrow();
            let o = at(addr);
            let used = u32::from_le_bytes([chip[o + 8], chip[o + 9], chip[o + 10], chip[o + 11]]);
            (chip[o..o + 4].to_vec(), used)
        };
        if magic != b"VKS7" || used as usize > FLASH_BYTES {
            return; // a blank copy: nothing to repair
        }
        let body = {
            let chip = self.0.borrow();
            let o = at(addr);
            chip[o..o + at(used) - 4].to_vec()
        };
        let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC).checksum(&body);
        self.patch(addr + used - 4, &crc.to_le_bytes());
    }

    fn erased(&self) -> bool {
        self.0.borrow().iter().all(|b| *b == 0xFF)
    }

    /// Power on: a key whose button nobody ever touches.
    fn key(&self) -> Key {
        let clock = Ticker::default();
        self.key_with(Button::new(&clock, Finger::Away), clock, Unbound)
    }

    /// Power on with a finger on the button and, maybe, a chip key.
    fn key_with<K: DeviceKey>(&self, button: Button, clock: Ticker, key: K) -> Key<K> {
        self.key_full(button, clock, key, NoAttachment)
    }

    /// Power on a board that keeps passkeys beside the vault, its owner at the button.
    fn key_attached(&self, passkeys: &Passkeys) -> Key<Unbound, Passkeys> {
        let clock = Ticker::default();
        let button = Button::new(&clock, Finger::Owner);
        self.key_full(button, clock, Unbound, passkeys.clone())
    }

    fn key_full<K: DeviceKey, A: Attachment>(
        &self,
        button: Button,
        clock: Ticker,
        key: K,
        attachment: A,
    ) -> Key<K, A> {
        // The index and the buffer outlive the device, as on the board.
        let index = Box::leak(Box::new(store::Index::empty()));
        let buf: Box<[u8; device::BUF_LEN]> = vec![0u8; device::BUF_LEN]
            .into_boxed_slice()
            .try_into()
            .expect("exact size");
        let buf = Box::leak(buf);
        Device::new(
            Store::new(self.clone(), LAYOUT),
            button,
            Repeatable(7),
            clock,
            key,
            attachment,
            COST,
            index,
            buf,
        )
    }
}

/// A board's passkey flash, faked: its sectors, and what the device did with the
/// freeze - whether it holds, and every thaw with whether it was told of a change.
#[derive(Clone)]
struct Passkeys(Rc<RefCell<PasskeyState>>);

struct PasskeyState {
    sectors: Vec<Vec<u8>>,
    frozen: bool,
    /// The board let go on its own: reads and writes fail.
    expired: bool,
    thaws: Vec<bool>,
}

const SECTOR: usize = store::SECTOR as usize;

impl Passkeys {
    fn blank(count: usize) -> Self {
        Passkeys(Rc::new(RefCell::new(PasskeyState {
            sectors: vec![vec![0xFF; SECTOR]; count],
            frozen: false,
            expired: false,
            thaws: Vec::new(),
        })))
    }

    fn fill(&self, sector: usize, byte: u8) -> &Self {
        self.0.borrow_mut().sectors[sector] = vec![byte; SECTOR];
        self
    }

    /// Each sector as the byte it is filled with, 0xFF for blank.
    fn bytes(&self) -> Vec<u8> {
        self.0.borrow().sectors.iter().map(|s| s[0]).collect()
    }

    fn frozen(&self) -> bool {
        self.0.borrow().frozen
    }

    fn last_thaw(&self) -> Option<bool> {
        self.0.borrow().thaws.last().copied()
    }
}

impl Attachment for Passkeys {
    fn sectors(&self) -> u32 {
        u32::try_from(self.0.borrow().sectors.len()).expect("a few")
    }

    fn read(&mut self, i: u32, out: &mut [u8]) -> bool {
        let s = self.0.borrow();
        if !s.frozen || s.expired {
            return false;
        }
        out.copy_from_slice(&s.sectors[i as usize]);
        true
    }

    fn put(&mut self, i: u32, data: Option<&[u8]>) -> Option<bool> {
        let mut s = self.0.borrow_mut();
        if !s.frozen || s.expired {
            return None;
        }
        let want = data.map_or_else(|| vec![0xFF; SECTOR], <[u8]>::to_vec);
        let changed = s.sectors[i as usize] != want;
        s.sectors[i as usize] = want;
        Some(changed)
    }

    fn freeze(&mut self) {
        let mut s = self.0.borrow_mut();
        s.frozen = true;
        s.expired = false;
    }

    fn thaw(&mut self, changed: bool) {
        let mut s = self.0.borrow_mut();
        s.frozen = false;
        s.thaws.push(changed);
    }
}

/// Not random on purpose: a failing test must fail the same way twice.
struct Repeatable(u64);

impl RngCore for Repeatable {
    fn next_u32(&mut self) -> u32 {
        let [a, b, c, d, ..] = self.next_u64().to_le_bytes();
        u32::from_le_bytes([a, b, c, d])
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl CryptoRng for Repeatable {}

/// A board whose eFuse key is not burned: the PIN alone.
struct Unbound;

impl DeviceKey for Unbound {
    fn bound(&self) -> bool {
        false
    }

    fn mac(&mut self, msg: &[u8; 32], out: &mut [u8; 32]) -> bool {
        *out = *msg;
        true
    }
}

/// What the eFuse HMAC peripheral does, with a key the test can see.
struct ChipKey([u8; 32]);

impl DeviceKey for ChipKey {
    fn bound(&self) -> bool {
        true
    }

    fn mac(&mut self, msg: &[u8; 32], out: &mut [u8; 32]) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("any key length");
        mac.update(msg);
        out.copy_from_slice(&mac.finalize().into_bytes());
        true
    }
}

/// A clock that advances ten milliseconds every time it is read, and can be moved.
#[derive(Clone, Default)]
struct Ticker(Rc<Cell<u64>>);

impl Ticker {
    fn jump(&self, ms: u64) {
        self.0.set(self.0.get() + ms);
    }

    /// The time without spending any: what the button reads off the wall.
    fn peek(&self) -> u64 {
        self.0.get()
    }
}

impl Clock for Ticker {
    fn now_ms(&self) -> u64 {
        self.jump(10);
        self.0.get()
    }
}

/// What the finger does every time the light asks for the button.
#[derive(Clone, Copy)]
enum Finger {
    Away,
    /// A tap, each time the light comes on.
    Tap,
    /// Down for this many milliseconds, each time the light comes on.
    Hold(u64),
    /// Two taps, `gap` milliseconds apart, each time the light comes on.
    DoubleTap {
        gap: u64,
    },
    /// One tap whose contact opens for 15 ms in the middle: one press, bouncing.
    BouncyTap,
    /// The owner, doing what the light asks: two taps at blue, otherwise down for six
    /// seconds, which a tap wait takes as a tap and a hold wait as the hold.
    Owner,
    /// Down before the request arrives, and never let go.
    Taped,
}

/// The button as the clock sees it: a press is a window in time, opened 100 ms after
/// the light asks, so however often the firmware polls, debounce and hold are real.
struct Button {
    clock: Ticker,
    finger: Finger,
    down: Vec<(u64, u64)>,
    asked: u32,
    /// When the request is withdrawn, if it ever is.
    withdrawn_at: Option<u64>,
}

impl Button {
    fn new(clock: &Ticker, finger: Finger) -> Self {
        Button {
            clock: clock.clone(),
            finger,
            down: Vec::new(),
            asked: 0,
            withdrawn_at: None,
        }
    }

    /// The same finger, on a request withdrawn at `ms` on the clock.
    fn withdrawn_at(self, ms: u64) -> Self {
        Button {
            withdrawn_at: Some(ms),
            ..self
        }
    }
}

impl Ui for Button {
    fn set(&mut self, state: State) {
        if state != State::Waiting && state != State::Export {
            return;
        }
        self.asked += 1;
        let from = self.clock.peek() + 100;
        self.down = match self.finger {
            Finger::Tap => vec![(from, from + 200)],
            Finger::Hold(ms) => vec![(from, from + ms)],
            Finger::DoubleTap { gap } => {
                vec![(from, from + 200), (from + 200 + gap, from + 400 + gap)]
            }
            Finger::BouncyTap => vec![(from, from + 100), (from + 115, from + 300)],
            Finger::Owner if state == State::Export => {
                vec![(from, from + 200), (from + 320, from + 520)]
            }
            Finger::Owner => vec![(from, from + 6_000)],
            Finger::Away | Finger::Taped => Vec::new(),
        };
    }

    fn pressed(&self) -> bool {
        matches!(self.finger, Finger::Taped)
            || self
                .down
                .iter()
                .any(|(a, b)| (*a..*b).contains(&self.clock.peek()))
    }

    fn withdrawn(&self) -> bool {
        self.withdrawn_at.is_some_and(|t| self.clock.peek() >= t)
    }
}

type Key<K = Unbound, A = NoAttachment> =
    Device<'static, MemFlash, Repeatable, Button, Ticker, K, A>;

// --- helpers ---------------------------------------------------------------------------

fn pin(s: &str) -> Pin<'_> {
    Pin::new(s.as_bytes()).expect("a valid test PIN")
}

fn name(s: &str) -> Name<'_> {
    Name::new(s.as_bytes()).expect("a valid test name")
}

/// What a service usually hands out: six digits, SHA-1, thirty seconds, as the three
/// bytes that go in front of a seed's value.
fn plain_params() -> [u8; Params::WIRE_LEN] {
    Params {
        algo: Algo::Sha1,
        digits: Digits::Six,
        period: std::num::NonZeroU8::new(30).expect("thirty is not zero"),
    }
    .wire()
}

/// A seed field's value: the parameters, then the secret.
fn seed_value(secret: &[u8]) -> Vec<u8> {
    let mut v = plain_params().to_vec();
    v.extend_from_slice(secret);
    v
}

/// An item packed the way the host would pack it.
fn pack(category: Category, fields: &[(Class, FieldKind, &str, &[u8])]) -> Vec<u8> {
    let mut buf = vec![0u8; 16384];
    let mut w = Writer::new(&mut buf, category).expect("room");
    for (class, kind, label, value) in fields {
        let f = Field::new(*class, *kind, b"", label.as_bytes(), value).expect("a valid field");
        assert!(w.push(&f), "the test item must fit");
    }
    let n = w.finish();
    buf.truncate(n);
    buf
}

/// A login item: an open username, a secret password.
fn login_item(user: &str, password: &str) -> Vec<u8> {
    pack(
        Category::Login,
        &[
            (Class::Open, FieldKind::String, "username", user.as_bytes()),
            (
                Class::Secret,
                FieldKind::Concealed,
                "password",
                password.as_bytes(),
            ),
        ],
    )
}

/// A TOTP item: one seed field and nothing else.
fn totp_item(secret: &[u8]) -> Vec<u8> {
    pack(
        Category::Login,
        &[(
            Class::Seed,
            FieldKind::Otp,
            "one-time password",
            &seed_value(secret),
        )],
    )
}

fn put<K: DeviceKey, A: Attachment>(
    dev: &mut Key<K, A>,
    n: &str,
    category: Category,
    item: &[u8],
    replace: bool,
) -> Result<(), Fail> {
    dev.put(name(n), category, item, replace)
}

/// The fields of an item that `reach` allows, as (category, packed item).
fn get<K: DeviceKey>(dev: &mut Key<K>, n: &str, reach: Reach) -> Result<(u8, Vec<u8>), Fail> {
    let mut out = (0u8, Vec::new());
    dev.get(name(n), reach, |category, _, item| {
        out = (category, item.to_vec());
    })?;
    Ok(out)
}

/// What an item holds, whatever this reach could see of it.
fn shape<K: DeviceKey>(dev: &mut Key<K>, n: &str, reach: Reach) -> Result<u8, Fail> {
    let mut present = 0u8;
    dev.get(name(n), reach, |_, p, _| present = p)?;
    Ok(present)
}

/// The labels of the fields an item hands back at this reach.
fn labels<K: DeviceKey>(dev: &mut Key<K>, n: &str, reach: Reach) -> Result<Vec<String>, Fail> {
    let (_, bytes) = get(dev, n, reach)?;
    let item = Item::parse(&bytes).expect("what the device returns parses");
    Ok(item
        .fields()
        .map(|f| String::from_utf8_lossy(f.label()).into_owned())
        .collect())
}

/// The value of one field by label, at this reach.
fn value<K: DeviceKey>(dev: &mut Key<K>, n: &str, reach: Reach, label: &str) -> Option<Vec<u8>> {
    let (_, bytes) = get(dev, n, reach).ok()?;
    let item = Item::parse(&bytes).expect("what the device returns parses");
    item.fields()
        .find(|f| f.label() == label.as_bytes())
        .map(|f| f.value().to_vec())
}

fn code<K: DeviceKey>(dev: &mut Key<K>, n: &str, t: u64) -> Result<String, Fail> {
    let mut out = [0u8; 8];
    let (len, _) = dev.code(name(n), t, &mut out)?;
    Ok(String::from_utf8_lossy(&out[..len]).into_owned())
}

fn names<K: DeviceKey, A: Attachment>(dev: &mut Key<K, A>) -> Result<Vec<String>, Fail> {
    let mut out = Vec::new();
    dev.list(|n, _| out.push(String::from_utf8_lossy(n.as_bytes()).into_owned()))?;
    Ok(out)
}

fn categories<K: DeviceKey>(dev: &mut Key<K>) -> Result<Vec<(String, u8)>, Fail> {
    let mut out = Vec::new();
    dev.list(|n, c| out.push((String::from_utf8_lossy(n.as_bytes()).into_owned(), c)))?;
    Ok(out)
}

fn tapping(flash: &MemFlash) -> Key {
    let clock = Ticker::default();
    flash.key_with(Button::new(&clock, Finger::Tap), clock, Unbound)
}

fn double_tapping(flash: &MemFlash) -> Key {
    let clock = Ticker::default();
    flash.key_with(
        Button::new(&clock, Finger::DoubleTap { gap: 120 }),
        clock,
        Unbound,
    )
}

fn owned(flash: &MemFlash) -> Key {
    let clock = Ticker::default();
    flash.key_with(Button::new(&clock, Finger::Owner), clock, Unbound)
}

fn passphrase(s: &str) -> Passphrase<'_> {
    Passphrase::new(s.as_bytes()).expect("a valid test passphrase")
}

fn export<K: DeviceKey, A: Attachment>(
    dev: &mut Key<K, A>,
    pass: &str,
) -> Result<(BackupHead, Vec<Vec<u8>>), Fail> {
    let head = dev.export_begin(passphrase(pass))?;
    let mut items = Vec::new();
    loop {
        let mut item = Vec::new();
        dev.export_next(|bytes| item = bytes.to_vec())?;
        if item.is_empty() {
            return Ok((head, items));
        }
        items.push(item);
    }
}

fn import<K: DeviceKey, A: Attachment>(
    dev: &mut Key<K, A>,
    pass: &str,
    head: BackupHead,
    items: &[Vec<u8>],
) -> Result<(), Fail> {
    dev.import_begin(passphrase(pass), head)?;
    for item in items {
        dev.import_item(item)?;
    }
    dev.import_end()
}

// --- what the crypto must do ---------------------------------------------------------

#[test]
fn totp_matches_rfc_6238() {
    // The published vector: the ASCII secret "12345678901234567890" at 59 s.
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");
    assert_eq!(code(&mut dev, "rfc", 59).expect("a code"), "287082");
}

#[test]
fn seal_and_open_refuse_the_wrong_key_name_or_bytes() {
    let mut rng = Repeatable(1);
    let key = [7u8; 32];
    let other = [8u8; 32];
    let mut sealed = [0u8; 64 + vault::OVERHEAD];
    let n = vault::seal(&key, &mut rng, b"aad", b"secret", &mut sealed).expect("seals");
    let mut out = [0u8; 64];

    assert_eq!(
        vault::open(&key, b"aad", &sealed[..n], &mut out),
        Some(6),
        "the same key and aad open it"
    );
    assert!(
        vault::open(&other, b"aad", &sealed[..n], &mut out).is_none(),
        "another key must not"
    );
    assert!(
        vault::open(&key, b"other", &sealed[..n], &mut out).is_none(),
        "another aad must not: that is what binds a secret to its name and category"
    );
    let mut damaged = sealed;
    damaged[n - 1] ^= 1;
    assert!(
        vault::open(&key, b"aad", &damaged[..n], &mut out).is_none(),
        "one flipped bit must not"
    );
}

#[test]
fn the_chip_key_changes_every_derived_key() {
    let mut plain = Unbound;
    let mut chip = ChipKey([3u8; 32]);
    let mem = &mut vec![Block::new(); KDF_BLOCKS];
    let salt = [1u8; vault::SALT_LEN];

    let a = vault::derive(pin("12345678"), &salt, COST, &mut plain, mem)
        .expect("derives without a chip key");
    let b = vault::derive(pin("12345678"), &salt, COST, &mut chip, mem).expect("derives with one");
    assert_ne!(a.dek, b.dek, "the same PIN and salt, a different data key");
    assert_ne!(a.kek, b.kek, "and a different verifier key");
    assert!(
        mem.iter().all(|b| b.as_ref().iter().all(|w| *w == 0)),
        "the working memory is scrubbed"
    );
    let mut short = vec![Block::new(); 8];
    assert!(
        vault::derive(pin("12345678"), &salt, COST, &mut plain, &mut short).is_none(),
        "too little memory is an error, not a cheaper derivation"
    );
}

// --- what may exist at all -----------------------------------------------------------

#[test]
fn only_valid_values_exist() {
    assert!(Name::new(b"").is_none(), "a name is never empty");
    assert!(Name::new(&[b'x'; 33]).is_none(), "nor longer than NAME_MAX");
    assert!(Name::new(b" x").is_none(), "nor starts with a space");
    assert!(Name::new(b"x ").is_none(), "nor ends with one");
    assert!(Name::new(b"a\nb").is_none(), "nor holds a control byte");
    assert!(Name::new(b"github.com").is_some());

    assert!(Pin::new(b"1234567").is_none(), "a PIN is eight digits");
    assert!(Pin::new(b"123456789").is_none());
    assert!(Pin::new(b"1234567a").is_none(), "digits only");
    assert!(Pin::new(b"12345678").is_some());

    assert!(
        Passphrase::new(b"too short").is_none(),
        "a backup passphrase is twelve bytes at least"
    );
    assert!(Passphrase::new(b"correct horse battery staple").is_some());

    assert!(
        Item::parse(&[]).is_none(),
        "an empty slice is not an item, it is nothing"
    );
    assert!(
        Category::from_wire(250).is_none(),
        "a category this firmware does not know is refused, not defaulted"
    );
    assert!(
        Category::from_wire(201).is_none() && Cmd::from_wire(0x19).is_none(),
        "vkey auth's category and command are gone, and nothing took their numbers"
    );
}

#[test]
fn wire_codes_round_trip() {
    for cmd in [
        Cmd::Info,
        Cmd::ItemPut,
        Cmd::List,
        Cmd::Code,
        Cmd::Delete,
        Cmd::ItemGet,
        Cmd::Rename,
        Cmd::PinStatus,
        Cmd::PinSet,
        Cmd::PinUnlock,
        Cmd::PinChange,
        Cmd::Lock,
        Cmd::Wipe,
        Cmd::ExportBegin,
        Cmd::ExportNext,
        Cmd::ImportBegin,
        Cmd::ImportItem,
        Cmd::ImportEnd,
        Cmd::LoginSet,
    ] {
        assert_eq!(Cmd::from_wire(cmd.wire()), Some(cmd), "{cmd:?}");
    }
    for f in [
        Fail::Refused,
        Fail::Internal,
        Fail::NotFound,
        Fail::Full,
        Fail::BadArg,
        Fail::Locked,
        Fail::WrongPin(3),
        Fail::Wiped,
        Fail::NoPin,
        Fail::PinExists,
        Fail::Exists,
        Fail::Incompatible,
        Fail::BadBackup,
    ] {
        let payload = match f {
            Fail::WrongPin(left) => vec![left],
            _ => vec![],
        };
        assert_eq!(Fail::from_code(f.code(), &payload), Some(f), "{f:?}");
    }
    assert_ne!(OK, Fail::Refused.code(), "success is not a failure code");
}

// --- the PIN and what it guards -------------------------------------------------------

#[test]
fn pin_then_items() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);

    assert_eq!(
        put(
            &mut dev,
            "x",
            Category::Login,
            &login_item("me", "pw"),
            false
        ),
        Err(Fail::Locked),
        "nothing is stored before a PIN exists"
    );
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    assert_eq!(
        dev.pin_set(pin("87654321")),
        Err(Fail::PinExists),
        "a second PIN is a change, not a set"
    );

    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");
    assert_eq!(
        put(
            &mut dev,
            "github.com",
            Category::Login,
            &login_item("me", "other"),
            false
        ),
        Err(Fail::Exists),
        "a name is taken until it is replaced on purpose"
    );
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "other"),
        true,
    )
    .expect("replaces");

    assert_eq!(names(&mut dev).expect("lists"), ["github.com"]);
    dev.lock();
    assert_eq!(
        names(&mut dev),
        Err(Fail::Locked),
        "which names exist is behind the PIN too"
    );
}

#[test]
fn eight_wrong_pins_wipe_everything() {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "x",
        Category::Login,
        &login_item("me", "pw"),
        false,
    )
    .expect("stores");

    for left in (1..MAX_ATTEMPTS).rev() {
        assert_eq!(
            dev.pin_unlock(pin("00000000")),
            Err(Fail::WrongPin(left)),
            "each wrong PIN costs one attempt"
        );
    }
    assert_eq!(
        dev.pin_unlock(pin("00000000")),
        Err(Fail::Wiped),
        "the last one wipes"
    );
    assert!(flash.erased(), "nothing is left in flash");
}

#[test]
fn items_and_spent_attempts_survive_a_power_cycle() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("12345678")).expect("sets the PIN");
        put(
            &mut dev,
            "github.com",
            Category::Login,
            &login_item("me", "hunter2"),
            false,
        )
        .expect("stores");
        assert_eq!(
            dev.pin_unlock(pin("00000000")),
            Err(Fail::WrongPin(MAX_ATTEMPTS - 1)),
            "one attempt spent"
        );
    }
    let mut dev = flash.key(); // the power went out and came back
    assert_eq!(
        dev.pin_unlock(pin("00000000")),
        Err(Fail::WrongPin(MAX_ATTEMPTS - 2)),
        "the spent attempt did not come back with the power"
    );
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    assert_eq!(names(&mut dev).expect("lists"), ["github.com"]);
    assert_eq!(
        dev.pin_unlock(pin("00000000")),
        Err(Fail::WrongPin(MAX_ATTEMPTS - 1)),
        "a success restores the counter"
    );
}

#[test]
fn pin_change_reseals_every_item() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    dev.pin_change(pin("12345678"), pin("87654321"))
        .expect("changes the PIN");
    dev.lock();
    assert_eq!(
        dev.pin_unlock(pin("12345678")),
        Err(Fail::WrongPin(MAX_ATTEMPTS - 1)),
        "the old PIN is gone"
    );
    dev.pin_unlock(pin("87654321")).expect("the new one works");
    assert_eq!(
        value(&mut dev, "github.com", Reach::Secret, "password"),
        Some(b"hunter2".to_vec()),
        "every item opens under the new PIN"
    );
    assert_eq!(code(&mut dev, "rfc", 59).expect("a code"), "287082");
}

// --- what the flash may do to itself ---------------------------------------------------

#[test]
fn a_torn_write_falls_back_to_the_previous_image() {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "first",
        Category::Login,
        &login_item("me", "pw"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "second",
        Category::Login,
        &login_item("you", "pw"),
        false,
    )
    .expect("stores");

    // Damage the newer copy the way a power cut in the middle of that second write
    // would: the older one still holds everything up to it.
    let (a, b) = (LAYOUT.state_a, LAYOUT.state_b);
    let newer = if flash.word(a + 4) > flash.word(b + 4) {
        a
    } else {
        b
    };
    flash.flip(newer + 20);

    let mut dev = flash.key();
    dev.pin_unlock(pin("12345678"))
        .expect("the older copy still opens");
    assert_eq!(
        names(&mut dev).expect("lists"),
        ["first"],
        "one write back, and nothing in between was lost"
    );
}

#[test]
fn unreadable_flash_is_refused_until_wiped() {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("12345678")).expect("sets the PIN");

    // Both copies damaged: not a power cut, something else entirely.
    flash.patch(LAYOUT.state_a + 20, &[0; 8]);
    flash.patch(LAYOUT.state_b + 20, &[0; 8]);

    let mut dev = flash.key();
    assert!(
        matches!(
            dev.pin_unlock(pin("12345678")),
            Err(Fail::Internal | Fail::NoPin)
        ),
        "a vault this firmware cannot read is refused, never written over"
    );
}

#[test]
fn a_header_asking_for_hours_of_work_is_corrupt() {
    assert!(
        Cost::from_wire(u32::MAX, u32::MAX).is_none(),
        "a cost the firmware will not run is refused, not rounded down"
    );
    assert!(Cost::from_wire(0, 0).is_none(), "nor one that is no work");
}

// --- the button ------------------------------------------------------------------------

#[test]
fn the_button_must_be_pressed_after_the_request() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Taped), clock, Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    assert_eq!(
        code(&mut dev, "rfc", 59),
        Err(Fail::Refused),
        "a taped-down button is not a tap: the press must start after the light"
    );
}

#[test]
fn a_tap_never_wipes_and_never_exports_a_seed() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    assert_eq!(dev.wipe(), Err(Fail::Refused), "a tap is not a hold");
    assert_eq!(
        dev.export_begin(passphrase("correct horse battery staple")),
        Err(Fail::Refused),
        "a tap is not two taps"
    );
    assert_eq!(
        get(&mut dev, "rfc", Reach::Seed),
        Err(Fail::Refused),
        "and a tap never hands over a seed"
    );
    assert_eq!(
        names(&mut dev).expect("lists"),
        ["rfc"],
        "and the vault is still there"
    );
}

#[test]
fn a_bounce_in_one_press_is_not_two_taps() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::BouncyTap), clock, Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");
    assert_eq!(
        dev.export_begin(passphrase("correct horse battery staple")),
        Err(Fail::Refused),
        "the contact opening for 15 ms mid-press is not a release"
    );
    code(&mut dev, "rfc", 59).expect("and the bouncing tap still approves a code");
}

#[test]
fn a_withdrawn_tap_wait_ends_refused_and_at_once() {
    let clock = Ticker::default();
    let mut button = Button::new(&clock, Finger::Away).withdrawn_at(1_000);
    assert!(!ui::await_confirmation(&mut button, &clock, 30_000));
    assert!(
        clock.peek() < 2_000,
        "the wait ends when the request goes, not at its deadline: {} ms",
        clock.peek()
    );
}

#[test]
fn a_withdrawn_hold_never_completes() {
    // Down from 100 ms for ten seconds; withdrawn two seconds into the hold.
    let clock = Ticker::default();
    let mut button = Button::new(&clock, Finger::Hold(10_000)).withdrawn_at(2_100);
    assert!(
        !ui::await_hold(&mut button, &clock, 30_000, 5_000),
        "a hold that goes on past five seconds after the request was withdrawn is no wipe"
    );
}

#[test]
fn a_withdrawn_second_tap_window_ends_refused() {
    // First tap 100..300 ms, second 700..900 ms; withdrawn between them.
    let clock = Ticker::default();
    let mut button = Button::new(&clock, Finger::DoubleTap { gap: 400 }).withdrawn_at(500);
    assert!(!ui::await_double_tap(&mut button, &clock, 30_000));
}

#[test]
fn a_hold_wipes_and_nothing_else_does() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Hold(6_000)), clock, Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    dev.wipe().expect("a five-second hold wipes");
    assert!(flash.erased());
}

// --- the class is the boundary ---------------------------------------------------------

#[test]
fn the_class_decides_what_comes_out_and_at_what_gesture() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Away), clock, Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me@example.com", "hunter2"),
        false,
    )
    .expect("stores");

    // No finger anywhere near the button.
    assert_eq!(
        labels(&mut dev, "github.com", Reach::Open).expect("open fields need no gesture"),
        ["username"],
        "the PIN alone reaches what is open"
    );
    assert_eq!(
        get(&mut dev, "github.com", Reach::Secret),
        Err(Fail::Refused),
        "and reaches nothing more without the tap"
    );

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    let mut fields = labels(&mut dev, "github.com", Reach::Secret).expect("a tap reaches secrets");
    fields.sort();
    assert_eq!(
        fields,
        ["password", "username"],
        "a tap hands over the open fields and the secrets, and nothing else exists here"
    );
}

#[test]
fn a_seed_leaves_only_under_the_export_gesture() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    assert_eq!(
        labels(&mut dev, "rfc", Reach::Secret).expect("a tap is answered"),
        Vec::<String>::new(),
        "a tap reaches no seed field at all: the item comes back empty, not refused"
    );
    assert_eq!(
        code(&mut dev, "rfc", 59).expect("a code"),
        "287082",
        "what a tap does get is the code the seed computes"
    );

    let mut dev = double_tapping(&flash);
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    assert_eq!(
        value(&mut dev, "rfc", Reach::Seed, "one-time password"),
        Some(seed_value(b"12345678901234567890")),
        "two taps, and the seed itself comes out - the maintainer's decision of 2026-09-19"
    );
}

#[test]
fn a_category_rewritten_in_flash_hands_over_nothing() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    // The category is plaintext in the index - and under the AEAD tag. An attacker with the
    // flash tools rewrites it and repairs the CRC, because a CRC catches damage, not
    // an attack; what must stop them is the tag.
    let name_at = flash.find(b"rfc").expect("the name is in the image");
    flash.patch(name_at - 3, &[Category::SecureNote.wire()]);
    flash.repair_crc(LAYOUT.state_a);
    flash.repair_crc(LAYOUT.state_b);

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("12345678"))
        .expect("the image still checks out: the CRC was repaired");
    assert_eq!(
        get(&mut dev, "rfc", Reach::Secret),
        Err(Fail::Internal),
        "but the category is under the AEAD tag, so the item opens for nobody"
    );
    assert_eq!(
        code(&mut dev, "rfc", 59),
        Err(Fail::Internal),
        "and no code comes out of it either"
    );
}

#[test]
fn a_class_rewritten_in_flash_hands_over_nothing() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");

    // The class lives inside the sealed item body. An attacker tampering with the
    // ciphertext byte where the class resides and repairing the CRC cannot forge
    // access: the AEAD authentication fails.
    let name_at = flash.find(b"rfc").expect("the name is in the image");
    let class_at = name_at + 4 + u32::try_from(vault::NONCE_LEN).expect("12 fits u32");
    flash.patch(class_at, &[Class::Open.wire()]);
    flash.repair_crc(LAYOUT.state_a);
    flash.repair_crc(LAYOUT.state_b);

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("12345678"))
        .expect("the image checks out: CRC repaired");
    assert_eq!(
        get(&mut dev, "rfc", Reach::Open),
        Err(Fail::Internal),
        "tampered class in ciphertext fails AEAD verification"
    );
    assert_eq!(
        code(&mut dev, "rfc", 59),
        Err(Fail::Internal),
        "and no code comes out of a tampered item"
    );
}

// --- names and renames -------------------------------------------------------------------

#[test]
fn a_rename_keeps_the_secret() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "old",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");

    dev.rename(name("old"), name("new")).expect("renames");
    assert_eq!(names(&mut dev).expect("lists"), ["new"]);
    assert_eq!(
        value(&mut dev, "new", Reach::Secret, "password"),
        Some(b"hunter2".to_vec()),
        "the name is under the tag, so this was a re-seal, and the secret survived it"
    );
    assert_eq!(
        dev.rename(name("new"), name("new")),
        Err(Fail::Exists),
        "a name is not free because it is its own"
    );
}

#[test]
fn a_deleted_item_is_gone_from_the_image() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "first",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "second",
        Category::Login,
        &login_item("you", "swordfish"),
        false,
    )
    .expect("stores");

    dev.delete(name("first")).expect("deletes");
    assert_eq!(names(&mut dev).expect("lists"), ["second"]);
    assert_eq!(
        get(&mut dev, "first", Reach::Open),
        Err(Fail::NotFound),
        "and it is not merely hidden"
    );

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    assert_eq!(
        names(&mut dev).expect("lists"),
        ["second"],
        "the deletion outlived the power cycle"
    );
}

#[test]
fn two_idle_minutes_lock_the_key() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Tap), clock.clone(), Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "x",
        Category::Login,
        &login_item("me", "pw"),
        false,
    )
    .expect("stores");

    clock.jump(121_000);
    dev.tick();
    assert_eq!(
        names(&mut dev),
        Err(Fail::Locked),
        "an unlocked key left on the desk locks itself"
    );
}

// --- a vault that moves ------------------------------------------------------------------

#[test]
fn a_vault_from_the_other_key_setup_is_refused_not_guessed_at() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key(); // no chip key
        dev.pin_set(pin("12345678")).expect("sets the PIN");
    }
    let clock = Ticker::default();
    let mut dev = flash.key_with(
        Button::new(&clock, Finger::Away),
        clock,
        ChipKey([9u8; 32]), // the same flash, a firmware whose eFuse key is burned
    );
    assert_eq!(
        dev.pin_unlock(pin("12345678")),
        Err(Fail::Incompatible),
        "the PIN would fail anyway; say so instead of spending the attempts"
    );
}

#[test]
fn a_backup_moves_every_item_to_another_board() {
    let source = MemFlash::blank();
    let mut dev = double_tapping(&source);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "myapp",
        Category::Env,
        &pack(
            Category::Env,
            &[(Class::Secret, FieldKind::String, ".env", b"KEY=value\n")],
        ),
        false,
    )
    .expect("stores an env item");

    let (head, items) = export(&mut dev, "correct horse battery staple").expect("exports");
    assert_eq!(items.len(), 3, "every item, and nothing twice");

    // A different board: a blank flash and a new PIN of its own.
    let target = MemFlash::blank();
    let mut other = owned(&target);
    other.pin_set(pin("87654321")).expect("sets its own PIN");
    import(&mut other, "correct horse battery staple", head, &items).expect("restores");

    let mut restored = names(&mut other).expect("lists");
    restored.sort();
    assert_eq!(restored, ["github.com", "myapp", "rfc"]);
    assert_eq!(
        value(&mut other, "github.com", Reach::Seed, "password"),
        Some(b"hunter2".to_vec()),
        "a password came across"
    );
    assert_eq!(
        value(&mut other, "myapp", Reach::Seed, ".env"),
        Some(b"KEY=value\n".to_vec()),
        "and so did a .env, which is now an item like any other"
    );

    let mut tapped = tapping(&target);
    tapped.pin_unlock(pin("87654321")).expect("unlocks");
    assert_eq!(
        code(&mut tapped, "rfc", 59).expect("a code"),
        "287082",
        "and the seed still computes the same codes"
    );
}

#[test]
fn a_backup_refuses_the_wrong_passphrase_and_a_reordered_file() {
    let flash = MemFlash::blank();
    let mut dev = double_tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "a",
        Category::Login,
        &login_item("me", "one"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "b",
        Category::Login,
        &login_item("me", "two"),
        false,
    )
    .expect("stores");
    let (head, items) = export(&mut dev, "correct horse battery staple").expect("exports");

    let target = MemFlash::blank();
    let mut other = owned(&target);
    other.pin_set(pin("87654321")).expect("sets a PIN");
    assert_eq!(
        import(&mut other, "wrong passphrase here", head, &items),
        Err(Fail::BadBackup),
        "another passphrase opens nothing"
    );

    let swapped = vec![items[1].clone(), items[0].clone()];
    assert_eq!(
        import(&mut other, "correct horse battery staple", head, &swapped),
        Err(Fail::BadBackup),
        "an item's position is under its tag: a reordered file is a changed file"
    );
}

// --- passkeys in a backup -----------------------------------------------------------------

const PASS: &str = "correct horse battery staple";

/// A board with passkeys in sectors 1 and 3 of four, a PIN and one item.
fn board_with_passkeys() -> (MemFlash, Passkeys, Key<Unbound, Passkeys>) {
    let flash = MemFlash::blank();
    let passkeys = Passkeys::blank(4);
    passkeys.fill(1, 0x11).fill(3, 0x33);
    let mut dev = flash.key_attached(&passkeys);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "pw"),
        false,
    )
    .expect("stores");
    (flash, passkeys, dev)
}

#[test]
fn passkeys_go_into_a_backup_and_come_back_exactly() {
    let (_, passkeys, mut dev) = board_with_passkeys();
    let (head, blobs) = export(&mut dev, PASS).expect("exports");
    assert_eq!(
        blobs.len(),
        3,
        "one item and the two sectors that are not blank"
    );
    assert!(!passkeys.frozen(), "and the passkeys are served again");

    let target = Passkeys::blank(4);
    target.fill(0, 0x55).fill(2, 0x77);
    let other_flash = MemFlash::blank();
    let mut other = other_flash.key_attached(&target);
    other.pin_set(pin("87654321")).expect("sets the PIN");
    import(&mut other, PASS, head, &blobs).expect("restores");
    assert_eq!(
        target.bytes(),
        [0xFF, 0x11, 0xFF, 0x33],
        "the copy exactly: what the file skipped is blank, whatever was there"
    );
    assert_eq!(
        target.last_thaw(),
        Some(true),
        "told it changed: the board restarts"
    );
    assert_eq!(names(&mut other).expect("lists"), ["github.com"]);

    import(&mut other, PASS, head, &blobs).expect("restores again");
    assert_eq!(
        target.last_thaw(),
        Some(false),
        "the same passkeys again change nothing, so nothing restarts"
    );
}

#[test]
fn a_backup_without_passkeys_leaves_them_alone() {
    let flash = MemFlash::blank();
    let mut plain = double_tapping(&flash);
    plain.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut plain,
        "github.com",
        Category::Login,
        &login_item("me", "pw"),
        false,
    )
    .expect("stores");
    let (head, blobs) = export(&mut plain, PASS).expect("exports");

    let (_, passkeys, mut dev) = board_with_passkeys();
    import(&mut dev, PASS, head, &blobs).expect("restores");
    assert_eq!(
        passkeys.bytes(),
        [0xFF, 0x11, 0xFF, 0x33],
        "an older backup, or one from the C6, keeps the passkeys there are"
    );
    assert_eq!(passkeys.last_thaw(), Some(false));
}

#[test]
fn a_board_without_passkeys_or_laid_out_otherwise_refuses_them() {
    let (_, _, mut dev) = board_with_passkeys();
    let (head, blobs) = export(&mut dev, PASS).expect("exports");

    let flash = MemFlash::blank();
    let mut plain = owned(&flash);
    plain.pin_set(pin("12345678")).expect("sets the PIN");
    assert_eq!(
        import(&mut plain, PASS, head, &blobs),
        Err(Fail::BadBackup),
        "a board with nowhere to put passkeys says so rather than drop them"
    );

    let wider = Passkeys::blank(5);
    wider.fill(4, 0x44);
    let other_flash = MemFlash::blank();
    let mut other = other_flash.key_attached(&wider);
    other.pin_set(pin("12345678")).expect("sets the PIN");
    assert_eq!(import(&mut other, PASS, head, &blobs), Err(Fail::BadBackup));
    assert_eq!(
        wider.bytes(),
        [0xFF, 0xFF, 0xFF, 0xFF, 0x44],
        "a filesystem of another size would not mount: nothing of it is written"
    );
    assert!(!wider.frozen());
}

#[test]
fn a_restore_takes_the_wipes_hold_and_nothing_less() {
    let (_, _, mut dev) = board_with_passkeys();
    let (head, blobs) = export(&mut dev, PASS).expect("exports");

    for finger in [
        Finger::Tap,
        Finger::DoubleTap { gap: 120 },
        Finger::Hold(2_000),
    ] {
        let passkeys = Passkeys::blank(4);
        passkeys.fill(0, 0x55);
        let flash = MemFlash::blank();
        let clock = Ticker::default();
        let mut other = flash.key_full(
            Button::new(&clock, finger),
            clock,
            Unbound,
            passkeys.clone(),
        );
        other.pin_set(pin("87654321")).expect("sets the PIN");
        put(
            &mut other,
            "mine",
            Category::Login,
            &login_item("me", "pw"),
            false,
        )
        .expect("stores");
        assert_eq!(
            import(&mut other, PASS, head, &blobs),
            Err(Fail::Refused),
            "a host that knows the PIN must not swap in passkeys of its own"
        );
        assert_eq!(passkeys.bytes(), [0x55, 0xFF, 0xFF, 0xFF], "untouched");
        assert_eq!(names(&mut other).expect("lists"), ["mine"]);
    }
}

#[test]
fn every_way_a_session_ends_lets_the_passkeys_go() {
    let (_, passkeys, mut dev) = board_with_passkeys();

    dev.export_begin(passphrase(PASS)).expect("begins");
    assert!(passkeys.frozen(), "held from the double tap on");
    dev.lock();
    assert!(!passkeys.frozen(), "a lock ends it");

    dev.pin_unlock(pin("12345678")).expect("unlocks");
    dev.export_begin(passphrase(PASS)).expect("begins");
    names(&mut dev).expect("lists");
    assert!(
        !passkeys.frozen(),
        "anything that reloads the index ends it"
    );

    let (head, blobs) = export(&mut dev, PASS).expect("exports");
    dev.import_begin(passphrase(PASS), head).expect("begins");
    assert!(passkeys.frozen(), "a restore holds it too");
    assert_eq!(
        dev.import_item(&blobs[2]),
        Err(Fail::BadBackup),
        "out of order"
    );
    assert!(!passkeys.frozen(), "and a refused item ends it");

    dev.import_begin(passphrase(PASS), head).expect("begins");
    dev.import_end().expect("an empty restore");
    assert!(!passkeys.frozen(), "as does the end");

    dev.export_begin(passphrase(PASS)).expect("begins");
    let mut item = Vec::new();
    dev.export_next(|b| item = b.to_vec()).expect("the item");
    passkeys.0.borrow_mut().expired = true;
    assert_eq!(
        dev.export_next(|_| {}),
        Err(Fail::Internal),
        "a board that let go mid-backup gives no sector, so no copy is torn"
    );
    assert!(!passkeys.frozen());
}

// --- the shape of a reach on the wire -------------------------------------------------------

#[test]
fn the_shape_says_what_is_there_without_handing_it_over() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Away), clock, Unbound);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "rfc",
        Category::Login,
        &totp_item(b"12345678901234567890"),
        false,
    )
    .expect("stores");
    put(
        &mut dev,
        "github.com",
        Category::Login,
        &login_item("me", "hunter2"),
        false,
    )
    .expect("stores");

    // No finger on the button: the shape costs no gesture, which is the point - the
    // host must not have to ask for a tap just to learn what an item is for.
    let seed_shape = shape(&mut dev, "rfc", Reach::Open).expect("answers");
    assert_eq!(
        seed_shape & HAS_SEED,
        HAS_SEED,
        "a TOTP item says it has a seed"
    );
    assert_eq!(
        get(&mut dev, "rfc", Reach::Open).expect("answers").1,
        {
            let mut empty = vec![0u8; 64];
            let w = Writer::new(&mut empty, Category::Login).expect("room");
            let n = w.finish();
            empty.truncate(n);
            empty
        },
        "and hands over nothing at all at this reach"
    );

    let login_shape = shape(&mut dev, "github.com", Reach::Open).expect("answers");
    assert_eq!(login_shape & HAS_SEED, 0, "a password item has no seed");
    assert_eq!(
        login_shape & (HAS_OPEN | HAS_SECRET),
        HAS_OPEN | HAS_SECRET,
        "it has an open field and a secret one"
    );
}

#[test]
fn every_reach_has_a_wire_byte_and_no_others_do() {
    assert_ne!(REACH_OPEN, REACH_SECRET);
    assert_ne!(REACH_SECRET, REACH_SEED);
    assert_ne!(REACH_OPEN, REACH_SEED);
    assert!(
        ![REACH_OPEN, REACH_SECRET, REACH_SEED].contains(&0),
        "zero is not a reach: an all-zero payload must not read as one"
    );
}

#[test]
fn a_category_the_host_invents_is_refused_before_anything_is_stored() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    let mut bad = login_item("me", "pw");
    bad[0] = 250; // a category byte inside the item that no firmware knows
    assert_eq!(
        put(&mut dev, "x", Category::Login, &bad, false),
        Err(Fail::BadArg),
        "an item the device cannot parse is never written"
    );
    assert!(names(&mut dev).expect("lists").is_empty());
}

#[test]
fn the_list_says_what_each_item_is() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    put(
        &mut dev,
        "card",
        Category::CreditCard,
        &pack(
            Category::CreditCard,
            &[
                (
                    Class::Open,
                    FieldKind::String,
                    "number",
                    b"4111111111111111",
                ),
                (Class::Secret, FieldKind::Concealed, "cvv", b"123"),
            ],
        ),
        false,
    )
    .expect("stores");

    assert_eq!(
        categories(&mut dev).expect("lists"),
        [("card".to_string(), Category::CreditCard.wire())],
        "the category travels with the name, so the host can show it without opening"
    );
    assert_eq!(
        labels(&mut dev, "card", Reach::Open).expect("open fields"),
        ["number"],
        "a card number is not a secret; the CVV is"
    );
}

// --- the login password and the unasked double tap -----------------------------------

/// How often the board looks at an idle button, at least: every read of the vkey line.
const IDLE_SAMPLE_MS: u64 = 5;

/// When `IdleDoubleTap` fires over `until` ms of samples, the button down in each of
/// `down`'s windows, and no sample at all during `pause`.
fn idle_fires(down: &[(u64, u64)], pause: Option<(u64, u64)>, until: u64) -> Vec<u64> {
    let mut gesture = ui::IdleDoubleTap::new();
    let mut fired = Vec::new();
    for now in (0..until).step_by(usize::try_from(IDLE_SAMPLE_MS).expect("small")) {
        if pause.is_some_and(|(from, to)| (from..to).contains(&now)) {
            continue;
        }
        let pressed = down.iter().any(|&(from, to)| (from..to).contains(&now));
        if gesture.sample(pressed, now) {
            fired.push(now);
        }
    }
    fired
}

#[test]
fn an_idle_double_tap_is_two_short_taps() {
    assert_eq!(
        idle_fires(&[(100, 180), (300, 380)], None, 1_000).len(),
        1,
        "two taps fire once, on the second release"
    );
    assert!(
        idle_fires(&[(100, 180)], None, 2_000).is_empty(),
        "one tap is a code's reflex, not this"
    );
    assert!(
        idle_fires(&[(100, 180), (1_100, 1_180)], None, 2_000).is_empty(),
        "taps too far apart are two single taps"
    );
    assert!(
        idle_fires(&[(100, 800), (900, 980)], None, 2_000).is_empty(),
        "a hold is not a tap"
    );
    assert!(
        idle_fires(&[(100, 180), (300, 1_300)], None, 2_000).is_empty(),
        "nor is a second press held on"
    );
    assert!(
        idle_fires(&[(100, 140), (155, 200)], None, 1_000).is_empty(),
        "a tap bouncing open for 15 ms is one tap"
    );
}

#[test]
fn an_idle_double_tap_starts_from_a_button_seen_up() {
    assert!(
        idle_fires(&[(0, 100), (250, 330)], None, 1_000).is_empty(),
        "a press already down when the board starts looking is not the first tap"
    );
    assert!(
        idle_fires(&[(100, 180), (300, 380)], Some((150, 250)), 1_000).is_empty(),
        "a tap that went to a request the key was serving is not the first tap"
    );
}

#[test]
fn the_login_password_takes_the_pin_and_a_tap() {
    fn typed(b: &[u8]) -> Login<'_> {
        Login::new(b).expect("a valid login password")
    }
    let flash = MemFlash::blank();
    let kept = RefCell::new(Vec::new());
    let keep = |login: Option<Login<'_>>| {
        kept.borrow_mut().push(login.map(|l| l.as_bytes().to_vec()));
        true
    };

    let mut dev = tapping(&flash);
    assert_eq!(
        dev.login(Some(typed(b"hunter2")), keep),
        Err(Fail::Locked),
        "nothing is kept before the vault is unlocked"
    );
    dev.pin_set(pin("12345678")).expect("sets the PIN");
    dev.login(Some(typed(b"hunter2")), keep)
        .expect("kept after a tap");
    dev.login(None, keep).expect("forgotten after a tap");
    assert_eq!(*kept.borrow(), [Some(b"hunter2".to_vec()), None]);

    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Away), clock, Unbound);
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    assert_eq!(
        dev.login(Some(typed(b"evil")), keep),
        Err(Fail::Refused),
        "no tap, nothing kept"
    );
    assert_eq!(kept.borrow().len(), 2, "the board was never asked");

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("12345678")).expect("unlocks");
    assert_eq!(
        dev.login(Some(typed(b"hunter2")), |_| false),
        Err(Fail::Internal),
        "a board that cannot keep it says so"
    );
}

#[test]
fn a_login_password_is_printable_ascii_only() {
    assert!(Login::new(b"Correct Horse 9!~").is_some());
    assert!(
        Login::new(b"").is_none(),
        "empty means forget, not a password"
    );
    assert!(Login::new(&[b'a'; LOGIN_MAX]).is_some());
    assert!(Login::new(&[b'a'; LOGIN_MAX + 1]).is_none());
    assert!(
        Login::new(b"pw\nrm -rf ~").is_none(),
        "a control character would type a command after it"
    );
    assert!(
        Login::new("пароль".as_bytes()).is_none(),
        "no key for it on a US keyboard"
    );
}
