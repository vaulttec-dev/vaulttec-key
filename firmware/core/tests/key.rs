//! The key on a flash made of RAM: every rule the firmware enforces, on the host, in a
//! second. Nothing here touches a pin; `vkey check --wipe-everything` does that on
//! the board. What these prove is the part that would be expensive to prove there:
//! power cuts, torn writes, damaged flash, a taped-down button, two idle minutes, a
//! vault moved between a chip-bound firmware and a plain one, and a record whose kind
//! was rewritten in flash.

use std::cell::{Cell, RefCell};
use std::num::NonZeroU8;
use std::rc::Rc;

use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use vaultkey_core::device::{self, Device};
use vaultkey_core::hal::{Clock, DeviceKey, Ui};
use vaultkey_core::oath::{self, Algo, Digits, Entry, Kind, Name, Params, SECRET_MAX};
use vaultkey_core::store::{self, Layout, MAX_ATTEMPTS, MAX_ENTRIES, Store};
use vaultkey_core::ui::State;
use vaultkey_core::vault::{self, Block, Cost, KDF_BLOCKS, Passphrase, Pin};
use vaultkey_core::wire::{BackupHead, Cmd, Fail, OK};

// --- the hardware, faked -------------------------------------------------------------

const LAYOUT: Layout = Layout {
    attempts: 0x0000,
    state_a: 0x1000,
    state_b: 0x16000,
    env: 0x2B000,
};
const FLASH_BYTES: usize = 0x6B000;
/// One copy of an env slot; a slot is two of them.
const ENV_COPY: u32 = 0x2000;

/// A flash chip with NOR semantics: erase sets 0xFF, a write can only clear bits.
/// Shared by reference so a "power cycle" is just a second `Device` on the same chip.
#[derive(Clone)]
struct MemFlash(Rc<RefCell<Vec<u8>>>);

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
    // Whole words only, like the board's driver: an unaligned read is a fault here
    // so it cannot pass on the host and fail on the chip.
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
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Fault> {
        if !offset.is_multiple_of(4) || !bytes.len().is_multiple_of(4) {
            return Err(Fault);
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
        MemFlash(Rc::new(RefCell::new(vec![0xFF; FLASH_BYTES])))
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

    fn bytes(&self, offset: u32, len: u32) -> Vec<u8> {
        self.0.borrow()[at(offset)..at(offset + len)].to_vec()
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
        // The Argon2 memory, the state and the env buffer outlive the device, as on
        // the board.
        let mem = Box::leak(vec![Block::new(); KDF_BLOCKS].into_boxed_slice());
        let state = Box::leak(Box::new(store::State::empty()));
        let env = Box::leak(Box::new([0u8; device::BUF_LEN]));
        Device::new(
            Store::new(self.clone(), LAYOUT),
            button,
            Repeatable(7),
            clock,
            key,
            mem,
            state,
            env,
        )
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
    /// One tap, for the first light only.
    TapOnce,
    /// Down for this many milliseconds, each time the light comes on.
    Hold(u64),
    /// Two taps, `gap` milliseconds apart, each time the light comes on.
    DoubleTap {
        gap: u64,
    },
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
}

impl Button {
    fn new(clock: &Ticker, finger: Finger) -> Self {
        Button {
            clock: clock.clone(),
            finger,
            down: Vec::new(),
            asked: 0,
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
            Finger::TapOnce if self.asked == 1 => vec![(from, from + 200)],
            Finger::Hold(ms) => vec![(from, from + ms)],
            Finger::DoubleTap { gap } => {
                vec![(from, from + 200), (from + 200 + gap, from + 400 + gap)]
            }
            Finger::Away | Finger::TapOnce | Finger::Taped => Vec::new(),
        };
    }

    fn pressed(&self) -> bool {
        matches!(self.finger, Finger::Taped)
            || self
                .down
                .iter()
                .any(|(a, b)| (*a..*b).contains(&self.clock.peek()))
    }
}

type Key<K = Unbound> = Device<'static, MemFlash, Repeatable, Button, Ticker, K>;

// --- helpers ---------------------------------------------------------------------------

fn pin(s: &str) -> Pin<'_> {
    Pin::new(s.as_bytes()).expect("a valid test PIN")
}

fn name(s: &str) -> Name<'_> {
    Name::new(s.as_bytes()).expect("a valid test name")
}

const fn params(algo: Algo, digits: Digits, period: u8) -> Params {
    Params {
        algo,
        digits,
        period: NonZeroU8::new(period).expect("test periods are never zero"),
    }
}

/// What a service usually hands out: six digits, SHA-1, thirty seconds.
const PLAIN: Kind = Kind::Totp(params(Algo::Sha1, Digits::Six, 30));

fn entry(n: &str, secret: &[u8]) -> Entry {
    Entry::new(name(n), PLAIN, secret).expect("a valid test entry")
}

fn password(n: &str, secret: &[u8]) -> Entry {
    Entry::password(name(n), b"me@example.com", secret, b"").expect("a valid test entry")
}

fn login(dev: &mut Key, n: &str) -> Result<Vec<u8>, Fail> {
    let mut out = [0u8; SECRET_MAX];
    let len = dev.login(name(n), &mut out)?;
    Ok(out[..len].to_vec())
}

fn code<K: DeviceKey>(dev: &mut Key<K>, n: &str, t: u64) -> Result<String, Fail> {
    let mut out = [0u8; 8];
    let len = dev.code(name(n), t, &mut out)?;
    Ok(String::from_utf8_lossy(&out[..len]).into_owned())
}

/// The password out of what `reveal` hands back: the packed entry, unpacked by the
/// same `Entry` the host uses.
fn reveal(dev: &mut Key, n: &str) -> Result<Vec<u8>, Fail> {
    let mut out = [0u8; SECRET_MAX];
    let len = dev.reveal(name(n), &mut out)?;
    let e = Entry::new(name(n), Kind::Password, &out[..len]).expect("a reveal is a password pack");
    Ok(e.password_bytes().expect("a password entry").to_vec())
}

fn names<K: DeviceKey>(dev: &mut Key<K>) -> Result<Vec<String>, Fail> {
    Ok(kinds(dev)?.into_iter().map(|(n, _)| n).collect())
}

fn kinds<K: DeviceKey>(dev: &mut Key<K>) -> Result<Vec<(String, Kind)>, Fail> {
    let mut v = Vec::new();
    dev.list(|n, k| v.push((String::from_utf8_lossy(n.as_bytes()).into_owned(), k)))?;
    Ok(v)
}

fn env_put<K: DeviceKey>(
    dev: &mut Key<K>,
    n: &str,
    blob: &[u8],
    replace: bool,
) -> Result<(), Fail> {
    dev.env_put(name(n), blob, replace)
}

fn env_get<K: DeviceKey>(dev: &mut Key<K>, n: &str) -> Result<Vec<u8>, Fail> {
    let mut out = Vec::new();
    dev.env_get(name(n), |plain| out.extend_from_slice(plain))?;
    Ok(out)
}

/// A key with a finger that taps whenever the light asks: how codes get requested.
fn tapping(flash: &MemFlash) -> Key {
    let clock = Ticker::default();
    flash.key_with(Button::new(&clock, Finger::Tap), clock, Unbound)
}

fn passphrase(s: &str) -> Passphrase<'_> {
    Passphrase::new(s.as_bytes()).expect("a valid test passphrase")
}

/// A whole backup as the host would keep it: the head, then every item in order.
fn export<K: DeviceKey>(dev: &mut Key<K>, pass: &str) -> Result<(BackupHead, Vec<Vec<u8>>), Fail> {
    let head = dev.export_begin(passphrase(pass))?;
    let mut items = Vec::new();
    loop {
        let mut item = Vec::new();
        dev.export_next(|sealed| item.extend_from_slice(sealed))?;
        if item.is_empty() {
            return Ok((head, items));
        }
        items.push(item);
    }
}

fn import<K: DeviceKey>(
    dev: &mut Key<K>,
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

/// A key whose finger taps twice at every light: how a backup gets approved.
fn double_tapping(flash: &MemFlash) -> Key {
    let clock = Ticker::default();
    let finger = Finger::DoubleTap { gap: 300 };
    flash.key_with(Button::new(&clock, finger), clock, Unbound)
}

// --- the maths -------------------------------------------------------------------------

#[test]
fn totp_matches_rfc_6238() {
    // Appendix B of the RFC: six moments, SHA-1 with the 20-byte seed and SHA-256
    // with the 32-byte one, eight digits each.
    let sha1 = params(Algo::Sha1, Digits::Eight, 30);
    let sha256 = params(Algo::Sha256, Digits::Eight, 30);
    let table = [
        (59, "94287082", "46119246"),
        (1_111_111_109, "07081804", "68084774"),
        (1_111_111_111, "14050471", "67062674"),
        (1_234_567_890, "89005924", "91819424"),
        (2_000_000_000, "69279037", "90698825"),
        (20_000_000_000, "65353130", "77737706"),
    ];
    let mut out = [0u8; 8];
    for (t, want_sha1, want_sha256) in table {
        let n = oath::totp(sha1, b"12345678901234567890", t, &mut out);
        assert_eq!(&out[..n], want_sha1.as_bytes(), "SHA-1 at T={t}");
        let n = oath::totp(sha256, b"12345678901234567890123456789012", t, &mut out);
        assert_eq!(&out[..n], want_sha256.as_bytes(), "SHA-256 at T={t}");
    }
    // Six digits are the low six of the same number.
    let six = params(Algo::Sha1, Digits::Six, 30);
    let n = oath::totp(six, b"12345678901234567890", 59, &mut out);
    assert_eq!(&out[..n], b"287082");
}

#[test]
fn seal_and_open_refuse_the_wrong_key_name_or_bytes() {
    let mut rng = Repeatable(1);
    let dek = [7u8; vault::KEY_LEN];
    let other = [8u8; vault::KEY_LEN];
    let mut sealed = [0u8; SECRET_MAX + vault::OVERHEAD];
    let n = vault::seal(&dek, &mut rng, b"github", b"secret", &mut sealed).expect("fits");
    assert_eq!(n, 6 + vault::OVERHEAD);
    let mut out = [0u8; SECRET_MAX];
    assert_eq!(
        vault::open(&dek, b"github", &sealed[..n], &mut out),
        Some(6)
    );
    assert_eq!(&out[..6], b"secret");

    assert_eq!(
        vault::open(&other, b"github", &sealed[..n], &mut out),
        None,
        "wrong key"
    );
    assert_eq!(
        vault::open(&dek, b"gitlab", &sealed[..n], &mut out),
        None,
        "another slot's name"
    );
    let mut bent = sealed;
    bent[vault::NONCE_LEN] ^= 1;
    assert_eq!(
        vault::open(&dek, b"github", &bent[..n], &mut out),
        None,
        "tampered ciphertext"
    );
    assert!(
        out[..6].iter().all(|b| *b == 0),
        "a failed open leaves nothing behind"
    );
    assert_eq!(
        vault::open(&dek, b"github", &sealed[..vault::OVERHEAD - 1], &mut out),
        None,
        "too short"
    );

    // The in-place pair, for blobs too big to hold twice: same bytes, same rules.
    let mut buf = [0u8; 6 + vault::OVERHEAD];
    buf[vault::NONCE_LEN..vault::NONCE_LEN + 6].copy_from_slice(b"secret");
    assert_eq!(
        vault::seal_in_place(&dek, &mut rng, b"github", &mut buf, 6),
        Some(buf.len())
    );
    let mut copy = buf;
    assert_eq!(vault::open_in_place(&dek, b"github", &mut copy), Some(6));
    assert_eq!(&copy[vault::NONCE_LEN..vault::NONCE_LEN + 6], b"secret");
    assert_eq!(
        vault::open_in_place(&other, b"github", &mut buf),
        None,
        "wrong key, in place"
    );
    assert!(
        buf[vault::NONCE_LEN..].iter().all(|b| *b == 0),
        "a failed open in place leaves nothing behind either"
    );
}

#[test]
fn the_chip_key_changes_every_derived_key() {
    let salt = [3u8; vault::SALT_LEN];
    let mut mem = vec![Block::new(); KDF_BLOCKS];
    let plain = vault::derive(pin("123456"), &salt, Cost::CURRENT, &mut Unbound, &mut mem)
        .expect("derives");
    let bound = vault::derive(
        pin("123456"),
        &salt,
        Cost::CURRENT,
        &mut ChipKey([9; 32]),
        &mut mem,
    )
    .expect("derives");
    let other = vault::derive(
        pin("123456"),
        &salt,
        Cost::CURRENT,
        &mut ChipKey([10; 32]),
        &mut mem,
    )
    .expect("derives");
    assert_ne!(plain.dek, bound.dek, "the chip key is mixed in");
    assert_ne!(bound.dek, other.dek, "a different chip, a different vault");
    assert!(
        mem.iter().all(|b| b.as_ref().iter().all(|w| *w == 0)),
        "the working memory is scrubbed"
    );
    let mut short = vec![Block::new(); 8];
    assert!(
        vault::derive(
            pin("123456"),
            &salt,
            Cost::CURRENT,
            &mut Unbound,
            &mut short
        )
        .is_none(),
        "too little memory is an error, not a cheaper derivation"
    );
}

// --- the types ------------------------------------------------------------------------

#[test]
fn only_valid_values_exist() {
    assert!(Pin::new(b"12345").is_none(), "five digits are too few");
    assert!(Pin::new(b"123456").is_some());
    assert!(Pin::new(b"12345678").is_some());
    assert!(Pin::new(b"123456789").is_none());
    assert!(Pin::new(b"12a456").is_none());
    assert!(Pin::new(b"").is_none());

    assert!(Name::new(b"").is_none());
    assert!(Name::new(&[b'a'; 32]).is_some());
    assert!(Name::new(&[b'a'; 33]).is_none());

    assert!(Kind::from_wire([1, 1, 6, 30]).is_some());
    assert!(
        Kind::from_wire([1, 3, 6, 30]).is_none(),
        "unknown algorithm"
    );
    assert!(Kind::from_wire([1, 1, 7, 30]).is_none(), "seven digits");
    assert!(Kind::from_wire([1, 1, 6, 0]).is_none(), "zero period");
    assert_eq!(Kind::from_wire([2, 0, 0, 0]), Some(Kind::Password));
    assert!(
        Kind::from_wire([2, 1, 6, 30]).is_none(),
        "a password has no parameters"
    );
    assert_eq!(Kind::from_wire([3, 0, 0, 0]), Some(Kind::Env));
    assert!(
        Kind::from_wire([3, 1, 0, 0]).is_none(),
        "an env blob has no parameters"
    );
    assert!(Kind::from_wire([4, 0, 0, 0]).is_none(), "unknown kind");
    for raw in [[1, 1, 6, 30], [1, 2, 8, 60], [2, 0, 0, 0], [3, 0, 0, 0]] {
        assert_eq!(Kind::from_wire(raw).expect("valid").wire(), raw);
    }
    assert!(
        Entry::new(name("proj"), Kind::Env, b"A=1").is_none(),
        "an env blob is never a table entry"
    );

    assert!(Cost::from_wire(128, 48).is_some());
    assert!(Cost::from_wire(4, 48).is_none(), "below Argon2's minimum");
    assert!(Cost::from_wire(130, 48).is_none(), "not a multiple of four");
    assert!(
        Cost::from_wire(256, 48).is_none(),
        "more than the board offers"
    );
    assert!(Cost::from_wire(128, 0).is_none());
    assert!(
        Cost::from_wire(128, 257).is_none(),
        "a header cannot park the key for hours"
    );

    assert!(Entry::new(name("x"), PLAIN, b"").is_none());
    assert!(Entry::new(name("x"), PLAIN, &[1; SECRET_MAX + 1]).is_none());
    assert!(Entry::new(name("x"), PLAIN, &[1; SECRET_MAX]).is_some());
}

#[test]
fn password_entries_pack_and_unpack() {
    // A password entry is login_len | login | password_len | password | note; the
    // password is never empty, the note may be.
    assert!(
        Entry::password(name("x"), b"", b"pw", b"").is_some(),
        "no login and no note is fine"
    );
    assert!(
        Entry::password(name("x"), b"me", b"", b"note").is_none(),
        "no password is not"
    );
    assert!(
        Entry::password(
            name("x"),
            &[b'l'; 100],
            &[b'p'; 28],
            &[b'n'; SECRET_MAX - 129]
        )
        .is_none(),
        "too long together"
    );
    assert!(
        Entry::password(
            name("x"),
            &[b'l'; 100],
            &[b'p'; 28],
            &[b'n'; SECRET_MAX - 130]
        )
        .is_some(),
        "exactly SECRET_MAX together"
    );
    assert!(
        Entry::password(name("x"), b"me", &[b'p'; 256], b"").is_none(),
        "a password longer than its byte-sized prefix"
    );
    assert!(
        Entry::new(name("x"), Kind::Password, &[5, b'a', b'b']).is_none(),
        "login longer than the blob"
    );
    assert!(
        Entry::new(name("x"), Kind::Password, &[2, b'a', b'b']).is_none(),
        "nothing left for the password prefix"
    );
    assert!(
        Entry::new(name("x"), Kind::Password, &[1, b'a', 0]).is_none(),
        "an empty password"
    );
    assert!(
        Entry::new(name("x"), Kind::Password, &[1, b'a', 3, b'p']).is_none(),
        "password longer than the blob"
    );
    let e = Entry::password(name("x"), b"me", b"pw", b"codes").expect("valid");
    assert_eq!(
        (e.login(), e.password_bytes(), e.note()),
        (Some(&b"me"[..]), Some(&b"pw"[..]), Some(&b"codes"[..]))
    );
    assert_eq!(
        e.secret(),
        b"\x02me\x02pwcodes",
        "packed as the wire spells it"
    );
    assert_eq!(
        (
            entry("y", b"s").login(),
            entry("y", b"s").password_bytes(),
            entry("y", b"s").note()
        ),
        (None, None, None),
        "a seed has none of them"
    );
}

#[test]
fn names_logins_and_passwords_are_one_line() {
    // Names, logins and passwords are one printable line; a note is text.
    assert!(
        Name::new(b"my bank:me").is_some(),
        "spaces inside a name are fine"
    );
    assert!(
        Name::new(b" x").is_none() && Name::new(b"x ").is_none(),
        "not at the ends"
    );
    assert!(
        Name::new(b"a\nb").is_none() && Name::new(b"a\tb").is_none(),
        "no control characters"
    );
    assert!(
        Entry::password(name("x"), b"me\n", b"pw", b"").is_none(),
        "login is one line"
    );
    assert!(
        Entry::password(name("x"), b"me", b"p\tw", b"").is_none(),
        "so is the password"
    );
    assert!(
        Entry::password(name("x"), b"me", b"pw", b"a\nb").is_some(),
        "a note has lines"
    );
    assert!(
        Entry::password(name("x"), b"me", b"pw", b"a\r\nb").is_none(),
        "but no CR"
    );
    assert!(
        Entry::new(name("x"), Kind::Password, b"\x02m\n\x02pw").is_none(),
        "the same rule for bytes off the wire"
    );
    assert!(
        Entry::new(name("x"), PLAIN, b"\x00\x01\xff").is_some(),
        "a seed is raw bytes"
    );
}

#[test]
fn wire_codes_round_trip() {
    for c in [
        Cmd::Info,
        Cmd::Add,
        Cmd::List,
        Cmd::Code,
        Cmd::Delete,
        Cmd::Reveal,
        Cmd::Login,
        Cmd::Rename,
        Cmd::EnvPut,
        Cmd::EnvGet,
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
    ] {
        assert_eq!(Cmd::from_wire(c.wire()), Some(c));
    }
    assert_eq!(Cmd::from_wire(0x19), None);
    assert_eq!(Cmd::from_wire(0x26), None);
    assert_eq!(Cmd::from_wire(0x35), None);
    let head = BackupHead {
        salt: [5; vault::SALT_LEN],
        cost: Cost::CURRENT,
    };
    assert_eq!(BackupHead::from_wire(head.wire()), Some(head));
    let mut hours = head.wire();
    hours[vault::SALT_LEN + 4..].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(
        BackupHead::from_wire(hours),
        None,
        "a file cannot park the key for hours either"
    );
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
        assert_eq!(Fail::from_code(f.code(), &[3]), Some(f));
    }
    assert_eq!(Fail::from_code(OK, &[]), None);
}

// --- the key ---------------------------------------------------------------------------

#[test]
fn pin_then_credentials() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    let st = dev.pin_status();
    assert!(!st.has_pin && !st.unlocked && st.retries_left == MAX_ATTEMPTS && !st.chip_bound);
    assert_eq!(dev.pin_unlock(pin("123456")), Err(Fail::NoPin));
    assert_eq!(
        dev.add(&entry("github", b"secret"), false),
        Err(Fail::Locked)
    );

    assert_eq!(dev.pin_set(pin("123456")), Ok(()));
    assert_eq!(dev.pin_set(pin("123456")), Err(Fail::PinExists));
    assert!(dev.pin_status().unlocked, "setting the PIN unlocks");

    assert_eq!(dev.add(&entry("github", b"secret"), false), Ok(()));
    assert_eq!(
        dev.add(&entry("github", b"other"), false),
        Err(Fail::Exists)
    );
    assert_eq!(dev.add(&entry("github", b"other"), true), Ok(()));
    assert_eq!(names(&mut dev).expect("unlocked"), ["github"]);

    // The device computes exactly what the reference does for the stored secret.
    let Kind::Totp(p) = PLAIN else { unreachable!() };
    let mut want = [0u8; 8];
    let n = oath::totp(p, b"other", 1_700_000_000, &mut want);
    assert_eq!(
        code(&mut dev, "github", 1_700_000_000)
            .expect("unlocked")
            .as_bytes(),
        &want[..n]
    );
    assert_eq!(code(&mut dev, "nope", 0), Err(Fail::NotFound));

    dev.lock();
    assert!(!dev.pin_status().unlocked);
    assert_eq!(code(&mut dev, "github", 0), Err(Fail::Locked));
    assert_eq!(
        dev.list(|_, _| {}),
        Err(Fail::Locked),
        "even the names need the PIN"
    );
    assert_eq!(dev.delete(name("github")), Err(Fail::Locked));

    assert_eq!(dev.pin_unlock(pin("123456")), Ok(()));
    assert_eq!(dev.delete(name("github")), Ok(()));
    assert!(names(&mut dev).expect("unlocked").is_empty());
    assert_eq!(dev.delete(name("github")), Err(Fail::NotFound));
}

#[test]
fn eight_wrong_pins_wipe_everything() {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("github", b"secret"), false).expect("add");
    env_put(&mut dev, "proj", b"A=1\n", false).expect("put");
    dev.lock();
    for left in (1..MAX_ATTEMPTS).rev() {
        assert_eq!(dev.pin_unlock(pin("000000")), Err(Fail::WrongPin(left)));
    }
    assert_eq!(dev.pin_unlock(pin("000000")), Err(Fail::Wiped));
    assert!(!dev.pin_status().has_pin);
    assert!(flash.erased(), "wiped means erased, not marked");
    assert_eq!(
        dev.pin_set(pin("999999")),
        Ok(()),
        "a wiped key starts over"
    );
}

#[test]
fn state_and_spent_attempts_survive_a_power_cycle() {
    let flash = MemFlash::blank();
    let moment = 1_700_000_000;
    let before = {
        let mut dev = tapping(&flash);
        dev.pin_set(pin("246800")).expect("set");
        dev.add(&entry("github", b"secret"), false).expect("add");
        dev.add(&password("mail", b"correct horse battery staple"), false)
            .expect("add");
        let c = code(&mut dev, "github", moment).expect("code");
        dev.lock();
        assert_eq!(dev.pin_unlock(pin("000000")), Err(Fail::WrongPin(7)));
        assert_eq!(dev.pin_unlock(pin("000000")), Err(Fail::WrongPin(6)));
        c
    };
    // Power off, power on: RAM is gone, flash is not - and neither are the two
    // attempts already spent.
    let mut dev = tapping(&flash);
    let st = dev.pin_status();
    assert!(st.has_pin && !st.unlocked);
    assert_eq!(st.retries_left, 6);
    assert_eq!(dev.pin_unlock(pin("246800")), Ok(()));
    assert_eq!(dev.pin_status().retries_left, MAX_ATTEMPTS);
    assert_eq!(names(&mut dev).expect("unlocked"), ["github", "mail"]);
    assert_eq!(code(&mut dev, "github", moment).expect("code"), before);
}

#[test]
fn pin_change_reseals_every_entry() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("123456")).expect("set");
    for i in 0..5u8 {
        dev.add(&entry(&format!("acct{i}"), &[i + 1; 10]), false)
            .expect("add");
    }
    let before = code(&mut dev, "acct3", 99).expect("code");
    assert_eq!(
        dev.pin_change(pin("000000"), pin("654321")),
        Err(Fail::WrongPin(7)),
        "the old PIN is checked"
    );
    assert_eq!(dev.pin_change(pin("123456"), pin("654321")), Ok(()));
    assert_eq!(code(&mut dev, "acct3", 99).expect("code"), before);
    dev.lock();
    assert_eq!(dev.pin_unlock(pin("123456")), Err(Fail::WrongPin(7)));
    assert_eq!(dev.pin_unlock(pin("654321")), Ok(()));
    assert_eq!(dev.pin_status().retries_left, MAX_ATTEMPTS);

    let mut fresh = tapping(&flash);
    fresh
        .pin_unlock(pin("654321"))
        .expect("the new PIN is in flash");
    assert_eq!(code(&mut fresh, "acct3", 99).expect("code"), before);
}

#[test]
fn the_table_has_thirty_two_slots() {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("123456")).expect("set");
    for i in 0..MAX_ENTRIES {
        dev.add(&entry(&format!("acct{i}"), b"s"), false)
            .expect("room");
    }
    assert_eq!(dev.add(&entry("one-more", b"s"), false), Err(Fail::Full));
    dev.delete(name("acct7")).expect("delete");
    assert_eq!(dev.add(&entry("one-more", b"s"), false), Ok(()));
    assert_eq!(names(&mut dev).expect("unlocked").len(), MAX_ENTRIES);
}

#[test]
fn a_vault_from_the_other_key_setup_is_refused_not_guessed_at() {
    let flash = MemFlash::blank();
    {
        let clock = Ticker::default();
        let mut bound = flash.key_with(Button::new(&clock, Finger::Away), clock, ChipKey([1; 32]));
        assert!(bound.pin_status().chip_bound);
        bound.pin_set(pin("123456")).expect("set");
        bound.add(&entry("github", b"secret"), false).expect("add");
    }
    // The same flash in a firmware without the chip key: the right PIN cannot work,
    // so it must not be tried - the attempts stay untouched.
    let mut plain = flash.key();
    assert_eq!(plain.pin_unlock(pin("123456")), Err(Fail::Incompatible));
    assert_eq!(plain.pin_status().retries_left, MAX_ATTEMPTS);
    assert_eq!(
        plain.list(|_, _| {}),
        Err(Fail::Locked),
        "and nothing is listed either"
    );

    // And a chip with a different key is a different chip.
    let clock = Ticker::default();
    let mut other = flash.key_with(Button::new(&clock, Finger::Away), clock, ChipKey([2; 32]));
    assert_eq!(
        other.pin_unlock(pin("123456")),
        Err(Fail::WrongPin(7)),
        "same setup, wrong chip: a wrong PIN, as it should look"
    );
}

// --- the flash -------------------------------------------------------------------------

#[test]
fn a_torn_write_falls_back_to_the_previous_image() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        dev.add(&entry("first", b"s"), false).expect("add");
        dev.add(&entry("second", b"s"), false).expect("add");
    }
    // The newest copy carries the higher sequence number; damage it.
    let newest = if flash.word(LAYOUT.state_a + 4) > flash.word(LAYOUT.state_b + 4) {
        LAYOUT.state_a
    } else {
        LAYOUT.state_b
    };
    flash.flip(newest + 100);

    let mut dev = flash.key();
    dev.pin_unlock(pin("123456"))
        .expect("the PIN is in both copies");
    assert_eq!(
        names(&mut dev).expect("unlocked"),
        ["first"],
        "the older good copy wins over the newer damaged one"
    );
    assert_eq!(
        dev.add(&entry("third", b"s"), false),
        Ok(()),
        "writing resumes over the damaged copy"
    );
    assert_eq!(names(&mut dev).expect("unlocked"), ["first", "third"]);
}

#[test]
fn unreadable_flash_is_refused_until_wiped() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        dev.add(&entry("a", b"s"), false).expect("add");
    }
    for copy in [LAYOUT.state_a, LAYOUT.state_b] {
        flash.flip(copy + 1); // neither blank nor a valid magic
    }
    let mut dev = flash.key();
    assert!(!dev.pin_status().has_pin, "nothing can be read");
    assert_eq!(
        dev.pin_set(pin("123456")),
        Err(Fail::Internal),
        "and nothing is written over it"
    );
    assert_eq!(dev.wipe(), Err(Fail::Refused), "not without the button");

    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Hold(6_000)), clock, Unbound);
    assert_eq!(dev.wipe(), Ok(()));
    assert!(flash.erased());
    assert_eq!(dev.pin_set(pin("123456")), Ok(()));
}

#[test]
fn a_header_asking_for_hours_of_work_is_corrupt() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
    }
    // The pass count lives right after the salt; setting its high byte asks for
    // sixteen million passes. Both copies, so there is nothing to fall back to.
    for copy in [LAYOUT.state_a, LAYOUT.state_b] {
        flash.flip(copy + 8 + 4 + 16 + 4 + 3);
    }
    let mut dev = flash.key();
    // The status row answers from the head alone, without the CRC or the cost: it
    // still says a PIN is set. The first real operation is what refuses.
    assert!(dev.pin_status().has_pin);
    assert_eq!(dev.pin_unlock(pin("123456")), Err(Fail::Internal));
}

// --- the button and the clock ---------------------------------------------------------

#[test]
fn the_button_must_be_pressed_after_the_request() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::TapOnce), clock, Unbound);
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("bank", b"s"), false).expect("add");
    assert!(code(&mut dev, "bank", 0).is_ok(), "a fresh press confirms");
    assert_eq!(
        code(&mut dev, "bank", 0),
        Err(Fail::Refused),
        "the same press does not confirm twice"
    );

    let clock = Ticker::default();
    let mut taped = flash.key_with(Button::new(&clock, Finger::Taped), clock, Unbound);
    taped.pin_unlock(pin("123456")).expect("unlock");
    assert_eq!(
        code(&mut taped, "bank", 0),
        Err(Fail::Refused),
        "a button held down when the request arrives is not a confirmation"
    );
    assert_eq!(taped.wipe(), Err(Fail::Refused));
}

#[test]
fn a_tap_never_wipes() {
    // The point of two gestures: a hostile host that asks for a wipe while the owner is
    // expecting a code request gets a tap, and a tap never wipes. A password takes the
    // same tap as a code (decided 2026-09-08).
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        dev.add(&entry("github", b"secret"), false).expect("add");
        dev.add(&password("mail", b"hunter2"), false).expect("add");
        env_put(&mut dev, "proj", b"A=1\n", false).expect("put");
    }
    let unlocked = |finger: Finger| {
        let clock = Ticker::default();
        let mut dev = flash.key_with(Button::new(&clock, finger), clock, Unbound);
        dev.pin_unlock(pin("123456")).expect("unlock");
        dev
    };

    let mut dev = unlocked(Finger::Tap);
    assert!(code(&mut dev, "github", 0).is_ok());
    assert_eq!(
        login(&mut dev, "mail"),
        Ok(b"me@example.com".to_vec()),
        "the login needs no gesture"
    );
    assert_eq!(
        login(&mut dev, "github"),
        Err(Fail::BadArg),
        "a seed has no login"
    );
    assert_eq!(
        reveal(&mut dev, "mail"),
        Ok(b"hunter2".to_vec()),
        "a tap reveals a password"
    );
    assert_eq!(
        env_get(&mut dev, "proj"),
        Ok(b"A=1\n".to_vec()),
        "and a blob"
    );
    assert_eq!(dev.wipe(), Err(Fail::Refused), "a tap is not a wipe");
    assert_eq!(
        names(&mut dev).expect("unlocked"),
        ["github", "mail", "proj"],
        "nothing was erased"
    );

    let mut dev = unlocked(Finger::Hold(4_500));
    assert_eq!(
        dev.wipe(),
        Err(Fail::Refused),
        "four and a half seconds is not five"
    );

    let mut dev = unlocked(Finger::Hold(6_000));
    assert_eq!(dev.wipe(), Ok(()), "held for five seconds");
    assert!(flash.erased());
}

#[test]
fn a_rename_keeps_the_secret_and_the_slot() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("github", b"secret"), false).expect("add");
    dev.add(&password("mail", b"hunter2"), false).expect("add");
    let before = code(&mut dev, "github", 1_700_000_000).expect("unlocked");

    assert_eq!(dev.rename(name("github"), name("gh")), Ok(()));
    assert_eq!(dev.rename(name("github"), name("gh")), Err(Fail::NotFound));
    assert_eq!(dev.rename(name("mail"), name("gh")), Err(Fail::Exists));
    assert_eq!(dev.rename(name("mail"), name("mail")), Err(Fail::Exists));
    assert_eq!(names(&mut dev).expect("unlocked"), ["gh", "mail"]);
    // The name is under the AEAD tag: only a real re-seal opens under the new one.
    assert_eq!(code(&mut dev, "gh", 1_700_000_000), Ok(before));
    assert_eq!(dev.rename(name("mail"), name("post")), Ok(()));
    assert_eq!(login(&mut dev, "post"), Ok(b"me@example.com".to_vec()));
    assert_eq!(reveal(&mut dev, "post"), Ok(b"hunter2".to_vec()));

    dev.lock();
    assert_eq!(dev.rename(name("gh"), name("github")), Err(Fail::Locked));
}

#[test]
fn a_seed_never_comes_out_and_a_password_never_makes_codes() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Hold(6_000)), clock, Unbound);
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("github", b"secret"), false).expect("add");
    dev.add(&password("mail", b"hunter2"), false).expect("add");
    // Refused by kind before the light ever comes on: no gesture can change it.
    assert_eq!(reveal(&mut dev, "github"), Err(Fail::BadArg));
    assert_eq!(code(&mut dev, "mail", 0), Err(Fail::BadArg));
}

#[test]
fn two_idle_minutes_lock_the_key() {
    let flash = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = flash.key_with(Button::new(&clock, Finger::Away), clock.clone(), Unbound);
    dev.pin_set(pin("123456")).expect("set");
    clock.jump(119_000);
    dev.tick();
    assert!(dev.pin_status().unlocked, "a minute and change is fine");
    clock.jump(2_000);
    dev.tick();
    assert!(
        !dev.pin_status().unlocked,
        "two minutes idle and the key is gone"
    );
}

#[test]
fn a_kind_rewritten_in_flash_reveals_nothing() {
    // The kind is plaintext metadata. Flip a TOTP entry into a "password" in flash,
    // CRC and all, and the reveal gesture must get an error, never the seed.
    const IMAGE: u32 = 83_076; // asserted in store.rs
    const RECORD0_KIND: u32 = 8 + 120 + 33; // magic+seq | header | name+name_len
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        dev.add(&entry("github", b"secret"), false).expect("add");
    }
    let newest = if flash.word(LAYOUT.state_a + 4) > flash.word(LAYOUT.state_b + 4) {
        LAYOUT.state_a
    } else {
        LAYOUT.state_b
    };
    flash.patch(newest + RECORD0_KIND, &Kind::Password.wire());
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
        .checksum(&flash.bytes(newest, IMAGE - 4))
        .to_le_bytes();
    flash.patch(newest + IMAGE - 4, &crc);

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    assert_eq!(
        names(&mut dev).expect("unlocked"),
        ["github"],
        "the forgery reads as a valid record"
    );
    assert_eq!(
        reveal(&mut dev, "github"),
        Err(Fail::Internal),
        "but its kind is under the tag"
    );
    assert_eq!(
        code(&mut dev, "github", 0),
        Err(Fail::Internal),
        "the forged record opens for nobody"
    );
}

// --- env blobs -------------------------------------------------------------------------

#[test]
fn an_env_blob_comes_back_whole_after_a_tap() {
    let flash = MemFlash::blank();
    let blob: Vec<u8> = (0..oath::ENV_MAX)
        .map(|i| u8::try_from(i % 251).expect("below 256"))
        .collect();
    {
        let mut dev = flash.key(); // nobody touches the button
        dev.pin_set(pin("123456")).expect("set");
        assert_eq!(env_put(&mut dev, "proj", &blob, false), Ok(()));
        assert_eq!(
            env_put(&mut dev, "big", &vec![1; oath::ENV_MAX + 1], false),
            Err(Fail::BadArg),
            "one byte over the limit"
        );
        assert_eq!(
            env_put(&mut dev, "empty", b"", false),
            Err(Fail::BadArg),
            "an empty blob is not a blob"
        );
        assert_eq!(
            env_get(&mut dev, "proj"),
            Err(Fail::Refused),
            "no tap, no blob"
        );
        assert_eq!(env_get(&mut dev, "nope"), Err(Fail::NotFound));
        dev.lock();
        assert_eq!(env_get(&mut dev, "proj"), Err(Fail::Locked));
        assert_eq!(env_put(&mut dev, "x", b"x", false), Err(Fail::Locked));
    }
    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    assert_eq!(
        env_get(&mut dev, "proj"),
        Ok(blob),
        "the biggest blob, byte for byte"
    );
    assert_eq!(
        kinds(&mut dev).expect("unlocked"),
        [("proj".to_string(), Kind::Env)],
        "listed with its kind"
    );
}

#[test]
fn env_blobs_survive_a_pin_change_and_a_power_cycle() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        env_put(&mut dev, "proj", b"A=1\nB=2\n", false).expect("put");
        dev.pin_change(pin("123456"), pin("654321"))
            .expect("change");
    }
    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("654321")).expect("the new PIN");
    assert_eq!(
        env_get(&mut dev, "proj"),
        Ok(b"A=1\nB=2\n".to_vec()),
        "the blob's own key was re-wrapped, the blob itself untouched"
    );
}

#[test]
fn env_and_table_names_never_collide() {
    let flash = MemFlash::blank();
    let mut dev = tapping(&flash);
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("github", b"secret"), false).expect("add");
    assert_eq!(env_put(&mut dev, "github", b"x", false), Err(Fail::Exists));
    assert_eq!(
        env_put(&mut dev, "github", b"x", true),
        Err(Fail::Exists),
        "replace only replaces a blob, never an entry"
    );
    env_put(&mut dev, "proj", b"one", false).expect("put");
    assert_eq!(dev.add(&entry("proj", b"s"), false), Err(Fail::Exists));
    assert_eq!(
        dev.add(&entry("proj", b"s"), true),
        Err(Fail::Exists),
        "and an entry never replaces a blob"
    );
    assert_eq!(dev.rename(name("github"), name("proj")), Err(Fail::Exists));
    assert_eq!(env_put(&mut dev, "proj", b"two", false), Err(Fail::Exists));
    assert_eq!(env_put(&mut dev, "proj", b"two", true), Ok(()));
    assert_eq!(env_get(&mut dev, "proj"), Ok(b"two".to_vec()));
    assert_eq!(names(&mut dev).expect("unlocked"), ["github", "proj"]);

    assert_eq!(dev.delete(name("proj")), Ok(()), "delete finds blobs too");
    assert_eq!(env_get(&mut dev, "proj"), Err(Fail::NotFound));
    assert_eq!(dev.delete(name("proj")), Err(Fail::NotFound));

    for i in 0..store::ENV_SLOTS {
        env_put(&mut dev, &format!("p{i}"), b"x", false).expect("a free slot");
    }
    assert_eq!(
        env_put(&mut dev, "one-more", b"x", false),
        Err(Fail::Full),
        "sixteen slots"
    );
}

#[test]
fn a_torn_env_write_keeps_the_previous_blob() {
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        env_put(&mut dev, "proj", b"one", false).expect("put");
        env_put(&mut dev, "proj", b"two", true).expect("put again");
    }
    // Slot 0, both copies valid: the newer one carries the higher sequence. Damage a
    // byte of its sealed body.
    let (a, b) = (LAYOUT.env, LAYOUT.env + ENV_COPY);
    let newest = if flash.word(a + 4) > flash.word(b + 4) {
        a
    } else {
        b
    };
    flash.flip(newest + 60);

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    assert_eq!(
        env_get(&mut dev, "proj"),
        Ok(b"one".to_vec()),
        "the older intact copy wins over the newer torn one"
    );
    assert_eq!(env_put(&mut dev, "proj", b"three", true), Ok(()));
    assert_eq!(env_get(&mut dev, "proj"), Ok(b"three".to_vec()));

    // Both copies torn: not a locked key, a free slot.
    flash.flip(a + 60);
    flash.flip(b + 60);
    assert_eq!(env_get(&mut dev, "proj"), Err(Fail::NotFound));
    assert_eq!(names(&mut dev).expect("unlocked"), Vec::<String>::new());
    assert_eq!(
        env_put(&mut dev, "proj", b"four", false),
        Ok(()),
        "the slot is written again"
    );
    assert_eq!(env_get(&mut dev, "proj"), Ok(b"four".to_vec()));
}

#[test]
fn a_blob_name_rewritten_in_flash_opens_for_nobody() {
    // The name is plaintext metadata under a CRC anyone can recompute; the AEAD tag
    // is what binds the blob to it.
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        env_put(&mut dev, "proj", b"SECRET=1\n", false).expect("put");
    }
    let copy = LAYOUT.env; // the first write lands in slot 0, copy A
    flash.patch(copy + 12, b"prox");
    let len_bytes = flash.bytes(copy + 44, 2);
    let len = u32::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
        .checksum(&flash.bytes(copy, 48 + len))
        .to_le_bytes();
    flash.patch(copy + 48 + len.next_multiple_of(4), &crc);

    let mut dev = tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    assert_eq!(
        names(&mut dev).expect("unlocked"),
        ["prox"],
        "the forgery reads as a valid slot"
    );
    assert_eq!(
        env_get(&mut dev, "prox"),
        Err(Fail::Internal),
        "but the name is under the tag"
    );
}

// --- backup ----------------------------------------------------------------------------

/// A vault with one of everything: a seed, a password with a note, a blob.
fn stocked() -> MemFlash {
    let flash = MemFlash::blank();
    let mut dev = flash.key();
    dev.pin_set(pin("123456")).expect("set");
    dev.add(&entry("github", b"secret"), false).expect("add");
    let mail = Entry::password(name("mail"), b"me@example.com", b"hunter2", b"codes\n1234")
        .expect("a valid test entry");
    dev.add(&mail, false).expect("add");
    env_put(&mut dev, "proj", b"A=1\nB=2\n", false).expect("put");
    flash
}

#[test]
fn a_backup_restores_every_entry_onto_another_chip() {
    let flash = stocked();
    let mut dev = double_tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    let (head, items) = export(&mut dev, "correct horse battery").expect("export");
    assert_eq!(items.len(), 3, "one item per entry and blob");
    for item in &items {
        for word in [&b"secret"[..], b"hunter2", b"A=1", b"github", b"proj"] {
            assert!(
                !item.windows(word.len()).any(|w| w == word),
                "nothing leaves in the clear, not even a name"
            );
        }
    }
    assert!(
        names(&mut dev).is_ok(),
        "the key is still unlocked and untouched"
    );

    // Another board, chip-bound, with its own PIN and a blob that must make way.
    let other = MemFlash::blank();
    let clock = Ticker::default();
    let mut dev = other.key_with(Button::new(&clock, Finger::Tap), clock, ChipKey([9; 32]));
    dev.pin_set(pin("87654321")).expect("set");
    env_put(&mut dev, "mail", b"OLD=1\n", false).expect("put");
    dev.add(&entry("keep", b"mine"), false).expect("add");
    assert_eq!(
        import(&mut dev, "correct horse battery", head, &items),
        Ok(())
    );
    assert_eq!(
        names(&mut dev).expect("unlocked"),
        ["keep", "github", "mail", "proj"],
        "restored next to what was there; the blob called mail gave way to the entry"
    );
    let Kind::Totp(p) = PLAIN else { unreachable!() };
    let mut want = [0u8; 8];
    let n = oath::totp(p, b"secret", 1_700_000_000, &mut want);
    assert_eq!(
        code(&mut dev, "github", 1_700_000_000).map(String::into_bytes),
        Ok(want[..n].to_vec()),
        "the seed made it, under the other chip's key"
    );
    let mut out = [0u8; SECRET_MAX];
    let n = dev.reveal(name("mail"), &mut out).expect("a tap");
    let mail = Entry::new(name("mail"), Kind::Password, &out[..n]).expect("a pack");
    assert_eq!(mail.login(), Some(&b"me@example.com"[..]));
    assert_eq!(mail.password_bytes(), Some(&b"hunter2"[..]));
    assert_eq!(mail.note(), Some(&b"codes\n1234"[..]));
    assert_eq!(env_get(&mut dev, "proj"), Ok(b"A=1\nB=2\n".to_vec()));
    assert!(code(&mut dev, "keep", 0).is_ok(), "what was there stays");

    // The same file onto the same key again is a no-op, not a duplicate.
    assert_eq!(
        import(&mut dev, "correct horse battery", head, &items),
        Ok(())
    );
    assert_eq!(names(&mut dev).expect("unlocked").len(), 4);
}

#[test]
fn a_backup_opens_only_as_written() {
    let flash = stocked();
    let mut dev = double_tapping(&flash);
    dev.pin_unlock(pin("123456")).expect("unlock");
    let (head, items) = export(&mut dev, "correct horse battery").expect("export");

    let fresh = || {
        let other = MemFlash::blank();
        let mut dev = other.key();
        dev.pin_set(pin("123456")).expect("set");
        dev
    };
    let mut dev = fresh();
    assert_eq!(
        import(&mut dev, "correct horse battery!", head, &items),
        Err(Fail::BadBackup),
        "the wrong passphrase opens nothing"
    );
    assert_eq!(
        dev.import_item(&items[0]),
        Err(Fail::BadBackup),
        "and the restore is over"
    );
    assert_eq!(names(&mut dev).expect("unlocked"), Vec::<String>::new());

    let mut swapped = items.clone();
    swapped.swap(0, 1);
    assert_eq!(
        import(&mut fresh(), "correct horse battery", head, &swapped),
        Err(Fail::BadBackup),
        "an item's place in the file is under its tag"
    );
    let mut bent = items.clone();
    bent[2][20] ^= 1;
    assert_eq!(
        import(&mut fresh(), "correct horse battery", head, &bent),
        Err(Fail::BadBackup),
        "so is every byte"
    );
    let mut dev = fresh();
    assert_eq!(
        import(&mut dev, "correct horse battery", head, &items[..2]),
        Ok(()),
        "a file cut short restores what it holds"
    );
    assert_eq!(names(&mut dev).expect("unlocked"), ["github", "mail"]);
    assert_eq!(dev.import_end(), Err(Fail::BadBackup), "nothing in flight");
}

#[test]
fn only_two_taps_let_a_backup_out() {
    let flash = stocked();
    let unlocked = |finger: Finger| {
        let clock = Ticker::default();
        let mut dev = flash.key_with(Button::new(&clock, finger), clock, Unbound);
        dev.pin_unlock(pin("123456")).expect("unlock");
        dev
    };
    assert_eq!(
        export(&mut unlocked(Finger::Tap), "correct horse battery").map(|_| ()),
        Err(Fail::Refused),
        "the code reflex is one tap"
    );
    assert_eq!(
        export(&mut unlocked(Finger::Hold(6_000)), "correct horse battery").map(|_| ()),
        Err(Fail::Refused),
        "a hold is one press, however long"
    );
    assert_eq!(
        export(
            &mut unlocked(Finger::DoubleTap { gap: 1_500 }),
            "correct horse battery"
        )
        .map(|_| ()),
        Err(Fail::Refused),
        "two taps a second and a half apart are two taps, not a double tap"
    );
    let mut dev = unlocked(Finger::DoubleTap { gap: 300 });
    assert_eq!(dev.wipe(), Err(Fail::Refused), "and two taps never wipe");
    assert!(export(&mut dev, "correct horse battery").is_ok());
    assert_eq!(
        dev.export_next(|_| {}),
        Err(Fail::BadBackup),
        "the backup ended with its last item"
    );

    let mut dev = flash.key();
    assert_eq!(
        dev.export_begin(passphrase("correct horse battery")),
        Err(Fail::Locked),
        "and needs the PIN first"
    );
    assert!(
        Passphrase::new(b"short").is_none(),
        "twelve characters at least"
    );
    assert!(Passphrase::new(b"tab\tin the middle").is_none());
    assert!(Passphrase::new(&[b'p'; vault::PASS_MAX + 1]).is_none());
}

#[test]
fn a_damaged_env_key_refuses_blobs_but_not_the_pin() {
    const IMAGE: u32 = 83_076; // asserted in store.rs
    const ENV_KEY_AT: u32 = 8 + 4 + 16 + 8 + 32 + 5; // magic+seq | flags | salt | cost | verifier | into env_key
    let flash = MemFlash::blank();
    {
        let mut dev = flash.key();
        dev.pin_set(pin("123456")).expect("set");
        env_put(&mut dev, "proj", b"A=1\n", false).expect("put");
    }
    for copy in [LAYOUT.state_a, LAYOUT.state_b] {
        if flash.word(copy) == 0xFFFF_FFFF {
            continue; // blank copy
        }
        flash.flip(copy + ENV_KEY_AT);
        let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
            .checksum(&flash.bytes(copy, IMAGE - 4))
            .to_le_bytes();
        flash.patch(copy + IMAGE - 4, &crc);
    }
    let mut dev = tapping(&flash);
    assert_eq!(
        dev.pin_unlock(pin("123456")),
        Ok(()),
        "the PIN and the entries do not depend on the env key"
    );
    assert_eq!(env_get(&mut dev, "proj"), Err(Fail::Internal));
    assert_eq!(env_put(&mut dev, "other", b"x", false), Err(Fail::Internal));
}
