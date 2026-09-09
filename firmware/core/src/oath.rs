//! What the key stores and what it computes from it. HOTP (RFC 4226) and TOTP
//! (RFC 6238): the device has no clock, the host sends the time with each request,
//! exactly as a `YubiKey` does; a lying host gets a code for the wrong moment, never
//! the secret. Passwords are stored the same way and come back out only through the
//! reveal gesture.
//!
//! Everything a code depends on is a type that can only hold a valid value: the wire
//! and the flash are checked once, at the edge, and nothing downstream checks again.

use core::num::NonZeroU8;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::OVERHEAD;

pub const NAME_MAX: usize = 32;
/// Long enough for any TOTP seed, and for a login, a password and a note of recovery
/// codes together (sixteen GitHub codes with room to spare). Not more: every add
/// rewrites the whole image, and its sectors are what an add costs in time.
pub const SECRET_MAX: usize = 256;
/// The most an env blob (a project's `.env`) may hold. It lives outside the record
/// table, in its own flash region, and comes back whole after a tap.
pub const ENV_MAX: usize = 8000;

/// The HMAC hash, numbered as the wire and the flash spell it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Algo {
    Sha1 = 1,
    Sha256 = 2,
}

impl Algo {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// Code length. Services use 6 or 8; the device needs a closed set to size its buffers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Digits {
    Six = 6,
    Eight = 8,
}

impl Digits {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            6 => Some(Self::Six),
            8 => Some(Self::Eight),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }

    /// How many digits a code has.
    #[must_use]
    pub const fn count(self) -> usize {
        self as usize
    }

    const fn modulus(self) -> u32 {
        match self {
            Self::Six => 1_000_000,
            Self::Eight => 100_000_000,
        }
    }
}

/// Everything a TOTP code depends on besides the secret. Three bytes on the wire and in
/// flash: algo, digits, period.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    pub algo: Algo,
    pub digits: Digits,
    pub period: NonZeroU8,
}

impl Params {
    pub const WIRE_LEN: usize = 3;
    /// What nearly every service hands out, and what the host assumes when a URI
    /// says nothing: SHA-1, six digits, thirty seconds.
    pub const DEFAULT: Params = Params {
        algo: Algo::Sha1,
        digits: Digits::Six,
        period: NonZeroU8::new(30).expect("thirty is not zero"),
    };

    #[must_use]
    pub const fn from_wire(b: [u8; Self::WIRE_LEN]) -> Option<Self> {
        let (Some(algo), Some(digits), Some(period)) = (
            Algo::from_wire(b[0]),
            Digits::from_wire(b[1]),
            NonZeroU8::new(b[2]),
        ) else {
            return None;
        };
        Some(Params {
            algo,
            digits,
            period,
        })
    }

    #[must_use]
    pub const fn wire(self) -> [u8; Self::WIRE_LEN] {
        [self.algo.wire(), self.digits.wire(), self.period.get()]
    }
}

/// What an entry is, which decides what may ever leave the device: a TOTP seed only
/// ever yields codes; a password comes back as itself, through the reveal gesture;
/// an env blob comes back whole the same way, but is never an [`Entry`] - it is too
/// big for the table and lives in its own region.
/// Four bytes on the wire and in flash: kind, then the TOTP parameters or zeros.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Totp(Params),
    Password,
    Env,
}

impl Kind {
    pub const WIRE_LEN: usize = 4;
    const TOTP: u8 = 1;
    const PASSWORD: u8 = 2;
    const ENV: u8 = 3;

    #[must_use]
    pub const fn from_wire(b: [u8; Self::WIRE_LEN]) -> Option<Self> {
        match b {
            [Self::TOTP, algo, digits, period] => match Params::from_wire([algo, digits, period]) {
                Some(p) => Some(Kind::Totp(p)),
                None => None,
            },
            [Self::PASSWORD, 0, 0, 0] => Some(Kind::Password),
            [Self::ENV, 0, 0, 0] => Some(Kind::Env),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> [u8; Self::WIRE_LEN] {
        match self {
            Kind::Totp(p) => {
                let [algo, digits, period] = p.wire();
                [Self::TOTP, algo, digits, period]
            }
            Kind::Password => [Self::PASSWORD, 0, 0, 0],
            Kind::Env => [Self::ENV, 0, 0, 0],
        }
    }
}

/// A credential name: 1..=`NAME_MAX` bytes. The device compares bytes, never text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Name<'a>(&'a [u8]);

impl<'a> Name<'a> {
    /// 1..=`NAME_MAX` printable bytes, not starting or ending with a space: a name is
    /// typed as a bare word in the shell and shown in a list, so a newline out of a
    /// CSV title or a stray trailing space would make it unreachable.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty()
            || bytes.len() > NAME_MAX
            || !printable(bytes)
            || bytes[0] == b' '
            || bytes[bytes.len() - 1] == b' '
        {
            None
        } else {
            Some(Name(bytes))
        }
    }

    /// For bytes copied out of a `Name` earlier: the invariant already holds.
    pub(crate) const fn trusted(bytes: &'a [u8]) -> Self {
        Name(bytes)
    }

    /// A u8-length-prefixed name at the start of `p` - how every wire payload and
    /// backup item carries one: (name, rest), or None if malformed.
    #[must_use]
    pub fn take(p: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let (name, rest) = take_len_prefixed(p)?;
        Some((Name::new(name)?, rest))
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Decrypted credential, in RAM only. Valid by construction; zeroized when dropped,
/// so no early return can leave a secret behind on the stack.
pub struct Entry {
    name: [u8; NAME_MAX],
    name_len: u8,
    pub kind: Kind,
    secret: [u8; SECRET_MAX],
    secret_len: u16,
}

impl Zeroize for Entry {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.secret_len = 0;
        self.name.zeroize();
        self.name_len = 0;
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Entry {
    /// None if the secret is empty or longer than `SECRET_MAX`, or - for a password -
    /// not `login_len | login | password_len | password | note` with a printable login
    /// and password (the password not empty) and a note of text. An env blob is never
    /// an entry: a wire `Add` of kind env must not smuggle one into the table.
    #[must_use]
    pub fn new(name: Name<'_>, kind: Kind, secret: &[u8]) -> Option<Entry> {
        if secret.is_empty() || secret.len() > SECRET_MAX || kind == Kind::Env {
            return None;
        }
        if kind == Kind::Password && !password_packed(secret) {
            return None;
        }
        let name = name.as_bytes();
        let mut e = Entry {
            name: [0; NAME_MAX],
            name_len: len_u8(name.len()),
            kind,
            secret: [0; SECRET_MAX],
            secret_len: len_u16(secret.len()),
        };
        e.name[..name.len()].copy_from_slice(name);
        e.secret[..secret.len()].copy_from_slice(secret);
        Some(e)
    }

    #[must_use]
    pub fn name(&self) -> Name<'_> {
        Name::trusted(&self.name[..usize::from(self.name_len)])
    }

    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret[..usize::from(self.secret_len)]
    }

    /// A password entry: `login_len | login | password_len | password | note`, sealed
    /// as one. The login comes first so it can be handed out without the gesture the
    /// rest needs; the note (recovery codes, a security answer) is whatever is left,
    /// possibly nothing.
    #[must_use]
    pub fn password(name: Name<'_>, login: &[u8], password: &[u8], note: &[u8]) -> Option<Entry> {
        let byte = usize::from(u8::MAX);
        if login.len() > byte || password.len() > byte {
            return None;
        }
        let total = 2 + login.len() + password.len() + note.len();
        if total > SECRET_MAX {
            return None;
        }
        let mut packed = Zeroizing::new([0u8; SECRET_MAX]);
        let mut at = 0;
        for part in [login, password] {
            packed[at] = len_u8(part.len());
            packed[at + 1..at + 1 + part.len()].copy_from_slice(part);
            at += 1 + part.len();
        }
        packed[at..total].copy_from_slice(note);
        Entry::new(name, Kind::Password, &packed[..total])
    }

    /// The login of a password entry; None for a TOTP seed.
    #[must_use]
    pub fn login(&self) -> Option<&[u8]> {
        Some(self.split()?.0)
    }

    /// The password of a password entry; None for a TOTP seed, which never comes out.
    #[must_use]
    pub fn password_bytes(&self) -> Option<&[u8]> {
        Some(self.split()?.1)
    }

    /// The note of a password entry, empty when there is none; None for a TOTP seed.
    #[must_use]
    pub fn note(&self) -> Option<&[u8]> {
        Some(self.split()?.2)
    }

    fn split(&self) -> Option<(&[u8], &[u8], &[u8])> {
        if self.kind != Kind::Password {
            return None;
        }
        let (login, rest) = take_len_prefixed(self.secret())?;
        let (password, note) = take_len_prefixed(rest)?;
        Some((login, password, note))
    }
}

/// Whether `secret` is a well-formed password pack: both length prefixes in bounds,
/// login and password printable, the password not empty, the note text (printable
/// plus newlines). What [`Entry::split`] relies on afterwards - and the one check for
/// bytes off the wire, so a host cannot store a login with a newline in it.
fn password_packed(secret: &[u8]) -> bool {
    let Some((login, rest)) = take_len_prefixed(secret) else {
        return false;
    };
    let Some((password, note)) = take_len_prefixed(rest) else {
        return false;
    };
    printable(login) && !password.is_empty() && printable(password) && text(note)
}

/// No control characters: what a name, a login, a password or a backup passphrase
/// may hold.
pub(crate) const fn printable(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] < 0x20 || bytes[i] == 0x7f {
            return false;
        }
        i += 1;
    }
    true
}

/// `printable`, plus newlines: what a note may hold.
const fn text(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if (bytes[i] < 0x20 && bytes[i] != b'\n') || bytes[i] == 0x7f {
            return false;
        }
        i += 1;
    }
    true
}

/// `len u8 | bytes` off the front, None if the prefix runs past the end.
fn take_len_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first()?;
    rest.split_at_checked(usize::from(*len))
}

/// A name length, or a byte-sized prefix: fits a byte by construction. The one cast
/// for every `len u8` on the wire and in flash.
pub(crate) const fn len_u8(n: usize) -> u8 {
    const _: () = assert!(
        NAME_MAX <= u8::MAX as usize,
        "name lengths are stored in a byte"
    );
    #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
    {
        n as u8
    }
}

/// A secret, sealed record or sealed blob length: fits two bytes by construction. The
/// longest of them is an env blob with its AEAD overhead.
pub(crate) const fn len_u16(n: usize) -> u16 {
    const _: () = assert!(
        ENV_MAX + OVERHEAD <= u16::MAX as usize && SECRET_MAX <= ENV_MAX,
        "lengths are stored in two bytes"
    );
    #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
    {
        n as u16
    }
}

fn hmac_sha1(key: &[u8], msg: &[u8], out: &mut [u8; 20]) {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    out.copy_from_slice(&mac.finalize().into_bytes());
}

/// RFC 4226 dynamic truncation. Writes the code as ASCII digits and returns the count.
pub fn hotp(params: Params, secret: &[u8], counter: u64, out: &mut [u8; 8]) -> usize {
    let msg = counter.to_be_bytes();
    let mut mac = Zeroizing::new([0u8; 32]);
    let mac_len = match params.algo {
        Algo::Sha256 => {
            crate::vault::hmac(secret, &msg, &mut mac);
            32
        }
        Algo::Sha1 => {
            let mut m = Zeroizing::new([0u8; 20]);
            hmac_sha1(secret, &msg, &mut m);
            mac[..20].copy_from_slice(&*m);
            20
        }
    };

    let off = usize::from(mac[mac_len - 1] & 0x0F);
    let bin = u32::from_be_bytes([mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]]);
    let digits = params.digits;
    let mut code = bin % digits.modulus();
    for slot in out[..digits.count()].iter_mut().rev() {
        *slot = b"0123456789"[(code % 10) as usize];
        code /= 10;
    }
    digits.count()
}

pub fn totp(params: Params, secret: &[u8], unix_time: u64, out: &mut [u8; 8]) -> usize {
    hotp(
        params,
        secret,
        unix_time / u64::from(params.period.get()),
        out,
    )
}
