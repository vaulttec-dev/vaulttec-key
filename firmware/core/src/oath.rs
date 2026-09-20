//! What a code is computed from. HOTP (RFC 4226) and TOTP (RFC 6238): the device has no
//! clock, the host sends the time with each request, exactly as a `YubiKey` does; a lying
//! host gets a code for the wrong moment, never the seed.
//!
//! What the key *stores* is in [`crate::item`]; what may leave it is a field's class.
//! Everything a code depends on is a type that can only hold a valid value: the wire and
//! the flash are checked once, at the edge, and nothing downstream checks again.

use core::num::NonZeroU8;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::vault::OVERHEAD;

pub const NAME_MAX: usize = 32;
/// An auth secret is an Ed25519 seed, exactly this long: the host draws it, keeps the
/// public key and forgets the seed.
pub const AUTH_SECRET_LEN: usize = 32;

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

/// `len u8 | bytes` off the front, None if the prefix runs past the end.
pub(crate) fn take_len_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
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

/// A field's or a sealed item's length: fits two bytes by construction. The longest of
/// them is a whole item with its AEAD overhead.
pub(crate) const fn len_u16(n: usize) -> u16 {
    const _: () = assert!(
        crate::item::ITEM_MAX + OVERHEAD <= u16::MAX as usize,
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
