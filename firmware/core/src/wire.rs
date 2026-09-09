//! The bytes on the wire. The firmware and the host CLI both compile this file, so
//! neither can drift from the other: a command, a status byte, a flag and the frame
//! itself exist here or do not exist. Payloads are parsed in `proto.rs` and built in
//! the CLI's `device.rs`; this comment is what ties those two together.
//!
//!   request:   "VTC2" | cmd u8    | len u16le | payload
//!   response:  "VTC2" | status u8 | len u16le | payload
//!
//! Payloads: a name is a u8 length followed by its bytes. `Add` carries
//! `name | kind(4) | flags | secret`; `List` answers with `name | kind(4)` per entry;
//! `Code` sends `name | time u64le` and gets the ASCII code back; `Login` sends a name
//! and gets the login of a password entry back; `Reveal` the entry's whole secret as
//! it was added, after a tap; `Rename` carries two names, `old | new`; `EnvPut` is
//! `name | flags | blob`, the whole `.env` in one frame; `EnvGet` sends a name and
//! gets the blob back after a tap; `PinChange` is `old_len u8 | old | new`;
//! `PinStatus` answers `has_pin | unlocked | attempts_left | chip_bound`. A password
//! entry's secret is `login_len u8 | login | password_len u8 | password | note`.
//!
//! A backup is every entry and blob, each sealed on the device under a key made from
//! a passphrase (Argon2id, no chip key): `ExportBegin` carries the passphrase, needs a
//! double tap, and answers a [`BackupHead`]; each `ExportNext` answers one sealed
//! item - `kind(4) | name | secret` under the tag, `BACKUP_AAD` plus the item's index
//! as associated data - and an empty answer ends it. `ImportBegin` is the head with
//! the passphrase behind it, `ImportItem` one sealed item, `ImportEnd` writes the
//! table. The host keeps the items in a file in that order; the device never sees
//! the file.

use crate::oath::{ENV_MAX, Kind, NAME_MAX};
use crate::vault::{Cost, OVERHEAD, SALT_LEN};

pub const MAGIC: [u8; 4] = *b"VTC2";

/// One step of finding the magic word in a byte stream: how many of its bytes are
/// matched after seeing `b`, given `matched` so far. Both ends resynchronise on log
/// lines and half frames with this same loop.
#[must_use]
pub const fn scan_magic(matched: usize, b: u8) -> usize {
    if b == MAGIC[matched] {
        matched + 1
    } else if b == MAGIC[0] {
        1
    } else {
        0
    }
}

/// The seven bytes in front of a payload: magic, the command or status byte, the
/// payload length.
#[must_use]
pub fn frame_head(tag: u8, len: u16) -> [u8; 7] {
    let mut head = [0u8; 7];
    head[..4].copy_from_slice(&MAGIC);
    head[4] = tag;
    head[5..7].copy_from_slice(&len.to_le_bytes());
    head
}
/// The longest backup item: an env blob with its kind and name, sealed.
pub const ITEM_MAX: usize = Kind::WIRE_LEN + 1 + NAME_MAX + ENV_MAX + OVERHEAD;
/// The longest request: an `ImportItem` with the biggest item, which outgrows an
/// `EnvPut` by the kind and the AEAD overhead. Requests only; a response is bounded
/// by its u16 length alone.
pub const MAX_PAYLOAD: usize = ITEM_MAX;
const _: () = assert!(
    MAX_PAYLOAD >= 2 + NAME_MAX + ENV_MAX && ITEM_MAX <= u16::MAX as usize,
    "an EnvPut and an item both fit a frame"
);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Cmd {
    Info = 0x01,
    Add = 0x10,
    List = 0x11,
    /// A TOTP code; the button must be tapped.
    Code = 0x12,
    Delete = 0x13,
    /// A password, as stored; the button must be tapped.
    Reveal = 0x14,
    /// The login that goes with a password; the PIN is enough.
    Login = 0x15,
    /// A new name for an entry; the PIN is enough, nothing leaves the device.
    Rename = 0x16,
    /// A whole env blob in; the PIN is enough.
    EnvPut = 0x17,
    /// A whole env blob out; the button must be tapped.
    EnvGet = 0x18,
    PinStatus = 0x20,
    PinSet = 0x21,
    PinUnlock = 0x22,
    PinChange = 0x23,
    Lock = 0x24,
    /// Factory reset; the button must be held longer still.
    Wipe = 0x25,
    /// A backup begins: the passphrase in, a `BackupHead` out; the button must be
    /// tapped twice.
    ExportBegin = 0x30,
    /// The next sealed item, or nothing when the backup is complete.
    ExportNext = 0x31,
    /// A restore begins: the head and the passphrase in; the PIN is enough.
    ImportBegin = 0x32,
    /// One sealed item back in, in the order it came out.
    ImportItem = 0x33,
    /// The restored table written to flash.
    ImportEnd = 0x34,
}

impl Cmd {
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Info,
            0x10 => Self::Add,
            0x11 => Self::List,
            0x12 => Self::Code,
            0x13 => Self::Delete,
            0x14 => Self::Reveal,
            0x15 => Self::Login,
            0x16 => Self::Rename,
            0x17 => Self::EnvPut,
            0x18 => Self::EnvGet,
            0x20 => Self::PinStatus,
            0x21 => Self::PinSet,
            0x22 => Self::PinUnlock,
            0x23 => Self::PinChange,
            0x24 => Self::Lock,
            0x25 => Self::Wipe,
            0x30 => Self::ExportBegin,
            0x31 => Self::ExportNext,
            0x32 => Self::ImportBegin,
            0x33 => Self::ImportItem,
            0x34 => Self::ImportEnd,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// `Add` and `EnvPut` flags.
pub const FLAG_REPLACE: u8 = 0x01;

/// Status bytes that are not a [`Fail`]: success, and two ways to send garbage.
pub const OK: u8 = 0x00;
pub const BAD_CMD: u8 = 0x01;
pub const BAD_LEN: u8 = 0x02;

/// Why a command did not happen. `WrongPin` carries the attempts left as its payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    Refused,
    Internal,
    NotFound,
    Full,
    BadArg,
    Locked,
    WrongPin(u8),
    Wiped,
    NoPin,
    PinExists,
    Exists,
    /// The vault was written under a different key setup (chip-bound or not) than
    /// this firmware has; only a wipe makes it usable again.
    Incompatible,
    /// A backup item did not open: the wrong passphrase, or a file changed since
    /// it was written. Also a restore step out of order.
    BadBackup,
}

impl Fail {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Refused => 0x03,
            Self::Internal => 0x04,
            Self::NotFound => 0x05,
            Self::Full => 0x06,
            Self::BadArg => 0x07,
            Self::Locked => 0x08,
            Self::WrongPin(_) => 0x09,
            Self::Wiped => 0x0A,
            Self::NoPin => 0x0B,
            Self::PinExists => 0x0C,
            Self::Exists => 0x0D,
            Self::Incompatible => 0x0E,
            Self::BadBackup => 0x0F,
        }
    }

    /// `payload` is the response body: only `WrongPin` puts anything in it.
    #[must_use]
    pub const fn from_code(code: u8, payload: &[u8]) -> Option<Self> {
        Some(match code {
            0x03 => Self::Refused,
            0x04 => Self::Internal,
            0x05 => Self::NotFound,
            0x06 => Self::Full,
            0x07 => Self::BadArg,
            0x08 => Self::Locked,
            0x09 => Self::WrongPin(match payload.first() {
                Some(left) => *left,
                None => 0,
            }),
            0x0A => Self::Wiped,
            0x0B => Self::NoPin,
            0x0C => Self::PinExists,
            0x0D => Self::Exists,
            0x0E => Self::Incompatible,
            0x0F => Self::BadBackup,
            _ => return None,
        })
    }
}

/// What a backup's key is made from, besides the passphrase: the `ExportBegin`
/// answer, and the front of an `ImportBegin`. `salt | m_kib u32le | t u32le`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackupHead {
    pub salt: [u8; SALT_LEN],
    pub cost: Cost,
}

impl BackupHead {
    pub const WIRE_LEN: usize = SALT_LEN + 8;

    #[must_use]
    pub fn wire(self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[..SALT_LEN].copy_from_slice(&self.salt);
        b[SALT_LEN..SALT_LEN + 4].copy_from_slice(&self.cost.m_kib.to_le_bytes());
        b[SALT_LEN + 4..].copy_from_slice(&self.cost.t.to_le_bytes());
        b
    }

    /// None for a cost this firmware will not run.
    #[must_use]
    pub fn from_wire(b: [u8; Self::WIRE_LEN]) -> Option<Self> {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[..SALT_LEN]);
        let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let cost = Cost::from_wire(word(SALT_LEN), word(SALT_LEN + 4))?;
        Some(BackupHead { salt, cost })
    }
}

/// The `PinStatus` answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PinStatus {
    pub has_pin: bool,
    pub unlocked: bool,
    pub retries_left: u8,
    /// Whether this firmware mixes a chip-only key into the PIN.
    pub chip_bound: bool,
}

impl PinStatus {
    pub const WIRE_LEN: usize = 4;

    #[must_use]
    pub fn wire(self) -> [u8; Self::WIRE_LEN] {
        [
            u8::from(self.has_pin),
            u8::from(self.unlocked),
            self.retries_left,
            u8::from(self.chip_bound),
        ]
    }

    #[must_use]
    pub const fn from_wire(b: [u8; Self::WIRE_LEN]) -> Self {
        PinStatus {
            has_pin: b[0] != 0,
            unlocked: b[1] != 0,
            retries_left: b[2],
            chip_bound: b[3] != 0,
        }
    }
}
