//! What a board must provide. Deliberately tiny: six traits with one job each, so a
//! new board is a page of glue, not a port of the firmware.
//!
//! Flash and entropy use the ecosystem traits directly
//! (`embedded_storage::nor_flash::NorFlash`, `rand_core::CryptoRng`).

/// The byte stream to the host. Reads are non-blocking; the framer polls with its own
/// deadlines.
pub trait Port {
    /// One byte if one is waiting, else None.
    fn read_byte(&mut self) -> Option<u8>;
    /// Blocks until all of `data` is queued.
    fn write(&mut self, data: &[u8]);
    /// Blocks until queued bytes have left.
    fn flush(&mut self);
}

/// Milliseconds since boot. Only differences are ever taken, so any monotonic source
/// will do.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// The physical confirmation channel: one button, one light.
pub trait Ui {
    fn set(&mut self, state: crate::ui::State);
    /// True while the button is held.
    fn pressed(&self) -> bool;
    /// True once whoever asked for the gesture has withdrawn the request: the wait ends
    /// refused, as if its time were up, and never as a press. Only a board serving
    /// requests that can be cancelled - passkeys - says anything but no.
    fn withdrawn(&self) -> bool {
        false
    }
}

/// Flash the board keeps for something besides the vault - the nRF52840's passkeys -
/// which a backup carries sealed like the items and a restore puts back, sector by
/// 4 KiB sector (`store::SECTOR`). A board with nothing of the kind uses
/// [`NoAttachment`].
///
/// While a backup or a restore runs, the board keeps its own user of the region off it
/// (`freeze`), so the copy is never torn and a restore never writes under a live
/// filesystem; it lets go at `thaw`, and after a restore that changed the region it
/// restarts that user. A board may also let go on its own, when the host stops talking
/// mid-session; reads and writes then fail, which ends the session.
pub trait Attachment {
    /// How many sectors it has.
    fn sectors(&self) -> u32;
    /// Sector `i` into `out`, `SECTOR` bytes. False when it cannot be read, or the
    /// freeze is no longer held.
    fn read(&mut self, i: u32, out: &mut [u8]) -> bool;
    /// Sector `i` made to hold `data`, `SECTOR` bytes, or blank when `None`: whether it
    /// changed, or None when it could not be written.
    fn put(&mut self, i: u32, data: Option<&[u8]>) -> Option<bool>;
    fn freeze(&mut self);
    fn thaw(&mut self, changed: bool);
}

/// The attachment of a board without one: no sectors, so a backup carries none and a
/// restore refuses any it is handed.
pub struct NoAttachment;

impl Attachment for NoAttachment {
    fn sectors(&self) -> u32 {
        0
    }

    fn read(&mut self, _: u32, _: &mut [u8]) -> bool {
        false
    }

    fn put(&mut self, _: u32, _: Option<&[u8]>) -> Option<bool> {
        None
    }

    fn freeze(&mut self) {}

    fn thaw(&mut self, _: bool) {}
}

/// Where a board with a keyboard interface keeps the login password it types
/// (`crate::login`). A board without one uses [`NoKeyboard`].
pub trait Keyboard {
    /// Keeps `login` for the keyboard, or forgets the one kept when `None`. False when
    /// it could not, or the board has no keyboard.
    fn keep(&mut self, login: Option<crate::login::Login<'_>>) -> bool;
}

/// The keyboard of a board without one: nothing is kept, so the command fails.
pub struct NoKeyboard;

impl Keyboard for NoKeyboard {
    fn keep(&mut self, _: Option<crate::login::Login<'_>>) -> bool {
        false
    }
}

/// A secret only this chip has, mixed into the key derivation so that a copy of the
/// flash is worthless without the chip: HMAC-SHA256 under a key the chip can use but
/// software never reads, such as one burned into its fuses.
pub trait DeviceKey {
    /// Whether `mac` really mixes in a chip-only key. Recorded in the vault so that a
    /// firmware with the other answer refuses the vault instead of burning attempts.
    /// A board answers false until it has such a key: the PIN alone, and said so.
    fn bound(&self) -> bool;
    /// HMAC-SHA256 of `msg` under the device key into `out` - or `msg` itself when
    /// not bound. False when the chip should have a key and cannot use it: an error,
    /// never a fallback.
    fn mac(&mut self, msg: &[u8; 32], out: &mut [u8; 32]) -> bool;
}
