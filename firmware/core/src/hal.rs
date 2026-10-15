//! What a board must provide. Deliberately tiny: four traits with one job each, so a
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
