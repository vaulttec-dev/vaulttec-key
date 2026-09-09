//! vaulttecdev hardware TOTP key - the key itself, with the hardware abstracted away.
//!
//! No chip name appears here. A board (`firmware/boards/<name>`) supplies flash,
//! entropy, a clock, the USB port and the button/LED through the traits in `hal`,
//! then hands them to [`proto::Proto::run`]. Everything else - the protocol, the PIN
//! lifecycle, the crypto, the flash layout, TOTP - is this crate.
//!
//! The host CLI compiles this crate too, for [`wire`], [`oath`]'s parameter types and
//! [`vault::Pin`]: one definition of what is valid, on both ends of the cable.

#![no_std]

pub mod device;
pub mod hal;
pub mod oath;
pub mod proto;
pub mod store;
pub mod ui;
pub mod vault;
pub mod wire;

/// The string INFO reports: firmware version plus the board it was built for. The
/// version lives here and nowhere else; boards only add their name.
#[macro_export]
macro_rules! version {
    ($board:literal) => {
        concat!("vaultkey 0.8 ", $board)
    };
}
