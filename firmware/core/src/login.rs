//! The computer's login password, which a board with a keyboard interface types on the
//! double tap made with nothing asked (`ui::IdleDoubleTap`), and then Enter. The board
//! keeps it outside the vault: at the login screen nothing has unlocked the vault yet.
//! Maintainer's decision, 2026-10-17; docs/threat-model.md says what it costs.

/// Longer than any password typed by hand, and short enough to type in a second.
pub const LOGIN_MAX: usize = 64;

/// A login password the keyboard can type: 1 to `LOGIN_MAX` printable ASCII characters.
/// Nothing else has a key on a US keyboard, and a control character - Enter above all -
/// would let whoever sets it type a second line after the password.
#[derive(Clone, Copy)]
pub struct Login<'a>(&'a [u8]);

impl<'a> Login<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let printable = bytes.iter().all(|b| (0x20..=0x7E).contains(b));
        (!bytes.is_empty() && bytes.len() <= LOGIN_MAX && printable).then_some(Login(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}
