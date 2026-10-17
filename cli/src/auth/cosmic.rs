//! COSMIC's greeter: its login screen and its lock screen in one PAM service. A tap at
//! the login screen lets the user in with the keyring still locked, since only the
//! password unlocks it, so while [`TYPED`] exists the key types that password there
//! instead, and [`SKIP_AT_LOGIN`] keeps the tap for the lock screen (`vkey login`;
//! maintainer's decisions, 2026-10-17).

use std::fs;
use std::path::Path;

use super::{PAM_LINE, add_line, enabled, remove_line, root_only, sudo_user};
use crate::device::Error;
use crate::file;

/// The PAM services that are COSMIC's greeter.
pub(super) const GREETERS: [&str; 1] = ["cosmic-greeter"];
/// There when the key types the login password at the login screen, absent when a tap
/// opens it as before. Root's, like the PAM files it decides about.
const TYPED: &str = "/etc/vkey/login-typed";
/// Put above [`PAM_LINE`] in a greeter while [`TYPED`] exists: it skips the tap when root
/// asks. The login is greetd's session worker, root; the lock screen is
/// `cosmic-greeter` in the user's session, and `pam_exec` runs `test` as its caller. If
/// COSMIC ever swaps who asks, the lock screen wants the typed password, or the login
/// screen a tap that leaves the keyring locked: neither lets anyone in without the key.
pub(super) const SKIP_AT_LOGIN: &str =
    "auth [success=1 default=ignore] pam_exec.so quiet /usr/bin/test -O /root";

/// `sudo vkey auth greeter typed|tap`: whether the login screen waits for the password
/// the key types, or for a tap as `enable` arms it. `typed` takes the tap away from the
/// login screen only, so that the double tap is not taken as a tap that logs in with the
/// keyring locked; the lock screen keeps it. Either way the tap is there only while
/// `enable` holds for the user.
pub fn greeter(typed: bool) -> Result<u8, Error> {
    let user = sudo_user()?;
    root_only("greeter")?;
    let mark = Path::new(TYPED);
    if typed {
        if let Some(dir) = mark.parent() {
            fs::create_dir_all(dir)?;
        }
        file::replace(mark, b"", 0o644)?;
    } else if mark.exists() {
        fs::remove_file(mark)?;
    }
    let armed = enabled(&user);
    for service in GREETERS {
        let path = Path::new("/etc/pam.d").join(service);
        if !path.exists() {
            continue;
        }
        if !armed {
            remove_line(&path)?;
        } else if !add_line(&path, greeter_lines(typed))? {
            println!(
                "{} has no line vkey recognises to put its own above; add these by hand:\n  {}",
                path.display(),
                greeter_lines(typed).join("\n  ")
            );
        }
    }
    println!(
        "{}",
        match (typed, armed) {
            (true, true) =>
                "the login screen waits for the password the key types on a double tap; the lock screen opens with a tap",
            (true, false) =>
                "the login screen waits for the password the key types on a double tap",
            (false, true) => "the login and the lock screen open with a tap, as before",
            (false, false) => "the login screen takes the password typed by hand",
        }
    );
    Ok(0)
}

/// What a greeter gets above its password check.
pub(super) fn greeter_lines(typed: bool) -> &'static [&'static str] {
    if typed {
        &[SKIP_AT_LOGIN, PAM_LINE]
    } else {
        &[PAM_LINE]
    }
}

/// Whether the key types the login password at the login screen. World-readable, so no
/// root is needed to ask.
pub fn typed() -> bool {
    Path::new(TYPED).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::with_line;

    const GREETER: &str = "#%PAM-1.0\n\
        auth    requisite       pam_nologin.so\n\
        @include common-auth\n\
        auth    optional        pam_gnome_keyring.so\n\
        @include common-account\n";

    #[test]
    fn a_typed_login_skips_the_tap_only_right_above_it() {
        let typed = with_line(GREETER, greeter_lines(true)).expect("has an anchor");
        assert!(
            typed.contains(&format!(
                "{SKIP_AT_LOGIN}\n{PAM_LINE}\n@include common-auth\n"
            )),
            "the skip covers the tap and nothing else:\n{typed}"
        );
        let tap = with_line(&typed, greeter_lines(false)).expect("has an anchor");
        assert!(
            !tap.contains(SKIP_AT_LOGIN),
            "and goes with the switch:\n{tap}"
        );
        assert!(tap.contains(&format!("{PAM_LINE}\n@include common-auth\n")));
    }
}
