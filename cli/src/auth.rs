//! `vkey auth`: `sudo` and the lock screen with a tap on the key, through `pam_u2f`.
//!
//! ```text
//! sudo vkey auth enable     once: a credential for this host's logins, PAM told
//! sudo vkey auth disable    all of it undone
//! ```
//!
//! The key is a FIDO2 authenticator (the nRF52840's passkeys), so a login is the scheme
//! every other key uses, `pam_u2f`'s (maintainer's decision, 2026-10-03). `enable` makes
//! a credential for `pam://<host>` after a tap and tries it after another, as
//! `pamu2fcfg` would if the 1.1.0 that distributions ship accepted a key that attests
//! with the credential's own key (`crate::fido`). Its public half goes into
//! `/etc/u2f_mappings`, which is root's: nothing running as the user can enrol a key of
//! its own. One `sufficient` line in each PAM service then lets a tap in. With no key,
//! or no tap before the key gives up (30 s), PAM asks for the password as it always did.
//! It replaced, 2026-10-15, an Ed25519 scheme of vkey's own over `pam_exec`, which
//! needed a chip key the nRF52840 does not have (restorable from 4bd49f3).

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use data_encoding::BASE64;

use crate::device::Error;
use crate::{fido, file};

/// Where distributions install the module - Debian's and Ubuntu's multiarch directories,
/// Fedora's and Arch's. Without it the line would lock nobody out, but let nobody in.
const PAM_U2F: [&str; 4] = [
    "/usr/lib/x86_64-linux-gnu/security/pam_u2f.so",
    "/usr/lib/aarch64-linux-gnu/security/pam_u2f.so",
    "/usr/lib64/security/pam_u2f.so",
    "/usr/lib/security/pam_u2f.so",
];

/// Who may log in with which credential: `user:keyHandle,publicKey,type,options`, one
/// line per user.
const MAPPINGS: &str = "/etc/u2f_mappings";
/// The one line `enable` adds. `sufficient`: a good assertion lets the user in, anything
/// else falls through to the password. `cue`: PAM says to tap the key.
const PAM_LINE: &str = "auth sufficient pam_u2f.so authfile=/etc/u2f_mappings cue";
/// The PAM services that get the line, when this host has them: `sudo`, and the lock
/// screens of COSMIC, GNOME, KDE, sway and Hyprland.
const SERVICES: [&str; 6] = [
    "sudo",
    "cosmic-greeter",
    "gdm-password",
    "kde",
    "swaylock",
    "hyprlock",
];
/// Where root runs vkey from: a copy only root can change, in sudo's `secure_path`, so
/// `sudo vkey auth enable` finds it, and a program running as the user cannot swap
/// what root runs, as it could `~/.local/bin/vkey`.
pub const ROOT_COPY: &str = "/usr/local/sbin/vkey";
/// A copy of each PAM file as it was before `enable` first touched it.
const BEFORE: &str = ".before-vkey";
/// What the scheme this replaced kept on the host: a public key per user.
const OLD_KEYS: &str = "/etc/vkey/auth";
/// And the copy of vkey its PAM line ran, which nothing runs any more.
const OLD_BINARY: &str = "/usr/local/bin/vkey";

/// `sudo vkey auth enable`: a credential on the key for the user who ran sudo, its
/// public half in the mapping, the line in PAM.
pub fn enable() -> Result<u8, Error> {
    let user = sudo_user()?;
    root_only("enable")?;
    let mapping = enrol(&user)?;
    let existing = read_or_empty(Path::new(MAPPINGS))?;
    file::replace(
        Path::new(MAPPINGS),
        with_mapping(&existing, &user, &mapping).as_bytes(),
        0o644,
    )?;
    forget_old(&user)?;

    let mut armed = Vec::new();
    let mut manual = Vec::new();
    for service in SERVICES {
        let path = Path::new("/etc/pam.d").join(service);
        if !path.exists() {
            continue;
        }
        if add_line(&path)? {
            armed.push(service);
        } else {
            manual.push(path);
        }
    }

    println!("a tap on this key now lets {user} in: {}", armed.join(", "));
    for path in manual {
        println!(
            "{} has no line vkey recognises to put its own above; add it by hand, above the\n\
             line that brings in the password check:\n  {PAM_LINE}",
            path.display()
        );
    }
    println!(
        "without the key the password works as before; with the key in and no tap, the\n\
         password prompt comes once the key gives up waiting, after 30 s"
    );
    Ok(0)
}

/// `sudo vkey auth disable`: the line out of every PAM file and the user out of the
/// mapping. The credential stays on the key, unused, until authenticatorReset.
pub fn disable() -> Result<u8, Error> {
    let user = sudo_user()?;
    root_only("disable")?;
    for service in SERVICES {
        let path = Path::new("/etc/pam.d").join(service);
        if path.exists() {
            remove_line(&path)?;
        }
    }
    let path = Path::new(MAPPINGS);
    if path.exists() {
        let left = without_mapping(&read_or_empty(path)?, &user);
        if left.is_empty() {
            fs::remove_file(path)?;
        } else {
            file::replace(path, left.as_bytes(), 0o644)?;
        }
    }
    forget_old(&user)?;
    println!("disabled: {user} logs in with the password alone");
    Ok(0)
}

/// A credential for `user` on the key, made and then tried with a login exactly as
/// `pam_u2f` will ask for it - a tap each - and its mapping line, in the shape
/// `pamu2fcfg` writes: `user:<id, base64>,<x and y, base64>,es256,+presence`. Nothing on
/// this host changes until both taps have answered.
fn enrol(user: &str) -> Result<String, Error> {
    if !module_present() {
        return Err(Error::Value(
            "pam_u2f is missing:  sudo apt install libpam-u2f".into(),
        ));
    }
    // What pam_u2f asserts with when no origin is given: pam:// and gethostname().
    let rp = format!("pam://{}", hostname()?);
    let mut key = fido::Key::open()?;
    eprintln!("tap the key when its light turns amber, to make the credential");
    let credential = key.make_credential(&rp, user)?;
    eprintln!("and once more, to try it the way a login will");
    key.get_assertion(&rp, &credential.id)?;
    Ok(format!(
        "{user}:{},{},es256,+presence",
        BASE64.encode(&credential.id),
        BASE64.encode(&credential.public)
    ))
}

/// Whether `pam_u2f` is installed where this host's PAM looks for it.
pub fn module_present() -> bool {
    PAM_U2F.iter().any(|p| Path::new(p).exists())
}

/// Whether a tap lets `user` in through `sudo`: the line in its PAM file and the user's
/// credential in the mapping. Both are world-readable, so no root is needed to ask.
pub fn enabled(user: &str) -> bool {
    let mine = format!("{user}:");
    fs::read_to_string("/etc/pam.d/sudo").is_ok_and(|t| t.lines().any(|l| l.trim() == PAM_LINE))
        && fs::read_to_string(MAPPINGS).is_ok_and(|t| t.lines().any(|l| l.starts_with(&mine)))
}

fn hostname() -> Result<String, Error> {
    let name = fs::read_to_string("/proc/sys/kernel/hostname")?;
    Ok(name.trim().to_string())
}

/// `existing` with `user`'s line replaced by `mapping`, every other user's kept.
fn with_mapping(existing: &str, user: &str, mapping: &str) -> String {
    let mut out = without_mapping(existing, user);
    out.push_str(mapping);
    out.push('\n');
    out
}

/// `existing` without `user`'s line.
fn without_mapping(existing: &str, user: &str) -> String {
    let mine = format!("{user}:");
    let mut out = String::new();
    for line in existing.lines().filter(|l| !l.starts_with(&mine)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// What the scheme this replaced left for `user`: the public key goes, the directory
/// with it once empty. Its copy of vkey is pointed out rather than deleted - this run
/// cannot tell whether someone put a binary there for another reason.
fn forget_old(user: &str) -> Result<(), Error> {
    let key = Path::new(OLD_KEYS).join(user);
    if key.exists() {
        fs::remove_file(&key)?;
        for dir in [OLD_KEYS, "/etc/vkey"] {
            // Only when empty: `remove_dir` refuses anything else, and that is fine.
            fs::remove_dir(dir).ok();
        }
    }
    if Path::new(OLD_BINARY).exists() {
        println!(
            "{OLD_BINARY} was the old scheme's copy for PAM and nothing runs it now:\n  \
             sudo rm {OLD_BINARY}"
        );
    }
    Ok(())
}

fn read_or_empty(path: &Path) -> Result<String, Error> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

/// Whether `line` is the one that brings in the password check: `vkey` goes right above
/// it. Debian's `@include common-auth`, and the `include`/`substack` of Fedora and Arch.
fn is_anchor(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["@include", "common-auth"] => true,
        ["auth", "include" | "substack", stack, ..] => matches!(
            *stack,
            "common-auth" | "system-auth" | "password-auth" | "system-login" | "system-local-login"
        ),
        _ => false,
    }
}

/// A line `enable` put there: this one, or the old scheme's `pam_exec` of `vkey auth`.
fn is_ours(line: &str) -> bool {
    line.trim() == PAM_LINE || (line.contains("pam_exec.so") && line.contains("vkey auth"))
}

/// `text` with the line above the anchor, any earlier form of it gone. None when there
/// is no anchor.
fn with_line(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().filter(|l| !is_ours(l)).collect();
    let at = lines.iter().position(|l| is_anchor(l))?;
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == at {
            out.push_str(PAM_LINE);
            out.push('\n');
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

/// The line added to the file at `path`, the file as it was kept once beside it. False
/// when there is no anchor, and then nothing is written.
fn add_line(path: &Path) -> Result<bool, Error> {
    let text = fs::read_to_string(path)?;
    let Some(out) = with_line(&text) else {
        return Ok(false);
    };
    if out != text {
        let mut before = path.as_os_str().to_owned();
        before.push(BEFORE);
        if !Path::new(&before).exists() {
            fs::copy(path, &before)?;
        }
        file::replace(path, out.as_bytes(), 0o644)?;
    }
    Ok(true)
}

fn remove_line(path: &Path) -> Result<(), Error> {
    let text = fs::read_to_string(path)?;
    if !text.lines().any(is_ours) {
        return Ok(());
    }
    let mut out = String::new();
    for line in text.lines().filter(|l| !is_ours(l)) {
        out.push_str(line);
        out.push('\n');
    }
    file::replace(path, out.as_bytes(), 0o644)
}

/// The user who ran sudo: the one whose logins the key will answer.
/// Refuses to change PAM from a binary that anyone but root may rewrite, itself or
/// through a directory above it: whoever can would run as root the next time it is
/// called this way. It cannot stop a program running as the user from putting its
/// own `sudo` first in PATH; `docs/threat-model.md` says so.
fn root_only(verb: &str) -> Result<(), Error> {
    let exe = std::env::current_exe()?;
    for path in exe.ancestors() {
        let meta = fs::metadata(path)?;
        // Group root is not root: a member of it who can write here is "others".
        let writable = meta.mode() & 0o022 != 0;
        if meta.uid() != 0 || writable {
            return Err(Error::Value(format!(
                "this runs as root from {}, and {} can be changed by others than root, so \
                 whoever changes it would run as root too. Run a copy only root can \
                 change:\n  sudo install -m 0755 {} {ROOT_COPY}\n  sudo vkey auth {verb}",
                exe.display(),
                path.display(),
                exe.display()
            )));
        }
    }
    Ok(())
}

fn sudo_user() -> Result<String, Error> {
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err(Error::Value("this changes PAM: run it with sudo".into()));
    }
    let user = std::env::var("SUDO_USER").map_err(|_| {
        Error::Value("run it through sudo as the user who logs in, not as root itself".into())
    })?;
    let ok = !user.is_empty()
        && !user.starts_with('.')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(user)
    } else {
        Err(Error::Value(format!(
            "'{user}' is not a login name vkey accepts"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUDO: &str = "#%PAM-1.0\n\
        session    required   pam_limits.so\n\
        auth sufficient pam_exec.so quiet stdout seteuid /usr/local/bin/vkey auth\n\
        @include common-auth\n\
        @include common-account\n";

    #[test]
    fn the_line_replaces_the_old_scheme_above_the_password_check() {
        let out = with_line(SUDO).expect("has an anchor");
        assert!(!out.contains("pam_exec.so"), "the old line is gone:\n{out}");
        assert!(
            out.contains(&format!("{PAM_LINE}\n@include common-auth\n")),
            "right above the password check:\n{out}"
        );
        assert_eq!(
            with_line(&out).as_deref(),
            Some(out.as_str()),
            "and twice is once"
        );
    }

    #[test]
    fn a_file_without_the_password_check_is_left_alone() {
        assert_eq!(with_line("auth required pam_unix.so\n"), None);
    }

    #[test]
    fn a_mapping_replaces_only_its_own_user() {
        let existing = "alice:aaa,bbb,es256,+presence\nhifes:old,old,es256,+presence\n";
        let out = with_mapping(existing, "hifes", "hifes:new,new,es256,+presence");
        assert_eq!(
            out,
            "alice:aaa,bbb,es256,+presence\nhifes:new,new,es256,+presence\n"
        );
        assert_eq!(
            without_mapping(&out, "hifes"),
            "alice:aaa,bbb,es256,+presence\n"
        );
        assert_eq!(
            without_mapping("hifesx:k,k\n", "hifes"),
            "hifesx:k,k\n",
            "a user whose name merely starts with another's is someone else"
        );
    }
}
